LOG_MAX=16*1024*1024
from pathlib import Path
import hashlib,json,os,signal,subprocess,time
MEMORY=4294967296
TASKS=64
CPUS=1
CONTROL_UNIT=None
class CapError(RuntimeError):pass
def need(v,m):
 if not v:raise CapError(m)
def _write_json(path, obj):
    raw=(json.dumps(obj,indent=2)+chr(10)).encode('utf-8');need(len(raw)<=8192,'RECEIPT_CAP')
    with open(path,'xb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
class LinuxChild:
    def __init__(self,pid): self.pid=pid; self.returncode=None
    def poll(self):
        if self.returncode is None:
            pid,status=os.waitpid(self.pid,os.WNOHANG)
            if pid: self.returncode=os.waitstatus_to_exitcode(status)
        return self.returncode
    def wait(self,timeout=None):
        deadline=time.monotonic()+timeout if timeout is not None else None
        while self.poll() is None:
            if deadline is not None and time.monotonic()>deadline: raise CapError('OWNED_CHILD_REAP_TIMEOUT')
            time.sleep(.02)
        return self.returncode
def stopped_linux_child(argv,cwd,env,out,err,pass_fds,cap):
    pid=os.fork()
    if pid==0:
        try:
            os.setsid();os.chdir(cwd)
            with open('/dev/null','rb') as null: os.dup2(null.fileno(),0)
            os.dup2(out.fileno(),1);os.dup2(err.fileno(),2)
            for fd in pass_fds: os.set_inheritable(fd,True)
            os.kill(os.getpid(),signal.SIGSTOP)
            os.execvpe(str(argv[0]),list(map(str,argv)),env)
        except BaseException: os._exit(127)
    p=LinuxChild(pid)
    try:
        waited,status=os.waitpid(pid,os.WUNTRACED)
        need(waited==pid and os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGSTOP,'OWNED_CHILD_STOP_BEFORE_EXEC')
        statrow=(Path('/proc')/str(pid)/'stat').read_text();tail=statrow[statrow.rfind(')')+2:].split()
        need(tail[0] in ('T','t'),'CHILD_NOT_STOPPED')
        membership=(Path('/proc')/str(pid)/'cgroup').read_text()
        need(('0::'+cap['cgroup']) in membership.splitlines(),'CHILD_CGROUP_MISMATCH')
        root=Path('/sys/fs/cgroup')/cap['cgroup'].lstrip('/')
        limits={k:(root/k).read_text().strip() for k in ('memory.max','memory.swap.max','pids.max','cpu.max')}
        need(limits==cap['kernelLimits'],'CHILD_ACTUAL_LIMIT_READBACK')
        proof={'pid':pid,'processStartIdentity':tail[19],'stateBeforeExec':tail[0],'cgroup':membership.strip(),'kernelLimitsBeforeExec':limits}
        os.killpg(pid,signal.SIGCONT)
        return p,proof
    except BaseException:
        try:os.killpg(pid,signal.SIGKILL)
        except ProcessLookupError: pass
        try:os.waitpid(pid,0)
        except ChildProcessError: pass
        raise
def linux_caps():
 need(os.getuid()>0 and os.getgid()>0 and CONTROL_UNIT,'OWN_NONROOT_UNIT')
 rel=next(x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'));need(rel=='/system.slice/'+CONTROL_UNIT,'OWN_CURRENT_CGROUP')
 root=Path('/sys/fs/cgroup')/rel.lstrip('/');limits={k:(root/k).read_text().strip() for k in ('memory.max','memory.swap.max','pids.max','cpu.max')};need(limits=={'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'100000 100000'},'OWN_CAPS')
 return {'uid':os.getuid(),'cgroup':rel,'kernelLimits':limits,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
def run(argv, *, cwd, env, timeout, evidence, pass_fds=()):
    """Linux caller must already be in the real bounded job; Windows creates a suspended Job child."""
    need(0<timeout<=1200,'WALL_CAP'); evidence=Path(evidence); evidence.mkdir(parents=True,exist_ok=False)
    need(os.name=='posix','LINUX_ONLY')
    cap=linux_caps(); start=time.monotonic()
    with open(evidence/'stdout.log','xb') as out,open(evidence/'stderr.log','xb') as err:
        p,child_proof=stopped_linux_child(argv,cwd,env,out,err,pass_fds,cap)
        timed=False
        try:
            child=Path('/proc')/str(p.pid)/'cgroup'
            if child.exists(): need(('0::'+cap['cgroup']) in child.read_text().splitlines(),'CHILD_CGROUP_MISMATCH')
            while p.poll() is None:
                if time.monotonic()-start>timeout or out.tell()+err.tell()>LOG_MAX:
                    os.killpg(p.pid,signal.SIGKILL); timed=True; break
                time.sleep(.1)
            p.wait(timeout=max(.1,start+timeout+10-time.monotonic()))
            # The outer owned service also reaps its entire cgroup before lane release.
            try: os.killpg(p.pid,0)
            except ProcessLookupError: pass
            else:
                os.killpg(p.pid,signal.SIGKILL)
                raise CapError('OWNED_PROCESS_GROUP_STILL_ACTIVE')
        finally:
            if p.poll() is None:
                try: os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                p.wait(timeout=max(.1,start+timeout+10-time.monotonic()))
    root=Path('/sys/fs/cgroup')/cap['cgroup'].lstrip('/')
    cap['memoryPeak']=(root/'memory.peak').read_text().strip() if (root/'memory.peak').exists() else None
    cap['memoryEvents']=(root/'memory.events').read_text().strip()
    record={'schema':'bounded-actionlint-process/v1','argv':argv,'cwd':str(cwd),'pid':p.pid,'exitCode':p.returncode,'timedOut':timed,'seconds':time.monotonic()-start,'actualCap':cap,'childBeforeExec':child_proof}
    _write_json(evidence/'process.json',record)
    need(not timed,'CHILD_WALL_OR_LOG_CAP'); need(p.returncode==0,'CHILD_NONZERO:'+str(p.returncode))
    return record
