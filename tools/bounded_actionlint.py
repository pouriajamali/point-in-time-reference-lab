"""Actual aggregate child supervision; library only, never an arbitrary command CLI."""
from __future__ import annotations
import contextlib, ctypes, hashlib, json, math, os, signal, subprocess, time
from pathlib import Path
MEMORY=4294967296
TASKS=64
CPUS=1
class CapError(RuntimeError): pass

def need(v, why):
    if not v: raise CapError(why)

def validate_linux_cap(cap):
    need(cap.get('kernelLimits')=={'memory.max':str(MEMORY),'memory.swap.max':'0','pids.max':str(TASKS),'cpu.max':'100000 100000'},'ACTUAL_GUEST_CAP_MISMATCH')
    need(isinstance(cap.get('cgroup'),str) and cap['cgroup'].startswith('/user.slice/') and cap['cgroup'].endswith('.service'),'ACTUAL_GUEST_MEMBERSHIP')
    need(cap.get('uid')==1000 and cap.get('bootId'),'ACTUAL_GUEST_IDENTITY')
    return cap

def check_owner(holder, expected):
    need(all(holder.get(k)==expected.get(k) and holder.get(k) is not None for k in ('projectId','randomToken','ownerPID','ownerProcessStartIdentity')),'LEASE_NOT_OWNED')

def linux_caps():
    text=Path('/proc/self/cgroup').read_text()
    rel=next((x[3:] for x in text.splitlines() if x.startswith('0::')),None)
    need(rel is not None,'NO_CGROUP_V2')
    root=Path('/sys/fs/cgroup')/rel.lstrip('/')
    values={n:(root/n).read_text().strip() for n in ('memory.max','memory.swap.max','pids.max','cpu.max')}
    need(values=={'memory.max':str(MEMORY),'memory.swap.max':'0','pids.max':str(TASKS),'cpu.max':'100000 100000'},'ACTUAL_GUEST_CAP_MISMATCH')
    return validate_linux_cap({'cgroup':rel,'kernelLimits':values,'bootId':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'uid':os.getuid()})

def phase_permission(reference, incoming):
    if incoming.get('ACTIONLINT_PORTABLE_PHASE_TOKEN'): return _portable_permission(reference,incoming)
    # A caller-supplied policy/hash pair is not a trust anchor: the source lock pins it.
    name=incoming.get('ACTIONLINT_LEASE_PROTOCOL'); token=incoming.get('ACTIONLINT_PHASE_TOKEN')
    need(name and token,'PHASE_PERMISSION_MISSING')
    protocol=Path(name); raw=protocol.read_bytes()
    need(hashlib.sha256(raw).hexdigest()==reference['execution']['protocolSha256'],'PHASE_PROTOCOL_IDENTITY')
    policy=json.loads(raw); need(policy.get('status')=='ACTIVE_SINGLE_CANONICAL_LANE','PHASE_POLICY_INACTIVE')
    lease=Path(policy['canonicalLeaseWindows' if os.name=='nt' else 'canonicalLeaseLinux'])
    need(lease.is_file() and lease.stat().st_size<=65536,'PHASE_LEASE_MISSING')
    holder=json.loads(lease.read_bytes())
    need(holder.get('randomToken')==token and holder.get('projectId')==reference['projectId'],'PHASE_FOREIGN_LEASE')
    need(holder.get('ownerPID') and holder.get('ownerProcessStartIdentity') and holder.get('phase'),'PHASE_OWNER_IDENTITY')
    if os.name!='nt':
        cap=linux_caps(); unit=holder.get('nativeUnit')
        need(unit and cap['cgroup'].endswith('/'+unit+'.service'),'PHASE_GUEST_MEMBERSHIP')
    return {'token':token,'phase':holder['phase'],'projectId':holder['projectId'],'protocolSha256':reference['execution']['protocolSha256']}

def _write_json(path, obj):
    with open(path,'x',encoding='utf-8') as f: json.dump(obj,f,indent=2)

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

def run(argv, *, cwd, env, timeout, evidence, pass_fds=()):
    """Linux caller must already be in the real bounded job; Windows creates a suspended Job child."""
    need(0<timeout<=1200,'WALL_CAP'); evidence=Path(evidence); evidence.mkdir(parents=True,exist_ok=False)
    if os.name=='nt': return _windows_run(argv,cwd,env,timeout,evidence)
    cap=linux_caps(); start=time.monotonic()
    with open(evidence/'stdout.log','xb') as out,open(evidence/'stderr.log','xb') as err:
        p,child_proof=stopped_linux_child(argv,cwd,env,out,err,pass_fds,cap)
        timed=False
        try:
            child=Path('/proc')/str(p.pid)/'cgroup'
            if child.exists(): need(('0::'+cap['cgroup']) in child.read_text().splitlines(),'CHILD_CGROUP_MISMATCH')
            while p.poll() is None:
                if time.monotonic()-start>timeout or out.tell()+err.tell()>128*1024*1024:
                    os.killpg(p.pid,signal.SIGKILL); timed=True; break
                time.sleep(.1)
            p.wait()
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
                p.wait(timeout=10)
    root=Path('/sys/fs/cgroup')/cap['cgroup'].lstrip('/')
    cap['memoryPeak']=(root/'memory.peak').read_text().strip() if (root/'memory.peak').exists() else None
    cap['memoryEvents']=(root/'memory.events').read_text().strip()
    record={'schema':'bounded-actionlint-process/v1','argv':argv,'cwd':str(cwd),'pid':p.pid,'exitCode':p.returncode,'timedOut':timed,'seconds':time.monotonic()-start,'actualCap':cap,'childBeforeExec':child_proof}
    _write_json(evidence/'process.json',record)
    need(not timed,'CHILD_WALL_OR_LOG_CAP'); need(p.returncode==0,'CHILD_NONZERO:'+str(p.returncode))
    return record

def _kernel():
    from ctypes import wintypes as W
    K=ctypes.WinDLL('kernel32',use_last_error=True)
    for n in ('CreateJobObjectW','CreateFileW'):
        getattr(K,n).restype=W.HANDLE
    K.CreateJobObjectW.argtypes=[ctypes.c_void_p,W.LPCWSTR]
    K.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
    K.CloseHandle.argtypes=[W.HANDLE]
    K.SetInformationJobObject.argtypes=[W.HANDLE,ctypes.c_int,ctypes.c_void_p,W.DWORD]
    K.QueryInformationJobObject.argtypes=[W.HANDLE,ctypes.c_int,ctypes.c_void_p,W.DWORD,ctypes.c_void_p]
    K.AssignProcessToJobObject.argtypes=[W.HANDLE,W.HANDLE]
    K.IsProcessInJob.argtypes=[W.HANDLE,W.HANDLE,ctypes.POINTER(W.BOOL)]
    K.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD]
    K.GetExitCodeProcess.argtypes=[W.HANDLE,ctypes.POINTER(W.DWORD)]
    K.TerminateJobObject.argtypes=[W.HANDLE,W.UINT]
    K.TerminateProcess.argtypes=[W.HANDLE,W.UINT]
    K.ResumeThread.argtypes=[W.HANDLE]
    K.ResumeThread.restype=W.DWORD
    return K,W

def _checked(v):
    if not v: raise ctypes.WinError(ctypes.get_last_error())
    return v

@contextlib.contextmanager
def held_windows_image(path):
    """Deny image write/delete; hold ancestors against rename while the native child starts."""
    import msvcrt
    K,W=_kernel(); path=Path(path).absolute(); handles=[]; fd=None
    invalid=ctypes.c_void_p(-1).value
    try:
        for parent in reversed(path.parents):
            h=K.CreateFileW(str(parent),0x80000000,3,None,3,0x02000000|0x00200000,None)
            need(h not in (None,invalid),'IMAGE_PARENT_HOLD'); handles.append(h)
        h=K.CreateFileW(str(path),0x80000000,1,None,3,0x00200000,None)
        need(h not in (None,invalid),'IMAGE_HOLD')
        fd=msvcrt.open_osfhandle(h,os.O_RDONLY|os.O_BINARY)
        with os.fdopen(fd,'rb',closefd=False) as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
        yield {'sha256':digest,'identity':{'canonicalPath':str(path),'heldReadOnlyDenyDelete':True,'ancestorHandles':len(handles)}}
    finally:
        if fd is not None: os.close(fd)
        for h in reversed(handles): K.CloseHandle(h)

def _windows_run(argv,cwd,env,timeout,evidence):
    import msvcrt
    K,W=_kernel(); U=ctypes.c_size_t
    class Basic(ctypes.Structure):
        _fields_=[('ProcessTime',ctypes.c_longlong),('JobTime',ctypes.c_longlong),('Flags',W.DWORD),('MinWS',U),('MaxWS',U),('ActiveProcesses',W.DWORD),('Affinity',U),('Priority',W.DWORD),('Scheduling',W.DWORD)]
    class IO(ctypes.Structure): _fields_=[(n,ctypes.c_ulonglong) for n in ('ReadOps','WriteOps','OtherOps','ReadBytes','WriteBytes','OtherBytes')]
    class Extended(ctypes.Structure):
        _fields_=[('Basic',Basic),('IO',IO),('ProcessMemory',U),('JobMemory',U),('PeakProcessMemory',U),('PeakJobMemory',U)]
    class Cpu(ctypes.Structure): _fields_=[('Flags',W.DWORD),('Rate',W.DWORD)]
    class Accounting(ctypes.Structure):
        _fields_=[('User',ctypes.c_longlong),('Kernel',ctypes.c_longlong),('PeriodUser',ctypes.c_longlong),('PeriodKernel',ctypes.c_longlong),('Faults',W.DWORD),('Total',W.DWORD),('Active',W.DWORD),('Terminated',W.DWORD)]
    class Startup(ctypes.Structure):
        _fields_=[('cb',W.DWORD),('reserved',W.LPWSTR),('desktop',W.LPWSTR),('title',W.LPWSTR),('x',W.DWORD),('y',W.DWORD),('xs',W.DWORD),('ys',W.DWORD),('xc',W.DWORD),('yc',W.DWORD),('fill',W.DWORD),('flags',W.DWORD),('show',W.WORD),('reserved2',W.WORD),('reservedPtr',ctypes.c_void_p),('stdin',W.HANDLE),('stdout',W.HANDLE),('stderr',W.HANDLE)]
    class Process(ctypes.Structure): _fields_=[('process',W.HANDLE),('thread',W.HANDLE),('pid',W.DWORD),('tid',W.DWORD)]
    class Security(ctypes.Structure): _fields_=[('length',W.DWORD),('descriptor',ctypes.c_void_p),('inherit',W.BOOL)]
    K.CreateProcessW.argtypes=[W.LPCWSTR,W.LPWSTR,ctypes.c_void_p,ctypes.c_void_p,W.BOOL,W.DWORD,ctypes.c_void_p,W.LPCWSTR,ctypes.POINTER(Startup),ctypes.POINTER(Process)]
    K.GetActiveProcessorCount.argtypes=[W.WORD]; K.GetActiveProcessorCount.restype=W.DWORD
    job=K.CreateJobObjectW(None,None); need(bool(job),'JOB_CREATE'); process=Process(); nul=None; start=time.monotonic(); timed=False
    try:
        limits=Extended(); limits.Basic.Flags=0x2000|0x200|0x8; limits.Basic.ActiveProcesses=TASKS; limits.JobMemory=MEMORY
        _checked(K.SetInformationJobObject(job,9,ctypes.byref(limits),ctypes.sizeof(limits)))
        logical=K.GetActiveProcessorCount(0xffff); need(logical>0,'CPU_COUNT'); rate=max(1,min(10000,int(10000*CPUS/logical))); cpu=Cpu(5,rate)
        _checked(K.SetInformationJobObject(job,15,ctypes.byref(cpu),ctypes.sizeof(cpu)))
        actual=Extended(); actualcpu=Cpu()
        _checked(K.QueryInformationJobObject(job,9,ctypes.byref(actual),ctypes.sizeof(actual),None)); _checked(K.QueryInformationJobObject(job,15,ctypes.byref(actualcpu),ctypes.sizeof(actualcpu),None))
        need(actual.JobMemory==MEMORY and actual.Basic.ActiveProcesses==TASKS and actualcpu.Flags==5 and actualcpu.Rate==rate,'JOB_LIMIT_READBACK')
        with open(evidence/'stdout.log','xb') as out,open(evidence/'stderr.log','xb') as err:
            oh,eh=msvcrt.get_osfhandle(out.fileno()),msvcrt.get_osfhandle(err.fileno()); os.set_handle_inheritable(oh,True); os.set_handle_inheritable(eh,True)
            sa=Security(ctypes.sizeof(Security),None,True); nul=K.CreateFileW('NUL',0x80000000,3,ctypes.byref(sa),3,0,None)
            need(nul not in (None,ctypes.c_void_p(-1).value),'NUL_STDIN')
            si=Startup(); si.cb=ctypes.sizeof(si); si.flags=0x100; si.stdin=nul; si.stdout=oh; si.stderr=eh
            line=ctypes.create_unicode_buffer(subprocess.list2cmdline(list(map(str,argv)))); block=ctypes.create_unicode_buffer('\0'.join(k+'='+str(v) for k,v in sorted(env.items(),key=lambda x:x[0].upper()))+'\0\0')
            _checked(K.CreateProcessW(None,line,None,None,True,0x4|0x400|0x08000000,block,str(cwd),ctypes.byref(si),ctypes.byref(process)))
            os.set_handle_inheritable(oh,False); os.set_handle_inheritable(eh,False)
            _checked(K.AssignProcessToJobObject(job,process.process)); member=W.BOOL(); _checked(K.IsProcessInJob(process.process,job,ctypes.byref(member))); need(bool(member.value),'ACTUAL_CHILD_JOB_MEMBERSHIP')
            _checked(K.ResumeThread(process.thread)!=0xffffffff)
            while K.WaitForSingleObject(process.process,100)==0x102:
                if time.monotonic()-start>timeout or out.tell()+err.tell()>128*1024*1024:
                    _checked(K.TerminateJobObject(job,124)); timed=True; break
            need(K.WaitForSingleObject(process.process,10000)==0,'OWNED_CHILD_REAP')
        code=W.DWORD(); _checked(K.GetExitCodeProcess(process.process,ctypes.byref(code)))
        accounting=Accounting(); deadline=time.monotonic()+10
        while True:
            _checked(K.QueryInformationJobObject(job,1,ctypes.byref(accounting),ctypes.sizeof(accounting),None))
            if accounting.Active==0: break
            if time.monotonic()>deadline: _checked(K.TerminateJobObject(job,124)); raise CapError('OWNED_DESCENDANTS_REAP')
            time.sleep(.1)
        _checked(K.QueryInformationJobObject(job,9,ctypes.byref(actual),ctypes.sizeof(actual),None))
        proof={'kind':'actual-Windows-Job','memoryMax':int(actual.JobMemory),'activeProcessMax':int(actual.Basic.ActiveProcesses),'cpuRate':int(actualcpu.Rate),'logicalHostCpu':int(logical),'effectiveCpuCores':actualcpu.Rate*logical/10000,'childMembershipBeforeResume':True,'peakJobMemory':int(actual.PeakJobMemory),'activeProcessesAtTeardown':int(accounting.Active),'totalProcesses':int(accounting.Total)}
        record={'schema':'bounded-actionlint-process/v1','argv':argv,'cwd':str(cwd),'pid':int(process.pid),'exitCode':int(code.value),'timedOut':timed,'seconds':time.monotonic()-start,'actualCap':proof}
        _write_json(evidence/'process.json',record); need(not timed,'CHILD_WALL_OR_LOG_CAP'); need(code.value==0,'CHILD_NONZERO:'+str(code.value)); return record
    finally:
        if process.process and K.WaitForSingleObject(process.process,0)==0x102:
            K.TerminateProcess(process.process,124); K.WaitForSingleObject(process.process,5000)
        if process.thread: K.CloseHandle(process.thread)
        if process.process: K.CloseHandle(process.process)
        if nul and nul!=ctypes.c_void_p(-1).value: K.CloseHandle(nul)
        K.CloseHandle(job)
if __name__=='__main__': raise SystemExit('Library only; use the independently guarded build/check/run entry points.')

def _start_identity(pid):
    if os.name!='nt':
        text=Path('/proc',str(pid),'stat').read_text();return 'proc-start:'+text[text.rfind(')')+2:].split()[19]
    from ctypes import wintypes as W
    K,W=_kernel();K.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];K.OpenProcess.restype=W.HANDLE
    K.GetProcessTimes.argtypes=[W.HANDLE,*[ctypes.POINTER(W.FILETIME)]*4]
    handle=K.OpenProcess(0x1000,False,pid);need(handle,'PORTABLE_OWNER_PROCESS')
    try:
        times=[W.FILETIME() for _ in range(4)];need(K.GetProcessTimes(handle,*[ctypes.byref(x) for x in times]),'PORTABLE_OWNER_START')
        return 'FILETIME:'+str((times[0].dwHighDateTime<<32)|times[0].dwLowDateTime)
    finally:K.CloseHandle(handle)

def _portable_profile(reference,root,incoming=None):
    env=os.environ if incoming is None else incoming
    profile=reference.get('execution',{}).get('portableProfile',{})
    need(profile.get('state')=='AUTHORIZED' and profile.get('id')=='sealed-actionlint-native-v1','PORTABLE_PROFILE_UNAPPROVED')
    need(profile.get('memoryMax')==MEMORY and profile.get('cpus')==CPUS and profile.get('tasksMax')==TASKS,'PORTABLE_PROFILE_LIMITS')
    need(not (root.parent/'state/operator-helpers/CURRENT-LANE-REFERENCE.json').exists(),'MANAGED_LOCAL_CANONICAL_REQUIRED')
    need(not env.get('ACTIONLINT_PHASE_TOKEN') and not env.get('ACTIONLINT_LEASE_PROTOCOL'),'PORTABLE_CANNOT_REPLACE_CANONICAL')
    return profile

def _portable_permission(reference,incoming):
    root=Path(__file__).resolve().parents[1];_portable_profile(reference,root,incoming)
    path=root/'artifacts/actionlint-local-phase.json';need(path.is_file() and not path.is_symlink() and path.stat().st_size<=65536,'PORTABLE_LEASE_MISSING')
    holder=json.loads(path.read_bytes());need(holder.get('randomToken')==incoming.get('ACTIONLINT_PORTABLE_PHASE_TOKEN') and holder.get('projectId')==reference['projectId'],'PORTABLE_FOREIGN_LEASE')
    need(holder.get('ownerProcessStartIdentity')==_start_identity(holder['ownerPID']) and holder.get('phase') in ('lint','prepare-sealed'),'PORTABLE_OWNER_IDENTITY')
    if os.name!='nt':need(linux_caps()['cgroup']==holder.get('cgroup'),'PORTABLE_NATIVE_MEMBERSHIP')
    return holder

@contextlib.contextmanager
def portable_phase(reference,root,phase):
    import uuid
    _portable_profile(reference,root);need(phase in ('lint','prepare-sealed'),'PORTABLE_PHASE')
    (root/'artifacts').mkdir(exist_ok=True);path=root/'artifacts/actionlint-local-phase.json'
    holder={'projectId':reference['projectId'],'randomToken':uuid.uuid4().hex,'ownerPID':os.getpid(),'ownerProcessStartIdentity':_start_identity(os.getpid()),'phase':phase}
    if os.name!='nt':holder['cgroup']=linux_caps()['cgroup']
    with open(path,'x',encoding='utf-8') as f:json.dump(holder,f)
    previous=os.environ.get('ACTIONLINT_PORTABLE_PHASE_TOKEN');os.environ['ACTIONLINT_PORTABLE_PHASE_TOKEN']=holder['randomToken']
    state={'started':False,'evidence':None}
    try:yield state
    finally:
        safe=not state['started']
        if state['evidence'] is not None:
            receipt=Path(state['evidence'])/'process.json'
            if receipt.is_file():
                record=json.loads(receipt.read_bytes());safe=record.get('actualCap',{}).get('activeProcessesAtTeardown')==0 if os.name=='nt' else type(record.get('exitCode')) is int and not record.get('timedOut')
        if previous is None:os.environ.pop('ACTIONLINT_PORTABLE_PHASE_TOKEN',None)
        else:os.environ['ACTIONLINT_PORTABLE_PHASE_TOKEN']=previous
        need(safe,'PORTABLE_TEARDOWN_UNKNOWN_LEASE_RETAINED');check_owner(json.loads(path.read_bytes()),holder);path.unlink()
