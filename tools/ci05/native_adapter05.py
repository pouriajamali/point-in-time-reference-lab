"""Fixed own project05 runtime boundary; inert until exact host/input/control admission."""
from pathlib import Path
import ctypes,hashlib,importlib.util,json,os,platform,select,signal,socket,struct,subprocess,sys,time,uuid,xml.etree.ElementTree as ET
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
class Hold(RuntimeError):pass
def need(v,m):
 if not v:raise Hold(m)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):
 p=Path(p);need(p.is_file() and p.stat().st_size<=8*1024*1024 and not p.is_symlink(),'INPUT_CAP');return json.loads(p.read_bytes())
def durable(p,data):
 raw=(json.dumps(data,indent=2)+chr(10)).encode();need(len(raw)<=8192,'RECEIPT_CAP')
 with Path(p).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def load(name):
 admission=read(HERE/'manager-admission.json');p=HERE/(name+'.py');need(p.is_file() and sha(p)==admission['sourceHashes'][name+'.py'],'CONTROL_SOURCE_PIN');s=importlib.util.spec_from_file_location('pit05_'+name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def parent_start():
 if os.name!='nt':return 'proc-start:'+Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
 from ctypes import wintypes as W
 k=ctypes.WinDLL('kernel32',use_last_error=True);k.GetCurrentProcess.restype=W.HANDLE;k.GetProcessTimes.argtypes=[W.HANDLE,*([ctypes.POINTER(W.FILETIME)]*4)];a,b,c,d=(W.FILETIME() for _ in range(4));need(k.GetProcessTimes(k.GetCurrentProcess(),ctypes.byref(a),ctypes.byref(b),ctypes.byref(c),ctypes.byref(d)),'OWN_START_IDENTITY');return 'FILETIME:'+str((a.dwHighDateTime<<32)|a.dwLowDateTime)
def disk_bytes(roots):
 total=0;count=0
 for root in roots:
  if not Path(root).exists():continue
  for directory,dirs,files in os.walk(root,followlinks=False):
   for n in files:
    p=Path(directory)/n;count+=1;need(count<=64000,'PRIVATE_OUTPUT_COUNT_CAP');total+=p.lstat().st_size
 return total

def worker_entry(specpath,specsha):
 need(sha(specpath)==specsha,'OWN_SPEC_IDENTITY');spec=read(specpath);ctx=spec['ctx'];out=Path(spec['out']);profile=read(HERE/'profile.json');source=spec['source'];row=spec['row'];admission=read(HERE/'manager-admission.json')
 need(admission['state']=='EXACT_CANDIDATE_HOST_CONTROL_ADMITTED' and Path.cwd()==ROOT,'OWN_WORKER_SOURCE_ROOT')
 need(ctx['rid']=='linux-x64' and os.name=='posix' and os.getuid()==ctx['uid']>0 and os.getgid()==ctx['gid']>0,'OWN_LINUX_NONROOT_REQUIRED_WINDOWS_DENIED')
 need(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_RUN_ID')==ctx['runId'] and os.environ.get('GITHUB_RUN_ATTEMPT')==ctx['attempt'] and os.environ.get('GITHUB_JOB')==ctx['job']=='verify','WORKER_CURRENT_CI_CONTEXT')
 need(all(sha(HERE/n)==h for n,h in source['controllerHashes'].items()),'OWN_WORKER_CONTROL_IDENTITIES')
 guard=load('host_fact05');control=load('bounded_linux_ci05');control.CONTROL_UNIT=ctx['unit'];actual=control.linux_caps()
 # Worker is actually stopped before supervisor records evidence and releases it.
 sock=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);sock.settimeout(min(20,spec['remaining']));sock.connect(str(out/'control.sock'));sock.sendall(json.dumps({'pid':os.getpid(),'start':parent_start(),'unit':ctx['unit']}).encode());os.kill(os.getpid(),signal.SIGSTOP);need(sock.recv(32)==b'GO','HELD_WORKER_GO_REQUIRED');sock.close()
 evidence=read(out/'own-normal-caps.json');before=evidence['beforeExec'];need(before['pid']==os.getpid() and before['processStartIdentity']==parent_start() and before['state']=='T' and before['retainedStartHandle'] and before['membershipBeforeRelease'],'ACTUAL_STOPPED_IDENTITY')
 caps={'uid':os.getuid(),'gid':os.getgid(),'memoryMax':4294967296,'cpuCores':1,'tasksMax':64,'swapMax':0,'runId':ctx['runId'],'jobId':ctx['jobId'],'sourceHashes':source['controllerHashes'],'heldChildMembershipBeforeResume':True};guard.own_caps(caps,ctx,source,(ctx['deadlineMonotonicNs']-time.monotonic_ns())/10**9,profile)
 durable(out/'own-current-control.json',{'ctx':ctx,'caps':caps,'actual':actual,'producerProofBorrowed':False});schema=read(ROOT/'tools/dotnet11-host-qualification.schema.json');admission_path=out/'consumer-host-handshake.json';durable(admission_path,guard.handshake(row,spec['identity'],sha(out/'own-normal-caps.json'),schema))
 deadline=ctx['deadlineMonotonicNs']/10**9-profile['stageSeconds']['terminalExistingUpload'];result={'targetGroupsTerminalKnown':False,'exitCode':1,'sdkCalls':0}
 try:
  control.run([sys.executable,'-I','-S','-B','-c','import os; print("PROJECT05_OWN_NATIVE_CONTROL_MARKER",os.getpid())'],cwd=ROOT,env=os.environ.copy(),timeout=min(30,max(.1,deadline-time.monotonic())),evidence=out/'own-native-child')
  if spec['phase']=='control-probe':result.update(targetGroupsTerminalKnown=True,exitCode=0);return
  # Existing 30+3 boundary modes remain required; this source integration does not replay them now.
  sdk0env={k:v for k,v in os.environ.items() if k not in ('PYTHONPATH','PYTHONHOME','PYTHONSTARTUP','PYTHONOPTIMIZE','GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN')};sdk0_deadline=min(deadline,time.monotonic()+90);control.LOG_MAX=1048576
  try:
   for mode,flags,optimize in (('normal',[],None),('O',['-O'],None),('env2',[],'2')):
    need(sdk0_deadline-time.monotonic()>10,'SDK0_AGGREGATE90_EXHAUSTED');modeenv=dict(sdk0env)
    if optimize:modeenv['PYTHONOPTIMIZE']=optimize
    destination=out/('sdk0-'+mode);control.run([sys.executable,'-S','-B',*flags,str(HERE/'sdk0_boundary05.py'),'--out',str(destination)],cwd=ROOT,env=modeenv,timeout=min(30,sdk0_deadline-time.monotonic()-10),evidence=out/('sdk0-process-'+mode));r=read(destination/'receipt.json');need(r['rejections']==30 and r['identityOnlyPositives']==3 and r['sdkSpawns']==0 and r['modeOptimize']==(2 if optimize else 1 if flags else 0),'ORIGINAL_SDK0_BOUNDARIES')
  finally:control.LOG_MAX=16777216
  binding=load('normal_binding05');entered=time.monotonic();prior_timer=signal.getitimer(signal.ITIMER_REAL);prior_handler=signal.getsignal(signal.SIGALRM);need(prior_timer[1]==0,'OWN_PERIODIC_TIMER_FORBIDDEN');prior_end=entered+prior_timer[0] if prior_timer[0]>0 else None
  input_end=min(deadline,entered+profile['stageSeconds']['admittedAcquisition']+profile['stageSeconds']['materialization']);input_end=min(input_end,prior_end) if prior_end else input_end;need(input_end>entered,'OWN_INPUT_DEADLINE')
  def input_expired(*_):raise Hold('OWN_ORIGINAL_ROW_INPUT_RESERVATION_EXHAUSTED')
  signal.signal(signal.SIGALRM,input_expired);signal.setitimer(signal.ITIMER_REAL,input_end-time.monotonic())
  try:sdk,receipt,module,normalctx=binding.transport_input(spec,evidence,out/'own-normal-caps.json',admission_path)
  finally:
   signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,prior_handler)
   if prior_end:
    need(prior_end>time.monotonic(),'OWN_PRIOR_TIMER_EXHAUSTED');signal.setitimer(signal.ITIMER_REAL,prior_end-time.monotonic())
  # Shared receipt is bounded1MiB data; it grants no SDK execution by itself.
  raw=json.dumps(receipt,separators=(',',':')).encode();need(len(raw)<=1048576,'COMMON_RECEIPT_BOUND')
  with (out/'shared-normal-input.json').open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  need(read(HERE/'manager-admission.json').get('productInputsSealed') is True,'ACTUAL_NATIVE_PACK_LOCK_NOTICE_SIGNATURE_GATE')
  entry=sdk/'dotnet';product_recipe_continuation(spec,ctx,source,profile,control,sdk,entry,deadline,result,module,normalctx)
 except BaseException as e:result.update(errorType=type(e).__name__,reason=str(e)[:1024]);raise
 finally:durable(out/'worker-terminal.json',result)


def fixed_project05_route(ctx,source,row,identity,profile,recipes,phase,worker_args):
 if worker_args:worker_entry(Path(worker_args[0]),worker_args[1]);return
 need(ctx['rid']=='linux-x64' and phase in ('control-probe','verify-product'),'WINDOWS_NORMAL_DENIED_FIXED_PHASE')
 temp=Path(ctx['runnerTemp']).resolve();nonce=uuid.uuid4().hex;scratch=temp/('pit05-'+nonce);need(not scratch.exists(),'FRESH0700_PRIVATE_ROOT');scratch.mkdir(mode=0o700);out=scratch/'proof';out.mkdir(mode=0o700)
 lease=out/'job-phase.lock';identity_start=parent_start();holder={'projectId':'05','token':nonce,'pid':os.getpid(),'start':identity_start}
 with lease.open('x') as f:json.dump(holder,f);f.flush();os.fsync(f.fileno());inode=os.fstat(f.fileno()).st_ino
 deadline=ctx['deadlineMonotonicNs']/10**9;remaining=(ctx['deadlineMonotonicNs']-time.monotonic_ns())/10**9;need(0<remaining<=1200 and remaining>60,'ORIGINAL_ROW_ENVELOPE');ctx.update(unit='pit05-ci-'+ctx['runId']+'-'+ctx['attempt']+'-'+nonce[:16]+'.service',nonce=nonce[:16])
 spec={'ctx':ctx,'source':source,'row':row,'identity':identity,'scratch':str(scratch),'out':str(out),'phase':phase,'remaining':remaining,'supervisorPID':os.getpid(),'supervisorStartIdentity':identity_start,'normalDirectory':str(temp/('sdk11-normal-05-'+nonce))};terminal=False;failure=None;held=None;server=None
 try:
  need(hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'),'OWN_RETAINED_PIDFD_REQUIRED');starter=load('ci_root_starter05');sp=scratch/'spec.json';durable(sp,spec)
  server=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);server.bind(str(out/'control.sock'));server.listen(1);server.settimeout(min(45,max(.1,deadline-time.monotonic()-60)))
  argv=starter.start_argv(ctx,HERE/'ci_route05.py',sp,deadline-60);started=subprocess.run(argv,capture_output=True,text=True,timeout=min(10,deadline-time.monotonic()-60));durable(out/'root-starter.json',{'argv':argv,'exit':started.returncode,'stdout':started.stdout[:1024],'stderr':started.stderr[:1024],'rootSDKOrProduct':False});need(started.returncode==0,'OWN_OS_STARTER_FAILED')
  conn,_=server.accept()
  with conn:
   conn.settimeout(min(10,deadline-time.monotonic()-60));pid,uid,gid=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));ready=json.loads(conn.recv(8192));need(pid==ready['pid'] and (uid,gid)==(ctx['uid'],ctx['gid']),'OWN_PEER_UID_PID');held=os.pidfd_open(pid)
   stopdeadline=min(deadline-60,time.monotonic()+5)
   while True:
    text=Path('/proc',str(pid),'stat').read_text();tail=text[text.rfind(')')+2:].split();state=tail[0];start='proc-start:'+tail[19]
    need(start==ready['start'],'HELD_START_IDENTITY')
    if state in ('T','t'):break
    need(time.monotonic()<stopdeadline,'ACTUAL_WORKER_STOP_NOT_OBSERVED');time.sleep(.02)
   status=dict(x.split(':',1) for x in Path('/proc',str(pid),'status').read_text().splitlines() if ':' in x);need(all(int(v)==ctx['uid'] for v in status['Uid'].split()) and all(int(v)==ctx['gid'] for v in status['Gid'].split()),'ACTUAL_HELD_UID_GID')
   observed=starter.query(ctx,deadline-60);need(observed.get('MainPID')==str(pid) and observed.get('ControlPID')=='0','ACTUAL_MAINPID');rel='/system.slice/'+ctx['unit'];need('0::'+rel in Path('/proc',str(pid),'cgroup').read_text().splitlines(),'ACTUAL_HELD_CGROUP');group=Path('/sys/fs/cgroup')/rel.lstrip('/');limits={k:(group/k).read_text().strip() for k in ('memory.max','memory.swap.max','pids.max','cpu.max')};need(limits=={'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'100000 100000'},'ACTUAL_OWN05_HELD_CAPS')
   need(Path('/proc',str(pid),'exe').resolve()==Path(sys.executable).resolve(),'ACTUAL_WORKER_PYTHON_BOOTSTRAP')
   before={'pid':pid,'processStartIdentity':start,'cgroup':rel,'kernelLimits':limits,'state':'T','membershipBeforeRelease':True,'retainedStartHandle':True};worker={'pid':pid,'processStartIdentity':start,'uid':uid,'gid':gid,'cgroup':rel,'kernelLimits':limits}
   evidence={'schema':'sdk11-own-current-cap-evidence/v1','projectId':'05','repository':'pouriajamali/point-in-time-reference-lab','sourceCommit':source['head'],'sourceTree':source['tree'],'profileSha256':sha(HERE/'normal-profile.json'),'controllerSha256':sha(HERE/'ci_route05.py'),'worker':worker,'beforeExec':before,'supervisor':{'pid':os.getpid(),'processStartIdentity':identity_start,'deadlineMonotonicNs':ctx['deadlineMonotonicNs']},'rowStartedMonotonicNs':ctx['rowStartedMonotonicNs'],'deadlineMonotonicNs':ctx['deadlineMonotonicNs'],'bootstrap':{'pythonVersion':platform.python_version(),'pythonExeSha256':sha(Path(sys.executable).resolve()),'gitSha256':sha('/usr/bin/git'),'systemctlSha256':sha('/usr/bin/systemctl')}}
   # fsync the real T-state/pidfd/membership evidence BEFORE releasing current worker.
   durable(out/'own-normal-caps.json',evidence);durable(out/'held-worker-before-targets.json',{'pid':pid,'start':start,'state':'T','capsEvidenceSha256':sha(out/'own-normal-caps.json'),'pidfdHeld':True});conn.sendall(b'GO');signal.pidfd_send_signal(held,signal.SIGCONT)
  roots=[scratch,Path(spec['normalDirectory']),ROOT/'artifacts',ROOT/'src/Reference.Core/obj',ROOT/'src/Reference.Cli/obj',ROOT/'tests/Reference.Tests/obj']
  while not select.select([held],[],[],min(1,max(0,deadline-time.monotonic()-60)))[0]:need(time.monotonic()<deadline-60 and disk_bytes(roots)<=profile['caps']['scratchMax'],'OWN_DEADLINE_OR_DISK_HOLD')
  starter.terminal_before_retire(ctx,group,out,deadline);terminal=True;result=read(out/'worker-terminal.json');need(result.get('exitCode')==0 and result.get('targetGroupsTerminalKnown') is True,'OWN_WORKER_FAILED')
 except BaseException as e:failure=type(e).__name__+':'+str(e)[:512];raise
 finally:
  if server is not None:server.close()
  if not terminal:
   durable(out/'terminal-unknown.json',{'terminalKnown':False,'unit':ctx['unit'],'uploadAllowed':False})
   if deadline>time.monotonic():
    try:subprocess.run(['/usr/bin/sudo','-n','/usr/bin/systemctl','stop',ctx['unit']],capture_output=True,timeout=min(5,deadline-time.monotonic()))
    except (OSError,subprocess.TimeoutExpired):pass
  # Unknown retains held pidfd/custody through this durable checkpoint and lease.
  checkpoint=out/'consumer-terminal-checkpoint.json';durable(checkpoint,{'terminalKnown':terminal,'qualifiedOn':identity['qualifiedOn'],'currentConsumer':identity['currentConsumer'],'apiJobId':ctx['jobId'],'phaseLeaseReleased':False,'failure':failure})
  if terminal:
   need(read(lease)==holder and parent_start()==identity_start and lease.stat().st_ino==inode,'EXACT_OWN_TOKEN_START_INODE');lease.unlink();durable(out/'phase-release-marker.json',{'released':True,'token':nonce,'terminalCheckpointSha256':sha(checkpoint)})
   if held is not None:os.close(held)
 need(terminal,'OWN_TERMINAL_UNKNOWN');proof=ROOT/'artifacts/ci-route'/phase;proof.mkdir(parents=True,exist_ok=False)
 import shutil
 for name in ('consumer-terminal-checkpoint.json','phase-release-marker.json','worker-terminal.json','own-current-control.json','own-normal-caps.json','consumer-host-handshake.json'):
  if (out/name).exists():shutil.copyfile(out/name,proof/name)



def product_recipe_continuation(spec,ctx,source,profile,control,sdk,entry,deadline,result,module,normalctx):
 # Exact manager/product input gate and common full input identity precede SDK.
 need(read(HERE/'manager-admission.json').get('productInputsSealed') is True,'PRODUCT_INPUTS_NOT_SEALED')
 out=Path(spec['out']);home=Path(spec['scratch'])/'home';home.mkdir();packages=Path(spec['scratch'])/'packages';packages.mkdir();env=os.environ.copy()
 for k in list(env):
  if k.startswith(('DOTNET_','COMPlus_','NUGET_')) or k in ('GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN','LD_PRELOAD','LD_LIBRARY_PATH','MSBuildSDKsPath','MSBUILD_EXE_PATH'):env.pop(k,None)
 env.update(DOTNET_ROOT=str(sdk),DOTNET_CLI_HOME=str(home),NUGET_PACKAGES=str(packages),PATH=str(sdk)+os.pathsep+env.get('PATH',''),DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_GENERATE_ASPNET_CERTIFICATE='false',MSBUILDDISABLENODEREUSE='1',DOTNET_CLI_USE_MSBUILD_SERVER='0',UseSharedCompilation='false',DOTNET_PROCESSOR_COUNT='1')
 (ROOT/'artifacts').mkdir(exist_ok=True)
 rid=ctx['rid'];ext='.zip' if rid=='win-x64' else '.tar.gz';archive=ROOT/'artifacts/delivery'/('point-in-time-reference-lab-v0.1.0-preview.4-'+rid+ext);package=ROOT/'artifacts/extracted with spaces'/('point-in-time-reference-lab-v0.1.0-preview.4-'+rid);values={'$SDK':str(entry),'$PYTHON':sys.executable,'$RID':rid,'$SOURCE_SHA':source['head'],'$ARCHIVE':str(archive),'$PACKAGE':str(package),'$CLI':str(package/('reference.exe' if rid=='win-x64' else 'reference')),'$PACKAGED_BOUNDARY':str(package/'tools/knowledge_boundary.py')}
 route=load('ci_route05');recipes=read(HERE/'product-recipes.json');product_deadline=min(deadline,time.monotonic()+profile['stageSeconds']['productAggregate'])
 for name,limit,argv in route.product_argv(recipes,values,rid):
  need(disk_bytes([spec['scratch'],spec['normalDirectory'],ROOT/'artifacts',ROOT/'src/Reference.Core/obj',ROOT/'src/Reference.Cli/obj',ROOT/'tests/Reference.Tests/obj'])<=profile['caps']['scratchMax'],'OUTPUT_DISK_CAP')
  left=min(limit,product_deadline-time.monotonic());need(left>0,'PRODUCT_AGGREGATE_ENVELOPE');control.run(argv,cwd=ROOT,env=env,timeout=left,evidence=out/name);result['sdkCalls']+=int(argv[0]==str(entry))
 module.inspect_sdk(ctx['rid'],sdk,normalctx);tests=ET.parse(ROOT/'artifacts/unit.xml').findall('.//test');need(len(tests)==51 and all(t.attrib.get('result')=='Pass' for t in tests),'51_UNITS_NO_SKIP');need(read(ROOT/'artifacts/package-checks.json')['checkCount']==8,'8_PACKAGE_CHECKS');result.update(targetGroupsTerminalKnown=True,exitCode=0)
