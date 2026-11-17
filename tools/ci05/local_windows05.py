"""Own05 local Windows compatibility route. No CI impersonation or SDK bootstrap."""
from pathlib import Path
import argparse,ctypes,datetime,hashlib,importlib.util,json,os,platform,subprocess,sys,time,uuid,winreg
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
CAPS_SHA='5d1091df16607fa23deff8ec1f22dc2cc87fd4f0b77d00e9993897ef5e231e6d'
COMMON_SHA='c37e2f48ee21ef1f02e4afb2bb1cd0af397781e487265c31e43fe06ea182befd'
class Hold(RuntimeError):pass

def need(v,m):
 if not v:raise Hold(m)

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def read(p):return json.loads(Path(p).read_bytes())

def write(p,v):
 raw=(json.dumps(v,indent=2)+'\n').encode();need(len(raw)<=1048576,'LOCAL_RECEIPT_BOUND')
 with Path(p).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

def load(p,name,expected):
 need(sha(p)==expected,'SOURCE_IDENTITY:'+name);s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m

def start_identity():
 from ctypes import wintypes as W
 k=ctypes.WinDLL('kernel32',use_last_error=True);k.GetCurrentProcess.restype=W.HANDLE;k.GetProcessTimes.argtypes=[W.HANDLE,*([ctypes.POINTER(W.FILETIME)]*4)];a,b,c,d=(W.FILETIME() for _ in range(4));need(k.GetProcessTimes(k.GetCurrentProcess(),ctypes.byref(a),ctypes.byref(b),ctypes.byref(c),ctypes.byref(d)),'CURRENT_START');return 'FILETIME:'+str((a.dwHighDateTime<<32)|a.dwLowDateTime)

def host():
 need(os.name=='nt' and platform.machine().lower() in ('amd64','x86_64'),'LOCAL_WINDOWS_X64');need(not any(os.environ.get(k) for k in ('GITHUB_ACTIONS','GITHUB_RUN_ID','RUNNER_ENVIRONMENT')),'NO_CI_CONTEXT')
 version=sys.getwindowsversion();need(version.product_type==1 and version.build==26300,'PINNED_LOCAL_CLIENT_HOST')
 with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion') as k:
  record={n:winreg.QueryValueEx(k,n)[0] for n in ('ProductName','DisplayVersion','CurrentBuildNumber','UBR','EditionID')}
 need(record['DisplayVersion']=='26H2' and record['CurrentBuildNumber']=='26300','LOCAL_OS_IDENTITY');return dict(record,kind='Own05LocalWindows11WorkstationX64',productType=1,architecture='x64',CI=False,vendorSupportBoundary='Observed local compatibility only; .NET11 explicit OS table dated2026-09-28 omits26H2. No vendor certification or GitHub/Server2025 attribution.')

def git(*args):return subprocess.check_output(['git','--no-optional-locks','-C',str(ROOT),*args],timeout=10).decode().strip()

def worker(specpath,digest):
 need(sha(specpath)==digest,'SPEC_IDENTITY');s=read(specpath);out=Path(s['out']);need(sha(__file__)==s['controllerSHA256'],'CONTROLLER_SOURCE');control=load(HERE/'bounded_windows05.py','own05_local_caps',CAPS_SHA);actual=control.inspect_current_job();before=read(out/'outer/caps-before-resume.json');need(before['childPID']==os.getpid() and before['childMembershipBeforeResume'],'OWN_HELD_BEFORE_SDK');control.CI_INHERITED_CPU=True
 current=host();need(current==s['host'] and git('rev-parse','HEAD')==s['HEAD'] and not git('status','--porcelain=v1'),'CURRENT_HOST_SOURCE');write(out/'own-current-caps.json',dict(actual,sourceCommit=s['HEAD'],controllerSHA256=s['controllerSHA256'],phase=s['phase'],host=current,workerStartIdentity=start_identity(),supervisorPID=s['supervisorPID'],supervisorStartIdentity=s['supervisorStartIdentity'],producerOrOtherConsumerCapsBorrowed=False))
 common=load(Path(s['sharedTools'])/'check_dotnet11.py','producer04_local_data_only',COMMON_SHA);native=common._load('normal_windows_input',common.PINS['windowsNormalHelperSha256']);cpu=native.measure_cpu(common,out)
 catalog,fact,schema=common._documents('win-x64');sdk=Path(s['sdk']);need(sdk.is_dir() and not sdk.is_symlink(),'EXISTING_SDK_ONLY');common.verify_tree(sdk,catalog['members'],'win-x64',full=True);write(out/'sdk-input.json',{'SDKPath':str(sdk),'memberManifestSHA256':catalog['memberManifestSha256'],'producerQualifiedOn':fact['qualifiedOn'],'scope':'Historical producer input bytes only; own current caps/host separately observed. No SDK download/copy or common qualification replay.','cpu':cpu})
 home=out/'home';home.mkdir();env={k:v for k,v in os.environ.items() if not k.startswith(('DOTNET_','COMPlus_','NUGET_')) and k not in ('GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN','MSBuildSDKsPath','MSBUILD_EXE_PATH')};env.update(DOTNET_ROOT=str(sdk),DOTNET_HOST_PATH=str(sdk/'dotnet.exe'),DOTNET_CLI_HOME=str(home),DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',DOTNET_EnableDiagnostics='0',DOTNET_NOLOGO='1',DOTNET_PROCESSOR_COUNT='1',MSBUILDDISABLENODEREUSE='1',DOTNET_CLI_USE_MSBUILD_SERVER='0',TESTINGPLATFORM_TELEMETRY_OPTOUT='1')
 if s['phase']=='inputs':
  native_phase=load(HERE/'local_native05.py','own05_local_native','0e3173463ac6bf762d89e9b8c18835b5237529e1d3015da5b7c36ae42b898aeb');native_phase.run(sys.modules[__name__],s,out,sdk,env,control,common,catalog);return
 if s['phase']=='curate':
  managed=load(HERE/'local_managed05.py','own05_local_managed','c48a1705713bd1e01bceb1ca305dabaa3e749fc6b5f73d936540ca2541869f9e');managed.run(sys.modules[__name__],s,out,sdk,env,control,common,catalog);return
 rows=[]
 for project in ('src/Reference.Core/Reference.Core.csproj','src/Reference.Cli/Reference.Cli.csproj','tests/Reference.Tests/Reference.Tests.csproj'):
  contexts=('win-x64','linux-x64') if '/tests/' not in '/'+project else ('framework-dependent',)
  for rid in contexts:
   argv=[str(sdk/'dotnet.exe'),'msbuild',project,'-nologo','-getProperty:TargetFramework,RuntimeIdentifier,RuntimeIdentifiers,RuntimeFrameworkVersion,SelfContained,UseAppHost,NuGetAudit,NuGetAuditMode','-getItem:PackageReference,FrameworkReference,ProjectReference,PackageDownload']
   if rid!='framework-dependent':argv+=['-p:RuntimeIdentifier='+rid,'-p:SelfContained=true']
   name=Path(project).stem+'-'+rid;left=(s['deadlineMonotonicNs']-time.monotonic_ns())/1e9-20;need(left>0,'ORIGINAL_PHASE_DEADLINE');common.verify_tree(sdk,catalog['members'],'win-x64');rec=control.run(argv,cwd=ROOT,env=env,timeout=min(30,left),evidence=out/name);rows.append({'project':project,'rid':rid,'processReceiptSHA256':sha(out/name/'process.json')})
 common.verify_tree(sdk,catalog['members'],'win-x64',full=True);write(out/'RESULT.json',{'state':'OWN05_LOCAL_HOST_CAPS_AND_NET11_PROJECT_GRAPH_OBSERVED','host':current,'caps':actual,'sourceCommit':s['HEAD'],'controllerSHA256':s['controllerSHA256'],'commands':rows,'SDKGlobalReadiness':False,'otherConsumerAdmission':False,'inputLocksOrProductTestsQualified':False,'Actions':0})

def claim_when_available(lease,holder,seconds=600):
 # Resource queue uses retained OS process handles, never chat/status polling.
 from ctypes import wintypes as W
 k=ctypes.WinDLL('kernel32',use_last_error=True);k.OpenProcess.argtypes=[W.DWORD,W.BOOL,W.DWORD];k.OpenProcess.restype=W.HANDLE;k.GetProcessTimes.argtypes=[W.HANDLE,*([ctypes.POINTER(W.FILETIME)]*4)];k.WaitForSingleObject.argtypes=[W.HANDLE,W.DWORD];k.CloseHandle.argtypes=[W.HANDLE];end=time.monotonic()+seconds;events=[]
 while True:
  try:
   with lease.open('x') as f:json.dump(holder,f);f.flush();os.fsync(f.fileno());inode=os.fstat(f.fileno()).st_ino
   return inode,events
  except FileExistsError:pass
  need(time.monotonic()<end,'RESOURCE_QUEUE_WAIT_EXPIRED')
  try:foreign=read(lease)
  except FileNotFoundError:continue
  need(str(foreign.get('ownerOS')).lower() in ('nt','windows'),'FOREIGN_NONWINDOWS_LANE_WAIT_REQUIRES_EXISTING_GUEST_METHOD');pid=foreign['ownerPID'];h=k.OpenProcess(0x100000|0x1000,False,pid);need(h,'FOREIGN_LANE_OWNER_NOT_INSPECTABLE_NO_RESET')
  try:
   a,b,c,d=(W.FILETIME() for _ in range(4));need(k.GetProcessTimes(h,ctypes.byref(a),ctypes.byref(b),ctypes.byref(c),ctypes.byref(d)),'FOREIGN_OWNER_START_READ');identity=str((a.dwHighDateTime<<32)|a.dwLowDateTime);need(identity==str(foreign['ownerProcessStartIdentity']).removeprefix('FILETIME:'),'FOREIGN_OWNER_PID_REUSE')
   while True:
    left=end-time.monotonic();need(left>0,'RESOURCE_QUEUE_WAIT_EXPIRED');code=k.WaitForSingleObject(h,min(45000,max(1,int(left*1000))));need(code in (0,258),'FOREIGN_OWNER_HANDLE_WAIT')
    if code==0:break
   events.append({'projectId':foreign['projectId'],'phase':foreign['phase'],'pid':pid,'startIdentity':identity,'terminalHandleObserved':True});need(len(events)<=32,'RESOURCE_QUEUE_EVENT_BOUND')
  finally:k.CloseHandle(h)

def parent(args):
 need(args.phase in ('graph','curate','inputs'),'FIXED_PHASE');out=Path(args.out).resolve();need(out.is_relative_to(ROOT.parents[1]/'outputs') and not out.exists(),'OWN_FRESH_OUTPUT');out.mkdir(parents=True);control=load(HERE/'bounded_windows05.py','own05_local_parent_caps',CAPS_SHA);h=host();head=git('rev-parse','HEAD');need(not git('status','--porcelain=v1'),'CLEAN_CURRENT_SOURCE')
 lease=ROOT.parents[2]/'portfolio-management/development-management-20261110/wave2-state/LOCAL-FIXTURE-LEASE.json';token=uuid.uuid4().hex;identity=start_identity();holder={'projectId':'05','randomToken':token,'ownerOS':'Windows','ownerPID':os.getpid(),'ownerProcessStartIdentity':identity,'phase':'own05-local-'+args.phase,'receiptDirectory':str(out)}
 inode,queueEvents=claim_when_available(lease,holder);write(out/'resource-queue.json',{'events':queueEvents,'acquiredByExactOwner':holder,'scope':'Wait before original own row clock; no other owner reset or process termination.'})
 s={'phase':args.phase,'out':str(out),'sdk':str(Path(args.sdk).resolve()),'sharedTools':str(Path(args.shared_tools).resolve()),'host':h,'HEAD':head,'controllerSHA256':sha(__file__),'supervisorPID':os.getpid(),'supervisorStartIdentity':identity,'rowStartedMonotonicNs':time.monotonic_ns()};s['deadlineMonotonicNs']=s['rowStartedMonotonicNs']+1200*10**9;sp=out/'context.json';write(sp,s);failure=None;terminal=False
 try:control.run([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--worker',str(sp),sha(sp)],cwd=ROOT,env=os.environ.copy(),timeout=1180,evidence=out/'outer')
 except BaseException as e:failure=type(e).__name__+':'+str(e)[:700]
 finally:
  proof=out/'outer/held-handle-terminal.json';terminal=proof.exists() and read(proof).get('teardownVerified') is True;write(out/'TERMINAL.json',{'ownedTerminalKnown':terminal,'failure':failure,'phaseResultExists':(out/'RESULT.json').exists(),'CI':'not run by owner instruction'})
  if terminal:
   need(read(lease)==holder and lease.stat().st_ino==inode and start_identity()==identity,'EXACT_LEASE_RELEASE');lease.unlink();write(out/'LEASE-RELEASED.json',{'exactOwnerReleased':True,'ownedWorkerTerminal':True})
 need(terminal and failure is None and (out/'RESULT.json').exists(),'LOCAL_PHASE_HOLD:'+str(failure));print(json.dumps({'state':'LOCAL05_PHASE_COMPLETE','phase':args.phase,'out':str(out),'HEAD':head}))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--phase',choices=['graph','curate','inputs']);p.add_argument('--out');p.add_argument('--sdk');p.add_argument('--shared-tools');p.add_argument('--worker',nargs=2);a=p.parse_args()
 if a.worker:worker(a.worker[0],a.worker[1])
 else:parent(a)
