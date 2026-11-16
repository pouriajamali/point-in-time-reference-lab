"""Portable data-only SDK11 transport/identity guard; never executes the downloaded SDK."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,re,stat,struct,tarfile,time,unicodedata,urllib.request,zipfile
from pathlib import Path,PurePosixPath
RAW_MAX=512*1024**2;EXPANDED_MAX=4*1024**3;MEMBER_MAX=256*1024**2;COUNT_MAX=64000
ROOT=Path(__file__).resolve().parents[1]
LOCK=ROOT/'tools/dotnet11-inputs.lock.json'
INPUTS={'win-x64': {'url': 'https://builds.dotnet.microsoft.com/dotnet/Sdk/11.0.100/dotnet-sdk-11.0.100-win-x64.zip', 'sha512': '5cdd9122c84873f090038548ebe8a4786e5c50a6b1b9792ca2c6dab82fd74a0d7f1d6cdf59e7dcd25e4903dd44f37af5d7ed73ecd3bca4d0cce948b5572452c3'}, 'linux-x64': {'url': 'https://builds.dotnet.microsoft.com/dotnet/Sdk/11.0.100/dotnet-sdk-11.0.100-linux-x64.tar.gz', 'sha512': '1bec9cca2ec689b1e80245b84f2b53c9441d1aa6daccf2ceb27490768bffa95954fa585bd275def31069d874d543d9ba9e6591fe9ade2dbd9f34ec5c0fd0050c'}}
class AdmissionError(RuntimeError):pass

def need(value,reason):
 if not value:raise AdmissionError(reason)

def digest(path,algorithm='sha256'):
 with Path(path).open('rb') as f:return hashlib.file_digest(f,algorithm).hexdigest()

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')

def member_path(name):
 need(isinstance(name,str) and len(name.encode('utf-8'))<=4096 and not any(ord(c)<32 or ord(c)==127 for c in name),'ARCHIVE_PATH_INVALID')
 need('\\' not in name and ':' not in name and not name.startswith('/') and unicodedata.normalize('NFC',name)==name,'ARCHIVE_PATH_INVALID')
 # A typed leading ./ and root directory entry are canonical TAR syntax, not traversal.
 if name.startswith('./'):name=name[2:]
 name=name.rstrip('/')
 if name in ('','.'):return ''
 parts=name.split('/');need(all(p not in ('','..','.') and not p.endswith((' ','.')) for p in parts),'ARCHIVE_PATH_INVALID')
 need(all(p.split('.')[0].upper() not in {'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]} for p in parts),'ARCHIVE_PATH_INVALID')
 need(not PurePosixPath(name).is_absolute(),'ARCHIVE_PATH_INVALID');return name

class Inventory:
 def __init__(self):self.seen={};self.members=[];self.total=0
 def add(self,name,size,kind,mode):
  need(kind in ('file','directory'),'ARCHIVE_SPECIAL_UNSUPPORTED');p=member_path(name)
  need(type(size) is int and 0<=size<=MEMBER_MAX and not(mode&0o7000),'ARCHIVE_LIMIT_EXCEEDED')
  if not p:
   need(kind=='directory' and size==0,'ARCHIVE_PATH_INVALID');need('' not in self.seen,'ARCHIVE_DUPLICATE_MEMBER');self.seen['']='directory'
   row={'path':'','type':'directory','bytes':0,'mode':mode&0o777};self.members.append(row);return row
  key=p.casefold();need(key not in self.seen,'ARCHIVE_DUPLICATE_MEMBER')
  for parent in PurePosixPath(p).parents:
   k=str(parent).casefold()
   if k!='.':need(self.seen.get(k)!='file','ARCHIVE_DUPLICATE_MEMBER')
  if kind=='file':need(not any(k.startswith(key+'/') for k in self.seen),'ARCHIVE_DUPLICATE_MEMBER')
  self.seen[key]=kind;self.total+=size;need(len(self.seen)<=COUNT_MAX and self.total<=EXPANDED_MAX,'ARCHIVE_LIMIT_EXCEEDED')
  row={'path':p,'type':kind,'bytes':size,'mode':mode&0o777};self.members.append(row);return row

def extract_members(archive,destination,rid):
 """Synthetic guard harness may call this parser; production requires extract_sdk raw admission first."""
 need(rid in INPUTS,'INPUT_IDENTITY_MISMATCH');dest=Path(destination);need(not dest.exists(),'OUTPUT_SCOPE_INVALID');dest.mkdir(parents=True)
 inv=Inventory();start=time.monotonic()
 def materialize(row,stream):
  if row is None:return
  p=dest/row['path'];need(p.resolve(strict=False).is_relative_to(dest.resolve()),'ARCHIVE_PATH_INVALID')
  if row['type']=='directory':p.mkdir(parents=True,exist_ok=True);return
  p.parent.mkdir(parents=True,exist_ok=True);h=hashlib.sha256();size=0
  with p.open('xb') as out:
   while True:
    need(time.monotonic()-start<=300,'ARCHIVE_LIMIT_EXCEEDED');data=stream.read(min(1024**2,row['bytes']-size+1))
    if not data:break
    size+=len(data);need(size<=row['bytes'],'ARCHIVE_LIMIT_EXCEEDED');out.write(data);h.update(data)
  need(size==row['bytes'],'ARCHIVE_LIMIT_EXCEEDED');row['sha256']=h.hexdigest()
  if os.name!='nt':p.chmod(row['mode'])
 if rid=='win-x64':
  with zipfile.ZipFile(archive) as z:
   need(len(z.infolist())<=COUNT_MAX,'ARCHIVE_LIMIT_EXCEEDED')
   for x in z.infolist():
    mode=x.external_attr>>16;kind=stat.S_IFMT(mode);need(not(x.flag_bits&1),'ARCHIVE_SPECIAL_UNSUPPORTED')
    need(kind!=stat.S_IFLNK,'ARCHIVE_LINK_UNSUPPORTED');need(kind in (0,stat.S_IFREG,stat.S_IFDIR),'ARCHIVE_SPECIAL_UNSUPPORTED')
    isdir=x.is_dir();need((kind!=stat.S_IFDIR or isdir) and (not isdir or x.file_size==0),'ARCHIVE_SPECIAL_UNSUPPORTED')
    row=inv.add(x.filename,x.file_size,'directory' if isdir else 'file',mode)
    if isdir:materialize(row,None)
    else:
     with z.open(x) as source:materialize(row,source)
 else:
  with gzip.open(archive,'rb') as gz,tarfile.open(fileobj=gz,mode='r|') as tar:
   for x in tar:
    need(not(x.issym() or x.islnk()),'ARCHIVE_LINK_UNSUPPORTED');need(x.isfile() or x.isdir(),'ARCHIVE_SPECIAL_UNSUPPORTED')
    row=inv.add(x.name,x.size,'directory' if x.isdir() else 'file',x.mode)
    if x.isdir():materialize(row,None)
    else:
     with tar.extractfile(x) as source:materialize(row,source)
   trailing=0
   while True:
    block=tar.fileobj.read(1024**2)
    if not block:break
    trailing+=len(block);need(trailing<=1024**2 and not any(block),'ARCHIVE_SPECIAL_UNSUPPORTED')
 return inv.members

def critical_names(rid):
 suffix='.exe' if rid=='win-x64' else ''
 native=['host/fxr/11.0.0/hostfxr.dll','shared/Microsoft.NETCore.App/11.0.0/coreclr.dll','shared/Microsoft.NETCore.App/11.0.0/clrjit.dll'] if suffix else ['host/fxr/11.0.0/libhostfxr.so','shared/Microsoft.NETCore.App/11.0.0/libcoreclr.so','shared/Microsoft.NETCore.App/11.0.0/libclrjit.so']
 return ['dotnet'+suffix,'sdk/11.0.100/dotnet.dll','sdk/11.0.100/Roslyn/bincore/csc.dll',*native]

def machine(path):
 with Path(path).open('rb') as f:
  header=f.read(64)
  if header[:2]==b'MZ':
   need(len(header)==64,'NATIVE_TARGET_UNSUPPORTED');f.seek(struct.unpack_from('<I',header,60)[0]);pe=f.read(6);need(pe[:4]==b'PE\0\0','NATIVE_TARGET_UNSUPPORTED');return ('PE',struct.unpack_from('<H',pe,4)[0])
  need(header[:4]==b'\x7fELF' and header[4:6]==b'\x02\x01','NATIVE_TARGET_UNSUPPORTED');return ('ELF',struct.unpack_from('<H',header,18)[0])

def verify_tree(root,members,rid,full=False):
 root=Path(root);files={x['path']:x for x in members if x['type']=='file'}
 names=files if full else critical_names(rid)
 for name in names:
  need(name in files,'SDK_MEMBER_MISMATCH');row=files[name];p=root/name
  need(p.is_file() and not p.is_symlink() and p.stat().st_size==row['bytes'] and digest(p)==row['sha256'],'SDK_MEMBER_MISMATCH')
  if os.name!='nt':need(stat.S_IMODE(p.stat().st_mode)==row['mode'],'SDK_MEMBER_MISMATCH')
 if full:
  actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()};need(actual==set(files),'SDK_MEMBER_MISMATCH')
  need(not any(p.is_symlink() for p in root.rglob('*')),'SDK_MEMBER_MISMATCH')
  directories={x['path'] for x in members if x['type']=='directory' and x['path']}
  for name in files:directories.update(str(p) for p in PurePosixPath(name).parents if str(p)!='.')
  need({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_dir()}==directories,'SDK_MEMBER_MISMATCH')
 need(machine(root/critical_names(rid)[0])==(('PE',0x8664) if rid=='win-x64' else ('ELF',62)),'NATIVE_TARGET_UNSUPPORTED')
 notices=[x for x in members if x['type']=='file' and re.match(r'(?i)(license|third.?party.?notices)',PurePosixPath(x['path']).name)]
 need(any(PurePosixPath(x['path']).name.lower()=='license.txt' for x in notices) and any('third' in PurePosixPath(x['path']).name.lower() for x in notices),'SDK_MEMBER_MISMATCH')
 need(any(n.startswith('packs/Microsoft.NETCore.App.Ref/11.0.0/ref/net11.0/') for n in files),'SDK_MEMBER_MISMATCH')
 return notices
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AdmissionError('SDK_TRANSPORT_REDIRECT_REJECTED')
def qualified(rid):
 raise AdmissionError('SDK_CATALOG_NOT_QUALIFIED')


import contextlib,importlib.util,signal,subprocess,sys,threading,platform,shutil
PINS={'catalogSha256': '686c6c778f7841e6015fa401f3892b853df80e3341fbb5d02b27c682887c1c78', 'factSha256': '757abf2d3dde65d10cd895cfc97eaeccb7fc11e8685b94ad046e6a8ec8829007', 'acceptanceSha256': '0452e1f3b4f2662d57e9b273428bb37ab0c5a733551a92394ca2a4e8b9b4ac08', 'schemaSha256': '63e04fa5d270c87b93e6e1f4c38bfbcf336b950b39fe1854dc4e514f0661f14c', 'guardSha256': '7420b08d78d3b1476be41385d179a42212a2a7e1a965a8d8ea3b67bb14da7925', 'materializerSha256': '5f0dbb951cbe615d8c6dd9edbb63b11143cc457319bdcc9000ea9a486f660fb8', 'rawMembersSha256': '4cbad1f9f1e43430621f88567768b3d761efe47868b7e7045f72397274c2f9a3', 'linksSha256': 'cead0d3279d952d30088e4ca430af41ae3ad9c1578179d6b7d19564b82077d34'}
def schema_check(v,s,path='$'):
 if 'const' in s:need(v==s['const'] and (not (isinstance(v,bool) or isinstance(s['const'],bool)) or type(v) is type(s['const'])),'FACT_SCHEMA_CONST:'+path)
 if 'enum' in s:need(v in s['enum'],'FACT_SCHEMA_ENUM:'+path)
 if 'type' in s:
  types=s['type'] if isinstance(s['type'],list) else [s['type']];ok=any((t=='object' and type(v) is dict) or (t=='array' and type(v) is list) or (t=='string' and type(v) is str) or (t=='integer' and type(v) is int) or (t=='number' and type(v) in (int,float)) or (t=='boolean' and type(v) is bool) or (t=='null' and v is None) for t in types);need(ok,'FACT_SCHEMA_TYPE:'+path)
 if type(v) is dict:
  props=s.get('properties',{});need(all(k in v for k in s.get('required',[])),'FACT_SCHEMA_REQUIRED:'+path)
  if s.get('additionalProperties') is False:need(set(v)<=set(props),'FACT_SCHEMA_EXTRA:'+path)
  for k,value in v.items():
   if k in props:schema_check(value,props[k],path+'.'+k)
 if type(v) is list:
  need(len(v)>=s.get('minItems',0) and len(v)<=s.get('maxItems',100000),'FACT_SCHEMA_ARRAY:'+path)
  prefix=s.get('prefixItems',[])
  for i,x in enumerate(v):
   if i<len(prefix):schema_check(x,prefix[i],path+'['+str(i)+']')
   else:
    item=s.get('items',{});need(item is not False,'FACT_SCHEMA_ARRAY_EXTRA:'+path)
    if isinstance(item,dict):schema_check(x,item,path+'[]')
 if type(v) is str:
  need(s.get('minLength',0)<=len(v)<=s.get('maxLength',100000),'FACT_SCHEMA_SIZE:'+path)
  if 'pattern' in s:need(re.fullmatch(s['pattern'],v) is not None,'FACT_SCHEMA_PATTERN:'+path)
 if type(v) in (int,float):need(v>=s.get('minimum',float('-inf')) and v>s.get('exclusiveMinimum',float('-inf')) and v<=s.get('maximum',float('inf')),'FACT_SCHEMA_RANGE:'+path)

HERE=Path(__file__).resolve().parent
BUDGETS={'01':900,'02':720,'03':1200,'04':900,'05':1200,'06':900}
FACT_SHA='757abf2d3dde65d10cd895cfc97eaeccb7fc11e8685b94ad046e6a8ec8829007'
ACCEPT_SHA='0452e1f3b4f2662d57e9b273428bb37ab0c5a733551a92394ca2a4e8b9b4ac08'
MEMBERS_SHA='d411111d23492b4d101dd62851d1d1fedf3a4badc057d999aedc155ae4cc103a'
HOST_CLASS='GitHubHostedUbuntu24.04x64'
CTX_KEYS={'projectId','repository','checkout','controller','contract','profile','sourcePins','admission','capsEvidence','expectedSourceCommit','expectedSourceTree','rowStartedMonotonicNs','deadlineMonotonicNs','supervisorPID','supervisorStartIdentity'}
SAFE_ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0','SYSTEMD_PAGER':'cat','SYSTEMD_COLORS':'0'}

def _pairs(rows):
 out={}
 for k,v in rows:need(k not in out,'NORMAL_JSON_DUPLICATE');out[k]=v
 return out

def _read(path,limit=16777216):
 p=Path(path);st=p.lstat();need(stat.S_ISREG(st.st_mode) and not p.is_symlink() and st.st_size<=limit,'NORMAL_INPUT_FILE')
 return json.loads(p.read_bytes(),object_pairs_hook=_pairs,parse_constant=lambda _:(_ for _ in ()).throw(AdmissionError('NORMAL_JSON_CONSTANT')))

def _load(name,pin):
 p=HERE/(name+'.py');need(digest(p)==pin,'NORMAL_LIBRARY_SOURCE')
 old=sys.modules.get(name)
 if old is not None:need(Path(getattr(old,'__file__','')).resolve()==p.resolve() and digest(p)==pin,'NORMAL_FOREIGN_MODULE');return old
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def validate_catalog_values(cat,fact,acceptance,schema):
 need(type(cat) is dict and cat.get('schema')=='sdk11-shared-normal-input-catalog/v1' and cat.get('state')=='SOURCE_HELD_NORMAL_ACCEPTED_RIDS_ONLY','NORMAL_CATALOG_STATE')
 need(cat.get('contractSha256')=='e092c4e8911c2b25f70fda3608d2c04212d3d81f6aaa1214688eea236cfbb089' and cat.get('SDK_READY') is False and set(cat.get('rids',{}))=={'linux-x64','win-x64'},'NORMAL_CATALOG_CONTRACT')
 need(cat.get('rids',{}).get('win-x64',{}).get('state')=='DENIED_NO_ACCEPTED_PRODUCER_FACT','NORMAL_WINDOWS_DENIED')
 entry=cat.get('rids',{}).get('linux-x64');need(type(entry) is dict and entry.get('state')=='ACCEPTED_PRODUCER_FACT_FOR_OWN_ADMITTED_HOST','NORMAL_RID_FACT_MISSING')
 need(entry.get('factSha256')==FACT_SHA and entry.get('acceptanceSha256')==ACCEPT_SHA,'NORMAL_FACT_AUTHORITY')
 schema_check(fact,schema);q=fact['qualifiedOn'];need(q['rid']=='linux-x64' and q['hostClass']==HOST_CLASS and q['runId']=='43920284996' and fact['source']['commit']==entry['producerCommit']=='803eb71621bad8eb45e30aaf3d4560b8c058d07c' and fact['source']['tree']==entry['producerTree']=='66794c0d3f4e2b3e6b7bd2aedc98972745a0783d','NORMAL_PRODUCER_HISTORY')
 need(acceptance.get('runId')==43920284996 and any(x.get('id')==133485418032 and x.get('status')=='completed' and x.get('conclusion')=='success' for x in acceptance.get('jobs',[])),'NORMAL_PRODUCER_ACCEPTANCE')
 c=entry.get('input');need(type(c) is dict and c.get('state')=='ACCEPTED_HOST_TYPED_NORMAL_INPUT' and c.get('normalTransportUse')=='OWN_CURRENT_TYPED_ADMISSION_REQUIRED','NORMAL_INPUT_STATE')
 need(c.get('rid')=='linux-x64' and c.get('sdk')=='11.0.100' and c.get('runtime')=='11.0.0','NORMAL_INPUT_RID')
 need((c.get('url'),c.get('bytes'),c.get('sha512'))==('https://builds.dotnet.microsoft.com/dotnet/Sdk/11.0.100/dotnet-sdk-11.0.100-linux-x64.tar.gz',211463422,INPUTS['linux-x64']['sha512']),'NORMAL_RAW_IDENTITY')
 need(c.get('memberManifestSha256')==MEMBERS_SHA==fact['tree']['memberManifestSha256'] and hashlib.sha256(canonical(c.get('members'))).hexdigest()==MEMBERS_SHA,'NORMAL_MEMBER_IDENTITY')
 need(hashlib.sha256(canonical(c.get('rawMembers'))).hexdigest()==entry.get('rawMembersSha256')==PINS['rawMembersSha256'],'NORMAL_RAW_HEADER_IDENTITY')
 need(hashlib.sha256(canonical(c.get('links'))).hexdigest()==entry.get('linksSha256')==PINS['linksSha256'],'NORMAL_ALIAS_IDENTITY')
 need(len(c['members'])==len(c['rawMembers'])==7055 and len(c['links'])==1830,'NORMAL_NAMESPACE_COUNTS');return c

def _documents(rid):
 need(rid=='linux-x64','NORMAL_RID_NOT_ACCEPTED')
 p=HERE/'sdk11-normal-inputs.lock.json';need(digest(p)==PINS['catalogSha256'],'NORMAL_CATALOG_SOURCE_BYTES');cat=_read(p)
 fp=HERE/'sdk11-normal/accepted-linux-fact.json';ap=HERE/'sdk11-normal/accepted-linux-acceptance.json';sp=HERE/'dotnet11-host-qualification.schema.json'
 need(digest(fp)==PINS['factSha256']==FACT_SHA,'NORMAL_FACT_SOURCE_BYTES');need(digest(ap)==PINS['acceptanceSha256']==ACCEPT_SHA,'NORMAL_ACCEPTANCE_SOURCE_BYTES');need(digest(sp)==PINS['schemaSha256'],'NORMAL_SCHEMA_SOURCE_BYTES')
 fact=_read(fp);acceptance=_read(ap);schema=_read(sp);c=validate_catalog_values(cat,fact,acceptance,schema);return c,fact,schema

def _deadline_values(ctx,now):
 need(type(ctx) is dict and set(ctx)==CTX_KEYS and ctx.get('projectId') in BUDGETS,'NORMAL_CONTEXT_SHAPE');start=ctx['rowStartedMonotonicNs'];end=ctx['deadlineMonotonicNs']
 need(type(start) is int and type(end) is int and 0<start<=now<end and end-start<=BUDGETS[ctx['projectId']]*1000000000,'NORMAL_ORIGINAL_DEADLINE')
 return end

@contextlib.contextmanager
def absolute_deadline(ctx):
 end=_deadline_values(ctx,time.monotonic_ns());need(os.name=='posix' and threading.current_thread() is threading.main_thread(),'NORMAL_LINUX_MAIN_WORKER_REQUIRED');oldhandler=signal.getsignal(signal.SIGALRM);oldtimer=signal.getitimer(signal.ITIMER_REAL);entered=time.monotonic_ns();need(oldtimer[1]==0,'NORMAL_PERIODIC_TIMER_UNSUPPORTED');oldend=entered+int(oldtimer[0]*1e9) if oldtimer[0]>0 else None;effective=min(end,oldend) if oldend else end
 def expired(*_):raise AdmissionError('NORMAL_ABSOLUTE_DEADLINE')
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,max(.000001,(effective-time.monotonic_ns())/1e9))
 try:yield effective
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,oldhandler)
  if oldend is not None:
   remaining=(oldend-time.monotonic_ns())/1e9
   need(remaining>0,'NORMAL_OUTER_DEADLINE_EXPIRED');signal.setitimer(signal.ITIMER_REAL,remaining)

def _remaining(end):
 need(time.monotonic_ns()<end,'NORMAL_ABSOLUTE_DEADLINE');return (end-time.monotonic_ns())/1e9

def _run(argv,cwd,end,limit=1048576):
 r=subprocess.run(list(map(str,argv)),cwd=cwd,env=SAFE_ENV,capture_output=True,timeout=min(10,_remaining(end)));need(len(r.stdout)+len(r.stderr)<=limit,'NORMAL_TOOL_OUTPUT_CAP');need(r.returncode==0,'NORMAL_SOURCE_OR_HOST_TOOL_FAILED');return r.stdout

def _start(pid):
 text=Path('/proc',str(pid),'stat').read_text();return 'proc-start:'+text[text.rfind(')')+2:].split()[19]

def _duration_us(text):
 if text.isdigit():return int(text)
 units={'us':1,'ms':1000,'s':1000000,'min':60000000,'h':3600000000};parts=re.findall(r'([0-9]+)(us|ms|min|s|h)',text);need(parts and ''.join(n+u for n,u in parts)==text.replace(' ',''),'NORMAL_FINITE_UNIT_DEADLINE');return sum(int(n)*units[u] for n,u in parts)

def _observe_current(ctx,profile,end):
 need(os.name=='posix' and os.getuid()>0 and os.getgid()>0 and platform.machine().lower() in ('x86_64','amd64'),'NORMAL_CURRENT_HOST')
 release=dict(x.split('=',1) for x in Path('/etc/os-release').read_text().splitlines() if '=' in x);need(release.get('ID')=='ubuntu' and release.get('VERSION_ID','').strip('"')=='24.04' and 'microsoft' not in platform.release().lower() and not os.environ.get('WSL_DISTRO_NAME'),'NORMAL_CURRENT_HOST')
 need(sys.version_info[:2]==(3,12) and bool(os.environ.get('ImageVersion')),'NORMAL_OWN_BOOTSTRAP_IMAGE')
 need(os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('RUNNER_OS')=='Linux' and os.environ.get('ImageOS')=='ubuntu24' and Path('/proc/1/comm').read_text().strip()=='systemd','NORMAL_CURRENT_HOST')
 raw=Path('/proc/cpuinfo').read_bytes();flags=[set(x.split(':',1)[1].split()) for x in raw.decode().splitlines() if x.startswith('flags')];need(flags and all({'cx16','popcnt','pni','ssse3','sse4_1','sse4_2','lahf_lm'}<=x for x in flags),'NORMAL_OWN_CPU_V2')
 group=next((x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::')),None);need(group and re.fullmatch('/system.slice/[A-Za-z0-9_.@-]+[.]service',group),'NORMAL_OWN_CGROUP');unit=group.rsplit('/',1)[1];need(unit.startswith(profile['ownedUnitPrefix']),'NORMAL_OWN_UNIT')
 root=Path('/sys/fs/cgroup')/group.lstrip('/');limits={k:(root/k).read_text().strip() for k in ['memory.max','memory.swap.max','pids.max','cpu.max']};need(os.getpid() in [int(x) for x in (root/'cgroup.procs').read_text().split()],'NORMAL_OWN_MEMBERSHIP')
 output=_run(['/usr/bin/systemctl','show',unit,'--property=MainPID,ControlGroup,RuntimeMaxUSec,ActiveEnterTimestampMonotonic,TimeoutStopUSec,KillMode,SendSIGKILL,FinalKillSignal'],ctx['checkout'],end,16384).decode();props=dict(x.split('=',1) for x in output.splitlines() if '=' in x)
 need(props.get('ControlGroup')==group and props.get('MainPID')==str(os.getpid()) and props.get('KillMode')=='control-group' and props.get('SendSIGKILL')=='yes' and props.get('FinalKillSignal') in ('9','SIGKILL'),'NORMAL_BLOCKING_OUTER_SUPERVISOR')
 entered=int(props['ActiveEnterTimestampMonotonic']);hardend=(entered+_duration_us(props['RuntimeMaxUSec'])+_duration_us(props['TimeoutStopUSec']))*1000;need(entered>0 and time.monotonic_ns()<hardend<=ctx['deadlineMonotonicNs'],'NORMAL_KERNEL_OUTER_DEADLINE')
 return {'hostClass':HOST_CLASS,'repository':os.environ.get('GITHUB_REPOSITORY'),'runId':os.environ.get('GITHUB_RUN_ID'),'job':os.environ.get('GITHUB_JOB'),'attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),'instanceId':os.environ.get('RUNNER_NAME'),'imageOS':os.environ.get('ImageOS'),'imageVersion':os.environ.get('ImageVersion'),'osVersion':'Ubuntu 24.04','kernelBuild':platform.release(),'architecture':'x64','bootstrap':{'pythonVersion':platform.python_version(),'pythonExeSha256':digest(Path(sys.executable).resolve()),'gitSha256':digest('/usr/bin/git'),'systemctlSha256':digest('/usr/bin/systemctl')},'pid':os.getpid(),'processStartIdentity':_start(os.getpid()),'uid':os.getuid(),'gid':os.getgid(),'cgroup':group,'kernelLimits':limits,'supervisorPID':ctx['supervisorPID'],'supervisorStartIdentity':_start(ctx['supervisorPID']),'hardOuterDeadlineNs':hardend,'cpuEvidenceSha256':hashlib.sha256(raw).hexdigest()}

def validate_current_values(ctx,admission,profile,sourcePins,current,caps,hashes,schema):
 _deadline_values(ctx,current['observedNowNs']);project=ctx['projectId'];need(profile.get('schema')=='sdk11-own-normal-input-profile/v1' and profile.get('state')=='ADMITTED_SOURCE_PROFILE' and profile.get('projectId')==project and profile.get('repository')==ctx['repository'],'NORMAL_OWN_PROFILE')
 need(type(profile.get('rowSeconds')) is int and 0<profile['rowSeconds']<=BUDGETS[project] and ctx['deadlineMonotonicNs']-ctx['rowStartedMonotonicNs']<=profile['rowSeconds']*10**9,'NORMAL_OWN_PROFILE_BUDGET')
 for k in ['memoryMaxBytes','tasksMax','cpuQuotaMicros','cpuPeriodMicros']:need(type(profile.get(k)) is int and profile[k]>0,'NORMAL_OWN_PROFILE_LIMITS')
 need(type(profile.get('swapMaxBytes')) is int and profile['swapMaxBytes']==0 and type(profile.get('ownedUnitPrefix')) is str and re.fullmatch('[A-Za-z0-9_.@-]{1,100}',profile['ownedUnitPrefix']),'NORMAL_OWN_PROFILE_LIMITS')
 schema_check(admission,schema['$defs']['consumerAdmission']);need(admission['projectId']==project and admission['producerFactSha256']==FACT_SHA,'NORMAL_OWN_ADMISSION')
 bound=admission['admittedFor'];need(bound['hostClass']==HOST_CLASS and bound['rid']=='linux-x64' and bound['memberManifestSha256']==MEMBERS_SHA,'NORMAL_ADMISSION_HOST_RID')
 need(bound['profileSha256']==hashes['profile'] and bound['controllerSha256']==hashes['controller'] and bound['contractSha256']==hashes['contract'] and bound['sourcePinTableSha256']==hashlib.sha256(canonical(sourcePins['sourcePins'])).hexdigest(),'NORMAL_OWN_SOURCE_PROFILE_HASH')
 need(sourcePins.get('schema')=='sdk11-own-source-pins/v1' and sourcePins.get('state')=='EXACT_SOURCE_REVIEWED' and sourcePins.get('projectId')==project and sourcePins.get('repository')==ctx['repository'],'NORMAL_OWN_SOURCE_PINS')
 need(current['hostClass']==HOST_CLASS and current['repository']==ctx['repository'] and current['commit']==ctx['expectedSourceCommit'] and current['tree']==ctx['expectedSourceTree'],'NORMAL_CURRENT_SOURCE')
 need(all(admission['currentExecution'][k]==current[k] and current[k] for k in ['runId','job','attempt','instanceId']) and admission['currentExecution']['ownCapsEvidenceSha256']==hashes['capsEvidence'],'NORMAL_CURRENT_EXECUTION')
 expected={'memory.max':str(profile['memoryMaxBytes']),'memory.swap.max':'0','pids.max':str(profile['tasksMax']),'cpu.max':str(profile['cpuQuotaMicros'])+' '+str(profile['cpuPeriodMicros'])};need(current['kernelLimits']==expected and current['uid']>0 and current['gid']>0,'NORMAL_ACTUAL_OWN_CAPS')
 need(caps.get('schema')=='sdk11-own-current-cap-evidence/v1' and caps.get('projectId')==project and caps.get('repository')==ctx['repository'] and caps.get('sourceCommit')==current['commit'] and caps.get('sourceTree')==current['tree'] and caps.get('profileSha256')==hashes['profile'] and caps.get('controllerSha256')==hashes['controller'],'NORMAL_OWN_CAP_EVIDENCE')
 need(caps.get('bootstrap')==current.get('bootstrap') and type(current.get('bootstrap')) is dict and set(current['bootstrap'])=={'pythonVersion','pythonExeSha256','gitSha256','systemctlSha256'} and current['bootstrap']['pythonVersion'].startswith('3.12.'),'NORMAL_OWN_BOOTSTRAP_IDENTITY')
 worker=caps.get('worker',{});before=caps.get('beforeExec',{});need(all(worker.get(k)==current[k] for k in ['pid','processStartIdentity','uid','gid','cgroup','kernelLimits']),'NORMAL_CURRENT_WORKER_IDENTITY')
 need(before.get('pid')==current['pid'] and before.get('processStartIdentity')==current['processStartIdentity'] and before.get('cgroup')==current['cgroup'] and before.get('kernelLimits')==expected and before.get('state')=='T' and before.get('membershipBeforeRelease') is True and before.get('retainedStartHandle') is True,'NORMAL_HELD_BEFORE_EXEC')
 supervisor=caps.get('supervisor',{});need(supervisor.get('pid')==current['supervisorPID']==ctx['supervisorPID'] and supervisor.get('processStartIdentity')==current['supervisorStartIdentity']==ctx['supervisorStartIdentity'] and supervisor.get('deadlineMonotonicNs')==ctx['deadlineMonotonicNs'] and current['hardOuterDeadlineNs']<=ctx['deadlineMonotonicNs'],'NORMAL_OUTER_SUPERVISOR_IDENTITY')
 need(caps.get('rowStartedMonotonicNs')==ctx['rowStartedMonotonicNs'] and caps.get('deadlineMonotonicNs')==ctx['deadlineMonotonicNs'],'NORMAL_DEADLINE_EVIDENCE')
 return True

def validate_source_file(path,row,committed):
 need(type(row) is dict and row.get('mode') in ('100644','100755'),'NORMAL_BINDING_NOT_TRACKED')
 blob=hashlib.sha1(b'blob '+str(len(committed)).encode()+b'\0'+committed).hexdigest()
 need(blob==row.get('gitBlob') and Path(path).read_bytes()==committed,'NORMAL_BINDING_SOURCE_CHANGED')

def _preflight(rid,ctx,end):
 c,fact,schema=_documents(rid);checkout=Path(ctx['checkout']).resolve();temp=Path(os.environ.get('RUNNER_TEMP','')).resolve();need(os.environ.get('RUNNER_TEMP') and temp.is_dir() and str(checkout)==os.environ.get('GITHUB_WORKSPACE'),'NORMAL_CURRENT_CHECKOUT')
 a=_load('qualification_input_guard',PINS['guardSha256']);paths={}
 for key in ['controller','contract','profile','sourcePins']:
  paths[key]=a.scoped(ctx[key],checkout);need(paths[key].is_file(),'NORMAL_CURRENT_SOURCE_FILE')
 mainfile=getattr(sys.modules.get('__main__'),'__file__',None);need(mainfile and Path(mainfile).resolve()==paths['controller'].resolve(),'NORMAL_CAPPED_CALLER_CONTROLLER')
 for key in ['admission','capsEvidence']:paths[key]=a.scoped(ctx[key],temp)
 parent=paths['capsEvidence'].parent;st=parent.stat();need(st.st_uid==os.getuid() and st.st_gid==os.getgid() and stat.S_IMODE(st.st_mode)==0o700,'NORMAL_OWN_EVIDENCE_SCOPE')
 admission=_read(paths['admission'],65536);caps=_read(paths['capsEvidence'],65536);profile=_read(paths['profile'],65536);pins=_read(paths['sourcePins'],1048576);hashes={key:digest(path) for key,path in paths.items()}
 # Current kernel/host/CPU and actual outer service lifetime are observed here,
 # not accepted from the producer receipt or from caller-supplied dictionaries.
 current=_observe_current(ctx,profile,end);source=_run(['/usr/bin/git','-C',checkout,'rev-parse','HEAD','HEAD^{tree}'],checkout,end,4096).decode().splitlines();need(len(source)==2,'NORMAL_CURRENT_SOURCE');current.update(commit=source[0],tree=source[1],observedNowNs=time.monotonic_ns());need(os.environ.get('GITHUB_SHA')==source[0],'NORMAL_EVENT_SOURCE')
 need(not _run(['/usr/bin/git','-C',checkout,'status','--porcelain=v1','--untracked-files=all'],checkout,end),'NORMAL_SOURCE_NOT_CLEAN')
 actual={}
 for row in _run(['/usr/bin/git','-C',checkout,'ls-tree','-r','-z','HEAD'],checkout,end,1048576).split(b'\0'):
  if not row:continue
  meta,name=row.split(b'\t',1);mode,kind,blob=meta.decode().split();need(kind=='blob' and mode in ('100644','100755'),'NORMAL_SOURCE_MODE');actual[name.decode()]={'path':name.decode(),'mode':mode,'gitBlob':blob}
 selfpin=paths['sourcePins'].relative_to(checkout).as_posix();need(selfpin in actual,'NORMAL_SOURCE_PINS_NOT_TRACKED');actual.pop(selfpin)
 for key in ['controller','contract','profile']:
  name=paths[key].relative_to(checkout).as_posix();need(name in actual,'NORMAL_BINDING_NOT_TRACKED');committed=_run(['/usr/bin/git','-C',checkout,'show','HEAD:'+name],checkout,end);validate_source_file(paths[key],actual[name],committed)
 expected={x['path']:x for x in pins.get('sourcePins',[])};need(len(expected)==len(pins.get('sourcePins',[])) and actual==expected,'NORMAL_SOURCE_PIN_TABLE')
 validate_current_values(ctx,admission,profile,pins,current,caps,hashes,schema)
 lm=_load('materialize_qualification_linux',PINS['materializerSha256']);members,aliases=lm.layout(c['rawMembers'],c['links']);need(members==c['members'] and len(aliases)==1830,'NORMAL_TYPED_LAYOUT')
 _remaining(end);return c,fact,admission,profile,current,hashes,a,lm

def _allocate(directory,ctx,a):
 temp=Path(os.environ['RUNNER_TEMP']).resolve();dest=Path(directory).absolute();need(dest.parent==temp and re.fullmatch('sdk11-normal-'+ctx['projectId']+'-[A-Za-z0-9_.-]{1,160}',dest.name),'NORMAL_FRESH_SCOPE');a.scoped(dest,temp,absent=True);dest.mkdir(mode=0o700);st=dest.lstat();need(stat.S_IMODE(st.st_mode)==0o700 and st.st_uid==os.getuid() and st.st_gid==os.getgid(),'NORMAL_FRESH_OWNER');return dest,(st.st_dev,st.st_ino)

def _cleanup(directory,identity,end):
 # Only this call's fresh inode under its original runner.temp. Never extend time.
 if directory is None:return 'NO_ALLOCATION'
 try:
  _remaining(end);st=directory.lstat();need((st.st_dev,st.st_ino)==identity and stat.S_ISDIR(st.st_mode) and not directory.is_symlink() and st.st_uid==os.getuid(),'NORMAL_CLEANUP_SCOPE');need(directory.parent==Path(os.environ['RUNNER_TEMP']).resolve(),'NORMAL_CLEANUP_SCOPE');shutil.rmtree(directory);_remaining(end);return 'OWN_FRESH_ALLOCATION_REMOVED'
 except Exception:return 'UNKNOWN_OR_DEADLINE_PARTIAL_RETAINED'

def _download(c,archive,end):
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());request=urllib.request.Request(c['url'],headers={'Accept-Encoding':'identity','User-Agent':'sdk11-shared-normal-data-only/v1'});size=0;h=hashlib.sha512()
 with opener.open(request,timeout=min(10,_remaining(end))) as response,archive.open('xb') as out:
  length=response.headers.get('Content-Length');need(response.status==200 and response.url==c['url'] and length==str(c['bytes']) and not response.headers.get('Content-Range') and response.headers.get('Content-Encoding','identity')=='identity','NORMAL_TRANSPORT_IDENTITY')
  while True:
   _remaining(end);block=response.read(min(1048576,c['bytes']-size+1))
   if not block:break
   size+=len(block);need(size<=c['bytes']<=RAW_MAX,'NORMAL_RAW_SIZE');out.write(block);h.update(block)
  out.flush();os.fsync(out.fileno());_remaining(end)
 need(size==c['bytes'] and h.hexdigest()==c['sha512'],'NORMAL_RAW_BODY_HASH');return {'url':c['url'],'bytes':size,'sha512':h.hexdigest()}

def _receipt(rid,ctx,c,fact,admission,current,hashes,raw,started,end):
 return {'schema':'sdk11-shared-normal-input-receipt/v1','state':'OWN_CURRENT_CALLER_INPUT_VERIFIED_NO_SDK_EXECUTION','projectId':ctx['projectId'],'rid':rid,'sdk':'11.0.100','runtime':'11.0.0','normalCatalogSha256':PINS['catalogSha256'],'producerFactSha256':FACT_SHA,'producerAcceptanceSha256':ACCEPT_SHA,'producerQualifiedOn':fact['qualifiedOn'],'producerSource':fact['source'],'consumerAdmission':admission,'ownCurrent':{k:current[k] for k in ['hostClass','repository','runId','job','attempt','instanceId','imageOS','imageVersion','osVersion','kernelBuild','architecture','bootstrap','commit','tree','pid','processStartIdentity','uid','gid','cgroup','kernelLimits','hardOuterDeadlineNs','cpuEvidenceSha256']},'ownBindingFileHashes':hashes,'rawArchive':raw,'memberManifestSha256':MEMBERS_SHA,'rawMembersSha256':PINS['rawMembersSha256'],'linksSha256':PINS['linksSha256'],'namespace':{'rawHeaders':7055,'physicalFiles':6015,'directoriesIncludingRoot':1040,'distinctRegularAliases':1830,'expandedFileBytes':733424833,'physicalLinks':0},'notices':[x for x in c['members'] if x['type']=='file' and re.match(r'(?i)(license|third.?party.?notices)',PurePosixPath(x['path']).name)],'criticalMembers':[x for x in c['members'] if x['path'] in critical_names(rid)],'inputStartedMonotonicNs':started,'originalRowStartedMonotonicNs':ctx['rowStartedMonotonicNs'],'absoluteOriginalDeadlineNs':ctx['deadlineMonotonicNs'],'effectiveAlarmDeadlineNs':end,'completedMonotonicNs':time.monotonic_ns(),'SDKExecutions':0,'SDKPathOrGitHubEnvironmentExports':0,'SDKCacheOrArtifactUploads':0,'boundary':'Input materialization only. Current caller continues inside its own verified caps/outer deadline; native prerequisites, SDK/product commands and final owned terminal proof remain its controller responsibility.'}

def transport(rid,directory,context):
 """Concrete shared API. Call inside the held own worker; returns (Path, receipt).
 context is the finite v1 dictionary in INTERFACE.md, never a callback/allow flag.
 """
 started=time.monotonic_ns();end=_deadline_values(context,started);allocation=None;identity=None
 with absolute_deadline(context) as effective:
  try:
   c,fact,admission,profile,current,hashes,a,lm=_preflight(rid,context,effective)
   allocation,identity=_allocate(directory,context,a);archive=allocation/'official-archive';raw=_download(c,archive,effective);_remaining(effective)
   sdk=allocation/'sdk';members=lm.materialize(c,archive,sdk);_remaining(effective);need(members==c['members'],'NORMAL_MEMBER_POSTIMAGE');_remaining(effective) # materialize already performs the full physical/member/mode/body verification
   # Re-observe the current own kernel and original deadline before releasing path.
   again=_observe_current(context,profile,effective);need(all(again[k]==current[k] for k in ['pid','processStartIdentity','uid','gid','cgroup','kernelLimits','hardOuterDeadlineNs']),'NORMAL_CAPS_CHANGED')
   archive.unlink();_remaining(effective);receipt=_receipt(rid,context,c,fact,admission,current,hashes,raw,started,effective);encoded=canonical(receipt);need(len(encoded)<=1048576,'NORMAL_RECEIPT_CAP')
   with (allocation/'input-receipt.json').open('xb') as f:f.write(encoded);f.flush();os.fsync(f.fileno())
   _remaining(effective);return sdk,receipt
  except BaseException as exc:
   # Cancellation/deadline never yields an SDK path. Cleanup shares the original
   # deadline; the observed owned unit hard limit covers blocking fsync/cleanup.
   state=_cleanup(allocation,identity,effective);exc.normalInputCleanup={'state':state,'allocationCreated':allocation is not None}
   if allocation is not None and state!='OWN_FRESH_ALLOCATION_REMOVED':
    # Do not perform post-deadline I/O or claim terminality. Supervisor owns any
    # retained partial and must keep HOLD until its actual terminal observation.
    pass
   raise

def inspect_sdk(rid,root,context):
 """Full data-only recheck for the same own capped caller/deadline, no fetch."""
 with absolute_deadline(context) as end:
  c,fact,admission,profile,current,hashes,a,lm=_preflight(rid,context,end);root=a.scoped(root,Path(os.environ['RUNNER_TEMP']));lm.verify_physical(root,c['members']);_remaining(end)
  return {'schema':'sdk11-shared-normal-recheck/v1','state':'OWN_CURRENT_FULL_INPUT_IDENTITY_VERIFIED','projectId':context['projectId'],'memberManifestSha256':MEMBERS_SHA,'producerFactSha256':FACT_SHA,'capsEvidenceSha256':hashes['capsEvidence'],'absoluteDeadlineNs':context['deadlineMonotonicNs'],'SDKExecutions':0}

def main():
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['transport','inspect']);parser.add_argument('--rid',choices=list(INPUTS),required=True);parser.add_argument('--context',type=Path,required=True);parser.add_argument('--directory',type=Path);parser.add_argument('--root',type=Path);args=parser.parse_args();ctx=_read(args.context,65536)
 if args.mode=='transport':
  need(args.directory is not None,'NORMAL_FRESH_SCOPE');sdk,receipt=transport(args.rid,args.directory,ctx);print(json.dumps({'sdkPath':str(sdk),'receipt':receipt}))
 else:need(args.root is not None,'NORMAL_INSPECT_SCOPE');print(json.dumps(inspect_sdk(args.rid,args.root,ctx)))
if __name__=='__main__':main()
