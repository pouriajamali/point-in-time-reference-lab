"""Current consumer job observation, never producer kernel-proof reuse."""
from pathlib import Path
import datetime,json,os,platform,subprocess,sys,time,urllib.request
class Hold(RuntimeError):pass
def need(v,m):
 if not v:raise Hold(m)
def api(path):
 token=os.environ.get('GITHUB_TOKEN');need(token,'API_JOB_READBACK_REQUIRED')
 req=urllib.request.Request('https://api.github.com/repos/pouriajamali/point-in-time-reference-lab/'+path,headers={'User-Agent':'project05-host-boundary','Accept':'application/vnd.github+json','Authorization':'Bearer '+token})
 with urllib.request.urlopen(req,timeout=15) as response:
  raw=response.read(2*1024*1024);need(len(raw)<2*1024*1024,'API_RESPONSE_CAP');return json.loads(raw)
def observe_api_backed_current_job(rid,root,source,profile):
 started=time.monotonic();need(sys.version_info[:2]==(3,12),'EXISTING_PYTHON312_ONLY_NO_DOWNLOAD');need(rid in profile['hostClasses'],'RID_REQUIRED');p=profile['hostClasses'][rid]
 need(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted','SUPPORTED_CI_ONLY')
 need(os.environ.get('GITHUB_REPOSITORY')=='pouriajamali/point-in-time-reference-lab','OWN_REPOSITORY_REQUIRED')
 run=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT'];record=api('actions/runs/'+run)
 need(record['head_sha']==source['head']==os.environ['GITHUB_SHA'],'CURRENT_RUN_HEAD_SOURCE')
 jobs=api('actions/runs/'+run+'/attempts/'+attempt+'/jobs?per_page=100')['jobs'];current=[j for j in jobs if j['name']=='verify-'+rid and j.get('runner_name')==os.environ.get('RUNNER_NAME') and j['status']=='in_progress'];need(len(current)==1,'CURRENT_JOB_API_IDENTITY');j=current[0]
 need(p['runner'] in j['labels'] and 'self-hosted' not in j['labels'],'ACTUAL_RUNNER_CLASS')
 ctx={'hostClass':p['name'],'rid':rid,'runId':run,'jobId':str(j['id']),'job':os.environ.get('GITHUB_JOB'),'attempt':attempt,'apiVerified':True,'runnerEnvironment':'github-hosted','container':False,'sourceCommit':source['head'],'imageOS':os.environ.get('ImageOS'),'imageVersion':os.environ.get('ImageVersion'),'runnerName':j['runner_name'],'runnerId':j['runner_id'],'checkout':str(root),'runnerTemp':os.environ['RUNNER_TEMP'],'architecture':platform.machine()}
 need(ctx['imageOS']==p['imageOS'] and ctx['imageVersion'],'OWN_HOST_IMAGE')
 if rid=='win-x64':
  need(os.name=='nt','WINDOWS_NATIVE_REQUIRED');v=sys.getwindowsversion();ctx.update(kernelBuild=v.build,productType=v.product_type)
  need(v.build==26100 and v.product_type==3,'WINDOWS_SERVER2025_REQUIRED')
 else:
  need(os.name=='posix' and 'microsoft' not in Path('/proc/sys/kernel/osrelease').read_text().lower() and not Path('/.dockerenv').exists() and not Path('/run/.containerenv').exists(),'UBUNTU_HOSTED_VM_REQUIRED')
  release=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line);version=release.get('VERSION_ID','').strip('"');need(version=='24.04' and platform.machine()=='x86_64','UBUNTU24_X64_REQUIRED')
  uid,gid=os.getuid(),os.getgid();need(uid>0 and gid>0,'NONROOT_RUNNER_UID_GID');ctx.update(uid=uid,gid=gid,osVersion=version)
  required={'cx16','popcnt','pni','ssse3','sse4_1','sse4_2','lahf_lm'};flags=[set(line.split(':',1)[1].split()) for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('flags')];need(flags and all(required<=row for row in flags),'OWN_X64_V2_CPU_REQUIRED')
 start=datetime.datetime.fromisoformat(j['started_at'].replace('Z','+00:00'));age=(datetime.datetime.now(datetime.timezone.utc)-start).total_seconds();need(0<=age<1200 and time.monotonic()-started<=60,'ORIGINAL_ROW_BOOTSTRAP_ENVELOPE');ctx['rowRemaining']=1200-age;ctx['rowDeadlineUnix']=start.timestamp()+1200;ctx['pythonExeSha256']=__import__('hashlib').sha256(Path(sys.executable).read_bytes()).hexdigest();ctx['pythonVersion']=sys.version;now_ns=time.monotonic_ns();ctx['deadlineMonotonicNs']=now_ns+int(ctx['rowRemaining']*10**9);ctx['rowStartedMonotonicNs']=ctx['deadlineMonotonicNs']-1200*10**9
 prior=root/'artifacts/ci-route/control-probe/own-current-control.json'
 if prior.is_file():
  previous=json.loads(prior.read_bytes())['ctx'];need(all(previous[k]==ctx[k] for k in ('runId','jobId','job','attempt','sourceCommit','runnerName')),'ORIGINAL_ROW_CONTEXT');need(previous['deadlineMonotonicNs']-previous['rowStartedMonotonicNs']==1200*10**9 and previous['rowStartedMonotonicNs']<now_ns<previous['deadlineMonotonicNs'],'ORIGINAL_ROW_CLOCK');ctx['deadlineMonotonicNs']=min(previous['deadlineMonotonicNs'],ctx['deadlineMonotonicNs']);ctx['rowStartedMonotonicNs']=previous['rowStartedMonotonicNs']
 need(ctx['job']=='verify','ACTUAL_LOGICAL_JOB')
 return ctx
