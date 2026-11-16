"""Inert proposed Ubuntu24 trusted OS boundary. No root SDK or arbitrary command."""
from pathlib import Path
import hashlib,json,os,re,subprocess,time
class Hold(RuntimeError):pass
def need(v,m):
 if not v:raise Hold(m)
def durable(path,data):
 raw=(json.dumps(data,indent=2)+chr(10)).encode();need(len(raw)<=8192,'RECEIPT_CAP')
 with Path(path).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def left(deadline,limit):
 n=min(limit,deadline-time.monotonic());need(n>0,'EXISTING_DEADLINE_EXHAUSTED');return n
def own_unit(unit,run,attempt,nonce):
 need(re.fullmatch('[0-9]+',str(run)) and re.fullmatch('[0-9]+',str(attempt)) and re.fullmatch('[0-9a-f]{16}',nonce),'OWN_CONTEXT_UNIT')
 need(unit=='pit05-ci-'+str(run)+'-'+str(attempt)+'-'+nonce+'.service','EXACT_OWN_UNIT')
def start_argv(ctx,script,spec,deadline):
 need(ctx['hostClass']=='GitHubHostedUbuntu24.04x64' and ctx['apiVerified'] and ctx['runnerEnvironment']=='github-hosted' and not ctx['container'],'SUPPORTED_HOSTED_VM_ONLY')
 uid,gid=os.getuid(),os.getgid();need(uid>0 and gid>0 and (uid,gid)==(ctx['uid'],ctx['gid']),'ACTUAL_NONROOT_RUNNER')
 own_unit(ctx['unit'],ctx['runId'],ctx['attempt'],ctx['nonce'])
 need(not any(c in str(script)+str(spec) for c in ('%','\n','\r','\x00')),'FIXED_SYSTEMD_ARGV_PATH')
 root=Path(ctx['checkout']).resolve();need(Path(script).resolve()==root/'tools/ci05/ci_route05.py','FIXED_WORKER_SOURCE')
 need(Path(spec).resolve().is_relative_to(Path(ctx['runnerTemp']).resolve()) and not Path(spec).is_symlink(),'PRIVATE0700_SPEC_ROOT')
 values={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux','GITHUB_REPOSITORY':'pouriajamali/point-in-time-reference-lab','GITHUB_SHA':ctx['sourceCommit'],'GITHUB_JOB':ctx['job'],'GITHUB_RUN_ID':ctx['runId'],'GITHUB_RUN_ATTEMPT':ctx['attempt'],'RUNNER_NAME':ctx['runnerName'],'GITHUB_WORKSPACE':str(root),'RUNNER_TEMP':ctx['runnerTemp'],'ImageOS':ctx['imageOS'],'ImageVersion':ctx['imageVersion']}
 need(not any(c in str(v) for v in values.values() for c in ('%','\n','\r','\x00')),'FIXED_SYSTEMD_CONTEXT_VALUE');sets=['--setenv='+k+'='+str(v) for k,v in values.items()]
 return ['/usr/bin/sudo','-n','/usr/bin/systemd-run','--unit='+ctx['unit'],'--property=Type=exec','--property=RemainAfterExit=yes','--property=MemoryMax=4294967296','--property=MemorySwapMax=0','--property=CPUQuota=100%','--property=CPUQuotaPeriodSec=100ms','--property=TasksMax=64','--property=TimeoutStopSec=5','--property=KillMode=control-group','--property=SendSIGKILL=yes','--property=FinalKillSignal=SIGKILL','--property=RuntimeMaxSec='+str(int(left(deadline,1200))),'--uid='+str(uid),'--gid='+str(gid),'--working-directory='+str(root),*sets,'--setenv=PATH=/usr/bin:/bin','--setenv=HOME='+__import__('pwd').getpwuid(uid).pw_dir,'/usr/bin/python3','-I','-S','-B',str(script),'--worker',str(spec),hashlib.sha256(Path(spec).read_bytes()).hexdigest()]
def query(ctx,deadline):
 own_unit(ctx['unit'],ctx['runId'],ctx['attempt'],ctx['nonce'])
 try:
  p=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/systemctl','show',ctx['unit'],'--property=MainPID','--property=ControlPID','--property=ActiveState','--property=SubState','--property=Result','--property=ExecMainCode','--property=ExecMainStatus'],capture_output=True,text=True,timeout=left(deadline,10))
  need(p.returncode==0,'OWN_QUERY_NONZERO_UNKNOWN');return dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
 except (OSError,subprocess.TimeoutExpired) as e:raise Hold('OWN_QUERY_UNKNOWN:'+type(e).__name__)
def terminal_before_retire(ctx,group,out,deadline):
 props=query(ctx,deadline);need(props.get('ActiveState') in ('active','inactive','failed') and props.get('SubState') in ('exited','dead','failed'),'OWN_TERMINAL_STATE_UNKNOWN');need(props.get('MainPID')=='0' and props.get('ControlPID')=='0','OWN_PIDS_NOT_ZERO')
 group=Path(group);need(group.is_dir() and group.name==ctx['unit'] and 'populated 0' in (group/'cgroup.events').read_text(),'OWN_POPULATION_UNKNOWN')
 # Keep cause before retiring the one owned transient unit; no --collect-before-cause.
 checkpoint=Path(out)/'terminal-before-retire.json';durable(checkpoint,{'terminalKnown':True,'ownedProcesses':0,'cause':props,'retirementPending':True})
 p=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/systemctl','stop',ctx['unit']],capture_output=True,text=True,timeout=left(deadline,5));need(p.returncode==0,'OWN_RETIREMENT_UNKNOWN')
 need(not group.exists() or 'populated 0' in (group/'cgroup.events').read_text(),'POST_RETIRE_POPULATION_UNKNOWN')
 durable(Path(out)/'release-marker.json',{'stopExit':0,'terminalCheckpointSha256':hashlib.sha256(checkpoint.read_bytes()).hexdigest(),'unitRemovalNotInferred':True})
