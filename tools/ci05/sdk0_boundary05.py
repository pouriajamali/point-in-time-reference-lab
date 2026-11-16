"""SOURCE ONLY. Pure identity projections; cannot be used as producer facts or runtime admission.
Future exact source/cap gate only: run in normal, -O and PYTHONOPTIMIZE=2 modes.
No subprocess/network/SDK/bootstrap or controller import; no runtime PASS fact emitted.
"""
from pathlib import Path
import argparse,copy,hashlib,importlib.util,json,os,sys,time
HERE=Path(__file__).resolve().parent

def need(v,m):
 if not v:raise ValueError(m)

def fixtures(g,p):
 # Deliberately incomplete raw fact shape: no outcome, caps, commands or native evidence.
 # Runtime admit rejects syntheticFixture and full schema rejects every projection.
 source={'head':'a'*40,'dirty':False,'contractSha256':p['sourceContractSha256'],'controllerHashes':{'ci_route05.py':'b'*64,'profile.json':'c'*64},'sourcePinTableSha256':'5'*64,'normalProfileSha256':'c'*64}
 ctx={'rid':'linux-x64','hostClass':p['hostClasses']['linux-x64']['name'],'runId':'200','jobId':'202','job':'verify','attempt':'1','runnerName':'consumer-identity-only','apiVerified':True,'runnerEnvironment':'github-hosted','container':False,'sourceCommit':'a'*40,'imageOS':'ubuntu24','imageVersion':'identity-image','osVersion':'24.04','architecture':'x86_64','uid':2001,'gid':2001}
 fact={'qualifiedOn':{'repository':'pouriajamali/data-admission-gate','rid':'linux-x64','hostClass':ctx['hostClass'],'uid':1001,'gid':1001,'runId':'100','job':'verify','attempt':'1','instanceId':'producer-identity-only'},'source':{'commit':'d'*40,'tree':'e'*40},'factType':'LinuxCIUbuntu24RID','archive':{'sha512':'f'*128},'tree':{'memberManifestSha256':'1'*64}}
 row={'syntheticFixture':True,'projectId':'05','acceptance':'INDEPENDENT_MANAGER_ACCEPTANCE','factBytesSha256':'2'*64,'factCanonicalSha256':g.canonical(fact),'producerCommit':'d'*40,'producerTree':'e'*40,'qualifiedOn':copy.deepcopy(fact['qualifiedOn']),'admittedFor':{'hostClass':ctx['hostClass'],'rid':'linux-x64','sdk':'11.0.100','runtime':'11.0.0','memberManifestSha256':'1'*64,'contractSha256':source['contractSha256'],'sourcePinTableSha256':source['sourcePinTableSha256'],'controllerSha256':'b'*64,'profileSha256':'c'*64},'imageVersions':['identity-image'],'consumerControlHashes':source['controllerHashes'].copy(),'archiveSha512':'f'*128,'treeSha256':'1'*64,'normalCatalogRole':'ADMITTED_IMMUTABLE_CONSUMER_INPUT'}
 proof={'runId':ctx['runId'],'jobId':ctx['jobId'],'sourceHashes':source['controllerHashes'].copy(),'uid':2001,'gid':2001,'memoryMax':4294967296,'cpuCores':1,'tasksMax':64,'swapMax':0,'heldChildMembershipBeforeResume':True}
 return {'ctx':ctx,'row':row,'fact':fact,'source':source,'proof':proof,'remaining':100}

def execute_case(g,p,case):
 v=fixtures(g,p)
 for path,value in case.get('set',[]):
  keys=path.split('.');obj=v
  for k in keys[:-1]:obj=obj[k]
  obj[keys[-1]]=value
 if case.get('refreshProjectionDigest'):
  v['row']['qualifiedOn']=copy.deepcopy(v['fact']['qualifiedOn']);v['row']['factCanonicalSha256']=g.canonical(v['fact'])
 route=case.get('route','identity')
 if route=='caps':return g.own_caps(v['proof'],v['ctx'],v['source'],v['remaining'],p)
 if route=='terminal':return g.terminal({'terminalKnown':False,'ownedProcesses':0})
 if route=='sdkroot':return g.sdk_root('/ambient/dotnet','/private')
 if route in ('missing','ambiguous','synthetic','unadmitted'):
  entries=[] if route=='missing' else [v['row']]* (2 if route=='ambiguous' else 1)
  state='UNADMITTED' if route=='unadmitted' else 'ACCEPTED_PER_HOST_CONSUMER_FACTS'
  # No callback returns an actual fact: synthetic/ambiguous cases must deny first.
  def forbidden(_):raise g.Hold('SYNTHETIC_PROJECTION_NOT_RAW_FACT')
  return g.admit({'state':state,'entries':entries},v['ctx'],v['source'],p,forbidden,{})
 result=g.identity_projection(v['row'],v['fact'],v['ctx'],v['source'],p)
 if route=='positive-uid':g.own_caps(v['proof'],v['ctx'],v['source'],100,p)
 if route=='positive-single':need(len([v['row']])==1 and v['row']['admittedFor']['rid']=='linux-x64','ONE_RID_ONLY')
 need(result['state']=='IDENTITY_BOUND_NOT_EXECUTION_PERMISSION','PROJECTION_ONLY')
 return result

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);a=parser.parse_args();start=time.monotonic()
 manager=json.loads((HERE/'manager-admission.json').read_bytes());p=HERE/'host_fact05.py';need(hashlib.sha256(p.read_bytes()).hexdigest()==manager['sourceHashes']['host_fact05.py'],'PURE_GUARD_SOURCE_PIN')
 spec=importlib.util.spec_from_file_location('identity_projection_only',p);g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
 profile=json.loads((HERE/'profile.json').read_bytes());raw=(HERE/'sdk0-cases.json').read_bytes();need(len(raw)<=16384,'FIXTURE_INPUT_CAP');cases=json.loads(raw);need(len(cases['negative'])==30 and len(cases['positive'])==3,'EXACT_CASES')
 for c in cases['negative']:
  try:execute_case(g,profile,c)
  except g.Hold:pass
  else:raise ValueError('NEGATIVE_NOT_REJECTED:'+c['id'])
 for c in cases['positive']:execute_case(g,profile,c)
 need(time.monotonic()-start<30,'MODE30_CAP');need(sys.flags.optimize in (0,1,2),'MODE_REQUIRED');a.out.mkdir(parents=True,exist_ok=False)
 receipt={'scope':'SYNTHETIC_IDENTITY_PROJECTIONS_ONLY_NOT_QUALIFICATION_OR_RUNTIME_AUTHORITY','modeOptimize':sys.flags.optimize,'rejections':30,'identityOnlyPositives':3,'sdkSpawns':0,'networkAttempts':0,'runtimeFactEmitted':False};raw=(json.dumps(receipt,indent=2)+'\n').encode();need(len(raw)<=8192,'RECEIPT_CAP')
 with (a.out/'receipt.json').open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
if __name__=='__main__':main()
