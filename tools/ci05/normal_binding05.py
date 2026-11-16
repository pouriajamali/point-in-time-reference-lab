"""Own05 adapter to immutable producer04 API. No authority from synthetic values."""
from pathlib import Path
import hashlib,importlib.util,json,os,sys,time,uuid
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
PROJECT='05'
REPOSITORY='pouriajamali/point-in-time-reference-lab'
SHARED_MODULE_SHA='d9c690d8c82825b018c04089c279036829d3baf2534c2634bba84910c415a37d'
SHARED_CATALOG_SHA='686c6c778f7841e6015fa401f3892b853df80e3341fbb5d02b27c682887c1c78'
SCHEMA_SHA='63e04fa5d270c87b93e6e1f4c38bfbcf336b950b39fe1854dc4e514f0661f14c'
FACT_SHA='757abf2d3dde65d10cd895cfc97eaeccb7fc11e8685b94ad046e6a8ec8829007'
ACCEPTANCE_SHA='0452e1f3b4f2662d57e9b273428bb37ab0c5a733551a92394ca2a4e8b9b4ac08'
CONTRACT_SHA='142dac81ae7f6e05f52319d3521d4825d5df028e37542b7623d16316ff7dd077'
MEMBERS_SHA='d411111d23492b4d101dd62851d1d1fedf3a4badc057d999aedc155ae4cc103a'
CTX_KEYS={'admission','capsEvidence','checkout','contract','controller','deadlineMonotonicNs','expectedSourceCommit','expectedSourceTree','profile','projectId','repository','rowStartedMonotonicNs','sourcePins','supervisorPID','supervisorStartIdentity'}
class Hold(ValueError):pass

def need(v,m):
 if not v:raise Hold(m)

def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def canonical(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def validate_binding_values(value):
 # Pure own changed-wiring values only. Never a native admission/producer fact.
 need(value.get('projectId')==PROJECT and value.get('repository')==REPOSITORY,'OWN05_IDENTITY')
 need(value.get('rid')=='linux-x64' and value.get('hostClass')=='GitHubHostedUbuntu24.04x64','WINDOWS_NORMAL_DENIED')
 need(value.get('moduleSha256')==SHARED_MODULE_SHA and value.get('catalogSha256')==SHARED_CATALOG_SHA and value.get('schemaSha256')==SCHEMA_SHA,'COMMON_SOURCE_IDENTITY')
 need(value.get('factSha256')==FACT_SHA and value.get('acceptanceSha256')==ACCEPTANCE_SHA,'PRODUCER_SCOPE_IDENTITY')
 need(value.get('contractSha256')==CONTRACT_SHA and value.get('controllerRelative')=='tools/ci05/ci_route05.py' and value.get('profileRelative')=='tools/ci05/normal-profile.json','OWN_TRACKED_BINDING')
 need(value.get('memoryMaxBytes')==4294967296 and value.get('tasksMax')==64 and value.get('swapMaxBytes')==0 and value.get('cpuMax')=='100000 100000','OWN05_ORIGINAL_CAPS')
 need(type(value.get('rowStartedMonotonicNs'))==int and type(value.get('deadlineMonotonicNs'))==int and 0<value['rowStartedMonotonicNs']<value['observedNowNs']<value['deadlineMonotonicNs'] and value['deadlineMonotonicNs']-value['rowStartedMonotonicNs']<=1200*10**9,'ORIGINAL_ROW_CLOCK')
 need(value.get('heldState')=='T' and value.get('retainedStartHandle') is True and value.get('membershipBeforeRelease') is True,'ACTUAL_STOPPED_HANDOFF_REQUIRED')
 need(value.get('logicalJob')=='verify' and bool(value.get('apiJobId')) and value.get('logicalJob')!=value.get('apiJobId'),'LOGICAL_AND_API_JOB_BOUNDARIES')
 need(value.get('sourcePinTableSha256')==value.get('observedSourcePinTableSha256') and isinstance(value.get('sourcePinTableSha256'),str) and len(value['sourcePinTableSha256'])==64,'COMPLETE_SOURCE_PIN_TABLE')
 return 'OWN05_WIRING_VALUES_ONLY_NOT_RUNTIME_PERMISSION'

def context(spec,held,caps_path,admission_path):
 ctx=spec['ctx'];source=spec['source'];profile=json.loads((HERE/'normal-profile.json').read_bytes());pins=json.loads((HERE/'source-pins.json').read_bytes())
 proof=json.loads(Path(caps_path).read_bytes());before=proof['beforeExec']
 value={'projectId':PROJECT,'repository':REPOSITORY,'rid':ctx['rid'],'hostClass':ctx['hostClass'],'moduleSha256':digest(ROOT/'tools/check_dotnet11.py'),'catalogSha256':digest(ROOT/'tools/sdk11-normal-inputs.lock.json'),'schemaSha256':digest(ROOT/'tools/dotnet11-host-qualification.schema.json'),'factSha256':digest(ROOT/'tools/sdk11-normal/accepted-linux-fact.json'),'acceptanceSha256':digest(ROOT/'tools/sdk11-normal/accepted-linux-acceptance.json'),'contractSha256':digest(HERE/'contract.json'),'controllerRelative':'tools/ci05/ci_route05.py','profileRelative':'tools/ci05/normal-profile.json','memoryMaxBytes':profile['memoryMaxBytes'],'tasksMax':profile['tasksMax'],'swapMaxBytes':profile['swapMaxBytes'],'cpuMax':str(profile['cpuQuotaMicros'])+' '+str(profile['cpuPeriodMicros']),'rowStartedMonotonicNs':ctx['rowStartedMonotonicNs'],'deadlineMonotonicNs':ctx['deadlineMonotonicNs'],'observedNowNs':time.monotonic_ns(),'heldState':before['state'],'retainedStartHandle':before['retainedStartHandle'],'membershipBeforeRelease':before['membershipBeforeRelease'],'logicalJob':ctx['job'],'apiJobId':ctx['jobId'],'sourcePinTableSha256':source['sourcePinTableSha256'],'observedSourcePinTableSha256':canonical(pins['sourcePins'])}
 validate_binding_values(value);need(proof==held and Path(caps_path).parent.stat().st_mode&0o777==0o700,'EXACT_HELD_EVIDENCE_SCOPE')
 result={'admission':str(admission_path),'capsEvidence':str(caps_path),'checkout':str(ROOT),'contract':str(HERE/'contract.json'),'controller':str(HERE/'ci_route05.py'),'deadlineMonotonicNs':ctx['deadlineMonotonicNs'],'expectedSourceCommit':source['head'],'expectedSourceTree':source['tree'],'profile':str(HERE/'normal-profile.json'),'projectId':PROJECT,'repository':REPOSITORY,'rowStartedMonotonicNs':ctx['rowStartedMonotonicNs'],'sourcePins':str(HERE/'source-pins.json'),'supervisorPID':spec['supervisorPID'],'supervisorStartIdentity':spec['supervisorStartIdentity']}
 need(set(result)==CTX_KEYS,'EXACT_SHARED_CONTEXT_KEYS');return result

def transport_input(spec,held,caps_path,admission_path):
 # Only reached by exact own gated controller AFTER actual held current evidence.
 ctx=context(spec,held,caps_path,admission_path);p=ROOT/'tools/check_dotnet11.py';need(digest(p)==SHARED_MODULE_SHA,'BYTE_IDENTICAL_SHARED_MODULE')
 entry=importlib.util.spec_from_file_location('producer04_shared_normal',p);module=importlib.util.module_from_spec(entry);entry.loader.exec_module(module)
 directory=Path(spec['normalDirectory']);need(directory.parent==Path(os.environ['RUNNER_TEMP']).resolve() and directory.name.startswith('sdk11-normal-05-'),'OWN_FRESH_ALLOCATION_BINDING')
 sdk,receipt=module.transport('linux-x64',directory,ctx)
 need(receipt['projectId']=='05' and receipt['SDKExecutions']==0 and receipt['producerFactSha256']==FACT_SHA and receipt['memberManifestSha256']==MEMBERS_SHA,'SHARED_TYPED_RETURN_BOUNDARY')
 return sdk,receipt,module,ctx
