"""Finite SDK0 source-value test for only changed own05 common API wiring.
Extracts the selected pure function AST; does not import own controller/shared module.
"""
from pathlib import Path
import ast,copy,hashlib,json,sys
HERE=Path(__file__).resolve().parent
source=(HERE/'normal_binding05.py').read_bytes().decode('utf-8');tree=ast.parse(source)
constants={'PROJECT','REPOSITORY','SHARED_MODULE_SHA','SHARED_CATALOG_SHA','SCHEMA_SHA','FACT_SHA','ACCEPTANCE_SHA','CONTRACT_SHA'}
selected=[n for n in tree.body if (isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id in constants for x in n.targets)) or (isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in ('Hold','need','validate_binding_values'))]
namespace={};exec(compile(ast.Module(body=selected,type_ignores=[]),'OWN05_PURE_WIRING_VALUES_ONLY','exec'),namespace)
validate=namespace['validate_binding_values'];Hold=namespace['Hold']
base={'projectId':'05','repository':'pouriajamali/point-in-time-reference-lab','rid':'linux-x64','hostClass':'GitHubHostedUbuntu24.04x64','moduleSha256':'d9c690d8c82825b018c04089c279036829d3baf2534c2634bba84910c415a37d','catalogSha256':'686c6c778f7841e6015fa401f3892b853df80e3341fbb5d02b27c682887c1c78','schemaSha256':'63e04fa5d270c87b93e6e1f4c38bfbcf336b950b39fe1854dc4e514f0661f14c','factSha256':'757abf2d3dde65d10cd895cfc97eaeccb7fc11e8685b94ad046e6a8ec8829007','acceptanceSha256':'0452e1f3b4f2662d57e9b273428bb37ab0c5a733551a92394ca2a4e8b9b4ac08','contractSha256':'142dac81ae7f6e05f52319d3521d4825d5df028e37542b7623d16316ff7dd077','controllerRelative':'tools/ci05/ci_route05.py','profileRelative':'tools/ci05/normal-profile.json','memoryMaxBytes':4294967296,'tasksMax':64,'swapMaxBytes':0,'cpuMax':'100000 100000','rowStartedMonotonicNs':1000000000,'observedNowNs':1100000000,'deadlineMonotonicNs':1201000000000,'heldState':'T','retainedStartHandle':True,'membershipBeforeRelease':True,'logicalJob':'verify','apiJobId':'22222','sourcePinTableSha256':'a'*64,'observedSourcePinTableSha256':'a'*64}
changes=[('foreign-owner','projectId','06'),('foreign-repository','repository','pouriajamali/data-admission-gate'),('windows-normal-denied','rid','win-x64'),('common-module-bytes','moduleSha256','0'*64),('normal-catalog-bytes','catalogSha256','0'*64),('frozen-schema-bytes','schemaSha256','0'*64),('producer-fact-bytes','factSha256','0'*64),('producer-authority-bytes','acceptanceSha256','0'*64),('own-contract-bytes','contractSha256','0'*64),('not-main-controller','controllerRelative','tools/ci05/native_adapter05.py'),('foreign-profile','profileRelative','tools/ci05/profile.json'),('producer-cpu-borrowed','cpuMax','200000 100000'),('not-stopped','heldState','S'),('no-retained-handle','retainedStartHandle',False),('deadline-reset','deadlineMonotonicNs',1201000000001),('numeric-job-is-not-logical','logicalJob','22222'),('partial-or-wrong-source-table','sourcePinTableSha256','b'*64)]
rows=[]
for case,key,value in changes:
 data=copy.deepcopy(base);data[key]=value
 try:validate(data)
 except Hold as e:rows.append({'case':case,'denied':True,'reason':str(e)})
 else:raise ValueError('CHANGED_WIRING_NEGATIVE_ACCEPTED:'+case)
for name,updates in [('different-current-api-job',{'apiJobId':'99999'}),('equal-complete-table-values',{'sourcePinTableSha256':'c'*64,'observedSourcePinTableSha256':'c'*64})]:
 data=dict(base,**updates)
 if validate(data)!='OWN05_WIRING_VALUES_ONLY_NOT_RUNTIME_PERMISSION':raise ValueError('POSITIVE_VALUE_ONLY')
 rows.append({'case':name,'identityOnly':True})
receipt={'scope':'NEW_OWN05_PURE_WIRING_VALUES_ONLY_NO_FACT_OR_NATIVE_AUTHORITY','optimize':sys.flags.optimize,'negative':17,'positiveValueControls':2,'cases':rows,'sourceSha256':hashlib.sha256(source.encode()).hexdigest(),'functionASTSha256':hashlib.sha256(ast.dump(next(n for n in selected if isinstance(n,ast.FunctionDef) and n.name=='validate_binding_values')).encode()).hexdigest(),'candidateControllerImports':0,'sharedModuleImports':0,'networkAttempts':0,'SDKSpawns':0,'nativeProbes':0,'runtimeFactEmitted':False};print(json.dumps(receipt,separators=(',',':')))
