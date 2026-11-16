"""Pure typed identity guard bound to producer04 canonical schema; no launches."""
import hashlib,json,re
SCHEMA_SHA256='63e04fa5d270c87b93e6e1f4c38bfbcf336b950b39fe1854dc4e514f0661f14c'
class Hold(ValueError):pass

def need(v,m):
 if not v:raise Hold(m)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def canonical(value):return sha(json.dumps(value,sort_keys=True,separators=(',',':')).encode())

def validate(value,s,path='$'):
 # Closed validator for only the keywords present in the pinned producer schema.
 if s is False:raise Hold('SCHEMA_FORBIDDEN:'+path)
 known={'$schema','$id','$defs','title','type','const','enum','required','properties','additionalProperties','pattern','minLength','maxLength','minimum','maximum','exclusiveMinimum','minItems','maxItems','prefixItems','items'}
 need(set(s)<=known,'UNREVIEWED_SCHEMA_KEYWORD')
 types={'object':lambda x:isinstance(x,dict),'array':lambda x:isinstance(x,list),'string':lambda x:isinstance(x,str),'integer':lambda x:type(x)==int,'number':lambda x:type(x) in (int,float),'boolean':lambda x:type(x)==bool,'null':lambda x:x is None}
 if 'type' in s:need(any(types[z](value) for z in (s['type'] if isinstance(s['type'],list) else [s['type']])),'SCHEMA_TYPE:'+path)
 if 'const' in s:need(value==s['const'] and not (type(value)==bool and type(s['const'])==int),'SCHEMA_CONST:'+path)
 if 'enum' in s:need(value in s['enum'],'SCHEMA_ENUM:'+path)
 if isinstance(value,dict):
  need(set(s.get('required',[]))<=set(value),'SCHEMA_REQUIRED:'+path);props=s.get('properties',{})
  if s.get('additionalProperties') is False:need(set(value)<=set(props),'SCHEMA_EXTRA:'+path)
  for k,v in value.items():
   if k in props:validate(v,props[k],path+'.'+k)
 if isinstance(value,str):
  need(s.get('minLength',0)<=len(value)<=s.get('maxLength',len(value)),'SCHEMA_LENGTH:'+path)
  if 'pattern' in s:need(re.search(s['pattern'],value) is not None,'SCHEMA_PATTERN:'+path)
 if type(value) in (int,float):
  need(s.get('minimum',value)<=value<=s.get('maximum',value),'SCHEMA_RANGE:'+path)
  if 'exclusiveMinimum' in s:need(value>s['exclusiveMinimum'],'SCHEMA_MIN:'+path)
 if isinstance(value,list):
  need(s.get('minItems',0)<=len(value)<=s.get('maxItems',len(value)),'SCHEMA_COUNT:'+path);prefix=s.get('prefixItems',[])
  for i,v in enumerate(value):
   sub=prefix[i] if i<len(prefix) else s.get('items',{})
   validate(v,sub,path+'['+str(i)+']')

def identity(row,fact,ctx,source,profile,schema):
 rid=ctx.get('rid');need(rid in profile['hostClasses'],'RID_NOT_SUPPORTED');host=profile['hostClasses'][rid]
 need(ctx.get('hostClass')==host['name'],'CI_HOST_CLASS_REQUIRED');target=row['admittedFor']
 validate(fact,schema);validate(target,schema['$defs']['consumerAdmission']['properties']['admittedFor'])
 expected=profile['artifactPins'][rid];need(fact['archive']['sha512']==expected['sha512'] and fact['archive']['bytes']==expected['bytes'] and fact['archive']['url']==expected['url'] and fact['tree']['memberManifestSha256']==expected['manifestSha256'],'OFFICIAL_PRODUCER_INPUT_PINS')
 need(fact['qualifiedOn']['uid']==fact['caps']['uid'] and fact['qualifiedOn']['gid']==fact['caps']['gid'],'PRODUCER_ACTUAL_UID_CAP_BINDING');need(sorted(x['optimize'] for x in fact['denials'])==[0,1,2],'PRODUCER_DENIAL_MODES')
 return identity_projection(row,fact,ctx,source,profile)

def identity_projection(row,fact,ctx,source,profile):
 # Pure projected-identity test seam. Does not validate raw facts or authorize execution.
 rid=ctx.get('rid');need(rid in profile['hostClasses'],'RID_NOT_SUPPORTED');host=profile['hostClasses'][rid];target=row['admittedFor']
 need(ctx.get('hostClass')==host['name'],'CI_HOST_CLASS_REQUIRED')
 need(row.get('projectId')=='05' and row.get('acceptance')=='INDEPENDENT_MANAGER_ACCEPTANCE','FACT_NOT_ADMITTED')
 need(canonical(fact)==row.get('factCanonicalSha256'),'FACT_BYTES_MISMATCH')
 producer=fact['qualifiedOn'];execution={'runId':ctx['runId'],'job':ctx['job'],'attempt':ctx['attempt'],'instanceId':ctx['runnerName']}
 need(producer['repository']=='pouriajamali/data-admission-gate' and fact['source']['commit']==row['producerCommit'] and fact['source']['tree']==row['producerTree'],'PRODUCER_SOURCE_MISMATCH')
 need(producer==row['qualifiedOn'],'PRODUCER_QUALIFIED_ON_MISMATCH')
 need(fact['factType']=={'win-x64':'WindowsCIServer2025RID','linux-x64':'LinuxCIUbuntu24RID'}[rid] and producer['rid']==rid and producer['hostClass']==host['name'],'FACT_HOST_RID_MISMATCH')
 need(target['rid']==rid and target['hostClass']==host['name'],'ADMITTED_HOST_RID_MISMATCH')
 # Historical qualifiedOn IDs/UID are never compared to current consumer IDs/UID.
 need(ctx.get('apiVerified') is True and ctx.get('runnerEnvironment')=='github-hosted' and ctx.get('container') is False,'ACTUAL_GITHUB_HOST_REQUIRED')
 need(ctx.get('imageOS')==host['imageOS'] and ctx.get('imageVersion') in row.get('imageVersions',[]),'IMAGE_VERSION_NOT_ADMITTED')
 if rid=='win-x64':need(ctx.get('kernelBuild')==26100 and ctx.get('productType')==3,'SERVER2025_KERNEL_REQUIRED')
 else:need(ctx.get('osVersion')=='24.04' and ctx.get('architecture')=='x86_64','UBUNTU24_REQUIRED')
 need(ctx.get('sourceCommit')==source.get('head') and source.get('dirty') is False,'CURRENT_SOURCE_MISMATCH')
 need(source.get('contractSha256')==target['contractSha256']==profile['sourceContractSha256'],'OWN_CONTRACT_MISMATCH')
 need(source.get('controllerHashes')==row.get('consumerControlHashes') and target['sourcePinTableSha256']==source['sourcePinTableSha256'],'OWN_CONTROL_PIN_TABLE')
 need(target['controllerSha256']==source['controllerHashes']['ci_route05.py'] and target['profileSha256']==source['normalProfileSha256'],'OWN_CONTROLLER_PROFILE')
 need(fact['archive']['sha512']==row['archiveSha512'] and fact['tree']['memberManifestSha256']==row['treeSha256']==target['memberManifestSha256'],'ARCHIVE_TREE_IDENTITY_MISMATCH')
 need(row.get('normalCatalogRole')=='ADMITTED_IMMUTABLE_CONSUMER_INPUT','QUALIFICATION_ONLY_CATALOG_FORBIDDEN')
 return {'state':'IDENTITY_BOUND_NOT_EXECUTION_PERMISSION','qualifiedOn':producer,'currentConsumer':execution,'allRidsRequiredForDelivery':True}

def own_caps(proof,ctx,source,remaining,profile):
 need(proof.get('runId')==ctx.get('runId') and proof.get('jobId')==ctx.get('jobId'),'OWN_CONTROL_CURRENT_JOB_REQUIRED')
 need(proof.get('sourceHashes')==source.get('controllerHashes'),'OWN_CONTROL_SOURCE_MISMATCH')
 if ctx['rid']=='linux-x64':need(type(proof.get('uid'))==int and proof['uid']>0 and proof['uid']==ctx.get('uid') and proof.get('gid')==ctx.get('gid')>0,'ACTUAL_NONROOT_UID_GID_REQUIRED')
 else:need(proof.get('nativeWindows') is True,'OWN_WINDOWS_REQUIRED')
 c=profile['caps'];need(proof.get('memoryMax')==c['memoryMax'] and 0<proof.get('cpuCores',0)<=c['cpuMax'],'OWN_MEMORY_CPU_CAPS')
 need(proof.get('tasksMax')==64 and (ctx['rid']!='linux-x64' or proof.get('swapMax')==0),'OWN_TASK_SWAP_CAPS')
 need(proof.get('heldChildMembershipBeforeResume') is True,'OWN_HELD_CHILD_REQUIRED');need(remaining>profile['stageSeconds']['terminalExistingUpload'],'ROW_ENVELOPE_EXHAUSTED')

def sdk_root(root,private):
 need(root.startswith(private+'/') and root!=private and '..' not in root.split('/'),'AMBIENT_SDK_ROOT_FORBIDDEN')

def terminal(proof):need(proof.get('terminalKnown') is True and proof.get('ownedProcesses')==0,'OWN_TERMINAL_UNKNOWN')

def admit(catalog,ctx,source,profile,load_fact,schema):
 need(catalog.get('state')=='ACCEPTED_PER_HOST_CONSUMER_FACTS','FACT_NOT_ADMITTED')
 rows=[r for r in catalog['entries'] if r.get('hostPolicy',r.get('admittedFor',{})).get('rid')==ctx['rid'] and r.get('hostPolicy',r.get('admittedFor',{})).get('hostClass')==ctx['hostClass']]
 need(len(rows)==1,'FACT_NOT_ADMITTED');row=rows[0];need(not row.get('syntheticFixture'),'SYNTHETIC_FACT_NOT_AUTHORITY');fact=load_fact(row);row=dict(row)
 if 'hostPolicy' in row:
  row['admittedFor']=dict(row['hostPolicy'],contractSha256=source['contractSha256'],sourcePinTableSha256=source['sourcePinTableSha256'],controllerSha256=source['controllerHashes']['ci_route05.py'],profileSha256=source['normalProfileSha256']);row['consumerControlHashes']=source['controllerHashes'];row['acceptance']='INDEPENDENT_MANAGER_ACCEPTANCE'
 return row,identity(row,fact,ctx,source,profile,schema)


def handshake(row,identity,own_caps_sha,schema):
 value={'schema':'sdk11-consumer-host-admission/v1','state':'ADMITTED_EXACT_SUPPORTED_HOST_CLASS','projectId':'05','producerFactSha256':row['factBytesSha256'],'admittedFor':row['admittedFor'],'currentExecution':dict(identity['currentConsumer'],ownCapsEvidenceSha256=own_caps_sha),'identityRule':'QUALIFIED_ON_IS_HISTORICAL_PRODUCER_INSTANCE_CURRENT_CONSUMER_JOB_MAY_DIFFER'}
 validate(value,schema['$defs']['consumerAdmission']);return value
