"""Own05 finite Windows package DATA acquisition/verification. Shared evidence stays immutable."""
from pathlib import Path
import argparse,base64,ctypes,hashlib,json,os,re,shutil,sys,time,urllib.request,xml.etree.ElementTree as ET
PLAN_SHA='79168b613d6dee10eab557ac2ad68fe463c160a15f94855fbc217ec49e463ba6'
DESKTOP='microsoft.windowsdesktop.app.runtime.win-x64'
class Hold(RuntimeError):pass
def need(v,c):
 if not v:raise Hold(c)
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(p,x):
 raw=(json.dumps(x,indent=2)+'\n').encode()
 with Path(p).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def allowed_url(url,kind):
 if kind=='registration':expected='https://api.nuget.org/v3/registration5-semver1/'+DESKTOP+'/11.0.0.json';need(url==expected,'FIXED_REGISTRATION_URL')
 elif kind=='catalog':need(re.fullmatch(r'https://api[.]nuget[.]org/v3/catalog0/data/[0-9.]+/'+DESKTOP+r'[.]11[.]0[.]0[.]json',url) is not None,'FIXED_CATALOG_URL')
 elif kind=='body':need(url=='https://api.nuget.org/v3-flatcontainer/'+DESKTOP+'/11.0.0/'+DESKTOP+'.11.0.0.nupkg','FIXED_BODY_URL')
 else:raise Hold('FIXED_FETCH_KIND')
 return url
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise Hold('NO_REDIRECT')
def fetch(specpath,digest):
 need(sha(specpath)==digest,'FETCH_SPEC_IDENTITY');s=json.loads(Path(specpath).read_bytes());allowed_url(s['url'],s['kind']);need(sha(__file__)==s['sourceSHA256'],'FETCH_SOURCE_IDENTITY');end=s['deadlineMonotonicNs'];limit=s['limit'];start=time.monotonic();count=0;h256=hashlib.sha256();h512=hashlib.sha512();need(not Path(s['destination']).exists(),'FRESH_FETCH_OUTPUT')
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());request=urllib.request.Request(s['url'],headers={'User-Agent':'point-in-time-reference-own05-inputs','Accept-Encoding':'identity','Connection':'close'})
 with opener.open(request,timeout=max(.1,(end-time.monotonic_ns())/1e9)) as response,Path(s['destination']).open('xb') as f:
  need(response.status==200 and response.geturl()==s['url'],'HTTP_STATUS_OR_URL');cl=response.headers.get_all('Content-Length',[]);te=response.headers.get_all('Transfer-Encoding',[]);ce=response.headers.get_all('Content-Encoding',[]);need(len(cl)<=1 and len(te)<=1 and len(ce)<=1 and (not ce or ce[0].lower()=='identity'),'HTTP_HEADER_COUNTS_ENCODING');need((len(cl)==1 and not te and re.fullmatch(r'[0-9]+',cl[0]) and int(cl[0])<=limit) or (not cl and te==['chunked']),'HTTP_BOUNDED_FRAMING')
  while True:
   need(time.monotonic_ns()<end,'FETCH_ABSOLUTE_DEADLINE');chunk=response.read(65536)
   if not chunk:break
   count+=len(chunk);need(count<=limit,'FETCH_BODY_CAP');f.write(chunk);h256.update(chunk);h512.update(chunk)
  need(not cl or count==int(cl[0]),'HTTP_EXACT_LENGTH');f.flush();os.fsync(f.fileno());date=response.headers.get('Date')
 need(time.monotonic_ns()<end,'FETCH_ABSOLUTE_DEADLINE');write(s['receipt'],{'url':s['url'],'kind':s['kind'],'bytes':count,'sha256':h256.hexdigest(),'sha512':h512.hexdigest(),'seconds':time.monotonic()-start,'HTTPDate':date,'redirects':0,'retries':0})
def run(L,s,out,sdk,env,control,common,catalog):
 planpath=Path(__file__).with_name('local-native-plan05.json');need(sha(planpath)==PLAN_SHA,'PLAN_SOURCE');plan=json.loads(planpath.read_bytes());tools=Path(s['sharedTools']);D=L.load(tools/'curation_data_inspector.py','own05_native_data',plan['inspectorSHA256']);M=L.load(tools/'curation_linux_method.py','own05_native_pki_data',plan['methodSHA256']);V=L.load(tools/'curate_dotnet11_linux_inputs.py','own05_native_verify_format',plan['verifyParserSHA256']);handoff=plan['producerHandoff'];need(sha(handoff['path'])==handoff['sha256'],'COMMON_HANDOFF_BYTES');old=json.loads(Path(handoff['path']).read_bytes());pki=old['certificateLevelPKIReuse'];factref=pki['nativeFact'];need(sha(factref['path'])==factref['sha256'],'EXACT_NATIVE_CERTIFICATE_FACT');fact=json.loads(Path(factref['path']).read_bytes());now=int(time.time());need(0<=now-fact['currentCRL']['fixedCurrentUnixTime']<=86400,'EXISTING_NATIVE_CRL_WINDOW');need(fact['currentCRLNativeResults']['state']=='ACTUAL_SUPPLEMENTAL_CURRENT_CRL_COVERAGE_PASS','NATIVE_CRL_PASS_REQUIRED')
 for ref in pki['retainedNativeReports']:need(sha(ref['retainedRedactedLog']['path'])==ref['retainedRedactedLog']['sha256'] and ref['recordedNativeExit']==0,'NATIVE_REPORT_PROVENANCE')
 for key in ('reusedSignatureReceipt','reusedVerifyLog'):need(sha(plan[key]['path'])==plan[key]['sha256'],'EXACT_REUSED_SIGNATURE_PROOF')
 original=Path(plan['reusedVerifyLog']['path']).read_bytes();feed=out/'feed';feed.mkdir();packages=[];gets=[];blobs=[]
 def tick():need(time.monotonic_ns()<s['deadlineMonotonicNs']-20*10**9,'ORIGINAL_PHASE_DEADLINE')
 def get(url,kind,dest,limit,seconds):
  tick();need(len(gets)<3,'FINITE_THREE_GETS');spec={'url':allowed_url(url,kind),'kind':kind,'destination':str(dest),'receipt':str(dest)+'.http.json','limit':limit,'deadlineMonotonicNs':min(s['deadlineMonotonicNs']-20*10**9,time.monotonic_ns()+int(seconds*1e9)),'sourceSHA256':sha(__file__)};sp=out/(kind+'-request.json');write(sp,spec);control.run([sys.executable,'-I','-S','-B',str(Path(__file__).resolve()),'--fetch',str(sp),sha(sp)],cwd=L.ROOT,env=env,timeout=seconds+2,evidence=out/('http-'+kind));gets.append(json.loads(Path(spec['receipt']).read_bytes()));return dest
 for index,row0 in enumerate(plan['packages']):
  tick();row=dict(row0);id=row['id'];dest=feed/(id.lower()+'.11.0.0.nupkg')
  if 'existingBody' in row:
   src=Path(row['existingBody']);need(src.stat().st_size==row['declaredBytes'] and sha(src)==row['rawSHA256'],'EXACT_REUSED_RAW_BODY');shutil.copyfile(src,dest);normalized=row['normalizedNuGetContentHash'];a=original.index(('Verifying '+id+'.11.0.0').encode());z=original.index(("Successfully verified package '"+id+".11.0.0'.").encode(),a);block=original[a:z+len(("Successfully verified package '"+id+".11.0.0'.").encode())];verified=V.content_hash(block,id,'11.0.0',0,{'id':id,'version':'11.0.0','sha256':sha(dest)});need(verified['normalizedNuGetContentHash']==normalized,'REUSED_NORMALIZED_HASH');signature={'reused':True,'receipt':plan['reusedSignatureReceipt'],'normalized':verified}
  else:
   metadataRefs=row['reusedMetadata'];need(all(sha(ref['path'])==ref['sha256'] for ref in metadataRefs.values()),'EXACT_EXISTING_DESKTOP_METADATA');registration=json.loads(Path(metadataRefs['registration']['path']).read_bytes());allowed_url(registration['catalogEntry'],'catalog');metadata=json.loads(Path(metadataRefs['catalog']['path']).read_bytes());need(metadata['id'].lower()==DESKTOP and metadata['version']=='11.0.0' and metadata['packageHashAlgorithm']=='SHA512' and metadata['licenseExpression']=='MIT' and 0<metadata['packageSize']<=plan['archiveBytesMax'],'DESKTOP_CATALOG_IDENTITY');row['declaredBytes']=metadata['packageSize'];row['catalogDeclaredSHA512']=metadata['packageHash'];get(row['url'],'body',dest,row['declaredBytes'],45);need(dest.stat().st_size==row['declaredBytes'],'DESKTOP_DECLARED_LENGTH');normalized=None;signature=None
  with dest.open('rb') as f:raw512=hashlib.file_digest(f,'sha512').digest()
  need(base64.b64encode(raw512).decode()==row.get('rawSHA512Base64',row['catalogDeclaredSHA512']),'OFFICIAL_RAW_BODY_IDENTITY');directory=out/('package-'+str(index));directory.mkdir();members=[];retained=[]
  def emit(x):members.append(x);need(len(members)<=10000,'NATIVE_MEMBER_COUNT')
  def retain(i,kind,raw):
   path=directory/('original-'+str(i)+'-'+kind+'.data');path.write_bytes(raw);r={'path':str(path),'kind':kind,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'memberIndex':i};retained.append(r);return r
  profile={'rawSingleMaxBytes':134217728,'membersPerArchiveMax':10000,'expandedStreamSingleMaxBytes':536870912,'CMSBytesPerPackageMax':2097152};inspection=D.inspect_package(dest,profile,tick,emit,retain,expected={'id':id,'version':'11.0.0'});write(directory/'members.json',members);cms=next(x for x in retained if x['kind']=='cms');blob=Path(cms['path']).read_bytes();blobs.append(blob);certs,roles=M.cms_roles([blob],pki['exactCertificatePoolSHA256']);need(roles==[fact['currentCRL']['roles'][0]],'EXACT_EXISTING_CERTIFICATE_ROLES')
  if signature is None:
   config=out/'NuGet.Config';config.write_text('<configuration><config><add key="signatureValidationMode" value="require"/></config><packageSources><clear/></packageSources><trustedSigners><clear/><repository name="nuget.org" serviceIndex="https://api.nuget.org/v3/index.json"><certificate fingerprint="'+plan['expectedRepositorySHA256']+'" hashAlgorithm="SHA256" allowUntrustedRoot="false"/></repository></trustedSigners></configuration>',encoding='utf-8');env.update(NUGET_CERT_REVOCATION_MODE='online',NUGET_PACKAGES=str(out/'packages'),NUGET_HTTP_CACHE_PATH=str(out/'http'),NUGET_SCRATCH=str(out/'scratch'),NUGET_PLUGINS_CACHE_PATH=str(out/'plugins'),NUGET_CLI_LANGUAGE='en-us',DOTNET_CLI_UI_LANGUAGE='en-US');common.verify_tree(sdk,catalog['members'],'win-x64');tick();rec=control.run([str(sdk/'dotnet.exe'),'nuget','verify','--all',str(dest),'--configfile',str(config),'--verbosity','detailed','--certificate-fingerprint',plan['expectedAuthorSHA256']],cwd=L.ROOT,env=env,timeout=min(45,(s['deadlineMonotonicNs']-time.monotonic_ns())/1e9-20),evidence=out/'verify-desktop');stdout=(out/'verify-desktop/stdout.log').read_bytes();verified=V.content_hash(stdout,id,'11.0.0',rec['exitCode'],{'id':id,'version':'11.0.0','sha256':sha(dest)});normalized=verified['normalizedNuGetContentHash'];signature={'reused':False,'normalized':verified,'processSHA256':sha(out/'verify-desktop/process.json'),'revocationMode':'online','trustRootOrPolicyChanges':False}
  nuspec=ET.fromstring(Path(next(x for x in retained if x['kind']=='nuspec')['path']).read_bytes()).find('{*}metadata');license=nuspec.find('{*}license');need(license is not None and license.get('type')=='expression' and license.text=='MIT' and nuspec.findtext('{*}copyright'),'ACTUAL_NATIVE_LICENSE_COPYRIGHT');notices=[dict(x,originalMember=members[x['memberIndex']]['path']) for x in retained if x['kind']=='notice'];need(any(Path(x['originalMember']).name.lower().startswith('license') for x in notices),'ORIGINAL_NATIVE_FULL_LICENSE');packages.append({'id':id,'version':'11.0.0','rawArchive':{'path':str(dest),'bytes':dest.stat().st_size,'sha256':sha(dest),'sha512':raw512.hex()},'normalizedNuGetContentHash':normalized,'signature':signature,'membersFile':str(directory/'members.json'),'membersSHA256':sha(directory/'members.json'),'CMS':cms,'certificateRoles':roles[0],'license':license.text,'copyright':nuspec.findtext('{*}copyright'),'originalData':retained,'notices':notices,'inspection':inspection});write(directory/'RESULT.json',packages[-1])
 certs,roles=M.cms_roles(blobs,pki['exactCertificatePoolSHA256']);oldcrl=fact['currentCRL'];anchors={chain[-1]:certs[chain[-1]] for category in ('codeCoverage','timestampCoverage') for chain in oldcrl[category]['chains'].values()};crls=[]
 for ref in pki['usedCurrentCRLOriginals']:need(sha(ref['path'])==ref['sha256'],'EXACT_CRL_BYTES');crls.append(M.crl_data(Path(ref['path']).read_bytes(),int(time.time())))
 for leaves,key in (([M.AUTHOR,M.REPOSITORY],'codeCoverage'),(sorted({v for r in roles for v in r['timestamp']}),'timestampCoverage')):
  coverage=M.coverage(certs,anchors,crls,leaves,int(time.time()));need(coverage['chains']==oldcrl[key]['chains'] and coverage['certificateToCRLSHA256']==oldcrl[key]['certificateToCRLSHA256'],'EXACT_FRESH_CRL_MAP')
 common.verify_tree(sdk,catalog['members'],'win-x64',full=True);write(out/'RESULT.json',{'state':'OWN05_THREE_WINDOWS_NATIVE_RAW_SIGNATURE_NORMALIZED_NOTICES_VERIFIED','sourceCommit':s['HEAD'],'packages':packages,'newGETs':gets,'newSDKVerifyCommands':1,'healthySignatureCommandsReplayed':0,'certificateCurrentProofReused':pki,'currentDataWindowCheckedAtUnix':int(time.time()),'advisory':'Exact closure scan required in curation restore; not omitted or disabled.','otherConsumerAdmission':False,'SDKGlobalReadiness':False,'Actions':0})
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--fetch',nargs=2,required=True);a=p.parse_args();fetch(*a.fetch)
