"""Fixed own05 full net11 lock curation from immutable accepted bodies; no product run."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,time,xml.etree.ElementTree as ET
PLAN_SHA='f53c01818fa7cbc38e751302675bb54dc6b4efae0edc3d11807fbd7e79c3a9f4'
NATIVE_HELPER_SHA='0e3173463ac6bf762d89e9b8c18835b5237529e1d3015da5b7c36ae42b898aeb'
PRUNED={'microsoft.extensions.dependencyinjection.abstractions','microsoft.extensions.logging.abstractions'}
def run(L,s,out,sdk,env,control,common,catalog):
 root=L.ROOT;base=root.parents[1];write=L.write;planpath=Path(__file__).with_name('local-managed-inputs05.json');L.need(L.sha(planpath)==PLAN_SHA,'MANAGED_PLAN_SOURCE');plan=L.read(planpath);old=base/'state/acquisition-raw-cache-01/outputs/receipts/A-ACQUISITION-RECEIPT.json';sig=base/'state/execution-evidence/nuget-signature-verification.json';L.need(L.sha(old)==plan['oldAcquisitionReceiptSHA256'] and L.sha(sig)==plan['oldSignatureReceiptSHA256'],'HISTORICAL_REUSE_IDENTITY');L.need(L.read(sig)['status']=='ALL28_SDK_NUGET_VERIFY_SUCCESS','HISTORICAL_VERIFY_SCOPE');L.need(all(L.sha(p['priorVerifyLog']['path'])==p['priorVerifyLog']['sha256'] and p['priorVerifyLog']['recordedExitCode']==0 for p in plan['managed']),'EXACT_PRIOR_SIGNER_LOGS')
 feed=out/'feed';feed.mkdir();inputs=[];selected={}
 for p in plan['managed']:
  src=base/'state/acquisition-raw-cache-01/archives'/p['filename'];L.need(src.is_file() and not src.is_symlink() and src.stat().st_size==p['bytes'],'EXISTING_MANAGED_BODY')
  with src.open('rb') as f:L.need(hashlib.file_digest(f,'sha512').hexdigest()==p['rawSHA512'],'MANAGED_RAW_IDENTITY')
  shutil.copyfile(src,feed/p['filename']);inputs.append(dict(p,source=str(src)));selected[p['id'].lower()]=p['version']
 tools=Path(s['sharedTools']);nativepath=tools/'sdk11-native-inputs.lock.json';L.need(L.sha(nativepath)==plan['nativeCatalogSHA256'],'NATIVE_CATALOG_IDENTITY');native=L.read(nativepath);nativebase=base.parent/'data-admission-gate/outputs/tech-refresh-m0-20261114/own04-common-normal-wiring-db748-sdk0-20261116/private-cas-local-20261116/curation-stage-a-20261116/STAGE-B-DISCOVERY-ONCE/raw'
 for p in native['packages']:
  name=p['id'].lower()+'.11.0.0.nupkg';src=(Path('C:/Users/Office/Documents/ChatGPT/Git Projects/frl01-local-inputs-20261117/feed')/name) if p['id']=='Microsoft.NETCore.App.Runtime.linux-x64' else nativebase/name;L.need(src.stat().st_size==p['rawSignedArchive']['bytes'],'LINUX_NATIVE_LENGTH')
  with src.open('rb') as f:L.need(hashlib.file_digest(f,'sha512').hexdigest()==p['rawSignedArchive']['sha512'],'LINUX_NATIVE_BODY')
  shutil.copyfile(src,feed/name);selected[p['id'].lower()]='11.0.0'
 nr=base/'outputs/tech-refresh-m0-20261114/local05-20261117/native-03/RESULT.json';win=L.read(nr);ctx=L.read(nr.parent/'context.json');L.need(win['state']=='OWN05_THREE_WINDOWS_NATIVE_RAW_SIGNATURE_NORMALIZED_NOTICES_VERIFIED' and L.read(nr.parent/'LEASE-RELEASED.json')['ownedWorkerTerminal'],'ACTUAL_OWN_NATIVE_RECEIPT');helper=subprocess.check_output(['git','show',ctx['HEAD']+':tools/ci05/local_native05.py'],cwd=root,timeout=10);L.need(hashlib.sha256(helper).hexdigest()==NATIVE_HELPER_SHA and win['sourceCommit']==ctx['HEAD'],'NATIVE_SOURCE_PROVENANCE');L.need(0<=time.time()-win['certificateCurrentProofReused']['nativeVerifiedAtUnix']<=86400,'CURRENT_PKI_SNAPSHOT_WINDOW')
 for p in win['packages']:
  a=p['rawArchive'];src=Path(a['path']);L.need(L.sha(src)==a['sha256'] and src.stat().st_size==a['bytes'],'WINDOWS_NATIVE_EXACT_BODY');shutil.copyfile(src,feed/(p['id'].lower()+'.11.0.0.nupkg'));selected[p['id'].lower()]='11.0.0'
 nativePlan=L.read(Path(__file__).with_name('local-native-plan05.json'));handoffRef=nativePlan['producerHandoff'];L.need(L.sha(handoffRef['path'])==handoffRef['sha256'],'WIN_HOST_COMMON_HANDOFF');handoff=L.read(handoffRef['path']);host=next(p for p in handoff['newPackages'] if p['id']=='Microsoft.NETCore.App.Host.win-x64');hostRaw=host['rawSignedArchive'];hostSource=Path(hostRaw['path']);L.need(hostSource.stat().st_size==hostRaw['bytes'] and L.sha(hostSource)==hostRaw['sha256'],'WIN_HOST_ORIGINAL_BODY');hostPath=feed/'microsoft.netcore.app.host.win-x64.11.0.0.nupkg';shutil.copyfile(hostSource,hostPath);selected[host['id'].lower()]='11.0.0';M=L.load(tools/'curation_linux_method.py','own05_curate_pki_data','e882af75dc56a5a0f9eb9b4101f2ccaf88141fa3ced9037ea0fd7b1eb357ed74');cms=next(v for v in host['originalData'] if v['kind']=='cms');L.need(L.sha(cms['path'])==cms['sha256'],'WIN_HOST_CMS_BYTES');hostCerts,hostRoles=M.cms_roles([Path(cms['path']).read_bytes()],win['certificateCurrentProofReused']['exactCertificatePoolSHA256']);L.need(hostRoles==[win['packages'][0]['certificateRoles']],'WIN_HOST_EXISTING_CERTIFICATE_ROLES')
 write(out/'reused-inputs.json',{'managed':inputs,'nativeLinuxCatalogSHA256':L.sha(nativepath),'nativeWindowsReceiptSHA256':L.sha(nr),'qualificationReplayed':False,'newNetworkBodies':0,'feedPackages':len(list(feed.iterdir()))})
 source=out/'source';source.mkdir()
 for name in subprocess.check_output(['git','ls-files','-z'],cwd=root,timeout=10).decode().split('\0'):
  if name:dst=source/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/name,dst)
 V=L.load(tools/'curate_dotnet11_linux_inputs.py','own05_curation_advisory_adapter','9e199eadd9d399dbb940f635a64d57e11ddd37f91e5bad15eba5bd6cd3f15216');A=L.load(tools/'curation_advisory_source04.py','own05_advisory_data','1e6c0de6defcd72f948bad758b587566610cee5eb1ab3272e0a44b5415074d86');snap={}
 for rec in native['completeMetadataSnapshots']:
  if '/vulnerability-' in rec['file'] and not rec['file'].endswith('.wire'):
   path=tools/rec['file'];L.need(L.sha(path)==rec['sha256'],'COMPLETE_ADVISORY_SNAPSHOT_BYTES');snap[Path(rec['file']).name]=json.loads(path.read_bytes())
 index=snap['vulnerability-index.json'];pages={p['@id']:A.vulnerability_page_entries(snap['vulnerability-page-'+str(i)+'.json']) for i,p in enumerate(index)};matches=[]
 for page in pages.values():
  for id,version in selected.items():
   for issue in page.get(id,[]):
    if A.in_range(version,issue['versions']):matches.append({'id':id,'version':version,'issue':issue})
 L.need(not matches,'ACTUAL_CLOSURE_CURRENT_ADVISORY_MATCH');write(out/'advisory-snapshot-closure.json',{'state':'NO_SELECTED_NUGET_ADVISORY_MATCH','selected':selected,'sourceCatalogSHA256':L.sha(nativepath),'completePages':[x['@id'] for x in index],'snapshotObservedAtUnix':win['certificateCurrentProofReused']['nativeVerifiedAtUnix'],'readAtUnix':int(time.time()),'maxAgeSeconds':86400,'generalSecurityCertification':False});server,thread,dispatcher,port=V._start_adapter({},index,pages);rows=[];config=out/'NuGet.Config';e=ET.Element('configuration');c=ET.SubElement(e,'config');ET.SubElement(c,'add',{'key':'signatureValidationMode','value':'require'});ps=ET.SubElement(e,'packageSources');ET.SubElement(ps,'clear');ET.SubElement(ps,'add',{'key':'own05-qualified-reuse','value':str(feed)});ET.SubElement(ET.SubElement(e,'fallbackPackageFolders'),'clear');audit=ET.SubElement(e,'auditSources');ET.SubElement(audit,'clear');ET.SubElement(audit,'add',{'key':'exact-producer04-snapshot','value':f'http://127.0.0.1:{port}/v3/index.json','allowInsecureConnections':'true'});signers=ET.SubElement(e,'trustedSigners');ET.SubElement(signers,'clear');repoSigner=ET.SubElement(signers,'repository',{'name':'nuget.org','serviceIndex':plan['requiredSignaturePolicy']['serviceIndex']});[ET.SubElement(repoSigner,'certificate',{'fingerprint':fp,'hashAlgorithm':'SHA256','allowUntrustedRoot':'false'}) for fp in plan['requiredSignaturePolicy']['repositoryCertificateSHA256']];config.write_bytes(ET.tostring(e,encoding='utf-8',xml_declaration=True));shutil.copyfile(config,source/'NuGet.Config');env.update(NUGET_PACKAGES=str(out/'packages'),NUGET_HTTP_CACHE_PATH=str(out/'http'),NUGET_PLUGINS_CACHE_PATH=str(out/'plugins'),NUGET_SCRATCH=str(out/'scratch'),NUGET_CERT_REVOCATION_MODE='online',APPDATA=str(out/'appdata'),LOCALAPPDATA=str(out/'localappdata'),NUGET_CLI_LANGUAGE='en-us',DOTNET_CLI_UI_LANGUAGE='en-US')
 def command(name,args,limit):
  left=(s['deadlineMonotonicNs']-time.monotonic_ns())/1e9-20;L.need(left>0,'ORIGINAL_PHASE_DEADLINE');common.verify_tree(sdk,catalog['members'],'win-x64');rec=control.run([str(sdk/'dotnet.exe'),*args],cwd=source,env=env,timeout=min(limit,left),evidence=out/name);rows.append({'name':name,'receiptSHA256':L.sha(out/name/'process.json')});L.need(not dispatcher.poisoned,'ADVISORY_STATIC_ROUTE_POISONED');return rec
 tests='tests/Reference.Tests/Reference.Tests.csproj';cli='src/Reference.Cli/Reference.Cli.csproj';args=['--disable-parallel','--configfile',str(config),'--packages',str(out/'packages'),'-p:NuGetAudit=true','-p:NuGetAuditMode=all'];paths=['src/Reference.Core/packages.lock.json','src/Reference.Cli/packages.lock.json','tests/Reference.Tests/packages.lock.json']
 try:
  command('verify-windows-apphost',['nuget','verify','--all',str(hostPath),'--configfile',str(config),'--verbosity','detailed','--certificate-fingerprint',nativePlan['expectedAuthorSHA256']],45);hostNormalized=V.content_hash((out/'verify-windows-apphost/stdout.log').read_bytes(),host['id'],'11.0.0',0,{'id':host['id'],'version':'11.0.0','sha256':L.sha(hostPath)});write(out/'windows-apphost-input.json',{'rawArchive':hostRaw,'normalized':hostNormalized,'certificateRoleReuse':hostRoles,'commonHandoffSHA256':handoffRef['sha256'],'shippedRuntimeComponent':False})
  command('curate-tests',['restore',tests,'--use-lock-file','--force-evaluate',*args],100);command('curate-cli-both-rids',['restore',cli,'--use-lock-file','--force-evaluate',*args,'-p:SelfContained=true'],100);locked={n:L.sha(source/n) for n in paths};observed={}
  for name in paths:
   data=L.read(source/name);L.need(set(data['dependencies'])=={'net11.0','net11.0/linux-x64','net11.0/win-x64'},'GENERATED_LOCK_SCOPES')
   for group in data['dependencies'].values():
    for id,p in group.items():
     if p.get('type')!='Project':observed[(id.lower(),p['resolved'])]=p['contentHash']
  expected={(p['id'].lower(),p['version']):p['normalizedContentHash'] for p in plan['managed']};removed={(id,'10.0.0') for id in PRUNED};L.need(observed=={k:v for k,v in expected.items() if k not in removed},'RETAINED_MANAGED_VERSION_CONTENT_CLOSURE_CHANGED');dg=L.read(source/'tests/Reference.Tests/obj/Reference.Tests.csproj.nuget.dgspec.json')
  for entry in dg['projects'].values():
   prune=entry['frameworks']['net11.0']['packagesToPrune'];L.need(all(any(k.lower()==id and A.in_range('10.0.0',bound) for k,bound in prune.items()) for id in PRUNED),'AUTOMATIC_SDK_PRUNING_NOT_PROVEN')
  write(out/'managed-pruning.json',{'scope':'Actual default SDK11 framework pruning, no PackageReference version edits or avoidance flags','retainedVersionContentIdentities':18,'prunedExistingIdentities':sorted('/'.join(x) for x in removed),'dgspecSHA256':L.sha(source/'tests/Reference.Tests/obj/Reference.Tests.csproj.nuget.dgspec.json')})
  for name,project,extra in [('locked-tests',tests,[]),('locked-cli-linux',cli,['--runtime','linux-x64','-p:SelfContained=true']),('locked-cli-win',cli,['--runtime','win-x64','-p:SelfContained=true'])]:
   command(name,['restore',project,'--locked-mode',*args,*extra],30);L.need({n:L.sha(source/n) for n in paths}==locked,'GENERATED_LOCK_BYTES_CHANGED_BETWEEN_CONTEXTS')
  for name,project in [('advisory-tests',tests),('advisory-cli',cli)]:
   command(name,['package','list','--project',project,'--vulnerable','--include-transitive','--no-restore','--format','json'],30);report=L.read(out/name/'stdout.log');L.need(report.get('version')==1 and len(report.get('projects',[]))==1 and report.get('sources'),'ACTUAL_ADVISORY_REPORT_SHAPE')
   def inspect(x):
    if isinstance(x,dict):
     for k,v in x.items():
      if k in ('vulnerabilities','errors','problems','logs'):L.need(not v,'ACTUAL_ADVISORY_ISSUE')
      inspect(v)
    elif isinstance(x,list):
     for v in x:inspect(v)
   inspect(report)
  L.need(dispatcher.calls>0 and not dispatcher.poisoned,'ACTUAL_SDK_STATIC_ADVISORY_CONSUMPTION');write(out/'advisory-adapter.json',{'calls':dispatcher.calls,'events':dispatcher.events,'sourceCatalogSHA256':L.sha(nativepath),'forwardingOrExternalGETs':0});L.need(sum(p.stat().st_size for p in out.rglob('*') if p.is_file())<=2147483648,'SCRATCH_CEILING');common.verify_tree(sdk,catalog['members'],'win-x64',full=True);write(out/'RESULT.json',{'state':'OWN05_ALL_THREE_NET11_LOCKS_NATIVE_INPUTS_AND_ADVISORY_QUALIFIED','sourceCommit':s['HEAD'],'sourceDirectory':str(source),'packagesDirectory':str(out/'packages'),'feedDirectory':str(feed),'locks':locked,'retainedManagedIdentities':18,'SDKDefaultPrunedIdentities':sorted('/'.join(x) for x in removed),'commands':rows,'unitTestsExecuted':0,'productBuildExecuted':False,'sourceLocksApplied':False,'otherConsumerAdmission':False,'Actions':0})
 finally:server.shutdown();server.server_close();thread.join(timeout=2)
