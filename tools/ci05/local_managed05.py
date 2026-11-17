"""Fixed own05 managed-lock/unit phase; native product admission remains separate."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,tarfile,xml.etree.ElementTree as ET
PLAN_SHA='8f68667e455dbb2ce3de5774baaa6ccd25d0c74fa1467a800ab731efd9e59ca2'
def run(L,s,out,sdk,env,control,common,catalog):
 root=L.ROOT; base=root.parents[1]; planpath=Path(__file__).with_name('local-managed-inputs05.json');L.need(L.sha(planpath)==PLAN_SHA,'MANAGED_PLAN_SOURCE');plan=L.read(planpath);old=base/'state/acquisition-raw-cache-01/outputs/receipts/A-ACQUISITION-RECEIPT.json';sig=base/'state/execution-evidence/nuget-signature-verification.json';L.need(L.sha(old)==plan['oldAcquisitionReceiptSHA256'] and L.sha(sig)==plan['oldSignatureReceiptSHA256'],'HISTORICAL_REUSE_IDENTITY');L.need(L.read(sig)['status']=='ALL28_SDK_NUGET_VERIFY_SUCCESS','HISTORICAL_VERIFY_SCOPE')
 feed=out/'feed';feed.mkdir();inputs=[]
 for p in plan['managed']:
  src=base/'state/acquisition-raw-cache-01/archives'/p['filename'];L.need(src.is_file() and not src.is_symlink() and src.stat().st_size==p['bytes'],'EXISTING_MANAGED_BODY');
  with src.open('rb') as f:digest=hashlib.file_digest(f,'sha512').hexdigest()
  L.need(digest==p['rawSHA512'],'MANAGED_RAW_IDENTITY');shutil.copyfile(src,feed/p['filename']);inputs.append(dict(p,source=str(src)))
 nativepath=Path(s['sharedTools'])/'sdk11-native-inputs.lock.json';L.need(L.sha(nativepath)==plan['nativeCatalogSHA256'],'NATIVE_CATALOG_IDENTITY');native=L.read(nativepath);p=next(p for p in native['packages'] if p['id']=='Microsoft.NETCore.App.Host.linux-x64');name=p['id'].lower()+'.11.0.0.nupkg';nativebase=base.parent/'data-admission-gate/outputs/tech-refresh-m0-20261114/own04-common-normal-wiring-db748-sdk0-20261116/private-cas-local-20261116/curation-stage-a-20261116/STAGE-B-DISCOVERY-ONCE/raw';src=nativebase/name
 L.need(src.stat().st_size==p['rawSignedArchive']['bytes'],'HOST_BODY_LENGTH')
 with src.open('rb') as f:L.need(hashlib.file_digest(f,'sha512').hexdigest()==p['rawSignedArchive']['sha512'],'HOST_BODY_IDENTITY')
 shutil.copyfile(src,feed/name);write=L.write;write(out/'reused-inputs.json',{'managed':inputs,'linuxAppHostInput':p,'qualificationReplayed':False,'networkBodiesDownloaded':0})
 source=out/'source';source.mkdir();files=subprocess.check_output(['git','ls-files','-z'],cwd=root,timeout=10).decode().split('\0')
 for name in files:
  if name:
   dst=source/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/name,dst)
 config=out/'NuGet.Config';config.write_text('<?xml version="1.0" encoding="utf-8"?><configuration><packageSources><clear/><add key="own05-qualified-reuse" value="'+str(feed)+'"/></packageSources><auditSources><clear/><add key="nuget.org" value="https://api.nuget.org/v3/index.json"/></auditSources></configuration>',encoding='utf-8')
 env.update(NUGET_PACKAGES=str(out/'packages'),NUGET_HTTP_CACHE_PATH=str(out/'http'),NUGET_PLUGINS_CACHE_PATH=str(out/'plugins'),APPDATA=str(out/'appdata'),LOCALAPPDATA=str(out/'localappdata'));project='tests/Reference.Tests/Reference.Tests.csproj'; restore=['restore',project,'--use-lock-file','--force-evaluate','--disable-parallel','--configfile',str(config),'--packages',str(out/'packages'),'-p:NuGetAudit=true','-p:NuGetAuditMode=all'];rows=[]
 def command(name,args,limit):
  import time
  left=(s['deadlineMonotonicNs']-time.monotonic_ns())/1e9-20;L.need(left>0,'ORIGINAL_PHASE_DEADLINE');common.verify_tree(sdk,catalog['members'],'win-x64');rec=control.run([str(sdk/'dotnet.exe'),*args],cwd=source,env=env,timeout=min(limit,left),evidence=out/name);rows.append({'name':name,'receiptSHA256':L.sha(out/name/'process.json')});return rec
 command('restore-managed-tests',restore,100)
 expected={(p['id'].lower(),p['version']):p['normalizedContentHash'] for p in plan['managed']};observed={};locks=[]
 for name in ('src/Reference.Core/packages.lock.json','tests/Reference.Tests/packages.lock.json'):
  path=source/name;data=L.read(path);L.need(set(data['dependencies'])=={'net11.0','net11.0/linux-x64','net11.0/win-x64'},'GENERATED_LOCK_SCOPES')
  for group in data['dependencies'].values():
   for identifier,p in group.items():
    if p.get('type')!='Project':observed[(identifier.lower(),p['resolved'])]=p['contentHash']
  locks.append({'path':name,'SHA256':L.sha(path)})
 L.need(observed==expected,'MANAGED_VERSION_CONTENT_CLOSURE_CHANGED');write(out/'managed-locks.json',{'state':'ACTUAL_SDK11_PRIVATE_TEST_AND_CORE_LOCKS_ONLY','locks':locks,'exactManagedIdentities':len(observed),'sourceLocksApplied':False,'cliAndNativeProductLocksComplete':False})
 command('unit51',['run','--project',project,'-c','Release','--no-restore','-p:UseSharedCompilation=false','--','-noLogo','-result-xml',str(out/'unit.xml')],180)
 xml=ET.parse(out/'unit.xml').getroot();assemblies=xml.findall('assembly');L.need(sum(int(a.attrib['total']) for a in assemblies)==51 and all(int(a.attrib['failed'])==0 and int(a.attrib['errors'])==0 and int(a.attrib['skipped'])==0 for a in assemblies),'ORIGINAL_51_UNIT_ACCEPTANCE')
 L.need(sum(p.stat().st_size for p in out.rglob('*') if p.is_file())<=2147483648,'SCRATCH_CEILING');common.verify_tree(sdk,catalog['members'],'win-x64',full=True);write(out/'RESULT.json',{'state':'OWN05_LOCAL_MANAGED20_EXACT_PRIVATE_LOCKS_AND_51_UNITS_PASSED','sourceCommit':s['HEAD'],'commands':rows,'sourceLocksApplied':False,'completeNativeProductAdmission':False,'otherOSUnitProof':False,'Actions':0})
