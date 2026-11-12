"""Build a clean exact-source API/CLI archive; no publication or overwrites.
Adapted from the public MIT Fenced Shard Ownership Lab delivery controls.
"""
import argparse,base64,datetime,hashlib,json,os,platform,shutil,subprocess,tarfile,uuid,xml.etree.ElementTree as ET,zipfile
from pathlib import Path
import notices
ROOT=Path(__file__).resolve().parents[1]
def require(condition,message):
    if not condition:raise ValueError(message)
def sha(path,algorithm='sha256'):
    value=hashlib.new(algorithm)
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):value.update(chunk)
    return value.hexdigest()
def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],text=True).strip()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['commit','rid','work','out']:p.add_argument('--'+name,required=True)
    p.add_argument('--dotnet',default='dotnet');p.add_argument('--local-candidate',action='store_true');a=p.parse_args()
    require(a.rid in ['win-x64','linux-x64'] and git('rev-parse','HEAD')==a.commit and not git('status','--porcelain'),'Exact clean HEAD required')
    if not a.local_candidate:require(platform.system()==('Windows' if a.rid=='win-x64' else 'Linux'),'Native public build host must match RID')
    work=Path(a.work).resolve();work.mkdir(parents=True,exist_ok=False);out=Path(a.out).resolve();out.mkdir(parents=True,exist_ok=True);published=work/'published'
    commands=[[a.dotnet,'restore','src/Reference.Cli/Reference.Cli.csproj','--locked-mode'],[a.dotnet,'publish','src/Reference.Cli/Reference.Cli.csproj','-c','Release','-r',a.rid,'--self-contained','true','--no-restore','-m:1','-p:UseSharedCompilation=false','-p:SourceRevisionId='+a.commit,'-o',str(published)]]
    with (work/'build.log').open('wb') as log:
        for command in commands:subprocess.run(command,cwd=ROOT,check=True,stdout=log,stderr=subprocess.STDOUT,timeout=300)
    require(not git('status','--porcelain'),'Build changed frozen source')
    version=ET.parse(ROOT/'Directory.Build.props').findtext('.//Version');name='point-in-time-reference-lab-v'+version+'-'+a.rid;package=work/name;shutil.copytree(published,package);require(a.commit.encode() in (package/'reference.dll').read_bytes(),'Actual source version absent')
    for file in ['README.md','LICENSE','NOTICE.md','PROVENANCE.md','SIGNING-PUBLIC-KEY.pub','CONTRIBUTING.md']:shutil.copy2(ROOT/file,package/file)
    for directory in ['docs','tools','vendor','examples']:shutil.copytree(ROOT/directory,package/directory,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    shutil.copytree(ROOT/'tests/provenance-fixture',package/'tests/provenance-fixture')
    assets=json.loads((ROOT/'src/Reference.Cli/obj/project.assets.json').read_text());folders=[Path(f) for f in assets['packageFolders']]
    deps=json.loads((package/'reference.deps.json').read_text());shipped={identity.removeprefix('runtimepack.'):entry for identity,entry in deps['libraries'].items() if entry['type'] in ['package','runtimepack']}
    require(set(shipped)=={'Npgsql/10.0.3','Microsoft.NETCore.App.Runtime.'+a.rid+'/10.0.15','Microsoft.AspNetCore.App.Runtime.'+a.rid+'/10.0.15'},'Reviewed actual shipped graph changed')
    locks=json.loads((ROOT/'src/Reference.Cli/packages.lock.json').read_text())['dependencies'];locked={(key,value['resolved'],value['contentHash']) for scope in locks.values() for key,value in scope.items() if 'contentHash' in value}
    mappings=json.loads((ROOT/'vendor/notices/NOTICE-SOURCES.json').read_text())['components'];licenses=package/'licenses';licenses.mkdir();dependencies=[]
    for identity,entry in sorted(shipped.items()):
        identifier,ver=identity.split('/');directory=next(f/identifier.lower()/ver for f in folders if (f/identifier.lower()/ver).is_dir());metadata=ET.parse(next(directory.glob('*.nuspec'))).find('{*}metadata')
        normalized=json.loads((directory/'.nupkg.metadata').read_text())['contentHash']
        if entry['type']=='package':require((identifier,ver,normalized) in locked,'Lock/shipped library mismatch')
        mapped=next(r for r in mappings if r['id']+'/'+r['version']==identity);raw_sha512=sha(next(directory.glob('*.nupkg')),'sha512')
        require(base64.b64decode(mapped['rawSignedNupkgSha512Base64']).hex()==raw_sha512,'Raw signed NuGet archive changed')
        notice=notices.resolve(ROOT,directory,identity,{'sha512':normalized},metadata);prefix=identifier+'-'+ver
        for file in notice['suppliedNotices']:shutil.copy2(file,licenses/(prefix+'-'+file.name))
        primary=licenses/(prefix+'-PRIMARY-LICENSE.txt');shutil.copy2(notice['primary'],primary);copyright_file=licenses/(prefix+'-COPYRIGHT.txt');copyright_file.write_text(notice['copyright']+'\n',encoding='utf-8',newline='\n')
        dependencies.append({'id':identifier,'version':ver,'kind':entry['type'],'license':notice['license'],'copyright':notice['copyright'],'copyrightFile':copyright_file.relative_to(package).as_posix(),'licenseFile':primary.relative_to(package).as_posix(),'licenseSha256':sha(primary),'licenseSource':notice['licenseSource'],'nugetContentHash':normalized,'nugetContentHashMeaning':'Normalized restore identity excluding signatures','rawSignedNupkgSha512':raw_sha512})
    resolved={k for k,v in assets['libraries'].items() if v['type']=='package'}
    (package/'DEPENDENCIES.json').write_text(json.dumps({'packages':dependencies,'resolvedButNotSeparatelyShipped':sorted(resolved-set(shipped)),'externalFixtures':'Five pinned PostgreSQL/support archives referenced in tools/upstream.lock.json, not bundled','testToolsNotBundled':['xunit.v3/4.0.3']},indent=2)+'\n',encoding='utf-8')
    packages=[{'name':'Point-in-Time Instrument Reference Lab','SPDXID':'SPDXRef-App','versionInfo':version,'downloadLocation':'NOASSERTION','filesAnalyzed':False,'licenseDeclared':'MIT','licenseConcluded':'NOASSERTION','copyrightText':'Copyright (c) 2026 Pouria Jamali'}];relations=[{'spdxElementId':'SPDXRef-DOCUMENT','relationshipType':'DESCRIBES','relatedSpdxElement':'SPDXRef-App'}]
    for i,dep in enumerate(dependencies):
        key=dep['id'].lower();ver=dep['version'];spdxid='SPDXRef-Package'+str(i);packages.append({'name':dep['id'],'SPDXID':spdxid,'versionInfo':ver,'downloadLocation':f'https://api.nuget.org/v3-flatcontainer/{key}/{ver}/{key}.{ver}.nupkg','filesAnalyzed':False,'licenseDeclared':dep['license'],'licenseConcluded':'NOASSERTION','copyrightText':dep['copyright'],'checksums':[{'algorithm':'SHA512','checksumValue':dep['rawSignedNupkgSha512']}],'comment':'Raw signed archive checksum at build; normalized NuGet contentHash remains separate.'});relations.append({'spdxElementId':'SPDXRef-App','relationshipType':'DEPENDS_ON','relatedSpdxElement':spdxid})
    sbom={'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT','name':name,'documentNamespace':'https://github.com/pouriajamali/point-in-time-reference-lab/spdx/'+str(uuid.uuid4()),'creationInfo':{'creators':['Tool: point-in-time-reference-package.py'],'created':datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')},'packages':packages,'relationships':relations};(package/'SBOM.spdx.json').write_text(json.dumps(sbom,indent=2)+'\n',encoding='utf-8')
    files=[]
    for file in sorted(package.rglob('*')):
        require(not file.is_symlink(),'Symlink in package')
        if not file.is_file():continue
        relative=file.relative_to(package).as_posix();require(not relative.lower().endswith(('.pdb','.private.json','.db','.sqlite')),'Private/debug/data file in package');files.append({'path':relative,'bytes':file.stat().st_size,'sha256':sha(file)})
    require(len(files)<1024 and sum(f['bytes'] for f in files)<512*1024*1024,'Package cap')
    manifest={'schema':1,'version':version,'rid':a.rid,'sourceCommit':a.commit,'sourceTree':git('rev-parse','HEAD^{tree}'),'localCandidate':a.local_candidate,'buildHost':platform.system(),'selfContained':True,'files':files};(package/'BUILD-MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    archive=out/(name+('.zip' if a.rid=='win-x64' else '.tar.gz'));require(not archive.exists(),'Archive exists')
    if a.rid=='win-x64':
        with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as zipped:
            for file in sorted(package.rglob('*')):
                if file.is_file():zipped.write(file,file.relative_to(work).as_posix())
    else:
        with tarfile.open(archive,'x:gz') as packed:
            for file in sorted(package.rglob('*')):
                if not file.is_file():continue
                info=packed.gettarinfo(str(file),arcname=file.relative_to(work).as_posix());info.mode=0o755 if file.name in ['reference','createdump'] else 0o644;info.uid=info.gid=0;info.uname=info.gname=''
                with file.open('rb') as stream:packed.addfile(info,stream)
    receipt={'status':'PACKAGED_NOT_RUNTIME_PROOF','sourceCommit':a.commit,'rid':a.rid,'archive':str(archive),'bytes':archive.stat().st_size,'sha256':sha(archive),'payloadFiles':len(files),'shippedComponents':len(dependencies),'localCandidate':a.local_candidate};(work/'archive.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
if __name__=='__main__':main()
