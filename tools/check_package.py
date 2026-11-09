"""Verify exact extracted bytes, full runtime/provider notices and native safeguards."""
import argparse,hashlib,json,os,platform,subprocess
from pathlib import Path,PurePosixPath

def require(condition,message):
    if not condition:raise ValueError(message)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--package',type=Path,required=True);p.add_argument('--commit',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();package=a.package.resolve();a.out.parent.mkdir(parents=True,exist_ok=True);require(not a.out.exists(),'Receipt exists')
    manifest=json.loads((package/'BUILD-MANIFEST.json').read_text());require(manifest['sourceCommit']==a.commit,'Source revision');expected=set();checks=[]
    for item in manifest['files']:
        relative=PurePosixPath(item['path']);require(not relative.is_absolute() and '..' not in relative.parts and item['path'] not in expected,'Manifest path');expected.add(item['path']);file=package/relative
        require(file.is_file() and not file.is_symlink() and file.stat().st_size==item['bytes'] and hashlib.sha256(file.read_bytes()).hexdigest()==item['sha256'],'Exact bytes')
    require({p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()}==expected|{'BUILD-MANIFEST.json'},'File set');checks.append('exact-payload-set-size-sha256')
    dependencies=json.loads((package/'DEPENDENCIES.json').read_text())['packages'];bom=json.loads((package/'SBOM.spdx.json').read_text());require(len(dependencies)==3 and len(bom['packages'])==4,'Actual shipped provider/core/aspnet graph');checks.append('actual-three-component-shipped-graph')
    for dep in dependencies:
        file=package/dep['licenseFile'];require(file.stat().st_size>=300 and hashlib.sha256(file.read_bytes()).hexdigest()==dep['licenseSha256'],'Full license')
        require((package/dep['copyrightFile']).read_text(encoding='utf-8').strip()==dep['copyright'],'Original copyright')
        item=next(x for x in bom['packages'] if x['name']==dep['id']);require(item['checksums']==[{'algorithm':'SHA512','checksumValue':dep['rawSignedNupkgSha512']}],'Raw signed archive checksum')
    checks.extend(['full-provider-runtime-license-and-copyright','raw-archive-checksums-separate-normalized-lock-identity'])
    app=package/('reference.exe' if os.name=='nt' else 'reference');env=os.environ.copy();env.pop('REFERENCE_LAB_DB',None)
    def call(args,expected):
        result=subprocess.run([str(app),*map(str,args)],cwd=package,env=env,capture_output=True,text=True,timeout=20);require(result.returncode==expected,'Native exit');return json.loads(result.stdout)
    for flag in ['--help','--version']:
        response=call([flag],0);require(a.commit in response['version'] and 'literal-loopback' in response['usage'],'Actual native version')
    checks.append('actual-native-help-version-source')
    require(call(['head','http://example.com:1234'],2)['status']=='FAILED_CLOSED','External endpoint');checks.append('external-endpoint-rejected-before-network')
    scratch=a.out.parent/(a.out.stem+'-private-checks');scratch.mkdir(exist_ok=False);file=scratch/'oversized.json';file.write_bytes(b'x'*16385)
    require(call(['ingest','http://127.0.0.1:65534',file],2)['status']=='FAILED_CLOSED','Input frame before network');checks.append('oversized-input-rejected-before-network')
    require(call(['query','http://127.0.0.1:65534','2024-01-01T00:00:00Z','0'],2)['status']=='FAILED_CLOSED','Zero is not a committed knowledge query');checks.append('explicit-positive-knowledge-cutoff-required')
    receipt={'status':'PASS','os':platform.system(),'sourceCommit':a.commit,'rid':manifest['rid'],'payloadFiles':len(expected),'shippedComponents':3,'checkCount':len(checks),'checks':checks};a.out.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8');print(json.dumps(receipt))
if __name__=='__main__':main()
