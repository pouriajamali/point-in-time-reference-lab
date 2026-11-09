"""Extract verified fixtures into a NEW local directory; never install a package."""
import argparse,hashlib,json,os,platform,subprocess,tarfile
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--archives',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);a=parser.parse_args()
    if platform.system()!='Linux':raise SystemExit('Run this step in existing Ubuntu24.04/Linux, including WSL.')
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    lock=json.loads(Path(__file__).with_name('upstream.lock.json').read_text())
    root=out/'root';root.mkdir()
    for record in lock['files']:
        file=a.archives/record['name']
        if hashlib.sha256(file.read_bytes()).hexdigest()!=record['sha256']:raise ValueError('Fixture digest changed')
        if file.name.endswith('.deb'):subprocess.run(['dpkg-deb','--extract',str(file),str(root)],check=True,timeout=60)
        else:
            with tarfile.open(file,'r:gz') as archive:archive.extractall(out,filter='data')
    env=os.environ.copy();env['LD_LIBRARY_PATH']=str(root/'usr/lib/x86_64-linux-gnu')
    postgres=root/'usr/lib/postgresql/18/bin/postgres'
    dependencies=subprocess.run(['ldd',str(postgres)],env=env,text=True,capture_output=True,check=True)
    missing=[line.strip() for line in dependencies.stdout.splitlines() if 'not found' in line]
    if missing:raise SystemExit('Required existing Linux libraries missing: '+','.join(missing))
    for command in [[str(postgres),'--version']]:
        result=subprocess.run(command,env=env,text=True,capture_output=True,check=True,timeout=10);print(result.stdout.strip())
    (out/'PREPARED.json').write_text(json.dumps({'status':'EXTRACTED_NOT_INSTALLED','root':str(out),'platform':platform.platform(),'upstream':lock},indent=2)+'\n')

if __name__=='__main__':main()
