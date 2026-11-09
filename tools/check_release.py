"""Validate already-executed native archives, then create exact Git source/SUMS.

No runtime build, tag change or publication is performed here.
"""
import argparse,hashlib,json,subprocess,tarfile,zipfile
from pathlib import Path,PurePosixPath
ROOT=Path(__file__).resolve().parents[1]

def require(condition,message='Validation failed'):
    if not condition:raise ValueError(message)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory',type=Path,required=True);parser.add_argument('--commit',required=True);parser.add_argument('--tag',required=True);a=parser.parse_args()
    directory=a.directory.resolve();names={f'point-in-time-reference-lab-{a.tag}-win-x64.zip':'win-x64',f'point-in-time-reference-lab-{a.tag}-linux-x64.tar.gz':'linux-x64'}
    require({p.name for p in directory.iterdir()}==set(names), 'Validation failed: check_release.py:12')
    tree=subprocess.check_output(['git','-C',str(ROOT),'rev-parse',a.commit+'^{tree}'],text=True).strip()
    for name,rid in names.items():
        archive=directory/name;files={}
        if name.endswith('.zip'):
            with zipfile.ZipFile(archive) as packed:
                for info in packed.infolist():
                    require(not info.is_dir() and info.filename not in files and info.file_size<128*1024*1024, 'Validation failed: check_release.py:19')
                    files[info.filename]=packed.read(info)
        else:
            with tarfile.open(archive,'r:gz') as packed:
                for info in packed:
                    require(info.isfile() and info.name not in files and info.size<128*1024*1024, 'Validation failed: check_release.py:24')
                    files[info.name]=packed.extractfile(info).read()
        require(len(files)<1024 and sum(map(len,files.values()))<512*1024*1024, 'Validation failed: check_release.py:26')
        require(all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts for n in files), 'Validation failed: check_release.py:27')
        roots={PurePosixPath(n).parts[0] for n in files};require(len(roots)==1, 'Validation failed: check_release.py:28');prefix=roots.pop()+'/'
        files={n[len(prefix):]:value for n,value in files.items()};manifest=json.loads(files.pop('BUILD-MANIFEST.json'))
        require(manifest['sourceCommit']==a.commit and manifest['sourceTree']==tree and manifest['version']==a.tag.removeprefix('v'), 'Validation failed: check_release.py:30')
        require(manifest['rid']==rid and manifest['selfContained'] and not manifest['localCandidate'], 'Validation failed: check_release.py:31')
        require(manifest['buildHost']==('Windows' if rid=='win-x64' else 'Linux'), 'Validation failed: check_release.py:32')
        require(set(files)=={item['path'] for item in manifest['files']}, 'Validation failed: check_release.py:33')
        for item in manifest['files']:require(len(files[item['path']])==item['bytes'] and hashlib.sha256(files[item['path']]).hexdigest()==item['sha256'], 'Validation failed: check_release.py:34')
        require(a.commit.encode() in files['reference.dll'] and 'SBOM.spdx.json' in files, 'Validation failed: check_release.py:35')
    source=directory/f'point-in-time-reference-lab-{a.tag}-source.zip';require(not source.exists(), 'Validation failed: check_release.py:36')
    prefix=f'point-in-time-reference-lab-{a.tag}-source/'
    subprocess.run(['git','-C',str(ROOT),'-c','core.autocrlf=false','-c','core.eol=lf','archive','--format=zip','--prefix='+prefix,'--output='+str(source),a.commit],check=True)
    tracked=subprocess.check_output(['git','-C',str(ROOT),'ls-tree','-r','--name-only',a.commit],text=True).splitlines()
    with zipfile.ZipFile(source) as packed:
        require({i.filename for i in packed.infolist() if not i.is_dir()}=={prefix+n for n in tracked}, 'Validation failed: check_release.py:41')
        for name in tracked:require(packed.read(prefix+name)==subprocess.check_output(['git','-C',str(ROOT),'show',a.commit+':'+name]), 'Validation failed: check_release.py:42')
    checks=''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(directory.iterdir()))
    (directory/'SHA256SUMS.txt').write_text(checks,encoding='utf-8',newline='\n')
    print(json.dumps({'status':'NATIVE_ARCHIVES_AND_GIT_SOURCE_VERIFIED','commit':a.commit,'tree':tree,'sourceFiles':len(tracked)}))

if __name__=='__main__':main()
