"""Run only the admitted maintainer linter, through the same default/direct gate."""
from __future__ import annotations
import contextlib, argparse, hashlib, json, os, platform, subprocess, sys, uuid
from pathlib import Path
from check_actionlint import AdmissionError, admitted_artifact, clean_environment, contained, read_json, require
from bounded_actionlint import CapError, phase_permission, portable_phase, run
ROOT=Path(__file__).resolve().parents[1]

def workflows(arguments):
    result=subprocess.run(['git','-C',str(ROOT),'ls-files','-z','.github/workflows/*.yml','.github/workflows/*.yaml'],capture_output=True,timeout=30)
    require(result.returncode==0 and len(result.stdout)<=1024*1024,'WORKFLOW_INVENTORY')
    tracked={x for x in result.stdout.decode('utf-8').split('\0') if x}
    selected=arguments or sorted(tracked)
    require(selected and len(selected)<=32 and len(set(selected))==len(selected),'WORKFLOW_COUNT')
    for name in selected:
        require(name in tracked,'WORKFLOW_NOT_TRACKED'); path=contained(ROOT/name,ROOT)
        require(path.is_file() and path.stat().st_size<=2*1024*1024,'WORKFLOW_TYPE_OR_CAP')
    return selected

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--portable',action='store_true');parser.add_argument('files',nargs='*'); args=parser.parse_args()
    target=('windows' if os.name=='nt' else 'linux')+'-amd64'
    require(platform.machine().lower() in ('amd64','x86_64'),'UNSUPPORTED_ARCH')
    reference=read_json(ROOT/'tools/actionlint-build.lock.json')
    bundle=ROOT/'artifacts/actionlint'/target
    chosen=workflows(args.files)
    managed=(ROOT.parent/'state/operator-helpers/CURRENT-LANE-REFERENCE.json').exists()
    portable=args.portable or not (managed or os.environ.get('ACTIONLINT_LEASE_PROTOCOL') or os.environ.get('ACTIONLINT_PHASE_TOKEN'))
    # Checking happens before creating work, acquiring handles or spawning a candidate.
    with admitted_artifact(reference,bundle,target) as image:
        with (portable_phase(reference,ROOT,'lint') if portable else contextlib.nullcontext(None)) as phase:
            phase_permission(reference,os.environ)
            work=ROOT/'artifacts/actionlint-runs'/uuid.uuid4().hex; work.mkdir(parents=True,exist_ok=False)
            env=clean_environment(os.environ,home=work/'home',gopath=work/'gopath',cache=work/'cache',temp=work/'tmp')
            for name in ('home','gopath','cache','tmp'): (work/name).mkdir()
            command=[image['argv0'],'-color','-shellcheck=','-pyflakes=',*chosen]
            if phase is not None:phase.update(started=True,evidence=work/'process')
            result=run(command,cwd=ROOT,env=env,timeout=90,evidence=work/'process',pass_fds=image['passFds'])
            for name,stream in [('stdout.log',sys.stdout),('stderr.log',sys.stderr)]:
                data=(work/'process'/name).read_text(encoding='utf-8',errors='replace'); stream.write(data)
            receipt={'schema':'actionlint-run/v1','state':'ACTUAL_ADMITTED_LINT_PASS','target':target,'artifactSha256':image['sha256'],'referenceSha256':hashlib.sha256((ROOT/'tools/actionlint-build.lock.json').read_bytes()).hexdigest(),'workflowHashes':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in chosen},'process':result}
            with open(work/'receipt.json','x',encoding='utf-8') as f: json.dump(receipt,f,indent=2)
            print(json.dumps({'status':receipt['state'],'target':target,'receipt':str(work/'receipt.json'),'artifactSha256':image['sha256'],'referenceSha256':receipt['referenceSha256'],'workflowHashes':receipt['workflowHashes'],'actualCap':result['actualCap']}))
if __name__=='__main__':
    try: main()
    except (AdmissionError,CapError,OSError,KeyError,TypeError,ValueError) as exc: raise SystemExit('actionlint HOLD: '+str(exc))
