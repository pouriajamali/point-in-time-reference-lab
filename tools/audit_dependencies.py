"""Record the current NuGet advisory check; not a security certification."""
import argparse,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def require(condition,message='Validation failed'):
    if not condition:raise ValueError(message)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dotnet',default='dotnet');p.add_argument('--out',type=Path,required=True);a=p.parse_args();require(not a.out.exists(), 'Validation failed: audit_dependencies.py:7');a.out.parent.mkdir(parents=True,exist_ok=True)
    reports=[]
    for project in ['src/Reference.Cli/Reference.Cli.csproj','tests/Reference.Tests/Reference.Tests.csproj']:
        result=subprocess.run([a.dotnet,'package','list','--project',project,'--vulnerable','--include-transitive','--no-restore','--format','json'],cwd=ROOT,capture_output=True,text=True,check=True,timeout=180)
        data=json.loads(result.stdout);require(data.get('version')==1 and len(data.get('projects',[]))==1 and data.get('sources'), 'Validation failed: audit_dependencies.py:11')
        def inspect(value):
            if isinstance(value,dict):
                for key,item in value.items():
                    if key in ['vulnerabilities','errors','problems','logs']:require(not item, (key,item))
                    inspect(item)
            elif isinstance(value,list):
                for item in value:inspect(item)
        inspect(data);reports.append(data)
    receipt={'status':'NO_KNOWN_ADVISORIES_REPORTED','scope':'Current NuGet source advisory query for locked direct/transitive application and test graph; not general vulnerability absence','reports':reports}
    a.out.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8');print(json.dumps({'status':receipt['status'],'projects':len(reports)}))

if __name__=='__main__':main()
