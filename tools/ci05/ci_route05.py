"""Typed project05 CI entry. No ambient SDK, local fallback or arbitrary argv."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,subprocess,sys
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
class Hold(RuntimeError):pass
def need(v,m):
 if not v:raise Hold(m)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):
 p=Path(path);need(p.is_file() and not p.is_symlink() and p.stat().st_size<=8*1024*1024,'BOUNDED_INPUT')
 def pairs(rows):
  result={}
  for k,v in rows:need(k not in result,'DUPLICATE_JSON_KEY');result[k]=v
  return result
 return json.loads(p.read_bytes(),object_pairs_hook=pairs)
def load(name,expected):
 p=HERE/(name+'.py');need(p.is_file() and sha(p)==expected,'EXACT_CONTROL_SOURCE_REQUIRED');s=importlib.util.spec_from_file_location('project05_'+name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def product_argv(recipes,values,rid):
 allowed={'$SDK','$PYTHON','$RID','$SOURCE_SHA','$ARCHIVE','$PACKAGE','$CLI','$PACKAGED_BOUNDARY'};need(set(values)==allowed,'FIXED_RECIPE_BINDINGS')
 rows=[]
 for row in recipes['rows']:
  if row['rid'] not in ('EACH',rid):continue
  argv=[values[v] if v in allowed else v for v in row['argv']];need(not any('$' in v or '\x00' in v for v in argv),'RECIPE_INTERPOLATION_DENIED');rows.append((row['stage'],row['stageCeilingSeconds'],argv))
 return rows

def source_context(admission):
 head=subprocess.check_output(['git','--no-optional-locks','rev-parse','HEAD'],cwd=ROOT,text=True,timeout=10).strip();dirty=bool(subprocess.check_output(['git','--no-optional-locks','status','--porcelain=v1'],cwd=ROOT,timeout=10))
 need(not dirty and head==os.environ.get('GITHUB_SHA'),'EXACT_CLEAN_CURRENT_SOURCE')
 hashes={n:sha(HERE/n) for n in admission['sourceNames']};need(hashes==admission['sourceHashes'],'OWN_SOURCE_BINDING')
 shared={n:sha(ROOT/n) for n in admission['sharedFiles']};need(shared==admission['sharedFiles'],'BYTE_IDENTICAL_COMMON_TUPLE');pins=read(HERE/'source-pins.json');pinsha=hashlib.sha256(json.dumps(pins['sourcePins'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest();tree=subprocess.check_output(['git','--no-optional-locks','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True,timeout=10).strip()
 return {'head':head,'tree':tree,'dirty':False,'controllerHashes':hashes,'contractSha256':sha(HERE/'contract.json'),'sourcePinTableSha256':pinsha,'normalProfileSha256':sha(HERE/'normal-profile.json')}
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--rid',choices=['win-x64','linux-x64']);parser.add_argument('--phase',choices=['control-probe','verify-product'],default='verify-product');parser.add_argument('--worker',nargs=2);args=parser.parse_args()
 if args.worker:
  admission=read(HERE/'manager-admission.json');need(admission['state']=='EXACT_CANDIDATE_HOST_CONTROL_ADMITTED','OWN_MANAGER_ADMISSION_REQUIRED');adapter=load('native_adapter05',admission['sourceHashes']['native_adapter05.py']);adapter.worker_entry(Path(args.worker[0]),args.worker[1]);return
 need(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('GITHUB_REPOSITORY')=='pouriajamali/point-in-time-reference-lab','SUPPORTED_CI_ONLY_LOCAL_ROUTES_RETIRED')
 admission=read(HERE/'manager-admission.json');need(admission['state']=='EXACT_CANDIDATE_HOST_CONTROL_ADMITTED','OWN_MANAGER_ADMISSION_REQUIRED');source=source_context(admission);profile=read(HERE/'profile.json')
 # Inert exact own-manager gate precedes every actual host/native/common call.
 # Linux fact history does not grant own current execution or global readiness.
 host_source=HERE/'actual_host05.py';native_source=HERE/'native_adapter05.py'
 need(host_source.is_file() and native_source.is_file(),'ACTUAL_HOST_CONTROL_SOURCE_NOT_YET_ADMITTED')
 need(args.rid=='linux-x64','WINDOWS_NORMAL_DENIED_NO_ACCEPTED_PRODUCER_FACT');host=load('actual_host05',admission['sourceHashes']['actual_host05.py']);ctx=host.observe_api_backed_current_job(args.rid,ROOT,source,profile)
 guard=load('host_fact05',admission['sourceHashes']['host_fact05.py']);need(sha(HERE/'host-admissions.json')==admission['acceptedCatalogSha256'],'EXACT_MANAGER_CATALOG_BINDING');catalog=read(HERE/'host-admissions.json')
 def fact(row):
  need(row['factFile']=='tools/sdk11-normal/accepted-linux-fact.json','EXACT_ACCEPTED_FACT_PATH');path=ROOT/row['factFile'];need(sha(path)==row['factBytesSha256'],'IMMUTABLE_PRODUCER_FACT_BYTES');return read(path)
 need(sha(ROOT/'tools/dotnet11-host-qualification.schema.json')==guard.SCHEMA_SHA256,'PRODUCER_SCHEMA_BINDING');schema=read(ROOT/'tools/dotnet11-host-qualification.schema.json');row,identity=guard.admit(catalog,ctx,source,profile,fact,schema)
 if args.phase=='verify-product':
  need(admission.get('productInputsSealed') is True,'REAL_NET11_LOCK_NOTICE_ADMISSION_REQUIRED')
  for rel,h in admission['lockAndNoticeHashes'].items():need(sha(ROOT/rel)==h,'PRODUCT_INPUT_IDENTITY')
  need(set(admission['lockAndNoticeHashes'])=={'src/Reference.Core/packages.lock.json','src/Reference.Cli/packages.lock.json','tests/Reference.Tests/packages.lock.json','vendor/notices/NOTICE-SOURCES.json'},'FOUR_REAL_INPUT_BINDINGS')
  for rel in ('src/Reference.Core/packages.lock.json','src/Reference.Cli/packages.lock.json','tests/Reference.Tests/packages.lock.json'):need('net11.0' in read(ROOT/rel)['dependencies'],'NET11_LOCK_SCOPES_REQUIRED')
  components=read(ROOT/'vendor/notices/NOTICE-SOURCES.json')['components'];need(all(c['version']=='11.0.0' for c in components if c['id'].startswith('Microsoft.')) and next(c['version'] for c in components if c['id']=='Npgsql')=='10.0.3','REAL_RUNTIME11_NOTICES_NPGSQL_PIN')
 adapter=load('native_adapter05',admission['sourceHashes']['native_adapter05.py'])
 # The reviewed adapter must prove actual own host/UID/held-child/kernel controls
 # before any acquire/extract/SDK/product, enforce remaining1200s/own caps, and
 # fsync terminal checkpoints before release/upload. It cannot accept arbitrary argv.
 adapter.fixed_project05_route(ctx,source,row,identity,profile,read(HERE/'product-recipes.json'),args.phase,args.worker)
if __name__=='__main__':
 try:main()
 except (Hold,OSError,ValueError,KeyError) as e:raise SystemExit('HOLD: '+str(e))
