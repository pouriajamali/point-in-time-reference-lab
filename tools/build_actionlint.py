"""Finite local actionlint recipe. Every consuming stage requires actual admitted06 tools.

No upstream executable fallback, compiler download, go get/tidy, generator or upstream test.
The source lock stays UNADMITTED until independent source/binary proof review pins outputs.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, os, shutil, tarfile, time, urllib.parse, urllib.request
from pathlib import Path
from check_actionlint import (AdmissionError, archive_inventory, clean_environment, contained,
    digest, inspect_format, path_parts, read_json, require, validate_reference, validate_buildinfo, check_file_hash, _pairs)
from bounded_actionlint import CapError, linux_caps, phase_permission, run
ROOT=Path(__file__).resolve().parents[1]
LOCK=ROOT/'tools/actionlint-build.lock.json'
MAX_INPUT=1024*1024*1024
MAX_WORK=4*1024*1024*1024
LDFLAGS='-s -w -buildid= -X github.com/rhysd/actionlint.version=1.7.12 -X github.com/rhysd/actionlint.installedFrom=maintainer-built-914e7df21a07-go1.26.11-xsys0.44.0'

def write(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    require(len(raw)<=8*1024*1024,'METADATA_CAP')
    with open(path,'xb') as f: f.write(raw)

def capacity(root,limit=MAX_WORK):
    size=0
    for p in Path(root).rglob('*'):
        require(not p.is_symlink(),'WORKSPACE_LINK')
        if p.is_file(): size+=p.stat().st_size; require(size<=limit,'WORKSPACE_CAP')
    return size

def verify_members(root,rows,*,exact=True,native=False):
    root=contained(root,Path(root).absolute()); names=set()
    for row in rows:
        name=row['path']; path_parts(name); p=contained(root/name,root)
        st=p.stat()
        require(p.is_file() and st.st_size==row['bytes'] and digest(p)==row['sha256'],'MEMBER_BYTES:'+name)
        if native: require(st.st_uid==1000 and st.st_gid==1000 and st.st_nlink==1 and st.st_mode&0o777==int(row['mode'],8),'TOOL_NATIVE_MODE_OR_ALIAS')
        names.add(name)
    if exact:
        actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() or p.is_symlink()}
        require(actual==names,'MEMBER_SET')

def source_tree(root,ref):
    # Original source contains no workspace file; added or dirty files cannot join the graph.
    verify_members(root,ref['source']['members'])
    require(not any(Path(root).rglob('go.work')) and not any(Path(root).rglob('go.work.sum')),'SOURCE_WORKSPACE')

def input_locations():
    name=os.environ.get('ACTIONLINT_INPUT_LOCATIONS');require(name,'INPUT_LOCATIONS_MISSING')
    locations=read_json(name,65536);require(type(locations) is dict,'INPUT_LOCATIONS_SCHEMA')
    return locations

def tool_reference(ref,kind):
    spec=ref[kind]; admitted=spec.get('admission')
    require(type(admitted) is dict and admitted.get('state')=='ADMITTED','TOOL_UNADMITTED:'+kind)
    if kind=='auditor':
        require(type(admitted.get('protocolConfig')) is dict and admitted['protocolConfig'].get('scanner_version') is not None,'AUDITOR_PROTOCOL_UNADMITTED')
    locations=input_locations().get(admitted.get('locationsKey',kind));require(type(locations) is dict and set(locations)=={'root','receipt','membersFile'},'TOOL_LOCATIONS_SCHEMA')
    receipt=admitted['receipt'];require(digest(locations['receipt'])==receipt['sha256'],'TOOL_RECEIPT_BYTES')
    observed=read_json(locations['receipt'],8*1024*1024)
    # The expected status/bindings are independently reviewed source-held pins, not supplied by a candidate.
    require(observed.get('status')==admitted['expectedStatus'],'TOOL_RECEIPT_STATUS')
    for key,value in admitted['receiptBindings'].items(): require(observed.get(key)==value,'TOOL_RECEIPT_BINDING:'+key)
    root=Path(locations['root']); members=admitted.get('members')
    if members is None:
        manifest=admitted['membersFile'];check_file_hash(locations['membersFile'],manifest['sha256'],'TOOL_MEMBER_MANIFEST_BYTES')
        members=read_json(locations['membersFile'],8*1024*1024); prefix=admitted.get('memberPrefix','')
        require(type(members) is list and members,'TOOL_MEMBER_MANIFEST')
        require(all(r['path'].startswith(prefix) for r in members),'TOOL_MEMBER_PREFIX')
        members=[dict(r,path=r['path'][len(prefix):]) for r in members]
    verify_members(root,members,native=True)
    exe=contained(root/admitted['executable'],root)
    require(digest(exe)==admitted['executableSha256'],'TOOL_EXECUTABLE_BYTES')
    return root,exe

def tools(ref,auditor_required=False):
    compiler,go=tool_reference(ref,'compiler');audit=None
    if auditor_required: _,audit=tool_reference(ref,'auditor')
    return compiler,go,audit

def overlay(work,ref):
    for name,key in [('actionlint.mod','mod'),('actionlint.sum','sum')]:
        p=contained(work/'overlay'/name,work)
        require(digest(p)==ref['graph'][key+'Sha256'],'OVERLAY_BYTES')
    return work/'overlay/actionlint.mod'

def environment(work,compiler,target,cache):
    paths={n:work/n for n in ('home','gopath','tmp')}
    for p in [*paths.values(),cache]: p.mkdir(parents=True,exist_ok=True)
    config=paths['home']/'.config';telemetry=config/'go/telemetry';telemetry.mkdir(parents=True,exist_ok=True)
    mode=telemetry/'mode'
    if mode.exists():require(mode.read_bytes()==b'off\n','TELEMETRY_MODE_MISMATCH')
    else:
        with open(mode,'xb') as stream:stream.write(b'off\n')
    env=clean_environment(os.environ,home=paths['home'],gopath=paths['gopath'],cache=cache,
                             temp=paths['tmp'],compiler_root=compiler,target=target)
    env['XDG_CONFIG_HOME']=str(config);env['XDG_CACHE_HOME']=str(paths['home']/'.cache');return env

def sequence(raw):
    require(len(raw.encode())<=8*1024*1024,'STREAM_CAP')
    decoder=json.JSONDecoder(object_pairs_hook=_pairs,parse_constant=lambda _: (_ for _ in ()).throw(AdmissionError('STREAM_CONSTANT'))); out=[]; pos=0
    while pos<len(raw):
        while pos<len(raw) and raw[pos].isspace(): pos+=1
        if pos==len(raw): break
        try: row,end=decoder.raw_decode(raw,pos)
        except json.JSONDecodeError as exc: raise AdmissionError('STREAM_PARSE') from exc
        require(type(row) is dict,'STREAM_OBJECT'); out.append(row); pos=end
    require(out,'STREAM_EMPTY'); return out

def command(argv,work,env,evidence,seconds):
    before=capacity(work); result=run(list(map(str,argv)),cwd=work/'source',env=env,timeout=seconds,evidence=evidence)
    capacity(work); result['workspaceBytesBefore']=before
    return result

def prepare(work,source,ref):
    require(not work.exists(),'WORKSPACE_EXISTS')
    require(source.is_file() and source.stat().st_size==ref['source']['archiveBytes'] and digest(source)==ref['source']['archiveSha256'],'SOURCE_ARCHIVE_BYTES')
    rows=archive_inventory(source); files=[r for r in rows if r['type']=='file']
    prefixes={r['path'].split('/')[0] for r in rows}; require(len(prefixes)==1,'SOURCE_PREFIX')
    prefix=next(iter(prefixes)); actual={r['path'][len(prefix)+1:]:r for r in files}
    require(set(actual)=={r['path'] for r in ref['source']['members']},'SOURCE_ARCHIVE_MEMBER_SET')
    for row in ref['source']['members']:
        a=actual[row['path']]; require(a['bytes']==row['bytes'] and a['sha256']==row['sha256'] and a['mode'] in (int(row['gitMode'],8)&0o777,(int(row['gitMode'],8)&0o777)|0o020),'SOURCE_ARCHIVE_MEMBER_BYTES:'+row['path'])
    # Complete archive preflight finishes before the first member is written.
    work.mkdir(parents=True,exist_ok=False); (work/'source').mkdir(); (work/'overlay').mkdir(); (work/'evidence').mkdir()
    with tarfile.open(source,'r:*') as archive:
        for member in archive:
            if not member.isfile(): continue
            relative=member.name[len(prefix)+1:]; p=contained(work/'source'/relative,work,existing=False)
            p.parent.mkdir(parents=True,exist_ok=True)
            with archive.extractfile(member) as src,open(p,'xb') as dst: shutil.copyfileobj(src,dst,1024*1024)
            p.chmod(int(next(r['gitMode'] for r in ref['source']['members'] if r['path']==relative),8)&0o777)
    for suffix,key in [('mod','modText'),('sum','sumText')]: (work/'overlay'/('actionlint.'+suffix)).write_bytes(ref['graph'][key].encode())
    source_tree(work/'source',ref); overlay(work,ref)
    write(work/'evidence/prepared.json',{'sourceArchiveSha256':digest(source),'sourceFiles':850,'referenceSha256':digest(LOCK),'state':'SOURCE_PREPARED_NOT_ARTIFACT_ADMITTED'})

def escaped(module):
    return ''.join('!'+c.lower() if c.isupper() else c for c in module)

class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,url):
        parsed=urllib.parse.urlsplit(url)
        require(parsed.scheme=='https' and parsed.hostname in ('proxy.golang.org','storage.googleapis.com') and parsed.username is None and parsed.port in (None,443),'DOWNLOAD_REDIRECT')
        return super().redirect_request(request,fp,code,msg,headers,url)

def fetch(url,path,budget,cap=64*1024*1024):
    require(urllib.parse.urlsplit(url).hostname=='proxy.golang.org' and url.startswith('https://proxy.golang.org/'),'DOWNLOAD_ORIGIN')
    # Do not inherit credentialed proxy/auth settings from a build shell.
    require(not any(os.environ.get(n) for n in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')),'DOWNLOAD_PROXY_ENV')
    count=0; start=time.monotonic(); opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirect())
    with opener.open(url,timeout=30) as response,open(path,'xb') as stream:
        while True:
            data=response.read(1024*1024)
            if not data: break
            count+=len(data); budget[0]+=len(data)
            require(count<=cap and budget[0]<=MAX_INPUT and time.monotonic()-start<=120 and time.monotonic()-budget[1]<=600,'DOWNLOAD_CAP')
            stream.write(data)
    return {'url':url,'bytes':count,'sha256':digest(path)}

def zip_h1(rows):
    h=hashlib.sha256()
    for row in sorted((r for r in rows if r['type']=='file'),key=lambda r:r['path']):
        h.update((row['sha256']+'  '+row['path']+'\n').encode())
    return 'h1:'+base64.b64encode(h.digest()).decode()

def acquire(work,ref,compiler,go):
    require(not (work/'proxy').exists(),'ACQUIRE_ALREADY_ATTEMPTED')
    baseline=capacity(work); (work/'proxy').mkdir(); budget=[0,time.monotonic()]; records=[]
    for module in ref['graph']['modules']:
        name=escaped(module['module']); version=escaped(module['version']); base=work/'proxy'/name/'@v'; base.mkdir(parents=True)
        inputs={}
        for suffix in ('mod','info','zip'):
            p=base/(version+'.'+suffix); inputs[suffix]=fetch('https://proxy.golang.org/'+name+'/@v/'+version+'.'+suffix,p,budget)
        require(inputs['mod']['sha256']==module['goModSha256'],'MODULE_MOD_BYTES')
        info=read_json(base/(version+'.info')); require(info.get('Version')==module['version'],'MODULE_INFO_VERSION')
        members=archive_inventory(base/(version+'.zip'),expanded_cap=256*1024*1024)
        prefix=module['module']+'@'+module['version']+'/'
        require(all(r['path'].startswith(prefix) for r in members),'MODULE_ZIP_PREFIX')
        require(zip_h1(members)==module['moduleH1'],'MODULE_H1')
        expanded=sum(r['bytes'] for record in records for r in record['members'])+sum(r['bytes'] for r in members)
        require(expanded+2*budget[0]+baseline<=MAX_WORK,'MODULE_MATERIALIZATION_CAP')
        records.append({'module':module['module'],'version':module['version'],'inputs':inputs,'members':members})
    # An empty separate cwd and fresh GOPATH contain no trusted go.sum or SumDB cache.
    # The admitted Go downloader authenticates canonical SumDB signed notes/tiles itself.
    empty=work/'sumdb-check'; empty.mkdir(); env=environment(work,compiler,None,work/'sumdb-go-cache')
    require(not (work/'gopath/pkg').exists(),'SUMDB_CACHE_NOT_FRESH')
    env['GOPROXY']=(work/'proxy').as_uri()
    args=[str(go),'mod','download','-json',*[x['module']+'@'+x['version'] for x in ref['graph']['modules']]]
    remaining=int(600-(time.monotonic()-budget[1])); require(remaining>0,'ACQUIRE_PHASE_WALL_CAP')
    result=run(args,cwd=empty,env=env,timeout=remaining,evidence=work/'evidence/sumdb-download')
    observed=sequence((work/'evidence/sumdb-download/stdout.log').read_text())
    expected={(m['module'],m['version']):m for m in ref['graph']['modules']}
    require(len(observed)==20 and {(m.get('Path'),m.get('Version')) for m in observed}==set(expected),'AUTHENTICATED_MODULE_SET')
    for row in observed:
        m=expected[row['Path'],row['Version']]
        require(not row.get('Error') and row.get('Sum')==m['moduleH1'] and row.get('GoModSum')==m['goModH1'],'AUTHENTICATED_SUM')
    sumdb=work/'gopath/pkg/sumdb'; require(sumdb.is_dir() and any(sumdb.rglob('latest')),'SUMDB_CHECKPOINT_MISSING')
    checkpoints=[{'path':str(p.relative_to(work)),'sha256':digest(p)} for p in sumdb.rglob('*') if p.is_file()]
    # Freeze the actual module cache. Later build phases run with GOPROXY=off.
    cache=work/'gopath/pkg/mod'; members=[]
    for p in sorted(cache.rglob('*')):
        require(not p.is_symlink(),'MODULE_CACHE_LINK')
        if p.is_file(): members.append({'path':p.relative_to(cache).as_posix(),'bytes':p.stat().st_size,'sha256':digest(p)})
    require(members and checkpoints,'AUTHENTICATED_CACHE_MISSING')
    write(work/'evidence/modules.json',{'state':'ACTUAL_SUMDB_AUTHENTICATED_MODULES','inputs':records,'cacheMembers':members,'checkpoints':checkpoints,'process':result})
    capacity(work)

def pinned(ref, section, name, path):
    expected=ref.get(section,{}).get(name)
    require(type(expected) is str and digest(path)==expected,'INPUT_SEAL:'+name)

def metadata_pins(ref):
    selected={(m['module'],m['version']) for m in ref['graph']['modules']};out=[]
    for line in ref['graph']['sumText'].splitlines():
        module,version,h1=line.split()
        if version.endswith('/go.mod') and (module,version[:-7]) not in selected:
            out.append({'module':module,'version':version[:-7],'goModH1':h1})
    require({(r['module'],r['version']) for r in out}=={('golang.org/x/sys','v0.6.0'),('golang.org/x/sys','v0.42.0')},'HISTORICAL_METADATA_PIN_SET')
    return out

def module_cache(work,ref):
    pinned(ref,'inputs','modulesReceiptSha256',work/'evidence/modules.json')
    record=read_json(work/'evidence/modules.json',8*1024*1024)
    require(record.get('state')=='ACTUAL_SUMDB_AUTHENTICATED_MODULES','MODULES_UNADMITTED')
    rows=record['cacheMembers'][:]
    if ref.get('inputs',{}).get('metadataReceiptSha256'):
        pinned(ref,'inputs','metadataReceiptSha256',work/'evidence/historical-metadata.json')
        meta=read_json(work/'evidence/historical-metadata.json',8*1024*1024)
        require(meta.get('moduleReceiptSha256')==ref['inputs']['modulesReceiptSha256'] and meta.get('sumSha256')==ref['graph']['sumSha256'] and meta.get('metadataPins')==metadata_pins(ref),'HISTORICAL_METADATA_BINDING')
        require(meta.get('codeZips')==0 and meta.get('selectedModules')==20,'HISTORICAL_METADATA_CODE_FORBIDDEN')
        expected_paths={'cache/download/'+escaped(r['module'])+'/@v/'+escaped(r['version'])+'.'+suffix for r in metadata_pins(ref) for suffix in ('mod','info')}
        require({r['path'] for r in meta['primaryAddedFiles']}==expected_paths and len(meta['primaryAddedFiles'])==4 and all(r['bytes']<=1048576 for r in meta['primaryAddedFiles']),'HISTORICAL_PRIMARY_PATH_SET')
        rows+=meta['primaryAddedFiles']
        for row in meta['proofFiles']: check_file_hash(contained(work/row['path'],work),row['sha256'],'METADATA_PROOF_BYTES')
    verify_members(work/'gopath/pkg/mod',rows)
    for row in record['checkpoints']: check_file_hash(contained(work/row['path'],work),row['sha256'],'SUMDB_CHECKPOINT_BYTES')
    return record

def historical_metadata(work,ref,compiler,go):
    # Only the2 already approved sidecar go.mod h1 pins; no lower-version source ZIP.
    scope=ref['execution']['metadataScopeGate'];scope_path=input_locations()['metadataScopeGate'];check_file_hash(scope_path,scope['sha256'],'METADATA_SCOPE_BYTES')
    gate=read_json(scope_path);require(gate.get('status')=='ACCEPTED_EXACT_METADATA_ONLY_S2_CLARIFICATION' and gate.get('planSha256')==scope['planSha256'] and gate.get('unchangedModSha256')==ref['graph']['modSha256'] and gate.get('unchangedSumSha256')==ref['graph']['sumSha256'] and gate.get('selectedModulesUnchanged')==20 and gate.get('selectedXsys')=='v0.44.0','METADATA_SCOPE_BINDING')
    pins=metadata_pins(ref);require([{k:r[k] for k in ('module','version','goModH1')} for r in gate['exactMetadataOnly']]==pins,'METADATA_SCOPE_NODES')
    overlay(work,ref);module_cache(work,ref);root=work/'historical-metadata';root.mkdir(exist_ok=False)
    require(not (work/'metadata-gopath').exists(),'METADATA_GOPATH_NOT_FRESH')
    budget=[0,time.monotonic()];raw=[]
    for row in pins:
        base=work/'proxy'/escaped(row['module'])/'@v';base.mkdir(parents=True,exist_ok=True);inputs={}
        for suffix in ('mod','info'):
            path=base/(escaped(row['version'])+'.'+suffix)
            inputs[suffix]=fetch('https://proxy.golang.org/'+escaped(row['module'])+'/@v/'+escaped(row['version'])+'.'+suffix,path,budget,1024*1024)
        mod=base/(escaped(row['version'])+'.mod');h1='h1:'+base64.b64encode(hashlib.sha256((digest(mod)+'  go.mod\n').encode()).digest()).decode()
        require(h1==row['goModH1'],'HISTORICAL_GOMOD_H1')
        require(read_json(base/(escaped(row['version'])+'.info')).get('Version')==row['version'],'HISTORICAL_INFO_VERSION')
        raw.append(dict(row,inputs=inputs))
    require(budget[0]<=4*1024*1024,'HISTORICAL_INPUT_CAP')
    empty=root/'empty-cwd';empty.mkdir();env=environment(work,compiler,None,work/'metadata-go-cache')
    env['GOPATH']=str(work/'metadata-gopath');env['GOPROXY']=(work/'proxy').as_uri()
    query=[go,'list','-m','-json',*[r['module']+'@'+r['version'] for r in pins]]
    result=run(list(map(str,query)),cwd=empty,env=env,timeout=300,evidence=root/'query')
    observed=sequence((root/'query/stdout.log').read_text());require({(r.get('Path'),r.get('Version')) for r in observed}=={(r['module'],r['version']) for r in pins} and len(observed)==2,'HISTORICAL_QUERY_SET')
    secondary=work/'metadata-gopath';files=[p for p in secondary.rglob('*') if p.is_file()]
    require(files and not any(p.name.endswith(('.zip','.ziphash')) for p in files),'HISTORICAL_CODE_ZIP_FORBIDDEN')
    require(all(p.relative_to(secondary).as_posix().startswith(('pkg/mod/cache/','pkg/sumdb/')) for p in files),'HISTORICAL_MATERIALIZATION_FORBIDDEN')
    require(any(p.name=='latest' and '/sumdb/' in p.as_posix() for p in files),'HISTORICAL_SUMDB_CHECKPOINT_MISSING')
    lookups=[p for p in files if '/lookup/' in p.as_posix()]
    for row in pins:
        expected=row['module']+' '+row['version']+'/go.mod '+row['goModH1']
        require(any(expected in p.read_text().splitlines() for p in lookups),'HISTORICAL_AUTHENTICATED_LOOKUP_MISSING')
    proofs=[{'path':p.relative_to(work).as_posix(),'bytes':p.stat().st_size,'sha256':digest(p)} for p in files]
    added=[]
    # All fresh crypto checks finish before adding metadata to the existing production cache.
    for row in pins:
        for suffix in ('mod','info'):
            relative='cache/download/'+escaped(row['module'])+'/@v/'+escaped(row['version'])+'.'+suffix
            source=contained(secondary/'pkg/mod'/relative,secondary);target=contained(work/'gopath/pkg/mod'/relative,work,existing=False)
            require(not target.exists(),'HISTORICAL_PRIMARY_FILE_EXISTS');target.parent.mkdir(parents=True,exist_ok=True)
            if suffix=='mod':require(digest(source)==next(x for x in raw if (x['module'],x['version'])==(row['module'],row['version']))['inputs']['mod']['sha256'],'HISTORICAL_CACHE_MOD_BYTES')
            else:require(read_json(source).get('Version')==row['version'],'HISTORICAL_CACHE_INFO_VERSION')
            with open(source,'rb') as src,open(target,'xb') as dst:shutil.copyfileobj(src,dst,1024*1024)
            added.append({'path':relative,'bytes':target.stat().st_size,'sha256':digest(target)})
    write(work/'evidence/historical-metadata.json',{'state':'ACTUAL_ALREADY_SUM_PINNED_METADATA_AUTHENTICATED_NO_CODE','metadataPins':pins,'inputs':raw,'primaryAddedFiles':added,'proofFiles':proofs,'sumSha256':ref['graph']['sumSha256'],'moduleReceiptSha256':digest(work/'evidence/modules.json'),'codeZips':0,'selectedModules':20,'infoTrust':'TLS raw metadata plus exact Version/bytes/hash; timestamps/code are not SumDB-attested','modTrust':'Canonical SumDB go.mod h1 via actual admitted Go from fresh separate cache; signed lookup/checkpoint frozen','process':result})
    capacity(work)


def package_graph(work,ref,compiler,go,target,attempt=1):
    source_tree(work/'source',ref); overlay(work,ref); module_cache(work,ref)
    suffix=target+('' if attempt==1 else '-02')
    env=environment(work,compiler,target,work/('graph-cache-'+suffix)); env['SOURCE_DATE_EPOCH']=ref['recipe']['sourceDateEpoch']
    dest=work/'evidence'/('graph-'+suffix); require(not dest.exists(),'GRAPH_ALREADY_ATTEMPTED')
    mvs=work/'evidence'/('mvs-'+suffix)
    command([go,'list','-mod=readonly','-modfile='+str(overlay(work,ref)),'-m','-json','all'],work,env,mvs,300)
    module_rows=sequence((mvs/'stdout.log').read_text());table={m['module']:m['version'] for m in ref['graph']['modules']}
    require(sum(1 for row in module_rows if row.get('Main') and row.get('Path')=='github.com/rhysd/actionlint')==1,'MVS_MAIN_IDENTITY')
    require(len({row.get('Path') for row in module_rows})==len(module_rows),'MVS_DUPLICATE')
    for row in module_rows:
        require(not row.get('Error') and not row.get('Replace'),'MVS_UNAPPROVED_OVERRIDE')
        if not row.get('Main'):require(table.get(row.get('Path'))==row.get('Version') and row.get('Path') in table,'MVS_UNAPPROVED_MODULE')
    command([go,'list','-buildvcs=false','-mod=readonly','-modfile='+str(overlay(work,ref)),'-deps','-json','./cmd/actionlint'],work,env,dest,600)
    finish_graph_binding(work,ref,target,dest,mvs)

def finish_graph_binding(work,ref,target,dest,mvs):
    rows=sequence((dest/'stdout.log').read_text()); table={m['module']:m['version'] for m in ref['graph']['modules']}
    imports={p.get('ImportPath') for p in rows}; require('github.com/rhysd/actionlint/cmd/actionlint' in imports,'GRAPH_ENTRY_MISSING')
    modules={'github.com/rhysd/actionlint'}
    for row in rows:
        require(not row.get('Error') and not row.get('DepsErrors') and not row.get('Incomplete'),'GRAPH_INCOMPLETE')
        module=row.get('Module')
        if module and not module.get('Main'):
            require(not module.get('Replace') and table.get(module.get('Path'))==module.get('Version'),'GRAPH_UNAPPROVED_MODULE')
            modules.add(module['Path'])
    require('plugin' not in imports and 'runtime/cgo' not in imports,'GRAPH_DYNAMIC_OR_CGO')
    source_tree(work/'source',ref); overlay(work,ref)
    # Go may write cache download locks: re-freeze only after verifying all existing bytes.
    write(dest/'binding.json',{'target':target,'sourceCommit':ref['source']['commit'],'sourceTree':ref['source']['tree'],'compilerSha256':ref['compiler']['archiveSha256'],'graphSha256':hashlib.sha256((ref['graph']['modText']+ref['graph']['sumText']).encode()).hexdigest(),'sourcePackageGraphSha256':digest(dest/'stdout.log'),'productionModules':sorted(modules),'dynamicPluginImports':[],'moduleReceiptSha256':digest(work/'evidence/modules.json'),'mvsGraphSha256':digest(mvs/'stdout.log'),'mvsEvidenceDirectory':mvs.name})

def finish_existing_graph(work,ref,target):
    approved=ref.get('graphRawReferences',{}).get(target);require(type(approved) is dict,'RAW_GRAPH_UNADMITTED')
    identity={k:ref['graph'][k] for k in ('modSha256','sumSha256')}
    identity.update({'sourceCommit':ref['source']['commit'],'compilerSha256':ref['compiler']['archiveSha256'],'modulesReceiptSha256':ref['inputs']['modulesReceiptSha256'],'metadataReceiptSha256':ref['inputs']['metadataReceiptSha256']})
    require(approved['inputIdentity']==identity,'RAW_GRAPH_INPUT_IDENTITY')
    for name,expected in approved['evidence'].items():path_parts(name);check_file_hash(contained(work/'evidence'/name,work),expected,'RAW_GRAPH_BYTES')
    mvs=contained(work/'evidence'/approved['paths']['mvs'],work);dest=contained(work/'evidence'/approved['paths']['packages'],work)
    require(not (dest/'binding.json').exists(),'GRAPH_ALREADY_FINALIZED')
    expected_limits={'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'200000 100000'}
    for folder in (mvs,dest):
        process=read_json(folder/'process.json');before=process['childBeforeExec']
        require(process.get('exitCode')==0 and process.get('timedOut') is False and before.get('stateBeforeExec')=='T' and before.get('kernelLimitsBeforeExec')==expected_limits and before.get('processStartIdentity'),'RAW_GRAPH_PROCESS_PROOF')
    module_rows=sequence((mvs/'stdout.log').read_text());table={m['module']:m['version'] for m in ref['graph']['modules']}
    require(sum(bool(r.get('Main')) and r.get('Path')=='github.com/rhysd/actionlint' for r in module_rows)==1,'MVS_MAIN_IDENTITY')
    require(len({r.get('Path') for r in module_rows})==len(module_rows),'MVS_DUPLICATE')
    for row in module_rows:
        require(not row.get('Error') and not row.get('Replace'),'MVS_UNAPPROVED_OVERRIDE')
        if not row.get('Main'):require(row.get('Path') in table and table[row['Path']]==row.get('Version'),'MVS_UNAPPROVED_MODULE')
    module_cache(work,ref);finish_graph_binding(work,ref,target,dest,mvs)

def graph_binding(work,ref,target):
    name=ref.get('targetGraphPaths',{}).get(target,'graph-'+target);path_parts(name)
    require(name in ('graph-'+target,'graph-'+target+'-02'),'GRAPH_EVIDENCE_DIRECTORY')
    folder=work/'evidence'/name
    pinned(ref,'targetGraphs',target,digest_path:=folder/'binding.json')
    row=read_json(digest_path)
    require(row['target']==target and row['sourceCommit']==ref['source']['commit'] and row['sourceTree']==ref['source']['tree'] and row['compilerSha256']==ref['compiler']['archiveSha256'],'GRAPH_BINDING')
    require(row['sourcePackageGraphSha256']==digest(folder/'stdout.log') and row['moduleReceiptSha256']==digest(work/'evidence/modules.json') and row['mvsGraphSha256']==digest(work/'evidence'/row['mvsEvidenceDirectory']/'stdout.log'),'GRAPH_EVIDENCE_BYTES')
    return row

def notice_name(path):
    name=Path(path).name.upper()
    return any(name==x or name.startswith(x+'.') or name.startswith(x+'-') for x in ('LICENSE','LICENCE','COPYING','NOTICE','PATENTS','AUTHORS'))

def capture_notices(work,ref,compiler):
    source_tree(work/'source',ref);modules=module_cache(work,ref)
    inputs=ref['auditor']['admission'].get('noticeInputs');require(type(inputs) is list and inputs,'AUDITOR_NOTICES_UNADMITTED')
    dest=work/'notices';dest.mkdir(exist_ok=False);files=[];represented=[]
    def save(relative,raw,expected):
        path_parts(relative);require(hashlib.sha256(raw).hexdigest()==expected,'NOTICE_INPUT_BYTES')
        require(len(raw)<=2*1024*1024,'NOTICE_TEXT_CAP')
        p=contained(dest/relative,dest,existing=False);p.parent.mkdir(parents=True,exist_ok=True)
        with open(p,'xb') as stream:stream.write(raw)
        files.append({'path':relative,'sha256':expected,'bytes':len(raw)})
    source=[r for r in ref['source']['members'] if notice_name(r['path'])]
    require(source,'SOURCE_NOTICE_MISSING')
    for row in source:save('actionlint/'+row['path'],(work/'source'/row['path']).read_bytes(),row['sha256'])
    for module in modules['inputs']:
        archive=contained(work/'proxy'/escaped(module['module'])/'@v'/(escaped(module['version'])+'.zip'),work)
        check_file_hash(archive,module['inputs']['zip']['sha256'],'NOTICE_MODULE_CONTAINER_BYTES')
        rows=[r for r in module['members'] if r['type']=='file' and notice_name(r['path'])]
        require(rows,'MODULE_NOTICE_MISSING:'+module['module'])
        import zipfile
        with zipfile.ZipFile(archive) as z:
            for row in rows:save('modules/'+row['path'],z.read(row['path']),row['sha256'])
        represented.append(module['module']+'@'+module['version'])
    manifest=ref['compiler']['admission']['membersFile'];manifest_path=input_locations()['compiler']['membersFile'];check_file_hash(manifest_path,manifest['sha256'],'TOOL_MEMBER_MANIFEST_BYTES')
    members=read_json(manifest_path,8*1024*1024);prefix=ref['compiler']['admission']['memberPrefix']
    for row in members:
        if notice_name(row['path']):save('compiler/'+row['path'][len(prefix):],(compiler/row['path'][len(prefix):]).read_bytes(),row['sha256'])
    # The producer's separate auditor graph/notices must be explicitly pinned in the handoff.
    for i,row in enumerate(inputs):
        p=Path(input_locations()['noticeInputs'][row['key']]);check_file_hash(p,row['sha256'],'AUDITOR_NOTICE_BYTES')
        save('auditor/'+str(i)+'-'+row['filename'],p.read_bytes(),row['sha256'])
    write(work/'evidence/notices.json',{'state':'ORIGINAL_TEXTS_CAPTURED_REVIEW_REQUIRED','files':files,'modules':represented,'moduleReceiptSha256':digest(work/'evidence/modules.json'),'compilerReceiptSha256':ref['compiler']['admission']['receipt']['sha256'],'auditorReceiptSha256':ref['auditor']['admission']['receipt']['sha256']})
    capacity(work)

def checked_notices(work,ref):
    pinned(ref,'inputs','noticesReceiptSha256',work/'evidence/notices.json')
    require(ref['inputs'].get('noticesState')=='REVIEWED_ORIGINAL_TOOLING_NOTICES','TOOLING_NOTICE_REVIEW_PENDING')
    row=read_json(work/'evidence/notices.json',8*1024*1024)
    require(set(row['modules'])=={m['module']+'@'+m['version'] for m in ref['graph']['modules']},'NOTICE_MODULE_SET')
    for file in row['files']:check_file_hash(contained(work/'notices'/file['path'],work),file['sha256'],'NOTICE_BYTES')
    require(row['compilerReceiptSha256']==ref['compiler']['admission']['receipt']['sha256'] and row['auditorReceiptSha256']==ref['auditor']['admission']['receipt']['sha256'],'NOTICE_TOOL_BINDING')
    return row

def database(ref):
    snapshot=ref.get('auditDatabase'); require(type(snapshot) is dict,'DATABASE_UNADMITTED')
    locations=input_locations()['auditDatabase'];root=Path(locations['root']);verify_members(root,snapshot['members'])
    require(digest(locations['archivePath'])==snapshot['archiveSha256'],'DATABASE_BYTES')
    return root,snapshot['archiveSha256']

def audit_protocol(folder,*,mode,db_hash,expected_config):
    # govulncheck -json is a framed object stream; a config-only or empty stream cannot clear findings.
    rows=sequence((folder/'stdout.log').read_text()); configs=[]; findings=[]; osvs={}; packages=set(); progress=[]
    for row in rows:
        require(len(row)==1,'AUDIT_PROTOCOL_MESSAGE')
        key=next(iter(row)); require(key in ('config','progress','osv','finding','SBOM'),'AUDIT_PROTOCOL_UNKNOWN')
        if key=='config': configs.append(row[key])
        elif key=='finding': findings.append(row[key])
        elif key=='osv': require(row[key].get('id'),'AUDIT_OSV_ID'); osvs[row[key]['id']]=row[key]
        elif key=='progress': progress.append(row[key])
        elif key=='SBOM':
            sbom=row[key]; require(sbom.get('go_version')=='go1.26.11' and sbom.get('roots')==[('github.com/rhysd/actionlint' if mode=='binary' else 'github.com/rhysd/actionlint/cmd/actionlint')] and sbom.get('modules'),'AUDIT_SBOM_BINDING')
            packages.add(json.dumps(sbom,sort_keys=True))
    require(next(iter(rows[0]))=='config' and len(configs)==1 and configs[0].get('scanner_name')=='govulncheck' and configs[0].get('protocol_version')=='v1.0.0','AUDIT_SCANNER_IDENTITY')
    require(type(expected_config) is dict and expected_config.get('scanner_version') is not None and all(configs[0].get(k)==v for k,v in expected_config.items()),'AUDIT_CONFIG_BINDING')
    require(configs[0].get('scan_mode')==mode and configs[0].get('scan_level')=='symbol' and configs[0].get('db') and packages,'AUDIT_PROTOCOL_INCOMPLETE')
    require(configs[0].get('go_version')=='go1.26.11' if mode=='source' else configs[0].get('go_version') in (None,'go1.26.11'),'AUDIT_CONFIG_COMPILER')
    require(all(f.get('osv') in osvs and isinstance(f.get('trace'),list) and f['trace'] for f in findings),'AUDIT_FINDING_PROTOCOL')
    return {'config':configs[0],'findingIds':sorted({f['osv'] for f in findings}),'findings':findings,'osvIds':sorted(osvs),'databaseSha256':db_hash,'protocolComplete':True,'streamSha256':digest(folder/'stdout.log'),'sbom':sbom}

def scan(work,ref,compiler,auditor,target,binary=False):
    source_tree(work/'source',ref); overlay(work,ref); module_cache(work,ref); checked_notices(work,ref); binding=graph_binding(work,ref,target)
    db,db_hash=database(ref); mode='binary' if binary else 'source'; folder=work/'evidence'/(mode+'-audit-'+target)
    env=environment(work,compiler,target,work/(mode+'-audit-cache-'+target))
    args=[auditor,'-json','-db='+db.as_uri(),'-mode='+mode]
    if binary:
        image=work/'builds'/target/'1'/('actionlint.exe' if target.startswith('windows') else 'actionlint')
        require(image.is_file(),'BINARY_NOT_BUILT'); args.append(image)
    else:
        # Explicit modfile argument belongs to source analysis only, never to auditor compilation.
        env['GOFLAGS']='-mod=readonly '+chr(34)+'-modfile='+str(overlay(work,ref))+chr(34)
        args.append('./cmd/actionlint')
    command(args,work,env,folder,600)
    record=audit_protocol(folder,mode=mode,db_hash=db_hash,expected_config=dict(ref['auditor']['admission']['protocolConfig'],db=db.as_uri(),scan_mode=mode,scan_level='symbol',**({'go_version':'go1.26.11'} if mode=='source' else {}))); record['binding']=binding
    if binary:
        bind_binary_sbom(record,read_json(image.parent/'buildinfo/stdout.log'),target,ref);record['binarySha256']=digest(image)
    write(folder/'protocol.json',record)

def bind_binary_sbom(record,info,target,ref):
    validate_buildinfo(info,target,ref);sbom=record['sbom']
    expected={r['Path']:r['Version'] for r in [info['Main'],*info['Deps']]};expected['stdlib']='go1.26.11'
    rows=sbom['modules'];require(len(rows)==len(expected) and {r.get('path'):r.get('version') for r in rows}==expected,'AUDIT_BINARY_SBOM_MODULES')

def finish_binary_audit(work,ref,target):
    folder=work/'evidence'/('binary-audit-'+target);require(not (folder/'protocol.json').exists(),'BINARY_AUDIT_ALREADY_FINALIZED')
    pins=ref.get('auditRecovery',{}).get(target);require(type(pins) is dict,'AUDIT_RECOVERY_UNAPPROVED')
    for name,sha in pins['evidence'].items():check_file_hash(contained(folder/name,folder),sha,'AUDIT_RECOVERY_BYTES')
    image=work/'builds'/target/'1'/('actionlint.exe' if target.startswith('windows') else 'actionlint');check_file_hash(image,pins['binarySha256'],'AUDIT_RECOVERY_BINARY')
    process=read_json(folder/'process.json');limits={'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'200000 100000'};child=process.get('childBeforeExec',{});cap=process.get('actualCap',{})
    require(process.get('exitCode')==0 and process.get('timedOut') is False and child.get('stateBeforeExec')=='T' and child.get('kernelLimitsBeforeExec')==limits and cap.get('kernelLimits')==limits and child.get('pid')==process.get('pid') and child.get('processStartIdentity') and child.get('cgroup')=='0::'+cap.get('cgroup',''),'AUDIT_RECOVERY_PROCESS')
    db=Path(input_locations()['auditDatabase']['root']);argv=process.get('argv',[])
    require(len(argv)==5 and argv[1:]==['-json','-db='+db.as_uri(),'-mode=binary',str(image)],'AUDIT_RECOVERY_ARGV')
    record=audit_protocol(folder,mode='binary',db_hash=ref['auditDatabase']['archiveSha256'],expected_config=dict(ref['auditor']['admission']['protocolConfig'],db=db.as_uri(),scan_mode='binary',scan_level='symbol'))
    bind_binary_sbom(record,read_json(image.parent/'buildinfo/stdout.log'),target,ref);record['binding']=graph_binding(work,ref,target);record['binarySha256']=digest(image);write(folder/'protocol.json',record)

def build(work,ref,compiler,go,target,number):
    require(number in (1,2),'BUILD_COUNT'); source_tree(work/'source',ref); overlay(work,ref); module_cache(work,ref); checked_notices(work,ref)
    binding=graph_binding(work,ref,target); source_scan=read_json(work/'evidence'/('source-audit-'+target)/'protocol.json')
    pinned(ref,'sourceAudits',target,work/'evidence'/('source-audit-'+target)/'protocol.json')
    require(source_scan.get('protocolComplete') and source_scan.get('binding')==binding,'SOURCE_AUDIT_MISSING')
    output=work/'builds'/target/str(number); output.mkdir(parents=True,exist_ok=False)
    cache=output/'cache'; require(not cache.exists(),'BUILD_CACHE_NOT_FRESH'); cache.mkdir()
    env=environment(work,compiler,target,cache); env['SOURCE_DATE_EPOCH']=ref['recipe']['sourceDateEpoch']
    image=output/('actionlint.exe' if target.startswith('windows') else 'actionlint')
    args=[go,'build','-mod=readonly','-modfile='+str(overlay(work,ref)),'-p=1','-trimpath','-buildvcs=false','-ldflags='+LDFLAGS,'-o='+str(image),'./cmd/actionlint']
    result=command(args,work,env,output/'process',1200); inspect_format(image.read_bytes(),target)
    info=output/'buildinfo'; command([go,'version','-m','-json',image],work,env,info,90)
    data=read_json(info/'stdout.log'); validate_buildinfo(data,target,ref)
    finalize_build(work,ref,target,number)

def finalize_build(work,ref,target,number,recovery=False):
    """Complete validation of existing bytes; never execute or rebuild the target."""
    output=work/'builds'/target/str(number);image=output/('actionlint.exe' if target.startswith('windows') else 'actionlint')
    contained(image,work);require(not (output/'receipt.json').exists(),'BUILD_ALREADY_FINALIZED')
    binding=graph_binding(work,ref,target);checked_notices(work,ref)
    pinned(ref,'sourceAudits',target,work/'evidence'/('source-audit-'+target)/'protocol.json')
    if recovery:
        pins=ref.get('buildRecovery',{}).get(target+'-'+str(number));require(type(pins) is dict,'BUILD_RECOVERY_UNAPPROVED')
        for relative,sha in pins.items():check_file_hash(contained(output/relative,output),sha,'BUILD_RECOVERY_BYTES')
    result=read_json(output/'process/process.json');argv=result.get('argv');require(type(argv) is list and len(argv)==10,'BUILD_PROCESS_ARGV')
    require(argv[1:]==['build','-mod=readonly','-modfile='+str(overlay(work,ref)),'-p=1','-trimpath','-buildvcs=false','-ldflags='+LDFLAGS,'-o='+str(image),'./cmd/actionlint'],'BUILD_PROCESS_RECIPE')
    require(result.get('cwd')==str(work/'source') and result.get('exitCode')==0 and result.get('timedOut') is False,'BUILD_PROCESS_FAILED')
    limits={'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'200000 100000'}
    child=result.get('childBeforeExec',{});cap=result.get('actualCap',{})
    require(cap.get('kernelLimits')==limits and child.get('kernelLimitsBeforeExec')==limits and child.get('stateBeforeExec')=='T' and child.get('pid')==result.get('pid') and child.get('processStartIdentity'),'BUILD_PROCESS_UNBOUNDED')
    require(child.get('cgroup','').strip()=='0::'+cap.get('cgroup','') and cap.get('uid')==1000 and cap.get('bootId'),'BUILD_PROCESS_MEMBERSHIP')
    info=output/'buildinfo';meta=read_json(info/'process.json');require(meta.get('exitCode')==0 and meta.get('timedOut') is False and meta.get('argv')==[argv[0],'version','-m','-json',str(image)],'BUILDINFO_PROCESS')
    data=read_json(info/'stdout.log');validate_buildinfo(data,target,ref);inspect_format(image.read_bytes(),target)
    source_tree(work/'source',ref);overlay(work,ref)
    record={'target':target,'number':number,'sha256':digest(image),'bytes':image.stat().st_size,'buildInfoSha256':digest(info/'stdout.log'),'process':result,'binding':binding}
    write(output/'receipt.json',record)
    if number==2:
        first=read_json(work/'builds'/target/'1/receipt.json')
        require(first['sha256']==record['sha256'],'NONREPRODUCIBLE')
        write(work/'evidence'/('reproducibility-'+target+'.json'),{'target':target,'hashes':[first['sha256'],record['sha256']]})

def workspace_path(candidate,ref,existing):
    path=Path(candidate).absolute();local=ROOT/'artifacts/actionlint-build'
    if path==local or local in path.parents:return contained(path,local,existing=existing)
    approved=ref['execution'].get('nativeWorkspaceGate');require(type(approved) is dict,'NATIVE_WORKSPACE_UNAPPROVED')
    gate_path=input_locations()['nativeWorkspaceGate'];check_file_hash(gate_path,approved['sha256'],'NATIVE_WORKSPACE_GATE_BYTES')
    gate=read_json(gate_path);require(gate.get('status')=='AUTHORIZED_EXACT_LOCAL_NATIVE_WORKSPACE_CONDITIONAL_GUARDS' and gate.get('proposalSha256')==approved['proposalSha256'],'NATIVE_WORKSPACE_SCOPE')
    root=Path(gate['nativeRoot']);require(path==root,'NATIVE_WORKSPACE_EXACT_ROOT');contained(path,root,existing=existing)
    st=path.stat();require(os.getuid()==1000 and st.st_uid==1000 and st.st_gid==1000 and st.st_mode&0o777==0o700,'NATIVE_WORKSPACE_OWNER_MODE')
    check_file_hash(path/'evidence/materialization-receipt.json',approved['materializationReceiptSha256'],'NATIVE_WORKSPACE_MATERIALIZATION_BYTES')
    return path

def main():
    import sys
    if len(sys.argv)>1 and sys.argv[1]=='prepare-ci-sealed':prepare_sealed();return
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=['prepare','acquire','metadata','finish-graph','notices','graph','source-audit','build','finish-build','binary-audit','finish-binary-audit'])
    parser.add_argument('--work',type=Path,required=True); parser.add_argument('--source-archive',type=Path)
    parser.add_argument('--attempt',type=int,choices=[1,2],default=1)
    parser.add_argument('--target',choices=['windows-amd64','linux-amd64']); parser.add_argument('--number',type=int,choices=[1,2])
    args=parser.parse_args(); ref=validate_reference(read_json(LOCK),admitted=False)
    # Each consuming operation requires its actual tools. Null auditor pins block scans; no artifact is admitted.
    phase_permission(ref,os.environ); require(os.name!='nt','LINUX_COMPILER_ONLY'); linux_caps()
    work=workspace_path(args.work,ref,args.phase!='prepare')
    if args.phase=='finish-binary-audit':
        require(args.target is not None,'AUDIT_RECOVERY_TARGET');finish_binary_audit(work,ref,args.target)
        print(json.dumps({'state':'EXISTING_BINARY_AUDIT_FINALIZED_NO_ANALYZER_OR_TARGET_REEXECUTION','target':args.target}));return
    if args.phase=='finish-build':
        require(args.target is not None and args.number is not None,'BUILD_RECOVERY_TARGET');finalize_build(work,ref,args.target,args.number,True)
        print(json.dumps({'state':'EXISTING_BUILD_FINALIZED_NO_REBUILD_OR_TARGET_EXECUTION','target':args.target,'number':args.number}));return
    if args.phase=='finish-graph':
        require(args.target is not None,'TARGET_REQUIRED');finish_existing_graph(work,ref,args.target)
        print(json.dumps({'state':'EXISTING_QUALIFIED_GRAPH_FINALIZED_NO_GO_REEXECUTION','target':args.target}));return
    compiler,go,auditor=tools(ref,args.phase in ('notices','source-audit','binary-audit'))
    if args.phase=='prepare': require(args.source_archive is not None,'SOURCE_ARCHIVE_REQUIRED'); prepare(work,args.source_archive,ref)
    elif args.phase=='acquire': acquire(work,ref,compiler,go)
    elif args.phase=='metadata': historical_metadata(work,ref,compiler,go)
    elif args.phase=='notices': capture_notices(work,ref,compiler)
    else:
        require(args.target is not None,'TARGET_REQUIRED')
        if args.phase=='graph': package_graph(work,ref,compiler,go,args.target,args.attempt)
        elif args.phase=='source-audit': scan(work,ref,compiler,auditor,args.target)
        elif args.phase=='binary-audit': scan(work,ref,compiler,auditor,args.target,True)
        elif args.phase=='build': require(args.number is not None,'BUILD_NUMBER_REQUIRED'); build(work,ref,compiler,go,args.target,args.number)
    print(json.dumps({'state':'BOUNDED_PHASE_FINISHED_ARTIFACT_STILL_UNADMITTED','phase':args.phase,'work':str(work)}))

def prepare_sealed():
    """Explicit source-pinned import only; ordinary lint never downloads or builds."""
    import sys
    from bounded_actionlint import portable_phase
    parser=argparse.ArgumentParser();parser.add_argument('--target',choices=['windows-amd64','linux-amd64'],required=True);parser.add_argument('--archive',type=Path);parser.add_argument('--inner',action='store_true');args=parser.parse_args(sys.argv[2:])
    ref=validate_reference(read_json(LOCK));require(args.target==('windows' if os.name=='nt' else 'linux')+'-amd64','SEALED_NATIVE_TARGET')
    if not args.inner:
        with portable_phase(ref,ROOT,'prepare-sealed') as phase:
            import uuid
            out=ROOT/'artifacts/sealed-import'/uuid.uuid4().hex;out.mkdir(parents=True)
            argv=[sys.executable,'-B',str(Path(__file__).resolve()),'prepare-ci-sealed','--inner','--target',args.target]
            if args.archive:argv+=['--archive',str(args.archive.absolute())]
            phase.update(started=True,evidence=out/'process');result=run(argv,cwd=ROOT,env=os.environ.copy(),timeout=120,evidence=out/'process')
            print(json.dumps({'state':'ACTUAL_SEALED_IMPORT_CHILD_COMPLETE','target':args.target,'actualCap':result['actualCap'],'receiptSha256':digest(out/'process/process.json')}))
        return
    phase_permission(ref,os.environ)
    asset=ref.get('distribution',{}).get('assets',{}).get(args.target);require(type(asset) is dict,'SEALED_DISTRIBUTION_UNAPPROVED')
    require(0<asset['bytes']<=64*1024**2 and asset['url'].startswith('https://github.com/pouriajamali/data-admission-gate/releases/download/tooling-actionlint-v1.7.12-go1.26.11-r1/'),'SEALED_ASSET_SCOPE')
    if args.archive:path=contained(args.archive,args.archive.parent)
    else:
        import uuid
        root=ROOT/'artifacts/sealed-downloads'/uuid.uuid4().hex;root.mkdir(parents=True);path=root/'sealed.zip'
        require(not any(os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')),'SEALED_PROXY_ENV')
        class Redirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,request,fp,code,msg,headers,url):
                p=urllib.parse.urlsplit(url);require(p.scheme=='https' and p.hostname in ('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com') and p.username is None and p.port in (None,443),'SEALED_REDIRECT')
                return super().redirect_request(request,fp,code,msg,headers,url)
        start=time.monotonic();total=0
        with urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirect()).open(asset['url'],timeout=30) as response,open(path,'xb') as output:
            while True:
                chunk=response.read(1024*1024)
                if not chunk:break
                total+=len(chunk);require(total<=asset['bytes'] and time.monotonic()-start<=90,'SEALED_DOWNLOAD_CAP');output.write(chunk)
    require(path.stat().st_size==asset['bytes'],'SEALED_ARCHIVE_SIZE');check_file_hash(path,asset['sha256'],'SEALED_ARCHIVE_BYTES')
    rows=archive_inventory(path,expanded_cap=128*1024**2,count_cap=1000);require(all(r['bytes']<=64*1024**2 for r in rows),'SEALED_MEMBER_CAP')
    dest=ROOT/'artifacts/actionlint'/args.target;require(not dest.exists(),'SEALED_DESTINATION_EXISTS');dest.mkdir(parents=True)
    import zipfile
    with zipfile.ZipFile(path) as archive:
        for row in rows:
            target=contained(dest/row['path'],dest,existing=False)
            if row['type']=='directory':target.mkdir(parents=True,exist_ok=True);continue
            target.parent.mkdir(parents=True,exist_ok=True)
            with archive.open(row['path']) as source,open(target,'xb') as output:shutil.copyfileobj(source,output,1024*1024)
            check_file_hash(target,row['sha256'],'SEALED_MATERIALIZED_BYTES')
    from check_actionlint import admitted_artifact
    with admitted_artifact(ref,dest,args.target):pass
    print(json.dumps({'state':'SEALED_INPUTS_IMPORTED_NO_TARGET_EXECUTION','target':args.target,'archiveSha256':asset['sha256']}))



if __name__=='__main__':
    try: main()
    except (AdmissionError,CapError,OSError,KeyError,TypeError,ValueError) as exc: raise SystemExit('actionlint build HOLD: '+str(exc))
