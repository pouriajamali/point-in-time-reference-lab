"""Independent component rejections; full50 admission proof requires actual admitted inputs.

These checks are useful before tools arrive, but never stand in for the approved
50-vector x3 complete run or actual native valid/invalid workflow controls.
"""
from __future__ import annotations
import argparse, copy, importlib.util, io, json, os, shutil, subprocess, sys, tarfile, tempfile, time, zipfile
from pathlib import Path
from unittest.mock import patch
import check_actionlint as c
import bounded_actionlint as b
import build_actionlint as g
ROOT=Path(__file__).resolve().parents[1]

class TestFailure(RuntimeError): pass

def need(value,reason):
    if not value: raise TestFailure(reason)

def archive(path,rows,kind='tar'):
    if kind=='zip':
        with zipfile.ZipFile(path,'w') as z:
            for name,data in rows: z.writestr(name,data)
    else:
        with tarfile.open(path,'w') as z:
            for name,typecode,data in rows:
                item=tarfile.TarInfo(name); item.type=typecode; item.mode=0o644
                if typecode==tarfile.REGTYPE: item.size=len(data); z.addfile(item,io.BytesIO(data))
                else: item.linkname='../outside'; z.addfile(item)

def baseline_audit():
    # Literal control values; no expected value is taken from checker output.
    e={'target':'linux-amd64','sourceCommit':c.SOURCE_COMMIT,'sourceTree':c.SOURCE_TREE,
       'compilerSha256':c.GO_SHA,'graphSha256':'1'*64,'databaseSha256':'2'*64,
       'sourcePackageGraphSha256':'3'*64,'binaryBuildInfoSha256':'4'*64,
       'findingIds':['GO-TEST-0001'],'findingModules':{'GO-TEST-0001':'golang.org/x/net'}}
    r={k:v for k,v in e.items() if k not in ('findingIds','findingModules')}
    r.update({'schema':'actionlint-audit/v1','sourceProductionModules':['github.com/rhysd/actionlint'],
       'binaryProductionModules':['github.com/rhysd/actionlint'],'sourceScanExit':0,'binaryScanExit':0,
       'protocolComplete':True,'dynamicPluginImports':[],
       'dispositions':[{'id':'GO-TEST-0001','module':'golang.org/x/net','status':'NOT_IN_SOURCE_OR_BINARY_PRODUCTION_MODULE_CLOSURE','sourceGraphSha256':'3'*64,'binaryGraphSha256':'4'*64}]})
    return r,e

def cap():
    return {'kernelLimits':{'memory.max':'4294967296','memory.swap.max':'0','pids.max':'64','cpu.max':'100000 100000'},
            'cgroup':'/user.slice/user-1000.slice/user@1000.service/app.slice/owned.service','uid':1000,'bootId':'fixed-fixture-boot'}

def owner(): return {'projectId':'05','randomToken':'literal-own-token','ownerPID':1234,'ownerProcessStartIdentity':'FILETIME:123456'}

def components(root,ref):
    cases=[]
    def add(id,expected,fn): cases.append((id,expected,fn))
    add('N01.1','JSON_TYPE',lambda:c.read_json(root/'missing.json'))
    bad=copy.deepcopy(ref);bad['schema']='unrecognized/v0'
    add('N01.2','REFERENCE_SCHEMA',lambda:c.validate_reference(bad,admitted=False))
    wrong=copy.deepcopy(ref);wrong['source']['commit']='0'*40
    add('N04.1','SOURCE_IDENTITY',lambda:c.validate_reference(wrong,admitted=False))
    graph=copy.deepcopy(ref)
    next(x for x in graph['graph']['modules'] if x['module']=='golang.org/x/sys')['version']='v0.42.0'
    add('N06.1','GRAPH_VERSION',lambda:c.validate_reference(graph,admitted=False))
    paths={'N09.1':'../escape','N09.2':'/absolute/escape','N10.1':'Z:/escape',
           'N10.2':r'\\host\share\escape','N10.3':r'root\escape.go',
           'N11.2':'bad\x01name'}
    for id,name in paths.items():
        p=root/(id+'.tar');archive(p,[(name,tarfile.REGTYPE,b'x')])
        expected='PATH_ESCAPE' if id=='N09.1' else 'PATH_CONTROL' if id=='N11.2' else 'PATH_ABSOLUTE_OR_WINDOWS'
        add(id,expected,lambda p=p:c.archive_inventory(p))
    # ZIP supports a raw embedded NUL; ZipInfo.orig_filename retains framing before truncation.
    p=root/'nul.zip';archive(p,[('badXname',b'x')],'zip');data=p.read_bytes().replace(b'badXname',b'bad\0name');p.write_bytes(data)
    add('N11.1','PATH_CONTROL',lambda:c.archive_inventory(root/'nul.zip'))
    for id,names in [('N12.1',['root/go.mod','root/go.mod']),('N12.2',['root/A.go','root/a.go'])]:
        p=root/(id+'.tar');archive(p,[(n,tarfile.REGTYPE,b'x') for n in names]);add(id,'ARCHIVE_DUPLICATE',lambda p=p:c.archive_inventory(p))
    for id,code in [('N13.1',tarfile.SYMTYPE),('N13.2',tarfile.LNKTYPE),('N13.3',tarfile.FIFOTYPE),('N13.4',tarfile.CHRTYPE)]:
        p=root/(id+'.tar');archive(p,[('root/item',code,b'')]);add(id,'ARCHIVE_SPECIAL',lambda p=p:c.archive_inventory(p))
    p=root/'size.tar';archive(p,[('root/a',tarfile.REGTYPE,b'xx')]);add('N14.1','ARCHIVE_EXPANSION_CAP',lambda:c.archive_inventory(root/'size.tar',expanded_cap=1))
    p=root/'count.tar';archive(p,[('root/a',tarfile.REGTYPE,b'x'),('root/b',tarfile.REGTYPE,b'x')]);add('N14.2','ARCHIVE_COUNT_CAP',lambda:c.archive_inventory(root/'count.tar',count_cap=1))
    add('N15.2','PATH_OUTSIDE_ROOT',lambda:c.contained(root.parent/'outside',root,existing=False))
    for id,key,value in [('N16.1','GOTOOLCHAIN','auto'),('N16.2','GOFLAGS','-mod=mod'),('N16.3','GONOSUMDB','*'),('N16.4','GOAUTH','synthetic-external-command')]:
        add(id,'UNSAFE_ENV:'+key,lambda k=key,v=value:c.clean_environment({k:v},home=root,gopath=root,cache=root,temp=root))
    row,expected=baseline_audit();row['sourceScanExit']='UNKNOWN'
    add('N18.1','AUDIT_INCOMPLETE',lambda:c.validate_audit(row,expected))
    applicable,expect2=baseline_audit();applicable['dispositions'][0]['status']='APPLICABLE'
    add('N19.1','AUDIT_UNRESOLVED',lambda:c.validate_audit(applicable,expect2))
    mismatch,expect3=baseline_audit();mismatch['sourcePackageGraphSha256']='5'*64
    add('N19.2','AUDIT_BINDING:sourcePackageGraphSha256',lambda:c.validate_audit(mismatch,expect3))
    elf=bytearray(64);elf[:6]=b'\x7fELF\x02\x01';elf[18:20]=(62).to_bytes(2,'little')
    add('N20.1','BINARY_TARGET',lambda:c.inspect_format(elf,'windows-amd64'))
    compiler=copy.deepcopy(ref);compiler['compiler']['archiveSha256']='9'*64
    add('N20.3','COMPILER_IDENTITY',lambda:c.validate_reference(compiler,admitted=False))
    add('N21.1','ACTUAL_GUEST_CAP_MISMATCH',lambda:b.validate_linux_cap({}))
    add('N21.2','ACTUAL_GUEST_CAP_MISMATCH',lambda:b.validate_linux_cap({'kind':'Windows Job on wsl.exe','memoryMax':4294967296}))
    wrong_group=cap();wrong_group['cgroup']='/unqualified/frontend'
    add('N22.1','ACTUAL_GUEST_MEMBERSHIP',lambda:b.validate_linux_cap(wrong_group))
    wrong_memory=cap();wrong_memory['kernelLimits']['memory.max']='max'
    add('N22.2','ACTUAL_GUEST_CAP_MISMATCH',lambda:b.validate_linux_cap(wrong_memory))
    foreign=owner();foreign['randomToken']='foreign'
    add('N27.1','LEASE_NOT_OWNED',lambda:b.check_owner(foreign,owner()))
    release=owner();release['randomToken']='wrong-release'
    add('N27.2','LEASE_NOT_OWNED',lambda:b.check_owner(owner(),release))
    add('N28.1','UNSAFE_ENV:GOFLAGS',lambda:c.clean_environment({'GOFLAGS':'-modfile=actionlint.mod'},home=root,gopath=root,cache=root,temp=root))
    return cases

class XorReader:
    # Fault injection alters the actual borrowed input stream, not digest decisions or expected pins.
    # This keeps each synthetic mutation below64KiB without writing a large corrupt executable.
    def __init__(self,stream,offset=0,suffix=None): self.stream=stream; self.offset=offset; self.position=0; self.suffix=suffix
    def readable(self): return True
    def readinto(self,buffer):
        n=self.stream.readinto(buffer)
        if n and self.suffix is None and self.position<=self.offset<self.position+n: buffer[self.offset-self.position]^=1
        self.position+=n
        if not n and self.suffix:
            n=min(len(buffer),len(self.suffix));buffer[:n]=self.suffix[:n];self.suffix=self.suffix[n:]
        return n
    def __enter__(self): return self
    def __exit__(self,*args): self.stream.close()

def xor_input(path,operation,offset=0,suffix=None):
    original=open
    def altered(name,*args,**kwargs):
        stream=original(name,*args,**kwargs)
        return XorReader(stream,offset,suffix) if Path(name)==Path(path) else stream
    with patch.object(c,'open',side_effect=altered,create=True): return operation()

def shadow(source,dest):
    c.contained(dest,ROOT.parent,existing=False)
    shutil.copytree(source,dest,copy_function=os.link)
    return dest

def import_entry(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def complete_vectors(root,ref,work,vendor):
    # Actual independent admission of both unchanged artifacts is a prerequisite, not a synthetic PASS.
    host='windows-amd64' if os.name=='nt' else 'linux-amd64';bundles=ROOT/'artifacts/actionlint'
    for target in ('windows-amd64','linux-amd64'):
        with c.admitted_artifact(ref,bundles/target,target): pass
    g.source_tree(work/'source',ref);modules=g.module_cache(work,ref)
    need(c.digest(vendor)=='54ca21be3de4c7cfa26914aa8b61bd76bf573ef3caac5f80d110558cdf241718','STALE_VENDOR_CONTROL_IDENTITY')
    items=[]
    def add(id,expected,fn): items.append((id,expected,fn))
    name='actionlint.exe' if host.startswith('windows') else 'actionlint';image=bundles/host/name;approved=ref['admission']['artifacts'][host]
    changed=shadow(bundles/host,root/'candidate-self-claim');manifest=c.read_json(changed/'admission.json')
    manifest.update({'PASS':True,'sha256':xor_input(image,lambda:c.digest(image))});(changed/'admission.json').unlink();(changed/'admission.json').write_text(json.dumps(manifest))
    def claimed():
        with c.admitted_artifact(ref,changed,host): raise TestFailure('SELF_CLAIM_WAS_ACCEPTED')
    add('N02.1','BINARY_BYTES',lambda:xor_input(changed/name,claimed))
    windows=ref['admission']['artifacts']['windows-amd64']
    expected='BINARY_SIZE' if vendor.stat().st_size!=windows['bytes'] else 'BINARY_BYTES'
    add('N03.1',expected,lambda:c.check_binary(vendor,windows,'windows-amd64'))
    mod=work/'source/go.mod'
    add('N05.1','MEMBER_BYTES:go.mod',lambda:xor_input(mod,lambda:g.source_tree(work/'source',ref),suffix=b'//dirty'))
    source=shadow(work/'source',root/'source-workspace');(source/'go.work').write_text('go 1.26.0\nuse .\n')
    add('N05.2','MEMBER_SET',lambda:g.source_tree(source,ref))
    checkpoint=next((x for x in modules['checkpoints'] if x['path'].endswith('/latest')),None)
    need(checkpoint is not None,'SIGNED_CHECKPOINT_CONTROL_MISSING');note=work/checkpoint['path']
    signature=note.read_bytes().rstrip(b'\n');signature_offset=len(signature)-1
    need(signature_offset>0,'CHECKPOINT_SIGNATURE_FIXTURE')
    add('N07.1','SUMDB_CHECKPOINT_BYTES',lambda:xor_input(note,lambda:c.check_file_hash(note,checkpoint['sha256'],'SUMDB_CHECKPOINT_BYTES'),offset=signature_offset))
    first=modules['inputs'][0];archive=work/'proxy'/g.escaped(first['module'])/'@v'/(g.escaped(first['version'])+'.zip')
    with zipfile.ZipFile(archive) as container:
        member=next((m for m in container.infolist() if m.compress_size>0),None)
        need(member is not None,'MODULE_PAYLOAD_CONTROL_MISSING')
        with open(archive,'rb') as stream:
            stream.seek(member.header_offset);header=stream.read(30)
        payload=member.header_offset+30+int.from_bytes(header[26:28],'little')+int.from_bytes(header[28:30],'little')
    add('N08.1','MODULE_CONTAINER_BYTES',lambda:xor_input(archive,lambda:c.check_file_hash(archive,first['inputs']['zip']['sha256'],'MODULE_CONTAINER_BYTES'),offset=payload))
    target=root/'redirect-target';target.mkdir();link=root/'redirect-link'
    if os.name=='nt':
        shell=Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
        quoted=lambda p:"'"+str(p).replace("'","''")+"'"
        command='New-Item -ItemType Junction -Path '+quoted(link)+' -Target '+quoted(target)+' | Out-Null'
        setup=subprocess.run([str(shell),'-NoProfile','-NonInteractive','-Command',command],cwd=root,capture_output=True,timeout=20)
        need(setup.returncode==0,'REDIRECT_FIXTURE_PRIVILEGE_HOLD')
    else: link.symlink_to(target,target_is_directory=True)
    add('N15.1','PATH_REDIRECTED',lambda:c.contained(link,root))
    notice_bundle=shadow(bundles/host,root/'missing-notice');notices=c.read_json(notice_bundle/'notices.json')
    notice=c.contained(notice_bundle/notices['files'][0]['path'],notice_bundle);notice.unlink()
    def check_notice():
        try:
            with c.admitted_artifact(ref,notice_bundle,host): raise TestFailure('NOTICE_WAS_ACCEPTED')
        except FileNotFoundError: raise c.AdmissionError('NOTICE_MISSING')
    add('N17.1','PATH_MISSING',check_notice)
    stream=work/'evidence'/('binary-audit-'+host)/'stdout.log'
    need(stream.is_file() and stream.read_bytes().lstrip().startswith(b'{'),'AUDIT_STREAM_CONTROL_MISSING')
    audit_text=stream.read_text(encoding='utf-8')
    add('N18.2','STREAM_PARSE',lambda:g.sequence(audit_text[:audit_text.index('{')+1]))
    def cgo_mismatch():
        rejected=0
        for target in ('windows-amd64','linux-amd64'):
            info=c.read_json(work/'builds'/target/'1/buildinfo/stdout.log')
            setting=next((r for r in info.get('Settings',[]) if r['Key']=='CGO_ENABLED'),None);need(setting is not None,'BUILDINFO_CGO_CONTROL_MISSING');setting['Value']='1'
            try:c.validate_buildinfo(info,target,ref)
            except c.AdmissionError as error:
                need(str(error)=='BUILDINFO_TARGET','CGO_WRONG_REJECTION');rejected+=1
        need(rejected==2,'CGO_MUST_REJECT_BOTH_TARGETS');raise c.AdmissionError('BUILDINFO_TARGET')
    add('N20.2','BUILDINFO_TARGET',cgo_mismatch)
    second=work/'builds'/host/'2'/name
    def repro():
        mutated=xor_input(second,lambda:c.digest(second))
        c.validate_reproduction({'target':host,'hashes':[approved['sha256'],mutated]},host,approved['sha256'])
    add('N23.1','NONREPRODUCIBLE',repro)
    direct=import_entry('direct_admission_control',ROOT/'tools/run_actionlint.py')
    empty=root/'direct-no-reference';empty.mkdir()
    def direct_missing():
        with patch.object(direct,'ROOT',empty),patch.object(direct,'workflows',return_value=['.github/workflows/control.yml']),patch.object(sys,'argv',['run_actionlint.py']):direct.main()
    add('N24.1','JSON_TYPE',direct_missing)
    default=root/'default-no-bundle';(default/'tools').mkdir(parents=True);(default/'.github/ci').mkdir(parents=True)
    os.link(ROOT/'tools/actionlint-build.lock.json',default/'tools/actionlint-build.lock.json')
    # Retain real stale bytes as a borrowed hardlink; there is still no approved bundle.
    (default/'stale-vendor-cache').mkdir();os.link(vendor,default/'stale-vendor-cache/actionlint.exe')
    policy=import_entry('default_admission_control',ROOT/'.github/ci/policy.py')
    def default_missing():
        def delegated(argv,**kwargs):
            need(Path(argv[2])==default/'tools/run_actionlint.py','DEFAULT_DELEGATION_TARGET')
            with patch.object(direct,'ROOT',default),patch.object(direct,'workflows',return_value=['.github/workflows/control.yml']),patch.object(sys,'argv',['run_actionlint.py']):direct.main()
        with patch.object(policy,'__file__',str(default/'.github/ci/policy.py')),patch.object(policy.subprocess,'run',side_effect=delegated):policy.lint()
    add('N25.1','PATH_MISSING',default_missing)
    swapped=shadow(bundles/host,root/'swapped-image');replacement=root/'replacement';replacement.write_bytes(b'X')
    def swap():
        protected=False
        with c.admitted_artifact(ref,swapped,host) as held:
            try:os.replace(replacement,swapped/name)
            except PermissionError:protected=True
            else:
                need(os.name!='nt' and c.digest(held['argv0'])==approved['sha256'],'SEALED_IMAGE_LOST')
                protected=c.digest(swapped/name)!=approved['sha256']
        need(protected,'EXECUTABLE_IDENTITY_NOT_PROTECTED')
        raise c.AdmissionError('MUTATED_IMAGE_CANNOT_BE_LAUNCHED')
    add('N26.1','MUTATED_IMAGE_CANNOT_BE_LAUNCHED',swap)
    need(len(items)==14,'COMPLETE_VECTOR_ADDITION_COUNT')
    return items

def run_components(output,full=False,work=None,vendor=None):
    c.contained(output,ROOT.parent,existing=False)
    need(not output.exists(),'OUTPUT_EXISTS')
    ref=c.read_json(ROOT/'tools/actionlint-build.lock.json');c.validate_reference(ref,admitted=full)
    if full:need(work is not None and vendor is not None,'ACTUAL_FULL_INPUTS_REQUIRED')
    output.mkdir(parents=True)
    ref=c.read_json(ROOT/'tools/actionlint-build.lock.json');c.validate_reference(ref,admitted=False)
    start=time.monotonic();records=[];spawns=[]
    with tempfile.TemporaryDirectory(prefix='fixtures-',dir=output) as name:
        fixture=Path(name);cases=components(fixture,ref)
        if full:
            cases+=complete_vectors(fixture,ref,work,vendor)
            def actual_target_mismatch():
                rejected=0
                for target,other in [('windows-amd64','linux-amd64'),('linux-amd64','windows-amd64')]:
                    image=ROOT/'artifacts/actionlint'/target/('actionlint.exe' if target.startswith('windows') else 'actionlint')
                    try:c.inspect_format(image.read_bytes(),other)
                    except c.AdmissionError as error:
                        need(str(error)=='BINARY_TARGET','TARGET_WRONG_REJECTION');rejected+=1
                need(rejected==2,'FORMAT_MUST_REJECT_BOTH_TARGETS');raise c.AdmissionError('BINARY_TARGET')
            cases=[(id,expected,actual_target_mismatch if id=='N20.1' else fn) for id,expected,fn in cases]
        need(not full or len(cases)==50,'FULL50_VECTOR_COUNT')
        need(len({id for id,_,_ in cases})==len(cases),'DUPLICATE_CASE')
        # Independent literals exercise successful component prerequisites before mutations.
        good,expect=baseline_audit();c.validate_audit(good,expect);b.validate_linux_cap(cap());b.check_owner(owner(),owner())
        def deny(*args,**kwargs): spawns.append('unexpected');raise TestFailure('CANDIDATE_SPAWN_ATTEMPT')
        # Cover the actual ctypes/fork launch backends as well as subprocess.
        with patch('subprocess.Popen',side_effect=deny), patch.object(b,'_windows_run',side_effect=deny), patch.object(b,'stopped_linux_child',side_effect=deny):
            for id,expected,fn in cases:
                error=None
                try:fn()
                except (c.AdmissionError,b.CapError) as exc:error=str(exc)
                need(error==expected,id+': expected '+expected+', observed '+str(error))
                records.append({'id':id,'expected':expected,'observed':error,'candidateSpawns':0})
                with open(output/'cases.jsonl','a',encoding='utf-8') as journal:journal.write(json.dumps(records[-1])+'\n')
                need(time.monotonic()-start<=120,'MODE_WALL_CAP')
        # Borrowed admitted inputs are hardlinks, never rewritten; only generated fixtures count here.
        sizes=[p.stat().st_size for p in fixture.rglob('*') if p.is_file() and p.stat().st_nlink==1]
        need(all(size<=65536 for size in sizes) and sum(sizes)<=8*1024*1024,'FIXTURE_CAP')
    need(not spawns,'CANDIDATE_SPAWNS')
    receipt={'schema':'actionlint-component-tests/v1','status':'ACTUAL_ADMITTED_INPUT_50_REJECTIONS_PASS_NATIVE_CONTROLS_SEPARATE' if full else 'COMPONENT_REJECTIONS_PASS_NOT_FULL50_GATE',
             'optimize':sys.flags.optimize,'caseCount':len(records),'cases':records,'candidateSpawns':0,'seconds':time.monotonic()-start,
             'full50Complete':full,'actualTrustedNativePositiveControls':False,'referenceSha256':c.digest(ROOT/'tools/actionlint-build.lock.json'),'harnessSha256':c.digest(Path(__file__)),'syntheticFixtureBytes':sum(sizes),'largestSyntheticFixtureBytes':max(sizes,default=0)}
    (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8');print(json.dumps({k:v for k,v in receipt.items() if k!='cases'}))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True);group.add_argument('--components',action='store_true');group.add_argument('--full',action='store_true')
    parser.add_argument('--out',required=True,type=Path);parser.add_argument('--source-work',type=Path);parser.add_argument('--stale-vendor',type=Path)
    args=parser.parse_args();run_components(args.out,args.full,args.source_work,args.stale_vendor)

if __name__=='__main__':
    try:main()
    except (TestFailure,c.AdmissionError,b.CapError,OSError,ValueError) as exc:raise SystemExit('actionlint tests HOLD: '+str(exc))
