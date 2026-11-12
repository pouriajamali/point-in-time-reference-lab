"""Independent fail-closed admission for maintainer-built actionlint. No execution here."""
from __future__ import annotations
import argparse, contextlib, hashlib, io, json, os, re, stat, tarfile, zipfile
from pathlib import Path, PurePosixPath
SOURCE_COMMIT = '914e7df21a07ef503a81201c76d2b11c789d3fca'
SOURCE_TREE = 'ecee8c9c752f012b2da57a5fc59863624539b43b'
GO_SHA = '9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec'
MOD_SHA = '551cd61e64ea59573ee0264e07a21b2db405f88ccfd0cac27c2e18a4b9e96daa'
SUM_SHA = 'c239b0e641d4da3b7ee719414b8041902776a48cfff18be1ebc938dc6d53750f'
RECIPE = 'actionlint-1.7.12-go1.26.11-xsys0.44.0-cgo0-v1'
SCHEMA = 'maintainer-actionlint-build/v1'
HEX = re.compile(r'\A[0-9a-f]{64}\Z')
UNSAFE_ENV = ('GO_TELEMETRY_CHILD','GOFLAGS','GOEXPERIMENT','GODEBUG','GOTOOLCHAIN','GOWORK','GOENV','GOPRIVATE','GONOSUMDB','GONOPROXY','GOINSECURE','GOAUTH','GOVCS')
SDK_DNS_FIX = {
    'id':'GO-2026-5942','module':'golang.org/x/net','compilerArchiveSha256':GO_SHA,
    'package':'vendor/golang.org/x/net/dns/dnsmessage',
    'sourceMember':'src/vendor/golang.org/x/net/dns/dnsmessage/svcb.go',
    'sourceSha256':'2a6051c720262a3ebb63c191f6886dd26b5b049a823345a4c15586395f69b4f2',
    'sourceGitBlobSha1':'252401b3cecd0cf17f0379530ef368db75176f01',
    'upstreamFixCommit':'cb1d721f7fb34abc9f4454685c2236d012e62176',
    'receiptSha256':'21ae0b0c6d616dfa2bce7b409218b827af70d9deb01c7423fbb06f24d05ab495',
}
class AdmissionError(ValueError):
    pass

def require(value, reason):
    if not value:
        raise AdmissionError(reason)

def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def _pairs(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, 'DUPLICATE_JSON_KEY')
        out[key] = value
    return out

def read_json(path, cap=2*1024*1024):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'JSON_TYPE')
    require(path.stat().st_size <= cap, 'JSON_CAP')
    raw = path.read_bytes()
    require(not raw.startswith(b'\xef\xbb\xbf') and b'\0' not in raw, 'JSON_FRAMING')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(AdmissionError('JSON_CONSTANT')))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AdmissionError('JSON_PARSE') from exc

def path_parts(name):
    require(isinstance(name, str) and name and not any(ord(c)<32 or ord(c)==127 for c in name), 'PATH_CONTROL')
    require('\\' not in name and ':' not in name and not name.startswith('/'), 'PATH_ABSOLUTE_OR_WINDOWS')
    require('//' not in name and all(p not in ('', '.', '..') for p in name.rstrip('/').split('/')), 'PATH_ESCAPE')
    path = PurePosixPath(name.rstrip('/'))
    require(path.parts and all(p not in ('', '.', '..') and not p.endswith((' ', '.')) for p in path.parts), 'PATH_ESCAPE')
    require(all(p.split('.')[0].upper() not in {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))} for p in path.parts), 'PATH_DEVICE')
    return path.parts

def contained(path, root, *, existing=True):
    require(not str(path).startswith(('\\\\','//')), 'PATH_NETWORK')
    require('..' not in Path(path).parts and '..' not in Path(root).parts,'PATH_ESCAPE')
    path, root = Path(path).absolute(), Path(root).absolute()
    require(path == root or root in path.parents, 'PATH_OUTSIDE_ROOT')
    for parent in [path, *path.parents]:
        try: st=parent.lstat()
        except FileNotFoundError:
            if parent==path: require(not existing,'PATH_MISSING')
            continue
        require(not stat.S_ISLNK(st.st_mode) and not getattr(st,'st_file_attributes',0)&0x400,'PATH_REDIRECTED')
    return path

def archive_inventory(path, expanded_cap=512*1024*1024, count_cap=20000):
    """Validate complete source/module archive before any materialization; never extractall."""
    rows, seen, folded, kinds, total = [], set(), set(), {}, 0
    def accept(name, kind, size, mode, stream=None, original=None):
        nonlocal total
        path_parts(original if original is not None else name)
        clean = '/'.join(path_parts(name)); key = clean.casefold()
        require(clean not in seen and key not in folded, 'ARCHIVE_DUPLICATE')
        require(kind in ('file','directory') and not mode&0o7000, 'ARCHIVE_SPECIAL')
        require(type(size) is int and size >= 0, 'ARCHIVE_SIZE')
        require(all(kinds.get('/'.join(PurePosixPath(clean).parts[:i])) != 'file' for i in range(1,len(PurePosixPath(clean).parts))), 'ARCHIVE_PARENT_FILE')
        require(not (kind=='file' and any(p.startswith(key+'/') for p in folded)), 'ARCHIVE_PARENT_FILE')
        seen.add(clean); folded.add(key); kinds[clean] = kind
        require(len(seen)<=count_cap, 'ARCHIVE_COUNT_CAP')
        row={'path':clean,'type':kind,'bytes':size,'mode':mode&0o777}
        if kind == 'file':
            total += size; require(total<=expanded_cap, 'ARCHIVE_EXPANSION_CAP')
            h=hashlib.sha256(); actual=0
            while True:
                data=stream.read(min(1048576, size-actual+1))
                if not data: break
                actual+=len(data); require(actual<=size, 'ARCHIVE_ACTUAL_SIZE'); h.update(data)
            require(actual==size,'ARCHIVE_ACTUAL_SIZE'); row['sha256']=h.hexdigest()
        rows.append(row)
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                mode=info.external_attr>>16
                kind='directory' if info.is_dir() else 'file'
                require(not stat.S_ISLNK(mode) and (stat.S_IFMT(mode) in (0,stat.S_IFREG,stat.S_IFDIR)), 'ARCHIVE_SPECIAL')
                if kind=='file':
                    with archive.open(info) as stream: accept(info.filename,kind,info.file_size,mode,stream,info.orig_filename)
                else: accept(info.filename,kind,0,mode,original=info.orig_filename)
    else:
        with tarfile.open(path,'r:*') as archive:
            for info in archive:
                require(info.isfile() or info.isdir(),'ARCHIVE_SPECIAL')
                if info.isfile():
                    with archive.extractfile(info) as stream: accept(info.name,'file',info.size,info.mode,stream)
                else: accept(info.name,'directory',0,info.mode)
    return rows

def clean_environment(incoming, *, home, gopath, cache, temp, compiler_root=None, target=None):
    for key in UNSAFE_ENV:
        require(not incoming.get(key), 'UNSAFE_ENV:'+key)
    require(not any(k.startswith('GIT_CONFIG_') and v for k,v in incoming.items()), 'UNSAFE_VCS_ENV')
    keep=('SystemRoot','WINDIR','COMSPEC','PATHEXT','LANG','LC_ALL','TZ')
    env={k:incoming[k] for k in keep if k in incoming}
    env.update({'HOME':str(home),'USERPROFILE':str(home),'GOPATH':str(gopath),'GOCACHE':str(cache),'GOTMPDIR':str(temp),
                'TEMP':str(temp),'TMP':str(temp),'TMPDIR':str(temp),'GOENV':'off','GOWORK':'off','GOTOOLCHAIN':'local',
                'GOTELEMETRY':'off','GOAUTH':'off','GOVCS':'*:off','GOSUMDB':'sum.golang.org','GOPROXY':'off',
                'CGO_ENABLED':'0','GOAMD64':'v1','GOMAXPROCS':'2'})
    env['PATH']=(str(Path(compiler_root)/'bin')+os.pathsep if compiler_root else '')+('/usr/bin:/bin' if os.name!='nt' else os.path.join(incoming.get('SystemRoot',r'C:\Windows'),'System32'))
    if compiler_root: env['GOROOT']=str(compiler_root)
    if target: env['GOOS'],env['GOARCH']=target.split('-')
    return env

def validate_reference(ref, *, admitted=True):
    require(type(ref) is dict and ref.get('schema')==SCHEMA, 'REFERENCE_SCHEMA')
    source=ref.get('source',{}); compiler=ref.get('compiler',{}); graph=ref.get('graph',{}); recipe=ref.get('recipe',{})
    require(source.get('commit')==SOURCE_COMMIT and source.get('tree')==SOURCE_TREE and source.get('version')=='1.7.12','SOURCE_IDENTITY')
    require(compiler.get('version')=='go1.26.11' and compiler.get('archiveSha256')==GO_SHA and compiler.get('os')=='linux','COMPILER_IDENTITY')
    auditor=ref.get('auditor',{})
    require(auditor.get('module')=='golang.org/x/vuln' and auditor.get('version')=='v1.9.0' and auditor.get('sourceCommit')=='e672cbe8fbc8c76e28fcb6db0efd9ce354e0dac5' and auditor.get('moduleH1')=='h1:12VaqnI9kJfqwRoPptxoqsUhQtdfrSbdksT7X/KY/sc=' and auditor.get('goModH1')=='h1:E/Frwm0xp49fTyBW+6CQHdkvobknbwUM49yEpMGUauw=','AUDITOR_IDENTITY')
    require(graph.get('modSha256')==MOD_SHA and graph.get('sumSha256')==SUM_SHA,'GRAPH_IDENTITY')
    require(recipe.get('id')==RECIPE and recipe.get('buildsPerTarget')==2 and recipe.get('sourceDateEpoch')=='1774892837' and recipe.get('targets')==['windows-amd64','linux-amd64'],'RECIPE_IDENTITY')
    modules=graph.get('modules',[])
    require(len(modules)==20 and len({x.get('module') for x in modules})==20,'GRAPH_CLOSURE')
    require(next((x.get('version') for x in modules if x.get('module')=='golang.org/x/sys'),None)=='v0.44.0','GRAPH_VERSION')
    for module in modules:
        require(isinstance(module.get('moduleH1'),str) and module['moduleH1'].startswith('h1:') and isinstance(module.get('goModH1'),str) and module['goModH1'].startswith('h1:'),'GRAPH_SUM')
    require(hashlib.sha256(graph.get('modText','').encode()).hexdigest()==MOD_SHA and hashlib.sha256(graph.get('sumText','').encode()).hexdigest()==SUM_SHA,'GRAPH_POSTIMAGE')
    if admitted:
        require(compiler.get('admission') is not None and ref.get('auditor',{}).get('admission') is not None,'TOOL_UNADMITTED')
        require(ref.get('admission',{}).get('state')=='ADMITTED','ARTIFACT_UNADMITTED')
    return ref

def validate_audit(row, expected):
    require(type(row) is dict and row.get('schema')=='actionlint-audit/v1','AUDIT_SCHEMA')
    for key in ('target','sourceCommit','sourceTree','compilerSha256','graphSha256','databaseSha256','sourcePackageGraphSha256','binaryBuildInfoSha256'):
        require(expected.get(key) is not None and row.get(key)==expected.get(key),'AUDIT_BINDING:'+key)
    require(type(row.get('sourceProductionModules')) is list and 'github.com/rhysd/actionlint' in row['sourceProductionModules'] and type(row.get('binaryProductionModules')) is list,'AUDIT_PRODUCTION_GRAPH')
    require(type(row.get('sourceScanExit')) is int and type(row.get('binaryScanExit')) is int and row['sourceScanExit']==0 and row['binaryScanExit']==0 and row.get('protocolComplete') is True,'AUDIT_INCOMPLETE')
    dispositions=row.get('dispositions'); ids=expected.get('findingIds')
    require(type(dispositions) is list and type(ids) is list and {x.get('id') for x in dispositions}==set(ids) and len(dispositions)==len(ids),'AUDIT_FINDING_SET')
    for x in dispositions:
        require(x.get('module')==expected.get('findingModules',{}).get(x.get('id')) and x.get('module') is not None,'AUDIT_FINDING_MODULE')
        if expected.get('findingRecordHashes'):
            require(x.get('recordSha256')==expected['findingRecordHashes'].get(x['id']),'AUDIT_PRIMARY_RECORD')
            require(x.get('affectedPackagesInGraph')==expected.get('sdkPackageMatches',{}).get(x['id']),'AUDIT_AFFECTED_PACKAGE_BINDING')
        if x.get('status')=='NOT_IN_SOURCE_OR_BINARY_PRODUCTION_MODULE_CLOSURE':
            require(not x.get('affectedPackagesInGraph'),'AUDIT_SDK_APPLICABLE')
        elif x.get('status')=='FIXED_IN_EXACT_COMPILER_SDK_SOURCE':
            require(row.get('target')=='windows-amd64' and x.get('id')==SDK_DNS_FIX['id'] and x.get('module')==SDK_DNS_FIX['module'],'AUDIT_SDK_FIX_SCOPE')
            require(expected.get('sdkBackport')==SDK_DNS_FIX and x.get('sdkBackport')==SDK_DNS_FIX and x.get('affectedPackagesInGraph')==[SDK_DNS_FIX['package']],'AUDIT_SDK_FIX_BINDING')
        else: raise AdmissionError('AUDIT_UNRESOLVED')
        require(x.get('module') not in row.get('sourceProductionModules',[]) and x.get('module') not in row.get('binaryProductionModules',[]),'AUDIT_APPLICABLE')
        require(x.get('sourceGraphSha256')==expected['sourcePackageGraphSha256'] and x.get('binaryGraphSha256')==expected['binaryBuildInfoSha256'],'AUDIT_DISPOSITION_BINDING')
    require(row.get('dynamicPluginImports')==[],'AUDIT_DYNAMIC_CLOSURE')

def check_file_hash(path, expected, reason):
    require(isinstance(expected,str) and HEX.fullmatch(expected) is not None and digest(path)==expected,reason)

def check_binary(path, approved, target):
    require(path.stat().st_size==approved.get('bytes') and path.stat().st_size<=20*1024*1024,'BINARY_SIZE')
    check_file_hash(path,approved.get('sha256'),'BINARY_BYTES')
    raw=path.read_bytes(); require(hashlib.sha256(raw).hexdigest()==approved['sha256'],'BINARY_SWAP')
    inspect_format(raw,target)
    return raw

def validate_buildinfo(data, target, ref):
    settings={r['Key']:r['Value'] for r in data.get('Settings',[])}
    require(data.get('GoVersion')=='go1.26.11' and data.get('Path')=='github.com/rhysd/actionlint/cmd/actionlint','BUILDINFO_TOOL_OR_ENTRY')
    require(settings.get('CGO_ENABLED')=='0' and settings.get('GOOS')==target.split('-')[0] and settings.get('GOARCH')=='amd64','BUILDINFO_TARGET')
    # Go deliberately omits -ldflags with -trimpath (go.dev/issue/52372).
    # Exact flags are checked against the recorded, bounded compiler invocation.
    require(settings.get('-trimpath')=='true' and settings.get('-buildmode')=='exe' and settings.get('-compiler')=='gc' and settings.get('GOAMD64')=='v1' and '-ldflags' not in settings and not any(k.startswith('vcs') for k in settings),'BUILDINFO_RECIPE')
    allowed={r['module']:r['version'] for r in ref['graph']['modules']}
    for row in data.get('Deps',[]): require(not row.get('Replace') and allowed.get(row.get('Path'))==row.get('Version'),'BUILDINFO_GRAPH')

def validate_reproduction(row, target, expected):
    require(row.get('target')==target and row.get('hashes')==[expected]*2,'NONREPRODUCIBLE')

def inspect_format(data, target):
    if target=='linux-amd64':
        require(len(data)>=64 and data[:4]==b'\x7fELF' and data[4:6]==b'\x02\x01' and int.from_bytes(data[16:18],'little')==2 and int.from_bytes(data[18:20],'little')==62,'BINARY_TARGET')
        offset=int.from_bytes(data[32:40],'little');width=int.from_bytes(data[54:56],'little');count=int.from_bytes(data[56:58],'little')
        require(width==56 and 0<count<=64 and offset+width*count<=len(data),'BINARY_ELF_HEADERS')
        require(all(int.from_bytes(data[offset+i*width:offset+i*width+4],'little') not in (2,3) for i in range(count)),'BINARY_DYNAMIC_LINKAGE')
    elif target=='windows-amd64':
        require(len(data)>=64 and data[:2]==b'MZ','BINARY_TARGET'); off=int.from_bytes(data[60:64],'little')
        require(off+26<=len(data) and data[off:off+4]==b'PE\0\0' and int.from_bytes(data[off+4:off+6],'little')==0x8664 and int.from_bytes(data[off+24:off+26],'little')==0x20b,'BINARY_TARGET')
        flags=int.from_bytes(data[off+22:off+24],'little');require(flags&2 and not flags&0x2000,'BINARY_PE_EXECUTABLE')
    else: raise AdmissionError('BINARY_TARGET')

@contextlib.contextmanager
def admitted_artifact(reference, bundle, target):
    ref=validate_reference(reference); bundle=contained(bundle,Path(bundle).absolute())
    approved=ref['admission'].get('artifacts',{}).get(target)
    require(type(approved) is dict and HEX.fullmatch(approved.get('sha256','')) is not None,'ARTIFACT_EXPECTATION')
    binding=approved.get('auditBinding',{})
    require(binding.get('target')==target and binding.get('sourceCommit')==SOURCE_COMMIT and binding.get('sourceTree')==SOURCE_TREE and binding.get('compilerSha256')==GO_SHA,'ARTIFACT_AUDIT_IDENTITY')
    for key in ('graphSha256','databaseSha256','sourcePackageGraphSha256','binaryBuildInfoSha256'):
        require(isinstance(binding.get(key),str) and HEX.fullmatch(binding[key]) is not None,'ARTIFACT_AUDIT_HASH')
    mandatory={'audit.json','reproducibility.json','notices.json','source-packages.json','buildinfo.json','source-scan.json','binary-scan.json','database.json','inputs.json'}
    require(mandatory.issubset(approved.get('evidence',{})),'EVIDENCE_SET')
    manifest=read_json(bundle/'admission.json')
    require(manifest.get('recipeId')==RECIPE and manifest.get('target')==target,'BUNDLE_IDENTITY')
    name='actionlint.exe' if target=='windows-amd64' else 'actionlint'; path=contained(bundle/name,bundle)
    # Source-controlled reference is the trust boundary, not candidate hashes/PASS fields.
    raw=check_binary(path,approved,target)
    for relative, expected in approved.get('evidence',{}).items():
        path_parts(relative); proof=contained(bundle/relative,bundle)
        require(HEX.fullmatch(expected) is not None and digest(proof)==expected,'EVIDENCE_BYTES')
    require(bool(approved.get('evidence')),'EVIDENCE_MISSING')
    audit=read_json(bundle/'audit.json'); validate_audit(audit,approved['auditBinding'])
    reproduction=read_json(bundle/'reproducibility.json')
    validate_reproduction(reproduction,target,approved['sha256'])
    notices=read_json(bundle/'notices.json'); require(notices.get('state')=='ADMITTED' and notices.get('files'),'NOTICES_MISSING')
    for row in notices['files']:
        path_parts(row['path']); require(digest(contained(bundle/row['path'],bundle))==row['sha256'],'NOTICE_BYTES')
    require(digest(path)==approved['sha256'],'BINARY_SWAP')
    # Linux executes a sealed copy, so a later source-path swap cannot change executed bytes.
    if os.name!='nt':
        import fcntl
        fd=os.memfd_create('admitted-actionlint',os.MFD_ALLOW_SEALING)
        offset=0
        while offset<len(raw): offset+=os.write(fd,raw[offset:])
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        try: yield {'argv0':'/proc/self/fd/'+str(fd),'passFds':(fd,),'sha256':approved['sha256'],'target':target}
        finally: os.close(fd)
    else:
        from bounded_actionlint import held_windows_image
        with held_windows_image(path) as held:
            require(held['sha256']==approved['sha256'],'BINARY_SWAP')
            yield {'argv0':str(path),'passFds':(),'sha256':approved['sha256'],'target':target,'heldIdentity':held['identity']}

def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--bundle',type=Path,required=True); parser.add_argument('--target',choices=['windows-amd64','linux-amd64'],required=True); args=parser.parse_args()
    ref=read_json(Path(__file__).with_name('actionlint-build.lock.json'))
    with admitted_artifact(ref,args.bundle,args.target) as artifact:
        print(json.dumps({'status':'INPUTS_ADMITTED_NO_EXECUTION','target':args.target,'sha256':artifact['sha256']}))
if __name__=='__main__':
    try: main()
    except (AdmissionError,OSError,KeyError,TypeError,ValueError) as exc: raise SystemExit('actionlint admission HOLD: '+str(exc))
