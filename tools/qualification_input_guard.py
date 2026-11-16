"""Reviewed data guard library, no command or target execution on import/CLI."""
from __future__ import annotations
import gzip,hashlib,json,os,re,stat,struct,tarfile,time,unicodedata,zipfile
from pathlib import Path,PurePosixPath
SDK='11.0.100';RUNTIME='11.0.0';RAW_MAX=536870912;EXPANDED_MAX=4294967296;MEMBER_MAX=268435456;COUNT_MAX=64000
INPUTS={'win-x64':{},'linux-x64':{}}
class AdmissionError(RuntimeError):pass


def need(value,reason):
 if not value:raise AdmissionError(reason)


def digest(path,algorithm='sha256'):
 with Path(path).open('rb') as f:return hashlib.file_digest(f,algorithm).hexdigest()


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')


def read_json(path,limit=16*1024**2):
 p=Path(path);need(p.is_file() and not p.is_symlink() and p.stat().st_size<=limit,'INPUT_IDENTITY_MISMATCH')
 return json.loads(p.read_bytes())


def write_new(path,value):
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('x',encoding='utf-8',newline='\n') as f:json.dump(value,f,indent=2);f.write('\n')


def scoped(path,root,absent=False):
 path=Path(path).absolute();root=Path(root).resolve();need(path.resolve(strict=False).is_relative_to(root),'OUTPUT_SCOPE_INVALID')
 for p in [path,*path.parents]:
  if p.exists():
   s=p.lstat();need(not p.is_symlink() and not(getattr(s,'st_file_attributes',0)&1024),'OUTPUT_SCOPE_INVALID')
  if p==root:break
 if absent:need(not path.exists(),'OUTPUT_SCOPE_INVALID')
 return path


def member_path(name):
 need(isinstance(name,str) and len(name.encode('utf-8'))<=4096 and not any(ord(c)<32 or ord(c)==127 for c in name),'ARCHIVE_PATH_INVALID')
 need('\\' not in name and ':' not in name and not name.startswith('/') and unicodedata.normalize('NFC',name)==name,'ARCHIVE_PATH_INVALID')
 # A typed leading ./ and root directory entry are canonical TAR syntax, not traversal.
 if name.startswith('./'):name=name[2:]
 name=name.rstrip('/')
 if name in ('','.'):return ''
 parts=name.split('/');need(all(p not in ('','..','.') and not p.endswith((' ','.')) for p in parts),'ARCHIVE_PATH_INVALID')
 need(all(p.split('.')[0].upper() not in {'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]} for p in parts),'ARCHIVE_PATH_INVALID')
 need(not PurePosixPath(name).is_absolute(),'ARCHIVE_PATH_INVALID');return name


class Inventory:
 def __init__(self):self.seen={};self.members=[];self.total=0
 def add(self,name,size,kind,mode):
  need(kind in ('file','directory'),'ARCHIVE_SPECIAL_UNSUPPORTED');p=member_path(name)
  need(type(size) is int and 0<=size<=MEMBER_MAX and not(mode&0o7000),'ARCHIVE_LIMIT_EXCEEDED')
  if not p:
   need(kind=='directory' and size==0,'ARCHIVE_PATH_INVALID');need('' not in self.seen,'ARCHIVE_DUPLICATE_MEMBER');self.seen['']='directory'
   row={'path':'','type':'directory','bytes':0,'mode':mode&0o777};self.members.append(row);return row
  key=p.casefold();need(key not in self.seen,'ARCHIVE_DUPLICATE_MEMBER')
  for parent in PurePosixPath(p).parents:
   k=str(parent).casefold()
   if k!='.':need(self.seen.get(k)!='file','ARCHIVE_DUPLICATE_MEMBER')
  if kind=='file':need(not any(k.startswith(key+'/') for k in self.seen),'ARCHIVE_DUPLICATE_MEMBER')
  self.seen[key]=kind;self.total+=size;need(len(self.seen)<=COUNT_MAX and self.total<=EXPANDED_MAX,'ARCHIVE_LIMIT_EXCEEDED')
  row={'path':p,'type':kind,'bytes':size,'mode':mode&0o777};self.members.append(row);return row


def extract_members(archive,destination,rid):
 """Synthetic guard harness may call this parser; production requires extract_sdk raw admission first."""
 need(rid in INPUTS,'INPUT_IDENTITY_MISMATCH');dest=Path(destination);need(not dest.exists(),'OUTPUT_SCOPE_INVALID');dest.mkdir(parents=True)
 inv=Inventory();start=time.monotonic()
 def materialize(row,stream):
  if row is None:return
  p=dest/row['path'];need(p.resolve(strict=False).is_relative_to(dest.resolve()),'ARCHIVE_PATH_INVALID')
  if row['type']=='directory':p.mkdir(parents=True,exist_ok=True);return
  p.parent.mkdir(parents=True,exist_ok=True);h=hashlib.sha256();size=0
  with p.open('xb') as out:
   while True:
    need(time.monotonic()-start<=300,'ARCHIVE_LIMIT_EXCEEDED');data=stream.read(min(1024**2,row['bytes']-size+1))
    if not data:break
    size+=len(data);need(size<=row['bytes'],'ARCHIVE_LIMIT_EXCEEDED');out.write(data);h.update(data)
  need(size==row['bytes'],'ARCHIVE_LIMIT_EXCEEDED');row['sha256']=h.hexdigest()
  if os.name!='nt':p.chmod(row['mode'])
 if rid=='win-x64':
  with zipfile.ZipFile(archive) as z:
   need(len(z.infolist())<=COUNT_MAX,'ARCHIVE_LIMIT_EXCEEDED')
   for x in z.infolist():
    mode=x.external_attr>>16;kind=stat.S_IFMT(mode);need(not(x.flag_bits&1),'ARCHIVE_SPECIAL_UNSUPPORTED')
    need(kind!=stat.S_IFLNK,'ARCHIVE_LINK_UNSUPPORTED');need(kind in (0,stat.S_IFREG,stat.S_IFDIR),'ARCHIVE_SPECIAL_UNSUPPORTED')
    isdir=x.is_dir();need((kind!=stat.S_IFDIR or isdir) and (not isdir or x.file_size==0),'ARCHIVE_SPECIAL_UNSUPPORTED')
    row=inv.add(x.filename,x.file_size,'directory' if isdir else 'file',mode)
    if isdir:materialize(row,None)
    else:
     with z.open(x) as source:materialize(row,source)
 else:
  with gzip.open(archive,'rb') as gz,tarfile.open(fileobj=gz,mode='r|') as tar:
   for x in tar:
    need(not(x.issym() or x.islnk()),'ARCHIVE_LINK_UNSUPPORTED');need(x.isfile() or x.isdir(),'ARCHIVE_SPECIAL_UNSUPPORTED')
    row=inv.add(x.name,x.size,'directory' if x.isdir() else 'file',x.mode)
    if x.isdir():materialize(row,None)
    else:
     with tar.extractfile(x) as source:materialize(row,source)
   trailing=0
   while True:
    block=tar.fileobj.read(1024**2)
    if not block:break
    trailing+=len(block);need(trailing<=1024**2 and not any(block),'ARCHIVE_SPECIAL_UNSUPPORTED')
 return inv.members


def critical_names(rid):
 suffix='.exe' if rid=='win-x64' else ''
 native=['host/fxr/11.0.0/hostfxr.dll','shared/Microsoft.NETCore.App/11.0.0/coreclr.dll','shared/Microsoft.NETCore.App/11.0.0/clrjit.dll'] if suffix else ['host/fxr/11.0.0/libhostfxr.so','shared/Microsoft.NETCore.App/11.0.0/libcoreclr.so','shared/Microsoft.NETCore.App/11.0.0/libclrjit.so']
 return ['dotnet'+suffix,'sdk/11.0.100/dotnet.dll','sdk/11.0.100/Roslyn/bincore/csc.dll',*native]


def machine(path):
 with Path(path).open('rb') as f:
  header=f.read(64)
  if header[:2]==b'MZ':
   need(len(header)==64,'NATIVE_TARGET_UNSUPPORTED');f.seek(struct.unpack_from('<I',header,60)[0]);pe=f.read(6);need(pe[:4]==b'PE\0\0','NATIVE_TARGET_UNSUPPORTED');return ('PE',struct.unpack_from('<H',pe,4)[0])
  need(header[:4]==b'\x7fELF' and header[4:6]==b'\x02\x01','NATIVE_TARGET_UNSUPPORTED');return ('ELF',struct.unpack_from('<H',header,18)[0])


def pe_imports(path):
 data=Path(path).read_bytes();need(len(data)<=MEMBER_MAX and data[:2]==b'MZ','NATIVE_TARGET_UNSUPPORTED')
 def u32(at):
  need(0<=at<=len(data)-4,'NATIVE_TARGET_UNSUPPORTED');return struct.unpack_from('<I',data,at)[0]
 pe=u32(60);need(data[pe:pe+4]==b'PE\0\0' and pe+24<=len(data),'NATIVE_TARGET_UNSUPPORTED')
 count=struct.unpack_from('<H',data,pe+6)[0];optional=struct.unpack_from('<H',data,pe+20)[0];opt=pe+24
 need(count<=96 and optional>=128 and data[opt:opt+2]==b'\x0b\x02','NATIVE_TARGET_UNSUPPORTED')
 tables=opt+optional;sections=[]
 for i in range(count):
  at=tables+i*40;need(at+40<=len(data),'NATIVE_TARGET_UNSUPPORTED');sections.append((u32(at+12),max(u32(at+8),u32(at+16)),u32(at+20),u32(at+16)))
 def offset(rva):
  for start,size,raw,rawsize in sections:
   if start<=rva<start+size:
    delta=rva-start;need(delta<rawsize and raw+delta<len(data),'NATIVE_TARGET_UNSUPPORTED');return raw+delta
  raise AdmissionError('NATIVE_TARGET_UNSUPPORTED')
 imports=[]
 # Both immediate and delay-load tables are data-only; don't load candidate DLLs to inspect them.
 for index,stride,name_index,flagged in [(1,20,12,False),(13,32,4,True)]:
  directory=opt+112+8*index
  if directory+8>opt+optional:continue
  rva=u32(directory)
  if not rva:continue
  start=offset(rva)
  for i in range(512):
   at=start+i*stride;need(at+stride<=len(data),'NATIVE_TARGET_UNSUPPORTED')
   if not any(data[at:at+stride]):break
   if flagged:need(u32(at)&1,'NATIVE_TARGET_UNSUPPORTED')
   name=offset(u32(at+name_index));end=data.find(b'\0',name,min(name+260,len(data)));need(end>name,'NATIVE_TARGET_UNSUPPORTED')
   dll=data[name:end].decode('ascii');need(re.fullmatch('[A-Za-z0-9_.-]+',dll) is not None,'NATIVE_TARGET_UNSUPPORTED');imports.append(dll)
  else:raise AdmissionError('NATIVE_TARGET_UNSUPPORTED')
 return sorted(set(imports),key=str.casefold)


def verify_tree(root,members,rid,full=False):
 root=Path(root);files={x['path']:x for x in members if x['type']=='file'}
 names=files if full else critical_names(rid)
 for name in names:
  need(name in files,'SDK_MEMBER_MISMATCH');row=files[name];p=root/name
  need(p.is_file() and not p.is_symlink() and p.stat().st_size==row['bytes'] and digest(p)==row['sha256'],'SDK_MEMBER_MISMATCH')
  if os.name!='nt':need(stat.S_IMODE(p.stat().st_mode)==row['mode'],'SDK_MEMBER_MISMATCH')
 if full:
  actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()};need(actual==set(files),'SDK_MEMBER_MISMATCH')
  need(not any(p.is_symlink() for p in root.rglob('*')),'SDK_MEMBER_MISMATCH')
  directories={x['path'] for x in members if x['type']=='directory' and x['path']}
  for name in files:directories.update(str(p) for p in PurePosixPath(name).parents if str(p)!='.')
  need({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_dir()}==directories,'SDK_MEMBER_MISMATCH')
 need(machine(root/critical_names(rid)[0])==(('PE',0x8664) if rid=='win-x64' else ('ELF',62)),'NATIVE_TARGET_UNSUPPORTED')
 notices=[x for x in members if x['type']=='file' and re.match(r'(?i)(license|third.?party.?notices)',PurePosixPath(x['path']).name)]
 need(any(PurePosixPath(x['path']).name.lower()=='license.txt' for x in notices) and any('third' in PurePosixPath(x['path']).name.lower() for x in notices),'SDK_MEMBER_MISMATCH')
 need(any(n.startswith('packs/Microsoft.NETCore.App.Ref/11.0.0/ref/net11.0/') for n in files),'SDK_MEMBER_MISMATCH')
 return notices

