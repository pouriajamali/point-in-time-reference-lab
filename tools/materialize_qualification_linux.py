"""Fixed reviewed1830map Linux materialization library; onlyfresh CI privateallocation."""
from __future__ import annotations
import gzip,hashlib,json,os,posixpath,re,stat,tarfile,time
from pathlib import Path,PurePosixPath
import qualification_input_guard as a
def sha(value):return hashlib.sha256(a.canonical(value)).hexdigest()


def layout(rows,links):
 a.need(type(rows) is list and type(links) is list and len(rows)<=a.COUNT_MAX,'COPY_LAYOUT_INVALID')
 inv=a.Inventory();regular={};syms={};result=[]
 for x in rows:
  a.need(type(x) is dict and x.get('type') in ('file','directory','symlink'),'COPY_TYPE_INVALID')
  a.need(type(x.get('mode')) is int and 0<=x['mode']<=0o777,'COPY_MODE_INVALID')
  n=a.member_path(x['name']);kind=x['type']
  a.need(kind=='directory' or bool(n),'COPY_LAYOUT_INVALID')
  if kind=='file':
   a.need(x.get('linkname')=='' and re.fullmatch('[0-9a-f]{64}',x.get('sha256','')) is not None,'COPY_BODY_INVALID');regular[n]=x
  elif kind=='directory':a.need(x.get('bytes')==0 and x.get('linkname')=='','COPY_LAYOUT_INVALID')
  else:a.need(x.get('bytes')==0 and type(x.get('linkname')) is str,'COPY_LINK_INVALID');syms[x['name']]=x
  row=inv.add(x['name'],x['bytes'],'file' if kind=='symlink' else kind,x['mode'])
  if kind=='file':row['sha256']=x['sha256']
  if not n:row['mode']=0o700
  result.append(row)
 a.need(len(links)==len(syms),'COPY_LINK_SET_INVALID');visited=set();projected=[]
 for l in links:
  a.need(type(l) is dict and l.get('name') in syms and l['name'] not in visited,'COPY_LINK_SET_INVALID');visited.add(l['name']);x=syms[l['name']]
  a.need({k:l.get(k) for k in x}==x,'COPY_LINK_HEADER_MISMATCH')
  literal=x['linkname'];a.need(bool(literal) and not literal.startswith('/') and '\\' not in literal and ':' not in literal and not any(ord(c)<32 or ord(c)==127 for c in literal),'COPY_LINK_INVALID')
  t=posixpath.normpath(posixpath.join(posixpath.dirname(x['name']),literal));a.need(t not in ('','.','..') and not t.startswith(('../','/')),'COPY_TARGET_ESCAPE')
  t=a.member_path(t);r=regular.get(t);a.need(r is not None,'COPY_TARGET_NOT_REGULAR')
  a.need(l.get('lexicalTarget')==t and l.get('regularTarget')==r,'COPY_TARGET_MISMATCH')
  projected.append({'source':x,'lexicalTarget':t,'regularTarget':r,'materialized':{'path':a.member_path(x['name']),'type':'file','bytes':r['bytes'],'mode':r['mode'],'sha256':r['sha256']}})
 alias={x['materialized']['path']:x['materialized'] for x in projected}
 result=[alias.get(x['path'],x) for x in result]
 a.need(sum(x['bytes'] for x in result if x['type']=='file')<=a.EXPANDED_MAX,'ARCHIVE_LIMIT_EXCEEDED')
 return result,projected


def checked_header(x,expected):
 kind='file' if x.isfile() else 'directory' if x.isdir() else 'symlink' if x.issym() else 'hardlink' if x.islnk() else 'special'
 actual={'name':x.name,'type':kind,'mode':x.mode,'bytes':x.size,'linkname':x.linkname,'headerOffset':x.offset,'dataOffset':x.offset_data}
 a.need(actual=={k:expected.get(k) for k in actual},'COPY_RAW_HEADER_MISMATCH')
 a.need(kind in ('file','directory','symlink'),'COPY_TYPE_INVALID');return kind


def body(stream,output,expected,started):
 h=hashlib.sha256();size=0
 while True:
  a.need(time.monotonic()-started<=540,'ARCHIVE_LIMIT_EXCEEDED');block=stream.read(min(1024**2,expected['bytes']-size+1))
  if not block:break
  size+=len(block);a.need(size<=expected['bytes'],'COPY_BODY_MISMATCH');h.update(block)
  if output is not None:output.write(block)
 a.need(size==expected['bytes'] and h.hexdigest()==expected['sha256'],'COPY_BODY_MISMATCH')


def fresh_check(dest):
 p=Path(dest);a.need(p.is_absolute(),'COPY_DEST_INVALID')
 for q in [p,*p.parents]:
  try:s=q.lstat()
  except FileNotFoundError:continue
  a.need(not stat.S_ISLNK(s.st_mode) and not(getattr(s,'st_file_attributes',0)&1024),'COPY_DEST_INVALID')
 a.need(not os.path.lexists(p) and p.parent.is_dir(),'COPY_DEST_NOT_FRESH')
 if os.name!='nt':
  s=p.parent.stat();a.need(s.st_uid==os.getuid() and s.st_gid==os.getgid() and not(s.st_mode&0o022),'COPY_DEST_INVALID')
 return p


def dir_fd(rootfd,name,create=False):
 fd=os.dup(rootfd)
 try:
  for part in PurePosixPath(name).parts:
   a.need(part not in ('','/','.','..'),'COPY_DEST_INVALID')
   if create:
    try:os.mkdir(part,0o700,dir_fd=fd)
    except FileExistsError:pass
   new=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=new
  return fd
 except BaseException:os.close(fd);raise


def relative_fd(rootfd,name,write=False):
 name=a.member_path(name);a.need(bool(name),'COPY_DEST_INVALID');parts=PurePosixPath(name)
 fd=dir_fd(rootfd,str(parts.parent) if str(parts.parent)!='.' else '',False)
 try:
  flags=(os.O_WRONLY|os.O_CREAT|os.O_EXCL if write else os.O_RDONLY)|os.O_NOFOLLOW
  filefd=os.open(parts.name,flags,0o600,dir_fd=fd);s=os.fstat(filefd)
  if not(stat.S_ISREG(s.st_mode) and s.st_nlink==1):os.close(filefd);raise a.AdmissionError('COPY_INODE_INVALID')
  return filefd
 finally:os.close(fd)


def verify_physical(root,members):
 expected={x['path']:x for x in members};seen={''}
 rootstat=Path(root).lstat();a.need(stat.S_ISDIR(rootstat.st_mode) and stat.S_IMODE(rootstat.st_mode)==0o700,'COPY_POSTIMAGE_MISMATCH')
 for parent,dirs,files in os.walk(root,followlinks=False):
  for name in dirs+files:
   p=Path(parent)/name;n=p.relative_to(root).as_posix();s=p.lstat();x=expected.get(n)
   a.need(x is not None and not stat.S_ISLNK(s.st_mode),'COPY_POSTIMAGE_MISMATCH')
   a.need((stat.S_ISDIR(s.st_mode) if x['type']=='directory' else stat.S_ISREG(s.st_mode) and s.st_nlink==1),'COPY_POSTIMAGE_MISMATCH')
   a.need(stat.S_IMODE(s.st_mode)==x['mode'],'COPY_POSTIMAGE_MISMATCH');seen.add(n)
 a.need(seen==set(expected),'COPY_POSTIMAGE_MISMATCH')
 a.verify_tree(root,members,'linux-x64',full=True)


def materialize(catalog,archive,dest):
 members,links=layout(catalog['rawMembers'],catalog['links']);a.need(members==catalog['members'] and sha(members)==catalog['memberManifestSha256'] and len(links)==1830,'CI_LINUX_LAYOUT_IDENTITY')
 a.need(len(catalog['rawMembers'])==7055 and sum(x['bytes'] for x in members if x['type']=='file')==733424833,'CI_LINUX_LAYOUT_IDENTITY');dest=fresh_check(dest);os.mkdir(dest,0o700);rootfd=os.open(dest,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);started=time.monotonic();seen=0
 try:
  for x in members:
   if x['type']=='directory' and x['path']:
    fd=dir_fd(rootfd,x['path'],True);os.close(fd)
  # ArchiveSHA512 was admitted by fixedtransport immediatelybefore this stage.
  with gzip.open(archive,'rb') as gz,tarfile.open(fileobj=gz,mode='r|') as tar:
   for x in tar:
    a.need(seen<7055,'CI_LINUX_HEADER_SET');expected=catalog['rawMembers'][seen];seen+=1;kind=checked_header(x,expected)
    if kind=='file':
     fd=relative_fd(rootfd,a.member_path(x.name),True)
     with os.fdopen(fd,'wb') as output,tar.extractfile(x) as stream:body(stream,output,expected,started);output.flush();os.fsync(output.fileno());os.fchmod(output.fileno(),expected['mode'])
   trailing=0
   while True:
    block=tar.fileobj.read(1048576)
    if not block:break
    trailing+=len(block);a.need(trailing<=1048576 and not any(block),'CI_LINUX_TRAILING_DATA')
  a.need(seen==7055,'CI_LINUX_HEADER_SET')
  for l in links:
   src=relative_fd(rootfd,l['lexicalTarget']);dst=relative_fd(rootfd,l['materialized']['path'],True)
   with os.fdopen(src,'rb') as source,os.fdopen(dst,'wb') as output:
    ss=os.fstat(source.fileno());ds=os.fstat(output.fileno());a.need((ss.st_dev,ss.st_ino)!=(ds.st_dev,ds.st_ino),'COPY_INODE_INVALID');body(source,output,l['regularTarget'],started);output.flush();os.fsync(output.fileno());os.fchmod(output.fileno(),l['regularTarget']['mode'])
  for x in sorted((x for x in members if x['type']=='directory' and x['path']),key=lambda x:x['path'].count('/'),reverse=True):
   fd=dir_fd(rootfd,x['path']);os.fchmod(fd,x['mode']);os.close(fd)
 finally:os.close(rootfd)
 for base,dirs,files in os.walk(dest,followlinks=False):
  for n in dirs+files:
   s=(Path(base)/n).lstat();a.need(s.st_uid==os.getuid() and s.st_gid==os.getgid(),'CI_LINUX_OWNERSHIP')
 verify_physical(dest,members);return members
