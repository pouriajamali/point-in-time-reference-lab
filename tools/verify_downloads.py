"""Verify a pinned SSH checksum signature, then every present selected archive."""
import argparse,base64,hashlib,json,re,struct,subprocess
from pathlib import Path

def read_bounded(path,limit):
    if path.is_symlink() or not path.is_file():raise ValueError('Expected regular verification input')
    with path.open('rb') as source:data=source.read(limit+1)
    if len(data)>limit:raise ValueError('Verification input exceeds cap')
    return data

def digest_archive(path):
    if path.is_symlink() or not path.is_file():raise ValueError('Expected regular archive')
    total=0;digest=hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda:source.read(1024*1024),b''):
            total+=len(block)
            if total>512*1024*1024:raise ValueError('Archive exceeds verification cap')
            digest.update(block)
    return digest.hexdigest()

def canonical_key(data):
    if len(data)>4096:raise ValueError('Public key exceeds input cap')
    if data.endswith(b'\r\n'):data=data[:-2]
    elif data.endswith(b'\n'):data=data[:-1]
    # A comment is untrusted single-line metadata and is never copied to signers.
    match=re.fullmatch(rb'ssh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: ([\x20-\x7e]{1,256}))?',data)
    if match is None:raise ValueError('Exactly one canonical ed25519 public key required')
    encoded=match.group(1)
    try:blob=base64.b64decode(encoded,validate=True)
    except ValueError as error:raise ValueError('Invalid SSH key base64') from error
    if base64.b64encode(blob)!=encoded or len(blob)!=51 or struct.unpack('>I',blob[:4])[0]!=11 or blob[4:15]!=b'ssh-ed25519' or struct.unpack('>I',blob[15:19])[0]!=32:
        raise ValueError('Noncanonical ed25519 SSH blob')
    fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode('ascii').rstrip('=')
    return 'ssh-ed25519 '+encoded.decode('ascii'),fingerprint

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory',type=Path,required=True);parser.add_argument('--work',type=Path,required=True);parser.add_argument('--trusted-fingerprint',required=True);parser.add_argument('--archive',required=True);a=parser.parse_args()
    directory=a.directory.resolve();work=a.work.resolve();work.mkdir(parents=True,exist_ok=False)
    if re.fullmatch(r'[A-Za-z0-9._-]{1,160}',a.archive) is None or not a.archive.endswith(('.zip','.tar.gz')):raise ValueError('Explicit plain archive filename required')
    key,fingerprint=canonical_key(read_bounded(directory/'SIGNING-PUBLIC-KEY.pub',4096))
    if fingerprint!=a.trusted_fingerprint:raise ValueError('Fingerprint must match the independently trusted value exactly')
    allowed=work/'allowed-signers';allowed.write_text('pouriajamali '+key+'\n',encoding='ascii',newline='\n')
    sums=read_bounded(directory/'SHA256SUMS.txt',64*1024)
    signature=work/'checksum-signature';signature.write_bytes(read_bounded(directory/'SHA256SUMS.txt.sig',16*1024))
    subprocess.run(['ssh-keygen','-Y','verify','-f',str(allowed),'-I','pouriajamali','-n','file','-s',str(signature)],input=sums,capture_output=True,check=True)
    entries={}
    for line in sums.decode('utf-8').splitlines():
        match=re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9._-]{1,160})',line)
        if match is None:raise ValueError('Invalid checksum framing')
        digest,name=match.groups()
        if name in entries or len(entries)>=64:raise ValueError('Duplicate/excess checksum entries')
        entries[name]=digest
    if a.archive not in entries or not (directory/a.archive).is_file():raise ValueError('Explicit archive missing')
    verified=[]
    for name,digest in entries.items():
        path=directory/name
        if path.exists():
            if digest_archive(path)!=digest:raise ValueError('Signed archive digest mismatch: '+name)
            verified.append(name)
    receipt={'status':'PINNED_SIGNATURE_AND_PRESENT_ARCHIVES_VERIFIED','fingerprint':a.trusted_fingerprint,'archives':verified,'requiredArchive':a.archive}
    (work/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))

if __name__=='__main__':main()
