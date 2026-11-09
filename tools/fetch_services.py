"""Fetch pinned upstream Linux fixtures; never install packages or start services.

TLS source URLs and published digest metadata are recorded, not an independent
vendor-signature verification. Binaries/archives stay outside the source tree.
"""
import argparse, hashlib, json, urllib.request
from pathlib import Path

def get(url):
    request = urllib.request.Request(url, headers={'User-Agent':'ownership-lab-fixtures/1'})
    with urllib.request.urlopen(request, timeout=60) as response:
        data=response.read(64*1024*1024+1)
        if len(data)>64*1024*1024:raise ValueError('Upstream fixture exceeds 64 MiB cap')
        return data

def sha(data):return hashlib.sha256(data).hexdigest()

def fetch(out):
    out.mkdir(parents=True,exist_ok=False)
    receipt=json.loads(Path(__file__).with_name('upstream.lock.json').read_text(encoding='utf-8'))
    for record in receipt['files']:
        data=get(record['url']);name=record['name']
        if Path(name).name!=name or sha(data)!=record['sha256'] or len(data)!=record['bytes']:
            raise ValueError('Frozen fixture mismatch: '+name)
        (out/name).write_bytes(data)
    (out/'UPSTREAM-FIXTURES.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':'FETCHED_VERIFIED_DIGESTS','files':len(receipt['files']),'out':str(out.resolve())}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    fetch(parser.parse_args().out.resolve())
