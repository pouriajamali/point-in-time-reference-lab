"""Resolve full license text and copyright for the exact frozen shipped graph."""
import hashlib,json
from pathlib import Path

def resolve(repo,package_dir,identity,entry,metadata):
    records=json.loads((repo/'vendor/notices/NOTICE-SOURCES.json').read_text(encoding='utf-8'))
    expected=next((r for r in records['components'] if r['id']+'/'+r['version']==identity),None)
    if expected is None:raise ValueError('No vetted notice mapping for '+identity)
    actual_license=metadata.find('{*}license');copyright=metadata.findtext('{*}copyright')
    if actual_license is None or actual_license.attrib.get('type')!='expression' or actual_license.text!=expected['license'] or not copyright or copyright!=expected['copyright'] or entry['sha512']!=expected['nugetContentHash']:
        raise ValueError('Dependency notice metadata changed: '+identity)
    source=expected['licenseSource'];name=source['file']
    if Path(name).name!=name:raise ValueError('Unsafe notice filename')
    primary=(repo/'vendor/notices'/name) if source['kind']=='vendor' else package_dir/name
    if not primary.is_file() or hashlib.sha256(primary.read_bytes()).hexdigest()!=source['sha256'] or primary.stat().st_size<300:
        raise ValueError('Required full license text missing or changed: '+identity)
    return {'license':expected['license'],'copyright':copyright,'licenseSource':source,'primary':primary,
            'suppliedNotices':[p for p in package_dir.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE','NOTICE','COPYRIGHT','THIRD-PARTY-NOTICES'))]}
