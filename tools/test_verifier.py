"""Real SSH-signature regressions; only a fresh disposable attacker key is created."""
import argparse,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
import verify_downloads
ROOT=Path(__file__).resolve().parents[1]
PIN='SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    fixture=ROOT/'tests/provenance-fixture'
    key_directory=Path(tempfile.mkdtemp(prefix='ownership-verifier-private-')) if os.name=='posix' else a.out
    if os.name=='posix':os.chmod(key_directory,0o700)
    attacker=key_directory/'disposable-attacker-key'
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','DISPOSABLE_TEST_KEY','-f',str(attacker)],check=True,timeout=20)
    public=(ROOT/'SIGNING-PUBLIC-KEY.pub').read_bytes();evil=attacker.with_suffix('.pub').read_bytes().strip();counter=0
    def attempt(key=public,pin=PIN,forged=False,tamper=False,mode='normal'):
        nonlocal counter
        counter+=1;folder=a.out/('case-'+str(counter));folder.mkdir()
        for name in ['fixture.zip','SHA256SUMS.txt','SHA256SUMS.txt.sig']:shutil.copy2(fixture/name,folder/name)
        (folder/'SIGNING-PUBLIC-KEY.pub').write_bytes(key)
        if forged:
            (folder/'SHA256SUMS.txt.sig').unlink()
            subprocess.run(['ssh-keygen','-Y','sign','-f',str(attacker),'-n','file',str(folder/'SHA256SUMS.txt')],capture_output=True,check=True,timeout=15)
        if tamper:
            data=bytearray((folder/'fixture.zip').read_bytes());data[0]^=1;(folder/'fixture.zip').write_bytes(data)
        env=os.environ.copy();env.pop('PYTHONOPTIMIZE',None)
        if mode=='env':env['PYTHONOPTIMIZE']='1'
        result=subprocess.run([sys.executable]+(['-O'] if mode=='flag' else [])+[str(ROOT/'tools/verify_downloads.py'),'--directory',str(folder),'--work',str(folder/'verification'),'--archive','fixture.zip','--trusted-fingerprint',pin],env=env,capture_output=True,text=True,timeout=20)
        return result,folder
    class Cases(unittest.TestCase):
        def test_actual_known_key_signature_and_archive(self):
            for mode in ['normal','flag','env']:
                result,folder=attempt(mode=mode);self.assertEqual(0,result.returncode,result.stderr)
                self.assertEqual('PINNED_SIGNATURE_AND_PRESENT_ARCHIVES_VERIFIED',json.loads(result.stdout)['status'])
                self.assertEqual('pouriajamali '+verify_downloads.canonical_key(public)[0]+'\n',(folder/'verification/allowed-signers').read_text())
        def test_valid_pinned_first_key_cannot_inject_attacker_principal(self):
            for mode in ['normal','flag','env']:
                result,_=attempt(public.strip()+b'\npouriajamali '+evil+b'\n',forged=True,mode=mode);self.assertNotEqual(0,result.returncode)
        def test_second_bare_key_and_extra_blank_line_are_rejected(self):
            for value in [public.strip()+b'\n'+evil+b'\n',public+b'\n']:
                with self.assertRaises(ValueError):verify_downloads.canonical_key(value)
                for mode in ['normal','flag','env']:
                    result,_=attempt(value,forged=True,mode=mode);self.assertNotEqual(0,result.returncode)
        def test_forged_single_line_comment_does_not_authorize_attacker(self):
            base=verify_downloads.canonical_key(public)[0].encode()
            for mode in ['normal','flag','env']:
                result,folder=attempt(base+b' pouriajamali '+evil+b'\n',forged=True,mode=mode)
                self.assertNotEqual(0,result.returncode)
                self.assertEqual('pouriajamali '+base.decode()+'\n',(folder/'verification/allowed-signers').read_text())
        def test_wrong_case_fingerprint_and_wrong_signature_fail(self):
            for mode in ['normal','flag','env']:
                result,_=attempt(pin='sha256:'+PIN.split(':')[1],mode=mode);self.assertNotEqual(0,result.returncode)
                result,_=attempt(forged=True,mode=mode);self.assertNotEqual(0,result.returncode)
                result,_=attempt(key=evil+b'\n',forged=True,mode=mode);self.assertNotEqual(0,result.returncode)
        def test_noncanonical_blob_and_controls_are_rejected(self):
            base=verify_downloads.canonical_key(public)[0].encode()
            for value in [base+b'=\n',base+b'\0comment\n',b'restrict '+base+b'\n',base+b'\rCOMMENT\n',b'ssh-ed25519 AAAA\n']:
                with self.assertRaises(ValueError):verify_downloads.canonical_key(value)
        def test_crlf_single_line_and_untrusted_comment_are_safe(self):
            base,fingerprint=verify_downloads.canonical_key(public)
            self.assertEqual((base,fingerprint),verify_downloads.canonical_key(base.encode()+b' arbitrary-comment\r\n'))
        def test_tampered_selected_archive_fails_after_valid_signature(self):
            for mode in ['normal','flag','env']:
                result,_=attempt(tamper=True,mode=mode);self.assertNotEqual(0,result.returncode)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
    receipt={'status':'PASS' if result.wasSuccessful() else 'FAIL','run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'subprocessScenarios':counter,'modes':['normal','python -O','PYTHONOPTIMIZE=1'],'scope':'Actual pinned signed fixture, fresh attacker signatures, multi-key/principal/comment injection, canonical blob/case/controls and tampered archive','originalPrivateKeyReadOrCopied':False,'disposablePrivateKeyMustRemainPrivate':True}
    (a.out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');raise SystemExit(0 if result.wasSuccessful() else 1)

if __name__=='__main__':main()
