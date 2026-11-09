"""Native API/CLI + real owned PostgreSQL, with an independent correction-list oracle."""
import argparse,concurrent.futures,datetime,hashlib,json,os,platform,random,socket,subprocess,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path

UTC=datetime.timezone.utc
def instant(value):
    # Independent UTC parser; producer canonicalization is not called.
    return datetime.datetime.fromisoformat(value.removesuffix('Z')+'+00:00').astimezone(UTC)
def canonical(value):return instant(value).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
def linux(path):
    path=Path(path).resolve()
    return '/mnt/'+path.drive[0].lower()+'/'+path.as_posix()[3:] if os.name=='nt' else str(path)
def atomic(path,value):
    temp=path.with_suffix('.partial');temp.write_text(json.dumps(value));os.replace(temp,path)
def require(condition,message):
    if not condition:raise ValueError(message)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cli',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    cli=a.cli.resolve();out=a.out.resolve();out.mkdir(parents=True,exist_ok=False);tools=Path(__file__).resolve().parent;hostdir=out/'host'
    hostile=out/'unrelated-cwd';hostile.mkdir();(hostile/'appsettings.json').write_text('INVALID_JSON_MUST_NOT_BE_READ')
    args=['python3',linux(tools/'pg_host.py'),'--fixtures',linux(a.fixtures),'--out',linux(hostdir)]
    if os.name=='nt':args=['wsl','-d','Ubuntu-24.04','--']+args
    hostlog=(out/'host-console.log').open('wb');host=subprocess.Popen(args,stdout=hostlog,stderr=subprocess.STDOUT)
    environment=os.environ.copy();environment['DOTNET_PROCESSOR_COUNT']='2';children=[];logs=[];history=[];checks=[];expected={};counter=0;input_counter=0;query_count=0;started=time.monotonic()
    def wait(path,seconds=90):
        until=time.monotonic()+seconds
        while time.monotonic()<until:
            if path.exists():return
            if host.poll() is not None or (hostdir/'host-error.json').exists():raise ValueError('Owned database fixture failed; inspect sanitized host error')
            time.sleep(.025)
        raise TimeoutError(path.name)
    def call(*args,codes=(0,)):
        result=subprocess.run([str(cli),*map(str,args)],cwd=cli.parent,env=environment,capture_output=True,text=True,timeout=20)
        try:value=json.loads(result.stdout)
        except json.JSONDecodeError:raise ValueError('Native CLI did not return one JSON response')
        require(result.returncode in codes,'Unexpected native status '+json.dumps(value));history.append({'command':str(args[0]),'exit':result.returncode,'reply':value});return value
    def control(action):
        nonlocal counter
        counter+=1;identity='c'+str(counter);atomic(hostdir/'control.json',{'id':identity,'action':action});path=hostdir/(identity+'.json');wait(path,45);return json.loads(path.read_text())
    def stop(child):
        if child.poll() is None:child.kill()
        child.wait(timeout=10)
    def server(hook=None):
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        env=environment.copy()
        if hook:env['REFERENCE_LAB_PAUSE']=hook[0];env['REFERENCE_LAB_HOOK_DIR']=str(hook[1])
        log=(out/('api-'+str(len(children))+'.log')).open('wb');logs.append(log);child=subprocess.Popen([str(cli),'serve',str(port)],cwd=hostile,env=env,stdout=log,stderr=subprocess.STDOUT);children.append(child)
        until=time.monotonic()+20
        while time.monotonic()<until:
            if child.poll() is not None:raise ValueError('Owned API failed startup')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2):return child,'http://127.0.0.1:'+str(port)
            except OSError:time.sleep(.025)
        raise TimeoutError('Owned API readiness')
    def mark(name):checks.append(name);print('PASS '+name,flush=True)
    def data(identity,begin='2024-01-01T00:00:00Z',end='2024-01-10T00:00:00Z',tick=10000,multiplier=1000000,observed='2024-02-01T00:00:00Z',source='synthetic'):
        return {'operationId':identity,'effectiveFrom':begin,'effectiveTo':end,'tickSizeMicros':str(tick),'contractMultiplierMicros':str(multiplier),'observedAt':observed,'sourceLabel':source}
    def file_for(value):
        nonlocal input_counter
        input_counter+=1;path=out/('input-'+str(input_counter)+'.json');path.write_text(json.dumps(value));return path
    def register(value,outcome):
        require(outcome['status'] in ['CORRECTION_COMMITTED','REPLAY'],'Correction not resolved '+json.dumps(outcome));receipt=outcome['receipt'];revision=int(receipt['knowledgeRevision']);identity=value['operationId']
        if identity in expected:require(expected[identity][0]==revision,'Replayed identity changed revision')
        else:expected[identity]=(revision,value.copy())
    def submit(value,url):
        file=file_for(value);digest=hashlib.sha256(file.read_bytes()).hexdigest();result=call('ingest',url,file,codes=(0,3,4))
        for attempt in range(2):
            if result['status']!='UNKNOWN':break
            require(hashlib.sha256(file.read_bytes()).hexdigest()==digest,'Uncertain input changed');result=call('ingest',url,file,codes=(0,3,4));history.append({'sameIdentityResolution':{'id':value['operationId'],'attempt':attempt+1,'inputSha256':digest,'status':result['status']}})
        register(value,result);return result
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def http(url,method='GET',body=None):
        nonlocal query_count
        query_count+=1;request=urllib.request.Request(url,data=body,method=method,headers={'Content-Type':'application/json'})
        try:
            with opener.open(request,timeout=10) as response:code=response.status;payload=response.read(16385)
        except urllib.error.HTTPError as error:code=error.code;payload=error.read(16385)
        require(len(payload)<=16384,'API response cap')
        return code,json.loads(payload)
    points=['2023-12-31T23:59:59Z',*[f'2024-01-{day:02}T00:00:00Z' for day in range(1,12)],'2024-01-04T00:00:00.000001Z','2024-01-04T00:00:00.000002Z','2024-01-04T00:00:00.000003Z']
    def oracle(url,with_queries=True):
        raw=control('oracle');state=raw['state'];receipts=raw['receipts'];segments=raw['segments']
        require(state['head_revision']==len(expected)==len(receipts),'Committed revision/count authority')
        require([r['knowledge_revision'] for r in receipts]==list(range(1,len(expected)+1)),'No aborted/invented known revisions')
        actual_ids={r['operation_id'] for r in receipts};require(actual_ids==set(expected),'Durable correction identities')
        for r in receipts:
            revision,value=expected[r['operation_id']];require(revision==r['knowledge_revision'],'Revision receipt')
            text='reference-v1\n'+value['operationId']+'\nSYNTH\n'+canonical(value['effectiveFrom'])+'\n'+canonical(value['effectiveTo'])+'\n'+str(int(value['tickSizeMicros']))+'\n'+str(int(value['contractMultiplierMicros']))+'\n'+canonical(value['observedAt'])+'\n'+value['sourceLabel']+'\n'
            require(r['request_hash']==hashlib.sha256(text.encode()).hexdigest(),'Independent normalized intent digest')
            require(r['observed_at']==canonical(value['observedAt']) and r['source_label']==value['sourceLabel'],'Original metadata retained')
            require(int(r['payload']['knowledgeRevision'])==revision and r['payload']['operationId']==value['operationId'],'Stored original result')
        require(state['history_rows']==len(segments) and state['active_segments']==sum(s['to_revision'] is None for s in segments),'Independent segment inventory')
        for s in segments:
            require(instant(s['effective_from'])<instant(s['effective_to']) and s['from_revision']>=1 and (s['to_revision'] is None or s['from_revision']<s['to_revision']),'Half-open segment ranges')
            require(s['value_operation_id'] in expected and s['assertion_operation_id'] in expected,'Attribution foreign identities')
            require(expected[s['value_operation_id']][0]<=s['from_revision'] and expected[s['assertion_operation_id']][0]==s['from_revision'],'Origin versus assertion knowledge revision')
        for i,left in enumerate(segments):
            for right in segments[i+1:]:
                effective=instant(left['effective_from'])<instant(right['effective_to']) and instant(right['effective_from'])<instant(left['effective_to'])
                knowledge=left['from_revision']<(right['to_revision'] or 2**63) and right['from_revision']<(left['to_revision'] or 2**63)
                require(not(effective and knowledge),'Independent two-dimensional no-overlap invariant')
        if with_queries:
            ordered=sorted(expected.values(),key=lambda entry:entry[0])
            for revision in range(1,len(expected)+1):
                for point in points:
                    # Deliberately different model: last covering correction; no range-splitting code.
                    applicable=[(rev,v) for rev,v in ordered if rev<=revision and instant(v['effectiveFrom'])<=instant(point)<instant(v['effectiveTo'])]
                    expected_value=applicable[-1] if applicable else None
                    query=urllib.parse.urlencode({'effectiveAt':point,'knownThroughRevision':revision});code,reply=http(url+'/v1/instruments/SYNTH/value?'+query)
                    require(code==200 and reply['knownThroughRevision']==str(revision) and reply['effectiveAt']==canonical(point),'Exact query cutoff/time')
                    if expected_value is None:require(reply['status']=='NOT_KNOWN' and reply['value'] is None,'No invented value in unknown interval')
                    else:
                        rev,v=expected_value;actual=reply['value'];require(reply['status']=='KNOWN','Known reference value missing')
                        require(actual=={'tickSizeMicros':str(int(v['tickSizeMicros'])),'contractMultiplierMicros':str(int(v['contractMultiplierMicros'])),'valueOperationId':v['operationId'],'originKnowledgeRevision':str(rev),'sourceLabel':v['sourceLabel'],'originObservedAt':canonical(v['observedAt'])},'Independent point-in-time history mismatch')
        history.append({'independentSqlAndCorrectionListOracle':{'head':state['head_revision'],'receipts':len(receipts),'segments':len(segments),'activeSegments':state['active_segments'],'totalHttpQueries':query_count}})
        return raw
    try:
        wait(hostdir/'ready.json');private=json.loads((hostdir/'connection.private.json').read_text());environment['REFERENCE_LAB_DB']=private['connection']
        require(call('init')['status']=='INITIALIZED_FRESH','Fresh schema');main_child,url=server();require(call('head',url)['headRevision']=='0','Bootstrap is not a known revision')
        oversized=out/'oversized.json';oversized.write_bytes(b'x'*16385);require(call('ingest',url,oversized,codes=(2,))['status']=='FAILED_CLOSED','Bounded input')
        require(call('head','http://example.com:1234',codes=(2,))['status']=='FAILED_CLOSED','External endpoint before network');mark('ambient-config-isolation-and-literal-loopback-bounded-client')
        baseline=data('baseline');first=submit(baseline,url);oracle(url);mark('initial-known-interval-and-unknown-outside-half-open-bounds')
        for action in ['negative-overlap','negative-empty-effective','negative-zero-revision']:control(action);oracle(url,False)
        mark('real-database-two-dimensional-exclusion-and-bound-checks')
        patch=data('late','2024-01-03T00:00:00Z','2024-01-05T00:00:00Z',5000,2000000);submit(patch,url);oracle(url)
        old=call('query',url,'2024-01-04T00:00:00Z','1');new=call('query',url,'2024-01-04T00:00:00Z','2')
        require(old['value']['tickSizeMicros']=='10000' and new['value']['tickSizeMicros']=='5000','Late correction must not leak');mark('late-correction-cannot-leak-earlier-committed-knowledge')
        micro=data('micro','2024-01-04T00:00:00.000001Z','2024-01-04T00:00:00.000003Z',2500,3000000);submit(micro,url);oracle(url);mark('microsecond-and-touching-half-open-boundaries')
        earlier_observed=data('older-observed','2024-01-02T00:00:00Z','2024-01-06T00:00:00Z',7500,1500000,'2023-12-01T00:00:00Z','late-source');submit(earlier_observed,url);oracle(url);mark('observed-time-is-metadata-not-knowledge-order')
        replay=submit(baseline,url);require(replay['status']=='REPLAY' and replay['receipt']==first['receipt'],'Stored original result across revisions')
        conflict=file_for({**baseline,'tickSizeMicros':'9999'});require(call('ingest',url,conflict,codes=(3,))['status']=='IDENTITY_CONFLICT','Conflicting reuse');oracle(url);mark('durable-semantic-idempotency-and-conflicting-reuse')
        for bad in [{**data('bad-zero'),'tickSizeMicros':'0'},{**data('bad-offset'),'effectiveFrom':'2024-01-01T00:00:00+00:00'},{**data('bad-precision'),'effectiveFrom':'2024-01-01T00:00:00.0000001Z'},{**data('bad-empty'),'effectiveTo':'2024-01-01T00:00:00Z'}]:
            code,reply=http(url+'/v1/instruments/SYNTH/corrections','POST',json.dumps(bad).encode());require(code==400 and reply['status']=='DENIED','Rejected bad reference data')
        duplicate=json.dumps(data('duplicate')).replace('"operationId": "duplicate"','"operationId": "duplicate", "operationId": "other"')
        require(http(url+'/v1/instruments/SYNTH/corrections','POST',duplicate.encode())[0]==400,'Duplicate JSON property denied')
        require(http(url+'/v1/instruments/SYNTH/value?'+urllib.parse.urlencode({'effectiveAt':points[2],'knownAt':'2024-02-01T00:00:00Z'}))[0]==400,'Ambiguous wall-clock-only lookup denied')
        require(call('query',url,points[2],'9223372036854775807',codes=(3,))['status']=='DENIED','Future uncommitted knowledge denied')
        oracle(url);mark('invalid-units-time-json-and-future-knowledge-denied-without-effects')
        concurrent_inputs=[data('concurrent-'+str(i),f'2024-01-{i+1:02}T00:00:00Z',f'2024-01-{i+6:02}T00:00:00Z',1000+i,4000000,source='concurrent') for i in range(4)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:outcomes=list(pool.map(lambda value:submit(value,url),concurrent_inputs))
        require(len({int(r['receipt']['knowledgeRevision']) for r in outcomes})==4,'Serialized unique committed revisions');oracle(url);mark('concurrent-same-observed-time-corrections-order-by-revision')
        same=data('same-concurrent',tick=17500,multiplier=4000000,source='dedup');file=file_for(same)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:call('ingest',url,file,codes=(0,4)),range(4)))
        for reply in results:register(same,reply)
        require(sum(r['status']=='CORRECTION_COMMITTED' for r in results)==1 and len({r['receipt']['knowledgeRevision'] for r in results})==1,'One correction for concurrent identity');oracle(url);mark('concurrent-identical-ingestion-one-revision-and-result')
        rng=random.Random(314159)
        for i in range(12):
            begin=rng.randrange(1,10);end=rng.randrange(begin+1,12)
            submit(data('seed-'+str(i),f'2024-01-{begin:02}T00:00:00Z',f'2024-01-{end:02}T00:00:00Z',rng.randrange(1,10000),1000000+i,source='seeded'),url)
        oracle(url);mark('seeded-overlapping-history-independent-last-covering-oracle')
        for pause,committed in [('before-commit',False),('after-commit',True)]:
            value=data('crash-'+pause,'2024-01-02T00:00:00Z','2024-01-09T00:00:00Z',23000,5000000,source='fault');file=file_for(value);hooks=out/('hook-'+pause);hooks.mkdir();child,endpoint=server((pause,hooks));before=len(expected)
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future=pool.submit(call,'ingest',endpoint,file,codes=(0,4));wait(hooks/'ready',15);raw=control('oracle')
                require(raw['state']['head_revision']==before+(1 if committed else 0),'Uncommitted state must not create known revision');stop(child);unknown=future.result(timeout=15)
            require(unknown['status']=='UNKNOWN','Commit uncertainty exposed')
            resolved=call('ingest',url,file,codes=(0,4));require(resolved['status']==('REPLAY' if committed else 'CORRECTION_COMMITTED'),'Same identity resolves exact commit window');register(value,resolved);oracle(url)
        mark('before-after-commit-owned-process-crash-no-invented-known-revision')
        control('restart');require(submit(baseline,url)['receipt']==first['receipt'],'Ordinary restart preserves identity and revision');oracle(url);mark('ordinary-postgres-restart-preserves-bitemporal-history')
        page=call('history',url,'0');require(len(page['entries'])==16 and [int(e['knowledgeRevision']) for e in page['entries']]==list(range(1,17)),'Bounded original history page')
        final=oracle(url,False);mark('bounded-history-pages-preserve-original-attribution')
        receipt={'status':'PASS','clientOs':platform.system(),'caseCount':len(checks),'cases':checks,'committedCorrections':len(expected),'headRevision':final['state']['head_revision'],'historyRows':len(final['segments']),'activeSegments':final['state']['active_segments'],'independentPointQueries':query_count,'durationSeconds':round(time.monotonic()-started,3),'boundary':'Native API+CLI on calling OS; real PostgreSQL in existing Linux/WSL; local committed knowledge revision, no external publication/commit-time assertion.'}
        (out/'history.json').write_text(json.dumps(history,indent=2)+'\n');(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
    except Exception as error:
        (out/'history.incomplete.json').write_text(json.dumps(history,indent=2)+'\n');(out/'receipt.incomplete.json').write_text(json.dumps({'status':'INCOMPLETE_NOT_A_PASS','errorType':type(error).__name__,'passedCases':checks},indent=2)+'\n');raise
    finally:
        for child in children:
            if child.poll() is None:stop(child)
        if host.poll() is None:
            try:control('shutdown');host.wait(timeout=30)
            except Exception:host.terminate();host.wait(timeout=10)
        for log in logs:log.close()
        hostlog.close()
if __name__=='__main__':main()
