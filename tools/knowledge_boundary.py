"""Bounded native-client history omission and seventeen-receipt SQL/point oracle.

Synthetic literal-loopback fixture. Source authoring is UNTESTED until execution
receipts exist. No producer module or range-splitting implementation is imported.
"""
import argparse, collections, datetime, hashlib, http.server, json, os, platform
import socket, subprocess, threading, time, urllib.parse
from pathlib import Path

def require(condition, message):
    if not condition:
        raise ValueError(message)

def instant(value):
    return datetime.datetime.fromisoformat(value.removesuffix('Z') + '+00:00')

def canonical(value):
    return instant(value).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

def inputs():
    def row(identity, begin, end, tick, multiplier, observed, label):
        return dict(operationId=identity, effectiveFrom=begin, effectiveTo=end,
                    tickSizeMicros=str(tick), contractMultiplierMicros=str(multiplier),
                    observedAt=observed, sourceLabel=label)
    seed = row('w2-seed', '2024-01-01T00:00:00Z', '2024-02-01T00:00:00Z',
               10000, 1000000, '2024-03-01T12:00:00Z', 'synthetic-seed')
    fill = [row(f'w2-fill-{i:02}', f'2025-01-{i:02}T00:00:00Z',
                f'2025-01-{i+1:02}T00:00:00Z', 20000+i, 1000000,
                '2024-03-01T12:00:00Z', 'synthetic-fill') for i in range(2, 17)]
    late = row('w2-late', '2024-01-10T00:00:00Z', '2024-01-20T00:00:00Z',
               5000, 2000000, '2023-12-01T00:00:00Z', 'synthetic-late')
    return [seed, *fill, late]

def receipt(value, revision):
    return {**value, 'instrument': 'SYNTH', 'knowledgeRevision': str(revision),
            **{k: canonical(value[k]) for k in ('effectiveFrom', 'effectiveTo', 'observedAt')}}

def digest(value):
    text = 'reference-v1\n' + value['operationId'] + '\nSYNTH\n'
    text += canonical(value['effectiveFrom']) + '\n' + canonical(value['effectiveTo']) + '\n'
    text += str(int(value['tickSizeMicros'])) + '\n' + str(int(value['contractMultiplierMicros'])) + '\n'
    text += canonical(value['observedAt']) + '\n' + value['sourceLabel'] + '\n'
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def expected_point(rows, at, cutoff):
    # Different model: select last declared covering correction, never split ranges.
    matches = [(i, v) for i, v in enumerate(rows, 1) if i <= cutoff and
               instant(v['effectiveFrom']) <= instant(at) < instant(v['effectiveTo'])]
    value = None
    if matches:
        revision, v = matches[-1]
        value = dict(tickSizeMicros=v['tickSizeMicros'], contractMultiplierMicros=v['contractMultiplierMicros'],
                     valueOperationId=v['operationId'], originKnowledgeRevision=str(revision),
                     sourceLabel=v['sourceLabel'], originObservedAt=canonical(v['observedAt']))
    return dict(status='KNOWN' if value else 'NOT_KNOWN', instrument='SYNTH',
                effectiveAt=canonical(at), knownThroughRevision=str(cutoff), value=value)

class Client:
    def __init__(self, cli, out):
        self.cli, self.out = cli, out
        self.environment = os.environ.copy()
        for name in ('REFERENCE_LAB_DB', 'REFERENCE_LAB_PAUSE', 'REFERENCE_LAB_HOOK_DIR'):
            self.environment.pop(name, None)
        self.environment['DOTNET_PROCESSOR_COUNT'] = '2'
        self.started, self.history = time.monotonic(), []

    def remaining(self, cap=20):
        left = 600 - (time.monotonic() - self.started)
        require(left > 0, 'Scenario wall deadline')
        return min(cap, left)

    def call(self, *args, code=0):
        result = subprocess.run([str(self.cli), *map(str, args)], cwd=self.cli.parent,
                                env=self.environment, capture_output=True, text=True,
                                timeout=self.remaining())
        require(len(result.stdout.encode()) <= 16384, 'CLI response frame')
        value = json.loads(result.stdout)
        self.history.append(dict(command=str(args[0]), exit=result.returncode, reply=value))
        require(result.returncode == code, 'Unexpected native CLI exit')
        return value

def wire(client, rows):
    receipts = [receipt(v, i) for i, v in enumerate(rows, 1)]
    cases = [(16, [], False), (0, list(range(1, 16)), False),
             (0, list(range(2, 18)), False), (0, [*range(1, 8), *range(9, 18)], False),
             (15, [17], False), (0, list(range(1, 17)), True), (16, [17], True)]
    results = []
    for after, revisions, accepted in cases:
        page = dict(headRevision='17', entries=[receipts[i-1] for i in revisions])
        payload = json.dumps(page).encode()
        require(len(payload) <= 16384, 'Wire fixture response cap')
        requested = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requested.append(self.path)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *_):
                pass
        with http.server.HTTPServer(('127.0.0.1', 0), Handler) as server:
            server.timeout = client.remaining(10)
            worker = threading.Thread(target=server.handle_request, daemon=True)
            worker.start()
            try:
                reply = client.call('history', f'http://127.0.0.1:{server.server_port}', after,
                                    code=0 if accepted else 4)
            finally:
                worker.join(timeout=client.remaining(12))
            require(not worker.is_alive() and requested ==
                    [f'/v1/instruments/SYNTH/history?afterRevision={after}'], 'One exact loopback request')
        require(reply == page if accepted else reply.get('status') == 'UNAVAILABLE',
                'Incomplete page must not be reported as successful history')
        results.append(dict(after=after, revisions=revisions, accepted=accepted))
    return dict(status='PASS', mode='wire-only', responseCount=7, cases=results,
                boundary='Owned loopback responses to actual native CLI; no database or POST.')

def expected_segments(rows):
    def segment(v, begin, end, start, stop, assertion):
        return dict(effective_from=canonical(begin), effective_to=canonical(end),
                    from_revision=start, to_revision=stop, tick_size_micros=int(v['tickSizeMicros']),
                    contract_multiplier_micros=int(v['contractMultiplierMicros']),
                    value_operation_id=v['operationId'], assertion_operation_id=assertion)
    seed, late = rows[0], rows[16]
    result = [segment(seed, seed['effectiveFrom'], seed['effectiveTo'], 1, 17, 'w2-seed')]
    result += [segment(v, v['effectiveFrom'], v['effectiveTo'], i, None, v['operationId'])
               for i, v in enumerate(rows[1:16], 2)]
    # Literal expected rectangles, not an implementation of the producer split planner.
    result += [segment(seed, '2024-01-01T00:00:00Z', '2024-01-10T00:00:00Z', 17, None, 'w2-late'),
               segment(seed, '2024-01-20T00:00:00Z', '2024-02-01T00:00:00Z', 17, None, 'w2-late'),
               segment(late, '2024-01-10T00:00:00Z', '2024-01-20T00:00:00Z', 17, None, 'w2-late')]
    return result

def sql_oracle(raw, rows, receipts):
    require(raw['state'] == dict(id=True, head_revision=17, active_segments=18, history_rows=19),
            'Exact committed SQL state')
    require(len(raw['receipts']) == 17, 'All original SQL receipts')
    for i, (actual, v) in enumerate(zip(raw['receipts'], rows), 1):
        require(actual == dict(operation_id=v['operationId'], knowledge_revision=i,
                request_hash=digest(v), observed_at=canonical(v['observedAt']),
                source_label=v['sourceLabel'], payload=receipts[i-1]), 'Independent SQL intent/receipt')
    segments = raw['segments']
    require(len(segments) == 19 and sum(s['to_revision'] is None for s in segments) == 18,
            'Exact independent segment inventory')
    ids = [s['row_id'] for s in segments]
    require(all(type(i) is int and i > 0 for i in ids) and len(set(ids)) == len(ids),
            'Storage identity uniqueness only; gaps remain legal')
    stripped = [{k: v for k, v in s.items() if k != 'row_id'} for s in segments]
    freeze = lambda values: collections.Counter(json.dumps(v, sort_keys=True) for v in values)
    require(freeze(stripped) == freeze(expected_segments(rows)), 'Literal SQL rectangles/provenance')
    for i, a in enumerate(segments):
        for b in segments[i+1:]:
            effective = instant(a['effective_from']) < instant(b['effective_to']) and \
                        instant(b['effective_from']) < instant(a['effective_to'])
            knowledge = a['from_revision'] < (b['to_revision'] or 4097) and \
                        b['from_revision'] < (a['to_revision'] or 4097)
            require(not (effective and knowledge), 'Independent two-dimensional exclusion')

def database(client, rows, fixtures):
    require(platform.system() == 'Linux' and os.getuid() != 0, 'Existing non-root native Linux profile')
    tools, hostdir = Path(__file__).resolve().parent, client.out / 'host'
    receipts = [receipt(v, i) for i, v in enumerate(rows, 1)]
    counter, api, host, logs = 0, None, None, []
    def wait(path, cap=45):
        end = time.monotonic() + client.remaining(cap)
        while time.monotonic() < end:
            if path.exists():
                return
            require(host.poll() is None and not (hostdir / 'host-error.json').exists(),
                    'Owned PostgreSQL supervisor unavailable; inspect private evidence')
            time.sleep(.025)
        raise TimeoutError('Owned fixture readiness/control deadline')
    def control(action):
        nonlocal counter
        counter += 1
        identity = 'k' + str(counter)
        temporary = hostdir / 'control.partial'
        temporary.write_text(json.dumps(dict(id=identity, action=action)))
        os.replace(temporary, hostdir / 'control.json')
        response = hostdir / (identity + '.json')
        wait(response)
        return json.loads(response.read_text())
    try:
        log = (client.out / 'host-console.log').open('xb'); logs.append(log)
        host = subprocess.Popen(['python3', str(tools / 'pg_host.py'), '--fixtures', str(fixtures),
                                 '--out', str(hostdir)], stdout=log, stderr=subprocess.STDOUT,
                                env=client.environment)
        wait(hostdir / 'ready.json', 90)
        client.environment['REFERENCE_LAB_DB'] = json.loads(
            (hostdir / 'connection.private.json').read_text())['connection']
        require(client.call('init')['status'] == 'INITIALIZED_FRESH', 'Fresh schema required')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        log = (client.out / 'api.log').open('xb'); logs.append(log)
        api = subprocess.Popen([str(client.cli), 'serve', str(port)], cwd=client.cli.parent,
                               env=client.environment, stdout=log, stderr=subprocess.STDOUT)
        url = 'http://127.0.0.1:' + str(port)
        end = time.monotonic() + client.remaining(20)
        while True:
            require(api.poll() is None and time.monotonic() < end, 'Owned API startup deadline')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    break
            except OSError:
                time.sleep(.025)
        paths = []
        for i, v in enumerate(rows, 1):
            path = client.out / f'input-{i:02}.json'
            path.write_text(json.dumps(v) + '\n'); paths.append(path)
            if i == 17:
                at = '2024-01-15T00:00:00Z'
                require(client.call('query', url, at, 16) == expected_point(rows[:16], at, 16),
                        'Before late correction: seed at cutoff16')
                require(client.call('query', url, at, 17, code=3)['status'] == 'DENIED',
                        'Uncommitted future cutoff denied')
                require(client.call('head', url)['headRevision'] == '16', 'Future denial has no effect')
            reply = client.call('ingest', url, path)
            require(reply == dict(status='CORRECTION_COMMITTED', operationId=v['operationId'],
                                  receipt=receipts[i-1]), 'Literal committed intent/revision/receipt')
        points = ['2023-12-31T23:59:59.999999Z', '2024-01-09T23:59:59.999999Z',
                  '2024-01-10T00:00:00Z', '2024-01-15T00:00:00Z',
                  '2024-01-19T23:59:59.999999Z', '2024-01-20T00:00:00Z', '2024-02-01T00:00:00Z']
        for cutoff in (16, 17):
            for at in points:
                require(client.call('query', url, at, cutoff) == expected_point(rows, at, cutoff),
                        'Independent last-covering-input point/provenance oracle')
        pages = [client.call('history', url, after) for after in (0, 16, 17)]
        require(pages == [dict(headRevision='17', entries=receipts[:16]),
                          dict(headRevision='17', entries=[receipts[16]]),
                          dict(headRevision='17', entries=[])], 'All full original history records')
        require(pages[0]['entries'] + pages[1]['entries'] == receipts, 'Actual continuation16->17')
        before = hashlib.sha256(paths[-1].read_bytes()).hexdigest()
        require(client.call('ingest', url, paths[-1]) == dict(status='REPLAY',
                operationId='w2-late', receipt=receipts[16]), 'Same bytes replay original receipt17')
        require(hashlib.sha256(paths[-1].read_bytes()).hexdigest() == before, 'Replay input unchanged')
        conflict = client.out / 'conflict.json'
        conflict.write_text(json.dumps({**rows[16], 'tickSizeMicros': '5001'}) + '\n')
        require(client.call('ingest', url, conflict, code=3) == dict(status='IDENTITY_CONFLICT',
                operationId='w2-late', receipt=None), 'Conflicting intent has no correction')
        require(client.call('head', url)['headRevision'] == '17', 'Replay/conflict retain committed head')
        raw = control('oracle'); sql_oracle(raw, rows, receipts)
        (client.out / 'sql-oracle.json').write_text(json.dumps(raw, indent=2) + '\n')
        return dict(status='PASS', mode='database', committedCorrections=17, historyRows=19,
                    activeSegments=18, preCorrectionPointQueries=1, futureCutoffDenials=1,
                    postCorrectionPointQueries=14, historyAfter=[0, 16, 17], replay=1, conflict=1,
                    boundary='One SYNTH; observedAt is metadata; per-page head, no snapshot/authenticity claim.')
    finally:
        if api is not None and api.poll() is None:
            api.terminate()
            try:
                api.wait(timeout=10)
            except subprocess.TimeoutExpired:
                api.kill(); api.wait(timeout=5)
        try:
            if host is not None and host.poll() is None:
                control('shutdown'); host.wait(timeout=40)
            if host is not None:
                require(host.returncode == 0, 'Owned PostgreSQL supervisor cleanup failed')
        finally:
            for log in logs:
                log.close()
        # Never kill an unrelated server or abruptly kill the PG supervisor.
        # An incomplete shutdown raises; its existing900s ownership deadline remains.

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--wire-only', action='store_true')
    mode.add_argument('--fixtures', type=Path)
    args = parser.parse_args()
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=False)
    client = Client(args.cli.resolve(strict=True), out)
    try:
        result = wire(client, inputs()) if args.wire_only else database(client, inputs(), args.fixtures.resolve())
        result['clientOs'] = platform.system()
        (out / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
        (out / 'history.json').write_text(json.dumps(client.history, indent=2) + '\n')
        print(json.dumps(result))
    except Exception as error:
        (out / 'receipt.incomplete.json').write_text(json.dumps(dict(
            status='INCOMPLETE_NOT_A_PASS', errorType=type(error).__name__)) + '\n')
        (out / 'history.incomplete.json').write_text(json.dumps(client.history, indent=2) + '\n')
        raise

if __name__ == '__main__':
    main()
