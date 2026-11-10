"""Fail-closed change classification and bounded documentation/pipeline checks.

Only ordinary source/PR validation is economized. Every tag/manual run is native.
No account settings, billing, artifact deletion, project execution or deployment.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile


class PolicyError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyError(message)


def docs_path(name: str) -> bool:
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or any(ord(c) < 32 for c in name):
        return False
    if name in {'README.md', 'CONTRIBUTING.md', 'CHANGELOG.md'}:
        return True
    # Provenance, license, fixture and workflow changes remain full native validation.
    if name.startswith('docs/') and name.endswith('.md'):
        return path.name not in {'PROVENANCE.md', 'NOTICE.md', 'LICENSE.md'}
    return name == 'docs/FLAGSHIP-EVIDENCE.json'


def native_required(event: str, ref: str, paths: list[str] | None) -> bool:
    if ref.startswith('refs/tags/') or event == 'workflow_dispatch':
        return True
    if event not in {'push', 'pull_request'} or not paths or len(paths) > 5000:
        return True
    return not all(docs_path(path) for path in paths)


def git_output(*args: str) -> bytes:
    result = subprocess.run(['git', *args], capture_output=True, timeout=30)
    require(result.returncode == 0 and len(result.stdout) <= 2 * 1024 * 1024, 'Git diff unavailable or beyond cap')
    return result.stdout


def changed_paths(event: str, payload: dict) -> list[str] | None:
    try:
        if event == 'push':
            base, head = payload['before'], payload['after']
        elif event == 'pull_request':
            base = payload['pull_request']['base']['sha']
            head = payload['pull_request']['head']['sha']
        else:
            return None
        require(all(isinstance(v, str) and re.fullmatch('[0-9a-f]{40}', v) and v != '0' * 40 for v in [base, head]), 'Ambiguous commit range')
        if event == 'pull_request':
            # Complete PR delta, not merely the final docs commit after a source commit.
            base = git_output('merge-base', base, head).decode('ascii').strip()
            require(re.fullmatch('[0-9a-f]{40}', base) is not None, 'Ambiguous PR merge base')
        data = git_output('diff', '--no-renames', '--name-only', '-z', base, head, '--')
        paths = data.decode('utf-8', errors='strict').split('\0')
        if paths and paths[-1] == '':
            paths.pop()
        return paths if paths and len(paths) <= 5000 else None
    except (KeyError, TypeError, ValueError, subprocess.SubprocessError, OSError):
        return None  # Unknown must never become a docs-only success.


def markdown_links(text: str) -> list[str]:
    visible = []
    fence = None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if match:
            token = match.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is None:
            visible.append(line)
    require(fence is None, 'Unclosed Markdown fence')
    return re.findall(r'\[[^\]\n]+\]\(([^)\s]+)\)', '\n'.join(visible))


def check_documents(paths: list[str] | None, root: Path) -> dict:
    checked, removed = 0, 0
    for name in paths or []:
        if not docs_path(name):
            continue
        target = root / name
        require(not target.is_symlink() and target.resolve().is_relative_to(root.resolve()), 'Document path escapes checkout')
        if not target.exists():
            require(name != 'README.md', 'Root README must remain present')
            removed += 1
            continue
        require(target.is_file() and target.stat().st_size <= 2 * 1024 * 1024, 'Document size/type cap')
        raw = target.read_bytes()
        require(not raw.startswith(b'\xef\xbb\xbf') and b'\0' not in raw, 'Document encoding/framing')
        text = raw.decode('utf-8', errors='strict')
        if name.endswith('.json'):
            value = json.loads(text)
            require(value.get('schema') == 'flagship-evidence/v1', 'Known evidence schema required')
            runtime = value.get('runtime', {})
            require(all(re.fullmatch('[0-9a-f]{40}', runtime.get(k, '')) for k in ['commit', 'tree', 'signedTagObject']), 'Frozen runtime identities required')
            assets = value.get('release', {}).get('assets', [])
            require(len(assets) == 6 and len({a.get('name') for a in assets}) == 6, 'Six unique frozen assets required')
            require(all(re.fullmatch('[0-9a-f]{64}', a.get('sha256', '')) for a in assets), 'Actual archive/key/signature SHA256 pins required')
        else:
            for link in markdown_links(text):
                if link.startswith(('https://', 'http://', 'mailto:', '#')):
                    continue
                require(':' not in link, 'Unsupported document URI scheme')
                relative = link.split('#', 1)[0].split('?', 1)[0]
                require(bool(relative), 'Empty relative link')
                destination = (target.parent / relative).resolve()
                require(destination.is_relative_to(root.resolve()) and destination.exists(), 'Missing or external relative document link: ' + link)
        checked += 1
    return {'checked': checked, 'removed': removed, 'scope': 'UTF-8/framing, balanced fences, bounded relative links and frozen-evidence JSON shape; not exhaustive prose/security review'}


def check_source_inventory(root: Path) -> int:
    """Read explicit source-package allowlists without importing/executing a packager."""
    checked = 0
    for name in ['scripts/package.py', 'scripts/source_package.py']:
        path = root / name
        if not path.is_file():
            continue
        require(path.stat().st_size <= 2 * 1024 * 1024, 'Packager AST cap')
        module = ast.parse(path.read_text(encoding='utf-8'))
        constants = {target.id: node.value.value for node in module.body if isinstance(node, ast.Assign)
                     and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                     for target in node.targets if isinstance(target, ast.Name)}
        values = [node.value for node in module.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == 'ALLOWED' for target in node.targets)]
        if not values:
            continue
        require(len(values) == 1, 'One explicit source allowlist required')
        value = values[0]
        require(isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == 'frozenset'
                and len(value.args) == 1 and not value.keywords and isinstance(value.args[0], ast.Set), 'Review computed source allowlist before using a light gate')
        allowed = set()
        for element in value.args[0].elts:
            item = element.value if isinstance(element, ast.Constant) else constants.get(element.id) if isinstance(element, ast.Name) else None
            require(isinstance(item, str), 'Literal source inventory only')
            allowed.add(item)
        tracked = set()
        for row in git_output('ls-files', '--stage', '-z').split(b'\0'):
            if not row:
                continue
            metadata, filename = row.split(b'\t', 1)
            mode, _, stage = metadata.split()
            require(mode == b'100644' and stage == b'0', 'Unsafe/unmerged source inventory mode')
            tracked.add(filename.decode('utf-8', errors='strict'))
        require(tracked == allowed, 'Source-package inventory differs; docs-only must not hide an unpackageable tree')
        checked += 1
    return checked


def gate() -> None:
    event, ref = os.environ.get('GITHUB_EVENT_NAME', ''), os.environ.get('GITHUB_REF', '')
    payload = {}
    try:
        event_file = Path(os.environ['GITHUB_EVENT_PATH'])
        require(event_file.is_file() and event_file.stat().st_size <= 4 * 1024 * 1024, 'Event payload cap')
        payload = json.loads(event_file.read_text(encoding='utf-8'))
    except (KeyError, OSError, ValueError):
        payload = {}
    paths = changed_paths(event, payload)
    full = native_required(event, ref, paths)
    checks = check_documents(paths, Path.cwd())
    inventory = check_source_inventory(Path.cwd()) if not full else 0
    output = os.environ.get('GITHUB_OUTPUT')
    require(bool(output), 'Runner output file required')
    with Path(output).open('a', encoding='utf-8', newline='\n') as stream:
        stream.write('native=' + ('true' if full else 'false') + '\n')
    result = {'nativeRequired': full, 'event': event, 'changedFiles': len(paths) if paths is not None else 'UNKNOWN', 'documents': checks, 'explicitSourceInventoriesChecked': inventory, 'unknownDiffMeansFullNative': True}
    print(json.dumps(result, ensure_ascii=True))
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with Path(summary).open('a', encoding='utf-8') as stream:
            stream.write('## CI scope\n\n```json\n' + json.dumps(result, indent=2) + '\n```\n')


def lint() -> None:
    # Pinned public upstream release; no token, global installation or latest URL.
    version = '1.7.12'
    if os.name == 'nt':
        name, size, digest, executable = 'windows_amd64.zip', 2479065, '6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9', 'actionlint.exe'
    else:
        name, size, digest, executable = 'linux_amd64.tar.gz', 2353908, '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8', 'actionlint'
    archive_name = f'actionlint_{version}_{name}'
    url = f'https://github.com/rhysd/actionlint/releases/download/v{version}/{archive_name}'
    request = urllib.request.Request(url, headers={'User-Agent': 'BoundedPortfolioCiPolicy/1.0'})
    with urllib.request.urlopen(request, timeout=45) as response:
        require(response.status == 200 and response.url.startswith('https://'), 'HTTPS linter download required')
        raw = response.read(4 * 1024 * 1024 + 1)
    require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, 'Pinned actionlint archive bytes')
    work = Path(tempfile.mkdtemp(prefix='portfolio-actionlint-', dir=os.environ.get('RUNNER_TEMP')))
    if name.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            info = archive.getinfo(executable)
            require(info.file_size <= 20 * 1024 * 1024 and not info.is_dir(), 'Linter executable cap')
            binary = archive.read(info)
    else:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            info = archive.getmember(executable)
            require(info.isfile() and info.size <= 20 * 1024 * 1024, 'Linter executable type/cap')
            binary = archive.extractfile(info).read()
    target = work / executable
    target.write_bytes(binary)
    if os.name != 'nt':
        target.chmod(0o755)
    workflows = git_output('ls-files', '-z', '.github/workflows/*.yml', '.github/workflows/*.yaml').decode('utf-8').split('\0')
    workflows = [name for name in workflows if name]
    require(bool(workflows), 'Tracked workflows required for actionlint')
    # Only actionlint itself is claimed; optional external ShellCheck/Pyflakes are not installed or inferred.
    subprocess.run([str(target), '-color', '-shellcheck=', '-pyflakes=', *workflows], check=True, timeout=90)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['gate', 'lint'])
    args = parser.parse_args()
    gate() if args.mode == 'gate' else lint()
