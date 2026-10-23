"""Capture real bounded command receipts. Raw output remains ignored/private.
Usage: python3 scripts/evidence.py --category unit --requirements AC-001 -- make test
Receipts prove execution provenance within a trusted host, not independent attestation.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import uuid
from common import ROOT, environment, source_hash

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args: str) -> str | None:
    r = subprocess.run(['git', *args], cwd=ROOT, text=True, capture_output=True)
    return r.stdout.strip() if r.returncode == 0 else None

def terminate(proc: subprocess.Popen, force: bool = False) -> None:
    if os.name == 'posix':
        try: os.killpg(proc.pid, signal.SIGKILL if force else signal.SIGTERM)
        except ProcessLookupError: pass
    elif os.name == 'nt':
        subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], capture_output=True, check=False)
    else:
        proc.kill() if force else proc.terminate()

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--category', required=True)
    p.add_argument('--requirements', default='')
    p.add_argument('--timeout', type=int, default=600)
    p.add_argument('command', nargs=argparse.REMAINDER)
    a = p.parse_args(); command = a.command
    if command and command[0] == '--': command = command[1:]
    if not command: p.error('command required')
    # Never run commands containing credential literals; this wrapper is not a redactor.
    run_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:10]
    folder = ROOT / '.local' / 'evidence' / run_id
    folder.mkdir(parents=True, mode=0o700)
    stdout = folder / 'stdout.txt'; stderr = folder / 'stderr.txt'
    start = dt.datetime.now(dt.timezone.utc).isoformat(); before = source_hash()
    versions = {}
    for name, args in {'go': ['go', 'version'], 'python': [sys.executable, '--version'], 'git': ['git', '--version']}.items():
        try:
            r = subprocess.run(args, text=True, capture_output=True, timeout=10)
            versions[name] = r.stdout.strip() if r.returncode == 0 else 'UNAVAILABLE'
        except (OSError, subprocess.TimeoutExpired): versions[name] = 'UNAVAILABLE'
    monotonic = time.monotonic(); reason = None
    with stdout.open('wb') as out, stderr.open('wb') as err:
        try:
            proc = subprocess.Popen(command, cwd=ROOT, env=environment(), stdout=out, stderr=err, start_new_session=(os.name == 'posix'))
            while proc.poll() is None:
                if time.monotonic() - monotonic > a.timeout:
                    reason = 'timeout'; terminate(proc); break
                if stdout.stat().st_size + stderr.stat().st_size > 16 * 1024 * 1024:
                    reason = 'output_limit'; terminate(proc); break
                time.sleep(0.1)
            try: code = proc.wait(timeout=5)
            except subprocess.TimeoutExpired: terminate(proc, force=True); code = proc.wait()
        except OSError as exc:
            code = 127; reason = type(exc).__name__; err.write(str(exc).encode())
    after = source_hash()
    record = {'schema_version': 1, 'evidence_type': 'command', 'run_id': run_id, 'category': a.category,
              'requirements': [x for x in a.requirements.split(',') if x],
              'commit': git('rev-parse', 'HEAD'), 'git_status': git('status', '--porcelain'),
              'source_before': before, 'source_after': after,
              'command': command, 'cwd': str(ROOT), 'environment': {'system': platform.system(), 'machine': platform.machine(), 'versions': versions},
              'started_at': start, 'ended_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'duration_seconds': time.monotonic()-monotonic, 'exit_code': code,
              'stdout': str(stdout.relative_to(ROOT)), 'stderr': str(stderr.relative_to(ROOT)),
              'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr),
              'status': 'PASS' if code == 0 and reason is None and before == after else 'FAIL',
              'termination_reason': reason, 'scope': 'command only; not whole-product release approval'}
    (folder/'receipt.json').write_text(json.dumps(record, indent=2)+'\n')
    manifest = ROOT/'.local/evidence/run_manifest.jsonl'
    # Single heavy writer policy also prevents concurrent append interleaving.
    with manifest.open('a') as f: f.write(json.dumps(record, separators=(',', ':'))+'\n')
    print(json.dumps(record, indent=2))
    return 0 if record['status'] == 'PASS' else (code if code > 0 else 1)
if __name__ == '__main__': raise SystemExit(main())
