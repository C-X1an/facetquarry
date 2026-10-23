"""Verify immutable public behavioral and phase locks, without rewriting them."""
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]

def main():
    expected=json.loads((ROOT/'verification/locks.json').read_text())
    failures=[]
    for path,digest in expected['files'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest:failures.append(path)
    phases=json.loads((ROOT/'verification/phase_definitions.json').read_text())
    actual=hashlib.sha256(json.dumps(phases,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if actual!=expected['phase_plan_sha256']:failures.append('phase definitions')
    print(json.dumps({'status':'FAIL' if failures else 'PASS','changed':failures,'action':'Record a deviation; never rewrite the lock to bypass failure.'}))
    return bool(failures)
if __name__=='__main__':sys.exit(main())
