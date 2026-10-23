"""Fail closed on missing, stale, incomplete or unsupported acceptance evidence."""
import hashlib
import json
from common import ROOT,source_hash

def main():
    path=ROOT/'verification/criterion_status.json'
    if not path.exists():print('NOT RUN: criterion evidence not yet assembled');return 2
    data=json.loads(path.read_text());failures=[];identity=source_hash()
    if data.get('source')!=identity:failures.append('criterion assessment belongs to a different technical source')
    criteria=data.get('criteria',[])
    expected={f'AC-{i:03d}' for i in range(1,25)}
    if {c.get('id') for c in criteria}!=expected or len(criteria)!=24:failures.append('criterion set incomplete or duplicated')
    for c in criteria:
        if c.get('status')!='PASS':failures.append(c.get('id','unknown')+': '+c.get('status','NOT RUN'));continue
        refs=c.get('receipts',[])
        if not refs:failures.append(c['id']+': no machine receipt or review artifact')
        for ref in refs:
            file=ROOT/ref['path']
            if not file.is_file():failures.append(c['id']+': evidence missing');continue
            if hashlib.sha256(file.read_bytes()).hexdigest()!=ref['sha256']:failures.append(c['id']+': evidence digest mismatch')
            if file.name == 'receipt.json':
                record=json.loads(file.read_text())
                if record.get('status')!='PASS' or record.get('exit_code')!=0:
                    failures.append(c['id']+': linked command did not pass')
                if record.get('source_before')!=identity or record.get('source_after')!=identity:
                    failures.append(c['id']+': linked command used different source')
    # These cannot be waived by marking unit tests green.
    for key in ('supported_toolchain','independent_review_complete','full_benchmark_complete','owner_walkthrough_complete','public_export_audited','fresh_checkout_complete','resource_inventory_complete'):
        if data.get(key) is not True:failures.append('required gate: '+key)
    print(json.dumps({'status':'FAIL' if failures else 'PASS','failures':failures,'note':'Repository-local assessment is not third-party attestation; independently inspect its linked evidence.'},indent=2))
    return 1 if failures else 0
if __name__=='__main__':raise SystemExit(main())
