"""Prove immutable acceptance and phase edits are rejected in a disposable copy."""
import json
from pathlib import Path
import shutil
import tempfile
from common import ROOT,run

def main():
    results=[]
    with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as d:
        tmp=Path(d)
        for rel in ('scripts/check_integrity.py','verification/locks.json','verification/phase_definitions.json','ACCEPTANCE_SPEC.md'):
            p=tmp/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,p)
        command=['python3','scripts/check_integrity.py']
        for rel in ('ACCEPTANCE_SPEC.md','verification/phase_definitions.json'):
            p=tmp/rel;original=p.read_text();before=run(command,cwd=tmp,check=False)
            if rel.endswith('.json'):
                data=json.loads(original);data[0]['title']='unauthorized change';p.write_text(json.dumps(data))
            else:p.write_text(original+'\nUnauthorized relaxation.\n')
            defect=run(command,cwd=tmp,check=False);p.write_text(original);after=run(command,cwd=tmp,check=False)
            passed=before.returncode==0 and defect.returncode!=0 and after.returncode==0
            results.append({'file':rel,'exits':[before.returncode,defect.returncode,after.returncode],'status':'PASS' if passed else 'FAIL'})
    print(json.dumps(results,indent=2));return 0 if all(x['status']=='PASS' for x in results) else 1
if __name__=='__main__':raise SystemExit(main())
