"""Byte-exact PASS -> intentional FAIL -> restored PASS integrity controls."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time
from common import ROOT,run,source_hash


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    results=[]
    out=ROOT/'.local/integrity-negative'/str(time.time_ns());out.mkdir(parents=True,exist_ok=True)
    identity=source_hash()
    with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as d:
        tmp=Path(d)
        for rel in ('scripts/check_integrity.py','verification/locks.json','verification/phase_definitions.json','ACCEPTANCE_SPEC.md'):
            path=tmp/rel;path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,path)
        command=['python3','scripts/check_integrity.py']
        for number,rel in enumerate(('ACCEPTANCE_SPEC.md','verification/phase_definitions.json')):
            path=tmp/rel;original=path.read_bytes();before=run(command,cwd=tmp,check=False)
            if rel.endswith('.json'):
                data=json.loads(original);data[0]['title']='unauthorized change';mutated=json.dumps(data).encode()
            else:
                mutated=original+b'\nUnauthorized relaxation.\n'
            try:
                path.write_bytes(mutated)
                defect=run(command,cwd=tmp,check=False)
            finally:
                path.write_bytes(original)
            after=run(command,cwd=tmp,check=False)
            for label,result in (('before',before),('defect',defect),('restored',after)):
                (out/f'{number}-{label}.stdout').write_bytes(result.stdout.encode())
                (out/f'{number}-{label}.stderr').write_bytes(result.stderr.encode())
            try:
                observed=json.loads(defect.stdout)
                assertion=observed.get('status')=='FAIL' and (rel in observed.get('changed',[]) or rel.endswith('phase_definitions.json') and 'phase definitions' in observed.get('changed',[]))
            except (ValueError,AttributeError):
                assertion=False
            restored=path.read_bytes()==original
            passed=before.returncode==0 and defect.returncode!=0 and after.returncode==0 and assertion and restored
            results.append({'file':rel,'command':command,'exits':[before.returncode,defect.returncode,after.returncode],
                'original_sha256':digest(original),'defect_sha256':digest(mutated),'restored_sha256':digest(path.read_bytes()),
                'byte_exact_restore':restored,'expected_assertion_failed':assertion,'status':'PASS' if passed else 'FAIL'})
    report={'schema_version':1,'source':identity,'status':'PASS' if all(x['status']=='PASS' for x in results) else 'FAIL','controls':results,'folder':str(out.relative_to(ROOT))}
    (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2));return 0 if report['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
