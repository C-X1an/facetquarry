"""Target four critical defects in disposable source copies, never the real branch."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import time
from common import ROOT, run, source_files, source_hash

MUTATIONS = [
    ('tenant', 'internal/engine/types.go', 'if g.Tenant == tenant {', 'if true {', 'TestTenantScope'),
    ('filter', 'internal/engine/types.go', 'if len(f) == 0 {', 'if len(f) >= 0 {', 'TestExactAndTies'),
    ('exact-label', 'internal/engine/search.go', 'r.Exact = false', 'r.Exact = true', 'TestBudget'),
    ('budget', 'internal/engine/search.go', 'if w.used >= w.budget {', 'if w.used > w.budget {', 'TestBudget'),
]

def main() -> int:
    out=ROOT/'.local/mutation'/str(time.time_ns());out.mkdir(parents=True,exist_ok=True);results=[]
    initial=source_hash()
    with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as d:
        copy=Path(d)
        for path in source_files():
            target=copy/path.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,target)
        for name,path,old,new,test in MUTATIONS:
            target=copy/path;original=target.read_text()
            if original.count(old)!=1:raise RuntimeError(f'{name}: mutation anchor changed; repair explicitly')
            command=['go','test','-count=1','./internal/engine','-run','^'+test+'$']
            baseline=run(command,cwd=copy,check=False)
            if baseline.returncode!=0:raise AssertionError('baseline fails: '+baseline.stdout+baseline.stderr)
            target.write_text(original.replace(old,new))
            mutated=run(command,cwd=copy,check=False)
            target.write_text(original)
            restored=run(command,cwd=copy,check=False)
            killed=mutated.returncode!=0 and ('--- FAIL: '+test) in mutated.stdout and '[build failed]' not in mutated.stdout
            for label,r in [('before',baseline),('defect',mutated),('restored',restored)]:
                (out/f'{name}-{label}.stdout').write_text(r.stdout);(out/f'{name}-{label}.stderr').write_text(r.stderr)
            ok=killed and restored.returncode==0 and target.read_text()==original
            results.append({'mutation':name,'test':test,'command':command,'before_exit':baseline.returncode,
                            'defect_exit':mutated.returncode,'restored_exit':restored.returncode,
                            'expected_assertion_failed':killed,'status':'PASS' if ok else 'FAIL',
                            'original_sha256':hashlib.sha256(original.encode()).hexdigest(),
                            'mutated_sha256':hashlib.sha256(original.replace(old,new).encode()).hexdigest()})
    if source_hash()!=initial:raise AssertionError('real source changed during mutation campaign')
    report={'schema_version':1,'evidence_type':'mutation_summary','source':initial,'controls':results,'scope':'four selected critical defects, not a whole-program mutation score',
            'status':'PASS' if all(x['status']=='PASS' for x in results) else 'FAIL'}
    (out/'summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    return 0 if report['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
