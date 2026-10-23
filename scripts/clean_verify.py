"""Rebuild a fresh local committed clone. Current-toolchain qualification is separate."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import time
import sys
from common import ROOT,run,source_hash

def main():
    dirty=run(['git','status','--porcelain'],check=False)
    if dirty.returncode!=0:print('BLOCKED: commit the audited public source first');return 2
    if dirty.stdout.strip():print('BLOCKED: clean reproduction requires a committed clean source tree');return 2
    out=ROOT/'.local/clean-verify'/str(time.time_ns());out.mkdir(parents=True)
    identity=source_hash()
    with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as d:
        clone=Path(d)/'source';run(['git','clone','--no-hardlinks','--local',str(ROOT),str(clone)])
        if source_hash(clone) != source_hash():
            raise SystemExit('FAIL: clean clone technical bytes differ from committed source')
        command=['make','build','fmt','lint','check','test','integration','demo','clean']
        wrapped=[sys.executable,str(clone/'scripts/evidence.py'),'--category','fresh-checkout-commands',
                 '--requirements','AC-019','--timeout','240','--']+command
        result=run(wrapped,cwd=clone,timeout=300,check=False)
        (out/'stdout.txt').write_text(result.stdout);(out/'stderr.txt').write_text(result.stderr)
        for name in ('evidence','test-failures'):
            if (clone/'.local'/name).exists():shutil.copytree(clone/'.local'/name,out/name)
        unchanged=source_hash(clone)==identity and source_hash()==identity
        record={'schema_version':1,'evidence_type':'fresh_checkout','clean_checkout':True,'supported_toolchain':'go1.27.3' in run(['go','version']).stdout,'source':identity,'commit':run(['git','rev-parse','HEAD']).stdout.strip(),'command':command,'exit_code':result.returncode,'go':run(['go','version']).stdout.strip(),'source_unchanged':unchanged,'retained_evidence':str(out.relative_to(ROOT)),'qualification':'fresh committed local checkout with retained nested command receipts; separate supported-toolchain gate still applies','status':'PASS' if result.returncode==0 and unchanged else 'FAIL'}
        (out/'summary.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
        return 0 if record['status']=='PASS' else (result.returncode or 1)
if __name__=='__main__':raise SystemExit(main())
