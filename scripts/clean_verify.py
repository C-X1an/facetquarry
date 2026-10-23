"""Rebuild a fresh local committed clone. Current-toolchain qualification is separate."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
from common import ROOT,run,source_hash

def main():
    dirty=run(['git','status','--porcelain'],check=False)
    if dirty.returncode!=0:print('BLOCKED: commit the audited public source first');return 2
    if dirty.stdout.strip():print('BLOCKED: clean reproduction requires a committed clean source tree');return 2
    with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as d:
        clone=Path(d)/'source';run(['git','clone','--no-hardlinks','--local',str(ROOT),str(clone)])
        command=['make','build','fmt','lint','check','test','integration','demo','clean']
        result=run(command,cwd=clone,timeout=240,check=False)
        out=ROOT/'.local/clean-verify';out.mkdir(parents=True,exist_ok=True)
        (out/'stdout.txt').write_text(result.stdout);(out/'stderr.txt').write_text(result.stderr)
        record={'schema_version':1,'evidence_type':'fresh_checkout','clean_checkout':True,'supported_toolchain':'go1.27.3' in run(['go','version']).stdout,'source':source_hash(),'commit':run(['git','rev-parse','HEAD']).stdout.strip(),'command':command,'exit_code':result.returncode,'go':run(['go','version']).stdout.strip(),'qualification':'fresh committed local checkout; separate supported-toolchain gate still applies','status':'PASS' if result.returncode==0 else 'FAIL'}
        (out/'summary.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
        return result.returncode
if __name__=='__main__':raise SystemExit(main())
