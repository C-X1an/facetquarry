"""Rebuild a fresh local committed clone. Current-toolchain qualification is separate."""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import time
import sys
from common import ROOT,run,source_hash

def checkout_commands(clone, out, command):
    """Retain available evidence even if the outer command wrapper cannot finish."""
    wrapped=[sys.executable,str(clone/'scripts/evidence.py'),'--category','fresh-checkout-commands',
             '--requirements','AC-019','--timeout','240','--']+command
    stdout=stderr='';code=None;termination=None;error=None;retention_errors=[]
    try:
        result=run(wrapped,cwd=clone,timeout=300,check=False)
        stdout=result.stdout;stderr=result.stderr;code=result.returncode
    except subprocess.TimeoutExpired as failure:
        stdout=failure.stdout or '';stderr=failure.stderr or ''
        termination='outer_timeout';error=str(failure)
    except OSError as failure:
        termination='wrapper_start_error';error=type(failure).__name__+': '+str(failure)
    finally:
        for name in ('evidence','test-failures'):
            if (clone/'.local'/name).exists():
                try:shutil.copytree(clone/'.local'/name,out/name)
                except OSError as failure:retention_errors.append(name+': '+str(failure))
    for name,value in (('stdout.txt',stdout),('stderr.txt',stderr)):
        if isinstance(value,bytes):(out/name).write_bytes(value)
        else:(out/name).write_text(value)
    return {'exit_code':code,'termination_reason':termination,'error':error,'retention_errors':retention_errors}

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
        outcome=checkout_commands(clone,out,command)
        unchanged=source_hash(clone)==identity and source_hash()==identity
        passed=outcome['exit_code']==0 and outcome['termination_reason'] is None and not outcome['retention_errors'] and unchanged
        version=run(['go','version']).stdout.strip()
        record={'schema_version':1,'evidence_type':'fresh_checkout','clean_checkout':True,'supported_toolchain':version.startswith('go version go1.27.3 '),'source':identity,'commit':run(['git','rev-parse','HEAD']).stdout.strip(),'command':command,**outcome,'go':version,'source_unchanged':unchanged,'retained_evidence':str(out.relative_to(ROOT)),'qualification':'fresh committed local checkout with retained nested command receipts; separate supported-toolchain gate still applies','status':'PASS' if passed else 'FAIL'}
        (out/'summary.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
        return 0 if passed else (outcome['exit_code'] or 1)
if __name__=='__main__':raise SystemExit(main())
