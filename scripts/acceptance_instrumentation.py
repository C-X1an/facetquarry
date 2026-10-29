"""Actual finite Go race sensitivity; every child uses owned bounded capture.

Expected negative tests must fail with the matching diagnostic while retaining
complete output and positive descendant quiescence. No all-path isolation claim.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time
import uuid

from common import ROOT, environment, source_hash
from reference_filesystem import whole_entry
from reference_transport_supervisor import run_owned
from reference_preflight import checked

SELECTOR='FACETQUARRY_HARNESS_CONTROL'
TEST='^TestAcceptanceScopeForeignReadSentinel$'
OUTPUT_LIMIT=1_000_000
STAGE_SECONDS=80
CHECKS=(('normal-before','normal',True),('intentional-foreign-read','race-read-discard',True),
        ('normal-restored','normal',True),('unknown-selector','unknown-control-must-fail',False))


def require(value,message):
    if not value:raise ValueError(message)


def save(path,value):
    owned_directory(path.parent)
    raw=(json.dumps(value,sort_keys=True,allow_nan=False)+'\n').encode()
    require(len(raw)<=1_000_000,'instrumentation receipt bound exceeded')
    with path.open('xb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def owned_directory(path):
    require(path.is_absolute() and '..' not in path.parts and path.is_relative_to(ROOT),
            'instrumentation directory escapes source root')
    info=checked(path)
    require(stat.S_ISDIR(info.st_mode),'instrumentation parent is not a directory')
    if sys.platform=='linux':require(info.st_uid==os.getuid(),'instrumentation parent is not owned')


def source_paths():
    """Reject unhashed linked package trees before the Go driver sees them."""
    for name in ('go.mod','.go-version'):
        require(stat.S_ISREG(checked(ROOT/name).st_mode),'required Go source metadata missing')
    stack=[ROOT/'internal',ROOT/'cmd'];seen=0
    while stack:
        path=stack.pop();info=checked(path);seen+=1
        require(seen<=10_000,'Go source entry bound exceeded')
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    require(seen+len(stack)<10_000,'Go source pending entry bound exceeded')
                    stack.append(path/entry.name)
        else:require(stat.S_ISREG(info.st_mode),'unexpected Go source path')


def error_text(failure):
    return type(failure).__name__+': '+str(failure)[:1000]


def file_digest(path,limit):
    before=checked(path)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=limit,
            'instrumentation file type/size differs')
    with path.open('rb') as stream:raw=stream.read(limit+1)
    after=path.lstat()
    require(len(raw)==before.st_size<=limit and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)
            ==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'instrumentation file changed')
    return raw,hashlib.sha256(raw).hexdigest()


def runtime():
    require(sys.platform=='linux' and os.getuid()>0,'dedicated ordinary Linux runner required')
    require(not os.environ.get('GOFLAGS','').strip(),'uncontrolled GOFLAGS/overlay is active')
    require(os.environ.get(SELECTOR) in (None,'','normal'),'unrelated instrumentation selector is active')
    require(os.environ.get('CGO_ENABLED','1')!='0','actual race sensitivity requires CGO')
    path=shutil.which('go');require(path is not None,'supported Go executable unavailable')
    go=Path(path).resolve(strict=True)
    _,sha=file_digest(go,50_000_000)
    env=environment()
    env.update(GOFLAGS='',GOENV='off',GOWORK='off',GOEXPERIMENT='',GOTOOLCHAIN='local',
               GOOS='linux',GOARCH='amd64',CGO_ENABLED='1',GO111MODULE='on',GOROOT=str(go.parent.parent))
    version='go'+(ROOT/'.go-version').read_text().strip().removeprefix('go')
    return go,sha,env,version


def expected_outcome(name,code,output,version):
    if type(code) is not int:return False
    if name=='toolchain':return code==0 and output==('go version '+version+' linux/amd64\n').encode()
    if name=='intentional-foreign-read':
        return code==1 and b'DATA RACE' in output and b'harnessReadAndDiscard' in output
    if name=='unknown-selector':return code==1 and b'unknown FACETQUARRY_HARNESS_CONTROL' in output
    return name in ('normal-before','normal-restored') and code==0 and b'DATA RACE' not in output


def execute(directory,name,selector,*,race,identity,go,env,version):
    started=time.monotonic()
    # The outer guard includes pending and terminal receipt writes/fsync, not
    # only the command. Its caller also retains the whole CLI command receipt.
    with whole_entry(STAGE_SECONDS,started=started):
        return _execute(directory,name,selector,race=race,identity=identity,
                        go=go,env=env,version=version,started=started)


def _execute(directory,name,selector,*,race,identity,go,env,version,started):
    command=[str(go),'version'] if name=='toolchain' else [str(go),'test','-count=1','-timeout=45s']
    if name!='toolchain':
        if race:command.append('-race')
        command+=['-run',TEST,'./internal/engine']
    actual=['timeout','--signal=TERM','--kill-after=2s','55s',*command]
    stdout,stderr=(directory/(name+'-'+label+'.txt') for label in ('stdout','stderr'))
    record={'name':name,'command':command,'actual_command':actual,'selector':selector,'status':'FAIL',
            'source_before':None,'source_after':None,'expected_outcome_observed':False}
    save(directory/(name+'.pending.json'),{**record,'descendant_quiescence':{'quiescent':False,'residual':None}})
    try:
        source_paths()
        record['source_before']=source_hash()
        require(record['source_before']==identity,'source changed before instrumentation command')
        require(Path.cwd()==ROOT,'owned instrumentation parent has wrong cwd')
        with whole_entry(STAGE_SECONDS,started=started):
            owned=run_owned(actual,stdout,stderr,started=started,total_seconds=STAGE_SECONDS,
                            cleanup_seconds=12,receipt_seconds=8,capture_bytes=OUTPUT_LIMIT,
                            environ={**env,SELECTOR:selector})
            record['owned']=owned
            save(directory/(name+'.owned.json'),owned)
            output=[]
            for label,path in (('stdout',stdout),('stderr',stderr)):
                raw,sha=file_digest(path,OUTPUT_LIMIT)
                require(owned.get('capture',{}).get(label)=={'path':str(path),'bytes':len(raw),'sha256':sha},
                        'owned instrumentation capture changed')
                output.append(raw)
            code=owned.get('worker_exit_code')
            quiet=owned.get('descendant_quiescence',{})
            complete=(owned.get('worker_started') is True and type(code) is int
                      and owned.get('termination_reason') is None and owned.get('errors')==[]
                      and owned.get('capture_complete') is True and owned.get('discarded_output_bytes')==0
                      and quiet.get('quiescent') is True and quiet.get('residual')==[]
                      and sum(map(len,output))==owned.get('captured_output_bytes')<=OUTPUT_LIMIT)
            record['exit_code']=code
            record['expected_outcome_observed']=bool(complete and expected_outcome(name,code,b''.join(output),version))
            record['source_after']=source_hash()
            require(record['source_after']==identity,'source changed during instrumentation command')
            require(time.monotonic()-started<STAGE_SECONDS,'instrumentation stage deadline exceeded')
            if record['expected_outcome_observed']:record['status']='PASS'
    except BaseException as failure:
        record.update(status='FAIL',error=error_text(failure))
    record['duration_seconds']=time.monotonic()-started
    save(directory/(name+'.json'),record)
    return record


def main():
    started=time.monotonic()
    # Remains live through final hashes, receipt fsync and best-effort console
    # reporting. A timed-out/incomplete entry requires a failing outer receipt.
    with whole_entry(410,started=started):
        result=_main()
        require(time.monotonic()-started<408,'complete instrumentation entry exceeded budget')
        return result


def _main():
    directory=ROOT/'.local/acceptance-instrumentation'/('attempt-'+str(time.time_ns())+'-'+uuid.uuid4().hex)
    owned_directory(ROOT)
    for path in (ROOT/'.local',ROOT/'.local/acceptance-instrumentation'):
        if not os.path.lexists(path):path.mkdir(mode=0o700)
        owned_directory(path)
    require(not os.path.lexists(directory),'instrumentation attempt already exists')
    directory.mkdir(mode=0o700);owned_directory(directory)
    original=after=None;go=go_sha=final_go_sha=None;results=[];failure=None
    try:
        with whole_entry(410):
            require(Path.cwd()==ROOT,'dedicated instrumentation entry must start in source root')
            source_paths()
            original=source_hash()
            go,go_sha,env,version=runtime()
            for name,selector,race in (('toolchain','normal',False),*CHECKS):
                result=execute(directory,name,selector,race=race,identity=original,go=go,env=env,version=version)
                results.append(result)
                require(result['status']=='PASS','instrumentation control failed: '+name)
    except BaseException as error:
        failure=error_text(error)
    try:
        after=source_hash()
        if go is not None:_,final_go_sha=file_digest(go,50_000_000)
    except BaseException as error:
        failure=failure or error_text(error)
    passed=(failure is None and len(results)==len(CHECKS)+1 and after==original and original is not None
            and go_sha==final_go_sha and go_sha is not None and all(r['status']=='PASS'
                and r['source_before']==r['source_after']==original for r in results))
    summary={'source_before':original,'source_after':after,'checks':results,'failure':failure,
             'go_executable':str(go) if go is not None else None,'go_sha256':go_sha,'go_final_sha256':final_go_sha,
             'status':'PASS' if passed else 'FAIL',
             'scope':'Actual finite Go race/control commands only; bounded complete capture and owned descendants. Executed read sentinel, not all-path isolation or benchmark qualification.'}
    try:save(directory/'summary.json',summary)
    except BaseException as error:
        passed=False
        summary.update(status='FAIL',failure=summary['failure'] or error_text(error))
        try:save(directory/'summary-retention-failure.json',summary)
        except BaseException:pass
        try:print('instrumentation summary retention failed: '+error_text(error),file=sys.stderr)
        except BaseException:pass
    try:print(json.dumps(summary))
    except BaseException:pass
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
