"""Rebuild a committed clone; retain its ancestor on incomplete preservation."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import sys
from common import ROOT,run,source_hash
import fixture_capsule

RETENTION_BYTES = 32 << 20
RETENTION_ENTRIES = 4096


def _retained_files(root, *, allow_unfinished=False):
    """Bounded no-link inventory used on both sides of an evidence copy."""
    root = fixture_capsule.checked_directory(root)
    rows, pending, total = {}, [(root,'',0)], 0
    while pending:
        folder, prefix, depth = pending.pop()
        if depth > 12:
            raise RuntimeError('RETENTION_DEPTH_BOUND')
        with os.scandir(folder) as iterator:
            for entry in iterator:
                relative = prefix+'/'+entry.name if prefix else entry.name
                if len(rows) >= RETENTION_ENTRIES:
                    raise RuntimeError('RETENTION_ENTRY_BOUND')
                info = Path(entry.path).lstat()
                if getattr(info,'st_file_attributes',0)&0x400 or stat.S_ISLNK(info.st_mode):
                    raise RuntimeError('RETENTION_LINK_OR_REPARSE')
                if stat.S_ISDIR(info.st_mode):
                    rows[relative] = ('directory',)
                    pending.append((Path(entry.path),relative,depth+1))
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    total += info.st_size
                    if total > RETENTION_BYTES:
                        raise RuntimeError('RETENTION_BYTE_BOUND')
                    path = Path(entry.path)
                    raw = fixture_capsule._read_file(path,info,RETENTION_BYTES)
                    if path.suffix == '.partial' and not allow_unfinished:
                        raise RuntimeError('UNFINISHED_CAPSULE_PARTIAL')
                    if path.suffix == '.fcap' and not allow_unfinished:
                        fixture_capsule.decode(raw)
                    rows[relative] = ('file',len(raw),hashlib.sha256(raw).hexdigest())
                else:
                    raise RuntimeError('RETENTION_UNSAFE_FILE')
    return rows


def _terminal_file(out, name, value):
    """Publish exact terminal bytes; never overwrite a previous terminal file."""
    if name not in ('stdout.txt','stderr.txt'):
        raise RuntimeError('TERMINAL_NAME')
    raw=value if isinstance(value,bytes) else value.encode('utf-8')
    path=out/name
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if fixture_capsule._read_file(path,path.lstat(),RETENTION_BYTES) != raw:
        raise RuntimeError('TERMINAL_PUBLICATION_READBACK')
    return ('file',len(raw),hashlib.sha256(raw).hexdigest())


def _sync_destination(out, *, synthetic_hook=None):
    """Flush files, descendants and the complete checked destination ancestry.

    allow_unfinished preserves observed partial/corrupt regular bytes on the
    failure branch; it makes no claim that such capsules are complete. Hooks
    raise synthetic boundary exceptions only, never simulated OS/power failures.
    """
    out=fixture_capsule.checked_directory(out)
    def event(name):
        if synthetic_hook is not None:synthetic_hook(name)
    before=_retained_files(out,allow_unfinished=True)
    for relative,row in sorted(before.items()):
        if row[0]=='file':
            path=out/relative
            access=os.O_RDWR if os.name=='nt' else os.O_RDONLY
            fd=os.open(path,access|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0))
            try:os.fsync(fd)
            finally:os.close(fd)
            event('destination_file_synced:'+relative)
    durable=os.name=='posix'
    if durable:
        descendants=[out/p for p,r in before.items() if r[0]=='directory']
        for directory in sorted(descendants,key=lambda p:len(p.parts),reverse=True):
            fixture_capsule.checked_directory(directory)
            fixture_capsule._sync_dir(directory)
            event('destination_directory_synced:'+str(directory))
        event('before_destination_ancestor_sync')
        for directory in (out,)+tuple(out.parents):
            # checked_directory(out) has checked every ancestor without links;
            # synchronize each directory entry, all the way to the root.
            fixture_capsule._sync_dir(directory)
            event('destination_directory_synced:'+str(directory))
    after=_retained_files(out,allow_unfinished=True)
    if after != before:
        raise RuntimeError('DESTINATION_CHANGED_DURING_PUBLICATION')
    event('destination_readback_verified')
    return after,durable


def _verify_copies(clone, out):
    for name in ('evidence','test-failures'):
        source=clone/'.local'/name
        if os.path.lexists(source):
            before=_retained_files(source)
            if before != _retained_files(out/name) or before != _retained_files(source):
                raise RuntimeError('COPIED_EVIDENCE_BYTES_OR_MEMBERSHIP')


def _unpreserved_cases(clone):
    # Successful POSIX capture removes only each exclusive case container;
    # discovery's empty run directories may remain. Windows raw containers are
    # retained and block clone disposal, with no directory-durability claim.
    for name in ('rms','fixture-capsule-tests'):
        base = clone/'.local'/name
        if not os.path.lexists(base):
            continue
        fixture_capsule.checked_directory(base)
        with os.scandir(base) as iterator:
            for entry in iterator:
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
                    return True
                with os.scandir(entry.path) as cases:
                    if next(cases,None) is not None:
                        return True
    return False


def checkout_commands(clone, out, command):
    """Copy and verify receipts/capsules even on outer timeout/start error.

    The caller MUST pass retention_errors to dispose_clone before deleting any
    clone/cache ancestor. A failed copy/decoder leaves the entire source owned.
    """
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
            source=clone/'.local'/name
            if os.path.lexists(source):
                try:
                    before=_retained_files(source)
                    shutil.copytree(source,out/name)
                    if before != _retained_files(out/name) or before != _retained_files(source):
                        raise RuntimeError('COPIED_EVIDENCE_BYTES_OR_MEMBERSHIP')
                except Exception as failure:
                    retention_errors.append(name+': '+type(failure).__name__+': '+str(failure))
        try:
            if _unpreserved_cases(clone):
                retention_errors.append('unpreserved raw fixture containers remain')
        except Exception as failure:
            retention_errors.append('raw fixture inspection: '+type(failure).__name__+': '+str(failure))
    terminal_files={}
    for name,value in (('stdout.txt',stdout),('stderr.txt',stderr)):
        try:
            terminal_files[name]=_terminal_file(out,name,value)
        except Exception as failure:
            retention_errors.append(name+': '+str(failure))
    try:
        published,_=_sync_destination(out)
        if any(published.get(name) != row for name,row in terminal_files.items()):
            raise RuntimeError('TERMINAL_CHANGED_AFTER_PUBLICATION')
        if not retention_errors:_verify_copies(clone,out)
    except Exception as failure:
        retention_errors.append('destination publication: '+type(failure).__name__+': '+str(failure))
    return {'exit_code':code,'termination_reason':termination,'error':error,
            'retention_errors':retention_errors,'terminal_files':terminal_files}


def dispose_clone(clone, out, temporary, retention_errors, *, terminal_files=None, synthetic_hook=None):
    """Move the exclusive clone on failure; otherwise remove only checked paths.

    A failed move/check retains the original cache ancestor. There is no
    TemporaryDirectory finalizer and no deletion on the failure branch. A
    retained failure clone can contain .git/caches/unsafe fixture aliases;
    unchanged whole-local remote capture can correctly REFUSE that tree.
    """
    clone, out, temporary = Path(clone), Path(out), Path(temporary)
    try:
        fixture_capsule.checked_directory(temporary)
        fixture_capsule.checked_directory(out)
        if clone.parent != temporary or clone.name != 'source' or temporary.resolve() != temporary.absolute():
            raise RuntimeError('CLONE_OWNED_CONTAINMENT')
        if out == temporary or temporary in out.parents or out in temporary.parents:
            raise RuntimeError('RETENTION_DESTINATION_CONTAINMENT')
        if not os.path.lexists(clone):
            retention_errors.append('clone missing; exclusive temporary ancestor retained: '+str(temporary))
            return
        fixture_capsule.checked_directory(clone)
        if not retention_errors and _unpreserved_cases(clone):
            retention_errors.append('raw fixtures appeared before clone cleanup')
        if not retention_errors:
            try:
                _verify_copies(clone,out)
            except Exception as failure:
                retention_errors.append('final preservation check: '+str(failure))
        # BOTH deletion and failure rename remove the original source pathname.
        # First flush all available regular output bytes, including terminals,
        # and persist every newly created destination ancestor entry. Windows
        # cannot meet this directory-fsync contract and keeps the original.
        published,durable=_sync_destination(out,synthetic_hook=synthetic_hook)
        if terminal_files is not None and any(published.get(name) != tuple(row)
                                              for name,row in terminal_files.items()):
            raise RuntimeError('TERMINAL_CHANGED_BEFORE_SOURCE_REMOVAL')
        if not durable:
            raise RuntimeError('DESTINATION_DIRECTORY_DURABILITY_UNSUPPORTED_RETAIN_ORIGINAL')
        if retention_errors:
            destination=out/'retained-failed-source'
            if os.path.lexists(destination) or destination.parent.resolve() != out.resolve():
                raise RuntimeError('RETAINED_SOURCE_NO_OVERWRITE_OR_CONTAINMENT')
            if synthetic_hook is not None:synthetic_hook('before_clone_rename')
            clone.rename(destination)
            if os.name == 'posix':
                fixture_capsule._sync_dir(out)
                fixture_capsule._sync_dir(temporary)
            return
        # Read both source and destination again after ALL terminal/file/ancestor
        # publication. No source removal is reachable on a failed readback.
        _verify_copies(clone,out)
        if synthetic_hook is not None:synthetic_hook('source_copy_readback_verified')
        if clone.resolve().parent != temporary.resolve():
            raise RuntimeError('CLONE_DELETE_CONTAINMENT')
        if synthetic_hook is not None:synthetic_hook('before_clone_delete')
        shutil.rmtree(clone)
        temporary.rmdir()  # Unexpected siblings retain the ancestor and fail.
    except Exception as failure:
        retention_errors.append('clone retention/cleanup: '+type(failure).__name__+': '+str(failure)
                                +'; original ancestor retained if present: '+str(temporary))


def main():
    dirty=run(['git','status','--porcelain'],check=False)
    if dirty.returncode!=0:print('BLOCKED: commit the audited public source first');return 2
    if dirty.stdout.strip():print('BLOCKED: clean reproduction requires a committed clean source tree');return 2
    out=ROOT/'.local/clean-verify'/str(time.time_ns());out.mkdir(parents=True)
    identity=source_hash()
    temporary=Path(tempfile.mkdtemp(prefix='clean-verify-',dir=ROOT/'.cache/tmp'))
    clone=temporary/'source'
    command=['make','build','fmt','lint','check','test','integration','demo','clean']
    outcome={'exit_code':None,'termination_reason':'driver_incomplete','error':None,'retention_errors':[]}
    unchanged=False;version='';commit=''
    try:
        run(['git','clone','--no-hardlinks','--local',str(ROOT),str(clone)])
        if source_hash(clone) != source_hash():
            raise RuntimeError('clean clone technical bytes differ from committed source')
        outcome=checkout_commands(clone,out,command)
        if outcome['termination_reason'] is not None:
            outcome['retention_errors'].append('uncertain subprocess closure; retain original clone')
        unchanged=source_hash(clone)==identity and source_hash()==identity
        version=run(['go','version']).stdout.strip()
        commit=run(['git','rev-parse','HEAD']).stdout.strip()
    except BaseException as failure:
        outcome['error']=type(failure).__name__+': '+str(failure)
        outcome['retention_errors'].append('driver failed before verified cleanup: '+outcome['error'])
    finally:
        dispose_clone(clone,out,temporary,outcome['retention_errors'],terminal_files=outcome.get('terminal_files'))
    passed=outcome['exit_code']==0 and outcome['termination_reason'] is None and not outcome['retention_errors'] and unchanged
    record={'schema_version':1,'evidence_type':'fresh_checkout','clean_checkout':True,'supported_toolchain':version.startswith('go version go1.27.3 '),'source':identity,'commit':commit,'command':command,**outcome,'go':version,'source_unchanged':unchanged,'retained_evidence':str(out.relative_to(ROOT)),'qualification':'fresh committed local checkout with retained nested command receipts; separate supported-toolchain gate still applies','status':'PASS' if passed else 'FAIL'}
    (out/'summary.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
    return 0 if passed else (outcome['exit_code'] or 1)


if __name__=='__main__':raise SystemExit(main())
