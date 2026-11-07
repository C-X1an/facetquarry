"""Standalone experimental original-byte transaction primitive.

Trusted caller bytes, never gzip parsing/regeneration or scientific semantics.
POSIX directory-fsync contract only; Windows durability is explicitly refused.
No archive/cloud, existing-profile integration, quota or privileged-writer
authenticity claim. All mutation failures retain existing/partial evidence.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import stat
import threading

MAX_MEMBERS = 16
MAX_MEMBER = 1 << 20
MAX_TOTAL = 4 << 20
MAX_METADATA = 65536
MAX_CONTROL = 2048
MAX_FAILURE_TAIL = 4096
XZ_OVERHEAD = 65536
XZ_MEMORY = 64 << 20
CHUNK = 65536
MAX_ENTRIES = 128
MAX_TRANSACTIONS = 32
MAX_ALLOWANCE = 32 << 20
PROTOCOL = 'caller-raw-originals-v1'
DEVICE = {'con','prn','aux','nul'} | {prefix+str(i) for prefix in ('com','lpt') for i in range(10)}
HOOKS = {'after_stage_write','after_stage_fsync','after_pack_write','after_pack_fsync',
         'after_manifest','after_commit_write','after_commit_fsync','after_close',
         'before_retire','after_retire_member'}


class Refusal(ValueError):
    """Fixed safe code, never raw member data."""


@dataclass(frozen=True, slots=True)
class Member:
    name: str
    size: int
    sha256: str
    encoding: str = 'identity'


@dataclass(frozen=True, slots=True)
class Plan:
    allowance: int
    allocation_unit: int = 4096
    failure_tail: int = MAX_FAILURE_TAIL


class InventoryRefusal(Refusal):
    def __init__(self,code,observed):
        super().__init__(code)
        self.observed = tuple(observed)


def _typed_equal(actual,expected):
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return set(actual) == set(expected) and all(_typed_equal(actual[key],value) for key,value in expected.items())
    if type(expected) is list:
        return len(actual) == len(expected) and all(_typed_equal(a,b) for a,b in zip(actual,expected))
    return actual == expected

def need(value, code):
    if not value:
        raise Refusal(code)


def integer(value, minimum, maximum, code):
    need(type(value) is int and minimum <= value <= maximum,code)


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None,'SHA_TYPE_OR_VALUE')


def member_name(value):
    need(type(value) is str and re.fullmatch('[a-z0-9][a-z0-9._-]{0,63}',value) is not None
         and not value.endswith('.') and value.split('.')[0] not in DEVICE,'MEMBER_NAME_OR_ALIAS')
    return value


def _canonical(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def _unique(pairs):
    result = {}
    for key,value in pairs:
        need(key not in result,'JSON_DUPLICATE_KEY')
        result[key] = value
    return result


def _decode(raw):
    need(type(raw) is bytes and len(raw) <= MAX_METADATA,'JSON_BOUND')
    try:
        result = json.loads(raw,object_pairs_hook=_unique,
                            parse_constant=lambda value:(_ for _ in ()).throw(Refusal('JSON_NONFINITE')))
    except (ValueError,UnicodeError,RecursionError) as error:
        raise Refusal('JSON_FORMAT') from error
    need(_canonical(result) == raw,'JSON_CANONICAL')
    return result


def _platform():
    need(os.name == 'posix' and hasattr(os,'O_NOFOLLOW') and hasattr(os,'O_DIRECTORY'),
         'DURABILITY_UNSUPPORTED_WINDOWS_OR_NONPOSIX')


def _directory(info):
    need(stat.S_ISDIR(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,
         'DIRECTORY_TYPE_OR_REPARSE')
    need(info.st_uid == os.getuid() and not info.st_mode&0o022,'DIRECTORY_OWNERSHIP_OR_WRITE_ALIAS')


def _regular(info):
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
         and not getattr(info,'st_file_attributes',0)&0x400,'FILE_TYPE_LINK_OR_OWNER')


def _open_root(root):
    _platform()
    path = Path(root)
    need(path.is_absolute() and '..' not in path.parts and path != Path(path.anchor),'EXPLICIT_ROOT_REQUIRED')
    fd = os.open(path.anchor,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd)
            fd = child
        _directory(os.fstat(fd))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_dir(parent,name):
    before = os.stat(name,dir_fd=parent,follow_symlinks=False)
    _directory(before)
    fd = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
    try:
        opened = os.fstat(fd)
        _directory(opened)
        need((before.st_dev,before.st_ino) == (opened.st_dev,opened.st_ino),'DIRECTORY_CHANGED')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _root_writer_lock(fd):
    """Serialize API writers through the root descriptor for the handle lifetime."""
    import fcntl
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise Refusal('ROOT_WRITER_ACTIVE') from error
    except OSError as error:
        raise Refusal('ROOT_WRITER_LOCK_UNSUPPORTED') from error


def _root_slots(fd,creating=False):
    """Count every root entry before append; unknown evidence consumes a slot."""
    names = []
    with os.scandir(fd) as iterator:
        for entry in iterator:
            need(len(names) < MAX_TRANSACTIONS,'ROOT_SLOT_CAPACITY')
            names.append(entry.name)
    need(not creating or len(names) < MAX_TRANSACTIONS,'ROOT_SLOT_CAPACITY')
    return names


def _open_file(parent,name):
    before = os.stat(name,dir_fd=parent,follow_symlinks=False)
    _regular(before)
    fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
    opened = os.fstat(fd)
    try:
        _regular(opened)
        need((before.st_dev,before.st_ino,before.st_size) ==
             (opened.st_dev,opened.st_ino,opened.st_size),'FILE_OPEN_CHANGED')
        return fd,opened
    except BaseException:
        os.close(fd)
        raise


def _same_file(fd,before):
    after = os.fstat(fd)
    _regular(after)
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) ==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'FILE_CHANGED_DURING_READ')


def _read(parent,name,maximum):
    fd,info = _open_file(parent,name)
    try:
        need(info.st_size <= maximum,'FILE_READ_BOUND')
        parts,total = [],0
        while True:
            raw = os.read(fd,min(CHUNK,maximum-total+1))
            if not raw:
                break
            total += len(raw)
            need(total <= maximum,'FILE_READ_BOUND')
            parts.append(raw)
        _same_file(fd,info)
        return b''.join(parts)
    finally:
        os.close(fd)


def _file_hash(parent,name,maximum):
    fd,info = _open_file(parent,name)
    try:
        need(info.st_size <= maximum,'FILE_HASH_BOUND')
        total,hashing = 0,hashlib.sha256()
        while raw := os.read(fd,CHUNK):
            total += len(raw)
            need(total <= maximum,'FILE_HASH_BOUND')
            hashing.update(raw)
        _same_file(fd,info)
        return total,hashing.hexdigest()
    finally:
        os.close(fd)


def _members(values):
    need(type(values) is tuple and 1 <= len(values) <= MAX_MEMBERS,'MEMBERS_EXACT_TUPLE_OR_COUNT')
    seen,total = set(),0
    for value in values:
        need(type(value) is Member,'MEMBER_EXACT_TYPE')
        member_name(value.name)
        integer(value.size,0,MAX_MEMBER,'MEMBER_SIZE')
        digest(value.sha256)
        need(type(value.encoding) is str and value.encoding in ('identity','xz'),'MEMBER_ENCODING')
        need(value.name not in seen,'MEMBER_DUPLICATE_OR_ALIAS')
        seen.add(value.name)
        total += value.size
    need(total <= MAX_TOTAL,'MEMBER_TOTAL_BOUND')
    return tuple(sorted(values,key=lambda value:value.name))


def _round(value,unit):
    return ((value+unit-1)//unit)*unit


def reservation(members,plan):
    values = _members(members)
    need(type(plan) is Plan,'PLAN_EXACT_TYPE')
    integer(plan.allowance,0,MAX_ALLOWANCE,'PLAN_ALLOWANCE')
    integer(plan.allocation_unit,4096,65536,'PLAN_ALLOCATION_UNIT')
    need(plan.allocation_unit & (plan.allocation_unit-1) == 0,'PLAN_ALLOCATION_POWER')
    integer(plan.failure_tail,0,MAX_FAILURE_TAIL,'PLAN_FAILURE_TAIL')
    unit = plan.allocation_unit
    stages = sum(_round(value.size,unit) for value in values)
    packed = sum(_round(value.size+(XZ_OVERHEAD if value.encoding == 'xz' else 0),unit) for value in values)
    metadata = 4*_round(MAX_METADATA,unit)
    tail = _round(plan.failure_tail,unit)
    allocation_headroom = (2*len(values)+16)*unit
    required = stages+packed+metadata+tail+allocation_headroom
    need(plan.allowance >= required,'PREADMISSION_REFUSED')
    return {'staging':stages,'packed_candidates':packed,'metadata_and_finalization':metadata,
            'failure_tail':tail,'allocation_headroom':allocation_headroom,'required':required,
            'allowance':plan.allowance,'allocation_unit':unit,
            'scope':'Finite caller reservation, not global admission or a hard filesystem quota.'}


def _declaration(source,transaction,members,plan):
    digest(source)
    need(type(transaction) is str and re.fullmatch('[0-9a-f]{32}',transaction) is not None,'TRANSACTION_ID')
    values = _members(members)
    bound = reservation(values,plan)
    result = {'version':1,'protocol':PROTOCOL,'source':source,'transaction':transaction,
              'members':[{'name':m.name,'size':m.size,'sha256':m.sha256,'encoding':m.encoding} for m in values],
              'plan':{'allowance':plan.allowance,'allocation_unit':plan.allocation_unit,
                      'failure_tail':plan.failure_tail},'reservation':bound}
    need(len(_canonical(result)) <= MAX_METADATA,'DECLARATION_METADATA_BOUND')
    return result,values,bound


def _load_declaration(raw):
    value = _decode(raw)
    need(type(value) is dict and set(value) == {'version','protocol','source','transaction','members','plan','reservation'}
         and type(value['version']) is int and value['version'] == 1
         and type(value['members']) is list and type(value['plan']) is dict
         and set(value['plan']) == {'allowance','allocation_unit','failure_tail'},'DECLARATION_SCHEMA')
    members = []
    for item in value['members']:
        need(type(item) is dict and set(item) == {'name','size','sha256','encoding'},'DECLARED_MEMBER_SCHEMA')
        members.append(Member(**item))
    expected,ordered,bound = _declaration(value['source'],value['transaction'],tuple(members),Plan(**value['plan']))
    need(_typed_equal(value,expected),'DECLARATION_BINDING')
    return value,ordered,bound


def _scan(fd,limit=MAX_ENTRIES):
    """Never follow unsafe entries; retain observed rows on an explicit refusal."""
    rows = []
    unsafe = []
    def walk(folder,prefix,depth):
        need(depth <= 3,'INVENTORY_DEPTH_BOUND')
        with os.scandir(folder) as iterator:
            for entry in iterator:
                need(len(rows) < limit,'INVENTORY_COUNT_BOUND')
                info = entry.stat(follow_symlinks=False)
                path = prefix+entry.name
                row = {'path':path,'bytes':info.st_size,'blocks_bytes':getattr(info,'st_blocks',0)*512,
                       'kind':'unknown','safe':False}
                rows.append(row)
                try:
                    if stat.S_ISDIR(info.st_mode):
                        row['kind'] = 'directory'
                        child = _open_dir(folder,entry.name)
                        row['safe'] = True
                        try:
                            walk(child,path+'/',depth+1)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode):
                        row['kind'] = 'file'
                        _regular(info)
                        size,sha = _file_hash(folder,entry.name,MAX_MEMBER+XZ_OVERHEAD)
                        row.update(safe=True,bytes=size,sha256=sha)
                    else:
                        raise Refusal('INVENTORY_LINK_OR_SPECIAL')
                except (OSError,Refusal) as error:
                    row.update(safe=False,error_type=type(error).__name__,
                               subtree_unexamined=stat.S_ISDIR(info.st_mode))
                    unsafe.append(path)
    try:
        walk(fd,'',0)
        need(not unsafe,'INVENTORY_UNSAFE_OR_UNEXAMINED')
    except (OSError,Refusal) as error:
        raise InventoryRefusal('INVENTORY_INCOMPLETE_OR_UNSAFE',sorted(rows,key=lambda row:row['path'])) from error
    return sorted(rows,key=lambda row:row['path'])

def _accounting(rows):
    files = [row for row in rows if row['kind'] == 'file']
    payload = sum(row['bytes'] for row in files if row['path'].startswith(('stage/','packed/')))
    total = sum(row['bytes'] for row in files)
    return {'all_file_bytes':total,'payload_file_bytes':payload,
            'every_metadata_and_control_byte':total-payload,
            'observed_blocks_bytes':sum(row['blocks_bytes'] for row in rows),
            'file_count':len(files),'every_observed_file_included':True,
            'hard_quota_or_global_admission':False}


def _verify_payload(fd,member,packed):
    need(type(packed) is dict and set(packed) == {'name','encoding','bytes','sha256'},'PACKED_ENTRY_SCHEMA')
    need(packed['name'] == member.name and packed['encoding'] == member.encoding,'PACKED_ENTRY_BINDING')
    integer(packed['bytes'],0,member.size+(XZ_OVERHEAD if member.encoding == 'xz' else 0),'PACKED_SIZE')
    digest(packed['sha256'])
    need(_file_hash(fd,member.name,MAX_MEMBER+XZ_OVERHEAD) == (packed['bytes'],packed['sha256']),
         'PACKED_BYTES_OR_SHA')
    source,before = _open_file(fd,member.name)
    output,total = hashlib.sha256(),0
    try:
        if member.encoding == 'identity':
            while raw := os.read(source,CHUNK):
                total += len(raw)
                need(total <= member.size,'IDENTITY_OUTPUT_BOUND')
                output.update(raw)
        else:
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=XZ_MEMORY)
            while raw := os.read(source,CHUNK):
                need(not decoder.eof,'XZ_TRAILING')
                chunk = raw
                while True:
                    decoded = decoder.decompress(chunk,max_length=min(CHUNK,member.size-total+1))
                    chunk = b''
                    total += len(decoded)
                    need(total <= member.size,'XZ_OUTPUT_BOUND')
                    output.update(decoded)
                    if decoder.eof:
                        need(not decoder.unused_data,'XZ_TRAILING_OR_CONCATENATED')
                        break
                    if decoder.needs_input:
                        break
                    need(decoded,'XZ_NO_PROGRESS')
            need(decoder.eof,'XZ_TRUNCATED')
        _same_file(source,before)
        need(total == member.size and output.hexdigest() == member.sha256,'ORIGINAL_BYTES_OR_SHA')
    except lzma.LZMAError as error:
        raise Refusal('XZ_DECODE_OR_MEMORY') from error
    finally:
        os.close(source)


def _verify_commit(fd,declared,members):
    writer = _decode(_read(fd,'.writer',MAX_CONTROL))
    need(_typed_equal(writer,{'version':1,'source':declared['source'],'transaction':declared['transaction']}),
         'WRITER_IDENTITY_BINDING')
    manifest_raw = _read(fd,'manifest.json',MAX_METADATA)
    manifest = _decode(manifest_raw)
    need(type(manifest) is dict and set(manifest) == {'version','protocol','source','transaction','members','packed'}
         and type(manifest['version']) is int and manifest['version'] == 1 and manifest['protocol'] == PROTOCOL
         and manifest['source'] == declared['source'] and manifest['transaction'] == declared['transaction']
         and _typed_equal(manifest['members'],declared['members'])
         and type(manifest['packed']) is list and len(manifest['packed']) == len(members),'MANIFEST_BINDING')
    packed_fd = _open_dir(fd,'packed')
    try:
        with os.scandir(packed_fd) as iterator:
            names = [entry.name for entry in iterator]
        need(set(names) == {member.name for member in members} and len(names) == len(members),'PACKED_MEMBERSHIP')
        for member,item in zip(members,manifest['packed']):
            _verify_payload(packed_fd,member,item)
    finally:
        os.close(packed_fd)
    commit_raw = _read(fd,'commit.json',MAX_CONTROL)
    commit = _decode(commit_raw)
    expected = {'version':1,'protocol':PROTOCOL,'source':declared['source'],'transaction':declared['transaction'],
                'manifest_bytes':len(manifest_raw),'manifest_sha256':hashlib.sha256(manifest_raw).hexdigest()}
    need(_typed_equal(commit,expected) and type(commit.get('version')) is int
         and type(commit.get('manifest_bytes')) is int,'COMMIT_BINDING')
    return commit,hashlib.sha256(commit_raw).hexdigest()


class Transaction:
    def __init__(self,root_fd,fd,stage_fd,packed_fd,declared,members,bound,hook,root):
        self.root_fd,self.fd,self.stage_fd,self.packed_fd = root_fd,fd,stage_fd,packed_fd
        self.declared,self.members,self.bound = declared,members,bound
        self._declared_raw = _canonical(declared)
        self._directory_links = ((root_fd,'txn-'+declared['transaction'],fd),
                                 (fd,'stage',stage_fd),(fd,'packed',packed_fd))
        self._hook = hook
        self._lock = threading.Lock()
        self._failed = self._committed = self._closed = self._retired = False
        self._released = False
        self._writer = None
        self._commit_sha = None
        self._root_path = Path(root)

    def _root_binding(self):
        """Reopen the explicit path without following links; compare root inode."""
        current = _open_root(self._root_path)
        try:
            original,observed = os.fstat(self.root_fd),os.fstat(current)
            need((original.st_dev,original.st_ino) == (observed.st_dev,observed.st_ino),
                 'ROOT_PATH_BINDING_CHANGED')
        finally:
            os.close(current)

    def _event(self,name):
        need(name in HOOKS,'UNKNOWN_CRASH_HOOK')
        if self._hook is not None:
            self._hook(name)

    @contextmanager
    def _operation(self,allow_failed=False):
        need(self._lock.acquire(blocking=False),'CONCURRENT_WRITER_REFUSED')
        try:
            need(not self._released,'HANDLE_RELEASED')
            need(allow_failed or not self._failed,'TRANSACTION_FAILED_RETAIN_ALL')
            self._root_binding()
            need(_canonical(self.declared) == self._declared_raw
                 and _read(self.fd,'transaction.json',MAX_METADATA) == self._declared_raw,
                 'IMMUTABLE_TRANSACTION_IDENTITY_CHANGED')
            for parent,name,child in self._directory_links:
                observed = os.stat(name,dir_fd=parent,follow_symlinks=False)
                opened = os.fstat(child)
                _directory(observed)
                _directory(opened)
                need((observed.st_dev,observed.st_ino) == (opened.st_dev,opened.st_ino),
                     'OWNED_DIRECTORY_BINDING_CHANGED')
            yield
        except BaseException:
            self._failed = True
            raise
        finally:
            self._lock.release()

    def _budget(self,pending):
        integer(pending,0,MAX_MEMBER+XZ_OVERHEAD,'WRITE_PENDING_BOUND')
        rows = _scan(self.fd)
        accounting = _accounting(rows)
        unit = self.bound['allocation_unit']
        conservative = max(accounting['all_file_bytes'],accounting['observed_blocks_bytes'])
        need(conservative+_round(pending,unit)+unit <= self.bound['allowance'],'LIVE_WRITE_RESERVATION_REFUSED')

    def _write(self,parent,name,chunks,maximum,event=None):
        need(type(name) is str and '/' not in name and '\\' not in name and name not in ('.','..'),'INTERNAL_FILE_NAME')
        self._budget(0)
        fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        total = 0
        iterator = iter(chunks)
        try:
            for raw in iterator:
                need(type(raw) is bytes and total+len(raw) <= maximum,'PREWRITE_OUTPUT_CAP')
                self._budget(len(raw))
                position = 0
                while position < len(raw):
                    written = os.write(fd,raw[position:])
                    need(written > 0,'WRITE_NO_PROGRESS')
                    position += written
                total += len(raw)
                if event:
                    self._event(event+'_write')
            os.fsync(fd)
            if event:
                self._event(event+'_fsync')
            _regular(os.fstat(fd))
        finally:
            os.close(fd)
            closer = getattr(iterator,'close',None)
            if closer is not None:
                closer()
        os.fsync(parent)
        return total

    def _save(self,name,value,maximum=MAX_CONTROL):
        raw = _canonical(value)
        need(len(raw) <= maximum,'CONTROL_METADATA_CAP')
        self._write(self.fd,name,(raw,),maximum)

    def stage(self,name,raw):
        with self._operation():
            need(not self._closed and not self._committed,'STAGE_AFTER_TERMINAL')
            member_name(name)
            matched = [member for member in self.members if member.name == name]
            need(len(matched) == 1,'UNDECLARED_MEMBER')
            member = matched[0]
            need(type(raw) is bytes and len(raw) == member.size
                 and hashlib.sha256(raw).hexdigest() == member.sha256,'STAGE_ORIGINAL_BINDING')
            chunks = (raw[offset:offset+CHUNK] for offset in range(0,len(raw),CHUNK))
            self._write(self.stage_fd,name,chunks,member.size,'after_stage')
            need(_file_hash(self.stage_fd,name,MAX_MEMBER) == (member.size,member.sha256),'STAGE_POSTWRITE_VERIFY')

    def failure_tail(self,raw):
        with self._operation(allow_failed=True):
            need(not self._closed and type(raw) is bytes
                 and len(raw) <= self.declared['plan']['failure_tail'],'FAILURE_TAIL_CAP_OR_CLOSED')
            self._write(self.fd,'failure-tail.bin',(raw,),self.declared['plan']['failure_tail'])

    def _candidate(self,member):
        source,info = _open_file(self.stage_fd,member.name)
        try:
            compressor = lzma.LZMACompressor(format=lzma.FORMAT_XZ,preset=6) if member.encoding == 'xz' else None
            while raw := os.read(source,CHUNK):
                yield compressor.compress(raw) if compressor is not None else raw
            _same_file(source,info)
            if compressor is not None:
                yield compressor.flush()
        finally:
            os.close(source)

    def finalize(self):
        with self._operation():
            need(not self._closed and not self._committed,'FINALIZE_AFTER_TERMINAL')
            need({row['path'] for row in _scan(self.stage_fd)} == {member.name for member in self.members},
                 'STAGING_EXACT_MEMBERSHIP')
            packed = []
            for member in self.members:
                need(_file_hash(self.stage_fd,member.name,MAX_MEMBER) == (member.size,member.sha256),'STAGING_ORIGINAL_VERIFY')
                maximum = member.size+(XZ_OVERHEAD if member.encoding == 'xz' else 0)
                self._write(self.packed_fd,member.name,self._candidate(member),maximum,'after_pack')
                size,sha = _file_hash(self.packed_fd,member.name,MAX_MEMBER+XZ_OVERHEAD)
                item = {'name':member.name,'encoding':member.encoding,'bytes':size,'sha256':sha}
                _verify_payload(self.packed_fd,member,item)
                packed.append(item)
            os.fsync(self.stage_fd)
            os.fsync(self.packed_fd)
            manifest = {'version':1,'protocol':PROTOCOL,'source':self.declared['source'],'transaction':self.declared['transaction'],
                        'members':self.declared['members'],'packed':packed}
            self._save('manifest.json',manifest,MAX_METADATA)
            self._event('after_manifest')
            raw = _canonical(manifest)
            commit = {'version':1,'protocol':PROTOCOL,'source':self.declared['source'],'transaction':self.declared['transaction'],
                      'manifest_bytes':len(raw),'manifest_sha256':hashlib.sha256(raw).hexdigest()}
            self._write(self.fd,'commit.json',(_canonical(commit),),MAX_CONTROL,'after_commit')
            os.fsync(self.fd)
            _verify_commit(self.fd,self.declared,self.members)
            self._commit_sha = hashlib.sha256(_canonical(commit)).hexdigest()
            self._committed = True
            return _accounting(_scan(self.fd))

    def close(self):
        with self._operation(allow_failed=True):
            need(not self._closed,'ALREADY_CLOSED')
            if self._writer is not None:
                os.fsync(self._writer)
                os.close(self._writer)
                self._writer = None
            self._save('closed.json',{'version':1,'source':self.declared['source'],
                       'transaction':self.declared['transaction'],'committed':self._committed,
                       'commit_sha256':self._commit_sha,'writers_closed':True})
            os.fsync(self.fd)
            self._closed = True
            self._event('after_close')
            return _accounting(_scan(self.fd))

    def retire_staging(self):
        with self._operation():
            need(self._closed and self._committed and self._writer is None and not self._retired,
                 'LIVE_DURABLE_COMMIT_AND_CLOSURE_REQUIRED')
            # The exact root-wide prerequisite used by restore must still hold.
            # In particular, no overflow or rejected optional artifact may make
            # the surviving packed original unreachable through that API.
            recovered = recover(self._root_path)
            need(recovered.get('state') == 'READ_ONLY_RECOVERY_REPORT',
                 'RETIRE_ROOT_RECOVERY_REFUSED')
            chosen = [row for row in recovered['transactions']
                      if row['name'] == 'txn-'+self.declared['transaction']]
            need(len(chosen) == 1 and chosen[0]['committed_accepted'] is True,
                 'RETIRE_RESTORABLE_CLOSED_COMMIT_REQUIRED')
            _,sha = _verify_commit(self.fd,self.declared,self.members)
            need(sha == self._commit_sha,'LIVE_COMMIT_CHANGED')
            closed = _decode(_read(self.fd,'closed.json',MAX_CONTROL))
            need(_typed_equal(closed,{'version':1,'source':self.declared['source'],
                 'transaction':self.declared['transaction'],'committed':True,
                 'commit_sha256':sha,'writers_closed':True}),'CLOSURE_CHANGED')
            # No byte is removed before all original stage files and the entire
            # separately decoded commit are verified again.
            for member in self.members:
                need(_file_hash(self.stage_fd,member.name,MAX_MEMBER) == (member.size,member.sha256),'RETIRE_STAGE_CHANGED')
            self._save('retirement-start.json',{'version':1,'commit_sha256':sha,'explicit_live_caller':True})
            self._event('before_retire')
            for member in self.members:
                self._root_binding()
                need(_file_hash(self.stage_fd,member.name,MAX_MEMBER) == (member.size,member.sha256),
                     'RETIRE_IMMEDIATE_ORIGINAL_VERIFY')
                # Recheck exact owned unique inode immediately before unlink.
                fd,info = _open_file(self.stage_fd,member.name)
                os.close(fd)
                now = os.stat(member.name,dir_fd=self.stage_fd,follow_symlinks=False)
                _regular(now)
                need((info.st_dev,info.st_ino,info.st_size) == (now.st_dev,now.st_ino,now.st_size),'RETIRE_INODE_CHANGED')
                os.unlink(member.name,dir_fd=self.stage_fd)
                self._event('after_retire_member')
            os.fsync(self.stage_fd)
            self._save('retirement-done.json',{'version':1,'commit_sha256':sha,'stage_members_removed':len(self.members)})
            os.fsync(self.fd)
            self._retired = True
            return _accounting(_scan(self.fd))

    def release(self):
        """Close handles only. Never unlink evidence or invent a closed receipt."""
        need(self._lock.acquire(blocking=False),'CONCURRENT_RELEASE_REFUSED')
        try:
            if not self._released:
                for fd in (self._writer,self.packed_fd,self.stage_fd,self.fd,self.root_fd):
                    if fd is not None:
                        os.close(fd)
                self._writer = None
                self._released = True
        finally:
            self._lock.release()


def begin(root,source,transaction,members,plan,*,hook=None):
    """Preadmit before creating a fresh transaction. Existing names always refuse."""
    declared,values,bound = _declaration(source,transaction,members,plan)
    need(hook is None or callable(hook),'TEST_HOOK_TYPE')
    root_fd = _open_root(root)
    fds = [root_fd]
    handle = None
    try:
        _root_writer_lock(root_fd)
        _root_slots(root_fd,creating=True)
        geometry = os.fstatvfs(root_fd)
        need(0 < geometry.f_frsize <= plan.allocation_unit,'ALLOCATION_UNIT_NOT_ADMITTED')
        os.fsync(root_fd)  # Unsupported actual directory fsync refuses before begin.
        os.mkdir('txn-'+transaction,0o700,dir_fd=root_fd)
        os.fsync(root_fd)
        fd = _open_dir(root_fd,'txn-'+transaction)
        fds.append(fd)
        for name in ('stage','packed'):
            os.mkdir(name,0o700,dir_fd=fd)
        os.fsync(fd)
        stage_fd = _open_dir(fd,'stage')
        fds.append(stage_fd)
        packed_fd = _open_dir(fd,'packed')
        fds.append(packed_fd)
        handle = Transaction(root_fd,fd,stage_fd,packed_fd,declared,values,bound,hook,root)
        writer = os.open('.writer',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        handle._writer = writer
        raw = _canonical({'version':1,'source':source,'transaction':transaction})
        need(os.write(writer,raw) == len(raw),'WRITER_METADATA_PARTIAL')
        os.fsync(writer)
        os.fsync(fd)
        handle._save('transaction.json',declared,MAX_METADATA)
        return handle
    except BaseException:
        if handle is not None and handle._writer is not None:
            os.close(handle._writer)
        for fd in reversed(fds):
            os.close(fd)
        raise


def resume(*args,**kwargs):
    """Resumption is deliberately unsupported, including matching identities."""
    raise Refusal('RESUME_UNSUPPORTED_RETAIN_EVERY_EXISTING_BYTE')


def recover(root):
    """Read-only bounded evidence inventory. Never discard or resume anything."""
    if os.name != 'posix':
        return {'state':'DURABILITY_UNSUPPORTED_WINDOWS_OR_NONPOSIX','inventory_complete':False,
                'committed_accepted':False,'evidence_deleted':False,
                'scope':'No POSIX durability or complete recovery claim on this platform.'}
    root_fd = _open_root(root)
    reports = []
    try:
        with os.scandir(root_fd) as iterator:
            names = []
            for entry in iterator:
                if len(names) >= MAX_TRANSACTIONS:
                    return {'state':'REFUSED_ROOT_COUNT_BOUND','inventory_complete':False,
                            'observed_root_entries':names,'unexamined_root_entries_present':True,
                            'committed_accepted':False,'evidence_deleted':False}
                names.append(entry.name)
        for name in sorted(names):
            report = {'name':name,'state':'UNKNOWN_EVIDENCE','inventory_complete':False,
                      'committed_accepted':False,'evidence_deleted':False}
            reports.append(report)
            fd = None
            try:
                need(re.fullmatch('txn-[0-9a-f]{32}',name) is not None,'UNKNOWN_ROOT_ENTRY')
                fd = _open_dir(root_fd,name)
                try:
                    rows = _scan(fd)
                except InventoryRefusal as error:
                    report['inventory'] = list(error.observed)
                    raise
                report.update(inventory=rows,inventory_complete=True,accounting=_accounting(rows))
                declared,members,bound = _load_declaration(_read(fd,'transaction.json',MAX_METADATA))
                need(name == 'txn-'+declared['transaction'],'RECOVERY_TRANSACTION_ALIAS')
                expected = {'stage','packed','.writer','transaction.json','failure-tail.bin','manifest.json',
                            'commit.json','closed.json','retirement-start.json','retirement-done.json'}
                expected |= {'stage/'+member.name for member in members}
                expected |= {'packed/'+member.name for member in members}
                unknown = sorted(row['path'] for row in rows if row['path'] not in expected)
                report['unknown_evidence'] = unknown
                need(not unknown,'UNKNOWN_TRANSACTION_EVIDENCE')
                by_path = {row['path']:row for row in rows}
                tail = by_path.get('failure-tail.bin')
                need(tail is None or tail['kind'] == 'file'
                     and tail['bytes'] <= declared['plan']['failure_tail'],
                     'RECOVERY_FAILURE_TAIL_KIND_OR_CAP')
                missing = []
                bad = []
                for member in members:
                    row = by_path.get('stage/'+member.name)
                    if row is None:
                        missing.append(member.name)
                    elif (row['bytes'],row['sha256']) != (member.size,member.sha256):
                        bad.append(member.name)
                report.update(declared_members=[member.name for member in members],
                              missing_stage_members=missing,corrupt_stage_members=bad)
                if 'commit.json' not in by_path:
                    report['state'] = 'PENDING_OR_PARTIAL_RETAIN_ALL'
                    continue
                commit,commit_sha = _verify_commit(fd,declared,members)
                report['commit_content_verified'] = True
                report['historical_fsync_independently_attested'] = False
                report['state'] = 'COMMIT_RECORD_PRESENT_CLOSURE_OR_DURABILITY_UNCERTAIN'
                if 'closed.json' in by_path:
                    closed = _decode(_read(fd,'closed.json',MAX_CONTROL))
                    need(_typed_equal(closed,{'version':1,'source':declared['source'],'transaction':declared['transaction'],
                         'committed':True,'commit_sha256':commit_sha,'writers_closed':True}),'RECOVERY_CLOSURE_BINDING')
                    report['state'] = 'COMMITTED_CONTENT_VERIFIED_CLOSURE_RECORDED'
                    report['committed_accepted'] = True
                if 'retirement-start.json' in by_path:
                    start = _decode(_read(fd,'retirement-start.json',MAX_CONTROL))
                    need(_typed_equal(start,{'version':1,'commit_sha256':commit_sha,'explicit_live_caller':True}),'RETIRE_START_BINDING')
                    report['retirement'] = 'STARTED_MAY_BE_PARTIAL'
                if 'retirement-done.json' in by_path:
                    done = _decode(_read(fd,'retirement-done.json',MAX_CONTROL))
                    need('retirement-start.json' in by_path
                         and _typed_equal(done,{'version':1,'commit_sha256':commit_sha,'stage_members_removed':len(members)})
                         and type(done.get('stage_members_removed')) is int
                         and len(missing) == len(members) and not bad,'RETIRE_DONE_BINDING')
                    report['retirement'] = 'DONE_CONTENT_BOUND'
                if missing or bad:
                    report['stage_gaps_explicit'] = True
            except BaseException as error:
                report.update(state='REFUSED_OR_PARTIAL_RETAIN_ALL',committed_accepted=False,
                              error_type=type(error).__name__,
                              error_detail_sha256=hashlib.sha256(str(error).encode('utf-8','replace')).hexdigest())
            finally:
                if fd is not None:
                    os.close(fd)
        return {'state':'READ_ONLY_RECOVERY_REPORT','transactions':reports,'evidence_deleted':False,
                'all_root_entries_reported':True,'hard_quota_or_global_admission':False,
                'scope':'Content/identity checks and recorded closure only; no privileged-writer authenticity or historical fsync attestation.'}
    finally:
        os.close(root_fd)

def restore(root,source,transaction,name):
    """Read one exact original only from a fully checked closed new-protocol commit."""
    digest(source)
    need(type(transaction) is str and re.fullmatch('[0-9a-f]{32}',transaction) is not None,'TRANSACTION_ID')
    member_name(name)
    reports = recover(root)
    need(reports.get('state') == 'READ_ONLY_RECOVERY_REPORT','RESTORE_RECOVERY_REFUSED')
    chosen = [row for row in reports['transactions'] if row['name'] == 'txn-'+transaction]
    need(len(chosen) == 1 and chosen[0]['committed_accepted'] is True,'RESTORE_CLOSED_COMMIT_REQUIRED')
    root_fd = _open_root(root)
    fd = packed_fd = None
    try:
        fd = _open_dir(root_fd,'txn-'+transaction)
        declaration,members,bound = _load_declaration(_read(fd,'transaction.json',MAX_METADATA))
        need(declaration['source'] == source and declaration['transaction'] == transaction,'RESTORE_TRUSTED_IDENTITY')
        matched = [member for member in members if member.name == name]
        need(len(matched) == 1,'RESTORE_DECLARED_MEMBER')
        member = matched[0]
        _,commit_sha = _verify_commit(fd,declaration,members)
        closed = _decode(_read(fd,'closed.json',MAX_CONTROL))
        need(_typed_equal(closed,{'version':1,'source':source,'transaction':transaction,
             'committed':True,'commit_sha256':commit_sha,'writers_closed':True}),'RESTORE_CLOSURE')
        packed_fd = _open_dir(fd,'packed')
        encoded = _read(packed_fd,name,member.size+(XZ_OVERHEAD if member.encoding == 'xz' else 0))
        if member.encoding == 'identity':
            raw = encoded
        else:
            try:
                decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=XZ_MEMORY)
                raw = decoder.decompress(encoded,max_length=member.size+1)
                need(decoder.eof and not decoder.unused_data,'RESTORE_XZ_SINGLE_MEMBER')
            except lzma.LZMAError as error:
                raise Refusal('RESTORE_XZ_DECODE') from error
        need(len(raw) == member.size and hashlib.sha256(raw).hexdigest() == member.sha256,'RESTORE_ORIGINAL_BINDING')
        return raw
    finally:
        for opened in (packed_fd,fd,root_fd):
            if opened is not None:
                os.close(opened)
