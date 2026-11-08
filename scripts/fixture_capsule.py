"""Bounded synthetic-fixture evidence, independent of raw_member_store.

This is a data-only JSON envelope, never an extraction format. Link targets are
bytes, including absolute and unsafe targets. The caller owns an exclusive,
quiescent case container and must release every writer before calling preserve.
POSIX cleanup requires file and directory fsync; Windows retains raw fixtures.
No privileged-writer authenticity or historical durability attestation is made.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat

MAX_ENTRIES = 2048
MAX_DEPTH = 6
MAX_FILE = 4 << 20
MAX_RAW = 16 << 20
MAX_CAPSULE = 24 << 20
MAX_OUTPUT = 24 << 20  # all complete and partial capsules in one output root
MAX_TARGET = 4096
PROTOCOL = 'synthetic-fixture-capsule-v1'


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def number(value, low, high):
    need(type(value) is int and low <= value <= high, 'INTEGER_BOUND')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _b64(raw):
    return base64.b64encode(raw).decode('ascii')


def _bytes(value, maximum):
    need(type(value) is str and len(value) <= 4*((maximum+2)//3), 'BASE64_BOUND')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError) as error:
        raise Refusal('BASE64_FORMAT') from error
    need(len(raw) <= maximum and _b64(raw) == value, 'BASE64_CANONICAL_OR_BOUND')
    return raw


def _keys(value, expected):
    need(type(value) is dict and set(value) == set(expected), 'EXACT_SCHEMA')


def _path(value):
    need(type(value) is str and len(value) <= 6*129, 'PATH_TYPE_OR_BOUND')
    parts = value.split('/') if value else []
    need(len(parts) <= MAX_DEPTH, 'PATH_DEPTH')
    for part in parts:
        need(re.fullmatch('[A-Za-z0-9_.-]{1,128}', part) is not None
             and part not in ('.', '..') and not part.endswith('.')
             and part.split('.')[0].lower() not in
             {'con','prn','aux','nul'} | {p+str(i) for p in ('com','lpt') for i in range(10)},
             'PATH_COMPONENT_OR_ALIAS')
    return tuple(parts)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'DUPLICATE_KEY')
        value[key] = item
    return value


def decode(raw):
    """Independent typed reader; no extraction and no encoder round trip."""
    need(type(raw) is bytes and len(raw) <= MAX_CAPSULE, 'CAPSULE_BOUND')
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refusal('NONFINITE')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refusal('JSON_FORMAT') from error
    _keys(value, ('version','protocol','source_path','entries','raw_bytes'))
    need(type(value['version']) is int and value['version'] == 1
         and type(value['protocol']) is str and value['protocol'] == PROTOCOL, 'VERSION')
    source = _bytes(value['source_path'], 32768)
    need(source and b'\0' not in source, 'SOURCE_PATH')
    number(value['raw_bytes'], 0, MAX_RAW)
    rows = value['entries']
    need(type(rows) is list and 1 <= len(rows) <= MAX_ENTRIES, 'ENTRY_COUNT')
    paths, aliases, groups, total = {}, set(), {}, 0
    for row in rows:
        need(type(row) is dict and type(row.get('kind')) is str, 'ENTRY_SCHEMA')
        kind = row['kind']
        extra = {'file': ('data','bytes','sha256','nlink'), 'symlink': ('target',), 'directory': ()}
        need(kind in extra, 'ENTRY_KIND')
        _keys(row, ('path','kind','mode','dev','ino')+extra[kind])
        parts = _path(row['path'])
        need(parts not in paths and tuple(p.lower() for p in parts) not in aliases, 'PATH_COLLISION')
        paths[parts] = row
        aliases.add(tuple(p.lower() for p in parts))
        number(row['mode'], 0, 0o7777)
        number(row['dev'], 0, (1<<128)-1)
        number(row['ino'], 0, (1<<128)-1)
        if kind == 'file':
            number(row['bytes'], 0, MAX_FILE)
            number(row['nlink'], 1, MAX_ENTRIES)
            data = _bytes(row['data'], MAX_FILE)
            need(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])
                 and len(data) == row['bytes'] and digest(data) == row['sha256'], 'FILE_BYTES_OR_HASH')
            total += len(data)
            need(total <= MAX_RAW, 'RAW_BOUND')
            groups.setdefault((row['dev'],row['ino']), []).append(row)
        elif kind == 'symlink':
            target = _bytes(row['target'], MAX_TARGET)
            need(target and b'\0' not in target, 'SYMLINK_TARGET')
    need(() in paths and paths[()]['kind'] == 'directory', 'ROOT_DIRECTORY')
    for parts in paths:
        need(not parts or parts[:-1] in paths and paths[parts[:-1]]['kind'] == 'directory', 'PARENT_DIRECTORY')
    for group in groups.values():
        first = group[0]
        need(len(group) == first['nlink'], 'EXTERNAL_HARDLINK_OR_GROUP_COUNT')
        for row in group:
            need(all(type(row[k]) is type(first[k]) and row[k] == first[k]
                     for k in ('mode','nlink','data','bytes','sha256')), 'HARDLINK_RELATION')
    # No directory/symlink may pretend to share a regular-file identity.
    identities = {}
    for row in rows:
        identity = (row['dev'], row['ino'])
        if identity in identities:
            need(row['kind'] == identities[identity] == 'file', 'NONFILE_IDENTITY_COLLISION')
        identities[identity] = row['kind']
    need(total == value['raw_bytes'], 'RAW_TOTAL')
    return value


def _cross_api_signature(info):
    """Fields with matching lstat/fstat meaning; Windows ctime is excluded.

    Supported birth times and attributes remain identity checks. No zero field
    is substituted or accepted as a stand-in for missing filesystem identity.
    """
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns,
            getattr(info,'st_birthtime_ns',None),getattr(info,'st_birthtime',None),
            getattr(info,'st_file_attributes',None),
            getattr(info,'st_uid',None),getattr(info,'st_gid',None))


def _signature(info):
    # Same-API before/after checks retain each API's own complete ctime value.
    return _cross_api_signature(info)+(info.st_ctime_ns,)


def checked_directory(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and path != Path(path.anchor), 'ABSOLUTE_OWNED_PATH')
    for ancestor in reversed((path,)+tuple(path.parents)[:-1]):
        info = ancestor.lstat()
        need(stat.S_ISDIR(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,
             'DIRECTORY_LINK_OR_REPARSE')
    info = path.lstat()
    if os.name == 'posix':
        need(info.st_uid == os.getuid() and not info.st_mode&0o022, 'OWNED_DIRECTORY_REQUIRED')
    return path


def _read_file(path, expected, maximum):
    need(stat.S_ISREG(expected.st_mode) and not getattr(expected,'st_file_attributes',0)&0x400,
         'REGULAR_REQUIRED')
    need(expected.st_size <= maximum, 'FILE_BOUND')
    fd = os.open(path, os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_BINARY',0))
    try:
        opened=os.fstat(fd)
        need(_cross_api_signature(opened) == _cross_api_signature(expected), 'OPEN_IDENTITY_CHANGED')
        need(_signature(path.lstat()) == _signature(expected), 'OPEN_PATH_CHANGED')
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, min(65536,maximum-total+1))
            if not chunk:
                break
            total += len(chunk)
            need(total <= maximum, 'READ_BOUND')
            chunks.append(chunk)
        need(_signature(os.fstat(fd)) == _signature(opened)
             and _signature(path.lstat()) == _signature(expected), 'READ_SOURCE_CHANGED')
        need(total == expected.st_size, 'READ_PHYSICAL_SIZE')
        return b''.join(chunks)
    finally:
        os.close(fd)


def _inventory(root):
    rows, signatures, total = [], {}, 0
    def walk(path, relative):
        nonlocal total
        _path(relative)
        need(len(rows) < MAX_ENTRIES, 'ENTRY_COUNT')
        info = path.lstat()
        signatures[relative] = _signature(info)
        row = dict(path=relative, mode=stat.S_IMODE(info.st_mode), dev=info.st_dev, ino=info.st_ino)
        rows.append(row)
        if stat.S_ISLNK(info.st_mode):
            target = os.fsencode(os.readlink(path))
            need(len(target) <= MAX_TARGET, 'TARGET_BOUND')
            row.update(kind='symlink', target=_b64(target))
        elif stat.S_ISDIR(info.st_mode):
            need(not getattr(info,'st_file_attributes',0)&0x400, 'DIRECTORY_REPARSE')
            row['kind'] = 'directory'
            with os.scandir(path) as iterator:
                names = []
                for entry in iterator:
                    need(len(names)+len(rows) < MAX_ENTRIES, 'ENTRY_COUNT')
                    names.append(entry.name)
            for name in sorted(names):
                walk(path/name, relative+'/'+name if relative else name)
        elif stat.S_ISREG(info.st_mode):
            raw = _read_file(path,info,MAX_FILE)
            total += len(raw)
            need(total <= MAX_RAW, 'RAW_BOUND')
            row.update(kind='file', data=_b64(raw), bytes=len(raw), sha256=digest(raw), nlink=info.st_nlink)
        else:
            raise Refusal('SPECIAL_FILE')
        need(_signature(path.lstat()) == signatures[relative], 'INVENTORY_CHANGED')
    walk(root,'')
    return dict(version=1, protocol=PROTOCOL, source_path=_b64(os.fsencode(root)),
                entries=rows, raw_bytes=total), signatures


def verify_source(value, root):
    """Compare independently decoded bytes, types, modes and inode relations.

    Enumeration here is separate from the encoder. Never follows link targets.
    Stable exclusive ownership is required; this is not a hostile-writer sandbox.
    """
    root = checked_directory(root)
    need(_bytes(value['source_path'],32768) == os.fsencode(root), 'SOURCE_PATH_BINDING')
    expected = {row['path']:row for row in value['entries']}
    seen = set()
    pending = [(root,'')]
    while pending:
        path, relative = pending.pop()
        need(relative in expected and relative not in seen and len(seen) < MAX_ENTRIES, 'SOURCE_MEMBERSHIP')
        seen.add(relative)
        row, info = expected[relative], path.lstat()
        need((stat.S_IMODE(info.st_mode),info.st_dev,info.st_ino) ==
             (row['mode'],row['dev'],row['ino']), 'SOURCE_METADATA')
        if row['kind'] == 'directory':
            need(stat.S_ISDIR(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400, 'SOURCE_DIRECTORY')
            with os.scandir(path) as iterator:
                for entry in iterator:
                    need(len(pending)+len(seen) < MAX_ENTRIES, 'SOURCE_COUNT')
                    pending.append((path/entry.name,relative+'/'+entry.name if relative else entry.name))
        elif row['kind'] == 'symlink':
            need(stat.S_ISLNK(info.st_mode) and os.fsencode(os.readlink(path)) ==
                 _bytes(row['target'],MAX_TARGET), 'SOURCE_LINK_BYTES')
        else:
            need(info.st_nlink == row['nlink'] and _read_file(path,info,MAX_FILE) ==
                 _bytes(row['data'],MAX_FILE), 'SOURCE_FILE_BYTES_OR_LINKS')
    need(seen == set(expected), 'SOURCE_MISSING_ENTRIES')


def read(path):
    path = Path(path)
    info = path.lstat()
    need(info.st_nlink == 1, 'CAPSULE_EXTERNAL_ALIAS')
    return decode(_read_file(path,info,MAX_CAPSULE))


def _sync_dir(path):
    need(os.name == 'posix' and hasattr(os,'O_DIRECTORY'), 'DIRECTORY_DURABILITY_UNSUPPORTED')
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|getattr(os,'O_NOFOLLOW',0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _output_slots(count,reserved):
    number(count,0,MAX_ENTRIES)
    number(reserved,0,2)
    need(count+reserved <= MAX_ENTRIES,'OUTPUT_COUNT_WITH_PUBLICATION_HEADROOM')
    return count+reserved


def _output_size(output, reserve_slots=0):
    total = 0
    _output_slots(0,reserve_slots)
    with os.scandir(output) as iterator:
        for count,entry in enumerate(iterator,1):
            _output_slots(count,reserve_slots)
            info = Path(entry.path).lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                 and not getattr(info,'st_file_attributes',0)&0x400, 'OUTPUT_REGULAR_ONLY')
            total += info.st_size
            need(total <= MAX_OUTPUT, 'OUTPUT_AGGREGATE_BOUND')
    return total


def preserve(root, output, name, *, remove=True, synthetic_hook=None):
    """No clobber; all failures retain partials and all surviving raw evidence.

    The hook is a synthetic test boundary exception, never a mocked OS failure.
    Cleanup can partially succeed before an OS refusal; the verified durable
    capsule still contains the complete original, and surviving raw is retained.
    """
    root, output = checked_directory(root), checked_directory(output)
    need(root != output and root not in output.parents and output not in root.parents, 'DISJOINT_OUTPUT')
    need(type(name) is str and re.fullmatch('[a-z0-9-]{1,100}',name), 'CAPSULE_NAME')
    need(type(remove) is bool and (synthetic_hook is None or callable(synthetic_hook)), 'CALLER_TYPES')
    final, partial = output/(name+'.fcap'), output/(name+'.partial')
    need(not os.path.lexists(final) and not os.path.lexists(partial), 'NO_OVERWRITE')
    value, signatures = _inventory(root)
    raw = (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('ascii')
    need(len(raw) <= MAX_CAPSULE and _output_size(output,2)+len(raw) <= MAX_OUTPUT, 'OUTPUT_ADMISSION')
    def event(name):
        if synthetic_hook is not None:
            synthetic_hook(name)
    with partial.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    event('after_partial_fsync')
    decoded = read(partial)
    verify_source(decoded,root)
    need(all(_signature((root/relative).lstat()) == signature
             for relative,signature in signatures.items()), 'SOURCE_CHANGED_AFTER_ENCODING')
    event('after_independent_readback')
    # Exclusive final creation avoids rename-overwrite differences across OSes.
    # Partial remains until the final has been read back, flushed, and published.
    need(_output_size(output,1)+len(raw) <= MAX_OUTPUT, 'PUBLICATION_AGGREGATE_BOUND')
    with final.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    need(_read_file(final,final.lstat(),MAX_CAPSULE) == raw, 'PUBLICATION_BYTES')
    verified = read(final)
    verify_source(verified,root)
    event('after_final_readback')
    durable = os.name == 'posix'
    if durable:
        # A new output directory also needs its parent directory entries
        # persisted. Sync the checked ancestor chain through the filesystem root.
        for directory in (output,)+tuple(output.parents):
            _sync_dir(directory)
    removed = False
    if remove and durable:
        verify_source(read(final),root)
        event('before_raw_cleanup')
        shutil.rmtree(root)
        _sync_dir(root.parent)
        removed = True
    # Retain both copies on cleanup failure, including a partially removed raw
    # tree. Windows has no raw-removal phase and makes no directory-fsync claim.
    partial.unlink()
    if durable:
        _sync_dir(output)
    return {'capsule':str(final),'capsule_bytes':len(raw),'raw_bytes':value['raw_bytes'],
            'entry_count':len(value['entries']),'directory_durability':durable,
            'raw_fixture_removed':removed}
