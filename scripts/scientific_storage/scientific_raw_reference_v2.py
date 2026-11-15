"""UNEXECUTED private v2 scientific raw-reference integration draft.

Fresh caller-created bytes only; never a legacy-gzip migration or a scientific
qualification. Uses the existing raw_member_store primitive without changing
its caps. No deletion/retirement API is implemented. All interrupted originals,
sidecars, transaction candidates and catalog partials remain caller evidence.
Trusted exclusive caller ownership is required; no hostile-writer sandbox,
kernel quota, historical fsync attestation or full-matrix fit is claimed.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import uuid

import raw_member_store as store
import scientific_capture_protocol as protocol

FORMAT = 'scientific-caller-raw-reference-v2'
CATALOG_FORMAT = 'scientific-caller-raw-catalog-v2'
GRID_SHA256 = protocol.GRID_SHA256
MAX_CATALOG = 8 << 20
MAX_REFERENCES = 64
MAX_ORIGINAL = 256 << 20
MAX_BATCH_RAW = 256 << 20
MAX_CHUNKS = 4096
MAX_SHARDS = 32
MAX_TRANSACTIONS = MAX_SHARDS * 32
MAX_TREE_ENTRIES = 100_000
MAX_TREE_DEPTH = 8
MAX_LAYER = 4_000_000_000
CHUNK = 1 << 20
TX_MEMBERS = 4  # <=16 and <=4MiB; never raise primitive caps.
ROLES = {'stdout', 'stderr', 'samples', 'corpus', 'queries'}
OUTCOMES = {'success', 'failed', 'timeout', 'start-error', 'available-partial'}
DEVICE = {'con', 'prn', 'aux', 'nul'} | {p + str(i) for p in ('com', 'lpt') for i in range(10)}


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, 'TYPED_INTEGER_BOUND')


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys), 'EXACT_SCHEMA')


def same(a, b):
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return set(a) == set(b) and all(same(a[k], b[k]) for k in a)
    if type(a) is list:
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return a == b


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    need(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value), 'SHA256')


def ident(value, count=32):
    need(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % count, value), 'HEX_ID')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'DUPLICATE_JSON_KEY')
        value[key] = item
    return value


def nonfinite(_):
    raise Refusal('NONFINITE_JSON')


def decode(raw):
    need(type(raw) is bytes and len(raw) <= MAX_CATALOG, 'METADATA_BYTE_BOUND')
    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
        need(canonical(value) == raw, 'CANONICAL_METADATA_REQUIRED')
        return value
    except (UnicodeError, RecursionError, ValueError) as error:
        raise Refusal('METADATA_FORMAT') from error


def component(value):
    need(type(value) is str and re.fullmatch(r'[a-z0-9_.-]{1,64}', value) and
         value not in ('.', '..') and not value.endswith('.') and
         value.split('.')[0] not in DEVICE, 'PORTABLE_COMPONENT')
    return value


def relative(value):
    need(type(value) is str and 0 < len(value) <= 1024, 'RELATIVE_PATH')
    parts = value.split('/')
    need(len(parts) <= MAX_TREE_DEPTH, 'RELATIVE_DEPTH')
    for part in parts:
        component(part)
    need(PurePosixPath(value).as_posix() == value, 'CANONICAL_RELATIVE_PATH')
    return parts


def _protocol_call(function, *arguments):
    """Delegate reviewed v2 metadata rules; preserve this module's refusal API."""
    try:
        return function(*arguments)
    except protocol.Refusal as error:
        raise Refusal(str(error)) from error


def frozen_config(concurrency):
    return _protocol_call(protocol.frozen_config, concurrency)


def primitive_contract():
    need((store.MAX_MEMBERS, store.MAX_MEMBER, store.MAX_TOTAL, store.MAX_TRANSACTIONS,
          store.PROTOCOL) == (16, 1 << 20, 4 << 20, 32, 'caller-raw-originals-v1'),
         'UNCHANGED_PRIMITIVE_CONTRACT_REQUIRED')


def validate_run(run):
    return _protocol_call(protocol.validate_run, run)


def validate_binding(binding, run):
    return _protocol_call(protocol.validate_binding, binding, run)


def logical_capture_key(binding, run):
    return _protocol_call(protocol.logical_key, binding, run)


def validate_binding_set(bindings, run):
    """Batch-local check only: integrator MUST also check every catalog together.

    Protocol logical keys include exact run SHA and invocation/tagged scope.
    This store neither registers other catalogs nor claims execution-wide dedup.
    External attempt metadata is NOT an inline raw-capture role.
    """
    return _protocol_call(protocol.validate_bindings, bindings, run)


@dataclass(frozen=True)
class Budget:
    global_baseline_bytes: int
    other_reserved_growth_bytes: int
    layer_allowance_bytes: int
    allocation_unit: int = 4096
    ceiling_bytes: int = 12_000_000_000

    def validate(self):
        integer(self.global_baseline_bytes, 0, 15_000_000_000)
        integer(self.other_reserved_growth_bytes, 0, 15_000_000_000)
        integer(self.layer_allowance_bytes, 0, MAX_LAYER)
        integer(self.allocation_unit, 4096, 65536)
        need(self.allocation_unit & (self.allocation_unit - 1) == 0, 'ALLOCATION_POWER')
        integer(self.ceiling_bytes, 1, 12_000_000_000)
        # Deliberate conservative double count if baseline contains this layer.
        need(self.global_baseline_bytes + self.other_reserved_growth_bytes +
             self.layer_allowance_bytes < self.ceiling_bytes, 'CALLER_GLOBAL_RESERVATION_REFUSED')
        return self


def _platform():
    need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY'),
         'POSIX_DURABILITY_REQUIRED')


def _directory(info):
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
         not info.st_mode & 0o022 and not getattr(info, 'st_file_attributes', 0) & 0x400,
         'OWNED_DIRECTORY_REQUIRED')


def _file(info):
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
         not getattr(info, 'st_file_attributes', 0) & 0x400, 'UNIQUE_OWNED_REGULAR_REQUIRED')


def _signature(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _root(path):
    _platform()
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and path != Path(path.anchor), 'EXPLICIT_OWNED_ROOT')
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            parent, fd = fd, child
            store._release_descriptors((parent,))
        _directory(os.fstat(fd))
        return fd
    except BaseException:
        store._release_descriptors((fd,))
        raise


def _dir(parent, name):
    component(name)
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _directory(before)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        after = os.fstat(fd)
        _directory(after)
        need((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), 'DIRECTORY_CHANGED')
        return fd
    except BaseException:
        store._release_descriptors((fd,))
        raise


def _open(parent, name):
    component(name)
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _file(before)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        opened = os.fstat(fd)
        _file(opened)
        need(_signature(before) == _signature(opened), 'FILE_OPEN_CHANGED')
        return fd, opened
    except BaseException:
        store._release_descriptors((fd,))
        raise


def _read(parent, name, maximum):
    fd, before = _open(parent, name)
    try:
        need(before.st_size <= maximum, 'BOUNDED_READ')
        parts, total = [], 0
        while raw := os.read(fd, min(65536, maximum - total + 1)):
            total += len(raw)
            need(total <= maximum, 'BOUNDED_READ')
            parts.append(raw)
        need(_signature(os.fstat(fd)) == _signature(before), 'FILE_READ_CHANGED')
        now = os.stat(name, dir_fd=parent, follow_symlinks=False)
        need(_signature(now) == _signature(before), 'FILE_PATH_CHANGED')
        need(total == before.st_size, 'SHORT_ORIGINAL_READ')
        return b''.join(parts)
    finally:
        store._release_descriptors((fd,))


def _hash(parent, name, maximum):
    fd, before = _open(parent, name)
    try:
        need(before.st_size <= maximum, 'HASH_BYTE_BOUND')
        h, total = hashlib.sha256(), 0
        while raw := os.read(fd, 65536):
            total += len(raw)
            need(total <= maximum, 'HASH_BYTE_BOUND')
            h.update(raw)
        need(total == before.st_size and _signature(os.fstat(fd)) == _signature(before) and
             _signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _signature(before),
             'ORIGINAL_CHANGED')
        return total, h.hexdigest(), _signature(before)
    finally:
        store._release_descriptors((fd,))


def _at(root, path):
    parts = relative(path)
    fd = os.dup(root)
    try:
        for part in parts[:-1]:
            child = _dir(fd, part)
            parent, fd = fd, child
            store._release_descriptors((parent,))
        return fd, parts[-1]
    except BaseException:
        store._release_descriptors((fd,))
        raise


def _inventory(root, unit, *, exclude_catalog=False, content=True,
               entry_limit=MAX_TREE_ENTRIES):
    """Every observed allocation/entry counts; unsafe or too-large trees refuse.

    Unknown safe regular files are inventoried and charged before publication
    refuses their membership. No link target is traversed or evidence deleted.
    """
    integer(entry_limit, 1, MAX_TREE_ENTRIES)
    root_info = os.fstat(root)
    root_charge = max(((root_info.st_size + unit - 1) // unit) * unit,
                      getattr(root_info, 'st_blocks', 0) * 512) + unit
    rows, total, discovered = [], root_charge, 0
    def walk(folder, prefix, depth):
        nonlocal total, discovered
        need(depth <= MAX_TREE_DEPTH, 'TREE_DEPTH_BOUND')
        with os.scandir(folder) as entries:
            names = []
            for entry in entries:
                # One shared discovery charge, including pending ancestor
                # siblings and excluded catalog copies. Refuse the first
                # over-budget entry before retaining or traversing it.
                discovered += 1
                need(discovered <= entry_limit, 'TREE_ENTRY_BOUND')
                names.append(entry.name)
        need(len(names) == len({name.lower() for name in names}), 'TREE_CASE_ALIAS')
        for name in sorted(names):
            if not prefix and exclude_catalog and name in ('catalog.json', 'catalog.partial'):
                continue
            component(name)
            info = os.stat(name, dir_fd=folder, follow_symlinks=False)
            path = prefix + name
            blocks = getattr(info, 'st_blocks', 0) * 512
            charge = max(((info.st_size + unit - 1) // unit) * unit, blocks) + unit
            total += charge
            need(total <= MAX_LAYER, 'TREE_ALLOCATION_BOUND')
            if stat.S_ISDIR(info.st_mode):
                child = _dir(folder, name)
                rows.append({'path': path, 'kind': 'directory',
                             'identity': [info.st_dev, info.st_ino, info.st_mode, info.st_nlink]})
                try:
                    walk(child, path + '/', depth + 1)
                finally:
                    store._release_descriptors((child,))
            else:
                _file(info)
                row = {'path': path, 'kind': 'file', 'identity': _signature(info),
                       'bytes': info.st_size}
                if content:
                    size, digest_value, signature = _hash(folder, name, MAX_ORIGINAL)
                    need(size == info.st_size and signature == _signature(info), 'INVENTORY_CHANGED')
                    row['sha256'] = digest_value
                rows.append(row)
    walk(root, '', 0)
    return sorted(rows, key=lambda row: row['path']), total


def portable_inventory(rows):
    """Content/type/path closure; native identity remains immutable provenance.

    Current reads still independently enforce no-follow, unique regular files,
    ownership, and stable live descriptor/path identities. Historical inode,
    device, mode permissions and timestamps are not copy/remount identities.
    Never rewrite the original catalog or substitute current IDs into it.
    """
    return [{'path': row['path'], 'kind': row['kind'],
             **({'bytes': row['bytes'], 'sha256': row['sha256']}
                if row['kind'] == 'file' else {})}
            for row in rows]


def _sync_ancestors(path):
    # Open every ancestor without following links; ancestors need not be owned.
    path = Path(path)
    for target in (path,) + tuple(path.parents):
        fd = os.open(target.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in target.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                parent, fd = fd, child
                store._release_descriptors((parent,))
            os.fsync(fd)
        finally:
            store._release_descriptors((fd,))


def _write_all(fd, raw):
    position = 0
    while position < len(raw):
        count = os.write(fd, raw[position:])
        need(count > 0, 'SHORT_WRITE_NO_PROGRESS')
        position += count


def _member_rows(refs):
    rows = []
    for ref in refs:
        for chunk in ref['chunks']:
            rows.append((chunk['shard'], chunk['transaction'], chunk['member'],
                         chunk['bytes'], chunk['sha256'], chunk['encoding']))
    return rows


def validate_catalog(value):
    exact(value, ('version', 'format', 'catalog_id', 'run', 'references',
                  'transactions', 'inventory', 'retirement', 'scope'))
    need(type(value['version']) is int and value['version'] == 2 and value['format'] == CATALOG_FORMAT,
         'CATALOG_VERSION')
    ident(value['catalog_id'])
    validate_run(value['run'])
    need(value['retirement'] == 'unsupported-retain-all-original-and-primitive-staging' and
         value['scope'] == 'storage-only-no-scientific-quota-or-release-qualification', 'HONEST_SCOPE')
    refs, txs, inventory = value['references'], value['transactions'], value['inventory']
    need(type(refs) is list and 1 <= len(refs) <= MAX_REFERENCES and type(txs) is list and
         1 <= len(txs) <= MAX_TRANSACTIONS and type(inventory) is list and
         1 <= len(inventory) <= MAX_TREE_ENTRIES, 'CATALOG_COUNTS')
    ref_ids, bindings, originals, chunk_keys = set(), [], set(), set()
    total_raw = total_chunks = 0
    for ref in refs:
        exact(ref, ('format', 'id', 'binding', 'original', 'chunks', 'writers_closed'))
        need(ref['format'] == FORMAT and ref['writers_closed'] is True, 'REFERENCE_FORMAT_OR_WRITERS')
        ident(ref['id'])
        need(ref['id'] not in ref_ids, 'DUPLICATE_REFERENCE')
        ref_ids.add(ref['id'])
        validate_binding(ref['binding'], value['run'])
        bindings.append(ref['binding'])
        original = ref['original']
        exact(original, ('path', 'bytes', 'sha256', 'identity'))
        need(original['path'] == 'originals/' + ref['id'] + '.raw' and
             original['path'] not in originals, 'ORIGINAL_PATH_BINDING')
        originals.add(original['path'])
        integer(original['bytes'], 0, MAX_ORIGINAL)
        digest(original['sha256'])
        need(type(original['identity']) is list and len(original['identity']) == 7, 'ORIGINAL_IDENTITY')
        for number in original['identity']:
            integer(number, 0, (1 << 128) - 1)
        need(stat.S_ISREG(original['identity'][2]) and original['identity'][3] == 1 and
             original['identity'][4] == original['bytes'], 'ORIGINAL_REGULAR_SIZE_IDENTITY')
        chunks = ref['chunks']
        expected_count = max(1, (original['bytes'] + CHUNK - 1) // CHUNK)
        need(type(chunks) is list and len(chunks) == expected_count, 'LOSSLESS_CHUNK_COUNT')
        offset = 0
        for index, chunk in enumerate(chunks):
            exact(chunk, ('index', 'offset', 'bytes', 'sha256', 'shard', 'transaction', 'member', 'encoding'))
            integer(chunk['index'], 0, MAX_CHUNKS - 1)
            integer(chunk['offset'], 0, MAX_ORIGINAL)
            integer(chunk['bytes'], 0, CHUNK)
            need(chunk['index'] == index and chunk['offset'] == offset and
                 chunk['bytes'] == min(CHUNK, original['bytes'] - offset), 'ORDERED_CONTIGUOUS_CHUNKS')
            digest(chunk['sha256'])
            need(type(chunk['shard']) is str and re.fullmatch(r'shards/s[0-9]{4}', chunk['shard']),
                 'SHARD_PATH')
            ident(chunk['transaction'])
            component(chunk['member'])
            need(re.fullmatch(r'm[0-9]{8}', chunk['member']) and chunk['encoding'] in ('identity', 'xz'),
                 'CHUNK_MEMBER_ENCODING')
            key = (chunk['shard'], chunk['transaction'], chunk['member'])
            need(key not in chunk_keys, 'DUPLICATE_CHUNK_REFERENCE')
            chunk_keys.add(key)
            offset += chunk['bytes']
        need(offset == original['bytes'], 'COMPLETE_ORIGINAL_BYTES')
        total_raw += original['bytes']
        total_chunks += len(chunks)
    validate_binding_set(bindings, value['run'])
    need(total_raw <= MAX_BATCH_RAW and total_chunks <= MAX_CHUNKS, 'BATCH_RAW_AND_CHUNK_BOUNDS')
    seen_tx, tx_members, shard_slots = set(), set(), {}
    for tx in txs:
        exact(tx, ('shard', 'transaction', 'members', 'declaration_sha256', 'manifest_sha256',
                   'commit_sha256', 'closed_sha256'))
        need(type(tx['shard']) is str and re.fullmatch(r'shards/s[0-9]{4}', tx['shard']), 'TX_SHARD')
        ident(tx['transaction'])
        key = (tx['shard'], tx['transaction'])
        need(key not in seen_tx, 'DUPLICATE_TRANSACTION')
        seen_tx.add(key)
        shard_slots.setdefault(tx['shard'], 0)
        shard_slots[tx['shard']] += 1
        need(shard_slots[tx['shard']] <= 32 and len(shard_slots) <= MAX_SHARDS, 'UNCHANGED_ROOT_SLOTS')
        for name in ('declaration_sha256', 'manifest_sha256', 'commit_sha256', 'closed_sha256'):
            digest(tx[name])
        need(type(tx['members']) is list and 1 <= len(tx['members']) <= 16, 'UNCHANGED_MEMBER_COUNT')
        tx_bytes = 0
        names = []
        for member in tx['members']:
            exact(member, ('name', 'bytes', 'sha256', 'encoding'))
            component(member['name'])
            integer(member['bytes'], 0, CHUNK)
            digest(member['sha256'])
            need(member['encoding'] in ('identity', 'xz'), 'TX_ENCODING')
            match = (tx['shard'], tx['transaction'], member['name'], member['bytes'],
                     member['sha256'], member['encoding'])
            need(match not in tx_members, 'DUPLICATE_TX_MEMBER')
            tx_members.add(match)
            names.append(member['name'])
            tx_bytes += member['bytes']
        need(len(names) == len(set(names)) and names == sorted(names) and tx_bytes <= 4 << 20,
             'UNCHANGED_TRANSACTION_BYTES_OR_MEMBERS')
    need(tx_members == set(_member_rows(refs)), 'CATALOG_TRANSACTION_MEMBER_CLOSURE')
    paths, aliases = {}, set()
    for row in inventory:
        need(type(row) is dict and row.get('kind') in ('directory', 'file'), 'INVENTORY_KIND')
        if row['kind'] == 'file':
            exact(row, ('path', 'kind', 'identity', 'bytes', 'sha256'))
            integer(row['bytes'], 0, MAX_ORIGINAL)
            digest(row['sha256'])
            count = 7
        else:
            exact(row, ('path', 'kind', 'identity'))
            count = 4
        relative(row['path'])
        need(row['path'] not in paths and row['path'].lower() not in aliases, 'INVENTORY_COLLISION')
        paths[row['path']] = row
        aliases.add(row['path'].lower())
        need(type(row['identity']) is list and len(row['identity']) == count, 'INVENTORY_IDENTITY')
        for number in row['identity']:
            integer(number, 0, (1 << 128) - 1)
        need(stat.S_ISREG(row['identity'][2]) if count == 7 else stat.S_ISDIR(row['identity'][2]),
             'INVENTORY_IDENTITY_TYPE')
        if count == 7:
            need(row['identity'][3] == 1 and row['identity'][4] == row['bytes'], 'INVENTORY_FILE_ALIAS_SIZE')
    expected = {'originals', 'shards'} | originals
    for ref in refs:
        row = paths.get(ref['original']['path'])
        need(row is not None and row['kind'] == 'file' and
             all(same(row[key], ref['original'][key]) for key in ('bytes', 'sha256', 'identity')),
             'CATALOG_ORIGINAL_INVENTORY_BINDING')
    for tx in txs:
        base = tx['shard'] + '/txn-' + tx['transaction']
        expected |= {tx['shard'], base, base + '/stage', base + '/packed', base + '/.writer',
                     base + '/transaction.json', base + '/manifest.json', base + '/commit.json', base + '/closed.json'}
        for member in tx['members']:
            expected |= {base + '/stage/' + member['name'], base + '/packed/' + member['name']}
            row = paths.get(base + '/stage/' + member['name'])
            need(row is not None and row['kind'] == 'file' and row['bytes'] == member['bytes'] and
                 row['sha256'] == member['sha256'], 'FULL_PRIMITIVE_STAGING_RETAINED')
            packed = paths.get(base + '/packed/' + member['name'])
            need(packed is not None and packed['kind'] == 'file' and
                 packed['bytes'] <= member['bytes'] + (65536 if member['encoding'] == 'xz' else 0),
                 'PACKED_CANDIDATE_BOUND')
        for file_name, key in (('transaction.json', 'declaration_sha256'), ('manifest.json', 'manifest_sha256'),
                               ('commit.json', 'commit_sha256'), ('closed.json', 'closed_sha256')):
            row = paths.get(base + '/' + file_name)
            need(row is not None and row['kind'] == 'file' and row['sha256'] == tx[key], 'TX_CONTROL_SHA_BINDING')
        tail = base + '/failure-tail.bin'
        if tail in paths:
            need(paths[tail]['kind'] == 'file' and paths[tail]['bytes'] <= 4096, 'FAILURE_TAIL_SIDECAR_CAP')
            expected.add(tail)
    need(set(paths) == expected, 'COMPLETE_STORE_CATALOG_CLOSURE')
    for path in paths:
        parent = PurePosixPath(path).parent.as_posix()
        need(parent == '.' or parent in paths and paths[parent]['kind'] == 'directory', 'INVENTORY_PARENT_CLOSURE')
    return value


class CaptureWriter:
    """Exclusive module-owned original; no fileno or destructive cleanup API.

    Integration must deliver bytes from a newly completed native capture or
    newly serialized samples. It must label available partial output honestly.
    This API cannot authenticate the origin of bytes supplied by a dishonest
    caller. It refuses decoded-legacy origin labels and never reads gzip.
    """
    def __init__(self, batch, binding):
        self.batch, self.binding = batch, decode(canonical(binding))
        self._binding_raw = canonical(self.binding)
        validate_binding(self.binding, batch.run)
        self.id = uuid.uuid4().hex
        self.name = self.id + '.raw'
        batch._live()
        self.fd = os.open(self.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=batch.original_fd)
        self.size, self.hashing, self.closed = 0, hashlib.sha256(), False
        self.original = None

    def write(self, raw):
        self.batch._live()
        need(not self.closed and type(raw) is bytes and len(raw) <= CHUNK, 'CAPTURE_WRITE_TYPE_OR_STATE')
        need(self.size + len(raw) <= MAX_ORIGINAL and self.batch.original_bytes + len(raw) <= MAX_BATCH_RAW,
             'ORIGINAL_CAPTURE_BOUND')
        self.batch._admit(len(raw) + self.batch.budget.allocation_unit)
        self._path_binding()
        try:
            _write_all(self.fd, raw)
            self.hashing.update(raw)
            self.size += len(raw)
            self.batch.original_bytes += len(raw)
        except BaseException:
            self.batch.failed = True
            raise

    def close(self):
        need(not self.closed and self.fd is not None, 'CAPTURE_ALREADY_CLOSED')
        self.batch._live()
        self._path_binding()
        try:
            os.fsync(self.fd)
            _file(os.fstat(self.fd))
        finally:
            fd,self.fd = self.fd,None
            store._release_descriptors((fd,))
        self.closed = True
        self.batch._live()
        os.fsync(self.batch.original_fd)
        size, digest_value, identity = _hash(self.batch.original_fd, self.name, MAX_ORIGINAL)
        need(size == self.size and digest_value == self.hashing.hexdigest(), 'CLOSED_CAPTURE_READBACK')
        self.original = {'path': 'originals/' + self.name, 'bytes': size,
                         'sha256': digest_value, 'identity': identity}
        return self.id

    def _path_binding(self):
        self.batch._live()
        held = os.fstat(self.fd)
        current = os.stat(self.name, dir_fd=self.batch.original_fd, follow_symlinks=False)
        _file(held)
        _file(current)
        need(_signature(held) == _signature(current), 'LIVE_CAPTURE_PATH_REPLACED')


class Batch:
    """One bounded immutable catalog, not an entire5400-cell execution index."""
    def __init__(self, root, run, budget):
        primitive_contract()
        validate_run(run)
        need(type(budget) is Budget, 'EXACT_BUDGET_TYPE')
        self.budget = budget.validate()
        self.root = Path(root)
        self.fd = None
        self.original_fd = self.shards_fd = None
        self.writers, self.original_bytes, self.failed, self.published = [], 0, False, False
        try:
            self.fd = _root(self.root)
            self.run = decode(canonical(run))
            self._run_raw = canonical(self.run)
            self.catalog_id = uuid.uuid4().hex
            import fcntl
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            geometry = os.fstatvfs(self.fd)
            need(0 < geometry.f_frsize <= budget.allocation_unit, 'ALLOCATION_UNIT_NOT_ADMITTED')
            # Existing roots are not resumed, adopted, reset or overwritten.
            with os.scandir(self.fd) as entries:
                need(next(entries, None) is None, 'EXCLUSIVE_EMPTY_BATCH_ROOT_REQUIRED')
            self._admit(4 * budget.allocation_unit)
            for name in ('originals', 'shards'):
                os.mkdir(name, 0o700, dir_fd=self.fd)
            os.fsync(self.fd)
            self.original_fd = _dir(self.fd, 'originals')
            self.shards_fd = _dir(self.fd, 'shards')
        except BaseException:
            self.release()
            raise

    def _live(self):
        need(self.fd is not None and not self.failed and not self.published, 'LIVE_UNFAILED_BATCH_REQUIRED')
        need(canonical(self.run) == self._run_raw, 'IMMUTABLE_RUN_BINDING_CHANGED')
        other = _root(self.root)
        try:
            need((os.fstat(other).st_dev, os.fstat(other).st_ino) ==
                 (os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino), 'BATCH_ROOT_REPLACED')
        finally:
            store._release_descriptors((other,))
        for name, held in (('originals', self.original_fd), ('shards', self.shards_fd)):
            need(held is not None, 'HELD_CHILD_DESCRIPTOR_REQUIRED')
            current = _dir(self.fd, name)
            try:
                _directory(os.fstat(held))
                need((os.fstat(current).st_dev, os.fstat(current).st_ino) ==
                     (os.fstat(held).st_dev, os.fstat(held).st_ino),
                     'BATCH_DESCENDANT_REPLACED')
            finally:
                store._release_descriptors((current,))

    def _admit(self, pending):
        integer(pending, 0, MAX_LAYER)
        _, used = _inventory(self.fd, self.budget.allocation_unit, content=False)
        need(used + pending <= self.budget.layer_allowance_bytes, 'LAYER_ALLOCATION_RESERVATION_REFUSED')
        return used

    def capture(self, binding):
        self._live()
        need(len(self.writers) < MAX_REFERENCES, 'REFERENCE_COUNT_BOUND')
        validate_binding(binding, self.run)
        validate_binding_set([writer.binding for writer in self.writers] + [binding], self.run)
        self._admit(2 * self.budget.allocation_unit)
        writer = CaptureWriter(self, binding)
        self.writers.append(writer)
        return writer

    def _chunk_plan(self, encoding):
        refs, groups, current = [], [], []
        count = 0
        for writer in self.writers:
            need(writer.closed and writer.original is not None, 'ALL_ORIGINAL_WRITERS_CLOSED_FIRST')
            need(canonical(writer.binding) == writer._binding_raw, 'IMMUTABLE_CAPTURE_BINDING_CHANGED')
            size, digest_value, identity = _hash(self.original_fd, writer.name, MAX_ORIGINAL)
            need(same(writer.original, {'path': 'originals/' + writer.name, 'bytes': size,
                                      'sha256': digest_value, 'identity': identity}), 'ORIGINAL_SEAL_CHANGED')
            fd, before = _open(self.original_fd, writer.name)
            chunks, offset, h = [], 0, hashlib.sha256()
            try:
                for index in range(max(1, (size + CHUNK - 1) // CHUNK)):
                    length = min(CHUNK, size - offset)
                    raw = bytearray()
                    while len(raw) < length:
                        part = os.read(fd, length - len(raw))
                        need(bool(part), 'CHUNK_ORIGINAL_SHORT_READ')
                        raw.extend(part)
                    raw = bytes(raw)
                    h.update(raw)
                    if not current:
                        need(len(groups) < MAX_TRANSACTIONS, 'TRANSACTION_COUNT_BOUND')
                        shard = 'shards/s%04d' % (len(groups) // 32)
                        transaction = uuid.uuid4().hex
                    chunk = {'index': index, 'offset': offset, 'bytes': length, 'sha256': sha(raw),
                             'shard': shard, 'transaction': transaction,
                             'member': 'm%08d' % count, 'encoding': encoding}
                    chunks.append(chunk)
                    current.append((writer, chunk))
                    offset += length
                    count += 1
                    need(count <= MAX_CHUNKS, 'CHUNK_COUNT_BOUND')
                    if len(current) == TX_MEMBERS:
                        groups.append(current)
                        current = []
                need(os.read(fd, 1) == b'' and h.hexdigest() == digest_value and
                     _signature(os.fstat(fd)) == _signature(before), 'CHUNK_ORIGINAL_COMPLETE_IDENTITY')
            finally:
                store._release_descriptors((fd,))
            refs.append({'format': FORMAT, 'id': writer.id, 'binding': writer.binding,
                         'original': writer.original, 'chunks': chunks, 'writers_closed': True})
        if current:
            groups.append(current)
        need(bool(refs), 'NONEMPTY_CATALOG')
        return refs, groups

    def publish(self, *, encoding='xz', synthetic_hook=None):
        self._live()
        need(type(encoding) is str and encoding in ('identity', 'xz') and
             (synthetic_hook is None or callable(synthetic_hook)), 'PUBLICATION_OPTIONS')
        need(all(writer.closed and writer.original is not None for writer in self.writers),
             'ALL_ORIGINAL_WRITERS_CLOSED_FIRST')
        try:
            refs, groups = self._chunk_plan(encoding)
            transactions = []
            for group in groups:
                self._live()
                first = group[0][1]
                shard_name = first['shard'].split('/')[1]
                shard_path = self.root / 'shards' / shard_name
                members = tuple(store.Member(chunk['member'], chunk['bytes'], chunk['sha256'], chunk['encoding'])
                                for _, chunk in group)
                plan = store.Plan(16 << 20, self.budget.allocation_unit, 4096)
                reserve = store.reservation(members, plan)
                try:
                    existing_shard = _dir(self.shards_fd, shard_name)
                except FileNotFoundError:
                    new_shard = True
                else:
                    store._release_descriptors((existing_shard,))
                    new_shard = False
                # Admit BEFORE mkdir: existing captures/catalogs/shards/partials,
                # new shard directory+parent entry, transaction slots/control
                # metadata, stage+packed overlap, and both catalog copies.
                directory_growth = 4 * self.budget.allocation_unit if new_shard else 0
                self._admit(reserve['required'] + 2 * MAX_CATALOG +
                            64 * self.budget.allocation_unit + directory_growth)
                self._live()
                if new_shard:
                    os.mkdir(shard_name, 0o700, dir_fd=self.shards_fd)
                    os.fsync(self.shards_fd)
                shard_fd = _dir(self.shards_fd, shard_name)
                store._release_descriptors((shard_fd,))
                handle = None
                try:
                    self._live()
                    handle = store.begin(shard_path, self.run['source'], first['transaction'], members, plan)
                    for writer, chunk in group:
                        self._live()
                        fd, before = _open(self.original_fd, writer.name)
                        try:
                            os.lseek(fd, chunk['offset'], os.SEEK_SET)
                            data = bytearray()
                            while len(data) < chunk['bytes']:
                                part = os.read(fd, chunk['bytes'] - len(data))
                                need(bool(part), 'STAGE_ORIGINAL_SHORT_READ')
                                data.extend(part)
                            need(_signature(before) == writer.original['identity'] and
                                 _signature(os.fstat(fd)) == _signature(before), 'STAGE_ORIGINAL_IDENTITY')
                        finally:
                            store._release_descriptors((fd,))
                        self._live()
                        handle.stage(chunk['member'], bytes(data))
                    self._live()
                    handle.finalize()
                    self._live()
                    handle.close()
                finally:
                    if handle is not None:
                        handle.release()  # Descriptors only; never retirement.
                # Independent primitive restore is compared byte-for-byte with
                # the still-retained module-owned original, not merely a hash.
                for writer, chunk in group:
                    restored = store.restore(shard_path, self.run['source'], chunk['transaction'], chunk['member'])
                    fd, before = _open(self.original_fd, writer.name)
                    try:
                        os.lseek(fd, chunk['offset'], os.SEEK_SET)
                        data = bytearray()
                        while len(data) < chunk['bytes']:
                            part = os.read(fd, chunk['bytes'] - len(data))
                            need(bool(part), 'ROUNDTRIP_ORIGINAL_SHORT_READ')
                            data.extend(part)
                        need(restored == bytes(data) and len(restored) == chunk['bytes'] and
                             sha(restored) == chunk['sha256'] and _signature(before) == writer.original['identity'] and
                             _signature(os.fstat(fd)) == _signature(before), 'RESTORED_EXACT_ORIGINAL_ROUNDTRIP')
                    finally:
                        store._release_descriptors((fd,))
                tx_root = _root(shard_path)
                tx_fd = None
                try:
                    tx_fd = _dir(tx_root, 'txn-' + first['transaction'])
                    controls = {key: sha(_read(tx_fd, filename, 65536)) for key, filename in (
                        ('declaration_sha256', 'transaction.json'), ('manifest_sha256', 'manifest.json'),
                        ('commit_sha256', 'commit.json'), ('closed_sha256', 'closed.json'))}
                finally:
                    store._release_descriptors((tx_fd, tx_root))
                transactions.append({'shard': first['shard'], 'transaction': first['transaction'],
                    'members': sorted([{'name': m.name, 'bytes': m.size, 'sha256': m.sha256,
                                        'encoding': m.encoding} for m in members], key=lambda m: m['name']),
                    **controls})
            inventory, _ = _inventory(self.fd, self.budget.allocation_unit)
            need(len(inventory) + 2 <= MAX_TREE_ENTRIES, 'CATALOG_ENTRY_HEADROOM')
            value = {'version': 2, 'format': CATALOG_FORMAT, 'catalog_id': self.catalog_id,
                     'run': self.run, 'references': refs, 'transactions': transactions,
                     'inventory': inventory,
                     'retirement': 'unsupported-retain-all-original-and-primitive-staging',
                     'scope': 'storage-only-no-scientific-quota-or-release-qualification'}
            validate_catalog(value)
            raw = canonical(value)
            need(len(raw) <= MAX_CATALOG, 'CATALOG_SERIALIZED_BOUND')
            self._admit(2 * len(raw) + 4 * self.budget.allocation_unit)
            for name in ('catalog.partial', 'catalog.json'):
                self._live()
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=self.fd)
                try:
                    _write_all(fd, raw)
                    os.fsync(fd)
                finally:
                    store._release_descriptors((fd,))
                need(_read(self.fd, name, MAX_CATALOG) == raw, 'CATALOG_PUBLICATION_READBACK')
                os.fsync(self.fd)
                if synthetic_hook is not None:
                    synthetic_hook('after_' + name.replace('.', '_') + '_fsync')
                if name == 'catalog.partial':
                    # Persist the complete pre-existing root/ancestor chain
                    # BEFORE the exclusive final catalog entry can appear.
                    _sync_ancestors(self.root)
            _sync_ancestors(self.root)
            # Prove complete content closure after both durable publications.
            observed, _ = _inventory(self.fd, self.budget.allocation_unit, exclude_catalog=True)
            need(same(observed, inventory), 'CATALOG_TREE_CHANGED_DURING_PUBLICATION')
            self.published = True
            return {'format': CATALOG_FORMAT, 'catalog_id': self.catalog_id,
                    'catalog_sha256': sha(raw), 'catalog_bytes': len(raw),
                    'root': str(self.root), 'references': len(refs),
                    'original_bytes': self.original_bytes, 'retirement_performed': False,
                    'scientific_or_quota_qualification': False}
        except BaseException:
            self.failed = True
            raise

    def retire(self, *args, **kwargs):
        raise Refusal('RETIREMENT_UNSUPPORTED_RETAIN_CALLER_ORIGINALS_AND_PRIMITIVE_STAGING')

    def release(self):
        # Even failed/partial original files stay on disk. Ownership is consumed
        # before any attempt: a close error never authorizes retrying an FD.
        fds = []
        for writer in self.writers:
            if not writer.closed:
                fds.append(writer.fd)
                writer.closed = True
            writer.fd = None
        for attribute in ('original_fd', 'shards_fd', 'fd'):
            fds.append(getattr(self, attribute, None))
            setattr(self, attribute, None)
        store._release_descriptors(fds)


class Resolver:
    """Strict new-v1 resolver. Legacy gzip remains on its unchanged old route."""
    def __init__(self, root, expected_catalog_sha256, expected_run):
        primitive_contract()
        digest(expected_catalog_sha256)
        validate_run(expected_run)
        self.root = Path(root)
        self.fd = _root(self.root)
        try:
            raw = _read(self.fd, 'catalog.json', MAX_CATALOG)
            need(sha(raw) == expected_catalog_sha256 and
                 _read(self.fd, 'catalog.partial', MAX_CATALOG) == raw, 'DURABLE_CATALOG_PAIR_BINDING')
            self.catalog = validate_catalog(decode(raw))
            self.catalog_sha256 = expected_catalog_sha256
            self.catalog_bytes = len(raw)
            need(same(self.catalog['run'], expected_run), 'TRUSTED_EXPECTED_RUN_BINDING')
            self._closure()
        except BaseException:
            self.release()
            raise

    def _closure(self):
        need(sha(canonical(self.catalog)) == self.catalog_sha256, 'IMMUTABLE_RESOLVER_CATALOG_CHANGED')
        catalog_raw = _read(self.fd, 'catalog.json', MAX_CATALOG)
        need(len(catalog_raw) == self.catalog_bytes and sha(catalog_raw) == self.catalog_sha256 and
             _read(self.fd, 'catalog.partial', MAX_CATALOG) == catalog_raw,
             'CATALOG_PAIR_CHANGED')
        current = _root(self.root)
        try:
            need((os.fstat(current).st_dev, os.fstat(current).st_ino) ==
                 (os.fstat(self.fd).st_dev, os.fstat(self.fd).st_ino), 'RESOLVER_ROOT_REPLACED')
        finally:
            store._release_descriptors((current,))
        observed, _ = _inventory(self.fd, 4096, exclude_catalog=True)
        need(same(portable_inventory(observed), portable_inventory(self.catalog['inventory'])),
             'EVERY_STORE_MEMBER_STILL_EXACT')
        shards = {tx['shard'] for tx in self.catalog['transactions']}
        for shard in shards:
            report = store.recover(self.root / shard)
            need(report.get('state') == 'READ_ONLY_RECOVERY_REPORT' and
                 report.get('all_root_entries_reported') is True, 'ROOT_RECOVERY_COMPLETE')
            expected = {'txn-' + tx['transaction'] for tx in self.catalog['transactions'] if tx['shard'] == shard}
            actual = {row['name'] for row in report['transactions']}
            need(actual == expected and all(row.get('committed_accepted') is True and
                 row.get('inventory_complete') is True and not row.get('missing_stage_members') and
                 not row.get('corrupt_stage_members') for row in report['transactions']),
                 'EVERY_TRANSACTION_CLOSED_AND_COMPLETE')
        for tx in self.catalog['transactions']:
            parent, name = _at(self.fd, tx['shard'] + '/txn-' + tx['transaction'] + '/transaction.json')
            try:
                declared = decode(_read(parent, name, 65536))
            finally:
                store._release_descriptors((parent,))
            expected_members = [{'name': item['name'], 'size': item['bytes'],
                                 'sha256': item['sha256'], 'encoding': item['encoding']}
                                for item in tx['members']]
            need(declared.get('source') == self.catalog['run']['source'] and
                 declared.get('transaction') == tx['transaction'] and
                 declared.get('protocol') == 'caller-raw-originals-v1' and
                 same(declared.get('members'), expected_members),
                 'EXACT_CATALOG_TO_PRIMITIVE_DECLARATION')

    def iter_original(self, reference_id, expected_binding):
        ident(reference_id)
        validate_binding(expected_binding, self.catalog['run'])
        need(self.fd is not None, 'RESOLVER_RELEASED')
        self._closure()
        matches = [ref for ref in self.catalog['references'] if ref['id'] == reference_id]
        need(len(matches) == 1 and same(matches[0]['binding'], expected_binding), 'TRUSTED_REFERENCE_BINDING')
        ref = matches[0]
        parent, name = _at(self.fd, ref['original']['path'])
        original_fd = None
        try:
            original_fd, before = _open(parent, name)
            # Historical IDs remain catalog provenance; a transported copy
            # must instead match current live type/owner/unique identity,
            # whole original bytes/SHA, and stable FD/path during this read.
            need(before.st_size == ref['original']['bytes'], 'CURRENT_ORIGINAL_SIZE_BINDING')
            total, h = 0, hashlib.sha256()
            for chunk in ref['chunks']:
                restored = store.restore(self.root / chunk['shard'], self.catalog['run']['source'],
                                         chunk['transaction'], chunk['member'])
                data = bytearray()
                while len(data) < chunk['bytes']:
                    part = os.read(original_fd, chunk['bytes'] - len(data))
                    need(bool(part), 'RESOLVER_ORIGINAL_SHORT_READ')
                    data.extend(part)
                need(restored == bytes(data) and len(restored) == chunk['bytes'] and
                     sha(restored) == chunk['sha256'], 'RESTORED_ORIGINAL_BYTES_LENGTH_SHA')
                total += len(restored)
                h.update(restored)
                yield restored
            need(os.read(original_fd, 1) == b'' and total == ref['original']['bytes'] and
                 h.hexdigest() == ref['original']['sha256'] and
                 _signature(os.fstat(original_fd)) == _signature(before) and
                 _signature(os.stat(name, dir_fd=parent, follow_symlinks=False)) == _signature(before),
                 'COMPLETE_RESOLVED_ORIGINAL')
            self._closure()
        finally:
            store._release_descriptors((original_fd, parent))

    def read_original(self, reference_id, expected_binding, maximum):
        integer(maximum, 0, MAX_ORIGINAL)
        matches = [ref for ref in self.catalog['references'] if ref['id'] == reference_id]
        need(len(matches) == 1 and matches[0]['original']['bytes'] <= maximum, 'CALLER_READ_BOUND')
        return b''.join(self.iter_original(reference_id, expected_binding))

    def retire(self, *args, **kwargs):
        raise Refusal('RETIREMENT_UNSUPPORTED_RETAIN_EVERY_ORIGINAL')

    def release(self):
        fd, self.fd = self.fd, None
        store._release_descriptors((fd,))

def validate_reference(reference):
    """Portable selector; trusted expected run/binding remain separate inputs."""
    exact(reference, ('format', 'store', 'catalog', 'catalog_sha256', 'catalog_bytes',
                      'reference_id', 'run_sha256', 'binding_sha256', 'bytes', 'sha256'))
    need(reference['format'] == FORMAT and reference['catalog'] == 'catalog.json', 'EXTERNAL_REFERENCE_VERSION')
    relative(reference['store'])
    digest(reference['catalog_sha256'])
    integer(reference['catalog_bytes'], 1, MAX_CATALOG)
    ident(reference['reference_id'])
    digest(reference['run_sha256'])
    digest(reference['binding_sha256'])
    integer(reference['bytes'], 0, MAX_ORIGINAL)
    digest(reference['sha256'])
    return reference


def reference_for(resolver, reference_id, expected_binding, store_relative):
    """Create a source-bound selector only from an already checked catalog."""
    relative(store_relative)
    resolver._closure()
    validate_binding(expected_binding, resolver.catalog['run'])
    matched = [ref for ref in resolver.catalog['references'] if ref['id'] == reference_id]
    need(len(matched) == 1 and same(matched[0]['binding'], expected_binding), 'SELECTOR_TRUSTED_BINDING')
    original = matched[0]['original']
    return validate_reference({'format': FORMAT, 'store': store_relative, 'catalog': 'catalog.json',
        'catalog_sha256': resolver.catalog_sha256, 'catalog_bytes': resolver.catalog_bytes,
        'reference_id': reference_id, 'run_sha256': sha(canonical(resolver.catalog['run'])),
        'binding_sha256': sha(canonical(expected_binding)), 'bytes': original['bytes'],
        'sha256': original['sha256']})


def resolve_reference(base, reference, expected_run, expected_binding, maximum):
    """Bounded full read from an explicit owned base and portable store path.

    No basename guessing, archive extraction, gzip decoding, path resolution
    through links, environment defaults or migration from historical bytes.
    """
    validate_reference(reference)
    validate_run(expected_run)
    validate_binding(expected_binding, expected_run)
    integer(maximum, 0, MAX_ORIGINAL)
    need(reference['run_sha256'] == sha(canonical(expected_run)) and
         reference['binding_sha256'] == sha(canonical(expected_binding)) and
         reference['bytes'] <= maximum, 'EXTERNAL_TRUSTED_IDENTITY_AND_READ_BOUND')
    base = Path(base)
    base_fd = _root(base)
    target = None
    resolver = None
    try:
        target = os.dup(base_fd)
        for part in relative(reference['store']):
            child = _dir(target, part)
            parent, target = target, child
            store._release_descriptors((parent,))
        resolver = Resolver(base.joinpath(*relative(reference['store'])),
                            reference['catalog_sha256'], expected_run)
        need((os.fstat(target).st_dev, os.fstat(target).st_ino) ==
             (os.fstat(resolver.fd).st_dev, os.fstat(resolver.fd).st_ino) and
             resolver.catalog_bytes == reference['catalog_bytes'], 'OWNED_STORE_SELECTOR_IDENTITY')
        raw = resolver.read_original(reference['reference_id'], expected_binding, maximum)
        need(len(raw) == reference['bytes'] and sha(raw) == reference['sha256'], 'EXTERNAL_ORIGINAL_LENGTH_SHA')
        current = _root(base)
        try:
            need((os.fstat(current).st_dev, os.fstat(current).st_ino) ==
                 (os.fstat(base_fd).st_dev, os.fstat(base_fd).st_ino), 'OWNED_BASE_REPLACED')
        finally:
            store._release_descriptors((current,))
        return raw
    finally:
        store._release_descriptors((target, base_fd),
            before=(resolver.release,) if resolver is not None else ())
