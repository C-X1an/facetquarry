"""Source-only Linux supervisor and neutral complete-failure collector.

No fixture is executable data. A neutral blob is never extracted or imported.
The independently pinned caller must verify this file BEFORE starting Python.
"""
import sys

if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
    raise SystemExit('LAUNCH_WITH_PYTHON_MINUS_I_MINUS_S_MINUS_B')

import argparse
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
if os.name == 'posix':
    import resource
else:
    # Portable injected-error controls may import pure helpers. Every real CLI
    # action still calls require_linux() before touching a lifecycle resource.
    resource = None
import selectors
import signal
import stat
import struct
import subprocess
import time


FORMAT = 'scientific-posix-complete-failure-copy-v1'
ADMISSION_FORMAT = 'scientific-posix-lifecycle-admission-v1'
PREPARE_FORMAT = 'scientific-posix-quota-prepare-v1'
STATUS = 'AUTHORIZED_FOR_REVIEWED_SYNTHETIC_POSIX_ONLY'
SPI_PROFILE = 'scientific-posix-integration-retain-all-v2'
SPI_CONTEXT = 'explicit-owned-quota-posix-v2'
IMAGE_BYTES = 268_435_456
MEMORY_BYTES = 536_870_912
SOURCE_LOGICAL = 100_663_296
SOURCE_BYTES = 167_772_160
SOURCE_ENTRIES = 4096
SPI_BYTES = 855_638_016
SPI_ENTRIES = 20608
OVERHEAD_BYTES = 16_777_216
ON_VOLUME_REQUIRED_BYTES = 201_326_592
CONTROL_TESTS = 22
JOB_BYTES = IMAGE_BYTES + 4 * SOURCE_BYTES + 2 * IMAGE_BYTES + OVERHEAD_BYTES
EXTRA_OVER_SPI = JOB_BYTES - SPI_BYTES
UNIT = 8192
FILE_BYTES = 8 << 20
DOCUMENT_BYTES = 256 << 10
PACKET_BYTES = 16 << 20
HEADER_BYTES = 2048
PATH_BYTES = 512
DEPTH = 16
LOG_BYTES = 512 << 10
TOOL_LOG_BYTES = 64 << 10
PROBE_LOG_BYTES = 16 << 10
IO_BYTES = 65536
CHILD_SECONDS = 120
COPY_SECONDS = 180
TOOL_SECONDS = 90
ERRORS = 64
ERROR_RECORD_BYTES = 2048
ERROR_LIST_BYTES = 16384
MAGIC = b'FQNEUTRAL1\n'
BLOB_BYTES = SOURCE_LOGICAL + (SOURCE_ENTRIES + 1) * (HEADER_BYTES + 4) + len(MAGIC)
MANIFEST_NAME = 'LIFECYCLE_SOURCE_MANIFEST.json'
SPI_MANIFEST = 'POSIX_SOURCE_MANIFEST.json'
SPI_NAMES = frozenset({
    'run_scientific_posix_integration.py', 'scientific_posix_integration.py',
    'scientific_capture_protocol.py', 'scientific_raw_reference_v2.py',
    'scientific_execution_registry.py', 'scientific_registry_publication.py',
    'scientific_registry_transport.py', 'scientific_analyzer_adapter.py',
    'raw_member_store.py', 'README.md', 'BOUNDS.md', 'ADMISSION.template.json',
})
LIFE_NAMES = frozenset({
    'scientific_posix_lifecycle.py', 'test_scientific_posix_lifecycle.py',
    'README.md', 'BOUNDS.md', 'ADMISSION.template.json', 'PREPARE.template.json',
})
INTERRUPTS = []


def need(condition, code):
    if not condition:
        raise RuntimeError(code)


def integer(value, minimum, maximum):
    need(type(value) is int and minimum <= value <= maximum, 'TYPED_BOUNDED_INTEGER')
    return value


def sha(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) and value != '0' * 64,
         'EXTERNAL_NONZERO_SHA256_REQUIRED')
    return value


def error_record(error, operation):
    """Bounded transport data, retaining group context and individual leaves."""
    def clip(value, maximum):
        return str(value).encode('utf-8', 'replace')[:maximum].decode('utf-8', 'ignore')
    def details(value, message_bytes):
        number = getattr(value, 'errno', None)
        name, message = type(value).__name__, str(value)
        short_name, short_message = clip(name, 48), clip(message, message_bytes)
        return {'type': short_name, 'type_truncated': short_name != name,
                'errno': number if type(number) is int and -(1 << 31) <= number < (1 << 31) else None,
                'message': short_message, 'message_truncated': short_message != message}
    record = {'operation': clip(operation, 80), **details(error, 160), 'details_truncated': False}
    record['details_truncated'] = record['message_truncated'] or record['type_truncated']
    if isinstance(error, BaseExceptionGroup):
        contexts, leaves, pending, nodes = [], [], [(error, ())], 0
        while pending:
            value, path = pending.pop()
            if nodes >= 32 or len(path) > 8:
                record['details_truncated'] = True
                break
            nodes += 1
            if isinstance(value, BaseExceptionGroup):
                context = {'path': list(path), 'type': clip(type(value).__name__, 48),
                           'message': clip(value.message, 64)}
                context['type_truncated'] = context['type'] != type(value).__name__
                context['message_truncated'] = context['message'] != value.message
                contexts.append(context)
                record['details_truncated'] |= context['message_truncated'] or context['type_truncated']
                children = value.exceptions
                if len(children) > 16:
                    record['details_truncated'] = True
                for index in range(min(len(children), 16) - 1, -1, -1):
                    pending.append((children[index], path + (index,)))
            elif len(leaves) < 16:
                leaf = {'path': list(path), **details(value, 96)}
                leaves.append(leaf)
                record['details_truncated'] |= leaf['message_truncated'] or leaf['type_truncated']
            else:
                record['details_truncated'] = True
                break
        record.update(group_context=contexts, leaf_errors=leaves)
    while len(json_bytes(record)) > ERROR_RECORD_BYTES:
        record['details_truncated'] = True
        if record.get('leaf_errors'):
            record['leaf_errors'].pop()
        elif record.get('group_context'):
            record['group_context'].pop()
        elif len(record['message']) > 16:
            record['message'] = record['message'][:len(record['message']) // 2]
        elif len(record['operation']) > 16:
            record['operation'] = record['operation'][:len(record['operation']) // 2]
        else:
            record['type'] = record['type'][:16]
    return record


def add_error(errors, error, operation):
    if errors and errors[-1].get('operation') == 'error-overflow':
        errors[-1]['omitted_errors_at_least'] = min((1 << 63) - 1, errors[-1]['omitted_errors_at_least'] + 1)
        return
    record = error_record(error, operation)
    overflow = {'operation': 'error-overflow', 'type': 'INCOMPLETE', 'errno': None,
                'message': 'Further exceptions exceed the bounded count or byte budget.',
                'omitted_errors_at_least': 1}
    # Reserve the overflow marker before each append so no earlier record has
    # to be removed to report that subsequent details were omitted.
    if len(errors) < ERRORS and len(json_bytes(errors + [record, overflow])) <= ERROR_LIST_BYTES - 32:
        errors.append(record)
    else:
        errors.append(overflow)


def close_owned(*descriptors):
    """Attempt every distinct descriptor once; retain the active exception."""
    primary = sys.exception()
    failures, seen = [], set()
    for fd in descriptors:
        if fd is None or fd in seen:
            continue
        seen.add(fd)
        try:
            os.close(fd)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise BaseExceptionGroup('EVERY_OWNED_DESCRIPTOR_CLOSE_ATTEMPTED',
                                 ([primary] if primary is not None else []) + failures) from None


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_blocks, info.st_mtime_ns, info.st_ctime_ns)


def explicit_path(value):
    path = Path(value)
    need(path.is_absolute() and len(path.parts) <= 32 and '..' not in path.parts and
         re.fullmatch('/[A-Za-z0-9_./-]{1,1000}', str(path)) and
         all(part not in ('.', '..') and len(part) <= 64 for part in path.parts[1:]),
         'EXPLICIT_BOUNDED_ABSOLUTE_OWNED_PATH')
    return path


def owned_dir(path, *, owner=None, private=True):
    """Open a trusted chain without following links, retaining no ancestors."""
    path = explicit_path(path)
    owner = os.geteuid() if owner is None else owner
    descriptors, final = [], None
    try:
        descriptors.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for index, name in enumerate(path.parts[1:]):
            is_final = index == len(path.parts) - 2
            before = os.stat(name, dir_fd=descriptors[-1], follow_symlinks=False)
            permitted = {0, owner}
            need(stat.S_ISDIR(before.st_mode) and before.st_uid in permitted and
                 before.st_mode & 0o022 == 0 and
                 (not (private and is_final) or
                  (before.st_uid == owner and before.st_mode & 0o077 == 0)),
                 'TRUSTED_OWNED_DIRECTORY_CHAIN_REQUIRED')
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptors[-1])
            descriptors.append(child)
            need(signature(before) == signature(os.fstat(child)) ==
                 signature(os.stat(name, dir_fd=descriptors[-2], follow_symlinks=False)),
                 'DIRECTORY_OPEN_IDENTITY_CHANGED')
        final = descriptors.pop()
        closing, descriptors = descriptors, []
        close_owned(*closing)
        answer, final = final, None
        return answer
    finally:
        close_owned(final, *descriptors)


def read_owned(path, maximum, *, owner=None):
    path = explicit_path(path)
    owner = os.geteuid() if owner is None else owner
    parent = owned_dir(path.parent, owner=owner)
    fd = None
    try:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == owner and
             before.st_nlink == 1 and before.st_mode & 0o077 == 0 and
             0 <= before.st_size <= maximum, 'UNIQUE_PRIVATE_BOUNDED_INPUT')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        need(signature(before) == signature(os.fstat(fd)), 'INPUT_OPEN_IDENTITY_CHANGED')
        pieces, used = [], 0
        while True:
            raw = os.read(fd, min(IO_BYTES, maximum - used + 1))
            if not raw:
                break
            used += len(raw)
            need(used <= maximum, 'INPUT_GREW_BEYOND_BOUND')
            pieces.append(raw)
        need(used == before.st_size and signature(before) == signature(os.fstat(fd)) ==
             signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
             'INPUT_CHANGED_DURING_READ')
        return b''.join(pieces)
    finally:
        close_owned(fd, parent)


def json_load(raw, *, maximum=DOCUMENT_BYTES):
    """Bound lexical extents before json creates decoded containers."""
    need(type(raw) is bytes and len(raw) <= maximum, 'JSON_BYTE_BOUND')
    depth = tokens = string_bytes = 0
    in_string = escaped = False
    for byte in raw:
        if in_string:
            string_bytes += 1
            need(string_bytes <= 8192, 'JSON_STRING_BYTE_BOUND')
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                in_string = False
        elif byte == 34:
            in_string, string_bytes = True, 0
            tokens += 1
        elif byte in (91, 123):
            depth += 1
            tokens += 1
            need(depth <= 24, 'JSON_DEPTH_BOUND')
        elif byte in (93, 125):
            depth -= 1
            need(depth >= 0, 'JSON_NEGATIVE_DEPTH')
        elif byte in (44, 58):
            tokens += 1
        need(tokens <= 32768, 'JSON_TOKEN_BOUND')
    need(not in_string and depth == 0, 'JSON_LEXICAL_COMPLETION')

    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'JSON_DUPLICATE_KEY')
            value[key] = item
        return value

    def number(text):
        need(len(text) <= 20, 'JSON_INTEGER_TOKEN_BOUND')
        return integer(int(text), -(1 << 63), (1 << 63) - 1)

    def refuse(_):
        raise RuntimeError('JSON_FLOAT_OR_NONFINITE_REFUSED')

    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_int=number,
                      parse_float=refuse, parse_constant=refuse)


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                       allow_nan=False) + '\n').encode('ascii')


def write_all(fd, raw):
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        need(count > 0, 'ZERO_WRITE')
        view = view[count:]


def create_file(path, raw, *, owner=None, maximum=DOCUMENT_BYTES):
    path = explicit_path(path)
    need(len(raw) <= maximum, 'OUTPUT_DOCUMENT_BOUND')
    parent = owned_dir(path.parent, owner=owner)
    fd = None
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        write_all(fd, raw)
        os.fsync(fd)
        if owner is not None and owner != os.geteuid():
            os.fchown(fd, owner, -1)
        os.fsync(parent)
    finally:
        close_owned(fd, parent)


def new_dir(path, *, owner=None, gid=None):
    path = explicit_path(path)
    parent = owned_dir(path.parent, owner=owner)
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        if owner is not None:
            os.chown(path.name, owner, -1 if gid is None else gid,
                     dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
    finally:
        close_owned(parent)


def hash_file(path, maximum, *, owner=None, exact=None):
    """Stream a private regular file; never allocate the whole large image."""
    path = explicit_path(path)
    owner = os.geteuid() if owner is None else owner
    parent = owned_dir(path.parent, owner=owner)
    fd = None
    try:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             before.st_uid == owner and before.st_mode & 0o077 == 0 and
             0 <= before.st_size <= maximum and (exact is None or before.st_size == exact),
             'PRIVATE_STREAM_INPUT_BOUND')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        need(signature(before) == signature(os.fstat(fd)), 'HASH_OPEN_IDENTITY_CHANGED')
        result, size, started = hashlib.sha256(), 0, time.monotonic()
        while True:
            need(time.monotonic() - started <= COPY_SECONDS, 'HASH_STREAM_WALL_BOUND')
            raw = os.read(fd, IO_BYTES)
            if not raw:
                break
            size += len(raw)
            need(size <= maximum, 'HASH_STREAM_BOUND')
            result.update(raw)
        need(size == before.st_size and signature(before) == signature(os.fstat(fd)) ==
             signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
             'HASH_INPUT_CHANGED')
        return {'bytes': size, 'sha256': result.hexdigest(), 'identity': list(signature(before))}
    finally:
        close_owned(fd, parent)


def pinned_document(path, expected_sha, *, owner=None):
    sha(expected_sha)
    raw = read_owned(path, DOCUMENT_BYTES, owner=owner)
    need(hashlib.sha256(raw).hexdigest() == expected_sha, 'EXTERNAL_DOCUMENT_PIN_MISMATCH')
    value = json_load(raw)
    need(type(value) is dict, 'DOCUMENT_OBJECT_REQUIRED')
    return value, raw


def check_packet(directory, manifest_name, expected_sha, names, *, owner=None):
    directory = explicit_path(directory)
    value, raw = pinned_document(directory / manifest_name, expected_sha, owner=owner)
    rows = value.get('packet_files')
    need(type(rows) is list and len(rows) == len(names), 'EXACT_PACKET_ROW_COUNT')
    found, total, observed = set(), len(raw), []
    for row in rows:
        need(type(row) is dict and set(row) == {'origin', 'name', 'bytes', 'sha256'} and
             row['name'] in names and row['name'] not in found and type(row['origin']) is str and
             len(row['origin']) <= 1024, 'EXACT_FLAT_PIN_ROW')
        integer(row['bytes'], 1, PACKET_BYTES)
        sha(row['sha256'])
        result = hash_file(directory / row['name'], row['bytes'], owner=owner, exact=row['bytes'])
        need(result['sha256'] == row['sha256'], 'COMPLETE_SOURCE_PIN_MISMATCH')
        total += row['bytes']
        need(total <= PACKET_BYTES, 'TOTAL_SOURCE_PACKET_BOUND')
        found.add(row['name'])
        observed.append({'name': row['name'], **result})
    fd = owned_dir(directory, owner=owner)
    try:
        observed_names = set()
        with os.scandir(fd) as iterator:
            for entry in iterator:
                need(len(observed_names) < len(names) + 1, 'EXTRA_PACKET_ENTRIES')
                observed_names.add(entry.name)
        need(found == names and observed_names == names | {manifest_name},
             'EXACT_PACKET_DIRECTORY_REQUIRED')
    finally:
        close_owned(fd)
    return value, raw, observed


def require_linux():
    need(sys.version_info >= (3, 11) and sys.platform == 'linux' and os.name == 'posix' and
         hasattr(os, 'posix_fallocate') and hasattr(os, 'O_NOFOLLOW') and
         hasattr(os, 'O_DIRECTORY') and os.open in os.supports_dir_fd and
         os.stat in os.supports_dir_fd, 'ACTUAL_SUPPORTED_LINUX_REQUIRED_NO_SKIP')


def check_global(value):
    need(value['profile'] == FORMAT and value['reserved_job_bytes'] == JOB_BYTES and
         value['reserved_job_entries'] == SPI_ENTRIES and value['image_capacity_bytes'] == IMAGE_BYTES and
         value['neutral_copy_equivalents'] == 4 and value['raw_image_copy_equivalents'] == 2 and
         value['control_overhead_bytes'] == OVERHEAD_BYTES and
         value['all_attributable_allocations_admitted'] is True and
         value['no_other_heavy_process'] is True, 'EXACT_COMPLETE_PLACEMENT_ADMISSION')
    for field in ('baseline_excluding_reserve_bytes', 'other_growth_bytes', 'global_reserve_bytes'):
        integer(value[field], 0, 15_000_000_000)
    need(value['global_reserve_bytes'] >= 2_000_000_000 and
         value['baseline_excluding_reserve_bytes'] + value['other_growth_bytes'] +
         value['global_reserve_bytes'] + JOB_BYTES < 12_000_000_000,
         'FRESH_GLOBAL_HEAVY_GROWTH_REFUSED')
    sha(value['fresh_global_inventory_sha256'])


def pin_runtime(row):
    need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'}, 'EXACT_RUNTIME_PIN')
    path = explicit_path(row['path'])
    integer(row['bytes'], 1, 256 << 20)
    sha(row['sha256'])
    parent = owned_dir(path.parent, owner=0, private=False)
    fd = None
    try:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_mode & 0o022 == 0 and
             before.st_size == row['bytes'], 'TRUSTED_INSTALLED_RUNTIME_REQUIRED_NO_DOWNLOAD')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        need(signature(before) == signature(os.fstat(fd)), 'RUNTIME_OPEN_CHANGED')
        result, size, started = hashlib.sha256(), 0, time.monotonic()
        while True:
            need(time.monotonic() - started <= COPY_SECONDS, 'RUNTIME_HASH_WALL_BOUND')
            raw = os.read(fd, IO_BYTES)
            if not raw:
                break
            result.update(raw)
            size += len(raw)
            need(size <= row['bytes'], 'RUNTIME_GROWTH_BOUND')
        need(size == row['bytes'] and result.hexdigest() == row['sha256'] and
             signature(before) == signature(os.fstat(fd)) ==
             signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'RUNTIME_PIN_MISMATCH')
    finally:
        close_owned(fd, parent)
    return str(path)


def clean_environment():
    return {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'}


def child_limits(file_bytes=FILE_BYTES):
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (CHILD_SECONDS, CHILD_SECONDS + 1))


def process_group_gone(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    return False


def stop_group(pgid, sig, errors):
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass
    except BaseException as error:
        add_error(errors, error, 'kill-process-group')


def run_process(command, cwd, log_root, *, seconds=CHILD_SECONDS, memory_limit=True,
                owner=None, file_limit=FILE_BYTES, log_limit=LOG_BYTES):
    """One active child session; hard log caps trigger termination, retaining prefixes."""
    integer(seconds, 1, CHILD_SECONDS)
    integer(file_limit, 1, IMAGE_BYTES)
    integer(log_limit, 1, LOG_BYTES)
    need(memory_limit is True, 'THIS_PROFILE_NEVER_DISABLING_CHILD_LIMITS')
    started = time.monotonic()
    logs, log_fds, errors = {}, [], []
    selector = selectors.DefaultSelector()
    process = None
    reason, term_at, kill_at = None, None, None
    try:
        for name in ('stdout', 'stderr'):
            path = explicit_path(log_root) / (name + '.bin')
            parent = owned_dir(path.parent, owner=owner)
            fd = None
            try:
                fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
                log_fds.append(fd)
            finally:
                close_owned(parent)
            logs[name] = {'fd': fd, 'retained_bytes': 0, 'observed_bytes': 0, 'write_failed': False}
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=str(cwd), env=clean_environment(),
                                   close_fds=True, start_new_session=True,
                                   preexec_fn=(lambda: child_limits(file_limit)) if memory_limit else None)
        for name, pipe in (('stdout', process.stdout), ('stderr', process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if INTERRUPTS and reason is None:
                reason = 'supervisor-interrupted'
            if now - started > seconds and reason is None:
                reason = 'wall-timeout'
            if reason is not None and term_at is None:
                stop_group(process.pid, signal.SIGTERM, errors)
                term_at = now
            if term_at is not None and now - term_at >= 2 and kill_at is None:
                stop_group(process.pid, signal.SIGKILL, errors)
                kill_at = now
            if kill_at is not None and now - kill_at > 8:
                need(process.poll() is not None and not selector.get_map(), 'CHILD_DID_NOT_QUIESCE')
            for key, _ in selector.select(0.05):
                try:
                    raw = os.read(key.fileobj.fileno(), IO_BYTES)
                except BlockingIOError:
                    continue
                if not raw:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                row = logs[key.data]
                row['observed_bytes'] += len(raw)
                keep = raw[:max(0, log_limit - row['retained_bytes'])]
                if keep and not row['write_failed']:
                    try:
                        write_all(row['fd'], keep)
                        row['retained_bytes'] += len(keep)
                    except BaseException as error:
                        row['write_failed'] = True
                        add_error(errors, error, key.data + '-write')
                        reason = reason or 'log-write-failure'
                if row['observed_bytes'] > log_limit:
                    reason = reason or 'log-limit'
        returncode = process.wait(timeout=1)
        if not process_group_gone(process.pid):
            reason = reason or 'descendants-after-leader-exit'
            stop_group(process.pid, signal.SIGKILL, errors)
            deadline = time.monotonic() + 5
            while not process_group_gone(process.pid) and time.monotonic() < deadline:
                time.sleep(0.02)
        quiescent = process_group_gone(process.pid)
        for row in logs.values():
            row['retained_bytes'] = os.fstat(row['fd']).st_size
        return {'command': command, 'pid': process.pid, 'pgid': process.pid, 'returncode': returncode,
                'signal': -returncode if returncode < 0 else None,
                'reason': reason or ('process-exit-zero' if returncode == 0 else 'process-exit-failure'),
                'quiescent': quiescent, 'elapsed_milliseconds': int((time.monotonic() - started) * 1000),
                'limits': {'RLIMIT_AS': MEMORY_BYTES if memory_limit else None,
                           'RLIMIT_FSIZE': file_limit if memory_limit else None,
                           'retained_bytes_per_output_stream': log_limit},
                'logs': {key: {field: value for field, value in row.items() if field != 'fd'}
                         for key, row in logs.items()}, 'errors': errors,
                'ru_maxrss_kib': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}
    except BaseException as primary:
        add_error(errors, primary, 'subprocess-lifecycle-exception')
        if process is not None:
            stop_group(process.pid, signal.SIGKILL, errors)
            try:
                process.wait(timeout=8)
            except BaseException as error:
                add_error(errors, error, 'exception-wait')
        return {'command': command, 'pid': None if process is None else process.pid,
                'pgid': None if process is None else process.pid,
                'returncode': None if process is None else process.poll(), 'signal': None,
                'reason': 'spawn-failure' if process is None else 'subprocess-lifecycle-exception',
                'quiescent': process is None or process_group_gone(process.pid),
                'elapsed_milliseconds': int((time.monotonic() - started) * 1000),
                'limits': {'RLIMIT_AS': MEMORY_BYTES if memory_limit else None,
                           'RLIMIT_FSIZE': file_limit if memory_limit else None,
                           'retained_bytes_per_output_stream': log_limit},
                'logs': {key: {field: value for field, value in row.items() if field != 'fd'}
                         for key, row in logs.items()}, 'errors': errors,
                'ru_maxrss_kib': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}
    finally:
        for fd in log_fds:
            try:
                os.fsync(fd)
            except BaseException as error:
                add_error(errors, error, 'log-fsync-on-every-outcome')
        try:
            selector.close()
        except BaseException as error:
            add_error(errors, error, 'selector-close')
        if process is not None:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:
                    try:
                        pipe.close()
                    except BaseException as error:
                        add_error(errors, error, 'pipe-close')
        try:
            close_owned(*log_fds)
        except BaseException as error:
            add_error(errors, error, 'log-descriptor-close')


def read_kernel(path, maximum=65536):
    """Only caller-fixed proc/sysfs paths; these are evidence, never code."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        pieces, used, started = [], 0, time.monotonic()
        while True:
            need(time.monotonic() - started <= COPY_SECONDS, 'KERNEL_EVIDENCE_WALL_BOUND')
            raw = os.read(fd, min(IO_BYTES, maximum - used + 1))
            if not raw:
                break
            used += len(raw)
            need(used <= maximum, 'KERNEL_EVIDENCE_BOUND')
            pieces.append(raw)
        return b''.join(pieces)
    finally:
        close_owned(fd)


def cgroup_oom_observation():
    """Optional actual kernel counters; a delta is not attribution to this child."""
    try:
        rows = read_kernel('/proc/self/cgroup', 65536).decode('ascii').splitlines()
        matches = [row[3:] for row in rows if row.startswith('0::')]
        need(len(matches) == 1 and matches[0].startswith('/') and
             '..' not in matches[0].split('/') and len(matches[0]) <= 2048,
             'BOUNDED_CGROUP_V2_PATH')
        raw = read_kernel('/sys/fs/cgroup' + matches[0].rstrip('/') + '/memory.events', 4096)
        values = {}
        for line in raw.decode('ascii').splitlines():
            key, count = line.split()
            need(len(values) < 16 and re.fullmatch('[a-z_]{1,40}', key), 'CGROUP_COUNTER_BOUND')
            values[key] = integer(int(count), 0, (1 << 63) - 1)
        return {'available': True, 'counters': values, 'attribution': 'NOT_ESTABLISHED'}
    except BaseException as error:
        return {'available': False, 'observation_error': error_record(error, 'cgroup-memory-events')}


def mount_observation(mount, image, owner):
    mount, image = explicit_path(mount), explicit_path(image)
    rows = []
    for line in read_kernel('/proc/self/mountinfo', 256 << 10).decode('ascii').splitlines():
        fields = line.split(' ')
        if len(fields) >= 10 and fields[4] == str(mount):
            rows.append(fields)
    need(len(rows) == 1, 'EXACT_PRIVATE_MOUNT_REQUIRED')
    row = rows[0]
    divider = row.index('-')
    source, fs_type = row[divider + 2], row[divider + 1]
    need(re.fullmatch('/dev/loop[0-9]{1,5}', source) and fs_type == 'ext4' and row[3] == '/' and
         {'nodev', 'nosuid', 'noexec'}.issubset(set(row[5].split(','))),
         'ACTUAL_EXT4_LOOP_NODEV_NOSUID_NOEXEC_REQUIRED')
    loop = source.rsplit('/', 1)[1]
    block_identity = read_kernel('/sys/block/' + loop + '/dev', 64).decode('ascii').strip()
    device = os.stat(source, follow_symlinks=False)
    need(block_identity == row[2] and stat.S_ISBLK(device.st_mode) and
         '%d:%d' % (os.major(device.st_rdev), os.minor(device.st_rdev)) == block_identity,
         'MOUNTINFO_SYSFS_AND_ACTUAL_BLOCK_DEVICE_IDENTITY_REQUIRED')
    backing = read_kernel('/sys/block/' + loop + '/loop/backing_file', 2048).decode('ascii').strip()
    need(backing in (str(image), str(image).lstrip('/')), 'LOOP_BACKING_IMAGE_PATH_MISMATCH')
    size = int(read_kernel('/sys/block/' + loop + '/size', 64).strip()) * 512
    offset = int(read_kernel('/sys/block/' + loop + '/loop/offset', 64).strip())
    sizelimit = int(read_kernel('/sys/block/' + loop + '/loop/sizelimit', 64).strip())
    need(size == IMAGE_BYTES and offset == 0 and sizelimit in (0, IMAGE_BYTES), 'ACTUAL_LOOP_CAPACITY_REQUIRED')
    parent = owned_dir(image.parent, owner=owner)
    image_fd = volume_fd = None
    try:
        before = os.stat(image.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_nlink == 1 and
             before.st_mode & 0o077 == 0 and before.st_size == IMAGE_BYTES and
             before.st_blocks * 512 >= IMAGE_BYTES, 'FULL_CAPACITY_IMAGE_ALLOCATION_REQUIRED')
        image_fd = os.open(image.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        need(signature(before) == signature(os.fstat(image_fd)), 'IMAGE_OPEN_BINDING')
        volume_fd = owned_dir(mount, owner=owner)
        info, geometry = os.fstat(volume_fd), os.fstatvfs(volume_fd)
        need('%d:%d' % (os.major(info.st_dev), os.minor(info.st_dev)) == row[2] and
             0 < max(geometry.f_frsize, geometry.f_bsize) <= UNIT and
             0 < geometry.f_blocks * geometry.f_frsize <= IMAGE_BYTES,
             'MOUNT_DEVICE_GEOMETRY_AND_CAPACITY_BINDING')
        return {'mount_id': int(row[0]), 'major_minor': row[2], 'source': source,
                'sysfs_block_device': block_identity,
                'filesystem': fs_type, 'mount': str(mount), 'image': str(image),
                'image_identity': [before.st_dev, before.st_ino, before.st_uid, before.st_nlink, before.st_size],
                'image_allocated_bytes': before.st_blocks * 512, 'loop_capacity_bytes': size,
                'filesystem_capacity_bytes': geometry.f_blocks * geometry.f_frsize,
                'allocation_unit_bytes': max(geometry.f_frsize, geometry.f_bsize)}
    finally:
        close_owned(image_fd, volume_fd, parent)


def memory_probe_child():
    need(resource.getrlimit(resource.RLIMIT_AS) == (MEMORY_BYTES, MEMORY_BYTES),
         'ACTUAL_PROBE_RLIMIT_AS_NOT_SET')
    denied = False
    try:
        forbidden = bytearray(MEMORY_BYTES + 1)
        forbidden[0] = 1
    except MemoryError:
        denied = True
    need(denied, 'ACTUAL_MEMORY_ALLOCATION_DENIAL_REQUIRED')
    write_all(1, json_bytes({'format': 'scientific-posix-memory-denial-v1',
                             'limit_bytes': MEMORY_BYTES, 'actual_getrlimit': [MEMORY_BYTES, MEMORY_BYTES],
                             'attempted_bytes': MEMORY_BYTES + 1, 'exception': 'MemoryError',
                             'denial_observed': True,
                             'ru_maxrss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
    return 0


def prepare_quota(value, life_manifest_sha):
    need(os.geteuid() == 0 and value['format'] == PREPARE_FORMAT and
         value['status'] == 'AUTHORIZED_REVIEWED_NEW_QUOTA_PREPARATION_ONLY' and
         value['lifecycle_manifest_sha256'] == life_manifest_sha, 'EXPLICIT_PRIVILEGED_NEW_QUOTA_PREPARATION')
    check_global(value)
    uid = integer(value['owner_uid'], 1, (1 << 31) - 1)
    gid = integer(value['owner_gid'], 1, (1 << 31) - 1)
    job = explicit_path(value['job_root'])
    tools = value['installed_tools']
    need(type(tools) is dict and set(tools) == {'mke2fs', 'mount', 'umount'}, 'EXACT_PREINSTALLED_TOOLS')
    pinned = {name: pin_runtime(row) for name, row in tools.items()}
    # The explicit root MUST be new. No reuse, cleanup, truncation or retry.
    new_dir(job, owner=uid, gid=gid)
    new_dir(job / 'control', owner=uid, gid=gid)
    new_dir(job / 'volume', owner=uid, gid=gid)
    new_dir(job / 'exports', owner=uid, gid=gid)
    image = job / 'quota.img'
    parent = owned_dir(job, owner=uid)
    fd = None
    try:
        fd = os.open(image.name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        os.posix_fallocate(fd, 0, IMAGE_BYTES)
        os.fsync(fd)
        os.fchown(fd, uid, gid)
        need(os.fstat(fd).st_size == IMAGE_BYTES and os.fstat(fd).st_blocks * 512 >= IMAGE_BYTES,
             'FULL_IMAGE_ALLOCATION_FAILED')
        os.fsync(parent)
    finally:
        close_owned(fd, parent)
    # Fixed commands only; no shell, package acquisition, inherited credential environment or global tmp.
    for name, command in (
        ('mkfs', [pinned['mke2fs'], '-t', 'ext4', '-q', '-F', '-m', '0', '-b', '4096',
                  '-E', 'nodiscard', str(image)]),
        ('mount', [pinned['mount'], '-i', '-o', 'loop,nodev,nosuid,noexec,nodiscard', str(image), str(job / 'volume')]),
    ):
        logs = job / 'control' / name
        new_dir(logs, owner=uid, gid=gid)
        # Root opens new root-owned logs in a target-owned private directory; chown exact new files below.
        result = run_process(command, job, logs, seconds=TOOL_SECONDS, memory_limit=True,
                             owner=uid, file_limit=IMAGE_BYTES, log_limit=TOOL_LOG_BYTES)
        for leaf in ('stdout.bin', 'stderr.bin'):
            os.chown(logs / leaf, uid, gid, follow_symlinks=False)
        create_file(job / 'control' / (name + '.json'), json_bytes(result), owner=uid)
        need(result['returncode'] == 0 and result['reason'] == 'process-exit-zero' and
             result['quiescent'] and not result['errors'], 'QUOTA_SETUP_COMMAND_FAILED_RETAIN_NEW_JOB')
    os.chown(job / 'volume', uid, gid, follow_symlinks=False)
    os.chmod(job / 'volume', 0o700, follow_symlinks=False)
    new_dir(job / 'volume' / 'work', owner=uid, gid=gid)
    actual = mount_observation(job / 'volume', image, uid)
    work = owned_dir(job / 'volume' / 'work', owner=uid)
    probe = None
    denial = None
    try:
        probe = os.open('enospc-probe.retained', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=work)
        os.fchown(probe, uid, gid)
        before_allocation = os.fstat(probe)
        geometry_before = os.fstatvfs(work)
        limits_before = {'RLIMIT_FSIZE': list(resource.getrlimit(resource.RLIMIT_FSIZE)),
                         'RLIMIT_AS': list(resource.getrlimit(resource.RLIMIT_AS))}
        try:
            os.posix_fallocate(probe, 0, IMAGE_BYTES + UNIT)
        except OSError as error:
            denial = error_record(error, 'actual-posix-fallocate-beyond-image-capacity')
        os.fsync(probe)
        remaining = os.fstat(probe)
        geometry_after = os.fstatvfs(work)
        observation = {'format': 'scientific-posix-quota-attempt-observation-v1',
            'lifecycle_manifest_sha256': life_manifest_sha, 'job_root': str(job),
            'owner_uid': uid, 'owner_gid': gid, 'actual_mount': actual,
            'attempted_bytes': IMAGE_BYTES + UNIT, 'attempt_error': denial,
            'probe_before': {'bytes': before_allocation.st_size, 'blocks_512': before_allocation.st_blocks},
            'probe_after': {'bytes': remaining.st_size, 'blocks_512': remaining.st_blocks},
            'limits_before': limits_before,
            'limits_after': {'RLIMIT_FSIZE': list(resource.getrlimit(resource.RLIMIT_FSIZE)),
                             'RLIMIT_AS': list(resource.getrlimit(resource.RLIMIT_AS))},
            'geometry_before': {'available_bytes': geometry_before.f_bavail * geometry_before.f_frsize,
                                'capacity_bytes': geometry_before.f_blocks * geometry_before.f_frsize,
                                'fragment_size_bytes': geometry_before.f_frsize},
            'geometry_after': {'available_bytes': geometry_after.f_bavail * geometry_after.f_frsize,
                               'capacity_bytes': geometry_after.f_blocks * geometry_after.f_frsize,
                               'fragment_size_bytes': geometry_after.f_frsize},
            'scope': 'Actual attempt facts before the unchanged acceptance guard; no quota success claimed.'}
        create_file(job / 'control' / 'quota-attempt-observation.json', json_bytes(observation), owner=uid)
        need(denial is not None and denial['errno'] == errno.ENOSPC and remaining.st_size == 0 and
             remaining.st_blocks == 0, 'ACTUAL_ATOMIC_ENOSPC_DENIAL_REQUIRED_RETAIN_PROBE')
        os.fsync(work)
    finally:
        close_owned(probe, work)
    proof = {'format': 'scientific-posix-quota-denial-v1', 'lifecycle_manifest_sha256': life_manifest_sha,
             'job_root': str(job), 'owner_uid': uid, 'owner_gid': gid,
             'actual_mount': actual, 'attempted_bytes': IMAGE_BYTES + UNIT,
             'denial': denial, 'probe_retained_bytes': 0, 'probe_retained_blocks': 0,
             'installed_tools': tools, 'retirement': 'NONE',
             'created_unix_seconds': int(time.time())}
    create_file(job / 'control' / 'quota-proof.json', json_bytes(proof), owner=uid)
    return {'status': 'QUOTA_PREPARED_NOT_A_RUN_ADMISSION', 'quota_proof': str(job / 'control' / 'quota-proof.json')}


def prepare_memory(job, interpreter, life_manifest_sha):
    need(os.geteuid() != 0, 'MEMORY_PROBE_MUST_USE_UNPRIVILEGED_PAYLOAD_UID')
    job = explicit_path(job)
    python = pin_runtime(interpreter)
    need(Path(sys.executable) == Path(python), 'EXACT_PROBE_INTERPRETER_REQUIRED')
    logs = job / 'control' / 'memory-probe'
    new_dir(logs)
    command = [python, '-I', '-S', '-B', str(Path(__file__).absolute()), '_memory-denial-child']
    result = run_process(command, job, logs, seconds=20, log_limit=PROBE_LOG_BYTES)
    need(result['returncode'] == 0 and result['reason'] == 'process-exit-zero' and
         result['quiescent'] and not result['errors'], 'ACTUAL_MEMORY_PROBE_PROCESS_FAILED')
    observed = json_load(read_owned(logs / 'stdout.bin', 4096), maximum=4096)
    need(observed['format'] == 'scientific-posix-memory-denial-v1' and
         observed['actual_getrlimit'] == [MEMORY_BYTES, MEMORY_BYTES] and
         observed['denial_observed'] is True and observed['exception'] == 'MemoryError' and
         observed['attempted_bytes'] == MEMORY_BYTES + 1, 'ACTUAL_MEMORY_DENIAL_PROOF_REQUIRED')
    proof = {'format': 'scientific-posix-memory-proof-v1', 'owner_uid': os.geteuid(),
             'job_root': str(job), 'lifecycle_manifest_sha256': life_manifest_sha,
             'interpreter': interpreter, 'probe': observed, 'process': result}
    path = job / 'control' / 'memory-proof.json'
    create_file(path, json_bytes(proof))
    return {'status': 'MEMORY_PROBED_NOT_A_RUN_ADMISSION', 'memory_proof': str(path)}


def entry_stat(info):
    return {'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid, 'nlink': info.st_nlink,
            'size': info.st_size, 'blocks_512': info.st_blocks, 'device': info.st_dev,
            'inode': info.st_ino, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def kind_of(info):
    for name, check in (('directory', stat.S_ISDIR), ('regular', stat.S_ISREG),
                        ('symlink', stat.S_ISLNK), ('fifo', stat.S_ISFIFO),
                        ('socket', stat.S_ISSOCK), ('block', stat.S_ISBLK), ('character', stat.S_ISCHR)):
        if check(info.st_mode):
            return name
    return 'unrecognized'


def open_relative(root_fd, components, *, directory=False):
    descriptors, result = [], None
    try:
        current = root_fd
        for index, name in enumerate(components):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(components) - 1 or directory:
                flags |= os.O_DIRECTORY
            child = os.open(name, flags, dir_fd=current)
            descriptors.append(child)
            current = child
        if not components:
            descriptors.append(os.dup(root_fd))
        result = descriptors.pop()
        closing, descriptors = descriptors, []
        close_owned(*closing)
        answer, result = result, None
        return answer
    finally:
        close_owned(result, *descriptors)


def snapshot_tree(root):
    """Inventory EVERY bounded entry. Unsafe types are records, never traversed."""
    root = explicit_path(root)
    rows, errors, logical, accounted = [], [], 0, 0
    exhausted = False
    root_fd = owned_dir(root)
    try:
        started = time.monotonic()
        root_info = os.fstat(root_fd)
        root_dev = root_info.st_dev
        pending = [()]
        while pending:
            need(time.monotonic() - started <= COPY_SECONDS, 'INVENTORY_WALL_BOUND')
            components = pending.pop()
            fd = None
            try:
                if components:
                    parent = open_relative(root_fd, components[:-1], directory=True)
                    try:
                        before = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
                        kind = kind_of(before)
                        target = None
                        if kind == 'symlink':
                            target = os.readlink(components[-1], dir_fd=parent)
                            if isinstance(target, str):
                                target = os.fsencode(target)
                            need(len(target) <= 4096, 'SYMLINK_EVIDENCE_BOUND')
                    finally:
                        close_owned(parent)
                else:
                    before, kind, target = root_info, 'directory', None
                path_raw = b'/'.join(components)
                need(len(rows) < SOURCE_ENTRIES and len(components) <= DEPTH and len(path_raw) <= PATH_BYTES,
                     'COMPLETE_TREE_ENTRY_PATH_DEPTH_BOUND')
                row = {'path_b64': base64.b64encode(path_raw).decode('ascii'), 'kind': kind,
                       'stat': entry_stat(before), 'data_bytes': 0, 'sha256': None,
                       'components': components, 'signature': signature(before), 'unsafe': None}
                rows.append(row)
                if target is not None:
                    row['link_target_prefix_b64'] = base64.b64encode(target[:512]).decode('ascii')
                    row['link_target_bytes'] = len(target)
                    row['link_target_sha256'] = hashlib.sha256(target).hexdigest()
                if before.st_dev != root_dev:
                    row['unsafe'] = 'foreign-device-not-followed'
                elif before.st_uid != os.geteuid() or before.st_mode & 0o077:
                    row['unsafe'] = 'unexpected-owner-or-nonprivate-mode'
                elif kind not in ('directory', 'regular'):
                    row['unsafe'] = 'unsafe-or-unrecognized-type-not-followed'
                elif kind == 'regular' and before.st_nlink != 1:
                    row['unsafe'] = 'hardlink-not-followed'
                if kind == 'directory':
                    accounted += 2 * UNIT
                    if before.st_size > UNIT or before.st_blocks * 512 > UNIT:
                        row['unsafe'] = 'directory-allocation-outside-profile'
                else:
                    accounted += max(before.st_size, before.st_blocks * 512) + 2 * UNIT
                need(accounted <= SOURCE_BYTES, 'COMPLETE_SOURCE_ALLOCATION_BOUND')
                if row['unsafe']:
                    continue
                fd = open_relative(root_fd, components, directory=kind == 'directory')
                need(signature(before) == signature(os.fstat(fd)), 'SNAPSHOT_ENTRY_CHANGED_ON_OPEN')
                # Linux caps listxattr's returned name list at 64KiB. Attributes/ACLs
                # need the retained raw image rather than an invented normal-copy claim.
                if os.listxattr(fd):
                    row['unsafe'] = 'extended-attributes-or-acl-require-raw-image'
                    continue
                if kind == 'directory':
                    children = []
                    with os.scandir(fd) as iterator:
                        for entry in iterator:
                            name = os.fsencode(entry.name)
                            need(0 < len(name) <= 255 and name not in (b'.', b'..') and b'/' not in name and
                                 len(rows) + len(pending) + len(children) < SOURCE_ENTRIES,
                                 'DIRECTORY_ENTRY_BOUND')
                            children.append(components + (name,))
                    pending.extend(sorted(children, reverse=True))
                else:
                    need(0 <= before.st_size <= FILE_BYTES, 'COMPLETE_SOURCE_FILE_BOUND')
                    logical += before.st_size
                    need(logical <= SOURCE_LOGICAL, 'COMPLETE_SOURCE_LOGICAL_BOUND')
                    hashed, size = hashlib.sha256(), 0
                    while True:
                        need(time.monotonic() - started <= COPY_SECONDS, 'INVENTORY_WALL_BOUND')
                        raw = os.read(fd, IO_BYTES)
                        if not raw:
                            break
                        size += len(raw)
                        need(size <= before.st_size, 'SOURCE_FILE_GREW')
                        hashed.update(raw)
                    need(size == before.st_size, 'SOURCE_FILE_SHRANK')
                    row['data_bytes'], row['sha256'] = size, hashed.hexdigest()
                need(signature(before) == signature(os.fstat(fd)), 'SOURCE_CHANGED_DURING_INVENTORY')
            except BaseException as error:
                add_error(errors, error, 'whole-tree-inventory')
                exhausted = True
                break
            finally:
                close_owned(fd)
    except BaseException as error:
        add_error(errors, error, 'whole-tree-inventory-boundary')
        exhausted = True
    finally:
        try:
            close_owned(root_fd)
        except BaseException as error:
            add_error(errors, error, 'whole-tree-root-release')
            exhausted = True
    return {'rows': rows, 'errors': errors, 'enumeration_complete': not exhausted and not pending,
            'safe': not errors and all(row['unsafe'] is None for row in rows),
            'logical_bytes': logical, 'accounted_bytes': accounted, 'entries': len(rows)}


def public_row(row):
    return {key: value for key, value in row.items() if key not in ('components', 'signature')}


def inventory_fingerprint(snapshot):
    hashed = hashlib.sha256()
    for row in snapshot['rows']:
        hashed.update(json_bytes(public_row(row)))
    return hashed.hexdigest()


def write_neutral(root, snapshot, destination):
    """Retain an exclusive neutral prefix even if a later source/copy read fails."""
    destination = explicit_path(destination)
    source_fd = out = None
    errors, count, data_bytes, written = [], 0, 0, 0

    def emit(raw):
        nonlocal written
        need(written + len(raw) <= BLOB_BYTES, 'NEUTRAL_ENCODING_BOUND')
        write_all(out, raw)
        written += len(raw)

    parent = owned_dir(destination.parent)
    try:
        started = time.monotonic()
        geometry = os.fstatvfs(parent)
        need(0 < max(geometry.f_frsize, geometry.f_bsize) <= UNIT, 'NEUTRAL_DESTINATION_GEOMETRY')
        out = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600, dir_fd=parent)
        emit(MAGIC)
        source_fd = owned_dir(root)
        for row in snapshot['rows']:
            need(time.monotonic() - started <= COPY_SECONDS, 'NEUTRAL_COPY_WALL_BOUND')
            header = json_bytes(public_row(row))
            need(len(header) <= HEADER_BYTES, 'NEUTRAL_HEADER_BOUND')
            emit(struct.pack('>I', len(header)))
            emit(header)
            if row['kind'] == 'regular' and row['unsafe'] is None:
                fd = open_relative(source_fd, row['components'])
                try:
                    need(signature(os.fstat(fd)) == row['signature'], 'SOURCE_CHANGED_BEFORE_COPY')
                    hashed, size = hashlib.sha256(), 0
                    while True:
                        need(time.monotonic() - started <= COPY_SECONDS, 'NEUTRAL_COPY_WALL_BOUND')
                        raw = os.read(fd, IO_BYTES)
                        if not raw:
                            break
                        size += len(raw)
                        need(size <= row['data_bytes'], 'SOURCE_GREW_DURING_COPY')
                        emit(raw)
                        hashed.update(raw)
                    need(size == row['data_bytes'] and hashed.hexdigest() == row['sha256'] and
                         signature(os.fstat(fd)) == row['signature'], 'SOURCE_COPY_BYTES_OR_IDENTITY_CHANGED')
                    data_bytes += size
                finally:
                    close_owned(fd)
            count += 1
        # This is framing completion, not a scientific seal or a claim about unsafe entries.
        footer = json_bytes({'end': True, 'entries': count, 'data_bytes': data_bytes,
                             'inventory_sha256': inventory_fingerprint(snapshot),
                             'enumeration_complete': snapshot['enumeration_complete'], 'safe': snapshot['safe']})
        emit(struct.pack('>I', len(footer)))
        emit(footer)
    except BaseException as error:
        add_error(errors, error, 'neutral-copy-retained-prefix')
    finally:
        if out is not None:
            try:
                os.fsync(out)
                os.fsync(parent)
            except BaseException as error:
                add_error(errors, error, 'neutral-copy-fsync')
        try:
            close_owned(out, source_fd, parent)
        except BaseException as error:
            add_error(errors, error, 'neutral-copy-release')
    return {'framed_entries': count, 'framed_data_bytes': data_bytes, 'errors': errors}


def verify_neutral(path, *, expected=None):
    """Read-only data verification; never extract names, import, or execute bodies."""
    result = hash_file(path, BLOB_BYTES)
    if expected is not None:
        need(result['bytes'] == expected['bytes'] and result['sha256'] == expected['sha256'],
             'NEUTRAL_EXTERNAL_REFERENCE_MISMATCH')
    fd = None
    started, seen, data_total, inventory = None, {}, 0, None
    observed_safe = True

    def exact(count):
        value = bytearray()
        while len(value) < count:
            need(time.monotonic() - started <= COPY_SECONDS, 'NEUTRAL_VERIFY_WALL_BOUND')
            raw = os.read(fd, min(IO_BYTES, count - len(value)))
            need(bool(raw), 'INCOMPLETE_NEUTRAL_PREFIX')
            value.extend(raw)
        return bytes(value)

    parent = owned_dir(explicit_path(path).parent)
    try:
        started = time.monotonic()
        inventory = hashlib.sha256()
        fd = os.open(explicit_path(path).name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        before = os.fstat(fd)
        need(signature(before) == tuple(result['identity']), 'NEUTRAL_VERIFY_OPEN_CHANGED')
        need(exact(len(MAGIC)) == MAGIC, 'NEUTRAL_MAGIC')
        while True:
            size = struct.unpack('>I', exact(4))[0]
            need(1 <= size <= HEADER_BYTES, 'NEUTRAL_HEADER_BOUND')
            raw = exact(size)
            row = json_load(raw, maximum=HEADER_BYTES)
            need(type(row) is dict, 'NEUTRAL_RECORD_OBJECT')
            if row.get('end') is True:
                need(set(row) == {'end', 'entries', 'data_bytes', 'inventory_sha256',
                                  'enumeration_complete', 'safe'} and row['entries'] == len(seen) and
                     row['data_bytes'] == data_total and row['inventory_sha256'] == inventory.hexdigest() and
                     os.read(fd, 1) == b'', 'NEUTRAL_COMPLETE_FRAMING_AND_INVENTORY')
                need(type(row['enumeration_complete']) is bool and type(row['safe']) is bool and
                     row['safe'] == observed_safe and b'' in seen and seen[b''] == 'directory' and
                     signature(before) == signature(os.fstat(fd)) ==
                     signature(os.stat(explicit_path(path).name, dir_fd=parent, follow_symlinks=False)),
                     'NEUTRAL_CHANGED_DURING_VERIFY')
                return {**result, 'entries': len(seen), 'data_bytes': data_total,
                        'enumeration_complete': row['enumeration_complete'], 'safe': row['safe'],
                        'verified_framing': True}
            need(set(row).issubset({'path_b64', 'kind', 'stat', 'data_bytes', 'sha256', 'unsafe',
                                   'link_target_prefix_b64', 'link_target_bytes', 'link_target_sha256'}) and
                 {'path_b64', 'kind', 'stat', 'data_bytes', 'sha256', 'unsafe'}.issubset(row),
                 'NEUTRAL_ENTRY_SCHEMA')
            path_raw = base64.b64decode(row['path_b64'], validate=True)
            need(len(seen) < SOURCE_ENTRIES and len(path_raw) <= PATH_BYTES and
                 base64.b64encode(path_raw).decode('ascii') == row['path_b64'] and b'\x00' not in path_raw and
                 (not path_raw or (not path_raw.startswith(b'/') and
                  all(0 < len(part) <= 255 and part not in (b'.', b'..') for part in path_raw.split(b'/')))) and
                 len(path_raw.split(b'/')) <= DEPTH and path_raw not in seen,
                 'NEUTRAL_UNIQUE_BOUNDED_DATA_NAMES')
            need((not path_raw and not seen and row['kind'] == 'directory') or
                 (path_raw and seen.get(path_raw.rpartition(b'/')[0]) == 'directory'),
                 'NEUTRAL_ROOT_AND_PARENT_DIRECTORY_ORDER')
            need(row['kind'] in ('directory', 'regular', 'symlink', 'fifo', 'socket', 'block',
                                 'character', 'unrecognized') and
                 (row['unsafe'] is None or (type(row['unsafe']) is str and 0 < len(row['unsafe']) <= 160)),
                 'NEUTRAL_TYPED_KIND_AND_UNSAFE_MARKER')
            observed_safe = observed_safe and row['unsafe'] is None and row['kind'] in ('directory', 'regular')
            seen[path_raw] = row['kind']
            inventory.update(raw)
            count = integer(row['data_bytes'], 0, FILE_BYTES)
            data_total += count
            need(data_total <= SOURCE_LOGICAL, 'NEUTRAL_DECODED_DATA_BOUND')
            if row['kind'] == 'regular' and row['unsafe'] is None:
                hashed, remaining = hashlib.sha256(), count
                while remaining:
                    block = exact(min(IO_BYTES, remaining))
                    hashed.update(block)
                    remaining -= len(block)
                need(hashed.hexdigest() == row['sha256'], 'NEUTRAL_SUBJECT_BYTES_MISMATCH')
            else:
                need(count == 0 and row['sha256'] is None,
                     'UNSAFE_OR_DIRECTORY_HAS_NO_READ_PAYLOAD')
    finally:
        close_owned(fd, parent)


def copy_blob(source, destination, maximum):
    """One exclusive byte copy, including an incomplete neutral prefix; no retry."""
    source, destination = explicit_path(source), explicit_path(destination)
    source_ref = hash_file(source, maximum)
    source_parent = dest_parent = source_fd = dest_fd = None
    errors = []
    try:
        source_parent = owned_dir(source.parent)
        dest_parent = owned_dir(destination.parent)
        geometry = os.fstatvfs(dest_parent)
        need(0 < max(geometry.f_frsize, geometry.f_bsize) <= UNIT, 'COPY_DESTINATION_GEOMETRY')
        source_fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_parent)
        need(signature(os.fstat(source_fd)) == tuple(source_ref['identity']), 'COPY_SOURCE_OPEN_CHANGED')
        dest_fd = os.open(destination.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=dest_parent)
        size, started = 0, time.monotonic()
        while True:
            need(time.monotonic() - started <= COPY_SECONDS, 'BLOB_COPY_WALL_BOUND')
            raw = os.read(source_fd, IO_BYTES)
            if not raw:
                break
            size += len(raw)
            need(size <= maximum, 'BLOB_COPY_BYTE_BOUND')
            write_all(dest_fd, raw)
        need(size == source_ref['bytes'] and signature(os.fstat(source_fd)) == tuple(source_ref['identity']),
             'COPY_SOURCE_CHANGED')
    except BaseException as error:
        add_error(errors, error, 'byte-copy-retained-prefix')
    finally:
        if dest_fd is not None:
            try:
                os.fsync(dest_fd)
                os.fsync(dest_parent)
            except BaseException as error:
                add_error(errors, error, 'byte-copy-fsync')
        try:
            close_owned(source_fd, dest_fd, source_parent, dest_parent)
        except BaseException as error:
            add_error(errors, error, 'byte-copy-release')
    result = {'source': source_ref, 'errors': errors, 'verified_equal': False}
    try:
        copied = hash_file(destination, maximum)
        result['destination'] = copied
        result['verified_equal'] = (not errors and copied['bytes'] == source_ref['bytes'] and
                                    copied['sha256'] == source_ref['sha256'])
    except BaseException as error:
        add_error(errors, error, 'byte-copy-readback')
    return result


def collect_tree(root, exports, *, quiescent):
    """Entire-tree collection on EVERY child outcome; complete requires all checks."""
    errors, snapshot, blob = [], None, None
    result = {'format': FORMAT, 'root': str(root), 'producer_quiescent': quiescent,
              'source_tree_complete': False, 'raw_source_retained': True,
              'raw_image_export_required': True, 'errors': errors}
    if quiescent is not True:
        result['collection_not_started'] = 'PRODUCERS_NOT_QUIESCENT_RETAIN_SOURCE_AND_IMAGE'
        return result
    first, second = explicit_path(exports) / 'fixture.neutral', explicit_path(exports) / 'fixture-copy.neutral'
    try:
        snapshot = snapshot_tree(root)
        result['inventory'] = {key: value for key, value in snapshot.items() if key != 'rows'}
        result['inventory']['sha256'] = inventory_fingerprint(snapshot)
        unsafe = [row for row in snapshot['rows'] if row['unsafe']]
        result['unsafe_entries_count'] = len(unsafe)
        result['unsafe_observation_prefix'] = [public_row(row) for row in unsafe[:16]]
        result['neutral_write'] = write_neutral(root, snapshot, first)
    except BaseException as error:
        add_error(errors, error, 'entire-tree-collection')
    try:
        # Even a malformed/incomplete first blob is retained and byte-copied.
        blob = hash_file(first, BLOB_BYTES)
        blob['format'] = 'scientific-posix-neutral-prefix-reference-v1'
        result['neutral_prefix'] = blob
        result['second_copy'] = copy_blob(first, second, BLOB_BYTES)
    except BaseException as error:
        add_error(errors, error, 'available-neutral-prefix-copy')
    # Hash each available output independently even if copying, fsync, release
    # or the other output's strict framing/readback failed. These are byte-only
    # references to retained prefixes, never assertions of complete framing.
    for key, path in (('neutral_prefix', first), ('second_prefix', second)):
        try:
            current = hash_file(path, BLOB_BYTES)
            current['format'] = 'scientific-posix-neutral-prefix-reference-v1'
            result[key] = current
            if key == 'neutral_prefix':
                previous, blob = blob, current
                need(previous is None or (previous['bytes'], previous['sha256']) ==
                     (current['bytes'], current['sha256']), 'FIRST_NEUTRAL_CHANGED_AFTER_COPY')
        except BaseException as error:
            add_error(errors, error, key + '-independent-byte-readback')
    for key, path in (('neutral_verify', first), ('second_verify', second)):
        try:
            result[key] = verify_neutral(path, expected=blob)
        except BaseException as error:
            add_error(errors, error, key + '-strict-framing-readback')
    try:
        after = snapshot_tree(root)
        result['after_inventory'] = {key: value for key, value in after.items() if key != 'rows'}
        result['after_inventory']['sha256'] = inventory_fingerprint(after)
        stable = snapshot is not None and inventory_fingerprint(after) == inventory_fingerprint(snapshot)
        result['source_stable_after_copy'] = stable
        result['source_tree_complete'] = bool(
            quiescent and snapshot is not None and snapshot['enumeration_complete'] and snapshot['safe'] and
            not snapshot['errors'] and after['enumeration_complete'] and after['safe'] and not after['errors'] and
            stable and not errors and not result.get('neutral_write', {}).get('errors', [True]) and
            result.get('second_copy', {}).get('verified_equal') is True and
            result.get('neutral_verify', {}).get('verified_framing') is True and
            result.get('second_verify', {}).get('verified_framing') is True)
    except BaseException as error:
        add_error(errors, error, 'entire-source-post-copy-inventory')
    return result


def verify_prefix(path, reference):
    """Independently referenced bytes, including failed A/B prefixes; never parse or extract."""
    need(reference['format'] == 'scientific-posix-neutral-prefix-reference-v1',
         'EXTERNAL_NEUTRAL_PREFIX_REFERENCE_REQUIRED')
    integer(reference['bytes'], 0, BLOB_BYTES)
    sha(reference['sha256'])
    actual = hash_file(path, BLOB_BYTES, exact=reference['bytes'])
    need(actual['sha256'] == reference['sha256'], 'DELIVERED_NEUTRAL_PREFIX_BYTES_MISMATCH')
    return {**actual, 'status': 'BYTE_PREFIX_VERIFIED_NEUTRAL_FRAMING_NOT_CLAIMED'}


def verify_actual_proofs(admission, owner):
    job = explicit_path(admission['job_root'])
    quota, _ = pinned_document(job / 'control' / 'quota-proof.json', admission['quota_proof_sha256'], owner=owner)
    memory, _ = pinned_document(job / 'control' / 'memory-proof.json', admission['memory_proof_sha256'], owner=owner)
    actual = mount_observation(job / 'volume', job / 'quota.img', owner)
    need(quota['format'] == 'scientific-posix-quota-denial-v1' and quota['job_root'] == str(job) and
         quota['owner_uid'] == owner and quota['lifecycle_manifest_sha256'] == admission['lifecycle_manifest_sha256'] and
         quota['denial']['errno'] == errno.ENOSPC and quota['attempted_bytes'] == IMAGE_BYTES + UNIT and
         quota['probe_retained_bytes'] == quota['probe_retained_blocks'] == 0 and
         quota['actual_mount'] == actual, 'FRESH_ACTUAL_QUOTA_PROOF_AND_CURRENT_MOUNT_REQUIRED')
    need(memory['format'] == 'scientific-posix-memory-proof-v1' and memory['job_root'] == str(job) and
         memory['owner_uid'] == owner and memory['lifecycle_manifest_sha256'] == admission['lifecycle_manifest_sha256'] and
         memory['interpreter'] == admission['interpreter'] and
         memory['probe']['actual_getrlimit'] == [MEMORY_BYTES, MEMORY_BYTES] and
         memory['probe']['denial_observed'] is True and memory['probe']['exception'] == 'MemoryError' and
         memory['probe']['attempted_bytes'] == MEMORY_BYTES + 1 and
         memory['process']['returncode'] == 0 and memory['process']['quiescent'] is True and
         memory['process']['reason'] == 'process-exit-zero' and not memory['process']['errors'],
         'FRESH_ACTUAL_MEMORY_LIMIT_AND_DENIAL_PROOF_REQUIRED')
    return quota, memory, actual


def require_source_headroom(mount, owner):
    """Actual free space after staging/control fixtures, before the SPI producer."""
    fd = owned_dir(mount, owner=owner)
    try:
        geometry = os.fstatvfs(fd)
        available = geometry.f_bavail * geometry.f_frsize
        need(available >= ON_VOLUME_REQUIRED_BYTES,
             'ACTUAL_AVAILABLE_QUOTA_SPACE_CANNOT_FIT_UNWEAKENED_SOURCE_AND_HEADROOM')
        return {'actual_available_bytes_before_producer': available,
                'required_available_bytes': ON_VOLUME_REQUIRED_BYTES}
    finally:
        close_owned(fd)


def validate_admission(value, life_manifest_sha, expected_admission_sha):
    need(value['format'] == ADMISSION_FORMAT and value['status'] == STATUS and
         value['lifecycle_manifest_sha256'] == life_manifest_sha, 'EXTERNAL_REVIEWED_LIFECYCLE_ADMISSION')
    check_global(value)
    need(type(value['attempt_id']) is str and re.fullmatch('[a-z0-9][a-z0-9-]{0,47}', value['attempt_id']),
         'BOUNDED_EXPLICIT_ATTEMPT_ID')
    owner = integer(value['owner_uid'], 1, (1 << 31) - 1)
    need(os.geteuid() == owner, 'RUN_SUPERVISOR_AND_CHILD_UNPRIVILEGED_AS_ADMITTED_OWNER')
    for key in ('quota_proof_sha256', 'memory_proof_sha256', 'integration_manifest_sha256',
                'integration_admission_sha256', 'independent_first_findings_sha256',
                'external_profile_control_proof_sha256'):
        sha(value[key])
    job, packet = explicit_path(value['job_root']), explicit_path(value['integration_packet'])
    root = job / 'volume' / 'work' / ('fixture-' + value['attempt_id'])
    need(str(root) == value['test_root'] and packet == job / 'volume' / 'packet', 'FIXED_OWNED_PLACEMENT')
    python = pin_runtime(value['interpreter'])
    need(Path(sys.executable) == Path(python), 'SUPERVISOR_USES_EXACT_ADMITTED_INSTALLED_INTERPRETER')
    quota, memory, actual = verify_actual_proofs(value, owner)
    headroom = require_source_headroom(job / 'volume', owner)
    controls, _ = pinned_document(job / 'control' / 'external-profile-control-proof.json',
                                  value['external_profile_control_proof_sha256'])
    for field in ('actual_tests_run', 'actual_failures', 'actual_errors', 'actual_skips'):
        integer(controls[field], 0, CONTROL_TESTS)
    integer(controls['process_returncode'], 0, 0)
    need(controls['format'] == 'scientific-posix-external-profile-control-proof-v1' and
         controls['lifecycle_manifest_sha256'] == life_manifest_sha and
         controls['actual_linux_posix'] is True and controls['actual_tests_run'] == CONTROL_TESTS and
         controls['actual_failures'] == controls['actual_errors'] == controls['actual_skips'] == 0 and
         controls['process_returncode'] == 0 and controls['all_control_prefixes_retained'] is True,
         'ACTUAL_PINNED_EXTERNAL_PROFILE_CONTROLS_REQUIRED')
    sha(controls['actual_command_receipt_sha256'])
    packet_manifest, _, packet_pins = check_packet(packet, SPI_MANIFEST, value['integration_manifest_sha256'], SPI_NAMES)
    need(packet_manifest['format'] == 'scientific-posix-source-packet-v1' and
         packet_manifest['profile'] == SPI_PROFILE, 'EXACT_CURRENT_INTEGRATION_PACKET_FORMAT_AND_PROFILE')
    spi, _ = pinned_document(job / 'control' / 'integration-admission.json', value['integration_admission_sha256'])
    need(spi['format'] == 'scientific-posix-runner-admission-v2' and spi['profile'] == SPI_PROFILE and
         spi['status'] == STATUS and spi['runner_context'] == SPI_CONTEXT and spi['test_root'] == str(root) and
         spi['source_manifest_sha256'] == value['integration_manifest_sha256'] and
         spi['fixture_source_bytes'] == SOURCE_BYTES and spi['fixture_source_entries'] == SOURCE_ENTRIES and
         spi['total_reserved_bytes'] == SPI_BYTES and spi['total_reserved_entries'] == SPI_ENTRIES and
         spi['complete_failure_copies'] == 4 and spi['memory_limit_bytes'] == MEMORY_BYTES and
         spi['hard_quota_bytes'] == IMAGE_BYTES and spi['hard_quota_enforced'] is True and
         spi['memory_quota_enforced'] is True and spi['hard_quota_evidence_sha256'] == value['quota_proof_sha256'] and
         spi['memory_quota_evidence_sha256'] == value['memory_proof_sha256'] and
         spi['external_complete_failure_transport_profile'] == FORMAT and
         spi['external_transport_source_sha256'] == life_manifest_sha and
         spi['external_transport_proof_sha256'] == value['external_profile_control_proof_sha256'] and
         spi['independent_first_findings_sha256'] == value['independent_first_findings_sha256'] and
         spi['fresh_global_inventory_sha256'] == value['fresh_global_inventory_sha256'] and
         spi['baseline_excluding_reserve_bytes'] == value['baseline_excluding_reserve_bytes'] and
         spi['other_growth_bytes'] == value['other_growth_bytes'] + EXTRA_OVER_SPI and
         spi['global_reserve_bytes'] == value['global_reserve_bytes'] and
         spi['all_allocations_including_external_copies_admitted'] is True and spi['no_other_heavy_process'] is True,
         'INDEPENDENT_SPI_CONTEXT_MUST_BIND_ACTUAL_PROOFS_AND_COMPLETE_PLACEMENT')
    parent = owned_dir(root.parent)
    try:
        try:
            os.stat(root.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError('TEST_ROOT_EXISTS_RETAIN_OLD_ROOT_AND_ADMIT_NEW_JOB')
    finally:
        close_owned(parent)
    return {'job': job, 'packet': packet, 'root': root, 'python': python,
            'packet_pins': packet_pins, 'actual_quota': actual,
            'source_headroom': headroom,
            'admission_sha256': expected_admission_sha, 'quota': quota, 'memory': memory}


def interrupted(signum, _frame):
    if len(INTERRUPTS) < 16:
        INTERRUPTS.append(signum)


def supervise(value, life_manifest_sha, admission_sha, life_packet, admission_path):
    context = validate_admission(value, life_manifest_sha, admission_sha)
    job, packet, root = context['job'], context['packet'], context['root']
    _, life_raw, life_pins = check_packet(life_packet, MANIFEST_NAME, life_manifest_sha, LIFE_NAMES)
    spi_manifest, spi_raw, _ = check_packet(packet, SPI_MANIFEST, value['integration_manifest_sha256'], SPI_NAMES)
    need(sum(row['bytes'] for row in life_pins) + len(life_raw) +
         sum(row['bytes'] for row in spi_manifest['packet_files']) + len(spi_raw) <= 1 << 20,
         'FROZEN_COMBINED_PACKET_ONE_MIB_OVERHEAD_BOUND')
    # The exclusive lock is retained. Any interrupted old job needs a NEW root.
    create_file(job / 'control' / 'active.lock', json_bytes({'pid': os.getpid(), 'attempt_id': value['attempt_id']}))
    run_dir = job / 'control' / 'run'
    new_dir(run_dir)
    command = [context['python'], '-I', '-S', '-B', str(packet / 'run_scientific_posix_integration.py'),
               '--test-root', str(root), '--profile', SPI_PROFILE, '--runner-context', SPI_CONTEXT,
               '--manifest-sha256', value['integration_manifest_sha256'],
               '--admission', str(job / 'control' / 'integration-admission.json'),
               '--admission-sha256', value['integration_admission_sha256']]
    receipt = {'format': 'scientific-posix-lifecycle-receipt-v1', 'profile': FORMAT,
               'admission_sha256': admission_sha, 'lifecycle_manifest_sha256': life_manifest_sha,
               'integration_manifest_sha256': value['integration_manifest_sha256'],
               'before_packet_pins': context['packet_pins'], 'actual_quota_before': context['actual_quota'],
               'source_headroom_before': context['source_headroom'],
               'before_lifecycle_pins': life_pins, 'cgroup_oom_before': cgroup_oom_observation(),
               'child': None, 'collection': None, 'after_source_pins_valid': False, 'errors': [],
               'scientific_qualification': 'NOT_CLAIMED', 'retirement': 'NONE'}
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    # Bound the trusted supervisor too; child limits are applied independently before exec.
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        try:
            receipt['child'] = run_process(command, packet, run_dir)
        except BaseException as error:
            add_error(receipt['errors'], error, 'payload-lifecycle')
        child = receipt['child']
        quiescent = child is not None and child['quiescent'] is True
        receipt['cgroup_oom_after'] = cgroup_oom_observation()
        receipt['log_byte_references'] = {}
        for name in ('stdout', 'stderr'):
            try:
                receipt['log_byte_references'][name] = hash_file(run_dir / (name + '.bin'), LOG_BYTES)
            except BaseException as error:
                add_error(receipt['errors'], error, name + '-actual-retained-log-readback')
        # Missing root, constructor failure, unsafe tree and ENOSPC are collected as actual failures.
        receipt['collection'] = collect_tree(root, job / 'exports', quiescent=quiescent)
        try:
            _, _, after_pins = check_packet(packet, SPI_MANIFEST, value['integration_manifest_sha256'], SPI_NAMES)
            _, _, after_life = check_packet(life_packet, MANIFEST_NAME, life_manifest_sha, LIFE_NAMES)
            need(after_pins == context['packet_pins'] and after_life == life_pins,
                 'COMPLETE_BEFORE_AFTER_SOURCE_IDENTITIES_CHANGED')
            pinned_document(admission_path, admission_sha)
            pinned_document(job / 'control' / 'integration-admission.json', value['integration_admission_sha256'])
            pinned_document(job / 'control' / 'external-profile-control-proof.json',
                            value['external_profile_control_proof_sha256'])
            verify_actual_proofs(value, os.geteuid())
            pin_runtime(value['interpreter'])
            receipt['after_source_pins_valid'] = True
            receipt['after_packet_pins'] = after_pins
            receipt['actual_quota_after'] = mount_observation(job / 'volume', job / 'quota.img', os.geteuid())
        except BaseException as error:
            add_error(receipt['errors'], error, 'after-source-runtime-quota-verification')
    finally:
        receipt['interrupted_signals'] = list(INTERRUPTS)
        receipt['raw_image_export_required'] = True
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        # No success file or test result is invented, including when the child was killed.
        raw = json_bytes(receipt)
        need(len(raw) <= DOCUMENT_BYTES, 'RECEIPT_BOUND_EXCEEDED_RAW_IMAGE_STILL_RETAINED')
        create_file(job / 'control' / 'lifecycle-receipt.json', raw)
    okay = bool(receipt['child'] and receipt['child']['returncode'] == 0 and
                receipt['child']['reason'] == 'process-exit-zero' and not receipt['child']['errors'] and
                receipt['collection']['source_tree_complete'] and receipt['after_source_pins_valid'] and
                not receipt['errors'] and not receipt['interrupted_signals'])
    return {'status': 'LOCAL_PROCESS_AND_NEUTRAL_COPY_VERIFIED_CUSTODY_PENDING' if okay else
                     'FAILURE_RETAINED_REQUIRES_REVIEW',
            'exit_code': 0 if okay else 1, 'receipt': str(job / 'control' / 'lifecycle-receipt.json'),
            'raw_image_still_required': True}


def finalize_image(value, life_manifest_sha, owner, receipt_sha, admission_sha):
    """Privileged separate final step: ordinary unmount only, then immutable byte reference."""
    need(os.geteuid() == 0 and value['format'] == ADMISSION_FORMAT and value['status'] == STATUS and
         value['owner_uid'] == owner and value['lifecycle_manifest_sha256'] == life_manifest_sha,
         'EXPLICIT_REVIEWED_FINALIZATION_CONTEXT')
    check_global(value)
    job = explicit_path(value['job_root'])
    receipt, _ = pinned_document(job / 'control' / 'lifecycle-receipt.json', receipt_sha, owner=owner)
    need(receipt['format'] == 'scientific-posix-lifecycle-receipt-v1' and
         receipt['admission_sha256'] == admission_sha and
         receipt['lifecycle_manifest_sha256'] == life_manifest_sha and
         receipt['integration_manifest_sha256'] == value['integration_manifest_sha256'], 'PINNED_TERMINAL_RECEIPT')
    child = receipt['child']
    need(child is not None and child['quiescent'] is True and
         (child['pgid'] is None or process_group_gone(child['pgid'])),
         'PRODUCERS_MUST_BE_TERMINAL_BEFORE_IMAGE_FINALIZATION')
    quota, _ = pinned_document(job / 'control' / 'quota-proof.json', value['quota_proof_sha256'], owner=owner)
    actual = mount_observation(job / 'volume', job / 'quota.img', owner)
    need(quota['format'] == 'scientific-posix-quota-denial-v1' and
         quota['owner_uid'] == owner and quota['job_root'] == str(job) and
         quota['lifecycle_manifest_sha256'] == life_manifest_sha and quota['actual_mount'] == actual,
         'SAME_PREPARED_IMAGE_AND_MOUNT_REQUIRED_BEFORE_UNMOUNT')
    umount = pin_runtime(quota['installed_tools']['umount'])
    # Only exact NEW finalization logs are written. No lazy/forced unmount, detach, removal or retry.
    logs = job / 'control' / 'finalize'
    new_dir(logs, owner=owner)
    result = run_process([umount, str(job / 'volume')], job, logs, seconds=TOOL_SECONDS,
                         owner=owner, file_limit=IMAGE_BYTES, log_limit=TOOL_LOG_BYTES)
    for leaf in ('stdout.bin', 'stderr.bin'):
        os.chown(logs / leaf, owner, -1, follow_symlinks=False)
    create_file(job / 'control' / 'finalize-process.json', json_bytes(result), owner=owner)
    need(result['returncode'] == 0 and result['quiescent'] and result['reason'] == 'process-exit-zero' and
         not result['errors'], 'UNMOUNT_FAILED_RETAIN_RAW_IMAGE_AND_MOUNT')
    lines = read_kernel('/proc/self/mountinfo', 256 << 10).decode('ascii').splitlines()
    need(all(line.split(' ')[4] != str(job / 'volume') and
             line.split(' ')[2] != actual['major_minor'] for line in lines),
         'IMAGE_FILESYSTEM_STILL_MOUNTED_IN_CURRENT_NAMESPACE')
    # The ordinary mount helper created an autoclear loop. A remaining backing
    # association is a refusal, never permission to detach a possibly live image.
    backing_path = '/sys/block/' + actual['source'].rsplit('/', 1)[1] + '/loop/backing_file'
    try:
        backing = read_kernel(backing_path, 2048).strip()
    except FileNotFoundError:
        backing = b''
    need(not backing, 'LOOP_BACKING_ASSOCIATION_STILL_ACTIVE_RETAIN_IMAGE')
    parent = owned_dir(job, owner=owner)
    fd = None
    try:
        fd = os.open('quota.img', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        os.fsync(fd)
    finally:
        close_owned(fd, parent)
    reference = hash_file(job / 'quota.img', IMAGE_BYTES, owner=owner, exact=IMAGE_BYTES)
    reference.update(format='scientific-posix-closed-image-reference-v1',
                     lifecycle_manifest_sha256=life_manifest_sha, lifecycle_receipt_sha256=receipt_sha,
                     mount_absent=True, raw_source_retained=True,
                     semantic_tree_complete=bool(receipt.get('collection') and
                                                  receipt['collection']['source_tree_complete']),
                     instruction='DATA_ONLY_NEVER_MOUNT_EXTRACT_IMPORT_OR_EXECUTE_UNTRUSTED_CONTENTS')
    create_file(job / 'control' / 'closed-image-reference.json', json_bytes(reference), owner=owner)
    return {'status': 'CLOSED_IMAGE_BYTES_REFERENCED_TRANSPORT_STILL_REQUIRED',
            'image': str(job / 'quota.img'), 'reference': str(job / 'control' / 'closed-image-reference.json')}


def main():
    require_linux()
    if len(sys.argv) == 2 and sys.argv[1] == '_memory-denial-child':
        return memory_probe_child()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'probe-memory', 'supervise', 'finalize-image',
                                           'verify-neutral', 'verify-prefix', 'verify-image'))
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--context', type=explicit_path, required=True)
    parser.add_argument('--context-sha256', required=True)
    parser.add_argument('--owner-uid', type=int)
    parser.add_argument('--receipt-sha256')
    parser.add_argument('--data', type=explicit_path)
    args = parser.parse_args()
    life_packet = Path(__file__).absolute().parent
    manifest, _, _ = check_packet(
        life_packet, MANIFEST_NAME, args.manifest_sha256, LIFE_NAMES,
        owner=args.owner_uid if os.geteuid() == 0 and args.owner_uid is not None else None)
    need(manifest['format'] == 'scientific-posix-lifecycle-source-packet-v1' and manifest['profile'] == FORMAT and
         manifest['status'] == 'SOURCE_ONLY_REQUIRES_INDEPENDENT_FIRST_FINDINGS',
         'EXACT_EXTERNALLY_PINNED_LIFECYCLE_SOURCE_PACKET')
    owner = args.owner_uid if os.geteuid() == 0 and args.owner_uid is not None else None
    context, _ = pinned_document(args.context, args.context_sha256, owner=owner)
    os.umask(0o077)
    if args.action == 'prepare':
        result = prepare_quota(context, args.manifest_sha256)
    elif args.action == 'probe-memory':
        need(context['format'] == PREPARE_FORMAT and
             context['status'] == 'AUTHORIZED_REVIEWED_NEW_QUOTA_PREPARATION_ONLY' and
             context['owner_uid'] == os.geteuid() and
             context['lifecycle_manifest_sha256'] == args.manifest_sha256,
             'PINNED_PREPARATION_CONTEXT')
        check_global(context)
        quota, _ = pinned_document(explicit_path(context['job_root']) / 'control' / 'quota-proof.json',
                                   sha(context['quota_proof_sha256']))
        need(quota['lifecycle_manifest_sha256'] == args.manifest_sha256 and
             quota['actual_mount'] == mount_observation(explicit_path(context['job_root']) / 'volume',
                                                        explicit_path(context['job_root']) / 'quota.img',
                                                        os.geteuid()),
             'ACTUAL_PREPARED_QUOTA_REQUIRED_BEFORE_MEMORY_PROBE')
        result = prepare_memory(context['job_root'], context['interpreter'], args.manifest_sha256)
    elif args.action == 'supervise':
        result = supervise(context, args.manifest_sha256, args.context_sha256, life_packet, args.context)
    elif args.action == 'finalize-image':
        integer(args.owner_uid, 1, (1 << 31) - 1)
        result = finalize_image(context, args.manifest_sha256, args.owner_uid,
                                sha(args.receipt_sha256), args.context_sha256)
    elif args.action == 'verify-prefix':
        need(args.data is not None, 'EXPLICIT_DATA_ONLY_PREFIX_PATH_REQUIRED')
        result = verify_prefix(args.data, context)
    elif args.action == 'verify-neutral':
        need(args.data is not None and context['format'] in
             ('scientific-posix-neutral-reference-v1', 'scientific-posix-neutral-prefix-reference-v1'),
             'EXTERNALLY_PINNED_NEUTRAL_REFERENCE')
        result = verify_neutral(args.data, expected=context)
    else:
        need(args.data is not None and context['format'] == 'scientific-posix-closed-image-reference-v1' and
             context['mount_absent'] is True, 'EXTERNALLY_PINNED_CLOSED_IMAGE_REFERENCE')
        result = hash_file(args.data, IMAGE_BYTES, exact=IMAGE_BYTES)
        need(result['bytes'] == context['bytes'] and result['sha256'] == context['sha256'],
             'DELIVERED_IMAGE_BYTES_MISMATCH')
        result['status'] = 'BYTE_COPY_VERIFIED_NO_SEMANTIC_SUCCESS_CLAIM'
    write_all(1, json_bytes(result))
    return result.get('exit_code', 0)


if __name__ == '__main__':
    raise SystemExit(main())
