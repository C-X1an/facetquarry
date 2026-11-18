"""Bounded 22-control Linux proof job. Source only until separately admitted.

All fixtures live in the new quota image. No SPI run/receipt is synthesized.
The existing evidence.py bytes capture the controller and original22 command.
"""
import sys

if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
    raise SystemExit('REQUIRE_PYTHON_MINUS_I_MINUS_S_MINUS_B')

import argparse
import hashlib
import importlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import time


BRANCH = 'refs/heads/scientific-posix-proof-20261115'
ADMISSION = 'verification/scientific-posix-proof-admission-20261115.json'
ADMISSION_FORMAT = 'scientific-posix-proof-job-admission-v1'
ADMISSION_STATUS = 'AUTHORIZED_REVIEWED_ORIGINAL22_ONLY'
LIFE_SHA = '25469beefb73ab1fe449d890c773ce967743d9ff1389a6bb278d845db0744f54'
EVIDENCE_SHA = 'f3e187eeefc5e0c0208572b58df3e41110b8591be6a1b476d11343836ef8d469'
COMMON_SHA = '15f8f1027ffcc94c3219f1c6a7c86788aeb62d5531056cc5825d11a9d33367cf'
BASE_BYTES = 1_493_172_224
OTHER_BYTES = 603_979_776
BASELINE_CEILING = 9_850_000_000
IMAGE_BYTES = 268_435_456
MEMORY_BYTES = 536_870_912
SOURCE_BYTES = 16 << 20
SUPPLEMENT_BYTES = 64 << 20
PAYLOAD_BYTES = 304 << 20
ENTRY_LIMIT = 4096
SMALL = 256 << 10
STREAM_BYTES = 2 << 20
IO_BYTES = 65536
LIFE_NAMES = frozenset({'scientific_posix_lifecycle.py', 'test_scientific_posix_lifecycle.py',
    'README.md', 'BOUNDS.md', 'ADMISSION.template.json', 'PREPARE.template.json'})
RUNTIME_PATHS = {'python': '/usr/bin/python3.12', 'mke2fs': '/usr/sbin/mke2fs',
    'mount': '/usr/bin/mount', 'umount': '/usr/bin/umount', 'git': '/usr/bin/git',
    'sudo': '/usr/bin/sudo', 'env': '/usr/bin/env'}
STOP = []
ACTIVE = set()
TRUSTED_UID = os.getuid()


def need(ok, message):
    if not ok:
        raise RuntimeError(message)


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, 'BOUNDED_TYPED_INTEGER')
    return value


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) and value != '0' * 64,
         'INDEPENDENT_NONZERO_SHA256_REQUIRED')
    return value


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                       allow_nan=False) + '\n').encode('ascii')


def decode(raw, maximum=SMALL):
    need(SMALL <= maximum <= 4 << 20 and type(raw) is bytes and len(raw) <= maximum,
         'BOUNDED_JSON_DOCUMENT')
    def pairs(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'DUPLICATE_JSON_KEY')
            out[key] = value
        return out
    def number(text):
        need(len(text) <= 20, 'INTEGER_TOKEN_BOUND')
        return integer(int(text), -(1 << 63), (1 << 63) - 1)
    def refuse(_):
        raise RuntimeError('FLOAT_OR_NONFINITE_REFUSED')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_int=number,
                      parse_float=refuse, parse_constant=refuse)


def decode_command_receipt(raw):
    """Accept only the real wrapper's finite top-level elapsed duration."""
    need(type(raw) is bytes and len(raw) <= SMALL, 'BOUNDED_COMMAND_RECEIPT')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def finite(text):
        need(len(text) <= 64, 'RECEIPT_NUMBER_TOKEN_BOUND')
        value = float(text)
        need(math.isfinite(value), 'NONFINITE_COMMAND_RECEIPT')
        return value
    def refuse(_):
        raise RuntimeError('NONFINITE_COMMAND_RECEIPT')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                       parse_float=finite, parse_constant=refuse)
    need(type(value) is dict and type(value.get('schema_version')) is int and value['schema_version'] == 1 and
         value.get('evidence_type') == 'command', 'ACTUAL_COMMAND_RECEIPT_SCHEMA')
    duration = value.get('duration_seconds')
    need(type(duration) in (int, float) and 0 <= duration <= 1200 and math.isfinite(duration),
         'BOUNDED_FINITE_COMMAND_DURATION')
    # Validate every other value through the unchanged integer-only decoder.
    # The original receipt bytes remain the hash/provenance input, untouched.
    checked = decode(encode({**value, 'duration_seconds': 0}))
    checked['duration_seconds'] = duration
    return checked


def fault(error, operation):
    # No environment dump, credential redaction or unbounded traceback.
    result = {'operation': operation[:80], 'type': type(error).__name__[:80],
              'errno': getattr(error, 'errno', None), 'message': str(error)[:512],
              'message_truncated': len(str(error)) > 512}
    if isinstance(error, BaseExceptionGroup):
        pending, leaves, visited = [(error, 0)], [], 0
        truncated = result['message_truncated']
        while pending and len(leaves) < 8 and visited < 24:
            current, depth = pending.pop()
            visited += 1
            if isinstance(current, BaseExceptionGroup) and depth < 6:
                truncated |= len(current.exceptions) > 8
                pending.extend((child, depth + 1) for child in current.exceptions[:8])
            else:
                leaves.append({'type': type(current).__name__[:48],
                    'errno': getattr(current, 'errno', None), 'message': str(current)[:96],
                    'message_truncated': len(str(current)) > 96})
                truncated |= isinstance(current, BaseExceptionGroup) or len(str(current)) > 96
        result.update(leaf_errors=leaves, details_truncated=truncated or bool(pending))
    return result


def sig(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def close_all(*fds):
    primary, failures = sys.exception(), []
    for fd in dict.fromkeys(fd for fd in fds if fd is not None):
        try:
            os.close(fd)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise BaseExceptionGroup('OWNED_CLOSE_FAILURES',
            ([primary] if primary is not None else []) + failures) from None


def path(value):
    value = Path(value)
    need(value.is_absolute() and '..' not in value.parts and len(value.parts) <= 32 and
         re.fullmatch('/[A-Za-z0-9_./-]{1,1000}', str(value)) and
         all(len(part) <= 64 for part in value.parts[1:]), 'EXPLICIT_SAFE_ABSOLUTE_PATH')
    return value


def chain(value, *, owner=None, final_private=False):
    value = path(value)
    owner = TRUSTED_UID if owner is None else owner
    for index in range(1, len(value.parts)):
        item = Path(*value.parts[:index + 1])
        info = item.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, owner) and
             info.st_mode & 0o022 == 0, 'TRUSTED_DIRECTORY_CHAIN')
        if index == len(value.parts) - 1 and final_private:
            need(info.st_uid == owner and info.st_mode & 0o077 == 0, 'PRIVATE_FINAL_DIRECTORY')
    return value


def file_ref(value, maximum, *, exact=None, owner=None, timeout=90):
    value = path(value)
    chain(value.parent, owner=TRUSTED_UID if owner is None else owner)
    before = value.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         (owner is None or before.st_uid == owner) and 0 <= before.st_size <= maximum and
         (exact is None or before.st_size == exact), 'BOUNDED_UNIQUE_REGULAR_FILE')
    fd, count, started, hashed = None, 0, time.monotonic(), hashlib.sha256()
    try:
        fd = os.open(value, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(sig(before) == sig(os.fstat(fd)), 'FILE_OPEN_IDENTITY')
        while True:
            need(time.monotonic() - started <= timeout, 'FILE_HASH_WALL_BOUND')
            raw = os.read(fd, IO_BYTES)
            if not raw:
                break
            count += len(raw)
            need(count <= maximum, 'FILE_GROWTH_BOUND')
            hashed.update(raw)
        need(count == before.st_size and sig(before) == sig(os.fstat(fd)) == sig(value.lstat()),
             'FILE_CHANGED_DURING_READ')
        return {'bytes': count, 'sha256': hashed.hexdigest(), 'identity': list(sig(before)),
                'allocated_bytes': before.st_blocks * 512}
    finally:
        close_all(fd)


def read(value, maximum=SMALL):
    reference = file_ref(value, maximum)
    fd = None
    try:
        fd = os.open(value, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(list(sig(os.fstat(fd))) == reference['identity'], 'READ_OPEN_CHANGED')
        pieces, used = [], 0
        while True:
            block = os.read(fd, min(IO_BYTES, maximum - used + 1))
            if not block:
                break
            pieces.append(block)
            used += len(block)
            need(used <= maximum, 'READ_BOUND')
        raw = b''.join(pieces)
        need(len(raw) == reference['bytes'] and hashlib.sha256(raw).hexdigest() == reference['sha256'] and
             list(sig(os.fstat(fd))) == reference['identity'], 'READ_CHANGED')
        return raw
    finally:
        close_all(fd)


def make_dir(value, uid, gid):
    value = path(value)
    chain(value.parent, owner=uid)
    os.mkdir(value, 0o700)
    os.chown(value, uid, gid, follow_symlinks=False)


def create(value, raw, uid, gid, maximum=SMALL):
    need(type(raw) is bytes and len(raw) <= maximum, 'NEW_FILE_BOUND')
    value, fd = path(value), None
    chain(value.parent, owner=uid)
    try:
        fd = os.open(value, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.fchown(fd, uid, gid)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            need(count > 0, 'ZERO_WRITE')
            view = view[count:]
        os.fsync(fd)
    finally:
        close_all(fd)


def copy_new(source, destination, uid, gid, maximum):
    raw = read(source, maximum)
    create(destination, raw, uid, gid, maximum)
    need(file_ref(destination, maximum)['sha256'] == hashlib.sha256(raw).hexdigest(), 'COPY_READBACK')


def root_runtime(name):
    value = path(RUNTIME_PATHS[name])
    chain(value.parent, owner=0)
    info = value.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o022 == 0,
         'PREINSTALLED_ROOT_OWNED_RUNTIME_REQUIRED')
    observed = file_ref(value, 256 << 20, owner=0)
    return {'path': str(value), 'bytes': observed['bytes'], 'sha256': observed['sha256']}


def verify_runtime(row):
    need(set(row) == {'path', 'bytes', 'sha256'}, 'EXACT_RUNTIME_PIN')
    observed = file_ref(row['path'], 256 << 20, exact=row['bytes'], owner=0)
    need(observed['sha256'] == digest(row['sha256']), 'INSTALLED_RUNTIME_CHANGED')
    return row['path']


def clean():
    return {'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'TZ': 'UTC'}


def interrupted(number, _frame):
    if len(STOP) < 16:
        STOP.append(number)


def group_gone(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    return False


def kill_group(pgid, number, errors):
    try:
        os.killpg(pgid, number)
    except ProcessLookupError:
        pass
    except BaseException as error:
        errors.append(fault(error, 'process-group-signal'))


def limits(file_limit=8 << 20):
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CPU, (600, 601))


def bounded(command, cwd, logs, label, uid, gid, *, seconds, as_owner=False, env=None,
            output_limit=SMALL, allow_stop=False, file_limit=8 << 20):
    """One exact command; complete observed prefixes remain even on failure."""
    need(1 <= seconds <= 780 and 1 <= output_limit <= STREAM_BYTES, 'COMMAND_BOUNDS')
    need(1 <= file_limit <= IMAGE_BYTES + 8192, 'CHILD_FILE_LIMIT_BOUND')
    make_dir(logs / label, uid, gid)
    folder = logs / label
    files, pipes, errors = {}, {}, []
    proc = None
    selector = selectors.DefaultSelector()
    reason, term, killed, began = None, None, None, time.monotonic()
    result = {'command': command, 'quiescent': False, 'errors': errors}
    try:
        for name in ('stdout', 'stderr'):
            fd = os.open(folder / (name + '.bin'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            files[name] = {'fd': fd, 'observed': 0, 'retained': 0}
            os.fchown(fd, uid, gid)
        options = {'user': uid, 'group': gid, 'extra_groups': []} if as_owner else {}
        proc = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean() if env is None else env,
            close_fds=True, start_new_session=True, preexec_fn=lambda: limits(file_limit), **options)
        ACTIVE.add(proc.pid)
        create(folder / 'started.json', encode({'pid': proc.pid, 'pgid': proc.pid,
            'command': command, 'owner_uid': uid if as_owner else os.geteuid()}), uid, gid)
        for name, stream in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
            pipes[name] = stream
        while selector.get_map() or proc.poll() is None:
            now = time.monotonic()
            if now - began > seconds:
                reason = reason or 'wall-timeout'
            if STOP and not allow_stop:
                reason = reason or 'controller-interrupted'
            if reason and term is None:
                kill_group(proc.pid, signal.SIGTERM, errors)
                term = now
            if term is not None and now - term >= 2 and killed is None:
                kill_group(proc.pid, signal.SIGKILL, errors)
                killed = now
            if killed is not None and now - killed > 8:
                need(proc.poll() is not None and not selector.get_map(), 'PROCESS_DRAIN_NOT_TERMINAL')
            for key, _ in selector.select(0.05):
                try:
                    raw = os.read(key.fileobj.fileno(), IO_BYTES)
                except BlockingIOError:
                    continue
                if not raw:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                row = files[key.data]
                row['observed'] += len(raw)
                keep = raw[:max(0, output_limit - row['retained'])]
                while keep:
                    count = os.write(row['fd'], keep)
                    need(count > 0, 'ZERO_LOG_WRITE')
                    row['retained'] += count
                    keep = keep[count:]
                if row['observed'] > output_limit:
                    reason = reason or 'output-limit-prefix-retained'
        code = proc.wait(timeout=1)
        if not group_gone(proc.pid):
            reason = reason or 'descendants-after-exit'
            kill_group(proc.pid, signal.SIGKILL, errors)
            end = time.monotonic() + 5
            while not group_gone(proc.pid) and time.monotonic() < end:
                time.sleep(0.05)
        result.update(pid=proc.pid, pgid=proc.pid, exit_code=code,
                      quiescent=group_gone(proc.pid), reason=reason or 'process-exit')
    except BaseException as error:
        errors.append(fault(error, 'bounded-command'))
        if proc is not None:
            kill_group(proc.pid, signal.SIGKILL, errors)
            try:
                proc.wait(timeout=8)
            except BaseException as error2:
                errors.append(fault(error2, 'bounded-wait'))
        result.update(pid=None if proc is None else proc.pid,
                      pgid=None if proc is None else proc.pid,
                      exit_code=None if proc is None else proc.poll(),
                      quiescent=proc is None or group_gone(proc.pid), reason='command-exception')
    finally:
        try:
            selector.close()
        except BaseException as error:
            errors.append(fault(error, 'selector-close'))
        for stream in pipes.values():
            if not stream.closed:
                try:
                    stream.close()
                except BaseException as error:
                    errors.append(fault(error, 'pipe-close'))
        for row in files.values():
            try:
                os.fsync(row['fd'])
            except BaseException as error:
                errors.append(fault(error, 'log-fsync'))
        try:
            close_all(*(row['fd'] for row in files.values()))
        except BaseException as error:
            errors.append(fault(error, 'log-close'))
        if proc is not None:
            ACTIVE.discard(proc.pid)
    result['elapsed_milliseconds'] = int((time.monotonic() - began) * 1000)
    result['streams'] = {name: {key: value for key, value in row.items() if key != 'fd'}
                         for name, row in files.items()}
    for name in files:
        try:
            result['streams'][name]['reference'] = file_ref(folder / (name + '.bin'), output_limit)
        except BaseException as error:
            errors.append(fault(error, 'log-byte-readback'))
    create(folder / 'result.json', encode(result), uid, gid)
    return result


def admission(workspace, expected, own_sha, ref):
    need(ref == BRANCH, 'EXACT_NEW_PROOF_BRANCH_ONLY')
    raw = read(workspace / ADMISSION, 8192)
    need(hashlib.sha256(raw).hexdigest() == digest(expected), 'INDEPENDENT_ADMISSION_DIGEST')
    value = decode(raw)
    fields = {'format', 'status', 'branch', 'attempt_id', 'created_unix_seconds', 'expires_unix_seconds',
        'baseline_including_reserve_bytes', 'global_reserve_bytes', 'fresh_inventory_sha256',
        'base_lifecycle_bytes', 'connector_bytes', 'supplement_bytes', 'other_growth_bytes',
        'no_other_heavy_process', 'independent_review_closed', 'source_pins'}
    need(type(value) is dict and set(value) == fields and value['format'] == ADMISSION_FORMAT and
         value['status'] == ADMISSION_STATUS and value['branch'] == BRANCH and
         value['no_other_heavy_process'] is True and value['independent_review_closed'] is True,
         'EXACT_EXPLICIT_ROOT_ADMISSION')
    need(re.fullmatch('[a-z0-9][a-z0-9-]{0,47}', value['attempt_id']), 'BOUNDED_ATTEMPT_ID')
    now = int(time.time())
    created = integer(value['created_unix_seconds'], 1, (1 << 63) - 1)
    expires = integer(value['expires_unix_seconds'], created + 1, created + 21600)
    need(created - 30 <= now <= expires and now - created <= 21600, 'FRESH_SIX_HOUR_ADMISSION_REQUIRED')
    base = integer(value['baseline_including_reserve_bytes'], 2_000_000_000, BASELINE_CEILING)
    need(value['global_reserve_bytes'] == 2_000_000_000 and value['base_lifecycle_bytes'] == BASE_BYTES and
         value['connector_bytes'] == 536_870_912 and value['supplement_bytes'] == SUPPLEMENT_BYTES and
         value['other_growth_bytes'] == OTHER_BYTES and base + BASE_BYTES + OTHER_BYTES < 12_000_000_000,
         'COMPLETE_FIXED_PEAK_ADMISSION')
    digest(value['fresh_inventory_sha256'])
    need(value['source_pins'] == {'job_script_sha256': own_sha, 'lifecycle_manifest_sha256': LIFE_SHA,
                                 'evidence_sha256': EVIDENCE_SHA, 'common_sha256': COMMON_SHA},
         'EXACT_REVIEWED_SOURCE_PINS')
    return value, raw


def source_inventory(root, *, copy_to=None, uid=None, gid=None, maximum=SOURCE_BYTES):
    """Every checkout source entry; exclude only git and ignored generated roots."""
    rows, used, count, pending, started = [], 0, 0, [(root, Path('.'))], time.monotonic()
    excluded = {'.git', '.local', '.cache', '__pycache__'}
    while pending:
        need(time.monotonic() - started < 90, 'SOURCE_TREE_TIME_BOUND')
        current, relative = pending.pop()
        entries = sorted(os.scandir(current), key=lambda item: item.name)
        need(len(entries) <= ENTRY_LIMIT, 'SOURCE_DIRECTORY_ENTRY_BOUND')
        for entry in entries:
            if relative == Path('.') and entry.name in excluded:
                continue
            count += 1
            need(count <= ENTRY_LIMIT and re.fullmatch('[A-Za-z0-9_.-]{1,128}', entry.name) and
                 entry.name not in ('.', '..'), 'SOURCE_NAME_OR_COUNT_BOUND')
            rel = relative / entry.name
            need(len(str(rel).encode()) <= 512 and len(rel.parts) <= 24, 'SOURCE_PATH_BOUND')
            info = entry.stat(follow_symlinks=False)
            target = None if copy_to is None else copy_to / rel
            if stat.S_ISDIR(info.st_mode):
                if target is not None:
                    make_dir(target, uid, gid)
                pending.append((Path(entry.path), rel))
                rows.append({'path': str(rel), 'kind': 'directory'})
            else:
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4 << 20,
                     'ONLY_BOUNDED_REGULAR_CHECKOUT_SOURCE')
                used += max(info.st_size, info.st_blocks * 512) + 8192
                need(used <= maximum, 'COMPLETE_SOURCE_COPY_RESERVATION')
                reference = file_ref(entry.path, 4 << 20)
                if target is not None:
                    copy_new(entry.path, target, uid, gid, 4 << 20)
                rows.append({'path': str(rel), 'kind': 'regular', 'bytes': reference['bytes'],
                             'sha256': reference['sha256']})
    return {'rows': rows, 'accounted_bytes': used, 'entries': count,
            'sha256': hashlib.sha256(encode(rows)).hexdigest()}


def packet(workspace, destination, uid, gid):
    original = workspace / 'scripts' / 'scientific_lifecycle'
    raw = read(original / 'LIFECYCLE_SOURCE_MANIFEST.json')
    need(hashlib.sha256(raw).hexdigest() == LIFE_SHA, 'PINNED_PUBLIC_LIFECYCLE_MANIFEST')
    manifest = decode(raw)
    rows = manifest['packet_files']
    need(len(rows) == 6 and {row['name'] for row in rows} == LIFE_NAMES, 'EXACT_LIFE_RUNTIME_SELECTION')
    make_dir(destination, uid, gid)
    for row in rows:
        need(set(row) == {'name', 'origin', 'bytes', 'sha256'}, 'PIN_ROW_SCHEMA')
        result = file_ref(original / row['name'], 180000, exact=row['bytes'])
        need(result['sha256'] == row['sha256'], 'CURRENT_PUBLIC_PACKET_PIN')
        copy_new(original / row['name'], destination / row['name'], uid, gid, 180000)
    create(destination / 'LIFECYCLE_SOURCE_MANIFEST.json', raw, uid, gid)
    need(set(os.listdir(destination)) == LIFE_NAMES | {'LIFECYCLE_SOURCE_MANIFEST.json'},
         'NO_ANCILLARY_OR_UNPINNED_RUNTIME_FILES')


def load_life(container, uid):
    folder = container / 'lifecycle'
    need(hashlib.sha256(read(folder / 'LIFECYCLE_SOURCE_MANIFEST.json')).hexdigest() == LIFE_SHA,
         'STAGED_MANIFEST_CHANGED')
    manifest = decode(read(folder / 'LIFECYCLE_SOURCE_MANIFEST.json'))
    need(set(os.listdir(folder)) == LIFE_NAMES | {'LIFECYCLE_SOURCE_MANIFEST.json'}, 'STAGED_EXACT_SET')
    for row in manifest['packet_files']:
        need(file_ref(folder / row['name'], 180000, exact=row['bytes'], owner=uid)['sha256'] == row['sha256'],
             'STAGED_SOURCE_CHANGED')
    need('scientific_posix_lifecycle' not in sys.modules, 'NO_PREEXISTING_LIFE_IMPORT')
    sys.path.insert(0, str(folder))
    spec = importlib.util.find_spec('scientific_posix_lifecycle')
    need(spec is not None and Path(spec.origin) == folder / 'scientific_posix_lifecycle.py', 'EXACT_LIFE_ORIGIN')
    module = importlib.import_module('scientific_posix_lifecycle')
    module.require_linux()
    module.check_packet(folder, module.MANIFEST_NAME, LIFE_SHA, module.LIFE_NAMES, owner=uid)
    return module


def run_inputs(args):
    """Identity comes from the runner's explicit arguments, never partial context."""
    global TRUSTED_UID
    uid = integer(args.owner_uid, 1, (1 << 31) - 1)
    gid = integer(args.owner_gid, 1, (1 << 31) - 1)
    TRUSTED_UID = uid
    need(type(args.run_id) is str and re.fullmatch('[0-9]{1,24}', args.run_id) and
         type(args.run_attempt) is str and re.fullmatch('[0-9]{1,8}', args.run_attempt), 'ACTUAL_RUN_ID')
    need(args.ref == BRANCH and type(args.commit) is str and
         re.fullmatch('[0-9a-f]{40}', args.commit), 'ACTUAL_BRANCH_AND_COMMIT')
    workspace = chain(args.workspace, owner=uid)
    temporary = chain(args.runner_temp, owner=uid)
    own = file_ref(Path(__file__).absolute(), 80000)['sha256']
    need(own == digest(args.job_sha256), 'EXTERNAL_JOB_SOURCE_PIN')
    container = Path('/srv') / ('fq-posix-proof-' + args.run_id + '-' + args.run_attempt)
    if args.container is not None:
        need(args.container == container, 'EXACT_TRUSTED_RUN_NAMESPACE')
    return {'format': 'scientific-posix-proof-recovery-inputs-v1', 'container': str(container),
        'run_id': args.run_id, 'run_attempt': args.run_attempt, 'owner_uid': uid, 'owner_gid': gid,
        'workspace': str(workspace), 'runner_temp': str(temporary), 'job_source_sha256': own,
        'admission_sha256': digest(args.admission_sha256), 'checkout_commit': args.commit,
        'branch': args.ref, 'host_attribution_roots': [str(workspace), str(temporary),
                                                    str(workspace.parent.parent / '_actions')]}


def repair_readability(target, uid, gid):
    """Metadata only on exact root/runner-owned entries; never open a special file."""
    target = path(target)
    chain(target.parent, owner=uid)
    before = target.lstat()
    need((stat.S_ISREG(before.st_mode) and before.st_nlink == 1 or stat.S_ISDIR(before.st_mode)) and
         before.st_uid in (0, uid) and before.st_gid in (0, gid) and before.st_mode & 0o022 == 0,
         'EXACT_ROOT_OR_RUNNER_OWNED_READABILITY_REPAIR_ONLY')
    fd = None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        fd = os.open(target, flags | (os.O_DIRECTORY if stat.S_ISDIR(before.st_mode) else 0))
        need(sig(before) == sig(os.fstat(fd)), 'REPAIR_OPEN_IDENTITY')
        if (before.st_uid, before.st_gid) != (uid, gid):
            os.fchown(fd, uid, gid)
        required = 0o700 if stat.S_ISDIR(before.st_mode) else 0o400
        if before.st_mode & required != required:
            os.fchmod(fd, stat.S_IMODE(before.st_mode) | required)
        after = os.fstat(fd)
        need(sig(after) == sig(target.lstat()) and after.st_uid == uid and after.st_gid == gid,
             'REPAIR_PATH_CHANGED')
        return after
    finally:
        close_all(fd)


def private_namespace(container, uid, gid, *, repair=False):
    need(re.fullmatch('/srv/fq-posix-proof-[0-9]{1,24}-[0-9]{1,8}', str(container)),
         'EXACT_OWNED_RUN_NAMESPACE')
    info = repair_readability(container, uid, gid) if repair else container.lstat()
    need(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == (uid, gid) and
         info.st_mode & 0o077 == 0, 'EXACT_PRIVATE_NAMESPACE_UID_GID')
    chain(container, owner=uid, final_private=True)


def recovery_record(container):
    value = decode(read(container / 'recovery.json'))
    fields = {'format', 'container', 'run_id', 'run_attempt', 'owner_uid', 'owner_gid', 'workspace',
        'runner_temp', 'job_source_sha256', 'admission_sha256', 'checkout_commit', 'branch',
        'host_attribution_roots', 'runtime'}
    need(type(value) is dict and set(value) == fields and
         value['format'] == 'scientific-posix-proof-recovery-inputs-v1' and
         value['container'] == str(container) and value['branch'] == BRANCH and
         re.fullmatch('[0-9]{1,24}', value['run_id']) and re.fullmatch('[0-9]{1,8}', value['run_attempt']) and
         container == Path('/srv/fq-posix-proof-' + value['run_id'] + '-' + value['run_attempt']) and
         re.fullmatch('[0-9a-f]{40}', value['checkout_commit']), 'EXACT_RECOVERY_METADATA')
    uid = integer(value['owner_uid'], 1, (1 << 31) - 1)
    gid = integer(value['owner_gid'], 1, (1 << 31) - 1)
    private_namespace(container, uid, gid)
    workspace = chain(value['workspace'], owner=uid)
    temporary = chain(value['runner_temp'], owner=uid)
    need(value['host_attribution_roots'] == [str(workspace), str(temporary),
         str(workspace.parent.parent / '_actions')] and set(value['runtime']) == set(RUNTIME_PATHS),
         'EXACT_RECOVERY_PATHS_AND_RUNTIME_NAMES')
    for name, row in value['runtime'].items():
        need(row['path'] == RUNTIME_PATHS[name], 'EXACT_INSTALLED_RUNTIME_PATH')
        verify_runtime(row)
    digest(value['job_source_sha256'])
    digest(value['admission_sha256'])
    return value


def context(container):
    retained = recovery_record(container)
    value = decode(read(container / 'control' / 'context.json'))
    need(set(value) == {'format', 'container', 'owner_uid', 'owner_gid', 'runtime', 'preparation',
         'source_root', 'source_inventory_sha256', 'git_only_path', 'lifecycle_manifest_sha256',
         'admission_sha256', 'checkout_commit', 'branch', 'host_attribution_roots'} and
         value['format'] == 'scientific-posix-proof-controller-context-v1' and
         value['container'] == str(container) and value['lifecycle_manifest_sha256'] == LIFE_SHA and
         all(value[key] == retained[key] for key in ('owner_uid', 'owner_gid', 'runtime',
             'admission_sha256', 'checkout_commit', 'branch', 'host_attribution_roots')) and
         value['source_root'] == str(container / 'source' / 'checkout') and
         value['git_only_path'] == str(container / 'support' / 'git-only') and
         value['preparation']['owner_uid'] == retained['owner_uid'] and
         value['preparation']['owner_gid'] == retained['owner_gid'] and
         value['preparation']['job_root'] == str(container / 'job'),
         'EXACT_RETAINED_CONTROLLER_CONTEXT')
    digest(value['source_inventory_sha256'])
    return value


def evidence_command(ctx, command, category, seconds):
    source = Path(ctx['source_root'])
    for name, expected in (('evidence.py', EVIDENCE_SHA), ('common.py', COMMON_SHA)):
        need(file_ref(source / 'scripts' / name, SMALL)['sha256'] == expected, 'EXISTING_EVIDENCE_BYTES_CHANGED')
    bootstrap = (
        'import pathlib,runpy,sys;'
        'p=pathlib.Path(sys.argv[1]);'
        'sys.path.insert(0,str(p.parent));'
        'sys.argv=[str(p)]+sys.argv[2:];'
        'runpy.run_path(str(p),run_name="__main__")')
    return [ctx['runtime']['python']['path'], '-I', '-S', '-B', '-c', bootstrap,
            str(source / 'scripts' / 'evidence.py'), '--category', category,
            '--requirements', 'AC-020', '--timeout', str(seconds), '--', *command]


def as_root_command(ctx, action):
    return [ctx['runtime']['sudo']['path'], '-n', '--', ctx['runtime']['env']['path'], '-i',
            'LANG=C.UTF-8', 'LC_ALL=C.UTF-8', 'TZ=UTC', ctx['runtime']['python']['path'], '-I', '-S', '-B',
            str(Path(ctx['source_root']) / 'scripts' / 'run_scientific_lifecycle_job.py'),
            action, '--container', ctx['container']]


def verify_sources(ctx):
    source = Path(ctx['source_root'])
    observed = source_inventory(source)
    need(observed['sha256'] == ctx['source_inventory_sha256'], 'RETAINED_SOURCE_TREE_CHANGED')
    for row in ctx['runtime'].values():
        verify_runtime(row)
    return observed['sha256']


def host_attribution(ctx):
    """Known new checkout/action/temp allocations; metadata only, never their contents."""
    total, count, reports, began = 0, 0, [], time.monotonic()
    for value in ctx['host_attribution_roots']:
        root = path(value)
        pending, used, entries = [root], 0, 0
        while pending:
            need(time.monotonic() - began < 45, 'HOST_ATTRIBUTION_TIME_BOUND')
            current = pending.pop()
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            count += 1
            entries += 1
            need(count <= 16384, 'HOST_ATTRIBUTION_ENTRY_BOUND')
            if stat.S_ISDIR(info.st_mode):
                used += max(info.st_blocks * 512, 4096)
                with os.scandir(current) as iterator:
                    for item in iterator:
                        pending.append(Path(item.path))
                        need(len(pending) <= 16384, 'HOST_ATTRIBUTION_PENDING_BOUND')
            else:
                # Include links as allocations, never follow them into global tool caches.
                used += max(info.st_size, info.st_blocks * 512) + 4096
            need(total + used <= SUPPLEMENT_BYTES, 'KNOWN_CHECKOUT_ACTION_TEMP_SUPPLEMENT_EXCEEDED')
        total += used
        reports.append({'root': str(root), 'accounted_bytes': used, 'entries': entries})
    return {'format': 'scientific-posix-proof-host-allocation-observation-v1',
        'roots': reports, 'total_accounted_bytes': total, 'ceiling_bytes': SUPPLEMENT_BYTES,
        'hard_quota': False, 'scope': 'Known checkout/action/temp roots before upload; no credential contents read.'}


def process_image_writers(volume, image):
    """Conservative current-namespace check. Any unreadable relevant process refuses."""
    result, started = [], time.monotonic()
    entries = [item for item in os.scandir('/proc') if item.name.isdigit()]
    need(len(entries) <= 4096, 'PROCESS_SCAN_COUNT_BOUND')
    for entry in entries:
        need(time.monotonic() - started < 15, 'PROCESS_SCAN_TIME_BOUND')
        pid = int(entry.name)
        if pid == os.getpid():
            continue
        proc = Path('/proc') / entry.name
        try:
            # Only the root controller and admitted owner can have project writers.
            if proc.stat().st_uid not in (0, context_uid):
                continue
            relevant = False
            try:
                cwd = os.readlink(proc / 'cwd')
                relevant |= cwd == str(volume) or cwd.startswith(str(volume) + '/')
            except FileNotFoundError:
                continue
            fds = list(os.scandir(proc / 'fd'))
            need(len(fds) <= 4096, 'PROCESS_FD_SCAN_BOUND')
            for fd in fds:
                try:
                    target = os.readlink(fd.path)
                except FileNotFoundError:
                    continue
                relevant |= target == str(image) or target.startswith(str(volume) + '/')
            if relevant:
                result.append(pid)
        except FileNotFoundError:
            continue
        except PermissionError as error:
            raise RuntimeError('CANNOT_PROVE_NO_RELEVANT_PROCESS_WRITER') from error
    return result


def mounts():
    with open('/proc/self/mountinfo', 'rb') as stream:
        raw = stream.read(SMALL + 1)
    need(len(raw) <= SMALL, 'MOUNTINFO_BOUND')
    return [line.split() for line in raw.decode('ascii').splitlines()]


def loop_associations(image):
    answer, started = [], time.monotonic()
    entries = list(os.scandir('/sys/block'))
    need(len(entries) <= 4096, 'SYSFS_BLOCK_COUNT_BOUND')
    for item in entries:
        need(time.monotonic() - started < 10, 'SYSFS_BLOCK_TIME_BOUND')
        if not re.fullmatch('loop[0-9]+', item.name):
            continue
        try:
            with open(Path(item.path) / 'loop' / 'backing_file', 'rb') as stream:
                raw = stream.read(2049)
            need(len(raw) <= 2048, 'LOOP_BACKING_BOUND')
            target = raw.decode('ascii').strip()
            if target in (str(image), str(image).lstrip('/')):
                answer.append('/dev/' + item.name)
        except FileNotFoundError:
            pass
    return answer


context_uid = -1


def close_image(container, ctx, life, *, recovery=False):
    """Independent 22-only image closure; never fabricates an SPI lifecycle receipt."""
    global context_uid
    uid, gid = ctx['owner_uid'], ctx['owner_gid']
    context_uid = uid
    control, job = container / 'control', container / 'job'
    image, volume = job / 'quota.img', job / 'volume'
    result = {'format': 'scientific-posix-proof-image-closure-v1', 'complete_closed_image': False,
              'image_retained': image.exists(), 'recovery': recovery, 'errors': [],
              'cloud_native_custody': 'NOT_VERIFIED', 'scientific_qualification': 'NOT_CLAIMED'}
    try:
        need(not ACTIVE, 'OWNED_COMMAND_STILL_ACTIVE')
        info = image.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid in (0, uid) and
             info.st_mode & 0o077 == 0 and info.st_size == IMAGE_BYTES and
             info.st_blocks * 512 >= IMAGE_BYTES, 'FULL_OWNED_IMAGE_REQUIRED_FOR_COMPLETE_REFERENCE')
        need(not process_image_writers(volume, image), 'ACTUAL_PRODUCER_WRITERS_REMAIN')
        current = [row for row in mounts() if row[4] == str(volume)]
        need(len(current) <= 1, 'ONE_EXACT_MOUNT_ONLY')
        expected = None
        if current:
            # This inspects actual identity even when quota proof creation failed.
            expected = life.mount_observation(volume, image, uid)
            attempt = control / 'unmount-attempt.json'
            need(not attempt.exists(), 'UNMOUNT_ALREADY_ATTEMPTED_NO_AUTOMATIC_RETRY')
            create(attempt, encode({'actual_mount': expected, 'image_identity': list(sig(info)),
                                   'pid': os.getpid()}), uid, gid)
            umount = verify_runtime(ctx['runtime']['umount'])
            command = bounded([umount, str(volume)], container, control / 'commands',
                              'ordinary-unmount', uid, gid, seconds=60, output_limit=65536, allow_stop=True)
            need(command['exit_code'] == 0 and command['quiescent'] and
                 command['reason'] == 'process-exit' and not command['errors'],
                 'ORDINARY_UNMOUNT_FAILED_RETAIN_ALL_NO_RETRY')
        need(not any(row[4] == str(volume) or (expected and row[2] == expected['major_minor'])
                     for row in mounts()), 'IMAGE_FILESYSTEM_STILL_MOUNTED')
        need(not loop_associations(image), 'ACTIVE_LOOP_BACKING_ASSOCIATION_REMAINS')
        need(not process_image_writers(volume, image), 'WRITER_REMAINS_AFTER_UNMOUNT')
        # Root-created partial-setup image metadata may be repaired only for upload readability.
        if info.st_uid != uid or info.st_gid != gid:
            os.chown(image, uid, gid, follow_symlinks=False)
        fd = os.open(image, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            close_all(fd)
        reference = file_ref(image, IMAGE_BYTES, exact=IMAGE_BYTES, owner=uid, timeout=90)
        reference.update(format='scientific-posix-closed-image-reference-v1', mount_absent=True,
            lifecycle_manifest_sha256=LIFE_SHA,
            proof_context_sha256=file_ref(control / 'context.json', SMALL)['sha256'],
            instruction='DATA_ONLY_NEVER_MOUNT_EXTRACT_IMPORT_OR_EXECUTE_RETURNED_CONTENTS')
        if (control / 'closed-image-reference.json').exists():
            previous = decode(read(control / 'closed-image-reference.json'))
            need((previous['bytes'], previous['sha256']) == (reference['bytes'], reference['sha256']),
                 'RETAINED_CLOSED_IMAGE_REFERENCE_MISMATCH')
        else:
            create(control / 'closed-image-reference.json', encode(reference), uid, gid)
        result.update(complete_closed_image=True, raw_image=reference,
                      assertion='FULL_BYTES_ONLY_NO_EXTRACTION_OR_SCIENTIFIC_SUCCESS')
    except BaseException as error:
        result['errors'].append(fault(error, 'image-closure'))
        # An unsafe/active/partial image is still retained and uploaded as failure data.
        try:
            info = image.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid in (0, uid):
                os.chown(image, uid, gid, follow_symlinks=False)
                result['retained_image_bytes'] = info.st_size
        except BaseException as error2:
            result['errors'].append(fault(error2, 'failed-image-observation'))
    return result


def actual_controls_receipt(ctx):
    root = Path(ctx['source_root'])
    folder = root / '.local' / 'evidence'
    candidates = []
    for entry in os.scandir(folder):
        if entry.is_dir(follow_symlinks=False):
            try:
                raw = read(Path(entry.path) / 'receipt.json')
                value = decode_command_receipt(raw)
                if value.get('category') == 'scientific-posix-original22':
                    candidates.append((Path(entry.path), value, raw))
            except FileNotFoundError:
                pass
    need(len(candidates) == 1, 'ONE_ACTUAL_ORIGINAL22_RECEIPT_REQUIRED')
    location, receipt, raw = candidates[0]
    streams = {}
    for name in ('stdout', 'stderr'):
        relative = Path(receipt[name])
        need(not relative.is_absolute() and '..' not in relative.parts and
             root / relative == location / (name + '.txt'), 'EXACT_RECEIPT_STREAM_PATH')
        data = read(root / relative, STREAM_BYTES)
        need(hashlib.sha256(data).hexdigest() == receipt[name + '_sha256'], 'ACTUAL_RECEIPT_STREAM_HASH')
        streams[name] = data
    text = streams['stderr'].decode('utf-8', 'strict')
    lines = text.splitlines()
    tests = [line for line in lines if re.fullmatch(r'test_[A-Za-z0-9_]+ \(__main__\.LifecycleControls\.test_[A-Za-z0-9_]+\) \.\.\. ok', line)]
    summaries = re.findall(r'^Ran ([0-9]+) tests? in [0-9.]+s$', text, flags=re.MULTILINE)
    need(len(tests) == 22 and len({line.split(' ', 1)[0] for line in tests}) == 22 and summaries == ['22'] and
         lines[-1:] == ['OK'] and receipt['status'] == 'PASS' and receipt['exit_code'] == 0 and
         receipt['termination_reason'] is None and receipt['source_before'] == receipt['source_after'],
         'ACTUAL22_STREAMS_AND_RECEIPT_MUST_AGREE_ZERO_FAILURE_ERROR_SKIP')
    return {'format': 'scientific-posix-external-profile-control-proof-v1',
        'lifecycle_manifest_sha256': LIFE_SHA, 'actual_linux_posix': True, 'actual_tests_run': len(tests),
        'actual_failures': 0, 'actual_errors': 0, 'actual_skips': 0,
        'process_returncode': receipt['exit_code'], 'all_control_prefixes_retained': True,
        'actual_command_receipt_sha256': hashlib.sha256(raw).hexdigest(),
        'receipt_relative_path': str(location.relative_to(root) / 'receipt.json'),
        'scope': 'Original22 only; actual kernel/closure/custody are separate facts.'}


def controller(container):
    need(os.geteuid() == 0, 'ROOT_CONTROLLER_REQUIRED')
    ctx = context(container)
    uid, gid = ctx['owner_uid'], ctx['owner_gid']
    life = load_life(container, uid)
    result = {'format': 'scientific-posix-original22-job-result-v1', 'status': 'FAILURE_RETAINED',
              'original22_verified': False, 'quota_prepared': False, 'memory_probed': False,
              'spi_cases': 'NOT_RUN', 'scientific_qualification': 'NOT_CLAIMED', 'errors': []}
    try:
        verify_sources(ctx)
        create(container / 'control' / 'host-before.json', encode(host_attribution(ctx)), uid, gid)
        need(not STOP, 'INTERRUPTED_BEFORE_PREPARATION')
        prep = ctx['preparation']
        life.prepare_quota(prep, LIFE_SHA)
        result['quota_prepared'] = True
        memory = bounded([ctx['runtime']['python']['path'], '-I', '-S', '-B',
            str(Path(ctx['source_root']) / 'scripts' / 'run_scientific_lifecycle_job.py'),
            '_memory-owner', '--container', str(container)], container,
            container / 'control' / 'commands', 'memory-owner', uid, gid, seconds=35,
            as_owner=True, output_limit=65536)
        need(memory['exit_code'] == 0 and memory['quiescent'] and not memory['errors'] and
             memory['reason'] == 'process-exit', 'ACTUAL_MEMORY_OWNER_PROCESS_FAILED')
        proof = decode(read(container / 'job' / 'control' / 'memory-proof.json'))
        need(proof['probe']['actual_getrlimit'] == [MEMORY_BYTES, MEMORY_BYTES] and
             proof['probe']['denial_observed'] is True and proof['probe']['exception'] == 'MemoryError' and
             proof['probe']['attempted_bytes'] == MEMORY_BYTES + 1 and proof['process']['quiescent'] is True,
             'ACTUAL_UNPRIVILEGED_MEMORY_PROOF')
        result['memory_probed'] = True
        result['headroom'] = life.require_source_headroom(container / 'job' / 'volume', uid)
        need(not STOP, 'INTERRUPTED_BEFORE_ORIGINAL22')
        original = [ctx['runtime']['python']['path'], '-I', '-S', '-B',
            str(Path(ctx['source_root']) / 'scripts' / 'run_scientific_lifecycle_job.py'),
            '_controls-owner', '--container', str(container)]
        command = evidence_command(ctx, original, 'scientific-posix-original22', 240)
        env = {**clean(), 'PATH': ctx['git_only_path']}
        nested = bounded(command, Path(ctx['source_root']), container / 'control' / 'commands',
            'original22-evidence', uid, gid, seconds=280, as_owner=True, env=env)
        need(nested['exit_code'] == 0 and nested['quiescent'] and not nested['errors'] and
             nested['reason'] == 'process-exit', 'ORIGINAL22_EVIDENCE_COMMAND_FAILED')
        actual = actual_controls_receipt(ctx)
        create(container / 'job' / 'control' / 'external-profile-control-proof.json', encode(actual), uid, gid)
        result['original22_verified'] = True
        result['actual_proof_sha256'] = file_ref(container / 'job' / 'control' /
            'external-profile-control-proof.json', SMALL)['sha256']
        verify_sources(ctx)
        create(container / 'control' / 'host-after-controls.json', encode(host_attribution(ctx)), uid, gid)
    except BaseException as error:
        result['errors'].append(fault(error, 'original22-controller'))
    finally:
        result['closure'] = close_image(container, ctx, life)
        result['interrupted_signals'] = list(STOP)
        if result['original22_verified'] and result['closure']['complete_closed_image'] and not result['errors'] and not STOP:
            result['status'] = 'ORIGINAL22_AND_CLOSED_IMAGE_BYTES_VERIFIED_CUSTODY_PENDING'
        create(container / 'control' / 'controller-result.json', encode(result), uid, gid)
    return 0 if result['status'].startswith('ORIGINAL22_AND_') else 1


def owner_action(container, action):
    ctx = context(container)
    need(os.geteuid() == ctx['owner_uid'] and os.geteuid() != 0, 'ACTUAL_UNPRIVILEGED_OWNER_REQUIRED')
    life = load_life(container, ctx['owner_uid'])
    for row in ctx['runtime'].values():
        verify_runtime(row)
    if action == '_memory-owner':
        life.prepare_memory(container / 'job', ctx['runtime']['python'], LIFE_SHA)
        return 0
    command = [ctx['runtime']['python']['path'], '-I', '-S', '-B',
        str(container / 'lifecycle' / 'test_scientific_posix_lifecycle.py'),
        '--test-root', str(container / 'job' / 'volume' / 'work' / 'original22'),
        '--lifecycle-sha256', '3589e499156427ed0f1b790a00feaf2a2b90f3d3a245188f62911c5b6147a858',
        '--python', ctx['runtime']['python']['path'], '--python-bytes', str(ctx['runtime']['python']['bytes']),
        '--python-sha256', ctx['runtime']['python']['sha256']]
    # evidence.py adds its own cache variables; reset before the original test exec.
    os.execve(command[0], command, clean())


def outbound_inventory(container, uid, gid):
    """Admit every namespace file or reject the whole payload, regardless of test outcome."""
    rows, files, errors, missing = [], [], [], []
    total, accounted, count, began = 0, 0, 0, time.monotonic()
    pending = [(container, '')]
    complete = False
    try:
        need(not any((row[4] == str(container) or row[4].startswith(str(container) + '/')) and
             row[4] != str(container / 'job' / 'volume') for row in mounts()), 'UNEXPECTED_NAMESPACE_MOUNT')
        for relative in ('recovery.json', 'control/context.json', 'source', 'lifecycle',
                         'job/control', 'job/exports', 'job/quota.img'):
            try:
                (container / relative).lstat()
            except FileNotFoundError:
                missing.append(relative)
        while pending:
            need(time.monotonic() - began < 180, 'OUTBOUND_INVENTORY_TIME_BOUND')
            target, relative = pending.pop()
            count += 1
            need(count <= ENTRY_LIMIT and len(relative.encode('ascii')) <= 768, 'OUTBOUND_ENTRY_PATH_BOUND')
            need(relative not in ('outbound-inventory.json', 'custody-result.json', 'upload-manifest.json'),
                 'REUSED_CUSTODY_OUTPUT_REFUSED')
            info = target.lstat()
            row = {'path': relative or '.', 'mode': info.st_mode, 'uid': info.st_uid,
                   'gid': info.st_gid, 'bytes': info.st_size, 'blocks_512': info.st_blocks}
            rows.append(row)
            if relative == 'job/volume':
                image = (container / 'job' / 'quota.img').lstat()
                need(stat.S_ISDIR(info.st_mode) and stat.S_ISREG(image.st_mode) and image.st_nlink == 1,
                     'MOUNT_ALIAS_REQUIRES_RETAINED_RAW_IMAGE')
                row.update(kind='raw-image-alias-not-traversed', represented_by='job/quota.img')
            elif relative == 'support/git-only/git' and stat.S_ISLNK(info.st_mode):
                target_text = os.readlink(target)
                need(target_text == RUNTIME_PATHS['git'], 'EXACT_INSTALLED_GIT_REFERENCE_ONLY')
                root_runtime('git')
                accounted += max(info.st_size, info.st_blocks * 512) + 4096
                row.update(kind='installed-runtime-reference', link_text=target_text,
                           representation='Complete link text only; installed binary is not new payload.')
            elif stat.S_ISDIR(info.st_mode):
                info = repair_readability(target, uid, gid)
                accounted += max(info.st_blocks * 512, 4096)
                row.update(kind='directory', uid=uid, gid=gid, mode=info.st_mode)
                with os.scandir(target) as iterator:
                    for item in iterator:
                        need(re.fullmatch('[A-Za-z0-9_.-]{1,64}', item.name) and item.name not in ('.', '..'),
                             'OUTBOUND_NO_GLOB_NEWLINE_OR_UNSAFE_NAME')
                        pending.append((Path(item.path), (relative + '/' if relative else '') + item.name))
                        need(count + len(pending) <= ENTRY_LIMIT, 'OUTBOUND_DIRECTORY_PENDING_BOUND')
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                repair_readability(target, uid, gid)  # Before hashing, even without context.json.
                maximum = IMAGE_BYTES if relative == 'job/quota.img' else 8 << 20
                reference = file_ref(target, maximum, owner=uid, timeout=90)
                total += reference['bytes']
                accounted += max(reference['bytes'], reference['allocated_bytes']) + 4096
                row.update(kind='regular', uid=uid, gid=gid, reference=reference)
                files.append({'path': str(path(target)), **reference})
            else:
                row['kind'] = 'UNSAFE_OUTSIDE_IMAGE'
                raise RuntimeError('UNSAFE_OUTSIDE_IMAGE_NO_FOLLOW_NO_UPLOAD: ' + relative[:512])
            need(total <= PAYLOAD_BYTES and accounted <= PAYLOAD_BYTES, 'COMPLETE_ARTIFACT_CONTENT_ALLOCATION_BOUND')
        complete = True
    except BaseException as error:
        errors.append(fault(error, 'namespace-inventory-admission'))
    inventory = {'format': 'scientific-posix-proof-outbound-inventory-v2', 'rows': rows,
        'regular_payload_bytes': total, 'accounted_namespace_bytes': accounted, 'entries': count,
        'errors': errors, 'missing_expected': missing, 'safe_complete_scan': complete,
        'complete_regular_file_inventory': complete and not missing,
        'unexamined_or_unreadable_bytes': 'NONE_OBSERVED' if complete else 'UNKNOWN_CUSTODY_INCOMPLETE',
        'mount_alias_representation': 'All job/volume fixture bytes require the full job/quota.img.',
        'cloud_native_custody': 'INCOMPLETE_UNTIL_SEPARATELY_VERIFIED'}
    if len(encode(inventory)) > 4 << 20:
        return {'format': inventory['format'], 'safe_complete_scan': False, 'complete_regular_file_inventory': False,
            'errors': [{'operation': 'inventory-metadata', 'message': 'OUTBOUND_METADATA_BOUND'}],
            'omitted_metadata_and_namespace_bytes': 'UNKNOWN_CUSTODY_INCOMPLETE'}, []
    return inventory, files


FALLBACK_NAMES = {'driver.txt': 80000, 'workflow.txt': 24000, 'proof.txt': 24000,
                  'admission.txt': 8192, 'status.jsonl': 8192}


def fallback_root(inputs):
    root = Path(inputs['runner_temp']) / ('fq-posix-fallback-' + inputs['run_id'] + '-' + inputs['run_attempt'])
    chain(root, owner=inputs['owner_uid'], final_private=True)
    info = root.lstat()
    need(info.st_gid == inputs['owner_gid'], 'EXACT_FALLBACK_GID')
    return root


def append_fallback(inputs, value):
    fd = None
    try:
        target = fallback_root(inputs) / 'status.jsonl'
        raw = encode(value)
        need(len(raw) <= 4096, 'FALLBACK_ERROR_RECORD_BOUND')
        before = file_ref(target, 8192, owner=inputs['owner_uid'])
        need(before['bytes'] + len(raw) <= 8192, 'FALLBACK_TOTAL_ERROR_BOUND')
        fd = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(list(sig(os.fstat(fd))) == before['identity'] and
             os.fstat(fd).st_gid == inputs['owner_gid'], 'EXACT_FALLBACK_APPEND_IDENTITY')
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            need(count > 0, 'ZERO_FALLBACK_WRITE')
            view = view[count:]
        os.fsync(fd)
    finally:
        close_all(fd)


def upload_files(inputs, container_files):
    files = list(container_files)
    fallback, fallback_bytes = fallback_root(inputs), 0
    for name, maximum in FALLBACK_NAMES.items():
        target = fallback / name
        try:
            reference = file_ref(target, maximum, owner=inputs['owner_uid'])
        except FileNotFoundError:
            need(name != 'status.jsonl', 'FALLBACK_STATUS_REQUIRED')
            continue  # Initial status explicitly records each absent source.
        need(reference['identity'][4] == inputs['owner_gid'], 'EXACT_FALLBACK_FILE_GID')
        fallback_bytes += reference['bytes']
        files.append({'path': str(target), **reference})
    need(fallback_bytes <= 100000 + 2 * 8192 and len(files) + 1 <= ENTRY_LIMIT, 'UPLOAD_FIXED_FALLBACK_AND_FILE_COUNT_BOUND')
    return files


def exact_upload_paths(files):
    paths = [str(path(row['path'])) for row in files]
    need(len(paths) == len(set(paths)) and all('\n' not in value for value in paths), 'UNIQUE_LITERAL_UPLOAD_FILES')
    raw = ('\n'.join(paths) + '\n').encode('ascii')
    need(len(raw) <= SMALL - 256, 'UPLOAD_PATH_LIST_BOUND')
    return raw


def recover(args):
    need(os.geteuid() == 0, 'ROOT_RECOVERY_REQUIRED')
    inputs = run_inputs(args)
    container = Path(inputs['container'])
    uid, gid = inputs['owner_uid'], inputs['owner_gid']
    result = {'format': 'scientific-posix-proof-custody-result-v1',
        'closure_command_exit_code': None, 'closure_command_complete': False,
        'closure_evidence_available': False, 'host_bounds_admitted': False,
        'custody': 'INCOMPLETE', 'cloud_native_custody': 'NOT_VERIFIED', 'errors': [],
        'if_full_manifest_absent': 'ALL_NAMESPACE_IMAGE_LOG_SOURCE_PREFIX_BYTES_OMITTED_UNKNOWN'}
    try:
        private_namespace(container, uid, gid, repair=True)
        for folder in (container / 'control', container / 'control' / 'commands'):
            try:
                folder.lstat()
            except FileNotFoundError:
                make_dir(folder, uid, gid)
            repair_readability(folder, uid, gid)
        try:
            create(container / 'control' / 'recovery-once.lock', encode({'pid': os.getpid()}), uid, gid)
            retained = recovery_record(container)
            need(all(retained[key] == value for key, value in inputs.items()), 'TRUSTED_RECOVERY_ARGUMENTS_MATCH')
            ctx = context(container)
            # Complete context/packet/evidence are required for closure, never for inventory.
            command = evidence_command(ctx, as_root_command(ctx, '_close-root'), 'scientific-posix-image-recovery', 120)
            observed = bounded(command, Path(ctx['source_root']), container / 'control' / 'commands',
                'recovery-evidence', uid, gid, seconds=150, as_owner=True,
                env={**clean(), 'PATH': ctx['git_only_path']}, allow_stop=True)
            result.update(closure_command_exit_code=observed['exit_code'], closure_evidence_available=True,
                closure_command_complete=observed['exit_code'] == 0 and observed['quiescent'] and
                observed['reason'] == 'process-exit' and not observed['errors'])
        except BaseException as error:
            result['errors'].append(fault(error, 'closure-unavailable-no-substitute-proof'))
        try:
            host = host_attribution(inputs)
            create(container / 'control' / 'host-before-upload.json', encode(host), uid, gid)
            result['host_bounds_admitted'] = True
        except BaseException as error:
            result['errors'].append(fault(error, 'host-bounds-reject-full-payload'))
        create(container / 'control' / 'recovery-status.json', encode(result), uid, gid)
        inventory, files = outbound_inventory(container, uid, gid)
        create(container / 'outbound-inventory.json', encode(inventory), uid, gid, 4 << 20)
        preliminary = result['host_bounds_admitted'] and inventory['safe_complete_scan']
        result.update(safe_complete_scan=inventory['safe_complete_scan'],
            complete_regular_file_inventory=inventory['complete_regular_file_inventory'],
            missing_expected=inventory.get('missing_expected', []),
            final_admission='REQUIRES_EXACT_UPLOAD_MANIFEST' if preliminary else 'REJECTED_FALLBACK_ONLY')
        create(container / 'custody-result.json', encode(result), uid, gid)
        append_fallback(inputs, result)
        if preliminary:
            for name in ('outbound-inventory.json', 'custody-result.json'):
                files.append({'path': str(container / name), **file_ref(container / name, 4 << 20, owner=uid)})
            files = upload_files(inputs, files)
            manifest = {'format': 'scientific-posix-proof-safe-exact-upload-v1', 'inputs': inputs,
                'status': 'SAFE_EXACT_FILES_ADMITTED_CUSTODY_UNVERIFIED', 'files': files,
                'test_success_is_not_an_admission_condition': True,
                'missing_unreadable_or_omitted_data_never_qualifies_a_gate': True}
            raw = encode(manifest)
            need(len(raw) <= 4 << 20, 'UPLOAD_MANIFEST_METADATA_BOUND')
            need(sum(row['bytes'] for row in files) + len(raw) <= PAYLOAD_BYTES and
                 inventory['accounted_namespace_bytes'] + sum(max(row['bytes'], row['allocated_bytes']) + 4096
                 for row in files if not row['path'].startswith(str(container) + '/') or
                 row['path'] in (str(container / 'outbound-inventory.json'), str(container / 'custody-result.json'))) +
                 len(raw) + 8192 <= PAYLOAD_BYTES, 'FINAL_PAYLOAD_AND_ALLOCATION_BOUND')
            exact_upload_paths(files + [{'path': str(container / 'upload-manifest.json')}])
            create(container / 'upload-manifest.json', raw, uid, gid, 4 << 20)
            result['payload_admitted'] = True
    except BaseException as error:
        result['errors'].append(fault(error, 'full-payload-rejected'))
        result['payload_admitted'] = False
        try:
            append_fallback(inputs, {'custody': 'INCOMPLETE', 'payload_admitted': False,
                'omitted_namespace_bytes': 'ALL_OR_UNKNOWN; NO_FULL_PAYLOAD_UPLOAD', 'errors': result['errors'][-3:]})
        except BaseException as error2:
            result['errors'].append(fault(error2, 'fallback-error-append-unavailable'))
    result.setdefault('payload_admitted', False)
    print(json.dumps(result, sort_keys=True))
    # Ten still publishes the admitted complete available failure payload. One selects fallback only.
    if not result['payload_admitted']:
        return 1
    return 0 if result['closure_command_complete'] and result['complete_regular_file_inventory'] and not result['errors'] else 10


def emit_upload(args):
    """Unprivileged last check; output contains literal files, never a recursive glob."""
    inputs = run_inputs(args)
    uid, gid = inputs['owner_uid'], inputs['owner_gid']
    need((os.geteuid(), os.getegid()) == (uid, gid), 'RUNNER_OUTPUT_WRITER_UID_GID')
    container = Path(inputs['container'])
    private_namespace(container, uid, gid)
    target = container / 'upload-manifest.json'
    manifest = decode(read(target, 4 << 20), 4 << 20)
    need(set(manifest) == {'format', 'inputs', 'status', 'files', 'test_success_is_not_an_admission_condition',
         'missing_unreadable_or_omitted_data_never_qualifies_a_gate'} and
         manifest['format'] == 'scientific-posix-proof-safe-exact-upload-v1' and manifest['inputs'] == inputs and
         manifest['status'] == 'SAFE_EXACT_FILES_ADMITTED_CUSTODY_UNVERIFIED' and
         manifest['test_success_is_not_an_admission_condition'] is True and
         manifest['missing_unreadable_or_omitted_data_never_qualifies_a_gate'] is True and
         type(manifest['files']) is list and 1 <= len(manifest['files']) < ENTRY_LIMIT, 'EXACT_SAFE_UPLOAD_SCHEMA')
    files, began, total = manifest['files'], time.monotonic(), 0
    fallback = fallback_root(inputs)
    for row in files:
        need(time.monotonic() - began < 90 and set(row) == {'path', 'bytes', 'sha256', 'identity', 'allocated_bytes'},
             'UPLOAD_RECHECK_TIME_AND_ROW_BOUND')
        item = path(row['path'])
        need((item.is_relative_to(container) and item != container and
             not item.is_relative_to(container / 'job' / 'volume')) or
             (item.parent == fallback and item.name in FALLBACK_NAMES), 'UPLOAD_FILE_SCOPE')
        observed = file_ref(item, IMAGE_BYTES if item == container / 'job' / 'quota.img' else 8 << 20, owner=uid)
        need(row == {'path': str(item), **observed} and observed['identity'][4] == gid and
             observed['identity'][2] & stat.S_IRUSR, 'UPLOAD_BYTE_IDENTITY_AND_READABILITY_RECHECK')
        total += observed['bytes']
    reference = file_ref(target, 4 << 20, owner=uid)
    need(total + reference['bytes'] <= PAYLOAD_BYTES, 'UPLOAD_RECHECK_PAYLOAD_BOUND')
    raw_paths = exact_upload_paths(files + [{'path': str(target)}])
    output = path(args.output_file)
    need(output.parent == Path(inputs['runner_temp']) / '_runner_file_commands' and
         re.fullmatch('set_output_[A-Za-z0-9_-]{1,80}', output.name), 'EXACT_RUNNER_OUTPUT_FILE')
    chain(output.parent, owner=uid)
    before = output.lstat()
    data = b'paths<<FQ_SAFE_EXACT_UPLOAD_END\n' + raw_paths + b'FQ_SAFE_EXACT_UPLOAD_END\n'
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == uid and
         before.st_gid == gid and before.st_mode & 0o022 == 0 and before.st_size + len(data) <= SMALL,
         'FINITE_RUNNER_OUTPUT_FILE_BOUND')
    fd = None
    try:
        fd = os.open(output, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
        need(sig(before) == sig(os.fstat(fd)), 'RUNNER_OUTPUT_OPEN_IDENTITY')
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            need(count > 0, 'ZERO_RUNNER_OUTPUT_WRITE')
            view = view[count:]
        os.fsync(fd)
    finally:
        close_all(fd)
    print('SAFE_EXACT_FILES_ADMITTED_CUSTODY_STILL_UNVERIFIED')
    return 0


def bootstrap(args):
    global TRUSTED_UID
    need(os.geteuid() == 0 and sys.platform == 'linux' and sys.version_info >= (3, 12), 'ACTUAL_ROOT_LINUX_PYTHON312')
    uid = integer(args.owner_uid, 1, (1 << 31) - 1)
    gid = integer(args.owner_gid, 1, (1 << 31) - 1)
    TRUSTED_UID = uid
    workspace = chain(args.workspace, owner=uid)
    need(re.fullmatch('[0-9]{1,24}', args.run_id) and re.fullmatch('[0-9]{1,8}', args.run_attempt), 'ACTUAL_RUN_ID')
    need(re.fullmatch('[0-9a-f]{40}', args.commit), 'ACTUAL_CHECKOUT_COMMIT')
    own = file_ref(Path(__file__).absolute(), 80000)['sha256']
    need(own == digest(args.job_sha256), 'EXTERNAL_JOB_SOURCE_PIN')
    admitted, raw_admission = admission(workspace, args.admission_sha256, own, args.ref)
    runtime = {name: root_runtime(name) for name in RUNTIME_PATHS}
    need(Path(sys.executable) == Path(runtime['python']['path']), 'EXACT_INSTALLED_PYTHON_EXECUTABLE')
    for name, expected in (('evidence.py', EVIDENCE_SHA), ('common.py', COMMON_SHA)):
        need(file_ref(workspace / 'scripts' / name, SMALL)['sha256'] == expected, 'PINNED_EVIDENCE_DEPENDENCY')
    inputs = run_inputs(args)
    container = Path(inputs['container'])
    make_dir(container, uid, gid)
    # Durable identity precedes every source/packet byte. A partial record is only failure data.
    create(container / 'recovery.json', encode({**inputs, 'runtime': runtime}), uid, gid)
    for leaf in ('control', 'source', 'support'):
        make_dir(container / leaf, uid, gid)
    make_dir(container / 'control' / 'commands', uid, gid)
    make_dir(container / 'source' / 'checkout', uid, gid)
    selected = source_inventory(workspace, copy_to=container / 'source' / 'checkout', uid=uid, gid=gid)
    create(container / 'control' / 'checkout-source-inventory.json', encode(selected), uid, gid, 4 << 20)
    packet(workspace, container / 'lifecycle', uid, gid)
    make_dir(container / 'support' / 'git-only', uid, gid)
    os.symlink(runtime['git']['path'], container / 'support' / 'git-only' / 'git')
    prep = {'format': 'scientific-posix-quota-prepare-v1',
        'status': 'AUTHORIZED_REVIEWED_NEW_QUOTA_PREPARATION_ONLY',
        'profile': 'scientific-posix-complete-failure-copy-v1', 'owner_uid': uid, 'owner_gid': gid,
        'job_root': str(container / 'job'), 'lifecycle_manifest_sha256': LIFE_SHA,
        'interpreter': runtime['python'], 'installed_tools': {name: runtime[name] for name in ('mke2fs', 'mount', 'umount')},
        'reserved_job_bytes': BASE_BYTES, 'reserved_job_entries': 20608, 'image_capacity_bytes': IMAGE_BYTES,
        'neutral_copy_equivalents': 4, 'raw_image_copy_equivalents': 2, 'control_overhead_bytes': 16 << 20,
        'baseline_excluding_reserve_bytes': admitted['baseline_including_reserve_bytes'] - 2_000_000_000,
        'other_growth_bytes': OTHER_BYTES, 'global_reserve_bytes': 2_000_000_000,
        'fresh_global_inventory_sha256': admitted['fresh_inventory_sha256'],
        'all_attributable_allocations_admitted': True, 'no_other_heavy_process': True}
    ctx = {'format': 'scientific-posix-proof-controller-context-v1', 'container': str(container),
        'owner_uid': uid, 'owner_gid': gid, 'runtime': runtime, 'preparation': prep,
        'source_root': str(container / 'source' / 'checkout'), 'source_inventory_sha256': selected['sha256'],
        'git_only_path': str(container / 'support' / 'git-only'), 'lifecycle_manifest_sha256': LIFE_SHA,
        'admission_sha256': args.admission_sha256, 'checkout_commit': args.commit, 'branch': args.ref,
        'host_attribution_roots': inputs['host_attribution_roots']}
    create(container / 'control' / 'root-admission.json', raw_admission, uid, gid, 8192)
    create(container / 'control' / 'context.json', encode(ctx), uid, gid)
    command = evidence_command(ctx, as_root_command(ctx, '_controller-root'), 'scientific-posix-complete-proof-job', 660)
    result = bounded(command, Path(ctx['source_root']), container / 'control' / 'commands',
        'complete-job-evidence', uid, gid, seconds=720, as_owner=True,
        env={**clean(), 'PATH': ctx['git_only_path']}, output_limit=SMALL,
        file_limit=IMAGE_BYTES + 8192)
    create(container / 'control' / 'outer-command.json', encode(result), uid, gid)
    print(json.dumps({'status': 'CONTROLLER_RETURNED_RECOVERY_AND_CUSTODY_REQUIRED',
        'exit_code': result['exit_code'], 'container': str(container)}, sort_keys=True))
    return 0 if result['exit_code'] == 0 and result['quiescent'] and not result['errors'] else 1


def main():
    global TRUSTED_UID
    need(sys.platform == 'linux' and os.name == 'posix', 'LINUX_ONLY_NO_SKIP')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('bootstrap', 'recover', 'emit-upload', '_controller-root', '_memory-owner', '_controls-owner', '_close-root'))
    parser.add_argument('--container', type=path)
    parser.add_argument('--workspace', type=path)
    parser.add_argument('--runner-temp', type=path)
    parser.add_argument('--owner-uid', type=int)
    parser.add_argument('--owner-gid', type=int)
    parser.add_argument('--run-id')
    parser.add_argument('--run-attempt')
    parser.add_argument('--ref')
    parser.add_argument('--commit')
    parser.add_argument('--job-sha256')
    parser.add_argument('--admission-sha256')
    parser.add_argument('--output-file', type=path)
    args = parser.parse_args()
    if args.action == 'bootstrap':
        return bootstrap(args)
    if args.action == 'recover':
        return recover(args)
    if args.action == 'emit-upload':
        return emit_upload(args)
    need(args.container is not None and re.fullmatch('/srv/fq-posix-proof-[0-9]{1,24}-[0-9]{1,8}', str(args.container)),
         'EXACT_OWNED_RUN_NAMESPACE')
    owner = args.container.lstat()
    need(stat.S_ISDIR(owner.st_mode) and owner.st_uid > 0 and owner.st_mode & 0o077 == 0,
         'EXACT_PRIVATE_NAMESPACE_OWNER')
    TRUSTED_UID = owner.st_uid
    ctx = context(args.container)
    if args.action == '_controller-root':
        return controller(args.container)
    if args.action in ('_memory-owner', '_controls-owner'):
        return owner_action(args.container, args.action)
    need(os.geteuid() == 0, 'ROOT_IMAGE_CLOSURE_REQUIRED')
    life = load_life(args.container, ctx['owner_uid'])
    result = close_image(args.container, ctx, life, recovery=True)
    create(args.container / 'control' / 'recovery-closure.json', encode(result), ctx['owner_uid'], ctx['owner_gid'])
    return 0 if result['complete_closed_image'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
