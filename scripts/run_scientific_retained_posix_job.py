"""Bounded full-volume Linux job for Original22 and the retained POSIX cases.

The draft remains disabled until the exact driver, helpers, workflow and custody
path are independently verified. All fixtures live in the new quota image.
"""
import sys

if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
    raise SystemExit('REQUIRE_PYTHON_MINUS_I_MINUS_S_MINUS_B')

import argparse
from contextlib import contextmanager
import fcntl
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


BRANCH = 'refs/heads/scientific-posix-retained-r4'
ADMISSION = 'verification/scientific-posix-retained-all-admission.json'
ADMISSION_FORMAT = 'scientific-posix-full-volume-retained-job-admission-v1'
ADMISSION_STATUS = 'AUTHORIZED_REVIEWED_ORIGINAL22_AND_RETAINED_SPI3_ONLY'
ADMISSION_ENABLED = True
LIFE_SHA = '293bd67af9844af32d0bf7af9aeac4eaf0245b77bd2700b99e0170446c710e15'  # Set only after the complete lifecycle packet is frozen.
LIFE_MODULE_SHA = 'dde6e2e9a4bea25e122cb7f943ec805f8ff75865aba3734282319bbdd4824644'
SPI_SHA = '6b79a1e10108a8322888d854469beef618c36df2e4d3bac2790100e0eab33271'
HELPER_SHA = {
    'scientific_posix_full_volume_admission': 'e4fd45992af79237a37ff4623d06e7d7a035b43db2190167af1bea8cc0a70dd7',
    'scientific_posix_producer_group': 'd46fbbb65328ae52287b0d9fe4e6485b6bf09779658d08affcf7bdde5abf540a',
    'scientific_posix_transport_limits': '5181679129b6a69595603dcebe0a003ee8f61662b63a44b2a96dd040f4211753',
    'scientific_posix_failure_custody': '56750c4b87976123254d4bc8756f350c8ec20fec5f295ac10a6c8eb25b2e74d4',
}
EVIDENCE_SHA = 'f3e187eeefc5e0c0208572b58df3e41110b8591be6a1b476d11343836ef8d469'
COMMON_SHA = '15f8f1027ffcc94c3219f1c6a7c86788aeb62d5531056cc5825d11a9d33367cf'
BASE_BYTES = 1_493_172_224
OTHER_BYTES = 166_723_584
BASELINE_CEILING = 12_000_000_000 - BASE_BYTES - OTHER_BYTES - 1
NATIVE_TRANSFER = 'direct-native-single-bounded-archive'
IMAGE_BYTES = 268_435_456
MEMORY_BYTES = 536_870_912
SOURCE_BYTES = (16 << 20) + (128 << 10)  # Under the unchanged aggregate support and transport caps.
SUPPLEMENT_BYTES = 64 << 20
PAYLOAD_BYTES = 495 << 20
DRIVER_BYTES = 112_000
KNOWN_SUPPORT_TAIL_BYTES = 14 << 20
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
DIAGNOSTIC_GUARDS = frozenset('''
    ACTIVE_LOOP_BACKING_ASSOCIATION_REMAINS ACTIVE_OR_UNCONFIRMED_IMAGE_MUST_NOT_BE_SELECTED
    ACTUAL_ATOMIC_ENOSPC_DENIAL_REQUIRED_RETAIN_PROBE ACTUAL_COMPLETE_SPI_AND_NEUTRAL_PAIR_REQUIRED
    ACTUAL_AVAILABLE_QUOTA_SPACE_CANNOT_FIT_UNWEAKENED_SOURCE_AND_HEADROOM
    ACTUAL_EXT4_LOOP_NODEV_NOSUID_NOEXEC_REQUIRED ACTUAL_HEADROOM_REQUIRED_BEFORE_SATURATION
    ACTUAL_INHERITED_CONTROLLER_LIMITS_REQUIRED ACTUAL_LOOP_CAPACITY_REQUIRED ACTUAL_MEMORY_OWNER_PROCESS_FAILED
    ACTUAL_NO_NEW_PRIVILEGES_REQUIRED ACTUAL_PRODUCER_WRITERS_REMAIN ACTUAL_RETAINED_SPI_COMMAND_FAILED
    ACTUAL_UNPRIVILEGED_MEMORY_PROOF ACTUAL22_STREAMS_AND_RECEIPT_MUST_AGREE_ZERO_FAILURE_ERROR_SKIP
    BOUND_PRE_ENROLLMENT_LOCK_REQUIRED CANNOT_PROVE_NO_RELEVANT_PROCESS_WRITER COMPLETE_SOURCE_COPY_RESERVATION
    DISTINCT_EMPTY_QUOTA_PROBE_FILES_REQUIRED EXACT_FULL_VOLUME_PREPARATION_RESULT_REQUIRED
    EXACT_FULL_VOLUME_QUOTA_PROOF_REQUIRED_FOR_ORIGINAL22 EXACT_QUOTA_INODES_REQUIRED_AFTER_RELEASE_INTENT
    EXACT_SCRATCH_RELEASE_AND_RESTORED_HEADROOM_REQUIRED
    EXACT_SUCCESSFUL_RESERVATION_AND_UNMODIFIED_PROBE_REQUIRED_BEFORE_RELEASE
    EXACT_PRIVATE_MOUNT_REQUIRED EXACT_RETAINED_CONTROLLER_CONTEXT EXACT_ROOT_CONTROLLER_LEASE_REQUIRED
    FILL_AND_IMMEDIATE_ENOSPC_ZERO_RETENTION_REQUIRED FULL_CAPACITY_IMAGE_ALLOCATION_REQUIRED
    FULL_IMAGE_ALLOCATION_FAILED FULL_OWNED_IMAGE_REQUIRED_FOR_COMPLETE_REFERENCE
    FULL_VOLUME_HEADROOM_AND_ORIGINAL_PROBE_MUST_BE_PRESERVED FULL_VOLUME_QUOTA_LIVE_HEADROOM_CHANGED
    FULL_VOLUME_QUOTA_MOUNT_CHANGED FULL_VOLUME_QUOTA_RECORD_PIN_MISMATCH FULL_VOLUME_QUOTA_RECORD_SOURCE_MISMATCH
    FULL_VOLUME_QUOTA_RETAINED_INODE_CHANGED IMAGE_FILESYSTEM_STILL_MOUNTED IMAGE_OPEN_BINDING
    INTERRUPTED_BEFORE_MEMORY_PROBE INTERRUPTED_BEFORE_ORIGINAL22 INTERRUPTED_BEFORE_PREPARATION INTERRUPTED_BEFORE_SPI
    KNOWN_CHECKOUT_ACTION_TEMP_SUPPLEMENT_EXCEEDED LOOP_BACKING_IMAGE_PATH_MISMATCH
    MOUNTINFO_SYSFS_AND_ACTUAL_BLOCK_DEVICE_IDENTITY_REQUIRED MOUNT_DEVICE_GEOMETRY_AND_CAPACITY_BINDING
    NO_PRODUCER_WITHOUT_COMPLETE_SUPPORT_CAPACITY ONE_ACTUAL_ORIGINAL22_RECEIPT_REQUIRED ONE_EXACT_MOUNT_ONLY
    ORDINARY_UNMOUNT_FAILED_RETAIN_ALL_NO_RETRY ORIGINAL22_EVIDENCE_COMMAND_FAILED OWNED_COMMAND_STILL_ACTIVE
    OWNED_PRODUCER_AND_ALL_NESTED_SESSIONS_MUST_BE_TERMINAL QUOTA_SETUP_COMMAND_FAILED_RETAIN_NEW_JOB
    QUOTA_SATURATION_INTERRUPTED_BEFORE_INITIALIZATION QUOTA_SATURATION_INTERRUPTED_BEFORE_FILL
    QUOTA_SATURATION_INTERRUPTED_BEFORE_RAW_PROBE QUOTA_SATURATION_INTERRUPTED_BEFORE_RELEASE
    RETAINED_CLOSED_IMAGE_REFERENCE_MISMATCH RETAINED_QUOTA_PROBES_MUST_BE_ON_THE_ADMITTED_IMAGE
    SAME_EXACT_MOUNTED_IMAGE_REQUIRED_FOR_CLOSED_BYTE_HASH SAME_QUOTA_PROOF_MOUNT_REQUIRED_FOR_CLOSURE
    SAME_ROOT_VERIFIED_QUOTA_PROOF_REQUIRED_AFTER_ORIGINAL22 SOURCE_COPY_OR_SET_CHANGED
    STABLE_EMPTY_PROBE_AND_SATURATED_VOLUME_REQUIRED STABLE_SATURATED_VOLUME_AND_LIMITS_REQUIRED_AFTER_DENIAL
    OFF_MOUNT_ATTACHMENT_CHANGED OFF_MOUNT_EXACT_KERNEL_BACKING_REQUIRED
    OFF_MOUNT_EXACT_LIVE_BACKING_INODE_REQUIRED OFF_MOUNT_EXACT_LOOP_WITHOUT_EXTRA_MOUNTS_REQUIRED
    OFF_MOUNT_EXTERNAL_PROOF_NAMESPACE_ALIAS OFF_MOUNT_NONEMPTY_BOUNDED_DIAGNOSTICS_REQUIRED
    SCOPED_TERMINAL_OWNED_NAMESPACE_REQUIRED_FOR_DETACHED_DIAGNOSTICS
    SUCCESSFUL_OWNED_RESERVATION_MUST_EXHAUST_CALLER_AVAILABLE_SPACE UNMOUNT_ALREADY_ATTEMPTED_NO_AUTOMATIC_RETRY
    WRITER_REMAINS_AFTER_UNMOUNT WRITERS_OR_ATTACHED_LOOP_REFUSE_IMAGE_SELECTION
    '''.split())


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


def bounded_diagnostic_error(row):
    """Project the exact stage and fixed guard code without copying raw exceptions."""
    candidate = row.get('message')
    code = candidate if type(candidate) is str and candidate in DIAGNOSTIC_GUARDS else None
    kind = row.get('type')
    if type(kind) is not str or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,47}', kind):
        kind = 'Unavailable'
    number = row.get('errno')
    return {'guard': code, 'type': kind, 'errno': number if type(number) is int and 0 < number < 4096 else None}


def controller_diagnostic(result):
    return {'format': 'scientific-posix-root-terminal-diagnostic-v1', 'operation': 'controller',
            'phase': result['phase'], 'status': result['status'], 'quota_prepared': result['quota_prepared'],
            'memory_probed': result['memory_probed'], 'original22_verified': result['original22_verified'],
            'spi3_verified': isinstance(result['spi_cases'], dict),
            'errors': [bounded_diagnostic_error(error) for error in result['errors'][:2]]}


def image_diagnostic(operation, closure, persistence_errors=()):
    return {'format': 'scientific-posix-root-terminal-diagnostic-v1', 'operation': operation,
            'phase': closure.get('phase'), 'image_closed': closure.get('complete_closed_image') is True,
            'observed_image_metadata': closure.get('image_metadata'),
            'errors': [bounded_diagnostic_error(error) for error in closure.get('errors', [])[:1]],
            'record_errors': [bounded_diagnostic_error(error) for error in persistence_errors[:1]]}


def try_append_fallback(inputs, value):
    try:
        append_fallback(inputs, value)
    except Exception:
        print('FALLBACK_STATUS_APPEND_REFUSED_SEE_TERMINAL_REPORT', file=sys.stderr, flush=True)


def publish_root_diagnostic(inputs, value):
    raw = encode(value)
    need(len(raw) <= 640, 'ROOT_DIAGNOSTIC_RECORD_BOUND')
    print(raw.decode('ascii'), end='', file=sys.stderr, flush=True)
    try_append_fallback(inputs, value)


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


def bounded(command, cwd, logs, label, uid, gid, *, seconds, output_limit=SMALL,
            allow_stop=False, file_limit=8 << 20, driver_lock=None):
    """One exact command; complete observed prefixes remain even on failure."""
    need(1 <= seconds <= 2200 and 1 <= output_limit <= STREAM_BYTES, 'COMMAND_BOUNDS')
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
        proc = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean(),
            close_fds=True, pass_fds=() if driver_lock is None else (driver_lock,),
            start_new_session=True, preexec_fn=lambda: limits(file_limit))
        ACTIVE.add(proc.pid)
        create(folder / 'started.json', encode({'pid': proc.pid, 'pgid': proc.pid,
            'command': command, 'owner_uid_at_spawn': os.geteuid()}), uid, gid)
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
    need(ADMISSION_ENABLED and ref == BRANCH, 'DRAFT_REFUSES_RUN_UNTIL_EXACT_INDEPENDENT_ADMISSION')
    raw = read(workspace / ADMISSION, 8192)
    need(hashlib.sha256(raw).hexdigest() == digest(expected), 'INDEPENDENT_ADMISSION_DIGEST')
    value = decode(raw)
    fields = {'format', 'status', 'branch', 'attempt_id', 'created_unix_seconds', 'expires_unix_seconds',
        'baseline_including_reserve_bytes', 'global_reserve_bytes', 'fresh_inventory_sha256',
        'base_lifecycle_bytes', 'connector_bytes', 'supplement_bytes', 'other_growth_bytes', 'native_transfer',
        'no_other_heavy_process', 'independent_review_closed', 'independent_first_findings_sha256', 'source_pins'}
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
         type(value['connector_bytes']) is int and value['connector_bytes'] == 0 and
         value['native_transfer'] == NATIVE_TRANSFER and value['supplement_bytes'] == SUPPLEMENT_BYTES and
         value['other_growth_bytes'] == OTHER_BYTES and base + BASE_BYTES + OTHER_BYTES < 12_000_000_000,
         'COMPLETE_FIXED_PEAK_ADMISSION')
    digest(value['fresh_inventory_sha256'])
    digest(value['independent_first_findings_sha256'])
    need(value['source_pins'] == {'job_script_sha256': own_sha, 'lifecycle_manifest_sha256': LIFE_SHA,
                                 'lifecycle_module_sha256': LIFE_MODULE_SHA, 'integration_manifest_sha256': SPI_SHA,
                                 'evidence_sha256': EVIDENCE_SHA, 'common_sha256': COMMON_SHA, 'helpers': HELPER_SHA},
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
    retained = workspace / 'scripts' / 'scientific_retained_lifecycle'
    raw = read(retained / 'LIFECYCLE_SOURCE_MANIFEST.json')
    need(hashlib.sha256(raw).hexdigest() == LIFE_SHA, 'PINNED_PUBLIC_LIFECYCLE_MANIFEST')
    manifest = decode(raw)
    rows = manifest['packet_files']
    need(len(rows) == 6 and {row['name'] for row in rows} == LIFE_NAMES, 'EXACT_LIFE_RUNTIME_SELECTION')
    make_dir(destination, uid, gid)
    for row in rows:
        need(set(row) == {'name', 'origin', 'bytes', 'sha256'}, 'PIN_ROW_SCHEMA')
        source = (retained if row['name'] == 'scientific_posix_lifecycle.py' else original) / row['name']
        need(row['origin'] == source.relative_to(workspace).as_posix(), 'EXACT_PUBLIC_PACKET_ORIGIN')
        result = file_ref(source, 180000, exact=row['bytes'])
        need(result['sha256'] == row['sha256'], 'CURRENT_PUBLIC_PACKET_PIN')
        copy_new(source, destination / row['name'], uid, gid, 180000)
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
    module_path = folder / 'scientific_posix_lifecycle.py'
    module_raw = read(module_path, 128_000)
    need(hashlib.sha256(module_raw).hexdigest() == LIFE_MODULE_SHA, 'EXACT_PINNED_LIFECYCLE_EXECUTION_BYTES')
    spec = importlib.util.spec_from_file_location('scientific_posix_lifecycle', module_path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(module_raw, str(module_path), 'exec'), module.__dict__)
    module.require_linux()
    module.check_packet(folder, module.MANIFEST_NAME, LIFE_SHA, module.LIFE_NAMES, owner=uid)
    return module


def load_pinned_script(source, name, expected):
    """Load exactly one reviewed helper without adding the checkout to root sys.path."""
    file = source / 'scripts' / (name + '.py')
    raw = read(file, 128_000)
    need(hashlib.sha256(raw).hexdigest() == digest(expected), 'EXACT_PINNED_CONTROLLER_HELPER')
    spec = importlib.util.spec_from_file_location(name, file)
    loaded = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(file), 'exec'), loaded.__dict__)
    return loaded


def helper(source, name):
    return load_pinned_script(source, name, HELPER_SHA[name])


def stage_integration_packet(container, ctx, life):
    job, source = container / 'job', Path(ctx['source_root']) / 'scripts' / 'scientific_storage'
    uid, gid = ctx['owner_uid'], ctx['owner_gid']
    raw = read(source / life.SPI_MANIFEST)
    need(hashlib.sha256(raw).hexdigest() == SPI_SHA, 'EXACT_SPI_SOURCE_MANIFEST_PIN')
    manifest = decode(raw)
    rows = manifest['packet_files']
    need(manifest['format'] == 'scientific-posix-source-packet-v1' and manifest['profile'] == life.SPI_PROFILE and
         len(rows) == len(life.SPI_NAMES) and {row['name'] for row in rows} == life.SPI_NAMES,
         'EXACT_SPI_FLAT_PACKET_PROFILE_AND_SET')
    life_source, _, _ = life.check_packet(container / 'lifecycle', life.MANIFEST_NAME, LIFE_SHA, life.LIFE_NAMES, owner=uid)
    life_manifest = file_ref(container / 'lifecycle' / life.MANIFEST_NAME, SMALL, owner=uid)
    total = len(raw) + life_manifest['bytes'] + sum(row['bytes'] for row in life_source['packet_files'])
    for row in rows:
        need(set(row) == {'name', 'origin', 'bytes', 'sha256'}, 'EXACT_SPI_PACKET_PIN_ROW')
        total += integer(row['bytes'], 1, SMALL)
        need(file_ref(source / row['name'], SMALL, exact=row['bytes'], owner=uid)['sha256'] == row['sha256'],
             'SPI_PACKET_SOURCE_CHANGED')
    need(total <= 1 << 20, 'COMBINED_PACKET_SIZE_LIMIT')
    target = job / 'volume' / 'packet'
    make_dir(target, uid, gid)
    for row in rows:
        copy_new(source / row['name'], target / row['name'], uid, gid, row['bytes'])
    create(target / life.SPI_MANIFEST, raw, uid, gid)
    life.check_packet(target, life.SPI_MANIFEST, SPI_SHA, life.SPI_NAMES, owner=uid)


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
    own = file_ref(Path(__file__).absolute(), DRIVER_BYTES)['sha256']
    need(own == digest(args.job_sha256), 'EXTERNAL_JOB_SOURCE_PIN')
    container = Path('/srv') / ('fq-posix-proof-' + args.run_id + '-' + args.run_attempt)
    if args.container is not None:
        need(args.container == container, 'EXACT_TRUSTED_RUN_NAMESPACE')
    return {'format': 'scientific-posix-proof-recovery-inputs-v1', 'container': str(container),
        'run_id': args.run_id, 'run_attempt': args.run_attempt, 'owner_uid': uid, 'owner_gid': gid,
        'workspace': str(workspace), 'runner_temp': str(temporary), 'job_source_sha256': own,
        'admission_sha256': digest(args.admission_sha256), 'checkout_commit': args.commit,
        'branch': args.ref, 'host_attribution_roots': [str(workspace), str(temporary),
                                                    str(workspace.parent.parent / '_actions'), str(authority_path(container))]}


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


def authority_path(container):
    need(re.fullmatch('/srv/fq-posix-proof-[0-9]{1,24}-[0-9]{1,8}', str(container)), 'EXACT_AUTHORITY_PATH_SCOPE')
    return container.with_name(container.name.replace('fq-posix-proof-', 'fq-posix-authority-', 1))


def authority_dir(container, *, create_new=False):
    need(os.geteuid() == 0 and
         re.fullmatch('/srv/fq-posix-proof-[0-9]{1,24}-[0-9]{1,8}', str(container)),
         'ACTUAL_ROOT_AUTHORITY_AND_EXACT_CONTAINER_REQUIRED')
    chain(Path('/srv'), owner=0)
    folder = authority_path(container)
    if create_new:
        os.mkdir(folder, 0o700)
    chain(folder, owner=0, final_private=True)
    need(folder.lstat().st_gid == 0, 'ROOT_AUTHORITY_GROUP_REQUIRED')
    return folder


def recovery_record(container):
    record_root = authority_dir(container) if os.geteuid() == 0 else container
    value = decode(read(record_root / 'recovery.json'))
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
         str(workspace.parent.parent / '_actions'), str(authority_path(container))] and
         set(value['runtime']) == set(RUNTIME_PATHS),
         'EXACT_RECOVERY_PATHS_AND_RUNTIME_NAMES')
    for name, row in value['runtime'].items():
        need(row['path'] == RUNTIME_PATHS[name], 'EXACT_INSTALLED_RUNTIME_PATH')
        verify_runtime(row)
    digest(value['job_source_sha256'])
    digest(value['admission_sha256'])
    return value


def context(container):
    retained = recovery_record(container)
    control = authority_dir(container) if os.geteuid() == 0 else container / 'control'
    value = decode(read(control / 'context.json'))
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


def process_image_writers(volume, image, owner):
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
            if proc.stat().st_uid not in (0, owner):
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


def image_shape(info):
    return {'regular': stat.S_ISREG(info.st_mode), 'links': info.st_nlink, 'uid': info.st_uid, 'gid': info.st_gid,
            'mode': stat.S_IMODE(info.st_mode), 'bytes': info.st_size, 'allocated_bytes': info.st_blocks * 512}


def record_image_shape(container, inputs, stage):
    try:
        create(container / 'control' / (stage + '-image-metadata.json'),
               encode(image_shape((container / 'job' / 'quota.img').lstat())),
               inputs['owner_uid'], inputs['owner_gid'])
    except Exception as error:
        publish_root_diagnostic(inputs, {'format': 'scientific-posix-root-terminal-diagnostic-v1',
            'operation': stage + '-image-metadata',
            'error': bounded_diagnostic_error(fault(error, 'image-metadata-unavailable'))})


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


def close_image(container, ctx, life, lock, *, recovery=False):
    """Close the actual image after the external process barrier is terminal."""
    uid, gid = ctx['owner_uid'], ctx['owner_gid']
    control, job = container / 'control', container / 'job'
    image, volume = job / 'quota.img', job / 'volume'
    result = {'format': 'scientific-posix-proof-image-closure-v1', 'complete_closed_image': False, 'phase': 'producer-barrier',
              'image_retained': image.exists(), 'recovery': recovery, 'errors': [],
              'cloud_native_custody': 'NOT_VERIFIED', 'scientific_qualification': 'NOT_CLAIMED'}
    try:
        need(not ACTIVE, 'OWNED_COMMAND_STILL_ACTIVE')
        if recovery and (authority_dir(container) / 'producer-cgroup.json').exists():
            group = helper(Path(ctx['source_root']), 'scientific_posix_producer_group')
            record = decode(read(authority_dir(container) / 'producer-cgroup.json'))
            result['producer_recovery'] = group.stop_remaining(container, record)
        result['producer_cgroup_before'] = assert_producers_empty(container, ctx)
        result['phase'] = 'retained-image-and-writers'
        info = image.lstat()
        result['image_metadata'] = image_shape(info)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid in (0, uid) and
             info.st_mode & 0o077 == 0 and info.st_size == IMAGE_BYTES and
             info.st_blocks * 512 >= IMAGE_BYTES, 'FULL_OWNED_IMAGE_REQUIRED_FOR_COMPLETE_REFERENCE')
        need(not process_image_writers(volume, image, uid), 'ACTUAL_PRODUCER_WRITERS_REMAIN')
        current = [row for row in mounts() if row[4] == str(volume)]
        need(len(current) <= 1, 'ONE_EXACT_MOUNT_ONLY')
        expected = None
        if current:
            result['phase'] = 'exact-mount-binding'
            # This inspects actual identity even when quota proof creation failed.
            expected = life.mount_observation(volume, image, uid)
            attempt = control / 'unmount-attempt.json'
            need(not attempt.exists(), 'UNMOUNT_ALREADY_ATTEMPTED_NO_AUTOMATIC_RETRY')
            create(attempt, encode({'actual_mount': expected, 'image_identity': list(sig(info)),
                                   'pid': os.getpid()}), uid, gid)
            result['phase'] = 'ordinary-unmount'
            umount = verify_runtime(ctx['runtime']['umount'])
            command = bounded([umount, str(volume)], container, control / 'commands',
                              'ordinary-unmount', uid, gid, seconds=60, output_limit=65536, allow_stop=True,
                              driver_lock=lock)
            need(command['exit_code'] == 0 and command['quiescent'] and
                 command['reason'] == 'process-exit' and not command['errors'],
                 'ORDINARY_UNMOUNT_FAILED_RETAIN_ALL_NO_RETRY')
        result['phase'] = 'mount-and-loop-absence'
        need(not any(row[4] == str(volume) or (expected and row[2] == expected['major_minor'])
                     for row in mounts()), 'IMAGE_FILESYSTEM_STILL_MOUNTED')
        need(not loop_associations(image), 'ACTIVE_LOOP_BACKING_ASSOCIATION_REMAINS')
        need(not process_image_writers(volume, image, uid), 'WRITER_REMAINS_AFTER_UNMOUNT')
        result['producer_cgroup_after'] = assert_producers_empty(container, ctx)
        result['phase'] = 'closed-image-hash'
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
        result.update(complete_closed_image=True, raw_image=reference, phase='closed-image-verified',
                      assertion='FULL_BYTES_ONLY_NO_EXTRACTION_OR_SCIENTIFIC_SUCCESS')
    except BaseException as error:
        result['errors'].append(fault(error, 'image-closure'))
        # Observe the original without changing its ownership while it may be attached.
        try:
            info = image.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid in (0, uid):
                result['retained_image_bytes'] = info.st_size
        except BaseException as error2:
            result['errors'].append(fault(error2, 'failed-image-observation'))
    return result


def actual_controls_receipt(ctx, expected_command, expected_source):
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
         receipt['termination_reason'] is None and receipt['source_before'] == receipt['source_after'] == expected_source and
         receipt['command'] == expected_command and receipt['cwd'] == str(root),
         'ACTUAL22_STREAMS_AND_RECEIPT_MUST_AGREE_ZERO_FAILURE_ERROR_SKIP')
    return {'format': 'scientific-posix-external-profile-control-proof-v1',
        'lifecycle_manifest_sha256': LIFE_SHA, 'actual_linux_posix': True, 'actual_tests_run': len(tests),
        'actual_failures': 0, 'actual_errors': 0, 'actual_skips': 0,
        'process_returncode': receipt['exit_code'], 'all_control_prefixes_retained': True,
        'actual_command_receipt_sha256': hashlib.sha256(raw).hexdigest(),
        'receipt_relative_path': str(location.relative_to(root) / 'receipt.json'),
        'scope': 'Original22 only; actual kernel/closure/custody are separate facts.'}, raw


def assert_producers_empty(container, ctx):
    group = helper(Path(ctx['source_root']), 'scientific_posix_producer_group')
    record = decode(read(authority_dir(container) / 'producer-cgroup.json'))
    actual = group.observe(container, record)
    need(actual['populated'] is False, 'OWNED_PRODUCER_AND_ALL_NESTED_SESSIONS_MUST_BE_TERMINAL')
    return actual


@contextmanager
def driver_lock(container):
    """Exclude recovery while any controller or pre-enrollment wrapper can act."""
    lock = authority_dir(container) / 'controller.lock'
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0 and info.st_mode & 0o077 == 0,
             'ACTUAL_ROOT_OWNED_DRIVER_LOCK_REQUIRED')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need(sig(info) == sig(lock.lstat()), 'DRIVER_LOCK_PATH_CHANGED')
        yield fd
    finally:
        os.close(fd)


def start_controller_once(container):
    trusted = authority_dir(container)
    need(not (trusted / 'recovery-started.json').exists(), 'RECOVERY_FENCE_PROHIBITS_LATE_CONTROLLER')
    create(trusted / 'controller-started.json', encode({'pid': os.getpid()}), 0, 0)


def prevent_privilege_gain():
    """The ephemeral runner UID has sudo access outside this producer boundary."""
    import ctypes

    prctl = ctypes.CDLL(None, use_errno=True).prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    need(prctl(38, 1, 0, 0, 0) == 0 and prctl(39, 0, 0, 0, 0) == 1, 'ACTUAL_NO_NEW_PRIVILEGES_REQUIRED')


def grouped_command(container, ctx, action, lock, *, admission_sha=None):
    command = [ctx['runtime']['python']['path'], '-I', '-S', '-B',
               str(authority_dir(container) / 'driver.py'), action,
               '--container', str(container), '--driver-lock', str(lock)]
    if admission_sha is not None:
        command.extend(['--supervisor-admission-sha256', digest(admission_sha)])
    return command


def support_before_spi(container, life):
    """Measure support already present and reserve the bounded remaining metadata and logs."""
    job = container / 'job'
    omitted = {job / 'volume', job / 'quota.img'}
    expected_link = container / 'support' / 'git-only' / 'git'
    count, used, pending = 0, 0, [container]
    ceiling = PAYLOAD_BYTES - IMAGE_BYTES - 2 * life.BLOB_BYTES - 4 * 8192
    while pending:
        item = pending.pop()
        if item in omitted:
            continue
        count += 1
        need(count <= ENTRY_LIMIT, 'SUPPORT_BEFORE_SPI_ENTRY_BOUND')
        info = item.lstat()
        if stat.S_ISDIR(info.st_mode):
            for entry in os.scandir(item):
                pending.append(Path(entry.path))
                need(len(pending) + count <= ENTRY_LIMIT, 'SUPPORT_BEFORE_SPI_PENDING_BOUND')
        else:
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 or
                 (item == expected_link and stat.S_ISLNK(info.st_mode) and os.readlink(item) == RUNTIME_PATHS['git']),
                 'EXACT_BOUNDED_SUPPORT_FILE_TYPE_REQUIRED')
        used += max(info.st_size, info.st_blocks * 512) + 4096
        need(used + KNOWN_SUPPORT_TAIL_BYTES <= ceiling, 'NO_PRODUCER_WITHOUT_COMPLETE_SUPPORT_CAPACITY')
    return {'preproducer_support_accounted_bytes': used, 'remaining_support_reserved_bytes': KNOWN_SUPPORT_TAIL_BYTES,
            'total_support_capacity_bytes': ceiling, 'entries': count}


def actual_spis(container, ctx, life, admitted, control_proof, expected_source, lock, inputs):
    uid, gid = ctx['owner_uid'], ctx['owner_gid']
    job, source = container / 'job', Path(ctx['source_root'])
    interpreter = ctx['runtime']['python']
    stage_integration_packet(container, ctx, life)
    life.require_source_headroom(job / 'volume', uid)
    proof = job / 'control' / 'external-profile-control-proof.json'
    original_receipt = job / 'control' / 'original22-command-receipt.json'
    pins = {'lifecycle_manifest_sha256': LIFE_SHA, 'lifecycle_module_sha256': LIFE_MODULE_SHA,
            'integration_manifest_sha256': SPI_SHA,
            'external_profile_control_proof_sha256': file_ref(proof, SMALL, owner=uid)['sha256'],
            'independent_first_findings_sha256': admitted['independent_first_findings_sha256'],
            'quota_proof_sha256': control_proof['quota_proof_sha256'], 'memory_proof_sha256': control_proof['memory_proof_sha256'],
            'original22_receipt_sha256': file_ref(original_receipt, SMALL, owner=uid)['sha256']}
    binder = helper(source, 'scientific_posix_full_volume_admission')
    lifecycle_raw, spi_raw = binder.require_admission(job=str(job), owner=(uid, gid), runtime=ctx['runtime'],
        attempt=admitted['attempt_id'], envelope=ctx['preparation'], pins=pins)
    create(job / 'control' / 'integration-admission.json', spi_raw, uid, gid)
    create(job / 'control' / 'lifecycle-admission.json', lifecycle_raw, uid, gid)
    life_admission_sha = hashlib.sha256(lifecycle_raw).hexdigest()
    verify_sources(ctx)
    create(container / 'control' / 'support-before-spi.json', encode(support_before_spi(container, life)), uid, gid)
    observation = assert_producers_empty(container, ctx)
    create(container / 'control' / 'before-spi-producers.json', encode(observation), uid, gid)
    record_image_shape(container, inputs, 'before-spi')
    need(not STOP, 'INTERRUPTED_BEFORE_SPI')
    command = grouped_command(container, ctx, '_group-spi-owner', lock, admission_sha=life_admission_sha)
    outer = bounded(command, source, container / 'control' / 'commands', 'spi-supervisor-evidence', uid, gid,
                    seconds=1120, file_limit=life.BLOB_BYTES, driver_lock=lock)
    if outer['exit_code'] != 0 or outer['errors'] or not outer['quiescent'] or outer['reason'] != 'process-exit':
        streams = {name: {key: reference[key] for key in ('bytes', 'sha256')}
                   for name, stream in outer['streams'].items() if (reference := stream.get('reference'))}
        publish_root_diagnostic(inputs, {'format': 'scientific-posix-root-terminal-diagnostic-v1',
            'operation': 'spi-outer-process', 'exit_code': outer['exit_code'],
            'quiescent': outer['quiescent'], 'reason': outer['reason'], 'stream_references': streams,
            'errors': [bounded_diagnostic_error(error) for error in outer['errors'][:1]]})
    record_image_shape(container, inputs, 'after-spi')
    observation = assert_producers_empty(container, ctx)
    create(container / 'control' / 'after-spi-producers.json', encode(observation), uid, gid)
    need(outer['exit_code'] == 0 and outer['quiescent'] and outer['reason'] == 'process-exit' and
         not outer['errors'], 'ACTUAL_RETAINED_SPI_COMMAND_FAILED')
    raw = read(job / 'control' / 'lifecycle-receipt.json')
    receipt = decode(raw)
    child = receipt['child']
    need(receipt['profile'] == life.FULL_VOLUME_FORMAT and receipt['admission_sha256'] == life_admission_sha and
         receipt['original22_receipt_sha256'] == pins['original22_receipt_sha256'] and
         receipt['collector_terminal'] is True and receipt['after_source_pins_valid'] is True and not receipt['errors'] and
         child['quiescent'] is True and child['returncode'] == 0 and not child['errors'] and
         receipt['collection']['source_tree_complete'] is True, 'ACTUAL_COMPLETE_SPI_AND_NEUTRAL_PAIR_REQUIRED')
    suite_raw = read(Path(receipt['collection']['root']) / 'harness-result.json')
    report = decode(suite_raw)
    need(report['profile'] == life.SPI_PROFILE and report['tests_run'] == 3 and report['failures'] == 0 and
         report['errors'] == 0 and report['literal_skips'] == 0 and report['guard_error'] is None and
         decode(read(job / 'control' / 'run' / 'stdout.bin')) == report,
         'REAL_THREE_CASE_HARNESS_REPORT_MUST_MATCH_PROCESS_STDOUT')
    verify_sources(ctx)
    need(load_pinned_script(source, 'common', COMMON_SHA).source_hash() == expected_source,
         'ACTUAL_CHECKOUT_SOURCE_CHANGED_DURING_SPI')
    neutral = {}
    for label, name, proof_key in (('A', 'fixture.neutral', 'neutral_prefix'),
                                   ('B', 'fixture-copy.neutral', 'second_prefix')):
        reference = receipt['collection'][proof_key]
        actual = file_ref(job / 'exports' / name, life.BLOB_BYTES, owner=uid)
        need(all(actual[key] == reference[key] for key in ('bytes', 'sha256')), 'ROOT_NEUTRAL_READBACK_CHANGED')
        neutral[label] = {key: actual[key] for key in ('bytes', 'sha256', 'identity')}
    need(neutral['A']['identity'][:2] != neutral['B']['identity'][:2], 'DISTINCT_NEUTRAL_FILES_REQUIRED')
    return {'tests': 3, 'failures': 0, 'errors': 0, 'skips': 0,
            'scope': 'SYNTHETIC_FILESYSTEM_AND_LINKAGE_ONLY', 'custody': 'PENDING',
            'lifecycle_receipt_sha256': hashlib.sha256(raw).hexdigest(),
            'lifecycle_admission_sha256': life_admission_sha, 'neutral': neutral,
            'integration_admission_sha256': hashlib.sha256(spi_raw).hexdigest(),
            'quota_proof_sha256': pins['quota_proof_sha256'],
            'harness_report_sha256': hashlib.sha256(suite_raw).hexdigest()}


def controller(container, lock, inputs):
    need(os.geteuid() == 0, 'ROOT_CONTROLLER_REQUIRED')
    ctx = context(container)
    uid, gid = ctx['owner_uid'], ctx['owner_gid']
    life = load_life(container, uid)
    result = {'format': 'scientific-posix-full-volume-retained-cases-job-result-v1', 'status': 'FAILURE_RETAINED',
              'phase': 'source-and-producer-control',
              'original22_verified': False, 'quota_prepared': False, 'memory_probed': False,
              'spi_cases': 'NOT_RUN', 'scientific_qualification': 'NOT_CLAIMED', 'errors': []}
    try:
        verify_sources(ctx)
        source = Path(ctx['source_root'])
        technical_source = load_pinned_script(source, 'common', COMMON_SHA).source_hash()
        trusted = authority_dir(container)
        admission_raw = read(trusted / 'root-admission.json', 8192)
        need(hashlib.sha256(admission_raw).hexdigest() == ctx['admission_sha256'], 'RETAINED_ROOT_ADMISSION_CHANGED')
        admitted = decode(admission_raw)
        group = helper(source, 'scientific_posix_producer_group')
        group_record = group.create(container)
        create(trusted / 'producer-cgroup.json', encode(group_record), 0, 0)
        create(container / 'control' / 'producer-cgroup.json', encode(group_record), uid, gid)
        effective = {name: list(resource.getrlimit(limit)) for name, limit in {
            'cpu': resource.RLIMIT_CPU, 'file': resource.RLIMIT_FSIZE, 'memory': resource.RLIMIT_AS}.items()}
        create(container / 'control' / 'effective-controller-limits.json', encode(effective), uid, gid)
        need((effective['cpu'][1] == resource.RLIM_INFINITY or effective['cpu'][1] >= 601) and
             all(limit == resource.RLIM_INFINITY or limit >= IMAGE_BYTES + 8192 for limit in effective['file']) and
             effective['memory'] == [MEMORY_BYTES, MEMORY_BYTES], 'ACTUAL_INHERITED_CONTROLLER_LIMITS_REQUIRED')
        create(container / 'control' / 'host-before.json', encode(host_attribution(ctx)), uid, gid)
        need(not STOP, 'INTERRUPTED_BEFORE_PREPARATION')
        result['phase'] = 'full-volume-quota'
        prep = ctx['preparation']
        prepared = life.prepare_quota_on_full_volume(prep, LIFE_SHA, stop_requested=lambda: bool(STOP),
                                                    controller_lease=lock)
        need(prepared == {'status': 'FULL_VOLUME_QUOTA_PREPARED_NOT_A_RUN_ADMISSION',
                         'quota_proof': str(container / 'job' / 'control' / 'quota-proof.json')},
             'EXACT_FULL_VOLUME_PREPARATION_RESULT_REQUIRED')
        result['quota_proof'] = life.verify_full_volume_quota_for_original22(
            container / 'job', LIFE_SHA, uid, gid, prep['installed_tools'])
        result['quota_prepared'] = True
        try:
            create(authority_dir(container) / 'verified-quota-attachment.json',
                   encode(result['quota_proof']['actual_mount']), 0, 0)
        except Exception as error:
            publish_root_diagnostic(inputs, {'format': 'scientific-posix-root-terminal-diagnostic-v1',
                'operation': 'quota-attachment-pin',
                'error': bounded_diagnostic_error(fault(error, 'root-quota-attachment-pin-unavailable'))})
        record_image_shape(container, inputs, 'after-quota')
        need(not STOP, 'INTERRUPTED_BEFORE_MEMORY_PROBE')
        result['phase'] = 'unprivileged-memory'
        memory = bounded(grouped_command(container, ctx, '_group-memory-owner', lock), container,
            container / 'control' / 'commands', 'memory-owner', uid, gid, seconds=35,
            output_limit=65536, driver_lock=lock)
        assert_producers_empty(container, ctx)
        need(memory['exit_code'] == 0 and memory['quiescent'] and not memory['errors'] and
             memory['reason'] == 'process-exit', 'ACTUAL_MEMORY_OWNER_PROCESS_FAILED')
        memory_raw = read(container / 'job' / 'control' / 'memory-proof.json')
        proof = decode(memory_raw)
        need(proof['probe']['actual_getrlimit'] == [MEMORY_BYTES, MEMORY_BYTES] and
             proof['probe']['denial_observed'] is True and proof['probe']['exception'] == 'MemoryError' and
             proof['probe']['attempted_bytes'] == MEMORY_BYTES + 1 and proof['process']['quiescent'] is True,
             'ACTUAL_UNPRIVILEGED_MEMORY_PROOF')
        result['memory_proof_sha256'] = hashlib.sha256(memory_raw).hexdigest()
        result['memory_probed'] = True
        result['headroom'] = life.require_source_headroom(container / 'job' / 'volume', uid)
        need(not STOP, 'INTERRUPTED_BEFORE_ORIGINAL22')
        result['phase'] = 'original22'
        original = life.original22_command(container / 'job', ctx['runtime']['python'], LIFE_MODULE_SHA)
        command = grouped_command(container, ctx, '_group-original22-owner', lock)
        nested = bounded(command, Path(ctx['source_root']), container / 'control' / 'commands',
            'original22-evidence', uid, gid, seconds=280, driver_lock=lock)
        assert_producers_empty(container, ctx)
        need(nested['exit_code'] == 0 and nested['quiescent'] and not nested['errors'] and
             nested['reason'] == 'process-exit', 'ORIGINAL22_EVIDENCE_COMMAND_FAILED')
        actual, original_raw = actual_controls_receipt(ctx, original, technical_source)
        job = container / 'job'
        verified_quota_sha = digest(result['quota_proof']['proof_sha256'])
        need(file_ref(job / 'control' / 'quota-proof.json', SMALL, owner=uid)['sha256'] == verified_quota_sha,
             'SAME_ROOT_VERIFIED_QUOTA_PROOF_REQUIRED_AFTER_ORIGINAL22')
        actual.update(job_root=str(job), owner_uid=uid, owner_gid=gid, interpreter=ctx['runtime']['python'],
                      original22_test_root=str(job / 'volume' / 'work' / 'original22'),
                      original22_checkout_source_sha256=technical_source,
                      quota_proof_sha256=verified_quota_sha,
                      memory_proof_sha256=result['memory_proof_sha256'])
        create(job / 'control' / 'original22-command-receipt.json', original_raw, uid, gid)
        create(container / 'job' / 'control' / 'external-profile-control-proof.json', encode(actual), uid, gid)
        result['original22_verified'] = True
        result['actual_proof_sha256'] = file_ref(container / 'job' / 'control' /
            'external-profile-control-proof.json', SMALL)['sha256']
        verify_sources(ctx)
        create(container / 'control' / 'host-after-controls.json', encode(host_attribution(ctx)), uid, gid)
        result['spi_cases'] = 'STARTED_OR_EARLY_ADMISSION_REFUSED_SEE_ACTUAL_RECORDS'
        result['phase'] = 'retained-spi3'
        result['spi_cases'] = actual_spis(container, ctx, life, admitted, actual, technical_source, lock, inputs)
    except BaseException as error:
        result['errors'].append(fault(error, 'original22-controller'))
        publish_root_diagnostic(inputs, controller_diagnostic(result))
    finally:
        result['closure'] = close_image(container, ctx, life, lock)
        publish_root_diagnostic(inputs, image_diagnostic('controller-closure', result['closure']))
        if result['quota_prepared'] and result['closure']['complete_closed_image']:
            try:
                unmount = decode(read(container / 'control' / 'unmount-attempt.json'))
                need(unmount['actual_mount'] == result['quota_proof']['actual_mount'],
                     'SAME_QUOTA_PROOF_MOUNT_REQUIRED_FOR_CLOSURE')
                closed = result['closure']['raw_image']['identity']
                mounted_identity = result['quota_proof']['actual_mount']['image_identity']
                need([closed[i] for i in (0,1,3,5,6)] == mounted_identity,
                     'SAME_EXACT_MOUNTED_IMAGE_REQUIRED_FOR_CLOSED_BYTE_HASH')
                result['quota_image_mount_link_verified'] = True
            except BaseException as error:
                result['errors'].append(fault(error, 'quota-image-mount-binding'))
                publish_root_diagnostic(inputs, controller_diagnostic(result))
        result['interrupted_signals'] = list(STOP)
        binding = None
        if (result['original22_verified'] and type(result['spi_cases']) is dict and
                result['closure']['complete_closed_image'] and not result['errors'] and not STOP):
            spi = result['spi_cases']
            need(result['quota_image_mount_link_verified'] is True, 'INDEPENDENT_QUOTA_MOUNT_LINK_MISSING')
            closed = result['closure']['raw_image']
            binding = {'format': 'scientific-posix-root-terminal-custody-v1',
                'lifecycle_receipt_sha256': spi['lifecycle_receipt_sha256'],
                'lifecycle_admission_sha256': spi['lifecycle_admission_sha256'], 'neutral': spi['neutral'],
                'integration_admission_sha256': spi['integration_admission_sha256'],
                'quota_proof_sha256': spi['quota_proof_sha256'],
                'image': {key: closed[key] for key in ('bytes', 'sha256', 'identity')},
                'quota_mounted_image_identity': result['quota_proof']['actual_mount']['image_identity']}
            result['status'] = 'ORIGINAL22_AND_SPI3_CLOSED_IMAGE_BYTES_VERIFIED_CUSTODY_PENDING'
            result['phase'] = 'controller-terminal'
        if not result['errors']:
            publish_root_diagnostic(inputs, controller_diagnostic(result))
        controller_result = encode(result)
        create(container / 'control' / 'controller-result.json', controller_result, uid, gid)
        if binding is not None:
            binding['controller_result_sha256'] = hashlib.sha256(controller_result).hexdigest()
            sealed = encode(binding)
            create(container / 'control' / 'terminal-custody-binding.json', sealed, uid, gid)
            create(authority_dir(container) / 'terminal-custody-binding.json', sealed, 0, 0)
    return 0 if result['status'].startswith('ORIGINAL22_AND_') else 1


def owner_action(container, action, supervisor_sha, lock):
    ctx = context(container)
    uid, gid = ctx['owner_uid'], ctx['owner_gid']
    need(os.geteuid() == 0 and uid > 0 and gid > 0, 'ACTUAL_ROOT_TO_OWNER_PRODUCER_TRANSITION_REQUIRED')
    lock_info = os.fstat(integer(lock, 3, 63))
    need(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == 0 and lock_info.st_nlink == 1 and
         sig(lock_info) == sig((authority_dir(container) / 'controller.lock').lstat()),
         'BOUND_PRE_ENROLLMENT_LOCK_REQUIRED')
    group = helper(Path(ctx['source_root']), 'scientific_posix_producer_group')
    group.enter(container, decode(read(authority_dir(container) / 'producer-cgroup.json')))
    close_all(lock)
    prevent_privilege_gain()
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    need(os.getresuid() == (uid, uid, uid) and os.getresgid() == (gid, gid, gid) and not os.getgroups(),
         'EXACT_BOUND_OWNER_AND_GROUP_REQUIRED')
    life = load_life(container, uid)
    for row in ctx['runtime'].values():
        verify_runtime(row)
    job = container / 'job'
    if action == '_group-memory-owner':
        need(supervisor_sha is None, 'MEMORY_OWNER_TAKES_NO_SPI_ADMISSION_ARGUMENT')
        life.prepare_memory(container / 'job', ctx['runtime']['python'], LIFE_SHA)
        return 0
    if action == '_group-original22-owner':
        need(supervisor_sha is None, 'ORIGINAL22_OWNER_TAKES_NO_SPI_ADMISSION_ARGUMENT')
        leaf = life.original22_command(job, ctx['runtime']['python'], LIFE_MODULE_SHA)
        command = evidence_command(ctx, leaf, 'scientific-posix-original22', 240)
    else:
        need(action == '_group-spi-owner' and supervisor_sha is not None, 'EXACT_SPI_SUPERVISOR_OWNER_ACTION')
        leaf = [ctx['runtime']['python']['path'], '-I', '-S', '-B',
                str(container / 'lifecycle' / 'scientific_posix_lifecycle.py'), 'supervise',
                '--manifest-sha256', LIFE_SHA, '--context', str(job / 'control' / 'lifecycle-admission.json'),
                '--context-sha256', digest(supervisor_sha)]
        command = evidence_command(ctx, leaf, 'scientific-posix-retained-three-integration', 1080)
    os.execve(command[0], command, {**clean(), 'PATH': ctx['git_only_path']})


def outbound_inventory(container, uid, gid, transport):
    """Admit every namespace file or reject the whole payload, regardless of test outcome."""
    rows, files, errors, missing = [], [], [], []
    total, accounted, count, began = 0, 0, 0, time.monotonic()
    pending = [(container, '')]
    complete = False
    try:
        need(not any(row[4] == str(container) or row[4].startswith(str(container) + '/')
                     for row in mounts()), 'UNEXPECTED_NAMESPACE_MOUNT')
        for relative in ('recovery.json', 'control/context.json', 'source', 'lifecycle',
                         'job/control', 'job/exports', 'job/quota.img',
                         'job/exports/fixture.neutral', 'job/exports/fixture-copy.neutral',
                         'job/control/lifecycle-receipt.json', 'job/control/lifecycle-admission.json',
                         'job/control/integration-admission.json', 'job/control/quota-proof.json',
                         'control/controller-result.json', 'control/terminal-custody-binding.json'):
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
            if relative == 'support/git-only/git' and stat.S_ISLNK(info.st_mode):
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
                if relative == 'job/volume':
                    row['closed_filesystem_representation'] = 'job/quota.img if present; mountpoint entries scanned'
                with os.scandir(target) as iterator:
                    for item in iterator:
                        need(re.fullmatch('[A-Za-z0-9_.-]{1,64}', item.name) and item.name not in ('.', '..'),
                             'OUTBOUND_NO_GLOB_NEWLINE_OR_UNSAFE_NAME')
                        pending.append((Path(item.path), (relative + '/' if relative else '') + item.name))
                        need(count + len(pending) <= ENTRY_LIMIT, 'OUTBOUND_DIRECTORY_PENDING_BOUND')
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                repair_readability(target, uid, gid)  # Before hashing, even without context.json.
                maximum = transport.maximum_member_bytes(relative)
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


FALLBACK_NAMES = {'driver.txt': DRIVER_BYTES, 'workflow.txt': 24000, 'proof.txt': 24000,
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
    need(fallback_bytes <= sum(FALLBACK_NAMES.values()) and len(files) + 1 <= ENTRY_LIMIT,
         'UPLOAD_FIXED_FALLBACK_AND_FILE_COUNT_BOUND')
    return files


def exact_upload_paths(files):
    paths = [str(path(row['path'])) for row in files]
    need(len(paths) == len(set(paths)) and all('\n' not in value for value in paths), 'UNIQUE_LITERAL_UPLOAD_FILES')
    raw = ('\n'.join(paths) + '\n').encode('ascii')
    need(len(raw) <= SMALL - 256, 'UPLOAD_PATH_LIST_BOUND')
    return raw


def archive_size_bound(inputs, files, transport):
    container = Path(inputs['container'])
    members = []
    for row in files:
        item = path(row['path'])
        # The action may choose "/" as the common search root. Bound the
        # longest possible name as well as the type used to set its file cap.
        transport.member_name(item.as_posix().lstrip('/'))
        if item.is_relative_to(container):
            name = item.relative_to(container).as_posix()
        else:
            need(item.parent == fallback_root(inputs) and item.name in FALLBACK_NAMES,
                 'EXACT_SMALL_FALLBACK_NAMESPACE')
            name = 'fallback/' + item.name
        members.append((name, row['bytes']))
    return transport.validate_payload(members, require_complete_image=False)


def retained_reference_status(container, files, closure):
    by_path = {row['path']: row for row in files}
    job = container / 'job'
    receipt_path = job / 'control' / 'lifecycle-receipt.json'
    receipt, collection, issues = {}, {}, []
    receipt_row = by_path.get(str(receipt_path))
    if receipt_row is not None:
        try:
            raw = read(receipt_path)
            need(hashlib.sha256(raw).hexdigest() == receipt_row['sha256'], 'LIFECYCLE_RECEIPT_CHANGED_AFTER_INVENTORY')
            value = decode(raw)
            need(type(value) is dict and type(value.get('collection')) in (dict, type(None)),
                 'LIFECYCLE_RECEIPT_SCHEMA_UNAVAILABLE')
            receipt, collection = value, value.get('collection') or {}
        except (OSError, RuntimeError, ValueError, TypeError) as error:
            issues.append(fault(error, 'invalid-retained-lifecycle-receipt-kept-as-bytes'))
    choices = {'image': (job / 'quota.img', closure.get('raw_image')),
               'A': (job / 'exports' / 'fixture.neutral', collection.get('neutral_prefix')),
               'B': (job / 'exports' / 'fixture-copy.neutral', collection.get('second_prefix'))}
    observations = {}
    for key, (target, reference) in choices.items():
        observed = by_path.get(str(target))
        matches = bool(observed and type(reference) is dict and
                       all(observed[k] == reference.get(k) for k in ('bytes', 'sha256')))
        observations[key] = {'present': observed is not None, 'bytes': observed['bytes'] if observed else None,
                             'sha256': observed['sha256'] if observed else None, 'matches_retained_reference': matches}
    a, b = (by_path.get(str(choices[key][0])) for key in ('A', 'B'))
    distinct = bool(a and b and a['identity'][:2] != b['identity'][:2])
    trusted_path = authority_dir(container) / 'terminal-custody-binding.json'
    copy_path = container / 'control' / 'terminal-custody-binding.json'
    attested = False
    image = by_path.get(str(choices['image'][0]))
    if trusted_path.is_file() and str(copy_path) in by_path and receipt_row and a and b and image:
        try:
            trusted_raw = read(trusted_path)
            trusted = decode(trusted_raw)
            closed = closure.get('raw_image')
            fields = ('bytes', 'sha256', 'identity')

            def selected(observed):
                return {key: observed[key] for key in fields}

            admitted_documents = {'lifecycle-admission.json': 'lifecycle_admission_sha256',
                'integration-admission.json': 'integration_admission_sha256', 'quota-proof.json': 'quota_proof_sha256'}
            admitted_files_match = all(by_path.get(str(job / 'control' / name), {}).get('sha256') == trusted[key]
                                       for name, key in admitted_documents.items())
            controller_row = by_path.get(str(container / 'control' / 'controller-result.json'), {})
            attested = bool(closed and trusted['format'] == 'scientific-posix-root-terminal-custody-v1' and
                hashlib.sha256(trusted_raw).hexdigest() == by_path[str(copy_path)]['sha256'] and
                trusted['controller_result_sha256'] == controller_row.get('sha256') and
                trusted['lifecycle_receipt_sha256'] == receipt_row['sha256'] and
                trusted['lifecycle_admission_sha256'] == receipt.get('admission_sha256') and admitted_files_match and
                trusted['image'] == selected(closed) == selected(image) and
                trusted['quota_mounted_image_identity'] == [image['identity'][i] for i in (0, 1, 3, 5, 6)] and
                trusted['neutral'] == {'A': selected(a), 'B': selected(b)})
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, IndexError) as error:
            issues.append(fault(error, 'invalid-custody-binding-kept-as-bytes'))
    complete = bool(closure.get('complete_closed_image') is True and distinct and
                    attested and collection.get('source_tree_complete') is True and
                    all(row['matches_retained_reference'] for row in observations.values()))
    return {'files': observations, 'distinct_neutral_inodes': distinct, 'root_binding_verified': attested,
            'reference_errors': issues, 'complete_referenced_payload': complete}


def recover(args):
    need(os.geteuid() == 0, 'ROOT_RECOVERY_REQUIRED')
    inputs = run_inputs(args)
    container = Path(inputs['container'])
    try:
        with driver_lock(container) as lock:
            create(authority_dir(container) / 'recovery-started.json', encode({'pid': os.getpid()}), 0, 0)
            return recover_locked(inputs, lock)
    except BaseException as error:
        result = {'custody': 'INCOMPLETE', 'payload_admitted': False,
                  'error': bounded_diagnostic_error(fault(error, 'exclusive-root-recovery-refused-no-live-image-selection'))}
        try_append_fallback(inputs, result)
        print(json.dumps(result, sort_keys=True))
        return 1


def recover_off_mount(container, inputs, ctx, result, transport, custody):
    need(ctx is not None and not result['closure_command_complete'], 'OFF_MOUNT_REQUIRES_UNCLOSED_CONTEXT')
    quota = decode(read(authority_dir(container) / 'verified-quota-attachment.json'))
    uid, gid = inputs['owner_uid'], inputs['owner_gid']

    def writers_terminal():
        assert_producers_empty(container, ctx)
        need(not process_image_writers(container, container / 'job' / 'quota.img', uid),
             'SCOPED_TERMINAL_OWNED_NAMESPACE_REQUIRED_FOR_DETACHED_DIAGNOSTICS')

    host = host_attribution(inputs)
    create(container / 'control' / 'host-before-upload.json', encode(host), uid, gid)
    result.update(host_bounds_admitted=True, complete_regular_file_inventory=False,
                  reference_status={'complete_referenced_payload': False, 'scientific_qualification': 'NOT_CLAIMED'},
                  excluded_live_image_paths=custody.EXCLUDED, payload_scope=custody.FORMAT)
    create(container / 'control' / 'recovery-status.json', encode(result), uid, gid)
    pin, measured, count = custody.publish(container, inputs, quota, transport, create, writers_terminal)
    create(authority_dir(container) / 'upload-manifest-pin.json', encode({'sha256': pin, 'scope': custody.FORMAT}), 0, 0)
    result.update(payload_admitted=True, upload_manifest_sha256=pin, archive_bound=measured,
                  off_mount_file_count=count)
    try_append_fallback(inputs, {'custody': 'INCOMPLETE', 'operation': 'off-mount-failure-manifest',
        'sha256': pin, 'selected_off_mount_files': count, 'excluded_live_image_paths': custody.EXCLUDED})
    print(json.dumps(result, sort_keys=True))
    return 10


def recover_locked(inputs, lock):
    container = Path(inputs['container'])
    transport = helper(Path(inputs['workspace']), 'scientific_posix_transport_limits')
    uid, gid = inputs['owner_uid'], inputs['owner_gid']
    result = {'format': 'scientific-posix-proof-custody-result-v1',
        'closure_command_complete': False,
        'closure_evidence_available': False, 'host_bounds_admitted': False,
        'custody': 'INCOMPLETE', 'cloud_native_custody': 'NOT_VERIFIED', 'errors': [],
        'if_full_manifest_absent': 'ALL_NAMESPACE_IMAGE_LOG_SOURCE_PREFIX_BYTES_OMITTED_UNKNOWN'}
    try:
        custody = helper(Path(inputs['workspace']), 'scientific_posix_failure_custody')
        custody.namespace_live(container)
        private_namespace(container, uid, gid, repair=True)
        for folder in (container / 'control', container / 'control' / 'commands'):
            try:
                folder.lstat()
            except FileNotFoundError:
                make_dir(folder, uid, gid)
            repair_readability(folder, uid, gid)
        closure, ctx = {}, None
        try:
            create(container / 'control' / 'recovery-once.lock', encode({'pid': os.getpid()}), uid, gid)
            retained = recovery_record(container)
            need(all(retained[key] == value for key, value in inputs.items()), 'TRUSTED_RECOVERY_ARGUMENTS_MATCH')
            ctx = context(container)
            life = load_life(container, uid)
            closure = close_image(container, ctx, life, lock, recovery=True)
            create(container / 'control' / 'recovery-closure.json', encode(closure), uid, gid)
            result.update(closure_evidence_available=True, closure_command_complete=closure['complete_closed_image'])
        except BaseException as error:
            result['errors'].append(fault(error, 'closure-unavailable-no-substitute-proof'))
        publish_root_diagnostic(inputs, image_diagnostic('recovery-closure', closure, result['errors']))
        job = container / 'job'
        if custody.namespace_live(container):
            return recover_off_mount(container, inputs, ctx, result, transport, custody)
        if job.exists():
            need(ctx is not None, 'EXACT_ROOT_CONTEXT_REQUIRED_TO_SELECT_AVAILABLE_IMAGE_BYTES')
            assert_producers_empty(container, ctx)
            need(not loop_associations(job / 'quota.img') and
                 not process_image_writers(job / 'volume', job / 'quota.img', uid),
                 'WRITERS_OR_ATTACHED_LOOP_REFUSE_IMAGE_SELECTION')
        try:
            host = host_attribution(inputs)
            create(container / 'control' / 'host-before-upload.json', encode(host), uid, gid)
            result['host_bounds_admitted'] = True
        except BaseException as error:
            result['errors'].append(fault(error, 'host-bounds-reject-full-payload'))
        create(container / 'control' / 'recovery-status.json', encode(result), uid, gid)
        inventory, files = outbound_inventory(container, uid, gid, transport)
        result['reference_status'] = retained_reference_status(container, files, closure)
        create(container / 'outbound-inventory.json', encode(inventory), uid, gid, 4 << 20)
        preliminary = result['host_bounds_admitted'] and inventory['safe_complete_scan']
        result.update(safe_complete_scan=inventory['safe_complete_scan'],
            complete_regular_file_inventory=inventory['complete_regular_file_inventory'],
            missing_expected=inventory.get('missing_expected', []),
            final_admission='REQUIRES_EXACT_UPLOAD_MANIFEST' if preliminary else 'REJECTED_FALLBACK_ONLY')
        create(container / 'custody-result.json', encode(result), uid, gid)
        try_append_fallback(inputs, {'custody': 'INCOMPLETE', 'operation': 'payload-selection',
            'complete_source_inventory': result['complete_regular_file_inventory'],
            'image_closed': result['closure_command_complete'], 'final_admission': result['final_admission']})
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
            upload_member = {'path': str(container / 'upload-manifest.json'), 'bytes': len(raw)}
            result['archive_bound'] = archive_size_bound(inputs, files + [upload_member], transport)
            exact_upload_paths(files + [upload_member])
            create(container / 'upload-manifest.json', raw, uid, gid, 4 << 20)
            upload_pin = hashlib.sha256(raw).hexdigest()
            create(authority_dir(container) / 'upload-manifest-pin.json',
                   encode({'bytes': len(raw), 'sha256': upload_pin}), 0, 0)
            result['upload_manifest_sha256'] = upload_pin
            result['payload_admitted'] = True
    except BaseException as error:
        result['errors'].append(fault(error, 'full-payload-rejected'))
        result['payload_admitted'] = False
        try_append_fallback(inputs, {'custody': 'INCOMPLETE', 'payload_admitted': False,
            'omitted_namespace_bytes': 'ALL_OR_UNKNOWN; NO_FULL_PAYLOAD_UPLOAD',
            'errors': [bounded_diagnostic_error(error) for error in result['errors'][-2:]]})
    result.setdefault('payload_admitted', False)
    print(json.dumps(result, sort_keys=True))
    # Ten still publishes the admitted complete available failure payload. One selects fallback only.
    if not result['payload_admitted']:
        return 1
    return 0 if (result['closure_command_complete'] and result['complete_regular_file_inventory'] and
                 result['reference_status']['complete_referenced_payload'] and not result['errors']) else 10


def emit_upload(args):
    """Unprivileged last check; output contains literal files, never a recursive glob."""
    inputs = run_inputs(args)
    transport = helper(Path(inputs['workspace']), 'scientific_posix_transport_limits')
    uid, gid = inputs['owner_uid'], inputs['owner_gid']
    need((os.geteuid(), os.getegid()) == (uid, gid), 'RUNNER_OUTPUT_WRITER_UID_GID')
    container = Path(inputs['container'])
    custody = helper(Path(inputs['workspace']), 'scientific_posix_failure_custody')
    if custody.namespace_live(container):
        selection = custody.verify(container, inputs, digest(args.upload_manifest_sha256), transport, decode)
        return emit_literal_upload(inputs, args.output_file, selection)
    private_namespace(container, uid, gid)
    need(not any(row[4] == str(container) or row[4].startswith(str(container) + '/')
                 for row in mounts()), 'DETACHED_NAMESPACE_REQUIRED_AT_UPLOAD_SELECTION')
    target = container / 'upload-manifest.json'
    manifest_raw = read(target, 4 << 20)
    need(hashlib.sha256(manifest_raw).hexdigest() == digest(args.upload_manifest_sha256),
         'EXACT_ROOT_AUTHORIZED_UPLOAD_MANIFEST_DIGEST')
    manifest = decode(manifest_raw, 4 << 20)
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
        need((item.is_relative_to(container) and item != container) or
             (item.parent == fallback and item.name in FALLBACK_NAMES), 'UPLOAD_FILE_SCOPE')
        maximum = (transport.maximum_member_bytes(item.relative_to(container).as_posix())
                   if item.is_relative_to(container) else FALLBACK_NAMES[item.name])
        observed = file_ref(item, maximum, owner=uid)
        need(row == {'path': str(item), **observed} and observed['identity'][4] == gid and
             observed['identity'][2] & stat.S_IRUSR, 'UPLOAD_BYTE_IDENTITY_AND_READABILITY_RECHECK')
        total += observed['bytes']
    reference = file_ref(target, 4 << 20, owner=uid)
    need(reference['sha256'] == args.upload_manifest_sha256, 'UPLOAD_MANIFEST_CHANGED_AFTER_AUTHORIZED_READ')
    need(total + reference['bytes'] <= PAYLOAD_BYTES, 'UPLOAD_RECHECK_PAYLOAD_BOUND')
    selection = files + [{'path': str(target), 'bytes': reference['bytes']}]
    archive_size_bound(inputs, selection, transport)
    return emit_literal_upload(inputs, args.output_file, selection)


def emit_literal_upload(inputs, output_file, selection):
    uid, gid = inputs['owner_uid'], inputs['owner_gid']
    raw_paths = exact_upload_paths(selection)
    output = path(output_file)
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
    own = file_ref(Path(__file__).absolute(), DRIVER_BYTES)['sha256']
    need(own == digest(args.job_sha256), 'EXTERNAL_JOB_SOURCE_PIN')
    admitted, raw_admission = admission(workspace, args.admission_sha256, own, args.ref)
    runtime = {name: root_runtime(name) for name in RUNTIME_PATHS}
    need(Path(sys.executable) == Path(runtime['python']['path']), 'EXACT_INSTALLED_PYTHON_EXECUTABLE')
    for name, expected in (('evidence.py', EVIDENCE_SHA), ('common.py', COMMON_SHA)):
        need(file_ref(workspace / 'scripts' / name, SMALL)['sha256'] == expected, 'PINNED_EVIDENCE_DEPENDENCY')
    inputs = run_inputs(args)
    container = Path(inputs['container'])
    try:
        trusted = authority_dir(container, create_new=True)
        with driver_lock(container) as lock:
            need(not (trusted / 'recovery-started.json').exists(), 'RECOVERY_FENCE_PROHIBITS_LATE_STAGING')
            limits(IMAGE_BYTES + 8192)
            stage_bootstrap(args, inputs, container, trusted, own, raw_admission, runtime, admitted)
            start_controller_once(container)
            return controller(container, lock, inputs)
    except (OSError, RuntimeError, ValueError) as error:
        publish_root_diagnostic(inputs, {'format': 'scientific-posix-root-terminal-diagnostic-v1',
            'operation': 'bootstrap', 'phase': 'before-or-around-controller',
            'errors': [bounded_diagnostic_error(fault(error, 'bootstrap'))]})
        return 1


def stage_bootstrap(args, inputs, container, trusted, own, raw_admission, runtime, admitted):
    uid, gid = inputs['owner_uid'], inputs['owner_gid']
    workspace = Path(inputs['workspace'])
    driver_raw = read(Path(__file__).absolute(), DRIVER_BYTES)
    need(hashlib.sha256(driver_raw).hexdigest() == own, 'INDEPENDENT_DRIVER_COPY_PIN_MISMATCH')
    create(trusted / 'driver.py', driver_raw, 0, 0, DRIVER_BYTES)
    create(trusted / 'root-admission.json', raw_admission, 0, 0, 8192)
    recovery_raw = encode({**inputs, 'runtime': runtime})
    create(trusted / 'recovery.json', recovery_raw, 0, 0)
    make_dir(container, uid, gid)
    # Durable identity precedes every source/packet byte. A partial record is only failure data.
    create(container / 'recovery.json', recovery_raw, uid, gid)
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
    context_raw = encode(ctx)
    create(trusted / 'context.json', context_raw, 0, 0)
    create(container / 'control' / 'context.json', context_raw, uid, gid)


def main():
    global TRUSTED_UID
    need(sys.platform == 'linux' and os.name == 'posix', 'LINUX_ONLY_NO_SKIP')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    owner_actions = ('_group-memory-owner', '_group-original22-owner', '_group-spi-owner')
    parser.add_argument('action', choices=('bootstrap', 'recover', 'emit-upload', *owner_actions))
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
    parser.add_argument('--supervisor-admission-sha256')
    parser.add_argument('--upload-manifest-sha256')
    parser.add_argument('--driver-lock', type=int)
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
    if args.action in owner_actions:
        return owner_action(args.container, args.action, args.supervisor_admission_sha256, args.driver_lock)
    raise RuntimeError('understood CLI action required')


if __name__ == '__main__':
    raise SystemExit(main())
