"""Versioned zero-reserved ext4 observations; no formatter, mount or quota claim.

Pure proof controls are not actual filesystem/quota measurements. A SHA256 binds
record contents, not authenticity. Existing ENOSPC and reservation gates remain.
"""
from __future__ import annotations
import time
ENTRY_STARTED = time.monotonic()

from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys
import threading
import uuid

POLICY = 'owned-ext4-zero-reserved-v1'
NESTED_POLICY = 'owned-ext4-zero-reserved-nested-inodes50000-v1'
NESTED_INODES = 50_000
MAX_STREAM = 32768
MAX_CONTEXT = 8192
MAX_PROOF = 200_000
PROBE_BYTES = 4096
OBSERVATION_SECONDS = 18
COLLECTOR_SECONDS = 80
FAILURE_TAIL_SECONDS = 2
_DEADLINES = []
LIMITS = {'filesystem_floor_bytes': 500_000_000, 'control_bytes': 20_000_000,
          'global_reserve_bytes': 2_000_000_000, 'probe_bytes': PROBE_BYTES,
          'command_output_bytes': MAX_STREAM, 'command_seconds': 10}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    bounded(value)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False, ensure_ascii=False).encode()).hexdigest()


def bounded(value, *, budget=MAX_PROOF, fields=2048, string_limit=MAX_STREAM):
    """Refuse oversized/cyclic/unknown objects before clone, encode or hash."""
    remaining, nodes, active = budget, fields, set()
    def visit(item, depth=0):
        nonlocal remaining, nodes
        nodes -= 1
        require(nodes >= 0 and depth <= 8, 'filesystem proof field/depth bound exceeded')
        if type(item) is str:
            require(len(item) <= string_limit, 'filesystem proof string bound exceeded')
            cost = 2 + sum(6 if ord(c) < 32 else 2 if c in '\\"' else len(c.encode()) for c in item)
        elif item is None or type(item) is bool:
            cost = 5
        elif type(item) is int:
            require(item.bit_length() <= 64, 'filesystem proof integer bound exceeded')
            cost = 21
        elif type(item) is float:
            require(math.isfinite(item), 'nonfinite filesystem proof number')
            cost = 32
        else:
            require(type(item) in (dict, list) and id(item) not in active
                    and len(item) <= min(fields, 128), 'filesystem proof container bound exceeded')
            active.add(id(item))
            remaining -= 2 + 2 * len(item)
            for key, val in item.items() if type(item) is dict else enumerate(item):
                if type(item) is dict:
                    require(type(key) is str and len(key) <= 128, 'filesystem proof key bound exceeded')
                    visit(key, depth + 1)
                visit(val, depth + 1)
            active.remove(id(item))
            cost = 0
        remaining -= cost
        require(remaining >= 0, 'filesystem proof aggregate bound exceeded')
    visit(value)


class ObservationFailure(ValueError):
    """Available bounded streams survive command failure for caller retention."""
    def __init__(self, message, observation):
        super().__init__(message)
        self.observation = observation
        self.partial_record = None


class DeadlineExceeded(TimeoutError):
    pass


@contextmanager
def whole_entry(seconds, *, started=None):
    """Dedicated Linux main-thread guard, including cleanup and publication.

    The soft cutoff leaves two seconds for failure retention. The hard cutoff
    exits without claiming quiescence. Production MUST additionally retain an
    external timeout/owned-parent receipt: an in-process timer cannot establish
    cleanup after hard exit or interrupt an uninterruptible kernel operation.
    Nested observations preserve the earlier collector deadline.
    """
    require(sys.platform == 'linux' and threading.current_thread() is threading.main_thread()
            and hasattr(signal, 'setitimer'), 'whole-entry deadline requires dedicated Linux main thread')
    require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds > FAILURE_TAIL_SECONDS,
            'invalid whole-entry deadline')
    started = time.monotonic() if started is None else started
    end = started + seconds
    previous = signal.getsignal(signal.SIGALRM)
    require(_DEADLINES or signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
            'cannot replace unrelated real-time deadline')
    state = {'soft': end - FAILURE_TAIL_SECONDS, 'hard': end, 'expired': False}
    _DEADLINES.append(state)

    def arm():
        deadline = min(s['hard'] if s['expired'] else s['soft'] for s in _DEADLINES)
        signal.setitimer(signal.ITIMER_REAL, max(.000001, deadline - time.monotonic()))

    def interrupted(signum, frame):
        now = time.monotonic()
        if any(s['expired'] and now >= s['hard'] for s in _DEADLINES):
            os._exit(124)  # Pending records explicitly retain unknown quiescence.
        for item in _DEADLINES:
            if now >= item['soft']:
                item['expired'] = True
        arm()
        raise DeadlineExceeded('whole-entry soft cutoff; failure tail only')

    signal.signal(signal.SIGALRM, interrupted)
    arm()
    try:
        require(time.monotonic() < state['soft'], 'whole-entry setup exhausted failure-tail margin')
        yield
        require(not state['expired'] and time.monotonic() < state['soft'],
                'whole-entry deadline exhausted; success refused')
    finally:
        _DEADLINES.pop()
        signal.signal(signal.SIGALRM, previous)
        if _DEADLINES:
            arm()
        else:
            signal.setitimer(signal.ITIMER_REAL, 0)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def checked(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute normalized path required')
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode), 'linked owned path')
        require(stat.S_ISDIR(info.st_mode) or part == path and stat.S_ISREG(info.st_mode),
                'unexpected owned path type')
    return info


def identity(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'uid': info.st_uid, 'gid': info.st_gid, 'nlink': info.st_nlink,
            'size': info.st_size, 'device_major_minor': f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}'}


def mount_identity(info):
    return {k: v for k, v in identity(info).items() if k != 'size'}


def command(argv):
    """No unsafe implicit backend: the caller must retain owned supervision."""
    raise ValueError('explicit durable owned runner required before command launch')


def owned_capture(item):
    proof = item['ownership']
    require(proof['descendant_quiescence'] == {'quiescent': True, 'residual': []}
            and proof['capture_complete'] is True and proof['discarded_output_bytes'] == 0
            and isinstance(proof['receipt_path'], str) and Path(proof['receipt_path']).is_absolute()
            and re.fullmatch('[0-9a-f]{64}', proof['receipt_sha256']),
            'retained owned supervision and complete quiescent capture required')
    for stream in ('stdout', 'stderr'):
        require(proof['capture'][stream]['sha256'] == item[stream + '_sha256']
                and proof['capture'][stream]['bytes'] == len(item[stream].encode()),
                'retained supervision capture differs')


def write_exclusive(path, value):
    bounded(value)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode() + b'\n'
    require(len(raw) <= MAX_PROOF, 'serialized filesystem proof exceeds bound')
    parent = checked(path.parent)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid(), 'proof parent not owned')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


class OwnedRunner:
    """Use ONLY in a fresh dedicated Linux main process; retains all captures.

    Reuses run_owned's subreaper, adopted-child cleanup and quiescence proof.
    No formatter argv is executed by this adapter or collector.
    """
    owned_durable = True

    def __init__(self, audit_dir):
        require(sys.platform == 'linux' and os.getuid() > 0, 'ordinary dedicated Linux runner required')
        self.audit, self.sequence, self.checkpoints = Path(audit_dir), 0, 0
        parent = checked(self.audit.parent)
        require(parent.st_uid == os.getuid() and stat.S_ISDIR(parent.st_mode), 'audit parent not owned')
        self.audit.mkdir(mode=0o700)  # Exclusive; previous evidence is never reused.

    def __call__(self, argv):
        started = time.monotonic()
        self.active_observation = None
        try:
            with whole_entry(OBSERVATION_SECONDS, started=started):
                return self._capture(argv, started)
        except BaseException as failure:
            failure.audit_reference = self.active_observation
            raise

    def checkpoint(self, record):
        """Append-only bounded partials survive later failure and hard exit."""
        require(self.checkpoints < 24, 'filesystem checkpoint count exceeded')
        path = self.audit / ('partial-' + str(self.checkpoints) + '.json')
        self.checkpoints += 1
        return write_exclusive(path, {'status': 'INCOMPLETE', 'partial_record': record,
                                     'descendant_quiescence': {'quiescent': False, 'residual': None}})

    def _capture(self, argv, started):
        from reference_transport_supervisor import run_owned
        bounded(argv, budget=4096, fields=32, string_limit=2048)
        require(self.sequence < 4, 'filesystem observation count exceeded')
        prefix = self.audit / str(self.sequence)
        self.sequence += 1
        stdout, stderr, receipt = (prefix.with_suffix(suffix) for suffix in ('.stdout', '.stderr', '.json'))
        pending = prefix.with_suffix('.pending.json')
        self.active_observation = {'requested_command': argv, 'receipt_path': str(receipt),
                                   'stdout_path': str(stdout), 'stderr_path': str(stderr),
                                   'pending_path': str(pending), 'status': 'UNVERIFIED'}
        write_exclusive(pending, {'status': 'INCOMPLETE', 'requested_command': argv,
                        'started_at': utc(), 'whole_entry_seconds': OBSERVATION_SECONDS,
                        'receipt_path': str(receipt), 'stdout_path': str(stdout), 'stderr_path': str(stderr),
                        'descendant_quiescence': {'quiescent': False, 'residual': None}})
        # External timeout also bounds ordinary commands. Privileged commands
        # retain a root timeout so ordinary-UID cleanup need not signal root.
        actual = ['timeout', '--signal=TERM', '--kill-after=1s', '9s', *argv]
        if argv[:2] == ['sudo', '-n']:
            actual = ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=1s', '9s', *argv[2:]]
        record = run_owned(actual, stdout, stderr, started=started, total_seconds=OBSERVATION_SECONDS,
                           cleanup_seconds=6, receipt_seconds=2, capture_bytes=MAX_STREAM,
                           environ={**os.environ, 'LC_ALL': 'C'})
        record['requested_command'], record['actual_command'] = argv, actual
        receipt_sha = write_exclusive(receipt, record)
        streams = {}
        for label, path in (('stdout', stdout), ('stderr', stderr)):
            info = checked(path)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_STREAM,
                    'retained owned capture unavailable')
            raw = path.read_bytes()
            require(len(raw) == info.st_size and hashlib.sha256(raw).hexdigest() == record['capture'][label]['sha256'],
                    'retained owned capture changed')
            streams[label] = raw.decode('utf-8', errors='strict')
        quiet = record.get('descendant_quiescence', {})
        return {'exit_code': record['worker_exit_code'] if record['status'] == 'PASS' else -1, **streams,
                'ownership': {'descendant_quiescence': {'quiescent': quiet.get('quiescent'), 'residual': quiet.get('residual')},
                              'capture_complete': record['capture_complete'],
                              'discarded_output_bytes': record['discarded_output_bytes'], 'capture': record['capture'],
                              'receipt_path': str(receipt), 'receipt_sha256': receipt_sha}}


def observe(argv, runner):
    start = utc()
    value = runner(argv)
    bounded(value)
    require(isinstance(value, dict), 'filesystem observation failed')
    out = {'command': argv, 'started_at': start, 'ended_at': utc(), 'exit_code': value.get('exit_code'),
           'ownership': value.get('ownership')}
    for key in ('stdout', 'stderr'):
        raw = value.get(key)
        require(isinstance(raw, str), 'missing complete command stream')
        out[key], out[key + '_sha256'] = raw, hashlib.sha256(raw.encode()).hexdigest()
    require(len(out['stdout'].encode()) + len(out['stderr'].encode()) <= MAX_STREAM,
            'filesystem observation output exceeds bound')
    try:
        owned_capture(out)
        require(out['exit_code'] == 0, 'filesystem observation failed')
    except (ValueError, KeyError, TypeError) as failure:
        raise ObservationFailure('filesystem observation failed or is not quiescent', out) from failure
    return out


def policy_role(policy, image_bytes):
    require(policy in (POLICY, NESTED_POLICY), 'unknown filesystem policy')
    require(policy != NESTED_POLICY or type(image_bytes) is int and image_bytes == 1_100_000_000,
            'nested inode policy requires the fixed nested image role')


def formatter_argv(image, *, policy=POLICY):
    require(policy in (POLICY, NESTED_POLICY), 'unknown filesystem policy')
    return ['mkfs.ext4', '-F', '-q', '-m', '0',
            *(['-N', str(NESTED_INODES)] if policy == NESTED_POLICY else []), str(image)]


def geometry(raw, *, policy=POLICY):
    require(policy in (POLICY, NESTED_POLICY), 'unknown filesystem policy')
    result = {}
    labels = [('Filesystem UUID', 'uuid'), ('Block size', 'block_size'),
              ('Block count', 'block_count'), ('Reserved block count', 'reserved_blocks')]
    if policy == NESTED_POLICY:
        labels += [('Inode count', 'inode_count'), ('Inode size', 'inode_size'),
                   ('First block', 'first_data_block'), ('Blocks per group', 'blocks_per_group'),
                   ('Inodes per group', 'inodes_per_group'), ('Inode blocks per group', 'inode_blocks_per_group')]
    for label, key in labels:
        values = re.findall(r'^' + re.escape(label) + r':\s*(\S+)\s*$', raw, re.MULTILINE)
        require(len(values) == 1, 'missing or duplicate superblock ' + label)
        result[key] = values[0] if key == 'uuid' else int(values[0])
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', result['uuid']),
            'invalid filesystem UUID')
    return result


def validate_policy(record, image: Path, mount_point: Path, image_bytes: int, run_context: dict,
                    *, policy=POLICY) -> None:
    """Pure validation: no I/O, and never a replacement for actual ENOSPC proof."""
    try:
        r, ctx = record, run_context
        policy_role(policy, image_bytes)
        bounded(ctx, budget=MAX_CONTEXT, fields=128, string_limit=4096)
        bounded(r)
        require(isinstance(r, dict) and r['policy'] == policy and r['limits'] == LIMITS,
                'filesystem policy/limits differ')
        require(type(image_bytes) is int and image_bytes in (2_300_000_000, 1_100_000_000),
                'unsupported fixed image size')
        require(r['image_path'] == str(image) and r['mount_point'] == str(mount_point)
                and image.is_absolute() and mount_point.is_absolute()
                and '..' not in image.parts and '..' not in mount_point.parts
                and r['image_bytes'] == image_bytes and r['run_context'] == ctx,
                'image/path/run context substituted')
        require(isinstance(ctx, dict) and re.fullmatch('[0-9a-f]{64}', ctx['source'])
                and re.fullmatch('[0-9a-f]{40}', ctx['commit']) and ctx['git_status'] == ''
                and all(re.fullmatch('[1-9][0-9]{0,19}', ctx[k]) for k in ('github_run_id', 'github_run_attempt')),
                'missing source or clean execution context')
        require(r['proof_sha256'] == digest({k: v for k, v in r.items() if k != 'proof_sha256'}),
                'filesystem proof digest differs')
        uid, gid = r['uid'], r['gid']
        require(r['platform'] == 'linux' and type(uid) is int and uid > 0
                and type(gid) is int and gid > 0, 'missing ordinary UID/GID observation')
        before, after = r['image_before'], r['image_after']
        require(before == after and stat.S_ISREG(before['mode']) and before['nlink'] == 1
                and before['size'] == image_bytes and before['uid'] == uid and before['gid'] == gid
                and before['inode'] > 0, 'owned single-link image identity differs')
        require(r['mount_before'] == r['mount_after'] and stat.S_ISDIR(r['mount_before']['mode'])
                and r['mount_before']['uid'] == uid and r['mount_before']['gid'] == gid,
                'owned mount identity differs')
        cmd = r['formatter_command']
        require(isinstance(cmd, list) and len(cmd) <= 16 and cmd[-1] == str(image), 'formatter image differs')
        args = cmd[2:] if cmd[:2] == ['sudo', '-n'] else cmd
        require(args == formatter_argv(image, policy=policy) if policy == NESTED_POLICY else
                args[0] == 'mkfs.ext4' and args[1:-1] in (['-F', '-q', '-m', '0'], ['-F', '-q', '-m0']),
                'formatter must be exact mkfs.ext4 -F -q -m0 policy')
        expected = {'version': ['mkfs.ext4', '-V'], 'superblock': ['dumpe2fs', '-h', str(image)],
                    'mount': ['findmnt', '--json', '--mountpoint', str(mount_point), '-o', 'TARGET,FSTYPE,SOURCE,UUID,OPTIONS,MAJ:MIN'],
                    'loop': ['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                             '--output', 'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT']}
        started = dt.datetime.fromisoformat(r['started_at'])
        ended = dt.datetime.fromisoformat(r['ended_at'])
        require(started.tzinfo is not None and ended.tzinfo is not None
                and 0 <= (ended - started).total_seconds() <= 80, 'invalid observation timestamps')
        for key, argv in expected.items():
            item = r['observations'][key]
            require(item['command'] == argv and item['exit_code'] == 0, 'substituted observation command')
            require(started <= dt.datetime.fromisoformat(item['started_at'])
                    <= dt.datetime.fromisoformat(item['ended_at']) <= ended, 'command timestamp differs')
            require(sum(len(item[s].encode()) for s in ('stdout', 'stderr')) <= MAX_STREAM,
                    'observation stream too large')
            for stream in ('stdout', 'stderr'):
                require(hashlib.sha256(item[stream].encode()).hexdigest() == item[stream + '_sha256'],
                        'observation stream digest differs')
            owned_capture(item)
        version = r['observations']['version']
        require(re.search(r'mke2fs\s+\d+\.\d+', version['stdout'] + version['stderr']), 'missing formatter version')
        g = geometry(r['observations']['superblock']['stdout'], policy=policy)
        require(g == r['geometry'] and g['reserved_blocks'] == 0, 'reserved blocks are not zero')
        require(g['block_size'] in (1024, 2048, 4096) and type(g['block_count']) is int
                and g['block_count'] > 0 and 0 <= image_bytes - g['block_count'] * g['block_size'] < g['block_size'],
                'superblock image dimensions differ')
        if policy == NESTED_POLICY:
            validate_inode_geometry(r, g)
        mounts = json.loads(r['observations']['mount']['stdout'])['filesystems']
        loops = json.loads(r['observations']['loop']['stdout'])['loopdevices']
        require(len(mounts) == len(loops) == 1, 'ambiguous mount/loop observation')
        m, loop = mounts[0], loops[0]
        require(m['target'] == str(mount_point) and m['fstype'] == 'ext4' and m['uuid'] == g['uuid']
                and re.fullmatch('/dev/loop[0-9]+', m['source']) and 'rw' in m['options'].split(','),
                'wrong mounted filesystem/UUID')
        for dev in (before, r['mount_before'], r['mount_after'], r['probe']['before'], r['probe']['after']):
            number = dev['device']
            require(type(number) is int and 0 <= number < 2 ** 64
                    and dev['device_major_minor'] == f'{(number >> 8 & 4095) | (number >> 32 & 4294963200)}:{(number & 255) | (number >> 12 & 4294967040)}',
                    'device number and major/minor differ')
        require(m['maj:min'] == r['mount_before']['device_major_minor']
                == r['probe']['before']['device_major_minor'], 'mount/probe do not use observed loop device')
        require(loop['name'] == m['source'] and loop['back-file'] == str(image)
                and int(loop['back-ino']) == before['inode'] and loop['back-maj:min'] == before['device_major_minor']
                and int(loop['offset']) == 0 and int(loop['sizelimit']) == 0, 'wrong loop backing image')
        fs = r['statvfs']
        require(started <= dt.datetime.fromisoformat(fs['observed_at']) <= ended
                and fs['uid'] == uid and fs['gid'] == gid
                and all(type(fs[k]) is int for k in ('f_frsize', 'f_blocks', 'f_bfree', 'f_bavail'))
                and fs['f_frsize'] == g['block_size'] and 0 < fs['f_blocks'] <= g['block_count']
                # Ordinary available blocks can be less than total free even
                # with zero superblock reserved blocks. Keep both observations
                # and admit only the actual unprivileged available counter.
                and 0 <= fs['f_bavail'] <= fs['f_bfree'] <= fs['f_blocks']
                and fs['f_bavail'] * fs['f_frsize'] >= 520_000_000, 'inconsistent ordinary statvfs counters/floor')
        if policy == NESTED_POLICY:
            require(all(type(fs[k]) is int for k in ('f_files', 'f_ffree', 'f_favail'))
                    and fs['f_files'] == g['inode_count']
                    and 0 <= fs['f_favail'] <= fs['f_ffree'] <= fs['f_files'],
                    'inconsistent observed inode counters')
        p = r['probe']; pi = p['before']
        require(p['exclusive'] is True and p['cleaned'] is True and p['before'] == p['after']
                and pi['device'] == r['mount_before']['device'] and pi['uid'] == uid and pi['gid'] == gid
                and stat.S_ISREG(pi['mode']) and stat.S_IMODE(pi['mode']) == 0o600 and pi['nlink'] == 1
                and pi['size'] == PROBE_BYTES and p['sha256'] == hashlib.sha256(b'F' * PROBE_BYTES).hexdigest(),
                'exclusive owned fsync/readback probe differs')
    except (KeyError, TypeError, IndexError, AttributeError, OverflowError) as failure:
        raise ValueError('missing or malformed filesystem policy proof') from failure


def validate_inode_geometry(record, g):
    """Check per-group rounding, retaining requested and observed inode counts.

    These are authenticated historical observations, never free-space evidence.
    Actual post-copy byte/inode/time admission remains a separate required gate.
    """
    require(type(record.get('requested_inode_count')) is int
            and record['requested_inode_count'] == NESTED_INODES, 'requested inode count differs')
    keys = ('inode_count', 'inode_size', 'first_data_block', 'blocks_per_group',
            'inodes_per_group', 'inode_blocks_per_group')
    require(all(type(g[k]) is int for k in keys)
            and g['inode_size'] in (128, 256, 512, 1024) and g['inode_size'] <= g['block_size']
            and g['first_data_block'] == (1 if g['block_size'] == 1024 else 0)
            and 0 < g['blocks_per_group'] <= 8 * g['block_size']
            and 0 < g['inodes_per_group'] <= 8 * g['block_size']
            and g['inode_blocks_per_group'] > 0, 'unsupported observed inode geometry')
    groups = (g['block_count'] - g['first_data_block'] + g['blocks_per_group'] - 1) // g['blocks_per_group']
    per_block = g['block_size'] // g['inode_size']
    require(g['inode_count'] == groups * g['inodes_per_group']
            and g['inodes_per_group'] % per_block == 0
            and g['inode_blocks_per_group'] * per_block == g['inodes_per_group']
            and NESTED_INODES <= g['inode_count'] < NESTED_INODES + groups * per_block,
            'observed inode count/block-group rounding differs')


def collect_policy(image: Path, mount_point: Path, image_bytes: int, run_context: dict,
                   formatter_command: list, runner=None, *, policy=POLICY) -> dict:
    """Observe existing mount; CLI/owned external parent must bind publication.

    Same API; every post-admission exception carries ``partial_record``. With
    OwnedRunner, append-only partial-N.json files also survive a hard exit.
    """
    bounded(run_context, budget=MAX_CONTEXT, fields=128, string_limit=4096)
    policy_role(policy, image_bytes)
    bounded(formatter_command, budget=4096, fields=32, string_limit=2048)
    require(callable(runner) and getattr(runner, 'owned_durable', False) is True,
            'explicit durable owned runner required before command launch')
    require(sys.platform == 'linux' and os.getuid() > 0 and os.getgid() > 0, 'ordinary Linux UID/GID required')
    image, mount_point = Path(image), Path(mount_point)
    r = {'policy': policy, 'limits': dict(LIMITS), 'started_at': utc(), 'platform': sys.platform,
         'uid': os.getuid(), 'gid': os.getgid(), 'image_path': str(image), 'mount_point': str(mount_point),
         'image_bytes': image_bytes, 'run_context': json.loads(json.dumps(run_context)),
         'formatter_command': list(formatter_command), 'observations': {}}
    if policy == NESTED_POLICY:
        r['requested_inode_count'] = NESTED_INODES
    try:
        with whole_entry(COLLECTOR_SECONDS):
            try:
                return _collect_policy(r, image, mount_point, image_bytes, run_context, runner)
            except BaseException as failure:
                if isinstance(failure, ObservationFailure):
                    r['failed_observation'] = failure.observation
                if getattr(failure, 'audit_reference', None) is not None:
                    r['failed_observation_reference'] = failure.audit_reference
                r['failure'] = {'type': type(failure).__name__, 'message': str(failure)[:1000], 'at': utc()}
                failure.partial_record = failure_partial(r)
                try:
                    checkpoint(failure.partial_record, runner)
                except BaseException as retention_failure:
                    failure.partial_record['retention_error'] = (type(retention_failure).__name__ + ': ' + str(retention_failure))[:1000]
                raise
    except BaseException as failure:
        # Includes the guard's own final elapsed-time refusal. Do not start new
        # filesystem work after its bounded scope has closed.
        if getattr(failure, 'partial_record', None) is None:
            failure.partial_record = failure_partial(r)
        raise


def failure_partial(record):
    """Retain all structured facts when escaped raw streams exhaust proof size.

    Exact raw streams remain at their owned receipt capture paths; compacting a
    failure never turns it into a valid complete policy proof.
    """
    try:
        bounded(record, budget=MAX_PROOF - 8192)
        return record
    except ValueError:
        compact = dict(record)
        def observation(item):
            return {**{k: v for k, v in item.items() if k not in ('stdout', 'stderr')},
                    'raw_streams_in_owned_capture_only': True}
        compact['observations'] = {k: observation(v) for k, v in record['observations'].items()}
        if 'failed_observation' in compact:
            compact['failed_observation'] = observation(compact['failed_observation'])
        bounded(compact, budget=MAX_PROOF - 8192)
        return compact


def checkpoint(record, runner):
    retain = getattr(runner, 'checkpoint', None)
    if callable(retain):
        retain(record)


def _collect_policy(r, image, mount_point, image_bytes, run_context, runner):
    checkpoint(r, runner)
    r['stage'] = 'image_identity'
    r['image_before'] = identity(checked(image))
    r['stage'] = 'mount_identity'
    r['mount_before'] = mount_identity(checked(mount_point))
    checkpoint(r, runner)
    require(stat.S_ISREG(r['image_before']['mode']) and r['image_before']['uid'] == r['uid']
            and r['image_before']['nlink'] == 1 and r['image_before']['size'] == image_bytes
            and image_bytes in (2_300_000_000, 1_100_000_000), 'exact owned image required before observation')
    commands = {'version': ['mkfs.ext4', '-V'], 'superblock': ['dumpe2fs', '-h', str(image)],
                'mount': ['findmnt', '--json', '--mountpoint', str(mount_point), '-o', 'TARGET,FSTYPE,SOURCE,UUID,OPTIONS,MAJ:MIN'],
                'loop': ['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                         '--output', 'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT']}
    for key, argv in commands.items():
        r['stage'] = 'observation:' + key
        r['observations'][key] = observe(argv, runner)
        checkpoint(r, runner)
    r['stage'] = 'geometry'
    raw = r['observations']['superblock']['stdout']
    r['geometry'] = geometry(raw) if r['policy'] == POLICY else geometry(raw, policy=r['policy'])
    checkpoint(r, runner)
    r['stage'] = 'probe_open_directory'
    directory = os.open(mount_point, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name, fd, own = '.fq-fs-policy-' + uuid.uuid4().hex, None, None
    try:
        require(mount_identity(os.fstat(directory)) == r['mount_before'], 'mount directory substituted')
        fs = os.fstatvfs(directory)
        r['statvfs'] = {'observed_at': utc(), 'uid': os.getuid(), 'gid': os.getgid(),
                        **{k: getattr(fs, k) for k in ('f_frsize', 'f_blocks', 'f_bfree', 'f_bavail')}}
        if r['policy'] == NESTED_POLICY:
            r['statvfs'].update({k: getattr(fs, k) for k in ('f_files', 'f_ffree', 'f_favail')})
        r['stage'] = 'filesystem_floor'
        checkpoint(r, runner)
        require(fs.f_bavail * fs.f_frsize >= 520_000_000, 'initial filesystem floor/control margin unavailable')
        r['stage'] = 'probe_create'
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        own = os.fstat(fd)
        r['probe'] = {'exclusive': True, 'created_identity': identity(own), 'cleaned': False}
        checkpoint(r, runner)
        require(stat.S_ISREG(own.st_mode) and own.st_uid == r['uid'] and own.st_gid == r['gid']
                and own.st_nlink == 1 and own.st_dev == r['mount_before']['device'], 'probe ownership differs')
        r['stage'] = 'probe_write_fsync'
        require(os.write(fd, b'F' * PROBE_BYTES) == PROBE_BYTES, 'short filesystem probe write')
        os.fsync(fd)
        before = identity(os.fstat(fd))
        r['probe']['before'] = before
        r['stage'] = 'probe_readback'
        checkpoint(r, runner)
        os.lseek(fd, 0, os.SEEK_SET)
        data = os.read(fd, PROBE_BYTES + 1)
        require(data == b'F' * PROBE_BYTES, 'filesystem probe readback differs')
        r['probe'] = {'exclusive': True, 'before': before, 'after': identity(os.fstat(fd)),
                      'sha256': hashlib.sha256(data).hexdigest(), 'cleaned': False}
    finally:
        try:
            if own is not None:
                r['stage'] = 'probe_cleanup'
                found = os.stat(name, dir_fd=directory, follow_symlinks=False)
                require(identity(found) == identity(os.fstat(fd)) and found.st_nlink == 1
                        and (found.st_dev, found.st_ino) == (own.st_dev, own.st_ino),
                        'probe substituted before cleanup')
                os.unlink(name, dir_fd=directory)
                r['probe']['cleaned'] = True
        finally:
            if fd is not None:
                os.close(fd)
            os.close(directory)
    r['probe']['cleaned'] = True
    checkpoint(r, runner)
    r['stage'] = 'final_identity'
    r.update(image_after=identity(checked(image)), mount_after=mount_identity(checked(mount_point)), ended_at=utc())
    r['stage'] = 'validation'
    r['proof_sha256'] = digest(r)
    validate_policy(r, image, mount_point, image_bytes, run_context, policy=r['policy'])
    return r


def main():
    """Run ONLY under external timeout + retained owned parent supervision.

    80 seconds includes context, all observations, cleanup, fsync and proof
    publication; last two seconds are failure-only. A hard exit124 leaves
    INCOMPLETE audit records and never proves descendant quiescence. Formatter
    receipt authentication remains the integrating caller's responsibility.
    """
    with whole_entry(COLLECTOR_SECONDS, started=ENTRY_STARTED):
        return _main()


def _main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('image', 'mount', 'context-json', 'proof', 'audit-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--image-bytes', type=int, required=True, choices=(2_300_000_000, 1_100_000_000))
    parser.add_argument('--policy', choices=(POLICY, NESTED_POLICY), default=POLICY)
    args = parser.parse_args()
    failure_record = {'policy': args.policy, 'status': 'FAIL', 'started_at': utc(),
                      'descendant_quiescence': {'quiescent': False, 'residual': None}}
    runner, result = None, None
    try:
        require(sys.platform == 'linux' and os.getuid() > 0, 'ordinary Linux entry required')
        info = checked(args.context_json)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                and info.st_size <= MAX_CONTEXT, 'context input is not bounded owned metadata')
        fd = os.open(args.context_json, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            require(identity(os.fstat(stream.fileno())) == identity(info), 'context descriptor substituted')
            raw = stream.read(MAX_CONTEXT + 1)
            require(len(raw) <= MAX_CONTEXT and identity(os.fstat(stream.fileno())) == identity(info)
                    == identity(checked(args.context_json)), 'context input changed or exceeded bound')
        context = json.loads(raw)
        bounded(context, budget=MAX_CONTEXT, fields=128, string_limit=4096)
        runner = OwnedRunner(args.audit_dir)
        write_exclusive(runner.audit / 'entry.pending.json', {**failure_record, 'status': 'INCOMPLETE'})
        result = collect_policy(args.image, args.mount, args.image_bytes, context,
                                formatter_argv(args.image, policy=args.policy), runner, policy=args.policy)
        write_exclusive(args.proof, result)
        return 0
    except BaseException as failure:
        failure_record.update(ended_at=utc(), error=(type(failure).__name__ + ': ' + str(failure))[:1000])
        partial = getattr(failure, 'partial_record', None)
        if partial is not None or result is not None:
            failure_record['partial_record'] = partial if partial is not None else failure_partial(result)
        if isinstance(failure, ObservationFailure) and partial is None:
            failure_record['failed_observation'] = failure.observation
        if runner is not None:
            write_exclusive(runner.audit / 'failure.json', failure_record)
        write_exclusive(args.proof, failure_record)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
