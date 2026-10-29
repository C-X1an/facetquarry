"""Actual owned formatter/collector receipts, outside the pure policy collector.

Only live canonical Actions audit files can authorize a policy summary. Exported
copies and pure policy fixtures are evidence data, never live validation roots.
No filesystem/quota qualification follows from process supervision alone.
"""
from __future__ import annotations
import time
ENTRY_STARTED = time.monotonic()

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from common import ROOT
import reference_filesystem as fs

KIND = 'owned-filesystem-bindings-v1'
KEYS = ('source', 'commit', 'git_status', 'github_run_id', 'github_run_attempt')
PARENT_SECONDS = 100
ENTRY_SECONDS = 110
ENVELOPE_BYTES = 20_000_000
UNKNOWN = {'quiescent': False, 'residual': None}
require = fs.require


def normalized(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and str(path) == os.path.abspath(path),
            'absolute normalized filesystem binding path required')
    return path


def ordinary():
    require(sys.platform == 'linux' and os.getuid() > 0 and os.getgid() > 0,
            'actual filesystem binding requires ordinary Linux UID/GID')


def workspace():
    root = normalized(os.environ['GITHUB_WORKSPACE'])
    info = fs.checked(root)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), 'Actions workspace is not owned')
    return root


def layout(directory, image, image_bytes, mount=None, *, create=False):
    ordinary()
    root, directory, image = workspace(), normalized(directory), normalized(image)
    temporary = normalized(os.environ['RUNNER_TEMP'])
    base = root / '.local' / 'reference-filesystem'
    expected = {
        2_300_000_000: ('outer', temporary / 'facetquarry-reference.img', temporary / 'facetquarry-reference'),
        1_100_000_000: ('nested', temporary / 'facetquarry-reference' / 'reference-results.img',
                       temporary / 'facetquarry-reference' / 'source' / '.local'),
    }
    require(type(image_bytes) is int and image_bytes in expected, 'unsupported exact filesystem binding size')
    name, expected_image, expected_mount = expected[image_bytes]
    require(directory == base / name and image == expected_image
            and (mount is None or normalized(mount) == expected_mount),
            'filesystem binding paths differ from canonical Actions paths')
    if create:
        for path in (root / '.local', base, directory):
            if not os.path.lexists(path):
                path.mkdir(mode=0o700)
            info = fs.checked(path)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                    and not stat.S_IMODE(info.st_mode) & 0o022, 'binding directory is not privately owned')
    info = fs.checked(directory)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and not stat.S_IMODE(info.st_mode) & 0o022, 'binding directory is not privately owned')
    return root, directory, image, expected_mount


def context_shape(value):
    fs.bounded(value, budget=fs.MAX_CONTEXT, fields=128, string_limit=4096)
    require(type(value) is dict and set(value) == set(KEYS)
            and all(type(value[k]) is str for k in KEYS)
            and re.fullmatch('[0-9a-f]{64}', value['source'])
            and re.fullmatch('[0-9a-f]{40}', value['commit']) and value['git_status'] == ''
            and all(re.fullmatch('[1-9][0-9]{0,19}', value[k])
                    for k in ('github_run_id', 'github_run_attempt')), 'invalid minimal filesystem run context')


def current_context(expected):
    """Observe both original checkout and any importing source copy live."""
    from reference_internal_transport import command, bounded_source_hash
    context_shape(expected)
    ordinary()
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and expected['commit'] == os.environ.get('GITHUB_SHA')
            and expected['github_run_id'] == os.environ.get('GITHUB_RUN_ID')
            and expected['github_run_attempt'] == os.environ.get('GITHUB_RUN_ATTEMPT'),
            'actual Actions execution differs from filesystem context')
    for root in dict.fromkeys((workspace(), ROOT)):
        result = command(['git', '-C', str(root), 'status', '--porcelain=v2', '--branch', '--untracked-files=normal'])
        lines = result['stdout'].splitlines()
        commits = [line.removeprefix('# branch.oid ') for line in lines if line.startswith('# branch.oid ')]
        require(commits == [expected['commit']] and all(line.startswith('# ') for line in lines)
                and bounded_source_hash(root) == expected['source'], 'live clean checkout/source differs')


def stamp(info):
    return fs.identity(info), info.st_mtime_ns, info.st_ctime_ns


def read_file(path, limit):
    """Read actual stable owned single-link bytes; no fixture/injected backend."""
    path = normalized(path)
    before = fs.checked(path)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
            and before.st_gid == os.getgid() and before.st_size <= limit, 'bounded owned receipt/stream required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        require(stamp(os.fstat(stream.fileno())) == stamp(before), 'receipt descriptor substituted')
        raw = stream.read(limit + 1)
        require(len(raw) == before.st_size <= limit
                and stamp(os.fstat(stream.fileno())) == stamp(before) == stamp(fs.checked(path)),
                'receipt/stream changed during read')
    return raw, hashlib.sha256(raw).hexdigest()


def read_json(path, limit=fs.MAX_PROOF):
    raw, digest = read_file(path, limit)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate receipt JSON key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite receipt JSON')))
    fs.bounded(value)
    require(type(value) is dict, 'receipt must be an object')
    return value, digest


def envelope(directory):
    total, logical, count, stack = 0, 0, 0, [directory]
    while stack:
        path = stack.pop()
        info = fs.checked(path)
        require(info.st_uid == os.getuid() and info.st_gid == os.getgid(), 'audit allocation is not owned')
        count += 1
        require(count <= 128, 'filesystem audit entry bound exceeded')
        total += info.st_blocks * 512
        logical += info.st_size if stat.S_ISREG(info.st_mode) else 0
        require(max(total, logical) <= ENVELOPE_BYTES, 'complete filesystem audit exceeds 20MB envelope')
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    require(count + len(stack) < 128, 'filesystem audit pending-entry bound exceeded')
                    stack.append(path / entry.name)
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unexpected filesystem audit entry')
    return {'physical_bytes': total, 'logical_bytes': logical, 'entries': count}


def image_identity(image, image_bytes):
    value = fs.identity(fs.checked(image))
    require(stat.S_ISREG(value['mode']) and value['nlink'] == 1 and value['size'] == image_bytes
            and value['uid'] == os.getuid() and value['gid'] == os.getgid(), 'exact ordinary owned image required')
    return value


def stable_mount(value):
    """Directory child creation changes nlink/size without replacing the mount."""
    return {key: value[key] for key in ('device', 'inode', 'mode', 'uid', 'gid', 'device_major_minor')}


def formatter_command(image):
    return ['mkfs.ext4', '-F', '-q', '-m', '0', str(image)]


def actual_observation(argv):
    tail = ['timeout', '--signal=TERM', '--kill-after=1s', '9s']
    return ['sudo', '-n', *tail, *argv[2:]] if argv[:2] == ['sudo', '-n'] else [*tail, *argv]


def verify_receipt(path, stdout, stderr, requested, actual, *, expected_sha=None):
    value, digest = read_json(path)
    require(expected_sha is None or expected_sha == digest, 'referenced owned receipt SHA differs')
    quiet = value.get('descendant_quiescence', {})
    worker = value.get('worker_identity', {})
    require(value.get('status') == 'PASS' and value.get('worker_started') is True
            and value.get('worker_exit_code') == 0 and value.get('termination_reason') is None
            and value.get('errors') == [] and quiet.get('quiescent') is True and quiet.get('residual') == []
            and value.get('capture_complete') is True and value.get('discarded_output_bytes') == 0
            and value.get('requested_command') == requested and value.get('actual_command') == actual
            and all(type(worker.get(k)) is int and worker[k] > 0 for k in ('pid', 'ppid', 'start_time_ticks')),
            'actual complete quiescent owned command receipt required')
    total, streams = 0, {}
    for label, target in (('stdout', stdout), ('stderr', stderr)):
        raw, sha = read_file(target, fs.MAX_STREAM)
        capture = value.get('capture', {}).get(label, {})
        require(capture == {'path': str(target), 'bytes': len(raw), 'sha256': sha},
                'actual complete owned stream/capture differs')
        total += len(raw)
        streams[label] = raw.decode('utf-8', errors='strict')
    require(total == value.get('captured_output_bytes') <= fs.MAX_STREAM, 'combined owned capture differs')
    return value, digest, streams


def context_file(path):
    value, _ = read_json(path, fs.MAX_CONTEXT)
    context_shape(value)
    return value


def retain_failure(directory, name, record, failure):
    record.update(status='FAIL', ended_at=fs.utc(), error=(type(failure).__name__ + ': ' + str(failure))[:1000])
    if getattr(failure, 'partial_record', None) is not None:
        record['partial_record'] = failure.partial_record
    fs.write_exclusive(directory / name, record)


def validate_format(directory, image, image_bytes, context):
    require(not os.path.lexists(directory / 'formatter.failure.json'), 'failed formatter attempt is retained')
    record, digest = read_json(directory / 'formatter.json')
    argv = formatter_command(image)
    require(record.get('kind') == KIND and record.get('status') == 'PASS'
            and record.get('descendant_quiescence') == {'quiescent': True, 'residual': []}
            and record.get('run_context') == context and record.get('image_path') == str(image)
            and record.get('image_bytes') == image_bytes and record.get('directory') == str(directory)
            and record.get('image_before') == record.get('image_after') == image_identity(image, image_bytes),
            'actual formatter image/context binding differs')
    item = record['observation']
    receipt, receipt_sha, streams = verify_receipt(directory / 'formatter-audit' / '0.json',
        directory / 'formatter-audit' / '0.stdout', directory / 'formatter-audit' / '0.stderr',
        argv, actual_observation(argv), expected_sha=item['ownership']['receipt_sha256'])
    fs.owned_capture(item)
    require(item['command'] == argv and item['exit_code'] == 0
            and item['ownership']['receipt_path'] == str(directory / 'formatter-audit' / '0.json')
            and all(item[k] == streams[k] for k in streams)
            and item['ownership']['capture'] == receipt['capture'], 'formatter observation differs from actual receipt')
    stamps = [fs.dt.datetime.fromisoformat(value) for value in
              (record['started_at'], item['started_at'], item['ended_at'], record['ended_at'])]
    require(all(value.tzinfo is not None for value in stamps) and stamps == sorted(stamps)
            and 0 <= (stamps[2] - stamps[1]).total_seconds() < fs.OBSERVATION_SECONDS
            and (stamps[3] - stamps[0]).total_seconds() < 60, 'formatter whole-entry timeline differs')
    return record, digest, receipt_sha


def format_owned(image, image_bytes, context_json, directory):
    with fs.whole_entry(60):
        _, directory, image, _ = layout(directory, image, image_bytes, create=True)
        context = context_file(context_json)
        current_context(context)
        allocation = envelope(directory.parent)
        require(max(allocation['physical_bytes'], allocation['logical_bytes']) + 6_000_000 <= ENVELOPE_BYTES,
                'complete formatter/collector failure tail lacks control admission')
        record = {'kind': KIND, 'status': 'INCOMPLETE', 'run_context': context, 'image_path': str(image),
                  'directory': str(directory), 'image_bytes': image_bytes, 'started_at': fs.utc(),
                  'image_before': image_identity(image, image_bytes), 'descendant_quiescence': dict(UNKNOWN)}
        fs.write_exclusive(directory / 'formatter.pending.json', record)
        try:
            # Actual formatter execution belongs here, never in the pure collector.
            runner = fs.OwnedRunner(directory / 'formatter-audit')
            record['observation'] = fs.observe(formatter_command(image), runner)
            record['descendant_quiescence'] = record['observation']['ownership']['descendant_quiescence']
            record['image_after'] = image_identity(image, image_bytes)
            require(record['image_before'] == record['image_after'], 'formatter substituted image identity')
            current_context(context)
            record.update(status='PASS', ended_at=fs.utc())
            fs.write_exclusive(directory / 'formatter.json', record)
            validate_format(directory, image, image_bytes, context)
            envelope(directory.parent)
            return record
        except BaseException as failure:
            if isinstance(failure, fs.ObservationFailure):
                record['failed_observation'] = failure.observation
            retain_failure(directory, 'formatter.failure.json', record, failure)
            raise


def collector_command(root, image, mount, image_bytes, context_json, directory):
    return [sys.executable, str(root / 'scripts' / 'reference_filesystem.py'),
            '--image', str(image), '--mount', str(mount), '--image-bytes', str(image_bytes),
            '--context-json', str(context_json), '--proof', str(directory / 'proof.json'),
            '--audit-dir', str(directory / 'observations')]


def collect_owned(image, mount, image_bytes, context_json, directory):
    from reference_transport_supervisor import run_owned
    started = time.monotonic()
    with fs.whole_entry(ENTRY_SECONDS, started=started):
        root, directory, image, mount = layout(directory, image, image_bytes, mount)
        context = context_file(context_json)
        current_context(context)
        validate_format(directory, image, image_bytes, context)
        allocation = envelope(directory.parent)
        require(max(allocation['physical_bytes'], allocation['logical_bytes']) + 6_000_000 <= ENVELOPE_BYTES,
                'complete collector failure tail lacks control admission')
        requested = collector_command(root, image, mount, image_bytes, normalized(context_json), directory)
        actual = ['timeout', '--signal=TERM', '--kill-after=2s', '80s', *requested]
        record = {'kind': KIND, 'status': 'INCOMPLETE', 'scope': 'process-supervision-only',
                  'run_context': context, 'image_path': str(image), 'mount_point': str(mount),
                  'image_bytes': image_bytes, 'directory': str(directory), 'context_path': str(context_json),
                  'started_at': fs.utc(), 'requested_command': requested, 'actual_command': actual,
                  'total_seconds': PARENT_SECONDS, 'entry_seconds': ENTRY_SECONDS,
                  'cleanup_seconds': 6, 'receipt_seconds': 2, 'descendant_quiescence': dict(UNKNOWN)}
        fs.write_exclusive(directory / 'collector-supervisor.pending.json', record)
        try:
            outcome = run_owned(actual, directory / 'collector-supervisor.stdout',
                directory / 'collector-supervisor.stderr', started=started, total_seconds=PARENT_SECONDS,
                cleanup_seconds=6, receipt_seconds=2, capture_bytes=fs.MAX_STREAM,
                environ={**os.environ, 'LC_ALL': 'C'})
            record.update(outcome, ended_at=fs.utc())
            record['duration_seconds'] = time.monotonic() - started
            if record['duration_seconds'] >= PARENT_SECONDS:
                record.update(status='FAIL', binding_error='complete parent command/receipt budget exceeded')
            if outcome.get('status') == 'PASS':
                try:
                    _, record['proof_file_sha256'] = read_file(directory / 'proof.json', fs.MAX_PROOF)
                except Exception as error:
                    record.update(status='FAIL', binding_error=(type(error).__name__ + ': ' + str(error))[:1000])
            fs.write_exclusive(directory / 'collector-supervisor.json', record)
            require(record['status'] == 'PASS', 'actual filesystem collector supervision failed')
            return validate(directory, image, mount, image_bytes, context)
        except BaseException as failure:
            retain_failure(directory, 'collector.failure.json', record, failure)
            raise


def validate(directory, image, mount, image_bytes, context):
    """Authenticate live canonical files and their current mounted identity."""
    return _validate(directory, image, mount, image_bytes, context, live_mount=True)


def validate_retained(directory, image, mount, image_bytes, context):
    """Reauthenticate retained canonical bytes after unmount.

    Geometry/statvfs in the identical immutable summary are historical collector
    observations. This does not establish current geometry, loop absence, image
    contents or a freeze: callers still require their full-image hash, absence
    observations and independent supervisor receipts.
    """
    return _validate(directory, image, mount, image_bytes, context, live_mount=False)


def _validate(directory, image, mount, image_bytes, context, *, live_mount):
    root, directory, image, mount = layout(directory, image, image_bytes, mount)
    current_context(context)
    require(os.path.ismount(mount) is live_mount, 'filesystem binding mount state differs')
    require(not os.path.lexists(directory / 'collector.failure.json'), 'failed collector attempt is retained')
    # Both audits share this mutable allocation. Enforce it on every call, but
    # never bind legitimate nested-audit growth into the immutable proof summary.
    envelope(directory.parent)
    formatter, formatter_sha, formatter_receipt_sha = validate_format(directory, image, image_bytes, context)
    proof, proof_sha = read_json(directory / 'proof.json')
    fs.validate_policy(proof, image, mount, image_bytes, context)
    require(proof['image_before'] == formatter['image_after'] == image_identity(image, image_bytes),
            'collector image identity differs from actual formatter')
    if live_mount:
        require(stable_mount(fs.mount_identity(fs.checked(mount))) == stable_mount(proof['mount_after']),
                'live mount identity changed')
    parent, _ = read_json(directory / 'collector-supervisor.json')
    context_path = normalized(parent['context_path'])
    require(context_path == directory / 'context.json', 'collector context path is not canonical')
    require(context_file(context_path) == context, 'collector context file changed')
    _, context_sha = read_json(context_path, fs.MAX_CONTEXT)
    requested = collector_command(root, image, mount, image_bytes, context_path, directory)
    actual = ['timeout', '--signal=TERM', '--kill-after=2s', '80s', *requested]
    parent, parent_sha, _ = verify_receipt(directory / 'collector-supervisor.json',
        directory / 'collector-supervisor.stdout', directory / 'collector-supervisor.stderr', requested, actual)
    require(parent.get('kind') == KIND and parent.get('scope') == 'process-supervision-only'
            and parent.get('run_context') == context and parent.get('image_path') == str(image)
            and parent.get('mount_point') == str(mount) and parent.get('image_bytes') == image_bytes
            and parent.get('directory') == str(directory) and parent.get('total_seconds') == PARENT_SECONDS
            and parent.get('entry_seconds') == ENTRY_SECONDS and parent.get('cleanup_seconds') == 6
            and parent.get('receipt_seconds') == 2 and parent.get('proof_file_sha256') == proof_sha,
            'whole-collector parent context/proof/deadline binding differs')
    require(type(parent.get('duration_seconds')) in (int, float)
            and 0 <= parent['duration_seconds'] < PARENT_SECONDS, 'invalid whole-parent duration')
    stamps = [fs.dt.datetime.fromisoformat(value) for value in
              (formatter['ended_at'], parent['started_at'], proof['started_at'], proof['ended_at'], parent['ended_at'])]
    require(all(value.tzinfo is not None for value in stamps) and stamps == sorted(stamps),
            'formatter/collector execution timelines differ')
    receipts = {}
    files = {'context.json': context_sha, 'proof.json': proof_sha, 'formatter.json': formatter_sha,
             'formatter-audit/0.json': formatter_receipt_sha, 'collector-supervisor.json': parent_sha}
    for prefix, captures in (('formatter-audit/0', formatter['observation']['ownership']['capture']),
                             ('collector-supervisor', parent['capture'])):
        for label in ('stdout', 'stderr'):
            files[prefix + '.' + label] = captures[label]['sha256']
    for index, name in enumerate(('version', 'superblock', 'mount', 'loop')):
        item = proof['observations'][name]
        prefix = directory / 'observations' / str(index)
        receipt, sha, streams = verify_receipt(prefix.with_suffix('.json'), prefix.with_suffix('.stdout'),
            prefix.with_suffix('.stderr'), item['command'], actual_observation(item['command']),
            expected_sha=item['ownership']['receipt_sha256'])
        require(item['ownership']['receipt_path'] == str(prefix.with_suffix('.json'))
                and item['ownership']['capture'] == receipt['capture']
                and all(item[k] == streams[k] for k in streams), 'policy observation differs from actual owned files')
        receipts[name] = sha
        files['observations/' + str(index) + '.json'] = sha
        for label in ('stdout', 'stderr'):
            files['observations/' + str(index) + '.' + label] = receipt['capture'][label]['sha256']
    for relative, expected_sha in files.items():
        require(read_file(directory / relative, fs.MAX_PROOF)[1] == expected_sha,
                'referenced binding file changed during validation')
    require(image_identity(image, image_bytes) == proof['image_before']
            and os.path.ismount(mount) is live_mount, 'image identity or mount state changed during validation')
    current_context(context)
    envelope(directory.parent)
    result = {'kind': KIND, 'policy': fs.POLICY, 'status': 'PASS', 'run_context': context,
              'directory': str(directory), 'image_path': str(image), 'mount_point': str(mount),
              'image_bytes': image_bytes, 'proof_sha256': proof['proof_sha256'], 'proof_file_sha256': proof_sha,
              'formatter_file_sha256': formatter_sha, 'formatter_receipt_sha256': formatter_receipt_sha,
              'collector_supervisor_sha256': parent_sha, 'observation_receipts_sha256': receipts,
              'files_sha256': files,
              'geometry': proof['geometry'], 'statvfs': proof['statvfs']}
    fs.bounded(result)
    return result


def main():
    with fs.whole_entry(ENTRY_SECONDS, started=ENTRY_STARTED):
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('action', choices=('format', 'collect'))
        for name in ('image', 'context-json', 'directory'):
            parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--mount', type=Path)
        parser.add_argument('--image-bytes', type=int, required=True, choices=(2_300_000_000, 1_100_000_000))
        args = parser.parse_args()
        if args.action == 'format':
            require(args.mount is None, 'formatter does not mount filesystems')
            format_owned(args.image, args.image_bytes, args.context_json, args.directory)
        else:
            require(args.mount is not None, 'collector mount is required')
            collect_owned(args.image, args.mount, args.image_bytes, args.context_json, args.directory)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
