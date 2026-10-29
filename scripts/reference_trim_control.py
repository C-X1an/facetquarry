"""Forced trim and exact-image retention control; never scientific qualification.

Padding remains inside the existing admitted outer image. Preparation is a fresh
dedicated Linux parent; only its fallocate child uses the owned process runner.
Finite local controls test arithmetic/bytes/refusals, not a mounted filesystem.
"""
from __future__ import annotations
import time
ENTRY_STARTED = time.monotonic()

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

from common import ROOT
import reference_filesystem as filesystem
import reference_filesystem_bindings as bindings
import reference_internal_transport as transport
import reference_results as results
import reference_transport_supervisor as supervisor

KIND = 'reference-forced-trim-control-v1'
CONTROL_BYTES = 1_000_000
CONTROL_ENTRIES = 32
CAPTURE_BYTES = 64_000
TARGET_FREE = 600_000_000
DIAGNOSTIC_MARGIN = 70_000_000
MIN_FREE = transport.FILESYSTEM_FLOOR + transport.CONTROL_ALLOCATION + DIAGNOSTIC_MARGIN
ENTRY_SECONDS = 150
PARENT_SECONDS = 110
STAGE_BYTES = 32_000
VERIFY_STAGES = ('preparation', 'actual_branch_pressure', 'actual_guest_trim',
                 'failed_pack_parent_quiescence', 'intentional_failed_child',
                 'exact_image_readonly_retention', 'final_context_and_envelope')
SCOPE = ('Nonqualifying smoke forced-trim and complete exact-image retention control only. '
         'An intentional failed package and this control do not qualify scientific results, '
         'a benchmark, a new quota, or release acceptance.')
require = transport.require


def explicit_control(environ):
    require(environ.get('FQ_TRIM_CONTROL') == environ.get('FQ_PRESERVATION_CONTROL') == 'true'
            and environ.get('FQ_BENCH_PROFILE') == 'smoke'
            and environ.get('FQ_BENCH_CONCURRENCY') == '1'
            and environ.get('FQ_RESERVATION_PROFILE') == transport.PROFILE,
            'trim control requires explicit preservation, smoke, one reader and inside-outer profile')


def padding_plan(available, block_size):
    """Exact whole-block arithmetic; not evidence of actual free space."""
    require(type(available) is int and type(block_size) is int and block_size in (1024, 2048, 4096)
            and available > TARGET_FREE + block_size, 'insufficient controlled-padding headroom')
    amount = (available - TARGET_FREE) // block_size * block_size
    remaining = available - amount
    pressure = transport.physical_admission(remaining)
    require(0 < amount < transport.IMAGE_BYTES and MIN_FREE <= remaining < TARGET_FREE + block_size
            and pressure['allowed'] is False, 'padding cannot establish bounded branch pressure')
    return {'available_before_bytes': available, 'block_size': block_size, 'padding_bytes': amount,
            'predicted_available_after_bytes': remaining, 'target_available_bytes': TARGET_FREE,
            'minimum_available_bytes': MIN_FREE,
            'unchanged_package_threshold_bytes': pressure['required_available_bytes']}


def owned_padding(path, volume):
    info = transport.preflight.checked(path, volume)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o600,
            'padding must remain an ordinary owned single-link inode')
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'uid': info.st_uid, 'gid': info.st_gid, 'nlink': info.st_nlink,
            'bytes': info.st_size, 'physical_bytes': info.st_blocks * 512}


def allocation_check(before, after, plan, observed_available):
    identity = ('device', 'inode', 'mode', 'uid', 'gid', 'nlink')
    require(all(before[key] == after[key] for key in identity)
            and before['bytes'] == before['physical_bytes'] == 0
            and after['bytes'] == after['physical_bytes'] == plan['padding_bytes'],
            'padding inode or exact physical block allocation differs')
    require(type(observed_available) is int and MIN_FREE <= observed_available
            < transport.physical_admission(0)['required_available_bytes']
            and abs(observed_available - plan['predicted_available_after_bytes']) <= 1_000_000,
            'actual free space lacks controlled pressure or unchanged floor/diagnostic margin')
    return {'exact_allocated_bytes': after['physical_bytes'],
            'actual_available_after_bytes': observed_available,
            'prediction_difference_bytes': observed_available - plan['predicted_available_after_bytes']}


def envelope(directory):
    physical = logical = entries = 0
    for path, info in transport.bounded_tree([directory], CONTROL_ENTRIES):
        entries += 1
        require(info.st_uid == os.getuid() and info.st_gid == os.getgid(), 'control audit is not owned')
        physical += info.st_blocks * 512
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1, 'control audit file is hardlinked')
            logical += info.st_size
        else:
            require(stat.S_ISDIR(info.st_mode), 'unexpected control audit inode')
        require(max(logical, physical) <= CONTROL_BYTES, 'complete trim control exceeds 1MB envelope')
    return {'physical_bytes': physical, 'logical_bytes': logical, 'entries': entries}


def setup(volume, project, root):
    explicit_control(os.environ)
    bindings.ordinary()
    p = transport.paths(volume, project, root)
    ctx = transport.context(p['project'])
    require(transport.context(p['outer']) == ctx, 'trim control source/outer execution differs')
    plan = transport.growth_plan(int(os.environ['FQ_ACCOUNTED_BASE_BYTES']))
    require(plan['admission'] == 'ALLOW', 'trim control lacks current complete growth admission')
    audit = p['local'] / 'reference-trim-control'
    return p, ctx, plan, audit


def bounded_record(path, value):
    filesystem.bounded(value, budget=160_000)
    bindings.fs.write_exclusive(path, value)


def verification_admission(allocation, block_size):
    """Reserve fixed-size stage deltas, pending/final records and directory growth."""
    require(type(block_size) is int and block_size in (1024, 2048, 4096),
            'unsupported control audit allocation block size')
    limits = [160_000, 160_000] + [STAGE_BYTES] * (2 * len(VERIFY_STAGES))
    reserved = sum((limit + block_size - 1) // block_size * block_size + block_size for limit in limits)
    require(max(allocation['physical_bytes'], allocation['logical_bytes']) + reserved <= CONTROL_BYTES
            and allocation['entries'] + len(limits) <= CONTROL_ENTRIES,
            'complete append-only verification checkpoints lack control-envelope admission')
    return {'reserved_bytes': reserved, 'reserved_entries': len(limits)}


def stage_checkpoint(audit, record, name, *, pending):
    """One bounded stage delta; completed facts never require rewriting an old file."""
    require(name in VERIFY_STAGES and type(pending) is bool, 'unknown verification checkpoint')
    retention = record['stages']['exact_image_readonly_retention']['status']
    value = {'kind': KIND, 'source': record['source'], 'run_context': record['run_context'],
             'stage': name, 'status': 'PENDING' if pending else record['stages'][name]['status'],
             'retention_status': retention, 'recorded_at': results.utc(), 'scope': SCOPE}
    if not pending:
        value['outcome'] = record['stages'][name]
        if name == 'actual_branch_pressure':
            value['inode_refusals'] = record['inode_refusals']
    filesystem.bounded(value, budget=STAGE_BYTES)
    require(len(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                           allow_nan=False).encode()) + 1 <= STAGE_BYTES,
            'stage checkpoint exceeds complete serialization bound')
    suffix = '.pending.json' if pending else '.json'
    path = audit / ('verify-stage-' + str(VERIFY_STAGES.index(name)) + suffix)
    bounded_record(path, value)
    return value


def prepare(volume, project, root=ROOT, *, started=None):
    started = time.monotonic() if started is None else started
    with filesystem.whole_entry(ENTRY_SECONDS, started=started):
        p, ctx, growth, audit = setup(volume, project, root)
        transport.closed_guest(p, ctx)
        reservation = transport.observe_outer(p['volume'], p['project'])
        admitted = transport.external_admission(p)
        require(admitted['allowed'], 'trim control has no complete external metadata admission')
        require(not os.path.lexists(audit), 'previous trim control state is retained; blind retry forbidden')
        audit.mkdir(mode=0o700)
        prepared = audit / 'prepare'
        prepared.mkdir(mode=0o700)
        padding = p['volume'] / 'reference-trim-control-padding.bin'
        record = {'kind': KIND, 'status': 'PREPARING', 'source': ctx['source'], 'run_context': ctx,
                  'volume': str(p['volume']), 'project': str(p['project']), 'padding_path': str(padding),
                  'started_at': results.utc(), 'growth_plan': growth, 'reservation': reservation,
                  'external_admission': admitted, 'padding_retained': True, 'scope': SCOPE}
        bounded_record(prepared / 'pending.json', record)
        descriptor = None
        try:
            require(not os.path.lexists(padding), 'padding path already exists and must be retained')
            descriptor = os.open(padding, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            before = owned_padding(padding, p['volume'])
            require(os.fstat(descriptor).st_ino == before['inode'], 'new padding descriptor differs')
            counters = os.statvfs(p['volume'])
            plan = padding_plan(counters.f_bavail * counters.f_frsize, counters.f_frsize)
            record.update(padding_before=before, padding_plan=plan)
            requested = ['fallocate', '-l', str(plan['padding_bytes']), '--', str(padding)]
            actual = ['timeout', '--signal=TERM', '--kill-after=2s', '45s', *requested]
            bounded_record(prepared / 'allocation.pending.json', {
                'status': 'INCOMPLETE', 'run_context': ctx, 'requested_command': requested,
                'actual_command': actual, 'descendant_quiescence': {'quiescent': False, 'residual': None}})
            outcome = supervisor.run_owned(actual, prepared / 'allocation.stdout', prepared / 'allocation.stderr',
                started=started, total_seconds=PARENT_SECONDS, cleanup_seconds=6, receipt_seconds=2,
                capture_bytes=CAPTURE_BYTES, environ={**os.environ, 'LC_ALL': 'C'})
            outcome.update(requested_command=requested, actual_command=actual, run_context=ctx)
            bounded_record(prepared / 'allocation.json', outcome)
            bindings.verify_receipt(prepared / 'allocation.json', prepared / 'allocation.stdout',
                                   prepared / 'allocation.stderr', requested, actual)
            os.fsync(descriptor)
            after = owned_padding(padding, p['volume'])
            require(os.fstat(descriptor).st_ino == after['inode'], 'allocated padding descriptor differs')
            counters = os.statvfs(p['volume'])
            record.update(padding_after=after, actual_allocation=allocation_check(
                before, after, plan, counters.f_bavail * counters.f_frsize))
            transport.closed_guest(p, ctx)
            require(transport.observe_outer(p['volume'], p['project']) == reservation
                    and transport.context(p['project']) == transport.context(p['outer']) == ctx,
                    'outer/source binding changed during controlled allocation')
            record.update(status='PASS', ended_at=results.utc())
            bounded_record(prepared / 'prepare.json', record)
            envelope(audit)
            manifest = results.inventory(prepared)
            require(manifest['logical_bytes'] < CONTROL_BYTES and len(manifest['entries']) <= CONTROL_ENTRIES,
                    'complete preparation copy exceeds admission')
            destination = p['project'] / '.local/reference-trim-control'
            require(not os.path.lexists(destination), 'scientific trim control copy already exists')
            require(os.statvfs(destination.parent).f_bavail * os.statvfs(destination.parent).f_frsize
                    >= CONTROL_BYTES + transport.CONTROL_ALLOCATION,
                    'complete preparation copy lacks nested-image headroom')
            destination.mkdir(mode=0o700)
            results.copy_bootstrap(prepared, destination, manifest)
            envelope(audit)
            return record
        except BaseException as error:
            record.update(status='FAIL', ended_at=results.utc(),
                          error=(type(error).__name__ + ': ' + str(error))[:4000])
            bounded_record(prepared / 'failure.json', record)
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)


def inode_refusals(errors):
    """Keep exact producer facts; never infer an owner or cleanup cause."""
    marker = 'trim or provenance member is not an owned single-link inode: '
    found = []
    for error in errors:
        if type(error) is str and marker in error:
            raw = error.split(marker, 1)[1]
            require(len(raw.encode()) < 4096, 'inode refusal exceeds producer bound')
            value = json.loads(raw, object_pairs_hook=transport.bundle.unique_object)
            require(type(value) is dict and set(value) == {'path', 'path_truncated', 'expected_uid',
                'observed_uid', 'observed_gid', 'observed_nlink', 'mode', 'device', 'inode'}
                and type(value['path']) is str and len(value['path']) <= 512
                and type(value['path_truncated']) is bool
                and all(type(value[key]) is int for key in value if key not in ('path', 'path_truncated')),
                'malformed producer inode refusal facts')
            found.append(value)
    require(len(found) <= 8, 'too many inode refusal diagnostics')
    return found


def pressure_check(pack, ctx):
    require(pack.get('run_context') == ctx and pack.get('profile') == transport.PROFILE
            and pack.get('source') == ctx['source'] and pack.get('control') is True
            and pack.get('status') == 'FAIL', 'current intentional failed pack control is required')
    before = pack.get('physical_before', {})
    free = before.get('actual_available_bytes')
    require(type(free) is int and before == transport.physical_admission(free)
            and before['allowed'] is False and MIN_FREE <= free
            < transport.artifacts.PACKAGE_ALLOCATION + transport.FILESYSTEM_FLOOR + transport.CONTROL_ALLOCATION,
            'actual pack did not observe controlled branch pressure with unchanged floor')
    return before


def failed_child_check(attempt, ctx):
    require(attempt.get('status') == 'FAIL' and attempt.get('phase') == 'COMPLETE'
            and attempt.get('source') == ctx['source'] and attempt.get('commit') == ctx['commit']
            and attempt.get('run_id') == ctx['github_run_id'] and attempt.get('run_attempt') == ctx['github_run_attempt']
            and attempt.get('control') is True and attempt.get('termination_reason') == 'timeout'
            and attempt.get('child_stopped') is True and attempt.get('originals_unchanged') is True
            and attempt.get('stream_capture_complete') is True and attempt.get('discarded_stream_bytes') == 0
            and type(attempt.get('captured_stream_bytes')) is int
            and 0 <= attempt['captured_stream_bytes'] <= transport.artifacts.CAPTURE_BYTES
            and attempt.get('errors') == [] and attempt.get('residual_package_safe') is True,
            'complete positively stopped intentional timeout child is required')
    return {'status': 'PASS', 'termination_reason': attempt['termination_reason'], 'child_stopped': True}


def failed_child_capture(audit, attempt):
    """Rehash both complete actual streams and bind their combined byte count."""
    require(type(attempt.get('captured_stream_bytes')) is int
            and 0 <= attempt['captured_stream_bytes'] <= transport.artifacts.CAPTURE_BYTES,
            'failed child combined capture counter is missing or outside its bound')
    captured = 0
    for label in ('stdout', 'stderr'):
        stream = audit / ('pack-' + label + '.txt')
        info = transport.preflight.checked(stream)
        require(transport.file_sha(stream, transport.artifacts.CAPTURE_BYTES, transport.preflight.stamp(info))
                == attempt.get(label + '_sha256'), 'failed child capture changed')
        captured += info.st_size
    require(captured == attempt['captured_stream_bytes'] <= transport.artifacts.CAPTURE_BYTES,
            'failed child complete capture lengths differ')
    return {'captured_stream_bytes': captured}


def copied_manifest_check(prepared, before):
    manifest = results.inventory(prepared)
    prefix = '.local/reference-trim-control/'
    actual = {item['path']: item for item in before['manifest'] if item['path'].startswith(prefix)}
    expected = {}
    for item in manifest['entries']:
        name = prefix if item['path'] == '.' else prefix + item['path'] + ('/' if item['directory'] else '')
        expected[name] = {'path': name, 'directory': item['directory'],
                          'bytes': 0 if item['directory'] else item['bytes'],
                          'mode': stat.S_IMODE(item['identity'][2]),
                          'sha256': None if item['directory'] else item['sha256']}
    require(actual == expected, 'original image manifest lacks the complete sealed trim preparation copy')
    return {'copied_members': len(expected), 'copied_logical_bytes': manifest['logical_bytes']}


def verify(volume, project, root=ROOT, *, started=None):
    started = time.monotonic() if started is None else started
    with filesystem.whole_entry(ENTRY_SECONDS, started=started):
        p, ctx, _, audit = setup(volume, project, root)
        transport.preflight.checked(audit)
        require(not os.path.lexists(audit / 'verify.json') and not os.path.lexists(audit / 'verify.pending.json'),
                'previous trim verification is retained; blind retry forbidden')
        admitted = verification_admission(envelope(audit), os.statvfs(audit).f_frsize)
        record = {'kind': KIND, 'status': 'PREPARING', 'source': ctx['source'], 'run_context': ctx,
                  'started_at': results.utc(), 'stages': {name: {'status': 'PENDING'} for name in VERIFY_STAGES},
                  'errors': [], 'inode_refusals': [], 'checkpoint_admission': admitted, 'scope': SCOPE}
        bounded_record(audit / 'verify.pending.json', record)

        def stage(name, action):
            stage_checkpoint(audit, record, name, pending=True)
            try:
                record['stages'][name] = {'status': 'PASS', 'observation': action()}
            except BaseException as error:
                detail = (type(error).__name__ + ': ' + str(error))[:4000]
                record['stages'][name] = {'status': 'FAIL', 'error': detail}
                record['errors'].append(name + ': ' + detail)
            stage_checkpoint(audit, record, name, pending=False)

        prepared = audit / 'prepare'
        pack = {}
        def preparation():
            envelope(audit)
            require(not os.path.lexists(prepared / 'failure.json'), 'preparation retained a failure')
            value = transport.read_json(prepared / 'prepare.json', 160_000)
            require(value.get('kind') == KIND and value.get('status') == 'PASS' and value.get('run_context') == ctx
                    and value.get('padding_path') == str(p['volume'] / 'reference-trim-control-padding.bin'),
                    'complete current preparation is required')
            require(owned_padding(Path(value['padding_path']), p['volume']) == value.get('padding_after'),
                    'retained padding inode or allocated blocks changed')
            plan = value['padding_plan']
            require(plan == padding_plan(plan['available_before_bytes'], plan['block_size']), 'padding plan differs')
            requested = ['fallocate', '-l', str(plan['padding_bytes']), '--', value['padding_path']]
            actual = ['timeout', '--signal=TERM', '--kill-after=2s', '45s', *requested]
            bindings.verify_receipt(prepared / 'allocation.json', prepared / 'allocation.stdout',
                                   prepared / 'allocation.stderr', requested, actual)
            allocation_check(value['padding_before'], value['padding_after'], plan,
                             value['actual_allocation']['actual_available_after_bytes'])
            return {'preparation_sha256': transport.file_sha(prepared / 'prepare.json', 160_000)}
        stage('preparation', preparation)

        def pressure():
            pack.update(transport.read_json(p['audit'] / 'pack-result.json'))
            record['inode_refusals'] = inode_refusals(pack.get('errors', []))
            return pressure_check(pack, ctx)
        stage('actual_branch_pressure', pressure)

        def trimmed():
            summary = pack.get('guest_trim', {})
            require(summary.get('status') == 'PASS', 'actual guest trim PASS is missing; inspect retained inode facts/errors')
            path = p['audit'] / 'guest-trim.json'
            value = transport.read_json(path, transport.TRIM_PROOF_BYTES)
            require(value.get('status') == 'PASS' and value.get('run_context') == ctx
                    and value.get('source') == ctx['source'] and value.get('source_unchanged') is True
                    and transport.file_sha(path, transport.TRIM_PROOF_BYTES) == summary.get('complete_proof_sha256'),
                    'complete actual terminal trim proof differs')
            return {'removed_entries': value['removed_entries'], 'proof_sha256': summary['complete_proof_sha256']}
        stage('actual_guest_trim', trimmed)

        def quiet_parent():
            value = supervisor.validate_receipt(p, ctx, 'pack', require_pass=False)
            require(value.get('status') == 'FAIL' and value.get('worker_started') is True
                    and value.get('capture_complete') is True and value.get('discarded_output_bytes') == 0
                    and value.get('startup_gate_released_after_durable_publication') is True,
                    'positive complete failed-pack parent supervision is required')
            return {'status': 'FAIL', 'quiescent': True, 'supervisor_receipt_sha256': value['supervisor_receipt_sha256']}
        stage('failed_pack_parent_quiescence', quiet_parent)

        def failed_child():
            path = p['audit'] / 'pack-attempt.json'
            attempt = transport.read_json(path)
            observed = failed_child_check(attempt, ctx)
            require(transport.file_sha(path, 1_000_000) == pack.get('pack_attempt', {}).get('attempt_sha256'),
                    'child attempt differs from controller')
            return {**observed, **failed_child_capture(p['audit'], attempt)}
        stage('intentional_failed_child', failed_child)

        def retention():
            # Reuse the complete selection gates inside this entry's timer;
            # verified_frozen_candidate owns a separate non-nestable timer.
            phases = transport.prior_phase_quiescence(p, ctx)
            parent = supervisor.validate_receipt(p, ctx, 'reconcile')
            frozen = transport.validate_frozen_proof(
                p, ctx, p['volume'] / 'reference-results-reconciled-freeze.json')
            require(transport.prior_phase_quiescence(p, ctx) == phases,
                    'transport quiescence changed during trim recovery validation')
            before_path = p['volume'] / 'reference-results-control-before.json'
            recovery_path = p['volume'] / 'reference-results-control-recovery.json'
            before = transport.read_json(before_path, results.MAX_METADATA)
            recovery = transport.read_json(recovery_path, results.MAX_METADATA)
            require(before.get('status') == recovery.get('status') == 'PASS'
                    and before.get('source') == recovery.get('source') == ctx['source']
                    and before.get('run_context') == recovery.get('run_context') == transport.legacy_context(ctx)
                    and recovery.get('all_original_bytes_modes_and_membership_equal') is True
                    and recovery.get('image_unmounted') is True
                    and recovery.get('image_sha256') == frozen['image_sha256']
                    and recovery.get('complete_before_proof_sha256') == transport.file_sha(before_path, results.MAX_METADATA),
                    'actual complete read-only same-image recovery PASS is required')
            mount = recovery.get('readonly_mount', {})
            options = set(mount.get('options', '').split(','))
            require(mount.get('target') == str(p['project'] / '.local') and 'ro' in options and 'rw' not in options
                    and bool({'noload', 'norecovery'} & options), 'actual read-only no-replay mount proof is missing')
            digest = hashlib.sha256(json.dumps(before['manifest'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            require(digest == before.get('manifest_sha256') == recovery.get('manifest_sha256'),
                    'complete original/recovered manifests differ')
            copied = copied_manifest_check(prepared, before)
            return {'status': 'PASS', 'image_sha256': frozen['image_sha256'], **copied,
                    'freeze_supervisor_receipt_sha256': parent['supervisor_receipt_sha256'],
                    'recovery_sha256': transport.file_sha(recovery_path, results.MAX_METADATA)}
        # Always evaluate retention even when trim refused an actual inode.
        stage('exact_image_readonly_retention', retention)
        stage('final_context_and_envelope', lambda: final_check(p, ctx, audit))
        record.update(status='PASS' if not record['errors'] else 'FAIL', ended_at=results.utc())
        bounded_record(audit / 'verify.json', record)
        envelope(audit)
        return record


def final_check(p, ctx, audit):
    require(transport.context(p['project']) == transport.context(p['outer']) == ctx,
            'source/execution changed during trim verification')
    require(supervisor.capacity.children(os.getpid()) == [],
            'trim verification still owns child processes')
    return {**envelope(audit), 'descendant_quiescence': {'quiescent': True, 'residual': []}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'verify'))
    parser.add_argument('--volume', type=Path, required=True)
    parser.add_argument('--project', type=Path, required=True)
    args = parser.parse_args()
    try:
        record = (prepare if args.action == 'prepare' else verify)(args.volume, args.project, started=ENTRY_STARTED)
    except BaseException as error:
        record = {'status': 'FAIL', 'error': (type(error).__name__ + ': ' + str(error))[:4000], 'scope': SCOPE}
    print(json.dumps(record, sort_keys=True))
    return 0 if record.get('status') == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
