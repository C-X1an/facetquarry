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
    return inode_facts(info)


def inode_facts(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'uid': info.st_uid, 'gid': info.st_gid, 'nlink': info.st_nlink,
            'bytes': info.st_size, 'physical_bytes': info.st_blocks * 512}


def statvfs_facts(counters):
    return {name: getattr(counters, name) for name in (
        'f_bsize', 'f_frsize', 'f_blocks', 'f_bfree', 'f_bavail',
        'f_files', 'f_ffree', 'f_favail', 'f_flag', 'f_namemax')}


def allocation_check(before, after, plan, observed_available):
    identity = ('device', 'inode', 'mode', 'uid', 'gid', 'nlink')
    for key in identity:
        require(before[key] == after[key], 'padding invariant failed: after.' + key)
    for key in ('bytes', 'physical_bytes'):
        require(before[key] == 0, 'padding invariant failed: before.' + key + ' is not zero')
        require(after[key] == plan['padding_bytes'], 'padding invariant failed: after.' + key)
    require(type(observed_available) is int and MIN_FREE <= observed_available
            < transport.physical_admission(0)['required_available_bytes']
            and abs(observed_available - plan['predicted_available_after_bytes']) <= 1_000_000,
            'actual free space lacks controlled pressure or unchanged floor/diagnostic margin')
    return {'exact_allocated_bytes': after['physical_bytes'],
            'actual_available_after_bytes': observed_available,
            'prediction_difference_bytes': observed_available - plan['predicted_available_after_bytes']}


def check_observed_allocation(prepared, observation):
    """Persist raw facts first; a failed predicate cannot discard the observation."""
    bounded_record(prepared / 'allocation.observed.json', observation)
    return validate_allocation_observation(observation)


def validate_allocation_observation(observation):
    """Shared non-writing validation for freshly observed and retained facts."""
    for phase in ('before', 'after'):
        require(observation['descriptor_' + phase] == observation['padding_' + phase],
                'padding invariant failed: descriptor_' + phase + ' differs from pathname')
    before_counters, counters = observation['statvfs_before'], observation['statvfs_after']
    require(type(before_counters) is dict and type(counters) is dict,
            'padding allocation counters must be objects')
    compact = {'f_bavail', 'f_frsize'}
    if set(before_counters) - compact or set(counters) - compact:
        return complete_observed_allocation(observation)
    require(set(before_counters) == set(counters) == compact,
            'padding allocation counters are incomplete')
    # Compact facts retain the original exact-allocation contract. Only the
    # complete production observation below can establish any physical excess.
    return allocation_check(observation['padding_before'], observation['padding_after'],
                            observation['padding_plan'], counters['f_bavail'] * counters['f_frsize'])


def retained_allocation_check(record, observation, command):
    """Replay identical original proof without replacing its durable checkpoint."""
    require(type(observation) is dict and observation.get('kind') == KIND
            and observation.get('status') == 'OBSERVED_UNVALIDATED'
            and observation.get('source') == record.get('source')
            and observation.get('run_context') == record.get('run_context')
            and observation == record.get('allocation_observation')
            and all(record.get(key) == observation.get(key)
                    for key in ('padding_before', 'padding_after', 'padding_plan')),
            'retained allocation observation differs from preparation')
    require(command == observation.get('command_outcome'),
            'retained allocation command differs from original observed outcome')
    result = validate_allocation_observation(observation)
    require(record.get('actual_allocation') == result, 'retained allocation result differs from complete proof')
    return result


def complete_observed_allocation(observation):
    """Charge actual blocks with complete counter agreement, never substitute size.

    One extra allocation block is a deliberately narrow policy supported by the
    recorded run30 observation. Its internal purpose and any universal bound
    are unknown. A different allocation outside this policy remains a refusal.
    """
    before, after = observation['padding_before'], observation['padding_after']
    plan = observation['padding_plan']
    old, new = observation['statvfs_before'], observation['statvfs_after']
    fields = {'f_bsize', 'f_frsize', 'f_blocks', 'f_bfree', 'f_bavail',
              'f_files', 'f_ffree', 'f_favail', 'f_flag', 'f_namemax'}
    require(set(old) == set(new) == fields
            and all(type(row[key]) is int and row[key] >= 0 for row in (old, new) for key in fields),
            'complete allocation proof requires every exact nonnegative integer statvfs counter')
    block = old['f_frsize']
    require(block in (1024, 2048, 4096) and old['f_bsize'] == block
            and all(old[key] == new[key] for key in fields - {'f_bfree', 'f_bavail'}),
            'complete allocation geometry or inode counters changed')
    require(all(0 <= row['f_bavail'] <= row['f_bfree'] <= row['f_blocks']
                and 0 <= row['f_favail'] <= row['f_ffree'] <= row['f_files']
                and row['f_blocks'] > 0 and row['f_files'] > 0 and row['f_namemax'] > 0
                for row in (old, new)), 'complete allocation counter ordering differs')
    require(plan == padding_plan(old['f_bavail'] * block, block),
            'complete allocation plan differs from actual before counters')
    inode_fields = {'device', 'inode', 'mode', 'uid', 'gid', 'nlink', 'bytes', 'physical_bytes'}
    inode_rows = (before, after, observation['descriptor_before'], observation['descriptor_after'])
    require(all(type(row) is dict and set(row) == inode_fields for row in inode_rows)
            and all(type(row[key]) is int and row[key] >= 0 for row in inode_rows for key in inode_fields),
            'complete allocation inode facts are malformed')
    require(all(before[key] == after[key] for key in inode_fields - {'bytes', 'physical_bytes'})
            and before['device'] > 0 and before['inode'] > 0 and before['uid'] > 0 and before['gid'] > 0
            and stat.S_ISREG(before['mode']) and stat.S_IMODE(before['mode']) == 0o600
            and before['nlink'] == 1 and before['bytes'] == before['physical_bytes'] == 0
            and after['bytes'] == plan['padding_bytes'], 'complete allocation owned identity or logical size differs')
    physical = after['physical_bytes']
    overhead = physical - after['bytes']
    require(after['bytes'] % block == physical % block == 0 and 0 <= overhead <= block,
            'complete allocation physical excess exceeds the single-block policy')
    require((old['f_bavail'] - new['f_bavail']) * block == physical
            and (old['f_bfree'] - new['f_bfree']) * block == physical
            and old['f_bfree'] - old['f_bavail'] == new['f_bfree'] - new['f_bavail'],
            'complete allocation actual physical charge and both free-counter decreases differ')
    command = observation['command_outcome']
    require(type(command) is dict and command.get('status') == 'PASS'
            and type(command.get('worker_exit_code')) is int and command['worker_exit_code'] == 0
            and command.get('worker_started') is True and 'termination_reason' in command
            and command['termination_reason'] is None
            and command.get('errors') == [] and command.get('capture_complete') is True
            and type(command.get('discarded_output_bytes')) is int and command['discarded_output_bytes'] == 0
            and type(command.get('captured_output_bytes')) is int
            and 0 <= command['captured_output_bytes'] <= CAPTURE_BYTES,
            'complete allocation command outcome is not successful and complete')
    quiet = command.get('descendant_quiescence')
    capture = command.get('capture')
    require(type(quiet) is dict and quiet.get('quiescent') is True and quiet.get('residual') == []
            and type(capture) is dict and set(capture) == {'stdout', 'stderr'}
            and all(type(capture[label]) is dict and type(capture[label].get('bytes')) is int
                    and 0 <= capture[label]['bytes'] <= CAPTURE_BYTES for label in capture)
            and sum(capture[label]['bytes'] for label in capture) == command['captured_output_bytes'],
            'complete allocation command lacks quiescence or complete stream counts')
    require(command.get('run_context') == observation['run_context']
            and observation['source'] == observation['run_context'].get('source'),
            'complete allocation command/source context differs')
    available = new['f_bavail'] * block
    require(MIN_FREE <= available < transport.physical_admission(0)['required_available_bytes']
            and abs(available - plan['predicted_available_after_bytes']) <= 1_000_000,
            'actual free space lacks controlled pressure or unchanged floor/diagnostic margin')
    return {'exact_allocated_bytes': physical, 'physical_allocation_overhead_bytes': overhead,
            'physical_overhead_ceiling_bytes': block, 'actual_available_after_bytes': available,
            'prediction_difference_bytes': available - plan['predicted_available_after_bytes'],
            'accounting': 'complete-statvfs-before-after-v1'}


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
            descriptor_before = inode_facts(os.fstat(descriptor))
            require(descriptor_before == before, 'new padding descriptor differs')
            counters = os.statvfs(p['volume'])
            counters_before = statvfs_facts(counters)
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
            os.fsync(descriptor)
            after = inode_facts(os.lstat(padding))
            observation = {'kind': KIND, 'status': 'OBSERVED_UNVALIDATED', 'source': ctx['source'],
                'run_context': ctx, 'recorded_at': results.utc(), 'padding_before': before,
                'padding_after': after, 'descriptor_before': descriptor_before,
                'descriptor_after': inode_facts(os.fstat(descriptor)), 'padding_plan': plan,
                'statvfs_before': counters_before, 'statvfs_after': statvfs_facts(os.statvfs(p['volume'])),
                'command_outcome': outcome}
            # This assignment deliberately precedes all allocation validation.
            record.update(padding_after=after, allocation_observation=observation)
            allocation = check_observed_allocation(prepared, observation)
            bindings.verify_receipt(prepared / 'allocation.json', prepared / 'allocation.stdout',
                                   prepared / 'allocation.stderr', requested, actual)
            require(owned_padding(padding, p['volume']) == after, 'allocated padding pathname changed')
            record['actual_allocation'] = allocation
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
            retained_allocation_check(value,
                transport.read_json(prepared / 'allocation.observed.json', 160_000),
                transport.read_json(prepared / 'allocation.json', 160_000))
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
