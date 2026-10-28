"""Independent Linux process ownership for the inside-outer transport only.

The public CLI starts this parent before setup. A payload's own timer or PASS
cannot authorize upload: only a terminal parent receipt with positively empty
descendants can do so. The generic runner also permits tiny, nonprivileged
process controls; those controls are not a quota, mount or recovery measurement.
"""
from __future__ import annotations

import time
ENTRY_STARTED = time.monotonic()

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import threading
import uuid

from common import ROOT
import reference_capacity as capacity

PHASE_SECONDS = {'pack': 1710, 'verify': 210, 'reconcile': 180}
CAPTURE_BYTES = 1_000_000  # Combined stdout+stderr, for each supervised phase.
CLEANUP_SECONDS = 12
RECEIPT_SECONDS = 30
RECEIPT_BYTES = 1_000_000
KIND = 'reference_transport_supervision'


def require(value, message):
    if not value:
        raise ValueError(message)


def process_identity(pid):
    raw = (Path('/proc') / str(pid) / 'stat').read_text()
    require(len(raw) <= 8192, 'supervisor process identity exceeds bound')
    return capacity.parse_process_stat(raw)


def same_process(expected):
    try:
        current = process_identity(expected['pid'])
    except (FileNotFoundError, ProcessLookupError):
        return False
    return current['start_time_ticks'] == expected['start_time_ticks']


def receipt_path(p, phase):
    require(phase in PHASE_SECONDS, 'unknown transport supervision phase')
    return p['audit'] / (phase + '-supervisor.json')


def require_active_worker(p, ctx, phase):
    """A worker can use its parent's reservation, but cannot mint its PASS."""
    import reference_internal_transport as transport
    require(os.environ.get('FQ_TRANSPORT_WORKER_PHASE') == phase,
            'transport worker is not inside its independently supervised phase')
    proof = transport.read_json(receipt_path(p, phase))
    parent = proof.get('supervisor_identity', {})
    require(proof.get('kind') == KIND and proof.get('profile') == transport.PROFILE
            and proof.get('phase') == phase and proof.get('state') == 'RUNNING'
            and proof.get('status') == 'PREPARING' and proof.get('run_context') == ctx
            and proof.get('source') == ctx['source'] and proof.get('volume_path') == str(p['volume'])
            and proof.get('project_path') == str(p['project']) and proof.get('outer_path') == str(p['outer'])
            and proof.get('audit_path') == str(p['audit']) and proof.get('package_path') == str(p['package'])
            and proof.get('nonce') == os.environ.get('FQ_TRANSPORT_SUPERVISOR_NONCE')
            and parent.get('pid') == os.getppid() and same_process(parent),
            'active independent transport parent identity/context differs')
    worker = process_identity(os.getpid())
    require(proof.get('worker_identity', {}).get('pid') == worker['pid']
            and proof['worker_identity'].get('start_time_ticks') == worker['start_time_ticks'],
            'supervised payload process identity differs')
    admitted = proof.get('external_admission', {})
    require(admitted.get('allowed') is True
            and admitted.get('complete_control_allocation_bytes') == transport.CONTROL_ALLOCATION
            and admitted.get('actual_existing_bytes', transport.artifacts.EXTERNAL_METADATA_ALLOCATION)
                + transport.CONTROL_ALLOCATION <= transport.artifacts.EXTERNAL_METADATA_ALLOCATION
            and transport.physical_tree(p['local'])
                <= admitted['actual_existing_bytes'] + transport.CONTROL_ALLOCATION,
            'supervised payload no longer fits its admitted complete external control reservation')
    return proof


def validate_receipt(p, ctx, phase, *, require_pass=True, bind_payload=True):
    import reference_internal_transport as transport
    path = receipt_path(p, phase)
    digest = transport.file_sha(path, RECEIPT_BYTES)
    value = transport.read_json(path, RECEIPT_BYTES)
    quiet = value.get('descendant_quiescence', {})
    require(value.get('kind') == KIND and value.get('profile') == transport.PROFILE
            and value.get('phase') == phase and value.get('state') == 'COMPLETE'
            and value.get('status') in ('PASS', 'FAIL') and value.get('run_context') == ctx
            and value.get('source') == ctx['source'] and value.get('commit') == ctx['commit']
            and value.get('run_id') == ctx['github_run_id'] and value.get('run_attempt') == ctx['github_run_attempt']
            and value.get('volume_path') == str(p['volume']) and value.get('project_path') == str(p['project'])
            and value.get('outer_path') == str(p['outer']) and value.get('audit_path') == str(p['audit'])
            and value.get('package_path') == str(p['package']) and value.get('terminal_receipt') is True
            and value.get('total_budget_seconds') == PHASE_SECONDS[phase]
            and value.get('whole_phase_within_budget') is True
            and type(value.get('duration_seconds')) in (int, float)
            and 0 <= value['duration_seconds'] < PHASE_SECONDS[phase]
            and quiet.get('quiescent') is True and quiet.get('residual') == [],
            'terminal same-execution transport supervision and positive descendant quiescence are required')
    if require_pass:
        require(value['status'] == 'PASS' and value.get('worker_started') is True
                and value.get('startup_gate_released_after_durable_publication') is True
                and value.get('worker_exit_code') == 0 and value.get('termination_reason') is None
                and value.get('capture_complete') is True and value.get('discarded_output_bytes') == 0
                and value.get('payload_receipt', {}).get('status') == 'PASS',
                'independent transport supervisor PASS is required')
    captured = 0
    for label in ('stdout', 'stderr'):
        stream = p['audit'] / (phase + '-supervisor-' + label + '.txt')
        expected = value.get('capture', {}).get(label, {})
        require(expected.get('path') == str(stream)
                and transport.file_sha(stream, CAPTURE_BYTES) == expected.get('sha256')
                and stream.lstat().st_size == expected.get('bytes'),
                'complete supervisor output capture changed')
        captured += expected['bytes']
    require(captured == value.get('captured_output_bytes') <= CAPTURE_BYTES,
            'supervisor complete capture lengths differ')
    if bind_payload and value.get('payload_receipt'):
        payload = payload_path(p, phase)
        require(value['payload_receipt'].get('path') == str(payload)
                and transport.file_sha(payload, RECEIPT_BYTES) == value['payload_receipt'].get('sha256'),
                'supervised payload receipt changed after parent quiescence')
    require(transport.file_sha(path, RECEIPT_BYTES) == digest,
            'supervisor receipt changed during validation')
    return {**value, 'supervisor_receipt_sha256': digest}


def payload_path(p, phase):
    return (p['volume'] / 'reference-results-reconciled-freeze.json' if phase == 'reconcile'
            else p['audit'] / ('pack-result.json' if phase == 'pack' else 'verification.json'))


def await_startup_gate():
    """Do not inspect mutable parent state until its durable publication."""
    raw = os.environ.pop('FQ_TRANSPORT_STARTUP_GATE_FD', '')
    require(raw.isdecimal() and 2 < int(raw) <= 1_000_000,
            'private transport payload requires its inherited startup gate')
    descriptor = int(raw)
    selection = selectors.DefaultSelector()
    try:
        require(stat.S_ISFIFO(os.fstat(descriptor).st_mode), 'transport startup gate is not a pipe')
        os.set_inheritable(descriptor, False)
        os.set_blocking(descriptor, False)
        deadline = float(os.environ.get('FQ_TRANSPORT_PAYLOAD_DEADLINE', 'nan'))
        require(math.isfinite(deadline) and deadline > time.monotonic(),
                'transport startup gate has no live actual payload deadline')
        selection.register(descriptor, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if selection.select(min(.05, max(0, deadline - time.monotonic()))):
                require(os.read(descriptor, 2) == b'1',
                        'parent closed startup gate before durable worker publication')
                return
        raise TimeoutError('transport startup gate exceeded actual payload deadline')
    finally:
        selection.close()
        os.close(descriptor)


def run_owned(argv, stdout_path, stderr_path, *, started, total_seconds,
              cleanup_seconds=CLEANUP_SECONDS, receipt_seconds=RECEIPT_SECONDS,
              capture_bytes=CAPTURE_BYTES, environ=None, launched=None, startup_gate=False):
    """Own all descendants in a dedicated parent, including detached orphans.

    Production uses the exact fixed limits above. Smaller explicit limits are
    for real tiny process controls, which must use a fresh dedicated process.
    The unchanged capacity subreaper, /proc identities and cleanup primitives
    are reused; its stage contracts and reservation profile are not changed.
    """
    require(sys.platform == 'linux' and threading.current_thread() is threading.main_thread(),
            'independent transport ownership requires the Linux main thread')
    require(all(type(value) in (int, float) and math.isfinite(value) and value > 0
                for value in (started, total_seconds, cleanup_seconds, receipt_seconds))
            and cleanup_seconds >= 6 and total_seconds > cleanup_seconds + receipt_seconds
            and type(capture_bytes) is int and 0 < capture_bytes <= CAPTURE_BYTES
            and type(startup_gate) is bool and (not startup_gate or launched is not None),
            'invalid complete independent-supervisor limits')
    capacity.enable_subreaper()
    require(capacity.children(os.getpid()) == [], 'supervisor must start without unrelated children')
    stop_at = started + total_seconds - cleanup_seconds - receipt_seconds
    require(time.monotonic() < stop_at, 'phase setup exhausted the independently admitted payload time')
    record = {'worker_started': False, 'worker_exit_code': None, 'termination_reason': None,
              'captured_output_bytes': 0, 'discarded_output_bytes': 0,
              'capture_complete': True, 'capture': {}, 'errors': []}
    proc, selection, files = None, selectors.DefaultSelector(), {}
    gate_read = gate_write = None
    previous_signals = {}
    def interrupted(signum, frame):
        raise InterruptedError('owned transport parent interrupted by signal ' + str(signum))
    for sig in (signal.SIGTERM, signal.SIGINT):
        previous_signals[sig] = signal.getsignal(sig)
        signal.signal(sig, interrupted)

    def drain(wait):
        for key, _ in selection.select(wait):
            data = os.read(key.fileobj.fileno(), 4096)
            if not data:
                selection.unregister(key.fileobj)
                continue
            keep = min(len(data), max(0, capture_bytes - record['captured_output_bytes']))
            if keep:
                files[key.data].write(data[:keep])
            record['captured_output_bytes'] += keep
            record['discarded_output_bytes'] += len(data) - keep
            if keep != len(data):
                record['capture_complete'] = False
                record['termination_reason'] = 'output_limit'

    try:
        for label, path in (('stdout', stdout_path), ('stderr', stderr_path)):
            require(not os.path.lexists(path), 'supervisor capture already exists')
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                  | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            files[label] = os.fdopen(descriptor, 'wb')
        env = environ
        if startup_gate:
            gate_read, gate_write = os.pipe()
            os.set_inheritable(gate_read, False)
            os.set_inheritable(gate_write, False)
            env = {**(os.environ if environ is None else environ),
                   'FQ_TRANSPORT_STARTUP_GATE_FD': str(gate_read),
                   'FQ_TRANSPORT_PAYLOAD_DEADLINE': repr(stop_at)}
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, start_new_session=True,
                                pass_fds=(gate_read,) if startup_gate else ())
        if gate_read is not None:
            os.close(gate_read)
            gate_read = None
        record['worker_started'] = True
        record['worker_identity'] = process_identity(proc.pid)
        require(record['worker_identity']['ppid'] == os.getpid(), 'worker parent identity differs')
        if launched is not None:
            launched(record['worker_identity'])
        if startup_gate:
            require(time.monotonic() < stop_at, 'durable publication exhausted actual payload startup time')
            require(os.write(gate_write, b'1') == 1, 'transport startup gate release failed')
            os.close(gate_write)
            gate_write = None
            record['startup_gate_released_after_durable_publication'] = True
        for label, pipe in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selection.register(pipe, selectors.EVENT_READ, label)
        while proc.poll() is None:
            if time.monotonic() >= stop_at:
                record['termination_reason'] = 'whole_phase_payload_cutoff'
                break
            drain(min(.05, max(0, stop_at - time.monotonic())))
            if record['termination_reason']:
                break
        record['worker_exit_code'] = proc.poll()
    except BaseException as error:
        record['errors'].append((type(error).__name__ + ': ' + str(error))[:1000])
        record['termination_reason'] = record['termination_reason'] or 'supervisor_exception'
    finally:
        for descriptor in (gate_read, gate_write):
            if descriptor is not None:
                os.close(descriptor)
        for sig in previous_signals:
            signal.signal(sig, signal.SIG_IGN)
        # KILL is independent of any BaseException handler or signal disposition
        # in the payload. Children that setsid()/double-fork are adopted here.
        try:
            quiet = capacity.quiesce_children()
            record['descendant_quiescence'] = quiet
            if proc is not None and record['worker_exit_code'] is None:
                for item in quiet.get('reaped', []):
                    if item['pid'] == proc.pid:
                        record['worker_exit_code'] = os.waitstatus_to_exitcode(item['wait_status'])
                        proc.returncode = record['worker_exit_code']
                        break
            if not quiet.get('quiescent'):
                record['termination_reason'] = record['termination_reason'] or 'descendants_not_quiescent'
            while selection.get_map() and time.monotonic() < started + total_seconds - receipt_seconds:
                drain(.01)
            if selection.get_map():
                record['capture_complete'] = False
                record['termination_reason'] = record['termination_reason'] or 'capture_not_closed'
        except BaseException as error:
            record['errors'].append(('cleanup: ' + type(error).__name__ + ': ' + str(error))[:1000])
            record['descendant_quiescence'] = {'quiescent': False, 'residual': None}
            record['termination_reason'] = record['termination_reason'] or 'cleanup_exception'
        finally:
            selection.close()
            if proc is not None:
                for pipe in (proc.stdout, proc.stderr):
                    pipe.close()
            for label, stream in files.items():
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
                path = stdout_path if label == 'stdout' else stderr_path
                record['capture'][label] = {'path': str(path), 'bytes': path.lstat().st_size,
                                           'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            for sig, previous in previous_signals.items():
                signal.signal(sig, previous)
    record['status'] = ('PASS' if record['worker_exit_code'] == 0
                        and record['termination_reason'] is None and record['capture_complete']
                        and record['descendant_quiescence'].get('quiescent') is True
                        and not record['errors'] else 'FAIL')
    return record


def supervise(phase, volume, project, root=ROOT, *, control=False, started=None):
    """The production parent: setup, worker, cleanup and terminal receipt fit."""
    import reference_internal_transport as transport
    require(phase in PHASE_SECONDS and type(control) is bool and (not control or phase == 'pack'),
            'unsupported supervised transport action/control')
    require(sys.platform == 'linux' and threading.current_thread() is threading.main_thread()
            and hasattr(signal, 'setitimer'), 'transport supervisor requires the Linux main thread')
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
            'transport supervisor cannot replace an unrelated deadline')
    started = time.monotonic() if started is None else started
    total = PHASE_SECONDS[phase]
    remaining = started + total - time.monotonic()
    require(remaining > 0, 'transport entry setup exceeded its whole-phase budget')
    old_alarm, handlers = signal.getsignal(signal.SIGALRM), {}
    def hard_deadline(signum, frame):
        # Never let a caught BaseException or a blocking finalizer extend this
        # independent parent. An incomplete receipt cannot qualify any upload.
        os._exit(124)
    signal.signal(signal.SIGALRM, hard_deadline)
    signal.setitimer(signal.ITIMER_REAL, remaining)
    p = ctx = proof = record = None
    try:
        p = transport.paths(volume, project, root)
        ctx = transport.context(p['project'])
        require(transport.context(p['outer']) == ctx, 'supervisor source/outer execution differs')
        admitted = transport.external_admission(p)
        if not admitted['allowed']:
            return transport.preserve_refusal(p, ctx, phase, admitted,
                    'actual external metadata plus complete 20MB control reservation exceeds admission')
        timing = transport.current_time_admission(phase)
        if not timing['allowed']:
            return transport.preserve_refusal(p, ctx, phase, admitted,
                    'supervisor lacks actual remaining job time and complete failure tail')
        if phase == 'pack':
            require(not os.path.lexists(p['audit']) and not os.path.lexists(p['data']),
                    'refusing existing internal package, partial or audit state')
            p['audit'].mkdir()
        else:
            if phase == 'reconcile' and not os.path.lexists(p['audit']):
                p['audit'].mkdir()
            transport.preflight.checked(p['audit'])
        proof = receipt_path(p, phase)
        require(not os.path.lexists(proof) and not os.path.lexists(proof.with_name(proof.name + '.tmp')),
                'previous supervisor receipt/state is retained')
        parent = process_identity(os.getpid())
        record = {'schema_version': 1, 'kind': KIND, 'profile': transport.PROFILE,
                  'phase': phase, 'state': 'PREPARING', 'status': 'PREPARING',
                  'source': ctx['source'], 'run_context': ctx, 'commit': ctx['commit'],
                  'run_id': ctx['github_run_id'], 'run_attempt': ctx['github_run_attempt'],
                  'volume_path': str(p['volume']), 'project_path': str(p['project']),
                  'outer_path': str(p['outer']), 'package_path': str(p['package']),
                  'audit_path': str(p['audit']), 'started_at': transport.results.utc(),
                  'entry_started_monotonic': started, 'total_budget_seconds': total,
                  'cleanup_reserved_seconds': CLEANUP_SECONDS, 'receipt_reserved_seconds': RECEIPT_SECONDS,
                  'external_admission': admitted, 'time_admission': timing,
                  'supervisor_identity': parent, 'nonce': uuid.uuid4().hex,
                  'worker_started': False, 'terminal_receipt': False,
                  'descendant_quiescence': {'quiescent': False, 'residual': None},
                  'scope': 'Independent bounded process ownership only; no benchmark or release qualification.'}
        transport.write_small(proof, record)
        argv = [sys.executable, str(p['outer'] / 'scripts/reference_internal_transport.py'),
                '_' + phase + '_worker', '--volume', str(p['volume']), '--project', str(p['project'])]
        if control:
            argv.append('--control')
        env = {**os.environ, 'FQ_TRANSPORT_WORKER_PHASE': phase,
               'FQ_TRANSPORT_SUPERVISOR_NONCE': record['nonce'],
               'FQ_TRANSPORT_PAYLOAD_DEADLINE': repr(started + total - CLEANUP_SECONDS - RECEIPT_SECONDS)}
        def launched(identity):
            record.update(state='RUNNING', worker_started=True, worker_identity=identity)
            transport.write_small(proof, record, replace=True)
            directory = os.open(proof.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.getsignal(sig)
            def interrupted(signum, frame):
                raise InterruptedError('supervisor interrupted by signal ' + str(signum))
            signal.signal(sig, interrupted)
        outcome = run_owned(argv, p['audit'] / (phase + '-supervisor-stdout.txt'),
                            p['audit'] / (phase + '-supervisor-stderr.txt'), started=started,
                            total_seconds=total, environ=env, launched=launched, startup_gate=True)
        record.update(outcome)
        # Once cleanup starts it must finish despite a second TERM/INT. The
        # independently installed hard SIGALRM still ends this parent on time.
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        if record['descendant_quiescence'].get('quiescent') is True:
            payload = payload_path(p, phase)
            if os.path.lexists(payload):
                value = transport.read_json(payload, RECEIPT_BYTES)
                record['payload_receipt'] = {'path': str(payload), 'status': value.get('status'),
                                            'sha256': transport.file_sha(payload, RECEIPT_BYTES)}
                expected_context = (transport.legacy_context(ctx) if phase == 'reconcile' else ctx)
                require(value.get('source') == ctx['source'] and value.get('run_context') == expected_context,
                        'payload terminal receipt source/run differs')
                if value.get('status') != 'PASS':
                    record['status'] = 'FAIL'
            else:
                record['status'] = 'FAIL'
                record['errors'].append('payload terminal receipt is absent')
            if phase == 'pack':
                record['failure_sidecar'] = transport.copy_failure_sidecar(p['package'], p['audit'], True,
                        reuse_after_quiescence=record['descendant_quiescence'])
            require(transport.context(p['project']) == ctx and transport.context(p['outer']) == ctx,
                    'transport source/run changed before terminal parent receipt')
        duration = time.monotonic() - started
        record.update(state='COMPLETE', terminal_receipt=True, duration_seconds=duration,
                      whole_phase_within_budget=duration < total,
                      ended_at=transport.results.utc())
        if duration >= total or not record['descendant_quiescence'].get('quiescent'):
            record['status'] = 'FAIL'
        transport.write_small(proof, record, replace=True)
        require(time.monotonic() < started + total, 'terminal supervisor receipt exceeded whole-phase budget')
        return record
    except BaseException as error:
        if record is not None and proof is not None:
            record.update(status='FAIL', state='COMPLETE', terminal_receipt=True,
                          error=(type(error).__name__ + ': ' + str(error))[:2000],
                          duration_seconds=time.monotonic() - started,
                          whole_phase_within_budget=time.monotonic() < started + total,
                          ended_at=transport.results.utc())
            transport.write_small(proof, record, replace=True)
            return record
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_alarm)
        for sig, previous in handlers.items():
            signal.signal(sig, previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=tuple(PHASE_SECONDS))
    parser.add_argument('--volume', type=Path, required=True)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--control', action='store_true')
    args = parser.parse_args()
    value = supervise(args.phase, args.volume, args.project, control=args.control, started=ENTRY_STARTED)
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get('status') == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
