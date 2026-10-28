"""Bound read-only scientific selection separately from metadata finalization.

The45-second parent allocation includes descendant cleanup and capture. The
enclosing60-second admission step retains15 seconds for independent metadata.
Only compact validated selections cross the child boundary; failures retain
their complete bounded byte streams in the final admission receipt.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import threading
import time

from common import ROOT
import reference_capacity as capacity

TOTAL_SECONDS = 45
CLEANUP_SECONDS = 8
FINAL_SECONDS = 4
CAPTURE_BYTES = 32768
EVALUATION_BYTES = 128_000


def encoded_digest(value):
    digest, size = hashlib.sha256(), 0
    for part in json.JSONEncoder(sort_keys=True, separators=(',', ':')).iterencode(value):
        raw = part.encode()
        digest.update(raw)
        size += len(raw)
    return size, digest.hexdigest()


def cleanup_summary(value):
    size, digest = encoded_digest(value)
    result = {'quiescent': value.get('quiescent') is True and value.get('residual') == [],
              'residual': [] if value.get('residual') == [] else None,
              'complete_record_bytes': size, 'complete_record_sha256': digest,
              'details_complete': True}
    for name in ('adopted', 'signals', 'reaped', 'residual'):
        entries = value.get(name)
        if not isinstance(entries, list):
            continue
        result[name + '_count'] = len(entries)
        result[name + '_prefix'] = entries[:16]
        if len(entries) > 16:
            result['details_complete'] = False
    return result


def bounded_record(value):
    size, digest = encoded_digest(value)
    if size > EVALUATION_BYTES:
        # Preserve complete bounded streams. Oversized process evidence is
        # explicitly summarized and can never authorize scientific selection.
        value = {key: item for key, item in value.items() if key in {
            'stdout_base64', 'stderr_base64', 'stdout_sha256', 'stderr_sha256',
            'captured_bytes', 'discarded_bytes', 'duration_seconds', 'total_budget_seconds'}}
        value.update(status='FAIL', termination_reason='evaluation_record_limit',
                     complete_evaluation_bytes=size, complete_evaluation_sha256=digest,
                     descendant_quiescence={'quiescent': False, 'residual': None},
                     details_complete=False)
    require(encoded_digest(value)[0] <= EVALUATION_BYTES, 'bounded selection summary exceeds producer limit')
    return value


def require(value, message):
    if not value:
        raise ValueError(message)


def run_readonly(argv, *, total_seconds=TOTAL_SECONDS, cleanup_seconds=CLEANUP_SECONDS,
                 final_seconds=FINAL_SECONDS):
    """Use a dedicated ordinary Linux parent; own no unrelated children."""
    started = time.monotonic()
    require(sys.platform == 'linux' and threading.current_thread() is threading.main_thread(),
            'bounded scientific selection requires a dedicated Linux main thread')
    require(all(type(x) in (int, float) and math.isfinite(x) and x > 0
                for x in (total_seconds, cleanup_seconds, final_seconds))
            and cleanup_seconds >= 6 and total_seconds > cleanup_seconds + final_seconds,
            'invalid bounded selection deadline')
    require(hasattr(signal, 'setitimer') and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
            'selection cannot replace an unrelated deadline')
    record = {'status': 'FAIL', 'scope': 'Bounded read-only candidate evaluation; no benchmark qualification.',
              'total_budget_seconds': total_seconds, 'captured_bytes': 0, 'discarded_bytes': 0,
              'termination_reason': None, 'errors': [], 'exit_code': None,
              'descendant_quiescence': {'quiescent': False, 'residual': None}}
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    proc, selector, handlers = None, selectors.DefaultSelector(), {}
    previous_alarm, expired, ownership_admitted = signal.getsignal(signal.SIGALRM), False, False
    def absolute_cutoff(signum, frame):
        nonlocal expired
        expired = True
        raise TimeoutError('absolute selection setup/cleanup cutoff')
    signal.signal(signal.SIGALRM, absolute_cutoff)
    signal.setitimer(signal.ITIMER_REAL, max(.001, started + total_seconds - final_seconds - time.monotonic()))
    cutoff = started + total_seconds - cleanup_seconds - final_seconds
    def interrupted(signum, frame):
        raise InterruptedError('selection interrupted by signal ' + str(signum))
    def drain(wait):
        for key, _ in selector.select(wait):
            data = os.read(key.fileobj.fileno(), 4096)
            if not data:
                selector.unregister(key.fileobj)
                continue
            keep = min(len(data), CAPTURE_BYTES - record['captured_bytes'])
            streams[key.data].extend(data[:keep])
            record['captured_bytes'] += keep
            record['discarded_bytes'] += len(data) - keep
            if keep != len(data):
                record['termination_reason'] = 'output_limit'
    try:
        capacity.enable_subreaper()
        require(capacity.children(os.getpid()) == [], 'selection parent has unrelated children')
        ownership_admitted = True
        for sig in (signal.SIGTERM, signal.SIGINT):
            handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, interrupted)
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        for name, pipe in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, name)
        while proc.poll() is None:
            if time.monotonic() >= cutoff:
                record['termination_reason'] = 'candidate_deadline'
                break
            drain(min(.05, max(0, cutoff - time.monotonic())))
            if record['termination_reason']:
                break
        record['exit_code'] = proc.poll()
    except BaseException as error:
        record['errors'].append((type(error).__name__ + ': ' + str(error))[:2000])
        record['termination_reason'] = record['termination_reason'] or 'selection_exception'
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        try:
            require(ownership_admitted and not expired,
                    'selection ownership or absolute cutoff leaves quiescence unproven')
            quiet = capacity.quiesce_children()
            record['descendant_quiescence'] = cleanup_summary(quiet)
            if not record['descendant_quiescence']['details_complete']:
                record['termination_reason'] = record['termination_reason'] or 'cleanup_evidence_limit'
            if proc is not None and record['exit_code'] is None:
                for item in quiet.get('reaped', []):
                    if item['pid'] == proc.pid:
                        record['exit_code'] = os.waitstatus_to_exitcode(item['wait_status'])
                        proc.returncode = record['exit_code']
                        break
            while selector.get_map() and time.monotonic() < started + total_seconds - final_seconds:
                drain(.01)
            if selector.get_map():
                record['termination_reason'] = record['termination_reason'] or 'capture_not_closed'
        except BaseException as error:
            record['errors'].append('cleanup: ' + (type(error).__name__ + ': ' + str(error))[:2000])
            record['descendant_quiescence'] = {'quiescent': False, 'residual': None,
                'scope': 'Absolute cleanup cutoff or failure; descendant absence is unproven.'}
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_alarm)
            if expired and proc is not None and proc.poll() is None:
                # Popen owns this still-unreaped child/session. Do not scan or
                # signal unrelated PIDs after an interrupted ownership scan.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                    record['emergency_owned_group_kill'] = True
                    proc.wait(timeout=.1)
                except (OSError, subprocess.TimeoutExpired) as error:
                    record['errors'].append('owned group stop: ' + str(error)[:500])
            drain_until = min(started + total_seconds - .25, time.monotonic() + .25)
            while selector.get_map() and time.monotonic() < drain_until:
                drain(.001)
            record['capture_complete'] = not selector.get_map() and record['discarded_bytes'] == 0
            selector.close()
            if proc is not None:
                for pipe in (proc.stdout, proc.stderr):
                    if pipe is not None:
                        pipe.close()
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
    for name, raw in streams.items():
        record[name + '_base64'] = base64.b64encode(raw).decode('ascii')
        record[name + '_sha256'] = hashlib.sha256(raw).hexdigest()
    record['duration_seconds'] = time.monotonic() - started
    quiet = record['descendant_quiescence']
    if quiet.get('signals_count', 0) and record['termination_reason'] is None:
        record['termination_reason'] = 'unexpected_live_descendants'
    if (record['exit_code'] == 0 and record['termination_reason'] is None and not record['errors']
            and record['capture_complete'] and quiet.get('quiescent') is True
            and quiet.get('residual') == [] and record['duration_seconds'] < total_seconds):
        record['status'] = 'PASS'
    return bounded_record(record)


def evaluate(volume, package_ok, root=ROOT):
    require(type(package_ok) is bool, 'invalid candidate branch')
    argv = [sys.executable, str(ROOT / 'scripts/reference_upload_candidate.py'),
            '--volume', str(volume), '--root', str(root)]
    if package_ok:
        argv.append('--package-ok')
    result = run_readonly(argv)
    if result['status'] == 'PASS':
        try:
            candidate = json.loads(base64.b64decode(result['stdout_base64']))
            require(isinstance(candidate, dict) and candidate.get('status') == 'PASS',
                    'candidate child did not return a validated selection')
            result['candidate'] = candidate
        except (ValueError, TypeError, UnicodeError) as error:
            result.update(status='FAIL', error=(type(error).__name__ + ': ' + str(error))[:2000])
    return bounded_record(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volume', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--package-ok', action='store_true')
    args = parser.parse_args()
    import reference_internal_transport as internal
    try:
        candidate = (internal.verified_candidate if args.package_ok else internal.verified_frozen_candidate)(
            args.volume, args.volume / 'source', root=args.root)
        keys = ('status', 'source', 'run_context', 'profile_context', 'selected_path',
                'outer_image_retained_through_upload', 'bundle_bytes', 'verification_receipt_sha256',
                'image_unmounted', 'image_bytes', 'image_sha256', 'zip_upper_bound_bytes',
                'complete_freeze_proof_sha256', 'verify_supervisor_receipt_sha256')
        value = {key: candidate[key] for key in keys if key in candidate}
        raw = json.dumps(value, sort_keys=True)
        require(len(raw.encode()) <= 16384, 'compact candidate exceeds its producer bound')
        print(raw)
        return 0
    except BaseException as error:
        print(json.dumps({'status': 'FAIL', 'error': (type(error).__name__ + ': ' + str(error))[:2000]}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
