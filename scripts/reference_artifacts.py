"""Bounded diagnostics; scientific preservation requires a bundle or frozen image."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading
import time

import evidence_bundle as bundle

METADATA_BYTES = 35_000_000
METADATA_FILES = 3000
METADATA_ZIP = 45_000_000
# Physical reservations include block padding, fixed flat directories, and all
# bounded outside-image command captures (at most seven16MiB streams/receipts).
EXTERNAL_METADATA_ALLOCATION = 200_000_000
PACKET_ALLOCATION = 50_000_000
PACKAGE_ALLOCATION = 401_000_000
MANIFEST_BYTES = 1_000_000
CAPTURE_BYTES = 1_000_000
METADATA_SOURCE_BYTES = 35_000_000
RESULTS_IMAGE = 1_100_000_000
IMAGE_ZIP = RESULTS_IMAGE + 1_000_000
OVERHEAD = 50_000_000
CEILING = 12_000_000_000


def require(value, message):
    if not value:
        raise ValueError(message)


def growth_plan(base, image_bytes):
    require(type(base) is int and base >= 2_000_000_000, 'baseline must include the global reserve')
    require(type(image_bytes) is int and 0 < image_bytes <= 3_300_000_000, 'invalid outer image ceiling')
    metadata = EXTERNAL_METADATA_ALLOCATION + PACKET_ALLOCATION
    branches = {
        'packing_with_live_image': image_bytes + PACKAGE_ALLOCATION + metadata + OVERHEAD,
        'verified_bundle_upload_after_image_removal': PACKAGE_ALLOCATION + 450_000_000 + metadata + METADATA_ZIP + OVERHEAD,
        'verified_bundle_upload_with_retained_image': image_bytes + PACKAGE_ALLOCATION + 450_000_000 + metadata + METADATA_ZIP + OVERHEAD,
        # Original verification may forbid deleting a partial package.
        'failed_pack_exact_results_image_upload': image_bytes + PACKAGE_ALLOCATION + IMAGE_ZIP + metadata + METADATA_ZIP + OVERHEAD,
    }
    peak = base + max(branches.values())
    return {'baseline_includes_global_reserve': base, 'branches': branches,
            'maximum_new_stage_bytes': max(branches.values()), 'peak_bytes': peak,
            'admission': 'ALLOW' if peak < CEILING else 'REFUSE',
            'required_upload_policy': 'Upload either the bundle artifact or the exact results image artifact; never both. Admit actual residual external files before upload.',
            'scope': 'No profile is preauthorized from another profile admission. Nested results bytes reside inside the outer physical allocation.'}


def write_json(path, record, *, replace=False):
    bundle.no_links(path.parent)
    target = path.with_name(path.name + '.tmp') if replace else path
    if replace:
        bundle.no_links(path)
        original = path.lstat()
        require(stat.S_ISREG(original.st_mode) and original.st_nlink == 1, 'unsafe receipt replacement')
        original_identity = bundle.signature(original)
    with target.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(record, stream, sort_keys=True, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    if replace:
        temporary_identity = bundle.signature(target.lstat())
        for attempt in range(11):
            for current, expected in ((path, original_identity), (target, temporary_identity)):
                bundle.no_links(current)
                info = current.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and bundle.signature(info) == expected, 'receipt changed before atomic replacement')
            try:
                os.replace(target, path)
                break
            except PermissionError as error:
                # Actual Windows read handles can briefly deny delete sharing.
                # Bound sleeps to0.5s; retain both records on permanent denial.
                if os.name != 'nt' or getattr(error, 'winerror', None) not in (5, 32, 33) or attempt == 10:
                    raise
                time.sleep(.05)


def original_state(root):
    entries = bundle.inventory(root, ['.local'])
    return [(entry[0], entry[1], entry[2],
             None if entry[0].endswith('/') else bundle.sha(bundle.read_original(root, entry))) for entry in entries]


def residual_package_state(output):
    """Expose actual residual allocations; unsafe types refuse admission."""
    files, seen, total, logical, safe = [], set(), 0, 0, True
    for path in (output, output.with_name(output.name + '.partial')):
        if not os.path.lexists(path):
            continue
        info = path.lstat()
        regular = stat.S_ISREG(info.st_mode)
        files.append({'path': str(path), 'regular': regular, 'bytes': info.st_size,
                      'identity': list(bundle.signature(info))})
        safe = safe and regular
        if regular and (info.st_dev, info.st_ino) not in seen:
            logical += info.st_size
            total += max(info.st_size, getattr(info, 'st_blocks', 0) * 512)
            seen.add((info.st_dev, info.st_ino))
    return {'residual_package_bytes': total, 'residual_package_logical_bytes': logical,
            'residual_package_files': files,
            'residual_package_safe': safe and logical <= bundle.MAX_OUTPUT
                and total <= bundle.MAX_OUTPUT + 1_000_000}


def terminate_owned(proc, readers, record):
    """Stop only the new child session/process created by run_pack."""
    for sig, seconds in ((signal.SIGTERM, 5), (getattr(signal, 'SIGKILL', signal.SIGTERM), 5)):
        if proc.poll() is not None and not any(reader.is_alive() for reader in readers):
            break
        action = {'signal': int(sig), 'scope': 'child process group' if os.name == 'posix' else 'child process'}
        try:
            if os.name == 'posix': os.killpg(proc.pid, sig)
            elif sig == signal.SIGTERM: proc.terminate()
            else: proc.kill()
            action['sent'] = True
        except ProcessLookupError:
            action['already_exited'] = True
        except OSError as error:
            action['error'] = type(error).__name__ + ': ' + str(error)[:500]
        record['termination_actions'].append(action)
        try: proc.wait(timeout=seconds)
        except subprocess.TimeoutExpired: pass
        for reader in readers: reader.join(timeout=.2)
    return proc.poll() is not None and not any(reader.is_alive() for reader in readers)


def discard_partial(partial, expected):
    bundle.no_links(partial)
    require(bundle.signature(partial.lstat()) == expected, 'partial substituted before unlink')
    if os.name == 'posix' and os.unlink in os.supports_dir_fd:
        descriptor = os.open(partial.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require(bundle.signature(os.stat(partial.name, dir_fd=descriptor, follow_symlinks=False)) == expected,
                    'partial changed at owned directory descriptor')
            os.unlink(partial.name, dir_fd=descriptor)
        finally: os.close(descriptor)
    else:
        partial.unlink()


def run_pack(root, output, source, commit, run_id, timeout, preset=3, control=False):
    """Persist launch/termination/check failures; remove only verified cache data."""
    root = bundle.no_links(root)
    output = Path(os.path.abspath(output)); bundle.no_links(output.parent)
    require(not output.is_relative_to(root / '.local'), 'packer output must be outside measured results')
    require(type(timeout) is int and 1 <= timeout <= 1800, 'invalid pack timeout')
    require(preset in (1, 3, 6), 'unsupported compression preset')
    partial = output.with_name(output.name + '.partial')
    receipt = output.parent / 'pack-attempt.json'
    stdout, stderr = output.parent / 'pack-stdout.txt', output.parent / 'pack-stderr.txt'
    removal = output.parent / 'partial-removal.json'
    paths = (output, partial, receipt, stdout, stderr, removal, receipt.with_name(receipt.name + '.tmp'),
             output.with_name(output.name + '.failure.json'))
    require(not any(os.path.lexists(path) for path in paths), 'refusing existing pack state')
    command = [sys.executable, str(root / 'scripts/evidence_bundle.py'), 'pack', str(root), str(output),
               '--source', source, '--commit', commit, '--run-id', run_id,
               '--preset', str(preset), '--paths', '.local']
    if control:
        command = [sys.executable, '-c',
                   'import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_bytes(b"controlled-incomplete-package"); time.sleep(60)', str(partial)]
    tick = time.monotonic()
    result = {'status': 'PREPARING', 'source': source, 'commit': commit, 'run_id': run_id,
              'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
              'command': command, 'preset': preset, 'control': control,
              'started_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'exit_code': None,
              'termination_reason': None, 'termination_actions': [], 'errors': [],
              'originals_unchanged': False, 'partial_removed': False, 'complete_raw_preserved': False,
              'captured_stream_bytes': 0, 'discarded_stream_bytes': 0, 'stream_capture_complete': True,
              'scope': 'Packaging attempt only; complete scientific preservation requires a separately retained verified bundle or frozen image.'}
    write_json(receipt, result)
    before, proc, readers, saved_handlers = None, None, [], {}
    stopped, capture_errors = True, []
    limit_event, capture_lock = threading.Event(), threading.Lock()

    def interrupted(signum, frame):
        result['termination_reason'] = 'signal ' + str(signum)
        raise SystemExit(result['termination_reason'])

    def capture(pipe, path):
        try:
            with pipe, path.open('ab') as stream:
                while data := pipe.read(4096):
                    with capture_lock:
                        kept = min(len(data), max(0, CAPTURE_BYTES - result['captured_stream_bytes']))
                        stream.write(data[:kept]); stream.flush()
                        result['captured_stream_bytes'] += kept
                        result['discarded_stream_bytes'] += len(data) - kept
                        if kept != len(data):
                            result['stream_capture_complete'] = False; limit_event.set()
        except BaseException as error:
            with capture_lock: capture_errors.append(type(error).__name__ + ': ' + str(error)[:500])
            limit_event.set()

    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            try: saved_handlers[sig] = signal.signal(sig, interrupted)
            except ValueError: pass  # Production CLI is the main thread.
        stdout.touch(exist_ok=False); stderr.touch(exist_ok=False)
        before = original_state(root)
        result['phase'] = 'RUNNING'; write_json(receipt, result, replace=True)
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=(os.name == 'posix'))
        for pipe, path in ((proc.stdout, stdout), (proc.stderr, stderr)):
            reader = threading.Thread(target=capture, args=(pipe, path), daemon=True)
            readers.append(reader); reader.start()
        child_tick = time.monotonic()
        while proc.poll() is None:
            if time.monotonic() - child_tick >= timeout:
                result['termination_reason'] = 'timeout'; break
            if limit_event.is_set():
                result['termination_reason'] = 'output_limit_or_capture_error'; break
            time.sleep(.05)
        if result['termination_reason']:
            stopped = terminate_owned(proc, readers, result)
        else:
            for reader in readers: reader.join(timeout=2)
            if any(reader.is_alive() for reader in readers):
                result['termination_reason'] = 'output_pipe_remained_open'
                stopped = terminate_owned(proc, readers, result)
        if limit_event.is_set() and result['termination_reason'] is None:
            result['termination_reason'] = 'output_limit_or_capture_error'
        result['exit_code'] = proc.poll()
    except BaseException as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error)[:1000])
        result['termination_reason'] = result['termination_reason'] or 'wrapper_exception'
    finally:
        for sig in saved_handlers: signal.signal(sig, signal.SIG_IGN)
        try:
            if proc is not None:
                stopped = terminate_owned(proc, readers, result); result['exit_code'] = proc.poll()
            result['child_stopped'] = stopped; result['errors'].extend(capture_errors[:4])
            try: result['originals_unchanged'] = before is not None and original_state(root) == before
            except BaseException as error:
                result['errors'].append('original verification: ' + type(error).__name__ + ': ' + str(error)[:1000])
            success = (proc is not None and result['exit_code'] == 0 and result['termination_reason'] is None
                       and not control and output.is_file() and stopped and result['originals_unchanged'] and not result['errors'])
            result['status'] = 'PASS' if success else 'FAIL'
            if not success and os.path.lexists(partial):
                try:
                    bundle.no_links(partial); info = partial.lstat()
                    require(stopped and result['originals_unchanged'] and stat.S_ISREG(info.st_mode)
                            and info.st_nlink == 1 and info.st_size <= bundle.MAX_OUTPUT
                            and not os.path.lexists(output), 'unsafe partial package cleanup')
                    expected = bundle.signature(info)
                    result['partial'] = {'bytes': info.st_size, 'sha256': bundle.file_sha(partial), 'identity': list(expected)}
                    require(bundle.signature(partial.lstat()) == expected, 'partial substituted during hashing')
                    write_json(receipt, result, replace=True)
                    discard_partial(partial, expected)
                    result['partial_removed'] = True; write_json(removal, result)
                except BaseException as error:
                    result['errors'].append('partial retained: ' + type(error).__name__ + ': ' + str(error)[:1000])
        except BaseException as error:
            result['status'] = 'FAIL'
            result['errors'].append('finalization: ' + type(error).__name__ + ': ' + str(error)[:1000])
        finally:
            result['phase'] = 'COMPLETE'; result['ended_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
            result['duration_seconds'] = time.monotonic() - tick
            try:
                try:
                    result.update(residual_package_state(output))
                except BaseException as error:
                    result.update(residual_package_bytes=None, residual_package_safe=False)
                    result['errors'].append('residual inventory: ' + type(error).__name__ + ': ' + str(error)[:1000])
                if not result['residual_package_safe']: result['status'] = 'FAIL'
                for name, path in (('stdout', stdout), ('stderr', stderr)):
                    try: result[name + '_sha256'] = bundle.file_sha(path) if path.is_file() else None
                    except BaseException as error:
                        result[name + '_sha256'] = None; result['status'] = 'FAIL'
                        result['errors'].append('stream digest: ' + type(error).__name__ + ': ' + str(error)[:500])
                write_json(receipt, result, replace=True)
            finally:
                for sig, handler in saved_handlers.items(): signal.signal(sig, handler)
    return result


CRITICAL_SELECTIONS = [
    'reference-job-state.json', 'reference-upload-admission.json', 'reference-admission.json',
    'reference-quota.json',
    'reference-retention.json', 'reference-results-freeze.json',
    'reference-results-rescue.json', 'reference-guest-quiescence.json',
    'reference-trim-summary.json', 'reference-diagnostics.json',
    'reference-results-control-before.json', 'reference-results-control-recovery.json',
    'reference-transport/pack-attempt.json', 'reference-transport/partial-removal.json',
    'reference-transport/pack-stdout.txt', 'reference-transport/pack-stderr.txt',
    'reference-transport/pack-result.json', 'reference-transport/reference-members.tar.xz.failure.json',
    'reference-metadata-manifest.json', 'reference-enospc.stderr',
]


def metadata_files(source):
    """Never traverse even a selected root link; bound enumeration as well."""
    stack, visited = [source], 0
    while stack:
        path = stack.pop(); bundle.no_links(path); info = path.lstat(); visited += 1
        require(visited <= 10_000, 'metadata traversal entry bound exceeded')
        if stat.S_ISDIR(info.st_mode):
            names = []
            with os.scandir(path) as children:
                for child in children:
                    require(len(names) + len(stack) + visited < 10_000, 'metadata traversal entry bound exceeded')
                    names.append(child.name)
            stack.extend(path / name for name in reversed(sorted(names)))
        else:
            require(stat.S_ISREG(info.st_mode), 'nonregular metadata refused')
            yield path, info


def read_metadata(path, expected, count):
    """Hash the exact source snapshot while retaining only its declared prefix."""
    bundle.no_links(path)
    require(bundle.signature(path.lstat()) == bundle.signature(expected), 'metadata changed before read')
    require(expected.st_size <= METADATA_SOURCE_BYTES, 'metadata source exceeds bounded hashing admission')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    digest, prefix, total = hashlib.sha256(), bytearray(), 0
    with os.fdopen(descriptor, 'rb') as stream:
        require(bundle.descriptor_matches(os.fstat(stream.fileno()), bundle.signature(expected)), 'metadata descriptor changed')
        while block := stream.read(65536):
            total += len(block); require(total <= expected.st_size, 'metadata grew during read')
            digest.update(block); prefix.extend(block[:max(0, count - len(prefix))])
        require(total == expected.st_size and bundle.descriptor_matches(os.fstat(stream.fileno()), bundle.signature(expected)),
                'metadata changed during read')
    bundle.no_links(path)
    require(bundle.signature(path.lstat()) == bundle.signature(expected), 'metadata pathname changed after read')
    return bytes(prefix), digest.hexdigest()


def metadata_packet(local, output):
    """Independent bounded diagnostics; omissions never imply raw recoverability."""
    local = bundle.no_links(local); output = Path(os.path.abspath(output)); bundle.no_links(output.parent)
    require(not output.is_relative_to(local) and not local.is_relative_to(output), 'metadata output overlaps input')
    require(not os.path.lexists(output), 'refusing existing metadata packet')
    output.mkdir()
    record = {'evidence_type': 'bounded_diagnostic_packet', 'status': 'PASS', 'files': [], 'failures': [],
              'reductions': [], 'enumeration_complete': True, 'complete_scientific_preservation': False,
              'scope': 'Metadata only. Missing or reduced diagnostic originals may be unavailable; this packet never establishes complete scientific preservation.'}
    used, record_bytes, exported = 0, 0, 0
    reserve = min(16_000, MANIFEST_BYTES // 3)
    stop = False
    for name in [*CRITICAL_SELECTIONS, 'reference-metadata', 'evidence']:
        source = local / name
        if not os.path.lexists(source): continue
        try:
            bundle.no_links(source)
            if name in CRITICAL_SELECTIONS:
                require(stat.S_ISREG(source.lstat().st_mode), 'critical metadata selection is not a regular file')
            for path, info in metadata_files(source):
                relative = path.relative_to(local).as_posix(); critical = name in CRITICAL_SELECTIONS
                remaining = max(0, METADATA_BYTES - MANIFEST_BYTES - used)
                count = min(info.st_size, remaining, CAPTURE_BYTES)
                entry = {'path': relative, 'original_bytes': info.st_size, 'original_sha256': None,
                         'export_path': 'files/%06d.bin' % exported, 'export_bytes': count, 'export_sha256': '0' * 64,
                         'transformation': 'identity' if count == info.st_size else 'explicit bounded prefix; complete original availability is not established'}
                # SHA placeholders make the estimate include both complete hashes.
                estimate = {**entry, 'original_sha256': '0' * 64}
                cost = len(json.dumps(estimate, sort_keys=True, separators=(',', ':')).encode()) + 1
                if exported >= METADATA_FILES - 1 or record_bytes + cost > MANIFEST_BYTES - reserve:
                    record['reductions'].append({'selection': name, 'reason': 'file count or manifest byte budget; remaining selection was not enumerated'})
                    record['enumeration_complete'] = False; stop = True; break
                if info.st_size > METADATA_SOURCE_BYTES:
                    raise ValueError('metadata source exceeds bounded hashing admission: ' + relative[:200])
                if critical and count != info.st_size:
                    if len(record['failures']) < 20:
                        record['failures'].append('critical producer bound exceeded: ' + ascii(relative)[:200])
                    record['status'] = 'FAIL'
                data, entry['original_sha256'] = read_metadata(path, info, count)
                entry['export_sha256'] = hashlib.sha256(data).hexdigest()
                target = output / entry['export_path']; target.parent.mkdir(exist_ok=True)
                with target.open('xb') as stream: stream.write(data)
                used += len(data); exported += 1; record_bytes += cost; record['files'].append(entry)
        except (OSError, ValueError) as error:
            record['status'] = 'FAIL'; record['enumeration_complete'] = False
            if len(record['failures']) < 20:
                # ASCII representations keep serialized failure growth bounded
                # even for filenames containing escaped Unicode/surrogates.
                record['failures'].append(type(error).__name__ + ': ' + ascii(str(error))[:300])
        if stop: break
    raw = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(raw) <= MANIFEST_BYTES and used + len(raw) <= METADATA_BYTES, 'packet manifest exceeds reserved bound')
    (output / 'packet-manifest.json').write_bytes(raw)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('plan'); p.add_argument('base', type=int); p.add_argument('image_bytes', type=int)
    p = sub.add_parser('metadata'); p.add_argument('local', type=Path); p.add_argument('output', type=Path)
    p = sub.add_parser('pack')
    for name in ('root', 'output'): p.add_argument('--' + name, type=Path, required=True)
    for name in ('source', 'commit', 'run-id'): p.add_argument('--' + name, required=True)
    p.add_argument('--timeout', type=int, default=420); p.add_argument('--preset', type=int, choices=(1, 3, 6), default=3)
    p.add_argument('--control', action='store_true'); a = parser.parse_args()
    if a.action == 'plan': result = growth_plan(a.base, a.image_bytes)
    elif a.action == 'metadata': result = metadata_packet(a.local, a.output)
    else: result = run_pack(a.root, a.output, a.source, a.commit, a.run_id, a.timeout, a.preset, a.control)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('status', result.get('admission')) in ('PASS', 'ALLOW') else 1


if __name__ == '__main__':
    raise SystemExit(main())
