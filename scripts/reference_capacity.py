"""Bounded supported-verification capacity control and complete local diagnostics.

Only the dedicated same-repository Actions job may run the CLI. The filesystem
quota is established and checked separately; samples are observations, never
quota enforcement. This control does not run or qualify a scientific matrix.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import zipfile

from common import ROOT, source_hash
import evidence_bundle as bundle
import reference_artifacts as artifacts

PROFILE = 'supported-verification-capacity-v1'
REPOSITORY = 'C-X1an/facetquarry'
REPOSITORY_ID = 1430604581
IMAGE_BYTES = 2_000_000_000
PROBE_BYTES = 2_100_000_000
EXTERNAL_METADATA = 200_000_000
PACKET_BYTES = 50_000_000
CLOUD_METADATA = 45_000_000
OVERHEAD_BYTES = 50_000_000
CEILING = 12_000_000_000
COPY_BYTES = 35_000_000
COPY_FILES = 3000
CAPTURE_BYTES = 35_000_000
CAPTURE_FILES = 3000
MANIFEST_BYTES = 6_000_000
ZIP_BYTES = 44_000_000
MAX_ENTRIES = 10_000
SCOPE = ('Supported verification, clean reproduction and online scanner commands only. '
         'No scientific matrix, reference-host qualification or full release claim.')
MONITOR_SCOPE = ('Best-effort sampled statvfs and backing-file observations. '
                 'Sampled high water is not a continuous maximum or quota enforcement.')
STAGES = {
    ('make', 'verify'): 780,
    ('make', 'clean-verify'): 300,
    ('go', 'install', 'golang.org/x/vuln/cmd/govulncheck@v1.9.0'): 120,
    ('make', 'security-online'): 120,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def error_text(error):
    return (type(error).__name__ + ': ' + ascii(str(error)))[:1000]


def growth_plan(base):
    """Exact dedicated reservation; the main reference profile is unchanged."""
    require(type(base) is int and base >= 2_000_000_000,
            'fresh accounted baseline must include the global2GBreserve')
    reserved = {'owned_ext4_image': IMAGE_BYTES, 'external_metadata': EXTERNAL_METADATA,
                'diagnostic_packet': PACKET_BYTES, 'cloud_metadata_only': CLOUD_METADATA,
                'overhead': OVERHEAD_BYTES}
    maximum = sum(reserved.values())
    branches = {name: maximum for name in ('supported_verification', 'clean_reproduction',
                'scanner_install', 'online_security', 'cleanup_and_metadata_upload')}
    peak = base + maximum
    return {'schema_version': 1, 'profile': PROFILE, 'scope': SCOPE,
            'baseline_includes_global_reserve': base, 'reservations': reserved,
            'branches': branches, 'maximum_new_stage_bytes': maximum,
            'peak_bytes': peak, 'ceiling_bytes': CEILING,
            'admission': 'ALLOW' if peak < CEILING else 'REFUSE',
            'data_upload_allowed': False}


def bind_context(environ, commit, git_status, digest, ordinary_linux):
    """Pure validation, also used by small refusal tests without a live runner."""
    require(ordinary_linux, 'capacity control requires an ordinary nonroot Linux runner')
    require(environ.get('GITHUB_ACTIONS') == 'true'
            and environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and environ.get('GITHUB_REPOSITORY_ID') == str(REPOSITORY_ID)
            and environ.get('GITHUB_JOB') == 'reference_capacity'
            and environ.get('FQ_RESERVATION_PROFILE') == PROFILE,
            'capacity control requires its exact same-repository Actions job and profile')
    run, attempt = environ.get('GITHUB_RUN_ID', ''), environ.get('GITHUB_RUN_ATTEMPT', '')
    require(re.fullmatch('[1-9][0-9]*', run) and re.fullmatch('[1-9][0-9]*', attempt),
            'missing actual Actions run or attempt identity')
    require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit)
            and commit == environ.get('GITHUB_SHA') and git_status == '',
            'capacity checkout must be clean and equal the current Actions SHA')
    require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest),
            'capacity source identity is not a SHA256')
    return {'repository': REPOSITORY, 'repository_id': REPOSITORY_ID,
            'commit': commit, 'git_status': '', 'source': digest,
            'github_run_id': run, 'github_run_attempt': attempt,
            'job': 'reference_capacity', 'profile': PROFILE}


def command(argv, absent_ok=False):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    require(len(result.stdout) + len(result.stderr) <= 32768,
            'capacity observation output exceeds admission')
    if absent_ok and result.returncode == 1 and not result.stdout.strip():
        return None
    require(result.returncode == 0, 'capacity observation failed: ' + ' '.join(argv[:2]))
    return result.stdout.strip()


def context(source=ROOT):
    source = bundle.no_links(source)
    ordinary = sys.platform == 'linux' and os.name == 'posix' and os.getuid() != 0
    # Refuse before running Git when invoked outside the authorized runtime.
    require(ordinary, 'capacity control requires an ordinary nonroot Linux runner')
    commit = command(['git', '-C', str(source), 'rev-parse', 'HEAD'])
    status = command(['git', '-C', str(source), 'status', '--porcelain', '--untracked-files=normal'])
    return bind_context(os.environ, commit, status, source_hash(source), ordinary)


def paths(root=ROOT):
    root = Path(os.path.abspath(root))
    workspace = Path(os.path.abspath(os.environ['GITHUB_WORKSPACE']))
    require(root == workspace, 'capacity CLI must run from the outer Actions checkout')
    bundle.no_links(root)
    temporary = bundle.no_links(Path(os.environ['RUNNER_TEMP']))
    require(temporary.is_absolute() and temporary.is_dir(), 'invalid runner temporary directory')
    volume = temporary / 'facetquarry-capacity'
    return {'outer': root, 'local': root / '.local', 'volume': volume,
            'source': volume / 'source', 'image': temporary / 'facetquarry-capacity.img',
            'metadata': temporary / 'facetquarry-capacity-metadata',
            'packet': temporary / 'facetquarry-capacity-packet'}


def mkdir(path):
    ancestor = path
    while not os.path.lexists(ancestor):
        ancestor = ancestor.parent
    bundle.no_links(ancestor)
    path.mkdir(parents=True, exist_ok=True)
    bundle.no_links(path)
    require(path.is_dir(), 'capacity directory is not regular')


def encode(record, limit=MANIFEST_BYTES):
    raw = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(raw) <= limit, 'capacity receipt exceeds its complete manifest bound')
    return raw


def write(path, record):
    raw = encode(record)
    mkdir(path.parent)
    require(not os.path.lexists(path), 'refusing to replace an existing capacity receipt')
    with path.open('xb') as stream:
        stream.write(raw)


def load(path, limit=MANIFEST_BYTES):
    bundle.no_links(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
            'capacity JSON is not a bounded single-link regular file')
    raw, _ = artifacts.read_metadata(path, info, info.st_size)
    return json.loads(raw, object_pairs_hook=bundle.unique_object)


def image_identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_size]


def allocated(info):
    return max(info.st_size, getattr(info, 'st_blocks', 0) * 512)


def physical(root, maximum_entries=MAX_ENTRIES):
    """Include directory allocations and every regular file; never follow links."""
    if not os.path.lexists(root):
        bundle.no_links(root.parent)
        return 0
    total, entries, stack = 0, 0, [root]
    while stack:
        path = bundle.no_links(stack.pop())
        info = path.lstat(); entries += 1
        require(entries <= maximum_entries, 'physical inventory entry bound exceeded')
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                'physical inventory found a nonregular entry')
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1, 'hardlinked external allocation refused')
        total += allocated(info)
        require(total <= 15_000_000_000, 'physical inventory exceeds global contract')
        if stat.S_ISDIR(info.st_mode):
            names = []
            with os.scandir(path) as children:
                for child in children:
                    require(len(names) + len(stack) + entries < maximum_entries,
                            'physical inventory enumeration bound exceeded')
                    names.append(child.name)
            stack.extend(path / name for name in names)
    return total


def external_bytes(p):
    return physical(p['local']) + physical(p['metadata'])


def allocation_units(p):
    units = [os.statvfs(path).f_frsize for path in (p['outer'], p['image'].parent)]
    require(all(0 < unit <= 4096 for unit in units),
            'capacity reservations require allocation units no larger than4096bytes')
    return units


def plan(root=ROOT):
    p, ctx = paths(root), context(root)
    units = allocation_units(p)  # Before the image, SDK, or other heavy allocation.
    result = {**growth_plan(int(os.environ['FQ_ACCOUNTED_BASE_BYTES'])), 'run_context': ctx}
    write(p['local'] / 'capacity-admission.json', result)
    require(result['admission'] == 'ALLOW', 'global capacity growth admission refused')
    return {**result, 'allocation_units_bytes': units, 'status': 'PASS'}


def valid_name(name):
    require(isinstance(name, str) and re.fullmatch('[a-z][a-z0-9-]{0,63}', name),
            'invalid capacity stage name')


def sample_state(p):
    """No tree walk or subprocess in the once-per-second sampler."""
    row = {'at': stamp(), 'monotonic_seconds': time.monotonic()}
    try:
        observation = os.statvfs(p['volume'])
        unit = observation.f_frsize
        require(unit > 0, 'invalid statvfs allocation unit')
        row.update(filesystem_free_bytes=observation.f_bfree * unit,
                   filesystem_available_bytes=observation.f_bavail * unit,
                   filesystem_used_bytes=(observation.f_blocks - observation.f_bfree) * unit,
                   allocation_unit_bytes=unit)
    except (OSError, ValueError) as error:
        row['filesystem_error'] = error_text(error)
    try:
        info = p['image'].lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                'sampled image is not a single-link regular file')
        row.update(image_logical_bytes=info.st_size, image_allocated_bytes=allocated(info),
                   image_identity=image_identity(info))
    except (OSError, ValueError) as error:
        row['image_error'] = error_text(error)
    return row


def summarize_samples(rows):
    result = {'count': len(rows), 'scope': MONITOR_SCOPE, 'quota_enforcement': False}
    for field in ('filesystem_free_bytes', 'filesystem_available_bytes',
                  'filesystem_used_bytes', 'image_allocated_bytes'):
        values = [row[field] for row in rows if field in row]
        if values:
            result['sampled_min_' + field] = min(values)
            result['sampled_max_' + field] = max(values)
    result['observation_errors'] = sum('filesystem_error' in row or 'image_error' in row for row in rows)
    return result


def sample(name, root=ROOT):
    valid_name(name)
    p, ctx = paths(root), context(root)
    row = sample_state(p)
    result = {'schema_version': 1, 'profile': PROFILE, 'kind': 'capacity_snapshot',
              'name': name, 'run_context': ctx, 'status': 'PASS' if not any(
                  key.endswith('_error') for key in row) else 'FAIL',
              'sample': row, 'scope': MONITOR_SCOPE}
    write(p['local'] / 'capacity-control' / (name + '.json'), result)
    return result


def stage_contract(command_args, timeout):
    require(tuple(command_args) in STAGES and STAGES[tuple(command_args)] == timeout,
            'unsupported capacity command or evidence deadline')


def enable_subreaper():
    require(sys.platform == 'linux', 'descendant ownership requires Linux subreaper support')
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(36, 1, 0, 0, 0) == 0, 'could not enable Linux child subreaper')
    value = ctypes.c_int()
    require(libc.prctl(37, ctypes.byref(value), 0, 0, 0) == 0 and value.value == 1,
            'Linux child subreaper could not be positively observed')


def parse_process_stat(raw):
    """/proc comm can contain spaces and parentheses; fields follow its last )."""
    end = raw.rfind(')')
    require(end >= 0 and raw[:raw.find(' ')].isdecimal(), 'invalid process stat identity')
    fields = raw[end + 2:].split()
    require(len(fields) >= 20, 'incomplete process stat identity')
    return {'pid': int(raw[:raw.find(' ')]), 'state': fields[0],
            'ppid': int(fields[1]), 'start_time_ticks': int(fields[19])}


def children(parent):
    result, visited = [], 0
    with os.scandir('/proc') as entries:
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            visited += 1
            require(visited <= 50_000, 'process observation enumeration bound exceeded')
            try:
                raw = (Path('/proc') / entry.name / 'stat').read_text()
            except (FileNotFoundError, ProcessLookupError):
                continue
            require(len(raw) <= 8192, 'process stat exceeds observation bound')
            item = parse_process_stat(raw)
            if item['ppid'] == parent:
                result.append(item)
    return sorted(result, key=lambda item: item['pid'])


def reap_exited():
    reaped = []
    while True:
        try:
            pid, status_code = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            break
        reaped.append({'pid': pid, 'wait_status': status_code})
        require(len(reaped) <= 10_000, 'descendant reap count exceeds bound')
    return reaped


def signal_owned(item, sig):
    try:
        current = parse_process_stat((Path('/proc') / str(item['pid']) / 'stat').read_text())
        require(current['ppid'] == os.getpid()
                and current['start_time_ticks'] == item['start_time_ticks'],
                'adopted process identity changed before signal')
        os.kill(item['pid'], sig)
        return True
    except (FileNotFoundError, ProcessLookupError):
        return False


def quiesce_children():
    """Only this dedicated subreaper's positively identified adopted children."""
    result = {'quiescent': False, 'adopted': [], 'signals': [], 'reaped': []}
    for sig, seconds in ((signal.SIGTERM, 2), (signal.SIGKILL, 3)):
        deadline = time.monotonic() + seconds
        signalled = set()
        while True:
            result['reaped'].extend(reap_exited())
            remaining = children(os.getpid())
            if not remaining:
                result['quiescent'] = True
                result['residual'] = []
                return result
            for item in remaining:
                identity = item['pid'], item['start_time_ticks']
                if identity not in signalled:
                    signalled.add(identity)
                    result['adopted'].append(item)
                    if signal_owned(item, sig):
                        result['signals'].append({'pid': item['pid'],
                            'start_time_ticks': item['start_time_ticks'], 'signal': int(sig)})
            require(len(result['adopted']) <= 10_000, 'descendant cleanup observation bound exceeded')
            if time.monotonic() >= deadline:
                break
            time.sleep(0.05)
    result['reaped'].extend(reap_exited())
    result['residual'] = children(os.getpid())
    result['quiescent'] = not result['residual']
    return result


def stage(name, timeout, command_args, root=ROOT):
    valid_name(name); stage_contract(command_args, timeout)
    p, ctx = paths(root), context(root)
    require(os.environ.get('FQ_WORKSPACE_ROOT') == str(p['volume'])
            and os.environ.get('FQ_VOLUME') == str(p['volume'])
            and os.environ.get('FQ_IMAGE') == str(p['image']),
            'capacity stage requires exact owned image and workspace bindings')
    expected_env = {'GOPATH': p['volume'] / 'gopath', 'GOBIN': p['volume'] / 'tools/bin',
                    'TMPDIR': p['source'] / '.cache/tmp', 'TEMP': p['source'] / '.cache/tmp',
                    'TMP': p['source'] / '.cache/tmp', 'GOCACHE': p['source'] / '.cache/go-build',
                    'GOMODCACHE': p['source'] / '.cache/go-mod',
                    'GOTMPDIR': p['source'] / '.cache/tmp',
                    'XDG_CONFIG_HOME': p['volume'] / 'config', 'XDG_CACHE_HOME': p['volume'] / 'cache'}
    require(all(os.environ.get(key) == str(value) for key, value in expected_env.items()),
            'capacity stage tool, cache or temporary paths escape the quota')
    go = Path(shutil.which('go') or '')
    require(go == p['volume'] / 'tools/go/bin/go', 'capacity stage Go executable is outside owned tools')
    bundle.no_links(go)
    require(go.is_file() and os.access(go, os.X_OK), 'capacity stage Go executable is unavailable')
    require(context(p['source']) == ctx, 'inner supported source differs from outer checkout')
    require(growth_plan(int(os.environ['FQ_ACCOUNTED_BASE_BYTES']))['admission'] == 'ALLOW',
            'capacity stage has no global growth admission')
    # Observe quota and backing again before every actual heavy command. A
    # historical JSON receipt alone cannot turn an ordinary directory into a cap.
    from reference_capacity_reservation import validate_documents
    image = bundle.no_links(p['image']).lstat()
    mount = json.loads(command(['findmnt', '--json', '--mountpoint', str(p['volume']),
                               '-o', 'TARGET,FSTYPE,SOURCE']), object_pairs_hook=bundle.unique_object)['filesystems'][0]
    loops = json.loads(command(['sudo', '-n', 'losetup', '--json', '--list', '--associated',
                               str(p['image']), '--output', 'NAME,BACK-FILE']), object_pairs_hook=bundle.unique_object)
    quota = load(p['source'] / '.local/capacity-quota.json')
    require(quota.get('backing_identity') == image_identity(image), 'capacity quota image identity changed')
    stderr_path = bundle.no_links(p['source'] / '.local/capacity-enospc.stderr')
    stderr_info = stderr_path.lstat()
    require(stat.S_ISREG(stderr_info.st_mode) and stderr_info.st_nlink == 1 and stderr_info.st_size <= 32768,
            'capacity quota refusal stderr exceeds producer bound')
    stderr, _ = artifacts.read_metadata(stderr_path, stderr_info, stderr_info.st_size)
    result_proof = validate_documents(p['volume'], image.st_size, mount, loops, quota,
                                     load(p['source'] / '.local/capacity-admission.json'), ctx,
                                     stderr, int(os.environ['FQ_ACCOUNTED_BASE_BYTES']))
    current_mount = observe_mount(p['volume'])
    require(current_mount is not None, 'capacity filesystem is no longer mounted')
    validate_unmount_binding(p['volume'], p['image'], image, current_mount, observe_loops(p['image']))
    require({'nodev', 'nosuid'} <= set(current_mount.get('options', '').split(','))
            and 'noexec' not in current_mount.get('options', '').split(','),
            'capacity mount must be executable with nodev,nosuid')
    enable_subreaper()
    require(not children(os.getpid()), 'capacity stage already owns unrelated live children')
    record_path = p['local'] / 'capacity-control' / (name + '.json')
    require(not os.path.lexists(record_path), 'capacity stage name has already been used')
    result = {'schema_version': 1, 'profile': PROFILE, 'kind': 'capacity_stage',
              'name': name, 'command': command_args, 'timeout_seconds': timeout,
              'run_context': ctx, 'started_at': stamp(), 'status': 'FAIL',
              'quiescent': False, 'scope': SCOPE, 'monitor_scope': MONITOR_SCOPE,
              'reservation': result_proof}
    write(record_path.with_name(name + '-start.json'), {
        'schema_version': 1, 'profile': PROFILE, 'kind': 'capacity_stage_start',
        'name': name, 'command': command_args, 'timeout_seconds': timeout,
        'run_context': ctx, 'started_at': result['started_at'], 'status': 'RUNNING'})
    rows, stop = [sample_state(p)], threading.Event()
    maximum_samples = timeout + 45

    def monitor():
        while not stop.wait(1):
            if len(rows) >= maximum_samples:
                return
            rows.append(sample_state(p))

    thread = threading.Thread(target=monitor, name='capacity-statvfs-sampler', daemon=True)
    thread.start()
    try:
        argv = [sys.executable, str(p['source'] / 'scripts/evidence.py'),
                '--category', 'capacity-' + name, '--requirements', 'AC-018',
                '--timeout', str(timeout), '--', *command_args]
        # evidence.py owns the command timeout and command process-group cleanup.
        # The subreaper handles descendants detached from that command session.
        completed = subprocess.run(argv, cwd=p['source'], check=False)
        result['evidence_exit_code'] = completed.returncode
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result['error'] = error_text(error)
    finally:
        try:
            cleanup = quiesce_children()
            result['descendant_cleanup'] = cleanup
            result['quiescent'] = cleanup['quiescent']
        except (OSError, ValueError) as error:
            result['cleanup_error'] = error_text(error)
        stop.set(); thread.join(timeout=5)
        result['sampler_joined'] = not thread.is_alive()
        rows.append(sample_state(p))
        result.update(ended_at=stamp(), samples=rows, sampled_high_water=summarize_samples(rows))
        if (result.get('evidence_exit_code') == 0 and result['quiescent'] and result['sampler_joined']
                and not result.get('descendant_cleanup', {}).get('signals')):
            result['status'] = 'PASS'
        write(record_path, result)
    return result


def tree_files(source):
    """Whole tree, including hidden paths, with bounded directory enumeration."""
    stack, entries = [source], 0
    while stack:
        path = bundle.no_links(stack.pop()); info = path.lstat(); entries += 1
        require(entries <= MAX_ENTRIES, 'complete local traversal entry bound exceeded')
        relative = path.relative_to(source).as_posix()
        require(len(relative.encode('utf-8')) <= 4096, 'complete local source path exceeds bound')
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                'whole local retention refuses nonregular entries')
        if stat.S_ISDIR(info.st_mode):
            names = []
            with os.scandir(path) as children_stream:
                for child in children_stream:
                    require(len(names) + len(stack) + entries < MAX_ENTRIES,
                            'complete local directory enumeration bound exceeded')
                    names.append(child.name)
            stack.extend(path / name for name in reversed(sorted(names)))
        else:
            require(info.st_nlink == 1, 'whole local retention refuses hardlinks')
        yield path, info


def tree_identity(source):
    return [(path.relative_to(source).as_posix(), list(bundle.signature(info)),
             info.st_uid, info.st_nlink) for path, info in tree_files(source)]


def shared_copy_budget(metadata, current_kind, additional_bytes, additional_files):
    """Reserve all existing copies plus both export proofs and the packet proof."""
    rows = [(path, info) for path, info in tree_files(metadata) if stat.S_ISREG(info.st_mode)]
    logical = sum(info.st_size for _, info in rows)
    missing_manifests = sum(not os.path.lexists(metadata / (kind + '-manifest.json'))
                            for kind in ('volume', 'outer'))
    proof_bytes = (missing_manifests + 1) * MANIFEST_BYTES
    proof_files = missing_manifests + 1
    require(logical + additional_bytes + proof_bytes <= CAPTURE_BYTES
            and len(rows) + additional_files + proof_files <= CAPTURE_FILES,
            'aggregate complete-copy bytes/files including proof reservations exceeded')


def export_tree(source, destination, kind, ctx, external_used=0, closed_writer_proof=True,
                quiescence_error=None):
    """Complete originals only; any bound failure retains honest partial copies."""
    require(kind in ('volume', 'outer'), 'unsupported complete local export')
    source, destination = Path(os.path.abspath(source)), Path(os.path.abspath(destination))
    require(not destination.is_relative_to(source) and not source.is_relative_to(destination),
            'complete export source and destination overlap')
    require(type(external_used) is int and 0 <= external_used < EXTERNAL_METADATA,
            'invalid current external allocation inventory')
    require(not os.path.lexists(destination), 'refusing existing complete local export')
    mkdir(destination.parent)
    require(external_used + MANIFEST_BYTES + 4096 < EXTERNAL_METADATA,
            'external originals leave no complete manifest reservation')
    mkdir(destination)
    result = {'schema_version': 1, 'profile': PROFILE, 'kind': kind,
              'source_root': str(source), 'run_context': ctx, 'status': 'FAIL',
              'enumeration_complete': False, 'complete_local_retention': False,
              'closed_writer_proof': closed_writer_proof,
              'files': [], 'directories': [], 'logical_bytes': 0,
              'scope': 'Whole available .local only; identity copies, never prefixes or selected trees.'}
    if quiescence_error is not None:
        result['quiescence_error'] = quiescence_error
    identities, reserved = [], external_used + MANIFEST_BYTES + 4096
    try:
        require(os.path.lexists(source), 'local source was unavailable during partial setup')
        for path, info in tree_files(source):
            relative = path.relative_to(source).as_posix()
            original_identity = list(bundle.signature(info))
            identities.append((relative, original_identity, info.st_uid, info.st_nlink))
            common = {'source_path': relative, 'source_identity': original_identity,
                      'source_uid': info.st_uid, 'source_nlink': info.st_nlink,
                      'source_mode': info.st_mode}
            if stat.S_ISDIR(info.st_mode):
                encode({**result, 'directories': [*result['directories'], common]}, MANIFEST_BYTES - 2048)
                result['directories'].append(common)
                continue
            require(len(result['files']) < COPY_FILES
                    and result['logical_bytes'] + info.st_size <= COPY_BYTES,
                    'whole local complete-copy logical or file-count bound exceeded')
            cost = ((info.st_size + 4095) // 4096) * 4096
            shared_copy_budget(destination.parent, kind, info.st_size, 1)
            require(reserved + cost <= EXTERNAL_METADATA,
                    'whole local complete-copy external physical reservation exceeded')
            raw, digest = artifacts.read_metadata(path, info, info.st_size)
            require(len(raw) == info.st_size and list(bundle.signature(path.lstat())) == original_identity
                    and path.lstat().st_nlink == 1, 'complete local source changed after read')
            target = destination / ('%06d.bin' % len(result['files']))
            # Reserve the complete row before allocating its copy. File identity
            # integers below are conservatively overestimated for serialized size.
            estimate = {**common, 'bytes': info.st_size, 'sha256': digest, 'copy': target.name,
                        'copy_identity': [10**30] * 7, 'copy_mode': 10**10, 'transformation': 'identity'}
            encode({**result, 'files': [*result['files'], estimate]}, MANIFEST_BYTES - 2048)
            with target.open('xb') as stream:
                stream.write(raw)
            target.chmod(0o600)
            copied = target.lstat()
            actual_raw, actual_digest = artifacts.read_metadata(target, copied, copied.st_size)
            require(actual_raw == raw and actual_digest == digest, 'complete copy bytes or SHA differ')
            result['files'].append({**common, 'bytes': info.st_size, 'sha256': digest,
                'copy': target.name, 'copy_identity': list(bundle.signature(copied)),
                'copy_mode': copied.st_mode, 'transformation': 'identity'})
            result['logical_bytes'] += info.st_size; reserved += allocated(copied)
            # Include paths, complete identities, and worst remaining JSON delimiter.
            encode(result, MANIFEST_BYTES - 2048)
        require(tree_identity(source) == identities, 'whole local tree changed during complete capture')
        result.update(status='PASS' if closed_writer_proof else 'FAIL', enumeration_complete=True,
                      complete_local_retention=closed_writer_proof)
        if not closed_writer_proof:
            result['error'] = quiescence_error or 'Closed-writer proof unavailable; stable diagnostic bytes only.'
    except (OSError, ValueError) as error:
        result['error'] = error_text(error)
    result['copied_files'] = len(result['files'])
    write(destination.parent / (kind + '-manifest.json'), result)
    return result


def verify_export(metadata, kind, ctx):
    manifest = load(metadata / (kind + '-manifest.json'))
    require(manifest.get('profile') == PROFILE and manifest.get('kind') == kind
            and manifest.get('run_context') == ctx, 'complete local manifest execution identity differs')
    require(isinstance(manifest.get('files'), list) and len(manifest['files']) <= COPY_FILES,
            'complete local manifest file-count bound differs')
    directory = bundle.no_links(metadata / kind)
    expected, total, sources = set(), 0, set()
    for row in manifest['files']:
        name = row.get('copy', '')
        require(re.fullmatch(r'[0-9]{6}\.bin', name) and name not in expected,
                'complete local copy name differs or is duplicated')
        require(row.get('source_path') not in sources and row.get('transformation') == 'identity'
                and stat.S_ISREG(row.get('source_mode', 0)) and row.get('source_nlink') == 1,
                'complete local source identity or transformation differs')
        expected.add(name); sources.add(row['source_path'])
        path = bundle.no_links(directory / name); info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and list(bundle.signature(info)) == row.get('copy_identity')
                and info.st_mode == row.get('copy_mode') and info.st_size == row.get('bytes'),
                'retained complete copy identity changed')
        raw, digest = artifacts.read_metadata(path, info, info.st_size)
        require(len(raw) == row['bytes'] and digest == row.get('sha256'),
                'retained complete copy SHA differs')
        total += info.st_size
    require(total == manifest.get('logical_bytes') and total <= COPY_BYTES
            and {path.name for path in directory.iterdir()} == expected,
            'complete copy totals or full directory membership differ')
    return manifest


def privileged_cwd_argv(pid):
    require(type(pid) is int and 0 < pid <= 2_147_483_647, 'invalid cwd observation PID')
    return ['/usr/bin/sudo', '-n', '--', '/usr/bin/timeout', '--signal=TERM',
            '--kill-after=1s', '2s', '/usr/bin/readlink', '--zero', '--',
            '/proc/' + str(pid) + '/cwd']


def privileged_cwd_bytes(pid):
    """Read one protected cwd under the already exercised runner sudo grant."""
    require(sys.platform == 'linux', 'elevated cwd observation requires supported Linux')
    argv = privileged_cwd_argv(pid)
    # Both the root command and the parent have deadlines. The pipe consumes at
    # most8193bytes, including an over-limit sentinel; stderr is never retained.
    proc, selector = None, None
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, start_new_session=True)
        output, selector = bytearray(), selectors.DefaultSelector()
        deadline = time.monotonic() + 5
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0 and selector.select(remaining),
                    'elevated cwd observation timed out')
            chunk = os.read(proc.stdout.fileno(), min(4096, 8193 - len(output)))
            if not chunk: break
            output.extend(chunk)
            require(len(output) <= 8192, 'elevated cwd observation output exceeds bound')
        code = proc.wait(timeout=max(.001, deadline - time.monotonic()))
        require(code == 0, 'elevated cwd observation refused; exit=' + str(code))
        return bytes(output)
    finally:
        try:
            if selector is not None: selector.close()
        finally:
            if proc is not None:
                try:
                    if proc.poll() is None:
                        proc.terminate()
                        try: proc.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            proc.kill(); proc.wait(timeout=1)
                finally:
                    if proc.stdout is not None: proc.stdout.close()


def process_cwd_identity(directory):
    name = directory.name
    require(re.fullmatch(r'[1-9][0-9]{0,9}', name) is not None
            and directory == Path('/proc') / name, 'invalid cwd process directory')
    uid = directory.stat().st_uid
    raw = (directory / 'stat').read_text()
    require(len(raw) <= 8192, 'writer process identity exceeds bound')
    item = parse_process_stat(raw)
    require(item['pid'] == int(name), 'cwd process PID differs')
    return uid, item


def process_disappeared(directory):
    try: directory.stat()
    except (FileNotFoundError, ProcessLookupError): return True
    return False


def observed_process_cwd(directory, uid, budget):
    """Never classify an unreadable live process as unrelated."""
    try: before_uid, before = process_cwd_identity(directory)
    except (FileNotFoundError, ProcessLookupError):
        require(process_disappeared(directory), 'live process initial identity unavailable')
        return None, {'pid': int(directory.name), 'proof': 'process directory positively absent'}
    require(before_uid == uid, 'cwd process UID changed before observation')
    denial, raw, error = None, None, None
    method = 'same_uid_readlink'
    if before['state'] not in ('Z', 'X', 'x'):
        try: raw = os.fsencode(os.readlink(directory / 'cwd')) + b'\0'
        except PermissionError as original:
            denial = error_text(original)
            budget['calls'] += 1
            require(budget['calls'] <= 16, 'elevated cwd observation call bound exceeded')
            method = 'existing_sudo_fixed_readlink'
            try: raw = privileged_cwd_bytes(before['pid'])
            except (OSError, ValueError, subprocess.SubprocessError) as failure: error = failure
        except (FileNotFoundError, ProcessLookupError) as failure: error = failure
    try: after_uid, after = process_cwd_identity(directory)
    except (FileNotFoundError, ProcessLookupError):
        require(process_disappeared(directory), 'live process final identity unavailable')
        proof = {'pid': before['pid'], 'uid': uid, 'before': before,
                 'proof': 'process directory positively absent after observation'}
        if denial is not None: proof['original_denial'] = denial
        return None, proof
    require(after_uid == uid and all(before[key] == after[key] for key in
            ('pid', 'start_time_ticks')), 'cwd process identity or UID changed during observation')
    proof = {'pid': before['pid'], 'uid': uid, 'before': before, 'after': after, 'method': method}
    if denial is not None: proof['original_denial'] = denial
    if after['state'] in ('Z', 'X', 'x'):
        proof['proof'] = 'same-identity process positively nonwriting zombie/dead state'
        return None, proof
    require(error is None and raw is not None,
            'live process cwd unresolved; pid=' + directory.name + '; original=' +
            str(denial) + '; observation=' + (error_text(error) if error is not None else 'missing'))
    require(type(raw) is bytes and 1 < len(raw) <= 8192 and raw.endswith(b'\0')
            and raw.count(b'\0') == 1 and raw.startswith(b'/')
            and not raw[:-1].endswith(b' (deleted)'), 'ambiguous or deleted process cwd output')
    proof['cwd_sha256'] = hashlib.sha256(raw[:-1]).hexdigest()
    return Path(os.fsdecode(raw[:-1])), proof


def active_volume_processes(volume, observations=None):
    """A conservative live cwd observation complements subreaper stage receipts."""
    found, seen, budget = [], 0, {'calls': 0}
    with os.scandir('/proc') as entries:
        for entry in entries:
            if not entry.name.isdecimal() or int(entry.name) == os.getpid():
                continue
            seen += 1
            require(seen <= 50_000, 'writer observation process bound exceeded')
            directory = Path('/proc') / entry.name
            try:
                owner = directory.stat().st_uid
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError:
                raise ValueError('process UID unavailable; ownership unproven; pid=' + entry.name)
            if owner != os.getuid(): continue
            try:
                current, proof = observed_process_cwd(directory, owner, budget)
                if proof is not None and observations is not None and (
                        proof.get('method') != 'same_uid_readlink' or 'proof' in proof):
                    require(len(observations) < 64, 'exceptional cwd proof count exceeded')
                    observations.append(proof)
                if current is None: continue
                if current == volume or current.is_relative_to(volume):
                    found.append(proof['after'])
            except (FileNotFoundError, ProcessLookupError):
                require(process_disappeared(directory), 'live process writer identity unavailable')
            except PermissionError:
                raise ValueError('same-UID process cwd unavailable; project ownership unproven; pid=' + entry.name)
    return found


def assert_outside_evidence_wrapper(p):
    """Capture and packet must not include an active outer or inner wrapper."""
    visited = 0
    with os.scandir('/proc') as entries:
        for entry in entries:
            if not entry.name.isdecimal() or int(entry.name) == os.getpid():
                continue
            visited += 1
            require(visited <= 50_000, 'evidence wrapper process observation bound exceeded')
            directory = Path('/proc') / entry.name
            try:
                if directory.stat().st_uid != os.getuid():
                    continue
                raw = (directory / 'cmdline').read_bytes()
                require(len(raw) <= 65536, 'owned process command line exceeds observation bound')
                argv = raw.split(b'\0')
                if not any(arg.endswith(b'evidence.py') for arg in argv):
                    continue
                cwd = Path(os.readlink(directory / 'cwd'))
                owned = cwd == p['outer'] or cwd.is_relative_to(p['volume'])
                owned |= any(str(p['outer']).encode() in arg or str(p['volume']).encode() in arg for arg in argv)
                require(not owned, 'complete diagnostics must run outside an active evidence wrapper')
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError:
                raise ValueError('owned evidence-wrapper state could not be observed')


def stage_quiescence(p, ctx):
    records, completed = [], set()
    started, terminal = {}, {}
    control = p['local'] / 'capacity-control'
    if os.path.lexists(control):
        bundle.no_links(control)
        names = list(control.iterdir())
        require(len(names) <= 40, 'capacity control receipt count exceeds bound')
        for path in sorted(names):
            value = load(path)
            if value.get('kind') == 'capacity_stage_start':
                require(value.get('run_context') == ctx and value.get('status') == 'RUNNING'
                        and value.get('name') not in started, 'stage start identity differs')
                started[value['name']] = value
                continue
            if value.get('kind') != 'capacity_stage':
                continue
            require(value.get('run_context') == ctx and value.get('quiescent') is True
                    and value.get('sampler_joined') is True,
                    'a stage has no current positive descendant quiescence proof')
            cmd = tuple(value.get('command', []))
            stage_contract(list(cmd), value.get('timeout_seconds'))
            records.append({'name': value['name'], 'status': value['status'], 'command': list(cmd)})
            require(value['name'] not in terminal, 'duplicate terminal stage proof')
            terminal[value['name']] = value
            if value.get('status') == 'PASS':
                completed.add(cmd)
    require(set(started) == set(terminal), 'attempted stage has no matching terminal quiescence proof')
    for name, before in started.items():
        after = terminal[name]
        require(all(before.get(key) == after.get(key) for key in
                    ('run_context','name','started_at','command','timeout_seconds')),
                'terminal stage does not match its exact attempted command')
    observations = []
    live = active_volume_processes(p['volume'], observations)
    require(not live, 'capacity volume still has active owned processes')
    return {'quiescent': True, 'stages': records, 'execution_complete': completed == set(STAGES),
            'active_volume_processes': live,
            'exceptional_cwd_observations': observations,
            'scope': 'Current cwd observation plus Linux subreaper descendant receipts; no scientific qualification.'}


def capture(root=ROOT):
    p, ctx = paths(root), context(root)
    mkdir(p['metadata'])
    result = {'schema_version': 1, 'profile': PROFILE, 'run_context': ctx,
              'status': 'FAIL', 'complete_local_retention': False, 'scope': SCOPE}
    try:
        assert_outside_evidence_wrapper(p)
        try:
            result['quiescence'] = stage_quiescence(p, ctx)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            result['quiescence_error'] = error_text(error)
        if os.path.lexists(p['source']):
            require(context(p['source']) == ctx, 'inner source changed before complete capture')
        exported = export_tree(p['source'] / '.local', p['metadata'] / 'volume',
            'volume', ctx, external_bytes(p),
            closed_writer_proof=result.get('quiescence', {}).get('quiescent') is True,
            quiescence_error=result.get('quiescence_error'))
        result['export'] = {key: exported[key] for key in ('status', 'copied_files',
                             'logical_bytes', 'enumeration_complete', 'complete_local_retention')}
        result['external_allocated_bytes'] = external_bytes(p)
        require(result['external_allocated_bytes'] + 16384 <= EXTERNAL_METADATA,
                'actual external originals exceed capacity metadata admission')
        result['complete_local_retention'] = exported['complete_local_retention']
        if exported['status'] == 'PASS':
            result['status'] = 'PASS'
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result['error'] = error_text(error)
    write(p['local'] / 'capacity-capture.json', result)
    return result


def observe_mount(volume):
    raw = command(['findmnt', '--json', '--mountpoint', str(volume),
                   '-o', 'TARGET,FSTYPE,SOURCE,OPTIONS'], absent_ok=True)
    if raw is None:
        return None
    document = json.loads(raw, object_pairs_hook=bundle.unique_object)
    systems = document.get('filesystems', [])
    require(len(systems) == 1 and systems[0].get('target') == str(volume),
            'current exact capacity mount observation differs')
    return systems[0]


def observe_loops(image):
    raw = command(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                   '--output', 'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN'])
    document = json.loads(raw, object_pairs_hook=bundle.unique_object)
    require(isinstance(document.get('loopdevices'), list), 'loop observation is incomplete')
    return document['loopdevices']


def validate_unmount_binding(volume, image, info, mount, loops):
    """Pure observation check; a failed or absent quota receipt is irrelevant."""
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.getuid() and info.st_size == IMAGE_BYTES,
            'capacity image identity or exact size differs')
    require(mount.get('target') == str(volume) and mount.get('fstype') == 'ext4'
            and re.fullmatch('/dev/loop[0-9]+', str(mount.get('source', ''))),
            'refusing unmount of an unbound exact volume')
    require(len(loops) == 1 and loops[0].get('name') == mount['source']
            and loops[0].get('back-file') == str(image)
            and int(loops[0].get('back-ino', -1)) == info.st_ino
            and loops[0].get('back-maj:min') == str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev)),
            'live capacity loop backing pathname, inode or device differs')
    return image_identity(info)


def unmount(root=ROOT):
    p, ctx = paths(root), context(root)
    result = {'schema_version': 1, 'profile': PROFILE, 'run_context': ctx, 'status': 'FAIL',
              'image_path': str(p['image']), 'volume_path': str(p['volume']),
              'image_unmounted': False, 'image_removed': False, 'scope': SCOPE}
    try:
        try:
            result['quiescence'] = stage_quiescence(p, ctx)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            result['quiescence_error'] = error_text(error)
        if os.path.lexists(p['volume']):
            bundle.no_links(p['volume'])
        else:
            bundle.no_links(p['volume'].parent)
        mount = observe_mount(p['volume'])
        result['mount_before'] = mount
        image_exists = os.path.lexists(p['image'])
        result['image_exists'] = image_exists
        loops = observe_loops(p['image'])
        result['loops_before'] = loops
        if mount is None:
            require(not loops, 'unmounted capacity path still has a loop association')
            if image_exists:
                bundle.no_links(p['image']); info = p['image'].lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and info.st_uid == os.getuid(), 'unsafe unmounted capacity image')
                result['image_identity'] = image_identity(info)
            result.update(image_unmounted=True, already_unmounted=True)
        else:
            bundle.no_links(p['image']); info = p['image'].lstat()
            expected = validate_unmount_binding(p['volume'], p['image'], info, mount, loops)
            result['image_identity'] = expected
            require(image_identity(p['image'].lstat()) == expected,
                    'capacity image changed immediately before unmount')
            command(['sudo', '-n', 'umount', '--', str(p['volume'])])
            require(observe_mount(p['volume']) is None and not observe_loops(p['image']),
                    'capacity volume or backing loop remains active after exact unmount')
            bundle.no_links(p['image'])
            require(image_identity(p['image'].lstat()) == expected, 'capacity image changed during unmount')
            result.update(image_unmounted=True, already_unmounted=False)
        result['mount_after'] = observe_mount(p['volume'])
        result['loops_after'] = observe_loops(p['image'])
        require(result['mount_after'] is None and not result['loops_after'],
                'capacity mount absence could not be reconfirmed')
        if result.get('quiescence', {}).get('quiescent') is True:
            result['status'] = 'PASS'
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result.update(status='FAIL', image_unmounted=False, error=error_text(error))
    write(p['local'] / 'capacity-unmount.json', result)
    return result


class LimitedZipFile:
    """One seekable bounded file: even an invalid partial ZIP stays reserved."""
    def __init__(self, stream, limit):
        self.stream, self.limit = stream, limit

    def write(self, data):
        require(self.stream.tell() + len(data) <= self.limit, 'complete diagnostic ZIP exceeds hard byte bound')
        return self.stream.write(data)

    def seek(self, *args):
        return self.stream.seek(*args)

    def tell(self):
        return self.stream.tell()

    def flush(self):
        return self.stream.flush()


def zip_info(name, mode):
    bundle.safe_name(name)
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def verify_zip(path, expected, packet_manifest):
    """Read every byte; ZipExtFile also validates every member CRC on EOF."""
    bundle.no_links(path); before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= ZIP_BYTES,
            'diagnostic ZIP identity or byte bound differs')
    with zipfile.ZipFile(path, 'r') as archive:
        infos = archive.infolist()
        require(len(infos) == len(expected) and len({info.filename for info in infos}) == len(infos)
                and {info.filename for info in infos} == set(expected),
                'complete diagnostic ZIP membership differs')
        for info in infos:
            row = expected[info.filename]
            require(not info.is_dir() and not info.flag_bits & 1 and info.file_size == row['bytes']
                    and info.create_system == 3 and info.external_attr >> 16 == row['mode'],
                    'diagnostic ZIP full member identity differs')
            with archive.open(info) as stream:
                data = stream.read(row['bytes'] + 1)
                require(len(data) == row['bytes'] and stream.read(1) == b''
                        and hashlib.sha256(data).hexdigest() == row['sha256'],
                        'diagnostic ZIP member size, SHA or CRC differs')
            if info.filename == 'packet-manifest.json':
                require(json.loads(data, object_pairs_hook=bundle.unique_object) == packet_manifest,
                        'diagnostic ZIP complete manifest differs')
    require(bundle.signature(path.lstat()) == bundle.signature(before), 'diagnostic ZIP changed during verification')
    digest = bundle.file_sha(path)
    require(bundle.signature(path.lstat()) == bundle.signature(before), 'diagnostic ZIP changed during final SHA')
    return {'entries': len(expected), 'bytes': before.st_size,
            'sha256': digest, 'identity': list(bundle.signature(before)),
            'all_entries_crc_sha_identity_checked': True}


def make_packet(metadata, destination, ctx, execution_complete=False, volume_authorized=True,
                failure_reasons=(), allow_incomplete=False):
    """Package every retained original and manifest, including honest failures."""
    manifests, failures = [], list(failure_reasons)
    for kind in ('volume', 'outer'):
        try:
            manifests.append(verify_export(metadata, kind, ctx))
        except (OSError, ValueError, KeyError) as error:
            if not allow_incomplete:
                raise
            failures.append(kind + ' unfinished/corrupt capture: ' + error_text(error))
            manifests.append({'status': 'FAIL', 'complete_local_retention': False})
    require(not os.path.lexists(destination), 'refusing existing diagnostic packet directory')
    mkdir(destination)
    frozen = tree_identity(metadata)
    rows, expected = [], {}
    for path, info in tree_files(metadata):
        if not stat.S_ISREG(info.st_mode):
            continue
        require(len(rows) + 2 <= min(COPY_FILES, CAPTURE_FILES) and info.st_size <= COPY_BYTES,
                'aggregate complete packet file-count bound exceeded')
        require(info.st_size <= COPY_BYTES,
                'complete packet input file/count bound exceeded')
        name = 'metadata/' + path.relative_to(metadata).as_posix()
        bundle.safe_name(name)
        _, digest = artifacts.read_metadata(path, info, info.st_size)
        row = {'member': name, 'bytes': info.st_size, 'sha256': digest,
               'mode': info.st_mode, 'identity': list(bundle.signature(info))}
        rows.append(row); expected[name] = row
    record = {'schema_version': 1, 'profile': PROFILE, 'run_context': ctx,
              'status': 'PASS' if execution_complete and volume_authorized and all(m['complete_local_retention'] for m in manifests) else 'FAIL',
              'execution_complete': execution_complete,
              'complete_local_retention': volume_authorized and all(m['complete_local_retention'] for m in manifests),
              'failure_reasons': failures,
              'members': rows, 'data_upload_allowed': False,
              'scope': 'All available complete identity copies and manifests. Failed or incomplete capture remains explicit.'}
    manifest_raw = encode(record)
    require(sum(row['bytes'] for row in rows) + len(manifest_raw) <= min(COPY_BYTES, CAPTURE_BYTES),
            'aggregate complete packet decoded bytes including manifests exceeded')
    expected['packet-manifest.json'] = {'bytes': len(manifest_raw),
        'sha256': hashlib.sha256(manifest_raw).hexdigest(), 'mode': stat.S_IFREG | 0o600}
    output = destination / 'capacity-metadata.zip'
    with output.open('xb') as raw:
        with zipfile.ZipFile(LimitedZipFile(raw, ZIP_BYTES), 'w', compression=zipfile.ZIP_DEFLATED,
                             compresslevel=6, allowZip64=False) as archive:
            for row in rows:
                path = metadata / row['member'].removeprefix('metadata/')
                info = path.lstat()
                require(list(bundle.signature(info)) == row['identity'], 'packet original changed before ZIP write')
                data, digest = artifacts.read_metadata(path, info, info.st_size)
                require(digest == row['sha256'], 'packet original SHA changed before ZIP write')
                archive.writestr(zip_info(row['member'], row['mode']), data)
            archive.writestr(zip_info('packet-manifest.json', stat.S_IFREG | 0o600), manifest_raw)
    require(tree_identity(metadata) == frozen, 'retained original tree changed during packet creation')
    proof = verify_zip(output, expected, record)
    require(physical(destination) <= PACKET_BYTES, 'actual diagnostic packet allocation exceeds reservation')
    return output, record, proof


def actual_admission(base, image_bytes, metadata_bytes, packet_bytes):
    require(type(base) is int and base >= 2_000_000_000, 'actual baseline lacks global reserve')
    for value in (image_bytes, metadata_bytes, packet_bytes):
        require(type(value) is int and 0 <= value <= 15_000_000_000, 'invalid actual allocation input')
    peak = base + image_bytes + metadata_bytes + PACKET_BYTES + CLOUD_METADATA + OVERHEAD_BYTES
    allowed = (image_bytes <= IMAGE_BYTES + 4096
               and metadata_bytes <= EXTERNAL_METADATA and packet_bytes <= PACKET_BYTES and peak < CEILING)
    return {'metadata_allowed': allowed, 'data_allowed': False, 'data_upload_allowed': False,
            'actual_global_peak_bytes': peak, 'actual_image_allocated_bytes': image_bytes,
            'actual_external_allocated_bytes': metadata_bytes, 'actual_packet_allocated_bytes': packet_bytes,
            'reserved_packet_bytes': PACKET_BYTES, 'reserved_cloud_bytes': CLOUD_METADATA,
            'reserved_overhead_bytes': OVERHEAD_BYTES}


def workflow_outputs(result):
    output = os.environ.get('GITHUB_OUTPUT')
    if not output:
        return
    values = {'metadata_allowed': str(result.get('metadata_allowed') is True).lower(),
              'data_allowed': 'false', 'data_upload_allowed': 'false'}
    if result.get('metadata_allowed') is True:
        values['packet_path'] = result['packet_path']
    with open(output, 'a', encoding='utf-8') as stream:
        for key, value in values.items():
            require('\n' not in value and '\r' not in value, 'invalid capacity workflow output')
            stream.write(key + '=' + value + '\n')


def packet(root=ROOT):
    p, ctx = paths(root), context(root)
    result = {'schema_version': 1, 'profile': PROFILE, 'run_context': ctx,
              'status': 'FAIL', 'metadata_allowed': False, 'data_allowed': False,
              'data_upload_allowed': False, 'complete_local_retention': False, 'scope': SCOPE}
    try:
        assert_outside_evidence_wrapper(p)
        failures = []
        quiet = {'quiescent': False, 'execution_complete': False}
        try:
            quiet = stage_quiescence(p, ctx)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            failures.append('quiescence: ' + error_text(error))
        result['quiescence'] = quiet
        safe_unmounted = False
        try:
            cleanup = load(p['local'] / 'capacity-unmount.json')
            require(cleanup.get('run_context') == ctx and cleanup.get('image_unmounted') is True
                    and cleanup.get('status') == 'PASS', 'capacity volume lacks current exact unmount proof')
            require(observe_mount(p['volume']) is None and not observe_loops(p['image']),
                    'capacity image is mounted or associated during packet creation')
            safe_unmounted = True
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            failures.append('unmount: ' + error_text(error))
        result['cleanup_failures'] = failures
        used = external_bytes(p)
        outer = export_tree(p['local'], p['metadata'] / 'outer', 'outer', ctx, used)
        result['outer_complete_local_retention'] = outer['complete_local_retention']
        # Never read an unproven live inner tree to recover a missing capture.
        # Closed outer evidence remains independently useful after cleanup fails.
        if not os.path.lexists(p['metadata'] / 'volume-manifest.json'):
            mkdir(p['metadata'] / 'volume')
            write(p['metadata'] / 'volume-manifest.json', {
                'schema_version': 1, 'profile': PROFILE, 'kind': 'volume',
                'source_root': str(p['source'] / '.local'), 'run_context': ctx,
                'status': 'FAIL', 'enumeration_complete': False, 'complete_local_retention': False,
                'files': [], 'directories': [], 'logical_bytes': 0, 'copied_files': 0,
                'error': 'No complete closed-writer inner capture is available; outer diagnostics retained.'})
        path, manifest, proof = make_packet(p['metadata'], p['packet'], ctx,
            quiet['execution_complete'], quiet.get('quiescent') is True and safe_unmounted, failures,
            allow_incomplete=True)
        result.update(packet_path=str(path), packet=proof,
                      complete_local_retention=manifest['complete_local_retention'])
        image_bytes = 0
        if os.path.lexists(p['image']):
            bundle.no_links(p['image']); info = p['image'].lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(),
                    'unsafe retained capacity image')
            image_bytes = allocated(info)
        # Reserve the terminal external receipt before reporting admission.
        admission = actual_admission(int(os.environ['FQ_ACCOUNTED_BASE_BYTES']), image_bytes,
                                     external_bytes(p) + 65536, physical(p['packet']))
        result.update(admission)
        require(result['metadata_allowed'], 'actual complete diagnostic upload admission refused')
        result['status'] = 'PASS' if manifest['complete_local_retention'] and quiet['execution_complete'] else 'FAIL'
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        result.update(status='FAIL', metadata_allowed=False, error=error_text(error))
    mkdir(p['metadata'])
    write(p['metadata'] / 'packet-result.json', result)
    # Terminal receipt itself is attributable; outputs become true only after it
    # and every retained partial packet have been physically accounted for.
    try:
        require(external_bytes(p) <= EXTERNAL_METADATA and physical(p['packet']) <= PACKET_BYTES,
                'terminal external allocations exceed capacity reservations')
        if result['metadata_allowed']:
            require(bundle.file_sha(Path(result['packet_path'])) == result['packet']['sha256'],
                    'verified diagnostic ZIP changed before workflow output')
    except (OSError, ValueError) as error:
        result.update(status='FAIL', metadata_allowed=False, terminal_error=error_text(error))
    workflow_outputs(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('plan')
    snapshot = sub.add_parser('sample'); snapshot.add_argument('--name', required=True)
    runner = sub.add_parser('stage'); runner.add_argument('--name', required=True)
    runner.add_argument('--timeout', type=int, choices=(780, 300, 120), required=True)
    runner.add_argument('command', nargs=argparse.REMAINDER)
    for action in ('capture', 'unmount', 'packet'):
        sub.add_parser(action)
    args = parser.parse_args()
    try:
        if args.action == 'stage':
            argv = args.command[1:] if args.command[:1] == ['--'] else args.command
            result = stage(args.name, args.timeout, argv)
        elif args.action == 'sample':
            result = sample(args.name)
        else:
            result = {'plan': plan, 'capture': capture, 'unmount': unmount, 'packet': packet}[args.action]()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result = {'status': 'FAIL', 'profile': PROFILE, 'action': args.action,
                  'error': error_text(error), 'data_upload_allowed': False}
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result.get('status') == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
