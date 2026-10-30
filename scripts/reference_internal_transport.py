"""Package reference members inside their retained, admitted outer image.

This is a distinct Actions profile. Its external directory contains only audit
and provenance files; package data never has an external copy. Local controls
exercise refusals and byte comparisons, not an actual Linux quota or recovery.
"""
from __future__ import annotations

# The CLI passes this entry timestamp to its independent parent supervisor.
# Imports, argument parsing and admission are part of the whole-phase budget.
import time
ENTRY_STARTED = time.monotonic()

import argparse
import functools
import hashlib
import json
import math
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

from common import ROOT, EXCLUDED
import evidence_bundle as bundle
import reference_artifacts as artifacts
import reference_preflight as preflight
import reference_results as results
import reference_retention as retention

PROFILE = 'reference-inside-outer-v1'
REPOSITORY = 'C-X1an/facetquarry'
REPOSITORY_ID = 1430604581
IMAGE_BYTES = 2_300_000_000
PROBE_BYTES = 2_400_000_000
GLOBAL_RESERVE = 2_000_000_000
FILESYSTEM_FLOOR = 500_000_000
CONTROL_ALLOCATION = 20_000_000
CONTROL_ENTRIES = 64
PROVENANCE_BYTES = 80_000_000
PROVENANCE_ENTRIES = 10_000
TRIM_PROOF_BYTES = 8_000_000
JOB_SECONDS = 360 * 60
PACK_CHILD_SECONDS = 1500
PACK_VERIFY_SECONDS = 210
PACK_WRAPPER_SECONDS = 210
PACK_TOTAL_SECONDS = PACK_CHILD_SECONDS + PACK_WRAPPER_SECONDS
FREEZE_SECONDS = 180
FAILURE_TAIL_SECONDS = 1200
REFUSAL_ALLOCATION = 131_072
REFUSAL_BYTES = 32_768
SCOPE = ('Complete member transport inside the retained outer image. '
         'No external package copy, outer-image removal, benchmark qualification, '
         'or admission inherited from another profile.')


def require(condition, message):
    if not condition:
        raise ValueError(message)


class EntryBudget:
    """Count every discovered entry before retaining it, across all roots."""
    def __init__(self, limit):
        require(type(limit) is int and limit > 0, 'invalid enumeration bound')
        self.limit, self.discovered = limit, 0

    def admit(self):
        require(self.discovered < self.limit, 'transport enumeration entry bound exceeded')
        self.discovered += 1


def bounded_children(path, budget):
    names = []
    with os.scandir(path) as entries:
        for entry in entries:
            budget.admit()  # Before append AND before sorting/materialization.
            names.append(entry.name)
    return [path / name for name in sorted(names)]


def bounded_tree(roots, limit, *, excluded=frozenset()):
    """Bound visited plus pending entries, including excluded directory names."""
    budget, stack = EntryBudget(limit), []
    for root in roots:
        budget.admit()
        stack.append(Path(root))
    stack.reverse()
    while stack:
        path = stack.pop()
        info = preflight.checked(path)
        yield path, info
        if stat.S_ISDIR(info.st_mode):
            children = bounded_children(path, budget)
            stack.extend(child for child in reversed(children) if child.name not in excluded)


def admit_tree(roots, limit):
    return sum(1 for _ in bounded_tree(roots, limit))


def bounded_source_hash(project):
    """The common source digest, with bounded enumeration before os.walk."""
    selected = []
    for path, info in bounded_tree([project], preflight.MAX_ENTRIES, excluded=EXCLUDED):
        if not stat.S_ISREG(info.st_mode) or path.name in EXCLUDED:
            continue
        relative = path.relative_to(project)
        if (path.suffix in {'.go', '.py', '.mod', '.yml', '.yaml', '.toml'}
                or path.name in {'Makefile', '.go-version', '.gitignore', '.gitattributes',
                                 'go.sum', 'ACCEPTANCE_SPEC.md', 'phase_definitions.json', 'locks.json'}
                or path.suffix == '.json' and relative.parts[0] in {'examples', 'benchmarks'}):
            selected.append(path)
    digest = hashlib.sha256()
    for path in sorted(selected, key=lambda item: item.relative_to(project).as_posix()):
        digest.update(path.relative_to(project).as_posix().encode() + b'\0')
        digest.update(bytes.fromhex(file_sha(path, preflight.MAX_FILE_BYTES)))
    return digest.hexdigest()


def bounded_phase(seconds):
    """Enforce new-profile wrapper/verification bounds on the Linux main thread."""
    def decorate(function):
        @functools.wraps(function)
        def bounded(*args, **kwargs):
            require(sys.platform == 'linux' and threading.current_thread() is threading.main_thread()
                    and hasattr(signal, 'setitimer'), 'transport phase deadline requires the Linux main thread')
            require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
                    'transport cannot replace an unrelated active phase timer')
            previous = signal.getsignal(signal.SIGALRM)
            def expired(signum, frame):
                raise TimeoutError('inside-outer phase exceeded its admitted ' + str(seconds) + ' second bound')
            signal.signal(signal.SIGALRM, expired)
            signal.setitimer(signal.ITIMER_REAL, seconds)
            try:
                return function(*args, **kwargs)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)
        return bounded
    return decorate


def growth_plan(base, image_bytes=IMAGE_BYTES):
    """Count the contained package once, including the exact-image failure tail."""
    require(type(base) is int and base >= GLOBAL_RESERVE,
            'fresh accounted baseline must include the unchanged global 2GB reserve')
    require(type(image_bytes) is int and image_bytes == IMAGE_BYTES,
            'inside-outer profile requires the exact 2.3GB outer image')
    metadata = artifacts.EXTERNAL_METADATA_ALLOCATION + artifacts.PACKET_ALLOCATION
    branches = {
        'packing_with_live_image': image_bytes + metadata + artifacts.OVERHEAD,
        'verified_bundle_upload_with_retained_image': image_bytes + 450_000_000
            + metadata + artifacts.METADATA_ZIP + artifacts.OVERHEAD,
        'failed_pack_exact_results_image_upload': image_bytes + artifacts.IMAGE_ZIP
            + metadata + artifacts.METADATA_ZIP + artifacts.OVERHEAD,
    }
    maximum = max(branches.values())
    return {'schema_version': 1, 'profile': PROFILE, 'scope': SCOPE,
            'baseline_includes_global_reserve': base,
            'outer_image_bytes': IMAGE_BYTES, 'nested_results_image_bytes': artifacts.RESULTS_IMAGE,
            'package_allocation_inside_outer_bytes': artifacts.PACKAGE_ALLOCATION,
            'filesystem_free_floor_bytes': FILESYSTEM_FLOOR,
            'external_metadata_allocation_bytes': artifacts.EXTERNAL_METADATA_ALLOCATION,
            'diagnostic_packet_allocation_bytes': artifacts.PACKET_ALLOCATION,
            'cloud_metadata_bytes': artifacts.METADATA_ZIP,
            'overhead_bytes': artifacts.OVERHEAD,
            'branches': branches, 'maximum_new_stage_bytes': maximum,
            'peak_bytes': base + maximum, 'ceiling_bytes': artifacts.CEILING,
            'admission': 'ALLOW' if base + maximum < artifacts.CEILING else 'REFUSE',
            'outer_image_retained_through_upload': True,
            'external_package_copy_allowed': False,
            'required_upload_policy': 'Exactly one verified bundle or exact frozen results image; never both. The package and any retained partial are already contained in the retained outer image.'}


def bind_context(environ, commit, git_status, digest, ordinary_linux):
    """Pure identity validation; callers must supply actual observations."""
    require(ordinary_linux, 'inside-outer transport requires an ordinary nonroot Linux runner')
    require(environ.get('GITHUB_ACTIONS') == 'true'
            and environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and environ.get('GITHUB_REPOSITORY_ID') == str(REPOSITORY_ID)
            and environ.get('GITHUB_JOB') == 'reference'
            and environ.get('FQ_RESERVATION_PROFILE') == PROFILE,
            'inside-outer transport requires the exact repository, reference job and profile')
    run, attempt = environ.get('GITHUB_RUN_ID', ''), environ.get('GITHUB_RUN_ATTEMPT', '')
    require(all(re.fullmatch('[1-9][0-9]{0,19}', value) for value in (run, attempt)),
            'actual run and attempt identities are required')
    require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit)
            and commit == environ.get('GITHUB_SHA') and git_status == '',
            'checkout must be clean and equal the actual Actions commit')
    require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest),
            'source identity must be a SHA256')
    return {'profile': PROFILE, 'job': 'reference', 'repository': REPOSITORY,
            'repository_id': REPOSITORY_ID, 'source': digest, 'commit': commit,
            'git_status': '', 'github_run_id': run, 'github_run_attempt': attempt}


def legacy_context(ctx):
    """Keep the results-image proof contract unchanged."""
    return {key: ctx[key] for key in ('commit', 'git_status', 'github_run_id', 'github_run_attempt')}


def command(argv, *, timeout=10, accepted=(0,)):
    require(type(timeout) is int and 1 <= timeout <= 120, 'observation timeout exceeds bounds')
    # Capture is bounded while reading, rather than after communicate() has
    # already materialized arbitrary output. Privileged observations also have
    # their own root-owned timeout if the ordinary payload is killed.
    actual = argv
    if argv[:2] == ['sudo', '-n']:
        actual = ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=2s',
                  str(timeout) + 's', *argv[2:]]
    proc = subprocess.Popen(actual, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=(os.name == 'posix'))
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    end = time.monotonic() + timeout
    selection = selectors.DefaultSelector()
    try:
        for label, pipe in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selection.register(pipe, selectors.EVENT_READ, label)
        while selection.get_map() or proc.poll() is None:
            require(time.monotonic() < end, 'transport observation exceeded its deadline')
            for key, _ in selection.select(min(.05, max(0, end - time.monotonic()))):
                data = os.read(key.fileobj.fileno(), 4096)
                if not data:
                    selection.unregister(key.fileobj)
                    continue
                require(sum(map(len, output.values())) + len(data) <= 32768,
                        'transport observation output exceeded its bound')
                output[key.data].extend(data)
        require(proc.returncode in accepted, 'bounded transport observation failed: ' + str(argv[:2]))
        return {'command': argv, 'actual_command': actual, 'exit_code': proc.returncode,
                **{key: bytes(value).decode('utf-8', errors='strict') for key, value in output.items()}}
    finally:
        selection.close()
        if proc.poll() is None:
            if os.name == 'posix':
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                proc.kill()
            proc.wait(timeout=2)
        for pipe in (proc.stdout, proc.stderr):
            pipe.close()


def context(project=ROOT):
    ordinary = sys.platform == 'linux' and os.name == 'posix' and os.getuid() != 0
    require(ordinary, 'inside-outer transport requires an ordinary nonroot Linux runner')
    preflight.checked(project)
    commit = command(['git', '-C', str(project), 'rev-parse', 'HEAD'])['stdout'].strip()
    state = command(['git', '-C', str(project), 'status', '--porcelain', '--untracked-files=normal'])['stdout'].strip()
    return bind_context(os.environ, commit, state, bounded_source_hash(project), ordinary)


def image_identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_size]


def normalized(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and str(path) == os.path.abspath(path),
            'transport paths must be absolute and normalized')
    return path


def paths(volume, project, root=ROOT):
    volume, project, root = map(normalized, (volume, project, root))
    temporary = normalized(os.environ['RUNNER_TEMP'])
    workspace = normalized(os.environ['GITHUB_WORKSPACE'])
    require(root == workspace and volume == temporary / 'facetquarry-reference'
            and project == volume / 'source', 'transport requires exact owned source, volume and outer checkout')
    require(not root.is_relative_to(volume) and not volume.is_relative_to(root)
            and root != temporary, 'audit checkout overlaps the admitted image or its parent')
    for path in (temporary, root, volume, project):
        require(stat.S_ISDIR(preflight.checked(path).st_mode), 'owned path is not a directory')
    require(project.lstat().st_dev == volume.lstat().st_dev
            and root.lstat().st_dev != volume.lstat().st_dev,
            'source or external audit is on the wrong filesystem')
    image = temporary / 'facetquarry-reference.img'
    require(os.environ.get('FQ_VOLUME', str(volume)) == str(volume)
            and os.environ.get('FQ_IMAGE', str(image)) == str(image)
            and os.environ.get('FQ_WORKSPACE_ROOT') == str(volume),
            'configured workspace/image/volume conflicts with exact owned paths')
    local = root / '.local'
    preflight.checked(local)
    return {'volume': volume, 'project': project, 'outer': root, 'local': local,
            'image': image, 'data': volume / 'reference-transport',
            'package': volume / 'reference-transport/reference-members.tar.xz',
            'audit': local / 'reference-transport'}


def file_sha(path, limit, expected=None, *, checkpoint=None):
    """Hash the exact single-link inode, including packages larger than 256MB."""
    info = preflight.checked(path)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
            'transport file type, link count or byte bound differs')
    expected = tuple(expected) if expected is not None else preflight.stamp(info)
    require(preflight.stamp(info) == expected, 'transport file changed before hashing')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    digest, count = hashlib.sha256(), 0
    try:
        require(preflight.descriptor_matches(os.fstat(descriptor), expected), 'transport descriptor differs')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            while data := stream.read(1024 * 1024):
                count += len(data)
                require(count <= info.st_size, 'transport file grew while hashing')
                digest.update(data)
                if checkpoint is not None:
                    checkpoint('during_hashing')
                    checkpoint = None
        require(count == info.st_size and preflight.descriptor_matches(os.fstat(descriptor), expected)
                and preflight.stamp(preflight.checked(path)) == expected,
                'transport file or pathname changed while hashing')
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def read_json(path, limit=1_000_000):
    info = preflight.checked(path)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
            'transport JSON exceeds its complete producer bound')
    data, _ = artifacts.read_metadata(path, info, info.st_size)
    return json.loads(data, object_pairs_hook=bundle.unique_object)


def write_small(path, record, *, replace=False):
    require(len((json.dumps(record, sort_keys=True) + '\n').encode()) <= 1_000_000,
            'transport receipt exceeds complete producer bound')
    artifacts.write_json(path, record, replace=replace)


def validate_documents(volume, image_bytes, mount, loops, quota, planned, ctx,
                       enospc, expected_baseline):
    """Validate the new proof directly, without weakening a legacy plan."""
    image = volume.with_name(volume.name + '.img')
    require(volume.name == 'facetquarry-reference' and ctx.get('profile') == PROFILE
            and ctx.get('job') == 'reference' and ctx.get('repository') == REPOSITORY
            and ctx.get('repository_id') == REPOSITORY_ID
            and quota.get('profile') == PROFILE and quota.get('profile_context') == ctx,
            'transport reservation profile, repository, job or source differs')
    require(image_bytes == IMAGE_BYTES and quota.get('volume_file_bytes') == IMAGE_BYTES
            and quota.get('oversized_allocation_bytes') == PROBE_BYTES
            and quota.get('oversized_allocation') == 'DENIED_ENOSPC'
            and quota.get('hard_quota_enforced') is True
            and quota.get('enospc_sha256') == hashlib.sha256(enospc).hexdigest()
            and b'No space left on device' in enospc, 'actual inside-outer quota refusal proof differs')
    require(quota.get('run_context') == legacy_context(ctx) and not ctx.get('git_status')
            and quota.get('volume_path') == str(volume) and quota.get('image_path') == str(image)
            and quota.get('mount') == mount and mount.get('target') == str(volume)
            and mount.get('fstype') == 'ext4'
            and re.fullmatch('/dev/loop[0-9]+', str(mount.get('source', ''))),
            'transport filesystem floor belongs to another execution or mount')
    devices = loops.get('loopdevices', [])
    require(len(devices) == 1 and devices[0].get('name') == mount['source']
            and devices[0].get('back-file') == str(image), 'transport outer backing differs')
    expected = {**growth_plan(expected_baseline, image_bytes), 'run_context': ctx}
    require(planned == expected and expected['admission'] == 'ALLOW',
            'inside-outer plan differs from the exact fresh baseline or is refused')
    return {'profile': PROFILE, 'global_reserved_growth_bytes': GLOBAL_RESERVE,
            'filesystem_free_floor_bytes': FILESYSTEM_FLOOR,
            'global_peak_bytes': expected['peak_bytes'], 'run_context': ctx, 'scope': SCOPE}


def observe_outer(volume, project, *, quota_root=None):
    """Bind the current ENOSPC proof to the observed mount and exact backing."""
    require(os.environ.get('FQ_RESERVATION_PROFILE') == PROFILE, 'unknown or wrong transport profile')
    require(volume == normalized(os.environ['RUNNER_TEMP']) / 'facetquarry-reference'
            and os.environ.get('FQ_WORKSPACE_ROOT') == str(volume), 'unexpected reservation root')
    image = volume.with_name(volume.name + '.img')
    before = preflight.checked(image)
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and before.st_nlink == 1 and before.st_size == IMAGE_BYTES,
            'outer backing type, owner, links or size differs')
    ctx = context(project)
    mount_observed = json.loads(command(['findmnt', '--json', '--target', str(volume),
                                         '-o', 'TARGET,FSTYPE,SOURCE'])['stdout'])
    loop_observed = json.loads(command(['sudo', '-n', 'losetup', '--json', '--list', '--associated',
                                        str(image), '--output', 'NAME,BACK-FILE'])['stdout'])
    binding = results.mount_binding(volume, image, mount_observed, loop_observed)
    local = quota_root or project / '.local'
    quota = read_json(local / 'reference-quota.json')
    plan = read_json(local / 'reference-admission.json')
    enospc_path = local / 'enospc.stderr'
    enospc_info = preflight.checked(enospc_path)
    require(stat.S_ISREG(enospc_info.st_mode) and enospc_info.st_nlink == 1
            and enospc_info.st_size <= 32768, 'ENOSPC stream exceeds its producer bound')
    enospc, _ = artifacts.read_metadata(enospc_path, enospc_info, enospc_info.st_size)
    require(quota.get('backing_identity') == image_identity(before),
            'outer backing changed since its actual ENOSPC refusal')
    proof = validate_documents(volume, before.st_size, binding['mount'], loop_observed,
                               quota, plan, ctx, enospc, int(os.environ['FQ_ACCOUNTED_BASE_BYTES']))
    if os.environ.get('FQ_FILESYSTEM_POLICY') or quota.get('filesystem_policy'):
        from reference_filesystem import POLICY
        from reference_filesystem_bindings import validate
        require(os.environ.get('FQ_FILESYSTEM_POLICY') == quota.get('filesystem_policy') == POLICY,
                'declared filesystem policy is missing or differs')
        filesystem = validate(Path(os.environ['GITHUB_WORKSPACE']) / '.local/reference-filesystem/outer',
                              image, volume, IMAGE_BYTES, {**legacy_context(ctx), 'source': ctx['source']})
        require(filesystem == quota.get('filesystem_proof'), 'retained filesystem proof changed')
        proof.update(filesystem_policy=POLICY, filesystem_proof=filesystem)
    require(image_identity(preflight.checked(image)) == image_identity(before),
            'outer backing changed during observation')
    return {**proof, 'binding': binding, 'backing_identity': image_identity(before)}


def verify(root, global_reserve, filesystem_floor):
    """disk_guard entry point, including a clean clone inside this same volume."""
    require(sys.platform == 'linux' and os.name == 'posix' and os.getuid() != 0,
            'inside-outer floor override requires an ordinary Linux runner')
    require(global_reserve == GLOBAL_RESERVE and filesystem_floor == FILESYSTEM_FLOOR
            and os.environ.get('FQ_RESERVATION_PROFILE') == PROFILE,
            'unsupported inside-outer reserve override')
    volume = normalized(os.environ['RUNNER_TEMP']) / 'facetquarry-reference'
    require(Path(root) == volume, 'inside-outer floor requires the exact volume root')
    project = volume / 'source'
    for path in (volume, project, ROOT):
        preflight.checked(path)
    require(ROOT.is_relative_to(volume) and ROOT != volume
            and ROOT.lstat().st_dev == volume.lstat().st_dev
            and project.lstat().st_dev == volume.lstat().st_dev
            and bounded_source_hash(ROOT) == bounded_source_hash(project),
            'current source or clean clone is outside the admitted image or differs')
    observed = observe_outer(volume, project)
    require(context(ROOT) == observed['run_context'], 'current source/clean clone commit or source differs')
    return observed


def physical_admission(free_bytes):
    require(type(free_bytes) is int and free_bytes >= 0, 'invalid actual filesystem availability')
    required = artifacts.PACKAGE_ALLOCATION + FILESYSTEM_FLOOR + CONTROL_ALLOCATION
    return {'allowed': free_bytes >= required, 'actual_available_bytes': free_bytes,
            'package_allocation_bytes': artifacts.PACKAGE_ALLOCATION,
            'filesystem_free_floor_bytes': FILESYSTEM_FLOOR,
            'control_allocation_bytes': CONTROL_ALLOCATION, 'required_available_bytes': required}


def time_admission(started_epoch, now_epoch, phase='pack'):
    require(phase in ('pack', 'verify', 'reconcile'), 'unknown transport time phase')
    require(all(type(value) in (int, float) and math.isfinite(value) and value > 0
                for value in (started_epoch, now_epoch)) and now_epoch >= started_epoch,
            'missing, nonfinite, future or rolled-back actual job clock')
    phase_seconds = PACK_VERIFY_SECONDS
    if phase == 'pack':
        phase_seconds += PACK_CHILD_SECONDS + PACK_WRAPPER_SECONDS
    elif phase == 'reconcile':
        phase_seconds = FREEZE_SECONDS
    deadline = started_epoch + JOB_SECONDS
    # Reconciliation is the first part of the already reserved 1200s failure
    # tail, rather than a fresh 1200s tail after that same tail has begun.
    required = FAILURE_TAIL_SECONDS if phase == 'reconcile' else phase_seconds + FAILURE_TAIL_SECONDS
    return {'allowed': now_epoch + required < deadline, 'phase': phase,
            'job_started_epoch': started_epoch, 'observed_epoch': now_epoch,
            'absolute_job_deadline_epoch': deadline, 'remaining_seconds': deadline - now_epoch,
            'phase_seconds': phase_seconds, 'complete_failure_tail_seconds': FAILURE_TAIL_SECONDS,
            'required_remaining_seconds': required,
            'failure_tail_available': now_epoch + FAILURE_TAIL_SECONDS < deadline}


def current_time_admission(phase):
    raw = os.environ.get('FQ_REFERENCE_JOB_STARTED_EPOCH', '')
    require(re.fullmatch('[1-9][0-9]{8,11}', raw), 'actual job initialization timestamp is required')
    return time_admission(int(raw), time.time(), phase)


def closed_guest(p, ctx):
    """Require the complete unchanged results setup and positively idle units."""
    owned = results.owned_paths(p['volume'], p['project'])
    canonical = results.read_json(owned['proof'])
    require(canonical.get('status') == 'PASS' and canonical.get('source') == ctx['source']
            and canonical.get('run_context') == legacy_context(ctx)
            and canonical.get('paths') == {key: str(value) for key, value in owned.items()}
            and canonical.get('image_bytes') == artifacts.RESULTS_IMAGE,
            'complete current nested-results setup is required')
    outer = results.validate_outer(owned, command, legacy_context(ctx))
    require(outer == canonical.get('outer'), 'results outer proof or backing changed')
    nested = results.observe_binding(owned['mount'], owned['image'], command)
    require(nested == canonical.get('nested_binding')
            and nested['mount']['source'] != outer['binding']['mount']['source']
            and results.fixed_identity(owned['image']) == canonical.get('image_identity')
            and results.identity(owned['mount'])[:5] == canonical.get('mount_identity')
            and owned['mount'].lstat().st_dev != p['volume'].lstat().st_dev,
            'nested results mount, backing or identity differs')
    validate_nested_filesystem(owned, canonical, ctx, live_mount=True)
    guest = p['volume'] / 'reference-guest'
    if os.path.lexists(guest):
        quiescence = results.read_json(p['volume'] / 'reference-guest-quiescence.json')
        require(quiescence.get('status') == 'PASS' and quiescence.get('source') == ctx['source']
                and quiescence.get('run_context') == legacy_context(ctx)
                and quiescence.get('guest_setup_sha256') == preflight.file_sha(guest / 'setup.json'),
                'complete current guest quiescence proof is required')
    inactive = results.assert_no_active_guest(p['volume'], p['project'], canonical, command)
    return {'canonical': canonical, 'inactive_guest': inactive}


def validate_nested_filesystem(owned, canonical, ctx, *, live_mount):
    """Bind actual canonical nested receipts in either lifecycle state.

    Retained validation reauthenticates the original observations; the freeze
    path separately proves unmount/loop absence and hashes the complete image.
    """
    selected = os.environ.get('FQ_NESTED_FILESYSTEM_POLICY', '')
    if os.environ.get('FQ_FILESYSTEM_POLICY') or selected or canonical.get('filesystem_policy'):
        from reference_filesystem import POLICY, NESTED_POLICY
        from reference_filesystem_bindings import validate, validate_retained
        # Legacy v1 summaries retain their original validator contract. A new
        # nested summary always needs its separate explicit workflow selection.
        declared = canonical.get('filesystem_policy')
        expected = NESTED_POLICY if selected or declared == NESTED_POLICY else POLICY
        require(os.environ.get('FQ_FILESYSTEM_POLICY') == POLICY and declared == expected
                and (selected == NESTED_POLICY if expected == NESTED_POLICY else not selected),
                'declared nested filesystem policy is missing or differs')
        validator = validate if live_mount else validate_retained
        summary = validator(Path(os.environ['GITHUB_WORKSPACE']) / '.local/reference-filesystem/nested',
                            owned['image'], owned['mount'], artifacts.RESULTS_IMAGE,
                            {**legacy_context(ctx), 'source': ctx['source']}, policy=expected)
        require(summary == canonical.get('filesystem_proof'), 'retained nested filesystem proof changed')


def physical_tree(root, *, include_entries=False):
    """Actual bounded external allocation; links and hardlinks refuse growth."""
    total, count = 0, 0
    for path, info in bounded_tree([root], PROVENANCE_ENTRIES):
        count += 1
        if stat.S_ISDIR(info.st_mode):
            total += getattr(info, 'st_blocks', 0) * 512
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    'unsafe external allocation')
            total += max(info.st_size, getattr(info, 'st_blocks', 0) * 512)
        require(total <= artifacts.EXTERNAL_METADATA_ALLOCATION, 'external metadata allocation exceeds reservation')
    return {'accounted_bytes': total, 'entries': count} if include_entries else total


def external_admission(p):
    """Reserve the complete control producer before any audit allocation."""
    current = physical_tree(p['local'], include_entries=True)
    existing, entries = current['accounted_bytes'], current['entries']
    available = shutil.disk_usage(p['local']).free
    ceiling = artifacts.EXTERNAL_METADATA_ALLOCATION
    return {'allowed': (existing + CONTROL_ALLOCATION <= ceiling and available >= CONTROL_ALLOCATION
                        and entries + CONTROL_ENTRIES <= PROVENANCE_ENTRIES),
            'actual_existing_bytes': existing, 'actual_available_bytes': available,
            'actual_existing_entries': entries, 'complete_control_entry_reservation': CONTROL_ENTRIES,
            'external_entry_ceiling': PROVENANCE_ENTRIES,
            'complete_control_allocation_bytes': CONTROL_ALLOCATION,
            'external_metadata_ceiling_bytes': ceiling,
            'refusal_allocation_bytes': REFUSAL_ALLOCATION,
            'refusal_allowed': (existing + REFUSAL_ALLOCATION <= ceiling and available >= REFUSAL_ALLOCATION
                                and entries + 1 <= PROVENANCE_ENTRIES)}


def provenance_entry_admission(existing_entries, manifest, guest):
    """Count one copy root, every copied inode and synthesized parent once."""
    require(type(existing_entries) is int and 0 <= existing_entries <= PROVENANCE_ENTRIES,
            'invalid existing external entry count')
    names = set()
    for item in manifest['entries']:
        relative = (guest.parent / item['path']).relative_to(guest)
        for length in range(1, len(relative.parts) + 1):
            name = Path(*relative.parts[:length]).as_posix()
            if name not in names:
                require(len(names) < PROVENANCE_ENTRIES,
                        'complete provenance copy entries exceed external entry reservation')
                names.add(name)
    copied = 1 + len(names)  # Destination root is not in the source manifest.
    maximum = existing_entries + copied + CONTROL_ENTRIES
    return {'allowed': maximum <= PROVENANCE_ENTRIES, 'actual_existing_entries': existing_entries,
            'external_provenance_new_entries': copied,
            'complete_control_entry_reservation': CONTROL_ENTRIES,
            'maximum_external_entries': maximum, 'external_entry_ceiling': PROVENANCE_ENTRIES}


def preserve_refusal(p, ctx, phase, admission, error):
    """A separately admitted small refusal never creates the normal audit tree."""
    record = {'schema_version': 1, 'profile': PROFILE, 'status': 'FAIL', 'phase': phase,
              'source': ctx['source'], 'run_context': ctx, 'worker_started': False,
              'external_admission': admission, 'error': str(error)[:2000],
              'complete_scientific_preservation': False, 'scope': SCOPE}
    if admission.get('refusal_allowed'):
        target = p['local'] / ('reference-transport-' + phase + '-refusal.json')
        require(not os.path.lexists(target), 'previous transport refusal is retained')
        require(len((json.dumps(record, sort_keys=True) + '\n').encode()) <= REFUSAL_BYTES,
                'refusal exceeds its separate allocation')
        write_small(target, record)
        record['refusal_path'] = str(target)
    return record


def guest_selections(volume, ctx):
    """Choose only individually proved payloads and all remaining diagnostics."""
    guest = volume / 'reference-guest'
    preflight.checked(guest, volume)
    setup = read_json(guest / 'setup.json', 16_000_000)
    require(setup.get('source') == ctx['source'] and setup.get('run_context') == legacy_context(ctx)
            and setup.get('status') in ('PASS', 'FAIL'), 'guest setup must be terminal and current')
    candidates, diagnostics = [], []
    records = setup.get('packages', [])
    require(isinstance(records, list), 'invalid guest package provenance')
    archives = {}
    for item in records:
        name = item.get('archive')
        require(isinstance(name, str) and Path(name).name == name and name.endswith('.deb')
                and name not in archives, 'ambiguous package archive provenance')
        archives[name] = item
    allowed_dirs = {'commands', 'signed-indexes', 'apt', 'packages', 'rootfs'}
    budget = EntryBudget(PROVENANCE_ENTRIES)
    for path in bounded_children(guest, budget):
        info = preflight.checked(path, volume)
        if path.name in ('packages', 'rootfs'):
            require(stat.S_ISDIR(info.st_mode), 'regenerable payload must be a directory')
            if path.name == 'packages':
                require(records and all(item.get('extraction_status') == 'PASS' for item in records)
                        and all(item.get('status') in ('MATERIALIZED', 'OPTIONAL_DOCUMENTATION_REMOVAL')
                                for item in setup.get('package_link_materialization', [])),
                        'package extraction or link materialization was incomplete')
            candidates.append(path)
        elif path.name in ('vmlinuz', 'initrd.cpio.gz'):
            digest = setup.get('kernel_sha256' if path.name == 'vmlinuz' else 'initrd_sha256')
            require(isinstance(digest, str) and file_sha(path, 100_000_000) == digest,
                    'regenerable kernel/initrd provenance differs')
            candidates.append(path)
        elif path.name == 'apt':
            require(stat.S_ISDIR(info.st_mode), 'APT diagnostic root is not a directory')
            for entry in bounded_children(path, budget):
                if entry.name.endswith('.deb') and entry.name in archives:
                    item = archives[entry.name]
                    signed = item.get('signed_index', {})
                    require(item.get('extraction_status') == 'PASS'
                            and type(item.get('bytes')) is int
                            and str(item['bytes']) == str(signed.get('Size'))
                            and file_sha(entry, 200_000_000) == item.get('sha256') == signed.get('SHA256')
                            and entry.lstat().st_size == item['bytes'],
                            'APT archive lacks exact signed-index size/SHA provenance')
                    candidates.append(entry)
                else:
                    # Includes every nested APT log, state file and partial.
                    diagnostics.append(entry)
        else:
            require(stat.S_ISREG(info.st_mode) or path.name in allowed_dirs and stat.S_ISDIR(info.st_mode),
                    'unexpected guest directory outside the exact payload allowlist')
            diagnostics.append(path)
    require(guest / 'setup.json' in diagnostics and guest / 'commands' in diagnostics,
            'complete setup and commands diagnostics are required')
    if candidates:
        require(guest / 'signed-indexes' in diagnostics and guest / 'kernel-config.txt' in diagnostics,
                'signed indexes and kernel configuration must be preserved before trim')
    for entry in setup.get('commands', []):
        for field in ('stdout', 'stderr'):
            name, digest = entry.get(field), entry.get(field + '_sha256')
            if name is not None:
                require(isinstance(name, str) and not Path(name).is_absolute() and '..' not in Path(name).parts
                        and name.startswith('commands/') and isinstance(digest, str)
                        and file_sha(guest / name, 16 * 1024 * 1024) == digest,
                        'recorded guest command stream is missing or changed')
    return candidates, diagnostics


def owned_manifest(volume, roots):
    # Unchanged legacy tree() has a post-materialization check. Admission here
    # bounds cumulative pending+visited names before it can collect a directory.
    admit_tree(roots, preflight.MAX_ENTRIES)
    manifest = preflight.tree(volume, roots)
    owner = preflight.checked(volume).st_uid
    for item in manifest['entries']:
        info = preflight.checked(volume / item['path'], volume)
        if info.st_uid != owner or item['kind'] != 'directory' and info.st_nlink != 1:
            facts = {'path': item['path'][:512], 'path_truncated': len(item['path']) > 512,
                     'expected_uid': owner, 'observed_uid': info.st_uid, 'observed_gid': info.st_gid,
                     'observed_nlink': info.st_nlink, 'mode': info.st_mode,
                     'device': info.st_dev, 'inode': info.st_ino}
            raise ValueError('trim or provenance member is not an owned single-link inode: '
                             + json.dumps(facts, sort_keys=True, separators=(',', ':')))
    return manifest


def copy_manifest(volume, manifest, destination):
    """Copy every selected provenance byte, with fresh descriptor comparisons."""
    preflight.validate_plan(volume, manifest)
    require(not os.path.lexists(destination), 'provenance copy state already exists')
    preflight.checked(destination.parent)
    destination.mkdir()
    guest = volume / 'reference-guest'
    for item in manifest['entries']:
        original = volume / item['path']
        relative = original.relative_to(guest)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        preflight.checked(target.parent)
        if item['kind'] == 'directory':
            target.mkdir(exist_ok=True)
            continue
        descriptor = os.open(original, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
        try:
            require(preflight.descriptor_matches(os.fstat(descriptor), item['identity']), 'provenance descriptor changed')
            digest, count = hashlib.sha256(), 0
            with os.fdopen(descriptor, 'rb', closefd=False) as source, target.open('xb') as output:
                while data := source.read(65536):
                    count += len(data)
                    require(count <= item['bytes'], 'provenance source grew')
                    digest.update(data)
                    output.write(data)
                output.flush()
                os.fsync(output.fileno())
            require(count == item['bytes'] and digest.hexdigest() == item['sha256']
                    and preflight.descriptor_matches(os.fstat(descriptor), item['identity']),
                    'provenance source content changed')
        finally:
            os.close(descriptor)
    preflight.validate_plan(volume, manifest)
    verify_provenance_copy(volume, manifest, destination)


def verify_provenance_copy(volume, manifest, destination):
    expected = {}
    for item in manifest['entries']:
        relative = (volume / item['path']).relative_to(volume / 'reference-guest').as_posix()
        expected[relative] = item
    seen = set()
    for path, info in bounded_tree([destination], PROVENANCE_ENTRIES + 2):
        if path == destination:
            continue
        name = path.relative_to(destination).as_posix()
        # An APT container directory is synthesized when selecting its children.
        if name == 'apt' and name not in expected:
            require(stat.S_ISDIR(info.st_mode), 'provenance APT container differs')
            continue
        require(name in expected and name not in seen, 'provenance copy membership differs')
        seen.add(name)
        item = expected[name]
        require(stat.S_ISDIR(info.st_mode) == (item['kind'] == 'directory'), 'provenance copy type differs')
        if item['kind'] != 'directory':
            require(info.st_size == item['bytes'] and file_sha(path, PROVENANCE_BYTES) == item['sha256'],
                    'complete provenance copy bytes differ')
    require(seen == set(expected), 'complete provenance copy is missing members')


def observe_guest_selection(p, ctx, removal, provenance):
    """Retain complete bounded selection facts before admission or deletion."""
    admission = external_admission(p)
    require(admission['allowed'],
            'complete cumulative external provenance/control entries or bytes have no reservation')
    p['audit'].mkdir(mode=0o700, exist_ok=True)
    preflight.checked(p['audit'])
    full = {'status': 'OBSERVED_UNVALIDATED', 'source': ctx['source'], 'run_context': ctx,
            'removal_manifest': removal, 'provenance_manifest': provenance}
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'))
    encoded_bytes = 1 + sum(len(part.encode()) for part in encoder.iterencode(full))
    complete = encoded_bytes < min(TRIM_PROOF_BYTES, preflight.MAX_MANIFEST_BYTES)
    observed = {'status': 'OBSERVED_UNVALIDATED', 'source': ctx['source'], 'run_context': ctx,
                'observed_at': results.utc(), 'external_admission': admission,
                'provenance_entries': len(provenance['entries']),
                'provenance_logical_bytes': provenance['logical_bytes'],
                'provenance_accounted_bytes': provenance['accounted_bytes'],
                'removal_entries': len(removal['entries']),
                'logical_byte_limit': PROVENANCE_BYTES, 'entry_limit': PROVENANCE_ENTRIES,
                'complete_manifests_encoded_bytes': encoded_bytes,
                'complete_manifests_retained': complete,
                'scope': 'Observed selection only; no copy, trim, deletion or admission success implied.'}
    if complete:
        target = p['audit'] / 'guest-selection-manifests.json'
        preflight.write_proof(target, full, initial=True)
        observed['complete_manifests_sha256'] = file_sha(target, TRIM_PROOF_BYTES)
    write_small(p['audit'] / 'guest-selection-observed.json', observed)
    if os.name == 'posix':
        descriptor = os.open(p['audit'], os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    require(complete, 'complete guest selection observation exceeds byte admission; summary retained')
    return observed


@bounded_phase(PACK_WRAPPER_SECONDS)
def trim_guest(p, ctx):
    """Delete only exact regenerable roots after durable complete preservation.

    This function is production-only. No local fixture should call the deleter.
    A refused or interrupted copy leaves originals intact and visible to image
    recovery. The complete removal manifest is part of scientific .local data.
    """
    require(sys.platform == 'linux' and os.getuid() != 0, 'secure guest trim requires ordinary Linux')
    closed_guest(p, ctx)
    candidates, selected = guest_selections(p['volume'], ctx)
    require(candidates, 'no positively proved regenerable guest payload exists')
    removal, provenance = owned_manifest(p['volume'], candidates), owned_manifest(p['volume'], selected)
    observe_guest_selection(p, ctx, removal, provenance)
    require(len(provenance['entries']) <= PROVENANCE_ENTRIES
            and provenance['logical_bytes'] <= PROVENANCE_BYTES, 'complete guest provenance exceeds admission')
    allocated = provenance['accounted_bytes'] + len(provenance['entries']) * 4096
    external = physical_tree(p['local'], include_entries=True)
    entry_admission = provenance_entry_admission(external['entries'], provenance, p['volume'] / 'reference-guest')
    require(entry_admission['allowed'], 'complete cumulative external provenance/control entries have no reservation')
    require(external['accounted_bytes'] + allocated + 2 * TRIM_PROOF_BYTES + CONTROL_ALLOCATION
            <= artifacts.EXTERNAL_METADATA_ALLOCATION, 'complete external provenance has no reservation')
    require(shutil.disk_usage(p['project'] / '.local').free >= allocated + 2 * TRIM_PROOF_BYTES + CONTROL_ALLOCATION,
            'complete scientific provenance/proof has no space in results image')
    outside = p['audit'] / 'guest-provenance'
    inside = p['project'] / '.local/reference-internal-guest-provenance'
    copy_manifest(p['volume'], provenance, outside)
    copy_manifest(p['volume'], provenance, inside)
    proof_path = p['audit'] / 'guest-trim.json'
    scientific = p['project'] / '.local/reference-internal-guest-trim.json'
    proof = {'schema_version': 1, 'profile': PROFILE, 'status': 'PREPARED', 'source': ctx['source'],
             'run_context': ctx, 'volume': str(p['volume']), 'project': str(p['project']),
             'provenance_manifest': provenance, 'removal_manifest': removal,
             'external_entry_admission': entry_admission,
             'external_provenance': str(outside), 'scientific_provenance': str(inside),
             'started_at': results.utc(), 'scope': 'Complete preserved guest diagnostics and exact regenerable payload removal only; scientific results and the guest directory are retained.'}
    terminal = {**proof, 'status': 'FAIL', 'error': '\U0010ffff' * 4096,
                'ended_at': '9' * 64, 'source_unchanged': True, 'removed_entries': len(removal['entries'])}
    encoded = sum(len(part.encode()) for part in json.JSONEncoder(sort_keys=True, separators=(',', ':')).iterencode(terminal))
    require(encoded < TRIM_PROOF_BYTES, 'complete terminal trim proof exceeds predelete admission')
    preflight.write_proof(proof_path, proof, initial=True)
    preflight.write_proof(scientific, proof, initial=True)
    require(file_sha(proof_path, TRIM_PROOF_BYTES) == file_sha(scientific, TRIM_PROOF_BYTES),
            'complete predelete scientific trim proof differs')
    try:
        require(context(p['project']) == ctx and context(p['outer']) == ctx,
                'source/run changed before guest trim')
        observe_outer(p['volume'], p['project'])
        closed_guest(p, ctx)
        preflight.validate_plan(p['volume'], provenance)
        verify_provenance_copy(p['volume'], provenance, outside)
        verify_provenance_copy(p['volume'], provenance, inside)
        preflight.validate_plan(p['volume'], removal)
        preflight.delete_linux(p['volume'], removal)
        preflight.validate_plan(p['volume'], provenance)
        require(context(p['project']) == ctx and context(p['outer']) == ctx,
                'source changed during guest trim')
        verify_provenance_copy(p['volume'], provenance, outside)
        verify_provenance_copy(p['volume'], provenance, inside)
        proof.update(status='PASS', source_unchanged=True, removed_entries=len(removal['entries']))
    except BaseException as error:
        proof.update(status='FAIL', error=(type(error).__name__ + ': ' + str(error))[:4096])
        raise
    finally:
        proof['ended_at'] = results.utc()
        preflight.write_proof(proof_path, proof)
        preflight.write_proof(scientific, proof)
    require(file_sha(proof_path, TRIM_PROOF_BYTES) == file_sha(scientific, TRIM_PROOF_BYTES),
            'complete terminal scientific trim proof differs')
    return {'status': proof['status'], 'complete_proof_path': str(scientific),
            'complete_proof_sha256': file_sha(scientific, TRIM_PROOF_BYTES),
            'removed_entries': len(removal['entries']), 'removed_accounted_bytes': removal['accounted_bytes']}


def copy_failure_sidecar(package, audit, child_stopped, *, reuse_after_quiescence=None):
    """Preserve the complete adjacent child failure only after termination."""
    source = package.with_name(package.name + '.failure.json')
    if not os.path.lexists(source):
        return {'present': False}
    require(child_stopped is True, 'child failure sidecar cannot be copied before termination')
    before = preflight.checked(source)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= artifacts.CAPTURE_BYTES, 'unsafe or oversized child failure sidecar')
    target = audit / source.name
    raw, digest = artifacts.read_metadata(source, before, before.st_size)
    if os.path.lexists(target):
        require(reuse_after_quiescence is not None, 'child failure audit copy already exists')
        require(isinstance(reuse_after_quiescence, dict)
                and reuse_after_quiescence.get('quiescent') is True
                and reuse_after_quiescence.get('residual') == [],
                'existing sidecar reuse requires positive parent descendant quiescence')
        require(target.lstat().st_size == before.st_size
                and file_sha(target, artifacts.CAPTURE_BYTES) == digest,
                'retained child failure audit copy differs')
    else:
        with target.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    require(preflight.stamp(preflight.checked(source)) == preflight.stamp(before)
            and file_sha(source, artifacts.CAPTURE_BYTES, preflight.stamp(before)) == digest
            and file_sha(target, artifacts.CAPTURE_BYTES) == digest,
            'complete child failure sidecar changed during preservation')
    return {'present': True, 'source_path': str(source), 'source_identity': list(preflight.stamp(before)),
            'audit_path': str(target), 'bytes': before.st_size, 'sha256': digest,
            'audit_sha256': digest, 'complete': True, 'original_retained': True,
            'copy_role': 'Complete external audit copy of immutable adjacent child failure diagnostic.',
            'internal_control_allocation_bytes': before.st_size}


def validate_result_tree(project):
    """Refuse additional devices, aliases and hardlinks before packing results."""
    selected = project / '.local'
    root_info = preflight.checked(selected)
    owner = preflight.checked(project).st_uid
    admit_tree([selected], bundle.MAX_MEMBERS)
    entries = bundle.inventory(project, ['.local'])
    seen = set()
    for name, expected, size in entries:
        path = project / name.rstrip('/')
        info = preflight.checked(path)
        key = (info.st_dev, info.st_ino)
        require(info.st_dev == root_info.st_dev and info.st_uid == owner
                and bundle.signature(info) == expected and key not in seen
                and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                'result tree changed or contains a different device, owner, alias or hardlink')
        seen.add(key)
    return len(entries)


def pack(volume, project, root=ROOT, control=False):
    """Payload API; only the independent CLI parent can qualify its result."""
    wrapper_started = time.monotonic()
    require(type(control) is bool, 'invalid transport failure control flag')
    p = paths(volume, project, root)
    ctx = context(p['project'])
    require(context(p['outer']) == ctx, 'outer checkout and measured source execution differ')
    parent = None
    if os.environ.get('FQ_TRANSPORT_WORKER_PHASE'):
        import reference_transport_supervisor as supervisor
        parent = supervisor.require_active_worker(p, ctx, 'pack')
    require((parent is not None or not os.path.lexists(p['audit'])) and not os.path.lexists(p['data']),
            'refusing existing internal package, partial or audit state')
    admitted = parent['external_admission'] if parent else external_admission(p)
    if not admitted['allowed']:
        return preserve_refusal(p, ctx, 'pack', admitted,
                'actual external metadata plus complete 20MB control reservation exceeds admission')
    if parent is None:
        p['audit'].mkdir()
    proof = p['audit'] / 'pack-result.json'
    record = {'schema_version': 1, 'profile': PROFILE, 'status': 'PREPARING', 'source': ctx['source'],
              'commit': ctx['commit'], 'run_id': ctx['github_run_id'], 'run_attempt': ctx['github_run_attempt'],
              'run_context': ctx, 'package_path': str(p['package']), 'audit_path': str(p['audit']),
              'started_at': results.utc(), 'errors': [], 'control': control,
              'complete_scientific_preservation': False, 'external_admission': admitted,
              'independent_supervisor_required': True, 'scope': SCOPE}
    write_small(proof, record)
    try:
        record['reservation'] = observe_outer(p['volume'], p['project'])
        record['time_admission'] = current_time_admission('pack')
        require(record['time_admission']['allowed'], 'insufficient actual remaining job time for packing and complete image-recovery tail')
        closed_guest(p, ctx)
        before = physical_admission(shutil.disk_usage(p['volume']).free)
        record['physical_before'] = before
        if not before['allowed']:
            record['guest_trim'] = trim_guest(p, ctx)
        record['physical_admission'] = physical_admission(shutil.disk_usage(p['volume']).free)
        require(record['physical_admission']['allowed'], 'internal package would consume the unchanged 500MB filesystem floor')
        record['time_before_launch'] = current_time_admission('pack')
        require(record['time_before_launch']['allowed'], 'packing no longer has its complete absolute-deadline reservation')
        closed_guest(p, ctx)
        record['admitted_result_members'] = validate_result_tree(p['project'])
        require(context(p['project']) == ctx and context(p['outer']) == ctx, 'source changed before pack launch')
        observe_outer(p['volume'], p['project'])
        require(time.monotonic() - wrapper_started < PACK_WRAPPER_SECONDS,
                'prepack wrapper exhausted its admitted 210 second bound')
        p['data'].mkdir()
        require(p['data'].lstat().st_dev == p['volume'].lstat().st_dev,
                'package data directory is outside the actual outer filesystem')
        write_small(proof, record, replace=True)
        attempted = artifacts.run_pack(p['project'], p['package'], ctx['source'], ctx['commit'],
                                       ctx['github_run_id'], 2 if control else PACK_CHILD_SECONDS,
                                       preset=6, control=control, progress=True, audit_dir=p['audit'])
        record['pack_attempt'] = {'status': attempted.get('status'), 'child_stopped': attempted.get('child_stopped'),
                                  'originals_unchanged': attempted.get('originals_unchanged'),
                                  'residual_package_safe': attempted.get('residual_package_safe'),
                                  'residual_package_bytes': attempted.get('residual_package_bytes'),
                                  'attempt_sha256': file_sha(p['audit'] / 'pack-attempt.json', 1_000_000)}
        record['failure_sidecar'] = copy_failure_sidecar(p['package'], p['audit'], attempted.get('child_stopped'))
        require(attempted.get('status') == 'PASS' and attempted.get('child_stopped') is True
                and attempted.get('originals_unchanged') is True and attempted.get('stream_capture_complete') is True
                and attempted.get('discarded_stream_bytes') == 0 and attempted.get('residual_package_safe') is True
                and not record['failure_sidecar']['present'] and not control,
                'packing failed or audit capture was incomplete; retain the outer image and original results')
        require(shutil.disk_usage(p['volume']).free >= FILESYSTEM_FLOOR,
                'actual postpack availability is below the unchanged filesystem floor')
        record.update(status='PASS', bundle_sha256=file_sha(p['package'], bundle.MAX_OUTPUT),
                      bundle_bytes=p['package'].lstat().st_size, outer_image_retained=True)
    except BaseException as error:
        record.update(status='FAIL')
        record['errors'].append((type(error).__name__ + ': ' + str(error))[:2000])
    finally:
        record['ended_at'] = results.utc()
        write_small(proof, record, replace=True)
    return record


def verify_pack_audit(p, ctx):
    result = read_json(p['audit'] / 'pack-result.json')
    attempt_path = p['audit'] / 'pack-attempt.json'
    attempted = read_json(attempt_path)
    require(result.get('profile') == PROFILE and result.get('status') == 'PASS'
            and result.get('run_context') == ctx and result.get('package_path') == str(p['package'])
            and result.get('audit_path') == str(p['audit']) and result.get('control') is False,
            'current internal packaging controller PASS is required')
    require(attempted.get('status') == 'PASS' and attempted.get('phase') == 'COMPLETE'
            and attempted.get('source') == ctx['source'] and attempted.get('commit') == ctx['commit']
            and attempted.get('run_id') == ctx['github_run_id']
            and attempted.get('run_attempt') == ctx['github_run_attempt']
            and attempted.get('child_stopped') is True and attempted.get('originals_unchanged') is True
            and attempted.get('termination_reason') is None and attempted.get('exit_code') == 0
            and attempted.get('errors') == [] and attempted.get('stream_capture_complete') is True
            and attempted.get('discarded_stream_bytes') == 0 and attempted.get('residual_package_safe') is True
            and attempted.get('preset') == 6 and attempted.get('control') is False,
            'complete current child packaging/capture PASS is required')
    require(file_sha(attempt_path, 1_000_000) == result.get('pack_attempt', {}).get('attempt_sha256'),
            'child packaging receipt changed after controller observation')
    captured = 0
    for label in ('stdout', 'stderr'):
        stream = p['audit'] / ('pack-' + label + '.txt')
        require(file_sha(stream, artifacts.CAPTURE_BYTES) == attempted.get(label + '_sha256'),
                'complete packaging stream changed')
        captured += stream.lstat().st_size
    require(captured == attempted.get('captured_stream_bytes') <= artifacts.CAPTURE_BYTES,
            'packaging capture lengths differ')
    require(not os.path.lexists(p['package'].with_name(p['package'].name + '.partial'))
            and not os.path.lexists(p['package'].with_name(p['package'].name + '.failure.json'))
            and not os.path.lexists(p['audit'] / p['package'].name),
            'unsafe residual partial, child failure or external package copy exists')
    require(file_sha(p['package'], bundle.MAX_OUTPUT) == result.get('bundle_sha256')
            and p['package'].lstat().st_size == result.get('bundle_bytes'), 'packaged data changed')
    return result


def complete_comparisons(root, project, manifest):
    """Reuse all complete live, curated-metadata and fuzz comparisons."""
    validate_result_tree(project)
    physical_tree(root / '.local')
    fuzz_roots = [path for path in (project / '.cache/go-build/fuzz',
                  project / 'internal/engine/testdata/fuzz') if os.path.lexists(path)]
    if fuzz_roots:
        admit_tree(fuzz_roots, preflight.MAX_ENTRIES)
    fuzz = read_json(project / '.local/reference-fuzz/manifest.json', 16_000_000)
    return {'live_members': retention.verify_live_members(project, manifest),
            'metadata_members': retention.verify_metadata(root, project, manifest),
            'fuzz_members': retention.verify_fuzz(project, fuzz)}


def verify_transport(volume, project, root=ROOT):
    """Verification-only retention: freeze the child and retain the outer image."""
    p = paths(volume, project, root)
    preflight.checked(p['audit'])
    proof = p['audit'] / 'verification.json'
    require(not os.path.lexists(proof) and not os.path.lexists(proof.with_name(proof.name + '.tmp')),
            'internal transport verification state already exists')
    ctx = context(p['project'])
    require(context(p['outer']) == ctx, 'outer/source execution identity differs')
    import reference_transport_supervisor as supervisor
    supervisor.require_active_worker(p, ctx, 'verify')
    packed_supervision = supervisor.validate_receipt(p, ctx, 'pack')
    record = {'schema_version': 1, 'profile': PROFILE, 'status': 'PREPARING',
              'source': ctx['source'], 'run_context': ctx, 'commit': ctx['commit'],
              'run_id': ctx['github_run_id'], 'run_attempt': ctx['github_run_attempt'],
              'package_path': str(p['package']), 'audit_path': str(p['audit']),
              'started_at': results.utc(), 'scope': SCOPE,
              'complete_comparisons': False, 'outer_image_retained': True,
              'pack_supervisor_receipt_sha256': packed_supervision['supervisor_receipt_sha256'],
              'independent_supervisor_required': True}
    write_small(proof, record)
    try:
        record['time_admission'] = current_time_admission('verify')
        require(record['time_admission']['allowed'], 'insufficient remaining job time for complete verification and failure-image tail')
        record['reservation'] = observe_outer(p['volume'], p['project'])
        packed = verify_pack_audit(p, ctx)
        closed = closed_guest(p, ctx)
        info = preflight.checked(p['package'])
        require(info.st_dev == p['volume'].lstat().st_dev and info.st_uid == os.getuid()
                and info.st_nlink == 1 and 0 < info.st_size <= bundle.MAX_OUTPUT,
                'internal package filesystem, owner, link count or size differs')
        digest = file_sha(p['package'], bundle.MAX_OUTPUT)
        verified = bundle.verify(p['package'])
        with p['package'].open('rb') as stream:
            raw = bundle.transport_item(bundle.XZReader(stream), 'manifest.json', bundle.MAX_MANIFEST)
        manifest = json.loads(raw, object_pairs_hook=bundle.unique_object)
        require(verified.get('status') == 'PASS' and verified.get('source') == ctx['source']
                and verified.get('commit') == ctx['commit'] and verified.get('run_id') == ctx['github_run_id']
                and digest == packed['bundle_sha256']
                and file_sha(p['package'], bundle.MAX_OUTPUT, preflight.stamp(info)) == digest,
                'complete bundle verification identity differs')
        record['manifest_sha256'] = hashlib.sha256(raw).hexdigest()
        record['first_comparison'] = complete_comparisons(p['outer'], p['project'], manifest)
        require(context(p['project']) == ctx and context(p['outer']) == ctx, 'source/run changed during verification')
        require(observe_outer(p['volume'], p['project']) == record['reservation'], 'outer quota or binding changed')
        closed_guest(p, ctx)
        # Repeat every comparison immediately before the sole nested freeze.
        record['final_comparison'] = complete_comparisons(p['outer'], p['project'], manifest)
        require(record['first_comparison'] == record['final_comparison']
                and context(p['project']) == ctx and context(p['outer']) == ctx
                and file_sha(p['package'], bundle.MAX_OUTPUT, preflight.stamp(info)) == digest,
                'complete comparisons or source/package changed before nested freeze')
        supervisor.require_active_worker(p, ctx, 'verify')
        require(supervisor.capacity.children(os.getpid()) == [],
                'verification payload still owns children before nested freeze')
        frozen = freeze_results(p, ctx)
        require(frozen.get('status') == 'PASS' and frozen.get('image_unmounted') is True
                and frozen.get('source') == ctx['source'] and frozen.get('run_context') == legacy_context(ctx)
                and frozen.get('image_bytes') == artifacts.RESULTS_IMAGE,
                'complete nested results freeze is required')
        # The quota proof now lives in the exact frozen image; validate the same
        # still-mounted outer binding without trying to read the unmounted child.
        observed = results.observe_binding(p['volume'], p['image'], command)
        require(observed == record['reservation']['binding']
                and image_identity(preflight.checked(p['image'])) == record['reservation']['backing_identity']
                and file_sha(p['package'], bundle.MAX_OUTPUT, preflight.stamp(info)) == digest
                and os.path.ismount(p['volume']), 'outer image/package was not retained through verification')
        freeze_path = p['volume'] / 'reference-results-freeze.json'
        record.update(status='PASS', complete_comparisons=True, bundle_sha256=digest,
                      bundle_bytes=info.st_size, package_identity=list(preflight.stamp(info)),
                      nested_results_freeze={'status': 'PASS', 'image_unmounted': True,
                          'proof_path': str(freeze_path), 'proof_sha256': file_sha(freeze_path, 16_000_000),
                          'image_sha256': frozen['image_sha256'], 'image_bytes': frozen['image_bytes']},
                      complete_scientific_preservation=True)
    except BaseException as error:
        record.update(status='FAIL', error=(type(error).__name__ + ': ' + str(error))[:2000])
    finally:
        record['ended_at'] = results.utc()
        write_small(proof, record, replace=True)
    return record


def prior_phase_quiescence(p, ctx):
    """A failed payload is recoverable only after its independent parent stopped it."""
    import reference_transport_supervisor as supervisor
    observed = {}
    for phase, names in (('pack', ('pack-result.json', 'pack-attempt.json')),
                         ('verify', ('verification.json',))):
        proof = supervisor.receipt_path(p, phase)
        started = (os.path.lexists(proof)
                   or any(os.path.lexists(p['audit'] / name) for name in names)
                   or phase == 'pack' and os.path.lexists(p['data']))
        if started:
            value = supervisor.validate_receipt(p, ctx, phase, require_pass=False)
            observed[phase] = {'status': value['status'], 'quiescent': True,
                               'supervisor_receipt_sha256': value['supervisor_receipt_sha256']}
    return observed


def freeze_checkpoint(name):
    """Explicit smoke interruption; never enabled by a production default."""
    requested = os.environ.get('FQ_TRANSPORT_FREEZE_INTERRUPT', '')
    if requested:
        require(requested in ('before_unmount', 'after_unmount', 'during_hashing')
                and os.environ.get('FQ_TRANSPORT_FREEZE_INTERRUPT_PHASE', 'verify') in ('verify', 'reconcile')
                and os.environ.get('FQ_PRESERVATION_CONTROL') == 'true'
                and os.environ.get('FQ_BENCH_PROFILE') == 'smoke',
                'freeze interruption requires an explicit nonqualifying smoke control')
        if (requested == name and os.environ.get('FQ_TRANSPORT_WORKER_PHASE')
                == os.environ.get('FQ_TRANSPORT_FREEZE_INTERRUPT_PHASE', 'verify')):
            raise InterruptedError('controlled freeze interruption ' + name)


def frozen_base(p, ctx):
    """Bind the complete canonical setup even when its child is unmounted."""
    owned = results.owned_paths(p['volume'], p['project'])
    setup_sha = file_sha(owned['proof'], results.MAX_METADATA)
    canonical = read_json(owned['proof'], results.MAX_METADATA)
    require(canonical.get('status') == 'PASS' and canonical.get('source') == ctx['source']
            and canonical.get('run_context') == legacy_context(ctx)
            and canonical.get('paths') == {key: str(value) for key, value in owned.items()}
            and canonical.get('image_bytes') == artifacts.RESULTS_IMAGE
            and canonical.get('oversized_allocation') == 'DENIED_ENOSPC',
            'complete current canonical results setup is required for frozen recovery')
    require(results.fixed_identity(owned['image']) == canonical.get('image_identity')
            and results.identity(owned['outer_image']) == canonical.get('outer', {}).get('image_identity')
            and results.identity(owned['volume'])[:5] == canonical['outer'].get('volume_identity')
            and results.identity(owned['project'])[:5] == canonical.get('project_identity'),
            'frozen recovery full backing, volume or source identities differ')
    reservation = observe_outer(p['volume'], p['project'], quota_root=owned['bootstrap'])
    require(reservation['binding'] == canonical['outer'].get('binding')
            and file_sha(owned['bootstrap'] / 'reference-quota.json', 1_000_000)
                == canonical['outer'].get('quota_sha256') and os.path.ismount(p['volume']),
            'frozen recovery outer quota, binding or retained mount differs')
    validate_nested_filesystem(owned, canonical, ctx, live_mount=os.path.ismount(owned['mount']))
    require(file_sha(owned['proof'], results.MAX_METADATA) == setup_sha,
            'canonical setup changed during frozen recovery binding')
    return owned, canonical, setup_sha, reservation


def frozen_guest_idle(p, ctx, canonical):
    guest = p['volume'] / 'reference-guest'
    if os.path.lexists(guest):
        preflight.checked(guest)
        quiet = read_json(p['volume'] / 'reference-guest-quiescence.json', results.MAX_METADATA)
        require(quiet.get('status') == 'PASS' and quiet.get('source') == ctx['source']
                and quiet.get('run_context') == legacy_context(ctx)
                and quiet.get('guest_setup_sha256') == file_sha(guest / 'setup.json', results.MAX_METADATA),
                'current complete guest quiescence is required for frozen recovery')
    return results.assert_no_active_guest(p['volume'], p['project'], canonical, command)


def frozen_absence(owned):
    mounted = os.path.ismount(owned['mount'])
    observed = command(['findmnt', '--json', '--mountpoint', str(owned['mount']),
                        '-o', 'TARGET,FSTYPE,SOURCE'], accepted=(0, 1))
    mounts = json.loads(observed['stdout']) if observed['stdout'].strip() else {}
    loops = command(['sudo', '-n', 'losetup', '--json', '--list', '--associated',
                     str(owned['image']), '--output', 'NAME,BACK-FILE'])
    require(not mounted and not os.path.ismount(owned['mount'])
            and observed['exit_code'] == 1 and observed['stderr'] == ''
            and mounts.get('filesystems', []) == []
            and json.loads(loops['stdout']).get('loopdevices') == [],
            'results image is still mounted/associated or absence is unproven')
    return {'image_unmounted': True, 'mountpoint_observation': observed,
            'loop_absence_observation': loops}


def original_freeze_record(owned, ctx, setup_sha):
    proof = owned['freeze']
    if not os.path.lexists(proof):
        return {'present': False, 'path': str(proof)}
    before = preflight.checked(proof)
    digest = file_sha(proof, results.MAX_METADATA, preflight.stamp(before))
    original = read_json(proof, results.MAX_METADATA)
    require(original.get('status') in ('PREPARING', 'PREPARED', 'FAIL', 'PASS')
            and original.get('source') == ctx['source']
            and original.get('run_context') == legacy_context(ctx)
            and original.get('image_path') == str(owned['image'])
            and original.get('setup_proof_sha256') == setup_sha,
            'original freeze proof belongs to another setup/execution')
    return {'present': True, 'path': str(proof), 'sha256': digest,
            'identity': list(preflight.stamp(before)), 'status': original['status']}


def validate_prior_freeze(owned, prior):
    if prior.get('present'):
        require(file_sha(owned['freeze'], results.MAX_METADATA, prior['identity']) == prior.get('sha256'),
                'original failed/prepared freeze proof changed during reconciliation')
    else:
        require(not os.path.lexists(owned['freeze']), 'an original freeze proof appeared during reconciliation')


def _freeze_into(p, ctx, proof, *, reconciled):
    """One attempt, one new proof; an interrupted original is never rewritten."""
    require(not os.path.lexists(proof) and not os.path.lexists(proof.with_name(proof.name + '.tmp')),
            'existing freeze/reconciliation proof is retained; blind retry is forbidden')
    require(not Path.cwd().is_relative_to(p['project'] / '.local'),
            'freeze must run outside the child results mount')
    owned, canonical, setup_sha, reservation = frozen_base(p, ctx)
    prior = original_freeze_record(owned, ctx, setup_sha) if reconciled else {'present': False}
    require(reconciled or not os.path.lexists(owned['freeze']), 'original freeze proof already exists')
    require(shutil.disk_usage(p['volume']).free >= FILESYSTEM_FLOOR + CONTROL_ALLOCATION,
            'freeze control growth would consume the unchanged outer filesystem floor')
    phases = prior_phase_quiescence(p, ctx) if reconciled else {}
    record = {'schema_version': 1, 'evidence_type': ('reference_results_reconciled_freeze'
              if reconciled else 'reference_results_freeze'), 'profile': PROFILE, 'status': 'PREPARING',
              'source': ctx['source'], 'run_context': legacy_context(ctx), 'profile_context': ctx,
              'image_path': str(owned['image']), 'image_identity': canonical['image_identity'],
              'setup_proof_sha256': setup_sha, 'outer': canonical['outer'], 'reservation': reservation,
              'original_freeze': prior, 'prior_transport_quiescence': phases,
              'started_at': results.utc(), 'commands': [],
              'scope': 'Exact fixed unmounted results image; no workload or release qualification.'}
    write_small(proof, record)
    try:
        record['inactive_guest'] = frozen_guest_idle(p, ctx, canonical)
        if os.path.ismount(owned['mount']):
            binding = results.observe_binding(owned['mount'], owned['image'], command)
            require(binding == canonical.get('nested_binding')
                    and binding['mount']['source'] != canonical['outer']['binding']['mount']['source']
                    and results.identity(owned['mount'])[:5] == canonical.get('mount_identity'),
                    'current nested mount/backing differs before bounded freeze')
            record['nested_binding_before_unmount'] = binding
            record['commands'].append(command(['sync', '-f', str(owned['mount'])], timeout=60))
            freeze_checkpoint('before_unmount')
            validate_nested_filesystem(owned, canonical, ctx, live_mount=True)
            record['commands'].append(command(['sudo', '-n', 'umount', '--', str(owned['mount'])], timeout=60))
            freeze_checkpoint('after_unmount')
        else:
            require(reconciled, 'a first freeze requires its exact live child mount')
        record['current_image_state'] = frozen_absence(owned)
        digest = file_sha(owned['image'], artifacts.RESULTS_IMAGE,
                          checkpoint=freeze_checkpoint)
        require(results.fixed_identity(owned['image']) == canonical['image_identity']
                and frozen_base(p, ctx)[1:] == (canonical, setup_sha, reservation)
                and context(p['project']) == ctx and context(p['outer']) == ctx,
                'frozen image/setup/source changed during complete hashing')
        frozen_absence(owned)
        if reconciled:
            validate_prior_freeze(owned, prior)
            require(prior_phase_quiescence(p, ctx) == phases,
                    'prior transport quiescence proofs changed during reconciliation')
        record.update(status='PASS', image_unmounted=True, image_bytes=artifacts.RESULTS_IMAGE,
                      image_sha256=digest, complete_scientific_preservation=True,
                      original_freeze_preserved=True,
                      recovery='Mount a separately verified copy read-only as ext4; keep this exact fixed image.',
                      backing_relationship='Results image remains inside the retained admitted outer image.')
    except BaseException as error:
        record.update(status='FAIL', error=(type(error).__name__ + ': ' + str(error))[:2000])
    finally:
        record['ended_at'] = results.utc()
        write_small(proof, record, replace=True)
    return record


def freeze_results(p, ctx):
    import reference_transport_supervisor as supervisor
    supervisor.require_active_worker(p, ctx, 'verify')
    supervisor.validate_receipt(p, ctx, 'pack')
    return _freeze_into(p, ctx, p['volume'] / 'reference-results-freeze.json', reconciled=False)


def reconcile_freeze(volume, project, root=ROOT):
    """Supervised worker API; preserve the original and create one separate proof."""
    p = paths(volume, project, root)
    ctx = context(p['project'])
    require(context(p['outer']) == ctx, 'reconciliation outer/source execution differs')
    import reference_transport_supervisor as supervisor
    supervisor.require_active_worker(p, ctx, 'reconcile')
    return _freeze_into(p, ctx, p['volume'] / 'reference-results-reconciled-freeze.json', reconciled=True)


def validate_frozen_proof(p, ctx, proof):
    """Reobserve every binding and hash the complete image, including an old PASS."""
    digest = file_sha(proof, results.MAX_METADATA)
    value = read_json(proof, results.MAX_METADATA)
    owned, canonical, setup_sha, reservation = frozen_base(p, ctx)
    require(value.get('status') == 'PASS' and value.get('source') == ctx['source']
            and value.get('run_context') == legacy_context(ctx)
            and value.get('image_path') == str(owned['image'])
            and value.get('image_unmounted') is True and value.get('image_bytes') == artifacts.RESULTS_IMAGE
            and value.get('setup_proof_sha256') == setup_sha,
            'complete current frozen results proof is required')
    if proof.name == 'reference-results-reconciled-freeze.json':
        require(value.get('profile') == PROFILE and value.get('profile_context') == ctx
                and value.get('image_identity') == canonical['image_identity']
                and value.get('outer') == canonical['outer'] and value.get('reservation') == reservation
                and value.get('original_freeze_preserved') is True,
                'reconciled freeze setup/full identities differ')
        validate_prior_freeze(owned, value.get('original_freeze', {}))
    frozen_guest_idle(p, ctx, canonical)
    state = frozen_absence(owned)
    image_sha = file_sha(owned['image'], artifacts.RESULTS_IMAGE)
    require(image_sha == value.get('image_sha256')
            and results.fixed_identity(owned['image']) == canonical['image_identity']
            and frozen_base(p, ctx)[1:] == (canonical, setup_sha, reservation),
            'complete frozen image SHA or full current binding differs')
    frozen_absence(owned)
    require(file_sha(proof, results.MAX_METADATA) == digest and context(p['project']) == ctx
            and context(p['outer']) == ctx, 'frozen proof/source changed during fresh validation')
    return {**value, 'profile_context': ctx, 'complete_freeze_proof_path': str(proof),
            'complete_freeze_proof_sha256': digest, 'fresh_current_image_state': state,
            'selected_path': str(owned['image']), 'zip_upper_bound_bytes': artifacts.IMAGE_ZIP,
            'outer_image_retained_through_upload': True}


@bounded_phase(FREEZE_SECONDS)
def verified_frozen_candidate(volume, project, root=ROOT):
    p = paths(volume, project, root)
    ctx = context(p['project'])
    require(context(p['outer']) == ctx, 'frozen upload outer/source execution differs')
    phases = prior_phase_quiescence(p, ctx)
    reconciled = p['volume'] / 'reference-results-reconciled-freeze.json'
    proof = reconciled if os.path.lexists(reconciled) else p['volume'] / 'reference-results-freeze.json'
    import reference_transport_supervisor as supervisor
    if proof == reconciled:
        parent = supervisor.validate_receipt(p, ctx, 'reconcile')
    else:
        # An original PASS created by a directly invoked payload is insufficient.
        require('verify' in phases, 'original freeze requires independently supervised verification')
        parent = supervisor.validate_receipt(p, ctx, 'verify', require_pass=False)
    value = validate_frozen_proof(p, ctx, proof)
    require(prior_phase_quiescence(p, ctx) == phases, 'transport quiescence changed before frozen selection')
    return {**value, 'prior_transport_quiescence': phases,
            'freeze_supervisor_receipt_sha256': parent['supervisor_receipt_sha256']}


def verified_candidate(volume, project, root=ROOT):
    """Rebind a verification PASS immediately before selecting its sole upload.

    The original quota files reside in the now-unmounted child. Their validated
    reservation is bound to current source, backing identity and mount here;
    this function never fabricates a replacement legacy quota proof.
    """
    p = paths(volume, project, root)
    ctx = context(p['project'])
    require(context(p['outer']) == ctx, 'upload source and outer checkout differ')
    import reference_transport_supervisor as supervisor
    pack_supervision = supervisor.validate_receipt(p, ctx, 'pack')
    verify_supervision = supervisor.validate_receipt(p, ctx, 'verify')
    proof = p['audit'] / 'verification.json'
    receipt_digest = file_sha(proof, 1_000_000)
    receipt = read_json(proof)
    require(receipt.get('status') == 'PASS' and receipt.get('profile') == PROFILE
            and receipt.get('run_context') == ctx and receipt.get('source') == ctx['source']
            and receipt.get('commit') == ctx['commit'] and receipt.get('run_id') == ctx['github_run_id']
            and receipt.get('run_attempt') == ctx['github_run_attempt']
            and receipt.get('package_path') == str(p['package']) and receipt.get('audit_path') == str(p['audit'])
            and receipt.get('outer_image_retained') is True
            and receipt.get('complete_comparisons') is True
            and receipt.get('complete_scientific_preservation') is True,
            'complete current inside-outer verification PASS is required for bundle selection')
    require(receipt.get('pack_supervisor_receipt_sha256') == pack_supervision['supervisor_receipt_sha256'],
            'verification used another independent pack supervision receipt')
    comparisons = receipt.get('first_comparison', {})
    require(comparisons == receipt.get('final_comparison')
            and set(comparisons) == {'live_members', 'metadata_members', 'fuzz_members'}
            and all(type(value) is int and value >= 0 for value in comparisons.values())
            and comparisons['live_members'] > 0 and comparisons['metadata_members'] > 0,
            'complete repeated live, metadata and fuzz comparison receipt differs')
    packed = verify_pack_audit(p, ctx)
    reservation = receipt.get('reservation', {})
    plan = growth_plan(int(os.environ['FQ_ACCOUNTED_BASE_BYTES']))
    require(plan['admission'] == 'ALLOW' and reservation.get('profile') == PROFILE
            and reservation.get('run_context') == ctx
            and reservation.get('global_reserved_growth_bytes') == GLOBAL_RESERVE
            and reservation.get('filesystem_free_floor_bytes') == FILESYSTEM_FLOOR
            and reservation.get('global_peak_bytes') == plan['peak_bytes'],
            'bundle upload reservation differs from the fresh exact profile plan')
    binding = results.observe_binding(p['volume'], p['image'], command)
    backing = preflight.checked(p['image'])
    require(binding == reservation.get('binding') and stat.S_ISREG(backing.st_mode)
            and backing.st_uid == os.getuid() and backing.st_nlink == 1 and backing.st_size == IMAGE_BYTES
            and image_identity(backing) == reservation.get('backing_identity')
            and os.path.ismount(p['volume']), 'verified outer image was not retained with its exact mount/backing')
    package = preflight.checked(p['package'])
    require(package.st_dev == p['volume'].lstat().st_dev and package.st_uid == os.getuid()
            and package.st_nlink == 1 and list(preflight.stamp(package)) == receipt.get('package_identity')
            and package.st_size == receipt.get('bundle_bytes') == packed.get('bundle_bytes')
            and file_sha(p['package'], bundle.MAX_OUTPUT, preflight.stamp(package))
                == receipt.get('bundle_sha256') == packed.get('bundle_sha256'),
            'verified internal bundle identity or SHA changed before upload')
    frozen = receipt.get('nested_results_freeze', {})
    freeze_path = p['volume'] / 'reference-results-freeze.json'
    require(frozen.get('status') == 'PASS' and frozen.get('image_unmounted') is True
            and frozen.get('proof_path') == str(freeze_path)
            and file_sha(freeze_path, 16_000_000) == frozen.get('proof_sha256'),
            'complete nested freeze proof changed before upload')
    complete_freeze = validate_frozen_proof(p, ctx, freeze_path)
    require(complete_freeze['image_bytes'] == frozen.get('image_bytes')
            and complete_freeze['image_sha256'] == frozen.get('image_sha256'),
            'nested freeze bytes differ from complete verified transport')
    require(file_sha(proof, 1_000_000) == receipt_digest and context(p['project']) == ctx
            and context(p['outer']) == ctx, 'verification receipt/source changed during upload selection')
    return {**receipt, 'verification_receipt_sha256': receipt_digest,
            'verify_supervisor_receipt_sha256': verify_supervision['supervisor_receipt_sha256'],
            'selected_path': str(p['package']), 'outer_image_retained_through_upload': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    plan = actions.add_parser('plan')
    plan.add_argument('base', type=int)
    plan.add_argument('--image-bytes', type=int, default=IMAGE_BYTES)
    for name in ('pack', 'verify', 'reconcile', '_pack_worker', '_verify_worker', '_reconcile_worker'):
        action = actions.add_parser(name)
        action.add_argument('--volume', type=Path, required=True)
        action.add_argument('--project', type=Path, required=True)
        if name in ('pack', '_pack_worker'):
            action.add_argument('--control', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'plan':
            result = growth_plan(args.base, args.image_bytes)
        elif args.action in ('pack', 'verify', 'reconcile'):
            import reference_transport_supervisor as supervisor
            result = supervisor.supervise(args.action, args.volume, args.project,
                         control=getattr(args, 'control', False), started=ENTRY_STARTED)
        elif args.action == '_pack_worker':
            import reference_transport_supervisor as supervisor
            supervisor.await_startup_gate()
            result = pack(args.volume, args.project, control=args.control)
        elif args.action == '_reconcile_worker':
            import reference_transport_supervisor as supervisor
            supervisor.await_startup_gate()
            result = reconcile_freeze(args.volume, args.project)
        else:
            import reference_transport_supervisor as supervisor
            supervisor.await_startup_gate()
            result = verify_transport(args.volume, args.project)
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result = {'status': 'FAIL', 'profile': PROFILE, 'error': (type(error).__name__ + ': ' + str(error))[:2000],
                  'scope': SCOPE}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('status', result.get('admission')) in ('PASS', 'ALLOW') else 1


if __name__ == '__main__':
    raise SystemExit(main())
