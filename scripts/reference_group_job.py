"""Fail-closed named KVM group pilot. Mechanism evidence only; never release credit.

The caller owns quota admission and transport. This controller retains the outer
image, selects exactly one export, and never interprets upload as durable custody.
"""
from __future__ import annotations
import argparse
import base64
import contextlib
import hashlib
import gzip
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import sys
import tarfile
import traceback
import time

from common import ROOT, source_hash
import evidence_bundle
import reference_guest as guest
import reference_group_bootstrap as bootstrap
import reference_group_capacity as capacity
import reference_results as results
from reference_preflight import checked, file_sha, write_proof
from reference_retention import verify_live_members

MIB = 1 << 20
STREAM_BYTES = 19 * MIB
CONTROL_BYTES = 4 * MIB


def approved_context(env):
    capacity.require(env.get('GITHUB_REPOSITORY') == 'C-X1an/facetquarry'
                     and env.get('GITHUB_REPOSITORY_ID') == '1430604581'
                     and env.get('GITHUB_ACTOR_ID') == '53118172' and env.get('GITHUB_EVENT_NAME') == 'push'
                     and env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_OS') == 'Linux'
                     and env.get('ImageOS') == 'ubuntu24', 'unapproved repository or Ubuntu-24.04 run')
    for key, pattern in (('GITHUB_RUN_ID', '[1-9][0-9]{0,19}'),
                         ('GITHUB_RUN_ATTEMPT', '[1-9][0-9]{0,19}'), ('GITHUB_SHA', '[0-9a-f]{40}')):
        capacity.require(re.fullmatch(pattern, env.get(key, '')) is not None, 'invalid workflow identity')
    capacity.require(env['GITHUB_RUN_ATTEMPT'] == '1', 'pilot requires first attempt')
    return {'commit': env['GITHUB_SHA'], 'git_status': '', 'github_run_id': env['GITHUB_RUN_ID'],
            'github_run_attempt': env['GITHUB_RUN_ATTEMPT']}


def member(path):
    info = checked(path)
    capacity.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size > 0,
                     'export must be a nonempty unique regular file')
    return {'path': str(path), 'bytes': info.st_size, 'sha256': file_sha(path),
            'identity': results.identity(path)}


def canonical(path):
    path = Path(path)
    capacity.require(path.is_absolute() and path == path.resolve(strict=True)
                     and '..' not in path.parts and not any(c in str(path) for c in ('\n', '\r')),
                     'canonical absolute path without aliases required')
    checked(path)
    return path


def invocation_paths(volume, image, closure, env):
    context = approved_context(env)
    parent = canonical(Path(env['RUNNER_TEMP'])) / ('facetquarry-named-group-' + context['github_run_id'] + '-1')
    capacity.require((volume, image, closure) == (parent / 'volume', parent / 'outer.img', parent / 'closure'),
                     'named run-owned path scope differs')


def fresh_paths(volume, image, closure):
    volume, image, closure = [canonical(path) for path in (volume, image, closure)]
    capacity.require(not closure.is_relative_to(volume) and not volume.is_relative_to(closure)
                     and not image.is_relative_to(volume) and image.parent == volume.parent,
                     'external closure and sibling outer image required')
    for path in [closure / name for name in ('candidate.json', 'group-closure.json', 'group-failure.json', 'host-control.json')]:
        capacity.require(not os.path.lexists(path), 'closure belongs to an existing invocation')
    for name in ('group-control.json', 'reference-results-setup.json', 'reference-results.img',
                 'reference-guest', 'bootstrap-proof', 'tools', 'group-streams.img', 'group-records.img',
                 'group-results.tar.xz', 'group-results.tar.xz.partial', 'group-host-proof.tar'):
        capacity.require(not os.path.lexists(volume / name), 'pilot volume is not fresh')
    return volume, image, closure


class Budget:
    """One wall deadline, including a protected final closure interval.

    SIGALRM interrupts slow Python I/O and helpers as well as pure computation;
    existing command helpers still own subprocess termination. The caller must
    additionally use the documented 5700s GNU timeout and 100m Actions watchdog.
    """
    def __init__(self, seconds, clock=time.monotonic):
        capacity.require(type(seconds) is int and 1800 <= seconds <= 5400, 'total pilot budget outside bounds')
        self.clock, self.end = clock, clock() + seconds

    def remaining(self, reserve=0):
        value = int(self.end - self.clock()) - reserve
        capacity.require(value > 0, 'pilot deadline exhausted before reserved closure')
        return value

    @contextlib.contextmanager
    def stage(self, reserve=0):
        seconds = self.remaining(reserve)
        def expired(signum, frame):
            raise TimeoutError('pilot stage deadline exhausted')
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        started = self.clock()
        previous = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
            if previous_timer[0] > 0:
                signal.setitimer(signal.ITIMER_REAL, max(0.001, previous_timer[0] - (self.clock() - started)))


def bounded_command(budget, command, **kwargs):
    """Hand the remaining execution interval to the helper's own root timer."""
    total = min(kwargs.pop('total_seconds', 160), budget.remaining(600))
    capacity.require(total > 12, 'insufficient command capture and cleanup interval')
    timer = signal.getitimer(signal.ITIMER_REAL)
    previous = signal.getsignal(signal.SIGALRM)
    started = budget.clock()
    signal.setitimer(signal.ITIMER_REAL, 0)
    try:
        return bootstrap_command(command, total_seconds=total, **kwargs)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, max(0.001, timer[0] - (budget.clock() - started)))


bootstrap_command = bootstrap.run_readonly


def current_context(project):
    """Bound immediate checkout checks without modifying finalized journals."""
    def read(argv, *, timeout=30, accepted=(0,)):
        value = bootstrap_command(argv, total_seconds=30)
        capacity.require(value['status'] == 'PASS' and value['exit_code'] in accepted,
                         'bounded current checkout inspection failed')
        return {'stdout': base64.b64decode(value['stdout_base64'], validate=True).decode('utf-8')}
    return results.run_context(project, read)


def expected_paths(volume, closure, branch):
    capacity.require(branch in ('verified_bundle', 'frozen_results_image'), 'unknown export branch')
    payload = volume / ('group-results.tar.xz' if branch == 'verified_bundle' else 'reference-results.img')
    return [payload, volume / 'group-host-proof.tar', closure / 'group-closure.json']


def candidate(branch, volume, closure, source, context, controller_exit):
    paths = expected_paths(volume, closure, branch)
    rows = [dict(member(path), role=role) for path, role in
            zip(paths, (branch, 'host_proof', 'closure'), strict=True)]
    value = {'schema_version': 1, 'status': 'CANDIDATE', 'selected': branch,
             'source': source, 'run_context': context, 'controller_exit': controller_exit,
             'ordinal': 1, 'concurrency': 4, 'release_qualification': False,
             'full_reference_profiles': 'NOT RUN', 'custody': 'UNRESOLVED',
             'upload_paths': [str(path) for path in paths], 'members': rows,
             'final_journal': member(volume / 'group-control.json'),
             'admission': capacity.transport_limit({row['role']: row['bytes'] for row in rows})}
    verify_candidate(value, volume=volume, closure=closure, source=source,
                     context=context, controller_exit=controller_exit)
    return value


def verify_candidate(value, *, volume, closure, source, context, controller_exit):
    volume, closure = canonical(volume), canonical(closure)
    capacity.require(not closure.is_relative_to(volume) and not volume.is_relative_to(closure),
                     'closure containment differs')
    capacity.require(type(controller_exit) is int and controller_exit in (0, 1)
                     and re.fullmatch('[0-9a-f]{64}', source) is not None
                     and context.get('github_run_attempt') == '1', 'expected invocation differs')
    capacity.require(value.get('status') == 'CANDIDATE' and value.get('custody') == 'UNRESOLVED'
                     and value.get('release_qualification') is False
                     and value.get('ordinal') == 1 and value.get('concurrency') == 4
                     and value.get('full_reference_profiles') == 'NOT RUN'
                     and value.get('source') == source and value.get('run_context') == context
                     and value.get('controller_exit') == controller_exit,
                     'candidate invocation or scope differs')
    branch = value['selected']
    capacity.require((branch, controller_exit) in (('verified_bundle', 0), ('frozen_results_image', 1)),
                     'candidate branch and controller result differ')
    paths = expected_paths(volume, closure, branch)
    expected = [dict(member(canonical(path)), role=role) for path, role in
                zip(paths, (branch, 'host_proof', 'closure'), strict=True)]
    capacity.require(value['upload_paths'] == [str(path) for path in paths] and value['members'] == expected,
                     'export role, bytes, identity, or path changed')
    journal = member(volume / 'group-control.json')
    capacity.require(value.get('final_journal') == journal, 'final journal changed')
    receipt = results.read_json(paths[-1])
    capacity.require(receipt == results.read_json(volume / 'group-control.json')
                     and receipt.get('source') == source and receipt.get('run_context') == context
                     and receipt.get('status') == ('PASS' if controller_exit == 0 else 'FAIL')
                     and receipt.get('setup_state') == 'COMPLETE'
                     and receipt.get('image_unmounted') is True and receipt.get('selected') == branch
                     and receipt.get('release_qualification') is False
                     and receipt.get('custody') == 'UNRESOLVED', 'final closure does not authorize export')
    capacity.require(value['admission'] == capacity.transport_limit({row['role']: row['bytes'] for row in expected}),
                     'export admission changed')
    return [str(path) for path in paths]



def results_adapter(volume, image):
    # Load a separate module namespace: full-reference callers retain their exact
    # existing constants and lifecycle contracts even when imported in this process.
    spec = importlib.util.spec_from_file_location('_named_group_results', Path(results.__file__))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.IMAGE_BYTES = capacity.RESULT_IMAGE_BYTES
    module.PROBE_BYTES = 65 * MIB
    module.MAX_OUTER_BYTES = capacity.OUTER_IMAGE_BYTES
    def owned_paths(actual_volume, project):
        actual_volume, project = Path(actual_volume), Path(project)
        capacity.require(actual_volume == volume and project == volume / 'source', 'pilot owned paths differ')
        checked(actual_volume)
        checked(project, actual_volume)
        return {'volume': volume, 'project': project, 'image': volume / 'reference-results.img',
                'bootstrap': volume / 'reference-results-bootstrap', 'mount': project / '.local',
                'proof': volume / 'reference-results-setup.json', 'freeze': volume / 'reference-results-freeze.json',
                'outer_image': image}
    module.owned_paths = owned_paths
    original_outer = module.validate_outer
    def validate_outer(paths, runner, context, quota_root=None):
        capacity.require(checked(image).st_size == capacity.OUTER_IMAGE_BYTES, 'pilot outer size differs')
        value = original_outer(paths, runner, context, quota_root)
        quota_root = quota_root or paths['mount']
        quota = module.read_json(quota_root / 'reference-quota.json')
        refusal = quota_root / 'enospc.stderr'
        capacity.require(checked(refusal).st_size <= 32768 and file_sha(refusal) == quota.get('enospc_sha256')
                         and b'No space left on device' in refusal.read_bytes(), 'actual outer ENOSPC proof differs')
        return value
    module.validate_outer = validate_outer
    return module


def delegate_host_filesystem(mount, runner, uid, gid):
    recovery = mount / 'lost+found'
    root, before = checked(mount), checked(recovery)
    capacity.require(stat.S_ISDIR(root.st_mode) and stat.S_ISDIR(before.st_mode)
                     and root.st_dev == before.st_dev and stat.S_IMODE(before.st_mode) == 0o700
                     and (before.st_uid, before.st_gid) == (0, 0), 'unexpected recovery directory geometry')
    empty = runner(['sudo', '-n', 'find', str(recovery), '-mindepth', '1', '-maxdepth', '1', '-printf', '.', '-quit'])
    capacity.require(empty['stdout'] == '', 'new recovery directory is not empty')
    runner(['sudo', '-n', 'chown', '--no-dereference', f'{uid}:{gid}', '--', str(mount), str(recovery)])
    root_after, after = checked(mount), checked(recovery)
    capacity.require((root.st_dev, root.st_ino, root.st_mode) == (root_after.st_dev, root_after.st_ino, root_after.st_mode)
                     and (before.st_dev, before.st_ino, before.st_mode) == (after.st_dev, after.st_ino, after.st_mode)
                     and (root_after.st_uid, root_after.st_gid) == (after.st_uid, after.st_gid) == (uid, gid)
                     and not any(recovery.iterdir()), 'ordinary-user recovery directory access differs')


def bounded_filesystem(volume, name, size, runner):
    image, mount = volume / (name + '.img'), volume / name
    capacity.require(not os.path.lexists(image) and not os.path.lexists(mount), 'refusing reused evidence volume')
    mount.mkdir(mode=0o700)
    with image.open('xb'):
        pass
    runner(['fallocate', '-l', str(size), str(image)], timeout=60)
    initial = results.identity(image)
    capacity.require(initial[-1] == size, 'evidence image allocation differs')
    runner(['mkfs.ext4', '-F', '-q', '-m', '0', str(image)], timeout=60)
    runner(['sudo', '-n', 'mount', '-o', 'loop,nodev,nosuid,noexec', str(image), str(mount)])
    binding = results.observe_binding(mount, image, runner)
    delegate_host_filesystem(mount, runner, os.getuid(), os.getgid())
    # Exercise the physical boundary on each evidence filesystem, too.
    probe = mount / 'enospc-probe'
    observed = runner(['fallocate', '-l', str(size + MIB), str(probe)], accepted=(1,), timeout=60)
    capacity.require('No space left on device' in observed['stderr'], 'evidence ENOSPC not observed')
    info = checked(probe)
    capacity.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(),
                     'evidence probe ownership differs')
    probe.unlink()
    return {'image': image, 'mount': mount, 'identity': initial, 'binding': binding}


def available_bytes(path):
    usage = os.statvfs(path)
    return usage.f_bavail * usage.f_frsize


def record_capacity(path, size):
    capacity.require(type(size) is int and 0 <= size <= 2 * MIB
                     and available_bytes(path) >= size + 256 * 1024,
                     'control record or reserved failure capacity exhausted')


def retain_bootstrap(source, destination):
    # Reserve actual usable space for future metadata, independently of nominal
    # image size. Failure leaves the compressed partial and original untouched.
    limit = available_bytes(destination.parent) - 2 * MIB
    capacity.require(limit > 0, 'bootstrap custody cannot preserve metadata reserve')
    with destination.open('xb') as raw:
        with gzip.GzipFile(fileobj=evidence_bundle.LimitedWriter(raw, limit), mode='wb', mtime=0) as encoded:
            with tarfile.open(fileobj=encoded, mode='w|', format=tarfile.USTAR_FORMAT) as archive:
                for path in sorted(source.iterdir()):
                    info = checked(path)
                    capacity.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                                     'bootstrap proof member is not a unique regular file')
                    archive.add(path, arcname=path.name, recursive=False)


def close_filesystem(item, runner):
    capacity.require(results.identity(item['image']) == item['identity']
                     and results.observe_binding(item['mount'], item['image'], runner) == item['binding'],
                     'evidence backing changed')
    runner(['sync', '-f', str(item['mount'])], timeout=60)
    runner(['sudo', '-n', 'umount', '--', str(item['mount'])], timeout=60)
    loops = runner(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(item['image']),
                    '--output', 'NAME,BACK-FILE'])
    capacity.require(not os.path.ismount(item['mount']) and json.loads(loops['stdout'])['loopdevices'] == []
                     and results.identity(item['image']) == item['identity'], 'evidence image remains active')


def verify_bundle(bundle, project, context, source):
    with bundle.open('rb') as stream:
        verified = evidence_bundle.verify_stream(evidence_bundle.XZReader(stream), None)
    capacity.require(all(verified[key] == expected for key, expected in
                         (('source', source), ('commit', context['commit']), ('run_id', context['github_run_id']))),
                     'decoded result identity differs')
    with bundle.open('rb') as stream:
        raw = evidence_bundle.transport_item(evidence_bundle.XZReader(stream), 'manifest.json', evidence_bundle.MAX_MANIFEST)
    manifest = json.loads(raw, object_pairs_hook=evidence_bundle.unique_object)
    verify_live_members(project, manifest)
    return verified


def verify_guest(project, volume, source, context):
    """Repeat the selected-group binding against the unchanged grid on the host."""
    from benchmark import (FROZEN_GRID_SHA256, frozen_group_selection, grid_groups,
                           group_selection_bytes, verify_group_execution)
    setup = results.read_json(volume / 'reference-guest/setup.json')
    result_path = project / '.local/reference-guest-result.json'
    result = results.read_json(result_path)
    start_path = project / '.local/reference-benchmark-start.json'
    start = results.read_json(start_path)
    capacity.require(setup.get('status') == result.get('status') == 'PASS'
                     and result.get('exit_code') == 0 and setup.get('source') == result.get('source') == source
                     and setup.get('run_context') == result.get('run_context') == context
                     and setup.get('execution_id') == result.get('execution_id') == start.get('execution_id')
                     and start.get('source') == source and start.get('run_context') == context
                     and start.get('frozen_group') == 1 and start.get('concurrency') == 4
                     and start.get('profile') == 'full' and start.get('release_qualification') is False
                     and setup.get('guest_result_sha256') == file_sha(result_path)
                     and result.get('benchmark_start_sha256') == file_sha(start_path), 'guest execution binding differs')
    grid = (project / 'benchmarks/grid.json').read_bytes()
    capacity.require(hashlib.sha256(grid).hexdigest() == FROZEN_GRID_SHA256, 'frozen grid changed')
    config = json.loads(grid)['full']
    config['concurrency'] = 4
    cfg_hash = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:12]
    groups, cells, _ = grid_groups(config)
    selection = group_selection_bytes(frozen_group_selection(config, groups, 1, source, cfg_hash))
    folder = f'.local/benchmarks/full-{source[:12]}-{cfg_hash}-group-001'
    capacity.require(start.get('folder') == result.get('benchmark_folder') == folder
                     and start.get('config') == config, 'guest benchmark folder or full config differs')
    observed = verify_group_execution(project / folder, selection, config, cells)
    capacity.require(observed == setup.get('benchmark_group') == result.get('benchmark_group')
                     and observed['group_cells'] == 60 and observed['group_samples'] == 60000
                     and observed['release_qualification'] is False, 'complete 60-cell selected result differs')
    return observed


def pilot_setup_metadata(manifest, source, context):
    # Bind the initial journal before its first command. Later writes require
    # the same context independently collected from the guest helper's Git checks.
    manifest.setdefault('run_context', dict(context))
    capacity.require(manifest.get('source') == source and manifest['run_context'] == context,
                     'guest setup identity differs')
    return (json.dumps(manifest, indent=2) + '\n').encode()


def failure_evidence(stage, error, volume):
    value = {'stage': stage, 'type': type(error).__name__}
    if isinstance(error, OSError):
        locations = {
            volume / 'reference-guest/commands/lost+found': 'guest.commands/lost+found',
            volume / 'reference-guest/setup.json': 'guest.setup',
            volume / 'group-records/lost+found': 'host.controls/lost+found',
        }
        name = Path(error.filename) if isinstance(error.filename, str) else None
        value.update(errno=error.errno, location=locations.get(name, 'unknown'))
    sources = {'reference_group_job.py', 'reference_guest.py', 'reference_results.py',
               'reference_group_bootstrap.py', 'evidence_bundle.py'}
    frames = []
    for frame in traceback.extract_tb(error.__traceback__):
        path = Path(frame.filename)
        if path.parent == ROOT / 'scripts' and path.name in sources:
            frames.append({'file': path.name, 'line': frame.lineno})
    if frames:
        value['frames'] = frames[-3:]
    return value


def publish_candidate(volume, closure, report):
    """Persist all final state before the sole externally selectable manifest."""
    results.save(volume / 'group-control.json', report)
    write_proof(closure / 'group-closure.json', report, initial=True)
    value = candidate(report['selected'], volume, closure, report['source'], report['run_context'],
                      int(report['status'] != 'PASS'))
    write_proof(closure / 'candidate.json', value, initial=True)
    return value


def run(volume, image, closure, timeout, *, host_control=False):
    capacity.require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.getuid() != 0,
                     'ordinary Linux x86_64 required')
    context = approved_context(os.environ)
    volume, image, closure = fresh_paths(volume, image, closure)
    invocation_paths(volume, image, closure, os.environ)
    budget = Budget(timeout)
    project = volume / 'source'
    capacity.require(ROOT == project and Path.cwd() == project and os.path.ismount(volume)
                     and not closure.is_relative_to(volume),
                     'exact checkout/mount/closure scope differs')
    checked(volume)
    checked(closure)
    capacity.require(not os.environ.get('FQ_FILESYSTEM_POLICY') and not os.environ.get('FQ_RESERVATION_PROFILE'),
                     'pilot cannot inherit a full-reference profile')
    capacity.require(checked(image).st_size == capacity.OUTER_IMAGE_BYTES, 'exact pilot outer image required')
    report = {'status': 'FAIL', 'source': source_hash(project), 'run_context': context,
              'commands': [], 'errors': [], 'setup_state': 'NOT_STARTED',
              'release_qualification': False, 'custody': 'UNRESOLVED'}
    if host_control:
        report.update(scope='host-filesystem-control-v1', kvm='NOT RUN', measured_cells=0)
    control_path = volume / 'group-control.json'
    write_proof(control_path, report, initial=True)
    runner = results.Commands(report, control_path)
    adapter = results_adapter(volume, image)
    streams = controls = None
    freeze_record = None
    payload = None
    branch = None
    execution_alarm = budget.stage(reserve=600)
    execution_alarm.__enter__()
    try:
        capacity.require(results.run_context(project, runner) == context, 'checkout run identity differs')
        paths = adapter.owned_paths(volume, project)
        report['outer'] = adapter.validate_outer(paths, runner, context)
        for phase in ('checkout',):
            bootstrap.admit(volume, phase, report.setdefault('space_holder', {'space': []}),
                            STREAM_BYTES + CONTROL_BYTES + capacity.RESULT_IMAGE_BYTES, 128)
        streams = bounded_filesystem(volume, 'group-streams', STREAM_BYTES, runner)
        controls = bounded_filesystem(volume, 'group-records', CONTROL_BYTES, runner)
        report['host_usable_bytes'] = {'streams': available_bytes(streams['mount']),
                                       'controls': available_bytes(controls['mount']),
                                       'control_failure_reserve': 256 * 1024,
                                       'bootstrap_future_metadata_reserve': 2 * MIB}
        original_save = adapter.save
        def save(path, value, *, initial=False):
            record_capacity(controls['mount'], len(json.dumps(value).encode()) + 1)
            original_save(controls['mount'] / path.name, value,
                          initial=not (controls['mount'] / path.name).exists())
            original_save(path, value, initial=initial)
        adapter.save = save
        original_command = bootstrap.run_readonly
        bootstrap.run_readonly = lambda command, **kwargs: bounded_command(budget, command, **kwargs)
        try:
            with budget.stage(reserve=600):
                bootstrap.build(volume, project, volume / 'bootstrap-proof')
        finally:
            bootstrap.run_readonly = original_command
        # The build journal binds actual trim to retained binaries. No preflight
        # scientific/release gate is inferred from this narrow source build.
        build = results.read_json(volume / 'bootstrap-proof/build.json')
        capacity.require(build['status'] == 'PASS' and build['source'] == report['source'], 'build journal differs')
        if host_control:
            report['pinned_build'] = {'go': build['go'], 'space': build['space'],
                                      'installed_bytes': build['sdk_inventory']['required_bytes'],
                                      'installed_members': build['sdk_installed']['members'],
                                      'journal_sha256': file_sha(volume / 'bootstrap-proof/build.json')}
        write_proof(project / '.local/reference-preflight-trim.json',
                    {'status': 'PASS', 'source': report['source'], 'volume': str(volume),
                     'project': str(project), 'build_journal_sha256': file_sha(volume / 'bootstrap-proof/build.json'),
                     'scope': 'Pinned pilot binaries and SDK trim only; no release qualification.'}, initial=True)
        report['setup_state'] = 'INCOMPLETE_LOCAL_ONLY'
        with budget.stage(reserve=600):
            adapter.setup(volume, project)
        report['setup_state'] = 'COMPLETE'
        original_setup = guest.Setup
        class PilotSetup(original_setup):
            def __init__(self, args):
                super().__init__(args)
                runner(['sudo', '-n', 'mount', '--move', str(streams['mount']), str(self.logs)])
                streams['mount'] = self.logs
                streams['binding'] = results.observe_binding(self.logs, streams['image'], runner)
            def save(self):
                raw = pilot_setup_metadata(self.manifest, report['source'], context)
                capacity.require(len(raw) < 2 * MIB, 'guest control metadata exceeds reservation')
                target = controls['mount'] / 'setup.json'
                record_capacity(controls['mount'], len(raw))
                target.write_bytes(raw)
                super().save()
            def run(self, command, **kwargs):
                output = super().run(command, **kwargs)
                self.check()
                return output
            def check(self, growth=0):
                used = super().check(growth)
                capacity.require(available_bytes(self.logs) >= 256 * 1024,
                                 'capture filesystem full; complete streams unproved')
                capacity.require(sum(p.stat().st_size for p in self.logs.iterdir() if p.is_file()) < 18 * MIB,
                                 'aggregate command capture exhausted; complete streams unproved')
                return used
        # Losslessly retain the potentially large trim inventory within the
        # physically bounded control filesystem; compression earns no admission.
        retain_bootstrap(volume / 'bootstrap-proof', controls['mount'] / 'bootstrap-proof.tar.gz')
        guest.Setup = PilotSetup
        previous = sys.argv
        try:
            sys.argv = ['reference_guest.py', '--volume', str(volume), '--project', str(project),
                        '--mode', 'benchmark', '--profile', 'full', '--concurrency', '4', '--frozen-group', '1',
                        '--source-policy', 'reference-tracked-source-tmpfs-v1',
                        '--timeout', str(budget.remaining(reserve=1200)),
                        '--setup-max-bytes', '440000000']
            with (streams['mount'] / 'controller.stdout').open('w') as output, contextlib.redirect_stdout(output):
                with budget.stage(reserve=600):
                    if host_control:
                        setup = PilotSetup(argparse.Namespace(volume=volume, project=project,
                            timeout=budget.remaining(reserve=1200), setup_max_bytes=440_000_000,
                            source_policy='reference-tracked-source-tmpfs-v1'))
                        git_head = setup.run(['git', 'rev-parse', 'HEAD']).strip()
                        git_status = setup.run(['git', 'status', '--porcelain']).strip()
                        capacity.require(git_head == context['commit'] and git_status == context['git_status'],
                                         'host control checkout binding differs')
                        setup.manifest.update(status='PASS', scope='ordinary runtime traversed the owned host filesystems')
                        setup.save()
                        report['ordinary_guest_setup'] = {'git_commit': git_head, 'git_status': git_status,
                                                          'commands': len(setup.records)}
                        report['host_control_status'] = 'PASS'
                    else:
                        guest.main()
        finally:
            guest.Setup = original_setup
            sys.argv = previous
        if not host_control:
            verify_guest(project, volume, report['source'], context)
            report['workload_status'] = 'PASS'
    except BaseException as error:
        report['errors'].append(failure_evidence('execution', error, volume))
    finally:
        execution_alarm.__exit__(None, None, None)
        try:
            closure_alarm = budget.stage()
            closure_alarm.__enter__()
            if (volume / 'reference-results-setup.json').exists():
                setup = results.read_json(volume / 'reference-results-setup.json')
                if setup.get('status') == 'PASS':
                    guest_setup = volume / 'reference-guest/setup.json'
                    if guest_setup.exists():
                        destination = project / '.local/reference-guest-setup'
                        destination.mkdir(exist_ok=False)
                        shutil.copyfile(guest_setup, destination / 'setup.json')
                    adapter.quiesce_guest(volume, project)
                    if report.get('workload_status') == 'PASS':
                        try:
                            bootstrap.admit(volume, 'pack', {'space': []}, capacity.PACKET_BYTES + capacity.HOST_PROOF_BYTES)
                            bundle = volume / 'group-results.tar.xz'
                            with budget.stage(reserve=300):
                                evidence_bundle.pack(project, bundle, report['source'], context['commit'],
                                                     context['github_run_id'], ['.local'], preset=1,
                                                     output_limit_bytes=capacity.PACKET_BYTES)
                                report['decoded_readback'] = verify_bundle(bundle, project, context, report['source'])
                            payload, branch = bundle, 'verified_bundle'
                        except BaseException as error:
                            report['errors'].append(failure_evidence('pack', error, volume))
                    freeze_record = adapter.freeze(volume, project, setup)
                    if payload is None and not host_control:
                        payload, branch = volume / 'reference-results.img', 'frozen_results_image'
            capacity.require(freeze_record is not None and freeze_record['status'] == 'PASS',
                             'no safely closed complete results image; upload refused')
            for item in (streams, controls):
                capacity.require(item is not None, 'missing bounded host filesystem')
                close_filesystem(item, runner)
            report.update(status='PASS' if not report['errors'] else 'FAIL', selected=branch,
                          image_sha256=freeze_record['image_sha256'], image_unmounted=True)
            if host_control:
                report['host_filesystems_unmounted'] = True
                report['postclosure_available_bytes'] = available_bytes(volume)
                results.save(control_path, report)
                encoded = (json.dumps(report, sort_keys=True) + '\n').encode()
                capacity.require(len(encoded) <= 96 * 1024, 'host control report exceeds admission')
                with (closure / 'host-control.json').open('xb') as stream:
                    stream.write(encoded)
                print(json.dumps({'status': report['status'], 'measured_cells': 0, 'kvm': 'NOT RUN'}))
            else:
                host = volume / 'group-host-proof.tar'
                with tarfile.open(host, 'x', format=tarfile.USTAR_FORMAT) as archive:
                    for item in (streams, controls):
                        archive.add(item['image'], arcname=item['image'].name, recursive=False)
                capacity.require(host.stat().st_size <= capacity.HOST_PROOF_BYTES, 'host proof exceeds cap')
                publish_candidate(volume, closure, report)
                print(json.dumps({'status': report['status'], 'candidate': str(closure / 'candidate.json'),
                                  'release_qualification': False}))
        except BaseException as error:
            report['errors'].append(failure_evidence('closure', error, volume))
            report['status'] = 'FAIL'
            # Preserve outer and every partial object. No candidate means no upload.
            failed = closure / 'group-failure.json'
            if not failed.exists():
                write_proof(failed, report, initial=True)
            print(json.dumps({'status': 'FAIL', 'candidate': None, 'release_qualification': False}))
        finally:
            if 'closure_alarm' in locals():
                closure_alarm.__exit__(None, None, None)
    return int(report['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    work = actions.add_parser('run')
    for name in ('volume', 'image', 'closure'):
        work.add_argument('--' + name, type=Path, required=True)
    work.add_argument('--timeout', type=int, default=5400)
    work.add_argument('--host-control', action='store_true')
    verify = actions.add_parser('verify-candidate')
    verify.add_argument('manifest', type=Path)
    for name in ('volume', 'image', 'closure'):
        verify.add_argument('--' + name, type=Path, required=True)
    verify.add_argument('--source', required=True)
    verify.add_argument('--controller-exit', type=int, choices=(0, 1), required=True)
    args = parser.parse_args()
    if args.action == 'verify-candidate':
        volume, image, closure = [canonical(path) for path in (args.volume, args.image, args.closure)]
        invocation_paths(volume, image, closure, os.environ)
        capacity.require(current_context(volume / 'source') == approved_context(os.environ),
                         'checkout execution context changed before export')
        capacity.require(checked(image).st_size == capacity.OUTER_IMAGE_BYTES
                         and results.identity(image) == results.read_json(volume / 'group-control.json')['outer']['image_identity'],
                         'outer identity differs at export')
        capacity.require(canonical(args.manifest) == closure / 'candidate.json'
                         and image.parent == volume.parent and not image.is_relative_to(volume)
                         and source_hash(volume / 'source') == args.source, 'verification scope differs')
        for path in verify_candidate(results.read_json(args.manifest), volume=volume, closure=closure,
                                     source=args.source, context=approved_context(os.environ),
                                     controller_exit=args.controller_exit):
            print(path)
        return 0
    return run(args.volume, args.image, args.closure, args.timeout, host_control=args.host_control)


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise SystemExit('interrupted pilot')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())
