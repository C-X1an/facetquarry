"""Bound reference results by a nested ext4 image; preserve it without deletion.

Setup runs directly after all previous evidence writers finish. Freeze runs from
outside source/.local after metadata export. Local fixture tests do not claim a
Linux mount, ENOSPC probe, guest shutdown, or recoverable filesystem measurement.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

from common import ROOT, source_hash
from reference_preflight import checked, descriptor_matches, file_sha, stamp

IMAGE_BYTES = 1_100_000_000
PROBE_BYTES = 1_200_000_000
MAX_OUTER_BYTES = 3_300_000_000
MAX_BOOTSTRAP_BYTES = 200_000_000
MAX_ENTRIES = 30_000
MAX_METADATA = 16_000_000
MAX_RESCUE_ZIP = 350_000_000
MAX_RESCUE_NAME_BYTES = 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def identity(path):
    info = checked(path)
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_size]


def fixed_identity(path):
    info = checked(path)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == IMAGE_BYTES,
            'results image is not the exact fixed regular file')
    return identity(path)


def read_json(path):
    info = checked(path)
    require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_METADATA, 'metadata admission exceeded')
    raw = path.read_bytes()
    require(stamp(checked(path)) == stamp(info) and len(raw) == info.st_size, 'metadata changed while reading')
    return json.loads(raw)


def save(path, record, *, initial=False):
    checked(path.parent)
    target = path if initial else path.with_suffix('.tmp')
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    size = 0
    with os.fdopen(descriptor, 'wb') as stream:
        for part in json.JSONEncoder(sort_keys=True, separators=(',', ':')).iterencode(record):
            raw = part.encode()
            size += len(raw)
            require(size < MAX_METADATA, 'results proof admission exceeded')
            stream.write(raw)
        stream.write(b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    if not initial:
        os.replace(target, path)


class Commands:
    def __init__(self, record, proof):
        self.record, self.proof = record, proof

    def __call__(self, command, *, timeout=30, accepted=(0,)):
        require(1 <= timeout <= 120, 'command deadline outside bounds')
        actual = command
        if command[:2] == ['sudo', '-n']:
            # The root-owned timeout also ends its child if this ordinary-user
            # wrapper is interrupted. Never stop unrelated systemd units.
            actual = ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=5s',
                      str(timeout) + 's', *command[2:]]
        item = {'command': command, 'actual_command': actual, 'timeout_seconds': timeout,
                'started_at': utc(), 'exit_code': None}
        self.record['commands'].append(item)
        save(self.proof, self.record)
        try:
            result = subprocess.run(actual, capture_output=True, timeout=timeout + 10)
            require(len(result.stdout) + len(result.stderr) <= 1_000_000, 'command output admission exceeded')
            item.update(exit_code=result.returncode, stdout=result.stdout.decode('utf-8', errors='replace'),
                        stderr=result.stderr.decode('utf-8', errors='replace'),
                        stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
                        stderr_sha256=hashlib.sha256(result.stderr).hexdigest())
            require(result.returncode in accepted, 'results command failed: ' + str(command))
            return item
        except BaseException as failure:
            item['error'] = type(failure).__name__ + ': ' + str(failure)
            raise
        finally:
            item['ended_at'] = utc()
            save(self.proof, self.record)


def owned_paths(volume, project):
    volume, project = Path(volume), Path(project)
    checked(volume)
    checked(project)
    require(volume.name == 'facetquarry-reference' and project == volume / 'source', 'unexpected owned paths')
    require(project.lstat().st_dev == volume.lstat().st_dev, 'source is not in the outer filesystem')
    return {'volume': volume, 'project': project, 'image': volume / 'reference-results.img',
            'bootstrap': volume / 'reference-results-bootstrap', 'mount': project / '.local',
            'proof': volume / 'reference-results-setup.json', 'freeze': volume / 'reference-results-freeze.json',
            'outer_image': volume.parent / 'facetquarry-reference.img'}


def mount_binding(target, image, observation, association):
    mounts = observation.get('filesystems', [])
    loops = association.get('loopdevices', [])
    require(len(mounts) == len(loops) == 1, 'mount/backing observation is ambiguous')
    mount, loop = mounts[0], loops[0]
    require(mount.get('target') == str(target) and mount.get('fstype') == 'ext4'
            and re.fullmatch(r'/dev/loop[0-9]+', str(mount.get('source', ''))) is not None,
            'exact ext4 loop mountpoint differs')
    require(loop.get('name') == mount['source'] and loop.get('back-file') == str(image),
            'loop does not back the exact owned image')
    return {'mount': mount, 'loop': loop}


def observe_binding(target, image, runner):
    mounted = runner(['findmnt', '--json', '--target', str(target), '-o', 'TARGET,FSTYPE,SOURCE'])
    loop = runner(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                   '--output', 'NAME,BACK-FILE'])
    return mount_binding(target, image, json.loads(mounted['stdout']), json.loads(loop['stdout']))


def inventory(root):
    """Enumerate every bootstrap member, refusing links and cross-device data."""
    base = checked(root)
    entries, seen, total = [], set(), 0
    stack = [root]
    while stack:
        path = stack.pop()
        info = checked(path)
        require(info.st_dev == base.st_dev, 'bootstrap crosses a filesystem')
        inode = (info.st_dev, info.st_ino)
        require(inode not in seen and len(entries) < MAX_ENTRIES, 'duplicate inode or member admission exceeded')
        seen.add(inode)
        relative = path.relative_to(root).as_posix()
        item = {'path': relative, 'identity': list(stamp(info)),
                'directory': stat.S_ISDIR(info.st_mode)}
        if item['directory']:
            names = sorted(child.name for child in path.iterdir())
            require(len(names) + len(stack) + len(entries) <= MAX_ENTRIES, 'member admission exceeded')
            stack.extend(path / name for name in reversed(names))
        else:
            require(stat.S_ISREG(info.st_mode), 'nonregular bootstrap member')
            total += info.st_size
            require(total <= MAX_BOOTSTRAP_BYTES, 'bootstrap byte admission exceeded')
            item.update(bytes=info.st_size, sha256=file_sha(path, item['identity']))
        entries.append(item)
    require(not any(item['path'] == 'lost+found' or item['path'].startswith('lost+found/') for item in entries),
            'bootstrap uses reserved filesystem recovery directory')
    return {'entries': entries, 'logical_bytes': total}


def copy_bootstrap(bootstrap, destination, manifest):
    require(inventory(bootstrap) == manifest, 'bootstrap changed before bounded copy')
    checked(destination)
    for item in manifest['entries']:
        if item['path'] == '.':
            continue
        source, target = bootstrap / item['path'], destination / item['path']
        checked(target.parent)
        require(not target.exists() and not target.is_symlink(), 'copy destination already exists')
        if item['directory']:
            target.mkdir(mode=stat.S_IMODE(item['identity'][2]))
            continue
        descriptor = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
        try:
            require(descriptor_matches(os.fstat(descriptor), item['identity']), 'copy source inode changed')
            target_descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                        | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0),
                                        stat.S_IMODE(item['identity'][2]))
            digest, count = hashlib.sha256(), 0
            with os.fdopen(target_descriptor, 'wb') as output:
                with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                    while block := stream.read(1024 * 1024):
                        count += len(block)
                        require(count <= item['bytes'], 'copy source grew beyond manifest')
                        digest.update(block)
                        output.write(block)
                output.flush()
                os.fsync(output.fileno())
            require(count == item['bytes'] and digest.hexdigest() == item['sha256']
                    and descriptor_matches(os.fstat(descriptor), item['identity'])
                    and stamp(checked(source)) == tuple(item['identity']), 'copy bytes or source changed')
        finally:
            os.close(descriptor)
    require(inventory(bootstrap) == manifest, 'bootstrap changed during copy')
    verify_copy(bootstrap, destination, manifest)


def verify_copy(bootstrap, destination, manifest):
    require(inventory(bootstrap) == manifest, 'retained bootstrap differs')
    expected = {item['path']: item for item in manifest['entries']}
    seen, stack, device = set(), [destination], destination.lstat().st_dev
    while stack:
        path = stack.pop()
        info = checked(path)
        require(info.st_dev == device, 'copied results cross a filesystem')
        relative = path.relative_to(destination).as_posix()
        if relative == 'lost+found':
            require(stat.S_ISDIR(info.st_mode) and not any(path.iterdir()), 'unexpected recovery directory content')
            continue
        require(relative in expected and relative not in seen, 'copied membership differs')
        seen.add(relative)
        entry = expected[relative]
        require(stat.S_ISDIR(info.st_mode) == entry['directory'], 'copied member type differs')
        if entry['directory']:
            stack.extend(path.iterdir())
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_size == entry['bytes']
                    and file_sha(path) == entry['sha256'], 'copied bytes differ')
    require(seen == set(expected), 'copied membership is incomplete')
    return len(seen)


def run_context(project, runner):
    commit = runner(['git', '-C', str(project), 'rev-parse', 'HEAD'])['stdout'].strip()
    state = runner(['git', '-C', str(project), 'status', '--porcelain'])['stdout'].strip()
    context = {'commit': commit, 'git_status': state, 'github_run_id': os.environ.get('GITHUB_RUN_ID'),
               'github_run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT')}
    require(re.fullmatch('[0-9a-f]{40}', commit) is not None and not state, 'checkout is not clean and committed')
    require(all(re.fullmatch('[1-9][0-9]{0,19}', context[key] or '') is not None
                for key in ('github_run_id', 'github_run_attempt')), 'workflow execution identity missing')
    return context


def validate_outer(paths, runner, context, quota_root=None):
    outer = checked(paths['outer_image'])
    require(stat.S_ISREG(outer.st_mode) and outer.st_uid == os.getuid() and outer.st_nlink == 1
            and IMAGE_BYTES < outer.st_size <= MAX_OUTER_BYTES, 'outer image identity/ceiling differs')
    binding = observe_binding(paths['volume'], paths['outer_image'], runner)
    quota_root = quota_root or paths['mount']
    quota_path = quota_root / 'reference-quota.json'
    quota = read_json(quota_path)
    require(quota.get('hard_quota_enforced') is True and quota.get('volume_file_bytes') == outer.st_size
            and quota.get('volume_path') == str(paths['volume']) and quota.get('image_path') == str(paths['outer_image'])
            and quota.get('oversized_allocation') == 'DENIED_ENOSPC'
            and quota.get('mount') == binding['mount'] and quota.get('run_context') == context,
            'outer quota/mount proof differs')
    result = {'binding': binding, 'image_identity': identity(paths['outer_image']),
              'volume_identity': identity(paths['volume'])[:5], 'quota_sha256': file_sha(quota_path)}
    if os.environ.get('FQ_FILESYSTEM_POLICY') or quota.get('filesystem_policy'):
        from reference_filesystem import POLICY
        from reference_filesystem_bindings import validate
        require(os.environ.get('FQ_FILESYSTEM_POLICY') == quota.get('filesystem_policy') == POLICY,
                'declared filesystem policy is missing or differs')
        proof = validate(Path(os.environ['GITHUB_WORKSPACE']) / '.local/reference-filesystem/outer',
                         paths['outer_image'], paths['volume'], outer.st_size,
                         {**context, 'source': source_hash(paths['project'])})
        require(proof == quota.get('filesystem_proof'), 'retained outer filesystem proof changed')
        result.update(filesystem_policy=POLICY, filesystem_proof=proof)
    return result


def rescue_zip_admission(root, manifest):
    """Bound stored-ZIP data and names, counting all files AND directories.

    2048 bytes/member covers ZIP/ZIP64 headers, descriptors and a duplicated
    upload-root prefix up to 512 bytes. The selected absolute root is bounded
    accordingly; no archive comments or custom metadata are authorized.
    """
    require(len(str(root).encode('utf-8')) <= 512, 'rescue upload root name exceeds admission')
    # The upload also retains the complete canonical rescue proof beside the
    # selected directory, including its original inventory. Reserve its maximum
    # encoding before creation instead of relying on a reduced metadata packet.
    headers, logical, names = 1_000_000 + MAX_METADATA + 4096, 0, set()
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)),
                *(f'LPT{i}' for i in range(1, 10))}
    for item in manifest['entries']:
        name = item['path']
        encoded = name.encode('utf-8')
        require(len(encoded) <= MAX_RESCUE_NAME_BYTES and name not in names,
                'rescue member name/count admission exceeded')
        names.add(name)
        if name != '.':
            require(not name.startswith('/') and '\\' not in name, 'nonportable rescue member name')
            for part in name.split('/'):
                require(part not in ('', '.', '..') and len(part.encode('utf-8')) <= 240
                        and part.rstrip(' .') == part and part.split('.')[0].upper() not in reserved
                        and not any(ord(char) < 32 or ord(char) == 127 or char in '<>:"|?*' for char in part),
                        'nonportable rescue member component')
        headers += 2048 + 2 * (len(encoded) + int(item['directory']))
        if not item['directory']:
            logical += item['bytes']
    require(len(names) <= MAX_ENTRIES and logical == manifest['logical_bytes'] <= MAX_BOOTSTRAP_BYTES,
            'rescue byte/member admission exceeded')
    upper = logical + headers
    require(upper <= MAX_RESCUE_ZIP, 'rescue ZIP admission exceeded')
    return {'selected_bytes': logical, 'selected_members': len(names), 'zip_upper_bound_bytes': upper,
            'maximum_zip_bytes': MAX_RESCUE_ZIP, 'compression_level': 0,
            'scope': 'Stored ZIP of exactly this premeasurement directory; includes every member/name and bounded headers.'}


def assert_premeasurement(paths):
    require(not os.path.lexists(paths['volume'] / 'reference-guest'), 'guest setup already started; bootstrap rescue forbidden')
    for root in (paths['mount'], paths['bootstrap']):
        if not os.path.lexists(root):
            continue
        checked(root)
        for name in ('reference-benchmark-start.json', 'reference-guest-result.json'):
            require(not os.path.lexists(root / name), 'guest measurement marker exists; bootstrap rescue forbidden')
        benchmarks = root / 'benchmarks'
        if os.path.lexists(benchmarks):
            checked(benchmarks)
            require(not any(path.name.startswith(('full-', 'diagnostic-')) for path in benchmarks.iterdir()),
                    'scientific/diagnostic benchmark namespace already exists')
        progress = root / 'reference-progress.json'
        if os.path.lexists(progress):
            value = read_json(progress)
            require(not value.get('execution_id') and value.get('profile') == 'smoke',
                    'guest progress exists; bootstrap rescue forbidden')


def original_selection(paths, canonical):
    require(canonical is None or canonical.get('status') in ('FAIL', 'PREPARING'),
            'bootstrap rescue is only for incomplete results setup')
    relocated = os.path.lexists(paths['bootstrap'])
    selected = paths['bootstrap'] if relocated else paths['mount']
    require(checked(selected).st_dev == checked(paths['volume']).st_dev,
            'original bootstrap is not in the outer filesystem')
    observed = inventory(selected)
    expected = canonical.get('initial_bootstrap') if canonical else None
    if expected is None:
        require(not relocated and not os.path.lexists(paths['image']) and not os.path.ismount(paths['mount']),
                'relocation/image exists without the original pre-rename inventory')
        expected = observed
    require(len(observed['entries']) == len(expected['entries']) and observed['logical_bytes'] == expected['logical_bytes'],
            'original bootstrap membership/bytes changed')
    for actual, initial in zip(observed['entries'], expected['entries']):
        if relocated and actual['path'] == initial['path'] == '.':
            # Renaming the root changes its ctime. Every other field, every
            # descendant inode/stamp, and every original file SHA remain bound.
            actual = {**actual, 'identity': actual['identity'][:5] + initial['identity'][5:6] + actual['identity'][6:]}
        require(actual == initial, 'original bootstrap bytes/inodes changed')
    return selected, observed, rescue_zip_admission(selected, observed)


def validate_rescue_context(canonical, paths, current_source, context, outer):
    if canonical is None:
        return
    require(canonical.get('status') in ('FAIL', 'PREPARING') and canonical.get('source') == current_source
            and canonical.get('paths') == {key: str(value) for key, value in paths.items()},
            'rescue setup source/state/paths differ')
    require(canonical.get('run_context', context) == context, 'rescue workflow execution differs')
    if 'outer' in canonical:
        require(canonical['outer'] == outer, 'rescue outer image/quota/binding changed')
    if 'project_identity' in canonical:
        require(canonical['project_identity'] == identity(paths['project'])[:5], 'rescue source checkout inode changed')


def setup(volume, project):
    require(sys.platform == 'linux' and os.getuid() != 0, 'requires ordinary Linux reference runner')
    paths = owned_paths(volume, project)
    require(project == ROOT, 'setup must execute from owned source checkout')
    require(not os.path.ismount(paths['mount']) and checked(paths['mount']).st_dev == checked(volume).st_dev,
            'initial .local is not an ordinary directory in the outer filesystem')
    for label in ('image', 'bootstrap', 'proof', 'freeze'):
        require(not paths[label].exists() and not paths[label].is_symlink(), 'refusing existing results path: ' + label)
    record = {'schema_version': 1, 'evidence_type': 'reference_results_setup', 'status': 'PREPARING',
              'source': source_hash(project), 'started_at': utc(), 'commands': [],
              'paths': {key: str(value) for key, value in paths.items()}, 'image_bytes': IMAGE_BYTES,
              'project_identity': identity(project)[:5],
              'oversized_probe_bytes': PROBE_BYTES,
              'scope': 'Nested fixed ext4 results image; physical backing is inside the admitted outer image. Full inventories exclude nothing.'}
    save(paths['proof'], record, initial=True)
    runner = Commands(record, paths['proof'])
    try:
        record['run_context'] = run_context(project, runner)
        record['outer'] = validate_outer(paths, runner, record['run_context'])
        trim_path = paths['mount'] / 'reference-preflight-trim.json'
        trimmed = read_json(trim_path)
        require(trimmed.get('status') == 'PASS' and trimmed.get('source') == record['source']
                and trimmed.get('volume') == str(volume) and trimmed.get('project') == str(project),
                'current owned SDK trim PASS is required before allocating nested results')
        record['trim_sha256'] = file_sha(trim_path)
        require(shutil.disk_usage(volume).free >= IMAGE_BYTES + 500_000_000, 'nested allocation would consume outer 500MB reserve')
        # Persist the complete original inventory before relocation. Recovery
        # must never infer originals from an incomplete child copy.
        record['initial_bootstrap'] = inventory(paths['mount'])
        record['initial_bootstrap_zip'] = rescue_zip_admission(paths['mount'], record['initial_bootstrap'])
        save(paths['proof'], record)
        paths['mount'].rename(paths['bootstrap'])
        record['bootstrap'] = inventory(paths['bootstrap'])
        paths['mount'].mkdir()
        descriptor = os.open(paths['image'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        runner(['fallocate', '-l', str(IMAGE_BYTES), str(paths['image'])], timeout=60)
        record['image_identity'] = fixed_identity(paths['image'])
        policy = os.environ.get('FQ_FILESYSTEM_POLICY', '')
        if policy:
            from reference_filesystem import POLICY, write_exclusive
            require(policy == POLICY, 'unknown filesystem policy')
            directory = Path(os.environ['GITHUB_WORKSPACE']) / '.local/reference-filesystem/nested'
            checked(directory.parent)
            directory.mkdir(mode=0o700)
            filesystem_context = {**record['run_context'], 'source': record['source']}
            write_exclusive(directory / 'context.json', filesystem_context)
            helper = Path(os.environ['GITHUB_WORKSPACE']) / 'scripts/reference_filesystem_bindings.py'
            common_args = ['--image', str(paths['image']), '--image-bytes', str(IMAGE_BYTES),
                           '--context-json', str(directory / 'context.json'), '--directory', str(directory)]
            runner(['timeout', '--signal=TERM', '--kill-after=2s', '30s',
                    sys.executable, str(helper), 'format', *common_args], timeout=35)
        else:
            runner(['mkfs.ext4', '-F', '-q', str(paths['image'])], timeout=60)
        require(fixed_identity(paths['image']) == record['image_identity'], 'image replaced during formatting')
        runner(['sudo', '-n', 'mount', '-o', 'loop,nodev,nosuid', str(paths['image']), str(paths['mount'])])
        nested = observe_binding(paths['mount'], paths['image'], runner)
        require(nested['mount']['source'] != record['outer']['binding']['mount']['source'], 'nested device aliases outer device')
        record['nested_binding'] = nested
        runner(['sudo', '-n', 'chown', str(os.getuid()) + ':' + str(os.getgid()),
                str(paths['mount']), str(paths['mount'] / 'lost+found')])
        record['mount_identity'] = identity(paths['mount'])[:5]
        if policy:
            from reference_filesystem_bindings import validate
            runner(['timeout', '--signal=TERM', '--kill-after=2s', '112s',
                    sys.executable, str(helper), 'collect', '--mount', str(paths['mount']),
                    *common_args], timeout=115)
            record.update(filesystem_policy=POLICY,
                          filesystem_proof=validate(directory, paths['image'], paths['mount'],
                                                    IMAGE_BYTES, filesystem_context))
        probe = paths['mount'] / 'reference-results-enospc-probe'
        require(not probe.exists() and not probe.is_symlink(), 'probe path already exists')
        observed = runner(['fallocate', '-l', str(PROBE_BYTES), str(probe)], timeout=60, accepted=(1,))
        require('No space left on device' in observed['stderr'], 'nested oversized allocation was not denied with ENOSPC')
        probe_info = checked(probe)
        require(stat.S_ISREG(probe_info.st_mode) and probe_info.st_uid == os.getuid() and probe_info.st_nlink == 1,
                'refusing unexpected probe cleanup target')
        probe.unlink()  # The only data deletion performed by this helper.
        record['oversized_allocation'] = 'DENIED_ENOSPC'
        copy_bootstrap(paths['bootstrap'], paths['mount'], record['bootstrap'])
        if policy:
            # Canonical live receipts stay outside the child through freeze.
            # Full byte copies are also part of the scientific result image.
            destination = paths['mount'] / 'reference-filesystem/nested'
            require(not os.path.lexists(destination), 'nested filesystem export already exists')
            retained = inventory(directory)
            require(retained['logical_bytes'] <= 20_000_000 and len(retained['entries']) <= 256,
                    'filesystem proof export exceeds its control admission')
            checked(destination.parent)
            destination.mkdir(mode=0o700)
            copy_bootstrap(directory, destination, retained)
        require(source_hash(project) == record['source'], 'source changed during results setup')
        record.update(status='PASS', ended_at=utc(), retained_bootstrap=True)
        save(paths['proof'], record)
        save(paths['mount'] / 'reference-results-setup.json', record, initial=True)
        return record
    except BaseException as failure:
        record.update(status='FAIL', ended_at=utc(), error=type(failure).__name__ + ': ' + str(failure))
        save(paths['proof'], record)
        raise


def unit_properties(text):
    properties = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
    require(properties.get('LoadState') == 'not-found' or properties.get('ActiveState') in ('inactive', 'failed'),
            'guest privileged unit is still active or its state is unknown')
    return properties


def assert_no_active_guest(volume, project, record, runner):
    guest = volume / 'reference-guest'
    if not guest.exists():
        require(not guest.is_symlink(), 'linked guest setup path')
        return {'guest_setup_absent': True, 'units': []}
    checked(guest)
    setup_path = guest / 'setup.json'
    actual_sha = file_sha(setup_path)
    copied = None
    candidates = [project / '.local/reference-guest-setup/setup.json',
                  Path(os.environ['GITHUB_WORKSPACE']) / '.local/reference-metadata/reference-guest-setup/setup.json']
    for candidate in candidates:
        try:
            if file_sha(candidate) == actual_sha:
                copied = candidate
                break
        except (OSError, RuntimeError, ValueError):
            continue
    require(copied is not None, 'guest setup lacks identical preserved diagnostics')
    guest_setup = read_json(setup_path)
    require(guest_setup.get('source') == record['source'] and guest_setup.get('run_context') == record['run_context'],
            'guest setup belongs to another execution')
    if guest_setup.get('status') not in ('PASS', 'FAIL'):
        quiescence = read_json(volume / 'reference-guest-quiescence.json')
        require(quiescence.get('status') == 'PASS' and quiescence.get('source') == record['source']
                and quiescence.get('run_context') == record['run_context']
                and quiescence.get('guest_setup_sha256') == file_sha(setup_path),
                'interrupted guest lacks exact quiescence evidence')
    units = []
    for command in guest_setup.get('commands', []):
        unit = command.get('transient_unit')
        if unit is None:
            continue
        require(re.fullmatch('facetquarry-owned-[0-9a-f]{32}', unit) is not None, 'unexpected guest unit identity')
        observed = runner(['systemctl', 'show', '--no-pager', '--property=LoadState', '--property=ActiveState', unit],
                          accepted=(0, 1))
        units.append({'unit': unit, 'properties': unit_properties(observed['stdout'])})
    return {'guest_setup_sha256': file_sha(setup_path), 'units': units}


def rescue_setup(volume, project):
    """Expose exact originals only; never claim post-setup scientific recovery."""
    require(sys.platform == 'linux' and os.getuid() != 0, 'requires ordinary Linux reference runner')
    paths = owned_paths(Path(volume), Path(project))
    volume, project = paths['volume'], paths['project']
    canonical = read_json(paths['proof']) if os.path.lexists(paths['proof']) else None
    assert_premeasurement(paths)
    selected, initial, admitted = original_selection(paths, canonical)
    proof = volume / 'reference-results-rescue.json'
    record = {'schema_version': 1, 'evidence_type': 'premeasurement_bootstrap_rescue', 'status': 'PREPARING',
              'source': source_hash(project), 'selected_path': str(selected), 'initial_inventory': initial,
              'admission': admitted, 'commands': [], 'started_at': utc(),
              'complete_scientific_preservation': False,
              'scope': 'Exact completed premeasurement originals only. Partial child copies and later scientific results are not rescue selections.'}
    save(proof, record, initial=True)
    runner = Commands(record, proof)
    try:
        context = run_context(project, runner)
        record['run_context'] = context
        outer = validate_outer(paths, runner, context, quota_root=selected)
        record['outer'] = outer
        quota = read_json(selected / 'reference-quota.json')
        require(quota.get('volume_file_bytes') in (2_300_000_000, 3_300_000_000)
                and quota.get('oversized_allocation_bytes') == quota['volume_file_bytes'] + 100_000_000,
                'rescue outer quota geometry/probe differs')
        enospc = selected / 'enospc.stderr'
        require(checked(enospc).st_size <= 32768 and file_sha(enospc) == quota.get('enospc_sha256')
                and b'No space left on device' in enospc.read_bytes(), 'rescue actual quota refusal proof differs')
        validate_rescue_context(canonical, paths, record['source'], context, outer)
        if os.path.ismount(paths['mount']):
            require(canonical is not None and 'image_identity' in canonical
                    and fixed_identity(paths['image']) == canonical['image_identity'],
                    'refusing unbound child unmount during rescue')
            binding = observe_binding(paths['mount'], paths['image'], runner)
            require(binding['mount']['source'] != outer['binding']['mount']['source']
                    and ('nested_binding' not in canonical or binding == canonical['nested_binding']),
                    'rescue child backing differs')
            record['child_binding'] = binding
            runner(['sync', '-f', str(paths['mount'])], timeout=60)
            runner(['sudo', '-n', 'umount', '--', str(paths['mount'])], timeout=60)
            loops = runner(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(paths['image']),
                            '--output', 'NAME,BACK-FILE'])
            require(not os.path.ismount(paths['mount']) and json.loads(loops['stdout']).get('loopdevices') == [],
                    'rescued child remains mounted/associated')
            record['child_unmounted'] = True
        assert_premeasurement(paths)
        selected_after, after, bounds_after = original_selection(paths, canonical)
        require(selected_after == selected and after == initial and bounds_after == admitted
                and source_hash(project) == record['source'] and run_context(project, runner) == context,
                'rescue originals/source/run changed')
        record.update(status='PASS', original_bytes_and_inodes_unchanged=True,
                      selected_path=str(selected), zip_upper_bound_bytes=admitted['zip_upper_bound_bytes'])
        return record
    except BaseException as error:
        record.update(status='FAIL', error=type(error).__name__ + ': ' + str(error))
        raise
    finally:
        record['ended_at'] = utc()
        save(proof, record)


def verify_rescue(volume, project):
    """Repeat every original/run/binding check immediately before upload."""
    require(sys.platform == 'linux' and os.getuid() != 0, 'requires ordinary Linux reference runner')
    paths = owned_paths(Path(volume), Path(project))
    proof = paths['volume'] / 'reference-results-rescue.json'
    proof_digest = file_sha(proof)
    rescued = read_json(proof)
    require(rescued.get('status') == 'PASS' and rescued.get('original_bytes_and_inodes_unchanged') is True
            and rescued.get('complete_scientific_preservation') is False,
            'complete original premeasurement rescue proof is missing')
    assert_premeasurement(paths)
    canonical = read_json(paths['proof']) if os.path.lexists(paths['proof']) else None
    selected, observed, admitted = original_selection(paths, canonical)
    require(str(selected) == rescued.get('selected_path') and observed == rescued.get('initial_inventory')
            and admitted == rescued.get('admission')
            and admitted['zip_upper_bound_bytes'] == rescued.get('zip_upper_bound_bytes'),
            'rescued originals or archive admission changed')
    require(not os.path.ismount(paths['mount']), 'child must be unmounted before bootstrap upload')
    commands = []
    def runner(argv, *, timeout=30, accepted=(0,)):
        require(1 <= timeout <= 60, 'rescue verification deadline outside admission')
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        require(len(result.stdout) + len(result.stderr) <= 1_000_000 and result.returncode in accepted,
                'rescue verification command failed')
        item = {'command': argv, 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
        commands.append(item)
        return item
    context = run_context(paths['project'], runner)
    outer = validate_outer(paths, runner, context, quota_root=selected)
    require(context == rescued.get('run_context') and outer == rescued.get('outer')
            and source_hash(paths['project']) == rescued.get('source'),
            'rescued source/run/backing changed before upload')
    validate_rescue_context(canonical, paths, rescued['source'], context, outer)
    require(file_sha(proof) == proof_digest, 'rescue proof changed during verification')
    return {**rescued, 'complete_rescue_proof_sha256': proof_digest,
            'verification_commands': commands}


def quiesce_guest(volume, project):
    """Stop only this execution's named units; do not alter its failed status."""
    require(sys.platform == 'linux' and os.getuid() != 0, 'requires ordinary Linux reference runner')
    paths = owned_paths(volume, project)
    canonical = read_json(paths['proof'])
    require(canonical.get('status') == 'PASS' and canonical.get('paths') == {k: str(v) for k,v in paths.items()},
            'quiescence requires bound results setup')
    proof = volume / 'reference-guest-quiescence.json'
    record = {'status': 'PREPARING', 'source': canonical['source'], 'run_context': canonical['run_context'],
              'commands': [], 'started_at': utc(), 'scope': 'Owned-unit quiescence only; no workload success claim.'}
    save(proof, record, initial=True)
    runner = Commands(record, proof)
    try:
        require(run_context(project, runner) == canonical['run_context'] and source_hash(project) == canonical['source'],
                'quiescence source/run differs')
        require(observe_binding(volume, paths['outer_image'], runner) == canonical['outer']['binding']
                and observe_binding(paths['mount'], paths['image'], runner) == canonical['nested_binding'],
                'quiescence image backing differs')
        setup_path = volume / 'reference-guest/setup.json'
        if setup_path.exists():
            guest = read_json(setup_path)
            require(guest.get('source') == canonical['source'] and guest.get('run_context') == canonical['run_context'],
                    'guest unit scope differs')
            for command in guest.get('commands', []):
                unit = command.get('transient_unit')
                if unit is None: continue
                require(re.fullmatch('facetquarry-owned-[0-9a-f]{32}', unit), 'unexpected guest unit identity')
                observed = runner(['systemctl','show','--no-pager','--property=LoadState','--property=ActiveState',unit],accepted=(0,1))
                properties = dict(line.split('=',1) for line in observed['stdout'].splitlines() if '=' in line)
                if properties.get('LoadState') != 'not-found' and properties.get('ActiveState') not in ('inactive','failed'):
                    runner(['sudo','-n','systemctl','stop',unit])
                observed = runner(['systemctl','show','--no-pager','--property=LoadState','--property=ActiveState',unit],accepted=(0,1))
                unit_properties(observed['stdout'])
            record['guest_setup_sha256'] = file_sha(setup_path)
        record.update(status='PASS', ended_at=utc())
        return record
    except BaseException as error:
        record.update(status='FAIL', error=type(error).__name__+': '+str(error)); raise
    finally:
        save(proof,record)


def image_sha(path, expected):
    require(fixed_identity(path) == expected, 'image identity changed before hashing')
    before = stamp(checked(path))
    digest, count = hashlib.sha256(), 0
    with path.open('rb') as stream:
        require(identity(path) == expected, 'image pathname changed while opening')
        descriptor = os.fstat(stream.fileno())
        require([descriptor.st_dev, descriptor.st_ino, descriptor.st_mode, descriptor.st_uid,
                 descriptor.st_gid, descriptor.st_nlink, descriptor.st_size] == expected, 'image descriptor differs')
        while block := stream.read(1024 * 1024):
            count += len(block)
            require(count <= IMAGE_BYTES, 'image grew beyond fixed admission')
            digest.update(block)
        require(stamp(os.fstat(stream.fileno())) == before, 'image descriptor changed during hashing')
    require(count == IMAGE_BYTES and fixed_identity(path) == expected and stamp(checked(path)) == before,
            'image changed during hashing')
    return digest.hexdigest()


def freeze(volume, project, proof_path_or_record):
    """Unmount only the bound child after live proofs/export; never unlink images."""
    require(sys.platform == 'linux' and os.getuid() != 0, 'requires ordinary Linux reference runner')
    paths = owned_paths(Path(volume), Path(project))
    volume, project = paths['volume'], paths['project']
    require(not Path.cwd().is_relative_to(paths['mount']), 'freeze cwd must be outside child results mount')
    canonical = read_json(paths['proof'])
    supplied = proof_path_or_record if isinstance(proof_path_or_record, dict) else read_json(Path(proof_path_or_record))
    require(supplied == canonical and canonical.get('status') == 'PASS'
            and canonical.get('paths') == {key: str(value) for key, value in paths.items()}
            and canonical.get('image_bytes') == IMAGE_BYTES, 'results setup proof differs or is incomplete')
    require(not paths['freeze'].exists() and not paths['freeze'].is_symlink(), 'freeze proof already exists')
    record = {'schema_version': 1, 'evidence_type': 'reference_results_freeze', 'status': 'PREPARING',
              'source': canonical['source'], 'run_context': canonical['run_context'], 'started_at': utc(),
              'image_path': str(paths['image']), 'setup_proof_sha256': file_sha(paths['proof']), 'commands': []}
    save(paths['freeze'], record, initial=True)
    runner = Commands(record, paths['freeze'])
    try:
        require(run_context(project, runner) == canonical['run_context'] and source_hash(project) == canonical['source'],
                'freeze execution/source differs from setup')
        require(fixed_identity(paths['image']) == canonical['image_identity']
                and identity(paths['outer_image']) == canonical['outer']['image_identity']
                and identity(volume)[:5] == canonical['outer']['volume_identity']
                and identity(project)[:5] == canonical['project_identity'], 'backing/image/volume/source identity changed')
        require(observe_binding(volume, paths['outer_image'], runner) == canonical['outer']['binding'], 'outer backing changed')
        require(observe_binding(paths['mount'], paths['image'], runner) == canonical['nested_binding']
                and identity(paths['mount'])[:5] == canonical['mount_identity'], 'nested backing/mount identity changed')
        record['inactive_guest'] = assert_no_active_guest(volume, project, canonical, runner)
        runner(['sync', '-f', str(paths['mount'])], timeout=60)
        runner(['sudo', '-n', 'umount', '--', str(paths['mount'])], timeout=60)
        loops = runner(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(paths['image']),
                        '--output', 'NAME,BACK-FILE'])
        require(json.loads(loops['stdout']).get('loopdevices') == [] and not os.path.ismount(paths['mount']),
                'results image remains mounted or associated')
        digest = image_sha(paths['image'], canonical['image_identity'])
        record.update(status='PASS', image_bytes=IMAGE_BYTES, image_sha256=digest, image_unmounted=True,
                      recovery='Mount a separate verified copy read-only as ext4; retain this exact fixed image unchanged.',
                      backing_relationship='Image bytes reside inside the still-retained admitted outer loop image.',
                      scope='Fixed complete unmounted results image for read-only recovery; no source release qualification.')
        return record
    except BaseException as failure:
        record.update(status='FAIL', error=type(failure).__name__ + ': ' + str(failure))
        raise
    finally:
        record['ended_at'] = utc()
        save(paths['freeze'], record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('setup', 'freeze', 'quiesce', 'rescue'))
    parser.add_argument('--volume', type=Path, required=True)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--proof', type=Path)
    args = parser.parse_args()
    if args.action == 'setup':
        require(args.proof is None, 'setup does not accept a substitute proof')
        record = setup(args.volume, args.project)
    elif args.action == 'quiesce':
        require(args.proof is None, 'quiescence does not accept a substitute proof')
        record = quiesce_guest(args.volume, args.project)
    elif args.action == 'rescue':
        require(args.proof is None, 'rescue does not accept a substitute proof')
        record = rescue_setup(args.volume, args.project)
    else:
        record = freeze(args.volume, args.project, args.proof or args.volume / 'reference-results-setup.json')
    print(json.dumps({key: record.get(key) for key in ('status', 'evidence_type', 'image_bytes', 'image_sha256',
                                                     'image_unmounted', 'selected_path', 'zip_upper_bound_bytes',
                                                     'complete_scientific_preservation')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
