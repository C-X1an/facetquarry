"""Recover the frozen run34 ZIP as eight chunks; never run an engine or qualify it.

Only the separately selected same-repository Actions codec job can mutate this
job's owned allocation. Pure helpers support tiny defensive fixtures, not Linux
quota, retention, inspection or recovery claims.
"""
from __future__ import annotations
import time
ENTRY_STARTED = time.monotonic()

import argparse
import datetime as dt
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

from common import ROOT, source_hash
import evidence_bundle as bundle
import reference_filesystem as filesystem
import reference_transport_supervisor as supervisor

PROFILE = 'historical-run34-readonly-image-recovery-v1'
REPOSITORY = 'C-X1an/facetquarry'
REPOSITORY_ID = 1430604581
ARTIFACT_ID = 13042845270
TRANSPORT_RUN = 41181265797
TRANSPORT_HEAD = '024ceb5a2f79549b58f25ec7fb2259f3275dec0c'
TRANSPORT_NAME = 'reference-results-image-41181265797-1'
ZIP_BYTES = 753_697_518
ZIP_SHA = '81befee8db6a62b34e133e2f8fbfaa3490a2171fb591d86b60fdde9c1d7498b8'
IMAGE_NAME = 'reference-results.img'
IMAGE_BYTES = 1_100_000_000
IMAGE_SHA = 'b78c516c61e58ea414168c4a9f8b8312f49cc08144d53afa05bb5383fd6e6b4a'
OLD_SOURCE = 'e9d3f61469917718bb04f29784f8f08343d5a7eba176a0aa3b017b856bdc2fe3'
OUTER_BYTES = 2_100_000_000
PROBE_BYTES = 2_200_000_000
CHUNK_BYTES = 100_000_000
CHUNKS = 8
READBACK_BYTES = 101_000_000
ANALYSIS_BYTES = 48_000_000
ANALYSIS_FILE_BYTES = (6_000_000,) * 8  # Five reports, two captures, one result.
FREE_RESERVE = 10_000_000
EXTERNAL_BYTES = 50_000_000
CLOUD_METADATA = 10_000_000
OVERHEAD = 50_000_000
CEILING = 12_000_000_000
METADATA_BYTES = 8_000_000  # At most 10MB after the cloud wrapper reservation.
MAX_ENTRIES = 50_000
MAX_INVENTORY = 10_000_000
MAX_JSON = 2_000_000
FORMAT_POLICY = 'recovery-ext4-inodes4096-journal16m-v1'
FORMAT_FEATURES = frozenset(('has_journal', 'ext_attr', 'resize_inode', 'dir_index', 'filetype',
    'extent', '64bit', 'flex_bg', 'sparse_super', 'large_file', 'huge_file', 'dir_nlink',
    'extra_isize', 'metadata_csum'))
SCHEDULE = {'plan': 45, 'quota': 120, 'download': 300, 'extract': 300,
            'inspect': 900, 'uploads': 720, 'readback': 480,
            'metadata': 240, 'cleanup': 180}
ORDER = tuple(SCHEDULE)
SCOPE = ('Frozen run34 compressed ZIP byte recovery and readonly inspection only. '
         'No new benchmark, supported-toolchain, current-source, target or release qualification. '
         'Historical failures and partial analysis remain failures.')
require = filesystem.require


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def geometry_plan(base):
    require(type(base) is int and base >= 2_000_000_000,
            'fresh baseline must include every original/mirror and the unchanged global2GBreserve')
    reservations = {'owned_outer_image': OUTER_BYTES,
                    'eight_chunk_artifact_zip_ceiling': ZIP_BYTES + CHUNKS * 1_000_000,
                    'external_metadata_and_logs': EXTERNAL_BYTES,
                    'cloud_metadata': CLOUD_METADATA, 'overhead': OVERHEAD}
    maximum = sum(reservations.values())
    return {'profile': PROFILE, 'scope': SCOPE, 'baseline_includes_global_reserve': base,
            'reservations': reservations, 'maximum_new_stage_bytes': maximum,
            'peak_bytes': base + maximum, 'ceiling_bytes': CEILING,
            'admission': 'ALLOW' if base + maximum < CEILING else 'REFUSE',
            'scientific_qualification': False}


def time_admission(stage, started_epoch, now_epoch):
    require(stage in SCHEDULE and all(type(v) in (int, float) and math.isfinite(v)
            for v in (started_epoch, now_epoch)) and 0 <= now_epoch - started_epoch <= 3600,
            'invalid actual whole-job start/current time')
    remaining = 3600 - (now_epoch - started_epoch)
    # Cleanup precedes the final diagnostic upload, so both tails remain reserved.
    required = (SCHEDULE['cleanup'] + SCHEDULE['metadata'] if stage == 'cleanup'
                else SCHEDULE['metadata'] if stage == 'metadata'
                else sum(SCHEDULE[key] for key in ORDER[ORDER.index(stage):]))
    return {'stage': stage, 'remaining_seconds': remaining, 'required_seconds': required,
            'allowed': remaining >= required, 'job_seconds': 3600,
            'schedule_seconds': SCHEDULE, 'setup_cushion_seconds': 3600 - sum(SCHEDULE.values())}


def space_admission(frsize, bavail, favail, remaining_bytes, entries):
    require(all(type(v) is int for v in (frsize, bavail, favail, remaining_bytes, entries))
            and 0 < frsize <= 4096 and min(bavail, favail, remaining_bytes, entries) >= 0,
            'invalid observed filesystem growth geometry')
    rounded = ((remaining_bytes + frsize - 1) // frsize) * frsize
    return {'available_bytes': frsize * bavail, 'available_inodes': favail,
            'remaining_rounded_planned_bytes': rounded, 'remaining_planned_entries': entries,
            'recovery_free_reserve_bytes': FREE_RESERVE,
            'allowed': frsize * bavail >= rounded + FREE_RESERVE and favail >= entries + 64}


def physical_tail(frsize, file_sizes, directory_count):
    """Pad each remaining regular allocation and every directory independently."""
    require(type(frsize) is int and 0 < frsize <= 4096
            and type(file_sizes) in (tuple, list) and len(file_sizes) <= 64
            and all(type(size) is int and 0 <= size <= OUTER_BYTES for size in file_sizes)
            and type(directory_count) is int and 0 <= directory_count <= 32,
            'invalid bounded physical allocation tail')
    files = sum(((size + frsize - 1) // frsize) * frsize for size in file_sizes)
    directories = directory_count * frsize
    return {'allocation_unit_bytes': frsize, 'file_sizes': list(file_sizes),
            'logical_file_bytes': sum(file_sizes), 'file_allocation_bytes': files,
            'directory_allocation_bytes': directories, 'directories': directory_count,
            'physical_bytes': files + directories, 'entries': len(file_sizes) + directory_count}


def recovery_formatter_argv(image):
    return ['mkfs.ext4', '-F', '-q', '-m', '0', '-N', '4096', '-I', '256', '-J', 'size=16', str(image)]


def recovery_geometry(raw, *, lifecycle='clean'):
    """Parse the observed recovery superblock; unknown additions fail closed.

    Journal totals use upstream e2fsprogs lib/e2p/ljs.c's exact block count,
    rather than inferring allocation from its rounded display size alone.
    """
    require(type(raw) is str and len(raw.encode()) <= 32768, 'bounded recovery superblock required')
    require(lifecycle in ('clean', 'mounted'), 'unknown explicit recovery filesystem lifecycle')
    geometry = filesystem.geometry(raw, policy=filesystem.NESTED_POLICY)
    def field(label):
        values = re.findall(r'^' + re.escape(label) + r':\s*(.*?)\s*$', raw, re.MULTILINE)
        require(len(values) == 1, 'missing or duplicate recovery superblock field: ' + label)
        return values[0]
    features = field('Filesystem features').split()
    lifecycle_features = {'needs_recovery'} if lifecycle == 'mounted' else set()
    require(len(features) == len(set(features)) and set(features) == FORMAT_FEATURES | lifecycle_features,
            'unexpected recovery filesystem feature set')
    # e2fsprogs1.47.0 reports the disabled feature as an explicit zero even
    # when fast_commit is absent. Admit only that unique disabled observation.
    fast_commit_lines = re.findall(r'^Fast commit[^\r\n]*', raw, re.MULTILINE)
    require(not fast_commit_lines or (len(fast_commit_lines) == 1
            and re.fullmatch(r'Fast commit length:[ \t]*0[ \t]*', fast_commit_lines[0])),
            'unexpected nonzero, duplicate or unknown fast-commit report')
    require(field('Journal features') == '(none)' and field('Total journal size') == '16M'
            and not re.search(r'^Journal block size', raw, re.MULTILINE),
            'unexpected journal feature, fast-commit or block-size addition')
    journal_blocks = int(field('Total journal blocks'))
    block = geometry['block_size']
    require(block in (1024, 2048, 4096) and geometry['reserved_blocks'] == 0
            and geometry['block_count'] * block <= OUTER_BYTES
            and journal_blocks * block == 16 * 1024 * 1024,
            'observed recovery journal bytes, reserved blocks or image geometry differ')
    require(geometry['inode_size'] == 256
            and geometry['first_data_block'] == (1 if block == 1024 else 0)
            and 0 < geometry['blocks_per_group'] <= 8 * block
            and 0 < geometry['inodes_per_group'] <= 8 * block
            and geometry['inode_blocks_per_group'] > 0, 'unsupported recovery inode geometry')
    groups = ((geometry['block_count'] - geometry['first_data_block']
               + geometry['blocks_per_group'] - 1) // geometry['blocks_per_group'])
    per_block = block // 256
    require(groups > 0 and geometry['inode_count'] == groups * geometry['inodes_per_group']
            and geometry['inodes_per_group'] % per_block == 0
            and geometry['inode_blocks_per_group'] * per_block == geometry['inodes_per_group']
            and 4096 <= geometry['inode_count'] < 4096 + groups * per_block,
            'observed recovery requested inode count/group rounding differs')
    return {**geometry, 'policy': FORMAT_POLICY, 'features': sorted(set(features) - lifecycle_features),
            'observed_lifecycle_features': sorted(lifecycle_features),
            'journal_features': [], 'journal_blocks': journal_blocks, 'journal_bytes': journal_blocks * block,
            'requested_inode_count': 4096, 'requested_inode_size': 256, 'requested_journal_mib': 16}


def checked(path, *, regular=False):
    path = bundle.no_links(Path(path))
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode) if regular else
            stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode), 'unsupported owned path type')
    if regular:
        require(value.st_nlink == 1, 'linked regular file refused')
    return value


def identity(path):
    return list(bundle.signature(checked(path, regular=True)))


def backing_identity(path):
    info = checked(path, regular=True)
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_size]


def paths():
    parent = Path(os.environ['RUNNER_TEMP'])
    require(parent.is_absolute() and '..' not in parent.parts
            and str(parent) == os.path.abspath(parent), 'runner temporary path is not exact')
    checked(parent)
    volume = parent / 'facetquarry-image-recovery'
    return {'volume': volume, 'outer': parent / 'facetquarry-image-recovery.img',
            'chunks': volume / 'chunks', 'image': volume / IMAGE_NAME,
            'mount': volume / 'readonly-original', 'scratch': volume / 'scratch',
            'readback': volume / 'server-readback.zip', 'analysis': volume / 'reanalysis',
            'local': ROOT / '.local/reference-image-recovery',
            'evidence': ROOT / '.local/evidence'}


def physical(root, limit=4096):
    if not os.path.lexists(root):
        return 0, 0
    total, count, pending = 0, 0, [root]
    while pending:
        item = pending.pop(); info = checked(item); count += 1
        require(count <= limit, 'external metadata entry ceiling exceeded')
        total += max(info.st_size, getattr(info, 'st_blocks', 0) * 512)
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(item) as children:
                for child in children:
                    require(count + len(pending) < limit, 'external pending-entry ceiling exceeded')
                    pending.append(item / child.name)
        require(total <= EXTERNAL_BYTES, 'external metadata allocation ceiling exceeded')
    return total, count


def external_admission(extra=0):
    p = paths()
    actual = sum(physical(p[key])[0] for key in ('local', 'evidence'))
    require(type(extra) is int and extra >= 0 and actual + extra <= EXTERNAL_BYTES,
            'complete external metadata/log allocation refused')
    return actual


def ensure_metadata():
    for path in (ROOT / '.local', paths()['local'], paths()['local'] / 'commands'):
        if not os.path.lexists(path):
            path.mkdir(mode=0o700)
        info = checked(path)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and not stat.S_IMODE(info.st_mode) & 0o022, 'metadata directory ownership differs')


def save(path, value, *, replace=False):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(raw) <= MAX_JSON, 'recovery receipt exceeds complete producer bound')
    external_admission(len(raw) + 8192)
    checked(path.parent)
    if replace:
        checked(path, regular=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if replace else os.O_EXCL)
                         | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def load(path, limit=MAX_JSON):
    info = checked(path, regular=True)
    require(info.st_size <= limit, 'bounded JSON input exceeded')
    before = bundle.signature(info)
    with path.open('rb') as stream:
        require(bundle.descriptor_matches(os.fstat(stream.fileno()), before), 'JSON descriptor differs')
        raw = stream.read(limit + 1)
        require(len(raw) == info.st_size and bundle.descriptor_matches(os.fstat(stream.fileno()), before)
                and before == bundle.signature(checked(path, regular=True)), 'JSON input changed')
    return json.loads(raw, object_pairs_hook=bundle.unique_object)


def command(argv, label, *, seconds=20, accepted=(0,), environ=None):
    require(re.fullmatch('[a-z0-9-]{1,80}', label) and 1 <= seconds <= 900,
            'invalid owned helper bounds')
    external_admission(100_000)
    folder = paths()['local'] / 'commands'
    name = label + '-' + uuid.uuid4().hex[:12]
    out, err = folder / (name + '.stdout'), folder / (name + '.stderr')
    actual = argv
    if argv[:2] == ['sudo', '-n']:
        actual = ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=2s',
                  str(max(1, seconds - 12)) + 's', *argv[2:]]
    env = dict(os.environ if environ is None else environ)
    env.pop('GITHUB_TOKEN', None)  # No helper command receives the API credential.
    started = time.monotonic()
    observed = supervisor.run_owned(actual, out, err, started=started,
        total_seconds=max(16, seconds), cleanup_seconds=8, receipt_seconds=2,
        capture_bytes=32768, environ=env)
    complete = (observed.get('capture_complete') is True and observed.get('discarded_output_bytes') == 0
                and observed.get('descendant_quiescence', {}).get('quiescent') is True
                and observed.get('descendant_quiescence', {}).get('residual') == []
                and observed.get('termination_reason') is None and observed.get('errors') == [])
    record = {'requested_command': argv, 'actual_command': actual, 'supervision': observed,
              'status': 'PASS' if complete and observed['worker_exit_code'] in accepted else 'FAIL',
              'accepted_exit_codes': list(accepted), 'started_at': utc(),
              'duration_seconds': time.monotonic() - started}
    save(folder / (name + '.json'), record)
    require(record['status'] == 'PASS', 'recorded owned recovery helper failed: ' + label)
    return out.read_bytes(), err.read_bytes(), record


def context():
    require(sys.platform == 'linux' and os.getuid() > 0 and os.getgid() > 0
            and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and os.environ.get('GITHUB_REPOSITORY_ID') == str(REPOSITORY_ID)
            and os.environ.get('GITHUB_JOB') == 'codec'
            and os.environ.get('FQ_IMAGE_RECOVERY') == 'true', 'unauthorized recovery runtime')
    require(Path(os.environ['GITHUB_WORKSPACE']) == ROOT, 'recovery tool is outside actual checkout')
    run, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(all(re.fullmatch('[1-9][0-9]{0,19}', v) for v in (run, attempt)), 'actual run identity missing')
    raw, _, _ = command(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], 'context-head')
    commit = raw.decode().strip()
    raw, _, _ = command(['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=normal'],
                        'context-clean')
    require(re.fullmatch('[0-9a-f]{40}', commit) and commit == os.environ.get('GITHUB_SHA')
            and raw == b'', 'recovery checkout must be exact and clean')
    return {'profile': PROFILE, 'repository': REPOSITORY, 'repository_id': REPOSITORY_ID,
            'job': 'codec', 'github_run_id': run, 'github_run_attempt': attempt,
            'commit': commit, 'source': source_hash(),
            'job_started_epoch': int(os.environ['FQ_IMAGE_RECOVERY_JOB_STARTED_EPOCH'])}


def job_clock():
    """Bind the 60-minute deadline to actual server job start, including setup."""
    run, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(all(re.fullmatch('[1-9][0-9]{0,19}', value) for value in (run, attempt))
            and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and os.environ.get('GITHUB_REPOSITORY_ID') == str(REPOSITORY_ID)
            and os.environ.get('GITHUB_JOB') == 'codec' and os.environ.get('FQ_IMAGE_RECOVERY') == 'true',
            'actual recovery job identity required before clock observation')
    token = os.environ.get('GITHUB_TOKEN', ''); require(bool(token), 'missing ephemeral clock token')
    api = f'https://api.github.com/repos/{REPOSITORY}/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100'
    try:
        opener = urllib.request.build_opener(NoRedirect())
        request = urllib.request.Request(api, headers={'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
        with opener.open(request, timeout=10) as response:
            require(response.status == 200, 'actual job clock API response differs')
            raw = response.read(MAX_JSON + 1)
        require(len(raw) <= MAX_JSON, 'actual job clock API metadata exceeds bound')
        value = json.loads(raw, object_pairs_hook=bundle.unique_object)
        jobs = value.get('jobs', [])
        require(type(jobs) is list and len(jobs) == value.get('total_count') and len(jobs) <= 100,
                'job clock API pagination/count differs')
        selected = [job for job in jobs if job.get('name') == 'Historical run34 readonly image recovery (nonqualifying)'
                    and job.get('run_id') == int(run) and job.get('status') == 'in_progress'
                    and job.get('runner_name') == os.environ.get('RUNNER_NAME')]
        require(len(selected) == 1, 'actual assigned recovery job is absent or ambiguous')
        job = selected[0]
        started = dt.datetime.fromisoformat(job['started_at'].replace('Z', '+00:00'))
        require(started.tzinfo is not None and 0 <= time.time() - started.timestamp() < 315,
                'actual recovery job setup exhausted reserved cushion')
        os.environ['FQ_IMAGE_RECOVERY_JOB_STARTED_EPOCH'] = str(math.floor(started.timestamp()))
        ctx = context()
        record = {'status': 'PASS', 'run_context': ctx, 'server_job_id': job['id'],
                  'server_job_started_at': job['started_at'], 'observed_at': utc()}
        save(paths()['local'] / 'job-clock.json', record)
        with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as output:
            output.write('FQ_IMAGE_RECOVERY_JOB_STARTED_EPOCH=' + str(ctx['job_started_epoch']) + '\n')
        return record
    except BaseException as error:
        raise RuntimeError('bounded actual job clock observation failed: ' + type(error).__name__) from None


def admitted():
    p, ctx = paths(), context()
    record = load(p['local'] / 'plan.json')
    expected = geometry_plan(int(os.environ['FQ_ACCOUNTED_BASE_BYTES']))
    require(record.get('plan') == expected and expected['admission'] == 'ALLOW'
            and record.get('run_context') == ctx, 'recovery admission is stale or belongs to another run/source')
    return p, ctx


def plan():
    ctx, p = context(), paths()
    require(load(p['local'] / 'job-clock.json').get('run_context') == ctx,
            'actual server job clock proof differs from current context')
    require(all(0 < os.statvfs(path).f_frsize <= 4096 for path in (ROOT, p['outer'].parent)),
            'allocation unit exceeds admitted external overhead')
    record = {'plan': geometry_plan(int(os.environ['FQ_ACCOUNTED_BASE_BYTES'])),
              'run_context': ctx, 'created_at': utc(), 'scope': SCOPE}
    record['status'] = 'PASS' if record['plan']['admission'] == 'ALLOW' else 'REFUSE'
    save(p['local'] / 'plan.json', record)
    require(record['plan']['admission'] == 'ALLOW', 'fresh recovery global growth admission refused')
    return record


def mount_observation(image, mount, label, *, readonly, expected_bytes):
    before = backing_identity(image)
    require(checked(image, regular=True).st_size == expected_bytes, 'exact mount image size differs')
    raw, _, _ = command(['findmnt', '--json', '--mountpoint', str(mount), '-o',
                          'TARGET,FSTYPE,SOURCE,OPTIONS,MAJ:MIN'], label)
    mounts = json.loads(raw)['filesystems']
    require(len(mounts) == 1, 'ambiguous exact owned mount')
    selected = mounts[0]
    options = set(selected.get('options', '').split(','))
    require(selected.get('target') == str(mount) and selected.get('fstype') == 'ext4'
            and re.fullmatch('/dev/loop[0-9]+', selected.get('source', ''))
            and {'nodev', 'nosuid', 'noexec'} <= options
            and ('ro' in options if readonly else 'rw' in options)
            and (not readonly or 'noload' in options or 'norecovery' in options),
            'owned mount options or identity differ')
    raw, _, _ = command(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                          '--output', 'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT,RO'],
                         label + '-loop')
    devices = json.loads(raw)['loopdevices']
    require(len(devices) == 1, 'ambiguous exact owned loop association')
    loop = devices[0]; info = checked(image, regular=True)
    require(loop.get('name') == selected['source'] and loop.get('back-file') == str(image)
            and int(loop.get('back-ino', -1)) == info.st_ino
            and loop.get('back-maj:min') == str(os.major(info.st_dev)) + ':' + str(os.minor(info.st_dev))
            and loop.get('offset') == 0 and loop.get('sizelimit') == 0
            and bool(loop.get('ro')) == readonly and backing_identity(image) == before,
            'exact backing inode/device/offset/readonly binding differs')
    return {'mount': selected, 'loop': loop, 'image_identity': before}


def outer(p, label):
    require(type(label) is str and re.fullmatch('[a-z0-9-]{1,80}', label), 'invalid lifecycle observation label')
    proof = load(p['local'] / 'quota.json')
    require(proof.get('run_context') == context() and proof.get('hard_quota_enforced') is True
            and proof.get('outer_bytes') == OUTER_BYTES and proof.get('probe_bytes') == PROBE_BYTES
            and proof.get('oversized_allocation') == 'DENIED_ENOSPC', 'outer quota proof differs')
    require(proof.get('formatter_policy') == FORMAT_POLICY
            and proof.get('formatter_argv') == recovery_formatter_argv(p['outer']),
            'recovery-only formatter identity differs')
    raw, _, _ = command(['dumpe2fs', '-h', str(p['outer'])], label + '-geometry')
    observed = recovery_geometry(raw.decode(), lifecycle='mounted')
    clean = proof.get('geometry', {})
    # Exactly one declared ext4 journal lifecycle flag changes on the bound RW
    # mount. Every static feature and all journal/inode/block geometry stay exact.
    require(type(clean) is dict and clean.get('observed_lifecycle_features') == []
            and {key: value for key, value in observed.items() if key != 'observed_lifecycle_features'}
                == {key: value for key, value in clean.items() if key != 'observed_lifecycle_features'},
            'current recovery journal/inode/superblock geometry changed')
    current = mount_observation(p['outer'], p['volume'], label, readonly=False, expected_bytes=OUTER_BYTES)
    require(current == proof['binding'], 'outer filesystem/backing changed since actual ENOSPC')
    record = {'status': 'PASS', 'profile': PROFILE, 'run_context': proof['run_context'],
              'clean_geometry': clean, 'observed_geometry': observed, 'binding': current,
              'declared_transition': 'clean-to-bound-rw-mounted-needs-recovery'}
    save(p['local'] / ('lifecycle-' + label + '.json'), record)
    return record


def capacity(p, label, file_sizes, directories):
    require(checked(p['volume']).st_dev != checked(p['outer'].parent).st_dev,
            'recovery data path is not on the owned mounted filesystem')
    observed = os.statvfs(p['volume'])
    tail = physical_tail(observed.f_frsize, file_sizes, directories)
    record = space_admission(observed.f_frsize, observed.f_bavail, observed.f_favail,
                             tail['physical_bytes'], tail['entries'])
    record['physical_tail'] = tail
    record.update(observed_at=utc(), label=label)
    save(p['local'] / ('capacity-' + label + '-' + uuid.uuid4().hex[:8] + '.json'), record)
    require(record['allowed'], 'actual recovery free-byte/inode growth admission refused')
    return record


def quota():
    p, ctx = admitted()
    require(not os.path.lexists(p['outer']) and not os.path.lexists(p['volume']),
            'refusing occupied recovery image or mount slot')
    p['volume'].mkdir(mode=0o700)
    descriptor = os.open(p['outer'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.posix_fallocate(descriptor, 0, OUTER_BYTES)
        os.fsync(descriptor)
        require(os.fstat(descriptor).st_size == OUTER_BYTES
                and list(bundle.signature(os.fstat(descriptor))) == identity(p['outer']),
                'exact newly allocated outer descriptor differs')
    finally:
        os.close(descriptor)
    # This proves creation ownership only. ENOSPC and mount binding remain
    # separate later observations and must never be inferred from allocation.
    save(p['local'] / 'outer-allocation.json', {
        'status': 'PASS', 'run_context': ctx, 'outer_path': str(p['outer']),
        'volume_path': str(p['volume']), 'image_identity': backing_identity(p['outer']),
        'outer_bytes': OUTER_BYTES, 'created_via': 'exclusive-descriptor-fsynced-posix-fallocate-v1',
        'hard_quota_enforced': False})
    version_out, version_err, version_proof = command(['mkfs.ext4', '-V'], 'recovery-formatter-version')
    require(re.search(rb'mke2fs [0-9]+\.[0-9]+(?:\.[0-9]+)?', version_out + version_err),
            'actual recovery formatter version missing')
    format_argv = recovery_formatter_argv(p['outer'])
    _, _, format_proof = command(format_argv, 'format-zero-reserved', seconds=35)
    raw, _, superblock_proof = command(['dumpe2fs', '-h', str(p['outer'])], 'outer-superblock')
    geometry = recovery_geometry(raw.decode())
    command(['sudo', '-n', 'mount', '-o', 'loop,nodev,nosuid,noexec', str(p['outer']), str(p['volume'])],
            'mount-outer', seconds=30)
    command(['sudo', '-n', 'chown', str(os.getuid()) + ':' + str(os.getgid()),
             str(p['volume']), str(p['volume'] / 'lost+found')], 'own-outer')
    binding = mount_observation(p['outer'], p['volume'], 'outer-quota-binding',
                                readonly=False, expected_bytes=OUTER_BYTES)
    probe = p['volume'] / 'owned-enospc-probe'
    _, stderr, observation = command(['fallocate', '-l', str(PROBE_BYTES), str(probe)],
                                      'actual-enospc', seconds=30, accepted=(1,))
    require(b'No space left on device' in stderr, 'actual oversized probe did not fail with ENOSPC')
    info = checked(probe, regular=True)
    require(info.st_uid == os.getuid() and info.st_size <= PROBE_BYTES, 'unsafe known probe identity')
    os.unlink(probe)
    require(not os.path.lexists(probe), 'owned ENOSPC probe remains allocated')
    observed = os.statvfs(p['volume'])
    record = {'status': 'PASS', 'profile': PROFILE, 'run_context': ctx,
              'outer_bytes': OUTER_BYTES, 'probe_bytes': PROBE_BYTES,
              'hard_quota_enforced': True, 'oversized_allocation': 'DENIED_ENOSPC',
              'enospc_sha256': hashlib.sha256(stderr).hexdigest(), 'probe_observation': observation,
              'binding': binding, 'geometry': geometry, 'probe_removed': True,
              'formatter_policy': FORMAT_POLICY, 'formatter_argv': format_argv,
              'formatter_version_stdout': version_out.decode(), 'formatter_version_stderr': version_err.decode(),
              'formatter_version_proof': version_proof, 'formatter_proof': format_proof,
              'superblock_proof': superblock_proof,
              'statvfs_after_enospc': {key: getattr(observed, key) for key in
                  ('f_frsize', 'f_blocks', 'f_bavail', 'f_files', 'f_favail')}}
    save(p['local'] / 'quota.json', record)
    capacity(p, 'post-quota', [*chunk_sizes(), IMAGE_BYTES, READBACK_BYTES, *ANALYSIS_FILE_BYTES], 4)
    for key in ('chunks', 'mount', 'scratch'):
        p[key].mkdir(mode=0o700)
    return record


# These two request-boundary implementations intentionally retain the reviewed
# codec's NoRedirect and exact official production HTTPS destination policy.
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def artifact_destination(location):
    """Use only the exact official destination returned by authenticated API302.

    An unrecognized production endpoint is a retained refusal, never a reason
    to widen the allowlist automatically. The signed URL is never returned in
    receipts or exception text.
    """
    parsed = urllib.parse.urlsplit(location)
    require(parsed.scheme == 'https' and parsed.hostname is not None
            and re.fullmatch(r'productionresultssa[0-9]+\.blob\.core\.windows\.net', parsed.hostname)
            and parsed.netloc == parsed.hostname + (':443' if parsed.port == 443 else '')
            and parsed.port in (None, 443) and parsed.username is None
            and parsed.password is None and not parsed.fragment
            and parsed.path.startswith('/actions-results/') and bool(parsed.query)
            and not any(ord(character) <= 32 or ord(character) == 127 for character in location),
            'artifact destination is not the admitted official HTTPS production endpoint')
    return parsed.hostname


def metadata_identity(metadata, artifact_id, name, size, digest, run_id, commit):
    run = metadata.get('workflow_run', {})
    api = f'https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact_id}'
    require(type(artifact_id) is int and metadata.get('id') == artifact_id and metadata.get('name') == name
            and metadata.get('size_in_bytes') == size and metadata.get('expired') is False
            and metadata.get('digest') == 'sha256:' + digest
            and metadata.get('url') == api and metadata.get('archive_download_url') == api + '/zip'
            and run.get('id') == run_id and run.get('repository_id') == REPOSITORY_ID
            and run.get('head_repository_id') == REPOSITORY_ID and run.get('head_sha') == commit,
            'actual REST artifact metadata differs from frozen authorized identity')
    result = {key: metadata[key] for key in ('id', 'name', 'size_in_bytes', 'expired', 'digest',
              'created_at', 'updated_at', 'expires_at')}
    expires = dt.datetime.fromisoformat(result['expires_at'].replace('Z', '+00:00'))
    require(expires.tzinfo is not None and expires > dt.datetime.now(dt.timezone.utc),
            'artifact expired at actual transfer time')
    result['workflow_run'] = {key: run[key] for key in
                              ('id', 'repository_id', 'head_repository_id', 'head_sha')}
    return result


def api_transfer(artifact_id, validate, consume):
    token = os.environ.get('GITHUB_TOKEN', '')
    require(bool(token), 'missing ephemeral Actions token')
    opener = urllib.request.build_opener(NoRedirect())
    api = f'https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact_id}'
    def request(url):
        require(urllib.parse.urlsplit(url).scheme == 'https'
                and urllib.parse.urlsplit(url).netloc == 'api.github.com'
                and url in (api, api + '/zip'), 'API authentication destination differs')
        return urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
    try:
        with opener.open(request(api), timeout=30) as response:
            raw = response.read(MAX_JSON + 1)
        require(len(raw) <= MAX_JSON, 'REST metadata admission exceeded')
        metadata = validate(json.loads(raw, object_pairs_hook=bundle.unique_object))
        try:
            with opener.open(request(api + '/zip'), timeout=30):
                raise ValueError('expected authenticated GitHub artifact302redirect')
        except urllib.error.HTTPError as error:
            require(error.code == 302, 'GitHub artifact did not return expected302redirect')
            location = error.headers.get('Location', '')
        host = artifact_destination(location)
        delivery = urllib.request.build_opener(NoRedirect())
        with delivery.open(urllib.request.Request(location, headers={'Accept': 'application/octet-stream'}),
                           timeout=60) as response:
            require(response.status == 200, 'unexpected unauthenticated artifact delivery response')
            result = consume(response, metadata)
        return metadata, host, result
    except BaseException as error:
        # Network tracebacks may contain the signed URL; retain type only.
        raise RuntimeError('bounded authenticated artifact transfer failed: ' + type(error).__name__) from None


def chunk_sizes(total=ZIP_BYTES, chunk_bytes=CHUNK_BYTES):
    require(type(total) is int and type(chunk_bytes) is int and total > 0 and chunk_bytes > 0,
            'invalid chunk geometry')
    return [min(chunk_bytes, total - offset) for offset in range(0, total, chunk_bytes)]


def hash_regular(path, maximum, expected_size=None):
    info = checked(path, regular=True)
    require(info.st_size <= maximum and (expected_size is None or info.st_size == expected_size),
            'regular byte ceiling or exact size differs')
    before = bundle.signature(info); digest, count = hashlib.sha256(), 0
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        require(bundle.descriptor_matches(os.fstat(stream.fileno()), before), 'regular descriptor differs')
        while block := stream.read(1024 * 1024):
            count += len(block); require(count <= info.st_size, 'regular file grew')
            digest.update(block)
        require(count == info.st_size and bundle.descriptor_matches(os.fstat(stream.fileno()), before)
                and before == bundle.signature(checked(path, regular=True)), 'regular file changed while hashing')
    return digest.hexdigest()


def stream_chunks(stream, folder, *, total=ZIP_BYTES, chunk_bytes=CHUNK_BYTES,
                  expected_sha=ZIP_SHA, before_growth=None, progress=None):
    sizes = chunk_sizes(total, chunk_bytes); chunks, whole = [], hashlib.sha256()
    for number, size in enumerate(sizes):
        if before_growth is not None:
            before_growth(number, sum(sizes[number:]))
        path = folder / ('zip.part-' + f'{number:02d}')
        digest, count = hashlib.sha256(), 0
        with path.open('xb') as output:
            while count < size:
                data = stream.read(min(1024 * 1024, size - count))
                require(bool(data), 'original ZIP ended before frozen byte count')
                count += len(data); require(count <= size, 'original ZIP read exceeded chunk ceiling')
                output.write(data); digest.update(data); whole.update(data)
            output.flush(); os.fsync(output.fileno())
        item = {'number': number, 'name': path.name, 'bytes': count, 'sha256': digest.hexdigest(),
                'identity': identity(path)}
        chunks.append(item)
        if progress is not None:
            progress(chunks)
    require(stream.read(1) == b'', 'original ZIP exceeded frozen byte count')
    require(whole.hexdigest() == expected_sha, 'whole original ZIP SHA mismatch')
    return {'chunks': chunks, 'original_zip_bytes': total, 'original_zip_sha256': whole.hexdigest()}


def download():
    p, ctx = admitted(); outer(p, 'download-binding')
    def validate(value):
        return metadata_identity(value, ARTIFACT_ID, TRANSPORT_NAME, ZIP_BYTES, ZIP_SHA,
                                 TRANSPORT_RUN, TRANSPORT_HEAD)
    progress = p['local'] / 'download-progress.json'
    save(progress, {'status': 'INCOMPLETE', 'chunks': [], 'run_context': ctx})
    def consume(response, metadata):
        def growth(number, remaining):
            require(remaining == sum(chunk_sizes()[number:]), 'streaming remaining chunk geometry differs')
            capacity(p, 'download-' + str(number),
                     [*chunk_sizes()[number:], IMAGE_BYTES, READBACK_BYTES, *ANALYSIS_FILE_BYTES], 4)
        def retain(chunks):
            save(progress, {'status': 'INCOMPLETE', 'chunks': chunks, 'run_context': ctx}, replace=True)
        return stream_chunks(response, p['chunks'], before_growth=growth, progress=retain)
    metadata, host, result = api_transfer(ARTIFACT_ID, validate, consume)
    result.update(status='PASS', input_artifact=metadata, delivery_host=host,
                  run_context=ctx, scope=SCOPE)
    save(p['local'] / 'chunks.json', result)
    return result


class ChunkReader(io.RawIOBase):
    """Bounded random access over stable verified regular chunk descriptors."""
    def __init__(self, folder, chunks, total, digest):
        super().__init__()
        require(0 < len(chunks) <= CHUNKS and all(item.get('number') == i
                and item.get('name') == 'zip.part-' + f'{i:02d}'
                and type(item.get('bytes')) is int and 0 < item['bytes'] <= CHUNK_BYTES
                for i, item in enumerate(chunks)), 'ordered chunk manifest differs')
        self.streams, self.offsets, self.position, self.total = [], [], 0, total
        whole = hashlib.sha256(); offset = 0
        try:
            for item in chunks:
                path = folder / item['name']; info = checked(path, regular=True)
                require(info.st_size == item['bytes'] and identity(path) == item['identity'],
                        'verified chunk path/inode/size differs')
                descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                stream = os.fdopen(descriptor, 'rb'); self.streams.append((stream, path, item['identity']))
                require(bundle.descriptor_matches(os.fstat(descriptor), tuple(item['identity'])), 'chunk descriptor differs')
                per = hashlib.sha256()
                while block := stream.read(1024 * 1024):
                    per.update(block); whole.update(block)
                require(per.hexdigest() == item['sha256'], 'verified chunk SHA differs')
                self.offsets.append((offset, offset + item['bytes'])); offset += item['bytes']
            require(offset == total and whole.hexdigest() == digest, 'whole verified chunk representation differs')
        except BaseException:
            self.close(); raise

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position

    def seek(self, offset, whence=io.SEEK_SET):
        require(type(offset) is int and whence in (io.SEEK_SET, io.SEEK_CUR, io.SEEK_END), 'invalid chunk seek')
        target = offset + (self.position if whence == io.SEEK_CUR else self.total if whence == io.SEEK_END else 0)
        require(0 <= target <= self.total, 'chunk seek exceeds exact ZIP')
        self.position = target
        return target

    def read(self, size=-1):
        if size == -1:
            # ZipFile uses read() after seeking to its small end/directory
            # extent. It cannot materialize the full original through this API.
            size = self.total - self.position
        require(type(size) is int and 0 <= size <= 2_000_000, 'unbounded chunk reader allocation refused')
        remaining, pieces = min(size, self.total - self.position), []
        for (start, end), (stream, path, before) in zip(self.offsets, self.streams):
            if remaining == 0: break
            if not start <= self.position < end: continue
            require(identity(path) == before and bundle.descriptor_matches(os.fstat(stream.fileno()), tuple(before)),
                    'chunk changed during random access')
            stream.seek(self.position - start)
            data = stream.read(min(remaining, end - self.position))
            require(bool(data), 'short verified chunk read')
            pieces.append(data); self.position += len(data); remaining -= len(data)
        require(remaining == 0, 'verified chunks ended early')
        return b''.join(pieces)

    def close(self):
        for stream, _, _ in getattr(self, 'streams', []): stream.close()
        self.streams = []
        super().close()


def sole_zip(stream, total, name, size):
    """Admit the small directory before ZipFile creates any member objects."""
    require(22 <= total <= ZIP_BYTES and name in (IMAGE_NAME, *('zip.part-' + f'{i:02d}' for i in range(CHUNKS))),
            'unsupported sole-member ZIP contract')
    tail_size = min(total, 22 + 65535); stream.seek(total - tail_size); tail = stream.read(tail_size)
    offset = tail.rfind(b'PK\x05\x06')
    require(offset >= 0 and offset + 22 <= len(tail), 'ZIP end record absent')
    _, disk, directory_disk, disk_count, count, directory_size, directory_offset, comment = struct.unpack_from(
        '<4s4H2LH', tail, offset)
    end = total - tail_size + offset
    require(disk == directory_disk == 0 and disk_count == count == 1
            and offset + 22 + comment == len(tail) and directory_size <= 131072
            and directory_offset + directory_size == end, 'sole ordinary ZIP directory bounds differ')
    stream.seek(directory_offset); header = stream.read(46)
    require(len(header) == 46 and header[:4] == b'PK\x01\x02', 'ZIP central header differs')
    name_size, extra_size, comment_size, member_disk = struct.unpack_from('<4H', header, 28)
    require(member_disk == 0 and directory_size == 46 + name_size + extra_size + comment_size,
            'ZIP has an extra or malformed directory member')
    stream.seek(0)
    archive = zipfile.ZipFile(stream)
    try:
        infos = archive.infolist(); require(len(infos) == 1, 'ZIP member count differs')
        info = infos[0]; mode = info.external_attr >> 16
        require(info.filename == name and info.orig_filename == name and not info.is_dir()
                and not info.flag_bits & 1 and info.file_size == size
                and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and (stat.S_IFMT(mode) in (0, stat.S_IFREG)) and info.header_offset == 0
                and 0 < info.compress_size <= total, 'sole ZIP member identity/type/size differs')
        return archive, info
    except BaseException:
        archive.close(); raise


def extract():
    p, ctx = admitted(); outer(p, 'extract-binding')
    manifest = load(p['local'] / 'chunks.json')
    require(manifest.get('status') == 'PASS' and manifest.get('run_context') == ctx
            and manifest.get('original_zip_bytes') == ZIP_BYTES and manifest.get('original_zip_sha256') == ZIP_SHA
            and len(manifest['chunks']) == CHUNKS, 'complete original chunk proof required')
    capacity(p, 'extract-image', [IMAGE_BYTES, READBACK_BYTES, *ANALYSIS_FILE_BYTES], 3)
    with ChunkReader(p['chunks'], manifest['chunks'], ZIP_BYTES, ZIP_SHA) as reader:
        archive, info = sole_zip(reader, ZIP_BYTES, IMAGE_NAME, IMAGE_BYTES)
        digest, count = hashlib.sha256(), 0
        with archive, archive.open(info) as source, p['image'].open('xb') as output:
            while data := source.read(1024 * 1024):
                count += len(data); require(count <= IMAGE_BYTES, 'extracted image grew beyond exact admission')
                output.write(data); digest.update(data)
            output.flush(); os.fsync(output.fileno())
    require(count == IMAGE_BYTES and digest.hexdigest() == IMAGE_SHA, 'original image CRC/size/SHA differs')
    record = {'status': 'PASS', 'run_context': ctx, 'image_bytes': count, 'image_sha256': digest.hexdigest(),
              'image_identity': identity(p['image']), 'zip_crc_verified': True, 'scope': SCOPE}
    save(p['local'] / 'extraction.json', record)
    return record


def walk_inventory(root, output, *, max_entries=MAX_ENTRIES, max_bytes=IMAGE_BYTES):
    device = checked(root).st_dev
    count, total, written, files, errors, pending = 0, 0, 0, [], [], [root]
    digest = hashlib.sha256()
    with output.open('xb') as target:
        while pending:
            path = pending.pop(); count += 1
            require(count <= max_entries, 'complete inventory entry bound exceeded')
            relative = path.relative_to(root).as_posix()
            try:
                require(len(relative.encode()) <= 2048, 'inventory path too long')
                info = checked(path)
                require(info.st_dev == device, 'inventory crossed the readonly original filesystem')
                if stat.S_ISDIR(info.st_mode):
                    with os.scandir(path) as children:
                        names = []
                        for child in children:
                            require(count + len(pending) + len(names) < max_entries,
                                    'inventory pending enumeration bound exceeded')
                            names.append(child.name)
                    pending.extend(path / name for name in reversed(sorted(names)))
                    record = {'path': relative, 'type': 'directory', 'mode': info.st_mode}
                else:
                    require(info.st_nlink == 1, 'inventory linked regular file refused')
                    total += info.st_size; require(total <= max_bytes, 'complete inventory byte ceiling exceeded')
                    sha = hash_regular(path, max_bytes)
                    record = {'path': relative, 'type': 'regular', 'bytes': info.st_size,
                              'sha256': sha, 'mode': info.st_mode}
                    files.append(relative)
            except (OSError, ValueError) as error:
                require(len(errors) < 128, 'inventory error ceiling exceeded')
                record = {'path': relative, 'type': 'ERROR', 'error_type': type(error).__name__}
                errors.append(record)
            raw = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
            written += len(raw); require(written <= MAX_INVENTORY, 'complete inventory output ceiling exceeded')
            target.write(raw); digest.update(raw)
        target.flush(); os.fsync(target.fileno())
    return {'status': 'FAIL' if errors else 'PASS', 'complete': not errors, 'entries': count,
            'regular_files': len(files), 'original_file_bytes': total, 'inventory_bytes': written,
            'inventory_sha256': digest.hexdigest(), 'errors': errors}, files


def no_association(image, label):
    raw, _, _ = command(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                         '--output', 'NAME,BACK-FILE'], label)
    require(json.loads(raw).get('loopdevices') == [], 'owned image still has a current loop association')


def unmount_exact(p, image, mount, label, *, readonly, expected_bytes):
    before = mount_observation(image, mount, label + '-before', readonly=readonly,
                               expected_bytes=expected_bytes)
    command(['sudo', '-n', 'umount', '--', str(mount)], label, seconds=45)
    require(not os.path.ismount(mount) and backing_identity(image) == before['image_identity'],
            'owned mount did not close with exact original image identity')
    no_association(image, label + '-absent')
    return {'status': 'PASS', 'before': before, 'mount_absent': True, 'loop_absent': True}


def inspect():
    p, ctx = admitted(); outer(p, 'inspect-binding')
    extraction = load(p['local'] / 'extraction.json')
    require(extraction.get('run_context') == ctx and identity(p['image']) == extraction['image_identity']
            and hash_regular(p['image'], IMAGE_BYTES, IMAGE_BYTES) == IMAGE_SHA,
            'original image changed before readonly inspection')
    capacity(p, 'analysis-and-readback', [READBACK_BYTES, *ANALYSIS_FILE_BYTES], 2)
    pending = {'status': 'PREPARED', 'run_context': ctx, 'image_identity': identity(p['image'])}
    save(p['local'] / 'inner-mount.pending.json', pending)
    record = {'status': 'FAIL', 'run_context': ctx, 'scope': SCOPE, 'scientific_qualification': False}
    failures = []
    try:
        command(['sudo', '-n', 'mount', '-o', 'loop,ro,nodev,nosuid,noexec,noload',
                 str(p['image']), str(p['mount'])], 'mount-readonly-original', seconds=45)
        record['binding'] = mount_observation(p['image'], p['mount'], 'original-readonly-binding',
                                              readonly=True, expected_bytes=IMAGE_BYTES)
        external_admission(MAX_INVENTORY + 100_000)
        inventory, files = walk_inventory(p['mount'], p['local'] / 'original-file-inventory.jsonl')
        record['inventory'] = inventory
        candidates = [PurePosixPath(name).parent for name in files
                      if re.fullmatch(r'benchmarks/full-[^/]+/coverage\.json', name)]
        require(len(candidates) == 1, 'exactly one actual old full benchmark coverage folder is required')
        folder = p['mount'] / str(candidates[0]); coverage = load(folder / 'coverage.json')
        require(coverage.get('source') == OLD_SOURCE and coverage.get('profile') == 'full'
                and coverage.get('config', {}).get('concurrency') == 1,
                'actual original full-reader1 coverage identity differs')
        # Independently reject every nonregular/linked member in this subtree.
        # Root lost+found failures remain recorded, even when this subtree is readable.
        external_admission(MAX_INVENTORY + 100_000)
        nested, _ = walk_inventory(folder, p['local'] / 'benchmark-file-inventory.jsonl')
        record['benchmark_inventory'] = nested
        require(nested['complete'], 'actual raw benchmark subtree is not completely safe/readable')
        argv = [sys.executable, '-B', str(ROOT / 'scripts/analyze_reference.py'), str(folder),
                '--grid', str(ROOT / 'benchmarks/grid.json'), '--expected-source', OLD_SOURCE,
                '--output', str(p['analysis'])]
        record['analysis_command'] = argv
        # The dedicated analyzer worker applies file and address-space ceilings;
        # the unchanged analyzer writes only its five declared reports and two
        # capture files, all inside the admitted filesystem.
        _, _, observed = command([sys.executable, '-B', str(Path(__file__)), '_analyzer', str(folder)],
                                  'unchanged-old-source-analysis', seconds=760, accepted=(0, 1))
        record['analysis_supervision'] = observed
        result_path = p['scratch'] / 'analyzer-result.json'
        result = load(result_path); record['analysis'] = result
        if (p['analysis'] / 'analysis.json').is_file():
            report = load(p['analysis'] / 'analysis.json')
            record['analysis_summary'] = {key: report.get(key) for key in (
                'status', 'source', 'qualification', 'expected_cells', 'present_cells', 'sample_count',
                'successful_samples', 'target_outcome', 'target_status_counts')}
        record['status'] = 'PASS'
        record['inspection_status'] = ('PASS' if inventory['complete'] and result['exit_code'] == 0 else 'FAIL')
    except BaseException as error:
        failures.append({'phase': 'operation', 'error_type': type(error).__name__})
        record.update(inspection_status='FAIL', error_type=type(error).__name__)
    finally:
        # Every finalizer is attempted independently. An export failure must
        # never suppress exact unmount, final hashing or durable failure output.
        try:
            record['analysis_export'] = export_analysis(p)
        except BaseException as error:
            failures.append({'phase': 'analysis_export', 'error_type': type(error).__name__})
        try:
            record['readonly_close'] = unmount_exact(p, p['image'], p['mount'], 'close-original',
                                                      readonly=True, expected_bytes=IMAGE_BYTES)
        except BaseException as error:
            failures.append({'phase': 'readonly_close', 'error_type': type(error).__name__})
        try:
            record['image_sha256_after'] = hash_regular(p['image'], IMAGE_BYTES, IMAGE_BYTES)
            require(record['image_sha256_after'] == IMAGE_SHA, 'readonly original image bytes changed')
        except BaseException as error:
            failures.append({'phase': 'final_image_hash', 'error_type': type(error).__name__})
        record['failures'] = failures
        if failures:
            record.update(status='FAIL', inspection_status='FAIL')
        try:
            save(p['local'] / 'inspection.json', record)
        except BaseException as error:
            failures.append({'phase': 'inspection_receipt', 'error_type': type(error).__name__})
            record.update(status='FAIL', inspection_status='FAIL')
            try:
                save(p['local'] / 'inspection.failure.json', record)
            except BaseException as fallback_error:
                failures.append({'phase': 'alternate_inspection_receipt',
                                 'error_type': type(fallback_error).__name__})
    if failures:
        raise ValueError('readonly inspection failed: ' + ','.join(item['phase'] for item in failures)) from None
    return record


def export_analysis(p):
    """Preserve exact bounded actual reports/captures before outer cleanup."""
    target = p['local'] / 'analysis'
    target.mkdir(mode=0o700)
    names = ((p['analysis'], ('analysis.json', 'five-seed-intervals.json', 'paired-method-effects.json',
                             'per-seed-cells.csv', 'reference-target-cells.csv')),
             (p['scratch'], ('analysis.stdout', 'analysis.stderr', 'analyzer-result.json')))
    copied, records, missing, omitted = 0, [], [], []
    for folder, selections in names:
        for name in selections:
            path = folder / name
            if not os.path.lexists(path):
                missing.append(name); continue
            info = checked(path, regular=True); sha = hash_regular(path, 6_000_000)
            item = {'name': name, 'bytes': info.st_size, 'sha256': sha}
            if copied + info.st_size > 10_000_000:
                omitted.append(item); continue
            external_admission(info.st_size + 8192)
            before = identity(path)
            with path.open('rb') as source, (target / name).open('xb') as output:
                count = 0
                while data := source.read(1024 * 1024):
                    count += len(data); require(count <= info.st_size, 'analysis output grew during copy')
                    output.write(data)
                output.flush(); os.fsync(output.fileno())
            require(count == info.st_size and identity(path) == before
                    and hash_regular(target / name, 6_000_000) == sha, 'analysis capture/report copy differs')
            records.append(item); copied += info.st_size
    return {'files': records, 'missing': missing, 'omitted': omitted,
            'complete_available_output_export': not omitted, 'bytes': copied,
            'scope': 'Exact available actual outputs only; missing and omitted reports remain explicit.'}


def analyzer_worker(folder):
    import resource
    p, _ = admitted()
    require(folder.is_relative_to(p['mount']) and os.path.ismount(p['mount']), 'analyzer input is outside original mount')
    resource.setrlimit(resource.RLIMIT_FSIZE, (6_000_000, 6_000_000))
    resource.setrlimit(resource.RLIMIT_AS, (768_000_000, 768_000_000))
    env = dict(os.environ); env.pop('GITHUB_TOKEN', None)
    env.update(TMPDIR=str(p['scratch']), TMP=str(p['scratch']), TEMP=str(p['scratch']))
    argv = [sys.executable, '-B', str(ROOT / 'scripts/analyze_reference.py'), str(folder),
            '--grid', str(ROOT / 'benchmarks/grid.json'), '--expected-source', OLD_SOURCE,
            '--output', str(p['analysis'])]
    out, err = p['scratch'] / 'analysis.stdout', p['scratch'] / 'analysis.stderr'
    with out.open('xb') as stdout, err.open('xb') as stderr:
        result = subprocess.run(argv, stdout=stdout, stderr=stderr, env=env, timeout=710)
        stdout.flush(); stderr.flush(); os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
    record = {'exit_code': result.returncode, 'status': 'PASS' if result.returncode == 0 else 'FAIL',
              'expected_old_source': OLD_SOURCE, 'scientific_qualification': False,
              'stdout_bytes': checked(out, regular=True).st_size, 'stdout_sha256': hash_regular(out, 6_000_000),
              'stderr_bytes': checked(err, regular=True).st_size, 'stderr_sha256': hash_regular(err, 6_000_000)}
    save(p['scratch'] / 'analyzer-result.json', record)
    return record


def require_stage(p, name):
    require(name in ACTIONS, 'unknown canonical recovery stage')
    record = load(p['local'] / ('parent-' + name + '.json'))
    active = load(p['local'] / ('active-' + name + '.json'))
    observation = record.get('supervision', {})
    ctx = context()
    require(record.get('status') == 'PASS' and record.get('action') == name
            and record.get('run_context') == ctx and observation.get('status') == 'PASS'
            and observation.get('worker_started') is True
            and type(observation.get('worker_exit_code')) is int and observation['worker_exit_code'] == 0
            and observation.get('termination_reason') is None and observation.get('errors') == []
            and observation.get('startup_gate_released_after_durable_publication') is True
            and observation.get('capture_complete') is True and observation.get('discarded_output_bytes') == 0
            and observation.get('descendant_quiescence', {}).get('quiescent') is True
            and observation.get('descendant_quiescence', {}).get('residual') == [],
            'complete current quiescent parent receipt required: ' + name)
    parent, worker = record.get('parent_identity', {}), observation.get('worker_identity', {})
    require(all(type(value.get(key)) is int and value[key] > 0 for value in (parent, worker)
                for key in ('pid', 'ppid', 'start_time_ticks'))
            and worker['ppid'] == parent['pid'] and worker['pid'] != parent['pid']
            and active.get('action') == name and active.get('state') == 'RUNNING'
            and active.get('run_context') == ctx and active.get('parent_identity') == parent
            and active.get('worker_identity') == worker
            and type(record.get('nonce')) is str and bool(record['nonce'])
            and active.get('nonce') == record['nonce'],
            'exact durable parent/worker/startup identities differ: ' + name)
    captures, total = observation.get('capture', {}), 0
    require(type(captures) is dict and set(captures) == {'stdout', 'stderr'},
            'complete canonical recovery capture set required')
    for label in ('stdout', 'stderr'):
        path = p['local'] / ('parent-' + name + '.' + label)
        info = checked(path, regular=True)
        require(type(captures[label]) is dict and type(captures[label].get('bytes')) is int
                and info.st_size <= 32768 and captures[label] == {
            'path': str(path), 'bytes': info.st_size, 'sha256': hash_regular(path, 32768)},
            'actual canonical recovery capture path/bytes/SHA differs: ' + name)
        total += info.st_size
    require(total <= 32768 and type(observation.get('captured_output_bytes')) is int
            and observation['captured_output_bytes'] == total, 'combined actual recovery capture bytes differ')
    return record


def upload_admit():
    p, ctx = admitted(); outer(p, 'upload-binding')
    for stage in ('quota', 'download', 'extract', 'inspect'):
        require_stage(p, stage)
    require(not os.path.ismount(p['mount']), 'original readonly mount is still live before upload')
    no_association(p['image'], 'upload-original-unmounted')
    chunks = load(p['local'] / 'chunks.json')
    with ChunkReader(p['chunks'], chunks['chunks'], ZIP_BYTES, ZIP_SHA): pass
    record = {'status': 'PASS', 'run_context': ctx, 'original_zip_bytes': ZIP_BYTES,
              'original_zip_sha256': ZIP_SHA, 'original_image_sha256': IMAGE_SHA,
              'chunks': chunks['chunks'], 'chunk_artifact_zip_ceiling_bytes': ZIP_BYTES + CHUNKS * 1_000_000,
              'complete_retention': False, 'scope': SCOPE}
    save(p['local'] / 'upload-manifest.json', record)
    return record


def readback():
    p, ctx = admitted(); outer(p, 'readback-binding'); require_stage(p, 'uploads')
    manifest = load(p['local'] / 'upload-manifest.json')
    require(manifest.get('run_context') == ctx and manifest.get('status') == 'PASS', 'upload manifest differs')
    ids = [os.environ.get('FQ_RECOVERY_ARTIFACT_' + str(i), '') for i in range(CHUNKS)]
    require(all(re.fullmatch('[1-9][0-9]{0,19}', value) for value in ids)
            and len(set(ids)) == CHUNKS and str(ARTIFACT_ID) not in ids, 'eight new unique artifact IDs required')
    records = []
    progress = p['local'] / 'readback-progress.json'
    save(progress, {'status': 'INCOMPLETE', 'artifacts': [], 'run_context': ctx})
    for number, (artifact_id, chunk) in enumerate(zip(map(int, ids), manifest['chunks'])):
        require(not os.path.lexists(p['readback']), 'previous server readback remains allocated')
        capacity(p, 'readback-' + str(number), [READBACK_BYTES], 1)
        name = 'run34-original-zip-' + ctx['github_run_id'] + '-' + ctx['github_run_attempt'] + '-chunk-' + f'{number:02d}'
        def validate(value):
            size, digest = value.get('size_in_bytes'), value.get('digest', '')
            require(type(size) is int and chunk['bytes'] <= size <= chunk['bytes'] + 1_000_000
                    and size <= READBACK_BYTES and re.fullmatch('sha256:[0-9a-f]{64}', digest),
                    'new chunk server ZIP exceeds reserved wrapper bytes or lacks exact digest')
            return metadata_identity(value, artifact_id, name, size, digest[7:],
                                     int(ctx['github_run_id']), ctx['commit'])
        def consume(response, metadata):
            count, digest = 0, hashlib.sha256()
            with p['readback'].open('xb') as output:
                while data := response.read(min(1024 * 1024, metadata['size_in_bytes'] - count + 1)):
                    count += len(data)
                    require(count <= metadata['size_in_bytes'] <= READBACK_BYTES, 'server readback byte ceiling exceeded')
                    output.write(data); digest.update(data)
                output.flush(); os.fsync(output.fileno())
            require(count == metadata['size_in_bytes'] and 'sha256:' + digest.hexdigest() == metadata['digest'],
                    'actual server ZIP SHA/size differs from metadata')
            with p['readback'].open('rb') as stream:
                archive, info = sole_zip(stream, count, chunk['name'], chunk['bytes'])
                member_count, member_sha = 0, hashlib.sha256()
                with archive, archive.open(info) as member:
                    while data := member.read(1024 * 1024):
                        member_count += len(data); require(member_count <= chunk['bytes'], 'server member exceeded chunk')
                        member_sha.update(data)
            require(member_count == chunk['bytes'] and member_sha.hexdigest() == chunk['sha256'],
                    'actual server sole member CRC/size/SHA differs from original chunk')
            return {'server_zip_bytes': count, 'server_zip_sha256': digest.hexdigest(),
                    'member_bytes': member_count, 'member_sha256': member_sha.hexdigest(), 'crc_verified': True}
        metadata, host, verified = api_transfer(artifact_id, validate, consume)
        # Retire only this exact checked readback after preserving its verified identity.
        before = identity(p['readback'])
        require(hash_regular(p['readback'], READBACK_BYTES) == verified['server_zip_sha256']
                and identity(p['readback']) == before, 'readback changed before exact retirement')
        records.append({'number': number, 'artifact': metadata, 'delivery_host': host, **verified})
        save(progress, {'status': 'INCOMPLETE', 'artifacts': records, 'run_context': ctx}, replace=True)
        os.unlink(p['readback'])
        require(not os.path.lexists(p['readback']), 'retired server readback still occupies a slot')
    with ChunkReader(p['chunks'], manifest['chunks'], ZIP_BYTES, ZIP_SHA): pass
    record = {'status': 'PASS', 'run_context': ctx, 'artifacts': records,
              'original_zip_bytes': ZIP_BYTES, 'original_zip_sha256': ZIP_SHA,
              'complete_retention': False, 'awaiting_parent_capture_quiescence': True, 'scope': SCOPE}
    save(p['local'] / 'readback.json', record)
    return record


def retained_unmounted_outer(p, ctx):
    """Authenticate an owned pre-mount allocation; retain it without deletion."""
    proof = load(p['local'] / 'outer-allocation.json')
    info = checked(p['outer'], regular=True)
    observed = [info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                info.st_gid, info.st_nlink, info.st_size]
    require(set(proof) == {'status', 'run_context', 'outer_path', 'volume_path', 'image_identity',
                          'outer_bytes', 'created_via', 'hard_quota_enforced'}
            and proof.get('status') == 'PASS' and proof.get('run_context') == ctx
            and proof.get('outer_path') == str(p['outer']) and proof.get('volume_path') == str(p['volume'])
            and type(proof.get('outer_bytes')) is int and proof['outer_bytes'] == OUTER_BYTES
            and proof.get('created_via') == 'exclusive-descriptor-fsynced-posix-fallocate-v1'
            and proof.get('hard_quota_enforced') is False,
            'refusing unidentified pre-mount outer allocation')
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.getuid() and info.st_nlink == 1 and info.st_size == OUTER_BYTES
            and type(proof.get('image_identity')) is list and len(proof['image_identity']) == 7
            and all(type(value) is int for value in proof['image_identity'])
            and proof['image_identity'] == observed and backing_identity(p['outer']) == observed
            and not os.path.ismount(p['volume']), 'pre-mount ownership or unmounted state differs')
    raw, _, observation = command(['sudo', '-n', 'losetup', '--json', '--list', '--associated',
                                  str(p['outer']), '--output',
                                  'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT,RO'],
                                 'cleanup-unmounted-outer-loop')
    loops = json.loads(raw, object_pairs_hook=bundle.unique_object)
    require(type(loops) is dict and set(loops) == {'loopdevices'} and loops['loopdevices'] == []
            and backing_identity(p['outer']) == observed and not os.path.ismount(p['volume']),
            'unmounted allocation has an active, ambiguous or changed loop binding')
    return {'status': 'PASS', 'state': 'OWNED_UNMOUNTED_RETAINED', 'run_context': ctx,
            'image_identity': observed, 'allocation_proof': proof, 'loop_observation': observation,
            'hard_quota_enforced': False, 'deleted_or_detached': False,
            'scope': 'Positive creation ownership and no active loop only; no ENOSPC or quota claim.'}


def cleanup():
    p, ctx = admitted(); result = {'run_context': ctx, 'status': 'PASS', 'scope': SCOPE}
    if os.path.ismount(p['mount']):
        pending = load(p['local'] / 'inner-mount.pending.json')
        require(pending.get('run_context') == ctx and identity(p['image']) == pending['image_identity'],
                'refusing unbound inner cleanup')
        result['inner'] = unmount_exact(p, p['image'], p['mount'], 'cleanup-inner',
                                         readonly=True, expected_bytes=IMAGE_BYTES)
        require(hash_regular(p['image'], IMAGE_BYTES, IMAGE_BYTES) == IMAGE_SHA, 'cleanup original image SHA differs')
    if os.path.ismount(p['volume']):
        outer(p, 'cleanup-outer-binding')
        result['outer'] = unmount_exact(p, p['outer'], p['volume'], 'cleanup-outer',
                                         readonly=False, expected_bytes=OUTER_BYTES)
    elif os.path.lexists(p['outer']):
        result['outer'] = retained_unmounted_outer(p, ctx)
    result.update(owned_outer_retained_until_runner_termination=True,
                  remote_allocation_retirement_requires_actual_job_termination=True,
                  original_cloud_and_native_keepers_untouched=True)
    save(p['local'] / 'cleanup.json', result)
    return result


def metadata():
    p = paths(); packet = p['local'] / 'packet'
    require(not os.path.lexists(packet), 'metadata packet already exists')
    packet.mkdir(mode=0o700)
    selected, omitted, copied = [], [], 0
    # Keep the complete manifest and all small parent/failure/summary receipts.
    # Explicitly identify any oversized inventory/reports rather than silently
    # calling a reduced convenience export complete preservation.
    candidates = []
    for base in (p['local'], p['evidence']):
        if not base.is_dir(): continue
        pending = [base]
        while pending:
            item = pending.pop()
            if item == packet: continue
            if item.parent == p['local'] and item.name in (
                    'parent-metadata.stdout', 'parent-metadata.stderr', 'active-metadata.json'):
                continue  # This stage's open captures are explicitly not final.
            info = checked(item)
            require(len(candidates) + len(pending) < 4096, 'diagnostic enumeration bound exceeded')
            if stat.S_ISDIR(info.st_mode):
                with os.scandir(item) as children:
                    for child in children:
                        require(len(candidates) + len(pending) < 4096, 'diagnostic pending bound exceeded')
                        pending.append(item / child.name)
            else: candidates.append(item)
    for base in (p['analysis'], p['scratch']):
        if os.path.ismount(p['volume']) and base.is_dir():
            with os.scandir(base) as children:
                for child in children:
                    item = base / child.name
                    if stat.S_ISREG(checked(item).st_mode): candidates.append(item)
    candidates.sort(key=lambda item: (item.name != 'retention.json', item.name != 'upload-manifest.json', str(item)))
    for item in candidates:
        info = checked(item, regular=True)
        require(info.st_size <= MAX_INVENTORY, 'diagnostic file exceeds producer ceiling')
        sha = hash_regular(item, MAX_INVENTORY)
        description = {'path': str(item.relative_to(ROOT)) if item.is_relative_to(ROOT)
                       else 'inside-owned-volume/' + item.relative_to(p['volume']).as_posix(),
                       'bytes': info.st_size, 'sha256': sha}
        if copied + info.st_size + 4096 > 6_000_000:
            omitted.append(description); continue
        external_admission(info.st_size + 8192)
        target = packet / (hashlib.sha256(description['path'].encode()).hexdigest() + '.bin')
        before = identity(item)
        with item.open('rb') as source, target.open('xb') as output:
            count = 0
            while data := source.read(1024 * 1024):
                count += len(data); require(count <= info.st_size, 'diagnostic grew during bounded export')
                output.write(data)
            output.flush(); os.fsync(output.fileno())
        require(count == info.st_size and identity(item) == before
                and hash_regular(target, MAX_INVENTORY) == sha, 'diagnostic copy differs')
        copied += info.st_size + 4096; selected.append({**description, 'packet_member': target.name})
    external = external_admission()
    result = {'status': 'PASS', 'scope': SCOPE, 'external_actual_bytes': external,
              'selected_files': selected, 'omitted_files': omitted,
              'metadata_export_complete': not omitted, 'cloud_metadata_upper_bound_bytes': METADATA_BYTES + 1_000_000,
              'scientific_qualification': False, 'complete_data_retention_claim': False,
              'reduced_export_scope': 'Omissions and this metadata stage\'s unfinished self-receipts are explicit. Original bytes remain reconstructible only when the eight-chunk retention proof passes.'}
    if (p['local'] / 'retention.json').is_file():
        retention = load(p['local'] / 'retention.json')
        result['complete_data_retention_claim'] = retention.get('complete_retention') is True
    save(packet / 'manifest.json', result)
    require(physical(packet)[0] <= METADATA_BYTES, 'packet physical allocation exceeds cloud wrapper reservation')
    save(p['local'] / 'metadata.json', {'status': 'PASS', 'packet_bytes': physical(packet)[0],
                                       'metadata_export_complete': not omitted})
    return result


ACTIONS = {'plan': plan, 'quota': quota, 'download': download, 'extract': extract,
           'inspect': inspect, 'uploads': upload_admit, 'readback': readback,
           'cleanup': cleanup, 'metadata': metadata}


def supervise(action):
    seconds = 45 if action in ('uploads', 'metadata') else SCHEDULE[action]
    p, ctx = paths(), context()
    timing = time_admission(action, ctx['job_started_epoch'], time.time())
    save(p['local'] / ('time-' + action + '.json'), timing)
    require(timing['allowed'], 'actual whole-job remaining time cannot preserve later stages and tails')
    external_admission(200_000)
    env = dict(os.environ)
    nonce = uuid.uuid4().hex
    env['FQ_IMAGE_RECOVERY_PARENT_NONCE'] = nonce
    if action not in ('download', 'readback'): env.pop('GITHUB_TOKEN', None)
    if action not in ('plan', 'quota') and p['scratch'].is_dir():
        env.update(TMPDIR=str(p['scratch']), TEMP=str(p['scratch']), TMP=str(p['scratch']))
    argv = [sys.executable, '-B', str(Path(__file__)), '_worker', action]
    parent = supervisor.process_identity(os.getpid())
    def launched(worker):
        save(p['local'] / ('active-' + action + '.json'),
             {'run_context': ctx, 'parent_identity': parent, 'worker_identity': worker,
              'nonce': nonce, 'action': action, 'state': 'RUNNING'})
    observed = supervisor.run_owned(argv, p['local'] / ('parent-' + action + '.stdout'),
        p['local'] / ('parent-' + action + '.stderr'), started=ENTRY_STARTED,
        total_seconds=seconds - 3, cleanup_seconds=8, receipt_seconds=2, capture_bytes=32768,
        environ=env, launched=launched, startup_gate=True)
    record = {'status': observed['status'], 'run_context': ctx, 'action': action, 'scope': SCOPE,
              'parent_identity': parent, 'nonce': nonce,
              'supervision': observed, 'time_admission': timing,
              'entry_duration_seconds': time.monotonic() - ENTRY_STARTED}
    save(p['local'] / ('parent-' + action + '.json'), record)
    require(record['status'] == 'PASS', 'actual supervised recovery stage failed: ' + action)
    if action == 'readback':
        for required in ('quota', 'download', 'extract', 'inspect', 'uploads', 'readback'):
            require_stage(p, required)
        verified = load(p['local'] / 'readback.json')
        require(verified.get('status') == 'PASS' and verified.get('run_context') == ctx
                and len(verified['artifacts']) == CHUNKS, 'complete eight-artifact readback proof missing')
        verified.update(complete_retention=True, awaiting_parent_capture_quiescence=False,
                        parent_receipt_sha256=hash_regular(p['local'] / 'parent-readback.json', MAX_JSON),
                        scientific_qualification=False)
        save(p['local'] / 'retention.json', verified)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=(*ACTIONS, 'clock', '_worker', '_analyzer'))
    parser.add_argument('child', nargs='?')
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.getuid() > 0, 'ordinary Linux recovery runtime required')
    ensure_metadata()
    action = args.child if args.action == '_worker' else args.action
    try:
        if args.action == 'clock':
            require(args.child is None, 'unexpected clock argument')
            with filesystem.whole_entry(40, started=ENTRY_STARTED):
                result = job_clock()
        elif args.action == '_analyzer':
            require(args.child is not None, 'analyzer folder absent')
            result = analyzer_worker(Path(args.child))
        elif args.action == '_worker':
            require(action in ACTIONS, 'unknown recovery worker action')
            supervisor.await_startup_gate()
            proof = load(paths()['local'] / ('active-' + action + '.json'))
            current = supervisor.process_identity(os.getpid())
            require(proof.get('action') == action and proof.get('state') == 'RUNNING'
                    and proof.get('nonce') == os.environ.get('FQ_IMAGE_RECOVERY_PARENT_NONCE')
                    and proof.get('run_context') == context()
                    and proof.get('parent_identity', {}).get('pid') == os.getppid()
                    and supervisor.same_process(proof['parent_identity'])
                    and proof.get('worker_identity', {}).get('pid') == current['pid']
                    and proof['worker_identity'].get('start_time_ticks') == current['start_time_ticks'],
                    'recovery worker lacks exact live durable parent/startup binding')
            result = ACTIONS[action]()
        else:
            require(args.child is None, 'unexpected recovery argument')
            with filesystem.whole_entry(SCHEDULE[action], started=ENTRY_STARTED):
                result = supervise(action)
        print(json.dumps({'status': result.get('status'), 'action': action, 'scope': SCOPE}, sort_keys=True))
        if args.action == 'metadata' and result.get('status') == 'PASS' and os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
                output.write('metadata_allowed=true\n')
        return 0 if result.get('status') == 'PASS' else 1
    except BaseException as error:
        # Do not print exception text or tracebacks: signed delivery URLs and
        # credentials never enter captures, even on network/parser failures.
        failure = {'status': 'FAIL', 'profile': PROFILE, 'action': action,
                   'error_type': type(error).__name__, 'created_at': utc(), 'scope': SCOPE,
                   'complete_retention': False, 'scientific_qualification': False}
        try: save(paths()['local'] / ('failure-' + str(action) + '-' + uuid.uuid4().hex[:8] + '.json'), failure)
        except BaseException: pass
        print(json.dumps(failure, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
