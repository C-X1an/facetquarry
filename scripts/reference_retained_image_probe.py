"""Fixed run38 inputs -> readonly metadata. No benchmark, analyzer or data upload.

Each action runs under an independent bounded parent. This is a new admission
contract; it never selects or bypasses the original recovery stage guards.
"""
from __future__ import annotations
import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from common import ROOT, source_hash
import evidence_bundle as bundle
import reference_filesystem as fs
import reference_image_recovery as recovery
import reference_transport_supervisor as supervisor

PROFILE = 'run38-retained-readonly-metadata-probe-v1'
SCOPE = 'Fixed retained compressed bytes and exact image -> readonly metadata only; no analysis or scientific qualification.'
REPOSITORY = recovery.REPOSITORY
REPOSITORY_ID = recovery.REPOSITORY_ID
INPUT_RUN = 42160839625
INPUT_HEAD = '151942996d7dcb553d51eefbb68cca8b94c8f14f'
INPUT_IDS = (13476667063, 13477265192, 13477260207, 13476976782,
             13477165803, 13477270301, 13477145872, 13475944893)
OUTER_BYTES = 2_100_000_000
PROBE_BYTES = 2_200_000_000
EXTERNAL_BYTES = 50_000_000
CLOUD_BYTES = 10_000_000
OVERHEAD = 50_000_000
GROWTH = OUTER_BYTES + EXTERNAL_BYTES + CLOUD_BYTES + OVERHEAD
CEILING = 12_000_000_000
INVENTORY_BYTES = 8_000_000
JSON_BYTES = 2_000_000
STAGES = {'plan': 45, 'quota': 180, 'download': 480, 'extract': 300,
          'observe': 240, 'cleanup': 180, 'export': 120}
JOB_SECONDS = 1800
STARTED = time.monotonic()
require = fs.require
checked = recovery.checked
identity = recovery.identity
backing_identity = recovery.backing_identity
hash_regular = recovery.hash_regular


def paths():
    parent = Path(os.environ['RUNNER_TEMP'])
    require(parent.is_absolute() and '..' not in parent.parts and str(parent) == os.path.abspath(parent),
            'noncanonical runner temp')
    checked(parent)
    volume = parent / 'facetquarry-retained-metadata-probe'
    return {'outer': parent / 'facetquarry-retained-metadata-probe.img', 'volume': volume,
            'chunks': volume / 'chunks', 'wrapper': volume / 'wrapper.zip',
            'image': volume / recovery.IMAGE_NAME, 'mount': volume / 'readonly-original',
            'local': ROOT / '.local/retained-metadata-probe'}


def external(extra=0):
    require(type(extra) is int and extra >= 0, 'invalid control reservation')
    total, count, pending = 0, 0, [paths()['local']]
    while pending:
        path = pending.pop()
        if not os.path.lexists(path): continue
        info = checked(path); count += 1
        require(count <= 4096 and info.st_uid == os.getuid(), 'external ownership/entry bound')
        total += max(info.st_size, info.st_blocks * 512)
        require(total + extra <= EXTERNAL_BYTES, 'external evidence allocation refused')
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    require(count + len(pending) < 4096, 'pending external entry bound')
                    pending.append(path / entry.name)
    return total


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(raw) <= JSON_BYTES, 'bounded probe receipt required')
    external(len(raw) + 8192)
    checked(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def load(path, limit=JSON_BYTES):
    info = checked(path, regular=True)
    require(info.st_uid == os.getuid() and info.st_size <= limit, 'unowned or oversized probe JSON')
    before = identity(path)
    with path.open('rb') as stream:
        require(bundle.descriptor_matches(os.fstat(stream.fileno()), tuple(before)), 'JSON descriptor differs')
        raw = stream.read(limit + 1)
        require(len(raw) == info.st_size and identity(path) == before
                and bundle.descriptor_matches(os.fstat(stream.fileno()), tuple(before)), 'JSON changed')
    return json.loads(raw, object_pairs_hook=bundle.unique_object)


def ensure_local():
    for path in (ROOT / '.local', paths()['local'], paths()['local'] / 'commands'):
        if not os.path.lexists(path): path.mkdir(mode=0o700)
        info = checked(path)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and not stat.S_IMODE(info.st_mode) & 0o022, 'unsafe probe control directory')


def command(argv, label, seconds=30, accepted=(0,)):
    require(re.fullmatch('[a-z0-9-]{1,70}', label) and 20 <= seconds <= 120, 'invalid command bound')
    external(150_000)
    prefix = paths()['local'] / 'commands' / (label + '-' + uuid.uuid4().hex[:12])
    actual = argv
    if argv[:2] == ['sudo', '-n']:
        actual = ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=2s',
                  str(seconds - 12) + 's', *argv[2:]]
    env = dict(os.environ); env.pop('GITHUB_TOKEN', None); env['LC_ALL'] = 'C'
    observed = supervisor.run_owned(actual, prefix.with_suffix('.stdout'), prefix.with_suffix('.stderr'),
        started=time.monotonic(), total_seconds=seconds, cleanup_seconds=8, receipt_seconds=2,
        capture_bytes=32768, environ=env)
    complete = (observed.get('capture_complete') is True and observed.get('discarded_output_bytes') == 0
        and observed.get('descendant_quiescence', {}).get('quiescent') is True
        and observed.get('descendant_quiescence', {}).get('residual') == []
        and observed.get('termination_reason') is None and observed.get('errors') == [])
    record = {'requested_command': argv, 'actual_command': actual, 'supervision': observed,
              'accepted_exit_codes': list(accepted),
              'status': 'PASS' if complete and observed.get('worker_exit_code') in accepted else 'FAIL'}
    save(prefix.with_suffix('.json'), record)
    require(record['status'] == 'PASS', 'owned probe command failed: ' + label)
    return prefix.with_suffix('.stdout').read_bytes(), prefix.with_suffix('.stderr').read_bytes(), record


def context():
    require(sys.platform == 'linux' and os.getuid() > 0 and os.getgid() > 0
            and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
            and os.environ.get('GITHUB_REPOSITORY_ID') == str(REPOSITORY_ID)
            and os.environ.get('GITHUB_JOB') == 'codec'
            and os.environ.get('FQ_RETAINED_IMAGE_PROBE') == 'true'
            and os.environ.get('FQ_RESERVATION_PROFILE') == PROFILE
            and Path(os.environ['GITHUB_WORKSPACE']) == ROOT, 'unauthorized metadata probe runtime')
    run, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(all(re.fullmatch('[1-9][0-9]{0,19}', v) for v in (run, attempt)), 'actual run identities required')
    raw, _, _ = command(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], 'context-head')
    commit = raw.decode().strip()
    raw, _, _ = command(['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=normal'], 'context-clean')
    require(re.fullmatch('[0-9a-f]{40}', commit) and commit == os.environ.get('GITHUB_SHA') and raw == b'',
            'probe source must be exact clean checkout')
    epoch = os.environ.get('FQ_PROBE_STARTED_EPOCH', '')
    require(re.fullmatch('[1-9][0-9]{9,12}', epoch), 'observed job-start clock required')
    return {'profile': PROFILE, 'repository': REPOSITORY, 'repository_id': REPOSITORY_ID,
            'job': 'codec', 'commit': commit, 'source': source_hash(),
            'github_run_id': run, 'github_run_attempt': attempt, 'started_epoch': int(epoch)}


def growth_plan(base):
    require(type(base) is int and base >= 2_000_000_000, 'fresh full baseline with global reserve required')
    return {'profile': PROFILE, 'baseline_includes_global_reserve': base,
            'outer_image_bytes': OUTER_BYTES, 'external_bytes': EXTERNAL_BYTES,
            'cloud_metadata_bytes': CLOUD_BYTES, 'overhead_bytes': OVERHEAD,
            'maximum_new_bytes': GROWTH, 'peak_bytes': base + GROWTH, 'ceiling_bytes': CEILING,
            'admission': 'ALLOW' if base + GROWTH < CEILING else 'REFUSE'}


def inputs():
    path = ROOT / 'verification/published/run38-retention-run39-fixture-controls.json'
    raw = path.read_bytes(); require(len(raw) <= JSON_BYTES, 'curated fixed input bound')
    value = json.loads(raw, object_pairs_hook=bundle.unique_object)
    rows = value['retained_chunk_artifacts']
    require(type(rows) is list and len(rows) == recovery.CHUNKS, 'eight fixed input artifacts required')
    for number, (row, size, aid) in enumerate(zip(rows, recovery.chunk_sizes(), INPUT_IDS)):
        require(row.get('id') == aid and row.get('name') == f'run34-original-zip-{INPUT_RUN}-1-chunk-{number:02d}'
                and row.get('raw_member_bytes') == size and type(row.get('size_in_bytes')) is int
                and size <= row['size_in_bytes'] <= size + 1_000_000
                and re.fullmatch('sha256:[0-9a-f]{64}', row.get('digest', ''))
                and re.fullmatch('[0-9a-f]{64}', row.get('raw_member_sha256', '')),
                'curated fixed artifact identity differs')
    return rows, hashlib.sha256(raw).hexdigest()


def admitted():
    p, ctx = paths(), context(); proof = load(p['local'] / 'plan.json')
    expected = growth_plan(int(os.environ['FQ_ACCOUNTED_BASE_BYTES']))
    _, digest = inputs()
    require(proof.get('run_context') == ctx and proof.get('plan') == expected
            and expected['admission'] == 'ALLOW' and proof.get('input_manifest_sha256') == digest,
            'probe admission/context/input identity differs')
    return p, ctx


def plan():
    p, ctx = paths(), context(); _, digest = inputs()
    expected = growth_plan(int(os.environ['FQ_ACCOUNTED_BASE_BYTES']))
    require(expected['admission'] == 'ALLOW', 'fresh all-attributable growth refused')
    require(os.statvfs(p['outer'].parent).f_frsize <= 4096
            and os.statvfs(ROOT).f_frsize <= 4096, 'external allocation unit exceeds reservation')
    require(os.statvfs(p['outer'].parent).f_bavail * os.statvfs(p['outer'].parent).f_frsize
            >= OUTER_BYTES + EXTERNAL_BYTES + OVERHEAD, 'host physical free admission refused')
    record = {'status': 'PASS', 'run_context': ctx, 'plan': expected,
              'input_manifest_sha256': digest, 'scope': SCOPE}
    save(p['local'] / 'plan.json', record); return record


def require_stage(p, ctx, stage):
    record = load(p['local'] / ('parent-' + stage + '.json'))
    active = load(p['local'] / ('active-' + stage + '.json'))
    s = record.get('supervision', {})
    require(record.get('status') == 'PASS' and record.get('action') == stage
            and record.get('run_context') == active.get('run_context') == ctx
            and record.get('nonce') == active.get('nonce') and bool(record.get('nonce'))
            and record.get('parent_identity') == active.get('parent_identity')
            and s.get('worker_identity') == active.get('worker_identity')
            and active.get('action') == stage and s.get('status') == 'PASS'
            and s.get('worker_started') is True and s.get('worker_exit_code') == 0
            and s.get('startup_gate_released_after_durable_publication') is True
            and s.get('capture_complete') is True and s.get('discarded_output_bytes') == 0
            and s.get('termination_reason') is None and s.get('errors') == []
            and s.get('descendant_quiescence', {}).get('quiescent') is True
            and s.get('descendant_quiescence', {}).get('residual') == [], 'complete bound quiescent upstream stage required')
    parent, worker = record['parent_identity'], s['worker_identity']
    require(all(type(v.get(k)) is int and v[k] > 0 for v in (parent, worker)
                for k in ('pid', 'ppid', 'start_time_ticks'))
            and worker['ppid'] == parent['pid'] and worker['pid'] != parent['pid'], 'upstream process identity differs')
    captures = s.get('capture', {})
    require(type(captures) is dict and set(captures) == {'stdout','stderr'}, 'upstream capture set differs')
    total = 0
    for label in ('stdout','stderr'):
        path = p['local'] / ('parent-' + stage + '.' + label); info = checked(path, regular=True)
        require(info.st_size <= 32768 and captures[label] == {'path': str(path), 'bytes': info.st_size,
                'sha256': hash_regular(path, 32768)}, 'upstream complete capture changed')
        total += info.st_size
    require(total <= 32768 and total == s.get('captured_output_bytes'), 'combined upstream capture bound differs')
    return record


def mount_binding(image, mount, label, readonly, size):
    info = checked(image, regular=True); before = backing_identity(image)
    require(info.st_uid == os.getuid() and info.st_nlink == 1 and info.st_size == size, 'owned image binding differs')
    raw, _, _ = command(['findmnt', '--json', '--mountpoint', str(mount), '-o',
                         'TARGET,FSTYPE,SOURCE,OPTIONS,MAJ:MIN'], label)
    mounts = json.loads(raw, object_pairs_hook=bundle.unique_object)['filesystems']
    require(type(mounts) is list and len(mounts) == 1, 'ambiguous mount')
    selected = mounts[0]; options = set(selected.get('options', '').split(','))
    require(selected.get('target') == str(mount) and selected.get('fstype') == 'ext4'
            and re.fullmatch('/dev/loop[0-9]+', selected.get('source', ''))
            and {'nodev', 'nosuid', 'noexec'} <= options
            and ('ro' in options if readonly else 'rw' in options)
            and (not readonly or bool({'noload', 'norecovery'} & options)), 'mount options differ')
    raw, _, _ = command(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
        '--output', 'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT,RO'], label + '-loop')
    loops = json.loads(raw, object_pairs_hook=bundle.unique_object)['loopdevices']
    require(type(loops) is list and len(loops) == 1, 'ambiguous loop binding')
    loop = loops[0]
    require(loop.get('name') == selected['source'] and loop.get('back-file') == str(image)
            and int(loop.get('back-ino', -1)) == info.st_ino
            and loop.get('back-maj:min') == f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}'
            and loop.get('offset') == loop.get('sizelimit') == 0 and bool(loop.get('ro')) == readonly
            and backing_identity(image) == before, 'exact loop backing differs')
    return {'mount': selected, 'loop': loop, 'image_identity': before}


def outer(p, ctx, label):
    proof = load(p['local'] / 'quota.json')
    require(proof.get('run_context') == ctx and proof.get('hard_quota_enforced') is True, 'actual quota proof required')
    raw, _, _ = command(['dumpe2fs', '-h', str(p['outer'])], label + '-geometry')
    observed = recovery.recovery_geometry(raw.decode(), lifecycle='mounted')
    excluded = {'observed_lifecycle_features', 'journal_features', 'journal_checksum_type'}
    require({k:v for k,v in observed.items() if k not in excluded}
            == {k:v for k,v in proof['geometry'].items() if k not in excluded}, 'static outer geometry changed')
    require(mount_binding(p['outer'], p['volume'], label, False, OUTER_BYTES) == proof['binding'], 'outer binding changed')


def capacity(p, bytes_needed, entries_needed):
    require(type(bytes_needed) is int and type(entries_needed) is int
            and min(bytes_needed, entries_needed) >= 0 and os.path.ismount(p['volume'])
            and checked(p['volume']).st_dev != checked(p['outer'].parent).st_dev, 'owned capacity mount required')
    v = os.statvfs(p['volume'])
    require(recovery.space_admission(v.f_frsize, v.f_bavail, v.f_favail, bytes_needed, entries_needed)['allowed'],
            'actual ordinary free byte/inode admission refused')


class InventoryOutput:
    """Enforce the separately admitted output ceiling before every real write."""
    def __init__(self, path, maximum):
        require(type(maximum) is int and maximum >= 0, 'invalid inventory producer bound')
        self.path, self.maximum = path, maximum

    @contextlib.contextmanager
    def open(self, mode):
        require(mode == 'xb', 'inventory output must be new and binary')
        with self.path.open(mode) as stream:
            class Writer:
                written = 0

                def write(inner, data):
                    require(type(data) is bytes and inner.written + len(data) <= self.maximum,
                            'inventory producer reservation exceeded before write')
                    count = stream.write(data)
                    require(count == len(data), 'short inventory output write')
                    inner.written += count
                    return count

                def flush(inner): return stream.flush()

                def fileno(inner): return stream.fileno()
            yield Writer()


def quota():
    p, ctx = admitted()
    require(not os.path.lexists(p['outer']) and not os.path.lexists(p['volume']), 'occupied probe slots')
    p['volume'].mkdir(mode=0o700)
    fd = os.open(p['outer'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.posix_fallocate(fd, 0, OUTER_BYTES); os.fsync(fd)
        require(bundle.descriptor_matches(os.fstat(fd), tuple(identity(p['outer'])))
                and os.fstat(fd).st_size == OUTER_BYTES, 'new allocation descriptor differs')
    finally: os.close(fd)
    allocation = backing_identity(p['outer'])
    save(p['local'] / 'allocation.json', {'status': 'PASS', 'run_context': ctx,
         'image_identity': allocation, 'image_path': str(p['outer']), 'hard_quota_enforced': False})
    command(recovery.recovery_formatter_argv(p['outer']), 'format', 45)
    raw, _, _ = command(['dumpe2fs', '-h', str(p['outer'])], 'clean-superblock')
    geometry = recovery.recovery_geometry(raw.decode())
    require(backing_identity(p['outer']) == allocation, 'formatter backing changed')
    # Cleanup authenticates this intent and the allocation even when mount,
    # ownership, binding or ENOSPC validation prevents successful quota proof.
    save(p['local'] / 'mount-pending.json', {'run_context': ctx,
         'image_path': str(p['outer']), 'mount_path': str(p['volume']),
         'image_identity': allocation, 'hard_quota_enforced': False})
    command(['sudo', '-n', 'mount', '-o', 'loop,nodev,nosuid,noexec', str(p['outer']), str(p['volume'])], 'mount-outer', 45)
    command(['sudo', '-n', 'chown', f'{os.getuid()}:{os.getgid()}', str(p['volume']), str(p['volume'] / 'lost+found')], 'own-outer')
    binding = mount_binding(p['outer'], p['volume'], 'quota-binding', False, OUTER_BYTES)
    probe = p['volume'] / 'enospc-probe'
    require(not os.path.lexists(probe), 'occupied ENOSPC probe')
    _, err, observation = command(['fallocate', '-l', str(PROBE_BYTES), str(probe)], 'actual-enospc', 45, (1,))
    require(b'No space left on device' in err, 'actual oversized ENOSPC missing')
    info = checked(probe, regular=True)
    require(info.st_uid == os.getuid() and info.st_size <= PROBE_BYTES, 'unsafe probe retirement')
    probe.unlink()
    record = {'status': 'PASS', 'run_context': ctx, 'hard_quota_enforced': True,
              'outer_bytes': OUTER_BYTES, 'probe_bytes': PROBE_BYTES, 'geometry': geometry,
              'binding': binding, 'enospc_sha256': hashlib.sha256(err).hexdigest(), 'observation': observation}
    save(p['local'] / 'quota.json', record)
    capacity(p, recovery.ZIP_BYTES + recovery.IMAGE_BYTES + recovery.READBACK_BYTES + INVENTORY_BYTES, 24)
    p['chunks'].mkdir(mode=0o700); p['mount'].mkdir(mode=0o700)
    return record


def decode_wrapper(p, row, number):
    """Verify wrapper and exhaust member CRC before publishing a raw chunk."""
    require(type(number) is int and 0 <= number < recovery.CHUNKS, 'fixed chunk number required')
    require(type(row['raw_member_bytes']) is int and 0 < row['raw_member_bytes'] <= recovery.CHUNK_BYTES,
            'bounded raw chunk required')
    require(hash_regular(p['wrapper'], recovery.READBACK_BYTES, row['size_in_bytes']) == row['digest'][7:],
            'pinned wrapper SHA differs before decode')
    before = identity(p['wrapper']); name = f'zip.part-{number:02d}'; target = p['chunks'] / name
    with p['wrapper'].open('rb') as stream:
        require(bundle.descriptor_matches(os.fstat(stream.fileno()), tuple(before)), 'wrapper descriptor differs')
        archive, info = recovery.sole_zip(stream, row['size_in_bytes'], name, row['raw_member_bytes'])
        member_count, member_sha = 0, hashlib.sha256()
        # O_EXCL refuses an existing destination on every platform. Linux
        # additionally retains O_NOFOLLOW; tiny codec controls also run on Windows.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with archive, archive.open(info) as source, os.fdopen(fd, 'wb') as output:
            while data := source.read(1024 * 1024):
                member_count += len(data); require(member_count <= row['raw_member_bytes'], 'member exceeds exact bound')
                output.write(data); member_sha.update(data)
            output.flush(); os.fsync(output.fileno())
    require(member_count == row['raw_member_bytes'] and member_sha.hexdigest() == row['raw_member_sha256']
            and identity(p['wrapper']) == before, 'raw chunk CRC/SHA/size or wrapper identity differs')
    return {'number': number, 'name': name, 'bytes': member_count, 'sha256': member_sha.hexdigest(),
            'identity': identity(target), 'crc_verified': True, 'wrapper_identity': before,
            'server_zip_bytes': row['size_in_bytes'], 'server_zip_sha256': row['digest'][7:]}


def api_transfer(row, consume):
    """New probe-owned transfer; fixed inputs and the existing pure URL policy."""
    aid = row['id']; require(type(aid) is int and aid in INPUT_IDS, 'unpinned input artifact')
    token = os.environ.get('GITHUB_TOKEN', ''); require(bool(token), 'missing ephemeral transfer credential')
    api = f'https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{aid}'
    def request(url):
        require(url in (api, api + '/zip'), 'authenticated destination differs')
        return urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
    try:
        opener = urllib.request.build_opener(recovery.NoRedirect())
        with opener.open(request(api), timeout=30) as response: raw = response.read(JSON_BYTES + 1)
        require(len(raw) <= JSON_BYTES, 'artifact metadata exceeds bound')
        metadata = recovery.metadata_identity(json.loads(raw, object_pairs_hook=bundle.unique_object),
            aid, row['name'], row['size_in_bytes'], row['digest'][7:], INPUT_RUN, INPUT_HEAD)
        try:
            with opener.open(request(api + '/zip'), timeout=30): raise ValueError('expected artifact redirect')
        except urllib.error.HTTPError as error:
            require(error.code == 302, 'unexpected artifact redirect status')
            location = error.headers.get('Location', '')
        host = recovery.artifact_destination(location)
        delivery = urllib.request.build_opener(recovery.NoRedirect())
        # This request has no Authorization header or inherited API opener.
        with delivery.open(urllib.request.Request(location, headers={'Accept':'application/octet-stream'}),
                           timeout=60) as response:
            require(response.status == 200, 'unexpected unauthenticated delivery status')
            verified = consume(response, metadata)
        return metadata, host, verified
    except BaseException as error:
        # Signed destinations and exception text are never retained or printed.
        raise RuntimeError('bounded retained-input transfer failed: ' + type(error).__name__) from None


def download():
    p, ctx = admitted(); outer(p, ctx, 'download-binding'); rows, _ = inputs(); chunks = []
    for number, row in enumerate(rows):
        capacity(p, sum(recovery.chunk_sizes()[number:]) + recovery.READBACK_BYTES + recovery.IMAGE_BYTES + INVENTORY_BYTES, 24)
        require(not os.path.lexists(p['wrapper']), 'previous wrapper remains allocated')
        def consume(response, metadata):
            digest, count = hashlib.sha256(), 0
            fd = os.open(p['wrapper'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as output:
                while data := response.read(min(1024 * 1024, row['size_in_bytes'] - count + 1)):
                    count += len(data); require(count <= row['size_in_bytes'], 'wrapper exceeds pinned size')
                    output.write(data); digest.update(data)
                output.flush(); os.fsync(output.fileno())
            require(count == row['size_in_bytes'] and digest.hexdigest() == row['digest'][7:], 'wrapper SHA/size differs')
            return decode_wrapper(p, row, number)
        metadata, host, item = api_transfer(row, consume)
        save(p['local'] / f'input-{number:02d}.json', {'status': 'PASS', 'run_context': ctx,
             'artifact': metadata, 'delivery_host': host, 'verified': item})
        require(identity(p['wrapper']) == item['wrapper_identity']
                and hash_regular(p['wrapper'], recovery.READBACK_BYTES) == item['server_zip_sha256'], 'wrapper changed before retirement')
        p['wrapper'].unlink(); chunks.append({k:item[k] for k in ('number','name','bytes','sha256','identity')})
    with recovery.ChunkReader(p['chunks'], chunks, recovery.ZIP_BYTES, recovery.ZIP_SHA) as reader:
        observation = recovery.archive_observation(reader, recovery.ZIP_BYTES)
    record = {'status': 'PASS', 'run_context': ctx, 'chunks': chunks,
              'original_zip_bytes': recovery.ZIP_BYTES, 'original_zip_sha256': recovery.ZIP_SHA}
    save(p['local'] / 'chunks.json', record); save(p['local'] / 'zip-observation.json', observation)
    return record


def extract():
    p, ctx = admitted(); outer(p, ctx, 'extract-binding')
    manifest = load(p['local'] / 'chunks.json'); require(manifest['run_context'] == ctx, 'chunk execution differs')
    capacity(p, recovery.IMAGE_BYTES + INVENTORY_BYTES, 8)
    digest, count = hashlib.sha256(), 0
    with recovery.ChunkReader(p['chunks'], manifest['chunks'], recovery.ZIP_BYTES, recovery.ZIP_SHA) as reader:
        archive, info = recovery.sole_zip(reader, recovery.ZIP_BYTES, recovery.IMAGE_NAME, recovery.IMAGE_BYTES)
        fd = os.open(p['image'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with archive, archive.open(info) as source, os.fdopen(fd, 'wb') as output:
            while data := source.read(1024 * 1024):
                count += len(data); require(count <= recovery.IMAGE_BYTES, 'image exceeds frozen size')
                output.write(data); digest.update(data)
            output.flush(); os.fsync(output.fileno())
    require(count == recovery.IMAGE_BYTES and digest.hexdigest() == recovery.IMAGE_SHA, 'image CRC/SHA/size differs')
    record = {'status': 'PASS', 'run_context': ctx, 'image_identity': identity(p['image']),
              'image_sha256': digest.hexdigest(), 'image_bytes': count, 'zip_crc_verified': True}
    save(p['local'] / 'extraction.json', record); return record


def candidate_observation(root, files):
    """Facts only: missing coverage never creates or authorizes analysis."""
    base = root / 'benchmarks'; candidates = []
    if not os.path.lexists(base):
        return {'status': 'OBSERVED', 'benchmark_directory': 'ABSENT', 'candidates': [], 'analysis': 'NOT_RUN'}
    require(stat.S_ISDIR(checked(base).st_mode) and checked(base).st_dev == checked(root).st_dev, 'unsafe benchmark directory')
    with os.scandir(base) as entries:
        names = []
        for entry in entries:
            require(len(names) < 128, 'benchmark directory observation bound exceeded')
            names.append(entry.name)
    for name in sorted(names):
        if not name.startswith('full-'): continue
        require(len(candidates) < 32 and len(name.encode()) <= 256, 'candidate observation bound exceeded')
        folder = base / name
        require(stat.S_ISDIR(checked(folder).st_mode) and checked(folder).st_dev == checked(root).st_dev, 'unsafe full directory')
        prefix = 'benchmarks/' + name + '/'
        selected = [path for path in files if path.startswith(prefix)]
        row = {'path': prefix[:-1], 'summary_files': sum(x.endswith('.summary.json') for x in selected),
               'sample_files': sum(x.endswith('.samples.jsonl.gz') for x in selected), 'metadata': {}}
        for filename in ('coverage.json', 'provenance.json'):
            path = folder / filename
            if not os.path.lexists(path): row['metadata'][filename] = {'state': 'ABSENT'}; continue
            info = checked(path, regular=True)
            item = {'state': 'PRESENT', 'bytes': info.st_size, 'sha256': hash_regular(path, recovery.IMAGE_BYTES)}
            if info.st_size > JSON_BYTES: item['parse'] = 'EXCEEDS_EXISTING_JSON_BOUND'
            else:
                try:
                    before = identity(path); raw = path.read_bytes()
                    require(identity(path) == before and len(raw) == info.st_size, 'candidate metadata changed')
                    value = json.loads(raw, object_pairs_hook=bundle.unique_object)
                    require(type(value) is dict, 'candidate JSON not object')
                    config = value.get('config', {})
                    selected = {'source': value.get('source'), 'profile': value.get('profile'),
                        'concurrency': config.get('concurrency') if type(config) is dict else None,
                        'expected_cells': value.get('expected_cells'), 'completed_cells': value.get('completed_cells'),
                        'status': value.get('status')}
                    item['parse'] = 'OBJECT'; item['invalid_fields'] = []
                    for key, field in selected.items():
                        valid = (field is None or type(field) is str and len(field.encode()) <= 128
                                 if key in ('source','profile','status') else
                                 field is None or type(field) is int and 0 <= field < 2**63)
                        item[key] = field if valid else None
                        if not valid: item['invalid_fields'].append(key)
                except (ValueError, TypeError, UnicodeDecodeError): item['parse'] = 'MALFORMED_JSON'
            row['metadata'][filename] = item
        candidates.append(row)
    return {'status': 'OBSERVED', 'benchmark_directory': 'PRESENT', 'candidates': candidates,
            'coverage_candidates': sum(x['metadata']['coverage.json']['state'] == 'PRESENT' for x in candidates),
            'analysis': 'NOT_RUN', 'coverage_synthesized': False}


def observe():
    p, ctx = admitted(); outer(p, ctx, 'observe-binding')
    proof = load(p['local'] / 'extraction.json')
    require(proof['run_context'] == ctx and identity(p['image']) == proof['image_identity']
            and hash_regular(p['image'], recovery.IMAGE_BYTES, recovery.IMAGE_BYTES) == recovery.IMAGE_SHA, 'exact image input required')
    external(INVENTORY_BYTES + 1_000_000)
    save(p['local'] / 'inner-pending.json', {'run_context': ctx, 'image_identity': identity(p['image'])})
    command(['sudo', '-n', 'mount', '-o', 'loop,ro,nodev,nosuid,noexec,noload', str(p['image']), str(p['mount'])], 'mount-original', 45)
    binding = mount_binding(p['image'], p['mount'], 'original-binding', True, recovery.IMAGE_BYTES)
    output = InventoryOutput(p['local'] / 'original-file-inventory.jsonl', INVENTORY_BYTES)
    inventory, files = recovery.walk_inventory(p['mount'], output)
    require(inventory['inventory_bytes'] <= INVENTORY_BYTES, 'full inventory exceeds explicit export reservation')
    candidates = candidate_observation(p['mount'], files)
    record = {'status': 'PASS' if inventory['complete'] else 'FAIL', 'run_context': ctx,
              'scope': SCOPE, 'binding': binding, 'inventory': inventory, 'observation': candidates,
              'scientific_qualification': False, 'analysis': 'NOT_RUN'}
    save(p['local'] / 'candidates.json', record); return record


def close_exact(image, mount, label, readonly, size):
    before = mount_binding(image, mount, label + '-before', readonly, size)
    command(['sudo', '-n', 'umount', '--', str(mount)], label, 60)
    raw, _, _ = command(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                         '--output', 'NAME,BACK-FILE'], label + '-absent')
    require(not os.path.ismount(mount) and json.loads(raw, object_pairs_hook=bundle.unique_object) == {'loopdevices': []}
            and backing_identity(image) == before['image_identity'], 'exact mount/loop closure failed')
    return {'status': 'PASS', 'before': before, 'mount_absent': True, 'loop_absent': True}


def cleanup():
    p, ctx = admitted(); record = {'status': 'PASS', 'run_context': ctx, 'failures': []}
    try:
        if os.path.ismount(p['mount']):
            pending = load(p['local'] / 'inner-pending.json')
            require(pending['run_context'] == ctx and pending['image_identity'] == identity(p['image']), 'unbound inner cleanup')
            record['inner'] = close_exact(p['image'], p['mount'], 'close-original', True, recovery.IMAGE_BYTES)
        if os.path.lexists(p['image']):
            record['image_sha256_after'] = hash_regular(p['image'], recovery.IMAGE_BYTES, recovery.IMAGE_BYTES)
            require(record['image_sha256_after'] == recovery.IMAGE_SHA, 'original image changed')
    except BaseException as error: record['failures'].append({'phase': 'inner', 'error_type': type(error).__name__})
    try:
        if os.path.ismount(p['volume']):
            try:
                outer(p, ctx, 'cleanup-binding')
            except FileNotFoundError:
                require(not os.path.lexists(p['local'] / 'quota.json'),
                        'an existing quota proof must not be bypassed')
                allocation = load(p['local'] / 'allocation.json')
                pending = load(p['local'] / 'mount-pending.json')
                require(allocation['run_context'] == pending['run_context'] == ctx
                        and allocation['image_path'] == pending['image_path'] == str(p['outer'])
                        and pending['mount_path'] == str(p['volume'])
                        and allocation['image_identity'] == pending['image_identity'] == backing_identity(p['outer']),
                        'partial quota allocation or mount intent differs')
                record['partial_quota_cleanup'] = True
                record['hard_quota_enforced'] = False
            record['outer'] = close_exact(p['outer'], p['volume'], 'close-outer', False, OUTER_BYTES)
        elif os.path.lexists(p['outer']):
            allocation = load(p['local'] / 'allocation.json')
            require(allocation['run_context'] == ctx and allocation['image_path'] == str(p['outer'])
                    and allocation['image_identity'] == backing_identity(p['outer']), 'unidentified unmounted outer')
            raw, _, _ = command(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(p['outer']),
                                 '--output', 'NAME,BACK-FILE'], 'unmounted-outer')
            require(json.loads(raw, object_pairs_hook=bundle.unique_object) == {'loopdevices': []}, 'outer loop still active')
            record['outer'] = {'state': 'OWNED_UNMOUNTED_RETAINED', 'hard_quota_enforced': False}
    except BaseException as error: record['failures'].append({'phase': 'outer', 'error_type': type(error).__name__})
    record.update(status='FAIL' if record['failures'] else 'PASS', owned_data_retained_until_runner_termination=True)
    save(p['local'] / 'cleanup.json', record); return record


def export():
    """Manifest direct original evidence; no convenience projection drops inventory."""
    p, ctx = admitted(); records = []; total = 0
    for folder, dirs, names in os.walk(p['local'], followlinks=False):
        for name in sorted(names):
            path = Path(folder) / name
            # Export is last: do not describe its still-open captures as final.
            if name in ('parent-export.stdout', 'parent-export.stderr', 'active-export.json'): continue
            info = checked(path, regular=True)
            limit = INVENTORY_BYTES if name == 'original-file-inventory.jsonl' else JSON_BYTES
            require(info.st_size <= limit, 'direct evidence file producer bound exceeded')
            total += info.st_size; require(total + 200_000 <= CLOUD_BYTES - 1_000_000, 'complete direct metadata export refused')
            records.append({'path': path.relative_to(p['local']).as_posix(), 'bytes': info.st_size,
                            'sha256': hash_regular(path, limit)})
    record = {'status': 'PASS', 'run_context': ctx, 'scope': SCOPE, 'files': records,
              'selected_bytes': total, 'scientific_qualification': False,
              'unfinished_export_self_receipts_excluded': True, 'no_scientific_data_upload': True}
    save(p['local'] / 'export.json', record); return record


ACTIONS = {name: globals()[name] for name in STAGES}


def stage_parent(action):
    p, ctx = paths(), context()
    if action not in ('plan', 'cleanup', 'export'):
        for stage in list(STAGES)[:list(STAGES).index(action)]: require_stage(p, ctx, stage)
    elapsed = time.time() - ctx['started_epoch']
    tail = sum(list(STAGES.values())[list(STAGES).index(action):])
    require(0 <= elapsed and elapsed + tail <= JOB_SECONDS, 'whole-job time admission refused')
    nonce = uuid.uuid4().hex; parent = supervisor.process_identity(os.getpid())
    env = dict(os.environ); env['FQ_PROBE_PARENT_NONCE'] = nonce
    if action != 'download': env.pop('GITHUB_TOKEN', None)
    def launched(worker):
        save(p['local'] / ('active-' + action + '.json'), {'action': action, 'run_context': ctx,
             'parent_identity': parent, 'worker_identity': worker, 'nonce': nonce})
    observed = supervisor.run_owned([sys.executable, '-B', str(Path(__file__)), '_worker', action],
        p['local'] / ('parent-' + action + '.stdout'), p['local'] / ('parent-' + action + '.stderr'),
        started=STARTED, total_seconds=STAGES[action] - 4, cleanup_seconds=8, receipt_seconds=2,
        capture_bytes=32768, environ=env, launched=launched, startup_gate=True)
    record = {'status': observed['status'], 'action': action, 'run_context': ctx, 'nonce': nonce,
              'parent_identity': parent, 'supervision': observed, 'scope': SCOPE}
    save(p['local'] / ('parent-' + action + '.json'), record)
    require(record['status'] == 'PASS', 'supervised probe stage failed')
    if action == 'export':
        # The export worker has stopped. Seal every actual file including its
        # final parent/child captures without claiming to hash this manifest itself.
        sealed, total = [], 0
        for folder, dirs, names in os.walk(p['local'], followlinks=False):
            for name in sorted(names):
                path = Path(folder) / name; info = checked(path, regular=True)
                limit = INVENTORY_BYTES if name == 'original-file-inventory.jsonl' else JSON_BYTES
                total += info.st_size
                require(info.st_size <= limit and total + 200_000 <= CLOUD_BYTES - 1_000_000,
                        'complete final metadata seal refused')
                sealed.append({'path': path.relative_to(p['local']).as_posix(), 'bytes': info.st_size,
                               'sha256': hash_regular(path, limit)})
        manifest = {'status': 'PASS', 'run_context': ctx, 'files': sealed,
                    'scope': SCOPE, 'selected_bytes': total, 'scientific_qualification': False}
        manifest_bytes = len((json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode())
        require(len(sealed) <= 4096 and manifest_bytes <= JSON_BYTES
                and total + manifest_bytes + 1_000_000 <= CLOUD_BYTES
                and source_hash() == ctx['source'], 'final complete cloud metadata admission refused')
        save(p['local'] / 'manifest.json', manifest)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=(*STAGES, '_worker')); parser.add_argument('child', nargs='?')
    args = parser.parse_args(); action = args.child if args.action == '_worker' else args.action
    require(sys.platform == 'linux' and os.getuid() > 0 and action in ACTIONS, 'ordinary explicit Linux action required')
    ensure_local()
    try:
        if args.action == '_worker':
            supervisor.await_startup_gate(); p, ctx = paths(), context()
            proof = load(p['local'] / ('active-' + action + '.json')); current = supervisor.process_identity(os.getpid())
            require(proof['action'] == action and proof['run_context'] == ctx
                    and proof['nonce'] == os.environ.get('FQ_PROBE_PARENT_NONCE')
                    and proof['parent_identity']['pid'] == os.getppid() and supervisor.same_process(proof['parent_identity'])
                    and proof['worker_identity']['pid'] == current['pid']
                    and proof['worker_identity']['start_time_ticks'] == current['start_time_ticks'], 'worker/parent/startup binding differs')
            result = ACTIONS[action]()
        else:
            require(args.child is None, 'unexpected child action')
            with fs.whole_entry(STAGES[action], started=STARTED): result = stage_parent(action)
        print(json.dumps({'status': result['status'], 'action': action, 'scope': SCOPE}))
        if action == 'export' and args.action != '_worker' and os.environ.get('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output: output.write('metadata_allowed=true\n')
        return 0 if result['status'] == 'PASS' else 1
    except BaseException as error:
        failure = {'status': 'FAIL', 'action': action, 'error_type': type(error).__name__,
                   'scope': SCOPE, 'scientific_qualification': False}
        try: save(paths()['local'] / ('failure-' + action + '-' + uuid.uuid4().hex[:8] + '.json'), failure)
        except BaseException: pass
        print(json.dumps(failure)); return 1


if __name__ == '__main__': raise SystemExit(main())
