"""Fixed run38 inputs -> readonly metadata. No benchmark, analyzer or data upload.

Each action runs under an independent bounded parent. This is a new admission
contract; it never selects or bypasses the original recovery stage guards.
"""
from __future__ import annotations
import argparse
import gzip
import reversible_samples
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

PROFILE = 'run38-derived-storage-readonly-v1'
SCOPE = 'Readonly reversible byte-equivalence storage measurement only; originals retained; no scientific qualification.'
REPOSITORY = recovery.REPOSITORY
REPOSITORY_ID = recovery.REPOSITORY_ID
INPUT_RUN = 42160839625
INPUT_HEAD = '151942996d7dcb553d51eefbb68cca8b94c8f14f'
INPUT_IDS = (13476667063, 13477265192, 13477260207, 13476976782,
             13477165803, 13477270301, 13477145872, 13475944893)
OUTER_BYTES = 2_100_000_000
PROBE_BYTES = 2_200_000_000
EXTERNAL_BYTES = 50_000_000
# A stage parent and its nested command supervisor may each hold unread capture
# bytes. Reserve their complete caps and allocation rounding inside the same
# external ceiling, even before those bytes appear in filesystem metadata.
PENDING_CAPTURE_BYTES = 131_072
CLOUD_BYTES = 50_000_000
OVERHEAD = 50_000_000
GROWTH = OUTER_BYTES + EXTERNAL_BYTES + CLOUD_BYTES + OVERHEAD
CEILING = 12_000_000_000
INVENTORY_BYTES = 8_000_000
JSON_BYTES = 2_000_000
STAGES = {'plan': 45, 'quota': 180, 'download': 480, 'extract': 300,
          'observe': 240, 'derive': 1200, 'cleanup': 180, 'export': 120}
JOB_SECONDS = 3600
JOB_TAIL_SECONDS = 180
DERIVE_OUTPUT_BYTES = 45_000_000
EXPECTED_PAIRS = 4407
MAX_CANDIDATES = 6000
CANDIDATE = 'benchmarks/full-e9d3f6146991-f80208448535'
HISTORICAL_SOURCE = 'e9d3f61469917718bb04f29784f8f08343d5a7eba176a0aa3b017b856bdc2fe3'
PURE_MODULE_SHA256 = '509811c00a36af767bf3efba49054256b730f1f324fb406431948d94b2216fc2'
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
    volume = parent / 'facetquarry-derived-storage-probe'
    return {'outer': parent / 'facetquarry-derived-storage-probe.img', 'volume': volume,
            'chunks': volume / 'chunks', 'wrapper': volume / 'wrapper.zip',
            'image': volume / recovery.IMAGE_NAME, 'mount': volume / 'readonly-original',
            'local': ROOT / '.local/derived-storage-probe'}


def external(extra=0):
    require(type(extra) is int and extra >= 0, 'invalid control reservation')
    require(extra + PENDING_CAPTURE_BYTES <= EXTERNAL_BYTES, 'pending capture reservation refused')
    total, count, pending = 0, 0, [paths()['local']]
    while pending:
        path = pending.pop()
        if not os.path.lexists(path): continue
        info = checked(path); count += 1
        require(count <= 4096 and info.st_uid == os.getuid(), 'external ownership/entry bound')
        total += max(info.st_size, info.st_blocks * 512)
        require(total + extra + PENDING_CAPTURE_BYTES <= EXTERNAL_BYTES, 'external evidence allocation refused')
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as entries:
                for entry in entries:
                    require(count + len(pending) < 4096, 'pending external entry bound')
                    pending.append(path / entry.name)
    return total + PENDING_CAPTURE_BYTES


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
    parent = supervisor.process_identity(os.getpid())
    env = worker_environment(); env['LC_ALL'] = 'C'
    observed = supervisor.run_owned(actual, prefix.with_suffix('.stdout'), prefix.with_suffix('.stderr'),
        started=time.monotonic(), total_seconds=seconds, cleanup_seconds=8, receipt_seconds=2,
        capture_bytes=32768, environ=env)
    complete = (observed.get('capture_complete') is True and observed.get('discarded_output_bytes') == 0
        and observed.get('descendant_quiescence', {}).get('quiescent') is True
        and observed.get('descendant_quiescence', {}).get('residual') == []
        and observed.get('termination_reason') is None and observed.get('errors') == [])
    record = {'command_id': prefix.name, 'parent_identity': parent,
              'runtime_hint': runtime_hint(),
              'requested_command': argv, 'actual_command': actual, 'supervision': observed,
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
            and os.environ.get('FQ_DERIVED_STORAGE_PROBE') == 'true'
            and os.environ.get('FQ_RETAINED_IMAGE_PROBE', 'false') != 'true'
            and os.environ.get('FQ_RESERVATION_PROFILE') == PROFILE
            and Path(os.environ['GITHUB_WORKSPACE']) == ROOT, 'unauthorized metadata probe runtime')
    run, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(all(re.fullmatch('[1-9][0-9]{0,19}', v) for v in (run, attempt)), 'actual run identities required')
    raw, _, _ = command(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], 'context-head')
    commit = raw.decode().strip()
    raw, _, _ = command(['git', '-C', str(ROOT), 'status', '--porcelain', '--untracked-files=normal'], 'context-clean')
    require(re.fullmatch('[0-9a-f]{40}', commit) and commit == os.environ.get('GITHUB_SHA') and raw == b'',
            'probe source must be exact clean checkout')
    epoch = os.environ.get('FQ_DERIVED_STARTED_EPOCH', '')
    require(re.fullmatch('[1-9][0-9]{9,12}', epoch), 'observed job-start clock required')
    return {'profile': PROFILE, 'repository': REPOSITORY, 'repository_id': REPOSITORY_ID,
            'job': 'codec', 'commit': commit, 'source': source_hash(),
            'github_run_id': run, 'github_run_attempt': attempt, 'started_epoch': int(epoch)}


def file_limit(name):
    if name in ('derived-recipes.jsonl.gz', 'derived-ledger.jsonl'):
        return DERIVE_OUTPUT_BYTES
    return INVENTORY_BYTES if name == 'original-file-inventory.jsonl' else JSON_BYTES


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


def worker_environment(*, download=False):
    """Only declared runtime data reaches payloads; API authority is task-local."""
    allowed = {'PATH','HOME','USER','LOGNAME','SHELL','LANG','LC_ALL','LC_CTYPE',
        'TMPDIR','TMP','TEMP','PYTHONDONTWRITEBYTECODE','GOTOOLCHAIN','RUNNER_TEMP',
        'GITHUB_ACTIONS','GITHUB_REPOSITORY','GITHUB_REPOSITORY_ID','GITHUB_RUN_ID',
        'GITHUB_RUN_ATTEMPT','GITHUB_SHA','GITHUB_JOB','GITHUB_WORKSPACE',
        'FQ_DERIVED_STORAGE_PROBE','FQ_RETAINED_IMAGE_PROBE','FQ_RESERVATION_PROFILE',
        'FQ_ACCOUNTED_BASE_BYTES','FQ_DERIVED_STARTED_EPOCH'}
    env = {key:value for key,value in os.environ.items() if key in allowed}
    if download and 'GITHUB_TOKEN' in os.environ: env['GITHUB_TOKEN'] = os.environ['GITHUB_TOKEN']
    return env


def runtime_hint(ctx=None):
    if ctx is not None:
        return {key:ctx[key] for key in ('repository','repository_id','profile','commit','github_run_id','github_run_attempt')}
    return {'repository':REPOSITORY,'repository_id':REPOSITORY_ID,'profile':PROFILE,
        'commit':os.environ.get('GITHUB_SHA'),'github_run_id':os.environ.get('GITHUB_RUN_ID'),
        'github_run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT')}


def load_stage_control(path):
    if sys.platform == 'linux': return load(path)  # Keep actual runtime UID ownership checks.
    require(sys.platform == 'win32', 'metadata-only fixture reader unavailable')
    # No Windows execution/mount/process authority is granted. Main/context and
    # the actual supervisor remain Linux-only; this branch reads bounded bytes.
    return json.loads(read_original(path.parent, path.name, JSON_BYTES), object_pairs_hook=bundle.unique_object)


def process_closed(value, *, allow_current=False):
    require(type(value) is dict and all(type(value.get(key)) is int and value[key] > 0
            for key in ('pid','ppid','start_time_ticks')), 'closed process identity required')
    if supervisor.same_process(value):
        require(allow_current and value['pid'] == os.getpid()
                and value == supervisor.process_identity(os.getpid()), 'producer process is still live')


def terminal_capture(supervision, parent, prefix, *, allow_current_parent=False):
    require(type(supervision) is dict and supervision.get('status') in ('PASS','FAIL')
            and type(supervision.get('worker_started')) is bool
            and type(supervision.get('capture_complete')) is bool
            and type(supervision.get('discarded_output_bytes')) is int
            and supervision['discarded_output_bytes'] >= 0
            and type(supervision.get('descendant_quiescence')) is dict
            and supervision['descendant_quiescence'].get('quiescent') is True
            and supervision.get('descendant_quiescence', {}).get('residual') == [], 'terminal quiescent producer required')
    code, reason, errors = (supervision.get(key) for key in ('worker_exit_code','termination_reason','errors'))
    require((reason is None or type(reason) is str and 1 <= len(reason) <= 256)
            and type(errors) is list and len(errors) <= 128
            and all(type(error) is str and len(error) <= 1000 for error in errors),
            'terminal error/reason types differ')
    process_closed(parent, allow_current=allow_current_parent)
    if supervision['worker_started']:
        require(type(code) is int and -(2**31) <= code < 2**31, 'terminal integer worker exit required')
        worker = supervision.get('worker_identity')
        process_closed(worker)
        require(worker['ppid'] == parent['pid'] and worker['pid'] != parent['pid'], 'producer parent binding differs')
    else:
        require(supervision.get('worker_identity') is None and code is None
                and supervision['status'] == 'FAIL', 'unstarted worker cannot succeed')
    captures = supervision.get('capture')
    require(type(captures) is dict and set(captures) == {'stdout','stderr'}, 'closed capture set differs')
    total = 0
    for label in ('stdout','stderr'):
        path = prefix.with_suffix('.' + label); info = checked(path, regular=True)
        require(info.st_nlink == 1 and info.st_size <= 32768
                and captures[label] == {'path':str(path),'bytes':info.st_size,'sha256':hash_regular(path,32768)},
                'closed capture bytes changed')
        total += info.st_size
    require(type(supervision.get('captured_output_bytes')) is int
            and total == supervision['captured_output_bytes'] and total <= 32768, 'closed capture total differs')
    if supervision['capture_complete']: require(supervision['discarded_output_bytes'] == 0, 'complete capture discarded bytes')
    if supervision['status'] == 'PASS':
        require(supervision['worker_started'] and supervision.get('worker_exit_code') == 0
                and supervision['capture_complete'] and supervision.get('termination_reason') is None
                and supervision.get('errors') == [], 'successful producer proof incomplete')
    success = (supervision['worker_started'] and code == 0 and reason is None
               and supervision['capture_complete'] and not errors)
    require(supervision['status'] == ('PASS' if success else 'FAIL'), 'terminal supervisor status differs')


def stage_payload_markers(p, stage):
    local = p['local']
    names = {'plan':['plan.json'],'quota':['allocation.json','mount-pending.json','quota.json'],
        'download':['download.json'],'extract':['extraction.json'],
        'observe':['inner-pending.json','candidates.json','original-file-inventory.jsonl'],
        'derive':['derivation.json','derived-recipes.jsonl.gz','derived-ledger.jsonl'],
        'cleanup':['cleanup.json'],'export':['export.json','manifest.json']}[stage]
    outside = {'quota':['outer','volume'],'download':['wrapper'],'extract':['image']}
    markers = [local/name for name in names] + [p[key] for key in outside.get(stage,[]) if key in p]
    # Quota precreates these staging directories. Empty, unmounted slots do not
    # prove a later producer started. Nonempty or mounted slots still refuse
    # closure without that stage's terminal receipt, including unknown files.
    slot = p.get({'download':'chunks','observe':'mount'}.get(stage))
    if slot is not None and os.path.lexists(slot):
        require(stat.S_ISDIR(checked(slot).st_mode), 'staging directory changed type')
        if os.path.ismount(slot): markers.append(slot)
        else:
            with os.scandir(slot) as entries:
                if next(entries,None) is not None: markers.append(slot)
    return markers


def require_closed_stage(p, ctx, stage, *, require_success=False, allow_current_parent=False):
    require(stage in STAGES and type(require_success) is bool, 'unknown closed stage')
    prefix = p['local'] / ('parent-' + stage)
    parent_file = prefix.with_suffix('.json'); active_file = p['local'] / ('active-' + stage + '.json')
    evidence = [parent_file, active_file, prefix.with_suffix('.stdout'), prefix.with_suffix('.stderr')]
    if not any(os.path.lexists(path) for path in evidence):
        require(not any(os.path.lexists(path) for path in stage_payload_markers(p,stage)) and not require_success,
                'stage payload exists without terminal supervision')
        return None
    require(os.path.lexists(parent_file), 'launched producer has no terminal receipt')
    record = load_stage_control(parent_file)
    require(type(record) is dict and record.get('action') == stage and record.get('run_context') == ctx
            and record.get('status') in ('PASS','FAIL') and type(record.get('nonce')) is str
            and re.fullmatch('[0-9a-f]{32}',record['nonce']), 'terminal stage context/nonce differs')
    s = record.get('supervision'); require(type(s) is dict, 'terminal supervision missing')
    if s.get('worker_started'):
        active = load_stage_control(active_file)
        require(type(active) is dict and active.get('action') == stage and active.get('run_context') == ctx
            and active.get('nonce') == record['nonce'] and active.get('parent_identity') == record.get('parent_identity')
            and active.get('worker_identity') == s.get('worker_identity')
            and s.get('startup_gate_released_after_durable_publication') is True, 'closed stage startup binding differs')
    else:
        require(not os.path.lexists(active_file), 'unstarted worker has ambiguous active proof')
    terminal_capture(s, record.get('parent_identity'), prefix, allow_current_parent=allow_current_parent)
    if require_success or record['status'] == 'PASS':
        require(record['status'] == s['status'] == 'PASS' and s.get('startup_gate_released_after_durable_publication') is True,
                'successful closed stage required')
    return record


def require_stage(p, ctx, stage):
    return require_closed_stage(p, ctx, stage, require_success=True)


def require_closed_commands(p, ctx):
    folder = p['local'] / 'commands'
    if not os.path.lexists(folder): return []
    require(stat.S_ISDIR(checked(folder).st_mode), 'command evidence directory differs')
    groups = {}
    for path in sorted(folder.iterdir()):
        checked(path, regular=True)
        match = re.fullmatch('([a-z0-9-]{1,70}-[0-9a-f]{12})\\.(json|stdout|stderr)', path.name)
        require(match is not None, 'unknown command evidence member')
        groups.setdefault(match[1],set()).add(match[2])
        require(len(groups) <= 1024, 'command closure inventory bound')
    records = []
    for name, parts in groups.items():
        require(parts == {'json','stdout','stderr'}, 'command capture lacks complete terminal receipt')
        record = load_stage_control(folder/(name+'.json'))
        require(type(record) is dict and record.get('command_id') == name and record.get('runtime_hint') == runtime_hint(ctx),
                'command source/run identity differs')
        terminal_capture(record.get('supervision'),record.get('parent_identity'),folder/name,allow_current_parent=True)
        accepted = record.get('accepted_exit_codes'); s = record['supervision']
        require(type(accepted) is list and 1 <= len(accepted) <= 16
                and all(type(code) is int and -(2**31) <= code < 2**31 for code in accepted)
                and len(set(accepted)) == len(accepted), 'explicit accepted command exits required')
        success = (s['worker_started'] and s['worker_exit_code'] in accepted
                   and s['capture_complete'] and s['discarded_output_bytes'] == 0
                   and s['termination_reason'] is None and s['errors'] == [])
        require(record.get('status') == ('PASS' if success else 'FAIL'), 'command acceptance status differs')
        records.append(record)
    return records


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


def confined(root, relative):
    require(type(relative) is str and 0 < len(relative.encode()) <= 2048
            and '\\' not in relative and not relative.startswith('/')
            and all(part not in ('', '.', '..') for part in relative.split('/')),
            'noncanonical original relative path')
    return root.joinpath(*PurePosixPath(relative).parts)


def read_original(root, relative, maximum, expected=None):
    path = confined(root, relative); device = checked(root).st_dev
    current = root
    for part in PurePosixPath(relative).parts[:-1]:
        current = current / part; info = checked(current)
        require(stat.S_ISDIR(info.st_mode) and info.st_dev == device, 'original parent escape')
    info = checked(path, regular=True); before = identity(path)
    require(info.st_nlink == 1 and info.st_dev == device and info.st_size <= maximum,
            'original regular byte/link/device bound')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        require(bundle.descriptor_matches(os.fstat(stream.fileno()), tuple(before)), 'original descriptor differs')
        raw = stream.read(maximum + 1)
        require(len(raw) == info.st_size and identity(path) == before
                and bundle.descriptor_matches(os.fstat(stream.fileno()), tuple(before)), 'original changed during read')
    if expected is not None:
        require(expected.get('type') == 'regular' and expected.get('bytes') == len(raw)
                and expected.get('sha256') == hashlib.sha256(raw).hexdigest(), 'original inventory binding differs')
    return raw


def select_candidates(inventory):
    paths_seen, samples, summaries, full = set(), set(), set(), set()
    for row in inventory:
        name = row['path']
        require(name not in paths_seen, 'duplicate inventory path'); paths_seen.add(name)
        parts = PurePosixPath(name).parts
        if len(parts) >= 2 and parts[0] == 'benchmarks' and parts[1].startswith('full-'):
            full.add('/'.join(parts[:2]))
        if not name.startswith(CANDIDATE + '/') or row['type'] != 'regular': continue
        relative = name[len(CANDIDATE) + 1:]
        if '/' in relative: continue
        if relative.endswith('.samples.jsonl.gz'):
            cell = relative[:-len('.samples.jsonl.gz')]
            require(re.fullmatch('[0-9a-f]{20}', cell), 'invalid sample cell identity'); samples.add(cell)
        elif relative.endswith('.summary.json'):
            cell = relative[:-len('.summary.json')]
            require(re.fullmatch('[0-9a-f]{20}', cell), 'invalid summary cell identity'); summaries.add(cell)
    require(full == {CANDIDATE} and samples == summaries and len(samples) == EXPECTED_PAIRS
            and len(samples) <= MAX_CANDIDATES and CANDIDATE + '/coverage.json' not in paths_seen,
            'fixed historical candidate/pair/coverage observation differs')
    return sorted(samples)


def select_attempt(summary):
    require(type(summary) is dict and summary.get('source') == HISTORICAL_SOURCE
            and summary.get('stage') == 'measurement', 'original measurement source/stage differs')
    attempts = summary.get('attempts')
    require(type(attempts) is list and len(attempts) <= 16, 'bounded original attempts required')
    selected = [x for x in attempts if type(x) is dict and x.get('stage') == 'measurement']
    require(len(selected) == 1, 'exactly one original measurement attempt required')
    attempt = selected[0]
    require(type(attempt.get('attempt_id')) is str and re.fullmatch('[0-9]{1,30}-[0-9a-f]{8}', attempt['attempt_id'])
            and attempt.get('status') in ('PASS', 'FAIL'), 'original attempt identity/status differs')
    return attempt


def validate_stream(stream, attempt_id, label):
    require(type(stream) is dict and stream.get('path') == f'attempts/{attempt_id}/{label}.txt.gz'
            and type(stream.get('raw_bytes')) is int and 0 <= stream['raw_bytes'] <= reversible_samples.MAX_DECODED_BYTES
            and all(type(stream.get(key)) is str and re.fullmatch('[0-9a-f]{64}', stream[key])
                    for key in ('sha256', 'raw_sha256')), 'original stream metadata/path/bound differs')
    return stream


class BoundedOutput:
    """New output writes are admitted physically before every write; partials stay."""
    def __init__(self, path, maximum, shared=None):
        self.path, self.maximum, self.shared = path, maximum, shared

    @contextlib.contextmanager
    def open(self, mode):
        require(mode == 'xb', 'new bounded output required')
        checked(self.path.parent)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb', buffering=0) as stream:
            class Writer:
                written = 0
                def write(inner, raw):
                    require(type(raw) is bytes and inner.written + len(raw) <= self.maximum,
                            'derived output ceiling refused before write')
                    if self.shared is not None:
                        require(self.shared['written'] + len(raw) <= DERIVE_OUTPUT_BYTES,
                                'combined derived output ceiling refused before write')
                    external(len(raw) + 8192)
                    count = stream.write(raw); require(count == len(raw), 'short derived output write')
                    inner.written += count
                    if self.shared is not None: self.shared['written'] += count
                    return count
                def flush(inner): return stream.flush()
                def fileno(inner): return stream.fileno()
            yield Writer()
            stream.flush(); os.fsync(stream.fileno())


def cost_record(*, original_bytes, recipe_bytes, ledger_bytes, retained_metadata_bytes, identity_bytes, raw_attempt_bytes):
    values = (original_bytes, recipe_bytes, ledger_bytes, retained_metadata_bytes, identity_bytes, raw_attempt_bytes)
    require(all(type(x) is int and x >= 0 for x in values), 'nonnegative actual byte costs required')
    return {'original_file_bytes': original_bytes, 'encoded_recipe_gzip_bytes': recipe_bytes,
            'complete_perpath_ledger_bytes': ledger_bytes, 'retained_control_metadata_bytes': retained_metadata_bytes,
            'identity_retained_original_bytes': identity_bytes, 'raw_attempt_bytes_in_identity': raw_attempt_bytes,
            'encoded_representation_bytes': recipe_bytes + ledger_bytes + retained_metadata_bytes + identity_bytes + raw_attempt_bytes,
            'originals_retired_bytes': 0, 'scientific_qualification': False,
            'scope': 'Measured reversible representation cost only; every original remains retained in eight input keepers.'}


def derive_cell(root, cell, files):
    sample_name = CANDIDATE + '/' + cell + '.samples.jsonl.gz'
    record = {'path': sample_name, 'original_bytes': files[sample_name]['bytes'],
              'original_sha256': files[sample_name]['sha256'], 'mode': 'refused'}
    try:
        summary_name = CANDIDATE + '/' + cell + '.summary.json'
        summary_raw = read_original(root, summary_name, JSON_BYTES, files[summary_name])
        summary = json.loads(summary_raw, object_pairs_hook=bundle.unique_object)
        require(type(summary) is dict and type(summary.get('cell')) is dict
                and hashlib.sha256(json.dumps(summary['cell'], sort_keys=True).encode()).hexdigest()[:20] == cell,
                'original cell identity differs from path')
        attempt = select_attempt(summary); aid = attempt['attempt_id']
        original_name = CANDIDATE + '/attempts/' + aid + '/attempt.json'
        original_raw = read_original(root, original_name, JSON_BYTES, files[original_name])
        require(json.loads(original_raw, object_pairs_hook=bundle.unique_object) == attempt, 'summary/standalone original attempt differs')
        streams = attempt.get('streams'); require(type(streams) is dict and set(streams) == {'stdout', 'stderr'}, 'both raw streams retained')
        for label in ('stdout', 'stderr'):
            stream = validate_stream(streams[label], aid, label)
            relative = CANDIDATE + '/' + stream['path']
            compressed = read_original(root, relative, reversible_samples.MAX_COMPRESSED_BYTES, files[relative])
            require(hashlib.sha256(compressed).hexdigest() == stream['sha256'], 'original compressed stream hash differs')
            # The pure module verifies the identical bounded gzip/raw binding for
            # each stream. No original stderr or malformed raw bytes are dropped.
            reversible_samples._checked_stdout(compressed, stream['sha256'], stream['raw_sha256'], stream['raw_bytes'])
        stdout = read_original(root, CANDIDATE + '/' + streams['stdout']['path'], reversible_samples.MAX_COMPRESSED_BYTES,
                               files[CANDIDATE + '/' + streams['stdout']['path']])
        original = read_original(root, sample_name, reversible_samples.MAX_COMPRESSED_BYTES, files[sample_name])
        require(summary.get('samples_sha256') == record['original_sha256'], 'original summary sample hash differs')
        s = streams['stdout']
        proposal = reversible_samples.propose(original_samples_gzip=original, stdout_gzip=stdout,
            expected_samples_sha256=summary['samples_sha256'], expected_stdout_gzip_sha256=s['sha256'],
            expected_stdout_raw_sha256=s['raw_sha256'], expected_stdout_raw_bytes=s['raw_bytes'],
            source_id=summary['source'], attempt_status=attempt['status'])
        record.update(mode=proposal.mode, reason=proposal.reason, original_measurement_attempt=attempt,
                      summary_path=summary_name, attempt_path=original_name)
        if proposal.mode == 'derived':
            rebuilt = reversible_samples.reconstruct(recipe=proposal.recipe, stdout_gzip=stdout,
                expected_samples_sha256=record['original_sha256'], expected_samples_bytes=record['original_bytes'],
                expected_stdout_gzip_sha256=s['sha256'], expected_stdout_raw_sha256=s['raw_sha256'],
                expected_stdout_raw_bytes=s['raw_bytes'], expected_source_id=summary['source'])
            require(rebuilt == original and len(rebuilt) == record['original_bytes']
                    and hashlib.sha256(rebuilt).hexdigest() == record['original_sha256'], 'complete original compressed byte equivalence differs')
            return record, json.loads(proposal.recipe)
        return record, None
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, RecursionError) as error:
        record.update(mode='refused', reason_type=type(error).__name__, original_retained=True)
        return record, None


def derive():
    p, ctx = admitted(); outer(p, ctx, 'derive-outer-binding')
    observed = load(p['local'] / 'candidates.json')
    require(observed.get('run_context') == ctx and observed.get('status') == 'PASS'
            and observed.get('inventory', {}).get('complete') is True, 'complete original readonly inventory required')
    require(mount_binding(p['image'], p['mount'], 'derive-original-binding', True, recovery.IMAGE_BYTES) == observed['binding'], 'original mount binding changed')
    # These actual Linux controls include two simultaneous near-ceiling file
    # streams. Their owned captures are retained in this same external budget;
    # the existing 1200-second derive deadline includes this work.
    command([sys.executable, '-B', str(ROOT / 'scripts/derived_storage_controls.py'), '--actual-linux'],
            'actual-linux-storage-controls', 90)
    image_before = hash_regular(p['image'], recovery.IMAGE_BYTES, recovery.IMAGE_BYTES)
    require(image_before == recovery.IMAGE_SHA, 'original image SHA before derivation differs')
    require(hash_regular(Path(reversible_samples.__file__), JSON_BYTES) == PURE_MODULE_SHA256, 'reviewed pure codec source differs')
    inventory_path = p['local'] / 'original-file-inventory.jsonl'
    require(hash_regular(inventory_path, INVENTORY_BYTES) == observed['inventory']['inventory_sha256'], 'inventory SHA differs')
    raw = inventory_path.read_bytes(); require(len(raw) <= INVENTORY_BYTES, 'bounded original inventory required')
    inventory = [json.loads(line, object_pairs_hook=bundle.unique_object) for line in raw.splitlines()]
    cells = select_candidates(inventory)
    files = {row['path']: row for row in inventory if row['type'] == 'regular'}
    mappings, counts = {}, {'derived': 0, 'identity': 0, 'refused': 0}
    recipe_path, ledger_path = p['local'] / 'derived-recipes.jsonl.gz', p['local'] / 'derived-ledger.jsonl'
    external(1_000_000)
    # All files remain until runner termination, including an interrupted gzip
    # and a partial ledger; failure receipts and final export disclose them.
    shared = {'written': 0}
    with BoundedOutput(recipe_path, DERIVE_OUTPUT_BYTES, shared).open('xb') as encoded:
        with gzip.GzipFile(fileobj=encoded, filename='', mode='wb', mtime=0) as recipes:
            with BoundedOutput(ledger_path, DERIVE_OUTPUT_BYTES, shared).open('xb') as ledger:
                for number, cell in enumerate(cells):
                    record, recipe = derive_cell(p['mount'], cell, files)
                    counts[record['mode']] += 1
                    if recipe is not None:
                        line = (json.dumps({'path': record['path'], 'recipe': recipe}, sort_keys=True, separators=(',', ':')) + '\n').encode()
                        require(len(line) <= reversible_samples.MAX_RECIPE_BYTES + 4096, 'bounded flat recipe line required')
                        recipes.write(line)
                        record['recipe_line'] = counts['derived'] - 1
                    mappings[record['path']] = record
                for row in inventory:
                    name = row['path']
                    entry = {'original': row, 'retention': 'ORIGINAL_UNCHANGED_IN_EIGHT_KEEPERS',
                             'mapping': mappings.get(name, {'mode': 'identity'})}
                    raw = (json.dumps(entry, sort_keys=True, separators=(',', ':')) + '\n').encode()
                    ledger.write(raw)
    require(sum(counts.values()) == len(cells) == EXPECTED_PAIRS, 'all original candidate cells must be accounted')
    after = hash_regular(p['image'], recovery.IMAGE_BYTES, recovery.IMAGE_BYTES)
    require(after == image_before == recovery.IMAGE_SHA, 'original image SHA after derivation differs')
    original_bytes = sum(row['bytes'] for row in files.values())
    raw_attempt_bytes = sum(row['bytes'] for name, row in files.items() if name.startswith(CANDIDATE + '/attempts/'))
    derived_bytes = sum(row['original_bytes'] for row in mappings.values() if row['mode'] == 'derived')
    identity_without_raw = original_bytes - derived_bytes - raw_attempt_bytes
    control_bytes = sum(checked(Path(folder)/name, regular=True).st_size for folder, dirs, names in os.walk(p['local'])
                        for name in names if Path(folder)/name not in (recipe_path, ledger_path))
    costs = cost_record(original_bytes=original_bytes, recipe_bytes=recipe_path.stat().st_size,
                        ledger_bytes=ledger_path.stat().st_size, retained_metadata_bytes=control_bytes,
                        identity_bytes=identity_without_raw, raw_attempt_bytes=raw_attempt_bytes)
    record = {'status': 'PASS', 'run_context': ctx, 'scope': SCOPE, 'counts': counts, 'candidate': CANDIDATE,
              'complete_candidate_paths': len(cells), 'cost_at_derive_close': costs,
              'image_sha256_before': image_before, 'image_sha256_after': after,
              'originals_retired_bytes': 0, 'scientific_qualification': False,
              'all_original_raw_attempts_retained': True}
    save(p['local'] / 'derivation.json', record); return record


def close_exact(image, mount, label, readonly, size):
    before = mount_binding(image, mount, label + '-before', readonly, size)
    command(['sudo', '-n', 'umount', '--', str(mount)], label, 60)
    raw, _, _ = command(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                         '--output', 'NAME,BACK-FILE'], label + '-absent')
    require(not os.path.ismount(mount) and json.loads(raw, object_pairs_hook=bundle.unique_object) == {'loopdevices': []}
            and backing_identity(image) == before['image_identity'], 'exact mount/loop closure failed')
    return {'status': 'PASS', 'before': before, 'mount_absent': True, 'loop_absent': True}


def close_orphan_loop(image, label, readonly, size):
    """A failed mount may leave a loop: detach only its exact owned backing."""
    info = checked(image, regular=True); before = backing_identity(image)
    require(info.st_uid == os.getuid() and info.st_nlink == 1 and info.st_size == size, 'unbound orphan image')
    argv = ['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
            '--output', 'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT,RO']
    raw, _, _ = command(argv, label + '-observe')
    loops = json.loads(raw, object_pairs_hook=bundle.unique_object)['loopdevices']
    require(type(loops) is list and len(loops) <= 1, 'ambiguous orphan loop')
    if loops:
        loop = loops[0]
        require(re.fullmatch('/dev/loop[0-9]+', loop.get('name', '')) and loop.get('back-file') == str(image)
                and int(loop.get('back-ino', -1)) == info.st_ino
                and loop.get('back-maj:min') == f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}'
                and loop.get('offset') == loop.get('sizelimit') == 0 and bool(loop.get('ro')) == readonly
                and backing_identity(image) == before, 'orphan exact backing differs')
        raw, _, _ = command(['findmnt', '--json', '--source', loop['name'], '-o', 'TARGET,SOURCE'],
                             label + '-mount-absence', accepted=(1,))
        require(not raw.strip() or json.loads(raw, object_pairs_hook=bundle.unique_object) == {'filesystems': []},
                'orphan loop still mounted elsewhere')
        command(['sudo', '-n', 'losetup', '--detach', '--', loop['name']], label + '-detach')
    raw, _, _ = command(argv, label + '-absent')
    require(json.loads(raw, object_pairs_hook=bundle.unique_object) == {'loopdevices': []}
            and backing_identity(image) == before, 'orphan loop closure differs')
    return {'status': 'PASS', 'loop_absent': True, 'exact_backing': before, 'detached': bool(loops)}


def cleanup():
    p, ctx = admitted(); record = {'status': 'PASS', 'run_context': ctx, 'failures': []}
    try:
        if os.path.ismount(p['mount']):
            pending = load(p['local'] / 'inner-pending.json')
            require(pending['run_context'] == ctx and pending['image_identity'] == identity(p['image']), 'unbound inner cleanup')
            record['inner'] = close_exact(p['image'], p['mount'], 'close-original', True, recovery.IMAGE_BYTES)
        if os.path.lexists(p['image']):
            if not os.path.ismount(p['mount']) and os.path.lexists(p['local'] / 'inner-pending.json'):
                pending = load(p['local'] / 'inner-pending.json')
                require(pending['run_context'] == ctx and pending['image_identity'] == identity(p['image']), 'unbound orphan inner cleanup')
                record['inner_orphan'] = close_orphan_loop(p['image'], 'close-original-orphan', True, recovery.IMAGE_BYTES)
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
            record['outer_orphan'] = close_orphan_loop(p['outer'], 'unmounted-outer', False, OUTER_BYTES)
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
            limit = file_limit(name)
            require(info.st_size <= limit, 'direct evidence file producer bound exceeded')
            total += info.st_size; require(total + 200_000 <= CLOUD_BYTES - 1_000_000, 'complete direct metadata export refused')
            records.append({'path': path.relative_to(p['local']).as_posix(), 'bytes': info.st_size,
                            'sha256': hash_regular(path, limit)})
    record = {'status': 'PASS', 'run_context': ctx, 'scope': SCOPE, 'files': records,
              'selected_bytes': total, 'scientific_qualification': False,
              'unfinished_export_self_receipts_excluded': True, 'no_scientific_data_upload': True}
    save(p['local'] / 'export.json', record); return record


ACTIONS = {name: globals()[name] for name in STAGES}


def bound_derivation(p, ctx, expected=None):
    """Bind the complete successful payload and both outputs after worker exit."""
    value = load_stage_control(p['local'] / 'derivation.json')
    require(type(value) is dict and value.get('status') == 'PASS' and value.get('run_context') == ctx,
            'successful derivation payload differs')
    counts = value.get('counts')
    require(type(counts) is dict and set(counts) == {'derived','identity','refused'}
            and all(type(count) is int and 0 <= count <= EXPECTED_PAIRS for count in counts.values())
            and sum(counts.values()) == EXPECTED_PAIRS, 'complete derivation counts required')
    binding = {}
    for name in ('derivation.json','derived-recipes.jsonl.gz','derived-ledger.jsonl'):
        path = p['local'] / name; info = checked(path,regular=True)
        require(info.st_nlink == 1, 'unique closed derivation output required')
        binding[name] = {'path':str(path),'bytes':info.st_size,'sha256':hash_regular(path,file_limit(name))}
    require(sum(binding[name]['bytes'] for name in ('derived-recipes.jsonl.gz','derived-ledger.jsonl'))
            <= DERIVE_OUTPUT_BYTES, 'combined closed derivation output exceeds cap')
    if expected is not None:
        require(expected == binding, 'derivation outputs changed after their successful producer closed')
    return value, binding


def stage_parent(action):
    p, ctx = paths(), context()
    closed = {}
    if action in ('cleanup','export'):
        for stage in list(STAGES)[:list(STAGES).index(action)]:
            closed[stage] = require_closed_stage(p,ctx,stage)
        require_closed_commands(p,ctx)
    elif action != 'plan':
        for stage in list(STAGES)[:list(STAGES).index(action)]: require_stage(p, ctx, stage)
    elapsed = time.time() - ctx['started_epoch']
    tail = sum(list(STAGES.values())[list(STAGES).index(action):])
    require(0 <= elapsed and elapsed + tail + JOB_TAIL_SECONDS <= JOB_SECONDS, 'whole-job time admission refused')
    nonce = uuid.uuid4().hex; parent = supervisor.process_identity(os.getpid())
    env = worker_environment(download=action == 'download'); env['FQ_DERIVED_PARENT_NONCE'] = nonce
    def launched(worker):
        save(p['local'] / ('active-' + action + '.json'), {'action': action, 'run_context': ctx,
             'parent_identity': parent, 'worker_identity': worker, 'nonce': nonce})
    observed = supervisor.run_owned([sys.executable, '-B', str(Path(__file__)), '_worker', action],
        p['local'] / ('parent-' + action + '.stdout'), p['local'] / ('parent-' + action + '.stderr'),
        started=STARTED, total_seconds=STAGES[action] - 4, cleanup_seconds=8, receipt_seconds=2,
        capture_bytes=32768, environ=env, launched=launched, startup_gate=True)
    record = {'status': observed['status'], 'action': action, 'run_context': ctx, 'nonce': nonce,
              'parent_identity': parent, 'supervision': observed, 'scope': SCOPE}
    if action == 'derive' and record['status'] == 'PASS':
        try:
            _, record['result_binding'] = bound_derivation(p,ctx)
        except (ValueError,OSError,TypeError,KeyError) as error:
            record.update(status='FAIL',result_binding_error=type(error).__name__)
    save(p['local'] / ('parent-' + action + '.json'), record)
    require_closed_stage(p,ctx,action,allow_current_parent=True)
    require(record['status'] == 'PASS', 'supervised probe stage failed')
    if action == 'export':
        # Recheck every producer after the final worker has exited; no open or
        # ambiguous stage/command stream may be sealed immutable.
        closed = {stage:require_closed_stage(p,ctx,stage) for stage in list(STAGES)[:-1]}
        require_closed_commands(p,ctx)
        # The export worker has stopped. Seal every actual file including its
        # final parent/child captures without claiming to hash this manifest itself.
        sealed, total = [], 0
        for folder, dirs, names in os.walk(p['local'], followlinks=False):
            for name in sorted(names):
                path = Path(folder) / name; info = checked(path, regular=True)
                limit = file_limit(name)
                total += info.st_size
                require(info.st_size <= limit and total + 200_000 <= CLOUD_BYTES - 1_000_000,
                        'complete final metadata seal refused')
                sealed.append({'path': path.relative_to(p['local']).as_posix(), 'bytes': info.st_size,
                               'sha256': hash_regular(path, limit)})
        manifest = {'status': 'PASS', 'run_context': ctx, 'files': sealed,
                    'scope': SCOPE, 'selected_bytes': total, 'scientific_qualification': False}
        # Aggregate the bytes that actually exist after all producers stop.
        # Failed/partial derivations receive no replacement credit at all.
        complete = all(value is not None and value['status'] == 'PASS' for value in closed.values())
        complete = complete and os.path.lexists(p['local'] / 'derivation.json')
        if complete:
            binding = closed['derive'].get('result_binding')
            require(type(binding) is dict, 'closed derivation output binding missing')
            derivation, _ = bound_derivation(p,ctx,binding)
        manifest['derivation_complete'] = bool(complete)
        manifest['originals_retired_bytes'] = 0
        manifest['output_partial_files_preserved'] = not complete
        manifest['actual_export_payload_bytes_excluding_manifest'] = total
        if complete:
            cost = derivation['cost_at_derive_close']
            represented_original = cost['identity_retained_original_bytes'] + cost['raw_attempt_bytes_in_identity']
            manifest['aggregate_representation_cost'] = {'identity_retained_original_bytes': represented_original,
                'all_actual_export_bytes_including_final_seal': 0, 'encoded_representation_bytes': 0,
                'originals_retired_bytes': 0, 'scientific_qualification': False}
        # Manifest byte size is self-counted through a bounded integer fixed
        # point; its own hash is deliberately not claimed in its own file list.
        for _ in range(10):
            manifest_bytes = len((json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode())
            final = total + manifest_bytes
            if complete:
                aggregate = manifest['aggregate_representation_cost']
                if aggregate['all_actual_export_bytes_including_final_seal'] == final: break
                aggregate['all_actual_export_bytes_including_final_seal'] = final
                aggregate['encoded_representation_bytes'] = represented_original + final
            else:
                if manifest.get('all_actual_export_bytes_including_final_seal') == final: break
                manifest['all_actual_export_bytes_including_final_seal'] = final
        else: raise ValueError('final manifest byte-cost fixed point failed')
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
                    and proof['nonce'] == os.environ.get('FQ_DERIVED_PARENT_NONCE')
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
