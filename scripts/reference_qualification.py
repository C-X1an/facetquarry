"""Bind frozen measurements to an actual guest execution and lossless artifact.

The collector's coverage is never rewritten. The inner execution record precedes
packaging; a later, external envelope binds the final bundle and GitHub artifact.
These repository-local checks are reproducible evidence, not third-party attestation.
"""
from __future__ import annotations
import argparse
import csv
import datetime as dt
import gzip
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

from common import ROOT, source_hash
import analyze_reference as analysis
import evidence_bundle as bundle_tool

FORMAT = 'kvm-frozen-reference-v1'
GRID_SHA = '37d376ffa53b54fd37849b0fb682a76b944cea029185a0da4771dc1d20420992'
MAX_METADATA = 32_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def timestamp(value):
    require(isinstance(value, str), 'missing execution timestamp')
    result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None, 'timestamp has no timezone')
    return result


def safe_file(root, name):
    require(isinstance(name, str) and '\\' not in name and ':' not in name,
            'nonportable evidence path')
    parts = PurePosixPath(name).parts
    require(parts and not name.startswith('/') and all(x not in ('', '.', '..') for x in parts)
            and PurePosixPath(name).as_posix() == name, 'invalid evidence path')
    target = root
    for part in parts:
        target = target / part
        require(not target.is_symlink() and not getattr(target, 'is_junction', lambda: False)(),
                'linked evidence path')
    require(target.is_file(), 'missing evidence file: ' + name)
    return target


def read_metadata(path):
    require(path.stat().st_size <= MAX_METADATA, 'metadata file exceeds admission')
    return path.read_bytes()


def decoded_ref(ref, root):
    require(isinstance(ref, dict), 'invalid evidence reference')
    raw = read_metadata(safe_file(root, ref.get('path')))
    require(sha(raw) == ref.get('sha256'), 'curated file digest differs')
    if ref.get('encoding', 'identity') == 'gzip':
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            raw = stream.read(MAX_METADATA + 1)
        require(len(raw) <= MAX_METADATA, 'decoded metadata exceeds admission')
    else:
        require(ref.get('encoding', 'identity') == 'identity', 'unknown metadata encoding')
    require(sha(raw) == ref.get('decoded_sha256', ref.get('sha256')), 'decoded metadata digest differs')
    return raw


def frozen_config(concurrency):
    require(type(concurrency) is int and concurrency in (1, 4, 16), 'invalid reader profile')
    raw = (ROOT / 'benchmarks/grid.json').read_bytes()
    require(sha(raw) == GRID_SHA, 'frozen grid bytes changed')
    config = json.loads(raw)['full']
    config['concurrency'] = concurrency
    return config


def command_errors(record, identity, category):
    errors = []
    if not isinstance(record, dict):
        return ['command receipt is not an object']
    for condition, message in (
        (record.get('status') == 'PASS' and type(record.get('exit_code')) is int and record.get('exit_code') == 0
         and record.get('termination_reason') is None, 'command failed'),
        (record.get('source_before') == identity == record.get('source_after'), 'command source differs'),
        (record.get('category') == category, 'command category differs'),
        (bool(record.get('command')) and isinstance(record['command'], list), 'command invocation missing')):
        if not condition:
            errors.append(message)
    return errors


def check_inner(record, inputs, members, identity):
    """Validate independently retained inputs; raise on the first contradiction."""
    require(record.get('schema_version') == 1 and record.get('evidence_type') == 'reference_execution'
            and record.get('format') == FORMAT and record.get('status') == 'PASS', 'execution proof is not qualified')
    require(record.get('source') == identity, 'execution source differs')
    concurrency = record.get('concurrency')
    config = frozen_config(concurrency)
    cells = analysis.expected_cells(config)
    require(len(cells) == 5400, 'frozen expected-cell derivation differs')
    require(record.get('config') == config and record.get('grid_sha256') == GRID_SHA,
            'execution configuration differs')
    context = record['run_context']
    require(re.fullmatch('[0-9a-f]{40}', context.get('commit', '')) is not None
            and context.get('git_status') == '', 'execution checkout is not clean and committed')
    for key in ('github_run_id', 'github_run_attempt'):
        require(re.fullmatch('[1-9][0-9]{0,19}', context.get(key) or '') is not None, 'workflow identity missing')
    execution_id = record.get('execution_id')
    require(isinstance(execution_id, str) and re.fullmatch('[0-9a-f]{32}', execution_id), 'execution identity missing')
    documents = {}
    for label, ref in record['inputs'].items():
        require(label in inputs and ref['path'] in members, 'execution input missing from bundle')
        raw = inputs[label]
        require(sha(raw) == ref['sha256'] == members[ref['path']]['original_sha256']
                and len(raw) == ref['bytes'] == members[ref['path']]['original_bytes'], 'execution input digest differs')
        if label not in ('enospc', 'cells_csv', 'targets_csv'):
            documents[label] = json.loads(raw)
    required = {'coverage', 'provenance', 'invocation', 'start', 'guest', 'setup', 'quota',
                'analysis', 'cells_csv', 'targets_csv', 'guest_receipt', 'analysis_receipt', 'enospc'}
    require(set(documents) | {'enospc', 'cells_csv', 'targets_csv'} == required
            and set(record['inputs']) == required, 'execution input set differs')
    guest, setup, start = (documents[k] for k in ('guest', 'setup', 'start'))
    for proof in (guest, setup, start):
        require(proof.get('source') == identity and proof.get('execution_id') == execution_id
                and proof.get('run_context') == context, 'guest/session binding differs')
    require(guest.get('status') == setup.get('status') == 'PASS' and guest.get('mode') == 'benchmark'
            and guest.get('exit_code') == guest.get('command_exit_code') == 0, 'actual full guest execution did not pass')
    require(setup.get('guest_result_sha256') == record['inputs']['guest']['sha256'], 'host guest-result digest differs')
    host = guest['host']
    require(host.get('system') == 'Linux' and host.get('machine') == 'x86_64'
            and host.get('logical_cpu_count') == 4 and 7_500_000_000 <= host.get('physical_ram_bytes', 0) <= 8_000_000_000,
            'actual reference geometry differs')
    require(type(guest.get('uid')) is int and guest['uid'] > 0 and type(guest.get('gid')) is int and guest['gid'] > 0,
            'guest workload did not drop privilege')
    require(setup.get('guest_ram_bytes') == 8_000_000_000, 'configured reference RAM differs')
    argv = setup['qemu_command']
    for option, value in (('-accel', 'kvm'), ('-smp', '4,sockets=1,cores=4,threads=1'),
                          ('-m', '7812500K'), ('-nic', 'none')):
        require(argv.count(option) == 1 and argv[argv.index(option) + 1] == value, 'actual QEMU configuration differs: ' + option)
    last = setup['commands'][-1]
    require(last['command'] == argv and last.get('exit_code') == 0 and last.get('termination_reason') is None
            and last.get('transient_unit') and '--collect' in last.get('actual_command', []), 'QEMU execution did not terminate successfully')
    mount = setup['mount']
    require(mount.get('fstype') == 'ext4' and str(mount.get('source')).startswith('/dev/loop'), 'owned quota mount differs')
    dev = guest['devtmpfs_before_uid_drop']
    require(dev.get('uid') == 0 and 0 < dev.get('capacity_bytes', 0) <= 1048576
            and guest.get('unprivileged_device_controls') == 'PASS', 'actual device filesystem bound missing')
    ram = guest['ram_backed_filesystems']
    require(isinstance(ram, list) and {x['mount'] for x in ram} == {'/dev', '/tmp', '/run'}
            and all(type(x['bytes']) is int and x['bytes'] > 0 for x in ram)
            and sum(x['bytes'] for x in ram) <= 33554432, 'RAM-backed filesystem bound missing')
    require(guest['versions']['go']['exit_code'] == 0
            and guest['versions']['go']['stdout'].strip() == 'go version go1.27.3 linux/amd64', 'guest supported toolchain differs')
    quota = documents['quota']
    require(quota.get('volume_file_bytes') == 3_300_000_000
            and quota.get('oversized_allocation_bytes') == 3_400_000_000
            and quota.get('oversized_allocation') == 'DENIED_ENOSPC'
            and quota.get('hard_quota_enforced') is True and b'No space left on device' in inputs['enospc'],
            'actual fixed-volume refusal proof missing')
    require(quota.get('run_context') == context and quota.get('mount') == mount
            and quota.get('volume_path') == mount.get('target')
            and quota.get('image_path') == quota.get('volume_path', '') + '.img'
            and quota.get('enospc_sha256') == record['inputs']['enospc']['sha256'],
            'quota belongs to a different volume or execution')
    fsdevs = [argv[i + 1] for i, value in enumerate(argv[:-1]) if value == '-fsdev']
    volume = quota['volume_path']
    require('local,id=owned,path=' + volume + ',security_model=none,readonly=on' in fsdevs
            and 'local,id=project,path=' + volume + '/source,security_model=none' in fsdevs
            and 'local,id=rootfs,path=' + volume + '/reference-guest/rootfs,security_model=none,readonly=on' in fsdevs,
            'actual guest shares differ from the quota volume')
    require(start.get('preexisting_full_profiles') == [] and start.get('profile') == 'full'
            and start.get('concurrency') == concurrency and start.get('config') == config,
            'full benchmark namespace was not fresh')
    require(guest.get('benchmark_start_sha256') == record['inputs']['start']['sha256'], 'guest start proof differs')
    cfg_hash = sha(json.dumps(config, sort_keys=True).encode())[:12]
    folder = '.local/benchmarks/full-' + identity[:12] + '-' + cfg_hash
    require(start.get('folder') == guest.get('benchmark_folder') == record.get('folder') == folder, 'full benchmark folder differs')
    begin, end = timestamp(start['started_at']), timestamp(guest['ended_at'])
    require(timestamp(guest['started_at']) <= begin < end, 'guest time window differs')
    invocation = documents['invocation']
    require(invocation.get('source') == identity and invocation.get('status') == 'PASS'
            and invocation.get('completed_this_invocation') == 5400 and invocation.get('run_errors') == []
            and invocation.get('arguments') == {'profile': 'full', 'limit_cells': 0, 'concurrency': concurrency}
            and begin <= timestamp(invocation['started_at']) <= timestamp(invocation['ended_at']) <= end,
            'one fresh complete invocation not established')
    invocation_begin, invocation_end = timestamp(invocation['started_at']), timestamp(invocation['ended_at'])
    coverage, provenance = documents['coverage'], documents['provenance']
    analysis.validate_run(coverage, config, identity, 'full')
    require(coverage.get('config') == config and coverage.get('config_hash') == cfg_hash
            and coverage.get('provenance') == provenance and provenance.get('gomaxprocs_requested') == '4',
            'collector provenance differs')
    require(all(coverage.get(k) == v for k, v in {
        'status': 'PASS', 'expected_cells': 5400, 'completed_cells': 5400, 'missing_cells': [],
        'unexpected_cells': [], 'failed_cells': [], 'run_errors': [], 'limited': False,
        'grid_complete': True, 'reference_host_verified': False, 'reference_recall_target': 'PASS'}.items()),
        'immutable collector coverage is incomplete or target failed')
    require(provenance.get('declared_build_flags') == ['-trimpath', '-ldflags', '-X main.sourceID=' + identity],
            'build flag provenance differs')
    report = documents['analysis']
    require(all(report.get(k) == v for k, v in {
        'status': 'PASS', 'source': identity, 'profile': 'full', 'concurrency': concurrency,
        'expected_cells': 5400, 'present_cells': 5400, 'sample_count': 5_400_000,
        'successful_samples': 5_400_000, 'error_calls': 0, 'missing_cells': [], 'unexpected_cells': [],
        'analysis_failed_cells': [], 'baseline_errors': [], 'target_cells': 45, 'target_pass_cells': 45,
        'target_outcome': 'PASS', 'target_status_counts': {'PASS': 45}, 'five_seed_groups': 1080,
        'complete_five_seed_groups': 1080, 'paired_comparison_groups': 972}.items()),
        'independent full-grid reanalysis incomplete or target failed')
    require(report.get('input_coverage_sha256') == record['inputs']['coverage']['sha256']
            and report.get('locked_grid_sha256') == GRID_SHA
            and report.get('analysis_script_sha256') == sha((ROOT / 'scripts/analyze_reference.py').read_bytes())
            and report.get('method', {}).get('bootstrap_replicates') == 2000
            and report.get('method', {}).get('bootstrap_seed') == 20261023, 'reanalysis method/input binding differs')
    for label, category in (('guest_receipt', 'kvm-reference-benchmark'), ('analysis_receipt', 'reference-analysis')):
        receipt = documents[label]
        require(not command_errors(receipt, identity, category), label + ' failed or stale')
        for stream in ('stdout', 'stderr'):
            path = receipt[stream].replace('\\', '/')
            require(path in members and members[path]['original_sha256'] == receipt[stream + '_sha256'],
                    label + ' output digest missing from bundle')
        require(receipt.get('commit') == context['commit'], label + ' checkout differs')
    guest_receipt, analysis_receipt = documents['guest_receipt'], documents['analysis_receipt']
    expected_command = ['python3', 'scripts/benchmark.py', '--profile', 'full', '--concurrency', str(concurrency)]
    guest_command = guest.get('command', [])
    require(guest_command.count('--') == 1 and guest_command[guest_command.index('--') + 1:] == expected_command
            and guest_receipt.get('command') == expected_command, 'evidenced collector command differs')
    require(guest_receipt.get('environment', {}).get('versions', {}).get('go') == 'go version go1.27.3 linux/amd64'
            and begin <= timestamp(guest_receipt['started_at']) <= invocation_begin
            <= invocation_end <= timestamp(guest_receipt['ended_at']) <= end, 'guest command runtime/window differs')
    expected_analysis = ['python3', 'scripts/analyze_reference.py', folder, '--grid', 'benchmarks/grid.json',
                         '--expected-source', identity, '--output', '.local/reference-analysis']
    require(analysis_receipt.get('command') == expected_analysis
            and end <= timestamp(analysis_receipt['started_at']) <= timestamp(report['created_at'])
            <= timestamp(analysis_receipt['ended_at']), 'evidenced analyzer command/window differs')
    index = record['cells']
    require(isinstance(index, list) and len(index) == 5400 and {r['id'] for r in index} == set(cells), 'execution cell index differs')
    rows = list(csv.DictReader(io.StringIO(inputs['cells_csv'].decode('utf-8'))))
    require(len(rows) == 5400 and {r['grid_id'] for r in rows} == set(cells), 'analysis cell IDs differ')
    rows = {r['grid_id']: r for r in rows}
    targets = []
    for cell in index:
        cid, expected = cell['id'], cells[cell['id']]
        require(cell['cell'] == expected and cell['sample_count'] == 1000
                and cell['source'] == identity and cell['status'] == 'PASS'
                and cell['native_go'] == 'go1.27.3' and cell['native_workers'] == concurrency
                and cell['native_gomaxprocs'] == 4 and cell['errors'] == []
                and invocation_begin <= timestamp(cell['started_at']) <= timestamp(cell['ended_at']) <= invocation_end,
                'cell execution binding differs: ' + cid)
        for suffix, key in (('.summary.json', 'summary_sha256'), ('.samples.jsonl.gz', 'samples_sha256')):
            member = folder + '/' + cid + suffix
            require(member in members and members[member]['original_sha256'] == cell[key], 'cell member digest differs: ' + cid)
        row = rows[cid]
        require(row['analysis_status'] == 'PASS' and int(row['sample_count']) == int(row['successful_samples']) == 1000
                and row['corpus_sha256'] == cell['corpus_sha256'] and row['queries_sha256'] == cell['queries_sha256']
                and row['raw_samples_sha256'] == cell['samples_sha256'], 'recomputed cell binding differs: ' + cid)
        if expected['n'] == 10000 and expected['filter_label'] == 'all' and expected['mode'] == 'graph' and expected['ef'] == 128:
            value = float(row['mean_recall'])
            require(math.isfinite(value) and .95 <= value <= 1 and row['recall_target_status'] == 'PASS', 'per-seed recall target failed')
            targets.append(cid)
    target_rows = list(csv.DictReader(io.StringIO(inputs['targets_csv'].decode('utf-8'))))
    require(len(target_rows) == 45 and {r['grid_id'] for r in target_rows} == set(targets)
            and all(r['recall_target_status'] == 'PASS' and math.isfinite(float(r['mean_recall']))
                    and .95 <= float(r['mean_recall']) <= 1
                    and float(r['mean_recall']) == float(rows[r['grid_id']]['mean_recall']) for r in target_rows),
            'all per-seed targets not independently established')
    return {'concurrency': concurrency, 'cells': index, 'provenance': provenance, 'run_context': context}


def create_execution(root, output):
    require(not output.exists(), 'execution output already exists')
    identity = source_hash(root)
    guest = json.loads((root / '.local/reference-guest-result.json').read_text())
    folder = root / guest['benchmark_folder']
    invocations = list(folder.glob('invocation-*.json'))
    require(len(invocations) == 1, 'expected exactly one fresh invocation')
    setup_path = root / '.local/reference-guest-setup/setup.json'
    setup = json.loads(setup_path.read_text())
    names = {'coverage': folder / 'coverage.json', 'provenance': folder / 'provenance.json',
             'invocation': invocations[0], 'guest': root / '.local/reference-guest-result.json',
             'setup': setup_path, 'start': root / '.local/reference-benchmark-start.json',
             'quota': root / '.local/reference-quota.json', 'enospc': root / '.local/enospc.stderr',
             'analysis': root / '.local/reference-analysis/analysis.json',
             'cells_csv': root / '.local/reference-analysis/per-seed-cells.csv',
             'targets_csv': root / '.local/reference-analysis/reference-target-cells.csv'}
    for label, category in (('guest_receipt', 'kvm-reference-benchmark'), ('analysis_receipt', 'reference-analysis')):
        found = []
        for path in (root / '.local/evidence').glob('*/receipt.json'):
            receipt = json.loads(path.read_text())
            if receipt.get('category') == category:
                found.append(path)
        require(len(found) == 1, 'expected one evidenced ' + category)
        names[label] = found[0]
    inputs = {label: read_metadata(path) for label, path in names.items()}
    record = {'schema_version': 1, 'evidence_type': 'reference_execution', 'format': FORMAT,
              'source': identity, 'execution_id': guest['execution_id'], 'run_context': setup['run_context'],
              'concurrency': json.loads(inputs['coverage'])['config']['concurrency'], 'folder': guest['benchmark_folder'],
              'grid_sha256': GRID_SHA, 'config': json.loads(inputs['coverage'])['config'], 'status': 'PASS',
              'inputs': {label: {'path': path.relative_to(root).as_posix(), 'bytes': len(inputs[label]),
                                 'sha256': sha(inputs[label])} for label, path in names.items()}, 'cells': []}
    for path in sorted(folder.glob('*.summary.json')):
        raw = read_metadata(path)
        summary = json.loads(raw)
        native = summary['native_metadata']
        record['cells'].append({'id': path.name[:-13], 'cell': summary['cell'], 'source': summary['source'],
            'status': summary['status'], 'errors': summary['errors'], 'sample_count': summary['sample_count'],
            'started_at': summary['started_at'], 'ended_at': summary['ended_at'], 'summary_sha256': sha(raw),
            'samples_sha256': summary['samples_sha256'], 'corpus_sha256': summary['corpus_sha256'],
            'queries_sha256': summary['queries_sha256'], 'generation': summary['generation'],
            'native_go': native['go'], 'native_workers': native['workers'], 'native_gomaxprocs': native['gomaxprocs']})
    # Build a real file-byte index. Packaging will independently repeat this
    # inventory and bind the same original bytes in its verified manifest.
    members = {}
    for path in (root / '.local').rglob('*'):
        if path.is_file():
            require(not path.is_symlink(), 'linked execution evidence')
            members[path.relative_to(root).as_posix()] = {'original_bytes': path.stat().st_size,
                                                         'original_sha256': bundle_tool.file_sha(path)}
    check_inner(record, inputs, members, identity)
    output.write_text(json.dumps(record, indent=2) + '\n')
    return record


def validate_envelope(record, root, identity, cache=None):
    """Verify the exact transport plus its curated execution inputs."""
    require(record.get('qualification_format') == FORMAT, 'verified reference envelope missing')
    require(record.get('source') == identity and record.get('status') == 'PASS', 'reference envelope failed or stale')
    bundle_ref = record['bundle']
    path = safe_file(root, bundle_ref['path'])
    require(path.stat().st_size == bundle_ref['bytes'] <= bundle_tool.MAX_OUTPUT
            and bundle_tool.file_sha(path) == bundle_ref['sha256'], 'reference bundle identity differs')
    key = (str(path.resolve()), bundle_ref['sha256'])
    if cache is not None and key in cache:
        manifest = cache[key]
    else:
        verified = bundle_tool.verify(path)
        with path.open('rb') as compressed:
            manifest = json.loads(bundle_tool.transport_item(bundle_tool.XZReader(compressed), 'manifest.json', bundle_tool.MAX_MANIFEST))
        require(verified['source'] == identity == manifest['source'], 'bundle technical source differs')
        if cache is not None:
            cache[key] = manifest
    members = {r['path']: r for r in manifest['members'] if not r['directory']}
    execution_raw = decoded_ref(record['execution'], root)
    member = record['execution']['member']
    require(member in members and sha(execution_raw) == members[member]['original_sha256'], 'execution proof not bound to exact bundle member')
    execution = json.loads(execution_raw)
    inputs = {}
    require(set(record['inputs']) == set(execution['inputs']), 'curated input set differs')
    for label, ref in record['inputs'].items():
        require(ref['member'] == execution['inputs'][label]['path'], 'curated input member differs')
        inputs[label] = decoded_ref(ref, root)
    proof = check_inner(execution, inputs, members, identity)
    artifact = record['artifact']
    context = proof['run_context']
    require(artifact.get('repo') == 'C-X1an/facetquarry' and artifact.get('run_id') == int(context['github_run_id'])
            and artifact.get('head_sha') == context['commit'] and artifact.get('expired') is False
            and type(artifact.get('id')) is int and artifact['id'] > 0
            and type(artifact.get('size_in_bytes')) is int and artifact['size_in_bytes'] > 0
            and isinstance(artifact.get('digest'), str) and re.fullmatch('sha256:[0-9a-f]{64}', artifact['digest']),
            'authenticated artifact metadata missing or differs')
    observation = json.loads(decoded_ref(record['artifact_observation'], root))
    require(observation.get('repo') == artifact['repo'], 'artifact observation repository differs')
    timestamp(observation['observed_at'])
    observed = [item for item in observation['artifacts']['artifacts'] if item.get('id') == artifact['id']]
    require(len(observed) == 1, 'artifact observation is missing or duplicated')
    observed = observed[0]
    require(all(observed.get(key) == artifact.get(key) for key in ('id', 'size_in_bytes', 'digest', 'expired'))
            and observed.get('workflow_run', {}).get('id') == artifact['run_id']
            and observed.get('workflow_run', {}).get('head_sha') == artifact['head_sha'],
            'artifact descriptor differs from retained connector observation')
    jobs = observation['jobs']['jobs']
    require(isinstance(jobs, list) and len(jobs) == 1 and jobs[0].get('run_id') == artifact['run_id']
            and jobs[0].get('status') == 'completed' and jobs[0].get('conclusion') == 'success',
            'observed workflow did not complete successfully')
    zip_ref = record['artifact_zip']
    zip_path = safe_file(root, zip_ref['path'])
    require(zip_path.stat().st_size == zip_ref['bytes'] == artifact['size_in_bytes']
            and 0 < zip_ref['bytes'] <= 450_000_000
            and bundle_tool.file_sha(zip_path) == zip_ref['sha256'] == artifact['digest'].removeprefix('sha256:'),
            'actual artifact ZIP differs from connector identity')
    with zipfile.ZipFile(zip_path) as archive:
        infos = archive.infolist()
        require(len(infos) <= 50000, 'artifact ZIP member admission exceeded')
        matches = [item for item in infos if PurePosixPath(item.filename).name == 'reference-members.tar.xz']
        require(len(matches) == 1, 'artifact ZIP must contain exactly one reference bundle')
        item = matches[0]
        require(not item.is_dir() and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG)
                and item.file_size == bundle_ref['bytes'], 'artifact bundle member size/type differs')
        h = hashlib.sha256()
        count = 0
        with archive.open(item) as stream:
            while block := stream.read(1024 * 1024):
                count += len(block)
                require(count <= bundle_ref['bytes'], 'artifact bundle member exceeds admission')
                h.update(block)
        require(count == bundle_ref['bytes'] and h.hexdigest() == bundle_ref['sha256'], 'bundle bytes differ from actual artifact ZIP')
    require(manifest['commit'] == context['commit'] and manifest['run_id'] == context['github_run_id'], 'transport execution identity differs')
    return proof


def validate_profiles(proofs):
    require(len(proofs) == 3 and {p['concurrency'] for p in proofs} == {1, 4, 16}, 'required reader profiles1/4/16 missing or duplicated')
    reference = next(p for p in proofs if p['concurrency'] == 1)
    def correspondence(proof):
        return {json.dumps({k: v for k, v in r['cell'].items() if k != 'concurrency'}, sort_keys=True):
                (r['corpus_sha256'], r['queries_sha256'], r['generation']) for r in proof['cells']}
    baseline = correspondence(reference)
    for proof in proofs:
        require(proof['provenance']['binaries'] == reference['provenance']['binaries'], 'reader executable provenance differs')
        require(correspondence(proof) == baseline, 'reader corpus/query/generation correspondence differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        record = create_execution(ROOT, args.output)
    except (OSError, ValueError, TypeError, KeyError, IndexError) as failure:
        if not args.output.exists():
            args.output.write_text(json.dumps({'schema_version': 1, 'evidence_type': 'reference_execution',
                'source': source_hash(), 'status': 'FAIL', 'error': str(failure)}, indent=2) + '\n')
        print(json.dumps({'status': 'FAIL', 'error': str(failure)}))
        return 1
    print(json.dumps({'status': 'PASS', 'concurrency': record['concurrency'], 'cells': len(record['cells']),
                      'scope': 'Execution proof only; final transport envelope is separate'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
