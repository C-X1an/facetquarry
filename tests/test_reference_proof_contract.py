"""Synthetic proof-format controls, never VM/engine/measurement evidence.

The full-format fixture contains 5400 descriptors, not 5.4 million timings.
The separate tiny transport test exercises real codec bytes and stubs only the
inner-format layer, which the descriptor controls exercise independently.
"""
import copy
import csv
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_qualification as q

SOURCE = '1' * 64
COMMIT = 'a' * 40
EXECUTION = 'b' * 32
CONTEXT = {'commit': COMMIT, 'git_status': '', 'github_run_id': '123456', 'github_run_attempt': '1'}


def stamp(second):
    return '2026-10-24T16:00:%02d+00:00' % second


def json_bytes(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def csv_bytes(rows):
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


class FullFormatFixture:
    def __init__(self):
        config = q.frozen_config(1)
        cfg_hash = q.sha(json.dumps(config, sort_keys=True).encode())[:12]
        folder = '.local/benchmarks/full-' + SOURCE[:12] + '-' + cfg_hash
        provenance = {'source': SOURCE, 'binaries': {
            name: {'source': SOURCE, 'go': 'go1.27.3', 'sha256': q.sha(name.encode())}
            for name in ('facetquarry', 'fqbench')}, 'gomaxprocs_requested': '4',
            'declared_build_flags': ['-trimpath', '-ldflags', '-X main.sourceID=' + SOURCE]}
        argv = ['qemu-system-x86_64', '-accel', 'kvm', '-smp', '4,sockets=1,cores=4,threads=1',
                '-m', '7812500K', '-nic', 'none',
                '-fsdev', 'local,id=rootfs,path=/owned-volume/reference-guest/rootfs,security_model=none,readonly=on',
                '-fsdev', 'local,id=project,path=/owned-volume/source,security_model=none',
                '-fsdev', 'local,id=owned,path=/owned-volume,security_model=none,readonly=on']
        command = ['python3', 'scripts/benchmark.py', '--profile', 'full', '--concurrency', '1']
        guest_command = ['python3', 'scripts/evidence.py', '--category', 'kvm-reference-benchmark',
                         '--requirements', 'AC-016,AC-017', '--timeout', '100', '--', *command]
        self.record = {'schema_version': 1, 'evidence_type': 'reference_execution', 'format': q.FORMAT,
            'status': 'PASS', 'source': SOURCE, 'concurrency': 1, 'execution_id': EXECUTION,
            'run_context': dict(CONTEXT), 'config': config, 'grid_sha256': q.GRID_SHA,
            'folder': folder, 'inputs': {}, 'cells': []}
        self.docs = {
            'coverage': {'schema_version': 1, 'source': SOURCE, 'profile': 'full', 'config': config,
                'config_hash': cfg_hash, 'provenance': provenance, 'status': 'PASS',
                'expected_cells': 5400, 'completed_cells': 5400, 'missing_cells': [],
                'unexpected_cells': [], 'failed_cells': [], 'run_errors': [], 'limited': False,
                'grid_complete': True, 'reference_host_verified': False, 'reference_recall_target': 'PASS'},
            'provenance': provenance,
            'invocation': {'source': SOURCE, 'status': 'PASS', 'completed_this_invocation': 5400,
                'run_errors': [], 'arguments': {'profile': 'full', 'limit_cells': 0, 'concurrency': 1},
                'started_at': stamp(2), 'ended_at': stamp(8)},
            'start': {'source': SOURCE, 'execution_id': EXECUTION, 'run_context': dict(CONTEXT),
                'profile': 'full', 'concurrency': 1, 'config': config, 'preexisting_full_profiles': [],
                'folder': folder, 'started_at': stamp(1)},
            'guest': {'source': SOURCE, 'execution_id': EXECUTION, 'run_context': dict(CONTEXT),
                'status': 'PASS', 'mode': 'benchmark', 'exit_code': 0, 'command_exit_code': 0,
                'command': guest_command, 'started_at': stamp(0), 'ended_at': stamp(10),
                'host': {'system': 'Linux', 'machine': 'x86_64', 'logical_cpu_count': 4,
                         'physical_ram_bytes': 7_750_000_000}, 'uid': 1001, 'gid': 1001,
                'devtmpfs_before_uid_drop': {'uid': 0, 'capacity_bytes': 1048576},
                'unprivileged_device_controls': 'PASS', 'ram_backed_filesystems': [
                    {'mount': '/dev', 'bytes': 1048576}, {'mount': '/tmp', 'bytes': 16777216},
                    {'mount': '/run', 'bytes': 1048576}],
                'versions': {'go': {'exit_code': 0, 'stdout': 'go version go1.27.3 linux/amd64\n'}},
                'benchmark_folder': folder},
            'setup': {'source': SOURCE, 'execution_id': EXECUTION, 'run_context': dict(CONTEXT),
                'status': 'PASS', 'guest_ram_bytes': 8_000_000_000, 'qemu_command': argv,
                'commands': [{'command': argv, 'exit_code': 0, 'termination_reason': None,
                              'transient_unit': 'synthetic-owned-unit', 'actual_command': ['--collect']}],
                'mount': {'fstype': 'ext4', 'source': '/dev/loop9', 'target': '/owned-volume'}},
            'quota': {'volume_file_bytes': 3_300_000_000, 'oversized_allocation_bytes': 3_400_000_000,
                'oversized_allocation': 'DENIED_ENOSPC', 'hard_quota_enforced': True,
                'run_context': dict(CONTEXT), 'volume_path': '/owned-volume', 'image_path': '/owned-volume.img',
                'mount': {'fstype': 'ext4', 'source': '/dev/loop9', 'target': '/owned-volume'}},
            'enospc': b'SYNTHETIC FORMAT FIXTURE: No space left on device\n',
        }
        report = {'status': 'PASS', 'source': SOURCE, 'profile': 'full', 'concurrency': 1,
            'expected_cells': 5400, 'present_cells': 5400, 'sample_count': 5_400_000,
            'successful_samples': 5_400_000, 'error_calls': 0, 'missing_cells': [], 'unexpected_cells': [],
            'analysis_failed_cells': [], 'baseline_errors': [], 'target_cells': 45, 'target_pass_cells': 45,
            'target_outcome': 'PASS', 'target_status_counts': {'PASS': 45}, 'five_seed_groups': 1080,
            'complete_five_seed_groups': 1080, 'paired_comparison_groups': 972,
            'locked_grid_sha256': q.GRID_SHA,
            'analysis_script_sha256': q.sha((q.ROOT / 'scripts/analyze_reference.py').read_bytes()),
            'created_at': stamp(11), 'method': {'bootstrap_replicates': 2000, 'bootstrap_seed': 20261023}}
        self.docs['analysis'] = report
        self.members = {}
        rows, targets = [], []
        for cid, cell in q.analysis.expected_cells(config).items():
            descriptor = {'id': cid, 'cell': cell, 'sample_count': 1000, 'source': SOURCE,
                'status': 'PASS', 'native_go': 'go1.27.3', 'native_workers': 1, 'native_gomaxprocs': 4,
                'errors': [], 'started_at': stamp(3), 'ended_at': stamp(7),
                'summary_sha256': q.sha(('synthetic-summary-' + cid).encode()),
                'samples_sha256': q.sha(('synthetic-samples-' + cid).encode()),
                'corpus_sha256': 'c' * 64, 'queries_sha256': 'd' * 64, 'generation': 'e' * 64}
            self.record['cells'].append(descriptor)
            for suffix, key in (('.summary.json', 'summary_sha256'), ('.samples.jsonl.gz', 'samples_sha256')):
                self.members[folder + '/' + cid + suffix] = {'original_sha256': descriptor[key]}
            row = {'grid_id': cid, 'analysis_status': 'PASS', 'sample_count': 1000, 'successful_samples': 1000,
                'corpus_sha256': 'c' * 64, 'queries_sha256': 'd' * 64,
                'raw_samples_sha256': descriptor['samples_sha256'], 'mean_recall': 1.0,
                'recall_target_status': 'PASS' if cell['n'] == 10000 and cell['filter_label'] == 'all'
                    and cell['mode'] == 'graph' and cell['ef'] == 128 else 'NOT_TARGET'}
            rows.append(row)
            if row['recall_target_status'] == 'PASS': targets.append(dict(row))
        self.rows, self.targets = rows, targets
        for label, category, cmd in (
                ('guest_receipt', 'kvm-reference-benchmark', command),
                ('analysis_receipt', 'reference-analysis', ['python3', 'scripts/analyze_reference.py', folder,
                    '--grid', 'benchmarks/grid.json', '--expected-source', SOURCE,
                    '--output', '.local/reference-analysis'])):
            self.docs[label] = {'status': 'PASS', 'exit_code': 0, 'termination_reason': None,
                'source_before': SOURCE, 'source_after': SOURCE, 'category': category, 'command': cmd,
                'started_at': stamp(1 if label == 'guest_receipt' else 11),
                'ended_at': stamp(9 if label == 'guest_receipt' else 12), 'commit': COMMIT,
                'environment': {'versions': {'go': 'go version go1.27.3 linux/amd64'}}}
            for stream in ('stdout', 'stderr'):
                name = '.local/evidence/' + label + '/' + stream + '.txt'
                self.docs[label][stream] = name
                self.docs[label][stream + '_sha256'] = q.sha(b'synthetic command output')
                self.members[name] = {'original_sha256': q.sha(b'synthetic command output')}

    def sync(self):
        self.docs['cells_csv'] = csv_bytes(self.rows)
        self.docs['targets_csv'] = csv_bytes(self.targets)
        self.docs['guest']['benchmark_start_sha256'] = q.sha(json_bytes(self.docs['start']))
        self.docs['setup']['guest_result_sha256'] = q.sha(json_bytes(self.docs['guest']))
        self.docs['analysis']['input_coverage_sha256'] = q.sha(json_bytes(self.docs['coverage']))
        self.docs['quota']['enospc_sha256'] = q.sha(self.docs['enospc'])
        inputs = {label: value if isinstance(value, bytes) else json_bytes(value)
                  for label, value in self.docs.items()}
        for label, raw in inputs.items():
            name = '.local/synthetic-proof/' + label
            self.record['inputs'][label] = {'path': name, 'bytes': len(raw), 'sha256': q.sha(raw)}
            self.members[name] = {'original_bytes': len(raw), 'original_sha256': q.sha(raw)}
        return inputs

    def check(self):
        return q.check_inner(self.record, self.sync(), self.members, SOURCE)


class ReferenceProofContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = FullFormatFixture()

    def fixture(self):
        return copy.deepcopy(self.base)

    def test_synthetic_full_descriptor_format_accepts(self):
        proof = self.fixture().check()
        self.assertEqual(proof['concurrency'], 1)
        self.assertEqual(len(proof['cells']), 5400)

    def test_different_guest_session_rejected(self):
        fixture = self.fixture()
        fixture.docs['guest']['execution_id'] = 'f' * 32
        with self.assertRaises(ValueError): fixture.check()

    def test_cell_outside_collector_invocation_rejected(self):
        fixture = self.fixture()
        fixture.record['cells'][0]['started_at'] = stamp(1)
        with self.assertRaises(ValueError): fixture.check()

    def test_wrong_evidenced_collector_command_rejected(self):
        fixture = self.fixture()
        fixture.docs['guest_receipt']['command'] = ['python3', '-c', 'print("not a collector")']
        with self.assertRaises(ValueError): fixture.check()

    def test_receipt_outside_guest_execution_rejected(self):
        fixture = self.fixture()
        fixture.docs['guest_receipt']['ended_at'] = stamp(20)
        with self.assertRaises(ValueError): fixture.check()

    def test_wrong_analysis_input_command_rejected(self):
        fixture = self.fixture()
        fixture.docs['analysis_receipt']['command'][2] = '.local/another-run'
        with self.assertRaises(ValueError): fixture.check()

    def test_nonfinite_or_out_of_range_target_rejected(self):
        for value in ('inf', '1.1', 'nan'):
            fixture = self.fixture()
            fixture.targets[0]['mean_recall'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): fixture.check()

    def test_target_and_cell_csv_disagreement_rejected(self):
        fixture = self.fixture()
        fixture.targets[0]['mean_recall'] = .99
        with self.assertRaises(ValueError): fixture.check()

    def test_quota_from_different_volume_or_run_rejected(self):
        for key, value in (('volume_path', '/another-volume'), ('image_path', '/another-volume.img'),
                           ('mount', {'fstype': 'ext4', 'source': '/dev/loop8', 'target': '/owned-volume'}),
                           ('run_context', {**CONTEXT, 'github_run_id': '999'})):
            fixture = self.fixture()
            fixture.docs['quota'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): fixture.check()


class TinyTransportEnvelope(unittest.TestCase):
    """Real tiny codec roundtrip; the separately tested inner layer is stubbed."""
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        original = cls.root / 'original'
        original.mkdir()
        raw = b'SYNTHETIC proof-format input; not measurements\n'
        execution = {'inputs': {'coverage': {'path': 'original/coverage.json', 'sha256': q.sha(raw),
                                            'bytes': len(raw)}}}
        execution_raw = json_bytes(execution)
        (original / 'coverage.json').write_bytes(raw)
        (original / 'execution.json').write_bytes(execution_raw)
        bundle = cls.root / 'tiny.bundle.xz'
        q.bundle_tool.pack(cls.root, bundle, SOURCE, COMMIT, CONTEXT['github_run_id'], ['original'])
        recovered = cls.root / 'recovered'
        q.bundle_tool.verify(bundle, recovered)
        if (recovered / 'original/coverage.json').read_bytes() != raw:
            raise AssertionError('actual tiny bundle recovery changed bytes')
        curated = cls.root / 'curated'
        curated.mkdir()
        (curated / 'coverage.json').write_bytes(raw)
        (curated / 'execution.json').write_bytes(execution_raw)
        artifact_zip = cls.root / 'tiny-artifact.zip'
        with zipfile.ZipFile(artifact_zip, 'w', compression=zipfile.ZIP_STORED) as archive:
            archive.write(bundle, 'results/reference-members.tar.xz')
        zip_digest = q.bundle_tool.file_sha(artifact_zip)
        zip_size = artifact_zip.stat().st_size
        artifact = {'repo': 'C-X1an/facetquarry', 'run_id': int(CONTEXT['github_run_id']),
            'head_sha': COMMIT, 'expired': False, 'id': 77, 'size_in_bytes': zip_size,
            'digest': 'sha256:' + zip_digest}
        cls.observation = {'observed_at': stamp(30), 'repo': 'C-X1an/facetquarry',
            'jobs': {'jobs': [{'id': 88, 'run_id': int(CONTEXT['github_run_id']),
                              'status': 'completed', 'conclusion': 'success'}]},
            'artifacts': {'artifacts': [{'id': 77, 'size_in_bytes': zip_size, 'expired': False,
                'digest': artifact['digest'], 'workflow_run': {'id': int(CONTEXT['github_run_id']),
                                                             'head_sha': COMMIT}}]}}
        cls.envelope = {'qualification_format': q.FORMAT, 'source': SOURCE, 'status': 'PASS',
            'bundle': {'path': bundle.name, 'bytes': bundle.stat().st_size, 'sha256': q.bundle_tool.file_sha(bundle)},
            'artifact_zip': {'path': artifact_zip.name, 'bytes': zip_size, 'sha256': zip_digest},
            'execution': {'path': 'curated/execution.json', 'sha256': q.sha(execution_raw),
                          'member': 'original/execution.json'},
            'inputs': {'coverage': {'path': 'curated/coverage.json', 'sha256': q.sha(raw),
                                    'member': 'original/coverage.json'}}, 'artifact': artifact}

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def validate(self, envelope=None, observation=None):
        envelope = copy.deepcopy(self.envelope if envelope is None else envelope)
        raw = json_bytes(self.observation if observation is None else observation)
        (self.root / 'artifact-observation.json').write_bytes(raw)
        envelope['artifact_observation'] = {'path': 'artifact-observation.json', 'sha256': q.sha(raw)}
        def checked_inner(record, inputs, members, identity):
            self.assertEqual(identity, SOURCE)
            for label, ref in record['inputs'].items():
                self.assertEqual(q.sha(inputs[label]), members[ref['path']]['original_sha256'])
                self.assertEqual(len(inputs[label]), members[ref['path']]['original_bytes'])
            return {'concurrency': 1, 'run_context': dict(CONTEXT)}
        with patch.object(q, 'check_inner', side_effect=checked_inner) as checked:
            result = q.validate_envelope(envelope, self.root, SOURCE)
            checked.assert_called_once()
            return result

    def test_actual_tiny_bundle_and_curated_bytes_accept(self):
        self.assertEqual(self.validate()['concurrency'], 1)

    def test_artifact_descriptor_requires_matching_observation(self):
        envelope = copy.deepcopy(self.envelope)
        envelope['artifact']['id'] = 78
        with self.assertRaises(ValueError): self.validate(envelope=envelope)

    def test_observed_artifact_commit_and_job_must_match(self):
        observation = copy.deepcopy(self.observation)
        observation['artifacts']['artifacts'][0]['workflow_run']['head_sha'] = 'f' * 40
        with self.assertRaises(ValueError): self.validate(observation=observation)
        observation = copy.deepcopy(self.observation)
        observation['jobs']['jobs'][0]['conclusion'] = 'failure'
        with self.assertRaises(ValueError): self.validate(observation=observation)

    def test_changed_bundle_rejected_before_inner_validation(self):
        envelope = copy.deepcopy(self.envelope)
        envelope['bundle']['sha256'] = '0' * 64
        with self.assertRaises(ValueError): self.validate(envelope=envelope)

    def test_changed_curated_execution_rejected(self):
        envelope = copy.deepcopy(self.envelope)
        envelope['execution']['sha256'] = '0' * 64
        with self.assertRaises(ValueError): self.validate(envelope=envelope)

    def test_artifact_zip_digest_must_match_real_bytes(self):
        envelope = copy.deepcopy(self.envelope)
        envelope['artifact_zip']['sha256'] = '0' * 64
        with self.assertRaises(ValueError): self.validate(envelope=envelope)

    def test_observed_zip_must_contain_the_verified_bundle_bytes(self):
        envelope = copy.deepcopy(self.envelope)
        observation = copy.deepcopy(self.observation)
        wrong_zip = self.root / 'different-artifact.zip'
        with zipfile.ZipFile(wrong_zip, 'w', compression=zipfile.ZIP_STORED) as archive:
            archive.writestr('results/reference-members.tar.xz', b'SYNTHETIC different bundle bytes')
        digest = q.bundle_tool.file_sha(wrong_zip)
        size = wrong_zip.stat().st_size
        envelope['artifact_zip'] = {'path': wrong_zip.name, 'bytes': size, 'sha256': digest}
        envelope['artifact'].update(size_in_bytes=size, digest='sha256:' + digest)
        observation['artifacts']['artifacts'][0].update(size_in_bytes=size, digest='sha256:' + digest)
        with self.assertRaises(ValueError): self.validate(envelope=envelope, observation=observation)


if __name__ == '__main__':
    unittest.main()
