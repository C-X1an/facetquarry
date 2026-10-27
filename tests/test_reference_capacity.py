"""Tiny real-copy and refusal controls; none emulate live runner quota proof."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_capacity as capacity


def synthetic_environment():
    return {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': capacity.REPOSITORY,
            'GITHUB_REPOSITORY_ID': str(capacity.REPOSITORY_ID),
            'GITHUB_JOB': 'reference_capacity', 'FQ_RESERVATION_PROFILE': capacity.PROFILE,
            'GITHUB_RUN_ID': '12345', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40}


def synthetic_context():
    return capacity.bind_context(synthetic_environment(), 'a' * 40, '', 'b' * 64, True)


class CapacityAdmission(unittest.TestCase):
    def test_exact_new_reservation_and_strict_global_boundary(self):
        maximum = 2_345_000_000
        boundary = capacity.CEILING - maximum
        admitted = capacity.growth_plan(boundary - 1)
        self.assertEqual(sum(admitted['reservations'].values()), maximum)
        self.assertEqual(admitted['maximum_new_stage_bytes'], maximum)
        self.assertEqual(admitted['peak_bytes'], 11_999_999_999)
        self.assertEqual(admitted['admission'], 'ALLOW')
        self.assertTrue(all(branch == maximum for branch in admitted['branches'].values()))
        self.assertEqual(capacity.growth_plan(boundary)['admission'], 'REFUSE')
        self.assertFalse(admitted['data_upload_allowed'])
        for value in (True, 1_999_999_999, -1, 2_000_000_000.0, '2000000000'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                capacity.growth_plan(value)

    def test_context_binds_each_execution_and_source_field(self):
        env = synthetic_environment()
        ctx = synthetic_context()
        self.assertEqual(ctx['repository_id'], 1430604581)
        self.assertEqual(ctx['source'], 'b' * 64)
        self.assertEqual(ctx['git_status'], '')
        for field, value in [('GITHUB_ACTIONS', 'false'), ('GITHUB_REPOSITORY', 'other/repo'),
                             ('GITHUB_REPOSITORY_ID', '1430604582'), ('GITHUB_JOB', 'reference'),
                             ('FQ_RESERVATION_PROFILE', 'unknown'), ('GITHUB_RUN_ID', '0'),
                             ('GITHUB_RUN_ATTEMPT', '2\n'), ('GITHUB_SHA', 'c' * 40)]:
            changed = {**env, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                capacity.bind_context(changed, 'a' * 40, '', 'b' * 64, True)
        for commit, dirty, digest, ordinary in [('c' * 40, '', 'b' * 64, True),
                                               ('a' * 40, ' M x', 'b' * 64, True),
                                               ('a' * 40, '', 'x' * 64, True),
                                               ('a' * 40, '', 'b' * 64, False)]:
            with self.subTest(commit=commit, dirty=dirty, ordinary=ordinary), self.assertRaises(ValueError):
                capacity.bind_context(env, commit, dirty, digest, ordinary)

    def test_actual_external_originals_and_packet_residual_are_counted(self):
        admitted = capacity.actual_admission(8_000_000_000, 2_000_000_000, 200_000_000, 50_000_000)
        self.assertTrue(admitted['metadata_allowed'])
        self.assertFalse(admitted['data_allowed'])
        self.assertEqual(admitted['actual_global_peak_bytes'], 10_345_000_000)
        for image, metadata, packet in [(2_000_004_097, 1, 1), (1, 200_000_001, 1),
                                        (1, 1, 50_000_001)]:
            self.assertFalse(capacity.actual_admission(8_000_000_000, image, metadata, packet)['metadata_allowed'])
        boundary = capacity.CEILING - 2_345_000_000
        self.assertTrue(capacity.actual_admission(boundary, 0, 0, 0)['metadata_allowed'])
        self.assertFalse(capacity.actual_admission(boundary, capacity.IMAGE_BYTES,
                                                  capacity.EXTERNAL_METADATA, 0)['metadata_allowed'])

    def test_only_unchanged_commands_and_exact_evidence_deadlines_are_allowed(self):
        for command, timeout in capacity.STAGES.items():
            capacity.stage_contract(list(command), timeout)
            with self.assertRaises(ValueError):
                capacity.stage_contract(list(command), timeout - 1)
        for command in (['make', 'benchmark'], ['make', 'verify', 'SKIP_RACE=1'],
                        ['go', 'install', 'golang.org/x/vuln/cmd/govulncheck@latest']):
            with self.subTest(command=command), self.assertRaises(ValueError):
                capacity.stage_contract(command, 120)

    def test_sample_summary_identifies_sampled_maximum_and_errors_only(self):
        rows = [{'filesystem_available_bytes': 80, 'filesystem_used_bytes': 20,
                 'image_allocated_bytes': 100},
                {'filesystem_available_bytes': 70, 'filesystem_used_bytes': 30,
                 'image_allocated_bytes': 120}, {'filesystem_error': 'fixture observation error'}]
        result = capacity.summarize_samples(rows)
        self.assertEqual(result['sampled_min_filesystem_available_bytes'], 70)
        self.assertEqual(result['sampled_max_filesystem_used_bytes'], 30)
        self.assertEqual(result['sampled_max_image_allocated_bytes'], 120)
        self.assertEqual(result['observation_errors'], 1)
        self.assertFalse(result['quota_enforcement'])
        self.assertIn('not a continuous maximum', result['scope'])

    def test_process_identity_parser_handles_spaces_and_parentheses(self):
        tail = ['S', '77'] + ['0'] * 17 + ['987654'] + ['0'] * 4
        result = capacity.parse_process_stat('123 (a process (with) spaces) ' + ' '.join(tail))
        self.assertEqual(result, {'pid': 123, 'state': 'S', 'ppid': 77, 'start_time_ticks': 987654})
        for raw in ('', '123 invalid', '123 (a) S 1'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                capacity.parse_process_stat(raw)


class CapacityCompleteFiles(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[1] / '.cache/capacity-tests'
        cache.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=cache)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / 'source/.local'
        self.source.mkdir(parents=True)
        self.metadata = self.base / 'metadata'
        self.metadata.mkdir()
        self.ctx = synthetic_context()

    def export(self, kind='volume', source=None):
        return capacity.export_tree(source or self.source, self.metadata / kind, kind, self.ctx)

    def packet_inputs(self):
        (self.source / 'first.json').write_bytes(b'{"real_fixture":1}\n')
        self.export()
        outer = self.base / 'outer/.local'
        outer.mkdir(parents=True)
        (outer / 'receipt.json').write_bytes(b'{"status":"FAIL"}\n')
        self.export('outer', outer)

    def test_whole_local_capture_includes_unlisted_hidden_files_without_reduction(self):
        nested = self.source / '.hidden/unlisted'
        nested.mkdir(parents=True)
        data = b'actual small bytes\x00\xff'
        (nested / 'anything.bin').write_bytes(data)
        (self.source / 'empty').write_bytes(b'')
        result = self.export()
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['enumeration_complete'])
        self.assertTrue(result['complete_local_retention'])
        entries = {entry['source_path']: entry for entry in result['files']}
        row = entries['.hidden/unlisted/anything.bin']
        self.assertEqual((self.metadata / 'volume' / row['copy']).read_bytes(), data)
        self.assertEqual(row['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(row['source_identity'], list(capacity.bundle.signature((nested / 'anything.bin').lstat())))
        self.assertTrue(all(entry['transformation'] == 'identity' for entry in entries.values()))
        self.assertIn('.hidden/unlisted', {entry['source_path'] for entry in result['directories']})
        self.assertEqual(capacity.verify_export(self.metadata, 'volume', self.ctx), result)

    def test_total_byte_refusal_keeps_bounded_complete_partial_copies_and_originals(self):
        (self.source / 'a').write_bytes(b'a' * 6)
        (self.source / 'b').write_bytes(b'b' * 6)
        with mock.patch.object(capacity, 'COPY_BYTES', 10):
            result = self.export()
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['enumeration_complete'])
        self.assertFalse(result['complete_local_retention'])
        self.assertEqual(result['logical_bytes'], 6)
        self.assertEqual((self.metadata / 'volume/000000.bin').read_bytes(), b'a' * 6)
        self.assertEqual((self.source / 'b').read_bytes(), b'b' * 6)
        self.assertIn('logical or file-count', result['error'])

    def test_count_and_external_allocation_refusals_do_not_silently_omit(self):
        (self.source / 'a').write_bytes(b'a')
        (self.source / 'b').write_bytes(b'b')
        with mock.patch.object(capacity, 'COPY_FILES', 1):
            result = self.export()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['copied_files'], 1)
        with self.assertRaisesRegex(ValueError, 'manifest reservation'):
            capacity.export_tree(self.source, self.metadata / 'outer', 'outer', self.ctx,
                                 capacity.EXTERNAL_METADATA - 1)
        self.assertFalse((self.metadata / 'outer').exists())

    def test_single_file_over_bound_is_refused_without_prefix(self):
        (self.source / 'large').write_bytes(b'complete-original')
        with mock.patch.object(capacity, 'COPY_BYTES', 3):
            result = self.export()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['files'], [])
        self.assertEqual(list((self.metadata / 'volume').iterdir()), [])
        self.assertEqual((self.source / 'large').read_bytes(), b'complete-original')

    def test_mutated_source_between_descriptor_read_and_copy_is_refused(self):
        original = self.source / 'file'
        original.write_bytes(b'original')
        reader = capacity.artifacts.read_metadata

        def changed(path, info, count):
            result = reader(path, info, count)
            if path == original:
                original.write_bytes(b'MUTATION')
            return result

        with mock.patch.object(capacity.artifacts, 'read_metadata', side_effect=changed):
            result = self.export()
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('changed after read', result['error'])
        self.assertEqual(result['files'], [])

    def test_retained_copy_tamper_and_prior_attempt_manifest_are_refused(self):
        (self.source / 'file').write_bytes(b'original')
        result = self.export()
        copy_path = self.metadata / 'volume' / result['files'][0]['copy']
        copy_path.write_bytes(b'MUTATION')
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            capacity.verify_export(self.metadata, 'volume', self.ctx)
        other = {**self.ctx, 'github_run_attempt': '2'}
        with self.assertRaisesRegex(ValueError, 'execution identity'):
            capacity.verify_export(self.metadata, 'volume', other)

    def test_links_are_refused_and_never_copied(self):
        original = self.source / 'a'
        original.write_bytes(b'original')
        try:
            os.link(original, self.source / 'hardlink')
        except OSError as error:
            self.skipTest('filesystem does not support hardlink fixture: ' + str(error))
        result = self.export()
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('hardlinks', result['error'])
        self.assertEqual(result['files'], [])
        with self.assertRaisesRegex(ValueError, 'hardlinked'):
            capacity.physical(self.source)

    def test_source_destination_overlap_and_existing_exports_are_refused(self):
        with self.assertRaisesRegex(ValueError, 'overlap'):
            capacity.export_tree(self.source, self.source / 'recursive', 'volume', self.ctx)
        self.assertFalse((self.source / 'recursive').exists())
        self.export()
        with self.assertRaisesRegex(ValueError, 'existing complete'):
            self.export()

    def test_missing_partial_setup_is_explicit_and_available_diagnostics_can_be_packed(self):
        missing = self.base / 'unavailable/.local'
        result = self.export(source=missing)
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['complete_local_retention'])
        self.assertEqual(result['files'], [])
        (self.source / 'actual-failure.txt').write_bytes(b'available setup failure\n')
        self.export('outer')
        output, manifest, proof = capacity.make_packet(self.metadata, self.base / 'packet', self.ctx)
        self.assertEqual(manifest['status'], 'FAIL')
        self.assertFalse(manifest['complete_local_retention'])
        self.assertTrue(proof['all_entries_crc_sha_identity_checked'])
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read('metadata/outer/000000.bin'), b'available setup failure\n')

    def test_complete_packet_checks_every_copy_manifest_member_mode_crc_and_sha(self):
        self.packet_inputs()
        output, manifest, proof = capacity.make_packet(self.metadata, self.base / 'packet', self.ctx)
        self.assertTrue(manifest['complete_local_retention'])
        self.assertFalse(manifest['execution_complete'])
        self.assertEqual(manifest['status'], 'FAIL')  # Files alone do not prove commands passed.
        self.assertTrue(proof['all_entries_crc_sha_identity_checked'])
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(len(archive.infolist()), len(manifest['members']) + 1)
            self.assertEqual(json.loads(archive.read('packet-manifest.json')), manifest)
            for row in manifest['members']:
                self.assertEqual(hashlib.sha256(archive.read(row['member'])).hexdigest(), row['sha256'])
                self.assertEqual(archive.getinfo(row['member']).external_attr >> 16, row['mode'])
        expected = {row['member']: row for row in manifest['members']}
        raw = capacity.encode(manifest)
        expected['packet-manifest.json'] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                                          'mode': stat.S_IFREG | 0o600}
        wrong = copy.deepcopy(expected)
        wrong[manifest['members'][0]['member']]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'SHA or CRC'):
            capacity.verify_zip(output, wrong, manifest)
        wrong = copy.deepcopy(expected)
        wrong[manifest['members'][0]['member']]['mode'] ^= 0o100
        with self.assertRaisesRegex(ValueError, 'full member identity'):
            capacity.verify_zip(output, wrong, manifest)

    def test_zip_hard_bound_keeps_partial_file_and_never_creates_a_second_copy(self):
        self.packet_inputs()
        destination = self.base / 'packet'
        with mock.patch.object(capacity, 'ZIP_BYTES', 100):
            with self.assertRaisesRegex(ValueError, 'hard byte bound'):
                capacity.make_packet(self.metadata, destination, self.ctx)
        self.assertEqual({path.name for path in destination.iterdir()}, {'capacity-metadata.zip'})
        self.assertLessEqual((destination / 'capacity-metadata.zip').stat().st_size, 100)

    def test_workflow_never_outputs_packet_path_until_actual_metadata_admission(self):
        output = self.base / 'workflow-output'
        with mock.patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}):
            capacity.workflow_outputs({'metadata_allowed': False, 'packet_path': 'must-not-be-emitted'})
        text = output.read_text()
        self.assertIn('metadata_allowed=false\n', text)
        self.assertIn('data_upload_allowed=false\n', text)
        self.assertNotIn('packet_path=', text)

    def test_shared_packet_byte_limit_includes_both_namespaces_and_manifests(self):
        (self.source / 'one').write_bytes(b'a' * 6000)
        self.export()
        outer = self.base / 'outer/.local'; outer.mkdir(parents=True)
        (outer / 'two').write_bytes(b'b' * 6000)
        self.export('outer', outer)
        with mock.patch.object(capacity, 'COPY_BYTES', 10000):
            with self.assertRaisesRegex(ValueError, 'aggregate'):
                capacity.make_packet(self.metadata, self.base / 'packet', self.ctx)

    def test_shared_packet_file_limit_includes_proof_manifests(self):
        self.packet_inputs()
        # Two payloads + two export manifests + packet manifest cannot fit4.
        with mock.patch.object(capacity, 'COPY_FILES', 4):
            with self.assertRaisesRegex(ValueError, 'aggregate'):
                capacity.make_packet(self.metadata, self.base / 'packet', self.ctx)

    def test_failed_quiescence_still_observes_exact_mount_for_cleanup(self):
        p = {'outer': self.base, 'local': self.source, 'volume': self.base / 'volume',
             'source': self.base / 'volume/source', 'image': self.base / 'volume.img',
             'metadata': self.metadata, 'packet': self.base / 'packet'}
        with mock.patch.object(capacity, 'paths', return_value=p), \
             mock.patch.object(capacity, 'context', return_value=self.ctx), \
             mock.patch.object(capacity, 'stage_quiescence', side_effect=ValueError('fixture failed descendant proof')), \
             mock.patch.object(capacity, 'observe_mount', return_value=None) as observed, \
             mock.patch.object(capacity, 'observe_loops', return_value=[]):
            result = capacity.unmount(self.base)
        self.assertTrue(observed.called)
        self.assertTrue(result['image_unmounted'])
        self.assertEqual(result['status'], 'FAIL')

    def test_cleanup_failure_keeps_admitted_outer_failure_diagnostics(self):
        (self.source / 'actual-failure.txt').write_bytes(b'actual unit-fixture failure bytes\n')
        p = {'outer': self.base, 'local': self.source, 'volume': self.base / 'volume',
             'source': self.base / 'volume/source', 'image': self.base / 'volume.img',
             'metadata': self.metadata, 'packet': self.base / 'packet'}
        with mock.patch.object(capacity, 'paths', return_value=p), \
             mock.patch.object(capacity, 'context', return_value=self.ctx), \
             mock.patch.object(capacity, 'assert_outside_evidence_wrapper'), \
             mock.patch.object(capacity, 'stage_quiescence', side_effect=ValueError('fixture failed descendant proof')), \
             mock.patch.object(capacity, 'observe_mount', return_value=None), \
             mock.patch.object(capacity, 'observe_loops', return_value=[]), \
             mock.patch.dict(os.environ, {'FQ_ACCOUNTED_BASE_BYTES':'2000000000'}):
            result = capacity.packet(self.base)
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['complete_local_retention'])
        self.assertTrue(result['metadata_allowed'], result)
        with zipfile.ZipFile(result['packet_path']) as archive:
            self.assertEqual(archive.read('metadata/outer/000000.bin'), b'actual unit-fixture failure bytes\n')

    def test_interrupted_stage_cannot_supply_a_quiet_volume_claim(self):
        control = self.source / 'capacity-control'; control.mkdir()
        capacity.write(control / 'verify-start.json', {
            'kind':'capacity_stage_start', 'profile':capacity.PROFILE, 'name':'verify',
            'run_context':self.ctx, 'command':['make','verify'], 'timeout_seconds':780,
            'started_at':'synthetic-start', 'status':'RUNNING'})
        p = {'local':self.source, 'volume':self.base / 'volume'}
        with mock.patch.object(capacity, 'active_volume_processes', return_value=[]):
            with self.assertRaisesRegex(ValueError, 'no matching terminal'):
                capacity.stage_quiescence(p, self.ctx)

    def test_interrupted_volume_copy_does_not_suppress_outer_failure_packet(self):
        (self.source / 'actual-failure.txt').write_bytes(b'outer failure retained\n')
        volume = self.metadata / 'volume'; volume.mkdir()
        (volume / '000000.bin').write_bytes(b'partial interrupted copy')
        p = {'outer':self.base, 'local':self.source, 'volume':self.base / 'volume',
             'source':self.base / 'volume/source', 'image':self.base / 'volume.img',
             'metadata':self.metadata, 'packet':self.base / 'packet'}
        with mock.patch.object(capacity, 'paths', return_value=p), \
             mock.patch.object(capacity, 'context', return_value=self.ctx), \
             mock.patch.object(capacity, 'assert_outside_evidence_wrapper'), \
             mock.patch.object(capacity, 'stage_quiescence', side_effect=ValueError('interrupted stage fixture')), \
             mock.patch.object(capacity, 'observe_mount', return_value=None), \
             mock.patch.object(capacity, 'observe_loops', return_value=[]), \
             mock.patch.dict(os.environ, {'FQ_ACCOUNTED_BASE_BYTES':'2000000000'}):
            result = capacity.packet(self.base)
        self.assertTrue(result['metadata_allowed'], result)
        self.assertFalse(result['complete_local_retention'])
        self.assertEqual(result['status'], 'FAIL')
        with zipfile.ZipFile(result['packet_path']) as archive:
            self.assertEqual(archive.read('metadata/volume/000000.bin'), b'partial interrupted copy')
            self.assertEqual(archive.read('metadata/outer/000000.bin'), b'outer failure retained\n')

    def test_real_binary_above_one_megabyte_survives_complete_export_and_zip(self):
        data = bytes(range(256)) * 5000
        (self.source / 'large.bin').write_bytes(data)
        exported = self.export()
        outer = self.base / 'outer/.local'; outer.mkdir(parents=True)
        self.export('outer', outer)
        output, manifest, proof = capacity.make_packet(self.metadata, self.base / 'packet', self.ctx)
        self.assertTrue(manifest['complete_local_retention'])
        self.assertEqual(exported['logical_bytes'], 1_280_000)
        with zipfile.ZipFile(output) as archive:
            self.assertEqual(archive.read('metadata/volume/000000.bin'), data)

    def test_shared_capture_preallocation_reserves_both_export_and_packet_proofs(self):
        (self.source / 'one').write_bytes(b'a' * 20000)
        outer = self.base / 'outer/.local'; outer.mkdir(parents=True)
        (outer / 'two').write_bytes(b'b' * 20000)
        with mock.patch.object(capacity, 'CAPTURE_BYTES', 50000), \
             mock.patch.object(capacity, 'MANIFEST_BYTES', 6000):
            first = self.export()
            second = self.export('outer', outer)
        self.assertTrue(first['complete_local_retention'])
        self.assertFalse(second['complete_local_retention'])
        self.assertIn('aggregate complete-copy', second['error'])
        self.assertEqual((outer / 'two').read_bytes(), b'b' * 20000)

    @unittest.skipUnless(sys.platform == 'linux', 'actual isolated Linux subreaper/adoption control runs on supported runner')
    def test_actual_detached_grandchild_is_reaped_and_unrelated_process_survives(self):
        code = r'''import json,subprocess,sys,time
sys.path.insert(0,sys.argv[1])
import reference_capacity as c
c.enable_subreaper()
parent = subprocess.Popen([sys.executable,'-c',
    'import os,time\npid=os.fork()\nif pid==0:\n os.setsid()\n time.sleep(30)\n os._exit(0)\nos._exit(0)'])
parent.wait(timeout=5)
deadline=time.monotonic()+2
adopted=[]
while time.monotonic()<deadline:
 adopted=c.children(__import__('os').getpid())
 if adopted: break
 time.sleep(.02)
assert len(adopted)==1, adopted
proof=c.quiesce_children()
assert proof['quiescent'] and proof['signals'] and not proof['residual'], proof
assert adopted[0]['pid'] in [r['pid'] for r in proof['reaped']], proof
print(json.dumps(proof))
'''
        unrelated = subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])
        try:
            result = subprocess.run([sys.executable,'-c',code,str(Path(capacity.__file__).parent)],
                                    capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertTrue(json.loads(result.stdout)['quiescent'])
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate(); unrelated.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
