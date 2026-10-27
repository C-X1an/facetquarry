"""Real tiny corpus copies through capture and packet; runner proofs are fixtures."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_capacity as capacity
import reference_capacity_fuzz as fuzz


class CapacityFuzzCapture(unittest.TestCase):
    def setUp(self):
        temporary = Path(__file__).resolve().parents[1] / '.cache/tmp'
        temporary.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=temporary)
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.outer = self.base / 'outer'
        self.volume = self.base / 'facetquarry-capacity'
        self.source = self.volume / 'source'
        (self.outer / '.local').mkdir(parents=True)
        (self.source / '.local').mkdir(parents=True)
        (self.source / '.local/actual-stderr.txt').write_bytes(b'complete available diagnostic\n')
        self.seed = self.source / '.cache/go-build/fuzz/pkg/FuzzQuery/current'
        self.seed.parent.mkdir(parents=True)
        self.data = b'go test fuzz v1\nstring("current tiny fixture")\n'
        self.seed.write_bytes(self.data)
        self.ctx = {'repository': capacity.REPOSITORY, 'repository_id': capacity.REPOSITORY_ID,
                    'commit': 'a' * 40, 'git_status': '', 'source': 'b' * 64,
                    'github_run_id': '12345', 'github_run_attempt': '1',
                    'job': 'reference_capacity', 'profile': capacity.PROFILE}
        self.p = {'outer': self.outer, 'local': self.outer / '.local', 'volume': self.volume,
                  'source': self.source, 'image': self.base / 'facetquarry-capacity.img',
                  'metadata': self.base / 'metadata', 'packet': self.base / 'packet'}
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.dict(os.environ, {'RUNNER_TEMP': str(self.base),
            'GITHUB_WORKSPACE': str(self.outer), 'FQ_ACCOUNTED_BASE_BYTES': '2000000000'}))
        self.stack.enter_context(mock.patch.object(capacity, 'paths', return_value=self.p))
        self.stack.enter_context(mock.patch.object(capacity, 'context', return_value=self.ctx))
        self.stack.enter_context(mock.patch.object(capacity, 'assert_outside_evidence_wrapper'))
        self.stack.enter_context(mock.patch.object(capacity, 'stage_quiescence', return_value={
            'quiescent': True, 'execution_complete': True, 'active_volume_processes': []}))
        self.stack.enter_context(mock.patch.object(capacity, 'observe_mount', return_value=None))
        self.stack.enter_context(mock.patch.object(capacity, 'observe_loops', return_value=[]))
        capacity.write(self.p['local'] / 'capacity-unmount.json', {
            'status': 'PASS', 'run_context': self.ctx, 'image_unmounted': True})

    def test_current_corpus_bytes_manifest_and_run_proof_survive_complete_packet(self):
        captured = capacity.capture(self.outer)
        self.assertEqual(captured['status'], 'PASS', captured)
        proof = captured['fuzz_retention']
        self.assertEqual(proof['count'], 1)
        self.assertTrue(proof['corpus_observed'])
        self.assertFalse(proof['campaign_qualified'])
        self.assertEqual(proof['run_context'], self.ctx)
        self.assertEqual(self.seed.read_bytes(), self.data)
        result = capacity.packet(self.outer)
        self.assertEqual(result['status'], 'PASS', result)
        self.assertTrue(result['metadata_allowed'])
        self.assertEqual(result['fuzz_retention']['manifest_sha256'], proof['manifest_sha256'])
        manifest = capacity.load(self.p['metadata'] / 'volume-manifest.json')
        rows = {row['source_path']: row for row in manifest['files']}
        retained = rows['reference-capacity-fuzz/cache/pkg/FuzzQuery/current']
        with zipfile.ZipFile(result['packet_path']) as archive:
            data = archive.read('metadata/volume/' + retained['copy'])
            self.assertEqual(data, self.data)
            self.assertEqual(hashlib.sha256(data).hexdigest(), retained['sha256'])

    def test_fuzz_failure_keeps_available_diagnostics_and_cannot_report_packet_pass(self):
        with mock.patch.object(fuzz, 'preserve', side_effect=ValueError('injected complete corpus refusal')):
            captured = capacity.capture(self.outer)
        self.assertEqual(captured['status'], 'FAIL')
        self.assertTrue(captured['complete_local_retention'])
        self.assertEqual(captured['fuzz_retention']['status'], 'FAIL')
        self.assertIn('injected complete corpus refusal', captured['fuzz_retention']['error'])
        result = capacity.packet(self.outer)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['metadata_allowed'], result)
        self.assertTrue(result['complete_local_retention'])
        exported = capacity.load(self.p['metadata'] / 'volume-manifest.json')
        row = next(row for row in exported['files'] if row['source_path'] == 'actual-stderr.txt')
        with zipfile.ZipFile(result['packet_path']) as archive:
            self.assertEqual(archive.read('metadata/volume/' + row['copy']), b'complete available diagnostic\n')
            packet = json.loads(archive.read('packet-manifest.json'))
            self.assertEqual(packet['status'], 'FAIL')
            self.assertTrue(any('fuzz retention' in reason for reason in packet['failure_reasons']))

    def test_absent_current_capture_proof_cannot_turn_complete_local_into_fuzz_success(self):
        captured = capacity.capture(self.outer)
        self.assertEqual(captured['status'], 'PASS', captured)
        (self.p['local'] / 'capacity-capture.json').unlink()
        result = capacity.packet(self.outer)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['metadata_allowed'], result)
        self.assertEqual(result['fuzz_retention']['status'], 'FAIL')

    def test_late_retained_corpus_tamper_refuses_but_preserves_failure_packet(self):
        captured = capacity.capture(self.outer)
        self.assertEqual(captured['status'], 'PASS', captured)
        exported = capacity.load(self.p['metadata'] / 'volume-manifest.json')
        row = next(row for row in exported['files'] if row['source_path'].endswith('/FuzzQuery/current'))
        (self.p['metadata'] / 'volume' / row['copy']).write_bytes(b'changed')
        result = capacity.packet(self.outer)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['metadata_allowed'], result)
        self.assertFalse(result['complete_local_retention'])
        self.assertEqual(result['fuzz_retention']['status'], 'FAIL')

    def test_null_corpus_proof_still_retains_an_admitted_failure_packet(self):
        captured = capacity.capture(self.outer)
        self.assertEqual(captured['status'], 'PASS', captured)
        captured['fuzz_retention'] = None
        (self.p['local'] / 'capacity-capture.json').write_text(json.dumps(captured))
        result = capacity.packet(self.outer)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['metadata_allowed'], result)
        self.assertEqual(result['fuzz_retention']['status'], 'FAIL')

    def test_nonobject_capture_still_retains_an_admitted_failure_packet(self):
        captured = capacity.capture(self.outer)
        self.assertEqual(captured['status'], 'PASS', captured)
        (self.p['local'] / 'capacity-capture.json').write_text('[]\n')
        result = capacity.packet(self.outer)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['metadata_allowed'], result)
        self.assertEqual(result['fuzz_retention']['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
