"""Real bounded file copies and refusal paths; no hosted-runner claim."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_pipeline as pipeline


class ReferencePipeline(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[1] / '.cache/pipeline-tests'
        cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=cache); self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).absolute()
        self.root, self.volume = self.base / 'original', self.base / 'facetquarry-reference'
        self.local = self.root / '.local'; self.local.mkdir(parents=True)
        (self.volume / 'source/.local').mkdir(parents=True)
        self.env = patch.dict(os.environ, {'FQ_ACCOUNTED_BASE_BYTES': '7623223381',
            'GITHUB_RUN_ID': '40132496594', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40,
            'RUNNER_TEMP': str(self.base),
            'GITHUB_OUTPUT': str(self.base / 'workflow-output')})
        self.env.start(); self.addCleanup(self.env.stop)

    def test_failure_peak_includes_partial_package_and_mutually_exclusive_image(self):
        plan = pipeline.admission(7_623_223_381, 2_300_000_000, 435_000_000, 1_101_000_000)
        self.assertEqual(plan['scientific_peak_bytes'], 11_604_223_381)
        self.assertTrue(plan['metadata_allowed']); self.assertTrue(plan['data_allowed'])

    def test_initial_scientific_refusal_does_not_suppress_small_actual_metadata(self):
        plan = pipeline.admission(8_200_000_000, 0, 100_000, 0)
        self.assertEqual(plan['initial_scientific_admission'], 'REFUSE')
        self.assertTrue(plan['metadata_allowed']); self.assertFalse(plan['data_allowed'])

    def test_actual_physical_block_allocation_is_counted_without_false_refusal(self):
        plan = pipeline.admission(7_623_223_381, 2_300_000_000, 500_000_000, 1_101_000_000)
        self.assertTrue(plan['metadata_allowed']); self.assertTrue(plan['data_allowed'])
        self.assertEqual(plan['metadata_peak_bytes'], 10_568_223_381)
        self.assertFalse(pipeline.admission(11_900_000_000, 0, 0, 0)['metadata_allowed'])

    def test_missing_or_invalid_scientific_package_still_exposes_metadata_output(self):
        result = pipeline.admit_uploads(self.volume, True, self.root)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['metadata_allowed']); self.assertFalse(result['data_allowed'])
        self.assertIn('metadata_allowed=true', (self.base / 'workflow-output').read_text())
        self.assertTrue((self.local / 'reference-upload-admission.json').is_file())

    def test_external_host_diagnostics_survive_refused_child_copy(self):
        source = self.volume / 'reference-guest'; source.mkdir()
        raw = b'{"status":"FAIL","real_fixture":true}\n'
        (source / 'setup.json').write_bytes(raw)
        child = self.volume / 'source/.local/reference-guest-setup/setup.json'
        child.mkdir(parents=True)  # Real destination-type failure, no mock I/O.
        result = pipeline.diagnostics(self.volume, self.root)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual((self.local / 'reference-metadata/reference-guest-setup/setup.json').read_bytes(), raw)
        self.assertIn('existing diagnostic copy differs', result['errors'][0])

    def test_setup_precedes_capped_command_logs_and_still_permits_guest_identity_proof(self):
        import reference_results as results
        source = self.volume / 'reference-guest'; (source / 'commands').mkdir(parents=True)
        context = {'commit': 'a' * 40, 'git_status': '', 'github_run_id': '40132496594', 'github_run_attempt': '1'}
        raw = json.dumps({'source': 'current', 'run_context': context, 'status': 'FAIL', 'commands': []}).encode()
        (source / 'setup.json').write_bytes(raw)
        (source / 'commands/one.log').write_bytes(b'a' * 150)
        (source / 'commands/two.log').write_bytes(b'b' * 150)
        (self.volume / 'source/.local/reference-guest-setup/setup.json').mkdir(parents=True)
        with patch.object(pipeline, 'COPY_BYTES', len(raw) + 200):
            result = pipeline.diagnostics(self.volume, self.root)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual((self.local / 'reference-metadata/reference-guest-setup/setup.json').read_bytes(), raw)
        with patch.dict(os.environ, {'GITHUB_WORKSPACE': str(self.root)}):
            proof = results.assert_no_active_guest(self.volume, self.volume / 'source',
                {'source': 'current', 'run_context': context},
                lambda *args, **kwargs: self.fail('no guest units exist in this real-file fixture'))
        self.assertEqual(proof['guest_setup_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertTrue(any('cumulative admission' in message for message in result['errors']), result['errors'])

    def test_stale_freeze_pass_cannot_admit_currently_mounted_image(self):
        image = self.volume / 'reference-results.img'; image.write_bytes(b'no capacity claim')
        frozen = {'status': 'PASS', 'image_unmounted': True,
            'source': pipeline.source_hash(self.root), 'run_context': {'commit': 'a' * 40,
            'git_status': '', 'github_run_id': '40132496594', 'github_run_attempt': '1'}}
        (self.volume / 'reference-results-freeze.json').write_text(json.dumps(frozen))
        with patch.object(pipeline.os.path, 'ismount', return_value=True):
            result = pipeline.admit_uploads(self.volume, False, self.root)
        self.assertFalse(result['data_allowed']); self.assertTrue(result['metadata_allowed'])
        self.assertIn('still mounted after freeze/recovery', result['error'])

    def test_maximum_reserved_physical_originals_preserve_failure_branch(self):
        from reference_artifacts import PACKAGE_ALLOCATION, EXTERNAL_METADATA_ALLOCATION
        plan = pipeline.admission(7_623_223_381, 2_300_000_000,
            PACKAGE_ALLOCATION + EXTERNAL_METADATA_ALLOCATION, 1_101_000_000)
        self.assertTrue(plan['data_allowed'])
        self.assertEqual(plan['scientific_peak_bytes'], 11_770_223_381)

    def test_prior_attempt_frozen_image_is_rejected_before_any_image_read(self):
        frozen = {'status': 'PASS', 'image_unmounted': True,
            'source': pipeline.source_hash(self.root), 'run_context': {'commit': 'a' * 40,
            'git_status': '', 'github_run_id': '40132496594', 'github_run_attempt': '2'}}
        (self.volume / 'reference-results-freeze.json').write_text(json.dumps(frozen))
        result = pipeline.admit_uploads(self.volume, False, self.root)
        self.assertFalse(result['data_allowed']); self.assertTrue(result['metadata_allowed'])
        self.assertIn('freeze is not this execution', result['error'])

    def test_prior_attempt_package_is_rejected_even_with_same_commit_and_run(self):
        transport = self.local / 'reference-transport'; transport.mkdir()
        (transport / 'reference-members.tar.xz').write_bytes(b'synthetic proof refusal only')
        (transport / 'pack-attempt.json').write_text(json.dumps({'status': 'PASS',
            'originals_unchanged': True, 'source': pipeline.source_hash(self.root),
            'commit': 'a' * 40, 'run_id': '40132496594', 'run_attempt': '2'}))
        result = pipeline.admit_uploads(self.volume, True, self.root)
        self.assertFalse(result['data_allowed']); self.assertTrue(result['metadata_allowed'])
        self.assertIn('packaging branch identity differs', result['error'])

    def test_early_enospc_stderr_is_retained_before_source_setup(self):
        raw = b'fallocate: fallocate failed: No space left on device\n'
        (self.base / 'facetquarry-reference-enospc.stderr').write_bytes(raw)
        pipeline.final_state(self.volume, self.root)
        self.assertEqual((self.local / 'reference-enospc.stderr').read_bytes(), raw)

    def test_cumulative_budget_counts_existing_other_operation_copies(self):
        output = self.local / 'reference-metadata'; output.mkdir()
        (output / 'earlier').write_bytes(b'a' * 15)
        source = self.base / 'new'; source.write_bytes(b'b' * 10)
        with patch.object(pipeline, 'COPY_BYTES', 20):
            budget = pipeline.copy_budget(output)
            with self.assertRaisesRegex(ValueError, 'cumulative admission'):
                pipeline.copy_one(source, output / 'later', budget)
        self.assertFalse((output / 'later').exists())
        self.assertEqual((output / 'earlier').read_bytes(), b'a' * 15)

    def test_refused_copy_allocates_no_parent_and_external_exports_stay_flat(self):
        output = self.local / 'reference-metadata'; output.mkdir()
        source = self.base / 'new'; source.write_bytes(b'x' * 10)
        budget = pipeline.copy_budget(output)
        with self.assertRaisesRegex(ValueError, 'fixed flat directories'):
            pipeline.copy_one(source, output / 'unexpected/deep/file', budget)
        self.assertFalse((output / 'unexpected').exists())
        with patch.object(pipeline, 'COPY_BYTES', 8):
            with self.assertRaisesRegex(ValueError, 'complete-copy admission'):
                pipeline.copy_one(source, output / 'files/new', budget)
        self.assertFalse((output / 'files').exists())

    def test_complete_copy_hashes_and_refuses_changed_existing_original(self):
        source = self.base / 'source'; target = self.local / 'copy'
        source.write_bytes(b'original\x00bytes')
        budget = {'files': 0, 'bytes': 0}
        item = pipeline.copy_one(source, target, budget)
        self.assertEqual(item['sha256'], hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual(budget, {'files': 1, 'bytes': len(b'original\x00bytes')})
        pipeline.copy_one(source, target, budget)
        self.assertEqual(budget['files'], 1)
        source.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'existing diagnostic copy differs'):
            pipeline.copy_one(source, target, budget)
        self.assertEqual(target.read_bytes(), b'original\x00bytes')

    def test_export_retains_actual_failure_receipt_and_original_under_small_cap(self):
        source = self.volume / 'source/.local/reference-progress.json'
        source.write_bytes(b'{"phase":"interrupted"}\n')
        with patch.object(pipeline, 'COPY_BYTES', 8):
            result = pipeline.export_metadata(self.volume, self.root)
        self.assertEqual(result['status'], 'FAIL')
        manifest = json.loads((self.local / 'reference-metadata-manifest.json').read_text())
        self.assertEqual(manifest['status'], 'FAIL')
        self.assertEqual(source.read_bytes(), b'{"phase":"interrupted"}\n')


if __name__ == '__main__': unittest.main()
