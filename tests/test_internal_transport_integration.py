"""Allocation and selection controls; fixtures do not prove a hosted execution."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from common import ROOT
import disk_guard
import reference_artifacts as artifacts
import reference_internal_transport as internal
import reference_pipeline as pipeline
import reference_upload_candidate as selection


class InternalAllocationControls(unittest.TestCase):
    def test_unchanged_legacy_assertions_under_both_live_reservation_profiles(self):
        for profile in (internal.PROFILE, 'supported-verification-capacity-v1'):
            for filename in ('test_reference_pipeline.py', 'test_reference_image_control.py'):
                with self.subTest(profile=profile, filename=filename):
                    environment = {**os.environ, 'FQ_RESERVATION_PROFILE': profile}
                    completed = subprocess.run([sys.executable, '-m', 'unittest', 'discover',
                        '-s', 'tests', '-p', filename, '-v'], cwd=ROOT, env=environment,
                        capture_output=True, timeout=30)
                    self.assertEqual(completed.returncode, 0,
                        completed.stderr.decode('utf-8', errors='replace')[-12000:])

    def test_new_plan_admits_only_its_retained_image_and_external_metadata(self):
        base = 8_089_573_699  # Arithmetic fixture, never a current admission.
        actual = pipeline.admission(base, 2_300_000_000, 200_000_000, artifacts.IMAGE_ZIP,
                                    profile=internal.PROFILE)
        self.assertTrue(actual['data_allowed'])
        self.assertEqual(actual['scientific_peak_bytes'], base + 3_746_000_000)
        self.assertEqual(actual['scientific_peak_bytes'], internal.growth_plan(base)['peak_bytes'])
        self.assertTrue(actual['outer_image_retained_through_upload'])
        self.assertEqual(actual['upload_receipt_reserved_bytes'], 1_100_000)
        self.assertEqual(actual['upload_receipt_reserved_bytes'] + actual['remaining_overhead_reserved_bytes'],
                         artifacts.OVERHEAD)
        # The original larger external-package plan still refuses this baseline.
        legacy = pipeline.admission(base, 2_300_000_000, 200_000_000, artifacts.IMAGE_ZIP)
        self.assertFalse(legacy['data_allowed'])
        for image in (0, 1, 2_299_999_999):
            with self.subTest(image=image):
                self.assertFalse(pipeline.admission(base, image, 0, 1,
                                                   profile=internal.PROFILE)['data_allowed'])

    def test_strict_ceiling_external_cap_and_global_reserve_are_not_relaxed(self):
        for delta, allowed in ((-1, True), (0, False), (1, False)):
            base = 12_000_000_000 - 3_746_000_000 + delta
            value = pipeline.admission(base, 2_300_000_000, 200_000_000, artifacts.IMAGE_ZIP,
                                       profile=internal.PROFILE)
            self.assertEqual(value['data_allowed'], allowed)
        value = pipeline.admission(2_000_000_000, 2_300_000_000, 200_000_001, 1,
                                   profile=internal.PROFILE)
        self.assertFalse(value['metadata_allowed'])
        self.assertFalse(value['data_allowed'])
        for base in (True, 1_999_999_999):
            with self.assertRaises(ValueError):
                pipeline.admission(base, 2_300_000_000, 0, 1, profile=internal.PROFILE)
        with self.assertRaises(ValueError):
            pipeline.admission(2_000_000_000, True, 0, 1, profile=internal.PROFILE)
        with self.assertRaises(ValueError):
            pipeline.admission(2_000_000_000, 0, 0, 0, profile='invented-profile')

    def test_disk_guard_dispatch_requires_the_new_positive_reservation(self):
        env = {'FQ_RESERVATION_PROFILE': internal.PROFILE}
        argv = ['disk_guard.py', '--root', str(ROOT), '--filesystem-free-floor', '500000000']
        observation = {'bound_new_profile': True}
        with patch.dict(os.environ, env), patch.object(sys, 'argv', argv), \
                patch.object(internal, 'verify', return_value=observation) as verify, \
                patch.object(disk_guard, 'inventory_roots', return_value=[{'accounted_bytes': 100, 'symlinks_not_followed': []}]), \
                patch.object(disk_guard.shutil, 'disk_usage', return_value=type('Space', (), {'free': 500_000_000})()), \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(disk_guard.main(), 0)
        verify.assert_called_once_with(ROOT, 2_000_000_000, 500_000_000)
        self.assertEqual(json.loads(output.getvalue())['reference_reservation'], observation)
        with patch.dict(os.environ, env), patch.object(sys, 'argv', argv), \
                patch.object(internal, 'verify', side_effect=ValueError('stale quota backing')), \
                patch.object(disk_guard, 'inventory_roots') as inventory, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(disk_guard.main(), 1)
        inventory.assert_not_called()
        self.assertIn('stale quota backing', json.loads(output.getvalue())['error'])


class InternalSelectionControls(unittest.TestCase):
    def setUp(self):
        temporary = ROOT / '.cache/tmp'
        temporary.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=temporary)
        self.addCleanup(self.directory.cleanup)
        self.parent = Path(self.directory.name)
        self.root = self.parent / 'checkout'
        self.root.mkdir()
        self.volume = self.parent / 'facetquarry-reference'
        (self.volume / 'source').mkdir(parents=True)
        # Tiny real file. Its physical allocation cannot qualify any data upload.
        self.volume.with_name(self.volume.name + '.img').write_bytes(b'tiny fixture')
        # Production dispatch requires Linux. Use the fixture's actual owner
        # for these portable selection-unit controls on Windows as well.
        owner = patch.object(pipeline.os, 'getuid', return_value=self.root.lstat().st_uid, create=True)
        owner.start()
        self.addCleanup(owner.stop)
        self.env = patch.dict(os.environ, {'FQ_RESERVATION_PROFILE': internal.PROFILE,
            'FQ_ACCOUNTED_BASE_BYTES': '2000000000', 'GITHUB_SHA': 'b' * 40,
            'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'})
        self.env.start()
        self.addCleanup(self.env.stop)
        digest = patch.object(pipeline, 'source_hash', return_value='a' * 64)
        digest.start()
        self.addCleanup(digest.stop)

    def test_package_outcome_cannot_substitute_for_current_verification(self):
        failure = {'status': 'FAIL', 'error': 'verification failed',
                   'descendant_quiescence': {'quiescent': True, 'residual': []}}
        with patch.object(selection, 'evaluate', return_value=failure) as candidate:
            result = pipeline.admit_uploads(self.volume, True, self.root, profile=internal.PROFILE)
        candidate.assert_called_once_with(self.volume, True, root=self.root)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['kind'], 'NONE')
        self.assertFalse(result['data_allowed'])
        self.assertTrue(result['metadata_allowed'])
        self.assertEqual(result['candidate_evaluation'], failure)
        self.assertIn('candidate evaluation failed', result['error'])
        self.assertEqual(json.loads((self.root / '.local/reference-upload-admission.json').read_text()), result)

    def test_failed_package_can_only_select_the_verified_frozen_image(self):
        proof = {'status': 'PASS', 'source': 'a' * 64, 'selected_path': str(self.volume / 'reference-results.img'),
                 'image_unmounted': True, 'image_bytes': artifacts.RESULTS_IMAGE,
                 'zip_upper_bound_bytes': artifacts.IMAGE_ZIP, 'image_sha256': 'c' * 64}
        evaluated = {'status': 'PASS', 'candidate': proof,
                     'descendant_quiescence': {'quiescent': True, 'residual': []}}
        with patch.object(selection, 'evaluate', return_value=evaluated) as frozen:
            result = pipeline.admit_uploads(self.volume, False, self.root, profile=internal.PROFILE)
        frozen.assert_called_once_with(self.volume, False, root=self.root)
        self.assertEqual(result['kind'], 'IMAGE')
        self.assertEqual(result['path'], proof['selected_path'])
        self.assertEqual(result['image_sha256'], proof['image_sha256'])
        self.assertFalse(result['data_allowed'])  # The fixture is not a2.3GB retained outer.
        self.assertFalse((self.root / '.local/reference-transport/reference-members.tar.xz').exists())


if __name__ == '__main__':
    unittest.main()
