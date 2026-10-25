"""Synthetic reservation contracts; never claim an actual mounted quota."""
import copy
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import disk_guard
import reference_reservation as reservation
from reference_artifacts import growth_plan


class ReferenceFilesystemFloor(unittest.TestCase):
    def fixture(self):
        volume = Path('/synthetic-owned/facetquarry-reference')
        mount = {'target': str(volume), 'fstype': 'ext4', 'source': '/dev/loop12'}
        context = {'commit': 'a' * 40, 'git_status': '', 'github_run_id': '1234', 'github_run_attempt': '2'}
        stderr = b'No space left on device\n'
        quota = {'volume_file_bytes': 2_300_000_000, 'oversized_allocation_bytes': 2_400_000_000,
            'hard_quota_enforced': True, 'oversized_allocation': 'DENIED_ENOSPC',
            'enospc_sha256': hashlib.sha256(stderr).hexdigest(), 'run_context': context,
            'volume_path': str(volume), 'image_path': str(volume) + '.img', 'mount': mount}
        loops = {'loopdevices': [{'name': '/dev/loop12', 'back-file': str(volume) + '.img'}]}
        return [volume, 2_300_000_000, mount, loops, quota, growth_plan(7_623_223_381, 2_300_000_000), context, stderr, 7_623_223_381]

    def test_distinct_floor_preserves_global_reserved_growth_and_peak(self):
        result = reservation.validate_documents(*self.fixture())
        self.assertEqual(result['global_reserved_growth_bytes'], 2_000_000_000)
        self.assertEqual(result['filesystem_free_floor_bytes'], 500_000_000)
        self.assertFalse(disk_guard.admission(1_000_000_000, 2_000_000_000, 600_000_000))
        self.assertTrue(disk_guard.admission(1_000_000_000, 2_000_000_000, 600_000_000, False, 500_000_000))
        self.assertFalse(disk_guard.admission(10_100_000_000, 2_000_000_000, 600_000_000, False, 500_000_000))
        self.assertFalse(disk_guard.admission(1_000_000_000, 2_000_000_000, 499_999_999, False, 500_000_000))

    def test_wrong_run_attempt_backing_geometry_or_probe_is_rejected(self):
        original = self.fixture()
        def mutate_attempt(args): args[4]['run_context'] = {**args[6], 'github_run_attempt': '1'}
        def mutate_loop(args): args[3]['loopdevices'][0]['back-file'] += '.unrelated'
        def mutate_mount(args): args[2]['fstype'] = 'tmpfs'
        def mutate_probe(args): args[4]['oversized_allocation_bytes'] = 2_300_000_001
        def mutate_stderr(args): args[7] = b'Permission denied\n'
        def mutate_reserve(args): args[5]['baseline_includes_global_reserve'] = 1_999_999_999
        def mutate_branch(args): args[5]['maximum_new_stage_bytes'] -= 1
        def mutate_current_baseline(args): args[8] = 8_200_000_000
        for mutation in (mutate_attempt, mutate_loop, mutate_mount, mutate_probe, mutate_stderr,
                         mutate_reserve, mutate_branch, mutate_current_baseline):
            args = copy.deepcopy(original); mutation(args)
            with self.subTest(mutation=mutation.__name__), self.assertRaises(ValueError):
                reservation.validate_documents(*args)

    def test_live_cli_cannot_activate_override_without_owned_current_runner(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, str(root / 'scripts/disk_guard.py'),
            '--root', str(root), '--reserve', '2000000000', '--filesystem-free-floor', '500000000'],
            capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('REFUSE', result.stdout)


if __name__ == '__main__': unittest.main()
