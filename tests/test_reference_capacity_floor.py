"""Synthetic capacity bindings and real native refusals; no mounted-quota claim."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_capacity_reservation as capacity
import reference_reservation as main_reservation


class CapacityFilesystemFloor(unittest.TestCase):
    def fixture(self):
        volume = Path('/synthetic-owned/facetquarry-capacity')
        mount = {'target': str(volume), 'fstype': 'ext4', 'source': '/dev/loop12'}
        ctx = {'repository': 'C-X1an/facetquarry', 'repository_id': 1430604581,
               'commit': 'a' * 40, 'source': 'b' * 64, 'git_status': '',
               'github_run_id': '1234', 'github_run_attempt': '2',
               'job': 'reference_capacity', 'profile': capacity.PROFILE}
        stderr = b'No space left on device\n'
        quota = {'profile': capacity.PROFILE, 'volume_file_bytes': 2_000_000_000,
                 'oversized_allocation_bytes': 2_100_000_000, 'hard_quota_enforced': True,
                 'oversized_allocation': 'DENIED_ENOSPC', 'enospc_sha256': hashlib.sha256(stderr).hexdigest(),
                 'run_context': ctx, 'volume_path': str(volume),
                 'image_path': str(volume) + '.img', 'mount': mount}
        loops = {'loopdevices': [{'name': '/dev/loop12', 'back-file': str(volume) + '.img'}]}
        planned = {**capacity.growth_plan(8_013_967_856), 'run_context': ctx}
        return [volume, 2_000_000_000, mount, loops, quota, planned, ctx, stderr, 8_013_967_856]

    def test_capacity_preserves_global_reserve_and_main_still_rejects_small_image(self):
        result = capacity.validate_documents(*self.fixture())
        self.assertEqual(result['global_reserved_growth_bytes'], 2_000_000_000)
        self.assertEqual(result['filesystem_free_floor_bytes'], 500_000_000)
        self.assertEqual(result['global_peak_bytes'], 10_358_967_856)
        with self.assertRaisesRegex(ValueError, 'actual local quota refusal'):
            main_reservation.validate_documents(*self.fixture())

    def test_current_attempt_mount_probe_baseline_and_profile_are_mandatory(self):
        mutations = [
            lambda a: a[4].update(profile='main'),
            lambda a: a[4].update(run_context={**a[6], 'github_run_attempt': '1'}),
            lambda a: a[4].update(volume_file_bytes=2_300_000_000),
            lambda a: a[4].update(oversized_allocation_bytes=2_000_000_001),
            lambda a: a[4].update(hard_quota_enforced=False),
            lambda a: a[3]['loopdevices'][0].update({'back-file': '/unrelated.img'}),
            lambda a: a[2].update(fstype='tmpfs'),
            lambda a: a[5].update(data_upload_allowed=True),
            lambda a: a[5].update(maximum_new_stage_bytes=1),
            lambda a: a.__setitem__(7, b'Permission denied\n'),
            lambda a: a.__setitem__(8, 8_200_000_000),
            lambda a: a[6].update(job='reference'),
            lambda a: a[6].update(repository_id=1),
        ]
        for index, mutation in enumerate(mutations):
            args = copy.deepcopy(self.fixture()); mutation(args)
            with self.subTest(index=index), self.assertRaises(ValueError):
                capacity.validate_documents(*args)

    def test_live_cli_cannot_enable_capacity_floor_outside_owned_linux_runner(self):
        root = Path(__file__).resolve().parents[1]
        env = {**os.environ, 'FQ_RESERVATION_PROFILE': capacity.PROFILE}
        result = subprocess.run([sys.executable, str(root / 'scripts/disk_guard.py'),
            '--root', str(root), '--reserve', '2000000000', '--filesystem-free-floor', '500000000'],
            capture_output=True, text=True, env=env, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('REFUSE', result.stdout)

    def test_unknown_profile_refuses_even_without_a_floor_override(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, str(root / 'scripts/disk_guard.py'),
            '--root', str(root)], capture_output=True, text=True,
            env={**os.environ, 'FQ_RESERVATION_PROFILE': 'auto'}, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unknown filesystem reservation profile', result.stdout)

    def test_equal_floor_smoke_monitor_still_executes_under_capacity_profile(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=root / '.cache/tmp') as folder:
            result = subprocess.run([sys.executable, str(root / 'scripts/disk_guard.py'),
                '--root', folder, '--reserve', '500000000', '--filesystem-free-floor', '500000000'],
                capture_output=True, text=True, env={**os.environ, 'FQ_RESERVATION_PROFILE': capacity.PROFILE},
                timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            record = json.loads(result.stdout)
            self.assertIsNone(record['reference_reservation'])
            self.assertEqual(record['filesystem_free_floor_bytes'], 500_000_000)
            self.assertFalse(record['hard_quota_enforced'])

    def test_actual_nested_source_location_and_source_drift_refusal(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=root / '.cache/tmp') as folder:
            volume = Path(folder).absolute() / 'facetquarry-capacity'
            source = volume / 'source'; source.mkdir(parents=True)
            (source / 'fixture.py').write_text('identity = 1\n')
            clone = source / '.cache/tmp/clone'; clone.mkdir(parents=True)
            (clone / 'fixture.py').write_text('identity = 1\n')
            capacity.validate_source_location(volume, clone)
            (clone / 'fixture.py').write_text('identity = 2\n')
            with self.assertRaisesRegex(ValueError, 'outside the same admitted image'):
                capacity.validate_source_location(volume, clone)
            outside = Path(folder).absolute() / 'outside'; outside.mkdir()
            (outside / 'fixture.py').write_text('identity = 1\n')
            with self.assertRaisesRegex(ValueError, 'outside the same admitted image'):
                capacity.validate_source_location(volume, outside)


if __name__ == '__main__': unittest.main()
