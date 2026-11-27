"""Finite budget controls for the distinct named-host group pilot."""

from pathlib import Path
from types import SimpleNamespace
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_group_capacity as capacity


class FrozenGroupBudget(unittest.TestCase):
    def test_strict_ceiling_keeps_existing_global_reserve(self):
        peak_growth = 1_248_103_808
        last_admissible = 12_000_000_000 - peak_growth - 1
        candidate = capacity.growth_plan(last_admissible)
        self.assertEqual(candidate['maximum_new_bytes'], peak_growth)
        self.assertEqual(candidate['peak_bytes'], 11_999_999_999)
        self.assertEqual(candidate['admission'], 'ALLOW')
        self.assertEqual(candidate['global_reserve_bytes'], 2_000_000_000)
        self.assertEqual(capacity.growth_plan(last_admissible + 1)['admission'], 'REFUSE')
        for value in (True, -1, 1_999_999_999, 2_000_000_000.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                capacity.growth_plan(value)

    def test_actual_caller_available_blocks_and_remaining_phase_must_fit(self):
        usage = SimpleNamespace(f_blocks=250_000, f_frsize=4096, f_bfree=150_000,
                                f_bavail=128_000, f_favail=1000)
        value = capacity.phase_space(usage, 'boot', future_bytes=20_000_000, required_inodes=12)
        self.assertEqual(value['caller_available_bytes'], 524_288_000)
        self.assertEqual(value['unallocated_after_phase_bytes'], 504_288_000)
        self.assertEqual(value['status'], 'ALLOW')
        self.assertEqual(capacity.phase_space(usage, 'boot', future_bytes=24_288_001)['status'], 'REFUSE')
        self.assertEqual(capacity.phase_space(usage, 'pack', future_bytes=0, required_inodes=1001)['status'], 'REFUSE')
        usage.f_bavail = (500_000_000 - 1) // 4096
        refused = capacity.phase_space(usage, 'boot', future_bytes=0)
        self.assertEqual(refused['status'], 'REFUSE')
        with self.assertRaises(ValueError):
            capacity.phase_space(usage, '../unbounded', future_bytes=1)
        usage.f_blocks = 268_000
        with self.assertRaisesRegex(ValueError, 'bounded outer geometry'):
            capacity.phase_space(usage, 'boot', future_bytes=0)

    def test_exclusive_export_capacity_includes_runner_and_artifact_tail(self):
        mib = 1 << 20
        streams = {'host_proof': 24 * mib, 'closure': 4 * mib}
        success = capacity.transport_limit(dict(streams, verified_bundle=64 * mib))
        failure = capacity.transport_limit(dict(streams, frozen_results_image=64 * mib))
        self.assertEqual(success['selected'], 'verified_bundle')
        self.assertEqual(failure['selected'], 'frozen_results_image')
        self.assertEqual(success['maximum_transport_bytes'], 96 * mib)
        self.assertEqual(failure['maximum_transport_bytes'], 96 * mib)
        for record in (dict(streams), dict(streams, verified_bundle=64 * mib + 1),
                       dict(streams, frozen_results_image=64 * mib - 1),
                       dict(streams, verified_bundle=1, frozen_results_image=64 * mib),
                       dict(streams, frozen_results_image=64 * mib, unknown=1),
                       dict(streams, verified_bundle=1, host_proof=True)):
            with self.subTest(record=record), self.assertRaises(ValueError):
                capacity.transport_limit(record)

    def test_host_control_charges_its_whole_outer_volume_and_no_guest(self):
        growth = 1_030_000_000 + (66 << 20)
        limit = 12_000_000_000 - growth
        record = capacity.host_control_plan(limit - 1)
        self.assertEqual(record['maximum_new_bytes'], growth)
        self.assertEqual(record['guest_filesystems_and_initrd_bytes'], 0)
        self.assertEqual(record['maximum_artifact_bytes'], 2 << 20)
        self.assertEqual(record['admission'], 'ALLOW')
        self.assertFalse(record['release_qualification'])
        self.assertEqual(capacity.host_control_plan(limit)['admission'], 'REFUSE')

    def test_sequenced_peak_reserves_both_exclusive_phases_and_exact_recovery_size(self):
        growth = 1_030_000_000 + (128 << 20)
        limit = 12_000_000_000 - growth
        plan = capacity.sequenced_group_plan(limit - 1)
        self.assertEqual(plan['admission'], 'ALLOW')
        self.assertEqual(plan['peak_bytes'], 11_999_999_999)
        self.assertEqual(plan['maximum_artifact_bytes'], 64 << 20)
        self.assertEqual(plan['guest_phase_external_bytes'], 50 << 20)
        self.assertEqual(plan['results_image_inside_outer_bytes'], 32 << 20)
        self.assertEqual(capacity.sequenced_group_plan(limit)['admission'], 'REFUSE')
        parts = {'frozen_results_image': 32 << 20, 'host_proof': 24 << 20, 'closure': 4 << 20}
        self.assertEqual(capacity.transport_limit(parts, sequenced=True)['maximum_transport_bytes'], 64 << 20)
        with self.assertRaises(ValueError):
            capacity.transport_limit(parts)
        with self.assertRaises(ValueError):
            capacity.transport_limit(dict(parts, frozen_results_image=64 << 20), sequenced=True)


if __name__ == '__main__':
    unittest.main()
