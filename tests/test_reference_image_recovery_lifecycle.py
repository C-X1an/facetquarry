"""Synthetic clean/mounted ext4 lifecycle controls; no actual mount claim."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference_image_recovery as recovery
import test_reference_image_recovery_challenge as challenge


class RecoveryLifecycleControls(unittest.TestCase):
    def raw(self, mounted=False):
        raw = challenge.RecoveryPhysicalAndFormatChallenge().raw_geometry()
        return raw.replace('has_journal ', 'has_journal needs_recovery ') if mounted else raw

    def test_clean_geometry_preserves_static_features_and_declares_no_lifecycle_flag(self):
        result = recovery.recovery_geometry(self.raw())
        self.assertEqual(result['observed_lifecycle_features'], [])
        self.assertEqual(set(result['features']), recovery.FORMAT_FEATURES)

    def test_known_mounted_needs_recovery_flag_is_explicit_and_static_geometry_is_identical(self):
        clean = recovery.recovery_geometry(self.raw())
        mounted = recovery.recovery_geometry(self.raw(True), lifecycle='mounted')
        self.assertEqual(mounted['observed_lifecycle_features'], ['needs_recovery'])
        self.assertEqual({key: value for key, value in clean.items() if key != 'observed_lifecycle_features'},
                         {key: value for key, value in mounted.items() if key != 'observed_lifecycle_features'})

    def test_clean_rejects_mounted_flag_and_mounted_requires_its_exact_flag(self):
        with self.assertRaises(ValueError): recovery.recovery_geometry(self.raw(True))
        with self.assertRaises(ValueError): recovery.recovery_geometry(self.raw(), lifecycle='mounted')
        with self.assertRaises(ValueError): recovery.recovery_geometry(self.raw(), lifecycle='unknown')

    def outer(self, raw, *, change_clean=None):
        p = {'local': Path('/synthetic/metadata'), 'outer': Path('/synthetic/outer.img'),
             'volume': Path('/synthetic/volume')}
        ctx, binding = {'source': 'a' * 64}, {'mount': {'source': '/dev/loop7'}, 'image_identity': ['synthetic']}
        geometry = recovery.recovery_geometry(self.raw())
        if change_clean: change_clean(geometry)
        proof = {'run_context': ctx, 'hard_quota_enforced': True, 'outer_bytes': recovery.OUTER_BYTES,
                 'probe_bytes': recovery.PROBE_BYTES, 'oversized_allocation': 'DENIED_ENOSPC',
                 'formatter_policy': recovery.FORMAT_POLICY, 'formatter_argv': recovery.recovery_formatter_argv(p['outer']),
                 'geometry': geometry, 'binding': binding}
        saved = []
        with patch.object(recovery, 'load', return_value=proof), patch.object(recovery, 'context', return_value=ctx), \
                patch.object(recovery, 'command', return_value=(raw.encode(), b'', {})), \
                patch.object(recovery, 'mount_observation', return_value=binding), \
                patch.object(recovery, 'save', side_effect=lambda path, value, **kwargs: saved.append(copy.deepcopy(value))):
            result = recovery.outer(p, 'synthetic-lifecycle')
        return result, saved

    def test_actual_outer_path_accepts_known_mounted_transition_and_retains_binding(self):
        result, saved = self.outer(self.raw(True))
        self.assertEqual(result['observed_geometry']['observed_lifecycle_features'], ['needs_recovery'])
        self.assertEqual(saved[-1]['binding'], result['binding'])
        self.assertEqual(saved[-1]['observed_geometry'], result['observed_geometry'])
        self.assertEqual(saved[-1]['status'], 'PASS')

    def test_mounted_unknown_features_and_static_changes_remain_rejected(self):
        for raw in (self.raw(True).replace('has_journal ', 'has_journal unexpected_feature '),
                    self.raw(True).replace('has_journal ', 'has_journal fast_commit '),
                    self.raw(True).replace('12345678-abcd', '87654321-abcd'),
                    self.raw(True).replace('Total journal blocks: 4096', 'Total journal blocks: 8192')):
            with self.subTest(raw=raw[:100]), self.assertRaises(ValueError): self.outer(raw)


if __name__ == '__main__': unittest.main()
