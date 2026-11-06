"""Synthetic mounted journal transitions; no image, mount or Linux qualification."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference_image_recovery as recovery
import test_reference_image_recovery_challenge as challenge

JOURNAL = {'journal_incompat_revoke', 'journal_64bit', 'journal_checksum_v3'}


class RecoveryJournalTransitionControls(unittest.TestCase):
    def raw(self, mounted=False, modern=False):
        raw = challenge.RecoveryPhysicalAndFormatChallenge().raw_geometry()
        if mounted:
            raw = raw.replace('has_journal ', 'has_journal needs_recovery ')
        if modern:
            raw = raw.replace('Journal features: (none)',
                              'Journal features: journal_incompat_revoke journal_64bit journal_checksum_v3')
            raw += ('Journal sequence: 0x00000002\nJournal start: 1\n'
                    'Journal checksum type:    crc32c\nJournal checksum: 0xf3bdf628\n')
        return raw + 'Fast commit length:       0\n'

    def test_clean_and_mounted_inactive_journal_remain_explicit(self):
        for mounted in (False, True):
            with self.subTest(mounted=mounted):
                result = recovery.recovery_geometry(self.raw(mounted),
                    lifecycle='mounted' if mounted else 'clean')
                self.assertEqual(result['journal_features'], [])
                self.assertIsNone(result['journal_checksum_type'])

    def test_exact_mounted_modern_journal_preserves_actual_features_and_checksum(self):
        result = recovery.recovery_geometry(self.raw(True, True), lifecycle='mounted')
        self.assertEqual(result['journal_features'], sorted(JOURNAL))
        self.assertEqual(result['journal_checksum_type'], 'crc32c')
        self.assertEqual(result['observed_lifecycle_features'], ['needs_recovery'])
        self.assertEqual(result['journal_bytes'], 16 * 1024 * 1024)
        self.assertEqual(result['inode_count'], 4096)

    def test_clean_never_accepts_mounted_journal_or_checksum_declaration(self):
        for raw in (self.raw(False, True), self.raw() + 'Journal checksum type: crc32c\n',
                    self.raw() + 'Journal checksum type: unknown\n'):
            with self.subTest(raw=raw[-180:]), self.assertRaises(ValueError):
                recovery.recovery_geometry(raw)

    def test_mounted_partial_unknown_duplicate_and_fast_commit_journal_features_refuse(self):
        raw = self.raw(True, True)
        for features in ('journal_incompat_revoke journal_64bit',
                         'journal_checksum_v3', 'unknown journal_64bit journal_checksum_v3',
                         'journal_incompat_revoke journal_64bit journal_checksum_v3 journal_64bit',
                         'journal_incompat_revoke journal_64bit journal_checksum_v3 fast_commit'):
            changed = raw.replace('journal_incompat_revoke journal_64bit journal_checksum_v3', features)
            with self.subTest(features=features), self.assertRaises(ValueError):
                recovery.recovery_geometry(changed, lifecycle='mounted')
        with self.assertRaises(ValueError):
            recovery.recovery_geometry(raw + 'Journal features: (none)\n', lifecycle='mounted')

    def test_mounted_checksum_missing_wrong_duplicate_and_inactive_mismatch_refuse(self):
        raw = self.raw(True, True)
        for changed in (raw.replace('Journal checksum type:    crc32c\n', ''),
                        raw.replace('Journal checksum type:    crc32c', 'Journal checksum type: sha256'),
                        raw + 'Journal checksum type: crc32c\n',
                        self.raw(True) + 'Journal checksum type: crc32c\n',
                        raw.replace('Fast commit length:       0', 'Fast commit length: 1')):
            with self.subTest(raw=changed[-180:]), self.assertRaises(ValueError):
                recovery.recovery_geometry(changed, lifecycle='mounted')

    def outer(self, *, mounted_raw=None, mutate_clean=None, change_binding=False):
        p = {'local': Path('/synthetic/control'), 'outer': Path('/synthetic/outer.img'),
             'volume': Path('/synthetic/volume')}
        ctx = {'source': 'a' * 64}
        binding = {'mount': {'source': '/dev/loop7'}, 'image_identity': [7, 11, 12]}
        clean = recovery.recovery_geometry(self.raw())
        if mutate_clean:
            mutate_clean(clean)
        proof = {'run_context': ctx, 'hard_quota_enforced': True,
                 'outer_bytes': recovery.OUTER_BYTES, 'probe_bytes': recovery.PROBE_BYTES,
                 'oversized_allocation': 'DENIED_ENOSPC', 'formatter_policy': recovery.FORMAT_POLICY,
                 'formatter_argv': recovery.recovery_formatter_argv(p['outer']),
                 'geometry': clean, 'binding': binding}
        saved = []
        current_binding = {'mount': {'source': '/dev/loop8'}} if change_binding else binding
        with patch.object(recovery, 'load', return_value=proof), \
                patch.object(recovery, 'context', return_value=ctx), \
                patch.object(recovery, 'command', return_value=(
                    (self.raw(True, True) if mounted_raw is None else mounted_raw).encode(), b'', {})), \
                patch.object(recovery, 'mount_observation', return_value=current_binding), \
                patch.object(recovery, 'save', side_effect=lambda path, value, **kw: saved.append(copy.deepcopy(value))):
            result = recovery.outer(p, 'synthetic-modern-transition')
        return result, saved

    def test_outer_admits_declared_journal_transition_and_preserves_actual_observation(self):
        result, saved = self.outer()
        self.assertEqual(result['clean_geometry']['journal_features'], [])
        self.assertIsNone(result['clean_geometry']['journal_checksum_type'])
        self.assertEqual(result['observed_geometry']['journal_features'], sorted(JOURNAL))
        self.assertEqual(result['observed_geometry']['journal_checksum_type'], 'crc32c')
        self.assertEqual(saved[-1]['observed_geometry'], result['observed_geometry'])
        self.assertEqual(saved[-1]['binding'], result['binding'])
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['declared_transition'])

    def test_valid_journal_transition_never_masks_static_geometry_or_backing_changes(self):
        raw = self.raw(True, True)
        for changed in (raw.replace('12345678-abcd', '87654321-abcd'),
                        raw.replace('Total journal blocks: 4096', 'Total journal blocks: 8192'),
                        raw.replace('Inode size: 256', 'Inode size: 128'),
                        raw.replace('Block count: 512695', 'Block count: 512694')):
            with self.subTest(raw=changed[:100]), self.assertRaises(ValueError):
                self.outer(mounted_raw=changed)
        with self.assertRaises(ValueError): self.outer(change_binding=True)

    def test_outer_requires_original_clean_proof_without_mounted_features_or_checksum(self):
        for mutate in (lambda clean: clean.update(journal_features=sorted(JOURNAL)),
                       lambda clean: clean.update(journal_checksum_type='crc32c'),
                       lambda clean: clean.update(observed_lifecycle_features=['needs_recovery']),
                       lambda clean: clean.update(features=sorted(recovery.FORMAT_FEATURES | {'unknown'}))):
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.outer(mutate_clean=mutate)


if __name__ == '__main__': unittest.main()
