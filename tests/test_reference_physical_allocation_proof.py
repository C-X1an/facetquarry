"""Finite run30-shaped facts; no filesystem allocation or process is simulated as real."""
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_trim_control as control


class PhysicalAllocationProofTests(unittest.TestCase):
    def observation(self):
        before = dict(device=1792, inode=906, mode=stat.S_IFREG | 0o600,
                      uid=1001, gid=1001, nlink=1, bytes=0, physical_bytes=0)
        plan = control.padding_plan(1_865_027_584, 4096)
        after = {**before, 'bytes': 1_265_025_024, 'physical_bytes': 1_265_029_120}
        counters = dict(f_bavail=455329, f_bfree=459425, f_blocks=534663, f_bsize=4096,
                        f_frsize=4096, f_favail=135864, f_ffree=135864, f_files=140544,
                        f_flag=4096, f_namemax=255)
        ctx = {'source': 'a' * 64, 'commit': 'b' * 40, 'github_run_id': '17'}
        command = dict(status='PASS', worker_exit_code=0, worker_started=True, errors=[],
                       termination_reason=None, capture_complete=True, captured_output_bytes=0,
                       discarded_output_bytes=0, run_context=ctx,
                       capture={'stdout': {'bytes': 0}, 'stderr': {'bytes': 0}},
                       descendant_quiescence={'quiescent': True, 'residual': []})
        return dict(kind=control.KIND, status='OBSERVED_UNVALIDATED', source=ctx['source'],
                    run_context=ctx, padding_before=before, padding_after=after,
                    descriptor_before=dict(before), descriptor_after=dict(after), padding_plan=plan,
                    statvfs_before=counters, statvfs_after={**counters, 'f_bavail': 146484, 'f_bfree': 150580},
                    command_outcome=command)

    def check(self, observation):
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='physical-proof-', dir=cache)))
            stack.enter_context(patch.object(os, 'getuid', return_value=root.stat().st_uid, create=True))
            if not hasattr(os, 'O_NOFOLLOW'):
                stack.enter_context(patch.object(os, 'O_NOFOLLOW', 0, create=True))
            try:
                return control.check_observed_allocation(root, observation)
            finally:
                self.assertEqual(json.loads((root / 'allocation.observed.json').read_bytes()), observation)

    def test_complete_observed_physical_charge_admits_only_one_proved_block(self):
        result = self.check(self.observation())
        self.assertEqual(result['exact_allocated_bytes'], 1_265_029_120)
        self.assertEqual(result['physical_allocation_overhead_bytes'], 4096)
        self.assertEqual(result['actual_available_after_bytes'], 599_998_464)
        self.assertEqual(result['prediction_difference_bytes'], -4096)

    def test_zero_overhead_complete_proof_keeps_exact_original_charge(self):
        item = self.observation()
        item['padding_after']['physical_bytes'] -= 4096
        item['descriptor_after'] = dict(item['padding_after'])
        for key in ('f_bavail', 'f_bfree'):
            item['statvfs_after'][key] += 1
        result = self.check(item)
        self.assertEqual(result['exact_allocated_bytes'], 1_265_025_024)
        self.assertEqual(result['physical_allocation_overhead_bytes'], 0)

    def test_every_missing_or_noninteger_counter_refuses_extra_allocation(self):
        for phase in ('statvfs_before', 'statvfs_after'):
            for name in self.observation()[phase]:
                for value in ('missing', True, -1, '4096'):
                    item = self.observation()
                    if value == 'missing': del item[phase][name]
                    else: item[phase][name] = value
                    with self.subTest(phase=phase, name=name, value=value), self.assertRaises(ValueError):
                        self.check(item)

    def test_geometry_and_both_free_counter_deltas_must_match_original_facts(self):
        for phase, key, value in (
            ('statvfs_after', 'f_bavail', 146483), ('statvfs_after', 'f_bfree', 150579),
            ('statvfs_before', 'f_bavail', 455330), ('statvfs_before', 'f_bfree', 459426),
            ('statvfs_after', 'f_blocks', 534664), ('statvfs_after', 'f_frsize', 2048),
            ('statvfs_after', 'f_bsize', 8192), ('statvfs_after', 'f_files', 140545),
            ('statvfs_after', 'f_ffree', 135863), ('statvfs_after', 'f_favail', 135863),
            ('statvfs_after', 'f_flag', 0), ('statvfs_after', 'f_namemax', 256),
            ('statvfs_before', 'f_bfree', 455328)):
            item = self.observation(); item[phase][key] = value
            with self.subTest(phase=phase, key=key), self.assertRaises(ValueError): self.check(item)

    def test_plan_identity_and_unaligned_or_larger_overhead_are_refused(self):
        for edit in (
            lambda x: x['padding_plan'].update(padding_bytes=1_265_020_928),
            lambda x: x['padding_plan'].update(minimum_available_bytes=1),
            lambda x: x['padding_before'].update(uid=0),
            lambda x: x['descriptor_after'].update(inode=907),
            lambda x: x['padding_after'].update(bytes=1_265_025_025),
            lambda x: x['padding_after'].update(physical_bytes=1_265_029_121),
            lambda x: x['padding_after'].update(physical_bytes=1_265_033_216)):
            item = self.observation(); edit(item)
            with self.assertRaises(ValueError): self.check(item)

    def test_no_failed_incomplete_or_unquiescent_command_can_supply_proof(self):
        for key, value in (('status', 'FAIL'), ('worker_exit_code', 1), ('worker_exit_code', False),
                           ('worker_started', False), ('termination_reason', 'timeout'),
                           ('capture_complete', False), ('discarded_output_bytes', 1),
                           ('captured_output_bytes', 1), ('errors', ['refused']), ('run_context', {})):
            item = self.observation(); item['command_outcome'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.check(item)
        for quiet in ({'quiescent': False, 'residual': []}, {'quiescent': True, 'residual': [1]}):
            item = self.observation(); item['command_outcome']['descendant_quiescence'] = quiet
            with self.assertRaises(ValueError): self.check(item)
        for key in self.observation()['command_outcome']:
            item = self.observation(); del item['command_outcome'][key]
            with self.subTest(missing_command_key=key), self.assertRaises(ValueError): self.check(item)

    def test_boolean_descriptor_fact_cannot_equal_an_integer_identity(self):
        for phase in ('descriptor_before', 'descriptor_after'):
            item = self.observation(); item[phase]['nlink'] = True
            with self.subTest(phase=phase), self.assertRaises(ValueError): self.check(item)

    def test_single_block_limit_is_independent_of_descriptor_and_counter_guards(self):
        item = self.observation()
        item['padding_after']['physical_bytes'] += 4096
        item['descriptor_after'] = dict(item['padding_after'])
        for key in ('f_bavail', 'f_bfree'):
            item['statvfs_after'][key] -= 1
        # Inode facts, command and both physical charges agree. Only the
        # deliberately narrow overhead ceiling rejects this two-block excess.
        self.assertEqual(item['descriptor_after'], item['padding_after'])
        for key in ('f_bavail', 'f_bfree'):
            self.assertEqual((item['statvfs_before'][key] - item['statvfs_after'][key]) * 4096,
                             item['padding_after']['physical_bytes'])
        with self.assertRaisesRegex(ValueError, 'single-block policy'):
            self.check(item)

    def test_logical_size_and_alignment_are_not_masked_by_descriptor_mismatch(self):
        item = self.observation()
        item['padding_after']['bytes'] += 1
        item['descriptor_after'] = dict(item['padding_after'])
        with self.assertRaisesRegex(ValueError, 'logical size'):
            self.check(item)
        item = self.observation()
        item['padding_after']['physical_bytes'] += 1
        item['descriptor_after'] = dict(item['padding_after'])
        with self.assertRaisesRegex(ValueError, 'single-block policy'):
            self.check(item)


if __name__ == '__main__': unittest.main()
