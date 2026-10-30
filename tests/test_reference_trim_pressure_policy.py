"""Named pressure arithmetic and actual guard paths, with explicit platform doubles.

No mounted filesystem, allocation, reclaim, child or Linux qualification claim.
"""
import copy
from contextlib import ExitStack, nullcontext
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_trim_control as control
import test_reference_physical_allocation_proof as fixtures

LEGACY = 'reference-trim-pressure-600mb-v1'
SELECTED = 'reference-trim-pressure-700mb-v1'


class TrimPressurePolicyTests(unittest.TestCase):
    def test_legacy_output_is_exact_and_does_not_inherit_workflow_environment(self):
        expected = {'available_before_bytes': 1_000_000_000, 'block_size': 4096,
                    'padding_bytes': 399_998_976, 'predicted_available_after_bytes': 600_001_024,
                    'target_available_bytes': 600_000_000, 'minimum_available_bytes': 590_000_000,
                    'unchanged_package_threshold_bytes': 921_000_000}
        with patch.dict(os.environ, {'FQ_TRIM_PRESSURE_POLICY': SELECTED}):
            self.assertEqual(control.padding_plan(1_000_000_000, 4096), expected)
        self.assertEqual(control.padding_plan(1_000_000_000, 4096, policy=LEGACY), expected)
        self.assertEqual(control.TARGET_FREE, 600_000_000)

    def test_named_700_plan_is_aligned_and_still_forces_prepack_branch(self):
        self.assertEqual(control.PRESSURE_POLICY, SELECTED)
        for block in (1024, 2048, 4096):
            plan = control.padding_plan(1_800_000_003, block, policy=SELECTED)
            self.assertEqual(plan['pressure_policy'], SELECTED)
            self.assertEqual(plan['padding_bytes'] % block, 0)
            remaining = plan['predicted_available_after_bytes']
            self.assertEqual(1_800_000_003 - plan['padding_bytes'], remaining)
            self.assertGreaterEqual(remaining, 700_000_000)
            self.assertLess(remaining, 700_000_000 + block)
            self.assertFalse(control.transport.physical_admission(remaining)['allowed'])
            self.assertEqual(plan['minimum_available_bytes'], 590_000_000)
            self.assertEqual(plan['unchanged_package_threshold_bytes'], 921_000_000)
        # The real prebranch validator refuses an actual already-admissible pack.
        ctx = {'source': 'a' * 64}
        pack = {'run_context': ctx, 'source': ctx['source'], 'profile': control.transport.PROFILE,
                'control': True, 'status': 'FAIL',
                'physical_before': control.transport.physical_admission(921_000_000)}
        with self.assertRaisesRegex(ValueError, 'actual pack did not observe'):
            control.pressure_check(pack, ctx)

    def test_unknown_arbitrary_or_missing_production_selection_refused(self):
        for value in ('', 'unknown', '700000000', 700_000_000, True, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                control.padding_plan(1_800_000_000, 4096, policy=value)
            with self.subTest(selection=value), self.assertRaises(ValueError):
                control.selected_pressure_policy({'FQ_TRIM_PRESSURE_POLICY': value})
        self.assertEqual(control.selected_pressure_policy({'FQ_TRIM_PRESSURE_POLICY': SELECTED}), SELECTED)

    def observation(self):
        observed = fixtures.PhysicalAllocationProofTests().observation()
        block = observed['statvfs_before']['f_frsize']
        before = observed['statvfs_before']['f_bavail'] * block
        plan = control.padding_plan(before, block, policy=SELECTED)
        observed.update(pressure_policy=SELECTED, padding_plan=plan)
        observed['padding_after'].update(bytes=plan['padding_bytes'], physical_bytes=plan['padding_bytes'] + block)
        observed['descriptor_after'] = dict(observed['padding_after'])
        for key in ('f_bfree', 'f_bavail'):
            observed['statvfs_after'][key] = observed['statvfs_before'][key] - observed['padding_after']['physical_bytes'] // block
        return observed

    def record(self, observed):
        return {'source': observed['source'], 'run_context': copy.deepcopy(observed['run_context']),
                'pressure_policy': SELECTED, 'allocation_observation': copy.deepcopy(observed),
                **{key: copy.deepcopy(observed[key]) for key in ('padding_before', 'padding_after', 'padding_plan')},
                'actual_allocation': control.validate_allocation_observation(observed)}

    def test_full_original_counters_recompute_selected_policy_and_replay_without_writes(self):
        observed = self.observation()
        record = self.record(observed)
        original = copy.deepcopy((record, observed))
        result = control.retained_allocation_check(record, observed, observed['command_outcome'], expected_policy=SELECTED)
        self.assertEqual(result['physical_allocation_overhead_bytes'], 4096)
        self.assertEqual(result['exact_allocated_bytes'], observed['padding_after']['physical_bytes'])
        self.assertEqual((record, observed), original)
        for edit in (lambda r, o: r.update(pressure_policy=LEGACY),
                     lambda r, o: o.update(pressure_policy=LEGACY),
                     lambda r, o: o['padding_plan'].update(target_available_bytes=800_000_000),
                     lambda r, o: o['run_context'].update(source='c' * 64),
                     lambda r, o: o['command_outcome'].update(worker_exit_code=1)):
            changed_record, changed = copy.deepcopy(original)
            edit(changed_record, changed)
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                control.retained_allocation_check(changed_record, changed, changed['command_outcome'], expected_policy=SELECTED)
        # Even consistently replaced retained copies cannot change policy choice
        # or substitute a target without recomputation from original counters.
        changed = self.observation()
        changed['padding_plan']['target_available_bytes'] = 800_000_000
        record['padding_plan'] = changed['padding_plan']
        record['allocation_observation'] = copy.deepcopy(changed)
        with self.assertRaisesRegex(ValueError, 'actual before counters'):
            control.retained_allocation_check(record, changed, changed['command_outcome'], expected_policy=SELECTED)

    def test_production_setup_binds_selection_in_paths_without_mutating_run_context(self):
        env = {'FQ_TRIM_CONTROL': 'true', 'FQ_PRESERVATION_CONTROL': 'true',
               'FQ_BENCH_PROFILE': 'smoke', 'FQ_BENCH_CONCURRENCY': '1',
               'FQ_RESERVATION_PROFILE': control.transport.PROFILE,
               'FQ_ACCOUNTED_BASE_BYTES': '2000000000', 'FQ_TRIM_PRESSURE_POLICY': SELECTED}
        p = {'project': Path('/fixture/project'), 'outer': Path('/fixture/root'), 'local': Path('/fixture/root/.local')}
        ctx = {'source': 'a' * 64, 'commit': 'b' * 40}
        with patch.dict(os.environ, env), patch.object(control.bindings, 'ordinary'), \
             patch.object(control.transport, 'paths', side_effect=lambda *args: dict(p)), \
             patch.object(control.transport, 'context', return_value=ctx), \
             patch.object(control.transport, 'growth_plan', return_value={'admission': 'ALLOW'}):
            paths, returned, _, _ = control.setup(Path('/volume'), p['project'], p['outer'])
        self.assertEqual(paths['trim_pressure_policy'], SELECTED)
        self.assertEqual(returned, ctx)
        self.assertNotIn('pressure_policy', ctx)

    def test_actual_verify_stage_replays_selected_policy_and_rejects_missing_binding(self):
        class StopAfterPreparation(Exception): pass
        for missing in (False, True):
            cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
            cache.mkdir(parents=True, exist_ok=True)
            with ExitStack() as stack:
                folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='pressure-replay-', dir=cache)))
                volume, audit = folder / 'volume', folder / 'audit'
                volume.mkdir(); audit.mkdir()
                prepared = audit / 'prepare'; prepared.mkdir()
                observed = self.observation()
                record = self.record(observed)
                record.update(kind=control.KIND, status='PASS',
                              padding_path=str(volume / 'reference-trim-control-padding.bin'))
                if missing: record.pop('pressure_policy')
                values = {'prepare.json': record, 'allocation.observed.json': observed,
                          'allocation.json': observed['command_outcome']}
                for name, value in values.items():
                    (prepared / name).write_text(json.dumps(value), encoding='utf-8')
                originals = {name: (prepared / name).read_bytes() for name in values}
                outcome = {}
                def checkpoint(_audit, value, name, *, pending):
                    if name == 'preparation' and not pending:
                        outcome.update(value['stages'][name])
                        raise StopAfterPreparation()
                stack.enter_context(patch.object(control.filesystem, 'whole_entry', return_value=nullcontext()))
                stack.enter_context(patch.object(control, 'setup', return_value=(
                    {'volume': volume, 'project': volume / 'source', 'trim_pressure_policy': SELECTED},
                    observed['run_context'], {}, audit)))
                stack.enter_context(patch.object(control, 'envelope', return_value={
                    'physical_bytes': 0, 'logical_bytes': 0, 'entries': 0}))
                stack.enter_context(patch.object(os, 'statvfs', return_value=SimpleNamespace(f_frsize=4096), create=True))
                stack.enter_context(patch.object(os, 'getuid', return_value=folder.stat().st_uid, create=True))
                if not hasattr(os, 'O_NOFOLLOW'):
                    stack.enter_context(patch.object(os, 'O_NOFOLLOW', 0, create=True))
                stack.enter_context(patch.object(control, 'owned_padding', return_value=observed['padding_after']))
                receipt = stack.enter_context(patch.object(control.bindings, 'verify_receipt'))
                stack.enter_context(patch.object(control, 'stage_checkpoint', side_effect=checkpoint))
                with self.assertRaises(StopAfterPreparation): control.verify(volume, volume / 'source')
                self.assertEqual(outcome['status'], 'FAIL' if missing else 'PASS', outcome)
                self.assertEqual(receipt.call_count, 0 if missing else 1)
                self.assertEqual({name: (prepared / name).read_bytes() for name in values}, originals)

    def test_actual_run32_posttrim_availability_still_refuses_child_under_new_policy(self):
        # Exercise the production pack function. Host context/geometry/time and
        # trim are explicit doubles; the actual post-trim admission is active.
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='pressure-pack-', dir=cache) as folder:
            root = Path(folder).absolute()
            volume, outer = root / 'volume', root / 'outer'
            project = volume / 'source'
            (project / '.local').mkdir(parents=True)
            (outer / '.local').mkdir(parents=True)
            p = {'volume': volume, 'project': project, 'outer': outer, 'local': outer / '.local',
                 'audit': outer / '.local/reference-transport', 'data': volume / 'reference-transport',
                 'package': volume / 'reference-transport/reference-members.tar.xz',
                 'trim_pressure_policy': SELECTED}
            ctx = {'source': 'a' * 64, 'commit': 'b' * 40, 'github_run_id': '17', 'github_run_attempt': '1'}
            with patch.dict(os.environ, {'FQ_TRANSPORT_WORKER_PHASE': ''}), \
                 patch.object(control.transport, 'paths', return_value=p), \
                 patch.object(control.transport, 'context', return_value=ctx), \
                 patch.object(control.transport, 'external_admission', return_value={'allowed': True}), \
                 patch.object(control.transport, 'observe_outer', return_value={}), \
                 patch.object(control.transport, 'current_time_admission', return_value={'allowed': True}), \
                 patch.object(control.transport, 'closed_guest'), \
                 patch.object(control.transport.shutil, 'disk_usage', side_effect=[
                     SimpleNamespace(free=699_998_208), SimpleNamespace(free=881_876_992)]), \
                 patch.object(control.transport, 'trim_guest', return_value={'status': 'PASS',
                     'removed_accounted_bytes': 284_250_112}) as trimmed, \
                 patch.object(control.transport, 'validate_result_tree', return_value=[]) as members, \
                 patch.object(control.transport.artifacts, 'run_pack') as child:
                result = control.transport.pack(volume, project, outer, control=True)
            trimmed.assert_called_once()
            child.assert_not_called()
            members.assert_not_called()
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse(result['physical_before']['allowed'])
            self.assertFalse(result['physical_admission']['allowed'])
            self.assertEqual(result['physical_admission']['required_available_bytes'], 921_000_000)
            self.assertIn('unchanged 500MB filesystem floor', '\n'.join(result['errors']))
            self.assertFalse(p['data'].exists())


if __name__ == '__main__': unittest.main()
