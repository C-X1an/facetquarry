"""Finite recorded-proof replay through the real first verify stage.

Platform ownership, mounted geometry and child receipts are explicit fixture
doubles. These tests do not claim Linux allocation or read-only image recovery.
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
import test_reference_physical_allocation_proof as facts


class StopAfterPreparation(Exception):
    pass


class RetainedAllocationReplayTests(unittest.TestCase):
    def first_stage(self, edit=None):
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='retained-allocation-', dir=cache)))
            volume = root / 'volume'; volume.mkdir()
            project = volume / 'source'; project.mkdir()
            audit = root / 'audit'; audit.mkdir()
            prepared = audit / 'prepare'; prepared.mkdir()
            observation = facts.PhysicalAllocationProofTests().observation()
            ctx = observation['run_context']
            record = {'kind': control.KIND, 'status': 'PASS', 'source': observation['source'],
                'run_context': ctx, 'padding_path': str(volume / 'reference-trim-control-padding.bin'),
                'padding_before': copy.deepcopy(observation['padding_before']),
                'padding_after': copy.deepcopy(observation['padding_after']),
                'padding_plan': copy.deepcopy(observation['padding_plan']),
                'allocation_observation': copy.deepcopy(observation),
                'actual_allocation': control.complete_observed_allocation(observation)}
            records = {'prepare.json': record, 'allocation.observed.json': observation,
                       'allocation.json': copy.deepcopy(observation['command_outcome'])}
            if edit is not None: edit(records)
            for name, value in records.items():
                (prepared / name).write_text(json.dumps(value), encoding='utf-8')
            originals = {name: (prepared / name).read_bytes() for name in records}
            result = {}
            def checkpoint(_audit, value, name, *, pending):
                if name == 'preparation' and not pending:
                    result.update(value['stages'][name])
                    raise StopAfterPreparation()
            stack.enter_context(patch.object(control.filesystem, 'whole_entry', return_value=nullcontext()))
            stack.enter_context(patch.object(control, 'setup', return_value=(
                {'volume': volume, 'project': project}, ctx, {}, audit)))
            stack.enter_context(patch.object(control, 'envelope', return_value={
                'physical_bytes': 0, 'logical_bytes': 0, 'entries': 0}))
            stack.enter_context(patch.object(os, 'statvfs', return_value=SimpleNamespace(f_frsize=4096), create=True))
            stack.enter_context(patch.object(os, 'getuid', return_value=root.stat().st_uid, create=True))
            if not hasattr(os, 'O_NOFOLLOW'):
                stack.enter_context(patch.object(os, 'O_NOFOLLOW', 0, create=True))
            stack.enter_context(patch.object(control, 'owned_padding', return_value=record['padding_after']))
            receipt = stack.enter_context(patch.object(control.bindings, 'verify_receipt'))
            stack.enter_context(patch.object(control, 'stage_checkpoint', side_effect=checkpoint))
            with self.assertRaises(StopAfterPreparation):
                control.verify(volume, project)
            receipt.assert_called_once()
            self.assertEqual({name: (prepared / name).read_bytes() for name in records}, originals)
            return result

    def test_real_verify_stage_replays_same_complete_extra_block_proof(self):
        result = self.first_stage()
        self.assertEqual(result['status'], 'PASS', result)
        self.assertIn('preparation_sha256', result['observation'])

    def test_missing_original_observation_is_not_replaced_or_inferred(self):
        result = self.first_stage(lambda rows: rows.pop('allocation.observed.json'))
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('FileNotFoundError', result['error'])

    def test_changed_observation_cannot_disagree_with_preparation_record(self):
        def edit(rows): rows['allocation.observed.json']['recorded_at'] = 'different'
        result = self.first_stage(edit)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('retained allocation observation', result['error'])

    def test_actual_command_record_must_equal_observed_command(self):
        def edit(rows): rows['allocation.json']['worker_exit_code'] = 1
        result = self.first_stage(edit)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('retained allocation command', result['error'])

    def test_recorded_physical_charge_must_equal_recomputed_proof(self):
        def edit(rows): rows['prepare.json']['actual_allocation']['exact_allocated_bytes'] -= 4096
        result = self.first_stage(edit)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('retained allocation result', result['error'])


if __name__ == '__main__': unittest.main()
