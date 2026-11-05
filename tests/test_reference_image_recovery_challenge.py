"""New recovery regression controls. Synthetic units never qualify Linux fit."""
from contextlib import ExitStack, redirect_stdout
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference_image_recovery as recovery


class RecoveryPlanDispatchChallenge(unittest.TestCase):
    def dispatch(self, baseline):
        ctx = {'profile': recovery.PROFILE, 'source': 'a' * 64}
        local = ROOT / '.cache/tmp/synthetic-uncreated-recovery-dispatch'
        p = {'local': local, 'outer': local / 'outer.img'}
        parent = {'pid': os.getppid(), 'start_time_ticks': 17}
        worker = {'pid': os.getpid(), 'start_time_ticks': 23}
        active = {'action': 'plan', 'state': 'RUNNING', 'nonce': 'fixture-nonce',
                  'run_context': ctx, 'parent_identity': parent, 'worker_identity': worker}
        saved = {}
        def load(path, *args):
            return active if path.name == 'active-plan.json' else {'run_context': ctx}
        def save(path, value, **kwargs): saved[path.name] = copy.deepcopy(value)
        with ExitStack() as stack:
            for control in (
                patch.object(sys, 'argv', ['reference_image_recovery.py', '_worker', 'plan']),
                patch.object(sys, 'platform', 'linux'),
                patch.object(os, 'getuid', return_value=1001, create=True),
                patch.object(recovery, 'ensure_metadata'), patch.object(recovery, 'paths', return_value=p),
                patch.object(recovery, 'context', return_value=ctx), patch.object(recovery, 'load', side_effect=load),
                patch.object(recovery, 'save', side_effect=save),
                patch.object(recovery.os, 'statvfs', return_value=SimpleNamespace(f_frsize=4096), create=True),
                patch.object(recovery.supervisor, 'await_startup_gate'),
                patch.object(recovery.supervisor, 'process_identity', return_value=worker),
                patch.object(recovery.supervisor, 'same_process', return_value=True),
                patch.dict(os.environ, {'FQ_ACCOUNTED_BASE_BYTES': str(baseline),
                                       'FQ_IMAGE_RECOVERY_PARENT_NONCE': 'fixture-nonce'})):
                stack.enter_context(control)
            with redirect_stdout(io.StringIO()) as output:
                result = recovery.main()
        return result, saved, json.loads(output.getvalue().splitlines()[-1])

    def test_actual_worker_plan_dispatch_exits_zero_only_for_admitted_pass(self):
        code, saved, output = self.dispatch(2_000_000_000)
        self.assertEqual(code, 0)
        self.assertEqual(saved['plan.json']['status'], 'PASS')
        self.assertEqual(saved['plan.json']['plan']['admission'], 'ALLOW')
        self.assertEqual(output['status'], 'PASS')

    def test_refused_actual_worker_preserves_truthful_plan_and_exits_nonzero(self):
        code, saved, output = self.dispatch(12_000_000_000)
        self.assertEqual(code, 1)
        self.assertEqual(saved['plan.json']['status'], 'REFUSE')
        self.assertEqual(saved['plan.json']['plan']['admission'], 'REFUSE')
        self.assertEqual(output['status'], 'FAIL')


class RecoveryStageChallenge(unittest.TestCase):
    def setUp(self):
        cache = ROOT / '.cache/tmp'; cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='recovery-stage-challenge-', dir=cache)
        self.addCleanup(temporary.cleanup)
        self.local = Path(temporary.name)
        self.ctx = {'profile': recovery.PROFILE, 'source': 'a' * 64}

    def fixture(self):
        parent = {'pid': 12001, 'ppid': 12000, 'start_time_ticks': 11}
        worker = {'pid': 12002, 'ppid': 12001, 'start_time_ticks': 12}
        captures = {}
        for label, raw in (('stdout', b'actual tiny captured fixture\n'), ('stderr', b'')):
            path = self.local / ('parent-quota.' + label); path.write_bytes(raw)
            captures[label] = {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        active = {'action': 'quota', 'state': 'RUNNING', 'nonce': 'fixture', 'run_context': self.ctx,
                  'parent_identity': parent, 'worker_identity': worker}
        record = {'status': 'PASS', 'action': 'quota', 'run_context': self.ctx,
                  'nonce': 'fixture', 'parent_identity': parent,
                  'supervision': {'status': 'PASS', 'worker_started': True, 'worker_exit_code': 0,
                    'worker_identity': worker, 'termination_reason': None, 'errors': [],
                    'startup_gate_released_after_durable_publication': True,
                    'capture_complete': True, 'discarded_output_bytes': 0,
                    'captured_output_bytes': sum(item['bytes'] for item in captures.values()), 'capture': captures,
                    'descendant_quiescence': {'quiescent': True, 'residual': []}}}
        return record, active

    def validate(self, record, active):
        (self.local / 'parent-quota.json').write_text(json.dumps(record))
        (self.local / 'active-quota.json').write_text(json.dumps(active))
        with patch.object(recovery, 'context', return_value=self.ctx):
            return recovery.require_stage({'local': self.local}, 'quota')

    def test_complete_canonical_actual_capture_fixture_is_accepted(self):
        record, active = self.fixture()
        self.assertEqual(self.validate(record, active), record)

    def test_wrong_action_worker_failure_termination_and_capture_tampering_refuse(self):
        mutations = (
            lambda r, a: r.update(action='inspect'),
            lambda r, a: r['supervision'].update(status='FAIL'),
            lambda r, a: r['supervision'].update(worker_exit_code=1),
            lambda r, a: r['supervision'].update(worker_exit_code=False),
            lambda r, a: r['supervision'].update(worker_started=False),
            lambda r, a: r['supervision'].update(termination_reason='timeout'),
            lambda r, a: r['supervision'].update(errors=['actual retained error']),
            lambda r, a: r['supervision'].update(startup_gate_released_after_durable_publication=False),
            lambda r, a: r.update(nonce='different-parent'),
            lambda r, a: a.update(action='inspect'),
            lambda r, a: a['worker_identity'].update(start_time_ticks=99),
            lambda r, a: r['supervision'].update(captured_output_bytes=0),
            lambda r, a: r['supervision']['capture']['stdout'].update(path=str(self.local / 'elsewhere')),
            lambda r, a: r['supervision']['capture']['stdout'].update(bytes=1),
            lambda r, a: r['supervision']['capture']['stdout'].update(sha256='0' * 64),
            lambda r, a: (self.local / 'parent-quota.stdout').write_bytes(b'tampered after supervisor PASS'),
        )
        for number, mutation in enumerate(mutations):
            record, active = self.fixture()
            # Deliberately break aliasing between the durable parent records.
            record, active = copy.deepcopy(record), copy.deepcopy(active)
            mutation(record, active)
            with self.subTest(mutation=number), self.assertRaises(ValueError): self.validate(record, active)


class RecoveryFinalizerChallenge(unittest.TestCase):
    def exercise(self, *, body_failure=False, export_failure=False, unmount_failure=False,
                 hash_failure=False, save_failure=False):
        folder = ROOT / '.cache/tmp/synthetic-uncreated-inspection'
        p = {key: folder / key for key in ('local', 'outer', 'image', 'mount', 'scratch', 'analysis', 'volume')}
        ctx = {'source': 'a' * 64}; events, saved = [], {}
        def load(path, *args):
            if path.name == 'extraction.json': return {'run_context': ctx, 'image_identity': ['frozen']}
            if path.name == 'coverage.json': return {'source': recovery.OLD_SOURCE, 'profile': 'full',
                                                      'config': {'concurrency': 1}}
            return {'exit_code': 0}
        def save(path, value, **kwargs):
            events.append('save:' + path.name)
            if save_failure and path.name == 'inspection.json': raise OSError('synthetic receipt failure')
            saved[path.name] = copy.deepcopy(value)
        calls = {'hash': 0, 'walk': 0}
        def hash_file(*args):
            calls['hash'] += 1; events.append('hash')
            if hash_failure and calls['hash'] > 1: raise OSError('synthetic final hash failure')
            return recovery.IMAGE_SHA
        def walk(*args):
            calls['walk'] += 1
            if body_failure: raise ValueError('synthetic original operation failure')
            return {'complete': True}, ['benchmarks/full-fixture/coverage.json']
        def export(*args):
            events.append('export')
            if export_failure: raise PermissionError('synthetic export failure')
            return {'complete_available_output_export': True}
        def close(*args, **kwargs):
            events.append('unmount')
            if unmount_failure: raise OSError('synthetic close failure')
            return {'status': 'PASS'}
        with ExitStack() as stack:
            for control in (
                patch.object(recovery, 'admitted', return_value=(p, ctx)), patch.object(recovery, 'outer'),
                patch.object(recovery, 'identity', return_value=['frozen']),
                patch.object(recovery, 'hash_regular', side_effect=hash_file), patch.object(recovery, 'load', side_effect=load),
                patch.object(recovery, 'capacity'), patch.object(recovery, 'save', side_effect=save),
                patch.object(recovery, 'command', return_value=(b'', b'', {})),
                patch.object(recovery, 'mount_observation', return_value={}),
                patch.object(recovery, 'external_admission', return_value=0),
                patch.object(recovery, 'walk_inventory', side_effect=walk),
                patch.object(recovery, 'export_analysis', side_effect=export),
                patch.object(recovery, 'unmount_exact', side_effect=close)):
                stack.enter_context(control)
            try: result, error = recovery.inspect(), None
            except BaseException as actual: result, error = None, actual
        return result, error, events, saved

    def test_successful_unit_inspection_closes_hashes_and_retains_receipt(self):
        result, error, events, saved = self.exercise()
        self.assertIsNone(error)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(events.count('hash'), 2)
        self.assertIn('unmount', events)
        self.assertEqual(saved['inspection.json']['status'], 'PASS')

    def test_export_failure_still_unmounts_hashes_and_saves_explicit_failure(self):
        result, error, events, saved = self.exercise(export_failure=True)
        self.assertIsNone(result); self.assertIsInstance(error, ValueError)
        self.assertIn('unmount', events); self.assertEqual(events.count('hash'), 2)
        self.assertEqual(saved['inspection.json']['status'], 'FAIL')
        self.assertEqual(saved['inspection.json']['inspection_status'], 'FAIL')
        self.assertIn('analysis_export', [item['phase'] for item in saved['inspection.json']['failures']])

    def test_all_original_and_finalizer_failures_survive_alternate_receipt(self):
        result, error, events, saved = self.exercise(body_failure=True, export_failure=True,
            unmount_failure=True, hash_failure=True, save_failure=True)
        self.assertIsNone(result); self.assertIsInstance(error, ValueError)
        self.assertIn('unmount', events); self.assertEqual(events.count('hash'), 2)
        record = saved['inspection.failure.json']
        self.assertEqual(record['status'], 'FAIL')
        self.assertEqual({item['phase'] for item in record['failures']},
                         {'operation', 'analysis_export', 'readonly_close', 'final_image_hash', 'inspection_receipt'})


class RecoveryPhysicalAndFormatChallenge(unittest.TestCase):
    def test_two_one_byte_files_and_directory_have_independent_block_padding(self):
        result = recovery.physical_tail(4096, [1, 1], 1)
        self.assertEqual(result['physical_bytes'], 12288)
        self.assertEqual(result['file_allocation_bytes'], 8192)
        self.assertEqual(result['directory_allocation_bytes'], 4096)
        self.assertEqual(result['entries'], 3)
        for args in ((4096, [True], 1), (4096, [1], -1), (8192, [1], 1)):
            with self.subTest(args=args), self.assertRaises(ValueError): recovery.physical_tail(*args)

    def test_production_capacity_saves_physical_tail_and_refuses_aggregate_only_fit(self):
        p = {'volume': Path('/synthetic/volume'), 'outer': Path('/synthetic/outer.img'), 'local': Path('/synthetic/meta')}
        saved = []
        def check(path, **kwargs): return SimpleNamespace(st_dev=2 if path == p['volume'] else 1)
        def save(path, value, **kwargs): saved.append(copy.deepcopy(value))
        enough = (recovery.FREE_RESERVE + 12288 + 4095) // 4096
        with patch.object(recovery, 'checked', side_effect=check), patch.object(recovery, 'save', side_effect=save), \
                patch.object(recovery.os, 'statvfs', return_value=SimpleNamespace(
                    f_frsize=4096, f_bavail=enough, f_favail=100), create=True):
            result = recovery.capacity(p, 'synthetic', [1, 1], 1)
            self.assertTrue(result['allowed'])
            self.assertEqual(result['physical_tail']['physical_bytes'], 12288)
        with patch.object(recovery, 'checked', side_effect=check), patch.object(recovery, 'save', side_effect=save), \
                patch.object(recovery.os, 'statvfs', return_value=SimpleNamespace(
                    f_frsize=4096, f_bavail=enough - 1, f_favail=100), create=True), self.assertRaises(ValueError):
            recovery.capacity(p, 'insufficient', [1, 1], 1)
        self.assertFalse(saved[-1]['allowed'])
        self.assertEqual(saved[-1]['physical_tail']['physical_bytes'], 12288)

    def raw_geometry(self):
        return '\n'.join((
            'Filesystem UUID: 12345678-abcd-1234-abcd-123456789abc',
            'Filesystem features: has_journal ext_attr resize_inode dir_index filetype extent 64bit flex_bg sparse_super large_file huge_file dir_nlink extra_isize metadata_csum',
            'Block count: 512695', 'Block size: 4096', 'Reserved block count: 0',
            'Inode count: 4096', 'Inode size: 256', 'First block: 0', 'Blocks per group: 32768',
            'Inodes per group: 256', 'Inode blocks per group: 16', 'Journal features: (none)',
            'Total journal size: 16M', 'Total journal blocks: 4096')) + '\n'

    def test_recovery_only_formatter_and_exact_observed_journal_inode_geometry(self):
        image = Path('/synthetic/recovery.img')
        self.assertEqual(recovery.recovery_formatter_argv(image), ['mkfs.ext4', '-F', '-q', '-m', '0',
            '-N', '4096', '-I', '256', '-J', 'size=16', str(image)])
        result = recovery.recovery_geometry(self.raw_geometry())
        self.assertEqual(result['journal_bytes'], 16 * 1024 * 1024)
        self.assertEqual(result['requested_inode_count'], 4096)
        self.assertEqual(result['inode_count'], 4096)
        self.assertEqual(result['reserved_blocks'], 0)

    def test_fast_commit_unknown_features_journal_size_and_inode_rounding_refuse(self):
        raw = self.raw_geometry()
        mutations = (
            raw.replace('has_journal ', ''), raw.replace('has_journal ', 'has_journal fast_commit '),
            raw.replace('has_journal ', 'has_journal unexpected_feature '),
            raw.replace('Journal features: (none)', 'Journal features: journal_fast_commit'),
            raw.replace('Total journal blocks: 4096', 'Total journal blocks: 8192'),
            raw.replace('Total journal size: 16M', 'Total journal size: 32M'),
            raw.replace('Inode size: 256', 'Inode size: 128'),
            raw.replace('Inode count: 4096', 'Inode count: 4097'),
            raw.replace('Inodes per group: 256', 'Inodes per group: 257'),
            raw.replace('Reserved block count: 0', 'Reserved block count: 1'),
        )
        for number, value in enumerate(mutations):
            with self.subTest(mutation=number), self.assertRaises(ValueError): recovery.recovery_geometry(value)


if __name__ == '__main__': unittest.main()
