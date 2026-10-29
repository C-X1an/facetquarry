"""Finite arithmetic/real-byte/refusal controls. NO actual filesystem proof."""
import copy
from contextlib import ExitStack
import hashlib
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


class TrimControlTests(unittest.TestCase):
    def context(self):
        return {'source': 'a' * 64, 'commit': 'b' * 40, 'git_status': '',
                'github_run_id': '17', 'github_run_attempt': '2'}

    def test_control_requires_each_explicit_nonqualifying_selection(self):
        env = {'FQ_TRIM_CONTROL': 'true', 'FQ_PRESERVATION_CONTROL': 'true',
               'FQ_BENCH_PROFILE': 'smoke', 'FQ_BENCH_CONCURRENCY': '1',
               'FQ_RESERVATION_PROFILE': control.transport.PROFILE}
        control.explicit_control(env)
        for key in env:
            for value in ('', 'false', 'full', '4'):
                with self.subTest(key=key, value=value):
                    changed = {**env, key: value}
                    with self.assertRaises(ValueError):
                        control.explicit_control(changed)

    def test_exact_block_plan_forces_pressure_without_spending_the_floor_or_margin(self):
        for block in (1024, 2048, 4096):
            for available in (700_000_001, 921_000_000, 1_000_000_003):
                with self.subTest(block=block, available=available):
                    plan = control.padding_plan(available, block)
                    self.assertEqual(plan['padding_bytes'] % block, 0)
                    self.assertEqual(available - plan['padding_bytes'], plan['predicted_available_after_bytes'])
                    self.assertGreaterEqual(plan['predicted_available_after_bytes'], control.MIN_FREE)
                    self.assertLess(plan['predicted_available_after_bytes'], control.TARGET_FREE + block)
                    self.assertEqual(plan['unchanged_package_threshold_bytes'], 921_000_000)
                    self.assertEqual(control.transport.FILESYSTEM_FLOOR, 500_000_000)
                    self.assertEqual(control.transport.GLOBAL_RESERVE, 2_000_000_000)
        for available, block in ((600_000_000, 4096), (590_000_000, 4096), (1, 4096),
                                 (True, 4096), (900_000_000, 512), (4_000_000_000, 4096)):
            with self.assertRaises(ValueError):
                control.padding_plan(available, block)

    def test_synthetic_allocation_requires_same_inode_and_exact_physical_blocks(self):
        plan = control.padding_plan(1_000_000_000, 4096)
        before = {'device': 1792, 'inode': 11, 'mode': stat.S_IFREG | 0o600,
                  'uid': 1001, 'gid': 1001, 'nlink': 1, 'bytes': 0, 'physical_bytes': 0}
        after = {**before, 'bytes': plan['padding_bytes'], 'physical_bytes': plan['padding_bytes']}
        free = plan['predicted_available_after_bytes']
        result = control.allocation_check(before, after, plan, free)
        self.assertEqual(result['exact_allocated_bytes'], plan['padding_bytes'])
        for key, value in (('inode', 12), ('uid', 0), ('nlink', 2), ('bytes', 1), ('physical_bytes', 0)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                control.allocation_check(before, {**after, key: value}, plan, free)
        for value in (control.MIN_FREE - 1, 921_000_000, free - 2_000_000):
            with self.assertRaises(ValueError):
                control.allocation_check(before, after, plan, value)

    def test_actual_pack_receipt_context_control_and_branch_pressure_are_required(self):
        ctx = self.context()
        pack = {'run_context': ctx, 'profile': control.transport.PROFILE, 'source': ctx['source'],
                'control': True, 'status': 'FAIL', 'physical_before': control.transport.physical_admission(600_000_000)}
        self.assertFalse(control.pressure_check(pack, ctx)['allowed'])
        for edit in (lambda x: x.update(control=False), lambda x: x.update(status='PASS'),
                     lambda x: x.update(source='c' * 64), lambda x: x['run_context'].update(github_run_attempt='3'),
                     lambda x: x.update(physical_before=control.transport.physical_admission(921_000_000)),
                     lambda x: x['physical_before'].update(filesystem_free_floor_bytes=1),
                     lambda x: x.update(physical_before=control.transport.physical_admission(580_000_000))):
            value = copy.deepcopy(pack)
            edit(value)
            with self.assertRaises(ValueError):
                control.pressure_check(value, ctx)

    def test_intentional_child_needs_positive_stop_complete_capture_and_current_context(self):
        ctx = self.context()
        value = {'status': 'FAIL', 'phase': 'COMPLETE', 'source': ctx['source'], 'commit': ctx['commit'],
                 'run_id': '17', 'run_attempt': '2', 'control': True, 'termination_reason': 'timeout',
                 'child_stopped': True, 'originals_unchanged': True, 'stream_capture_complete': True,
                 'discarded_stream_bytes': 0, 'captured_stream_bytes': 0, 'errors': [], 'residual_package_safe': True}
        self.assertEqual(control.failed_child_check(value, ctx)['status'], 'PASS')
        for invalid in (None,True,-1,control.transport.artifacts.CAPTURE_BYTES+1):
            with self.subTest(captured_stream_bytes=invalid), self.assertRaises(ValueError):
                control.failed_child_check({**value,'captured_stream_bytes':invalid},ctx)
        missing=dict(value);missing.pop('captured_stream_bytes')
        with self.assertRaises(ValueError):control.failed_child_check(missing,ctx)
        for key, changed in (('child_stopped', False), ('stream_capture_complete', False),
                             ('originals_unchanged', False), ('termination_reason', 'wrapper_exception'),
                             ('run_attempt', '1'), ('discarded_stream_bytes', 1), ('errors', ['unknown']),
                             ('residual_package_safe', False)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                control.failed_child_check({**value, key: changed}, ctx)

    def test_refusal_facts_are_exact_bounded_and_never_inferred(self):
        facts = {'path': 'reference-guest/apt/partial', 'path_truncated': False, 'expected_uid': 1001,
                 'observed_uid': 0, 'observed_gid': 0, 'observed_nlink': 1,
                 'mode': stat.S_IFDIR | 0o700, 'device': 1792, 'inode': 31}
        prefix = 'ValueError: trim or provenance member is not an owned single-link inode: '
        self.assertEqual(control.inode_refusals([prefix + json.dumps(facts)]), [facts])
        self.assertEqual(control.inode_refusals(['some ownership issue without inode facts']), [])
        for changed in ({**facts, 'cause': 'guessed'}, {**facts, 'path': 'x' * 513},
                        {**facts, 'observed_uid': 'root'}):
            with self.assertRaises(ValueError):
                control.inode_refusals([prefix + json.dumps(changed)])
        with self.assertRaises(ValueError):
            control.inode_refusals([prefix + '{"path":"one","path":"two"}'])

    def test_combined_capture_binds_two_actual_tiny_streams_to_declared_counter(self):
        # Finite local bytes only; no launched child or integration qualification.
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='trim-capture-', dir=cache) as folder:
            audit = Path(folder)
            attempt = {'captured_stream_bytes': 9}
            for label, raw in (('stdout', b'four'), ('stderr', b'five!')):
                (audit / ('pack-' + label + '.txt')).write_bytes(raw)
                attempt[label + '_sha256'] = hashlib.sha256(raw).hexdigest()
            self.assertEqual(control.failed_child_capture(audit, attempt), {'captured_stream_bytes': 9})
            for wrong in (0, 8, 10, None, True, -1, control.transport.artifacts.CAPTURE_BYTES + 1):
                with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                    control.failed_child_capture(audit, {**attempt, 'captured_stream_bytes': wrong})
            missing = dict(attempt)
            missing.pop('captured_stream_bytes')
            with self.assertRaises(ValueError):
                control.failed_child_capture(audit, missing)
            (audit / 'pack-stderr.txt').write_bytes(b'other')
            with self.assertRaises(ValueError):
                control.failed_child_capture(audit, attempt)

    def test_fixed_checkpoint_reservation_refuses_complete_byte_or_entry_overflow(self):
        original = {'physical_bytes': 80_000, 'logical_bytes': 70_000, 'entries': 8}
        admitted = control.verification_admission(original, 4096)
        self.assertLessEqual(original['physical_bytes'] + admitted['reserved_bytes'], control.CONTROL_BYTES)
        self.assertLessEqual(original['entries'] + admitted['reserved_entries'], control.CONTROL_ENTRIES)
        for allocation in ({**original, 'physical_bytes': control.CONTROL_BYTES},
                           {**original, 'logical_bytes': control.CONTROL_BYTES},
                           {**original, 'entries': control.CONTROL_ENTRIES}):
            with self.assertRaises(ValueError):
                control.verification_admission(allocation, 4096)
        with self.assertRaises(ValueError):
            control.verification_admission(original, 65536)

    def test_append_only_stage_bytes_keep_completed_facts_and_unknown_retention(self):
        # A finite interrupted sequence, not an actual killed process test.
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='trim-checkpoint-', dir=cache) as folder, ExitStack() as stack:
            audit = Path(folder)
            stack.enter_context(patch.object(os, 'getuid', return_value=audit.stat().st_uid, create=True))
            if not hasattr(os, 'O_NOFOLLOW'):
                stack.enter_context(patch.object(os, 'O_NOFOLLOW', 0, create=True))
            record = {'source': self.context()['source'], 'run_context': self.context(), 'inode_refusals': [],
                      'stages': {name: {'status': 'PENDING'} for name in control.VERIFY_STAGES}}
            control.stage_checkpoint(audit, record, 'actual_guest_trim', pending=True)
            record['stages']['actual_guest_trim'] = {'status': 'FAIL', 'error': 'exact producer refusal retained'}
            control.stage_checkpoint(audit, record, 'actual_guest_trim', pending=False)
            completed_path = audit / 'verify-stage-2.json'
            completed_bytes = completed_path.read_bytes()
            control.stage_checkpoint(audit, record, 'exact_image_readonly_retention', pending=True)
            completed = json.loads(completed_bytes)
            self.assertEqual(completed['outcome'], record['stages']['actual_guest_trim'])
            self.assertEqual(completed['retention_status'], 'PENDING')
            pending = json.loads((audit / 'verify-stage-5.pending.json').read_bytes())
            self.assertEqual((pending['status'], pending['retention_status']), ('PENDING', 'PENDING'))
            self.assertFalse((audit / 'verify-stage-5.json').exists())
            self.assertEqual(completed_path.read_bytes(), completed_bytes)
            with self.assertRaises(FileExistsError):
                control.stage_checkpoint(audit, record, 'actual_guest_trim', pending=False)
            for path in audit.iterdir():
                self.assertLessEqual(path.stat().st_size, control.STAGE_BYTES)

    def test_complete_sealed_copy_manifest_checks_real_bytes_and_membership(self):
        # Real tiny byte reads only; this cannot authorize a mount or recovery.
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='trim-control-', dir=cache) as folder:
            prepared = Path(folder)
            file = prepared / 'prepare.json'
            file.write_bytes(b'finite original control proof\n')
            before = {'manifest': [
                {'path': '.local/reference-trim-control/', 'directory': True, 'bytes': 0,
                 'mode': stat.S_IMODE(prepared.stat().st_mode), 'sha256': None},
                {'path': '.local/reference-trim-control/prepare.json', 'directory': False,
                 'bytes': file.stat().st_size, 'mode': stat.S_IMODE(file.stat().st_mode),
                 'sha256': hashlib.sha256(file.read_bytes()).hexdigest()}]}
            self.assertEqual(control.copied_manifest_check(prepared, before)['copied_members'], 2)
            file.write_bytes(b'changed later bytes\n')
            with self.assertRaises(ValueError):
                control.copied_manifest_check(prepared, before)
            file.unlink()
            with self.assertRaises(ValueError):
                control.copied_manifest_check(prepared, before)


if __name__ == '__main__':
    unittest.main()
