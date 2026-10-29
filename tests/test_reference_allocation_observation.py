"""Finite recorded-fact controls; these do not prove a Linux allocation."""
from contextlib import ExitStack
import copy
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


class AllocationObservationTests(unittest.TestCase):
    def observation(self):
        plan = control.padding_plan(1_595_326_464, 4096)
        before = {'device': 1792, 'inode': 2243, 'mode': stat.S_IFREG | 0o600,
                  'uid': 1001, 'gid': 1001, 'nlink': 1, 'bytes': 0, 'physical_bytes': 0}
        after = {**before, 'bytes': plan['padding_bytes'], 'physical_bytes': plan['padding_bytes']}
        return {'kind': control.KIND, 'status': 'OBSERVED_UNVALIDATED',
                'source': 'a' * 64, 'run_context': {'source': 'a' * 64},
                'padding_before': before, 'padding_after': after,
                'descriptor_before': dict(before), 'descriptor_after': dict(after),
                'padding_plan': plan, 'statvfs_before': {'f_bavail': 389484, 'f_frsize': 4096},
                'statvfs_after': {'f_bavail': 146484, 'f_frsize': 4096},
                'command_outcome': {'exit_code': 0, 'capture_complete': True,
                                    'descendant_quiescence': {'quiescent': True, 'residual': []}}}

    def temporary(self, stack):
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        folder = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='allocation-facts-', dir=cache)))
        stack.enter_context(patch.object(os, 'getuid', return_value=folder.stat().st_uid, create=True))
        if not hasattr(os, 'O_NOFOLLOW'):
            stack.enter_context(patch.object(os, 'O_NOFOLLOW', 0, create=True))
        return folder

    def test_strict_physical_refusal_keeps_complete_exclusive_observation(self):
        observation = self.observation()
        observation['padding_after']['physical_bytes'] += 4096
        observation['descriptor_after'] = dict(observation['padding_after'])
        with ExitStack() as stack:
            folder = self.temporary(stack)
            with self.assertRaisesRegex(ValueError, 'after.physical_bytes'):
                control.check_observed_allocation(folder, observation)
            path = folder / 'allocation.observed.json'
            raw = path.read_bytes()
            self.assertEqual(json.loads(raw), observation)
            self.assertLessEqual(len(raw), 160_000)
            with self.assertRaises(FileExistsError):
                control.check_observed_allocation(folder, observation)
            self.assertEqual(path.read_bytes(), raw)

    def test_descriptor_substitution_is_named_and_recorded_before_refusal(self):
        observation = self.observation()
        observation['descriptor_after']['inode'] += 1
        with ExitStack() as stack:
            folder = self.temporary(stack)
            with self.assertRaisesRegex(ValueError, 'descriptor_after'):
                control.check_observed_allocation(folder, observation)
            self.assertEqual(json.loads((folder / 'allocation.observed.json').read_bytes()), observation)

    def test_matching_facts_pass_and_all_original_strict_checks_remain(self):
        observation = self.observation()
        with ExitStack() as stack:
            folder = self.temporary(stack)
            result = control.check_observed_allocation(folder, observation)
            self.assertEqual(result['exact_allocated_bytes'], observation['padding_plan']['padding_bytes'])
        for key, value in (('inode', 1), ('mode', stat.S_IFREG | 0o644), ('uid', 0),
                           ('gid', 0), ('nlink', 2), ('bytes', 0), ('physical_bytes', 0)):
            changed = copy.deepcopy(observation)
            changed['padding_after'][key] = value
            changed['descriptor_after'] = dict(changed['padding_after'])
            with self.subTest(key=key), ExitStack() as stack:
                folder = self.temporary(stack)
                with self.assertRaises(ValueError):
                    control.check_observed_allocation(folder, changed)
                self.assertTrue((folder / 'allocation.observed.json').is_file())


if __name__ == '__main__':
    unittest.main()
