"""Closed producer, byte binding and conservative capture reservation controls."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

if __package__:
    from .test_derived_profile_findings import probe, supervised, write_json
else:
    from test_derived_profile_findings import probe, supervised, write_json


class SealControls(unittest.TestCase):
    def test_empty_quota_staging_slots_are_not_started_later_producers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); local = root / 'local'; local.mkdir()
            volume = root / 'volume'; volume.mkdir()
            p = {'local': local, 'volume': volume, 'outer': root / 'outer.img',
                 'chunks': volume / 'chunks', 'mount': volume / 'readonly',
                 'wrapper': volume / 'wrapper.zip', 'image': volume / 'original.img'}
            p['chunks'].mkdir(); p['mount'].mkdir(); ctx = {'source': 'a' * 64}
            with patch.object(probe.os.path, 'ismount', return_value=False):
                for stage in ('download', 'observe'):
                    self.assertIsNone(probe.require_closed_stage(p, ctx, stage))
                for stage, path in [('download', p['chunks'] / 'partial'),
                                    ('observe', p['mount'] / 'unknown'),
                                    ('observe', local / 'inner-pending.json')]:
                    path.write_bytes(b'partial')
                    with self.subTest(stage=stage, path=path.name), self.assertRaises(ValueError):
                        probe.require_closed_stage(p, ctx, stage)
                    path.unlink()  # Fixture bytes only, deliberately created above.
            with patch.object(probe.os.path, 'ismount', return_value=True), self.assertRaises(ValueError):
                probe.require_closed_stage(p, ctx, 'observe')

    def test_external_reserves_unflushed_supervisor_streams_even_before_files_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            p = {'local': Path(directory) / 'absent'}
            with patch.object(probe, 'paths', return_value=p):
                self.assertGreaterEqual(probe.external(), 131072)
                with patch.object(probe, 'EXTERNAL_BYTES', 131071), self.assertRaises(ValueError):
                    probe.external()

    def test_terminal_metadata_rejects_wrong_exit_error_and_reason_types(self):
        cases = [('worker_exit_code', True), ('worker_exit_code', None),
                 ('worker_exit_code', '0'), ('errors', ''), ('errors', [17]),
                 ('termination_reason', []), ('termination_reason', 0)]
        for field, value in cases:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as directory:
                p = {'local': Path(directory)}; ctx = {'source': 'a' * 64}
                record, _ = supervised(p, ctx, status='FAIL')
                record['supervision'][field] = value
                write_json(p['local'] / 'parent-derive.json', record)
                with patch.object(probe.supervisor, 'same_process', return_value=False):
                    with self.assertRaises(ValueError): probe.require_closed_stage(p, ctx, 'derive')

    def test_command_accepted_nonzero_exit_is_valid_but_fabricated_status_refuses(self):
        ctx = {'repository': probe.REPOSITORY, 'repository_id': probe.REPOSITORY_ID,
               'profile': probe.PROFILE, 'commit': 'a' * 40,
               'github_run_id': '123', 'github_run_attempt': '1'}
        with tempfile.TemporaryDirectory() as directory:
            p = {'local': Path(directory)}; commands = p['local'] / 'commands'; commands.mkdir()
            stage, _ = supervised(p, ctx, status='FAIL')
            name = 'actual-enospc-0123456789ab'
            supervision = copy.deepcopy(stage['supervision'])
            supervision['termination_reason'] = None
            for label in ('stdout', 'stderr'):
                target = commands / (name + '.' + label)
                (p['local'] / ('parent-derive.' + label)).rename(target)
                supervision['capture'][label]['path'] = str(target)
            record = {'command_id': name, 'parent_identity': stage['parent_identity'],
                      'runtime_hint': probe.runtime_hint(ctx), 'supervision': supervision,
                      'accepted_exit_codes': [1], 'status': 'PASS'}
            write_json(commands / (name + '.json'), record)
            with patch.object(probe.supervisor, 'same_process', return_value=False):
                self.assertEqual(probe.require_closed_commands(p, ctx)[0]['status'], 'PASS')
                for change in ({'accepted_exit_codes': [0]}, {'status': 'FAIL'},
                               {'accepted_exit_codes': [True]}, {'accepted_exit_codes': []}):
                    write_json(commands / (name + '.json'), {**record, **change})
                    with self.subTest(change=change), self.assertRaises(ValueError):
                        probe.require_closed_commands(p, ctx)

    def test_recipe_or_ledger_mutation_cannot_keep_successful_derivation_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            p = {'local': Path(directory)}; ctx = {'source': 'a' * 64}
            value = {'status': 'PASS', 'run_context': ctx,
                     'counts': {'derived': 1, 'identity': probe.EXPECTED_PAIRS - 1, 'refused': 0}}
            write_json(p['local'] / 'derivation.json', value)
            for name in ('derived-recipes.jsonl.gz', 'derived-ledger.jsonl'):
                (p['local'] / name).write_bytes(b'original')
            _, binding = probe.bound_derivation(p, ctx)
            for name in ('derived-recipes.jsonl.gz', 'derived-ledger.jsonl', 'derivation.json'):
                path = p['local'] / name; original = path.read_bytes(); path.write_bytes(original + b' ')
                with self.subTest(name=name), self.assertRaises(ValueError):
                    probe.bound_derivation(p, ctx, binding)
                self.assertEqual(path.read_bytes(), original + b' ')
                path.write_bytes(original)
            restored, _ = probe.bound_derivation(p, ctx, binding)
            self.assertEqual(restored, value)


if __name__ == '__main__': unittest.main()
