"""Synthetic disabled-feature and pre-mount ownership controls; no Linux claim."""
import ast
from contextlib import ExitStack
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference_image_recovery as recovery
import test_reference_image_recovery_challenge as challenge


class RecoveryDisabledFeatureControls(unittest.TestCase):
    def raw(self):
        return challenge.RecoveryPhysicalAndFormatChallenge().raw_geometry()

    def test_optional_disabled_fast_commit_report_accepts_actual_like_padding(self):
        baseline = recovery.recovery_geometry(self.raw())
        for suffix in ('Fast commit length:       0\n', 'Fast commit length:\t0  \n'):
            with self.subTest(suffix=suffix):
                result = recovery.recovery_geometry(self.raw() + suffix)
                for key in baseline:
                    self.assertEqual(result[key], baseline[key])

    def test_nonzero_malformed_duplicate_and_unknown_fast_commit_reports_refuse(self):
        for suffix in ('Fast commit length: 1\n', 'Fast commit length: -1\n',
                       'Fast commit length: zero\n', 'Fast commit length: 0 extra\n',
                       'Fast commit length: 0\nFast commit length: 0\n',
                       'Fast commit unknown: 0\n', 'Fast commit length: 0\nFast commit unknown: 0\n'):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                recovery.recovery_geometry(self.raw() + suffix)

    def test_disabled_numeric_report_never_overrides_enabled_journal_features(self):
        raw = self.raw() + 'Fast commit length: 0\n'
        for value in (raw.replace('Journal features: (none)', 'Journal features: fast_commit'),
                      raw.replace('has_journal ', 'has_journal fast_commit '),
                      raw.replace('Total journal blocks: 4096', 'Total journal blocks: 8192')):
            with self.subTest(value=value[-160:]), self.assertRaises(ValueError):
                recovery.recovery_geometry(value)

    def fixture(self):
        p = {'local': Path('/synthetic/control'), 'outer': Path('/synthetic/outer.img'),
             'volume': Path('/synthetic/volume'), 'mount': Path('/synthetic/volume/original')}
        ctx = {'source': 'a' * 64, 'github_run_id': '123', 'github_run_attempt': '1'}
        identity = [7, 11, stat.S_IFREG | 0o600, 1001, 1001, 1, recovery.OUTER_BYTES]
        proof = {'status': 'PASS', 'run_context': ctx, 'outer_path': str(p['outer']),
                 'volume_path': str(p['volume']), 'image_identity': identity,
                 'outer_bytes': recovery.OUTER_BYTES,
                 'created_via': 'exclusive-descriptor-fsynced-posix-fallocate-v1',
                 'hard_quota_enforced': False}
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1001, st_gid=1001,
                               st_nlink=1, st_size=recovery.OUTER_BYTES, st_dev=7, st_ino=11)
        return p, ctx, proof, info

    def retained(self, *, mutate=None, loops=None, identities=None, mounted=False, missing=False):
        p, ctx, proof, info = self.fixture()
        actual_identity = list(proof['image_identity'])
        if mutate:
            mutate(proof, info)
        def load(path, *args):
            self.assertEqual(path, p['local'] / 'outer-allocation.json')
            if missing:
                raise FileNotFoundError('synthetic missing allocation proof')
            return proof
        command_result = b'{"loopdevices":[]}' if loops is None else loops
        with ExitStack() as stack:
            for control in (patch.object(recovery, 'load', side_effect=load),
                            patch.object(recovery, 'checked', return_value=info),
                            patch.object(recovery.os, 'getuid', return_value=1001, create=True),
                            patch.object(recovery.os.path, 'ismount', return_value=mounted),
                            patch.object(recovery, 'backing_identity', side_effect=identities) if identities
                            else patch.object(recovery, 'backing_identity', return_value=actual_identity),
                            patch.object(recovery, 'command', return_value=(command_result, b'', {}))):
                stack.enter_context(control)
            with patch.object(recovery.os, 'unlink') as unlink:
                result = recovery.retained_unmounted_outer(p, ctx)
                unlink.assert_not_called()
        return result

    def test_owned_unmounted_retention_requires_positive_creation_and_empty_exact_loop_query(self):
        p, ctx, _, _ = self.fixture()
        result = self.retained()
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['state'], 'OWNED_UNMOUNTED_RETAINED')
        self.assertIs(result['hard_quota_enforced'], False)
        # A dedicated call records the exact authorization-relevant query.
        _, _, proof, info = self.fixture()
        with patch.object(recovery, 'load', return_value=proof), \
                patch.object(recovery, 'checked', return_value=info), \
                patch.object(recovery.os, 'getuid', return_value=1001, create=True), \
                patch.object(recovery.os.path, 'ismount', return_value=False), \
                patch.object(recovery, 'backing_identity', return_value=proof['image_identity']), \
                patch.object(recovery, 'command', return_value=(b'{"loopdevices":[]}', b'', {})) as command:
            recovery.retained_unmounted_outer(p, ctx)
        self.assertEqual(command.call_args.args[0], ['sudo', '-n', 'losetup', '--json', '--list',
            '--associated', str(p['outer']), '--output', 'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT,RO'])

    def test_missing_cross_context_identity_or_incomplete_creation_proofs_refuse(self):
        with self.assertRaises((FileNotFoundError, ValueError)):
            self.retained(missing=True)
        mutations = [lambda p, i: p.update(run_context={'source': 'b' * 64}),
                     lambda p, i: p.update(image_identity=[0] * 7),
                     lambda p, i: p.update(outer_path='/other.img'),
                     lambda p, i: p.update(volume_path='/other'),
                     lambda p, i: p.update(status='FAIL'),
                     lambda p, i: p.pop('created_via'),
                     lambda p, i: p.update(created_via='unverified'),
                     lambda p, i: p.update(hard_quota_enforced=True),
                     lambda p, i: p.pop('hard_quota_enforced')]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.retained(mutate=mutation)

    def test_unmounted_retention_rejects_unsafe_stat_live_loops_and_identity_changes(self):
        for field, value in (('st_uid', 0), ('st_mode', stat.S_IFREG | 0o644),
                             ('st_mode', stat.S_IFLNK | 0o600), ('st_nlink', 2),
                             ('st_size', recovery.OUTER_BYTES - 1)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.retained(mutate=lambda p, i: setattr(i, field, value))
        for loops in (b'{}', b'{"loopdevices":[],"other":1}', b'{"loopdevices":[{"name":"/dev/loop7"}]}'):
            with self.subTest(loops=loops), self.assertRaises(ValueError):
                self.retained(loops=loops)
        with self.assertRaises(ValueError): self.retained(mounted=True)
        identity = self.fixture()[2]['image_identity']
        with self.assertRaises(ValueError): self.retained(identities=[identity, [0] * 7])

    def test_cleanup_routes_only_existing_unmounted_outer_to_retention_helper(self):
        p, ctx, _, _ = self.fixture()
        for mounted, exists, expected in ((False, True, 1), (False, False, 0), (True, True, 0)):
            def ismount(path): return path == p['volume'] and mounted
            with self.subTest(mounted=mounted, exists=exists), \
                    patch.object(recovery, 'admitted', return_value=(p, ctx)), \
                    patch.object(recovery.os.path, 'ismount', side_effect=ismount), \
                    patch.object(recovery.os.path, 'lexists', return_value=exists), \
                    patch.object(recovery, 'outer'), patch.object(recovery, 'unmount_exact', return_value={}), \
                    patch.object(recovery, 'save'), \
                    patch.object(recovery, 'retained_unmounted_outer', return_value={'status': 'PASS'}) as retained:
                recovery.cleanup()
                self.assertEqual(retained.call_count, expected)
                if expected: retained.assert_called_once_with(p, ctx)

    def test_production_quota_publishes_allocation_proof_after_close_before_formatter(self):
        tree = ast.parse(Path(recovery.__file__).read_text())
        quota = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'quota')
        calls = [node for node in ast.walk(quota) if isinstance(node, ast.Call)]
        close = next(node for node in calls if ast.unparse(node.func) == 'os.close')
        publication = next(node for node in calls if ast.unparse(node.func) == 'save'
                           and 'outer-allocation.json' in ast.unparse(node))
        formatter = next(node for node in calls if ast.unparse(node.func) == 'recovery_formatter_argv')
        self.assertLess(close.lineno, publication.lineno)
        self.assertLess(publication.lineno, formatter.lineno)
        for literal in ('exclusive-descriptor-fsynced-posix-fallocate-v1', 'hard_quota_enforced',
                        'image_identity', 'run_context', 'outer_path', 'volume_path'):
            self.assertIn(literal, ast.unparse(publication))


if __name__ == '__main__': unittest.main()
