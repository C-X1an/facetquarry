"""Synthetic exact partial-directory controls; privileged handoff needs Linux."""
import copy
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_apt_ownership as apt


class PartialHandoffTests(unittest.TestCase):
    def setUp(self):
        self.before = dict(device=17, inode=31, mode=stat.S_IFDIR | 0o755,
                           uid=1001, gid=1001, nlink=2, bytes=4096,
                           allocated=4096, mtime_ns=1, ctime_ns=1)
        self.after = {**self.before, 'gid': 0, 'mode': stat.S_IFDIR | 0o700}

    def validate(self, node=None, path='partial', binding=True, allow_root=True):
        return apt.validate_node(path, node or self.after, {}, 17, 1001, 1001,
                                 partial_binding=self.before if binding else None,
                                 allow_root=allow_root)

    def test_only_pinned_ordinary_uid_root_gid_private_partial_is_normalizable(self):
        self.assertTrue(self.validate())
        for changes in ({'inode': 32}, {'device': 18}, {'uid': 0, 'gid': 1001},
                        {'uid': 1002}, {'gid': 1002}, {'mode': stat.S_IFDIR | 0o755},
                        {'mode': stat.S_IFREG | 0o700}, {'nlink': 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.validate({**self.after, **changes})
        for path in ('log', 'lock'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.validate(path=path)
        with self.assertRaises(ValueError): self.validate(binding=False)
        with self.assertRaises(ValueError): self.validate(allow_root=False)

    def test_binding_must_describe_the_original_ordinary_directory(self):
        for changes in ({'uid': 0}, {'gid': 0}, {'mode': stat.S_IFLNK | 0o777},
                        {'mode': stat.S_IFDIR | 0o777}, {'inode': 32}, {'nlink': 1}):
            before = copy.deepcopy(self.before)
            self.before.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.validate()
            self.before = before

    def test_request_pins_the_precommand_partial_inode(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'reference-guest' / 'apt'
            (root / 'partial').mkdir(parents=True)
            account = {'name': 'fixture', 'uid': os.stat(root).st_uid, 'gid': os.stat(root).st_gid}
            request = apt.apt_request(root, account, [], 100000)
            self.assertEqual(request['partial_binding'], apt.facts((root / 'partial').lstat()))

    def test_complete_inventory_refuses_later_foreign_member_before_any_mutation(self):
        request = {'schema_version': 1, 'account': {'name': 'runner', 'uid': 1001, 'gid': 1001},
                   'archives': {}, 'max_bytes': 100000, 'anchors': {'root': {'device': 17}},
                   'partial_binding': self.before}
        def inventory(fd, request, output, **kwargs):
            output.append({'path': 'partial', **self.after})
            self.validate()
            raise ValueError('foreign later member')
        with patch.object(apt, 'require_root'), patch.object(apt, 'verify_requested_account'), \
             patch.object(apt, 'open_anchors', return_value=([], {'root': 7})), \
             patch.object(apt, 'inventory', side_effect=inventory), \
             patch.object(apt, 'chown_descriptor') as chown:
            with self.assertRaisesRegex(ValueError, 'foreign later'): apt.normalize(request)
            chown.assert_not_called()

    def test_normalization_requires_complete_final_inventory_and_retains_original_facts(self):
        request = {'schema_version': 1, 'account': {'name': 'runner', 'uid': 1001, 'gid': 1001},
                   'archives': {}, 'max_bytes': 100000, 'anchors': {'root': {'device': 17}},
                   'partial_binding': self.before}
        after = {**self.after, 'gid': 1001, 'ctime_ns': 2}
        seen = []
        def inventory(fd, request, output, *, allow_root):
            seen.append(allow_root)
            output.append({'path': 'partial', **(self.after if allow_root else after)})
            return 4096
        with patch.object(apt, 'require_root'), patch.object(apt, 'verify_requested_account'), \
             patch.object(apt, 'open_anchors', return_value=([], {'root': 7})) as anchors, \
             patch.object(apt, 'inventory', side_effect=inventory), \
             patch.object(apt, 'open_member', return_value=(9, [])), \
             patch.object(apt, 'chown_descriptor', return_value=after) as chown:
            result = apt.normalize(request)
            self.assertEqual(seen, [True, False])
            self.assertEqual(anchors.call_count, 3)
            chown.assert_called_once_with(9, self.after, 1001, 1001)
            self.assertEqual(result['normalized'][0]['before'], self.after)
            self.assertEqual(result['after'][0]['gid'], 1001)


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'geteuid') and os.geteuid() == 0,
                     'requires actual privileged Linux fchown')
class PrivilegedPartialHandoff(unittest.TestCase):
    def test_actual_mixed_partial_fchown_and_whole_tree_audit(self):
        # Finite owned temporary tree only; no APT invocation or runtime claim.
        with tempfile.TemporaryDirectory() as folder:
            volume = Path(folder)
            root = volume / 'reference-guest' / 'apt'
            partial = root / 'partial'
            partial.mkdir(parents=True)
            root.parent.chmod(0o700)
            partial.chmod(0o755)
            for path in (volume, root.parent, root, partial): os.chown(path, 1001, 1001)
            request = apt.apt_request(root, {'name': 'fixture', 'uid': 1001, 'gid': 1001}, [], 100000)
            original = request['partial_binding']
            partial.chmod(0o700)
            os.chown(partial, 1001, 0)
            with patch.object(apt, 'verify_requested_account'):
                result = apt.normalize(request)
            self.assertEqual(result['status'], 'PASS')
            self.assertEqual(result['normalized'][0]['path'], 'partial')
            self.assertEqual(result['after'][0]['inode'], original['inode'])
            self.assertEqual((partial.stat().st_uid, partial.stat().st_gid), (1001, 1001))


if __name__ == '__main__': unittest.main()
