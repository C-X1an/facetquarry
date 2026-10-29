"""Refusal facts remain inspectable without relaxing ownership/link checks.

Pure stat fixtures only: no filesystem quota, privileged trim or recovery claim.
"""
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_internal_transport as transport


class TrimRefusalDiagnostics(unittest.TestCase):
    def manifest(self, *, uid=1001, links=1, directory=False, name='reference-guest/apt/partial'):
        volume = Path('/synthetic-owned-volume')
        item = {'path': name, 'kind': 'directory' if directory else 'file'}
        observed = SimpleNamespace(st_uid=uid, st_gid=1001, st_nlink=links,
                                   st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | 0o700,
                                   st_dev=17, st_ino=31)
        def checked(path, *_):
            return SimpleNamespace(st_uid=1001) if path == volume else observed
        with patch.object(transport, 'admit_tree'), patch.object(transport.preflight, 'tree', return_value={'entries': [item]}), patch.object(transport.preflight, 'checked', side_effect=checked):
            return transport.owned_manifest(volume, [volume / name])

    def refused(self, **kwargs):
        with self.assertRaisesRegex(ValueError, 'not an owned single-link inode') as caught:
            self.manifest(**kwargs)
        message = str(caught.exception)
        self.assertIn(': ', message, 'refusal omitted the observed inode facts')
        facts = json.loads(message.split(': ', 1)[1])
        self.assertEqual(facts['expected_uid'], 1001)
        self.assertEqual(facts['observed_gid'], 1001)
        self.assertEqual(facts['device'], 17)
        self.assertEqual(facts['inode'], 31)
        self.assertLess(len(message.encode()), 4096)
        return facts

    def test_foreign_owner_is_refused_with_exact_relative_inode(self):
        facts = self.refused(uid=0)
        self.assertEqual(facts['path'], 'reference-guest/apt/partial')
        self.assertEqual(facts['observed_uid'], 0)
        self.assertEqual(facts['observed_nlink'], 1)
        self.assertFalse(facts['path_truncated'])

    def test_hardlinked_file_stays_refused_with_link_count(self):
        facts = self.refused(links=2)
        self.assertEqual(facts['observed_uid'], 1001)
        self.assertEqual(facts['observed_nlink'], 2)

    def test_directory_links_remain_legal_for_owned_directory(self):
        self.assertEqual(len(self.manifest(directory=True, links=3)['entries']), 1)

    def test_long_refusal_path_is_bounded_and_explicit(self):
        name = 'reference-guest/' + 'x' * 2048
        facts = self.refused(uid=0, name=name)
        self.assertEqual(facts['path'], name[:512])
        self.assertTrue(facts['path_truncated'])


if __name__ == '__main__': unittest.main()
