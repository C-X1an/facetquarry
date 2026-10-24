"""Complete fresh attribution with bounded filesystem metadata requests."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import disk_guard as guard


class InventoryMetadata(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'nested').mkdir()
        (self.root / 'a').write_bytes(b'a' * 13)
        (self.root / 'nested/b').write_bytes(b'b' * 19)

    def test_fresh_growth_and_hardlink_accounting(self):
        os.link(self.root / 'a', self.root / 'hardlink')
        before = guard.inventory(self.root)['accounted_bytes']
        with (self.root / 'nested/sparse').open('wb') as stream:
            stream.seek(2_000_000)
            stream.write(b'x')
        after = guard.inventory(self.root)['accounted_bytes']
        self.assertGreaterEqual(after - before, 2_000_001)
        expected = sum(max(p.stat().st_size, getattr(p.stat(), 'st_blocks', 0)*512)
                       for p in (self.root / 'a', self.root / 'nested/b', self.root / 'nested/sparse'))
        self.assertEqual(after, expected)

    def test_metadata_request_count_is_linear_with_one_stat_per_entry(self):
        calls = []
        real_stat = Path.stat
        real_scandir = os.scandir
        class Entry:
            def __init__(self, original): self.original = original; self.path = original.path
            def stat(self, **kwargs):
                calls.append(self.path)
                return self.original.stat(**kwargs)
        @contextlib.contextmanager
        def scan(path):
            with real_scandir(path) as entries:
                yield (Entry(entry) for entry in entries)
        def path_stat(path, *args, **kwargs):
            calls.append(str(path))
            return real_stat(path, *args, **kwargs)
        with patch.object(guard.os, 'scandir', scan), patch.object(Path, 'stat', path_stat):
            record = guard.inventory(self.root)
        self.assertEqual(len(calls), 4)  # root, nested, a, nested/b
        self.assertGreaterEqual(record['accounted_bytes'], 32)

    def test_enumeration_and_metadata_failures_propagate(self):
        with patch.object(guard.os, 'scandir', side_effect=PermissionError('bounded denial')):
            with self.assertRaises(PermissionError): guard.inventory(self.root)
        with patch.object(Path, 'lstat', side_effect=FileNotFoundError('bounded disappearance')):
            with self.assertRaises(FileNotFoundError): guard.inventory(self.root)

    def test_nonregular_entries_refuse(self):
        mode = type('Metadata', (), {'st_mode': stat.S_IFIFO, 'st_dev': 0, 'st_ino': 123})()
        with patch.object(Path, 'lstat', return_value=mode):
            with self.assertRaisesRegex(ValueError, 'unsupported inventory entry'):
                guard.inventory(self.root)

    def test_junction_metadata_is_reported_without_traversal(self):
        mode = type('Metadata', (), {'st_mode': stat.S_IFDIR, 'st_reparse_tag': 0xa0000003})()
        with patch.object(Path, 'lstat', return_value=mode), patch.object(guard.os, 'scandir') as scan:
            record = guard.inventory(self.root)
        self.assertEqual(record['symlinks_not_followed'], [str(self.root)])
        scan.assert_not_called()

    def test_progress_survives_failure_and_stdout_stays_json(self):
        error_output = io.StringIO(); output = io.StringIO()
        with patch.object(sys, 'argv', ['disk_guard.py', '--root', str(self.root)]), \
                patch.object(guard.os, 'scandir', side_effect=PermissionError('bounded denial')), \
                contextlib.redirect_stderr(error_output), contextlib.redirect_stdout(output):
            self.assertEqual(guard.main(), 1)
        self.assertEqual(json.loads(output.getvalue())['admission'], 'REFUSE')
        self.assertEqual(json.loads(error_output.getvalue())['state'], 'started')


if __name__ == '__main__':
    unittest.main()
