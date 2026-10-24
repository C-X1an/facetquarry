"""Small format/allocation controls; these do not emulate a VM boot."""
import stat
import tempfile
import unittest
import sys
from types import SimpleNamespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from reference_guest import allocated, newc, package_stanza, official_uri, admitted_copy, Setup, GUEST, INIT


class ReferenceGuestControls(unittest.TestCase):
    def test_inventory_refuses_missing_tree(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(OSError):
                allocated(Path(folder) / 'missing')

    def test_inventory_counts_nested_real_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'nested').mkdir()
            (root/'nested/data').write_bytes(b'x' * 15000)
            (root/'empty').write_bytes(b'')
            self.assertGreaterEqual(allocated(root), 15000)

    def test_alias_admission_refuses_before_creating_copy(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            project = root/'source'
            project.mkdir()
            source = root/'runtime'
            source.write_bytes(b'x' * 15000)
            setup = Setup(SimpleNamespace(volume=root, project=project, timeout=240, setup_max_bytes=9000))
            target = setup.base/'alias'
            with self.assertRaises(RuntimeError):
                admitted_copy(setup, source, target, executable=True)
            self.assertFalse(target.exists())

    def test_initrd_format_with_independent_header_decoder(self):
        entries = [('bin', b'', stat.S_IFDIR | 0o755),
                   ('bin/tool', b'abc\0xyz', stat.S_IFREG | 0o755)]
        archive = newc(entries)
        cursor = 0
        decoded = []
        while cursor < len(archive):
            self.assertEqual(archive[cursor:cursor+6], b'070701')
            header = [int(archive[cursor+i:cursor+i+8], 16) for i in range(6, 110, 8)]
            cursor += 110
            name = archive[cursor:cursor+header[11]-1].decode()
            self.assertEqual(archive[cursor+header[11]-1], 0)
            cursor = (cursor + header[11] + 3) & ~3
            payload = archive[cursor:cursor+header[6]]
            cursor = (cursor + header[6] + 3) & ~3
            if name == 'TRAILER!!!':
                break
            decoded.append((name, payload, header[1]))
        self.assertEqual(decoded, entries)
        self.assertEqual(cursor, len(archive))

    def test_signed_metadata_requires_version_and_sha(self):
        text = 'Package: qemu\nVersion: old\nSHA256: abc\n\nPackage: qemu\nVersion: current\nSize: 3\nSHA256: def\n'
        self.assertEqual(package_stanza(text, 'current')['SHA256'], 'def')
        with self.assertRaises(RuntimeError):
            package_stanza(text, 'missing')
        with self.assertRaises(RuntimeError):
            package_stanza('Version: current\nSize: 3\n', 'current')
        self.assertTrue(official_uri('https://archive.ubuntu.com/ubuntu/pool/test.deb'))
        self.assertFalse(official_uri('https://archive.ubuntu.com.evil.invalid/test.deb'))

    def test_embedded_guest_syntax(self):
        compile(GUEST, '<embedded guest>', 'exec')
        self.assertTrue(INIT.startswith('#!/bin/busybox sh\n'))


if __name__ == '__main__':
    unittest.main()
