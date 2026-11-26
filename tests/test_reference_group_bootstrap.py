"""Bootstrap custody controls using small local archive fixtures."""

import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_group_bootstrap as bootstrap


class GroupBootstrapControls(unittest.TestCase):
    def archive(self, members):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            for name, body in members:
                entry = tarfile.TarInfo(name)
                entry.size = len(body)
                archive.addfile(entry, io.BytesIO(body))
        output.seek(0)
        return output

    def test_sdk_archive_preflights_decoded_members_and_allocations(self):
        body = self.archive([('go/VERSION', b'v\n'), ('go/bin/go', b'binary-data')])
        with tarfile.open(fileobj=body, mode='r:gz') as package:
            usage = bootstrap.sdk_inventory(package, block_size=4096, decoded_limit=4096, member_limit=5)
            self.assertEqual(usage['members'], 2)
            self.assertEqual(usage['decoded_bytes'], 13)
            self.assertEqual(usage['required_bytes'], 4 * 4096)

    def test_sdk_archive_refuses_duplicate_members_and_size_before_extraction(self):
        for members, limit in (([('go/VERSION', b'aa'), ('go/VERSION', b'bb')], 1024),
                               ([('go/VERSION', b'aa')], 1), ([('VERSION', b'aa')], 1024)):
            with self.subTest(members=members, limit=limit), tempfile.TemporaryDirectory() as destination:
                path = Path(destination)
                body = self.archive(members)
                with tarfile.open(fileobj=body, mode='r:gz') as archive, self.assertRaises(ValueError):
                    bootstrap.sdk_inventory(archive, block_size=4096, decoded_limit=limit, member_limit=5)
                self.assertEqual(list(path.iterdir()), [])

    def test_installed_sdk_verifies_each_file_and_detects_a_change(self):
        with tempfile.TemporaryDirectory() as folder:
            volume = Path(folder).resolve()
            tools = volume / 'tools'
            tools.mkdir()
            body = self.archive([('go/VERSION', b'v\n'), ('go/bin/go', b'binary-data')])
            with tarfile.open(fileobj=body, mode='r:gz') as archive:
                expected = bootstrap.sdk_inventory(archive, block_size=4096, decoded_limit=4096, member_limit=5)
            body.seek(0)
            with tarfile.open(fileobj=body, mode='r:gz') as archive:
                archive.extractall(tools, filter='data')
            self.assertEqual(bootstrap.verify_installation(volume, tools, expected)['members'], 4)
            (tools / 'go/bin/go').write_bytes(b'other-bytes')
            with self.assertRaisesRegex(ValueError, 'installed SDK tree differs'):
                bootstrap.verify_installation(volume, tools, expected)


if __name__ == '__main__':
    unittest.main()
