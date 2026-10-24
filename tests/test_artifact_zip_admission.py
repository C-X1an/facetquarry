"""Bounded real ZIP metadata controls; no VM or benchmark qualification."""
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_qualification as q


class ZipDirectoryAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'artifact.zip'
        with zipfile.ZipFile(self.path, 'w') as archive:
            archive.writestr('reference-members.tar.xz', b'tiny bounded data')
        self.original = self.path.read_bytes()
        self.end = self.original.rfind(b'PK\x05\x06')
        self.offset = struct.unpack_from('<L', self.original, self.end + 16)[0]
        self.central = self.original[self.offset:self.end]

    def ordinary(self, count, declared=None):
        central = self.central * count
        end = struct.pack('<4s4H2LH', b'PK\x05\x06', 0, 0,
                          count if declared is None else declared,
                          count if declared is None else declared,
                          len(central), self.offset, 0)
        self.path.write_bytes(self.original[:self.offset] + central + end)

    def test_valid_real_transport_and_comment(self):
        self.assertEqual(q.check_artifact_zip_directory(self.path), 1)
        with zipfile.ZipFile(self.path, 'a') as archive:
            archive.comment = b'ordinary comment'
        self.assertEqual(q.check_artifact_zip_directory(self.path), 1)
        with zipfile.ZipFile(self.path) as archive:
            self.assertEqual(archive.read('reference-members.tar.xz'), b'tiny bounded data')

    def test_ambiguous_comment_refuses_before_reader_disagreement(self):
        with zipfile.ZipFile(self.path, 'a') as archive:
            archive.comment = b'ordinary comment PK\x05\x06 text'
        with self.assertRaises(zipfile.BadZipFile):
            zipfile.ZipFile(self.path)
        with self.assertRaisesRegex(ValueError, 'end record missing or malformed'):
            q.check_artifact_zip_directory(self.path)

    def test_count_limit_including_a_forged_low_end_count(self):
        for declared in (50001, 1):
            with self.subTest(declared=declared):
                self.ordinary(50001, declared)
                with self.assertRaisesRegex(ValueError, 'member admission'):
                    q.check_artifact_zip_directory(self.path)

    def test_exact_count_boundary(self):
        self.ordinary(50000)
        self.assertEqual(q.check_artifact_zip_directory(self.path), 50000)

    def test_directory_byte_limit_precedes_metadata_read(self):
        raw = bytearray(self.original)
        struct.pack_into('<L', raw, self.end + 12, q.MAX_METADATA + 1)
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'directory byte admission'):
            q.check_artifact_zip_directory(self.path)

    def test_malformed_and_split_directories(self):
        for label, position, fmt, value in [
            ('split-end', self.end + 4, '<H', 1),
            ('split-member', self.offset + 34, '<H', 1),
            ('wrong-count', self.end + 8, '<2H', (0, 0)),
            ('extent', self.end + 16, '<L', self.offset + 1),
            ('variable-data', self.offset + 28, '<H', 65535),
        ]:
            with self.subTest(label=label):
                raw = bytearray(self.original)
                struct.pack_into(fmt, raw, position, *(value if isinstance(value, tuple) else (value,)))
                self.path.write_bytes(raw)
                with self.assertRaises(ValueError):
                    q.check_artifact_zip_directory(self.path)
        for raw in (self.original[:-1], b'prefix' + self.original, self.original + b'trailing'):
            self.path.write_bytes(raw)
            with self.assertRaises(ValueError):
                q.check_artifact_zip_directory(self.path)

    def zip64(self):
        record = struct.pack('<4sQ2H2L4Q', b'PK\x06\x06', 44, 45, 45, 0, 0, 1, 1,
                             len(self.central), self.offset)
        locator = struct.pack('<4sLQL', b'PK\x06\x07', 0, self.end, 1)
        end = struct.pack('<4s4H2LH', b'PK\x05\x06', 0, 0, 65535, 65535,
                          0xffffffff, 0xffffffff, 0)
        return self.original[:self.end] + record + locator + end

    def test_bounded_zip64_accepts_and_malformed_refuses(self):
        raw = self.zip64()
        self.path.write_bytes(raw)
        self.assertEqual(q.check_artifact_zip_directory(self.path), 1)
        with zipfile.ZipFile(self.path) as archive:
            self.assertEqual(archive.read('reference-members.tar.xz'), b'tiny bounded data')
        for position, fmt, value in [(self.end + 4, '<Q', 4097),
                                     (self.end + 24, '<Q', 50001),
                                     (self.end + 56 + 16, '<L', 2)]:
            damaged = bytearray(raw)
            struct.pack_into(fmt, damaged, position, value)
            self.path.write_bytes(damaged)
            with self.assertRaises(ValueError):
                q.check_artifact_zip_directory(self.path)

    def test_zip64_locator_without_end_sentinels_matches_reader(self):
        raw = bytearray(self.zip64())
        end = len(raw) - 22
        struct.pack_into('<2H2L', raw, end + 8, 1, 1, len(self.central), self.offset)
        self.path.write_bytes(raw)
        self.assertEqual(q.check_artifact_zip_directory(self.path), 1)
        with zipfile.ZipFile(self.path) as archive:
            self.assertEqual(archive.read('reference-members.tar.xz'), b'tiny bounded data')
        struct.pack_into('<L', raw, end + 16, self.offset + 1)
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'ZIP64 directory disagrees'):
            q.check_artifact_zip_directory(self.path)


if __name__ == '__main__':
    unittest.main()
