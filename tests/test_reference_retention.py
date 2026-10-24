"""Byte-preservation controls; these never mount, unmount or delete an image."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import evidence_bundle as codec
import reference_retention as retention


class RetentionByteControls(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[1] / '.cache/retention-tests'
        cache.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=cache)
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.source = self.folder / 'source'
        (self.source / '.local/empty').mkdir(parents=True)
        self.data = self.source / '.local/data.json'
        self.data.write_bytes(b'{"control":true}\n')

    def manifest(self):
        path = self.folder / 'bundle.tar.xz'
        codec.pack(self.source, path, 'a' * 64, 'b' * 40, 'bounded-control', ['.local'])
        codec.verify(path)
        with path.open('rb') as stream:
            return json.loads(codec.transport_item(codec.XZReader(stream), 'manifest.json', codec.MAX_MANIFEST))

    def test_actual_codec_directories_and_files_match(self):
        manifest = self.manifest()
        self.assertEqual(retention.verify_live_members(self.source, manifest), 3)

    def test_mutation_is_rejected(self):
        manifest = self.manifest()
        self.data.write_bytes(b'{"control":false}\n')
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            retention.verify_live_members(self.source, manifest)

    def test_new_and_missing_members_are_rejected(self):
        manifest = self.manifest()
        extra = self.source / '.local/extra'
        extra.write_bytes(b'new')
        with self.assertRaisesRegex(ValueError, 'missing or duplicated'):
            retention.verify_live_members(self.source, manifest)
        extra.unlink()
        self.data.unlink()
        with self.assertRaisesRegex(ValueError, 'membership differs'):
            retention.verify_live_members(self.source, manifest)

    def test_file_directory_substitution_is_rejected(self):
        manifest = self.manifest()
        self.data.unlink()
        self.data.mkdir()
        with self.assertRaises(ValueError):
            retention.verify_live_members(self.source, manifest)

    def fuzz(self):
        raw = self.source / '.cache/go-build/fuzz/FuzzQuery/case'
        raw.parent.mkdir(parents=True)
        raw.write_bytes(b'go test fuzz v1\nstring("control")\n')
        copy = self.source / '.local/reference-fuzz/cache/FuzzQuery/case'
        copy.parent.mkdir(parents=True)
        shutil.copyfile(raw, copy)
        return raw, copy, {'files': [{'path': 'cache/FuzzQuery/case', 'bytes': raw.stat().st_size,
                                     'sha256': retention.digest(raw)}]}

    def test_all_live_fuzz_bytes_are_preserved(self):
        raw, copy, manifest = self.fuzz()
        self.assertEqual(retention.verify_fuzz(self.source, manifest), 1)
        raw.write_bytes(b'new failing corpus')
        with self.assertRaisesRegex(ValueError, 'bytes differ'):
            retention.verify_fuzz(self.source, manifest)

    def test_omitted_fuzz_member_is_rejected(self):
        self.fuzz()
        with self.assertRaisesRegex(ValueError, 'was not preserved'):
            retention.verify_fuzz(self.source, {'files': []})

    def test_curated_copy_is_bound_to_verified_bundle(self):
        manifest = self.manifest()
        original = self.folder / 'original'
        copied = original / '.local/reference-metadata/data.json'
        copied.parent.mkdir(parents=True)
        shutil.copyfile(self.data, copied)
        index = {'files': [{'member': '.local/data.json',
                            'path': '.local/reference-metadata/data.json',
                            'bytes': copied.stat().st_size, 'sha256': retention.digest(copied)}]}
        (original / '.local/reference-metadata-manifest.json').write_text(json.dumps(index))
        self.assertEqual(retention.verify_metadata(original, self.source, manifest), 1)
        copied.write_bytes(b'changed metadata')
        with self.assertRaisesRegex(ValueError, 'differs from complete bundle'):
            retention.verify_metadata(original, self.source, manifest)

    def test_curated_path_escape_is_rejected(self):
        manifest = self.manifest()
        original = self.folder / 'original'
        (original / '.local').mkdir(parents=True)
        index = {'files': [{'member': '.local/data.json', 'path': '../source/.local/data.json',
                            'bytes': self.data.stat().st_size, 'sha256': retention.digest(self.data)}]}
        (original / '.local/reference-metadata-manifest.json').write_text(json.dumps(index))
        with self.assertRaisesRegex(ValueError, 'escapes'):
            retention.verify_metadata(original, self.source, manifest)


if __name__ == '__main__':
    unittest.main()
