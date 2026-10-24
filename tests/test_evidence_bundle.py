"""Small synthetic transport controls; no engine or live integration claims."""
import base64
import gzip
import io
import json
import lzma
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import evidence_bundle as p


class DirectoryTransportControls(unittest.TestCase):
    def setUp(self):
        # Keep all fixtures in an owned ignored cache, including on Windows.
        cache = Path(__file__).resolve().parents[1] / '.cache' / 'evidence-bundle-tests'
        cache.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=cache)
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.root = self.folder / 'input'
        self.root.mkdir()
        (self.root / 'results').mkdir()
        (self.root / 'results' / 'empty').mkdir()
        (self.root / 'results' / 'measurement.json').write_bytes(b'{"real":false}\n')
        self.output = self.folder / 'bundle.tar.xz'

    def pack(self, **kwargs):
        return p.pack(self.root, kwargs.pop('output', self.output), 'a' * 64, 'b' * 40,
                      'synthetic-test', kwargs.pop('paths', ['results']), **kwargs)

    def rewrite(self, change):
        with tarfile.open(self.output, 'r:xz') as tar:
            entries = [(member.name, tar.extractfile(member).read()) for member in tar]
        manifest = json.loads(entries[0][1])
        change(manifest, entries)
        entries[0] = ('manifest.json', json.dumps(manifest).encode())
        with tarfile.open(self.output, 'w:xz', format=tarfile.USTAR_FORMAT) as tar:
            for name, data in entries:
                p.tar_item(tar, name, data)

    def test_roundtrip_preserves_opaque_gzip_header_and_identity_fallback(self):
        raw = b'{"value":1}\n' * 100
        # Extra bytes, filename, comment, header CRC and unusual mtime/OS are opaque.
        header = b'\x1f\x8b\x08\x1e' + struct.pack('<I', 123) + b'\x02\x03'
        header += b'\x03\x00xyzopaque.jsonl\x00comment\x00'
        header += struct.pack('<H', zlib.crc32(header) & 0xffff)
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        gz = header + c.compress(raw) + c.flush() + struct.pack('<II', zlib.crc32(raw), len(raw))
        originals = {'opaque.gz': gz, 'broken.gz': b'not gzip',
                     'different-compressor.gz': gzip.compress(raw, compresslevel=0, mtime=1)}
        for name, data in originals.items():
            (self.root / 'results' / name).write_bytes(data)
        result = self.pack()
        self.assertEqual(result['gzip_recipe_members'], 1)
        recovered = self.folder / 'recovered'
        p.verify(self.output, recovered)
        for name, data in originals.items():
            self.assertEqual((recovered / 'results' / name).read_bytes(), data)
            self.assertEqual((self.root / 'results' / name).read_bytes(), data)
        self.assertTrue((recovered / 'results' / 'empty').is_dir())
        with tarfile.open(self.output, 'r:xz') as tar:
            manifest = json.load(tar.extractfile('manifest.json'))
        self.assertEqual(manifest['source'], 'a' * 64)
        self.assertEqual(manifest['commit'], 'b' * 40)
        self.assertFalse(any('zip' in key or 'artifact_id' in key for key in manifest))

    def test_explicit_selection_does_not_silently_include_other_results(self):
        (self.root / 'unselected').write_bytes(b'exclude')
        self.pack(paths=['results/measurement.json'])
        self.assertEqual(p.verify(self.output)['member_count'], 1)

    def test_unsafe_paths_and_nonportable_layout_are_refused(self):
        for path in ('../secret', '/absolute', 'results\\file', 'results/./file', 'NUL.txt',
                     'a:/file', 'results//file', 'a./file', 'a?/file'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.pack(paths=[path])
        for paths in (['results', 'results/empty'], ['results', 'results-other', 'results/empty'],
                      ['results', 'RESULTS'], ['results/']):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                self.pack(paths=paths)
        with self.assertRaisesRegex(ValueError, 'case-colliding'):
            p.validate_layout([{'path': 'A/one', 'directory': False, 'original_bytes': 1},
                               {'path': 'a/two', 'directory': False, 'original_bytes': 1}])
        with self.assertRaisesRegex(ValueError, 'ancestor'):
            p.validate_layout([{'path': 'a', 'directory': False, 'original_bytes': 1},
                               {'path': 'a/one', 'directory': False, 'original_bytes': 1}])

    def test_output_inside_selection_and_overwrites_refused(self):
        with self.assertRaisesRegex(ValueError, 'outside'):
            self.pack(output=self.root / 'results' / 'bundle.tar.xz')
        self.pack()
        before = self.output.read_bytes()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.pack()
        self.assertEqual(self.output.read_bytes(), before)
        with self.assertRaisesRegex(ValueError, 'already exists'):
            p.verify(self.output, self.root)

    def test_symlink_and_windows_reparse_points_refused(self):
        target = self.root / 'results' / 'measurement.json'
        link = self.root / 'results' / 'link'
        try:
            link.symlink_to(target)
        except OSError:
            # Windows developer mode is not assumed. Exercise the actual admission
            # predicate using lstat's documented reparse bit instead of hiding a skip.
            original = Path.lstat

            def reparse(path, *args, **kwargs):
                result = original(path, *args, **kwargs)
                if path == target:
                    values = {name: getattr(result, name) for name in dir(result) if name.startswith('st_')}
                    values['st_file_attributes'] = 0x400
                    return type('ReparseStat', (), values)()
                return result
            with mock.patch.object(Path, 'lstat', reparse), self.assertRaisesRegex(ValueError, 'reparse'):
                self.pack()
        else:
            with self.assertRaisesRegex(ValueError, 'symlink'):
                self.pack()

    def test_nonregular_member_is_not_silently_skipped(self):
        if hasattr(os, 'mkfifo'):
            os.mkfifo(self.root / 'results' / 'pipe')
            with self.assertRaisesRegex(ValueError, 'nonregular'):
                self.pack()
        else:
            original = p.regular_stat

            def fail(path):
                if path.name == 'measurement.json':
                    raise ValueError('nonregular member refused')
                return original(path)
            with mock.patch.object(p, 'regular_stat', fail), self.assertRaisesRegex(ValueError, 'nonregular'):
                self.pack()

    def test_active_partial_source_is_refused(self):
        (self.root / 'results' / 'active.tar.xz.partial').write_bytes(b'partial')
        with self.assertRaisesRegex(ValueError, 'partial'):
            self.pack()

    def test_member_and_total_and_count_and_metadata_bounds(self):
        for constant, bound, message in (('MAX_MEMBER', 2, 'member'), ('MAX_ORIGINAL', 2, 'total'),
                                         ('MAX_MEMBERS', 1, 'count'), ('MAX_MANIFEST', 2, 'manifest'),
                                         ('MAX_PAYLOAD', 2, 'payload')):
            with self.subTest(constant=constant), mock.patch.object(p, constant, bound):
                with self.assertRaisesRegex(ValueError, message):
                    self.pack()

    def test_output_bound_retains_partial_diagnostics_and_originals(self):
        with mock.patch.object(p, 'MAX_OUTPUT', 10), self.assertRaisesRegex(ValueError, 'limit'):
            self.pack()
        self.assertTrue(self.output.with_name(self.output.name + '.partial').exists())
        self.assertTrue(self.output.with_name(self.output.name + '.failure.json').exists())
        self.assertFalse(self.output.exists())
        self.assertEqual((self.root / 'results' / 'measurement.json').read_bytes(), b'{"real":false}\n')

    def test_source_mutation_between_passes_is_refused_and_retained(self):
        original = p.read_original
        seen = set()

        def mutate(root, entry):
            if entry[0].endswith('measurement.json'):
                if entry[0] in seen:
                    (root / entry[0]).write_bytes(b'mutated')
                seen.add(entry[0])
            return original(root, entry)
        with mock.patch.object(p, 'read_original', mutate), self.assertRaisesRegex(ValueError, 'changed'):
            self.pack()
        self.assertFalse(self.output.exists())
        self.assertTrue(self.output.with_name(self.output.name + '.partial').exists())

    def test_file_added_after_inventory_refused(self):
        original = p.inventory
        calls = 0

        def mutate(root, paths):
            nonlocal calls
            calls += 1
            if calls == 2:
                (root / 'results' / 'new').write_bytes(b'new')
            return original(root, paths)
        with mock.patch.object(p, 'inventory', mutate), self.assertRaisesRegex(ValueError, 'changed'):
            self.pack()
        self.assertFalse(self.output.exists())

    def test_hash_check_refuses_byte_changes_even_if_metadata_check_is_bypassed(self):
        original = p.read_original
        seen = set()

        def changed(root, entry):
            data = original(root, entry)
            if entry[0].endswith('measurement.json'):
                if entry[0] in seen:
                    return data.replace(b'false', b'true ')
                seen.add(entry[0])
            return data
        with mock.patch.object(p, 'read_original', changed), self.assertRaisesRegex(ValueError, 'SHA changed'):
            self.pack()
        self.assertTrue(self.output.with_name(self.output.name + '.failure.json').exists())

    def test_hidden_tar_extensions_rejected_before_attacker_sized_read(self):
        header = tarfile.TarInfo('manifest.json')
        header.type = tarfile.XHDTYPE
        header.size = 2_000_000_000
        self.output.write_bytes(lzma.compress(header.tobuf(format=tarfile.USTAR_FORMAT)))
        with self.assertRaisesRegex(ValueError, 'type/size'):
            p.verify(self.output)

    def test_payload_original_hash_layout_and_total_tampering_refused(self):
        self.pack()
        original = self.output.read_bytes()
        changes = [lambda m, e: e.__setitem__(1, (e[1][0], b'tamper')),
                   lambda m, e: m['members'][-1].__setitem__('original_sha256', '0' * 64),
                   lambda m, e: m['members'][-1].__setitem__('path', '../escape'),
                   lambda m, e: m.__setitem__('streamed_payload_bytes', 0),
                   lambda m, e: m.__setitem__('selected_paths', ['other']),
                   lambda m, e: m['members'][-1].__setitem__('payload_name', 'payload/999999'),
                   lambda m, e: m['members'][-1].__setitem__('payload_bytes', p.MAX_MEMBER + 1)]
        for change in changes:
            self.output.write_bytes(original)
            self.rewrite(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                p.verify(self.output)
        recovery = self.folder / 'recover'
        with self.assertRaises(ValueError):
            p.verify(self.output, recovery)
        self.assertFalse(recovery.exists())

    def test_truncation_extra_members_and_trailing_compressed_data_refused(self):
        self.pack()
        original = self.output.read_bytes()
        self.rewrite(lambda m, e: e.append(('payload/unexpected', b'extra')))
        with self.assertRaisesRegex(ValueError, 'extra'):
            p.verify(self.output)
        for bad in (original[:-10], original + b'trailing', original + lzma.compress(b'other')):
            self.output.write_bytes(bad)
            with self.assertRaises((ValueError, lzma.LZMAError, tarfile.ReadError)):
                p.verify(self.output)


if __name__ == '__main__':
    unittest.main(verbosity=2)
