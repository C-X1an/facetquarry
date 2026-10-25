"""Real filesystem controls; no installed SDK is modified by these fixtures."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_preflight as trim


class ReferencePreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.volume = Path(self.temp.name).absolute()
        self.project = self.volume / 'source'
        for relative in ('tools/go/src/nested', 'tools/go/bin', 'source/.cache/go-build/ab',
                         'source/.cache/go-build/fuzz/Corpus', 'source/internal/engine/testdata/fuzz/Fuzz'):
            (self.volume / relative).mkdir(parents=True)
        (self.volume / 'tools/go/src/nested/code.go').write_bytes(b'package fixture\n')
        (self.volume / 'tools/go/bin/go').write_bytes(b'retained fixture, never executed')
        (self.project / '.cache/go-build/ab/object-a').write_bytes(b'compiled fixture')
        (self.project / '.cache/go-build/fuzz/Corpus/seed').write_bytes(b'go test fuzz v1\n[]byte("x")\n')
        (self.project / 'internal/engine/testdata/fuzz/Fuzz/seed').write_bytes(b'other seed')
        (self.project / '.cache/go-build/README').write_bytes(b'cache description')

    def plan(self):
        return trim.tree(self.volume, trim.selected_roots(self.volume, self.project))

    def test_manifest_hashes_real_regular_and_sparse_bytes(self):
        sparse = self.volume / 'tools/go/src/nested/sparse'
        with sparse.open('wb') as stream:
            stream.seek(1024 * 1024)
            stream.write(b'end')
        plan = self.plan()
        records = {item['path']: item for item in plan['entries'] if item['kind'] == 'file'}
        record = records['tools/go/src/nested/sparse']
        self.assertEqual(record['bytes'], 1024 * 1024 + 3)
        self.assertEqual(record['sha256'], hashlib.sha256(sparse.read_bytes()).hexdigest())
        self.assertGreaterEqual(record['accounted_bytes'], record['bytes'])
        self.assertFalse(any('/fuzz/' in path for path in records))
        trim.validate_plan(self.volume, plan)

    def test_fuzz_bytes_and_both_roots_are_preserved_in_plan(self):
        before = trim.fuzz_state(self.volume, self.project)
        files = [item for item in before['entries'] if item['kind'] == 'file']
        self.assertEqual(len(files), 2)
        self.assertEqual(before, trim.fuzz_state(self.volume, self.project))
        self.assertNotIn('tools/go/bin/go', [item['path'] for item in self.plan()['entries']])

    def test_unexpected_cache_entry_refuses_before_deletion(self):
        (self.project / '.cache/go-build/unexpected').write_bytes(b'leave alone')
        with self.assertRaisesRegex(RuntimeError, 'unexpected Go cache'):
            self.plan()
        self.assertTrue((self.volume / 'tools/go/src/nested/code.go').exists())

    def test_hex_named_regular_file_is_not_a_shard(self):
        (self.project / '.cache/go-build/12').write_bytes(b'not a directory')
        with self.assertRaisesRegex(RuntimeError, 'not a directory'):
            self.plan()

    def test_outside_and_dotdot_paths_refused(self):
        with self.assertRaises(RuntimeError):
            trim.checked(self.volume.parent, self.volume)
        with self.assertRaises(RuntimeError):
            trim.checked(self.volume / 'source/../tools', self.volume)

    def test_unlisted_file_and_inode_substitution_refuse(self):
        plan = self.plan()
        added = self.volume / 'tools/go/src/nested/added'
        added.write_bytes(b'new')
        with self.assertRaises(RuntimeError):
            trim.validate_plan(self.volume, plan)
        added.unlink()
        plan = self.plan()
        original = self.volume / 'tools/go/src/nested/code.go'
        replacement = original.with_name('replacement')
        replacement.write_bytes(original.read_bytes())
        os.replace(replacement, original)
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            trim.validate_plan(self.volume, plan)

    def test_regular_ancestor_path_substitution_refuses(self):
        plan = self.plan()
        sdk = self.volume / 'tools/go'
        sdk.rename(self.volume / 'tools/retained-go')
        sdk.mkdir()
        with self.assertRaisesRegex(RuntimeError, 'ancestor inode changed'):
            trim.validate_plan(self.volume, plan)
        self.assertTrue((self.volume / 'tools/retained-go/src/nested/code.go').exists())

    def test_file_content_mutation_refuses(self):
        plan = self.plan()
        path = self.volume / 'tools/go/src/nested/code.go'
        path.write_bytes(b'package changed\n')
        with self.assertRaises(RuntimeError):
            trim.validate_plan(self.volume, plan)

    def test_hardlink_refuses(self):
        original = self.volume / 'tools/go/src/nested/code.go'
        try:
            os.link(original, self.volume / 'other')
        except OSError as error:
            self.skipTest('fixture hardlinks unavailable: ' + str(error))
        with self.assertRaisesRegex(RuntimeError, 'hardlinked'):
            self.plan()

    def test_symlink_and_ancestor_substitution_refuse(self):
        original = self.volume / 'tools/go/src'
        moved = self.volume / 'retained-src'
        original.rename(moved)
        try:
            original.symlink_to(moved, target_is_directory=True)
        except OSError as error:
            moved.rename(original)
            self.skipTest('fixture symlinks unavailable: ' + str(error))
        with self.assertRaisesRegex(RuntimeError, 'linked/reparse'):
            self.plan()
        self.assertTrue((moved / 'nested/code.go').exists())

    def test_streamed_predelete_proof_contains_complete_manifest(self):
        plan = self.plan()
        output = self.volume / 'proof.json'
        trim.write_proof(output, {'status': 'PREPARED', 'removal_manifest': plan}, initial=True)
        self.assertEqual(json.loads(output.read_text())['removal_manifest'], plan)
        with self.assertRaises(FileExistsError):
            trim.write_proof(output, {}, initial=True)
        self.assertTrue((self.volume / 'tools/go/src/nested/code.go').exists())

    def test_terminal_proof_is_admitted_before_any_cache_deletion(self):
        from unittest.mock import patch
        proof = {'status': 'PREPARED', 'removal_manifest': self.plan(),
                 'before_inspections': {'commands': ['real retained metadata']},
                 'fuzz_before': trim.fuzz_state(self.volume, self.project)}
        admitted = trim.admit_terminal_proof(proof)
        self.assertGreater(admitted, len(json.dumps(proof)))
        with patch.object(trim, 'MAX_MANIFEST_BYTES', admitted):
            with self.assertRaisesRegex(RuntimeError, 'predelete admission'):
                trim.admit_terminal_proof(proof)
        self.assertTrue((self.volume / 'tools/go/src/nested/code.go').exists())

    def test_fuzz_is_copied_byte_for_byte_before_measurement(self):
        (self.project / '.local').mkdir(exist_ok=True)
        records = trim.preserve_fuzz(self.volume, self.project)
        self.assertGreater(len(records), 0)
        for item in records:
            target = self.project / '.local/reference-fuzz' / item['path']
            self.assertEqual(trim.file_sha(target), item['sha256'])
        with self.assertRaisesRegex(RuntimeError, 'already exists'):
            trim.preserve_fuzz(self.volume, self.project)

    def test_actual_loop_mount_target_and_type_are_required(self):
        good = {'target': str(self.volume), 'fstype': 'ext4', 'source': '/dev/loop7'}
        self.assertEqual(trim.validate_mount(self.volume, {'filesystems': [good]}), good)
        for field, value in [('target', str(self.volume / 'source')), ('fstype', 'tmpfs'),
                             ('source', '/dev/loop7-pretend'), ('source', '/dev/sda1')]:
            changed = {**good, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(RuntimeError):
                trim.validate_mount(self.volume, {'filesystems': [changed]})

    def test_current_source_pass_receipts_are_required_and_hashed(self):
        root = self.project / '.local/evidence'
        for number, category in enumerate(trim.REQUIRED_CATEGORIES):
            folder = root / str(number)
            folder.mkdir(parents=True)
            (folder / 'receipt.json').write_text(json.dumps({'category': category, 'status': 'PASS',
                'exit_code': 0, 'termination_reason': None, 'source_before': 'current', 'source_after': 'current'}))
        receipts = trim.verified_receipts(self.project, 'current')
        self.assertEqual(set(receipts), set(trim.REQUIRED_CATEGORIES))
        for record in receipts.values():
            self.assertEqual(record['sha256'], hashlib.sha256((self.project / record['path']).read_bytes()).hexdigest())
        with self.assertRaisesRegex(RuntimeError, 'missing current-source'):
            trim.verified_receipts(self.project, 'different-source')

    @unittest.skipUnless(sys.platform == 'linux', 'production descriptor deletion is Linux-only')
    def test_real_linux_deletion_preserves_fuzz_and_go_binary(self):
        before = trim.fuzz_state(self.volume, self.project)
        plan = self.plan()
        trim.delete_linux(self.volume, plan)
        self.assertFalse((self.volume / 'tools/go/src').exists())
        self.assertFalse((self.project / '.cache/go-build/ab').exists())
        self.assertTrue((self.volume / 'tools/go/bin/go').is_file())
        self.assertEqual(trim.fuzz_state(self.volume, self.project), before)


if __name__ == '__main__':
    unittest.main()
