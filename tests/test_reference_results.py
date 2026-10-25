"""Real bounded-copy fixtures and proof boundaries; no local mount/ENOSPC claim."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_results as results


class ReferenceResultsTests(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[1] / '.cache/results-tests'
        cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=cache)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).absolute()
        self.bootstrap, self.target = self.root / 'bootstrap', self.root / 'target'
        (self.bootstrap / 'nested/empty').mkdir(parents=True)
        (self.bootstrap / 'nested/data.json').write_bytes(b'{"real_fixture":true}\n')
        self.target.mkdir()

    def test_copy_all_real_bytes_empty_directories_and_sparse_file(self):
        sparse = self.bootstrap / 'sparse'
        with sparse.open('wb') as stream:
            stream.seek(65536)
            stream.write(b'end')
        manifest = results.inventory(self.bootstrap)
        results.copy_bootstrap(self.bootstrap, self.target, manifest)
        self.assertEqual((self.target / 'sparse').read_bytes(), sparse.read_bytes())
        self.assertTrue((self.target / 'nested/empty').is_dir())
        self.assertEqual(results.verify_copy(self.bootstrap, self.target, manifest), len(manifest['entries']))
        self.assertTrue(sparse.exists())

    def test_mutated_or_missing_copy_refused(self):
        manifest = results.inventory(self.bootstrap)
        results.copy_bootstrap(self.bootstrap, self.target, manifest)
        (self.target / 'nested/data.json').write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'copied bytes differ'):
            results.verify_copy(self.bootstrap, self.target, manifest)
        (self.target / 'nested/data.json').unlink()
        with self.assertRaises(ValueError):
            results.verify_copy(self.bootstrap, self.target, manifest)

    def test_unlisted_member_and_bootstrap_substitution_refused(self):
        manifest = results.inventory(self.bootstrap)
        results.copy_bootstrap(self.bootstrap, self.target, manifest)
        (self.target / 'unlisted').write_bytes(b'new')
        with self.assertRaisesRegex(ValueError, 'membership differs'):
            results.verify_copy(self.bootstrap, self.target, manifest)
        original = self.bootstrap / 'nested/data.json'
        replacement = self.bootstrap / 'replacement'
        replacement.write_bytes(original.read_bytes())
        os.replace(replacement, original)
        with self.assertRaisesRegex(ValueError, 'bootstrap differs'):
            results.verify_copy(self.bootstrap, self.target, manifest)

    def test_recovery_directory_must_be_empty(self):
        (self.target / 'lost+found').mkdir()
        manifest = results.inventory(self.bootstrap)
        results.copy_bootstrap(self.bootstrap, self.target, manifest)
        (self.target / 'lost+found/unexpected').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'recovery directory'):
            results.verify_copy(self.bootstrap, self.target, manifest)

    def test_existing_target_refuses_overwrite(self):
        manifest = results.inventory(self.bootstrap)
        (self.target / 'nested').mkdir()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            results.copy_bootstrap(self.bootstrap, self.target, manifest)

    def test_hardlink_and_symlink_are_not_followed(self):
        original = self.bootstrap / 'nested/data.json'
        try:
            os.link(original, self.root / 'alias')
        except OSError as failure:
            self.skipTest('fixture hardlinks unavailable: ' + str(failure))
        with self.assertRaises(RuntimeError):
            results.inventory(self.bootstrap)

    def test_exact_mount_and_backing_proof_required(self):
        target, image = self.root / 'mount', self.root / 'results.img'
        mount = {'target': str(target), 'fstype': 'ext4', 'source': '/dev/loop12'}
        loop = {'name': '/dev/loop12', 'back-file': str(image)}
        self.assertEqual(results.mount_binding(target, image, {'filesystems': [mount]}, {'loopdevices': [loop]})['loop'], loop)
        for changed in ({**loop, 'name': '/dev/loop1'}, {**loop, 'back-file': str(self.root / 'other.img')}):
            with self.assertRaisesRegex(ValueError, 'exact owned image'):
                results.mount_binding(target, image, {'filesystems': [mount]}, {'loopdevices': [changed]})
        with self.assertRaises(ValueError):
            results.mount_binding(target, image, {'filesystems': [{**mount, 'target': str(self.root)}]}, {'loopdevices': [loop]})

    def test_active_or_unknown_unit_refused(self):
        for state in ('LoadState=loaded\nActiveState=active\n', '', 'LoadState=loaded\nActiveState=activating\n'):
            with self.assertRaises(ValueError):
                results.unit_properties(state)
        self.assertEqual(results.unit_properties('LoadState=not-found\nActiveState=inactive\n')['LoadState'], 'not-found')
        self.assertEqual(results.unit_properties('LoadState=loaded\nActiveState=failed\n')['ActiveState'], 'failed')

    def test_only_exact_fixed_image_size_accepted(self):
        image = self.root / 'small.img'
        image.write_bytes(b'not a full image')
        with self.assertRaisesRegex(ValueError, 'exact fixed regular file'):
            results.fixed_identity(image)
        self.assertEqual(results.IMAGE_BYTES, 1_100_000_000)
        self.assertGreater(results.PROBE_BYTES, results.IMAGE_BYTES)

    def test_proof_exclusive_and_roundtrips(self):
        path = self.root / 'proof.json'
        record = {'status': 'PREPARED', 'real_inventory': results.inventory(self.bootstrap)}
        results.save(path, record, initial=True)
        self.assertEqual(results.read_json(path), record)
        with self.assertRaises(FileExistsError):
            results.save(path, record, initial=True)

    def rescue_fixture(self):
        volume = self.root / 'facetquarry-reference'; project = volume / 'source'
        local = project / '.local'; local.mkdir(parents=True)
        (local / 'nested/empty').mkdir(parents=True)
        (local / 'nested/real-failure.txt').write_bytes(b'failed premeasurement output\n')
        return {'volume': volume, 'project': project, 'mount': local,
                'bootstrap': volume / 'reference-results-bootstrap',
                'image': volume / 'reference-results.img'}

    def test_original_bootstrap_before_and_after_real_rename_is_identical(self):
        paths = self.rescue_fixture()
        original = results.inventory(paths['mount'])
        canonical = {'status': 'PREPARING', 'initial_bootstrap': original}
        selected, manifest, admission = results.original_selection(paths, canonical)
        self.assertEqual(selected, paths['mount'])
        paths['mount'].rename(paths['bootstrap']); paths['mount'].mkdir()
        selected, manifest, admission = results.original_selection(paths, canonical)
        self.assertEqual(selected, paths['bootstrap'])
        self.assertTrue((selected / 'nested/real-failure.txt').is_file())
        self.assertEqual(admission['selected_members'], len(original['entries']))
        self.assertGreater(admission['zip_upper_bound_bytes'], manifest['logical_bytes'] + results.MAX_METADATA)

    def test_rescue_refuses_original_mutation_or_missing_pre_rename_inventory(self):
        paths = self.rescue_fixture()
        canonical = {'status': 'FAIL', 'initial_bootstrap': results.inventory(paths['mount'])}
        paths['mount'].rename(paths['bootstrap']); paths['mount'].mkdir()
        with self.assertRaisesRegex(ValueError, 'pre-rename inventory'):
            results.original_selection(paths, None)
        (paths['bootstrap'] / 'nested/real-failure.txt').write_bytes(b'mutated original')
        with self.assertRaisesRegex(ValueError, 'changed'):
            results.original_selection(paths, canonical)

    def test_rescue_forbids_actual_guest_or_scientific_namespace(self):
        paths = self.rescue_fixture()
        results.assert_premeasurement(paths)
        guest = paths['volume'] / 'reference-guest'; guest.mkdir()
        with self.assertRaisesRegex(ValueError, 'guest setup already started'):
            results.assert_premeasurement(paths)
        guest.rmdir()
        namespace = paths['mount'] / 'benchmarks/diagnostic-fixture'; namespace.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, 'namespace already exists'):
            results.assert_premeasurement(paths)

    def test_rescue_name_and_header_bounds_include_directories_and_proof(self):
        manifest = results.inventory(self.bootstrap)
        admitted = results.rescue_zip_admission(self.bootstrap, manifest)
        self.assertEqual(admitted['selected_members'], len(manifest['entries']))
        self.assertGreater(admitted['zip_upper_bound_bytes'], manifest['logical_bytes'] + results.MAX_METADATA)
        altered = json.loads(json.dumps(manifest))
        altered['entries'][1]['path'] = '../outside'
        with self.assertRaisesRegex(ValueError, 'nonportable'):
            results.rescue_zip_admission(self.bootstrap, altered)
        altered['entries'][1]['path'] = 'x' * (results.MAX_RESCUE_NAME_BYTES + 1)
        with self.assertRaisesRegex(ValueError, 'name/count'):
            results.rescue_zip_admission(self.bootstrap, altered)

    @unittest.skipUnless(sys.platform == 'linux', 'actual Linux mount/ENOSPC/freeze are remote-only')
    def test_cli_operations_require_owned_runner_not_fixture(self):
        # This only checks the rejected fixture boundary, never invokes sudo.
        with self.assertRaises(ValueError):
            results.owned_paths(self.root, self.bootstrap)


if __name__ == '__main__':
    unittest.main()
