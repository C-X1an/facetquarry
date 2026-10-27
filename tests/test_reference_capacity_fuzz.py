"""Tiny file-backed corpus controls; these do not run a Go fuzz campaign."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_capacity_fuzz as fuzz


def fixture_context():
    return {'repository': 'C-X1an/facetquarry', 'repository_id': 1430604581,
            'commit': 'a' * 40, 'git_status': '', 'source': 'b' * 64,
            'github_run_id': '12345', 'github_run_attempt': '1',
            'job': 'reference_capacity', 'profile': 'supported-verification-capacity-v1'}


class CapacityFuzzFiles(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix='capacity-fuzz-', dir=cache)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.volume = self.base / 'facetquarry-capacity'
        self.project = self.volume / 'source'
        (self.project / '.local').mkdir(parents=True)
        self.output = self.project / fuzz.OUTPUT
        self.context = fixture_context()
        self.environment = mock.patch.dict(os.environ, {'RUNNER_TEMP': str(self.base)})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def seed(self, label='cache', name='package/FuzzQuery/seed', data=b'go test fuzz v1\nstring("fixture")\n'):
        root = self.project / dict(fuzz.ROOTS)[label]
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def preserve(self, **overrides):
        args = {'closed_writer_proof': True, 'run_context': self.context}
        args.update(overrides)
        return fuzz.preserve(self.volume, self.project, **args)

    def inject_after_first_copy(self, action):
        original = fuzz._copy
        injected = False

        def altered(binding, source, target, row):
            nonlocal injected
            original(binding, source, target, row)
            if not injected:
                injected = True
                action(source, target)

        return mock.patch.object(fuzz, '_copy', side_effect=altered)

    def test_complete_real_bytes_both_roots_hidden_empty_and_manifest(self):
        originals = {
            'cache/package/FuzzQuery/seed': self.seed(),
            'cache/.hidden/zero': self.seed(name='.hidden/zero', data=b''),
            'engine-testdata/FuzzSnapshot/seed': self.seed('engine-testdata', 'FuzzSnapshot/seed', b'\x00\xff\n')}
        (self.project / dict(fuzz.ROOTS)['cache'] / 'empty-directory').mkdir()
        proof = self.preserve()
        self.assertEqual(proof['status'], 'PASS')
        self.assertEqual(proof['run_context'], self.context)
        self.assertEqual(proof['count'], len(originals))
        self.assertEqual(proof['bytes'], sum(path.stat().st_size for path in originals.values()))
        self.assertTrue(proof['closed_writer_proof'])
        self.assertTrue(proof['corpus_observed'])
        self.assertFalse(proof['campaign_qualified'])
        raw = (self.project / proof['manifest']).read_bytes()
        self.assertEqual(proof['manifest_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(proof['retained_logical_bytes'], proof['bytes'] + len(raw))
        self.assertLess(proof['retained_logical_bytes'], 2_000_000)
        manifest = json.loads(raw)
        snapshot = manifest['snapshot']
        self.assertEqual(proof['snapshot_sha256'], hashlib.sha256(fuzz._encode(snapshot)).hexdigest())
        records = {row['path']: row for row in snapshot['entries'] if row['kind'] == 'file'}
        self.assertEqual(set(records), set(originals))
        self.assertEqual(manifest['run_context'], self.context)
        self.assertFalse(manifest['campaign_qualified'])
        for name, original in originals.items():
            with self.subTest(name=name):
                self.assertEqual((self.output / name).read_bytes(), original.read_bytes())
                self.assertEqual(records[name]['sha256'], hashlib.sha256(original.read_bytes()).hexdigest())
                self.assertEqual(records[name]['identity'], fuzz._identity(original.lstat()))
        self.assertTrue((self.output / 'cache/empty-directory').is_dir())

    def test_missing_roots_are_explicit_empty_observations(self):
        proof = self.preserve()
        self.assertEqual(proof['count'], 0)
        self.assertEqual(proof['bytes'], 0)
        self.assertEqual({row['label']: row['present'] for row in proof['roots']},
                         {'cache': False, 'engine-testdata': False})
        self.assertFalse(proof['corpus_observed'])
        self.assertFalse(proof['campaign_qualified'])

    def test_present_empty_root_does_not_invent_campaign(self):
        (self.project / dict(fuzz.ROOTS)['cache']).mkdir(parents=True)
        proof = self.preserve()
        self.assertEqual(proof['count'], 0)
        self.assertEqual({row['label']: row['present'] for row in proof['roots']},
                         {'cache': True, 'engine-testdata': False})
        self.assertTrue((self.output / 'cache').is_dir())
        self.assertFalse(proof['corpus_observed'])
        self.assertFalse(proof['campaign_qualified'])

    def test_positive_closed_writer_proof_is_required_before_any_output(self):
        self.seed()
        for value in (False, None, 1, {}, 'true'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'closed-writer'):
                self.preserve(closed_writer_proof=value)
            self.assertFalse(self.output.exists())

    def test_exact_context_fields_and_types_are_bound(self):
        for key, value in [('repository', 'other/repo'), ('repository_id', True),
                           ('commit', 'a' * 39), ('source', 'b' * 63), ('git_status', ' M file'),
                           ('github_run_id', '0'), ('github_run_attempt', '1\n'),
                           ('job', 'reference'), ('profile', 'unknown')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.preserve(run_context={**self.context, key: value})
        with self.assertRaises(ValueError):
            self.preserve(run_context={**self.context, 'unexpected': 'field'})
        self.assertFalse(self.output.exists())

    def test_wrong_volume_source_and_non_normalized_paths_are_refused(self):
        cases = [(self.base / 'other-volume', self.project),
                 (self.volume, self.volume / 'other-source'),
                 (self.volume, self.project / '../source'),
                 (Path('relative-volume'), self.project)]
        for volume, project in cases:
            with self.subTest(volume=volume, project=project), self.assertRaises(ValueError):
                fuzz.preserve(volume, project, closed_writer_proof=True, run_context=self.context)
        with mock.patch.dict(os.environ, {'RUNNER_TEMP': str(self.base / 'other')}):
            with self.assertRaisesRegex(ValueError, 'exact owned'):
                self.preserve()
        self.assertFalse(self.output.exists())

    def test_wrong_expected_uid_is_refused_against_actual_owned_files(self):
        self.seed()
        with mock.patch.object(fuzz, '_uid', return_value=self.volume.lstat().st_uid + 1):
            with self.assertRaisesRegex(ValueError, 'UID'):
                self.preserve()
        self.assertFalse(self.output.exists())

    def test_missing_local_parent_is_an_error_not_an_empty_corpus_pass(self):
        (self.project / '.local').rmdir()
        with self.assertRaises(FileNotFoundError):
            self.preserve()
        self.assertFalse(self.output.exists())

    def test_existing_output_is_refused_without_clobber(self):
        self.output.mkdir()
        sentinel = self.output / 'retained-failure'
        sentinel.write_bytes(b'keep these diagnostics')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.preserve()
        self.assertEqual(sentinel.read_bytes(), b'keep these diagnostics')

    def test_dangling_output_link_is_still_an_output_collision(self):
        try:
            self.output.symlink_to(self.base / 'absent-target', target_is_directory=True)
        except OSError as error:
            self.skipTest('fixture symlinks unavailable: ' + str(error))
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.preserve()
        self.assertTrue(self.output.is_symlink())

    def test_linked_corpus_root_is_refused(self):
        seed = self.seed()
        root = self.project / dict(fuzz.ROOTS)['cache']
        moved = self.base / 'retained-corpus'
        root.rename(moved)
        try:
            root.symlink_to(moved, target_is_directory=True)
        except OSError as error:
            moved.rename(root)
            self.skipTest('fixture symlinks unavailable: ' + str(error))
        with self.assertRaisesRegex(ValueError, 'linked/reparse'):
            self.preserve()
        self.assertTrue((moved / seed.relative_to(root)).is_file())
        self.assertFalse(self.output.exists())

    def test_hardlinked_corpus_member_is_refused(self):
        original = self.seed()
        try:
            os.link(original, self.base / 'second-link')
        except OSError as error:
            self.skipTest('fixture hardlinks unavailable: ' + str(error))
        with self.assertRaisesRegex(ValueError, 'hardlinked'):
            self.preserve()
        self.assertFalse(self.output.exists())

    def test_complete_byte_cap_refuses_before_copy_instead_of_skipping(self):
        original = self.seed(data=b'1234')
        with self.assertRaisesRegex(ValueError, 'corpus file/byte admission'):
            self.preserve(max_bytes=3)
        self.assertEqual(original.read_bytes(), b'1234')
        self.assertFalse(self.output.exists())

    def test_maximum_cannot_exceed_capacity_or_legacy_bound(self):
        for maximum in (True, 0, -1, 35_000_001, 100_000_001, 1.0):
            with self.subTest(maximum=maximum), self.assertRaisesRegex(ValueError, 'capacity/legacy'):
                self.preserve(max_bytes=maximum)
        self.assertFalse(self.output.exists())

    def test_manifest_cost_is_included_and_partial_copies_are_retained(self):
        original = self.seed(data=b'x')
        with self.assertRaisesRegex(ValueError, 'copies and manifest exceed'):
            self.preserve(max_bytes=2)
        self.assertEqual((self.output / 'cache/package/FuzzQuery/seed').read_bytes(), b'x')
        self.assertEqual(original.read_bytes(), b'x')
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_file_member_entry_and_manifest_limits_are_failures(self):
        original = self.seed(data=b'xyz')
        self.seed('engine-testdata', 'FuzzSnapshot/seed', b'second')
        for name, limit, expected in [('MAX_FILES', 1, 'corpus file/byte'),
                                       ('MAX_MEMBER', 2, 'corpus file/byte'),
                                       ('MAX_ENTRIES', 2, 'complete')]:
            with self.subTest(name=name), mock.patch.object(fuzz, name, limit):
                with self.assertRaisesRegex(ValueError, expected):
                    self.preserve()
            self.assertFalse(self.output.exists())
        with mock.patch.object(fuzz, 'MAX_MANIFEST', 1024):
            with self.assertRaisesRegex(ValueError, 'manifest exceeds'):
                self.preserve()
        self.assertEqual(original.read_bytes(), b'xyz')
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_new_live_member_during_copy_is_rejected(self):
        self.seed()
        with self.inject_after_first_copy(lambda source, target: source.with_name('new-member').write_bytes(b'new')):
            with self.assertRaisesRegex(ValueError, 'live fuzz corpus'):
                self.preserve()
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_live_byte_mutation_during_copy_is_rejected(self):
        self.seed()
        with self.inject_after_first_copy(lambda source, target: source.write_bytes(b'changed live bytes')):
            with self.assertRaisesRegex(ValueError, 'live fuzz corpus'):
                self.preserve()
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_same_bytes_new_live_inode_is_rejected(self):
        self.seed()

        def substitute(source, target):
            replacement = source.with_name('replacement')
            replacement.write_bytes(source.read_bytes())
            os.replace(replacement, source)

        with self.inject_after_first_copy(substitute):
            with self.assertRaisesRegex(ValueError, 'identity substituted'):
                self.preserve()

    def test_source_ancestor_substitution_during_copy_is_rejected(self):
        self.seed()

        def substitute(source, target):
            original = self.project / '.cache/go-build'
            original.rename(self.project / '.cache/retained-go-build')
            (original / 'fuzz').mkdir(parents=True)

        with self.inject_after_first_copy(substitute):
            with self.assertRaisesRegex(ValueError, 'identity substituted'):
                self.preserve()

    def test_preserved_byte_mutation_is_rejected(self):
        self.seed()
        with self.inject_after_first_copy(lambda source, target: target.write_bytes(b'corrupted copy')):
            with self.assertRaisesRegex(ValueError, 'preserved fuzz bytes'):
                self.preserve()
        self.assertFalse((self.output / 'manifest.json').exists())

    def test_new_preserved_member_is_rejected(self):
        self.seed()
        with self.inject_after_first_copy(lambda source, target: target.with_name('unlisted').write_bytes(b'added copy')):
            with self.assertRaisesRegex(ValueError, 'complete membership'):
                self.preserve()

    def test_unlisted_top_level_output_member_is_rejected(self):
        self.seed()
        with self.inject_after_first_copy(lambda source, target: (self.output / 'unlisted').write_bytes(b'added')):
            with self.assertRaisesRegex(ValueError, 'unlisted fuzz preservation'):
                self.preserve()

    def test_copy_error_propagates_and_keeps_actual_partial_diagnostics(self):
        original = self.seed()
        real_copy = fuzz._copy

        def fail_after_copy(binding, source, target, row):
            real_copy(binding, source, target, row)
            raise OSError('injected fixture copy failure')

        with mock.patch.object(fuzz, '_copy', side_effect=fail_after_copy):
            with self.assertRaisesRegex(OSError, 'injected fixture'):
                self.preserve()
        self.assertEqual((self.output / 'cache/package/FuzzQuery/seed').read_bytes(), original.read_bytes())
        self.assertFalse((self.output / 'manifest.json').exists())


if __name__ == '__main__':
    unittest.main()
