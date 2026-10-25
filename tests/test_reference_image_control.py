"""Real original-file controls; no local mount or cloud recovery claim."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_image_control as control
import reference_results as results


class ReferenceImageControl(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[1] / '.cache/image-control-tests'
        cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=cache); self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).absolute(); self.project = self.base / 'source'
        self.local = self.project / '.local'; (self.local / 'empty').mkdir(parents=True)
        (self.local / 'real-failure.txt').write_bytes(b'actual original failure\x00\xff\n')

    def test_complete_manifest_checks_all_real_bytes_and_empty_directories(self):
        manifest = control.member_manifest(self.project)
        checked = control.same_members(self.project, manifest)
        self.assertEqual(checked['members'], 3)
        self.assertEqual(checked['original_bytes'], len((self.local / 'real-failure.txt').read_bytes()))
        self.assertTrue(any(item['path'] == '.local/empty/' for item in manifest))

    def test_same_length_corruption_new_member_and_missing_directory_refused(self):
        manifest = control.member_manifest(self.project)
        path = self.local / 'real-failure.txt'; original = path.read_bytes()
        path.write_bytes(b'x' * len(original))
        with self.assertRaisesRegex(ValueError, 'membership, bytes or modes'):
            control.same_members(self.project, manifest)
        path.write_bytes(original)
        (self.local / 'extra').write_bytes(b'not in originals')
        with self.assertRaises(ValueError): control.same_members(self.project, manifest)
        (self.local / 'extra').unlink(); (self.local / 'empty').rmdir()
        with self.assertRaises(ValueError): control.same_members(self.project, manifest)

    def test_control_manifest_member_and_serialized_byte_admission(self):
        with patch.object(control, 'MAX_CONTROL_MEMBERS', 2):
            with self.assertRaisesRegex(ValueError, 'member bound'):
                control.member_manifest(self.project)
        with patch.object(control, 'MAX_CONTROL_PROOF', 32768):
            with self.assertRaisesRegex(ValueError, 'complete manifest'):
                control.member_manifest(self.project)

    def test_bad_freeze_never_unmounts_an_existing_child(self):
        # Fault injection checks only the refused cleanup boundary. No mounted
        # fixture, sudo command, or successful image recovery is simulated.
        paths = {'volume': self.base, 'project': self.project, 'mount': self.local,
                 'image': self.base / 'not-an-image', 'proof': self.base / 'setup.json',
                 'freeze': self.base / 'freeze.json'}
        (self.base / 'reference-results-control-before.json').write_text(json.dumps({'status': 'FAIL'}))
        paths['freeze'].write_text(json.dumps({'status': 'FAIL'})); paths['proof'].write_text('{}')
        def forbidden(*args, **kwargs): raise AssertionError('invalid recovery must not launch any command')
        with patch.object(control, 'control_paths', return_value=paths), \
             patch.object(results, 'run_context', return_value={}), \
             patch.object(results.Commands, '__call__', side_effect=forbidden):
            with self.assertRaisesRegex(ValueError, 'execution differs'):
                control.recover(self.base, self.project)
        receipt = json.loads((self.base / 'reference-results-control-recovery.json').read_text())
        self.assertEqual(receipt['status'], 'FAIL')
        self.assertEqual(receipt['commands'], [])


if __name__ == '__main__': unittest.main()
