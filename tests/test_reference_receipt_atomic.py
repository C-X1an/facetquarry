"""Real Windows sharing behavior and bounded receipt-replacement controls."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_artifacts as artifacts


@unittest.skipUnless(os.name == 'nt', 'Windows receipt sharing semantics control')
class WindowsReceiptReplacement(unittest.TestCase):
    def test_actual_read_handle_lock_is_released_before_bounded_replacement(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'
            artifacts.write_json(path, {'status': 'RUNNING'})
            held = path.open('rb')
            release = threading.Timer(.1, held.close)
            release.start()
            try:
                with patch.object(artifacts.os, 'replace', wraps=os.replace) as actual:
                    artifacts.write_json(path, {'status': 'FAIL', 'originals_unchanged': True}, replace=True)
                self.assertGreater(actual.call_count, 1, 'real held read handle did not cause sharing refusal')
                self.assertEqual(json.loads(path.read_text())['status'], 'FAIL')
                self.assertFalse(path.with_name(path.name + '.tmp').exists())
            finally:
                release.join()
                held.close()

    def test_persistent_refusal_is_bounded_and_preserves_both_records(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'
            artifacts.write_json(path, {'status': 'RUNNING'})
            denial = PermissionError('controlled persistent sharing refusal')
            denial.winerror = 5
            with patch.object(artifacts.os, 'replace', side_effect=denial) as replace, \
                    patch.object(artifacts.time, 'sleep') as sleep:
                with self.assertRaises(PermissionError):
                    artifacts.write_json(path, {'status': 'FAIL'}, replace=True)
            self.assertLessEqual(replace.call_count, 11)
            self.assertLessEqual(sum(call.args[0] for call in sleep.call_args_list), .501)
            self.assertEqual(json.loads(path.read_text())['status'], 'RUNNING')
            self.assertEqual(json.loads(path.with_name(path.name + '.tmp').read_text())['status'], 'FAIL')

    def test_replacement_refuses_substitution_between_sharing_retries(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'
            artifacts.write_json(path, {'status': 'RUNNING'})
            denial = PermissionError('controlled first sharing refusal')
            denial.winerror = 5

            def substituted(*args):
                path.write_bytes(b'changed by another writer')
                raise denial

            with patch.object(artifacts.os, 'replace', side_effect=substituted) as replace, \
                    patch.object(artifacts.time, 'sleep'):
                with self.assertRaisesRegex(ValueError, 'changed'):
                    artifacts.write_json(path, {'status': 'FAIL'}, replace=True)
            self.assertEqual(replace.call_count, 1)
            self.assertEqual(path.read_bytes(), b'changed by another writer')
            self.assertTrue(path.with_name(path.name + '.tmp').is_file())

    def test_nonsharing_error_is_not_retried(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'
            artifacts.write_json(path, {'status': 'RUNNING'})
            denial = PermissionError('controlled nonsharing failure')
            denial.winerror = 87
            with patch.object(artifacts.os, 'replace', side_effect=denial) as replace, \
                    patch.object(artifacts.time, 'sleep') as sleep:
                with self.assertRaises(PermissionError):
                    artifacts.write_json(path, {'status': 'FAIL'}, replace=True)
            self.assertEqual(replace.call_count, 1)
            sleep.assert_not_called()
            self.assertEqual(json.loads(path.read_text())['status'], 'RUNNING')

    def test_temporary_receipt_substitution_is_not_published(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'
            temporary = path.with_name(path.name + '.tmp')
            artifacts.write_json(path, {'status': 'RUNNING'})
            denial = PermissionError('controlled first sharing refusal')
            denial.winerror = 32

            def substituted(*args):
                temporary.write_bytes(b'changed temporary bytes')
                raise denial

            with patch.object(artifacts.os, 'replace', side_effect=substituted) as replace, \
                    patch.object(artifacts.time, 'sleep'):
                with self.assertRaisesRegex(ValueError, 'changed'):
                    artifacts.write_json(path, {'status': 'FAIL'}, replace=True)
            self.assertEqual(replace.call_count, 1)
            self.assertEqual(json.loads(path.read_text())['status'], 'RUNNING')
            self.assertEqual(temporary.read_bytes(), b'changed temporary bytes')


if __name__ == '__main__':
    unittest.main()
