"""Fault-injection unit controls; real committed reproduction is a separate gate."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import clean_verify


class CleanRetention(unittest.TestCase):
    def test_outer_timeout_and_start_error_keep_evidence_after_clone_cleanup(self):
        failures=[subprocess.TimeoutExpired(['wrapper'],300,output=b'partial\r\n',stderr=b'actual partial error'),
                  FileNotFoundError('deliberate missing wrapper')]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as directory:
                base=Path(directory);out=base/'retained';out.mkdir()
                with tempfile.TemporaryDirectory(dir=base) as cloned:
                    clone=Path(cloned)
                    for name in ('evidence','test-failures'):
                        target=clone/'.local'/name;target.mkdir(parents=True);(target/'marker').write_bytes(b'available evidence')
                    with patch.object(clean_verify,'run',side_effect=failure):
                        outcome=clean_verify.checkout_commands(clone,out,['make','test'])
                    self.assertIsNone(outcome['exit_code']);self.assertIsNotNone(outcome['termination_reason'])
                    self.assertEqual(outcome['retention_errors'],[])
                self.assertFalse(clone.exists())
                for name in ('evidence','test-failures'):
                    self.assertEqual((out/name/'marker').read_bytes(),b'available evidence')
                if isinstance(failure,subprocess.TimeoutExpired):
                    self.assertEqual((out/'stdout.txt').read_bytes(),b'partial\r\n')
                    self.assertEqual((out/'stderr.txt').read_bytes(),b'actual partial error')

    def test_copy_failure_is_reported_without_claiming_retention_success(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as directory:
            base=Path(directory);clone=base/'clone';out=base/'out';out.mkdir()
            (clone/'.local/evidence').mkdir(parents=True)
            with patch.object(clean_verify,'run',side_effect=FileNotFoundError('missing wrapper')), \
                    patch.object(clean_verify.shutil,'copytree',side_effect=PermissionError('copy denied')):
                outcome=clean_verify.checkout_commands(clone,out,['make','test'])
            self.assertIsNone(outcome['exit_code']);self.assertTrue(outcome['retention_errors'])


if __name__=='__main__':unittest.main()
