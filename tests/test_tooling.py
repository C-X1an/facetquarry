import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import disk_guard
import public_audit
class Tooling(unittest.TestCase):
    def test_inventory_counts_owned_file_and_reports_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'owned').write_bytes(b'x'*123)
            (p/'alias').symlink_to(p/'owned')
            inv=disk_guard.inventory(p)
            self.assertGreaterEqual(inv['accounted_bytes'],123);self.assertEqual(len(inv['symlinks_not_followed']),1)
    def test_external_file_inventory(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'toolchain.bin';p.write_bytes(b'x'*321)
            self.assertGreaterEqual(disk_guard.inventory(p)['accounted_bytes'],321)
    def test_admission_thresholds(self):
        self.assertTrue(disk_guard.admission(8_000_000_000,2_000_000_000,3_000_000_000))
        self.assertFalse(disk_guard.admission(11_000_000_000,2_000_000_000,3_000_000_000))
        self.assertFalse(disk_guard.admission(1,2_000_000_000,1_000_000_000))
        self.assertFalse(disk_guard.admission(1,1,3,True))
    def test_public_negative_controls(self):
        self.assertTrue(public_audit.problems('private/resume.md',b'private'))
        token=b'ghp_'+b'A'*36
        self.assertTrue(public_audit.problems('config.txt',token))
        self.assertEqual(public_audit.problems('internal/engine/valid.go',b'package engine\n'),[])
if __name__=='__main__':unittest.main()
