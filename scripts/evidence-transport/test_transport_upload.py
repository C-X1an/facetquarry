"""Exact combined-upload admission controls with small synthetic files."""
import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import admit_transport_upload as a

class UploadControls(unittest.TestCase):
    def test_receipts_are_counted_and_oversize_bundle_is_explicit_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'results').mkdir();logs=root/'source/.local/evidence';logs.mkdir(parents=True)
            (root/'results/x.tar.xz').write_bytes(b'x'*900);(logs/'stderr.txt').write_bytes(b'e'*200)
            outputs=root/'github-output'
            with patch.object(a,'LIMIT',2_001_000),patch.object(a.sys,'argv',['admit',str(root)]),patch.dict(os.environ,{'GITHUB_OUTPUT':str(outputs)}):
                self.assertEqual(a.main(),1)
            report=json.loads((root/'upload-admission.json').read_text())
            self.assertEqual(report['combined_requested_bytes'],1100)
            self.assertEqual(report['excluded_paths'],['results/x.tar.xz'])
            self.assertTrue(report['diagnostic_only'])
            paths=outputs.read_text();self.assertIn(str(logs/'stderr.txt'),paths)
            self.assertNotIn(str(root/'results/x.tar.xz'),paths)

    def test_admitted_exact_set_contains_bundle_and_logs(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'results').mkdir();logs=root/'source/.local/evidence';logs.mkdir(parents=True)
            (root/'results/x.tar.xz').write_bytes(b'x');(logs/'stderr.txt').write_bytes(b'e')
            outputs=root/'github-output'
            with patch.object(a.sys,'argv',['admit',str(root)]),patch.dict(os.environ,{'GITHUB_OUTPUT':str(outputs)}):self.assertEqual(a.main(),0)
            self.assertIn(str(root/'results/x.tar.xz'),outputs.read_text())
            self.assertIn(str(logs/'stderr.txt'),outputs.read_text())

if __name__=='__main__':unittest.main(verbosity=2)
