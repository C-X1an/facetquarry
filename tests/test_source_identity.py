"""Source membership and fail-closed controls, not a benchmark qualification."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import common


class SourceIdentity(unittest.TestCase):
    def test_mixed_case_paths_have_platform_independent_identity(self):
        # Fixed digest for these literal UTF-8 path/byte pairs in ASCII order.
        # Native Windows Path ordering casefolds and produces a different hash.
        names=['Alpha.py','Makefile','benchmarks/grid.json','nested/Z.go','nested/a.go']
        with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as directory:
            root=Path(directory)
            for name in reversed(names):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture\n')
            self.assertEqual(common.source_hash(root),
                '7fa3727f0420f89c131853897333b77a51b0ba5a0cde1af8ce6aa0b7b99b0859')
            self.assertEqual([p.relative_to(root).as_posix() for p in common.source_files(root)],names)
            (root/'Alpha.py').write_bytes(b'changed\n')
            self.assertNotEqual(common.source_hash(root),
                '7fa3727f0420f89c131853897333b77a51b0ba5a0cde1af8ce6aa0b7b99b0859')

    def test_membership_and_excluded_directories_are_not_opened(self):
        expected={'.gitattributes','Makefile','src/a.go','published.py',
                  'examples/query.json','benchmarks/grid.json','nested/phase_definitions.json'}
        ignored={'.cache/hidden.go','src/published/hidden.py','bin/hidden.go',
                 '.local/hidden.py','elsewhere/data.json','nested/examples/query.json','README.md','nested/.git'}
        with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as directory:
            root=Path(directory)
            for name in expected|ignored:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture\n')
            real_scandir=os.scandir
            def guarded(path):
                if Path(path).name in {'.cache','published','bin','.local'}:
                    raise AssertionError('excluded directory was opened: '+str(path))
                return real_scandir(path)
            with patch.object(common.os,'scandir',side_effect=guarded):
                selected=common.source_files(root)
                self.assertEqual({p.relative_to(root).as_posix() for p in selected},expected)
                before=common.source_hash(root)
                (root/'.gitattributes').write_text('* -text\n')
                self.assertNotEqual(common.source_hash(root),before)

    def test_included_directory_error_cannot_produce_partial_identity(self):
        # Deterministic filesystem fault injection; not an OS ACL/consent claim.
        with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as directory:
            root=Path(directory);(root/'included').mkdir();(root/'included/a.go').write_text('package a\n')
            real_scandir=os.scandir
            def denied(path):
                if Path(path).name=='included':raise PermissionError('deliberate included-directory failure')
                return real_scandir(path)
            with patch.object(common.os,'scandir',side_effect=denied):
                with self.assertRaises(PermissionError):common.source_hash(root)

    def test_selected_file_read_error_cannot_produce_identity(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as directory:
            root=Path(directory);target=root/'a.go';target.write_text('package a\n')
            real_read=Path.read_bytes
            def denied(path):
                if path==target:raise PermissionError('deliberate selected-file failure')
                return real_read(path)
            with patch.object(Path,'read_bytes',denied):
                with self.assertRaises(PermissionError):common.source_hash(root)


if __name__=='__main__':unittest.main()
