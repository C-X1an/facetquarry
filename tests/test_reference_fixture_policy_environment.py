"""Actual tiny fixture subprocess; not Make, Go or Linux filesystem qualification."""
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference_filesystem as filesystem


class FixturePolicyEnvironmentTests(unittest.TestCase):
    def test_recipe_isolates_both_workflow_policies_from_unchanged_positive_fixture(self):
        lines = (ROOT / 'Makefile').read_text().splitlines()
        start = lines.index('integration: build')
        recipe = next(line for line in lines[start + 1:] if '-m unittest discover' in line)
        prefix = recipe.split('$(PYTHON)', 1)[0].strip().split()
        env = dict(os.environ, FQ_FILESYSTEM_POLICY=filesystem.POLICY,
                   FQ_NESTED_FILESYSTEM_POLICY=filesystem.NESTED_POLICY)
        for assignment in prefix:
            self.assertRegex(assignment, re.compile(r'^FQ_[A-Z_]+=$'))
            env[assignment[:-1]] = ''
        result = subprocess.run([sys.executable, '-m', 'unittest',
            'test_reference_filesystem_bindings.FilesystemBindingTests.'
            'test_retained_summary_equal_and_nested_receipt_deletion_rejected_in_both_states', '-v'],
            cwd=ROOT / 'tests', env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Ran 1 test', result.stderr)
        self.assertNotIn('skipped=', result.stderr)


if __name__ == '__main__': unittest.main()
