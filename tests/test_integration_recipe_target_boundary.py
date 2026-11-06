"""Regress the independently reported recipe continuation boundary."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import integration_environment as runner

RECIPE = ('\tFQ_FILESYSTEM_POLICY= FQ_NESTED_FILESYSTEM_POLICY= '
          '$(PYTHON) -m unittest discover -s tests -p test_*.py -v\n')


class RecipeTargetBoundaryControls(unittest.TestCase):
    def specification(self, between):
        return 'python-fixtures:\n' + RECIPE + between + 'acceptance: test integration\n'

    def test_blank_and_comment_lines_do_not_end_the_target(self):
        for separator in ('\n', '# retained comment\n', '\n # retained comment\n\n'):
            with self.subTest(separator=separator), self.assertRaises(ValueError):
                runner.discovery_command(self.specification(separator + '\techo unexpected\n'))

    def test_comments_before_next_real_target_keep_the_single_command(self):
        expected = [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_*.py', '-v']
        self.assertEqual(runner.discovery_command(self.specification('\n# retained comment\n\n')), expected)

    def test_unknown_non_target_syntax_cannot_hide_a_second_recipe(self):
        for separator in ('UNRELATED=value\n', 'include other.mk\n', 'echo unexpected\n'):
            with self.subTest(separator=separator), self.assertRaises(ValueError):
                runner.discovery_command(self.specification(separator + '\techo unexpected\n'))


if __name__ == '__main__': unittest.main()
