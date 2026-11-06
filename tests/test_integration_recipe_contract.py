"""Bounded shared full-suite recipe controls; no Make or child execution."""
import importlib
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

RECIPE = ('\tFQ_FILESYSTEM_POLICY= FQ_NESTED_FILESYSTEM_POLICY= '
          '$(PYTHON) -m unittest discover -s tests -p test_*.py -v\n')
COMMAND = [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_*.py', '-v']


class IntegrationRecipeContractControls(unittest.TestCase):
    def runner(self):
        return importlib.import_module('integration_environment')

    def text(self):
        return ('integration: build\n\t$(PYTHON) scripts/integration_environment.py\n'
                'python-fixtures:\n' + RECIPE + 'acceptance: test integration\n')

    def test_exact_reusable_full_suite_recipe_yields_fixed_direct_python_command(self):
        text = self.text()
        self.assertEqual(self.runner().discovery_command(text), COMMAND)
        self.assertEqual(self.runner().discovery_command(text.replace('\n', '\r\n')), COMMAND)

    def test_missing_duplicate_or_ambiguous_target_refuses(self):
        for text in (self.text().replace('python-fixtures:', 'other:'),
                     self.text() + 'python-fixtures:\n' + RECIPE,
                     self.text().replace('python-fixtures:', 'python-fixtures: build'),
                     self.text().replace('python-fixtures:', 'python-fixtures other:'),
                     self.text().replace('python-fixtures:', 'python-fixtures::')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.runner().discovery_command(text)

    def test_missing_extra_and_non_tab_recipes_refuse(self):
        for text in (self.text().replace(RECIPE, ''),
                     self.text().replace(RECIPE, RECIPE + '\t$(PYTHON) -V\n'),
                     self.text().replace(RECIPE, RECIPE.lstrip('\t')),
                     self.text().replace(RECIPE, '\techo synthetic\n' + RECIPE)):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.runner().discovery_command(text)

    def test_wrong_executable_shortened_selection_or_extra_test_arguments_refuse(self):
        for before, after in (('$(PYTHON)', 'python3'), ('-m unittest', '-m pytest'),
                              ('test_*.py', 'test_reference_*.py'), ('-s tests', '-s tests/subset'),
                              (' -v', ' -q'), (' -v', ' -v -k passing'),
                              ('discover ', 'discover --failfast '), ('-p test_*.py', '')):
            changed = self.text().replace(RECIPE, RECIPE.replace(before, after))
            with self.subTest(after=after), self.assertRaises(ValueError):
                self.runner().discovery_command(changed)

    def test_missing_changed_extra_or_duplicate_environment_assignments_refuse(self):
        for before, after in (('FQ_FILESYSTEM_POLICY= ', ''),
                              ('FQ_NESTED_FILESYSTEM_POLICY= ', ''),
                              ('FQ_FILESYSTEM_POLICY=', 'FQ_FILESYSTEM_POLICY=unsafe'),
                              ('$(PYTHON)', 'FQ_RESERVATION_PROFILE= $(PYTHON)'),
                              ('$(PYTHON)', 'FQ_FILESYSTEM_POLICY= $(PYTHON)')):
            changed = self.text().replace(RECIPE, RECIPE.replace(before, after))
            with self.subTest(after=after), self.assertRaises(ValueError):
                self.runner().discovery_command(changed)

    def test_shell_operators_continuations_and_expansions_refuse(self):
        for fragment in ('; echo synthetic', ' && echo synthetic', ' || true', ' > output',
                         ' | cat', ' # ignored', ' $(shell echo synthetic)', ' `echo synthetic`',
                         ' \\\n\techo synthetic'):
            changed = self.text().replace(RECIPE, RECIPE.rstrip('\n') + fragment + '\n')
            with self.subTest(fragment=fragment), self.assertRaises(ValueError):
                self.runner().discovery_command(changed)

    def test_input_type_and_utf8_byte_bound_are_enforced(self):
        for value in (None, b'python-fixtures:', 123, self.text() + '#' + 'x' * 65536,
                      self.text() + '#' + '\u00e9' * 32768):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                self.runner().discovery_command(value)
        text = self.text()
        padded = text + '#' + 'x' * (65536 - len(text.encode()) - 1)
        self.assertEqual(len(padded.encode()), 65536)
        self.assertEqual(self.runner().discovery_command(padded), COMMAND)

    def test_main_consumes_validated_recipe_once_without_shell_and_keeps_child_failure(self):
        runner = self.runner()
        with patch.object(runner, 'discovery_command', return_value=COMMAND) as parser, \
                patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=23)) as run:
            self.assertEqual(runner.main(), 23)
        parser.assert_called_once()
        self.assertEqual(parser.call_args.args, ((ROOT / 'Makefile').read_text(),))
        run.assert_called_once()
        self.assertEqual(run.call_args.args, (COMMAND,))
        self.assertFalse(run.call_args.kwargs.get('shell', False))
        self.assertIs(run.call_args.kwargs['check'], False)

    def test_main_rejects_invalid_recipe_before_launch(self):
        runner = self.runner()
        with patch.object(runner, 'discovery_command', side_effect=ValueError('synthetic invalid recipe')), \
                patch.object(runner.subprocess, 'run') as run:
            with self.assertRaises(ValueError): runner.main()
        run.assert_not_called()

    def test_actual_make_target_is_the_command_source_for_the_runner(self):
        text = (ROOT / 'Makefile').read_text()
        self.assertEqual(self.runner().discovery_command(text), COMMAND)
        self.assertLess(text.index('integration: build'), text.index('python-fixtures:'))


if __name__ == '__main__': unittest.main()
