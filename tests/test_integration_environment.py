"""Tiny subprocess-boundary controls; no supported/Linux verification claim."""
import importlib
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference_outer_profile as outer_profile

REMOVED = {'FQ_RESERVATION_PROFILE', 'FQ_FILESYSTEM_POLICY', 'FQ_NESTED_FILESYSTEM_POLICY'}


class IntegrationEnvironmentControls(unittest.TestCase):
    def runner(self):
        return importlib.import_module('integration_environment')

    def inherited(self):
        return {'FQ_RESERVATION_PROFILE': 'supported-verification-capacity-v1',
                'FQ_FILESYSTEM_POLICY': 'owned-ext4-zero-reserved-v1',
                'FQ_NESTED_FILESYSTEM_POLICY': 'owned-ext4-zero-reserved-nested-inodes50000-v1',
                'FQ_FILESYSTEM_FREE_FLOOR': '500000000',
                'FQ_ACCOUNTED_BASE_BYTES': '9197542801', 'FQ_VOLUME': '/synthetic/quota',
                'FQ_IMAGE': '/synthetic/quota.img', 'FQ_WORKSPACE_ROOT': '/synthetic/quota',
                'GITHUB_ACTIONS': 'true', 'GITHUB_JOB': 'reference_capacity',
                'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                'GOTOOLCHAIN': 'local', 'TMPDIR': '/synthetic/quota/tmp',
                'TEMP': '/synthetic/quota/tmp', 'TMP': '/synthetic/quota/tmp',
                'GOCACHE': '/synthetic/quota/go-cache', 'GOMODCACHE': '/synthetic/quota/modules',
                'GOTMPDIR': '/synthetic/quota/tmp', 'PYTHONPATH': '/synthetic/source/scripts',
                'PATH': '/synthetic/tools', 'UNRELATED_EMPTY': '', 'UNRELATED_SENTINEL': 'preserve-me'}

    def test_child_removes_only_three_profile_selections_and_preserves_parent(self):
        original = self.inherited()
        before = original.copy()
        child = self.runner().fixture_environment(original)
        self.assertEqual(original, before)
        self.assertIsNot(child, original)
        self.assertEqual(child, {key: value for key, value in before.items() if key not in REMOVED})
        child['UNRELATED_SENTINEL'] = 'child-only'
        self.assertEqual(original['UNRELATED_SENTINEL'], 'preserve-me')

    def test_actual_capacity_profile_rejection_disappears_only_in_fixture_copy(self):
        original = self.inherited()
        with self.assertRaisesRegex(ValueError, 'unknown explicit inside-outer volume profile'):
            outer_profile.active(original)
        child = self.runner().fixture_environment(original)
        self.assertEqual(outer_profile.active(child), outer_profile.LEGACY)
        with self.assertRaises(ValueError): outer_profile.active(original)
        for unknown in ('', 'unknown', 'supported-verification-capacity-v1'):
            with self.subTest(profile=unknown), self.assertRaises(ValueError):
                outer_profile.active({'FQ_RESERVATION_PROFILE': unknown})

    def test_missing_profile_keys_do_not_mint_defaults_or_remove_other_keys(self):
        for parent in ({}, {'FQ_ACCOUNTED_BASE_BYTES': '2000000000', 'TMPDIR': '/synthetic/tmp'},
                       {'FQ_RESERVATION_PROFILE': outer_profile.STRICT_2100, 'KEEP': 'yes'}):
            before = parent.copy()
            with self.subTest(parent=parent):
                result = self.runner().fixture_environment(parent)
                self.assertEqual(result, {k: v for k, v in parent.items() if k not in REMOVED})
                self.assertEqual(parent, before)

    def invoke(self, returncode):
        runner = self.runner()
        original = self.inherited()
        with patch.dict(os.environ, original, clear=True), \
                patch.object(sys, 'argv', ['integration_environment.py', 'untrusted-test-subset']), \
                patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=returncode)) as run:
            before = dict(os.environ)
            result = runner.main()
            self.assertEqual(dict(os.environ), before)
        return result, run, original

    def test_main_executes_full_fixed_discovery_in_root_with_neutral_environment(self):
        result, run, original = self.invoke(0)
        self.assertEqual(result, 0)
        run.assert_called_once()
        self.assertEqual(run.call_args.args, ([sys.executable, '-m', 'unittest', 'discover',
            '-s', 'tests', '-p', 'test_*.py', '-v'],))
        self.assertEqual(run.call_args.kwargs['cwd'], ROOT)
        self.assertIs(run.call_args.kwargs['check'], False)
        self.assertEqual(run.call_args.kwargs['env'],
                         {key: value for key, value in original.items() if key not in REMOVED})
        self.assertFalse(run.call_args.kwargs.get('shell', False))

    def test_main_propagates_actual_failure_and_signal_return_codes(self):
        for code in (1, 2, 17, -15):
            with self.subTest(code=code):
                result, _, _ = self.invoke(code)
                self.assertEqual(result, code)

    def test_launch_errors_are_not_relabelled_as_success(self):
        runner = self.runner()
        with patch.object(runner.subprocess, 'run', side_effect=OSError('synthetic unavailable executable')):
            with self.assertRaises(OSError): runner.main()

    def test_make_integration_uses_runner_without_shortening_or_skipping_test_inventory(self):
        text = (ROOT / 'Makefile').read_text()
        target = re.search(r'^integration:[^\n]*\n((?:\t[^\n]*\n)+)', text, re.MULTILINE)
        self.assertIsNotNone(target)
        recipe = target.group(1)
        self.assertRegex(recipe, r'\$\(PYTHON\) scripts/integration_environment\.py(?:\s|$)')
        self.assertNotIn('-m unittest', recipe)
        self.assertNotIn('|| true', recipe)
        self.assertNotIn('|| exit 0', recipe)

    def test_real_capacity_profile_and_reservation_guards_remain_explicit(self):
        workflow = (ROOT / '.github/workflows/release-evidence.yml').read_text()
        capacity = workflow.split('  reference_capacity:', 1)[1]
        self.assertIn('FQ_RESERVATION_PROFILE: supported-verification-capacity-v1', capacity)
        self.assertIn('python3 scripts/reference_capacity.py stage --name verify --timeout 780 -- make verify', capacity)
        guard = (ROOT / 'scripts/reference_capacity_reservation.py').read_text()
        self.assertIn("os.environ.get('FQ_RESERVATION_PROFILE') == PROFILE", guard)
        self.assertIn('global_reserve == 2_000_000_000 and filesystem_floor == 500_000_000', guard)


if __name__ == '__main__': unittest.main()
