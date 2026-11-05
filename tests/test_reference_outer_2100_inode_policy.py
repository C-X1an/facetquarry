"""Pure policy-selection controls. Stubbed file validation is not Linux evidence."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_filesystem as filesystem
import reference_filesystem_bindings as bindings
import reference_internal_transport as transport
import reference_outer_profile as outer


class StrictNestedInodePolicyControls(unittest.TestCase):
    def check(self, selected, declared, *, strict=True):
        context = {'source': 'a' * 64, 'commit': 'b' * 40, 'git_status': '',
                   'github_run_id': '123', 'github_run_attempt': '1'}
        if strict:
            context['profile'] = outer.STRICT_2100
        env = {'FQ_FILESYSTEM_POLICY': filesystem.POLICY, 'GITHUB_WORKSPACE': '/workspace'}
        if selected is not None:
            env['FQ_NESTED_FILESYSTEM_POLICY'] = selected
        proof = {'synthetic_selector_fixture_only': True}
        canonical = {'filesystem_policy': declared, 'filesystem_proof': proof}
        owned = {'image': Path('/owned/results.img'), 'mount': Path('/owned/results')}
        with patch.dict(os.environ, env, clear=True), patch.object(bindings, 'validate', return_value=proof) as validator:
            transport.validate_nested_filesystem(owned, canonical, context, live_mount=True)
            return validator.call_args.kwargs['policy']

    def test_strict_profile_refuses_legacy_policy_without_inode_selection(self):
        with self.assertRaises(ValueError):
            self.check(None, filesystem.POLICY)

    def test_strict_profile_accepts_explicit_named_inode_policy_selection(self):
        self.assertEqual(self.check(filesystem.NESTED_POLICY, filesystem.NESTED_POLICY),
                         filesystem.NESTED_POLICY)

    def test_legacy_policy_selection_keeps_existing_compatibility(self):
        self.assertEqual(self.check(None, filesystem.POLICY, strict=False), filesystem.POLICY)


if __name__ == '__main__':
    unittest.main()
