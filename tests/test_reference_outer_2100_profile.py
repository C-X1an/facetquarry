"""Pure geometry and nonallocating workflow controls; no measured Linux fit."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_internal_transport as transport
import reference_outer_profile as outer
import reference_pipeline as pipeline
import reference_reservation as reservation
import reference_filesystem as fs
import reference_filesystem_bindings as bindings
import reference_transport_policy as timing
import test_reference_internal_transport as old_transport
import test_reference_filesystem as old_fs
import test_reference_slots as old_slots


class StrictOuterProfileControls(unittest.TestCase):
    def documents(self):
        args = old_transport.InsideOuterPureControls().documents()
        args[1] = 2_100_000_000
        args[6]['profile'] = outer.STRICT_2100
        args[4].update(profile=outer.STRICT_2100, volume_file_bytes=args[1],
                       oversized_allocation_bytes=2_200_000_000)
        args[5] = {**transport.growth_plan(args[8], args[1], profile=outer.STRICT_2100),
                   'run_context': args[6]}
        return args

    def test_exact_named_geometry_and_unchanged_reservations(self):
        args = self.documents()
        plan = args[5]
        self.assertEqual(plan['profile'], outer.STRICT_2100)
        self.assertEqual(plan['branches'], {
            'packing_with_live_image': 2_400_000_000,
            'verified_bundle_upload_with_retained_image': 2_895_000_000,
            'failed_pack_exact_results_image_upload': 3_546_000_000})
        self.assertEqual(plan['maximum_new_stage_bytes'], 3_546_000_000)
        self.assertEqual(plan['outer_image_bytes'], 2_100_000_000)
        self.assertEqual(plan['nested_results_image_bytes'], 1_100_000_000)
        self.assertEqual(plan['package_allocation_inside_outer_bytes'], 401_000_000)
        self.assertEqual(plan['filesystem_free_floor_bytes'], 500_000_000)
        result = transport.validate_documents(*args)
        self.assertEqual(result['global_reserved_growth_bytes'], 2_000_000_000)
        self.assertFalse(transport.physical_admission(920_999_999)['allowed'])
        self.assertTrue(transport.physical_admission(921_000_000)['allowed'])
        self.assertEqual(timing.phase_seconds('verify'), 210)
        self.assertEqual(timing.phase_seconds('verify', timing.VERIFY_600), 600)

    def test_default_api_stays_2300_even_under_strict_environment(self):
        original = transport.growth_plan(2_000_000_000)
        with patch.dict(os.environ, {'FQ_RESERVATION_PROFILE': outer.STRICT_2100}):
            self.assertEqual(transport.growth_plan(2_000_000_000), original)
            with self.assertRaises(ValueError):
                transport.growth_plan(2_000_000_000, 2_100_000_000)
        self.assertEqual(transport.IMAGE_BYTES, 2_300_000_000)
        self.assertEqual(transport.PROBE_BYTES, 2_400_000_000)
        # Existing local-floor validator cannot reinterpret the strict image.
        args = self.documents()
        args[6] = transport.legacy_context(args[6])
        with self.assertRaises(ValueError):
            reservation.validate_documents(*args)

    def test_strict_boundary_and_global_reserve_are_unchanged(self):
        def plan(base):
            return transport.growth_plan(base, 2_100_000_000, profile=outer.STRICT_2100)
        self.assertEqual(plan(12_000_000_000 - 3_546_000_000)['admission'], 'REFUSE')
        self.assertEqual(plan(12_000_000_000 - 3_546_000_000 - 1)['admission'], 'ALLOW')
        for base in (True, 1_999_999_999, 2_000_000_000.0):
            with self.subTest(base=base), self.assertRaises(ValueError):
                plan(base)
        for profile, size in ((outer.STRICT_2100, 2_300_000_000),
                              (outer.LEGACY, 2_100_000_000), ('inside-outer-2100', 2_100_000_000)):
            with self.subTest(profile=profile, size=size), self.assertRaises(ValueError):
                transport.growth_plan(2_000_000_000, size, profile=profile)

    def test_quota_profile_plan_probe_and_context_mixing_refuse(self):
        mutations = (
            lambda a: a.__setitem__(1, 2_300_000_000),
            lambda a: a[4].update(volume_file_bytes=2_300_000_000),
            lambda a: a[4].update(oversized_allocation_bytes=2_400_000_000),
            lambda a: a[4].update(profile=outer.LEGACY),
            lambda a: a[4].update(profile_context={**a[6], 'github_run_attempt': '1'}),
            lambda a: a[4].update(profile_context={**a[6], 'source': 'c' * 64}),
            lambda a: a[5].update(profile=outer.LEGACY),
            lambda a: a[5].update(maximum_new_stage_bytes=3_346_000_000),
            lambda a: a[6].update(profile=outer.LEGACY),
        )
        for mutation in mutations:
            args = copy.deepcopy(self.documents())
            mutation(args)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                transport.validate_documents(*args)

    def test_actual_context_requires_explicit_named_profile(self):
        env = old_transport.fixture_environment()
        ctx = old_transport.fixture_context()
        env['FQ_RESERVATION_PROFILE'] = outer.STRICT_2100
        bound = transport.bind_context(env, ctx['commit'], '', ctx['source'], True)
        self.assertEqual(bound['profile'], outer.STRICT_2100)
        self.assertNotEqual(bound, ctx)
        for bad in ('', 'inside-outer-2100', 'auto', 'reference-inside-outer-2100-v2'):
            with self.subTest(profile=bad), self.assertRaises(ValueError):
                transport.bind_context({**env, 'FQ_RESERVATION_PROFILE': bad},
                                       ctx['commit'], '', ctx['source'], True)

    def test_cli_plan_refuses_2100_without_exact_explicit_profile(self):
        script = str(Path(transport.__file__))
        common = [sys.executable, script, 'plan', '2000000000', '--image-bytes', '2100000000']
        legacy = subprocess.run(common, capture_output=True, text=True, timeout=5)
        self.assertEqual(legacy.returncode, 1, legacy.stderr)
        self.assertEqual(json.loads(legacy.stdout)['status'], 'FAIL')
        strict = subprocess.run([*common, '--profile', outer.STRICT_2100],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(strict.returncode, 0, strict.stderr)
        self.assertEqual(json.loads(strict.stdout)['profile'], outer.STRICT_2100)
        self.assertEqual(json.loads(strict.stdout)['maximum_new_stage_bytes'], 3_546_000_000)

    def test_filesystem_proof_requires_named_context_and_exact_size(self):
        fixture = old_fs.FilesystemPolicyTests()
        args = list(fixture.fixture(2_100_000_000))
        with self.assertRaises(ValueError):
            fs.validate_policy(*args)
        args[4] = outer.filesystem_context(args[4], outer.STRICT_2100)
        args[0]['run_context'] = args[4]
        fixture.seal(args[0])
        fs.validate_policy(*args)
        bindings.context_shape(args[4])
        for size in (2_300_000_000, 2_099_999_999, True):
            self.assertFalse(outer.filesystem_size(size, args[4]))
        self.assertTrue(outer.filesystem_size(1_100_000_000, args[4]))
        with self.assertRaises(ValueError):
            outer.filesystem_context(args[4], outer.LEGACY)

    def test_upload_and_qualification_geometry_cannot_cross_profiles(self):
        args = self.documents()
        self.assertTrue(outer.quota_geometry(args[4], transport.legacy_context(args[6])))
        for mutation in (
                lambda q: q.update(profile=outer.LEGACY),
                lambda q: q.update(volume_file_bytes=2_300_000_000),
                lambda q: q.update(oversized_allocation_bytes=2_400_000_000),
                lambda q: q.update(profile_context=None),
                lambda q: q['profile_context'].update(source='invalid'),
                lambda q: q['profile_context'].update(github_run_attempt='0'),
                lambda q: q['profile_context'].update(repository_id=1)):
            quota = copy.deepcopy(args[4]); mutation(quota)
            self.assertFalse(outer.quota_geometry(quota, transport.legacy_context(args[6])))
        self.assertFalse(outer.quota_geometry(args[4], {**transport.legacy_context(args[6]),
                                                       'github_run_attempt': '99'}))
        value = pipeline.admission(args[8], 2_100_000_000, 200_000_000, 1_101_000_000,
                                   profile=outer.STRICT_2100)
        self.assertTrue(value['data_allowed'])
        self.assertTrue(value['outer_image_retained_through_upload'])
        self.assertFalse(pipeline.admission(args[8], 2_100_000_000, 200_000_000, 1_101_000_000,
                                            profile=outer.LEGACY)['data_allowed'])
        with self.assertRaises(ValueError):
            pipeline.admission(args[8], 2_300_000_000, 0, 1, profile=outer.STRICT_2100)


class StrictWorkflowAllocationControls(unittest.TestCase):
    def test_actual_shell_block_selects_2100_allocation_and_2200_probe(self):
        fixture = old_slots.ReferenceAllocationSlots()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        # The existing fixture's shell stubs observe calls without allocating,
        # formatting, mounting, unlinking, or running privileged commands.
        block = fixture.block
        fixture.block = ('FQ_RESERVATION_PROFILE=reference-inside-outer-2100-v1\n'
                         'fallocate() { observe fallocate "$@"; '
                         'if test "$2" = 2200000000; then '
                         'printf "No space left on device\\n" >&2; return 1; fi; }\n' + block)
        result = fixture.run_block(fixture.base)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = (fixture.base / 'calls.txt').read_text().splitlines()
        self.assertEqual([line.split()[0] for line in lines],
                         ['mkdir', 'fallocate', 'mkfs.ext4', 'sudo', 'sudo', 'fallocate', 'rm'])
        self.assertIn('2100000000', lines[1])
        self.assertIn('2200000000', lines[-2])
        self.assertFalse((fixture.base / 'image.img').exists())


if __name__ == '__main__':
    unittest.main()
