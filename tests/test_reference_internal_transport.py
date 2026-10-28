"""Pure and tiny byte controls; never a Linux quota, mount or recovery claim.

All generated files stay below two MB per fixture in public/.cache/tmp. Tests do
not call the production guest deleter, freeze, mount or any privileged command.
"""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import evidence_bundle as bundle
import reference_artifacts as artifacts
import reference_internal_transport as transport


def fixture_context():
    return {'profile': transport.PROFILE, 'job': 'reference',
            'repository': transport.REPOSITORY, 'repository_id': transport.REPOSITORY_ID,
            'source': 'a' * 64, 'commit': 'b' * 40, 'git_status': '',
            'github_run_id': '1234567', 'github_run_attempt': '2'}


def fixture_environment():
    ctx = fixture_context()
    return {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': ctx['repository'],
            'GITHUB_REPOSITORY_ID': str(ctx['repository_id']), 'GITHUB_JOB': 'reference',
            'FQ_RESERVATION_PROFILE': transport.PROFILE, 'GITHUB_SHA': ctx['commit'],
            'GITHUB_RUN_ID': ctx['github_run_id'], 'GITHUB_RUN_ATTEMPT': ctx['github_run_attempt']}


class InsideOuterPureControls(unittest.TestCase):
    def documents(self):
        volume = Path('/synthetic-runner/facetquarry-reference')
        ctx = fixture_context()
        mount = {'target': str(volume), 'fstype': 'ext4', 'source': '/dev/loop17'}
        loops = {'loopdevices': [{'name': '/dev/loop17', 'back-file': str(volume) + '.img'}]}
        stderr = b'fallocate: No space left on device\n'
        base = 8_041_801_351  # Arithmetic example only, never a live baseline.
        quota = {'profile': transport.PROFILE, 'profile_context': ctx,
                 'run_context': transport.legacy_context(ctx),
                 'volume_file_bytes': transport.IMAGE_BYTES, 'oversized_allocation_bytes': transport.PROBE_BYTES,
                 'oversized_allocation': 'DENIED_ENOSPC', 'hard_quota_enforced': True,
                 'volume_path': str(volume), 'image_path': str(volume) + '.img', 'mount': mount,
                 'enospc_sha256': hashlib.sha256(stderr).hexdigest()}
        planned = {**transport.growth_plan(base), 'run_context': ctx}
        return [volume, transport.IMAGE_BYTES, mount, loops, quota, planned, ctx, stderr, base]

    def test_exact_new_branches_preserve_all_reservations(self):
        plan = transport.growth_plan(8_041_801_351)
        self.assertEqual(plan['profile'], transport.PROFILE)
        self.assertEqual(plan['branches'], {
            'packing_with_live_image': 2_600_000_000,
            'verified_bundle_upload_with_retained_image': 3_095_000_000,
            'failed_pack_exact_results_image_upload': 3_746_000_000})
        self.assertEqual(plan['peak_bytes'], 11_787_801_351)
        self.assertEqual(plan['nested_results_image_bytes'], 1_100_000_000)
        self.assertEqual(plan['package_allocation_inside_outer_bytes'], 401_000_000)
        self.assertEqual(plan['filesystem_free_floor_bytes'], 500_000_000)
        self.assertTrue(plan['outer_image_retained_through_upload'])
        self.assertFalse(plan['external_package_copy_allowed'])
        self.assertIn('never both', plan['required_upload_policy'])

    def test_strict_admission_boundary_and_fresh_baseline(self):
        maximum = transport.growth_plan(2_000_000_000)['maximum_new_stage_bytes']
        self.assertEqual(transport.growth_plan(12_000_000_000 - maximum)['admission'], 'REFUSE')
        self.assertEqual(transport.growth_plan(12_000_000_000 - maximum - 1)['admission'], 'ALLOW')
        for baseline in (True, 1_999_999_999, -1, 2_000_000_000.0):
            with self.subTest(baseline=baseline), self.assertRaises(ValueError):
                transport.growth_plan(baseline)
        for image in (2_299_999_999, 2_300_000_001, 3_300_000_000, True):
            with self.subTest(image=image), self.assertRaises(ValueError):
                transport.growth_plan(2_000_000_000, image)
        # Retained earlier artifacts alter the next actual baseline.
        self.assertEqual(transport.growth_plan(8_041_801_351 + 495_000_000)['admission'], 'REFUSE')

    def test_physical_floor_includes_package_and_bounded_controls(self):
        needed = 901_000_000 + transport.CONTROL_ALLOCATION
        self.assertFalse(transport.physical_admission(needed - 1)['allowed'])
        exact = transport.physical_admission(needed)
        self.assertTrue(exact['allowed'])
        self.assertEqual(exact['filesystem_free_floor_bytes'], 500_000_000)
        self.assertFalse(transport.physical_admission(901_000_000)['allowed'])
        for invalid in (-1, True, 921_000_000.0):
            with self.assertRaises(ValueError):
                transport.physical_admission(invalid)

    def test_absolute_job_time_reserves_complete_failure_tail(self):
        start = 1_800_000_000
        boundary = start + transport.JOB_SECONDS - 1920 - 1200
        self.assertTrue(transport.time_admission(start, boundary - .01)['allowed'])
        exact = transport.time_admission(start, boundary)
        self.assertFalse(exact['allowed'])
        self.assertEqual(exact['phase_seconds'], 1920)
        self.assertEqual(exact['complete_failure_tail_seconds'], 1200)
        verify_boundary = start + transport.JOB_SECONDS - 210 - 1200
        self.assertFalse(transport.time_admission(start, verify_boundary, 'verify')['allowed'])
        self.assertTrue(transport.time_admission(start, verify_boundary - 1, 'verify')['allowed'])
        self.assertFalse(transport.time_admission(start, start + transport.JOB_SECONDS)['failure_tail_available'])
        for invalid in ((start, start - 1), (float('nan'), start), (start, float('inf')), (True, start)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                transport.time_admission(*invalid)
        with self.assertRaises(ValueError):
            transport.time_admission(start, start, 'legacy')

    def test_actual_same_repository_context_only(self):
        env, ctx = fixture_environment(), fixture_context()
        self.assertEqual(transport.bind_context(env, ctx['commit'], '', ctx['source'], True), ctx)
        for key, bad in (('GITHUB_ACTIONS', 'false'), ('GITHUB_JOB', 'reference_capacity'),
                         ('GITHUB_REPOSITORY', 'someone/facetquarry'), ('GITHUB_REPOSITORY_ID', '1'),
                         ('FQ_RESERVATION_PROFILE', ''), ('FQ_RESERVATION_PROFILE', 'unknown'),
                         ('GITHUB_RUN_ID', '0'), ('GITHUB_RUN_ATTEMPT', 'missing'), ('GITHUB_SHA', 'c' * 40)):
            changed = {**env, key: bad}
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                transport.bind_context(changed, ctx['commit'], '', ctx['source'], True)
        for state, digest, ordinary in ((' M file', ctx['source'], True), ('', 'no digest', True), ('', ctx['source'], False)):
            with self.assertRaises(ValueError):
                transport.bind_context(env, ctx['commit'], state, digest, ordinary)

    def test_new_quota_document_is_not_a_converted_legacy_proof(self):
        result = transport.validate_documents(*self.documents())
        self.assertEqual(result['profile'], transport.PROFILE)
        self.assertEqual(result['global_reserved_growth_bytes'], 2_000_000_000)
        self.assertEqual(result['filesystem_free_floor_bytes'], 500_000_000)
        def wrong_profile(args): args[4]['profile'] = 'supported-verification-capacity-v1'
        def missing_full_context(args): del args[4]['profile_context']
        def stale_attempt(args): args[4]['profile_context'] = {**args[6], 'github_run_attempt': '1'}
        def stale_source(args): args[4]['profile_context'] = {**args[6], 'source': 'c' * 64}
        def old_plan(args): args[5] = artifacts.growth_plan(args[8], transport.IMAGE_BYTES)
        def fresh_baseline_differs(args): args[8] += 1
        def weakened_peak(args): args[5]['maximum_new_stage_bytes'] -= 1
        def wrong_device(args): args[3]['loopdevices'][0]['name'] = '/dev/loop18'
        def wrong_backing(args): args[3]['loopdevices'][0]['back-file'] += '.other'
        def ambiguous_backing(args): args[3]['loopdevices'].append(dict(args[3]['loopdevices'][0]))
        def wrong_mount(args): args[2]['target'] += '/source'
        def wrong_fs(args): args[2]['fstype'] = 'tmpfs'
        def no_enospc(args): args[7] = b'Permission denied\n'
        def different_probe(args): args[4]['oversized_allocation_bytes'] -= 1
        def no_quota(args): args[4]['hard_quota_enforced'] = False
        for mutation in (wrong_profile, missing_full_context, stale_attempt, stale_source, old_plan,
                         fresh_baseline_differs, weakened_peak, wrong_device, wrong_backing,
                         ambiguous_backing, wrong_mount, wrong_fs, no_enospc, different_probe, no_quota):
            args = copy.deepcopy(self.documents())
            mutation(args)
            with self.subTest(mutation=mutation.__name__), self.assertRaises(ValueError):
                transport.validate_documents(*args)


class InsideOuterByteControls(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='inside-outer-', dir=cache)
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name).absolute()
        self.volume, self.root = self.folder / 'facetquarry-reference', self.folder / 'checkout'
        self.project = self.volume / 'source'
        (self.project / '.local').mkdir(parents=True)
        (self.root / '.local').mkdir(parents=True)
        self.p = {'volume': self.volume, 'project': self.project, 'outer': self.root,
                  'local': self.root / '.local', 'image': self.folder / 'facetquarry-reference.img',
                  'data': self.volume / 'reference-transport',
                  'package': self.volume / 'reference-transport/reference-members.tar.xz',
                  'audit': self.root / '.local/reference-transport'}
        self.original = self.project / '.local/raw.json'
        self.original.write_bytes(b'{"actual_fixture":true}\n')
        self.ctx = fixture_context()
        environment = patch.dict(os.environ, fixture_environment())
        environment.start()
        self.addCleanup(environment.stop)

    def make_scripts(self, body=None):
        scripts = self.project / 'scripts'
        scripts.mkdir(exist_ok=True)
        target = scripts / 'evidence_bundle.py'
        if body is None:
            shutil.copyfile(Path(bundle.__file__), target)
        else:
            target.write_text(body)

    def attempt(self, *, control=False, timeout=20):
        self.p['data'].mkdir(exist_ok=True)
        self.p['audit'].mkdir(exist_ok=True)
        return artifacts.run_pack(self.project, self.p['package'], self.ctx['source'], self.ctx['commit'],
                                  self.ctx['github_run_id'], timeout, preset=6, control=control,
                                  progress=True, audit_dir=self.p['audit'])

    def save_controller(self, attempted):
        package = self.p['package']
        record = {'profile': transport.PROFILE, 'status': 'PASS', 'run_context': self.ctx,
                  'package_path': str(package), 'audit_path': str(self.p['audit']), 'control': False,
                  'bundle_sha256': bundle.file_sha(package), 'bundle_bytes': package.stat().st_size,
                  'pack_attempt': {'attempt_sha256': bundle.file_sha(self.p['audit'] / 'pack-attempt.json')}}
        transport.write_small(self.p['audit'] / 'pack-result.json', record)
        return record

    def test_wrong_paths_and_unmounted_same_device_are_rejected(self):
        env = {'RUNNER_TEMP': str(self.folder), 'GITHUB_WORKSPACE': str(self.root),
               'FQ_WORKSPACE_ROOT': str(self.volume), 'FQ_IMAGE': str(self.p['image'])}
        with patch.dict(os.environ, env):
            # A real tiny ordinary directory has no admitted separate ext4 device.
            with self.assertRaisesRegex(ValueError, 'wrong filesystem'):
                transport.paths(self.volume, self.project, self.root)
            for volume, project, root in ((self.volume, self.project / 'other', self.root),
                                          (self.folder / 'other', self.project, self.root),
                                          (self.volume, self.project, self.project)):
                with self.assertRaises(ValueError):
                    transport.paths(volume, project, root)

    def test_external_refusal_receipt_precedes_any_package_allocation(self):
        denied = transport.time_admission(1_800_000_000, 1_800_000_000 + transport.JOB_SECONDS)
        with patch.object(transport, 'paths', return_value=self.p), \
                patch.object(transport, 'context', return_value=self.ctx), \
                patch.object(transport, 'observe_outer', return_value={'profile': transport.PROFILE}), \
                patch.object(transport, 'current_time_admission', return_value=denied), \
                patch.object(artifacts, 'run_pack') as run:
            record = transport.pack(self.volume, self.project, self.root)
        run.assert_not_called()
        self.assertEqual(record['status'], 'FAIL')
        self.assertFalse(self.p['data'].exists())
        self.assertEqual(json.loads((self.p['audit'] / 'pack-result.json').read_text()), record)
        self.assertIn('remaining job time', '\n'.join(record['errors']))
        self.assertEqual(self.original.read_bytes(), b'{"actual_fixture":true}\n')

    def test_unprovable_trim_refuses_before_consuming_the_floor(self):
        allowed = transport.time_admission(1_800_000_000, 1_800_000_001)
        with patch.object(transport, 'paths', return_value=self.p), \
                patch.object(transport, 'context', return_value=self.ctx), \
                patch.object(transport, 'observe_outer', return_value={}), \
                patch.object(transport, 'current_time_admission', return_value=allowed), \
                patch.object(transport, 'closed_guest'), \
                patch.object(transport.shutil, 'disk_usage', return_value=SimpleNamespace(free=500_000_000)), \
                patch.object(transport, 'trim_guest', side_effect=ValueError('complete provenance unavailable')), \
                patch.object(artifacts, 'run_pack') as run:
            record = transport.pack(self.volume, self.project, self.root)
        run.assert_not_called()
        self.assertEqual(record['status'], 'FAIL')
        self.assertFalse(self.p['data'].exists())
        self.assertIn('provenance unavailable', '\n'.join(record['errors']))

    def test_existing_audit_state_is_never_overwritten(self):
        self.p['audit'].mkdir()
        previous = self.p['audit'] / 'pack-result.json'
        previous.write_bytes(b'previous failed attempt\n')
        with patch.object(transport, 'paths', return_value=self.p), \
                patch.object(transport, 'context', return_value=self.ctx), \
                self.assertRaisesRegex(ValueError, 'existing internal package'):
            transport.pack(self.volume, self.project, self.root)
        self.assertEqual(previous.read_bytes(), b'previous failed attempt\n')

    def test_real_tiny_codec_uses_internal_data_and_external_complete_audit(self):
        self.make_scripts()
        attempted = self.attempt()
        self.assertEqual(attempted['status'], 'PASS')
        self.save_controller(attempted)
        self.assertEqual(transport.verify_pack_audit(self.p, self.ctx)['status'], 'PASS')
        self.assertTrue(self.p['package'].is_file())
        self.assertFalse((self.p['audit'] / self.p['package'].name).exists())
        for name in ('pack-attempt.json', 'pack-stdout.txt', 'pack-stderr.txt'):
            self.assertTrue((self.p['audit'] / name).is_file())
            self.assertFalse((self.p['data'] / name).exists())
        self.assertEqual(self.original.read_bytes(), b'{"actual_fixture":true}\n')

    def test_complete_audit_rejects_stream_mutation_stale_attempt_and_external_copy(self):
        self.make_scripts()
        attempted = self.attempt()
        record = self.save_controller(attempted)
        stale = {**self.ctx, 'github_run_attempt': '1'}
        with self.assertRaises(ValueError):
            transport.verify_pack_audit(self.p, stale)
        external = self.p['audit'] / self.p['package'].name
        external.write_bytes(b'forbidden package duplicate')
        with self.assertRaisesRegex(ValueError, 'external package copy'):
            transport.verify_pack_audit(self.p, self.ctx)
        external.unlink()
        (self.p['audit'] / 'pack-stdout.txt').write_bytes(b'changed completed output')
        with self.assertRaisesRegex(ValueError, 'packaging stream changed'):
            transport.verify_pack_audit(self.p, self.ctx)
        self.assertEqual(record['bundle_sha256'], bundle.file_sha(self.p['package']))

    def test_real_timeout_keeps_all_originals_and_external_failure_streams(self):
        attempted = self.attempt(control=True, timeout=1)
        self.assertEqual(attempted['status'], 'FAIL')
        self.assertEqual(attempted['termination_reason'], 'timeout')
        self.assertTrue(attempted['child_stopped'])
        self.assertTrue(attempted['originals_unchanged'])
        self.assertTrue((self.p['audit'] / 'pack-attempt.json').is_file())
        self.assertFalse((self.p['data'] / 'pack-attempt.json').exists())
        self.assertFalse((self.p['audit'] / self.p['package'].name).exists())

    def test_changed_original_forbids_partial_deletion_and_reports_residual(self):
        popen = subprocess.Popen
        def mutate_original(*args, **kwargs):
            child = popen(*args, **kwargs)
            self.original.write_bytes(b'actual changed original\n')
            return child
        with patch.object(artifacts.subprocess, 'Popen', side_effect=mutate_original):
            attempted = self.attempt(control=True, timeout=1)
        self.assertEqual(attempted['status'], 'FAIL')
        self.assertFalse(attempted['originals_unchanged'])
        self.assertFalse(attempted['partial_removed'])
        partial = self.p['package'].with_name(self.p['package'].name + '.partial')
        self.assertTrue(partial.exists())
        self.assertGreater(attempted['residual_package_bytes'], 0)
        self.assertEqual(self.original.read_bytes(), b'actual changed original\n')

    def test_real_capture_overflow_is_preserved_and_cannot_be_pass(self):
        self.make_scripts('import sys\nsys.stdout.buffer.write(b"x" * %d)\nsys.stdout.flush()\n'
                          % (artifacts.CAPTURE_BYTES + 12345))
        attempted = self.attempt(timeout=5)
        self.assertEqual(attempted['status'], 'FAIL')
        self.assertFalse(attempted['stream_capture_complete'])
        self.assertGreater(attempted['discarded_stream_bytes'], 0)
        self.assertEqual(attempted['captured_stream_bytes'], artifacts.CAPTURE_BYTES)
        self.assertLessEqual(sum((self.p['audit'] / name).stat().st_size
                                 for name in ('pack-stdout.txt', 'pack-stderr.txt')), artifacts.CAPTURE_BYTES)

    def test_complete_child_failure_copy_requires_termination_and_keeps_original(self):
        self.p['data'].mkdir()
        self.p['audit'].mkdir()
        sidecar = self.p['package'].with_name(self.p['package'].name + '.failure.json')
        raw = b'{"status":"FAIL","error":"complete original child diagnostic"}\n'
        sidecar.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'before termination'):
            transport.copy_failure_sidecar(self.p['package'], self.p['audit'], False)
        copied = transport.copy_failure_sidecar(self.p['package'], self.p['audit'], True)
        self.assertTrue(copied['complete'])
        self.assertEqual(copied['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(Path(copied['audit_path']).read_bytes(), raw)
        self.assertEqual(sidecar.read_bytes(), raw)
        self.assertEqual(copied['bytes'], len(raw))
        with self.assertRaisesRegex(ValueError, 'already exists'):
            transport.copy_failure_sidecar(self.p['package'], self.p['audit'], True)

    def test_failure_sidecar_hardlink_is_rejected(self):
        self.p['data'].mkdir()
        self.p['audit'].mkdir()
        sidecar = self.p['package'].with_name(self.p['package'].name + '.failure.json')
        try:
            os.link(self.original, sidecar)
        except OSError as error:
            self.skipTest('actual filesystem refused bounded fixture hardlink: ' + str(error))
        with self.assertRaisesRegex(ValueError, 'unsafe or oversized'):
            transport.copy_failure_sidecar(self.p['package'], self.p['audit'], True)

    def complete_fixture(self):
        fuzz = self.project / '.cache/go-build/fuzz/FuzzQuery/case'
        fuzz.parent.mkdir(parents=True)
        fuzz.write_bytes(b'go test fuzz v1\nstring("retained")\n')
        preserved = self.project / '.local/reference-fuzz/cache/FuzzQuery/case'
        preserved.parent.mkdir(parents=True)
        shutil.copyfile(fuzz, preserved)
        manifest = {'files': [{'path': 'cache/FuzzQuery/case', 'bytes': fuzz.stat().st_size,
                               'sha256': bundle.file_sha(fuzz)}]}
        (self.project / '.local/reference-fuzz/manifest.json').write_text(json.dumps(manifest))
        curated = self.root / '.local/reference-metadata/raw.json'
        curated.parent.mkdir()
        shutil.copyfile(self.original, curated)
        (self.root / '.local/reference-metadata-manifest.json').write_text(json.dumps({'files': [
            {'member': '.local/raw.json', 'path': '.local/reference-metadata/raw.json',
             'bytes': curated.stat().st_size, 'sha256': bundle.file_sha(curated)}]}))
        self.p['data'].mkdir()
        bundle.pack(self.project, self.p['package'], self.ctx['source'], self.ctx['commit'],
                    self.ctx['github_run_id'], ['.local'], preset=6)
        bundle.verify(self.p['package'])
        with self.p['package'].open('rb') as stream:
            raw = bundle.transport_item(bundle.XZReader(stream), 'manifest.json', bundle.MAX_MANIFEST)
        return json.loads(raw), fuzz, curated

    def test_all_live_metadata_and_fuzz_comparisons_are_reused(self):
        manifest, fuzz, curated = self.complete_fixture()
        compared = transport.complete_comparisons(self.root, self.project, manifest)
        self.assertGreater(compared['live_members'], 1)
        self.assertEqual(compared['metadata_members'], 1)
        self.assertEqual(compared['fuzz_members'], 1)
        self.assertEqual(transport.complete_comparisons(self.root, self.project, manifest), compared)
        fuzz.write_bytes(b'new unpreserved actual fuzz bytes')
        with self.assertRaisesRegex(ValueError, 'fuzz preservation bytes differ'):
            transport.complete_comparisons(self.root, self.project, manifest)

    def test_complete_comparisons_reject_missing_raw_members_and_changed_metadata(self):
        manifest, fuzz, curated = self.complete_fixture()
        curated.write_bytes(b'changed curated bytes')
        with self.assertRaisesRegex(ValueError, 'curated metadata differs'):
            transport.complete_comparisons(self.root, self.project, manifest)
        shutil.copyfile(self.original, curated)
        extra = self.project / '.local/extra-failure.json'
        extra.write_bytes(b'new original failure')
        with self.assertRaisesRegex(ValueError, 'missing or duplicated'):
            transport.complete_comparisons(self.root, self.project, manifest)

    def guest_fixture(self):
        guest = self.volume / 'reference-guest'
        for name in ('packages', 'rootfs', 'commands', 'signed-indexes', 'apt/log/nested'):
            (guest / name).mkdir(parents=True, exist_ok=True)
        for name, raw in (('packages/data', b'regenerable extraction'), ('rootfs/data', b'regenerable runtime'),
                          ('commands/000.stdout', b'complete command stdout\n'),
                          ('commands/000.stderr', b'complete command stderr\n'),
                          ('signed-indexes/ubuntu-InRelease', b'signed-index fixture bytes'),
                          ('apt/log/nested/history.log', b'complete nested APT history\n'),
                          ('kernel-config.txt', b'CONFIG_KVM=y\n'), ('vmlinuz', b'kernel fixture'),
                          ('initrd.cpio.gz', b'initrd fixture'), ('apt/verified.deb', b'archive fixture')):
            (guest / name).write_bytes(raw)
        archive = guest / 'apt/verified.deb'
        setup = {'status': 'PASS', 'source': self.ctx['source'], 'run_context': transport.legacy_context(self.ctx),
                 'commands': [{'stdout': 'commands/000.stdout', 'stderr': 'commands/000.stderr',
                     'stdout_sha256': bundle.file_sha(guest / 'commands/000.stdout'),
                     'stderr_sha256': bundle.file_sha(guest / 'commands/000.stderr')}],
                 'packages': [{'archive': archive.name, 'extraction_status': 'PASS', 'bytes': archive.stat().st_size,
                     'sha256': bundle.file_sha(archive), 'signed_index': {'Size': str(archive.stat().st_size),
                                                                         'SHA256': bundle.file_sha(archive)}}],
                 'package_link_materialization': [], 'kernel_sha256': bundle.file_sha(guest / 'vmlinuz'),
                 'initrd_sha256': bundle.file_sha(guest / 'initrd.cpio.gz')}
        (guest / 'setup.json').write_text(json.dumps(setup))
        return guest

    def test_exact_guest_allowlist_preserves_complete_nested_apt_logs(self):
        guest = self.guest_fixture()
        candidates, selected = transport.guest_selections(self.volume, self.ctx)
        self.assertEqual({path.relative_to(guest).as_posix() for path in candidates},
                         {'packages', 'rootfs', 'apt/verified.deb', 'vmlinuz', 'initrd.cpio.gz'})
        self.assertNotIn(guest, candidates)
        provenance = transport.owned_manifest(self.volume, selected)
        names = {item['path'] for item in provenance['entries']}
        self.assertIn('reference-guest/apt/log/nested/history.log', names)
        outside = self.root / '.local/complete-provenance'
        transport.copy_manifest(self.volume, provenance, outside)
        transport.verify_provenance_copy(self.volume, provenance, outside)
        self.assertEqual((outside / 'apt/log/nested/history.log').read_bytes(), b'complete nested APT history\n')
        self.assertTrue((guest / 'packages/data').exists())
        (outside / 'commands/000.stderr').write_bytes(b'truncated')
        with self.assertRaisesRegex(ValueError, 'copy bytes differ'):
            transport.verify_provenance_copy(self.volume, provenance, outside)

    def test_unverified_archive_wrong_source_and_unrelated_directory_refuse_trim(self):
        guest = self.guest_fixture()
        setup_path = guest / 'setup.json'
        initial = json.loads(setup_path.read_text())
        for changed in ({**initial, 'source': 'c' * 64},
                        {**initial, 'packages': [{**initial['packages'][0], 'sha256': '0' * 64}]}):
            setup_path.write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                transport.guest_selections(self.volume, self.ctx)
        setup_path.write_text(json.dumps(initial))
        (guest / 'unrelated').mkdir()
        with self.assertRaisesRegex(ValueError, 'outside the exact payload allowlist'):
            transport.guest_selections(self.volume, self.ctx)

    def test_new_or_hardlinked_payload_cannot_pass_fresh_manifest_checks(self):
        guest = self.guest_fixture()
        candidates, selected = transport.guest_selections(self.volume, self.ctx)
        manifest = transport.owned_manifest(self.volume, candidates)
        (guest / 'packages/new-file').write_bytes(b'new after predelete plan')
        with self.assertRaises(RuntimeError):
            transport.preflight.validate_plan(self.volume, manifest)
        try:
            os.link(guest / 'rootfs/data', guest / 'rootfs/hardlink')
        except OSError as error:
            self.skipTest('actual filesystem refused bounded fixture hardlink: ' + str(error))
        with self.assertRaises((RuntimeError, ValueError)):
            transport.owned_manifest(self.volume, candidates)


if __name__ == '__main__':
    unittest.main()
