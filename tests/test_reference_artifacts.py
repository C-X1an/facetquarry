"""Actual bounded failure controls, never scientific or VM qualification."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_artifacts as a
import evidence_bundle as b


class ReferenceArtifacts(unittest.TestCase):
    @contextmanager
    def pack_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).absolute() / 'source'; (root / '.local').mkdir(parents=True)
            original = root / '.local/completed-failure.txt'; original.write_bytes(b'actual original failed data\n')
            output = root.parent / 'outside/reference-members.tar.xz'; output.parent.mkdir()
            yield root, output, original

    def run_control(self, root, output):
        return a.run_pack(root, output, '1'*64, 'a'*40, 'control', 1, control=True)

    def packet_bytes(self, output, record, original_path):
        entry = next(item for item in record['files'] if item['path'] == original_path)
        data = (output / entry['export_path']).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), entry['export_sha256'])
        return data

    def assert_receipt(self, output, result):
        saved = json.loads((output.parent / 'pack-attempt.json').read_text())
        self.assertEqual(saved, result)
        self.assertEqual(saved['phase'], 'COMPLETE')
        self.assertFalse(saved['complete_raw_preserved'])

    def test_all_branches_and_exact_refusal_boundary(self):
        plan = a.growth_plan(7_623_223_381, 2_300_000_000)
        self.assertEqual(plan['admission'], 'ALLOW')
        self.assertEqual(plan['branches']['failed_pack_exact_results_image_upload'],
                         2_300_000_000 + a.PACKAGE_ALLOCATION + a.IMAGE_ZIP
                         + a.EXTERNAL_METADATA_ALLOCATION + a.PACKET_ALLOCATION + 45_000_000 + 50_000_000)
        self.assertEqual(plan['peak_bytes'], 11_770_223_381)
        size = plan['maximum_new_stage_bytes']
        self.assertEqual(a.growth_plan(a.CEILING - size, 2_300_000_000)['admission'], 'REFUSE')
        self.assertEqual(a.growth_plan(a.CEILING - size - 1, 2_300_000_000)['admission'], 'ALLOW')
        self.assertIn('never both', plan['required_upload_policy'])
        with self.assertRaises(ValueError): a.growth_plan(1, 2_300_000_000)

    def test_profiles_require_fresh_retained_artifact_admission(self):
        # A retained 450MB bundle artifact and 45MB packet are attributable
        # even when neither is downloaded. No later run inherits ALLOW.
        base = 7_623_223_381
        self.assertEqual(a.growth_plan(base, 2_300_000_000)['admission'], 'ALLOW')
        self.assertEqual(a.growth_plan(base + 495_000_000, 2_300_000_000)['admission'], 'REFUSE')

    def test_preserved_actual_old_failure_numbers(self):
        old = 7_623_223_381 + 3_300_000_000 + 369_776_442 + 50_000_000 + 371_345_786 + 867_638_413
        self.assertEqual(old, 12_581_984_022)
        self.assertGreater(old, a.CEILING)
        # Arithmetic does not manufacture recovery of unavailable old raw data.

    def test_real_timeout_preserves_originals_and_failed_command(self):
        with self.pack_fixture() as (root, output, original):
            before = a.original_state(root)
            record = self.run_control(root, output)
            self.assertEqual(record['status'], 'FAIL')
            self.assertEqual(record['termination_reason'], 'timeout')
            self.assertTrue(record['originals_unchanged']); self.assertTrue(record['child_stopped'])
            self.assertTrue(record['partial_removed'])
            self.assertEqual(record['residual_package_bytes'], 0)
            self.assertFalse(output.exists()); self.assertFalse(Path(str(output) + '.partial').exists())
            self.assertEqual(a.original_state(root), before)
            self.assert_receipt(output, record)
            self.assertTrue((output.parent / 'partial-removal.json').is_file())

    def test_popen_oserror_still_has_complete_failure_receipt(self):
        with self.pack_fixture() as (root, output, original):
            with patch.object(a.subprocess, 'Popen', side_effect=OSError('fixture launch denied')):
                record = self.run_control(root, output)
            self.assertEqual(record['status'], 'FAIL')
            self.assertIsNone(record['exit_code'])
            self.assertTrue(record['originals_unchanged'])
            self.assertIn('fixture launch denied', '\n'.join(record['errors']))
            self.assert_receipt(output, record)

    def test_initial_inventory_failure_is_recorded_before_launch(self):
        with self.pack_fixture() as (root, output, original):
            with patch.object(a, 'original_state', side_effect=ValueError('fixture oversized original')):
                record = self.run_control(root, output)
            self.assertFalse(record['originals_unchanged']); self.assertEqual(record['status'], 'FAIL')
            self.assertIn('fixture oversized original', '\n'.join(record['errors']))
            self.assert_receipt(output, record)

    def test_postpack_inventory_failure_retains_partial_and_exposes_bytes(self):
        with self.pack_fixture() as (root, output, original):
            before = a.original_state(root)
            with patch.object(a, 'original_state', side_effect=[before, ValueError('fixture changed layout')]):
                record = self.run_control(root, output)
            self.assertFalse(record['partial_removed']); self.assertFalse(record['originals_unchanged'])
            partial = Path(str(output) + '.partial')
            self.assertTrue(partial.is_file()); self.assertGreater(record['residual_package_bytes'], 0)
            self.assertEqual(original.read_bytes(), b'actual original failed data\n')
            self.assert_receipt(output, record)

    def test_cleanup_refusal_retains_partial_and_full_failure_receipt(self):
        with self.pack_fixture() as (root, output, original):
            with patch.object(a, 'discard_partial', side_effect=PermissionError('fixture cleanup refused')):
                record = self.run_control(root, output)
            self.assertTrue(record['originals_unchanged']); self.assertFalse(record['partial_removed'])
            self.assertGreater(record['residual_package_bytes'], 0)
            self.assertIn('fixture cleanup refused', '\n'.join(record['errors']))
            self.assert_receipt(output, record)

    def test_actual_original_mutation_forbids_partial_cleanup(self):
        with self.pack_fixture() as (root, output, original):
            launch = subprocess.Popen
            def competing_writer(*args, **kwargs):
                child = launch(*args, **kwargs)
                original.write_bytes(b'changed actual original bytes\n')
                return child
            with patch.object(a.subprocess, 'Popen', side_effect=competing_writer):
                record = self.run_control(root, output)
            self.assertFalse(record['originals_unchanged']); self.assertFalse(record['partial_removed'])
            self.assertEqual(original.read_bytes(), b'changed actual original bytes\n')
            self.assertGreater(record['residual_package_bytes'], 0)
            self.assert_receipt(output, record)

    def test_process_exit_during_signal_is_not_lost(self):
        with self.pack_fixture() as (root, output, original):
            real_popen = subprocess.Popen
            if os.name == 'posix':
                real_killpg = os.killpg
                def racing_kill(pid, sig):
                    real_killpg(pid, sig)
                    raise ProcessLookupError('fixture exited as signal was sent')
                context = patch.object(a.os, 'killpg', side_effect=racing_kill)
            else:
                def launch(*args, **kwargs):
                    child = real_popen(*args, **kwargs)
                    real_terminate = child.terminate
                    def racing_terminate():
                        real_terminate()
                        raise ProcessLookupError('fixture exited as signal was sent')
                    child.terminate = racing_terminate
                    return child
                context = patch.object(a.subprocess, 'Popen', side_effect=launch)
            with context: record = self.run_control(root, output)
            self.assertEqual(record['status'], 'FAIL'); self.assertTrue(record['child_stopped'])
            self.assert_receipt(output, record)

    def test_real_output_capture_is_hard_bounded_and_declares_discard(self):
        with self.pack_fixture() as (root, output, original):
            (root / 'scripts').mkdir()
            (root / 'scripts/evidence_bundle.py').write_text(
                'import sys\nsys.stdout.buffer.write(b"x" * %d)\nsys.stdout.flush()\n' % (a.CAPTURE_BYTES + 12345))
            record = a.run_pack(root, output, '1'*64, 'a'*40, 'noisy-fixture', 5)
            self.assertEqual(record['status'], 'FAIL')
            self.assertEqual(record['captured_stream_bytes'], a.CAPTURE_BYTES)
            self.assertGreater(record['discarded_stream_bytes'], 0)
            self.assertFalse(record['stream_capture_complete'])
            self.assertLessEqual(sum((output.parent / name).stat().st_size for name in ('pack-stdout.txt', 'pack-stderr.txt')), a.CAPTURE_BYTES)
            self.assert_receipt(output, record)

    def test_real_successful_pack_is_still_only_packaging_evidence(self):
        with self.pack_fixture() as (root, output, original):
            (root / 'scripts').mkdir()
            shutil.copyfile(Path(b.__file__), root / 'scripts/evidence_bundle.py')
            record = a.run_pack(root, output, '1'*64, 'a'*40, 'real-codec-fixture', 20)
            self.assertEqual(record['status'], 'PASS')
            self.assertTrue(record['originals_unchanged']); self.assertGreater(record['residual_package_bytes'], 0)
            recovered = root.parent / 'recovered'; b.verify(output, recovered)
            self.assertEqual((recovered / '.local/completed-failure.txt').read_bytes(), original.read_bytes())
            self.assert_receipt(output, record)

    @unittest.skipUnless(os.name == 'posix', 'actual wrapper SIGTERM delivery is Linux/POSIX-only; Windows termination is not SIGTERM')
    def test_real_wrapper_sigterm_stops_owned_child_and_saves_receipt(self):
        with self.pack_fixture() as (root, output, original):
            code = ('import sys;sys.path.insert(0,sys.argv[1]);from pathlib import Path;import reference_artifacts as a;'
                    'r=a.run_pack(Path(sys.argv[2]),Path(sys.argv[3]),"1"*64,"a"*40,"signal-fixture",20,control=True);'
                    'raise SystemExit(1 if r["status"]=="FAIL" else 0)')
            child = subprocess.Popen([sys.executable, '-B', '-c', code, str(Path(a.__file__).parent), str(root), str(output)])
            self.addCleanup(lambda: child.kill() if child.poll() is None else None)
            partial = Path(str(output) + '.partial'); deadline = time.monotonic() + 5
            while not partial.exists() and child.poll() is None and time.monotonic() < deadline: time.sleep(.02)
            self.assertTrue(partial.exists())
            child.send_signal(signal.SIGTERM); self.assertEqual(child.wait(timeout=15), 1)
            record = json.loads((output.parent / 'pack-attempt.json').read_text())
            self.assertEqual(record['termination_reason'], 'signal ' + str(signal.SIGTERM))
            self.assertTrue(record['child_stopped']); self.assertTrue(record['partial_removed'])

    def test_metadata_survives_refusal_and_declares_bounded_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            local = Path(temporary) / '.local'; (local / 'reference-metadata').mkdir(parents=True)
            refusal = b'{"status":"FAIL","admission":"REFUSE"}'
            (local / 'reference-upload-admission.json').write_bytes(refusal)
            large = local / 'reference-metadata/large.log'; large.write_bytes(b'x' * (a.CAPTURE_BYTES + 1))
            out = Path(temporary) / 'metadata'; result = a.metadata_packet(local, out)
            self.assertEqual(result['status'], 'PASS'); self.assertFalse(result['complete_scientific_preservation'])
            self.assertEqual(self.packet_bytes(out, result, 'reference-upload-admission.json'), refusal)
            record = next(x for x in result['files'] if x['path'].endswith('large.log'))
            self.assertEqual(record['export_bytes'], a.CAPTURE_BYTES)
            self.assertEqual(record['original_sha256'], hashlib.sha256(large.read_bytes()).hexdigest())
            self.assertIn('availability is not established', record['transformation'])

    def test_critical_pack_receipts_precede_bulk_and_remain_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            local = Path(temporary) / '.local'; (local / 'reference-metadata').mkdir(parents=True)
            (local / 'reference-transport').mkdir()
            critical = b'{"status":"FAIL","termination_reason":"timeout"}\n'
            (local / 'reference-transport/pack-attempt.json').write_bytes(critical)
            (local / 'reference-metadata/bulk.log').write_bytes(b'b' * 5000)
            with patch.object(a, 'METADATA_BYTES', 4096), patch.object(a, 'MANIFEST_BYTES', 2048):
                out = Path(temporary) / 'metadata'; result = a.metadata_packet(local, out)
            self.assertEqual(self.packet_bytes(out, result, 'reference-transport/pack-attempt.json'), critical)
            self.assertEqual(result['files'][0]['transformation'], 'identity')
            self.assertLessEqual(sum(path.stat().st_size for path in out.rglob('*') if path.is_file()), 4096)

    def test_oversized_path_manifest_stops_with_bounded_honest_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            local = Path(temporary) / '.local'; bulk = local / 'reference-metadata'; bulk.mkdir(parents=True)
            for index in range(30): (bulk / ('%02d-' % index + 'long-path-' * 9)).write_bytes(b'x')
            out = Path(temporary) / 'metadata'
            with patch.object(a, 'MANIFEST_BYTES', 4096): result = a.metadata_packet(local, out)
            self.assertFalse(result['enumeration_complete']); self.assertTrue(result['reductions'])
            self.assertLess(len(result['files']), 30)
            self.assertLessEqual((out / 'packet-manifest.json').stat().st_size, 4096)
            self.assertEqual(json.loads((out / 'packet-manifest.json').read_text()), result)
            self.assertTrue(all(len(entry['export_path']) < 32 for entry in result['files']))

    def test_selected_root_symlink_or_reparse_is_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); local = root / '.local'; local.mkdir()
            secret = root / 'outside'; secret.mkdir(); (secret / 'secret.txt').write_bytes(b'never export')
            selected = local / 'reference-metadata'
            try: selected.symlink_to(secret, target_is_directory=True)
            except OSError:
                # Exercise the same ancestor predicate on Windows without
                # claiming an actual privileged junction/symlink was created.
                selected.mkdir(); (selected / 'secret.txt').write_bytes(b'never export')
                real_stat = Path.lstat
                def reparse(path, *args, **kwargs):
                    info = real_stat(path, *args, **kwargs)
                    if path == selected:
                        values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                        values['st_file_attributes'] = 0x400
                        return type('ReparseStat', (), values)()
                    return info
                with patch.object(Path, 'lstat', reparse): result = a.metadata_packet(local, root / 'metadata')
            else: result = a.metadata_packet(local, root / 'metadata')
            self.assertEqual(result['status'], 'FAIL'); self.assertFalse(result['files'])
            self.assertTrue((root / 'metadata/packet-manifest.json').is_file())
            self.assertEqual((secret / 'secret.txt').read_bytes(), b'never export')

    def test_output_overlap_and_existing_output_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); local = root / '.local'; local.mkdir()
            for output in (local / 'packet', root, local):
                with self.subTest(output=output), self.assertRaises(ValueError): a.metadata_packet(local, output)
            existing = root / 'packet'; existing.mkdir(); marker = existing / 'keep'; marker.write_bytes(b'keep')
            with self.assertRaises(ValueError): a.metadata_packet(local, existing)
            self.assertEqual(marker.read_bytes(), b'keep')

    def test_linked_output_ancestor_is_refused_before_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); local = root / '.local'; local.mkdir()
            real = root / 'destination'; real.mkdir(); linked = root / 'linked'
            try: linked.symlink_to(real, target_is_directory=True)
            except OSError:
                linked.mkdir()
                real_stat = Path.lstat
                def reparse(path, *args, **kwargs):
                    info = real_stat(path, *args, **kwargs)
                    if path == linked:
                        values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                        values['st_file_attributes'] = 0x400
                        return type('ReparseStat', (), values)()
                    return info
                with patch.object(Path, 'lstat', reparse), self.assertRaises(ValueError):
                    a.metadata_packet(local, linked / 'packet')
            else:
                with self.assertRaises(ValueError): a.metadata_packet(local, linked / 'packet')
            self.assertFalse((linked / 'packet').exists()); self.assertFalse((real / 'packet').exists())

    def test_metadata_works_before_setup_and_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            local = Path(temporary) / '.local'; local.mkdir()
            (local / 'reference-job-state.json').write_text('{"image_exists":false}')
            result = a.metadata_packet(local, Path(temporary) / 'metadata')
            self.assertEqual(len(result['files']), 1)

    def test_compression_choices_recover_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'source'; (root / '.local').mkdir(parents=True)
            data = b'bounded repeated record\n' * 1000; (root / '.local/failure.txt').write_bytes(data)
            for preset in (1, 3, 6):
                archive = Path(temporary) / ('preset%d.xz' % preset)
                self.assertEqual(b.pack(root, archive, '1'*64, 'a'*40, 'fixture', ['.local'], preset)['status'], 'PASS')
                recovered = Path(temporary) / ('recovered%d' % preset); b.verify(archive, recovered)
                self.assertEqual((recovered / '.local/failure.txt').read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
