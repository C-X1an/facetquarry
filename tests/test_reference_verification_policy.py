"""Bounded time arithmetic and real small checkpoint-file controls.

These fixtures do not establish Linux quota, full bundle verification speed,
benchmark completion or release qualification.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import reference_internal_transport as transport
import reference_result_capacity as capacity
import reference_transport_policy as policy
import reference_transport_supervisor as supervisor
import reference_verification_progress as progress


class VerificationTimePolicyTests(unittest.TestCase):
    def test_explicit_policy_reserves_all_390_additional_seconds_at_each_boundary(self):
        start = 1_800_000_000
        legacy = capacity.time_plan(start, start)
        named = capacity.time_plan(start, start, time_policy=policy.VERIFY_600)
        self.assertEqual(legacy['required_remaining_seconds'], 19840)
        self.assertEqual(named['required_remaining_seconds'], 20230)
        self.assertEqual(named['verify_seconds'], 600)
        for key in ('measurement_command_seconds', 'pack_seconds', 'freeze_seconds',
                    'complete_failure_tail_seconds', 'analysis_and_qualification_seconds'):
            self.assertEqual(legacy[key], named[key])
        boundary = start + transport.JOB_SECONDS - named['required_remaining_seconds']
        self.assertEqual(capacity.time_plan(start, boundary, time_policy=policy.VERIFY_600)['admission'], 'REFUSE')
        self.assertEqual(capacity.time_plan(start, boundary - .01, time_policy=policy.VERIFY_600)['admission'], 'ALLOW')
        for phase in ('pack', 'verify'):
            total = (1710 if phase == 'pack' else 0) + 600 + 1200
            cutoff = start + transport.JOB_SECONDS - total
            denied = transport.time_admission(start, cutoff, phase, time_policy=policy.VERIFY_600)
            allowed = transport.time_admission(start, cutoff - .01, phase, time_policy=policy.VERIFY_600)
            self.assertFalse(denied['allowed'])
            self.assertTrue(allowed['allowed'])
            self.assertEqual(denied['required_remaining_seconds'], total)
        reconciled = transport.time_admission(start, start, 'reconcile', time_policy=policy.VERIFY_600)
        self.assertEqual(reconciled['phase_seconds'], 180)
        self.assertEqual(reconciled['required_remaining_seconds'], 1200)
        self.assertEqual(policy.phase_seconds('verify', policy.VERIFY_600)
                         - supervisor.CLEANUP_SECONDS - supervisor.RECEIPT_SECONDS, 558)

    def test_ambient_policy_cannot_change_default_or_legacy_arithmetic(self):
        start = 1_800_000_000
        baseline = (capacity.time_plan(start, start), transport.time_admission(start, start))
        for value in (policy.VERIFY_600, 'auto', 'unknown', ''):
            with self.subTest(value=value), patch.dict(os.environ, {'FQ_TRANSPORT_TIME_POLICY': value}):
                self.assertEqual((capacity.time_plan(start, start), transport.time_admission(start, start)), baseline)
                self.assertEqual(policy.phase_seconds('verify'), 210)
                self.assertEqual(supervisor.PHASE_SECONDS['verify'], 210)

    def test_unknown_or_mismatched_receipt_policy_is_refused(self):
        for value in ('auto', '600', '', None, True, 600):
            with self.subTest(value=value), self.assertRaises(ValueError):
                capacity.time_plan(1_800_000_000, 1_800_000_000, time_policy=value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.receipt_policy({'time_policy': value})
        self.assertEqual(policy.receipt_policy({}), policy.LEGACY)
        self.assertEqual(policy.receipt_policy({'time_policy': policy.VERIFY_600}), policy.VERIFY_600)
        with self.assertRaises(ValueError):
            policy.receipt_policy({'time_policy': policy.VERIFY_600}, policy.LEGACY)
        with self.assertRaises(ValueError):
            policy.receipt_policy({}, policy.VERIFY_600)

    def test_workflow_explicitly_propagates_policy_without_extending_native_measurement(self):
        workflow = (SCRIPTS.parent / '.github/workflows/release-evidence.yml').read_text()
        self.assertIn("'reference-verify-600s-v1' || 'legacy'", workflow)
        self.assertIn("time_policy=os.environ['FQ_TRANSPORT_TIME_POLICY']", workflow)
        for action in ('pack', 'verify', 'reconcile'):
            self.assertIn('scripts/reference_internal_transport.py ' + action
                          + ' --volume "$FQ_VOLUME" --project "$FQ_VOLUME/source"'
                          + ' --time-policy "$FQ_TRANSPORT_TIME_POLICY"', workflow)
        self.assertIn("&& 40 || 18", workflow)
        self.assertIn('--timeout 15840 --progress-file', workflow)
        self.assertIn('--timeout 15120 --setup-max-bytes 800000000', workflow)

    def test_terminal_receipt_cannot_claim_named_policy_with_legacy_budget(self):
        # Small synthetic receipt fixture; actual process supervision is a
        # separate Linux-only gate and is not inferred from these files.
        cache = SCRIPTS.parent / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='time-receipt-', dir=cache) as folder:
            root = Path(folder).absolute()
            paths = {name: root / name for name in ('volume', 'project', 'outer', 'audit', 'package')}
            paths['audit'].mkdir()
            context = {'source': 'a' * 64, 'commit': 'b' * 40,
                       'github_run_id': '123', 'github_run_attempt': '1'}
            captures = {}
            for label in ('stdout', 'stderr'):
                stream = paths['audit'] / ('verify-supervisor-' + label + '.txt')
                stream.write_bytes(b'')
                captures[label] = {'path': str(stream), 'sha256': transport.file_sha(stream, 100), 'bytes': 0}
            record = {'kind': supervisor.KIND, 'profile': transport.PROFILE, 'phase': 'verify',
                      'state': 'COMPLETE', 'status': 'FAIL', 'run_context': context,
                      'source': context['source'], 'commit': context['commit'],
                      'run_id': '123', 'run_attempt': '1', 'terminal_receipt': True,
                      'whole_phase_within_budget': True, 'duration_seconds': 250,
                      'total_budget_seconds': 600, 'time_policy': policy.VERIFY_600,
                      'descendant_quiescence': {'quiescent': True, 'residual': []},
                      'capture': captures, 'captured_output_bytes': 0}
            for name in paths:
                record[name + '_path'] = str(paths[name])
            proof = supervisor.receipt_path(paths, 'verify')
            transport.write_small(proof, record)
            value = supervisor.validate_receipt(paths, context, 'verify', require_pass=False,
                                               bind_payload=False, time_policy=policy.VERIFY_600)
            self.assertEqual(value['total_budget_seconds'], 600)
            for changes in ({'total_budget_seconds': 210}, {'time_policy': policy.LEGACY},
                            {'time_policy': 'auto'}, {'duration_seconds': 600}):
                transport.write_small(proof, {**record, **changes}, replace=True)
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    supervisor.validate_receipt(paths, context, 'verify', require_pass=False,
                                                bind_payload=False, time_policy=policy.VERIFY_600)


class DurableVerificationStageTests(unittest.TestCase):
    def setUp(self):
        cache = SCRIPTS.parent / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='verification-stage-', dir=cache)
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.proof = self.folder / 'verification.json'
        self.record = {'status': 'PREPARING', 'complete_comparisons': False}
        transport.write_small(self.proof, self.record)
        self.checkpoints = progress.Progress(self.proof, self.record, transport.write_small, transport.results.utc)

    def read(self):
        return json.loads(self.proof.read_bytes())

    def test_all_ordered_stages_have_on_disk_start_before_operations_and_end_after(self):
        for index, name in enumerate(progress.STAGES):
            with self.checkpoints.stage(name):
                observed = self.read()
                self.assertEqual(observed['active_verification_stage'], name)
                self.assertEqual(observed['verification_stages'][-1]['state'], 'RUNNING')
                self.assertEqual(len(observed['verification_stages']), index + 1)
                self.assertFalse(progress.complete(observed))
            observed = self.read()
            self.assertIsNone(observed['active_verification_stage'])
            self.assertEqual(observed['verification_stages'][-1]['state'], 'COMPLETE')
        self.assertTrue(progress.complete(observed))
        for name in progress.STAGES:
            mutated = copy.deepcopy(observed)
            mutated['verification_stages'] = [row for row in mutated['verification_stages'] if row['stage'] != name]
            self.assertFalse(progress.complete(mutated))
        self.assertFalse(observed['complete_comparisons'])  # Observation cannot mint a verification PASS.
        self.assertEqual(observed['status'], 'PREPARING')
        with self.assertRaises(ValueError):
            with self.checkpoints.stage(progress.STAGES[-1]):
                self.fail('duplicate stage executed')

    def test_caught_failure_retains_active_stage_and_refuses_skipping(self):
        with self.assertRaises(ValueError):
            with self.checkpoints.stage('bundle_decode'):
                self.fail('out-of-order operation executed')
        with self.assertRaisesRegex(InterruptedError, 'fixture'):
            with self.checkpoints.stage('admission'):
                raise InterruptedError('fixture')
        observed = self.read()
        self.assertEqual(observed['active_verification_stage'], 'admission')
        self.assertEqual(observed['verification_stages'][-1]['state'], 'FAIL')
        self.assertFalse(progress.complete(observed))
        self.assertFalse(observed['complete_comparisons'])
        with self.assertRaises(ValueError):
            with self.checkpoints.stage('admission'):
                self.fail('failed checkpoint restarted within the same proof')

    def test_actual_abrupt_child_exit_leaves_durable_start_and_no_false_completion(self):
        proof = self.folder / 'abrupt.json'
        code = ('import os,sys\nfrom pathlib import Path\n'
                'sys.path.insert(0,sys.argv[1])\n'
                'import reference_internal_transport as t\n'
                'from reference_verification_progress import Progress\n'
                'p=Path(sys.argv[2]);r={"status":"PREPARING","complete_comparisons":False}\n'
                't.write_small(p,r)\n'
                'v=Progress(p,r,t.write_small,t.results.utc)\n'
                'with v.stage("admission"):\n os._exit(23)\n')
        done = subprocess.run([sys.executable, '-B', '-c', code, str(SCRIPTS), str(proof)],
                              timeout=10, capture_output=True)
        self.assertEqual(done.returncode, 23, done.stderr)
        observed = json.loads(proof.read_bytes())
        self.assertEqual(observed['active_verification_stage'], 'admission')
        self.assertEqual(observed['verification_stages'][-1]['state'], 'RUNNING')
        self.assertFalse(progress.complete(observed))
        self.assertEqual(observed['status'], 'PREPARING')


if __name__ == '__main__':
    unittest.main()
