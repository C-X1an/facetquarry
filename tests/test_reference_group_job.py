"""Local refusal/custody fixtures only; no mount, ENOSPC or KVM claim."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_group_job as job

ENV = dict(GITHUB_REPOSITORY='C-X1an/facetquarry', RUNNER_OS='Linux', ImageOS='ubuntu24',
           GITHUB_ACTIONS='true', GITHUB_RUN_ID='12', GITHUB_RUN_ATTEMPT='1', GITHUB_SHA='a' * 40)
CONTEXT = job.approved_context(ENV)
SOURCE = 'b' * 64


class GroupJobTests(unittest.TestCase):
    def fixture(self, root):
        volume, closure = root / 'volume', root / 'closure'
        volume.mkdir()
        closure.mkdir()
        for path in (volume / 'group-results.tar.xz', volume / 'group-host-proof.tar'):
            path.write_bytes(b'fixture')
        report = dict(status='PASS', source=SOURCE, run_context=CONTEXT, selected='verified_bundle',
                      setup_state='COMPLETE', image_unmounted=True, release_qualification=False, custody='UNRESOLVED')
        job.results.save(volume / 'group-control.json', report, initial=True)
        job.write_proof(closure / 'group-closure.json', report, initial=True)
        value = job.candidate('verified_bundle', volume, closure, SOURCE, CONTEXT, 0)
        return volume, closure, value, report

    def verify(self, value, volume, closure, **kwargs):
        expected = dict(volume=volume, closure=closure, source=SOURCE, context=CONTEXT, controller_exit=0)
        expected.update(kwargs)
        return job.verify_candidate(value, **expected)

    def test_scope_requires_approved_attempt_one(self):
        self.assertEqual(job.approved_context(ENV)['github_run_id'], '12')
        for key, value in [('GITHUB_REPOSITORY', 'other/repo'), ('ImageOS', 'ubuntu22'),
                           ('GITHUB_ACTIONS', 'false'), ('GITHUB_SHA', 'HEAD'),
                           ('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_RUN_ATTEMPT', '100')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                job.approved_context(dict(ENV, **{key: value}))

    def test_candidate_has_exact_exclusive_digest_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            volume, closure, value, _ = self.fixture(Path(folder).resolve())
            self.assertFalse(value['release_qualification'])
            self.assertEqual(value['custody'], 'UNRESOLVED')
            self.assertEqual(len(self.verify(value, volume, closure)), 3)
            (volume / 'group-results.tar.xz').write_bytes(b'changed')
            with self.assertRaises(ValueError):
                self.verify(value, volume, closure)

    def test_wrong_source_run_attempt_exit_or_role_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            volume, closure, value, _ = self.fixture(Path(folder).resolve())
            changes = [dict(source='c' * 64), dict(controller_exit=1),
                       dict(context=dict(CONTEXT, github_run_id='13')),
                       dict(context=dict(CONTEXT, github_run_attempt='2'))]
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    self.verify(value, volume, closure, **change)
            for key, changed in [('selected', 'frozen_results_image'), ('controller_exit', 1)]:
                with self.assertRaises(ValueError):
                    self.verify(dict(value, **{key: changed}), volume, closure)
            changed = copy.deepcopy(value)
            changed['members'][0]['role'] = 'host_proof'
            with self.assertRaises(ValueError):
                self.verify(changed, volume, closure)

    def test_duplicate_or_self_consistent_wrong_paths_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            volume, closure, value, _ = self.fixture(Path(folder).resolve())
            changed = copy.deepcopy(value)
            other = volume / 'other'
            other.write_bytes(b'fixture')
            changed['members'][0] = dict(job.member(other), role='verified_bundle')
            changed['upload_paths'][0] = str(other)
            with self.assertRaises(ValueError):
                self.verify(changed, volume, closure)
            changed['upload_paths'][1] = changed['upload_paths'][0]
            with self.assertRaises(ValueError):
                self.verify(changed, volume, closure)

    def test_reused_closure_cannot_select_old_candidate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            volume, closure, value, _ = self.fixture(root)
            image = root / 'outer.img'
            image.write_bytes(b'fixture')
            job.write_proof(closure / 'candidate.json', value, initial=True)
            with self.assertRaisesRegex(ValueError, 'existing invocation'):
                job.fresh_paths(volume, image, closure)
            with self.assertRaises(ValueError):
                self.verify(value, volume, closure, context=dict(CONTEXT, github_run_id='13'))

    def test_canonical_scope_rejects_dotdot_and_link_alias(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            volume = root / 'volume'
            volume.mkdir()
            self.assertEqual(job.canonical(volume), volume)
            with self.assertRaises(ValueError):
                job.canonical(root / 'volume' / '..' / 'volume')
            alias = root / 'alias'
            try:
                alias.symlink_to(volume, target_is_directory=True)
            except OSError:
                return  # Windows may forbid link creation; dotdot case still executed.
            with self.assertRaises((ValueError, RuntimeError)):
                job.canonical(alias)

    def test_final_journal_failure_never_exposes_candidate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            volume, closure = root / 'volume', root / 'closure'
            volume.mkdir()
            closure.mkdir()
            with patch.object(job.results, 'save', side_effect=OSError('full')):
                with self.assertRaises(OSError):
                    job.publish_candidate(volume, closure, {})
            self.assertFalse((closure / 'candidate.json').exists())
            self.assertFalse((closure / 'group-closure.json').exists())

    def test_incomplete_setup_phases_never_authorize_scientific_export(self):
        with tempfile.TemporaryDirectory() as folder:
            volume, closure, value, report = self.fixture(Path(folder).resolve())
            for phase in ('relocation', 'allocation', 'mounting', 'bootstrap_copy'):
                failed = dict(report, setup_state='INCOMPLETE_LOCAL_ONLY', setup_failure_phase=phase)
                job.results.save(volume / 'group-control.json', failed)
                job.results.save(closure / 'group-closure.json', failed)
                changed = dict(value, final_journal=job.member(volume / 'group-control.json'))
                changed['members'] = copy.deepcopy(value['members'])
                changed['members'][2] = dict(job.member(closure / 'group-closure.json'), role='closure')
                changed['admission'] = job.capacity.transport_limit({r['role']: r['bytes'] for r in changed['members']})
                with self.subTest(phase=phase), self.assertRaises(ValueError):
                    self.verify(changed, volume, closure)

    def test_deadline_reserves_closure_and_refuses_work_after_expiry(self):
        now = [100.0]
        budget = job.Budget(1800, clock=lambda: now[0])
        self.assertEqual(budget.remaining(600), 1200)
        now[0] = 1300.1
        with self.assertRaises(ValueError):
            budget.remaining(600)
        self.assertGreater(budget.remaining(), 0)
        now[0] = 1901
        with self.assertRaises(ValueError):
            budget.remaining()

    def test_deadline_interrupts_slow_python_stage_and_restores_handler(self):
        handlers = []
        with patch.object(job.signal, 'SIGALRM', 14, create=True), \
             patch.object(job.signal, 'ITIMER_REAL', 0, create=True), \
             patch.object(job.signal, 'getitimer', return_value=(0.0, 0.0), create=True), \
             patch.object(job.signal, 'setitimer', create=True), \
             patch.object(job.signal, 'signal', side_effect=lambda sig, fn: handlers.append(fn)):
            budget = job.Budget(1800)
            with self.assertRaises(TimeoutError):
                with budget.stage(600):
                    handlers[0](14, None)
            self.assertEqual(len(handlers), 2)

    def test_bounded_bootstrap_hands_off_alarm_and_restores_remaining_interval(self):
        now = [10.0]
        timer = [1000.0, 0.0]
        def set_timer(which, seconds):
            timer[0] = seconds
        def execute(command, **kwargs):
            self.assertEqual(timer[0], 0)
            self.assertEqual(kwargs['total_seconds'], 160)
            now[0] += 20
            return {'fixture': True}
        with patch.object(job.signal, 'SIGALRM', 14, create=True), \
             patch.object(job.signal, 'ITIMER_REAL', 0, create=True), \
             patch.object(job.signal, 'getitimer', side_effect=lambda which: tuple(timer), create=True), \
             patch.object(job.signal, 'getsignal', return_value=None), \
             patch.object(job.signal, 'setitimer', side_effect=set_timer, create=True), \
             patch.object(job.signal, 'signal'), patch.object(job, 'bootstrap_command', side_effect=execute):
            budget = job.Budget(1800, clock=lambda: now[0])
            self.assertEqual(job.bounded_command(budget, ['fixture'], total_seconds=160), {'fixture': True})
            self.assertEqual(timer[0], 980)

    def test_usable_control_space_reserves_failure_record_before_writes(self):
        with patch.object(job, 'available_bytes', return_value=512 * 1024):
            job.record_capacity(Path('fixture'), 128 * 1024)
            with self.assertRaises(ValueError):
                job.record_capacity(Path('fixture'), 512 * 1024)

    def test_original_results_contract_is_not_mutated(self):
        import reference_results
        old = (reference_results.IMAGE_BYTES, reference_results.owned_paths)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            adapter = job.results_adapter(root, root / 'outer.img')
            self.assertEqual(adapter.IMAGE_BYTES, 64 * (1 << 20))
            self.assertEqual(adapter.PROBE_BYTES, 65 * (1 << 20))
            self.assertEqual((reference_results.IMAGE_BYTES, reference_results.owned_paths), old)

    def test_lossless_bundle_readback_covers_complete_live_results(self):
        import evidence_bundle
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            project = root / 'source'
            local = project / '.local'
            (local / 'empty').mkdir(parents=True)
            (local / 'result.json').write_bytes(b'{"fixture": true}\n')
            bundle = root / 'results.tar.xz'
            evidence_bundle.pack(project, bundle, SOURCE, CONTEXT['commit'], '12', ['.local'],
                                 preset=1, output_limit_bytes=1024 * 1024)
            self.assertEqual(job.verify_bundle(bundle, project, CONTEXT, SOURCE)['status'], 'PASS')
            with self.assertRaises(ValueError):
                job.verify_bundle(bundle, project, dict(CONTEXT, github_run_id='13'), SOURCE)
            (local / 'late.txt').write_bytes(b'not archived')
            with self.assertRaises(ValueError):
                job.verify_bundle(bundle, project, CONTEXT, SOURCE)


if __name__ == '__main__':
    unittest.main()
