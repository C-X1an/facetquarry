"""Process observation and actual Bash slot-refusal regression controls."""
import contextlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_capacity as capacity

PID = 111111

def process_stat(start=900, state='S'):
    fields = [state, '1'] + ['0'] * 17 + [str(start)]
    return str(PID) + ' (capacity fixture) ' + ' '.join(fields)


def admitted_capacity_sudo_control(environ=None, platform=None):
    environ = os.environ if environ is None else environ
    platform = sys.platform if platform is None else platform
    expected = {'FQ_RESERVATION_PROFILE': capacity.PROFILE, 'GITHUB_JOB': 'reference_capacity',
                'GITHUB_REPOSITORY': capacity.REPOSITORY,
                'GITHUB_REPOSITORY_ID': str(capacity.REPOSITORY_ID), 'GITHUB_ACTIONS': 'true'}
    return platform == 'linux' and all(environ.get(key) == value for key, value in expected.items())


class PositiveCwdObservation(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self, raw=b'/unrelated\0', identities=None, uid=1001):
        with contextlib.ExitStack() as stack:
            scan = stack.enter_context(mock.patch.object(capacity.os, 'scandir'))
            scan.return_value.__enter__.return_value = [SimpleNamespace(name=str(PID))]
            stack.enter_context(mock.patch.object(capacity.os, 'getuid', create=True, return_value=1001))
            stack.enter_context(mock.patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=uid)))
            stack.enter_context(mock.patch.object(Path, 'read_text', side_effect=identities or [process_stat(), process_stat()]))
            link = stack.enter_context(mock.patch.object(capacity.os, 'readlink', side_effect=PermissionError('actual denial fixture')))
            elevated = stack.enter_context(mock.patch.object(capacity, 'privileged_cwd_bytes', create=True, return_value=raw))
            yield link, elevated

    def test_same_uid_denial_requires_and_uses_positive_elevated_observation(self):
        with self.fixture() as (_, elevated):
            self.assertEqual(capacity.active_volume_processes(Path('/capacity-volume')), [])
            elevated.assert_called_once_with(PID)

    def test_positive_observation_still_finds_a_writer_inside_the_volume(self):
        with self.fixture(raw=b'/capacity-volume/source\0'):
            found = capacity.active_volume_processes(Path('/capacity-volume'))
        self.assertEqual([x['pid'] for x in found], [PID])

    def test_success_retains_original_denial_and_identity_bound_proof(self):
        observations = []
        with self.fixture():
            self.assertEqual(capacity.active_volume_processes(Path('/capacity-volume'), observations), [])
        self.assertEqual(len(observations), 1)
        proof = observations[0]
        self.assertIn('actual denial fixture', proof['original_denial'])
        self.assertEqual(proof['before']['start_time_ticks'], proof['after']['start_time_ticks'])
        self.assertEqual(proof['method'], 'existing_sudo_fixed_readlink')
        self.assertEqual(proof['uid'], 1001)
        self.assertEqual(len(proof['cwd_sha256']), 64)

    def test_changed_uid_and_unknown_uid_refuse_without_elevated_assumptions(self):
        with self.fixture() as (_, elevated), mock.patch.object(Path, 'stat', side_effect=PermissionError('UID unavailable')):
            with self.assertRaises(ValueError): capacity.active_volume_processes(Path('/capacity-volume'))
            elevated.assert_not_called()
        with self.fixture(), mock.patch.object(Path, 'stat', side_effect=[
                SimpleNamespace(st_uid=1001), SimpleNamespace(st_uid=1001), SimpleNamespace(st_uid=1002)]):
            with self.assertRaises(ValueError): capacity.active_volume_processes(Path('/capacity-volume'))

    def test_positive_zombie_and_exited_process_proofs_do_not_need_cwd(self):
        observations = []
        with self.fixture(identities=[process_stat(state='Z'), process_stat(state='Z')]) as (link, elevated):
            self.assertEqual(capacity.active_volume_processes(Path('/capacity-volume'), observations), [])
            link.assert_not_called(); elevated.assert_not_called()
        self.assertIn('positively nonwriting', observations[0]['proof'])
        observations = []
        with self.fixture() as (link, elevated), mock.patch.object(Path, 'stat', side_effect=[
                SimpleNamespace(st_uid=1001), SimpleNamespace(st_uid=1001), FileNotFoundError(), FileNotFoundError()]):
            link.side_effect = FileNotFoundError('cwd unavailable')
            self.assertEqual(capacity.active_volume_processes(Path('/capacity-volume'), observations), [])
            elevated.assert_not_called()
        self.assertIn('positively absent', observations[0]['proof'])

    def test_fixed_elevated_argv_never_accepts_a_noninteger_pid(self):
        for pid in (True, '123', '1; id', -1, 0, 2_147_483_648):
            with self.subTest(pid=pid), self.assertRaises(ValueError): capacity.privileged_cwd_argv(pid)
        self.assertEqual(capacity.privileged_cwd_argv(PID), [
            '/usr/bin/sudo','-n','--','/usr/bin/timeout','--signal=TERM','--kill-after=1s','2s',
            '/usr/bin/readlink','--zero','--','/proc/111111/cwd'])

    def test_changed_start_time_cannot_be_labeled_closed(self):
        with self.fixture(identities=[process_stat(), process_stat(901)]):
            with self.assertRaises(ValueError): capacity.active_volume_processes(Path('/capacity-volume'))

    def test_other_uid_never_gets_an_elevated_observation(self):
        with self.fixture(uid=1002) as (link, elevated):
            self.assertEqual(capacity.active_volume_processes(Path('/capacity-volume')), [])
            link.assert_not_called(); elevated.assert_not_called()

    def test_denied_or_timed_out_elevated_observation_remains_failure(self):
        for error in (PermissionError('sudo refused'), subprocess.TimeoutExpired('fixed readlink', 2)):
            with self.subTest(error=type(error).__name__), self.fixture() as (_, elevated):
                elevated.side_effect = error
                with self.assertRaises((ValueError, PermissionError, subprocess.SubprocessError)):
                    capacity.active_volume_processes(Path('/capacity-volume'))

    def test_relative_deleted_multivalue_and_unterminated_outputs_refuse(self):
        for raw in (b'relative\0', b'/gone (deleted)\0', b'/one\0/two\0', b'/unterminated', b'\0'):
            with self.subTest(raw=raw), self.fixture(raw=raw):
                with self.assertRaises(ValueError): capacity.active_volume_processes(Path('/capacity-volume'))

    def test_live_missing_cwd_is_never_treated_as_a_foreign_process(self):
        with self.fixture() as (link, elevated):
            link.side_effect = FileNotFoundError('cwd missing but process still observed')
            with self.assertRaises(ValueError): capacity.active_volume_processes(Path('/capacity-volume'))
            elevated.assert_not_called()


class BashSlotRefusal(unittest.TestCase):
    def test_actual_bash_refuses_each_existing_slot_and_accepts_fresh_slots(self):
        bash = shutil.which('bash')
        if not bash and os.name == 'nt':
            candidate = Path('C:/Program Files/Git/bin/bash.exe')
            if candidate.is_file(): bash = str(candidate)
        if not bash: self.skipTest('Bash unavailable; actual Linux control remains required')
        root = Path(__file__).resolve().parents[1]
        body = (root / '.github/workflows/release-evidence.yml').read_text().split('\n  reference_capacity:\n', 1)[1]
        guards = '\n'.join(line.strip() for line in body.splitlines()
            if line.strip().startswith(('test ! -e "$fq_image"', 'test ! -L "$fq_image"')))
        self.assertTrue(guards)
        with tempfile.TemporaryDirectory(dir=root / '.cache/tmp') as folder:
            base = Path(folder)
            for occupied in ('image-file', 'image-dir', 'volume-file', 'volume-dir', 'fresh'):
                with self.subTest(occupied=occupied):
                    case = base / occupied; case.mkdir()
                    if occupied != 'fresh':
                        slot = case / ('image.img' if occupied.startswith('image') else 'volume')
                        if occupied.endswith('file'): slot.write_bytes(b'original bytes')
                        else: slot.mkdir()
                    command = 'set -euo pipefail\nfq_image="$PWD/image.img"\nfq_volume="$PWD/volume"\n' + guards + '\nprintf admitted > admitted.txt\n'
                    result = subprocess.run([bash, '--noprofile', '--norc', '-c', command], cwd=case,
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode == 0, occupied == 'fresh', result.stdout + result.stderr)
                    self.assertEqual((case / 'admitted.txt').exists(), occupied == 'fresh')


class ElevatedCwdLifecycle(unittest.TestCase):
    def test_actual_sudo_gate_selects_only_the_admitted_job_environment(self):
        expected = {'FQ_RESERVATION_PROFILE': capacity.PROFILE, 'GITHUB_JOB': 'reference_capacity',
                    'GITHUB_REPOSITORY': capacity.REPOSITORY,
                    'GITHUB_REPOSITORY_ID': str(capacity.REPOSITORY_ID), 'GITHUB_ACTIONS': 'true'}
        self.assertTrue(admitted_capacity_sudo_control(expected, 'linux'))
        self.assertFalse(admitted_capacity_sudo_control({}, 'linux'))
        self.assertFalse(admitted_capacity_sudo_control(expected, 'win32'))
        for key in expected:
            with self.subTest(key=key):
                changed = dict(expected); changed[key] = 'different'
                self.assertFalse(admitted_capacity_sudo_control(changed, 'linux'))
        text = (Path(__file__).resolve().parents[1] / '.github/workflows/release-evidence.yml').read_text()
        actual = text.split('\n  reference_capacity:\n', 1)[1]
        self.assertIn('FQ_RESERVATION_PROFILE: ' + capacity.PROFILE, actual)

    def test_selector_acquisition_failure_stops_waits_and_closes_child_pipe(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        with mock.patch.object(capacity.sys, 'platform', 'linux'), \
             mock.patch.object(capacity.subprocess, 'Popen', return_value=proc), \
             mock.patch.object(capacity.selectors, 'DefaultSelector', side_effect=OSError('descriptor exhaustion fixture')):
            with self.assertRaises(OSError): capacity.privileged_cwd_bytes(PID)
        proc.terminate.assert_called_once()
        proc.wait.assert_called_once()
        proc.stdout.close.assert_called_once()

    def test_cleanup_failure_still_closes_child_stdout(self):
        proc, selector = mock.Mock(), mock.Mock()
        proc.poll.return_value = None
        proc.terminate.side_effect = PermissionError('cleanup denial fixture')
        selector.register.side_effect = ValueError('registration failure fixture')
        with mock.patch.object(capacity.sys, 'platform', 'linux'), \
             mock.patch.object(capacity.subprocess, 'Popen', return_value=proc), \
             mock.patch.object(capacity.selectors, 'DefaultSelector', return_value=selector):
            with self.assertRaises(PermissionError): capacity.privileged_cwd_bytes(PID)
        selector.close.assert_called_once()
        proc.stdout.close.assert_called_once()

    @unittest.skipUnless(sys.platform == 'linux', 'actual bounded pipe/deadline controls run on supported Linux')
    def test_actual_child_pipe_output_bound_deadline_and_reaping(self):
        actual_popen = subprocess.Popen
        cases = [('valid', "import os; os.write(1,b'/fixture\\x00')"),
                 ('oversized', "import os; os.write(1,b'x'*9000)"),
                 ('deadline', 'import time; time.sleep(30)')]
        for name, code in cases:
            children = []
            def fixture_child(argv, **kwargs):
                self.assertEqual(argv, capacity.privileged_cwd_argv(PID))
                child = actual_popen([sys.executable, '-c', code], **kwargs)
                children.append(child)
                return child
            with self.subTest(case=name), mock.patch.object(capacity.subprocess, 'Popen', side_effect=fixture_child):
                if name == 'valid': self.assertEqual(capacity.privileged_cwd_bytes(PID), b'/fixture\0')
                else:
                    with self.assertRaises(ValueError): capacity.privileged_cwd_bytes(PID)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll())
            self.assertTrue(children[0].stdout.closed)

    @unittest.skipUnless(admitted_capacity_sudo_control(),
        'actual fixed sudo readlink uses only the admitted capacity runner grant')
    def test_existing_capacity_runner_grant_executes_the_fixed_readlink(self):
        self.assertEqual(capacity.privileged_cwd_bytes(os.getpid()), os.fsencode(os.getcwd()) + b'\0')


if __name__ == '__main__': unittest.main()
