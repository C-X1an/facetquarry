"""Real small transport controls for opt-in, bounded pack observations."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import evidence_bundle as p


class PackProgressControls(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[1] / '.cache' / 'evidence-bundle-progress-tests'
        cache.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=cache)
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.root = self.folder / 'originals'
        self.selected = self.root / 'private-looking-results'
        (self.selected / 'empty').mkdir(parents=True)
        payload = b'PAYLOAD_MUST_NOT_APPEAR_IN_PROGRESS\n' * 20
        header = b'\x1f\x8b\x08\x08' + struct.pack('<I', 123) + b'\x02\x03OPAQUE_HEADER.gz\x00'
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        gzip_bytes = (header + compressor.compress(payload) + compressor.flush()
                      + struct.pack('<II', zlib.crc32(payload), len(payload)))
        self.originals = {'measurement.json': b'{"synthetic":true}\n',
                          'opaque.gz': gzip_bytes, 'identity.gz': b'not a gzip payload'}
        for name, data in self.originals.items():
            (self.selected / name).write_bytes(data)
        self.output = self.folder / 'bundle.tar.xz'

    def pack(self, output=None, **kwargs):
        return p.pack(self.root, output or self.output, 'a' * 64, 'b' * 40,
                      'synthetic-progress', [self.selected.name], preset=3, **kwargs)

    def cli(self, *args):
        return subprocess.run([sys.executable, str(Path(p.__file__)), *map(str, args)],
                              text=True, capture_output=True, timeout=30)

    def cli_pack(self, output, progress=False):
        args = ['pack', self.root, output, '--source', 'a' * 64, '--commit', 'b' * 40,
                '--run-id', 'synthetic-progress', '--preset', '3', '--paths', self.selected.name]
        if progress:
            args.append('--progress')
        return self.cli(*args)

    def assert_originals(self):
        self.assertEqual({path.name for path in self.selected.iterdir()}, set(self.originals) | {'empty'})
        for name, data in self.originals.items():
            self.assertEqual((self.selected / name).read_bytes(), data)
        self.assertEqual(list((self.selected / 'empty').iterdir()), [])

    def assert_events(self, events, member_count, duration):
        phases = ['inventory', 'manifest_encoding', 'archive_encoding_xz',
                  'input_recheck', 'internal_verification', 'promotion']
        self.assertTrue(events)
        self.assertLessEqual(len(events), 230)
        encoded_events = [json.dumps(event, sort_keys=True, separators=(',', ':')).encode() + b'\n'
                          for event in events]
        self.assertTrue(all(len(line) <= 2048 for line in encoded_events))
        self.assertLess(sum(map(len, encoded_events)), 1_000_000)
        serialized = b''.join(encoded_events)
        for private_value in (self.selected.name.encode(), b'measurement.json', b'opaque.gz',
                              b'PAYLOAD_MUST_NOT_APPEAR_IN_PROGRESS', b'OPAQUE_HEADER',
                              str(self.root).encode()):
            self.assertNotIn(private_value, serialized)
        self.assertEqual(list(dict.fromkeys(event['phase'] for event in events)), phases)
        previous_total = 0
        for event in events:
            self.assertEqual(set(event), {'schema', 'source', 'commit', 'run_id', 'phase', 'event',
                                          'completed_members', 'member_count', 'phase_seconds', 'total_seconds'})
            self.assertEqual(event['schema'], 'facetquarry.pack-progress.v1')
            self.assertEqual((event['source'], event['commit'], event['run_id']),
                             ('a' * 64, 'b' * 40, 'synthetic-progress'))
            self.assertIn(event['event'], ('start', 'progress', 'end'))
            self.assertGreaterEqual(event['total_seconds'], previous_total)
            self.assertLessEqual(event['total_seconds'], duration)
            self.assertGreaterEqual(event['phase_seconds'], 0)
            self.assertLessEqual(event['phase_seconds'], event['total_seconds'])
            self.assertGreaterEqual(event['completed_members'], 0)
            self.assertLessEqual(event['completed_members'], member_count)
            self.assertIn(event['member_count'], (None, member_count))
            previous_total = event['total_seconds']
        for phase in phases[:-1]:
            observed = [event for event in events if event['phase'] == phase]
            self.assertEqual(observed[0]['event'], 'start')
            self.assertEqual(observed[0]['completed_members'], 0)
            self.assertEqual(observed[-1]['event'], 'end')
            self.assertEqual(observed[-1]['completed_members'], member_count)
            self.assertEqual(observed[-1]['member_count'], member_count)
            self.assertEqual([event['completed_members'] for event in observed],
                             sorted(event['completed_members'] for event in observed))
            self.assertEqual([event['phase_seconds'] for event in observed],
                             sorted(event['phase_seconds'] for event in observed))
        # The last callback precedes publication. Actual completion is the existing
        # pack result, so observers cannot fail after a published success.
        self.assertEqual(events[-1]['phase'], 'promotion')
        self.assertEqual(events[-1]['event'], 'start')
        self.assertFalse(any(event['phase'] == 'complete' for event in events))

    def test_mixed_real_roundtrip_reports_checked_members_and_actual_phase_times(self):
        events = []
        begin = time.monotonic()
        with mock.patch.object(p, 'decoded', wraps=p.decoded) as decode:
            result = self.pack(progress=events.append)
        duration = time.monotonic() - begin
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['gzip_recipe_members'], 1)
        self.assertEqual(decode.call_count, result['member_count'])
        self.assert_events(events, result['member_count'], duration)
        recovery = self.folder / 'recovered'
        self.assertEqual(p.verify(self.output, recovery)['status'], 'PASS')
        for name, data in self.originals.items():
            self.assertEqual((recovery / self.selected.name / name).read_bytes(), data)
        self.assertTrue((recovery / self.selected.name / 'empty').is_dir())
        self.assert_originals()

    def test_actual_thousand_member_checkpoints_are_bounded_and_verification_is_separate(self):
        for index in range(1000):
            (self.selected / f'tiny-{index:04d}').write_bytes(b'')
        events = []
        begin = time.monotonic()
        result = self.pack(progress=events.append)
        self.assert_events(events, result['member_count'], time.monotonic() - begin)
        checkpoints = [event for event in events if event['event'] == 'progress']
        self.assertEqual({event['phase'] for event in checkpoints},
                         {'inventory', 'manifest_encoding', 'archive_encoding_xz', 'internal_verification'})
        for event in checkpoints:
            self.assertEqual(event['completed_members'], 1000)
        verified = next(event for event in checkpoints if event['phase'] == 'internal_verification')
        archive_end = next(event for event in events
                           if event['phase'] == 'archive_encoding_xz' and event['event'] == 'end')
        self.assertGreaterEqual(verified['total_seconds'], archive_end['total_seconds'])
        self.assertEqual(p.verify(self.output)['member_count'], result['member_count'])

    def test_default_pack_api_and_cli_remain_quiet_with_one_json_result(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(self.pack()['status'], 'PASS')
        self.assertEqual((stdout.getvalue(), stderr.getvalue()), ('', ''))
        cli_output = self.folder / 'cli.tar.xz'
        command = self.cli_pack(cli_output)
        self.assertEqual(command.returncode, 0, command.stderr)
        self.assertEqual(len(command.stdout.splitlines()), 1)
        self.assertEqual(json.loads(command.stdout)['status'], 'PASS')
        self.assertEqual(command.stderr, '')
        for args in (('verify', cli_output), ('recover', cli_output, self.folder / 'cli-recovered')):
            verified = self.cli(*args)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(len(verified.stdout.splitlines()), 1)
            self.assertEqual(json.loads(verified.stdout)['status'], 'PASS')
            self.assertEqual(verified.stderr, '')
        self.assert_originals()

    def test_cli_progress_is_jsonl_on_stderr_only(self):
        begin = time.monotonic()
        command = self.cli_pack(self.output, progress=True)
        self.assertEqual(command.returncode, 0, command.stderr)
        self.assertEqual(len(command.stdout.splitlines()), 1)
        result = json.loads(command.stdout)
        self.assertEqual(result['status'], 'PASS')
        events = [json.loads(line) for line in command.stderr.splitlines()]
        self.assert_events(events, result['member_count'], time.monotonic() - begin)
        self.assert_originals()

    def test_observer_mutation_before_second_encoding_still_fails_original_check(self):
        def mutate(event):
            if event['phase'] == 'manifest_encoding' and event['event'] == 'end':
                (self.selected / 'measurement.json').write_bytes(b'changed by callback')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.pack(progress=mutate)
        self.assertFalse(self.output.exists())

    def test_late_observer_mutations_fail_before_the_only_promotion(self):
        for phase, event_type in (('internal_verification', 'end'), ('promotion', 'start')):
            with self.subTest(phase=phase):
                output = self.folder / f'mutated-{phase}.tar.xz'
                def mutate(event):
                    if (event['phase'], event['event']) == (phase, event_type):
                        (self.selected / 'measurement.json').write_bytes(b'late changed input')
                with mock.patch.object(p.os, 'link', wraps=p.os.link) as link:
                    with self.assertRaisesRegex(ValueError, 'changed'):
                        self.pack(output=output, progress=mutate)
                    link.assert_not_called()
                self.assertFalse(output.exists())
                self.assertTrue(output.with_name(output.name + '.partial').exists())
                for name, data in self.originals.items():
                    (self.selected / name).write_bytes(data)

    def test_observer_failure_never_returns_pass_or_publishes(self):
        for phase, event_type in (('inventory', 'start'), ('archive_encoding_xz', 'start'),
                                  ('internal_verification', 'end'), ('promotion', 'start')):
            with self.subTest(phase=phase):
                output = self.folder / f'failed-{phase}.tar.xz'
                def fail(event):
                    if (event['phase'], event['event']) == (phase, event_type):
                        raise RuntimeError('observer unavailable')
                with mock.patch.object(p.os, 'link', wraps=p.os.link) as link:
                    with self.assertRaisesRegex(RuntimeError, 'observer unavailable'):
                        self.pack(output=output, progress=fail)
                    link.assert_not_called()
                self.assertFalse(output.exists())
                diagnostic = json.loads(output.with_name(output.name + '.failure.json').read_text())
                self.assertEqual(diagnostic['status'], 'FAIL')
                self.assertFalse(diagnostic['originals_deleted'])
                self.assert_originals()

    def test_cli_capture_failure_is_not_a_success(self):
        class BrokenStderr(io.StringIO):
            def write(self, text):
                raise OSError('progress capture failed')
        args = ['evidence_bundle.py', 'pack', str(self.root), str(self.output),
                '--source', 'a' * 64, '--commit', 'b' * 40, '--run-id', 'synthetic-progress',
                '--paths', self.selected.name, '--progress']
        stdout = io.StringIO()
        with mock.patch.object(sys, 'argv', args), redirect_stdout(stdout), redirect_stderr(BrokenStderr()):
            with self.assertRaisesRegex(OSError, 'progress capture failed'):
                p.main()
        self.assertEqual(stdout.getvalue(), '')
        self.assertFalse(self.output.exists())
        self.assert_originals()


if __name__ == '__main__':
    unittest.main(verbosity=2)
