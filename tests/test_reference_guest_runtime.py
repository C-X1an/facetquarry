"""Owned-file/probe contract controls; not a Go execution or VM substitute."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_guest as guest


class ProbeRecorder:
    def __init__(self, volume):
        self.args = SimpleNamespace(volume=volume, project=volume / 'source')
        self.args.project.mkdir()
        (self.args.project / '.go-version').write_text('1.27.3\n', encoding='ascii')
        self.goroot = volume / 'tools/go'
        (self.goroot / 'bin').mkdir(parents=True)
        self.go = self.goroot / 'bin/go'
        self.go.write_bytes(b'bounded stand-in; never executed by these controls')
        self.go.chmod(0o700)
        (self.goroot / 'VERSION').write_text('go1.27.3\ntime 2026-10-01T00:00:00Z\n', encoding='ascii')
        (self.goroot / 'go.env').write_text('GOTOOLCHAIN=auto\n', encoding='ascii')
        self.manifest = {}
        self.calls = []
        self.saved = False
        self.reported_root = str(self.goroot)
        self.reported_version = 'go version go1.27.3 linux/amd64'
        self.after_probe = lambda: None

    def run(self, command, *, env):
        self.calls.append((command, dict(env)))
        if command[1:] == ['env', 'GOROOT']:
            return self.reported_root + '\n'
        if command[1:] == ['version']:
            self.after_probe()
            return self.reported_version + '\n'
        raise AssertionError('unexpected probe')

    def save(self):
        self.saved = True


class OwnedGoRuntimeControls(unittest.TestCase):
    def test_explicit_owned_runtime_overrides_hostile_environment_and_path(self):
        with tempfile.TemporaryDirectory() as folder:
            setup = ProbeRecorder(Path(folder))
            with mock.patch.dict(os.environ, {'GOROOT': '/outside/sdk', 'GOTOOLCHAIN': 'auto',
                                             'GOTELEMETRY': 'on', 'GOENV': '/outside/env',
                                             'PATH': '/outside/decoy'}), \
                    mock.patch.object(guest.shutil, 'which', side_effect=AssertionError('PATH consulted')):
                root, files, identities = guest.pinned_go_runtime(setup)
            self.assertEqual(root, setup.goroot)
            self.assertEqual(len(files), 3)
            self.assertEqual(len(setup.calls), 2)
            self.assertTrue(setup.saved)
            for command, env in setup.calls:
                self.assertEqual(command[0], str(setup.go))
                self.assertEqual(env['GOROOT'], str(setup.goroot))
                self.assertEqual(env['GOTOOLCHAIN'], 'local')
                self.assertEqual(env['GOTELEMETRY'], 'off')
                self.assertEqual(env['GOENV'], 'off')
            # Detect real byte substitution after the recorded probes.
            (setup.goroot / 'go.env').write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                guest.verify_go_runtime(identities, setup.args.volume)

    def test_wrong_owned_subdirectory_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            setup = ProbeRecorder(Path(folder))
            setup.reported_root = str(setup.args.volume / 'another-sdk')
            with self.assertRaisesRegex(RuntimeError, 'exact owned SDK'):
                guest.pinned_go_runtime(setup)
            self.assertEqual(len(setup.calls), 1)
            self.assertFalse(setup.saved)

    def test_nearby_or_wrong_platform_executable_version_is_rejected(self):
        for version in ('go version go1.27.30 linux/amd64',
                        'go version go1.27.3 windows/amd64'):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as folder:
                setup = ProbeRecorder(Path(folder))
                setup.reported_version = version
                with self.assertRaisesRegex(RuntimeError, 'pinned Linux x86_64'):
                    guest.pinned_go_runtime(setup)
                self.assertFalse(setup.saved)

    def test_bad_version_metadata_is_rejected_before_execution(self):
        for version in ('go1.27.30\n', '', 'x' * 4097):
            with self.subTest(version=version[:20]), tempfile.TemporaryDirectory() as folder:
                setup = ProbeRecorder(Path(folder))
                (setup.goroot / 'VERSION').write_text(version, encoding='ascii')
                with self.assertRaises(RuntimeError):
                    guest.pinned_go_runtime(setup)
                self.assertEqual(setup.calls, [])

    def test_nonregular_and_hardlinked_go_are_rejected_before_execution(self):
        for kind in ('directory', 'hardlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                setup = ProbeRecorder(Path(folder))
                if kind == 'directory':
                    setup.go.unlink()
                    setup.go.mkdir()
                else:
                    os.link(setup.go, setup.args.volume / 'second-name')
                with self.assertRaises(RuntimeError):
                    guest.pinned_go_runtime(setup)
                self.assertEqual(setup.calls, [])

    def test_symlinked_executable_and_sdk_are_rejected_before_execution(self):
        for kind in ('executable', 'directory'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as folder:
                setup = ProbeRecorder(Path(folder))
                target = setup.go if kind == 'executable' else setup.goroot
                renamed = target.with_name(target.name + '-original')
                target.rename(renamed)
                try:
                    target.symlink_to(renamed, target_is_directory=kind == 'directory')
                except OSError as error:
                    if os.name == 'nt' and getattr(error, 'winerror', None) == 1314:
                        self.skipTest('actual Windows symlink privilege unavailable (1314)')
                    raise
                with self.assertRaises(RuntimeError):
                    guest.pinned_go_runtime(setup)
                self.assertEqual(setup.calls, [])

    def test_probe_time_runtime_substitution_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            setup = ProbeRecorder(Path(folder))
            setup.after_probe = lambda: setup.go.write_bytes(b'substituted during probe')
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                guest.pinned_go_runtime(setup)
            self.assertFalse(setup.saved)

    @unittest.skipUnless(hasattr(os, 'getuid'), 'owner uid control requires POSIX stat semantics')
    def test_foreign_owned_go_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            setup = ProbeRecorder(Path(folder))
            checked = guest.checked_runtime

            def foreign_owner(path, volume=None):
                info = checked(path, volume)
                if path == setup.go:
                    return SimpleNamespace(st_mode=info.st_mode, st_nlink=1, st_uid=os.getuid() + 1)
                return info

            with mock.patch.object(guest, 'checked_runtime', side_effect=foreign_owner):
                with self.assertRaisesRegex(RuntimeError, 'owned regular files'):
                    guest.pinned_go_runtime(setup)
            self.assertEqual(setup.calls, [])


if __name__ == '__main__':
    unittest.main()
