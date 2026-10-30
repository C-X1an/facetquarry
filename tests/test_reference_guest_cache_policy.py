"""Finite command-boundary controls; actual APT behavior requires Linux evidence."""
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_guest as guest


class BinaryCacheProducerControls(unittest.TestCase):
    def test_policy_indexes_and_signed_metadata_queries_share_explicit_cache_options(self):
        with tempfile.TemporaryDirectory() as folder:
            setup = SimpleNamespace(base=Path(folder), manifest={}, save=lambda: None,
                args=SimpleNamespace(setup_max_bytes=1_000_000_000), check=lambda *a: None)
            calls = []
            def run(command, **options):
                calls.append(command)
                if command[:2] == ['dpkg-deb', '-f']:
                    return 'Package: fixture\nVersion: 1\nArchitecture: amd64\nInstalled-Size: 1\n'
                if command[0] == 'apt-cache' and 'show' in command:
                    raise RuntimeError('finite fixture stops at signed metadata command')
                return ''
            setup.run = run
            def run_apt(setup, command, request, phase, **options):
                if phase == 'plan':
                    return "'https://archive.ubuntu.com/ubuntu/pool/a.deb' a.deb 1 SHA256:abc\n"
                (setup.base / 'apt/a.deb').write_bytes(b'x')
                return ''
            with patch.object(guest, 'ordinary_account', return_value={'name': 'runner', 'uid': 1001, 'gid': 1001}), \
                    patch.object(guest, 'apt_request', return_value={}), \
                    patch.object(guest, 'run_apt', side_effect=run_apt), \
                    patch.object(guest, 'retain_signed_indexes'):
                with self.assertRaisesRegex(RuntimeError, 'finite fixture stops'):
                    guest.packages(setup)
            selected = [command for command in calls if command[0] in ('apt-cache', 'apt-get')]
            self.assertEqual(len(selected), 3)
            self.assertTrue(any('policy' in command for command in selected))
            self.assertTrue(any('indextargets' in command for command in selected))
            self.assertTrue(any('show' in command for command in selected))
            for command in selected:
                with self.subTest(command=command):
                    options = [command[i+1] for i, arg in enumerate(command[:-1]) if arg == '-o']
                    self.assertEqual([x for x in options if x.startswith('Dir::Cache::pkgcache=')],
                                     ['Dir::Cache::pkgcache='])
                    self.assertEqual([x for x in options if x.startswith('Dir::Cache::srcpkgcache=')],
                                     ['Dir::Cache::srcpkgcache='])

    def test_plan_and_download_disable_both_binary_caches_without_dropping_diagnostics(self):
        with tempfile.TemporaryDirectory() as folder:
            setup = SimpleNamespace(base=Path(folder), manifest={}, save=lambda: None,
                args=SimpleNamespace(setup_max_bytes=1_000_000_000), check=lambda *a: None,
                run=lambda *a, **kw: '')
            calls = []
            def run_apt(setup, command, request, phase, **options):
                calls.append((phase, command))
                if phase == 'plan':
                    return "'https://archive.ubuntu.com/ubuntu/pool/a.deb' a.deb 1 SHA256:abc\n"
                raise RuntimeError('finite fixture stops at download boundary')
            account = {'name': 'runner', 'uid': 1001, 'gid': 1001}
            with patch.object(guest, 'ordinary_account', return_value=account), \
                    patch.object(guest, 'apt_request', return_value={}), \
                    patch.object(guest, 'run_apt', side_effect=run_apt), \
                    patch.object(guest, 'retain_signed_indexes'):
                with self.assertRaisesRegex(RuntimeError, 'finite fixture'):
                    guest.packages(setup)
            self.assertEqual([phase for phase, _ in calls], ['plan', 'download'])
            for phase, command in calls:
                with self.subTest(phase=phase):
                    options = [command[i+1] for i, arg in enumerate(command[:-1]) if arg == '-o']
                    self.assertEqual([x for x in options if x.startswith('Dir::Cache::pkgcache=')],
                                     ['Dir::Cache::pkgcache='])
                    self.assertEqual([x for x in options if x.startswith('Dir::Cache::srcpkgcache=')],
                                     ['Dir::Cache::srcpkgcache='])
                    self.assertIn('Dir::Cache::archives=' + str(setup.base / 'apt'), options)
                    self.assertIn('Dir::State::extended_states=' + str(setup.base / 'apt/extended_states'), options)
                    self.assertIn('Dir::Log=' + str(setup.base / 'apt/log'), options)
                    self.assertIn('APT::Sandbox::User=runner', options)


if __name__ == '__main__':
    unittest.main()
