"""Finite APT producer controls; real descriptor/chown checks require Linux."""
import importlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_guest as guest


def helper():
    return importlib.import_module('reference_apt_ownership')


def account(name='runner', uid=1001, gid=1001):
    return SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=gid)


class AptOwnershipControls(unittest.TestCase):
    def ordinary(self, **changes):
        options = dict(uid=1001, gid=1001, euid=1001, egid=1001,
                       lookup_uid=lambda uid: account(), lookup_name=lambda name: account())
        options.update(changes)
        return helper().ordinary_account(**options)

    def test_numeric_uid_is_replaced_by_verified_account_name(self):
        self.assertEqual(self.ordinary(), {'name': 'runner', 'uid': 1001, 'gid': 1001})

    def test_root_or_effective_identity_mismatch_refused(self):
        for options in ({'uid': 0}, {'gid': 0}, {'euid': 0}, {'egid': 0}, {'gid': 1002}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.ordinary(**options)

    def test_account_roundtrip_mismatch_refused(self):
        for record in (account(uid=1002), account(gid=1002), account(name='other')):
            with self.subTest(record=record), self.assertRaises(ValueError):
                self.ordinary(lookup_name=lambda name: record)

    def test_unsafe_account_name_refused(self):
        for name in ('1001', '-root', 'root:runner', 'bad\nname', ''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.ordinary(lookup_uid=lambda uid: account(name=name))

    def policy(self):
        return helper().archive_policy([{'filename': 'busybox_1%3a1_amd64.deb', 'size': 1234}])

    def test_exact_archive_and_partial_paths_are_admitted(self):
        policy = self.policy()
        for name in ('busybox_1%3a1_amd64.deb', 'partial/busybox_1%3a1_amd64.deb'):
            self.assertEqual(helper().path_rule(name, policy), ('file', 1234))
        self.assertEqual(helper().path_rule('log/history.log', policy)[0], 'file')
        self.assertEqual(helper().path_rule('lock', policy)[0], 'file')

    def test_unknown_paths_and_unsafe_plan_names_refused(self):
        for name in ('unknown.deb', 'log/nested', 'partial/other.deb', '../lock', 'log/terminal.log.1'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                helper().path_rule(name, self.policy())
        for name in ('../bad.deb', '/bad.deb', 'bad\\name.deb', '-bad.deb', 'bad\n.deb', 'lock'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                helper().archive_policy([{'filename': name, 'size': 1}])

    def test_admission_rejects_duplicate_oversize_and_unbounded_plans(self):
        for plan in ([{'filename': 'a.deb', 'size': 1}] * 2,
                     [{'filename': 'a.deb', 'size': 200_000_001}],
                     [{'filename': 'a.deb', 'size': True}],
                     [{'filename': f'a{i}.deb', 'size': 1} for i in range(129)]):
            with self.subTest(plan=plan[:2]), self.assertRaises(ValueError):
                helper().archive_policy(plan)

    def test_root_metadata_is_normalizable_but_foreign_owner_is_not(self):
        node = dict(device=17, inode=31, mode=stat.S_IFREG | 0o644, uid=0, gid=0,
                    nlink=1, bytes=100, allocated=4096, mtime_ns=1, ctime_ns=1)
        self.assertTrue(helper().validate_node('lock', node, {}, 17, 1001, 1001))
        for changes in ({'uid': 1002}, {'gid': 1002}, {'nlink': 2}, {'device': 18},
                        {'mode': stat.S_IFLNK | 0o777}, {'mode': stat.S_IFIFO | 0o600},
                        {'mode': stat.S_IFREG | 0o666}, {'bytes': 256_000_001}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                helper().validate_node('lock', {**node, **changes}, {}, 17, 1001, 1001)

    def test_archive_cannot_exceed_exact_admitted_size(self):
        node = dict(device=17, inode=31, mode=stat.S_IFREG | 0o644, uid=0, gid=0,
                    nlink=1, bytes=1235, allocated=4096, mtime_ns=1, ctime_ns=1)
        with self.assertRaises(ValueError):
            helper().validate_node('busybox_1%3a1_amd64.deb', node, self.policy(), 17, 1001, 1001)

    def test_changed_descriptor_refused_before_any_chown(self):
        before = {'device': 17, 'inode': 31}
        with patch.object(helper().os, 'fstat'), \
             patch.object(helper(), 'facts', return_value={**before, 'inode': 32}), \
             patch.object(helper().os, 'fchown', create=True) as chown:
            with self.assertRaisesRegex(ValueError, 'changed before'):
                helper().chown_descriptor(7, before, 1001, 1001)
            chown.assert_not_called()

    def test_audit_preinventory_exception_cannot_run_arbitrary_root_command(self):
        setup = SimpleNamespace(deadline=guest.time.monotonic() + 120)
        with self.assertRaisesRegex(ValueError, 'only the bounded APT'):
            guest.Setup.run(setup, ['sudo', '-n', 'true'], _apt_ownership_audit=True)

    def fake_setup(self):
        result = SimpleNamespace(manifest={}, records=[], saves=0)
        def save(): result.saves += 1
        result.save = save
        return result

    def test_post_call_observation_preserves_original_apt_failure(self):
        setup = self.fake_setup()
        original = RuntimeError('original APT failure')
        setup.run = lambda *a, **kw: (_ for _ in ()).throw(original)
        with patch.object(guest, 'audit_apt', side_effect=ValueError('ownership refused')):
            with self.assertRaises(RuntimeError) as caught:
                guest.run_apt(setup, ['apt-get'], {}, 'download')
        self.assertIs(caught.exception, original)
        record = setup.manifest['apt_ownership'][-1]
        self.assertIn('original APT failure', record['command_error'])
        self.assertIn('ownership refused', record['audit_error'])
        self.assertGreater(setup.saves, 0)

    def test_successful_apt_cannot_hide_failed_ownership_audit(self):
        setup = self.fake_setup()
        setup.run = lambda *a, **kw: 'APT output'
        with patch.object(guest, 'audit_apt', side_effect=ValueError('ownership refused')):
            with self.assertRaisesRegex(ValueError, 'ownership refused'):
                guest.run_apt(setup, ['apt-get'], {}, 'plan')

    def test_helper_proof_is_retained_before_full_budget_recheck(self):
        setup = self.fake_setup()
        checked = []
        setup.records = [{'exit_code': 0, 'termination_reason': None}]
        setup.check = lambda: checked.append('full inventory')
        def run(command, **options):
            self.assertTrue(options['_apt_ownership_audit'])
            self.assertEqual(checked, [])
            return json.dumps({'status': 'PASS', 'before': [{'path': 'lock', 'uid': 0}]})
        setup.run = run
        observation = {}
        guest.audit_apt(setup, {}, observation)
        self.assertEqual(checked, ['full inventory'])
        self.assertEqual(observation['inventory']['before'][0]['uid'], 0)

    def test_refused_helper_retains_observed_foreign_inode_facts(self):
        setup = self.fake_setup()
        setup.records = [{'exit_code': 1, 'termination_reason': None}]
        setup.run = lambda *a, **kw: json.dumps({'status': 'FAIL', 'before': [{'path': 'lock', 'uid': 1002}]})
        observation = {}
        with self.assertRaisesRegex(ValueError, 'ownership helper refused'):
            guest.audit_apt(setup, {}, observation)
        self.assertEqual(observation['inventory']['before'][0]['uid'], 1002)

    def test_both_privileged_commands_share_named_sandbox_and_audit(self):
        with tempfile.TemporaryDirectory() as folder:
            setup = SimpleNamespace(base=Path(folder), manifest={}, save=lambda: None,
                                    args=SimpleNamespace(setup_max_bytes=1_000_000_000))
            commands = []
            def run_apt(setup, command, request, phase, **options):
                commands.append((command, phase))
                if phase == 'plan':
                    return "'https://archive.ubuntu.com/ubuntu/pool/a.deb' a.deb 1 SHA256:abc\n"
                raise RuntimeError('stop after second audited command')
            setup.check = lambda *args: None
            setup.run = lambda *args, **kwargs: ''
            with patch.object(guest, 'ordinary_account', return_value=self.ordinary()), \
                 patch.object(guest, 'apt_request', return_value={}), \
                 patch.object(guest, 'run_apt', side_effect=run_apt), \
                 patch.object(guest, 'retain_signed_indexes'):
                with self.assertRaisesRegex(RuntimeError, 'stop after second'):
                    guest.packages(setup)
            self.assertEqual([phase for _, phase in commands], ['plan', 'download'])
            for command, _ in commands:
                self.assertEqual(command[:3], ['sudo', '-n', 'apt-get'])
                self.assertIn('APT::Sandbox::User=runner', command)
                self.assertNotIn('APT::Sandbox::User=1001', command)


@unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'fchown'),
                     'requires actual Linux directory descriptors and fchown')
class LinuxAptDescriptors(unittest.TestCase):
    def test_descriptor_inventory_and_actual_individual_fchown(self):
        # Non-root execution still exercises actual fchown to the existing IDs.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'reference-guest' / 'apt'
            root.mkdir(parents=True)
            root.parent.chmod(0o700)
            (root / 'partial').mkdir()
            (root / 'log').mkdir()
            (root / 'lock').write_bytes(b'')
            request = helper().apt_request(root, {'name': 'fixture', 'uid': os.getuid(), 'gid': os.getgid()}, [], 1_000_000)
            # The ordinary-account policy is separately tested; descriptor fixture
            # supplies the real IDs so root CI can also run this finite check.
            with patch.object(helper(), 'verify_requested_account'), patch.object(helper(), 'require_root'):
                result = helper().normalize(request)
            self.assertEqual(result['status'], 'PASS')
            self.assertIn('lock', [entry['path'] for entry in result['after']])
            descriptor = os.open(root / 'lock', os.O_RDONLY | os.O_NOFOLLOW)
            try:
                before = helper().facts(os.fstat(descriptor))
                after = helper().chown_descriptor(descriptor, before, os.getuid(), os.getgid())
                self.assertEqual(after['inode'], before['inode'])
            finally:
                os.close(descriptor)

    def test_real_symlink_and_hardlink_refused_without_chown(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'reference-guest' / 'apt'
            root.mkdir(parents=True)
            root.parent.chmod(0o700)
            (root / 'lock').write_bytes(b'')
            request = helper().apt_request(root, {'name': 'fixture', 'uid': os.getuid(), 'gid': os.getgid()}, [], 1_000_000)
            (root / 'pkgcache.bin').symlink_to(root / 'lock')
            with patch.object(helper(), 'verify_requested_account'), patch.object(helper(), 'require_root'), \
                 patch.object(helper().os, 'fchown') as chown:
                with self.assertRaises(ValueError): helper().normalize(request)
                chown.assert_not_called()
            (root / 'pkgcache.bin').unlink()
            os.link(root / 'lock', root / 'pkgcache.bin')
            with patch.object(helper(), 'verify_requested_account'), patch.object(helper(), 'require_root'), \
                 patch.object(helper().os, 'fchown') as chown:
                with self.assertRaises(ValueError): helper().normalize(request)
                chown.assert_not_called()


if __name__ == '__main__': unittest.main()
