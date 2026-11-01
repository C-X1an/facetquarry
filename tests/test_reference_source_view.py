"""Synthetic source-view contracts plus native file controls; never VM evidence."""
import copy
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_source_view as view
import reference_guest as guest_script
import test_reference_proof_contract as contract

SOURCE, EXECUTION, CONTEXT = contract.SOURCE, contract.EXECUTION, contract.CONTEXT
UID, GID = 1001, 1001


def manifest():
    files = [{'path': name, 'bytes': 12, 'sha256': contract.q.sha(name.encode()),
              'mode': 0o755 if name in view.BINARIES else 0o644}
             for name in ('README.md', 'bin/facetquarry', 'bin/fqbench', 'go.mod', 'scripts/common.py')]
    # Existing full-format fixture binds its binaries using these exact SHAs.
    for row in files:
        if row['path'] in view.BINARIES:
            row['sha256'] = contract.q.sha(Path(row['path']).name.encode())
    return {'schema_version': 1, 'policy': view.SOURCE_POLICY, 'source': SOURCE,
            'execution_id': EXECUTION, 'run_context': copy.deepcopy(CONTEXT), 'uid': UID, 'gid': GID,
            'files': files, 'tracked_count': 3,
            'tracked_index_sha256': view.manifest_digest(
                {row['path']: row['mode'] for row in files if row['path'] not in view.BINARIES})}


def mount_rows():
    def row(mount, device, kind, access, root='/', source='none'):
        return {'device': device, 'root': root, 'mount': mount,
                'options': [access, 'nosuid', 'nodev'], 'fstype': kind,
                'source': source, 'super_options': ['rw']}
    rows = [row('/', '0:1', '9p', 'ro', source='rootfs'),
            row(view.ORIGIN, '0:2', '9p', 'ro', source='project'),
            row('/owned', '0:3', '9p', 'ro', source='owned'),
            row('/project', '0:4', 'tmpfs', 'ro', source='fq-tracked-source')]
    rows.extend(row('/project/' + name, '0:2', '9p', access, '/' + name, 'project')
                for name, access in view.BINDINGS.items())
    rows.extend(row(name, '0:' + str(n), kind, 'rw') for name, n, kind in
                (('/dev', 5, 'devtmpfs'), ('/tmp', 6, 'tmpfs'), ('/run', 7, 'tmpfs')))
    return rows


def fixture():
    value = manifest()
    dirs = view.validate_manifest(value, SOURCE, EXECUTION, CONTEXT, UID, GID)
    cap = {'bytes': view.SOURCE_BYTES, 'free_bytes': view.SOURCE_BYTES, 'block_bytes': 4096,
           'inodes': view.SOURCE_INODES, 'free_inodes': view.SOURCE_INODES - 1}
    def copies(device):
        return [{'path': item['path'], 'sha256': item['sha256'],
                 'identity': [device, i + 1, item['bytes'], 1, 1, UID, GID,
                              stat.S_IFREG | item['mode'], 1, 8]}
                for i, item in enumerate(value['files'])]
    originals, copied = copies(2), copies(4)
    ram = {'/dev': 1048576, '/tmp': view.TMP_BYTES, '/run': 1048576, '/project': view.SOURCE_BYTES}
    proof = {'schema_version': 1, 'policy': view.SOURCE_POLICY, 'source': SOURCE,
             'execution_id': EXECUTION, 'run_context': copy.deepcopy(CONTEXT), 'status': 'PASS',
             'manifest_sha256': view.manifest_digest(value), 'staging_uid': 0,
             'workload_uid': UID, 'workload_gid': GID,
             'phase_order': ['root_original_verified', 'capacity_admitted', 'copied_verified',
                             'disk_bindings_verified', 'source_remounted_readonly', 'before_uid_drop'],
             'original_before': originals, 'original_after': copy.deepcopy(originals),
             'original_final': copy.deepcopy(originals), 'copied_before': copied,
             'copied_readonly': copy.deepcopy(copied), 'copied_final': copy.deepcopy(copied),
             'source_before': SOURCE, 'source_after': SOURCE, 'copied_source': SOURCE,
             'git_status': '', 'commit': CONTEXT['commit'], 'capacity_before': cap,
             'capacity_readonly': {**cap, 'free_bytes': cap['free_bytes'] - 5 * 4096,
                                   'free_inodes': cap['free_inodes'] - 10},
             'admission': view.admit(value, dirs, cap), 'mounts': mount_rows(), 'final_mounts': mount_rows(),
             'bindings': [{'name': name, 'access': access, 'same_inode': True, 'uid': UID, 'gid': GID}
                          for name, access in view.BINDINGS.items()],
             'ram_capacities': ram, 'final_ram_capacities': copy.deepcopy(ram)}
    setup = {'source_policy': view.SOURCE_POLICY, 'source_view_manifest': value,
             'tmpfs_limit_bytes': view.RAM_BYTES,
             'source_view_host_after': {'manifest_sha256': view.manifest_digest(value), 'status': 'PASS'}}
    guest = {'source_policy': view.SOURCE_POLICY, 'uid': UID, 'gid': GID, 'source_view': proof,
             'ram_backed_filesystems': [{'mount': name, 'bytes': size} for name, size in ram.items()]}
    return setup, guest


class SourceViewFormatControls(unittest.TestCase):
    def check(self, setup, guest):
        view.validate_proof(setup, guest, SOURCE, EXECUTION, CONTEXT)

    def test_explicit_selection_ignores_environment_and_keeps_legacy_constants(self):
        with patch.dict(os.environ, {'FQ_GUEST_SOURCE_POLICY': view.SOURCE_POLICY}):
            self.assertEqual(view.policy(), 'legacy')
        self.assertEqual(guest_script.TMPFS_BYTES, 18 * 1024 * 1024)
        self.assertIn('size=16777216,mode=1777', guest_script.INIT)
        with self.assertRaises(ValueError):
            view.policy('ambient-or-unknown')

    def test_synthetic_source_view_format_positive(self):
        self.check(*fixture())

    def test_tracked_index_digest_rejects_self_consistent_dropped_or_renamed_docs(self):
        for change in ('drop', 'rename'):
            setup, guest = fixture()
            value, proof = setup['source_view_manifest'], guest['source_view']
            if change == 'drop':
                value['files'] = [row for row in value['files'] if row['path'] != 'README.md']
                value['tracked_count'] -= 1
                proof['admission']['needed_bytes'] -= proof['capacity_before']['block_bytes']
                proof['admission']['needed_inodes'] -= 1
            else:
                value['files'][0]['path'] = 'RENAMED.md'
            for label in ('original_before', 'original_after', 'original_final',
                          'copied_before', 'copied_readonly', 'copied_final'):
                if change == 'drop':
                    proof[label] = [row for row in proof[label] if row['path'] != 'README.md']
                else:
                    proof[label][0]['path'] = 'RENAMED.md'
            # Bind all other rows/counts to the edited manifest while retaining
            # the original tracked-index digest. Docs do not change source ID.
            bound = view.manifest_digest(value)
            proof['manifest_sha256'] = bound
            setup['source_view_host_after']['manifest_sha256'] = bound
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check(setup, guest)

    def test_mount_origin_must_use_exact_project_export_and_root(self):
        for change in ('origin_source', 'origin_root', 'all_bind_sources'):
            rows = mount_rows()
            if change == 'origin_source':
                rows[1]['source'] = 'owned'
            elif change == 'origin_root':
                rows[1]['root'] = '/substituted'
                for row in rows[4:7]:
                    row['root'] = '/substituted' + row['root']
            else:
                for row in (rows[1], *rows[4:7]):
                    row['source'] = 'rootfs'
            with self.subTest(change=change), self.assertRaises(ValueError):
                view.validate_mounts(rows)

    def test_each_child_bind_must_use_project_export(self):
        for name in view.BINDINGS:
            rows = mount_rows()
            row = next(row for row in rows if row['mount'] == '/project/' + name)
            row['source'] = 'owned'
            with self.subTest(name=name), self.assertRaises(ValueError):
                view.validate_mounts(rows)

    def test_full_format_dispatch_accepts_source_view_with_native_binary_binding(self):
        full = contract.FullFormatFixture()
        setup, guest = fixture()
        full.docs['setup'].update(setup)
        full.docs['guest'].update(guest)
        self.assertEqual(full.check()['concurrency'], 1)
        full.docs['provenance']['binaries']['fqbench']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'native binary provenance'):
            full.check()

    def test_full_format_legacy_remains_accepted_and_new_fields_fail_closed(self):
        full = contract.FullFormatFixture()
        self.assertEqual(full.check()['concurrency'], 1)
        full.docs['guest']['source_view'] = {}
        with self.assertRaisesRegex(ValueError, 'legacy policy'):
            full.check()

    def test_full_format_unknown_and_mismatched_policy_rejected(self):
        for where, value in (('setup', 'unknown'), ('guest', view.SOURCE_POLICY)):
            full = contract.FullFormatFixture()
            full.docs[where]['source_policy'] = value
            with self.subTest(where=where), self.assertRaises(ValueError):
                full.check()

    def test_path_identity_owner_size_count_and_copy_proofs_fail_closed(self):
        mutations = [
            lambda s, g: s['source_view_manifest']['files'][0].update(path='../private.txt'),
            lambda s, g: s['source_view_manifest']['files'][0].update(path='scripts/./common.py'),
            lambda s, g: s['source_view_manifest']['files'][0].update(path='.cache/file'),
            lambda s, g: s['source_view_manifest']['files'].append(s['source_view_manifest']['files'][0]),
            lambda s, g: s['source_view_manifest']['files'].pop(),
            lambda s, g: s['source_view_manifest']['files'][0].update(bytes=view.SOURCE_BYTES + 1),
            lambda s, g: s['source_view_manifest'].update(source='f' * 64),
            lambda s, g: g['source_view'].update(manifest_sha256='f' * 64),
            lambda s, g: g['source_view']['copied_final'][0].update(sha256='f' * 64),
            lambda s, g: g['source_view']['copied_before'][0]['identity'].__setitem__(5, 0),
            lambda s, g: g['source_view']['copied_before'][0]['identity'].__setitem__(2, 1000),
            lambda s, g: g['source_view']['copied_before'][0]['identity'].__setitem__(8, 2),
            lambda s, g: g['source_view'].update(original_after=[]),
            lambda s, g: g['source_view'].update(copied_readonly=[]),
            lambda s, g: g['source_view'].update(staging_uid=UID),
            lambda s, g: g['source_view'].update(workload_uid=0),
            lambda s, g: g['source_view']['phase_order'].reverse(),
            lambda s, g: g['source_view']['run_context'].update(github_run_attempt='2'),
            lambda s, g: g['source_view']['bindings'][0].update(same_inode=False),
            lambda s, g: s.pop('source_view_host_after'),
        ]
        for number, mutate in enumerate(mutations):
            setup, guest = fixture()
            mutate(setup, guest)
            with self.subTest(number=number), self.assertRaises(ValueError):
                self.check(setup, guest)

    def test_capacity_block_rounding_and_inode_admission(self):
        setup, guest = fixture()
        value = setup['source_view_manifest']
        dirs = view.validate_manifest(value, SOURCE, EXECUTION, CONTEXT, UID, GID)
        facts = guest['source_view']['capacity_before']
        admitted = view.admit(value, dirs, facts)
        self.assertGreater(admitted['needed_bytes'], sum(x['bytes'] for x in value['files']))
        for changed in ({'free_bytes': admitted['needed_bytes'] - 1},
                        {'free_inodes': admitted['needed_inodes']}, {'bytes': view.SOURCE_BYTES + 4096},
                        {'inodes': view.SOURCE_INODES * 2}, {'block_bytes': 0}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                view.admit(value, dirs, {**facts, **changed})

    def test_readonly_mounts_disk_binds_and_aliases_rejected(self):
        mutations = [
            lambda rows: rows[3].update(options=['rw', 'nosuid', 'nodev']),
            lambda rows: rows.append({**rows[3], 'mount': '/run/writable-alias', 'options': ['rw']}),
            lambda rows: rows[1].update(options=['rw']),
            lambda rows: rows[4].update(fstype='tmpfs'),
            lambda rows: rows[4].update(root='/some-other-local'),
            lambda rows: rows[6].update(options=['rw']),
            lambda rows: rows.append({**rows[1], 'mount': '/writable-origin', 'options': ['rw']}),
            lambda rows: rows.append({**rows[3], 'device': '0:99', 'mount': '/project/data'}),
        ]
        for number, mutate in enumerate(mutations):
            rows = mount_rows(); mutate(rows)
            with self.subTest(number=number), self.assertRaises(ValueError):
                view.validate_mounts(rows)

    def test_actual_ram_capacities_and_exact_mount_set_required(self):
        for mutate in (
                lambda s, g: g['source_view']['ram_capacities'].update({'/tmp': 16 * 1024 * 1024}),
                lambda s, g: g['source_view']['final_ram_capacities'].update({'/project': view.SOURCE_BYTES + 4096}),
                lambda s, g: g['ram_backed_filesystems'].append({'mount': '/run/extra', 'bytes': 1}),
                lambda s, g: g['source_view']['final_mounts'].append({**mount_rows()[-1], 'mount': '/extra'}),
                lambda s, g: s.update(tmpfs_limit_bytes=guest_script.TMPFS_BYTES)):
            setup, guest = fixture(); mutate(setup, guest)
            with self.assertRaises(ValueError):
                self.check(setup, guest)

    def test_mountinfo_parser_and_escaped_paths(self):
        rows = view.mounts('19 1 0:5 / /project ro,nosuid,nodev - tmpfs fq-source rw,size=24576k\n')
        self.assertEqual(rows[0]['fstype'], 'tmpfs')
        with self.assertRaises(ValueError):
            view.mounts('19 1 0:5 / /bad\\040path ro - tmpfs fq-source rw\n')


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'getuid') and os.getuid() > 0,
                     'native ordinary-account inode/owner tests require POSIX; fixtures above are portable')
class SourceViewNativeFileControls(unittest.TestCase):
    def test_real_regular_copy_digest_owner_and_mutation_controls(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            p = root / 'README.md'; p.write_bytes(b'bounded actual file'); p.chmod(0o644)
            row = {'path': 'README.md', 'bytes': p.stat().st_size, 'mode': 0o644,
                   'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
            first = view.inspect_file(root, row, os.getuid(), os.getgid())
            self.assertEqual(first['sha256'], row['sha256'])
            with self.assertRaises(ValueError):
                view.inspect_file(root, row, os.getuid() + 1, os.getgid())
            p.write_bytes(b'changed actual file')
            with self.assertRaises(ValueError):
                view.inspect_file(root, row, os.getuid(), os.getgid())
            p.unlink()
            with self.assertRaises(FileNotFoundError):
                view.inspect_file(root, row, os.getuid(), os.getgid())

    def test_real_symlinks_hardlinks_and_writable_modes_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            p = root / 'README.md'; p.write_bytes(b'x'); p.chmod(0o644)
            row = {'path': 'README.md', 'bytes': 1, 'mode': 0o644, 'sha256': hashlib.sha256(b'x').hexdigest()}
            linked = root / 'linked'; linked.symlink_to(p)
            with self.assertRaises(ValueError):
                view.inspect_file(root, {**row, 'path': 'linked'}, os.getuid(), os.getgid())
            linked.unlink(); os.link(p, linked)
            with self.assertRaises(ValueError):
                view.inspect_file(root, row, os.getuid(), os.getgid())
            linked.unlink(); p.chmod(0o666)
            with self.assertRaises(ValueError):
                view.inspect_file(root, row, os.getuid(), os.getgid())

    def test_tracked_selection_includes_docs_and_refuses_index_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            names = {'README.md': b'tracked documentation', 'go.mod': b'module synthetic\n',
                     'scripts/common.py': b'# synthetic source, no engine\n'}
            for name, data in names.items():
                p = root / name; p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data); p.chmod(0o644)
            for name in view.BINARIES:
                p = root / name; p.parent.mkdir(exist_ok=True)
                p.write_bytes(b'\x7fELFsynthetic fixture only'); p.chmod(0o755)
            def run(*args):
                return view.git(root, *args)
            import subprocess
            subprocess.run(['git', 'init', '-q', str(root)], check=True, capture_output=True)
            run('add', '--', *names)
            run('-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid',
                'commit', '-qm', 'synthetic tracked selection')
            # Binaries are deliberately untracked and must be ignored as in the real checkout.
            (root / '.git/info/exclude').write_text('bin/\n')
            selected = view.create_manifest(root, SOURCE, EXECUTION, CONTEXT, os.getuid(), os.getgid())
            self.assertIn('README.md', [x['path'] for x in selected['files']])
            self.assertEqual(selected['tracked_count'], len(names))
            p = root / 'README.md'; p.unlink(); p.symlink_to(root / 'go.mod')
            run('add', '--', 'README.md')
            with self.assertRaises(ValueError):
                view.tracked(root)


if __name__ == '__main__':
    unittest.main()
