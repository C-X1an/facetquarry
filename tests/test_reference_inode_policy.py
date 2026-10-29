"""Additive nested-inode policy controls; no real formatter/capacity claim."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_filesystem as fs
import reference_filesystem_bindings as bindings
import reference_result_capacity as capacity
import test_reference_filesystem as fixtures
import test_reference_filesystem_bindings as binding_fixtures

NESTED = 'owned-ext4-zero-reserved-nested-inodes50000-v1'


class NestedInodePolicyTests(unittest.TestCase):
    def fixture(self):
        r, image, mount, size, context = fixtures.FilesystemPolicyTests().fixture(1_100_000_000)
        r.update(policy=NESTED, formatter_command=['mkfs.ext4', '-F', '-q', '-m', '0', '-N', '50000', str(image)],
                 requested_inode_count=50000)
        r['geometry'].update(inode_count=50112, inode_size=256, first_data_block=0,
                             blocks_per_group=32768, inodes_per_group=5568, inode_blocks_per_group=348)
        item = r['observations']['superblock']
        item['stdout'] += ('Inode count: 50112\nInode size: 256\nFirst block: 0\n'
                           'Blocks per group: 32768\nInodes per group: 5568\nInode blocks per group: 348\n')
        item['stdout_sha256'] = hashlib.sha256(item['stdout'].encode()).hexdigest()
        item['ownership']['capture']['stdout'] = {'bytes': len(item['stdout'].encode()), 'sha256': item['stdout_sha256']}
        r['statvfs'].update(f_files=50112, f_ffree=50101, f_favail=50101)
        fixtures.FilesystemPolicyTests().seal(r)
        return r, image, mount, size, context

    def test_explicit_formatter_policy_preserves_default_and_allows_rounding(self):
        self.assertEqual(fs.NESTED_POLICY, NESTED)
        self.assertEqual(bindings.formatter_command(Path('image')), ['mkfs.ext4', '-F', '-q', '-m', '0', 'image'])
        self.assertEqual(bindings.formatter_command(Path('image'), policy=NESTED),
                         ['mkfs.ext4', '-F', '-q', '-m', '0', '-N', '50000', 'image'])
        fs.validate_policy(*self.fixture(), policy=NESTED)

    def test_missing_unknown_substituted_policy_and_wrong_role_refused(self):
        args = self.fixture()
        with self.assertRaises(ValueError): fs.validate_policy(*args)
        with self.assertRaises(ValueError): fs.validate_policy(*args, policy='unknown')
        for edit in (lambda r: r.update(policy=fs.POLICY), lambda r: r.pop('requested_inode_count'),
                     lambda r: r.update(requested_inode_count=50001),
                     lambda r: r.update(image_bytes=2_300_000_000)):
            self.reject(edit)
        with self.assertRaises(ValueError): bindings.policy_for_role(NESTED, 2_300_000_000)

    def reject(self, edit):
        args = self.fixture()
        edit(args[0])
        fixtures.FilesystemPolicyTests().seal(args[0])
        with self.assertRaises(ValueError): fs.validate_policy(*args, policy=NESTED)

    def test_wrong_formatter_args_geometry_and_inode_counters_refused(self):
        for edit in (lambda r: r['formatter_command'].remove('-N'),
                     lambda r: r['formatter_command'].__setitem__(-2, '60000'),
                     lambda r: r['geometry'].update(inode_count=50000),
                     lambda r: r['geometry'].update(inode_blocks_per_group=347),
                     lambda r: r['statvfs'].update(f_files=50000),
                     lambda r: r['statvfs'].update(f_ffree=50113),
                     lambda r: r['statvfs'].update(f_favail=True)):
            self.reject(edit)

    def test_actual_full_capacity_floors_and_time_remain_required(self):
        plan = capacity.floor_plan(4096)
        self.assertEqual(plan['required_available_bytes'], 1_016_177_920)
        self.assertEqual(plan['required_available_inodes'], 33384)
        counters = dict(f_frsize=4096, f_blocks=268554, f_bfree=250000, f_bavail=250000,
                        f_files=50112, f_ffree=50101, f_favail=50101)
        self.assertEqual(capacity.decide(counters, 'full')['admission'], 'ALLOW')
        for change in ({'f_bavail': plan['required_available_bytes'] // 4096 - 1},
                       {'f_favail': plan['required_available_inodes'] - 1}):
            self.assertEqual(capacity.decide({**counters, **change}, 'full')['admission'], 'REFUSE')
        self.assertEqual(capacity.time_plan(100, 100 + capacity.transport.JOB_SECONDS - 1)['admission'], 'REFUSE')

    def test_self_consistent_but_wrong_geometry_is_refused(self):
        # Change both parsed fields and stream: this reaches arithmetic gates,
        # rather than only demonstrating the raw/parsed equality check.
        for changes in ({'inode_count': 49968, 'inodes_per_group': 5552, 'inode_blocks_per_group': 347},
                        {'inode_count': 50256, 'inodes_per_group': 5584, 'inode_blocks_per_group': 349},
                        {'inode_count': 50112, 'inodes_per_group': 5568, 'inode_blocks_per_group': 347}):
            r, *tail = self.fixture()
            labels = {'inode_count': 'Inode count', 'inodes_per_group': 'Inodes per group',
                      'inode_blocks_per_group': 'Inode blocks per group'}
            item = r['observations']['superblock']
            for key, val in changes.items():
                item['stdout'] = item['stdout'].replace(f'{labels[key]}: {r["geometry"][key]}\n',
                                                       f'{labels[key]}: {val}\n')
            r['geometry'].update(changes)
            r['statvfs'].update(f_files=changes['inode_count'], f_ffree=changes['inode_count'] - 11,
                                f_favail=changes['inode_count'] - 11)
            self.capture_stream(item)
            fixtures.FilesystemPolicyTests().seal(r)
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'rounding'):
                fs.validate_policy(r, *tail, policy=NESTED)

    def capture_stream(self, item):
        item['stdout_sha256'] = hashlib.sha256(item['stdout'].encode()).hexdigest()
        item['ownership']['capture']['stdout'] = {'bytes': len(item['stdout'].encode()),
                                                'sha256': item['stdout_sha256']}

    def lifecycle(self, folder):
        """Upgrade finite synthetic canonical files, retaining real byte reads.

        Production receipt/hash/command validation remains active. No Actions
        execution, Linux formatting, mount or capacity observation is claimed.
        """
        helper = binding_fixtures.FilesystemBindingTests()
        fixture = helper.lifecycle_fixture(folder)
        root, directory, image, mount, size, context, *_ = fixture
        def read(path): return json.loads(path.read_text(encoding='utf-8'))
        def write(path, value): path.write_text(json.dumps(value), encoding='utf-8')
        def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
        format_path = directory / 'formatter.json'
        formatter = read(format_path)
        format_cmd = bindings.formatter_command(image, policy=NESTED)
        formatter['policy'] = NESTED
        formatter['observation']['command'] = format_cmd
        receipt_path = directory / 'formatter-audit/0.json'
        receipt = read(receipt_path)
        receipt.update(requested_command=format_cmd, actual_command=bindings.actual_observation(format_cmd))
        write(receipt_path, receipt)
        formatter['observation']['ownership']['receipt_sha256'] = sha(receipt_path)
        write(format_path, formatter)
        proof_path = directory / 'proof.json'
        proof = read(proof_path)
        nested = self.fixture()[0]
        proof.update(policy=NESTED, formatter_command=format_cmd, requested_inode_count=50000)
        proof['geometry'] = nested['geometry']
        proof['statvfs'].update({key: nested['statvfs'][key] for key in ('f_files', 'f_ffree', 'f_favail')})
        item = proof['observations']['superblock']
        item['stdout'] = nested['observations']['superblock']['stdout']
        self.capture_stream(item)
        stream_path = directory / 'observations/1.stdout'
        stream_path.write_bytes(item['stdout'].encode())
        receipt_path = directory / 'observations/1.json'
        receipt = read(receipt_path)
        receipt['capture']['stdout'].update(bytes=stream_path.stat().st_size, sha256=sha(stream_path))
        receipt['captured_output_bytes'] = sum(x['bytes'] for x in receipt['capture'].values())
        write(receipt_path, receipt)
        item['ownership'].update(capture=receipt['capture'], receipt_sha256=sha(receipt_path))
        fixtures.FilesystemPolicyTests().seal(proof)
        write(proof_path, proof)
        parent_path = directory / 'collector-supervisor.json'
        parent = read(parent_path)
        command = bindings.collector_command(root, image, mount, size, directory / 'context.json', directory, policy=NESTED)
        parent.update(policy=NESTED, requested_command=command,
                      actual_command=['timeout', '--signal=TERM', '--kill-after=2s', '80s', *command],
                      proof_file_sha256=sha(proof_path))
        write(parent_path, parent)
        return helper, fixture

    def test_live_and_retained_nested_summary_authenticates_exact_policy_receipts(self):
        helper = binding_fixtures.FilesystemBindingTests()
        with helper.temporary_folder() as folder:
            helper, fixture = self.lifecycle(Path(folder))
            _, directory, image, mount, size, context, *_ = fixture
            with helper.lifecycle_checks(fixture, True):
                summary = bindings.validate(directory, image, mount, size, context, policy=NESTED)
                self.assertEqual(summary['requested_inode_count'], 50000)
                self.assertEqual(summary['geometry']['inode_count'], 50112)
                with self.assertRaises(ValueError): bindings.validate(directory, image, mount, size, context)
            with helper.lifecycle_checks(fixture, False):
                self.assertEqual(bindings.validate_retained(directory, image, mount, size, context, policy=NESTED), summary)
                canonical = {'filesystem_policy': NESTED, 'filesystem_proof': summary}
                owned = {'image': image, 'mount': mount}
                with patch.dict(os.environ, {'FQ_FILESYSTEM_POLICY': fs.POLICY,
                        'FQ_NESTED_FILESYSTEM_POLICY': NESTED, 'GITHUB_WORKSPACE': str(fixture[0])}):
                    capacity.transport.validate_nested_filesystem(owned, canonical, context, live_mount=False)
                    for bad in ('', fs.POLICY, 'unknown'):
                        with patch.dict(os.environ, {'FQ_NESTED_FILESYSTEM_POLICY': bad}), self.assertRaises(ValueError):
                            capacity.transport.validate_nested_filesystem(owned, canonical, context, live_mount=False)
                stream = directory / 'observations/1.stdout'
                stream.write_bytes(b'changed observed geometry')
                with self.assertRaises(ValueError): bindings.validate_retained(directory, image, mount, size, context, policy=NESTED)

    def test_canonical_policy_argv_and_parent_substitution_refused(self):
        helper = binding_fixtures.FilesystemBindingTests()
        for name, edit in (
                ('formatter.json', lambda x: x.pop('policy')),
                ('formatter-audit/0.json', lambda x: x['requested_command'].__setitem__(-2, '60000')),
                ('collector-supervisor.json', lambda x: x.pop('policy')),
                ('collector-supervisor.json', lambda x: x['requested_command'].__setitem__(-1, fs.POLICY))):
            with self.subTest(name=name), helper.temporary_folder() as folder:
                helper, fixture = self.lifecycle(Path(folder))
                _, directory, image, mount, size, context, *_ = fixture
                path = directory / name
                value = json.loads(path.read_text(encoding='utf-8'))
                edit(value)
                path.write_text(json.dumps(value), encoding='utf-8')
                with helper.lifecycle_checks(fixture, True), self.assertRaises(ValueError):
                    bindings.validate(directory, image, mount, size, context, policy=NESTED)


if __name__ == '__main__': unittest.main()
