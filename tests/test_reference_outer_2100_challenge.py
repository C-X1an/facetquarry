"""Independent synthetic descriptor controls, never Linux or full-run evidence.

These challenge the actual check_inner qualification gate. The 5,400 cell
descriptors and filesystem summary are synthetic; no image is allocated,
mounted, measured, or authenticated by this fixture. Existing test bytes and
production interfaces remain unchanged.
"""
import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_filesystem as filesystem
import reference_filesystem_bindings as bindings
import reference_outer_profile as outer
import test_reference_proof_contract as contract
import test_reference_source_view as source_view


def synthetic_filesystem_summary():
    """Use the existing bindings._validate return shape, without forging files."""
    names = ['context.json', 'proof.json', 'formatter.json',
             'formatter-audit/0.json', 'collector-supervisor.json']
    names += [prefix + '.' + stream
              for prefix in ('formatter-audit/0', 'collector-supervisor')
              for stream in ('stdout', 'stderr')]
    names += ['observations/' + str(index) + '.' + suffix
              for index in range(4) for suffix in ('json', 'stdout', 'stderr')]
    files = {name: contract.q.sha(('synthetic-only:' + name).encode())
             for name in names}
    context = {**contract.CONTEXT, 'source': contract.SOURCE,
               'outer_profile': outer.STRICT_2100}
    blocks = 2_100_000_000 // 4096
    return {
        'kind': bindings.KIND, 'policy': filesystem.POLICY, 'status': 'PASS',
        'run_context': context,
        'directory': '/synthetic-workspace/.local/reference-filesystem/outer',
        'image_path': '/owned-volume.img', 'mount_point': '/owned-volume',
        'image_bytes': 2_100_000_000,
        'proof_sha256': contract.q.sha(b'synthetic-only policy proof digest'),
        'proof_file_sha256': files['proof.json'],
        'formatter_file_sha256': files['formatter.json'],
        'formatter_receipt_sha256': files['formatter-audit/0.json'],
        'collector_supervisor_sha256': files['collector-supervisor.json'],
        'observation_receipts_sha256': {
            name: files['observations/' + str(index) + '.json']
            for index, name in enumerate(('version', 'superblock', 'mount', 'loop'))},
        'files_sha256': files,
        'geometry': {'uuid': '12345678-abcd-1234-abcd-123456789abc',
                     'block_size': 4096, 'block_count': blocks,
                     'reserved_blocks': 0},
        'statvfs': {'observed_at': contract.stamp(0), 'uid': 1001, 'gid': 1001,
                    'f_frsize': 4096, 'f_blocks': blocks - 1000,
                    'f_bfree': blocks - 2000, 'f_bavail': blocks - 3000},
    }


def strict_full_fixture():
    """Retain all existing full-format checks and its independent source view."""
    full = contract.FullFormatFixture()
    setup, guest = source_view.fixture()
    full.docs['setup'].update(setup)
    full.docs['guest'].update(guest)
    # The nested layout requires the same remapped shares as the real workflow.
    # Mutate the shared argv list, preserving its link to the command receipt.
    argv = full.docs['setup']['qemu_command']
    argv[:] = [value.replace(',security_model=none',
                             ',security_model=none,multidevs=remap')
               if value.startswith('local,id=') else value for value in argv]
    full.docs['quota'].update(
        profile=outer.STRICT_2100,
        profile_context={
            'profile': outer.STRICT_2100, 'job': 'reference',
            'repository': 'C-X1an/facetquarry', 'repository_id': 1430604581,
            'source': contract.SOURCE, **contract.CONTEXT},
        volume_file_bytes=2_100_000_000,
        oversized_allocation_bytes=2_200_000_000,
        filesystem_policy=filesystem.POLICY,
        filesystem_proof=synthetic_filesystem_summary())
    return full


class IndependentStrictOuterQualificationChallenge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = strict_full_fixture()

    def fixture(self):
        return copy.deepcopy(self.base)

    def reject_quota(self, change):
        full = self.fixture()
        change(full.docs['quota'])
        # sync() rebinds the altered input bytes and stream hashes. Rejection
        # must come from the real format gate, not a stale outer input digest.
        with self.assertRaises(ValueError):
            full.check()

    def reject_proof(self, change):
        self.reject_quota(lambda quota: change(quota['filesystem_proof']))

    def test_correct_strict_synthetic_full_descriptor_is_accepted(self):
        result = self.fixture().check()
        self.assertEqual(result['concurrency'], 1)
        self.assertEqual(len(result['cells']), 5400)

    def test_actual_qualifier_rejects_float_probe_despite_equal_numeric_value(self):
        self.reject_quota(lambda quota: quota.update(
            oversized_allocation_bytes=2_200_000_000.0))

    def test_geometry_helper_rejects_float_probe(self):
        quota = copy.deepcopy(self.base.docs['quota'])
        quota['oversized_allocation_bytes'] = 2_200_000_000.0
        self.assertFalse(outer.quota_geometry(quota, contract.CONTEXT))

    def test_actual_qualifier_requires_complete_filesystem_summary(self):
        for key in ('filesystem_policy', 'filesystem_proof'):
            with self.subTest(missing=key):
                self.reject_quota(lambda quota: quota.pop(key))
        self.reject_quota(lambda quota: quota.update(filesystem_proof={}))

    def test_actual_qualifier_rejects_legacy_or_missing_profile_marker(self):
        self.reject_proof(lambda proof: proof['run_context'].pop('outer_profile'))
        self.reject_proof(lambda proof: proof['run_context'].update(
            outer_profile=outer.LEGACY))
        self.reject_proof(lambda proof: proof.update(image_bytes=2_300_000_000))

    def test_actual_qualifier_rejects_failed_or_wrong_policy_summary(self):
        for key, value in (('kind', 'another-binding-kind'), ('status', 'FAIL'),
                           ('policy', filesystem.NESTED_POLICY)):
            with self.subTest(key=key):
                self.reject_proof(lambda proof: proof.update({key: value}))

    def test_actual_qualifier_binds_run_and_source_of_filesystem_summary(self):
        for key, value in (('github_run_id', '999'), ('github_run_attempt', '2'),
                           ('commit', 'f' * 40), ('source', 'f' * 64)):
            with self.subTest(key=key):
                self.reject_proof(lambda proof: proof['run_context'].update({key: value}))

    def test_actual_qualifier_binds_summary_image_and_mount_paths(self):
        for key, value in (('image_path', '/another-volume.img'),
                           ('mount_point', '/another-volume')):
            with self.subTest(key=key):
                self.reject_proof(lambda proof: proof.update({key: value}))

    def test_actual_qualifier_rejects_inconsistent_geometry(self):
        for key, value in (('block_count', 2_300_000_000 // 4096),
                           ('reserved_blocks', 1), ('block_size', 0)):
            with self.subTest(key=key):
                self.reject_proof(lambda proof: proof['geometry'].update({key: value}))
        self.reject_proof(lambda proof: proof['statvfs'].update(f_frsize=1024))

    def test_actual_qualifier_requires_well_formed_bound_file_digests(self):
        self.reject_proof(lambda proof: proof.update(proof_file_sha256='not-a-sha256'))
        # A syntactically valid replacement is still inconsistent with the
        # complete files_sha256 map emitted by bindings._validate.
        self.reject_proof(lambda proof: proof.update(proof_file_sha256='f' * 64))
        self.reject_proof(lambda proof: proof['files_sha256'].pop('proof.json'))
        self.reject_proof(lambda proof: proof['observation_receipts_sha256'].update(
            loop='f' * 64))


if __name__ == '__main__':
    unittest.main()
