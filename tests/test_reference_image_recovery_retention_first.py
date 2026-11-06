"""Bounded retention-before-interpretation challenges; no live recovery claim."""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference_image_recovery as recovery


class RetentionFirstControls(unittest.TestCase):
    def fixture(self):
        p = {'local': Path('/synthetic/control'), 'outer': Path('/synthetic/outer.img'),
             'volume': Path('/synthetic/volume'), 'mount': Path('/synthetic/volume/original'),
             'image': Path('/synthetic/volume/reference-results.img')}
        ctx = {'profile': recovery.PROFILE, 'repository': recovery.REPOSITORY,
               'repository_id': recovery.REPOSITORY_ID, 'job': 'codec',
               'source': 'a' * 64, 'commit': 'f' * 40,
               'github_run_id': '123', 'github_run_attempt': '1', 'job_started_epoch': 1000,
               'retention_order_policy': recovery.RETENTION_FIRST}
        return p, ctx

    def test_named_timing_preserves_individual_reservations_and_legacy_api(self):
        self.assertEqual(sum(recovery.RETENTION_FIRST_SCHEDULE.values()), 3285)
        self.assertEqual(dict(recovery.RETENTION_FIRST_SCHEDULE), dict(recovery.SCHEDULE))
        self.assertEqual(tuple(recovery.RETENTION_FIRST_SCHEDULE),
                         ('plan', 'quota', 'download', 'uploads', 'readback',
                          'extract', 'inspect', 'metadata', 'cleanup'))
        for stage, required in (('uploads', 2820), ('readback', 2100),
                                ('cleanup', 420), ('metadata', 240)):
            observed = recovery.time_admission(stage, 1000, 1000, policy=recovery.RETENTION_FIRST)
            self.assertEqual(observed['required_seconds'], required)
        self.assertEqual(recovery.time_admission('uploads', 1000, 1000)['required_seconds'], 1620)
        with self.assertRaises(ValueError):
            recovery.time_admission('uploads', 1000, 1000, policy='unknown')

    def prerequisites(self, *, occupied=None, mounted=False, failed=None):
        p, ctx = self.fixture()
        def stage(_p, name):
            self.assertEqual(_p, p)
            if name == failed:
                raise ValueError('synthetic nonquiescent or failed parent')
            return {'status': 'PASS', 'run_context': ctx}
        with patch.object(recovery, 'context', return_value=ctx), \
                patch.object(recovery, 'require_stage', side_effect=stage) as required, \
                patch.object(recovery.os.path, 'lexists', side_effect=lambda path: path == occupied), \
                patch.object(recovery.os.path, 'ismount', return_value=mounted):
            result = recovery.retention_prerequisites(p)
        return result, [call.args[1] for call in required.call_args_list]

    def test_byte_prerequisites_need_quiescent_quota_download_only(self):
        result, stages = self.prerequisites()
        self.assertEqual(stages, ['quota', 'download'])
        self.assertIsInstance(result, dict)

    def test_failed_upstream_cannot_be_relabelled_retention_ready(self):
        for stage in ('quota', 'download'):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                self.prerequisites(failed=stage)

    def test_attempted_interpretation_image_or_mount_refuses_early_retention(self):
        p, _ = self.fixture()
        occupied = [p['image']]
        occupied += [p['local'] / (prefix + stage + '.json')
                     for prefix in ('active-', 'parent-') for stage in ('extract', 'inspect')]
        for path in occupied:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.prerequisites(occupied=path)
        with self.assertRaises(ValueError): self.prerequisites(mounted=True)

    def retained(self, *, mutate=None, changed=False, failed=False):
        p, ctx = self.fixture()
        artifacts = []
        for number, size in enumerate(recovery.chunk_sizes()):
            server_sha = hashlib.sha256(('server-' + str(number)).encode()).hexdigest()
            member_sha = hashlib.sha256(('member-' + str(number)).encode()).hexdigest()
            artifacts.append({'number': number,
                'artifact': {'id': 900000 + number,
                    'name': 'run34-original-zip-123-1-chunk-' + f'{number:02d}',
                    'size_in_bytes': size + 200, 'digest': 'sha256:' + server_sha,
                    'expired': False, 'created_at': '2026-11-06T00:00:00Z',
                    'updated_at': '2026-11-06T00:00:00Z', 'expires_at': '2099-11-13T00:00:00Z',
                    'workflow_run': {'id': 123, 'head_sha': ctx['commit'],
                        'repository_id': recovery.REPOSITORY_ID,
                        'head_repository_id': recovery.REPOSITORY_ID}},
                'delivery_host': 'productionresultssa0.blob.core.windows.net',
                'server_zip_bytes': size + 200, 'server_zip_sha256': server_sha,
                'member_bytes': size, 'member_sha256': member_sha, 'crc_verified': True})
        proof = {'status': 'PASS', 'complete_retention': True, 'run_context': ctx,
                 'retention_order_policy': recovery.RETENTION_FIRST,
                 'original_zip_bytes': recovery.ZIP_BYTES, 'original_zip_sha256': recovery.ZIP_SHA,
                 'artifacts': artifacts, 'awaiting_parent_capture_quiescence': False,
                 'parent_receipt_sha256': 'b' * 64, 'readback_record_sha256': 'e' * 64,
                 'scope': 'Compressed ZIP bytes only; image and inspection NOT RUN.',
                 'scientific_qualification': False}
        if mutate: mutate(proof)
        readback = copy.deepcopy(proof)
        readback.update(complete_retention=False, awaiting_parent_capture_quiescence=True)
        readback.pop('parent_receipt_sha256', None)
        readback.pop('readback_record_sha256', None)
        reads = 0
        def load(path, *args):
            nonlocal reads
            if path == p['local'] / 'readback.json':
                return copy.deepcopy(readback)
            self.assertEqual(path, p['local'] / 'retention.json')
            reads += 1
            result = copy.deepcopy(proof)
            if changed and reads > 1: result['complete_retention'] = False
            return result
        def digest(path, *args):
            if path.name == 'parent-readback.json': return 'b' * 64
            if path.name == 'readback.json': return 'e' * 64
            return ('d' if changed and reads else 'c') * 64
        def stage(_p, name):
            self.assertEqual(name, 'readback')
            if failed: raise ValueError('synthetic incomplete parent capture')
            return {'status': 'PASS', 'run_context': ctx}
        with patch.object(recovery, 'load', side_effect=load), \
                patch.object(recovery, 'context', return_value=ctx), \
                patch.object(recovery, 'identity', return_value=[7, 11, 0o100600, 1001, 1001, 1, 900]), \
                patch.object(recovery, 'hash_regular', side_effect=digest), \
                patch.object(recovery, 'require_stage', side_effect=stage):
            return recovery.require_retained_zip(p, ctx)

    def test_retained_bytes_proof_accepts_exact_context_and_parent_binding(self):
        self.retained()

    def test_retained_bytes_rejects_cross_context_incomplete_or_wrong_hash(self):
        mutations = [lambda p: p.update(status='FAIL'),
                     lambda p: p.update(complete_retention=False),
                     lambda p: p.update(run_context={'source': 'e' * 64}),
                     lambda p: p.update(retention_order_policy='unknown'),
                     lambda p: p.update(original_zip_bytes=recovery.ZIP_BYTES - 1),
                     lambda p: p.update(original_zip_sha256='0' * 64),
                     lambda p: p.update(artifacts=p['artifacts'][:-1]),
                     lambda p: p.update(parent_receipt_sha256='0' * 64),
                     lambda p: p.update(readback_record_sha256='0' * 64),
                     lambda p: p['artifacts'][0].pop('crc_verified'),
                     lambda p: p['artifacts'][0].update(crc_verified=False),
                     lambda p: p['artifacts'][0].update(member_bytes=1),
                     lambda p: p['artifacts'][0].update(member_sha256='invalid'),
                     lambda p: p['artifacts'][0].update(server_zip_sha256='0' * 64),
                     lambda p: p['artifacts'][1]['artifact'].update(id=p['artifacts'][0]['artifact']['id']),
                     lambda p: p['artifacts'][0]['artifact'].update(id=recovery.ARTIFACT_ID),
                     lambda p: p['artifacts'][0]['artifact']['workflow_run'].update(head_sha='0' * 40)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.retained(mutate=mutation)
        with self.assertRaises(ValueError): self.retained(failed=True)

    def test_retention_proof_mutation_during_parent_validation_refuses(self):
        with self.assertRaises(ValueError): self.retained(changed=True)

    def test_production_interpretation_gate_precedes_worker_launch(self):
        tree = ast.parse(Path(recovery.__file__).read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'supervise')
        gates = [node for node in ast.walk(function) if isinstance(node, ast.Call)
                 and ast.unparse(node.func) == 'require_retained_zip']
        launches = [node for node in ast.walk(function) if isinstance(node, ast.Call)
                    and ast.unparse(node.func) == 'supervisor.run_owned']
        self.assertEqual(len(gates), 1)
        self.assertEqual(len(launches), 1)
        self.assertLess(gates[0].lineno, launches[0].lineno)
        guards = [node for node in ast.walk(function) if isinstance(node, ast.If)
                  and gates[0] in list(ast.walk(node))]
        self.assertTrue(any('extract' in ast.unparse(node.test)
                            and 'inspect' in ast.unparse(node.test) for node in guards))

    def test_workflow_retains_and_reads_back_before_interpretation(self):
        text = (ROOT / '.github/workflows/release-evidence.yml').read_text()
        ids = ['image_recovery_download', 'image_recovery_uploads']
        ids += ['image_recovery_chunk_' + str(i) for i in range(recovery.CHUNKS)]
        ids += ['image_recovery_readback', 'image_recovery_extract', 'image_recovery_inspect']
        positions = [text.index('id: ' + name + '\n') for name in ids]
        self.assertEqual(positions, sorted(positions))

    def test_archive_observation_is_bounded_and_does_not_admit_formats(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('tiny', b'synthetic bytes')
        raw = stream.getvalue()
        class BoundedReader(io.BytesIO):
            def read(self, size=-1):
                self_test.assertGreaterEqual(size, 0)
                self_test.assertLessEqual(size, 65557)
                return super().read(size)
        self_test = self
        result = recovery.archive_observation(BoundedReader(raw), len(raw))
        self.assertIsInstance(result, dict)
        self.assertLess(len(json.dumps(result).encode()), 100_000)
        self.assertEqual(result['status'], 'OBSERVED')
        self.assertIs(result['accepted'], False)
        self.assertIs(result['scientific_qualification'], False)
        self.assertEqual(result['eocd']['member_count'], 1)
        self.assertEqual(result['eocd']['disk'], 0)
        self.assertTrue(result['eocd']['ends_at_input_end'])
        self.assertEqual(result['zip64_signatures']['eocd_count'], 0)
        self.assertLessEqual(result['central_header']['bytes'], 46)
        truncated = recovery.archive_observation(BoundedReader(b'not an archive'), 14)
        self.assertEqual(truncated['status'], 'PARSE_ERROR')
        self.assertTrue(truncated['parse_errors'])
        self.assertIs(truncated['accepted'], False)
        self.assertLess(len(json.dumps(truncated).encode()), 100_000)
        for total in (False, 0, -1, recovery.ZIP_BYTES + 1):
            with self.subTest(total=total), self.assertRaises(ValueError):
                recovery.archive_observation(io.BytesIO(b''), total)

    def test_nonordinary_disk_fields_are_observed_without_format_acceptance(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('tiny', b'fixture')
        raw = bytearray(stream.getvalue())
        end = raw.rfind(b'PK\x05\x06')
        struct.pack_into('<H', raw, end + 4, 1)
        result = recovery.archive_observation(io.BytesIO(raw), len(raw))
        self.assertEqual(result['eocd']['disk'], 1)
        self.assertIs(result['accepted'], False)
        self.assertIs(result['scientific_qualification'], False)
        self.assertLess(len(json.dumps(result).encode()), 100_000)


if __name__ == '__main__': unittest.main()
