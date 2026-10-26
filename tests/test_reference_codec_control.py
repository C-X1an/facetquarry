"""Bounded codec/identity fixtures; no hosted job, network, or quota emulation."""
import copy
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_codec_control as control


def artifact_fixture():
    api = f'https://api.github.com/repos/{control.REPOSITORY}/actions/artifacts/{control.ARTIFACT_ID}'
    return {'id': control.ARTIFACT_ID, 'name': control.TRANSPORT_NAME,
            'size_in_bytes': control.ZIP_BYTES, 'expired': False, 'digest': 'sha256:' + control.ZIP_SHA,
            'url': api, 'archive_download_url': api + '/zip',
            'created_at': '2026-10-23T18:36:01Z', 'updated_at': '2026-10-23T18:36:01Z',
            'expires_at': '2026-10-30T18:35:57Z',
            'workflow_run': {'id': control.TRANSPORT_RUN, 'repository_id': control.REPOSITORY_ID,
                             'head_repository_id': control.REPOSITORY_ID, 'head_sha': control.TRANSPORT_HEAD}}


def legacy_fixture():
    # Include both nested historical source paths and the outer metadata member.
    entries = [('source/', b''), ('source/.local/', b''),
               ('source/.local/sample.json', b'{"actual_fixture":true}\n'),
               ('toolchain-download.json', b'{"fixture":"outer"}\n')]
    members = []
    for number, (name, data) in enumerate(entries):
        members.append({'path': name, 'directory': name.endswith('/'),
                        'original_bytes': len(data), 'original_sha256': hashlib.sha256(data).hexdigest(),
                        'payload_bytes': len(data), 'payload_sha256': hashlib.sha256(data).hexdigest(),
                        'payload_name': f'payload/{number:06d}', 'encoding': 'identity'})
    total = sum(len(raw) for _, raw in entries)
    manifest = {'schema_version': 1, 'evidence_type': 'lossless_member_transport',
                'measured_source': control.HISTORICAL_SOURCE,
                'original_artifact_id': control.HISTORICAL_ARTIFACT,
                'original_run_id': control.HISTORICAL_RUN,
                'original_zip_bytes': control.HISTORICAL_ZIP_BYTES,
                'original_zip_sha256': control.HISTORICAL_ZIP_SHA,
                'packaging_commit': control.TRANSPORT_HEAD,
                'original_member_bytes': total, 'streamed_payload_bytes': total, 'members': members}
    raw_manifest = json.dumps(manifest, separators=(',', ':')).encode()
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in [('manifest.json', raw_manifest)] + [
                (row['payload_name'], data) for row, (_, data) in zip(members, entries)]:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return manifest, raw_manifest, lzma.compress(raw_tar.getvalue(), preset=3), entries


class CodecAdmissionControls(unittest.TestCase):
    def test_all_stages_reserve_every_allocation_and_refuse_exact_boundary(self):
        reserved = 2_746_000_000
        boundary = 12_000_000_000 - reserved
        before = control.growth_plan(boundary - 1)
        self.assertEqual(before['maximum_new_stage_bytes'], reserved)
        self.assertEqual(before['peak_bytes'], 11_999_999_999)
        self.assertEqual(before['admission'], 'ALLOW')
        self.assertTrue(all(value == reserved for value in before['branches'].values()))
        self.assertFalse(before['data_upload_allowed'])
        self.assertEqual(control.growth_plan(boundary)['admission'], 'REFUSE')
        for base in (True, 1_999_999_999, -1, '8000000000'):
            with self.subTest(base=base), self.assertRaises(ValueError):
                control.growth_plan(base)

    def test_artifact_metadata_is_exact_and_does_not_retain_urls(self):
        original = artifact_fixture()
        accepted = control.artifact_metadata(original)
        self.assertNotIn('url', accepted)
        self.assertNotIn('archive_download_url', accepted)
        for key, value in [('id', control.ARTIFACT_ID + 1), ('size_in_bytes', control.ZIP_BYTES + 1),
                           ('digest', 'sha256:' + '0' * 64), ('expired', True)]:
            bad = copy.deepcopy(original)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                control.artifact_metadata(bad)
        bad = copy.deepcopy(original)
        bad['workflow_run']['head_repository_id'] += 1
        with self.assertRaises(ValueError):
            control.artifact_metadata(bad)

    def test_signed_destination_refuses_authority_and_path_changes(self):
        host = 'productionresultssa123.blob.core.windows.net'
        good = f'https://{host}/actions-results/fixture?sig=synthetic-only'
        self.assertEqual(control.artifact_destination(good), host)
        for bad in (good.replace('https:', 'http:'), good.replace(host, host + '.evil.invalid'),
                    good.replace(host, 'unrelated.blob.core.windows.net'),
                    good.replace(host, 'user:password@' + host), good.replace(host, host + ':444'),
                    good.replace('/actions-results/', '/other/'), good.split('?')[0],
                    good + '#fragment', good + '\n'):
            with self.subTest(kind=bad.split('?')[0]), self.assertRaises(ValueError) as failure:
                control.artifact_destination(bad)
            self.assertNotIn('synthetic-only', str(failure.exception))

    def test_complete_metadata_chunks_detect_tamper_and_path_substitution(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            rows = [{'path': 'source/.local/a', 'original_sha256': 'a' * 64},
                    {'path': 'toolchain-download.json', 'original_sha256': 'b' * 64}]
            index = control.rows_write(root, 'members', rows)
            actual, proof = control.rows_read(root, 'members')
            self.assertEqual(actual, rows)
            self.assertEqual(proof, index)
            chunk = root / index['chunks'][0]['name']
            chunk.write_bytes(chunk.read_bytes().replace(b'source', b'SOURCE'))
            with self.assertRaisesRegex(ValueError, 'chunk differs'):
                control.rows_read(root, 'members')
            index['chunks'][0]['name'] = '../outside.jsonl'
            (root / 'members-index.json').write_text(json.dumps(index), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'chunk path'):
                control.rows_read(root, 'members')

    def test_legacy_identity_and_all_member_count_are_mandatory(self):
        manifest, raw, _, _ = legacy_fixture()
        with mock.patch.object(control, 'HISTORICAL_MEMBERS', 4):
            self.assertEqual(control.legacy_manifest(raw), manifest)
            for key, value in [('measured_source', '0' * 64), ('original_run_id', 1),
                               ('original_member_bytes', manifest['original_member_bytes'] + 1)]:
                bad = copy.deepcopy(manifest)
                bad[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    control.legacy_manifest(json.dumps(bad).encode())
            bad = copy.deepcopy(manifest)
            bad['members'] = bad['members'][:-1]
            with self.assertRaisesRegex(ValueError, 'member count'):
                control.legacy_manifest(json.dumps(bad).encode())

    def test_legacy_mapping_preserves_outer_and_nested_members_without_mode_invention(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            volume = root / 'volume'
            (volume / 'input').mkdir(parents=True)
            metadata = root / 'metadata'
            metadata.mkdir()
            manifest, _, compressed, entries = legacy_fixture()
            (volume / 'input/legacy-members.tar.xz').write_bytes(compressed)
            (metadata / 'input-binding.json').write_text('{"run_context":{}}', encoding='ascii')
            paths = {'volume': volume, 'metadata': metadata}
            with mock.patch.object(control, 'admitted', return_value=(paths, {})), \
                    mock.patch.object(control, 'mounted'), mock.patch.object(control, 'context', return_value={}), \
                    mock.patch.object(control, 'INNER_BYTES', len(compressed)), \
                    mock.patch.object(control, 'INNER_SHA', hashlib.sha256(compressed).hexdigest()), \
                    mock.patch.object(control, 'HISTORICAL_MEMBERS', len(entries)):
                receipt = control.recover()
            self.assertEqual(receipt['status'], 'PASS')
            self.assertEqual(receipt['original_member_count'], 4)
            self.assertTrue(receipt['original_modes'].startswith('UNKNOWN'))
            rows, _ = control.rows_read(metadata, 'legacy-members')
            self.assertEqual({row['path'] for row in rows}, {name for name, _ in entries})
            self.assertTrue(all(row['mode'] is None for row in rows))
            for name, raw in entries:
                target = volume / 'data/.local' / name
                self.assertEqual(target.is_dir(), name.endswith('/'))
                if not name.endswith('/'):
                    self.assertEqual(target.read_bytes(), raw)
            complete, _ = control.rows_read(metadata, 'recovered-members')
            self.assertTrue(all('mode' in row for row in complete))
            self.assertEqual(receipt['original_member_bytes'], manifest['original_member_bytes'])

    def test_identity_substitution_refuses_regenerable_unlink(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'package.tar.xz'
            path.write_bytes(b'original')
            identity = control.bundle.signature(path.lstat())
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            path.write_bytes(b'substitute')
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                control.exact_remove(path, 8, digest, Path(folder) / 'proof.json', identity)
            self.assertTrue(path.is_file())
            self.assertFalse((Path(folder) / 'proof.json').exists())

    def test_missing_pack_receipt_or_reduced_packet_cannot_claim_complete_proof(self):
        for degraded in (False, True):
            with self.subTest(degraded=degraded), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                local = root / '.local'
                metadata = local / 'reference-metadata/codec'
                metadata.mkdir(parents=True)
                packet_dir = root / 'packet'
                packet_dir.mkdir()
                verified = {'status': 'PASS', 'run_context': {}}
                for name, key in (('legacy-members', 'legacy_inventory'),
                                  ('recovered-members', 'recovered_inventory')):
                    verified[key] = control.rows_write(metadata, name, [{'path': 'fixture'}])
                for name in ('input-binding.json', 'recovery.json'):
                    (metadata / name).write_text('{}', encoding='ascii')
                (metadata / 'verification.json').write_text(json.dumps(verified), encoding='ascii')
                packet = {'status': 'FAIL' if degraded else 'PASS', 'files': [],
                          'failures': ['pack receipt omitted'] if degraded else [],
                          'reductions': ['pack receipt prefix only'] if degraded else [],
                          'enumeration_complete': not degraded}
                for path in metadata.iterdir():
                    raw = path.read_bytes()
                    packet['files'].append({'path': path.relative_to(local).as_posix(),
                                            'transformation': 'identity', 'original_bytes': len(raw),
                                            'export_bytes': len(raw),
                                            'original_sha256': hashlib.sha256(raw).hexdigest(),
                                            'export_sha256': hashlib.sha256(raw).hexdigest()})
                paths = {'local': local, 'metadata': metadata, 'packet': packet_dir,
                         'image': root / 'absent-image',
                         'output': local / 'reference-transport/reference-members.tar.xz'}
                with mock.patch.object(control, 'paths', return_value=paths), \
                        mock.patch.object(control, 'context', return_value={}), \
                        mock.patch.object(control.artifacts, 'metadata_packet', return_value=packet), \
                        mock.patch.dict(os.environ, {'FQ_ACCOUNTED_BASE_BYTES': '7700000000', 'GITHUB_OUTPUT': ''}):
                    result = control.metadata()
                self.assertTrue(result['metadata_allowed'])
                self.assertFalse(result['codec_proof_export']['complete_codec_proof_metadata_export'])
                self.assertEqual(result['status'], 'FAIL')

    def test_complete_small_proof_exports_and_incomplete_enumeration_refuses(self):
        for incomplete in (False, True):
            with self.subTest(incomplete=incomplete), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                local = root / '.local'
                metadata = local / 'reference-metadata/codec'
                (metadata / 'commands').mkdir(parents=True)
                transport = local / 'reference-transport'
                transport.mkdir()
                verified = {'status': 'PASS', 'run_context': {}}
                for name, key in (('legacy-members', 'legacy_inventory'),
                                  ('recovered-members', 'recovered_inventory')):
                    verified[key] = control.rows_write(metadata, name, [{'path': 'fixture'}])
                for name in ('input-binding.json', 'recovery.json', 'pack-result.json', 'unmount.json'):
                    (metadata / name).write_text('{}', encoding='ascii')
                for stage in ('plan', 'quota', 'download', 'recover', 'pack', 'verify', 'unmount'):
                    (metadata / (stage + '-stage.json')).write_text('{}', encoding='ascii')
                for name in ('reference-admission.json', 'reference-quota.json'):
                    (local / name).write_text('{}', encoding='ascii')
                for name in ('pack-attempt.json', 'pack-stdout.txt', 'pack-stderr.txt'):
                    (transport / name).write_bytes(b'{}' if name.endswith('.json') else b'')
                for suffix in ('.json', '.stdout.txt', '.stderr.txt'):
                    (metadata / 'commands' / ('enospc-proof' + suffix)).write_bytes(b'{}')
                (metadata / 'verification.json').write_text(json.dumps(verified), encoding='ascii')
                paths = {'local': local, 'metadata': metadata, 'packet': root / 'packet',
                         'image': root / 'absent-image', 'output': transport / 'reference-members.tar.xz'}
                make_packet = control.artifacts.metadata_packet

                def observed_packet(*args):
                    packet = make_packet(*args)
                    if incomplete:
                        packet['enumeration_complete'] = False
                    return packet

                with mock.patch.object(control, 'paths', return_value=paths), \
                        mock.patch.object(control, 'context', return_value={}), \
                        mock.patch.object(control.artifacts, 'metadata_packet', side_effect=observed_packet), \
                        mock.patch.dict(os.environ, {'FQ_ACCOUNTED_BASE_BYTES': '7700000000', 'GITHUB_OUTPUT': ''}):
                    result = control.metadata()
                self.assertTrue(result['metadata_allowed'])
                self.assertEqual(result['codec_proof_export']['complete_codec_proof_metadata_export'],
                                 not incomplete, result['codec_proof_export'])
                self.assertEqual(result['status'], 'FAIL' if incomplete else 'PASS')


if __name__ == '__main__':
    unittest.main()
