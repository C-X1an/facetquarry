"""Tiny synthetic controls only; no Linux capacity, mount or retention claim."""
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference_image_recovery as recovery


class RecoveryPureControls(unittest.TestCase):
    def test_exact_growth_includes_all_wrappers_and_unchanged_global_reserve(self):
        plan = recovery.geometry_plan(2_000_000_000)
        self.assertEqual(plan['maximum_new_stage_bytes'], 2_971_697_518)
        self.assertEqual(plan['reservations'], {
            'owned_outer_image': 2_100_000_000, 'eight_chunk_artifact_zip_ceiling': 761_697_518,
            'external_metadata_and_logs': 50_000_000, 'cloud_metadata': 10_000_000, 'overhead': 50_000_000})
        self.assertFalse(plan['scientific_qualification'])
        boundary = 12_000_000_000 - plan['maximum_new_stage_bytes']
        self.assertEqual(recovery.geometry_plan(boundary)['admission'], 'REFUSE')
        self.assertEqual(recovery.geometry_plan(boundary - 1)['admission'], 'ALLOW')
        for invalid in (True, 1_999_999_999, 2_000_000_000.0):
            with self.subTest(base=invalid), self.assertRaises(ValueError):
                recovery.geometry_plan(invalid)

    def test_exact_eight_chunks_and_only_one_readback_are_admitted(self):
        self.assertEqual(recovery.chunk_sizes(), [100_000_000] * 7 + [53_697_518])
        self.assertEqual(recovery.ZIP_BYTES + recovery.IMAGE_BYTES + recovery.READBACK_BYTES, 1_954_697_518)
        self.assertEqual(recovery.PROBE_BYTES, 2_200_000_000)
        self.assertEqual(recovery.OUTER_BYTES, 2_100_000_000)
        self.assertEqual(recovery.READBACK_BYTES, 101_000_000)

    def test_observed_free_bytes_rounding_and_inodes_refuse_before_growth(self):
        block = 4096
        required = 101_000_001
        rounded = (required + block - 1) // block * block
        available_blocks = (rounded + recovery.FREE_RESERVE + block - 1) // block
        self.assertTrue(recovery.space_admission(block, available_blocks, 66, required, 2)['allowed'])
        self.assertFalse(recovery.space_admission(block, available_blocks - 1, 66, required, 2)['allowed'])
        self.assertFalse(recovery.space_admission(block, available_blocks, 65, required, 2)['allowed'])
        self.assertEqual(recovery.space_admission(block, available_blocks, 66, required, 2)
                         ['remaining_rounded_planned_bytes'], rounded)
        for args in ((True, 1, 1, 1, 1), (8192, 1, 1, 1, 1), (4096, -1, 1, 1, 1)):
            with self.subTest(args=args), self.assertRaises(ValueError): recovery.space_admission(*args)

    def test_actual_remaining_time_preserves_uploads_readbacks_and_both_tails(self):
        start = 1_800_000_000
        self.assertEqual(sum(recovery.SCHEDULE.values()), 3285)
        self.assertEqual(recovery.time_admission('plan', start, start)['setup_cushion_seconds'], 315)
        self.assertTrue(recovery.time_admission('plan', start, start + 315)['allowed'])
        self.assertFalse(recovery.time_admission('plan', start, start + 315.01)['allowed'])
        self.assertEqual(recovery.time_admission('uploads', start, start)['required_seconds'], 1620)
        self.assertEqual(recovery.time_admission('cleanup', start, start)['required_seconds'], 420)
        self.assertFalse(recovery.time_admission('readback', start, start + 2700.01)['allowed'])
        for args in (('unknown', start, start), ('plan', start, start - 1), ('plan', start, float('nan'))):
            with self.subTest(args=args), self.assertRaises(ValueError): recovery.time_admission(*args)

    def metadata(self):
        api = f'https://api.github.com/repos/{recovery.REPOSITORY}/actions/artifacts/{recovery.ARTIFACT_ID}'
        return {'id': recovery.ARTIFACT_ID, 'name': recovery.TRANSPORT_NAME,
                'size_in_bytes': recovery.ZIP_BYTES, 'digest': 'sha256:' + recovery.ZIP_SHA,
                'expired': False, 'created_at': '2026-10-31T12:18:11Z',
                'updated_at': '2026-10-31T12:18:11Z', 'expires_at': '2099-11-07T12:18:11Z',
                'url': api, 'archive_download_url': api + '/zip',
                'workflow_run': {'id': recovery.TRANSPORT_RUN, 'repository_id': recovery.REPOSITORY_ID,
                                 'head_repository_id': recovery.REPOSITORY_ID, 'head_sha': recovery.TRANSPORT_HEAD}}

    def validate(self, value):
        return recovery.metadata_identity(value, recovery.ARTIFACT_ID, recovery.TRANSPORT_NAME,
            recovery.ZIP_BYTES, recovery.ZIP_SHA, recovery.TRANSPORT_RUN, recovery.TRANSPORT_HEAD)

    def test_frozen_original_identity_rejects_old_codec_and_cross_run_data(self):
        self.assertEqual(self.validate(self.metadata())['id'], 13042845270)
        mutations = [lambda m: m.update(id=12523238011), lambda m: m.update(name='arbitrary'),
                     lambda m: m.update(size_in_bytes=753697517), lambda m: m.update(digest='sha256:' + '0' * 64),
                     lambda m: m.update(expired=True), lambda m: m.update(expires_at='2000-01-01T00:00:00Z'),
                     lambda m: m.update(archive_download_url='https://example.com/archive'),
                     lambda m: m['workflow_run'].update(id=1),
                     lambda m: m['workflow_run'].update(head_repository_id=1),
                     lambda m: m['workflow_run'].update(head_sha='a' * 40)]
        for mutation in mutations:
            value = copy.deepcopy(self.metadata()); mutation(value)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.validate(value)

    def test_official_redirect_validator_is_literal_existing_reviewed_policy(self):
        original = ast.parse((ROOT / 'scripts/reference_codec_control.py').read_text())
        new = ast.parse(Path(recovery.__file__).read_text())
        for name in ('NoRedirect', 'artifact_destination'):
            before = next(node for node in original.body if getattr(node, 'name', None) == name)
            after = next(node for node in new.body if getattr(node, 'name', None) == name)
            self.assertEqual(ast.dump(before, include_attributes=False), ast.dump(after, include_attributes=False))
        self.assertEqual(recovery.artifact_destination(
            'https://productionresultssa1.blob.core.windows.net/actions-results/a?sig=synthetic'),
            'productionresultssa1.blob.core.windows.net')
        for url in ('http://productionresultssa1.blob.core.windows.net/actions-results/a?sig=x',
                    'https://evil.example/actions-results/a?sig=x',
                    'https://productionresultssa1.blob.core.windows.net.evil.example/actions-results/a?sig=x',
                    'https://user@productionresultssa1.blob.core.windows.net/actions-results/a?sig=x',
                    'https://productionresultssa1.blob.core.windows.net:444/actions-results/a?sig=x',
                    'https://productionresultssa1.blob.core.windows.net/other/a?sig=x',
                    'https://productionresultssa1.blob.core.windows.net/actions-results/a?sig=x#fragment'):
            with self.subTest(url=url), self.assertRaises(ValueError): recovery.artifact_destination(url)

    def test_api_authentication_never_reaches_delivery_request_or_failure_text(self):
        test = self
        url = 'https://productionresultssa1.blob.core.windows.net/actions-results/a?sig=synthetic-secret'
        requests = []
        class Response(io.BytesIO):
            status = 200
        class API:
            def open(self, request, timeout):
                requests.append(request)
                test.assertTrue(request.full_url.startswith('https://api.github.com/'))
                test.assertEqual(request.get_header('Authorization'), 'Bearer synthetic-token')
                if request.full_url.endswith('/zip'):
                    raise urllib.error.HTTPError(request.full_url, 302, 'redirect', {'Location': url}, None)
                return Response(json.dumps(test.metadata()).encode())
        class Delivery:
            def open(self, request, timeout):
                requests.append(request)
                test.assertEqual(request.full_url, url)
                test.assertIsNone(request.get_header('Authorization'))
                test.assertIsNone(request.get_header('Cookie'))
                return Response(b'fixture')
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'synthetic-token'}), \
                patch.object(recovery.urllib.request, 'build_opener', side_effect=[API(), Delivery()]):
            def consume(response, metadata):
                raise RuntimeError('synthetic-secret signed URL must not escape')
            with self.assertRaises(RuntimeError) as raised:
                recovery.api_transfer(recovery.ARTIFACT_ID, self.validate, consume)
        self.assertNotIn('synthetic-secret', str(raised.exception))
        self.assertNotIn('synthetic-token', str(raised.exception))
        self.assertEqual(len(requests), 3)


class RecoveryByteControls(unittest.TestCase):
    def setUp(self):
        cache = ROOT / '.cache/tmp'; cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='image-recovery-unit-', dir=cache)
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)

    def chunks(self, raw, chunk_bytes=100):
        target = self.folder / ('chunks-' + str(len(list(self.folder.iterdir())))); target.mkdir()
        manifest = recovery.stream_chunks(io.BytesIO(raw), target, total=len(raw), chunk_bytes=chunk_bytes,
                                          expected_sha=hashlib.sha256(raw).hexdigest())
        return target, manifest

    def test_exact_stream_and_random_access_cross_chunk_boundaries(self):
        raw = bytes(range(250)) * 3
        folder, manifest = self.chunks(raw)
        self.assertEqual(len(manifest['chunks']), 8)
        self.assertEqual(sum(item['bytes'] for item in manifest['chunks']), len(raw))
        with recovery.ChunkReader(folder, manifest['chunks'], len(raw), hashlib.sha256(raw).hexdigest()) as reader:
            reader.seek(95); self.assertEqual(reader.read(220), raw[95:315])
            reader.seek(-25, io.SEEK_END); self.assertEqual(reader.read(), raw[-25:])
            for offset in (-1, len(raw) + 1):
                with self.assertRaises(ValueError): reader.seek(offset)
            with self.assertRaises(ValueError): reader.read(2_000_001)

    def test_short_long_and_wrong_hash_streams_preserve_explicit_partial_bytes(self):
        for label, raw, total, expected in (
                ('short', b'abc', 4, hashlib.sha256(b'abcd').hexdigest()),
                ('long', b'abcde', 4, hashlib.sha256(b'abcd').hexdigest()),
                ('hash', b'abcd', 4, '0' * 64)):
            folder = self.folder / label; folder.mkdir()
            with self.subTest(label=label), self.assertRaises(ValueError):
                recovery.stream_chunks(io.BytesIO(raw), folder, total=total, chunk_bytes=2, expected_sha=expected)
            self.assertTrue(list(folder.iterdir()), 'actual partial bytes must remain available')

    def test_manifest_order_inodes_and_content_tampering_fail_closed(self):
        raw = b'a' * 301; folder, manifest = self.chunks(raw)
        changed = copy.deepcopy(manifest['chunks']); changed[0]['number'] = 1
        with self.assertRaises(ValueError): recovery.ChunkReader(folder, changed, len(raw), hashlib.sha256(raw).hexdigest())
        changed = copy.deepcopy(manifest['chunks']); changed[0]['name'] = '../escape'
        with self.assertRaises(ValueError): recovery.ChunkReader(folder, changed, len(raw), hashlib.sha256(raw).hexdigest())
        first = folder / manifest['chunks'][0]['name']; first.write_bytes(b'b' * first.stat().st_size)
        with self.assertRaises(ValueError):
            recovery.ChunkReader(folder, manifest['chunks'], len(raw), hashlib.sha256(raw).hexdigest())

    def zip_bytes(self, members):
        target = io.BytesIO()
        with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_STORED) as archive:
            for name, raw in members: archive.writestr(name, raw)
        return target.getvalue()

    def test_sole_zip_crc_and_image_bytes_through_verified_chunks(self):
        image = b'original synthetic image bytes' * 5
        raw = self.zip_bytes([(recovery.IMAGE_NAME, image)])
        folder, manifest = self.chunks(raw)
        with recovery.ChunkReader(folder, manifest['chunks'], len(raw), hashlib.sha256(raw).hexdigest()) as reader:
            archive, info = recovery.sole_zip(reader, len(raw), recovery.IMAGE_NAME, len(image))
            with archive, archive.open(info) as member: self.assertEqual(member.read(), image)
        damaged = bytearray(raw); local_size = 30 + len(recovery.IMAGE_NAME.encode()); damaged[local_size] ^= 1
        archive, info = recovery.sole_zip(io.BytesIO(damaged), len(damaged), recovery.IMAGE_NAME, len(image))
        with archive, archive.open(info) as member, self.assertRaises(zipfile.BadZipFile): member.read()

    def test_duplicate_extra_path_symlink_encrypted_and_size_controls(self):
        image = b'original'
        duplicate = self.zip_bytes([(recovery.IMAGE_NAME, image), ('extra', b'x')])
        with patch.object(recovery.zipfile, 'ZipFile') as constructor, self.assertRaises(ValueError):
            recovery.sole_zip(io.BytesIO(duplicate), len(duplicate), recovery.IMAGE_NAME, len(image))
        constructor.assert_not_called()
        symbolic = zipfile.ZipInfo(recovery.IMAGE_NAME); symbolic.create_system = 3
        symbolic.external_attr = (stat.S_IFLNK | 0o777) << 16
        raw_cases = [self.zip_bytes([('../' + recovery.IMAGE_NAME, image)]),
                     self.zip_bytes([(symbolic, image)]),
                     self.zip_bytes([(recovery.IMAGE_NAME, image + b'x')])]
        encrypted = bytearray(self.zip_bytes([(recovery.IMAGE_NAME, image)]))
        central = encrypted.index(b'PK\x01\x02')
        struct.pack_into('<H', encrypted, 6, struct.unpack_from('<H', encrypted, 6)[0] | 1)
        struct.pack_into('<H', encrypted, central + 8, struct.unpack_from('<H', encrypted, central + 8)[0] | 1)
        raw_cases.append(encrypted)
        for raw in raw_cases:
            with self.subTest(raw=bytes(raw[:20])), self.assertRaises(ValueError):
                recovery.sole_zip(io.BytesIO(raw), len(raw), recovery.IMAGE_NAME, len(image))

    def test_complete_inventory_hashes_every_file_and_does_not_skip_permission_failures(self):
        root = self.folder / 'original'; root.mkdir()
        (root / 'raw').mkdir(); (root / 'raw/samples').write_bytes(b'actual fixture samples')
        lost = root / 'lost+found'; lost.mkdir()
        original = recovery.os.scandir
        def denied(path):
            if Path(path) == lost: raise PermissionError('synthetic unreadable original directory')
            return original(path)
        with patch.object(recovery.os, 'scandir', side_effect=denied):
            result, files = recovery.walk_inventory(root, self.folder / 'inventory.jsonl')
        self.assertFalse(result['complete']); self.assertEqual(result['status'], 'FAIL')
        self.assertIn('raw/samples', files)
        self.assertEqual(result['errors'][0]['path'], 'lost+found')
        lines = [json.loads(line) for line in (self.folder / 'inventory.jsonl').read_text().splitlines()]
        actual = next(line for line in lines if line['path'] == 'raw/samples')
        self.assertEqual(actual['sha256'], hashlib.sha256(b'actual fixture samples').hexdigest())

    def test_inventory_hardlinks_and_entry_ceiling_never_claim_complete(self):
        root = self.folder / 'original'; root.mkdir(); (root / 'first').write_bytes(b'x')
        try: os.link(root / 'first', root / 'second')
        except OSError: self.skipTest('Host does not permit a tiny hardlink fixture')
        result, _ = recovery.walk_inventory(root, self.folder / 'linked.jsonl')
        self.assertEqual(result['status'], 'FAIL'); self.assertFalse(result['complete'])
        result, _ = recovery.walk_inventory(root, self.folder / 'bounded.jsonl', max_entries=2)
        self.assertFalse(result['complete'])


class RecoveryWorkflowControls(unittest.TestCase):
    def test_recovery_routing_guards_and_eight_fixed_uploads(self):
        text = (ROOT / '.github/workflows/release-evidence.yml').read_text()
        codec = text.split('\n  codec:\n', 1)[1].split('\n  conflicting_controls:\n', 1)[0]
        self.assertIn('timeout-minutes: 60', codec)
        self.assertIn('actions: read', codec)
        for block in codec.split('      - name:')[1:]:
            if 'reference_codec_control.py' in block:
                self.assertIn('!inputs.image_recovery', block)
        self.assertEqual(codec.count('path: ${{ runner.temp }}/facetquarry-image-recovery/chunks/zip.part-'), 8)
        self.assertEqual(codec.count('FQ_RECOVERY_ARTIFACT_'), 8)
        self.assertIn('reference_image_recovery.py readback', codec)
        self.assertIn('reference_image_recovery.py clock', codec)
        self.assertNotIn('reference_guest.py', codec)
        self.assertNotIn('make verify', codec)
        self.assertIn("test '${{ inputs.codec_control }}' = true", codec)
        guard = codec.index('Validate exclusive image mode before quota, installation or artifact download')
        self.assertLess(guard, codec.index('reference_codec_control.py quota'))
        self.assertLess(guard, codec.index('reference_image_recovery.py quota'))
        self.assertLess(guard, codec.index('reference_image_recovery.py download'))
        for name in ('reference', 'reference_capacity'):
            branch = re.split(r'\n  [a-z_]+:\n', text.split('\n  ' + name + ':\n', 1)[1])[0]
            self.assertLess(branch.index('Refuse image recovery outside its explicitly selected codec job before growth'),
                            branch.index('fallocate -l'))

    def test_actual_codec_mode_guard_refuses_every_unsupported_combination(self):
        bash = shutil.which('bash')
        if os.name == 'nt' and Path('C:/Program Files/Git/bin/bash.exe').is_file():
            bash = 'C:/Program Files/Git/bin/bash.exe'
        if not bash: self.skipTest('Bash unavailable; actual mode guard control remains NOT RUN')
        text = (ROOT / '.github/workflows/release-evidence.yml').read_text()
        selected = text.split('      - name: Validate exclusive image mode before quota, installation or artifact download\n', 1)[1]
        block = selected.split('        run: |\n', 1)[1].split('      - name:', 1)[0]
        script = '\n'.join(line[10:] for line in block.splitlines())
        valid = {'codec_control': 'true', 'capacity_control': 'false', 'preservation_control': 'false',
                 'trim_control': 'false', 'profile': 'smoke', 'concurrency': '1'}
        cases = [valid] + [{**valid, key: value} for key, value in (
            ('codec_control', 'false'), ('capacity_control', 'true'), ('preservation_control', 'true'),
            ('trim_control', 'true'), ('profile', 'full'), ('profile', 'diagnostic'),
            ('concurrency', '4'), ('concurrency', '16'))]
        for values in cases:
            concrete = re.sub(r'\$\{\{ inputs\.([a-z_]+) \}\}', lambda match: values[match[1]], script)
            result = subprocess.run([bash, '--noprofile', '--norc', '-c', concrete],
                                    capture_output=True, text=True, timeout=5)
            with self.subTest(values=values): self.assertEqual(result.returncode == 0, values == valid)


if __name__ == '__main__': unittest.main()
