"""Real tiny codec children; mounted-quota orchestration is fixture-only here."""
from contextlib import ExitStack
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
import evidence_bundle as bundle
import reference_artifacts as artifacts
import reference_codec_control as control
from test_reference_codec_control import legacy_fixture


class CodecPresetControls(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[1] / '.cache/codec-preset-tests'
        cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=cache)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.volume = self.root / 'volume'
        (self.volume / 'input').mkdir(parents=True)
        self.metadata = self.root / 'metadata'
        self.metadata.mkdir()
        self.output = self.root / 'transport/reference-members.tar.xz'
        self.output.parent.mkdir()
        _, _, compressed, entries = legacy_fixture()
        (self.volume / 'input/legacy-members.tar.xz').write_bytes(compressed)
        (self.metadata / 'input-binding.json').write_text('{"run_context":{}}', encoding='ascii')
        paths = {'volume': self.volume, 'metadata': self.metadata, 'output': self.output}
        self.stack = self.enterContext(ExitStack())
        for patch in (mock.patch.object(control, 'admitted', return_value=(paths, {})),
                      mock.patch.object(control, 'mounted'),
                      mock.patch.object(control, 'context', return_value={}),
                      mock.patch.object(control, 'INNER_BYTES', len(compressed)),
                      mock.patch.object(control, 'INNER_SHA', hashlib.sha256(compressed).hexdigest()),
                      mock.patch.object(control, 'HISTORICAL_MEMBERS', len(entries)),
                      mock.patch.dict(os.environ, {'GITHUB_RUN_ID': '12345678901'})):
            self.stack.enter_context(patch)
        # Windows lacks getuid. This fixture supplies its native owner value;
        # it does not establish Linux ownership, mount or hard-quota enforcement.
        if not hasattr(os, 'getuid'):
            self.stack.enter_context(mock.patch.object(os, 'getuid', return_value=0, create=True))
        self.recovery = control.recover()

    def direct_pack(self, preset):
        result = artifacts.run_pack(self.volume / 'data', self.output, control.HISTORICAL_SOURCE,
                                    control.HISTORICAL_COMMIT, 'codec-control-12345678901',
                                    30, preset, progress=True)
        self.assertEqual(result['status'], 'PASS', result)
        return result

    def manifest(self):
        with self.output.open('rb') as compressed:
            return json.loads(bundle.transport_item(bundle.XZReader(compressed),
                                                     'manifest.json', bundle.MAX_MANIFEST))

    def test_controller_requests_preset6_and_real_child_roundtrips_with_progress(self):
        result = control.pack()
        self.assertEqual(result['preset'], 6)
        self.assertTrue(result['progress_enabled'])
        self.assertEqual(self.manifest()['compression'],
                         {'preset': 6, 'dictionary_bytes': 64 * 1024 * 1024})
        events = [json.loads(line) for line in
                  (self.output.parent / 'pack-stderr.txt').read_text().splitlines()]
        self.assertTrue(any(event['phase'] == 'internal_verification'
                            and event['event'] == 'end' for event in events))
        verified = control.verify()
        self.assertEqual(verified['preset'], 6)
        self.assertEqual(verified['dictionary_bytes'], 64 * 1024 * 1024)
        self.assertEqual(verified['all_original_members_compared'], 4)
        self.assertTrue(verified['actual_recovered_modes_unchanged'])
        self.assertEqual(control.snapshot(self.volume / 'data'),
                         control.rows_read(self.metadata, 'recovered-members')[0])

    def test_valid_preset3_transport_is_rejected_by_preset6_experiment(self):
        self.direct_pack(3)
        self.assertEqual(bundle.verify(self.output)['status'], 'PASS')
        with self.assertRaisesRegex(ValueError, 'compression parameters differ'):
            control.verify()

    def test_recomputed_valid_xz_cannot_substitute_dictionary_declaration(self):
        self.direct_pack(6)
        unpacked = lzma.decompress(self.output.read_bytes())
        with tarfile.open(fileobj=io.BytesIO(unpacked), mode='r:') as archive:
            members = [(member.name, archive.extractfile(member).read())
                       for member in archive.getmembers()]
        manifest = json.loads(members[0][1])
        manifest['compression']['dictionary_bytes'] = 16 * 1024 * 1024
        members[0] = ('manifest.json', json.dumps(manifest, sort_keys=True,
                                                  separators=(',', ':')).encode())
        changed = io.BytesIO()
        with tarfile.open(fileobj=changed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in members:
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        self.output.write_bytes(lzma.compress(changed.getvalue(), check=lzma.CHECK_SHA256,
            filters=[{'id': lzma.FILTER_LZMA2, 'preset': 6, 'dict_size': 64 * 1024 * 1024}]))
        self.assertEqual(bundle.verify(self.output)['status'], 'PASS')
        with self.assertRaisesRegex(ValueError, 'compression parameters differ'):
            control.verify()


if __name__ == '__main__':
    unittest.main()
