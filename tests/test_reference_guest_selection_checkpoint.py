"""Bounded synthetic manifest controls; no guest, mount or deletion is executed."""
import hashlib
from contextlib import nullcontext
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_internal_transport as transport
import reference_artifacts as artifacts


class GuestSelectionCheckpointControls(unittest.TestCase):
    def test_narrow_manifest_transport_does_not_expand_other_critical_capture_limits(self):
        path = self.p['local'] / 'reference-upload-admission.json'
        original = b'x' * 1_000_001
        path.write_bytes(original)
        output = self.p['outer'] / 'ordinary-packet'
        packet = artifacts.metadata_packet(self.p['local'], output)
        self.assertEqual(packet['status'], 'FAIL')
        self.assertTrue(packet['failures'])
        row = next(x for x in packet['files'] if x['path'] == path.name)
        self.assertEqual(row['export_bytes'], 1_000_000)
        self.assertEqual(row['original_bytes'], 1_000_001)
        self.assertNotEqual(row['transformation'], 'identity')
        self.assertEqual((output / row['export_path']).read_bytes(), original[:1_000_000])

    def test_complete_refusal_checkpoint_above_one_mb_survives_actual_packet_roundtrip(self):
        provenance = {'entries': [{'path': 'reference-guest/' + 'group/' * 110 + str(i)}
                                  for i in range(2000)],
                      'logical_bytes': 125265213, 'accounted_bytes': 125272064}
        observed = self.refused(provenance, 'complete guest provenance exceeds admission')
        original = (self.p['audit'] / 'guest-selection-manifests.json').read_bytes()
        self.assertGreater(len(original), 1_000_000)
        self.assertLess(len(original), 8_000_000)
        output = self.p['outer'] / 'packet'
        packet = artifacts.metadata_packet(self.p['local'], output)
        self.assertEqual(packet['status'], 'PASS')
        self.assertEqual(packet['failures'], [])
        self.assertEqual(packet['reductions'], [])
        self.assertTrue(packet['enumeration_complete'])
        self.assertFalse(packet['complete_scientific_preservation'])
        row = next(x for x in packet['files'] if x['path'] == 'reference-transport/guest-selection-manifests.json')
        self.assertEqual(row['transformation'], 'identity')
        retained = (output / row['export_path']).read_bytes()
        self.assertEqual(retained, original)
        self.assertEqual(row['original_sha256'], observed['complete_manifests_sha256'])
        self.assertEqual(row['original_sha256'], row['export_sha256'])
        self.assertLessEqual(sum(path.stat().st_size for path in output.rglob('*') if path.is_file()),
                             artifacts.METADATA_BYTES)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name).absolute()
        volume, outer = folder / 'volume', folder / 'outer'
        (volume / 'source/.local').mkdir(parents=True)
        (outer / '.local/reference-transport').mkdir(parents=True)
        self.p = {'volume': volume, 'project': volume / 'source', 'outer': outer,
                  'local': outer / '.local', 'audit': outer / '.local/reference-transport'}
        self.ctx = {'source': 'a' * 64, 'commit': 'b' * 40, 'git_status': '',
                    'github_run_id': '1', 'github_run_attempt': '1'}
        self.removal = {'entries': [{'path': 'reference-guest/packages', 'kind': 'directory'}],
                        'logical_bytes': 0, 'accounted_bytes': 0}

    def refused(self, provenance, expected, **changes):
        with patch.object(transport.sys, 'platform', 'linux'), \
                patch.object(transport.os, 'getuid', return_value=1001, create=True), \
                patch.object(transport, 'closed_guest'), \
                patch.object(transport, 'guest_selections', return_value=([self.p['volume'] / 'payload'], [])), \
                patch.object(transport, 'owned_manifest', side_effect=[self.removal, provenance]), \
                patch.object(transport, 'copy_manifest') as copied, \
                patch.object(transport.preflight, 'delete_linux') as deleted, \
                (patch.multiple(transport, **changes) if changes else nullcontext()):
            with self.assertRaisesRegex(ValueError, expected):
                transport.trim_guest.__wrapped__(self.p, self.ctx)
        copied.assert_not_called()
        deleted.assert_not_called()
        return json.loads((self.p['audit'] / 'guest-selection-observed.json').read_bytes())

    def test_run31_sized_manifest_is_preserved_before_unchanged_byte_refusal(self):
        # Exact observed postdownload cache sizes, synthetic manifests only.
        entries = [{'path': 'reference-guest/apt/pkgcache.bin', 'kind': 'file', 'bytes': 62663961},
                   {'path': 'reference-guest/apt/srcpkgcache.bin', 'kind': 'file', 'bytes': 62601252}]
        provenance = {'entries': entries, 'logical_bytes': 125265213, 'accounted_bytes': 125272064}
        observed = self.refused(provenance, 'complete guest provenance exceeds admission')
        self.assertEqual(observed['status'], 'OBSERVED_UNVALIDATED')
        self.assertEqual(observed['run_context'], self.ctx)
        self.assertEqual(observed['provenance_logical_bytes'], 125265213)
        self.assertEqual(observed['provenance_accounted_bytes'], 125272064)
        self.assertEqual(observed['provenance_entries'], 2)
        self.assertEqual(observed['logical_byte_limit'], 80_000_000)
        self.assertEqual(observed['entry_limit'], 10_000)
        self.assertTrue(observed['complete_manifests_retained'])
        raw = (self.p['audit'] / 'guest-selection-manifests.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), observed['complete_manifests_sha256'])
        full = json.loads(raw)
        self.assertEqual(full['provenance_manifest'], provenance)
        self.assertEqual(full['removal_manifest'], self.removal)
        self.assertFalse((self.p['audit'] / 'guest-provenance').exists())

    def test_entry_refusal_keeps_complete_manifest_and_unchanged_limit(self):
        provenance = {'entries': [{'path': f'reference-guest/file{i}'} for i in range(10_001)],
                      'logical_bytes': 0, 'accounted_bytes': 0}
        observed = self.refused(provenance, 'complete guest provenance exceeds admission')
        self.assertEqual(observed['provenance_entries'], 10_001)
        self.assertEqual(observed['entry_limit'], 10_000)
        full = json.loads((self.p['audit'] / 'guest-selection-manifests.json').read_bytes())
        self.assertEqual(full['provenance_manifest'], provenance)

    def test_complete_checkpoint_overflow_retains_explicit_summary_without_partial_full_file(self):
        provenance = {'entries': [{'path': 'reference-guest/' + 'x' * 1024}],
                      'logical_bytes': 0, 'accounted_bytes': 0}
        observed = self.refused(provenance, 'complete guest selection observation exceeds', TRIM_PROOF_BYTES=512)
        self.assertFalse(observed['complete_manifests_retained'])
        self.assertGreater(observed['complete_manifests_encoded_bytes'], 512)
        self.assertFalse((self.p['audit'] / 'guest-selection-manifests.json').exists())


if __name__ == '__main__':
    unittest.main()
