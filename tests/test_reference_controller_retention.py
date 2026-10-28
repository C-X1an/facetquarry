"""Real diagnostic bytes and proof bindings; no hosted execution claim."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_artifacts as artifacts
import reference_pipeline as pipeline


class ControllerRetention(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[1] / '.cache/controller-retention-tests'
        cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=cache)
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).absolute()
        self.root = self.base / 'checkout'
        self.local = self.root / '.local'
        self.local.mkdir(parents=True)
        self.volume = self.base / 'volume'
        self.volume.mkdir()
        environment = patch.dict(os.environ, {
            'GITHUB_RUN_ID': '123456789', 'GITHUB_SHA': 'a' * 40,
            'RUNNER_TEMP': str(self.base),
        })
        environment.start()
        self.addCleanup(environment.stop)

    def packet_bytes(self):
        output = self.base / 'packet'
        record = artifacts.metadata_packet(self.local, output)
        self.assertEqual(record['status'], 'PASS', record)
        self.assertEqual(record['failures'], [])
        self.assertEqual(record['reductions'], [])
        self.assertTrue(record['enumeration_complete'])
        retained = {}
        for entry in record['files']:
            raw = (output / entry['export_path']).read_bytes()
            self.assertEqual(entry['transformation'], 'identity')
            self.assertEqual(entry['original_bytes'], len(raw))
            self.assertEqual(entry['export_bytes'], len(raw))
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual(entry['original_sha256'], digest)
            self.assertEqual(entry['export_sha256'], digest)
            retained[entry['path']] = raw
        self.assertLessEqual(sum(p.stat().st_size for p in output.rglob('*') if p.is_file()), 35_000_000)
        self.assertLessEqual(len(record['files']) + 1, 3000)
        return retained

    def test_all_phase_captures_and_actual_refusal_names_survive_packet(self):
        expected = {}
        for phase in ('pack', 'verify', 'reconcile'):
            for stream in ('stdout', 'stderr'):
                name = f'reference-transport/{phase}-supervisor-{stream}.txt'
                # Exercise a full admitted combined capture per phase.
                raw = (phase + stream).encode().ljust(500_000, b'\x00')
                expected[name] = raw
            name = f'reference-transport-{phase}-refusal.json'
            expected[name] = json.dumps({'phase': phase, 'status': 'FAIL'}).encode().ljust(32_768, b' ')
        for name, raw in expected.items():
            path = self.local / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
        (self.local / 'reference-transport/unselected.bin').write_bytes(b'not a selected diagnostic')
        self.assertEqual(self.packet_bytes(), expected)

    def test_empty_supervisor_captures_remain_explicit_packet_members(self):
        expected = {}
        for phase in ('pack', 'verify', 'reconcile'):
            for stream in ('stdout', 'stderr'):
                name = f'reference-transport/{phase}-supervisor-{stream}.txt'
                path = self.local / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(b'')
                expected[name] = b''
        self.assertEqual(self.packet_bytes(), expected)

    def test_internal_freeze_proofs_preserve_complete_original_bytes_and_digest(self):
        expected = {}
        for name in ('reference-results-freeze.json', 'reference-results-reconciled-freeze.json'):
            raw = ('{\n  "status" : "PASS", "source":"fixture",\n'
                   '  "complete_nested_proof":{"identity":[7,11],"commands":[{"exit":0}]},\n'
                   '  "original_failure":{"status":"FAIL","reason":"retained"}\n}\n').encode()
            (self.volume / name).write_bytes(raw)
            expected[name] = raw
        result = pipeline.final_state(self.volume, self.root, profile='reference-inside-outer-v1')
        self.assertEqual(result['status'], 'PASS')
        retained = self.packet_bytes()
        for name, raw in expected.items():
            self.assertEqual((self.local / name).read_bytes(), raw)
            self.assertEqual(retained[name], raw)
            self.assertEqual(hashlib.sha256(retained[name]).hexdigest(), hashlib.sha256(raw).hexdigest())

    def test_internal_freeze_copy_rejects_oversize_before_output_creation(self):
        name = 'reference-results-reconciled-freeze.json'
        raw = json.dumps({'status': 'PASS', 'complete': 'x' * 1_000_000}).encode()
        (self.volume / name).write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'complete-copy admission'):
            pipeline.final_state(self.volume, self.root, profile='reference-inside-outer-v1')
        self.assertFalse((self.local / name).exists())
        self.assertFalse((self.local / 'reference-job-state.json').exists())
        self.assertEqual((self.volume / name).read_bytes(), raw)

    def test_internal_freeze_copy_rejects_directory_instead_of_reporting_success(self):
        name = 'reference-results-freeze.json'
        (self.volume / name).mkdir()
        with self.assertRaisesRegex(ValueError, 'unsafe diagnostic source'):
            pipeline.final_state(self.volume, self.root, profile='reference-inside-outer-v1')
        self.assertFalse((self.local / name).exists())

    def test_internal_freeze_copy_rejects_hardlinked_source(self):
        name = 'reference-results-freeze.json'
        source = self.volume / name
        source.write_bytes(b'{"status":"PASS","full":{"proof":true}}\n')
        os.link(source, self.base / 'source-alias')
        with self.assertRaisesRegex(ValueError, 'unsafe diagnostic source'):
            pipeline.final_state(self.volume, self.root, profile='reference-inside-outer-v1')
        self.assertFalse((self.local / name).exists())

    def test_internal_freeze_copy_refuses_differing_existing_copy(self):
        name = 'reference-results-reconciled-freeze.json'
        (self.volume / name).write_bytes(b'{"status":"PASS","full":{"proof":true}}\n')
        original = b'earlier independently retained bytes'
        (self.local / name).write_bytes(original)
        with self.assertRaises((ValueError, FileExistsError)):
            pipeline.final_state(self.volume, self.root, profile='reference-inside-outer-v1')
        self.assertEqual((self.local / name).read_bytes(), original)

    def test_legacy_freeze_projection_remains_unchanged(self):
        name = 'reference-results-freeze.json'
        proof = {'status': 'FAIL', 'source': 'fixture', 'error': 'retained',
                 'complete_nested_proof': {'legacy': 'not projected'}}
        (self.volume / name).write_text(json.dumps(proof))
        result = pipeline.final_state(self.volume, self.root)
        self.assertEqual(result['status'], 'PASS')
        projection = json.loads((self.local / name).read_text())
        self.assertEqual(projection, {key: proof.get(key) for key in (
            'status', 'source', 'run_context', 'image_path', 'image_bytes', 'image_sha256',
            'image_unmounted', 'selected_path', 'zip_upper_bound_bytes', 'scope', 'error')})


if __name__ == '__main__':
    unittest.main()
