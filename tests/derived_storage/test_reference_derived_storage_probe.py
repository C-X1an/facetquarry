"""Draft adversarial controls, authored before implementation; NOT RUN."""
import contextlib
import hashlib
import gzip
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PUBLIC = HERE.parents[1]
sys.path.insert(0, str(PUBLIC / 'scripts'))
sys.path.insert(0, str(HERE.parent / 'derived_measurement_draft_20261106'))
sys.path.insert(0, str(HERE))
import reference_derived_storage_probe as probe


class DerivedStorageControls(unittest.TestCase):
    def test_distinct_geometry_growth_and_deadline(self):
        self.assertEqual(probe.PROFILE, 'run38-derived-storage-readonly-v1')
        self.assertEqual(probe.GROWTH, 2_250_000_000)
        self.assertEqual(probe.JOB_SECONDS, 3600)
        self.assertEqual(sum(probe.STAGES.values()), 2745)
        self.assertEqual(probe.STAGES['derive'], 1200)
        self.assertEqual(probe.growth_plan(9_750_000_000)['admission'], 'REFUSE')
        self.assertEqual(probe.growth_plan(9_749_999_999)['admission'], 'ALLOW')

    def test_path_traversal_absolute_escape_backslash_and_wrong_candidate_refuse(self):
        root = Path('/tmp/readonly')
        for path in ['../escape', '/tmp/x', 'benchmarks/../x', 'a\\b', 'a//b', 'a/./b', '']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                probe.confined(root, path)
        inventory = [{'path': 'benchmarks/full-wrong/a.samples.jsonl.gz', 'type': 'regular'}]
        with self.assertRaises(ValueError):
            probe.select_candidates(inventory)

    def test_missing_extra_duplicate_sample_or_summary_refuse(self):
        cell = 'a' * 20
        a = {'path': probe.CANDIDATE + '/' + cell + '.samples.jsonl.gz', 'type': 'regular'}
        b = {'path': probe.CANDIDATE + '/' + cell + '.summary.json', 'type': 'regular'}
        with patch.object(probe, 'EXPECTED_PAIRS', 1):
            self.assertEqual(probe.select_candidates([a, b]), [cell])
            for rows in [[a], [b], [a, b, a], [a, b, {'path': probe.CANDIDATE + '/coverage.json', 'type': 'regular'}]]:
                with self.subTest(rows=rows), self.assertRaises(ValueError):
                    probe.select_candidates(rows)

    def test_measurement_attempt_must_be_exact_single_original_record(self):
        attempt = {'attempt_id': '123-aabbccdd', 'stage': 'measurement', 'status': 'PASS'}
        summary = {'source': probe.HISTORICAL_SOURCE, 'stage': 'measurement', 'attempts': [attempt]}
        self.assertEqual(probe.select_attempt(summary), attempt)
        for wrong in [{**summary, 'source': 'a'*64}, {**summary, 'attempts': []}, {**summary, 'attempts': [attempt, attempt]}, {**summary, 'attempts': [{**attempt, 'attempt_id': '../x'}]}]:
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                probe.select_attempt(wrong)

    def test_stream_metadata_exact_path_hash_type_and_cap(self):
        aid = '123-aabbccdd'
        stream = {'path': 'attempts/' + aid + '/stdout.txt.gz', 'sha256': 'a'*64, 'raw_sha256': 'b'*64, 'raw_bytes': 4}
        self.assertEqual(probe.validate_stream(stream, aid, 'stdout'), stream)
        for patch_value in [{'path': '../../x'}, {'sha256': 'bad'}, {'raw_bytes': True}, {'raw_bytes': 8*1024*1024+1}]:
            with self.subTest(patch_value=patch_value), self.assertRaises(ValueError):
                probe.validate_stream({**stream, **patch_value}, aid, 'stdout')

    def test_prewrite_bound_preserves_partial_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'partial'
            with patch.object(probe, 'external'):
                with self.assertRaises(ValueError):
                    with probe.BoundedOutput(path, 3).open('xb') as output:
                        output.write(b'ab')
                        output.write(b'cd')
            self.assertEqual(path.read_bytes(), b'ab')

    def test_partial_quota_exact_cleanup_and_mismatch_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            local = Path(temporary); ctx = {'source': 'a'*64}
            p = {'local': local, 'mount': local/'inner', 'volume': local/'outer-mount', 'image': local/'image', 'outer': local/'outer'}
            for binding, expected in [([1,2,3], 'PASS'), ([9,9,9], 'FAIL')]:
                allocation = {'run_context': ctx, 'image_path': str(p['outer']), 'mount_path': str(p['volume']), 'image_identity': binding}
                with contextlib.ExitStack() as stack:
                    stack.enter_context(patch.object(probe, 'admitted', return_value=(p,ctx)))
                    stack.enter_context(patch.object(probe.os.path, 'ismount', side_effect=lambda x:x == p['volume']))
                    stack.enter_context(patch.object(probe, 'outer', side_effect=FileNotFoundError()))
                    stack.enter_context(patch.object(probe, 'load', return_value=allocation))
                    stack.enter_context(patch.object(probe, 'backing_identity', return_value=[1,2,3]))
                    stack.enter_context(patch.object(probe, 'save'))
                    close = stack.enter_context(patch.object(probe, 'close_exact', return_value={'status':'PASS'}))
                    self.assertEqual(probe.cleanup()['status'], expected)
                    self.assertEqual(close.call_count, expected == 'PASS')

    def test_complete_cost_includes_identity_metadata_and_recipe(self):
        cost = probe.cost_record(original_bytes=100, recipe_bytes=12, ledger_bytes=13,
                                 retained_metadata_bytes=14, identity_bytes=15, raw_attempt_bytes=16)
        self.assertEqual(cost['encoded_representation_bytes'], 70)
        self.assertEqual(cost['originals_retired_bytes'], 0)
        self.assertFalse(cost['scientific_qualification'])

    def test_stage_binding_requires_derive_before_successful_cleanup_export(self):
        self.assertEqual(list(probe.STAGES), ['plan','quota','download','extract','observe','derive','cleanup','export'])
        self.assertEqual(probe.file_limit('derived-recipes.jsonl.gz'), probe.DERIVE_OUTPUT_BYTES)
        self.assertEqual(probe.file_limit('derived-ledger.jsonl'), probe.DERIVE_OUTPUT_BYTES)

    def test_failed_cell_retains_real_originals_and_tampered_attempt_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); cell_record = {'mode': 'graph', 'ef': 4}
            cell = hashlib.sha256(json.dumps(cell_record, sort_keys=True).encode()).hexdigest()[:20]
            folder = root.joinpath(*probe.CANDIDATE.split('/')); attempt_id = '123-aabbccdd'
            target = folder/'attempts'/attempt_id; target.mkdir(parents=True)
            streams = {}
            for label, raw in [('stdout', b'partial malformed output\n'), ('stderr', b'failed')]:
                encoded = gzip.compress(raw, mtime=0); (target/(label+'.txt.gz')).write_bytes(encoded)
                streams[label] = {'path': f'attempts/{attempt_id}/{label}.txt.gz',
                    'sha256': hashlib.sha256(encoded).hexdigest(), 'raw_sha256': hashlib.sha256(raw).hexdigest(), 'raw_bytes': len(raw)}
            attempt = {'attempt_id': attempt_id, 'stage': 'measurement', 'status': 'FAIL', 'streams': streams}
            (target/'attempt.json').write_text(json.dumps(attempt))
            sample = gzip.compress(b'', mtime=0); (folder/(cell+'.samples.jsonl.gz')).write_bytes(sample)
            summary = {'source': probe.HISTORICAL_SOURCE, 'stage': 'measurement', 'cell': cell_record,
                'attempts': [attempt], 'samples_sha256': hashlib.sha256(sample).hexdigest()}
            (folder/(cell+'.summary.json')).write_text(json.dumps(summary))
            files = {}
            for path in root.rglob('*'):
                if path.is_file():
                    raw = path.read_bytes(); files[path.relative_to(root).as_posix()] = {'type':'regular','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
            before = {name: (root/name).read_bytes() for name in files}
            result, recipe = probe.derive_cell(root, cell, files)
            self.assertEqual(result['mode'], 'identity'); self.assertIsNone(recipe)
            (target/'attempt.json').write_text('{}')
            result, recipe = probe.derive_cell(root, cell, files)
            self.assertEqual(result['mode'], 'refused'); self.assertIsNone(recipe)
            for name, raw in before.items():
                if name.endswith('/attempt.json'): continue
                self.assertEqual((root/name).read_bytes(), raw)

    def test_shared_output_cap_refuses_before_cross_file_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            shared = {'written':0}; root = Path(temporary)
            with patch.object(probe, 'external'), patch.object(probe, 'DERIVE_OUTPUT_BYTES', 3):
                with probe.BoundedOutput(root/'a', 10, shared).open('xb') as first:
                    first.write(b'ab')
                with self.assertRaises(ValueError):
                    with probe.BoundedOutput(root/'b', 10, shared).open('xb') as second:
                        second.write(b'cd')
                self.assertEqual((root/'b').read_bytes(), b'')

    def test_workflow_patch_keeps_top_level_job_conditions_unchanged(self):
        patch_text = (HERE/'workflow.patch').read_text()
        for condition in [
            '    if: ${{ !inputs.codec_control && !inputs.capacity_control }}',
            '    if: ${{ inputs.codec_control && !inputs.capacity_control && !inputs.preservation_control }}',
            "    if: ${{ (inputs.codec_control && inputs.preservation_control) || (inputs.capacity_control && (inputs.codec_control || inputs.preservation_control || inputs.profile != 'smoke' || inputs.concurrency != '1')) }}",
            "    if: ${{ inputs.capacity_control && !inputs.codec_control && !inputs.preservation_control && inputs.profile == 'smoke' && inputs.concurrency == '1' }}"]:
            self.assertNotIn('-'+condition+'\n', patch_text)
        self.assertIn('+      derived_storage_probe:', patch_text)
        self.assertIn('+          FQ_RESERVATION_PROFILE: run38-derived-storage-readonly-v1', patch_text)
        self.assertNotIn('-        if: ${{ inputs.retained_image_probe }}', patch_text)


if __name__ == '__main__':
    unittest.main()
