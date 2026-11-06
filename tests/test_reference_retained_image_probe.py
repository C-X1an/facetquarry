"""New tiny probe controls; no benchmark, network, mount or quota qualification."""
import ast
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import reference_retained_image_probe as probe


class RetainedMetadataProbeControls(unittest.TestCase):
    def setUp(self):
        cache = ROOT / '.cache/tmp'; cache.mkdir(parents=True, exist_ok=True)
        temp = tempfile.TemporaryDirectory(prefix='retained-probe-control-', dir=cache)
        self.addCleanup(temp.cleanup); self.local = Path(temp.name)

    def test_growth_reserves_outer_external_cloud_and_failure_overhead_once(self):
        result = probe.growth_plan(9_520_000_000)
        self.assertEqual(result['maximum_new_bytes'], 2_210_000_000)
        self.assertEqual(result['peak_bytes'], 11_730_000_000)
        self.assertEqual(result['admission'], 'ALLOW')
        self.assertEqual(result['outer_image_bytes'], 2_100_000_000)
        self.assertEqual(result['cloud_metadata_bytes'], 10_000_000)

    def test_global_ceiling_and_fresh_baseline_refuse_without_waiver(self):
        self.assertEqual(probe.growth_plan(probe.CEILING - probe.GROWTH)['admission'], 'REFUSE')
        for value in (True, 1_999_999_999, -1):
            with self.subTest(value=value), self.assertRaises(ValueError): probe.growth_plan(value)

    def test_published_inputs_pin_all_eight_distinct_original_artifacts(self):
        rows, sha = probe.inputs()
        self.assertEqual(tuple(row['id'] for row in rows), probe.INPUT_IDS)
        self.assertEqual(len(set(row['id'] for row in rows)), 8)
        self.assertEqual(sum(row['raw_member_bytes'] for row in rows), probe.recovery.ZIP_BYTES)
        self.assertRegex(sha, r'^[0-9a-f]{64}$')
        self.assertNotIn(probe.recovery.ARTIFACT_ID, probe.INPUT_IDS)

    def test_fixed_input_identity_and_geometry_cannot_be_reselected(self):
        original = json.loads((ROOT / 'verification/published/run38-retention-run39-fixture-controls.json').read_text())
        target = self.local / 'verification/published/run38-retention-run39-fixture-controls.json'
        target.parent.mkdir(parents=True)
        for field, value in (('id', 1), ('name', 'other'), ('raw_member_bytes', 3), ('digest', 'sha256:invalid')):
            mutated = copy.deepcopy(original); mutated['retained_chunk_artifacts'][0][field] = value
            target.write_text(json.dumps(mutated))
            with self.subTest(field=field), patch.object(probe, 'ROOT', self.local), self.assertRaises(ValueError):
                probe.inputs()

    def test_actual_tiny_wrapper_requires_pinned_SHA_and_exhausted_member_CRC(self):
        payload = b'actual bounded chunk bytes'; stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
            archive.writestr('zip.part-00', payload)
        original = stream.getvalue()
        for case in ('valid', 'wrong-sha', 'bad-crc'):
            folder = self.local / case; folder.mkdir(); chunks = folder / 'chunks'; chunks.mkdir()
            raw = bytearray(original)
            if case == 'bad-crc': raw[raw.find(payload)] ^= 1
            wrapper = folder / 'wrapper.zip'; wrapper.write_bytes(raw)
            row = {'size_in_bytes':len(raw), 'digest':'sha256:'+hashlib.sha256(raw).hexdigest(),
                   'raw_member_bytes':len(payload), 'raw_member_sha256':hashlib.sha256(payload).hexdigest()}
            if case == 'wrong-sha': row['digest'] = 'sha256:'+'0'*64
            with self.subTest(case=case):
                if case == 'valid':
                    result = probe.decode_wrapper({'wrapper':wrapper,'chunks':chunks},row,0)
                    self.assertTrue(result['crc_verified'])
                    self.assertEqual((chunks/'zip.part-00').read_bytes(),payload)
                    self.assertTrue(wrapper.exists())
                else:
                    with self.assertRaises((ValueError,zipfile.BadZipFile)):
                        probe.decode_wrapper({'wrapper':wrapper,'chunks':chunks},row,0)

    def test_missing_coverage_with_real_partial_files_is_explicit_observation(self):
        folder = self.local / 'benchmarks/full-synthetic'; folder.mkdir(parents=True)
        (folder / 'one.summary.json').write_text('{}')
        (folder / 'one.samples.jsonl.gz').write_bytes(b'fixture')
        files = ['benchmarks/full-synthetic/one.summary.json', 'benchmarks/full-synthetic/one.samples.jsonl.gz']
        result = probe.candidate_observation(self.local, files)
        row = result['candidates'][0]
        self.assertEqual(result['coverage_candidates'], 0)
        self.assertEqual(row['metadata']['coverage.json'], {'state': 'ABSENT'})
        self.assertEqual((row['summary_files'], row['sample_files']), (1, 1))
        self.assertEqual(result['analysis'], 'NOT_RUN')
        self.assertFalse(result['coverage_synthesized'])
        self.assertFalse((folder / 'coverage.json').exists())

    def test_coverage_identity_is_observed_without_accepting_historical_results(self):
        folder = self.local / 'benchmarks/full-synthetic'; folder.mkdir(parents=True)
        raw = json.dumps({'source':'b'*64,'profile':'full','config':{'concurrency':16},
                          'expected_cells':5400,'completed_cells':17,'status':'FAIL'}).encode()
        (folder / 'coverage.json').write_bytes(raw)
        result = probe.candidate_observation(self.local, ['benchmarks/full-synthetic/coverage.json'])
        value = result['candidates'][0]['metadata']['coverage.json']
        self.assertEqual(value['sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(value['source'], 'b'*64)
        self.assertEqual(value['concurrency'],16)
        self.assertEqual(value['status'],'FAIL')
        self.assertEqual(result['status'],'OBSERVED')
        self.assertEqual(result['analysis'],'NOT_RUN')

    def test_malformed_coverage_and_candidate_excess_remain_bounded(self):
        folder = self.local / 'benchmarks/full-synthetic'; folder.mkdir(parents=True)
        (folder / 'coverage.json').write_text('not JSON')
        result = probe.candidate_observation(self.local, [])
        self.assertEqual(result['candidates'][0]['metadata']['coverage.json']['parse'], 'MALFORMED_JSON')
        for number in range(32): (folder.parent / f'full-{number}').mkdir()
        with self.assertRaises(ValueError): probe.candidate_observation(self.local, [])

    def stage_fixture(self):
        ctx = {'source':'a'*64}; parent={'pid':100,'ppid':99,'start_time_ticks':1}
        worker={'pid':101,'ppid':100,'start_time_ticks':2}
        captures = {}
        for label, raw in (('stdout',b'actual tiny fixture\n'),('stderr',b'')):
            path=self.local/('parent-download.'+label);path.write_bytes(raw)
            captures[label]={'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        active={'action':'download','run_context':ctx,'parent_identity':parent,'worker_identity':worker,'nonce':'fixture'}
        record={'status':'PASS','action':'download','run_context':ctx,'parent_identity':parent,'nonce':'fixture',
                'supervision':{'status':'PASS','worker_identity':worker,'worker_started':True,'worker_exit_code':0,
                    'startup_gate_released_after_durable_publication':True,'capture_complete':True,
                    'discarded_output_bytes':0,'termination_reason':None,'errors':[],
                    'descendant_quiescence':{'quiescent':True,'residual':[]},'capture':captures,
                    'captured_output_bytes':sum(x['bytes'] for x in captures.values())}}
        return ctx,active,record

    def test_parent_stage_authenticates_real_tiny_capture_bytes(self):
        ctx, active, record = self.stage_fixture()
        with patch.object(probe,'load',side_effect=[record,active]):
            self.assertEqual(probe.require_stage({'local':self.local},ctx,'download'),record)

    def test_wrong_context_residual_descendant_or_capture_hash_refuses(self):
        for mutation in (lambda r:r.update(run_context={'source':'b'*64}),
                         lambda r:r['supervision']['descendant_quiescence'].update(residual=[{'pid':42}]),
                         lambda r:r['supervision']['capture']['stdout'].update(sha256='0'*64)):
            ctx,active,record=self.stage_fixture(); mutation(record)
            with self.subTest(mutation=mutation),patch.object(probe,'load',side_effect=[record,active]),self.assertRaises(ValueError):
                probe.require_stage({'local':self.local},ctx,'download')

    def test_cleanup_attempts_exact_outer_close_even_when_inner_finalization_fails(self):
        p={'local':self.local,'mount':self.local/'inner','volume':self.local/'outer-mount',
           'image':self.local/'original.img','outer':self.local/'outer.img'};ctx={'source':'a'*64}
        pending={'run_context':ctx,'image_identity':[1,2,3]}
        with patch.object(probe,'admitted',return_value=(p,ctx)),patch.object(probe,'load',return_value=pending), \
             patch.object(probe,'identity',return_value=[1,2,3]),patch.object(probe.os.path,'ismount',return_value=True), \
             patch.object(probe,'outer') as outer,patch.object(probe,'save'), \
             patch.object(probe,'close_exact',side_effect=[ValueError('inner refusal'),{'status':'PASS'}]) as close:
            result=probe.cleanup()
        self.assertEqual(result['status'],'FAIL')
        self.assertEqual(close.call_count,2);outer.assert_called_once()
        self.assertEqual(result['failures'][0]['phase'],'inner')

    def test_production_has_no_analyzer_benchmark_or_scientific_upload_action(self):
        self.assertEqual(tuple(probe.ACTIONS),('plan','quota','download','extract','observe','cleanup','export'))
        tree=ast.parse(Path(probe.__file__).read_text())
        forbidden={'analyzer_worker','benchmark','upload_admit','readback','require_retained_zip'}
        for node in ast.walk(tree):
            if isinstance(node,ast.Call):
                name=ast.unparse(node.func).split('.')[-1]
                self.assertNotIn(name,forbidden)
        self.assertEqual(sum(probe.STAGES.values()),1545)
        self.assertLess(sum(probe.STAGES.values()),probe.JOB_SECONDS)


if __name__ == '__main__': unittest.main()
