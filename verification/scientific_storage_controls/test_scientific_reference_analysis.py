"""Source-only synthetic scientific-analysis unit controls, not native evidence.

These readers feed invented rows to isolated analysis functions. They do not
claim to be ScientificSampleReader or exercise filesystem/wrapper integration.
The full execution API must reject them. No mocked integration or reduced grid.
"""
import copy
import statistics
import unittest

import scientific_reference_analysis as analysis
import analyze_reference as legacy
import scientific_capture_protocol as protocol
from test_scientific_analyzer_adapter import SyntheticOriginals


class SyntheticSamples:
    def __init__(self, *, mode='exact', recall=1.0, eligible=2000, filter_label='all'):
        self.fixture = SyntheticOriginals()
        f = self.fixture
        if mode != 'exact' or filter_label != 'all':
            f.cid, f.cell = next((cid, cell) for cid, cell in protocol.cells_for_group(f.group, f.run).items()
                               if cell['mode'] == mode and cell['filter_label'] == filter_label and
                               cell['ef'] == (512 if mode=='exact' else 128))
            f.summary['cell'] = copy.deepcopy(f.cell)
            f.summary['scope'].update(cell_id=f.cid, cell=copy.deepcopy(f.cell))
        plan = 'exact' if eligible==0 or mode=='exact' or mode=='auto' and eligible<=256 else 'graph' if mode=='auto' else mode
        for rows in (f.native_rows, f.normalized_rows):
            for row in rows:
                response = row['response']; response.update(plan=plan, exact=plan=='exact', eligible=eligible,
                                                           distance_evaluations=eligible)
                if recall == .9:
                    response['hits'][-1] = {'id':'r000099','distance':9.5}
        for row in f.normalized_rows:
            row['recall_at_k'] = recall
        self.provenance = {'source':f.run['source'],'binaries':{
            name:{'source':f.run['source'],'sha256':f.run['binaries'][name],'go':'go1.27.3'}
            for name in ('facetquarry','fqbench')}}
        f.summary.update(provenance=self.provenance,errors=[],generation='9'*64,
                         corpus_sha256='a'*64,queries_sha256='b'*64,build_process_seconds=1.0,
                         build_distance_evaluations=123,snapshot_bytes=10000,mean_recall=recall,
                         p50_search_ns=101,p95_search_ns=191,p99_search_ns=199,mean_distance_evaluations=eligible)
        f.refresh()
        self.cid, self.cell, self.summary, self.rows = f.cid, f.cell, f.summary, f.normalized_rows
        self.run, self.config, self.source = f.run, f.run['config'], f.run['source']
        self.calls = 0

    def samples(self, cell_id, summary):
        if cell_id != self.cid or summary is not self.summary:
            raise ValueError('explicit synthetic unit-reader identity differs')
        self.calls += 1
        return iter(self.rows)

    def truth(self):
        return analysis.exact_truth(self,self.cid,self.summary,self.cell,self.config,self.provenance,self.source)

    def analyze(self, truth):
        return analysis.analyze_cell(self,self.cid,self.cell,self.summary,self.config,self.provenance,self.source,truth)


class PureScientificAnalysisContracts(unittest.TestCase):
    def test_auto_exact_cannot_claim_success_with_non_nearest_eligible_id(self):
        # Explicit synthetic eligible set0..99; exact top10 is0..9. The
        # substituted r000099 is eligible but not among the nearest10.
        exact = SyntheticSamples(eligible=100,filter_label='p05')
        auto = SyntheticSamples(mode='auto',recall=.9,eligible=100,filter_label='p05')
        result = auto.analyze(exact.truth())
        self.assertEqual(result['analysis_status'],'FAIL')
        self.assertIn('exact baseline drift',result['analysis_errors'])

    def test_all_empty_native_modes_and_auto_boundary_match_engine_contract(self):
        data = SyntheticSamples()
        empty = {'schema_version':1,'generation':data.summary['generation'],'plan':'exact','status':'complete',
                 'exact':True,'eligible':0,'distance_evaluations':0,'hits':[]}
        for mode in ('exact','graph','postfilter','auto'):
            cell = {**data.cell,'mode':mode}
            with self.subTest(mode=mode):
                self.assertEqual(analysis.response_values(empty,cell,data.config,data.summary['generation']),( [],[],0,0))
                wrong = {**empty,'exact':False,'plan':'graph'}
                with self.assertRaises(ValueError):
                    analysis.response_values(wrong,cell,data.config,data.summary['generation'])
                with self.assertRaises(ValueError):
                    analysis.response_values({**empty,'distance_evaluations':1},cell,data.config,data.summary['generation'])
        for eligible, plan, exact in ((256,'exact',True),(257,'graph',False)):
            response = copy.deepcopy(data.rows[0]['response'])
            response.update(eligible=eligible,distance_evaluations=eligible,plan=plan,exact=exact)
            self.assertEqual(analysis.response_values(response,{**data.cell,'mode':'auto'},data.config,data.summary['generation'])[2:],
                             (eligible,eligible))

    def test_oversize_native_count_and_interval_return_failed_cell_without_escape(self):
        for key in ('successful_queries','measured_interval_ns'):
            data = SyntheticSamples(); truth = data.truth()
            data.summary['native_metadata'][key] = 10**400
            with self.subTest(key=key):
                result = data.analyze(truth)
                self.assertEqual(result['analysis_status'],'FAIL')
                self.assertIsNone(result['completed_queries_per_second'])

    def test_exact_full_count_truth_and_metrics_preserve_existing_algorithms(self):
        data = SyntheticSamples(); truth = data.truth(); row = data.analyze(truth)
        self.assertEqual(row['analysis_status'], 'PASS')
        self.assertEqual((row['sample_count'],row['successful_samples'],row['error_calls']), (1000,1000,0))
        self.assertEqual((row['p50_search_ns'],row['p95_search_ns'],row['p99_search_ns']), (101,191,199))
        self.assertEqual(row['mean_recall'],1.0)
        self.assertEqual(row['completed_queries_per_second'],1000.0)
        self.assertEqual(row['raw_samples_original_sha256'],data.summary['samples_original_sha256'])
        self.assertNotIn('raw_samples_sha256',row)

    def test_graph_recall_is_recomputed_and_a_measured_miss_stays_target_fail(self):
        exact = SyntheticSamples(); graph = SyntheticSamples(mode='graph',recall=.9)
        row = graph.analyze(exact.truth())
        self.assertEqual(row['analysis_status'],'PASS')
        self.assertAlmostEqual(row['mean_recall'],.9)
        self.assertEqual(legacy.target_status(row),'FAIL')

    def test_forged_recorded_recall_fails_independent_intersection(self):
        exact = SyntheticSamples(); graph = SyntheticSamples(mode='graph',recall=.9)
        for row in graph.rows:
            row['recall_at_k'] = 1.0
        result = graph.analyze(exact.truth())
        self.assertEqual(result['analysis_status'],'FAIL')
        self.assertIn('recorded recall differs from exact baseline intersection',result['analysis_errors'])

    def test_graph_cannot_gain_exact_label_or_wrong_plan(self):
        for field, value in (('exact',True),('plan','exact')):
            data = SyntheticSamples(mode='graph'); truth = SyntheticSamples().truth()
            data.rows[0]['response'][field] = value
            row = data.analyze(truth)
            self.assertEqual(row['analysis_status'],'FAIL')
            self.assertTrue(any('plan/exact label' in error for error in row['analysis_errors']))

    def test_exact_truth_repeated_answers_and_full_coverage_remain_required(self):
        for changed in ('answer','missing','duplicate'):
            data = SyntheticSamples()
            if changed == 'answer':
                data.rows[-1]['response']['hits'][-1]['distance'] = 10
            elif changed == 'missing':
                data.rows.pop()
            else:
                data.rows[-1] = copy.deepcopy(data.rows[0])
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                data.truth()

    def test_invalid_work_typed_counts_and_foreign_ids_still_refuse(self):
        for field, value in (('distance_evaluations',1000001),('eligible',True),('foreign_id',None)):
            data = SyntheticSamples(mode='graph'); truth = SyntheticSamples().truth()
            if field == 'foreign_id':
                data.rows[0]['response']['hits'][0]['id'] = 'r999999'
            else:
                data.rows[0]['response'][field] = value
            self.assertEqual(data.analyze(truth)['analysis_status'],'FAIL')

    def test_legacy_digest_cannot_be_relabelled_as_restored_original_digest(self):
        for change in ('mixed','missing-original','version'):
            data = SyntheticSamples()
            if change == 'mixed':
                data.summary['samples_sha256'] = 'c'*64
            elif change == 'missing-original':
                del data.summary['samples_original_sha256']
            else:
                del data.summary['evidence_format']
            with self.subTest(change=change), self.assertRaises(ValueError):
                data.truth()

    def test_missing_baseline_and_corpus_generation_drift_do_not_become_pass(self):
        data = SyntheticSamples(mode='graph')
        self.assertEqual(data.analyze(None)['analysis_status'],'FAIL')
        for key in ('corpus_sha256','generation'):
            truth = SyntheticSamples().truth(); truth[key] = '0'*64
            result = data.analyze(truth)
            self.assertEqual(result['analysis_status'],'FAIL')
            self.assertIn('cell corpus/generation differs from exact baseline',result['analysis_errors'])

    def test_bad_collector_metrics_and_native_interval_remain_explicit_failures(self):
        for field in ('mean_recall','p95_search_ns','mean_distance_evaluations','native_throughput'):
            data = SyntheticSamples(); truth = data.truth()
            if field == 'native_throughput':
                data.summary['native_metadata']['completed_queries_per_second'] += 1
            else:
                data.summary[field] += 1
            self.assertEqual(data.analyze(truth)['analysis_status'],'FAIL')

    def test_failed_sample_is_counted_and_never_dropped_for_a_success(self):
        data = SyntheticSamples(); truth = data.truth()
        data.rows[0].pop('response'); data.rows[0].update(error='synthetic analysis failure',recall_at_k=None)
        data.summary['status'] = 'FAIL'; data.summary['errors'] = ['synthetic collector failure']
        data.summary['native_metadata'].update(successful_queries=999,completed_queries_per_second=999.0)
        row = data.analyze(truth)
        self.assertEqual((row['sample_count'],row['successful_samples'],row['error_calls']), (1000,999,1))
        self.assertEqual(row['analysis_status'],'FAIL')
        self.assertIn('error calls excluded from successful-search latency',row['analysis_errors'])

    def test_auto_plan_and_exact_work_follow_the_fixed_cardinality_rule(self):
        data = SyntheticSamples(); response = copy.deepcopy(data.rows[0]['response'])
        cell = {**data.cell,'mode':'auto'}
        with self.assertRaisesRegex(ValueError,'plan/exact label'):
            analysis.response_values(response,cell,data.config,data.summary['generation'])
        response.update(eligible=10,distance_evaluations=9)
        with self.assertRaisesRegex(ValueError,'did not exhaust'):
            analysis.response_values(response,cell,data.config,data.summary['generation'])
        response['distance_evaluations'] = 10
        self.assertEqual(analysis.response_values(response,cell,data.config,data.summary['generation'])[2:],(10,10))

    def test_synthetic_unit_reader_cannot_enter_live_complete_execution_route(self):
        with self.assertRaisesRegex(ValueError,'real scientific sample reader'):
            analysis.analyze_execution(SyntheticSamples())


if __name__ == '__main__':
    unittest.main()
