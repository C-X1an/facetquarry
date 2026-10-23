"""Bounded analyzer unit controls with synthetic records; no engine integration."""
import copy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import analyze_reference as a

SOURCE='e'*64
def fixture():
    config={'queries':1,'repetitions':1,'k':1,'concurrency':1}
    cell={'n':2,'dimension':1,'distribution':'uniform','correlation':'independent','seed':11,
          'filter_label':'all','filter':{},'mode':'graph','ef':128,'concurrency':1}
    response={'generation':'a'*64,'eligible':2,'hits':[{'id':'r000000','distance':0.0}],
              'distance_evaluations':2,'plan':'graph','exact':False,'status':'complete'}
    sample={'query':0,'repetition':0,'nanoseconds':1000,'response':response,'recall_at_k':1.0}
    provenance={'source':SOURCE}
    summary={'cell':cell,'source':SOURCE,'provenance':provenance,'status':'PASS','stage':'measurement',
             'generation':'a'*64,'corpus_sha256':'b'*64,'queries_sha256':'c'*64,'samples_sha256':'d'*64,
             'sample_count':1,'errors':[],'build_process_seconds':.1,'build_distance_evaluations':2,'snapshot_bytes':100,
             'mean_recall':1.0,'p50_search_ns':1000,'p95_search_ns':1000,'p99_search_ns':1000,'mean_distance_evaluations':2,
             'native_metadata':{'source':SOURCE,'go':'go1.27.3','workers':1,'gomaxprocs':2,'samples':1,
                                'successful_queries':1,'peak_rss_bytes':1024,'measured_interval_ns':1000,
                                'completed_queries_per_second':1_000_000,'clock':{'monotonic':True,'fallback':False,
                                'frequency_hz':1_000_000_000,'calibration':{}}}}
    truth={'queries':{0:(['r000000'],2,[(0.0,'r000000')])},'corpus_sha256':'b'*64,'generation':'a'*64}
    return config,cell,summary,provenance,sample,truth

def analyze(parts):
    config,cell,summary,provenance,sample,truth=parts
    with patch.object(a,'raw_samples',return_value=iter([sample])):
        return a.analyze_cell(Path('.'),'fixture',cell,summary,config,provenance,SOURCE,truth)

class AnalyzerControls(unittest.TestCase):
    def test_valid_fixture_and_excess_hits(self):
        parts=fixture();self.assertEqual(analyze(parts)['analysis_status'],'PASS')
        parts[4]['response']['hits'].append({'id':'r000001','distance':1.0})
        row=analyze(parts);self.assertEqual(row['analysis_status'],'FAIL');self.assertIn('excess returned hits',row['analysis_errors'])

    def test_baseline_cell_and_input_binding(self):
        parts=fixture();config,cell,summary,prov,sample,truth=parts
        exact={**cell,'mode':'exact'}
        with self.assertRaisesRegex(ValueError,'cell/source/provenance'):
            a.exact_truth(Path('.'),'fixture',summary,exact,config,prov,SOURCE)
        parts[5]['corpus_sha256']='f'*64
        self.assertIn('cell corpus/generation differs from exact baseline',analyze(parts)['analysis_errors'])

    def test_malformed_metadata_and_ambiguous_sample(self):
        for mutate in (lambda p:p[2]['native_metadata'].update(peak_rss_bytes='bad'),
                       lambda p:p[4].update(error='failure'),
                       lambda p:p[4]['response'].update(eligible=True)):
            parts=fixture();mutate(parts);self.assertEqual(analyze(parts)['analysis_status'],'FAIL')
        self.assertIsNone(a.interval(['bad']*5,[[0]*5]))

    def test_pass_with_collector_errors_is_invalid(self):
        parts=fixture();parts[2]['errors']=['filter violation']
        row=analyze(parts)
        self.assertEqual(row['analysis_status'],'FAIL')
        self.assertEqual(row['collector_errors'],['filter violation'])
        self.assertEqual(a.target_status(row),'INVALID')
        config,cell,summary,prov,_,_=parts
        with self.assertRaisesRegex(ValueError,'PASS summary contains collector errors'):
            a.exact_truth(Path('.'),'fixture',summary,cell,config,prov,SOURCE)

    def test_missing_invalid_and_measured_target_states(self):
        row={'collector_status':'MISSING','stage':None,'sample_count':0,'analysis_status':'FAIL','mean_recall':None}
        self.assertEqual(a.target_status(row),'NOT_RUN')
        row.update(collector_status='PASS',stage='measurement')
        self.assertEqual(a.target_status(row),'INVALID')
        row.update(analysis_status='PASS',mean_recall=.94)
        self.assertEqual(a.target_status(row),'FAIL')
        statuses=[{'recall_target_status':'PASS'} for _ in range(45)]
        self.assertEqual(a.target_outcome(statuses)[0],'PASS')
        statuses[0]['recall_target_status']='NOT_RUN';self.assertEqual(a.target_outcome(statuses)[0],'NOT_RUN')

    def test_rank_and_paired_five_seed_effects(self):
        self.assertEqual([a.nearest_rank(list(range(1,1001)),q) for q in (.5,.95,.99)],[500,950,990])
        draws=[[0,1,2,3,4],[4,3,2,1,0]]
        self.assertEqual(a.interval([42]*5,draws)['lower'],42)
        rows=[];seeds=[11,23,47,83,131]
        for seed in seeds:
            _,cell,_,_,_,_=fixture()
            base={**cell,'seed':seed,'mode':'exact','ef':512,'analysis_status':'PASS','corpus_sha256':'b'*64,
                  'generation':'a'*64,'mean_recall':1.0,'mean_distance_evaluations':2,'p95_search_ns':2000,
                  'completed_queries_per_second':1000}
            rows.extend([base,{**base,'mode':'graph','ef':128,'p95_search_ns':1000,'completed_queries_per_second':2000}])
        effects=a.paired_effects(rows,{'seeds':seeds,'ef':[32,128,512]},draws)
        value=effects[0]['effects']['p95_ratio_exact_over_method']
        self.assertEqual((value['mean'],value['lower'],value['upper']),(2,2,2))

    def test_optimized_python_keeps_source_guard(self):
        config={'concurrency':1,'k':1};provenance={'source':SOURCE,'binaries':{
            n:{'source':SOURCE,'go':'go1.27.3','sha256':'a'*64} for n in ('facetquarry','fqbench')}}
        coverage={'config':config,'source':SOURCE,'provenance':provenance,'profile':'full'}
        code='import analyze_reference as a\ntry:\n a.validate_run('+repr(coverage)+','+repr(config)+',"'+('f'*64)+'","full")\nexcept ValueError:\n print("REJECTED")\nelse:\n raise RuntimeError("source guard disappeared")'
        result=subprocess.run([sys.executable,'-O','-c',code],cwd=Path(__file__).parent,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip(),'REJECTED')

if __name__=='__main__':unittest.main(verbosity=2)
