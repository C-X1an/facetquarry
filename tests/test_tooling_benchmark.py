"""Harness failure controls plus real native build/search failure integration.

Temporary grids deliberately inject invalid data; no successful benchmark or
release qualification is inferred from these negative-control fixtures.
"""
import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import benchmark
import benchmark_support
import common


class RetainedAttempts(unittest.TestCase):
    def test_real_timeout_retains_partial_raw_streams(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as directory:
            folder=Path(directory)
            command=[sys.executable,'-c',"import sys,time;sys.stdout.buffer.write(b'partial\\r\\n');sys.stdout.flush();sys.stderr.write('before timeout');sys.stderr.flush();time.sleep(5)"]
            record,stdout,stderr=benchmark_support.command_attempt(folder,'measurement',command,common.run,1)
            self.assertEqual(record['status'],'FAIL')
            self.assertEqual(record['termination_reason'],'timeout')
            self.assertIn('partial',stdout);self.assertIn('before timeout',stderr)
            raw=gzip.decompress((folder/record['streams']['stdout']['path']).read_bytes())
            self.assertEqual(raw,b'partial\r\n')
            self.assertEqual(record['streams']['stdout']['raw_sha256'],hashlib.sha256(raw).hexdigest())
            self.assertIsNone(record['exit_code'])

    def test_real_start_error_retained(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as directory:
            record,stdout,stderr=benchmark_support.command_attempt(Path(directory),'build',[str(Path(directory)/'absent-program')],common.run,1)
            self.assertEqual(record['status'],'FAIL');self.assertEqual(record['termination_reason'],'start_error')
            self.assertIn('FileNotFoundError',record['error']);self.assertEqual((stdout,stderr),('',''))

    def test_required_host_metadata_present(self):
        host=benchmark_support.host_metadata()
        for key in ('system','kernel','os_version','machine','cpu_model','logical_cpu_count','physical_ram_bytes','power_mode','competing_workload'):
            self.assertIn(key,host)
        self.assertGreater(host['logical_cpu_count'],0)
        self.assertGreater(host['physical_ram_bytes'],0)


class NativeOutputValidation(unittest.TestCase):
    def output(self):
        sample={'query':0,'repetition':0,'nanoseconds':0,'response':{'hits':[{'id':'r0'}],'distance_evaluations':1}}
        meta={'summary':True,'source':'identity','samples':1,'workers':1,'gomaxprocs':2,'zero_duration_count':0,
              'measured_interval_ns':100,'clock':{'name':'test counter','frequency_hz':10_000_000,'monotonic':True,'fallback':False,'calibration':{}}}
        return sample,meta

    def measure(self,lines):
        return benchmark.measurement('\n'.join(lines),[[{'id':'r0'}]],{'r0'},{'mode':'exact'},
                                     {'queries':1,'repetitions':1,'concurrency':1},'identity')

    def test_zero_duration_is_retained_and_count_must_match(self):
        sample,meta=self.output();meta['zero_duration_count']=1
        samples,timings,_,_,_,errors=self.measure([json.dumps(sample),json.dumps(meta)])
        self.assertEqual(errors,[]);self.assertEqual(timings,[0]);self.assertEqual(samples[0]['nanoseconds'],0)
        meta['zero_duration_count']=0
        self.assertIn('native zero-duration count mismatch',self.measure([json.dumps(sample),json.dumps(meta)])[-1])

    def test_invalid_json_shape_and_truncation_fail_without_losing_valid_samples(self):
        sample,meta=self.output();meta['zero_duration_count']=1
        for invalid in ('not JSON','[]','{"query":0,"repetition":0,"nanoseconds":1,"response":42}'):
            with self.subTest(invalid=invalid):
                result=self.measure([json.dumps(sample),invalid,json.dumps(meta)])
                self.assertEqual(len(result[0]),1);self.assertTrue(result[-1])
        self.assertIn('native sample coverage incomplete',self.measure([json.dumps(meta)])[-1])


class ActualNativeFailureCoverage(unittest.TestCase):
    def check_failure(self,stage):
        # Only the generated data is faulted. Both executables, subprocesses,
        # command attempts, summaries and final coverage are real.
        config={'n':[2],'dimension':1,'distributions':['ties'],'correlations':['independent'],
                'seeds':[11],'selectivities':[1.0],'two_facet':False,'ef':[4],
                'queries':1,'warmup':0,'repetitions':1,'k':1,'m':2,'ef_construction':4,
                'build_budget':100,'concurrency':1}
        identity=common.source_hash()
        provenance=benchmark.binary_provenance(identity)
        original_workload=benchmark.workload
        with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as directory:
            root=Path(directory);(root/'benchmarks').mkdir();(root/'bin').mkdir()
            (root/'benchmarks/grid.json').write_text(json.dumps({'smoke':config}))
            for name in ('facetquarry','fqbench'):
                shutil.copy2(common.executable(name),common.executable(name,root))
            def faulted_workload(*args):
                records,vectors=original_workload(*args)
                if stage=='build':records[0]['vector'][0]=float('nan')
                else:vectors[0].append(1.0) # Dimension mismatch rejected by actual Search.
                return records,vectors
            with patch.object(benchmark,'ROOT',root),patch.object(benchmark,'source_hash',return_value=identity), \
                    patch.object(benchmark,'binary_provenance',return_value=provenance), \
                    patch.object(benchmark,'workload',side_effect=faulted_workload), \
                    patch.object(sys,'argv',['benchmark.py','--profile','smoke']),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(benchmark.main(),1)
            folders=list((root/'.local/benchmarks').iterdir());self.assertEqual(len(folders),1)
            folder=folders[0];coverage=json.loads((folder/'coverage.json').read_text())
            self.assertEqual(coverage['status'],'FAIL');self.assertEqual(coverage['completed_cells'],4)
            self.assertEqual(coverage['missing_cells'],[]);self.assertEqual(len(coverage['failed_cells']),4)
            self.assertEqual(coverage['run_errors'],[])
            for path in folder.glob('*.summary.json'):
                summary=json.loads(path.read_text());self.assertEqual(summary['stage'],stage)
                self.assertEqual(summary['status'],'FAIL');self.assertTrue(summary['errors'])
                attempt=summary['attempts'][-1];self.assertEqual(attempt['stage'],stage)
                self.assertNotEqual(attempt['exit_code'],0)
                self.assertGreater(attempt['streams']['stderr']['raw_bytes'],0)
                if stage=='measurement':
                    self.assertEqual(summary['sample_count'],1)
                    meta=summary['native_metadata']
                    self.assertGreater(meta['measured_interval_ns'],0)
                    self.assertIn('calibration',meta['clock'])
                    self.assertEqual(meta['successful_queries'],0)
                    if os.name=='nt':self.assertEqual(meta['clock']['name'],'Windows QueryPerformanceCounter')

    def test_actual_native_build_failure_is_terminal_and_retained(self):self.check_failure('build')
    def test_actual_native_search_failure_is_terminal_and_retained(self):self.check_failure('measurement')


class HarnessFaultCoverage(unittest.TestCase):
    def test_admission_refusal_never_generates_or_builds(self):
        # A full-harness control, not a claim of an actual disk exhaustion run.
        config={'n':[10000],'dimension':64,'distributions':['uniform'],'correlations':['independent'],
                'seeds':[11],'selectivities':[1.0],'two_facet':False,'ef':[4],
                'queries':200,'warmup':20,'repetitions':5,'k':10,'m':12,'ef_construction':96,
                'build_budget':200000000,'concurrency':1}
        identity='refusal-control';provenance={'source':identity,'binaries':{}}
        with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as directory:
            root=Path(directory);(root/'benchmarks').mkdir()
            (root/'benchmarks/grid.json').write_text(json.dumps({'smoke':config}))
            commands=[]
            def refuse(command,**kwargs):
                commands.append(command)
                if command!=['python3','scripts/disk_guard.py','--reserve','500000000']:
                    raise AssertionError('native builder or measurement ran after refusal')
                return subprocess.CompletedProcess(command,1,b'{"admission":"REFUSE"}',b'resource limit')
            with patch.object(benchmark,'ROOT',root),patch.object(benchmark,'source_hash',return_value=identity), \
                    patch.object(benchmark,'binary_provenance',return_value=provenance),patch.object(benchmark,'verify_binary_hashes'), \
                    patch.object(benchmark,'run',side_effect=refuse), \
                    patch.object(benchmark,'workload',side_effect=AssertionError('workload generated after refusal')) as generator, \
                    patch.object(benchmark,'prepare_records',side_effect=AssertionError('oracle prepared after refusal')) as prepare, \
                    patch.object(sys,'argv',['benchmark.py','--profile','smoke']),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(benchmark.main(),1)
            generator.assert_not_called();prepare.assert_not_called();self.assertEqual(len(commands),1)
            folder=next((root/'.local/benchmarks').iterdir());coverage=json.loads((folder/'coverage.json').read_text())
            self.assertEqual(coverage['completed_cells'],4);self.assertEqual(len(coverage['failed_cells']),4)
            self.assertEqual(coverage['missing_cells'],[]);self.assertEqual(coverage['run_errors'],[])
            self.assertEqual(list(folder.glob('active-*')),[])
            for path in folder.glob('*.summary.json'):
                summary=json.loads(path.read_text());self.assertEqual(summary['stage'],'admission')
                self.assertEqual(summary['status'],'FAIL');self.assertIsNone(summary['corpus_sha256'])
                self.assertIsNone(summary['queries_sha256']);self.assertEqual(len(summary['attempts']),1)
                self.assertEqual(summary['attempts'][0]['exit_code'],1)

    def test_injected_timeout_start_error_and_invalid_json_are_terminal(self):
        # Fault injection tests the Python harness controls. The separate class
        # above covers real engine failures, and RetainedAttempts runs a real
        # timed-out subprocess rather than representing these fixtures as one.
        config={'n':[2],'dimension':1,'distributions':['ties'],'correlations':['independent'],
                'seeds':[11],'selectivities':[1.0],'two_facet':False,'ef':[4],
                'queries':1,'warmup':0,'repetitions':1,'k':1,'m':2,'ef_construction':4,
                'build_budget':100,'concurrency':1}
        identity='fault-control';provenance={'source':identity,'binaries':{}}
        for fault in ('timeout','start_error','invalid_json'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as directory:
                root=Path(directory);(root/'benchmarks').mkdir()
                (root/'benchmarks/grid.json').write_text(json.dumps({'smoke':config}))
                def controlled_run(command,**kwargs):
                    if 'build' in command:
                        Path(command[command.index('--output')+1]).write_bytes(b'control')
                        return subprocess.CompletedProcess(command,0,b'{"generation":"control"}',b'')
                    if '--repetitions' not in command:return subprocess.CompletedProcess(command,0,b'admitted',b'')
                    if fault=='timeout':raise subprocess.TimeoutExpired(command,1,output=b'partial native stream\r\n',stderr=b'partial error')
                    if fault=='start_error':raise FileNotFoundError('injected absent native program')
                    return subprocess.CompletedProcess(command,0,b'{invalid native JSON}\r\n',b'')
                with patch.object(benchmark,'ROOT',root),patch.object(benchmark,'source_hash',return_value=identity), \
                        patch.object(benchmark,'binary_provenance',return_value=provenance), \
                        patch.object(benchmark,'verify_binary_hashes'),patch.object(benchmark,'run',side_effect=controlled_run), \
                        patch.object(sys,'argv',['benchmark.py','--profile','smoke']),contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(benchmark.main(),1)
                folder=next((root/'.local/benchmarks').iterdir());coverage=json.loads((folder/'coverage.json').read_text())
                self.assertEqual(coverage['completed_cells'],4);self.assertEqual(len(coverage['failed_cells']),4)
                self.assertEqual(coverage['missing_cells'],[]);self.assertEqual(coverage['run_errors'],[])
                for path in folder.glob('*.summary.json'):
                    summary=json.loads(path.read_text());self.assertEqual(summary['status'],'FAIL')
                    attempt=summary['attempts'][-1]
                    self.assertEqual(attempt['termination_reason'],None if fault=='invalid_json' else fault)
                    raw=gzip.decompress((folder/attempt['streams']['stdout']['path']).read_bytes())
                    if fault=='timeout':self.assertEqual(raw,b'partial native stream\r\n')
                    if fault=='invalid_json':self.assertEqual(raw,b'{invalid native JSON}\r\n')


if __name__=='__main__':unittest.main()
