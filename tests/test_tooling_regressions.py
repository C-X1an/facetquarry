"""Evidence/tooling regressions; subprocess refusal test uses the actual binaries.
Run the complete suite after make build and the fqbench build, so the executable
provenance regression exercises both native Go programs without compiling here.
"""
import contextlib
import gzip
import hashlib
import io
import itertools
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import benchmark
import common
import disk_guard
import oracle
import release_gate

IDENTITY = 'a'*64
PROVENANCE = {'schema_version': 1, 'source': IDENTITY, 'binaries': {
    name: {'source': IDENTITY, 'sha256': 'b'*64, 'go': 'go1.27.3'}
    for name in ('facetquarry', 'fqbench')}}


class ReleaseEvidence(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def ref(self, record, kind='command', name='evidence.json'):
        file = self.root/name
        file.write_text(json.dumps(record))
        return {'path': name, 'sha256': hashlib.sha256(file.read_bytes()).hexdigest(), 'kind': kind}

    def command(self):
        return {'status':'PASS', 'exit_code':0, 'source_before':IDENTITY,
                'source_after':IDENTITY, 'termination_reason':None, 'command':['make','test'],
                'stdout_sha256':'c'*64, 'stderr_sha256':'d'*64}

    def complete(self):
        cmd = self.ref(self.command())
        data = {'source':IDENTITY, 'criteria':[
            {'id':f'AC-{i:03d}', 'status':'PASS', 'receipts':[cmd]} for i in range(1,25)],
            'gate_evidence':{}}
        detail = {
            'toolchain': {'go':'go1.27.3','platform':'linux/amd64','runtime_verified':True},
            'review': {'initially_read_only':True,'independent':True,'reviewer':'separate reviewer',
                       'findings_artifact':'review.json','unresolved_critical_high':[],'fixes_verified':True},
            'benchmark_coverage': {'profile':'full','grid_complete':True,'missing_cells':[],
                'unexpected_cells':[],'failed_cells':[],'limited':False,'expected_cells':5400,
                'completed_cells':5400,'reference_host_verified':True,'reference_recall_target':'PASS',
                'provenance':PROVENANCE},
            'manual': {'reviewer':'owner','notes':'actual walkthrough notes','owner_walkthrough':'PASS','keyboard_usability':'PASS'},
            'export_audit': {'findings':[],'history_audited':True,'allowlist_audited':True},
            'fresh_checkout': {'exit_code':0,'clean_checkout':True,'supported_toolchain':True,'commit':'1'*40},
            'resource': {'total_attributable_bytes':100,'inventory':[{'accounted_bytes':100,'symlinks_not_followed':[]}],
                'external_allocations_complete':True,'admission':'ALLOW','hard_quota_enforced':True,'enforcement_record':'quota record'},
        }
        for key,kind in release_gate.GATE_KINDS.items():
            data[key] = True
            record = {'schema_version':1,'evidence_type':kind,'source':IDENTITY,'status':'PASS',**detail[kind]}
            data['gate_evidence'][key] = [self.ref(record,kind,kind+'.json')]
        return data

    def test_typed_fixture_requires_actual_reference_envelope(self):
        data=self.complete()
        # These other typed gates remain valid. The historical benchmark
        # fixture has no real execution/transport proof and must now fail.
        for key,kind in release_gate.GATE_KINDS.items():
            if kind!='benchmark_coverage':
                for ref in data['gate_evidence'][key]:
                    self.assertEqual(release_gate.validate_reference(ref,IDENTITY,self.root,kind),[])
        errors=release_gate.assess(data,IDENTITY,self.root)
        self.assertTrue(any('verified reference envelope missing' in e for e in errors))
        self.assertTrue(any('reader profiles1/4/16' in e for e in errors))
        self.assertTrue(all(e.startswith('full_benchmark_complete:') for e in errors))

    def test_digest_correct_failed_and_stale_summaries_reject(self):
        for changed in ({'status':'FAIL'}, {'source':'f'*64}):
            with self.subTest(changed=changed):
                data=self.complete()
                record={'schema_version':1,'evidence_type':'oracle_summary','source':IDENTITY,'status':'PASS','seed_count':1000,**changed}
                data['criteria'][0]['receipts']=[self.ref(record,'oracle_summary','summary.json')]
                self.assertTrue(any(e.startswith('AC-001:') for e in release_gate.assess(data,IDENTITY,self.root)))

    def test_renamed_or_mislabeled_command_cannot_bypass_status(self):
        data=self.complete()
        ref=self.ref({**self.command(),'status':'FAIL','exit_code':1},'oracle_summary','renamed.json')
        data['criteria'][0]['receipts']=[ref]
        self.assertTrue(any(e.startswith('AC-001:') for e in release_gate.assess(data,IDENTITY,self.root)))
        del ref['kind']
        self.assertTrue(any(e.startswith('AC-001:') for e in release_gate.assess(data,IDENTITY,self.root)))

    def test_boolean_gates_do_not_substitute_for_evidence(self):
        data=self.complete();data.pop('gate_evidence')
        self.assertEqual(sum('typed gate evidence missing' in x for x in release_gate.assess(data,IDENTITY,self.root)),7)

    def test_review_resource_manual_schema_source_and_status_enforced(self):
        for kind in ('review','resource','manual'):
            for change in ({'status':'FAIL'}, {'source':'f'*64}, {'evidence_type':'unknown'}):
                with self.subTest(kind=kind,change=change):
                    data=self.complete()
                    key=next(key for key,value in release_gate.GATE_KINDS.items() if value==kind)
                    ref=data['gate_evidence'][key][0]
                    record=json.loads((self.root/ref['path']).read_text());record.update(change)
                    data['gate_evidence'][key]=[self.ref(record,kind,kind+'.json')]
                    self.assertTrue(any(e.startswith(key+':') for e in release_gate.assess(data,IDENTITY,self.root)))
        data=self.complete();record={'schema_version':1,'evidence_type':'resource','source':IDENTITY,'status':'PASS'}
        data['gate_evidence']['resource_inventory_complete']=[self.ref(record,'resource','resource.json')]
        self.assertTrue(any(e.startswith('resource_inventory_complete:') for e in release_gate.assess(data,IDENTITY,self.root)))

    def test_invalid_or_external_reference_rejects(self):
        self.assertTrue(release_gate.validate_reference({'path':'../outside.json','sha256':'c'*64},IDENTITY,self.root))
        self.assertTrue(release_gate.validate_reference(True,IDENTITY,self.root))
        self.assertTrue(release_gate.validate_record([], 'command', IDENTITY))


class BenchmarkResume(unittest.TestCase):
    def test_limit_keeps_later_persisted_failure(self):
        config={'n':[2],'dimension':1,'distributions':['ties'],'correlations':['independent'],
            'seeds':[11,23],'selectivities':[1.0],'two_facet':False,'ef':[10],
            'queries':1,'warmup':0,'repetitions':1,'k':1,'m':2,'ef_construction':4,
            'build_budget':100,'concurrency':1}
        cfg_hash=hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()[:12]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'benchmarks').mkdir();(root/'benchmarks/grid.json').write_text(json.dumps({'smoke':config}))
            folder=root/'.local/benchmarks'/f'smoke-{IDENTITY[:12]}-{cfg_hash}';folder.mkdir(parents=True)
            (folder/'provenance.json').write_text(json.dumps(PROVENANCE))
            first_missing=True
            for seed in config['seeds']:
                for mode in ('exact','graph','postfilter','auto'):
                    cell={'n':2,'dimension':1,'distribution':'ties','correlation':'independent','seed':seed,
                        'filter_label':'all','filter':{},'mode':mode,'ef':10,'concurrency':1}
                    cid=hashlib.sha256(json.dumps(cell,sort_keys=True).encode()).hexdigest()[:20]
                    if first_missing:first_missing=False;continue
                    sample=folder/f'{cid}.samples.jsonl.gz'
                    with gzip.open(sample,'wt') as output:output.write('{}\n')
                    record={'cell':cell,'source':IDENTITY,'provenance':PROVENANCE,'stage':'measurement',
                        'status':'FAIL' if seed==23 and mode=='auto' else 'PASS',
                        'samples_sha256':hashlib.sha256(sample.read_bytes()).hexdigest()}
                    (folder/f'{cid}.summary.json').write_text(json.dumps(record))
            def fake_run(args,**kwargs):
                return subprocess.CompletedProcess(args,2 if 'build' in args else 0,'','deliberate build failure')
            with patch.object(benchmark,'ROOT',root),patch.object(benchmark,'source_hash',return_value=IDENTITY), \
                    patch.object(benchmark,'binary_provenance',return_value=PROVENANCE), \
                    patch.object(benchmark,'verify_binary_hashes'),patch.object(benchmark,'run',side_effect=fake_run), \
                    patch.object(sys,'argv',['benchmark.py','--profile','smoke','--limit-cells','1']),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(benchmark.main(),1)
            coverage=json.loads((folder/'coverage.json').read_text())
            self.assertEqual(coverage['completed_cells'],8)
            self.assertEqual(len(coverage['failed_cells']),2)
            self.assertEqual(coverage['missing_cells'],[])
            self.assertEqual(coverage['status'],'FAIL')

    def test_resume_rejects_changed_summary_source_or_binary(self):
        cell={'mode':'exact'}
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            record={'source':IDENTITY,'provenance':PROVENANCE,'cell':cell,'stage':'build','status':'FAIL'}
            path=folder/'one.summary.json'
            for update in ({'source':'f'*64},{'provenance':{}}):
                path.write_text(json.dumps({**record,**update}))
                with self.assertRaisesRegex(RuntimeError,'provenance'):
                    benchmark.collect_summaries(folder,{'one':cell},IDENTITY,PROVENANCE)

    def test_direct_benchmark_refuses_real_old_binaries_before_measuring(self):
        # A fresh copied technical tree differs from the source embedded in the
        # actual built executables. Neither build nor native timing may run.
        binaries=[common.executable(name) for name in ('facetquarry','fqbench')]
        for binary in binaries:
            self.assertTrue(binary.is_file(),f'build both executables before integration: {binary}')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'scripts').mkdir();(root/'bin').mkdir();(root/'benchmarks').mkdir()
            for name in ('benchmark.py','benchmark_support.py','common.py','oracle.py'):
                shutil.copy2(ROOT/'scripts'/name,root/'scripts'/name)
            shutil.copy2(ROOT/'benchmarks/grid.json',root/'benchmarks/grid.json')
            (root/'different.py').write_text('# new technical source after binary build\n')
            for binary in binaries:shutil.copy2(binary,root/'bin'/binary.name)
            result=subprocess.run([sys.executable,str(root/'scripts/benchmark.py'),'--profile','smoke'],cwd=root,text=True,capture_output=True,timeout=30)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('executable source differs',result.stderr)
            self.assertFalse((root/'.local/benchmarks').exists())

    def test_each_binary_source_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'bin').mkdir()
            for name in ('facetquarry','fqbench'):common.executable(name,root).write_bytes(name.encode())
            for stale_name in ('facetquarry','fqbench'):
                def fake_run(args,**kwargs):
                    name=Path(args[0]).stem
                    return subprocess.CompletedProcess(args,0,json.dumps({'source':'f'*64 if name==stale_name else IDENTITY,'go':'go1.27.3'}),'')
                with self.subTest(stale=stale_name),patch.object(benchmark,'ROOT',root),patch.object(benchmark,'run',side_effect=fake_run):
                    with self.assertRaisesRegex(RuntimeError,stale_name+': executable source differs'):
                        benchmark.binary_provenance(IDENTITY)


class ResourceInventory(unittest.TestCase):
    def test_operator_workspace_and_external_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);workspace=base/'workspace';workspace.mkdir()
            (workspace/'public').mkdir();(workspace/'public/source').write_bytes(b'a'*10)
            (workspace/'private').mkdir();(workspace/'private/toolchain').write_bytes(b'b'*300)
            external=base/'external.bin';external.write_bytes(b'c'*400)
            manifest=base/'allocations.json';manifest.write_text(json.dumps([str(external)]))
            output=io.StringIO()
            with patch.dict(os.environ,{'FQ_WORKSPACE_ROOT':str(workspace),'FQ_EXTERNAL_ALLOCATIONS':str(manifest)}), \
                    patch.object(sys,'argv',['disk_guard.py','--reserve','1']),contextlib.redirect_stdout(output):
                self.assertEqual(disk_guard.main(),0)
            report=json.loads(output.getvalue())
            self.assertGreaterEqual(report['total_attributable_bytes'],710)
            self.assertEqual(len(report['inventory']),2)
            self.assertFalse(report['hard_quota_enforced'])
            manifest.write_text(json.dumps([str(base/'missing')]))
            with patch.dict(os.environ,{'FQ_WORKSPACE_ROOT':str(workspace),'FQ_EXTERNAL_ALLOCATIONS':str(manifest)}), \
                    patch.object(sys,'argv',['disk_guard.py']),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(disk_guard.main(),1)

    def test_nested_external_roots_not_double_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);child=root/'child';child.mkdir();(child/'file').write_bytes(b'x'*10)
            external=root/'allocations.json';external.write_text(json.dumps([str(child),str(root)]))
            self.assertEqual(len(disk_guard.inventory_roots(root,external)),1)

    def test_prepared_oracle_preserves_float32_order_and_distances(self):
        rng=random.Random(71)
        records=[{'tenant':'alpha','id':f'r{i:03d}','vector':[rng.uniform(-2,2) for _ in range(5)],'metadata':{'tag':str(i%2)}} for i in range(30)]
        prepared=oracle.prepare_records(records)
        for filt in ({},{'tag':'0'},{'tag':'absent'}):
            query={'vector':[1/3]*5,'filter':filt,'k':7}
            q=[oracle.f32(x) for x in query['vector']]
            direct=[]
            for r in records:
                if all(r['metadata'].get(k)==v for k,v in filt.items()):
                    direct.append({'id':r['id'],'distance':sum((a-oracle.f32(b))**2 for a,b in zip(q,r['vector']))})
            direct=sorted(direct,key=lambda x:(x['distance'],x['id']))[:7]
            self.assertEqual(oracle.expected_prepared(prepared,query,'alpha'),direct)


if __name__=='__main__':unittest.main()
