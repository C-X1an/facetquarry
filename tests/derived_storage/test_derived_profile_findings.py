"""Regressions for independent first findings; original controls stay frozen."""
import contextlib
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
if __package__:
    from .test_reference_derived_storage_probe import probe
else:
    from test_reference_derived_storage_probe import probe

def write_json(path,value):
    path.write_text(json.dumps(value),encoding='utf-8')

def supervised(p,ctx,stage='derive',status='PASS'):
    parent={'pid':111,'ppid':110,'start_time_ticks':21}
    worker={'pid':112,'ppid':111,'start_time_ticks':22}
    active={'action':stage,'run_context':ctx,'nonce':'a'*32,'parent_identity':parent,'worker_identity':worker}
    captures={}
    for label,data in (('stdout',b'ok\n'),('stderr',b'')):
        path=p['local']/('parent-'+stage+'.'+label);path.write_bytes(data)
        captures[label]={'path':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    observation={'status':status,'worker_started':True,'worker_identity':worker,
        'worker_exit_code':0 if status=='PASS' else 1,
        'startup_gate_released_after_durable_publication':True,'capture_complete':True,
        'discarded_output_bytes':0,'captured_output_bytes':3,'capture':captures,
        'termination_reason':None if status=='PASS' else 'worker_failed','errors':[],
        'descendant_quiescence':{'quiescent':True,'residual':[]}}
    record={'status':status,'action':stage,'run_context':ctx,'nonce':'a'*32,
        'parent_identity':parent,'supervision':observation}
    write_json(p['local']/('active-'+stage+'.json'),active)
    write_json(p['local']/('parent-'+stage+'.json'),record)
    return record,active

class IndependentFindings(unittest.TestCase):
    def test_worker_environment_has_only_declared_runtime_and_download_authority(self):
        canaries={'OPENAI_API_KEY':'test-only-canary','GITHUB_WEBHOOK_SECRET':'test-only-canary',
            'ACTIONS_RUNTIME_TOKEN':'test-only-canary','OTHER_API_KEY':'test-only-canary','GITHUB_TOKEN':'test-only-download',
            'GITHUB_RUN_ID':'123','FQ_DERIVED_STORAGE_PROBE':'true'}
        with patch.dict(os.environ,canaries):
            ordinary=probe.worker_environment()
            download=probe.worker_environment(download=True)
        for name in canaries:
            if name not in ('GITHUB_TOKEN','GITHUB_RUN_ID','FQ_DERIVED_STORAGE_PROBE'):
                self.assertNotIn(name,ordinary);self.assertNotIn(name,download)
        self.assertNotIn('GITHUB_TOKEN',ordinary)
        self.assertEqual(download['GITHUB_TOKEN'],'test-only-download')
        self.assertEqual(ordinary['GITHUB_RUN_ID'],'123')

    def test_orphan_command_capture_denies_final_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            p={'local':Path(directory)};ctx={'source':'a'*64}
            commands=p['local']/'commands';commands.mkdir()
            (commands/'context-head-0123456789ab.stdout').write_bytes(b'partial')
            with self.assertRaises((ValueError,OSError)):
                probe.require_closed_commands(p,ctx)

    def test_cleanup_and_export_refuse_unresolved_active_producer_before_launch(self):
        for action in ('cleanup','export'):
            with self.subTest(action=action),tempfile.TemporaryDirectory() as directory:
                p={'local':Path(directory)};ctx={'source':'a'*64,'started_epoch':int(time.time())-1}
                write_json(p['local']/'active-derive.json',{'run_context':ctx,'action':'derive','nonce':'a'*32})
                with contextlib.ExitStack() as stack:
                    stack.enter_context(patch.object(probe,'paths',return_value=p))
                    stack.enter_context(patch.object(probe,'context',return_value=ctx))
                    stack.enter_context(patch.object(probe,'save'))
                    stack.enter_context(patch.object(probe.supervisor,'process_identity',return_value={'pid':200,'ppid':199,'start_time_ticks':30}))
                    launch=stack.enter_context(patch.object(probe.supervisor,'run_owned',return_value={'status':'PASS'}))
                    with self.assertRaises((ValueError,OSError)):
                        probe.stage_parent(action)
                    launch.assert_not_called()

    def test_failed_but_closed_stage_is_diagnostic_and_never_success(self):
        with tempfile.TemporaryDirectory() as directory:
            p={'local':Path(directory)};ctx={'source':'a'*64}
            supervised(p,ctx,status='FAIL')
            with patch.object(probe.supervisor,'same_process',return_value=False):
                observed=probe.require_closed_stage(p,ctx,'derive',require_success=False)
                self.assertEqual(observed['status'],'FAIL')
                with self.assertRaises(ValueError):
                    probe.require_closed_stage(p,ctx,'derive',require_success=True)

    def test_closed_stage_checks_real_capture_bytes_nonce_and_live_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            p={'local':Path(directory)};ctx={'source':'a'*64}
            record,active=supervised(p,ctx)
            with patch.object(probe.supervisor,'same_process',return_value=True),self.assertRaises(ValueError):
                probe.require_closed_stage(p,ctx,'derive',require_success=False)
            with patch.object(probe.supervisor,'same_process',return_value=False):
                active['nonce']='b'*32;write_json(p['local']/'active-derive.json',active)
                with self.assertRaises(ValueError):probe.require_closed_stage(p,ctx,'derive',require_success=False)
                active['nonce']='a'*32;write_json(p['local']/'active-derive.json',active)
                (p['local']/'parent-derive.stdout').write_bytes(b'changed')
                with self.assertRaises(ValueError):probe.require_closed_stage(p,ctx,'derive',require_success=False)

    def test_unknown_quiescence_or_residual_descendants_refuse(self):
        for quiet in ({'quiescent':False,'residual':[]},{'quiescent':True,'residual':[{'pid':123}]},{}):
            with self.subTest(quiet=quiet),tempfile.TemporaryDirectory() as directory:
                p={'local':Path(directory)};ctx={'source':'a'*64}
                record,_=supervised(p,ctx,status='FAIL')
                record['supervision']['descendant_quiescence']=quiet
                write_json(p['local']/'parent-derive.json',record)
                with patch.object(probe.supervisor,'same_process',return_value=False),self.assertRaises(ValueError):
                    probe.require_closed_stage(p,ctx,'derive',require_success=False)

    def test_derivation_json_without_bound_stage_and_cleanup_cannot_earn_credit(self):
        with tempfile.TemporaryDirectory() as directory:
            p={'local':Path(directory)};ctx={'source':'a'*64,'started_epoch':int(time.time())-1}
            value={'status':'PASS','run_context':ctx,'counts':{'derived':probe.EXPECTED_PAIRS,'identity':0,'refused':0},
                'cost_at_derive_close':{'identity_retained_original_bytes':15,'raw_attempt_bytes_in_identity':16}}
            write_json(p['local']/'derivation.json',value)
            def save(path,value):write_json(path,value)
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(probe,'paths',return_value=p));stack.enter_context(patch.object(probe,'context',return_value=ctx))
                stack.enter_context(patch.object(probe,'source_hash',return_value=ctx['source']));stack.enter_context(patch.object(probe,'save',side_effect=save))
                stack.enter_context(patch.object(probe.supervisor,'process_identity',return_value={'pid':200,'ppid':199,'start_time_ticks':30}))
                stack.enter_context(patch.object(probe.supervisor,'run_owned',return_value={'status':'PASS'}))
                try:probe.stage_parent('export')
                except (ValueError,OSError):
                    self.assertFalse((p['local']/'manifest.json').exists())
                else:
                    final=json.loads((p['local']/'manifest.json').read_bytes())
                    self.assertFalse(final['derivation_complete'])
                    self.assertNotIn('aggregate_representation_cost',final)

    def test_nonobject_summary_is_an_opaque_fallback_and_preserves_every_byte(self):
        cell_record={'mode':'graph','ef':4}
        cell=hashlib.sha256(json.dumps(cell_record,sort_keys=True).encode()).hexdigest()[:20]
        for bad in ([],None,17,'bad'):
            with self.subTest(summary=bad),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);folder=root.joinpath(*probe.CANDIDATE.split('/'));folder.mkdir(parents=True)
                summary=folder/(cell+'.summary.json');sample=folder/(cell+'.samples.jsonl.gz')
                write_json(summary,bad);sample.write_bytes(gzip.compress(b'',mtime=0))
                files={}
                for path in (summary,sample):
                    raw=path.read_bytes();files[path.relative_to(root).as_posix()]={'type':'regular','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
                before={str(path):path.read_bytes() for path in (summary,sample)}
                result,recipe=probe.derive_cell(root,cell,files)
                self.assertEqual(result['mode'],'refused');self.assertIsNone(recipe)
                self.assertEqual(before,{str(path):path.read_bytes() for path in (summary,sample)})

    @unittest.skipUnless(sys.platform=='linux','Actual Linux st_blocks/uid physical ceiling control; NOT RUN on this platform')
    def test_two_real_output_streams_refuse_before_pending_bytes_exceed_physical_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            local=Path(directory);p={'local':local}
            with patch.object(probe,'paths',return_value=p):
                with probe.BoundedOutput(local/'one',20000).open('xb') as one:
                    with probe.BoundedOutput(local/'two',20000).open('xb') as two:
                        base=probe.external()
                        ceiling=base+8191+8192
                        with patch.object(probe,'EXTERNAL_BYTES',ceiling):
                            one.write(b'a'*8191)
                            with self.assertRaises(ValueError):two.write(b'b'*8191)
                            self.assertLessEqual(probe.external(),ceiling)
                with patch.object(probe,'EXTERNAL_BYTES',ceiling):
                    self.assertLessEqual(probe.external(),ceiling)

if __name__=='__main__':unittest.main()
