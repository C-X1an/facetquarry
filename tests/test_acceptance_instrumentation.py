"""Finite recorder controls with fake owned Go results; NOT Go integration."""
import contextlib
import hashlib
import io
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import acceptance_instrumentation as gate


class InstrumentationRecorderTests(unittest.TestCase):
    def fixture(self):
        base=Path(__file__).resolve().parents[1]/'.cache/tmp'
        base.mkdir(parents=True,exist_ok=True)
        temporary=tempfile.TemporaryDirectory(prefix='instrumentation-unit-',dir=base)
        root=Path(temporary.name)
        binary=root/'fake-go';binary.write_bytes(b'explicit unit fixture; not a Go binary')
        (root/'go.mod').write_text('module synthetic-recorder-fixture\n')
        (root/'.go-version').write_text('1.27.3\n')
        (root/'internal').mkdir();(root/'cmd').mkdir()
        return temporary,root,binary

    def exercise(self,root,binary,*,hashes=None,quiet=True,complete=True,version='go1.27.3'):
        calls=[]
        if not hasattr(self,'attempt_counter'):self.attempt_counter=itertools.count(1)
        def fake_owned(command,stdout,stderr,**kwargs):
            calls.append((command,kwargs['environ']))
            selector=kwargs['environ'][gate.SELECTOR]
            if 'version' in command:code,out=0,('go version '+version+' linux/amd64\n').encode()
            elif selector=='race-read-discard':code,out=1,b'WARNING: DATA RACE\nengine.harnessReadAndDiscard\n'
            elif selector=='normal':code,out=0,b'ok synthetic unit only\n'
            else:code,out=1,b'unknown FACETQUARRY_HARNESS_CONTROL\n'
            stdout.write_bytes(out);stderr.write_bytes(b'')
            captures={key:{'path':str(path),'bytes':path.stat().st_size,
                           'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
                      for key,path in (('stdout',stdout),('stderr',stderr))}
            return {'status':'PASS' if code==0 else 'FAIL','worker_started':True,'worker_exit_code':code,
                    'capture':captures,'captured_output_bytes':len(out),'discarded_output_bytes':0 if complete else 1,
                    'capture_complete':complete,'errors':[],'termination_reason':None,
                    'descendant_quiescence':{'quiescent':quiet,'residual':[] if quiet else None}}
        runtime=(binary,hashlib.sha256(binary.read_bytes()).hexdigest(),{},'go1.27.3')
        hash_options={'return_value':'a'*64} if hashes is None else {'side_effect':hashes}
        with patch.object(gate,'ROOT',root),patch.object(gate,'runtime',return_value=runtime), \
             patch.object(gate,'source_hash',**hash_options),patch.object(gate,'run_owned',side_effect=fake_owned), \
             patch.object(gate,'whole_entry',side_effect=lambda *args,**kwargs:contextlib.nullcontext()), \
             patch.object(gate.Path,'cwd',return_value=root), \
             patch.object(gate.time,'time_ns',side_effect=lambda:next(self.attempt_counter)), \
             patch.object(gate.uuid,'uuid4',return_value=SimpleNamespace(hex='unit')), \
             contextlib.redirect_stdout(io.StringIO()):
            result=gate.main()
        summaries=[json.loads(path.read_text()) for path in sorted((root/'.local/acceptance-instrumentation').glob('attempt-*/summary.json'))]
        return result,summaries,calls

    def test_negative_exit_requires_actual_helper_diagnostic_and_positive_envelope(self):
        temp,root,binary=self.fixture()
        with temp:
            code,summaries,calls=self.exercise(root,binary)
            self.assertEqual(code,0);self.assertEqual(summaries[-1]['status'],'PASS')
            negative=summaries[-1]['checks'][2]
            self.assertEqual(negative['exit_code'],1)
            self.assertEqual(negative['owned']['status'],'FAIL')
            self.assertEqual(negative['status'],'PASS')
            self.assertEqual([env[gate.SELECTOR] for _,env in calls],
                             ['normal','normal','race-read-discard','normal','unknown-control-must-fail'])
            self.assertTrue(all('-timeout=45s' in command for command,_ in calls[1:]))
            self.assertFalse(gate.expected_outcome('intentional-foreign-read',1,b'compile error','go1.27.3'))
            self.assertFalse(gate.expected_outcome('intentional-foreign-read',0,b'DATA RACE harnessReadAndDiscard','go1.27.3'))

    def test_unknown_quiescence_and_incomplete_capture_cannot_qualify(self):
        for options in ({'quiet':False},{'complete':False}):
            with self.subTest(options=options):
                temp,root,binary=self.fixture()
                with temp:
                    code,summaries,_=self.exercise(root,binary,**options)
                    self.assertEqual(code,1);self.assertEqual(summaries[-1]['status'],'FAIL')
                    self.assertEqual(summaries[-1]['checks'][0]['status'],'FAIL')

    def test_all_passing_steps_with_final_source_drift_return_failure(self):
        temp,root,binary=self.fixture()
        with temp:
            code,summaries,_=self.exercise(root,binary,hashes=['a'*64]*11+['b'*64])
            summary=summaries[-1]
            self.assertTrue(all(row['status']=='PASS' for row in summary['checks']))
            self.assertEqual(summary['source_after'],'b'*64)
            self.assertEqual(summary['status'],'FAIL');self.assertEqual(code,1)

    def test_post_command_hash_failure_retains_stage_summary_and_raw_files(self):
        temp,root,binary=self.fixture()
        with temp:
            code,summaries,_=self.exercise(root,binary,hashes=['a'*64,'a'*64,RuntimeError('unit hash failure'),RuntimeError('unit final hash failure')])
            self.assertEqual(code,1);self.assertEqual(summaries[-1]['status'],'FAIL')
            attempts=list((root/'.local/acceptance-instrumentation').glob('attempt-*'))
            stage=json.loads((attempts[0]/'toolchain.json').read_text())
            self.assertIn('unit hash failure',stage['error'])
            self.assertTrue((attempts[0]/'toolchain.owned.json').is_file())
            self.assertIn(b'go1.27.3',(attempts[0]/'toolchain-stdout.txt').read_bytes())

    def test_retry_keeps_previous_attempt_bytes(self):
        temp,root,binary=self.fixture()
        with temp:
            self.exercise(root,binary,quiet=False)
            first=next((root/'.local/acceptance-instrumentation').glob('attempt-*/summary.json'))
            before=first.read_bytes()
            code,summaries,_=self.exercise(root,binary)
            self.assertEqual(code,0);self.assertEqual(len(summaries),2)
            self.assertEqual(first.read_bytes(),before)

    def test_stale_toolchain_version_is_an_explicit_failed_stage(self):
        temp,root,binary=self.fixture()
        with temp:
            code,summaries,calls=self.exercise(root,binary,version='go1.23.2')
            self.assertEqual(code,1);self.assertEqual(len(calls),1)
            self.assertEqual(summaries[-1]['checks'][0]['status'],'FAIL')

    def test_go_overlay_is_refused_before_executable_selection(self):
        with patch.object(gate.sys,'platform','linux'),patch.object(os,'getuid',return_value=1001,create=True), \
             patch.dict(os.environ,{'GOFLAGS':'-overlay=untracked.json'}),patch.object(gate.shutil,'which') as which:
            with self.assertRaisesRegex(ValueError,'GOFLAGS/overlay'):gate.runtime()
            which.assert_not_called()

    def test_timeout_and_signal_exits_never_qualify_a_matching_negative_diagnostic(self):
        for code in (124,137,143,-9,2):
            with self.subTest(code=code):
                self.assertFalse(gate.expected_outcome('intentional-foreign-read',code,
                    b'WARNING: DATA RACE engine.harnessReadAndDiscard','go1.27.3'))
                self.assertFalse(gate.expected_outcome('unknown-selector',code,
                    b'unknown FACETQUARRY_HARNESS_CONTROL','go1.27.3'))


if __name__=='__main__':unittest.main()
