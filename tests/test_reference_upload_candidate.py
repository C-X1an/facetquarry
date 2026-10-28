"""Bounded selection fixtures and real tiny Linux ownership; no quota claim."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from common import ROOT
import reference_upload_candidate as selection


class CandidateProjectionControls(unittest.TestCase):
    def test_only_a_complete_valid_child_selection_crosses_the_boundary(self):
        for raw, expected in ((b'{"status":"PASS","source":"fixture"}', 'PASS'),
                              (b'{"status":"FAIL"}', 'FAIL'), (b'[]', 'FAIL'), (b'invalid', 'FAIL')):
            result = {'status': 'PASS', 'stdout_base64': base64.b64encode(raw).decode()}
            with self.subTest(raw=raw), patch.object(selection, 'run_readonly', return_value=result) as run:
                actual = selection.evaluate(Path('/fixture'), False)
            self.assertEqual(actual['status'], expected)
            self.assertEqual(run.call_args.args[0][-2:], ['--root', str(ROOT)])
        with patch.object(selection, 'run_readonly', return_value={'status': 'FAIL'}) as run:
            self.assertEqual(selection.evaluate(Path('/fixture'), True)['status'], 'FAIL')
        self.assertEqual(run.call_args.args[0][-1], '--package-ok')


@unittest.skipUnless(sys.platform == 'linux', 'real bounded selection ownership requires Linux /proc/subreaper')
class TinyLinuxCandidateControls(unittest.TestCase):
    def launch(self, body):
        env = {**os.environ, 'PYTHONPATH': str(ROOT / 'scripts')}
        completed = subprocess.run([sys.executable, '-c', body], env=env, cwd=ROOT,
                                   capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors='replace')[-12000:])
        return json.loads(completed.stdout)

    def test_candidate_timeout_still_emits_independent_metadata_and_keeps_originals(self):
        body = r'''
import base64,json,os,sys,tempfile
from pathlib import Path
from unittest.mock import patch
from common import ROOT
import reference_pipeline as pipeline
import reference_upload_candidate as selection
base=ROOT/'.cache/tmp';base.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory(dir=base) as temporary:
    parent=Path(temporary);root=parent/'checkout';root.mkdir()
    volume=parent/'facetquarry-reference';(volume/'source').mkdir(parents=True)
    image=volume.with_name(volume.name+'.img');image.write_bytes(b'untouched tiny image')
    output=parent/'actions-output.txt'
    os.environ.update(FQ_ACCOUNTED_BASE_BYTES='2000000000',GITHUB_OUTPUT=str(output))
    def bounded(*args,**kwargs):
        return selection.run_readonly([sys.executable,'-c',
            'import time; print("retained-delay-diagnostic",flush=True); time.sleep(61)'],
            total_seconds=8,cleanup_seconds=6,final_seconds=.5)
    with patch.object(selection,'evaluate',side_effect=bounded),patch.object(pipeline,'source_hash',return_value='a'*64):
        result=pipeline.admit_uploads(volume,True,root,profile='reference-inside-outer-v1')
    assert image.read_bytes()==b'untouched tiny image'
    assert json.loads((root/'.local/reference-upload-admission.json').read_text())==result
    assert 'metadata_allowed=true' in output.read_text() and 'data_allowed=false' in output.read_text()
    print(json.dumps(result))
'''
        result = self.launch(body)
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['metadata_allowed'])
        self.assertFalse(result['data_allowed'])
        observed = result['candidate_evaluation']
        self.assertEqual(observed['termination_reason'], 'candidate_deadline')
        self.assertTrue(observed['descendant_quiescence']['quiescent'])
        self.assertEqual(observed['descendant_quiescence']['residual'], [])
        self.assertLess(observed['duration_seconds'], 8)
        self.assertEqual(base64.b64decode(observed['stdout_base64']), b'retained-delay-diagnostic\n')

    def test_output_overflow_is_explicit_and_readonly_child_is_reaped(self):
        result = self.launch(r'''
import json,sys
import reference_upload_candidate as selection
result=selection.run_readonly([sys.executable,'-c','import sys,time;sys.stdout.write("x"*1000000);sys.stdout.flush();time.sleep(61)'],total_seconds=8,cleanup_seconds=6,final_seconds=.5)
print(json.dumps(result))
''')
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['termination_reason'], 'output_limit')
        self.assertEqual(result['captured_bytes'], selection.CAPTURE_BYTES)
        self.assertGreater(result['discarded_bytes'], 0)
        self.assertTrue(result['descendant_quiescence']['quiescent'])
        self.assertEqual(result['descendant_quiescence']['residual'], [])
        self.assertLess(result['duration_seconds'], 8)

    def test_slow_or_oversized_cleanup_cannot_suppress_metadata_outputs(self):
        template = r'''
import json,os,sys,tempfile,time
from pathlib import Path
from unittest.mock import patch
from common import ROOT
import reference_capacity as capacity
import reference_pipeline as pipeline
import reference_upload_candidate as selection
fault=FAULT
base=ROOT/'.cache/tmp';base.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory(dir=base) as temporary:
    parent=Path(temporary);root=parent/'checkout';root.mkdir()
    volume=parent/'facetquarry-reference';(volume/'source').mkdir(parents=True)
    volume.with_name(volume.name+'.img').write_bytes(b'unchanged tiny image')
    output=parent/'actions-output.txt'
    os.environ.update(FQ_ACCOUNTED_BASE_BYTES='2000000000',GITHUB_OUTPUT=str(output))
    original=capacity.quiesce_children
    def faulty_cleanup():
        quiet=original()
        if fault=='slow':time.sleep(61)
        else:quiet['reaped']=[{'pid':i,'wait_status':0} for i in range(10000)]
        return quiet
    def bounded(*args,**kwargs):
        return selection.run_readonly([sys.executable,'-c','print("complete child diagnostic",flush=True)'],
            total_seconds=8,cleanup_seconds=6,final_seconds=.5)
    with patch.object(capacity,'quiesce_children',side_effect=faulty_cleanup),patch.object(selection,'evaluate',side_effect=bounded),patch.object(pipeline,'source_hash',return_value='a'*64):
        result=pipeline.admit_uploads(volume,True,root,profile='reference-inside-outer-v1')
    raw=(root/'.local/reference-upload-admission.json').read_bytes()
    assert len(raw)<1000000 and json.loads(raw)==result
    assert 'metadata_allowed=true' in output.read_text() and 'data_allowed=false' in output.read_text()
    print(json.dumps(result))
'''
        for fault in ('slow', 'oversized'):
            with self.subTest(fault=fault):
                result = self.launch(template.replace('FAULT', repr(fault)))
                self.assertEqual(result['status'], 'FAIL')
                self.assertTrue(result['metadata_allowed'])
                self.assertFalse(result['data_allowed'])
                observed = result['candidate_evaluation']
                self.assertLess(observed['duration_seconds'], 8)
                self.assertLessEqual(selection.encoded_digest(observed)[0], selection.EVALUATION_BYTES)
                if fault == 'slow':
                    self.assertFalse(observed['descendant_quiescence']['quiescent'])
                    self.assertIsNone(observed['descendant_quiescence']['residual'])
                else:
                    self.assertEqual(observed['termination_reason'], 'cleanup_evidence_limit')
                    self.assertEqual(observed['descendant_quiescence']['reaped_count'], 10000)
                    self.assertFalse(observed['descendant_quiescence']['details_complete'])


if __name__ == '__main__':
    unittest.main()
