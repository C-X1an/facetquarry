"""Recorder units with explicit fake CLI results; NOT Go integration evidence."""
import contextlib
import base64
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import oracle


class OracleRawRetention(unittest.TestCase):
    def exercise(self, root, *, wrong_id=False, build_failure=False, malformed=False,
                 cli_timeout=False, oversized_output=False, cleanup_failure=False,
                 summary_failure=False, broken_stdout=False, broken_stderr=False):
        calls=[]
        class BrokenWriter(io.StringIO):
            def write(self, text):raise OSError('unit console write failure')
        real_temporary_directory=tempfile.TemporaryDirectory
        @contextlib.contextmanager
        def temporary_directory(**kwargs):
            with real_temporary_directory(**kwargs) as name:
                yield name
            if cleanup_failure:raise OSError('unit cleanup failure after passing comparisons')
        def fake_cli(args, **kwargs):
            calls.append(args)
            if args[1]=='build':
                if build_failure:raise subprocess.CalledProcessError(2,args,output=b'unit fake build failure',stderr=b'unit build stderr\xff')
                return subprocess.CompletedProcess(args,0,b'x'*5000 if oversized_output else b'{}',b'')
            if cli_timeout:raise subprocess.TimeoutExpired(args,120,output=b'partial timeout stdout',stderr=b'partial timeout stderr\xff')
            if malformed:return subprocess.CompletedProcess(args,0,b'{unit invalid JSON\xff',b'unit parser stderr')
            corpus=json.loads(Path(args[args.index('--index')+1]).with_name('corpus.json').read_text())
            query=json.loads(Path(args[args.index('--query')+1]).read_text())
            hits=oracle.expected(corpus['records'],query,'alpha')
            if wrong_id and hits:hits[0]['id']='unit-wrong-id'
            return subprocess.CompletedProcess(args,0,json.dumps({'hits':hits,'exact':True,'status':'complete','generation':'unit-generation'}).encode(),b'')
        source_kwargs={'side_effect':RuntimeError('unit summary source failure')} if summary_failure else {'return_value':'f'*64}
        with patch.object(oracle,'ROOT',root),patch.object(oracle,'run',side_effect=fake_cli),patch.object(oracle.tempfile,'TemporaryDirectory',side_effect=temporary_directory),patch.object(oracle,'source_hash',**source_kwargs),patch.object(sys,'argv',['oracle.py','--seeds','2']),contextlib.redirect_stdout(BrokenWriter() if broken_stdout else io.StringIO()),contextlib.redirect_stderr(BrokenWriter() if broken_stderr else io.StringIO()):
            oracle.main()
        return calls

    def fixture(self):
        base=Path(__file__).resolve().parents[1]/'.cache/tmp';base.mkdir(parents=True,exist_ok=True)
        temp=tempfile.TemporaryDirectory(dir=base)
        root=Path(temp.name);(root/'.cache/tmp').mkdir(parents=True)
        return temp,root

    def test_every_success_keeps_actual_and_independent_raw_values(self):
        temp,root=self.fixture()
        with temp:
            calls=self.exercise(root)
            rows=[json.loads(line) for line in (root/'.local/oracle/cases.jsonl').read_text().splitlines()]
            self.assertEqual(len(calls),4)
            self.assertEqual([r['seed'] for r in rows],[0,1])
            for row in rows:
                self.assertEqual(row['actual']['hits'],row['independent_expected'])
                self.assertTrue(row['corpus']['records'])
                self.assertEqual(row['query']['mode'],'exact')
                self.assertEqual(row['status'],'PASS')

    def test_wrong_result_is_retained_before_comparison_raises(self):
        temp,root=self.fixture()
        with temp:
            with self.assertRaisesRegex(AssertionError,'ID mismatch seed=0'):
                self.exercise(root,wrong_id=True)
            row=json.loads((root/'.local/oracle/cases.jsonl').read_text())
            self.assertEqual(row['status'],'FAIL')
            self.assertEqual(row['actual']['hits'][0]['id'],'unit-wrong-id')
            self.assertNotEqual(row['actual']['hits'],row['independent_expected'])
            self.assertEqual(json.loads((root/'.local/oracle/summary.json').read_text())['status'],'FAIL')

    def test_build_failure_keeps_seed_inputs_and_missing_actual_explicit(self):
        temp,root=self.fixture()
        with temp:
            with self.assertRaises(subprocess.CalledProcessError):self.exercise(root,build_failure=True)
            row=json.loads((root/'.local/oracle/cases.jsonl').read_text())
            self.assertEqual(row['status'],'FAIL');self.assertIsNone(row['actual'])
            self.assertEqual(row['generator_seed'],20261023)
            self.assertEqual(row['error']['type'],'CalledProcessError')
            command=row['commands'][0]
            self.assertEqual(command['exit_code'],2)
            self.assertEqual(base64.b64decode(command['stdout']['base64']),b'unit fake build failure')
            self.assertEqual(base64.b64decode(command['stderr']['base64']),b'unit build stderr\xff')

    def test_cleanup_failure_cannot_publish_a_passing_summary(self):
        temp,root=self.fixture()
        with temp:
            with self.assertRaisesRegex(OSError,'unit cleanup failure'):
                self.exercise(root,cleanup_failure=True)
            summary=json.loads((root/'.local/oracle/summary.json').read_text())
            self.assertEqual(summary['status'],'FAIL')
            self.assertEqual(summary['failure']['type'],'OSError')
            rows=[json.loads(line) for line in (root/'.local/oracle/cases.jsonl').read_text().splitlines()]
            self.assertTrue(all(row['status']=='PASS' for row in rows))

    def test_malformed_search_retains_the_exact_non_utf8_bytes(self):
        temp,root=self.fixture()
        with temp:
            with self.assertRaises((UnicodeDecodeError,json.JSONDecodeError)):
                self.exercise(root,malformed=True)
            row=json.loads((root/'.local/oracle/cases.jsonl').read_text())
            self.assertEqual(row['status'],'FAIL');self.assertIsNone(row['actual'])
            self.assertEqual(base64.b64decode(row['commands'][1]['stdout']['base64']),b'{unit invalid JSON\xff')
            self.assertEqual(base64.b64decode(row['commands'][1]['stderr']['base64']),b'unit parser stderr')

    def test_timeout_keeps_partial_stdout_and_stderr(self):
        temp,root=self.fixture()
        with temp:
            with self.assertRaises(subprocess.TimeoutExpired):self.exercise(root,cli_timeout=True)
            row=json.loads((root/'.local/oracle/cases.jsonl').read_text())
            command=row['commands'][1]
            self.assertEqual(command['exception'],'TimeoutExpired')
            self.assertIsNone(command['exit_code'])
            self.assertEqual(base64.b64decode(command['stdout']['base64']),b'partial timeout stdout')
            self.assertEqual(base64.b64decode(command['stderr']['base64']),b'partial timeout stderr\xff')

    def test_oversized_output_is_an_explicit_failure_with_bounded_prefix(self):
        temp,root=self.fixture()
        with temp:
            with self.assertRaisesRegex(ValueError,'CLI stream retention admission'):
                self.exercise(root,oversized_output=True)
            row=json.loads((root/'.local/oracle/cases.jsonl').read_text())
            stream=row['commands'][0]['stdout']
            self.assertTrue(stream['truncated'])
            self.assertEqual(stream['observed_bytes'],5000)
            self.assertEqual(len(base64.b64decode(stream['base64'])),4096)
            self.assertEqual(json.loads((root/'.local/oracle/summary.json').read_text())['status'],'FAIL')

    def test_next_invocation_preserves_previous_failed_comparisons(self):
        temp,root=self.fixture()
        with temp:
            with self.assertRaises(AssertionError):self.exercise(root,wrong_id=True)
            old=(root/'.local/oracle/cases.jsonl').read_bytes()
            self.exercise(root)
            histories=list((root/'.local/oracle').glob('previous-*/cases.jsonl'))
            self.assertEqual(len(histories),1);self.assertEqual(histories[0].read_bytes(),old)
            self.assertEqual(json.loads((root/'.local/oracle/summary.json').read_text())['status'],'PASS')

    def test_console_failure_does_not_turn_a_completed_passing_run_into_failure(self):
        temp,root=self.fixture()
        with temp:
            self.exercise(root,broken_stdout=True)
            self.assertEqual(json.loads((root/'.local/oracle/summary.json').read_text())['status'],'PASS')

    def test_double_finalizer_failure_preserves_original_cli_failure(self):
        temp,root=self.fixture()
        with temp:
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                self.exercise(root,build_failure=True,summary_failure=True,broken_stderr=True)
            self.assertEqual(caught.exception.returncode,2)
            self.assertFalse((root/'.local/oracle/summary.json').exists())
            row=json.loads((root/'.local/oracle/cases.jsonl').read_text())
            self.assertEqual(row['error']['type'],'CalledProcessError')

    def test_summary_failure_without_prior_error_remains_a_command_failure(self):
        temp,root=self.fixture()
        with temp:
            with self.assertRaisesRegex(RuntimeError,'unit summary source failure'):
                self.exercise(root,summary_failure=True)
            self.assertFalse((root/'.local/oracle/summary.json').exists())


if __name__=='__main__':unittest.main()
