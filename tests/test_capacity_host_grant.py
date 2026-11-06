"""Mocked boundary controls only; no actual sudo/host qualification here."""
import contextlib
import copy
import io
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import capacity_host_grant as host


class HostGrantBoundaryControls(unittest.TestCase):
    def environ(self):
        return {'FQ_RESERVATION_PROFILE':host.capacity.PROFILE,'GITHUB_JOB':'reference_capacity',
                'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':host.capacity.REPOSITORY,
                'GITHUB_REPOSITORY_ID':str(host.capacity.REPOSITORY_ID),'GITHUB_SHA':'a'*40,
                'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1','FQ_WORKSPACE_ROOT':'/synthetic/volume'}

    def context(self):
        return {'commit':'a'*40,'git_status':'','source':'b'*64,'github_run_id':'123',
                'github_run_attempt':'1','repository':host.capacity.REPOSITORY,
                'repository_id':host.capacity.REPOSITORY_ID,'job':'reference_capacity','profile':host.capacity.PROFILE}

    def test_plain_and_other_reference_profiles_are_explicitly_not_applicable(self):
        for env in ({},{'FQ_RESERVATION_PROFILE':'reference-inside-outer-v1','GITHUB_JOB':'reference'}):
            self.assertFalse(host.requested(env))

    def test_capacity_selection_requires_original_identity_and_rejects_partial_context(self):
        env=self.environ();self.assertTrue(host.requested(env))
        for key in ('FQ_RESERVATION_PROFILE','GITHUB_JOB','GITHUB_ACTIONS','GITHUB_REPOSITORY',
                    'GITHUB_REPOSITORY_ID','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'):
            changed=dict(env);changed.pop(key)
            with self.subTest(key=key),self.assertRaises(ValueError):host.requested(changed)

    def invoke(self,*,mutate_context=None,mutate_reservation=None,count=1,change_environment=False,**result_fields):
        ctx=self.context()
        if mutate_context:mutate_context(ctx)
        proof={'run_context':copy.deepcopy(ctx),'profile':host.capacity.PROFILE,
               'global_reserved_growth_bytes':2000000000,'filesystem_free_floor_bytes':500000000}
        if mutate_reservation:mutate_reservation(proof)
        result=SimpleNamespace(testsRun=1,skipped=[],errors=[],failures=[],expectedFailures=[],unexpectedSuccesses=[])
        for key,value in result_fields.items():setattr(result,key,value)
        result.wasSuccessful=lambda:not result.errors and not result.failures and not result.unexpectedSuccesses
        suite=SimpleNamespace(countTestCases=lambda:count)
        module=SimpleNamespace(__file__=str(ROOT/'tests/test_reference_capacity_process.py'))
        with patch.dict(os.environ,self.environ(),clear=True),contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(host.filesystem,'whole_entry',return_value=contextlib.nullcontext()))
            stack.enter_context(patch.object(host.capacity,'context',return_value=ctx))
            verify=stack.enter_context(patch.object(host.reservation,'verify',return_value=proof))
            stack.enter_context(patch.object(host,'source_hash',return_value='b'*64))
            imported=stack.enter_context(patch.object(host.importlib,'import_module',return_value=module))
            load=stack.enter_context(patch.object(host.unittest.TestLoader,'loadTestsFromName',return_value=suite))
            def run(_suite):
                if change_environment:os.environ['MUTATED']='yes'
                return result
            executed=stack.enter_context(patch.object(host.unittest.TextTestRunner,'run',side_effect=run))
            before=dict(os.environ);value=host.run_gate()
            self.assertEqual(dict(os.environ),before)
            verify.assert_called_once_with(Path('/synthetic/volume'),2000000000,500000000)
            imported.assert_called_once_with('test_reference_capacity_process')
            load.assert_called_once_with(host.LEAF)
            executed.assert_called_once_with(suite)
        return value

    def test_exact_original_host_context_executes_one_unskipped_fixed_leaf(self):
        value=self.invoke();self.assertEqual(value['status'],'PASS');self.assertTrue(value['host_grant_verified'])

    def test_wrong_run_source_or_dirty_context_refuses(self):
        for key,value in (('commit','c'*40),('source','c'*64),('github_run_id','124'),('github_run_attempt','2'),('git_status','dirty')):
            with self.subTest(key=key),self.assertRaises(ValueError):self.invoke(mutate_context=lambda c:c.update({key:value}))

    def test_live_quota_context_and_reserve_binding_cannot_be_omitted_or_changed(self):
        for mutate in (lambda p:p.update(run_context={}),lambda p:p.update(profile='unknown'),
                       lambda p:p.update(global_reserved_growth_bytes=1),lambda p:p.update(filesystem_free_floor_bytes=1)):
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):self.invoke(mutate_reservation=mutate)

    def test_missing_multiple_skipped_failed_error_or_expected_failure_cannot_pass(self):
        for count in (0,2):
            with self.subTest(count=count),self.assertRaises(ValueError):self.invoke(count=count)
        for fields in ({'testsRun':0},{'testsRun':2},{'skipped':[('leaf','reason')]},
                       {'errors':[('leaf','error')]},{'failures':[('leaf','failure')]},
                       {'expectedFailures':[('leaf','expected')]},{'unexpectedSuccesses':['leaf']}):
            with self.subTest(fields=fields),self.assertRaises(ValueError):self.invoke(**fields)

    def test_environment_mutation_refuses_success(self):
        with self.assertRaises(ValueError):self.invoke(change_environment=True)

    def test_main_propagates_failed_observation_as_nonzero(self):
        with patch.object(host,'run_gate',side_effect=PermissionError('synthetic denied')),patch('sys.stdout',new=io.StringIO()):
            self.assertEqual(host.main(),1)

    def test_make_runs_host_gate_after_complete_neutral_fixture_discovery(self):
        text=(ROOT/'Makefile').read_text();recipe=text.split('integration: build\n',1)[1].split('python-fixtures:',1)[0]
        self.assertLess(recipe.index('scripts/integration_environment.py'),recipe.index('scripts/capacity_host_grant.py'))


if __name__=='__main__':unittest.main()
