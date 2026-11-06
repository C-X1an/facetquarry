"""A separate original-parent capacity positive control; fixtures stay neutral."""
from __future__ import annotations
import importlib
import json
import os
import re
from pathlib import Path
import sys
import time
import unittest

from common import ROOT, source_hash
import reference_capacity as capacity
import reference_capacity_reservation as reservation
import reference_filesystem as filesystem

LEAF = ('test_reference_capacity_process.ElevatedCwdLifecycle.'
        'test_existing_capacity_runner_grant_executes_the_fixed_readlink')


def requested(environ):
    if (environ.get('FQ_RESERVATION_PROFILE') != capacity.PROFILE
            and environ.get('GITHUB_JOB') != 'reference_capacity'):
        return False
    expected = {'FQ_RESERVATION_PROFILE':capacity.PROFILE,'GITHUB_JOB':'reference_capacity',
                'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':capacity.REPOSITORY,
                'GITHUB_REPOSITORY_ID':str(capacity.REPOSITORY_ID)}
    capacity.require(all(environ.get(key)==value for key,value in expected.items()),
                     'partial or mismatched capacity host context')
    capacity.require(re.fullmatch('[0-9a-f]{40}',environ.get('GITHUB_SHA',''))
                     and all(re.fullmatch('[1-9][0-9]*',environ.get(key,''))
                             for key in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')),
                     'capacity host revision or run identity missing')
    return True


def run_gate():
    original = dict(os.environ)
    if not requested(original):
        return {'status':'NOT_APPLICABLE','host_grant_verified':False,
                'scope':'The fixed positive host control applies only to the admitted capacity job.'}
    with filesystem.whole_entry(45,started=time.monotonic()):
        ctx = capacity.context(ROOT)
        expected = {'commit':original['GITHUB_SHA'],'git_status':'','source':source_hash(ROOT),
                    'github_run_id':original['GITHUB_RUN_ID'],'github_run_attempt':original['GITHUB_RUN_ATTEMPT'],
                    'repository':capacity.REPOSITORY,'repository_id':capacity.REPOSITORY_ID,
                    'job':'reference_capacity','profile':capacity.PROFILE}
        capacity.require(ctx==expected,'current capacity host source or execution identity differs')
        proof = reservation.verify(Path(original['FQ_WORKSPACE_ROOT']),2000000000,500000000)
        capacity.require(proof.get('run_context')==ctx and proof.get('profile')==capacity.PROFILE
                         and proof.get('global_reserved_growth_bytes')==2000000000
                         and proof.get('filesystem_free_floor_bytes')==500000000,
                         'current exact host quota and reservation proof required')
        capacity.require(dict(os.environ)==original,'host environment changed before positive control')
        # A fresh interpreter reaches this import only under the original host
        # profile, so the frozen leaf's import-time decorator sees real context.
        tests = ROOT/'tests'
        sys.path.insert(0,str(tests))
        module = importlib.import_module('test_reference_capacity_process')
        capacity.require(Path(module.__file__).resolve()==(tests/'test_reference_capacity_process.py').resolve(),
                         'host positive control resolved outside the current source')
        suite = unittest.TestLoader().loadTestsFromName(LEAF)
        count = suite.countTestCases()
        capacity.require(type(count) is int and count==1,'exactly one fixed host test must be selected')
        result = unittest.TextTestRunner(verbosity=2,stream=sys.stderr).run(suite)
        capacity.require(type(result.testsRun) is int and result.testsRun==1
                         and result.wasSuccessful() and not any((result.skipped,result.errors,result.failures,
                             result.expectedFailures,result.unexpectedSuccesses)),
                         'actual host positive control failed, skipped or did not run exactly once')
        capacity.require(dict(os.environ)==original,'host positive control changed its parent environment')
        return {'schema_version':1,'kind':'capacity_host_grant','status':'PASS','host_grant_verified':True,
                'run_context':ctx,'reservation':proof,'test_id':LEAF,'tests_run':1,'skipped':0,
                'parent_environment_unchanged':True,
                'scope':'Actual existing fixed sudo-readlink grant only; no new privilege or general sudo authority.'}


def main():
    try:
        value = run_gate()
    except (OSError, ValueError, KeyError, ImportError) as error:
        print(json.dumps({'status':'FAIL','host_grant_verified':False,'error_type':type(error).__name__}))
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0 if value['status'] in ('PASS', 'NOT_APPLICABLE') else 1


if __name__ == '__main__': raise SystemExit(main())
