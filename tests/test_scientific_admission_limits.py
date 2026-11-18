"""Exact admission-function fault controls; injected bytes/clock, no Linux job.

The driver is SHA-pinned and only its admission functions/constants are selected
as AST. These pure boundary controls make no quota, provider or live-job claim.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT/'scripts/run_scientific_lifecycle_job.py'
EXPECTED_DRIVER_SHA = 'c428110971b73a97da509463bac17b4f3a35a043fc00abdcac1c08d5e929e07d'
NOW = 1_795_000_000

def selected_admission():
    raw = DRIVER.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED_DRIVER_SHA
    tree = ast.parse(raw)
    names = {'need','integer','digest','decode','admission'}
    constants = {'BRANCH','ADMISSION','ADMISSION_FORMAT','ADMISSION_STATUS','LIFE_SHA',
        'EVIDENCE_SHA','COMMON_SHA','BASE_BYTES','OTHER_BYTES','BASELINE_CEILING','SUPPLEMENT_BYTES','SMALL'}
    scope = {'hashlib':hashlib,'json':json,'re':re,'time':SimpleNamespace(time=lambda:NOW)}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0],ast.Name):
            name = node.targets[0].id
            if name in constants:
                scope[name] = eval(compile(ast.Expression(node.value),str(DRIVER)+'::constant','eval'),
                    {'__builtins__':{}},{})
    assert constants <= scope.keys()
    selected = [node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names]
    assert {node.name for node in selected} == names
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(DRIVER)+'::admission','exec'),scope)
    return scope

class AdmissionLimits(unittest.TestCase):
    def setUp(self):
        self.scope = selected_admission()
        s = self.scope
        self.valid = {'format':s['ADMISSION_FORMAT'],'status':s['ADMISSION_STATUS'],
            'branch':s['BRANCH'],'attempt_id':'bounded-admission-control',
            'created_unix_seconds':NOW-1,'expires_unix_seconds':NOW+60,
            'baseline_including_reserve_bytes':9_600_000_000,'global_reserve_bytes':2_000_000_000,
            'fresh_inventory_sha256':'1'*64,'base_lifecycle_bytes':s['BASE_BYTES'],
            'connector_bytes':536_870_912,'supplement_bytes':s['SUPPLEMENT_BYTES'],
            'other_growth_bytes':s['OTHER_BYTES'],'no_other_heavy_process':True,
            'independent_review_closed':True,'source_pins':{'job_script_sha256':EXPECTED_DRIVER_SHA,
                'lifecycle_manifest_sha256':s['LIFE_SHA'],'evidence_sha256':s['EVIDENCE_SHA'],
                'common_sha256':s['COMMON_SHA']}}

    def check(self,value,*,expected=None,ref=None):
        raw = (json.dumps(value,separators=(',',':'))+'\n').encode()
        def supplied_read(path, maximum):
            self.assertEqual(path,ROOT/self.scope['ADMISSION'])
            self.assertEqual(maximum,8192)
            self.assertLessEqual(len(raw),maximum)
            return raw
        self.scope['read'] = supplied_read
        result,original = self.scope['admission'](ROOT,
            expected or hashlib.sha256(raw).hexdigest(),EXPECTED_DRIVER_SHA,
            self.scope['BRANCH'] if ref is None else ref)
        self.assertEqual(original,raw)
        self.assertEqual(result,value)
        return result

    def test_fixed_ceiling_is_accepted_and_one_byte_above_is_refused(self):
        value = copy.deepcopy(self.valid)
        value['baseline_including_reserve_bytes'] = 9_850_000_000
        self.check(value)
        self.assertEqual(self.scope['BASELINE_CEILING'],9_850_000_000)
        self.assertEqual(value['baseline_including_reserve_bytes']+self.scope['BASE_BYTES']+
            self.scope['OTHER_BYTES'],11_947_152_000)
        value['baseline_including_reserve_bytes'] += 1
        with self.assertRaisesRegex(RuntimeError,'BOUNDED_TYPED_INTEGER'):
            self.check(value)

    def test_noninteger_or_malformed_baselines_are_refused(self):
        for baseline in [True,False,None,'9850000000',9_850_000_000.0,-1,1_999_999_999]:
            with self.subTest(baseline=baseline):
                value = copy.deepcopy(self.valid)
                value['baseline_including_reserve_bytes'] = baseline
                with self.assertRaises((RuntimeError,ValueError)):
                    self.check(value)

    def test_unchanged_reserve_and_each_growth_slice_are_required(self):
        for name in ['global_reserve_bytes','base_lifecycle_bytes','connector_bytes',
                     'supplement_bytes','other_growth_bytes']:
            with self.subTest(name=name):
                value = copy.deepcopy(self.valid)
                value[name] -= 1
                with self.assertRaisesRegex(RuntimeError,'COMPLETE_FIXED_PEAK_ADMISSION'):
                    self.check(value)

    def test_stale_expired_future_or_excessive_lifetime_is_refused(self):
        for created,expires in [(NOW-21601,NOW-1),(NOW-61,NOW-1),
                                (NOW+31,NOW+100),(NOW-1,NOW+21600)]:
            with self.subTest(created=created,expires=expires):
                value = copy.deepcopy(self.valid)
                value.update(created_unix_seconds=created,expires_unix_seconds=expires)
                with self.assertRaises(RuntimeError):
                    self.check(value)

    def test_digest_branch_and_each_source_pin_must_match(self):
        with self.assertRaisesRegex(RuntimeError,'INDEPENDENT_ADMISSION_DIGEST'):
            self.check(self.valid,expected='2'*64)
        with self.assertRaisesRegex(RuntimeError,'EXACT_NEW_PROOF_BRANCH_ONLY'):
            self.check(self.valid,ref='refs/heads/main')
        for name in self.valid['source_pins']:
            with self.subTest(pin=name):
                value = copy.deepcopy(self.valid)
                value['source_pins'][name] = '2'*64
                with self.assertRaisesRegex(RuntimeError,'EXACT_REVIEWED_SOURCE_PINS'):
                    self.check(value)
        value = copy.deepcopy(self.valid)
        value['fresh_inventory_sha256'] = '0'*64
        with self.assertRaisesRegex(RuntimeError,'INDEPENDENT_NONZERO_SHA256_REQUIRED'):
            self.check(value)

    def test_independent_total_guard_rejects_exactly_twelve_billion(self):
        # Isolate the independent peak guard from the stricter baseline cap in
        # this injected unit namespace only; production source is untouched.
        s = self.scope
        old = s['BASELINE_CEILING']
        s['BASELINE_CEILING'] = 12_000_000_000
        try:
            value = copy.deepcopy(self.valid)
            value['baseline_including_reserve_bytes'] = 12_000_000_000-s['BASE_BYTES']-s['OTHER_BYTES']
            with self.assertRaisesRegex(RuntimeError,'COMPLETE_FIXED_PEAK_ADMISSION'):
                self.check(value)
            value['baseline_including_reserve_bytes'] -= 1
            self.check(value)
        finally:
            s['BASELINE_CEILING'] = old

if __name__ == '__main__':
    unittest.main(verbosity=2)
