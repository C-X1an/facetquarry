"""Synthetic admission arithmetic only; NO actual capacity or quota proof."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import reference_result_capacity as capacity


class ResultCapacityTests(unittest.TestCase):
    def counters(self):
        return {'f_frsize':4096,'f_blocks':268554,'f_bfree':260000,'f_bavail':260000,
                'f_files':67000,'f_ffree':65000,'f_favail':65000}

    def test_full_floor_requires_both_space_and_inodes_without_claiming_upper_bound(self):
        good=self.counters()
        self.assertEqual(capacity.decide(good,'full')['admission'],'ALLOW')
        self.assertFalse(capacity.decide(good,'full')['reference_floor']['guaranteed_current_output_upper_bound'])
        for edit in ({'f_bfree':100000,'f_bavail':100000},{'f_ffree':100,'f_favail':100}):
            self.assertEqual(capacity.decide({**good,**edit},'full')['admission'],'REFUSE')
            self.assertEqual(capacity.decide({**good,**edit},'smoke')['admission'],'ALLOW')

    def test_invalid_counters_fail_instead_of_becoming_zero_usage(self):
        for key,value in (('f_frsize',512),('f_bavail',True),('f_favail',-1),('f_ffree',68000),('f_files',None)):
            with self.subTest(key=key),self.assertRaises(ValueError):capacity.decide({**self.counters(),key:value},'full')

    def test_remaining_job_time_reserves_measurement_and_complete_failure_tail(self):
        start=1793260000
        plan=capacity.time_plan(start,start)
        self.assertEqual(plan['admission'],'ALLOW')
        self.assertEqual(plan['complete_failure_tail_seconds'],1200)
        boundary=start+capacity.transport.JOB_SECONDS-plan['required_remaining_seconds']
        self.assertEqual(capacity.time_plan(start,boundary)['admission'],'REFUSE')
        self.assertEqual(capacity.time_plan(start,boundary-1)['admission'],'ALLOW')


if __name__=='__main__':unittest.main()
