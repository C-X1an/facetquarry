"""Tiny controls derived from independent findings; no mount/host qualification."""
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import reference_retained_image_probe as probe


class RetainedProbePreflightFindings(unittest.TestCase):
    def setUp(self):
        parent=ROOT/'.cache/tmp';parent.mkdir(parents=True,exist_ok=True)
        temporary=tempfile.TemporaryDirectory(prefix='probe-preflight-',dir=parent)
        self.addCleanup(temporary.cleanup);self.local=Path(temporary.name)

    def test_partial_quota_failure_still_attempts_exact_owned_outer_unmount(self):
        ctx={'source':'a'*64}
        p={'local':self.local,'mount':self.local/'inner','volume':self.local/'outer-mount',
           'image':self.local/'original.img','outer':self.local/'outer.img'}
        allocation={'run_context':ctx,'image_path':str(p['outer']),'mount_path':str(p['volume']),
                    'image_identity':[1,2,3]}
        for failed_phase in ('ownership','mount-binding','enospc'):
            with self.subTest(failed_phase=failed_phase),contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(probe,'admitted',return_value=(p,ctx)))
                stack.enter_context(patch.object(probe.os.path,'ismount',side_effect=lambda x:x==p['volume']))
                stack.enter_context(patch.object(probe,'outer',side_effect=FileNotFoundError('quota proof absent')))
                stack.enter_context(patch.object(probe,'load',return_value=allocation))
                stack.enter_context(patch.object(probe,'backing_identity',return_value=[1,2,3]))
                stack.enter_context(patch.object(probe,'save'))
                close=stack.enter_context(patch.object(probe,'close_exact',return_value={'status':'PASS'}))
                result=probe.cleanup()
                close.assert_called_once_with(p['outer'],p['volume'],'close-outer',False,probe.OUTER_BYTES)
                self.assertEqual(result['status'],'PASS')

    def test_mismatched_partial_allocation_never_authorizes_unmount(self):
        ctx={'source':'a'*64}
        p={'local':self.local,'mount':self.local/'inner','volume':self.local/'outer-mount',
           'image':self.local/'original.img','outer':self.local/'outer.img'}
        allocation={'run_context':ctx,'image_path':str(p['outer']),'mount_path':str(p['volume']),
                    'image_identity':[9,9,9]}
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(probe,'admitted',return_value=(p,ctx)))
            stack.enter_context(patch.object(probe.os.path,'ismount',side_effect=lambda x:x==p['volume']))
            stack.enter_context(patch.object(probe,'outer',side_effect=FileNotFoundError('quota proof absent')))
            stack.enter_context(patch.object(probe,'load',return_value=allocation))
            stack.enter_context(patch.object(probe,'backing_identity',return_value=[1,2,3]))
            stack.enter_context(patch.object(probe,'save'))
            close=stack.enter_context(patch.object(probe,'close_exact'))
            result=probe.cleanup()
            self.assertEqual(result['status'],'FAIL');close.assert_not_called()

    def observe(self,payload):
        p={'local':self.local,'image':self.local/'original.img','mount':self.local/'inner'}
        ctx={'source':'a'*64}
        def producer(root,output):
            self.assertTrue(admission.called,'inventory opened before admitted producer reservation')
            with output.open('xb') as stream:stream.write(payload)
            return {'complete':True,'inventory_bytes':len(payload)},[]
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(probe,'INVENTORY_BYTES',32))
            stack.enter_context(patch.object(probe,'admitted',return_value=(p,ctx)))
            stack.enter_context(patch.object(probe,'outer'))
            stack.enter_context(patch.object(probe,'load',return_value={'run_context':ctx,'image_identity':[1,2,3]}))
            stack.enter_context(patch.object(probe,'identity',return_value=[1,2,3]))
            stack.enter_context(patch.object(probe,'hash_regular',return_value=probe.recovery.IMAGE_SHA))
            admission=stack.enter_context(patch.object(probe,'external'))
            stack.enter_context(patch.object(probe,'save'))
            stack.enter_context(patch.object(probe,'command'))
            stack.enter_context(patch.object(probe,'mount_binding',return_value={}))
            stack.enter_context(patch.object(probe.recovery,'walk_inventory',side_effect=producer))
            stack.enter_context(patch.object(probe,'candidate_observation',return_value={}))
            return probe.observe()

    def test_inventory_refuses_before_emitting_the_first_byte_over_its_reserved_ceiling(self):
        with self.assertRaises(ValueError):self.observe(b'x'*33)
        output=self.local/'original-file-inventory.jsonl'
        self.assertTrue(output.is_file())
        self.assertLessEqual(output.stat().st_size,32)

    def test_exact_inventory_ceiling_remains_usable(self):
        self.assertEqual(self.observe(b'x'*32)['status'],'PASS')
        self.assertEqual((self.local/'original-file-inventory.jsonl').read_bytes(),b'x'*32)


if __name__=='__main__':unittest.main()
