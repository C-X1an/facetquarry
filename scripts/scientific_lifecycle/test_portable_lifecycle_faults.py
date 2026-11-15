"""Fake-descriptor/error-data units only; never Linux execution or enforcement."""
import errno
import hashlib
import json
from pathlib import PurePosixPath
from types import SimpleNamespace
import unittest
from unittest import mock

import scientific_posix_lifecycle as life


def leaves(error):
    if isinstance(error,BaseExceptionGroup):
        return [leaf for child in error.exceptions for leaf in leaves(child)]
    return [error]


class FakeOS:
    O_RDONLY=O_WRONLY=O_CREAT=O_EXCL=O_NOFOLLOW=0
    def __init__(self, failures=None):self.failures=failures or {};self.closes=[];self.opens=iter([31,32]);self.written=bytearray()
    def close(self,fd):
        if fd not in (21,22,31,32,55):raise AssertionError('UNOWNED_FAKE_FD')
        self.closes.append(fd)
        if fd in self.failures:raise self.failures[fd]
    def fstatvfs(self,fd):return SimpleNamespace(f_frsize=4096,f_bsize=4096)
    def open(self,*args,**kwargs):return next(self.opens)
    def fstat(self,fd):return object()
    def fsync(self,fd):pass


class PortableLifecycleFaults(unittest.TestCase):
    def error_leaves(self,records):
        return [leaf for record in records for leaf in record.get('leaf_errors',[record])]

    def assert_recorded(self,records,error):
        self.assertTrue(any(row['type']==type(error).__name__ and row['errno']==getattr(error,'errno',None)
            and row['message']==str(error) for row in self.error_leaves(records)),records)

    def raised(self,function):
        try:function()
        except BaseException as error:return error
        self.fail('EXPECTED_SYNTHETIC_FAILURE')

    def test_snapshot_setup_failure_closes_owner_and_retains_primary_and_cleanup(self):
        primary=RuntimeError('SNAPSHOT_CLOCK');cleanup=OSError(errno.EIO,'ROOT_CLOSE');ops=FakeOS({55:cleanup})
        with mock.patch.object(life,'os',ops),mock.patch.object(life,'explicit_path',side_effect=PurePosixPath),\
             mock.patch.object(life,'owned_dir',return_value=55),\
             mock.patch.object(life,'time',SimpleNamespace(monotonic=lambda:(_ for _ in ()).throw(primary))):
            result=None;caught=None
            try:result=life.snapshot_tree('/owned')
            except BaseException as error:caught=error
        self.assertEqual(ops.closes,[55])
        if caught is not None:
            self.assertIn(primary,leaves(caught));self.assertIn(cleanup,leaves(caught))
        else:
            self.assertFalse(result['enumeration_complete']);self.assertFalse(result['safe'])
            self.assert_recorded(result['errors'],primary);self.assert_recorded(result['errors'],cleanup)

    def test_neutral_write_clock_failure_closes_parent_and_retains_both_errors(self):
        primary=RuntimeError('WRITE_CLOCK');cleanup=OSError(errno.EIO,'PARENT_CLOSE');ops=FakeOS({55:cleanup})
        with mock.patch.object(life,'os',ops),mock.patch.object(life,'explicit_path',side_effect=PurePosixPath),\
             mock.patch.object(life,'owned_dir',return_value=55),\
             mock.patch.object(life,'time',SimpleNamespace(monotonic=lambda:(_ for _ in ()).throw(primary))):
            result=None;caught=None
            try:result=life.write_neutral('/owned',{},'/export/a')
            except BaseException as error:caught=error
        self.assertEqual(ops.closes,[55])
        if caught is not None:
            self.assertIn(primary,leaves(caught));self.assertIn(cleanup,leaves(caught))
        else:
            self.assert_recorded(result['errors'],primary);self.assert_recorded(result['errors'],cleanup)
            self.assertEqual(result['framed_entries'],0)

    def verify_setup(self,fail_hash):
        primary=RuntimeError('VERIFY_HASH' if fail_hash else 'VERIFY_CLOCK');cleanup=OSError(errno.EIO,'VERIFY_PARENT')
        ops=FakeOS({55:cleanup})
        timer=SimpleNamespace(monotonic=(lambda:0) if fail_hash else lambda:(_ for _ in ()).throw(primary))
        hashing=SimpleNamespace(sha256=lambda:(_ for _ in ()).throw(primary)) if fail_hash else hashlib
        with mock.patch.object(life,'os',ops),mock.patch.object(life,'explicit_path',side_effect=PurePosixPath),\
             mock.patch.object(life,'owned_dir',return_value=55),mock.patch.object(life,'hash_file',return_value={}),\
             mock.patch.object(life,'time',timer),mock.patch.object(life,'hashlib',hashing):
            error=self.raised(lambda:life.verify_neutral('/export/a'))
        self.assertEqual(ops.closes,[55]);self.assertIn(primary,leaves(error));self.assertIn(cleanup,leaves(error))

    def test_neutral_verify_clock_failure_is_under_cleanup_guard(self):self.verify_setup(False)
    def test_neutral_verify_hash_constructor_failure_is_under_cleanup_guard(self):self.verify_setup(True)

    def test_written_second_prefix_has_reference_after_copy_and_close_failures(self):
        primary=OSError(errno.EIO,'COPY_READ');cleanup=OSError(errno.EBADF,'SOURCE_CLOSE')
        ops=FakeOS({31:cleanup});chunks=iter([b'ab'])
        def read(fd,maximum):
            try:return next(chunks)
            except StopIteration:raise primary
        ops.read=read
        def reference(path,maximum):
            raw=b'abc' if path.name=='a' else bytes(ops.written)
            return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':['sig']}
        def write(fd,raw):self.assertEqual(fd,32);ops.written.extend(raw)
        result=None;caught=None
        with mock.patch.object(life,'os',ops),mock.patch.object(life,'explicit_path',side_effect=PurePosixPath),\
             mock.patch.object(life,'owned_dir',side_effect=[21,22]),mock.patch.object(life,'hash_file',side_effect=reference),\
             mock.patch.object(life,'signature',return_value=('sig',)),mock.patch.object(life,'write_all',side_effect=write):
            try:result=life.copy_blob('/source/a','/export/b',10)
            except BaseException as error:caught=error
        self.assertEqual(ops.closes,[31,32,21,22]);self.assertEqual(bytes(ops.written),b'ab')
        self.assertIsNone(caught)
        self.assertEqual(result['destination']['bytes'],2)
        self.assertEqual(result['destination']['sha256'],hashlib.sha256(b'ab').hexdigest())
        self.assertFalse(result['verified_equal']);self.assert_recorded(result['errors'],primary);self.assert_recorded(result['errors'],cleanup)

    def test_collection_references_a_and_b_independently_when_copy_and_strict_verify_raise(self):
        snapshot={'rows':[],'errors':[],'enumeration_complete':True,'safe':True}
        raw_a,raw_b=b'bad-a',b'partial-b'
        def reference(path,maximum):
            raw=raw_b if path.name=='fixture-copy.neutral' else raw_a
            return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':[1]}
        failure=OSError(errno.EIO,'COPY_CLOSE_AFTER_WRITTEN_B')
        with mock.patch.object(life,'explicit_path',side_effect=PurePosixPath),\
             mock.patch.object(life,'snapshot_tree',return_value=snapshot),\
             mock.patch.object(life,'inventory_fingerprint',return_value='a'*64),\
             mock.patch.object(life,'write_neutral',return_value={'errors':[]}),\
             mock.patch.object(life,'hash_file',side_effect=reference),\
             mock.patch.object(life,'copy_blob',side_effect=failure),\
             mock.patch.object(life,'verify_neutral',side_effect=RuntimeError('MALFORMED_NEUTRAL')) as verify:
            result=life.collect_tree('/owned','/exports',quiescent=True)
        self.assertEqual(result['neutral_prefix']['sha256'],hashlib.sha256(raw_a).hexdigest())
        self.assertEqual(result['second_prefix']['sha256'],hashlib.sha256(raw_b).hexdigest())
        self.assertEqual(verify.call_count,2);self.assertFalse(result['source_tree_complete'])
        self.assertTrue(result['raw_source_retained']);self.assertTrue(result['raw_image_export_required'])
        self.assert_recorded(result['errors'],failure)

    def test_nested_group_serialization_keeps_each_leaf_type_errno_message_and_context(self):
        primary=RuntimeError('BODY');first=OSError(errno.EIO,'FIRST_CLOSE');second=KeyboardInterrupt('SECOND_CLOSE')
        error=BaseExceptionGroup('outer',[primary,BaseExceptionGroup('cleanup',[first,second])])
        rows=[];life.add_error(rows,error,'failure-path')
        transported=json.loads(json.dumps(rows))
        for expected in (primary,first,second):self.assert_recorded(transported,expected)
        self.assertTrue(transported[0]['group_context']);self.assertFalse(transported[0]['details_truncated'])

    def test_group_and_error_list_overflow_are_bounded_and_explicit(self):
        error=ExceptionGroup('many',[OSError(errno.EIO,'x'*512) for _ in range(64)])
        record=life.error_record(error,'bounded')
        self.assertTrue(record['details_truncated']);self.assertLessEqual(len(life.json_bytes(record)),2048)
        self.assertLessEqual(len(record['leaf_errors']),16)
        errors=[]
        for _ in range(70):life.add_error(errors,error,'bounded')
        self.assertLessEqual(len(life.json_bytes(errors)),16384)
        self.assertTrue(any(row['type']=='INCOMPLETE' for row in errors))

    def test_long_message_prefixes_have_explicit_truncation_flags(self):
        single=life.error_record(RuntimeError('s'*512),'single')
        self.assertTrue(single['details_truncated']);self.assertTrue(single['message_truncated'])
        group=life.error_record(ExceptionGroup('group',[RuntimeError('g'*512)]),'group')
        self.assertTrue(group['details_truncated'])
        self.assertTrue(group['leaf_errors'][0]['message_truncated'])
        self.assertLessEqual(len(life.json_bytes(single)),2048)
        self.assertLessEqual(len(life.json_bytes(group)),2048)


if __name__=='__main__':unittest.main()
