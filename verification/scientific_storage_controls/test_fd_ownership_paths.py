"""Injected ownership-failure unit controls; no actual POSIX FDs or fixtures.

Every descriptor is a synthetic integer intercepted by FakeOS. Passing these
controls establishes neither kernel failure semantics nor filesystem durability.
"""
from contextlib import ExitStack, contextmanager
import hashlib
from pathlib import PurePosixPath
from types import SimpleNamespace
import unittest
from unittest import mock

import raw_member_store as store
import scientific_raw_reference_v2 as rawref
import scientific_registry_publication as publication
import run_scientific_posix_integration as launcher


def leaves(error):
    if isinstance(error, BaseExceptionGroup):
        return [item for child in error.exceptions for item in leaves(child)]
    return [error]


def info(size=3, directory=True):
    return SimpleNamespace(st_mode=(0o040700 if directory else 0o100600), st_uid=0,
        st_dev=1, st_ino=100, st_nlink=1, st_size=size, st_blocks=0,
        st_mtime_ns=1, st_ctime_ns=1, f_frsize=4096, f_bsize=4096)


class FakeOS:
    """No fallback to a real OS operation is permitted."""
    O_RDONLY=O_WRONLY=O_CREAT=O_EXCL=O_NOFOLLOW=O_DIRECTORY=O_CLOEXEC=SEEK_SET=0

    def __init__(self, failures=None):
        self.failures=failures or {}; self.closes=[]; self.opens=[10,11]
    def close(self, fd):
        if type(fd) is not int:
            raise AssertionError('ONLY_FAKE_INTEGER_DESCRIPTORS')
        self.closes.append(fd)
        if fd in self.failures:
            raise self.failures[fd]
    def open(self, *args, **kwargs): return self.opens.pop(0)
    def fstat(self, fd): return info()
    def stat(self, *args, **kwargs): return info()
    def getuid(self): return 0
    def geteuid(self): return 0
    def dup(self, fd): return 10
    def fsync(self, fd): pass
    def mkdir(self, *args, **kwargs): pass
    def write(self, fd, raw): return len(raw)
    def fstatvfs(self, fd): return info()
    def lseek(self, *args): pass


@contextmanager
def operations(ops, *modules):
    with ExitStack() as stack:
        for module in dict.fromkeys((store,rawref,*modules)):
            stack.enter_context(mock.patch.object(module,'os',ops))
        yield stack


class ReachableOwnershipControls(unittest.TestCase):
    def capture(self, function):
        try:
            function()
        except BaseException as error:
            return error
        self.fail('EXPECTED_INJECTED_FAILURE')

    def test_directory_root_transfers_never_retry_parent_or_lose_child(self):
        cases=[(launcher,lambda:launcher.owned_directory(PurePosixPath('/owned'),private_final=True)),
               (publication,lambda:publication._owned_base('/owned')),
               (store,lambda:store._open_root('/owned')),
               (rawref,lambda:rawref._root('/owned'))]
        for module,call in cases:
            with self.subTest(module=module.__name__):
                failure=OSError('PARENT_CONSUMED_THEN_CLOSE_RAISED'); ops=FakeOS({10:failure})
                with operations(ops,module) as stack:
                    if hasattr(module,'_platform'):
                        stack.enter_context(mock.patch.object(module,'_platform',return_value=None))
                    if hasattr(module,'Path'):
                        stack.enter_context(mock.patch.object(module,'Path',PurePosixPath))
                    error=self.capture(call)
                self.assertEqual(ops.closes,[10,11])
                self.assertIn(failure,leaves(error))

    def test_rawref_at_transfer_releases_new_child_without_closing_borrowed_root(self):
        failure=OSError('AT_PARENT_CLOSE'); ops=FakeOS({10:failure})
        with operations(ops),mock.patch.object(rawref,'_dir',return_value=11):
            error=self.capture(lambda:rawref._at(99,'owned/file'))
        self.assertEqual(ops.closes,[10,11]); self.assertIn(failure,leaves(error))
        self.assertNotIn(99,ops.closes)

    def test_ancestor_sync_transfer_attempts_each_owner_once(self):
        failure=OSError('SYNC_PARENT_CLOSE'); ops=FakeOS({10:failure})
        with operations(ops),mock.patch.object(rawref,'Path',PurePosixPath):
            error=self.capture(lambda:rawref._sync_ancestors('/owned'))
        self.assertEqual(ops.closes,[10,11]); self.assertIn(failure,leaves(error))

    def test_resolver_release_consumes_failed_number_before_second_release(self):
        failure=OSError('RESOLVER_CLOSE_CONSUMED'); ops=FakeOS({41:failure})
        resolver=rawref.Resolver.__new__(rawref.Resolver); resolver.fd=41
        with operations(ops):
            error=self.capture(resolver.release)
            self.assertIsNone(resolver.fd)
            resolver.release()
        self.assertEqual(ops.closes,[41]); self.assertIn(failure,leaves(error))

    def test_store_open_postacquisition_fstat_failure_releases_new_fd(self):
        primary=RuntimeError('POST_OPEN_FSTAT'); cleanup=OSError('FILE_CLOSE')
        ops=FakeOS({10:cleanup}); ops.fstat=lambda fd:(_ for _ in ()).throw(primary)
        with operations(ops),mock.patch.object(store,'_regular',return_value=None):
            error=self.capture(lambda:store._open_file(99,'file'))
        self.assertEqual(ops.closes,[10]); self.assertIn(primary,leaves(error)); self.assertIn(cleanup,leaves(error))

    @contextmanager
    def scanned_file_operations(self, ops, primary=None):
        file_info=info(directory=False)
        file=SimpleNamespace(name='file',stat=lambda **kwargs:file_info)
        root_entry=SimpleNamespace(name='txn-'+'b'*32)
        @contextmanager
        def scandir(fd):
            if fd==55: yield iter([root_entry])
            elif fd==54: yield iter([file])
            else: raise AssertionError('UNEXPECTED_SCANNED_FAKE_DESCRIPTOR')
        ops.name='posix'; ops.scandir=scandir
        chunks=iter([b'abc',b''])
        def read(fd, maximum):
            if primary is not None: raise primary
            return next(chunks)
        ops.read=read
        with operations(ops),mock.patch.object(store,'_open_file',return_value=(21,file_info)),\
             mock.patch.object(store,'_same_file'),mock.patch.object(store,'_open_root',return_value=55),\
             mock.patch.object(store,'_open_dir',return_value=54):
            yield

    def test_scan_keeps_observed_file_and_grouped_hash_failures(self):
        for body_failure in (False,True):
            with self.subTest(body_failure=body_failure):
                primary=RuntimeError('HASH_READ') if body_failure else None
                cleanup=OSError('HASH_CLOSE'); ops=FakeOS({21:cleanup})
                with self.scanned_file_operations(ops,primary):
                    error=self.capture(lambda:store._scan(54))
                self.assertIsInstance(error,store.InventoryRefusal)
                self.assertEqual(len(error.observed),1); row=error.observed[0]
                self.assertEqual((row['path'],row['kind'],row['bytes'],row['safe']),('file','file',3,False))
                self.assertEqual(ops.closes,[21]); self.assertIn(cleanup,leaves(error.__cause__))
                if primary is not None: self.assertIn(primary,leaves(error.__cause__))

    def test_recover_retains_observed_inventory_after_grouped_hash_close_failure(self):
        cleanup=OSError('HASH_CLOSE'); ops=FakeOS({21:cleanup})
        with self.scanned_file_operations(ops):
            result=store.recover('/owned')
        self.assertEqual(result['state'],'READ_ONLY_RECOVERY_REPORT')
        self.assertTrue(result['all_root_entries_reported']); self.assertFalse(result['evidence_deleted'])
        self.assertEqual(len(result['transactions']),1); row=result['transactions'][0]
        self.assertEqual(row['state'],'REFUSED_OR_PARTIAL_RETAIN_ALL')
        self.assertFalse(row['committed_accepted']); self.assertFalse(row['inventory_complete'])
        self.assertEqual(len(row['inventory']),1)
        self.assertEqual(row['inventory'][0]['path'],'file'); self.assertFalse(row['inventory'][0]['safe'])
        self.assertEqual(ops.closes,[21,54,55])

    def test_scan_retains_prior_errors_when_later_traversal_terminates(self):
        for mode in ('bound','stat','iteration','exit'):
            with self.subTest(mode=mode):
                primary=OSError('FIRST_HASH_READ'); cleanup=OSError('FIRST_HASH_CLOSE')
                terminal=OSError('LATER_'+mode.upper()); ops=FakeOS({21:cleanup})
                first=SimpleNamespace(name='first',stat=lambda **kwargs:info(directory=False))
                second=SimpleNamespace(name='second',stat=lambda **kwargs:(_ for _ in ()).throw(terminal))
                def entries():
                    yield first
                    raise terminal
                @contextmanager
                def scandir(fd):
                    self.assertEqual(fd,54)
                    if mode=='iteration': yield entries()
                    else: yield iter([first] if mode=='exit' else [first,second])
                    if mode=='exit': raise terminal
                with self.scanned_file_operations(ops,primary):
                    ops.scandir=scandir
                    error=self.capture(lambda:store._scan(54,limit=1 if mode=='bound' else store.MAX_ENTRIES))
                self.assertIsInstance(error,store.InventoryRefusal)
                self.assertEqual(len(error.observed),1); self.assertEqual(error.observed[0]['path'],'first')
                errors=leaves(error.__cause__)
                self.assertIn(primary,errors); self.assertIn(cleanup,errors)
                if mode=='bound':
                    self.assertTrue(any(isinstance(item,store.Refusal) and str(item)=='INVENTORY_COUNT_BOUND' for item in errors))
                else: self.assertIn(terminal,errors)
                self.assertEqual(ops.closes,[21])

    def test_snapshot_root_fstat_failure_is_inside_cleanup_guard(self):
        primary=RuntimeError('SNAPSHOT_FSTAT'); cleanup=OSError('ROOT_CLOSE')
        ops=FakeOS({10:cleanup}); ops.fstat=lambda fd:(_ for _ in ()).throw(primary)
        with operations(ops,publication),mock.patch.object(publication,'_owned_base',return_value=10):
            error=self.capture(lambda:publication.snapshot_owned_base('/owned',maximum_entries=8,
                                maximum_file_bytes=1024,allocation_unit=4096))
        self.assertEqual(ops.closes,[10]); self.assertIn(primary,leaves(error)); self.assertIn(cleanup,leaves(error))

    def reference_context(self):
        run,binding={},{}
        reference={'store':'owned','catalog_sha256':'a'*64,'catalog_bytes':1,'reference_id':'b'*32,
                   'run_sha256':rawref.sha(rawref.canonical(run)),
                   'binding_sha256':rawref.sha(rawref.canonical(binding)),
                   'bytes':3,'sha256':hashlib.sha256(b'abc').hexdigest()}
        return reference,run,binding

    @contextmanager
    def resolve_validation(self):
        with mock.patch.object(rawref,'validate_reference'),mock.patch.object(rawref,'validate_run'),\
             mock.patch.object(rawref,'validate_binding'):
            yield

    def test_resolve_dup_failure_releases_already_acquired_base(self):
        primary=RuntimeError('DUP_FAILED'); cleanup=OSError('BASE_CLOSE'); ops=FakeOS({55:cleanup})
        ops.dup=lambda fd:(_ for _ in ()).throw(primary)
        reference,run,binding=self.reference_context()
        with operations(ops),self.resolve_validation(),mock.patch.object(rawref,'_root',return_value=55):
            error=self.capture(lambda:rawref.resolve_reference('/owned',reference,run,binding,3))
        self.assertEqual(ops.closes,[55]); self.assertIn(primary,leaves(error)); self.assertIn(cleanup,leaves(error))

    def test_batch_constructor_setup_failure_releases_root(self):
        primary=RuntimeError('UUID_SETUP_FAILED'); cleanup=OSError('BATCH_ROOT_CLOSE'); ops=FakeOS({55:cleanup})
        budget=rawref.Budget(0,0,1<<20)
        with operations(ops),mock.patch.object(rawref,'primitive_contract'),\
             mock.patch.object(rawref,'validate_run'),mock.patch.object(rawref,'_root',return_value=55),\
             mock.patch.object(rawref.uuid,'uuid4',side_effect=primary):
            error=self.capture(lambda:rawref.Batch('/owned',{},budget))
        self.assertEqual(ops.closes,[55]); self.assertIn(primary,leaves(error)); self.assertIn(cleanup,leaves(error))

    def test_begin_failure_attempts_writer_and_all_directories_at_every_position(self):
        for failed_fd in (51,52,53,54,55):
            with self.subTest(failed_fd=failed_fd):
                primary=RuntimeError('SAVE_FAILED'); cleanup=OSError('BEGIN_CLOSE')
                ops=FakeOS({failed_fd:cleanup}); ops.opens=[51]
                declared={'source':'a'*64,'transaction':'b'*32}
                with operations(ops),mock.patch.object(store,'_declaration',return_value=(declared,[],{})),\
                     mock.patch.object(store,'_open_root',return_value=55),\
                     mock.patch.object(store,'_root_writer_lock'),mock.patch.object(store,'_root_slots'),\
                     mock.patch.object(store,'_open_dir',side_effect=[54,53,52]),\
                     mock.patch.object(store.Transaction,'_save',side_effect=primary):
                    error=self.capture(lambda:store.begin('/owned','a'*64,'b'*32,(),store.Plan(1<<20)))
                self.assertEqual(ops.closes,[51,52,53,54,55])
                self.assertIn(primary,leaves(error)); self.assertIn(cleanup,leaves(error))

    def test_restore_attempts_every_local_close_at_every_position(self):
        source,transaction='a'*64,'b'*32; commit='c'*64
        member=store.Member('file',3,hashlib.sha256(b'abc').hexdigest())
        closed=store._canonical({'version':1,'source':source,'transaction':transaction,
                                'committed':True,'commit_sha256':commit,'writers_closed':True})
        for failed_fd in (53,54,55):
            with self.subTest(failed_fd=failed_fd):
                cleanup=OSError('RESTORE_CLOSE'); ops=FakeOS({failed_fd:cleanup})
                def read(parent,name,maximum): return {'closed.json':closed,'file':b'abc','transaction.json':b'{}'}[name]
                with operations(ops),mock.patch.object(store,'recover',return_value={'state':'READ_ONLY_RECOVERY_REPORT',
                     'transactions':[{'name':'txn-'+transaction,'committed_accepted':True}]}),\
                     mock.patch.object(store,'_open_root',return_value=55),\
                     mock.patch.object(store,'_open_dir',side_effect=[54,53]),mock.patch.object(store,'_read',side_effect=read),\
                     mock.patch.object(store,'_load_declaration',return_value=({'source':source,'transaction':transaction},[member],{})),\
                     mock.patch.object(store,'_verify_commit',return_value=({},commit)):
                    error=self.capture(lambda:store.restore('/owned',source,transaction,'file'))
                self.assertEqual(ops.closes,[53,54,55]); self.assertIn(cleanup,leaves(error))

    def test_packing_output_close_failure_still_finalizes_iterator_and_retains_all_errors(self):
        primary=RuntimeError('ITERATION_FAILED'); output=OSError('OUTPUT_CLOSE'); iterator_error=RuntimeError('ITERATOR_CLOSE')
        finalized=[]
        class Chunks:
            def __iter__(self): return self
            def __next__(self): raise primary
            def close(self): finalized.append(True); raise iterator_error
        tx=store.Transaction.__new__(store.Transaction); tx._budget=lambda pending:None
        ops=FakeOS({10:output})
        with operations(ops): error=self.capture(lambda:tx._write(99,'file',Chunks(),10))
        self.assertEqual(ops.closes,[10]); self.assertEqual(finalized,[True])
        for expected in (primary,output,iterator_error): self.assertIn(expected,leaves(error))

    def test_packing_iter_acquisition_failure_does_not_leak_output(self):
        primary=RuntimeError('ITER_ACQUISITION'); cleanup=OSError('OUTPUT_CLOSE')
        class Chunks:
            def __iter__(self): raise primary
        tx=store.Transaction.__new__(store.Transaction); tx._budget=lambda pending:None; ops=FakeOS({10:cleanup})
        with operations(ops): error=self.capture(lambda:tx._write(99,'file',Chunks(),10))
        self.assertEqual(ops.closes,[10]); self.assertIn(primary,leaves(error)); self.assertIn(cleanup,leaves(error))

    def test_resolve_cleanup_preserves_body_and_all_owners_after_resolver_failure(self):
        primary=RuntimeError('ORIGINAL_READ'); errors={52:OSError('RESOLVER'),53:OSError('TARGET'),55:OSError('BASE')}
        ops=FakeOS(errors); ops.dup=lambda fd:54
        resolver=SimpleNamespace(fd=52,catalog_bytes=1,read_original=lambda *a:(_ for _ in ()).throw(primary),
                                 release=lambda:ops.close(52))
        reference,run,binding=self.reference_context()
        with operations(ops),self.resolve_validation(),mock.patch.object(rawref,'_root',return_value=55),\
             mock.patch.object(rawref,'_dir',return_value=53),mock.patch.object(rawref,'Resolver',return_value=resolver):
            error=self.capture(lambda:rawref.resolve_reference('/owned',reference,run,binding,3))
        self.assertEqual(ops.closes,[54,52,53,55])
        for expected in (primary,*errors.values()): self.assertIn(expected,leaves(error))

    def test_iter_original_failure_attempts_both_locals_and_preserves_body(self):
        primary=RuntimeError('RESTORE_FAILED'); errors={21:OSError('ORIGINAL_CLOSE'),20:OSError('PARENT_CLOSE')}
        ops=FakeOS(errors); resolver=rawref.Resolver.__new__(rawref.Resolver)
        resolver.fd=99; resolver.root=PurePosixPath('/owned'); resolver._closure=lambda:None
        resolver.catalog={'run':{'source':'a'*64},'references':[{'id':'b'*32,'binding':{},
          'original':{'path':'originals/file','bytes':3,'sha256':hashlib.sha256(b'abc').hexdigest()},
          'chunks':[{'shard':'shards/a','transaction':'c'*32,'member':'file','bytes':3}]}]}
        with operations(ops),mock.patch.object(rawref,'validate_binding'),\
             mock.patch.object(rawref,'_at',return_value=(20,'file')),\
             mock.patch.object(rawref,'_open',return_value=(21,info())),mock.patch.object(store,'restore',side_effect=primary):
            error=self.capture(lambda:list(resolver.iter_original('b'*32,{})))
        self.assertEqual(ops.closes,[21,20]); self.assertNotIn(99,ops.closes)
        for expected in (primary,*errors.values()): self.assertIn(expected,leaves(error))

    def test_publisher_release_attempts_all_errors_and_consumes_every_field(self):
        errors={41:OSError('FIRST'),42:OSError('SECOND'),43:KeyboardInterrupt('THIRD')}
        ops=FakeOS(errors); p=publication.Publisher.__new__(publication.Publisher)
        p.directories={'a':41,'b':42}; p.fd=43; p.base_fd=44
        with operations(ops,publication):
            error=self.capture(p.release)
            self.assertEqual(p.directories,{}); self.assertIsNone(p.fd); self.assertIsNone(p.base_fd)
            p.release()
        self.assertEqual(ops.closes,[41,42,43,44])
        for expected in errors.values(): self.assertIn(expected,leaves(error))

    def test_batch_publish_control_failure_closes_both_transaction_locals(self):
        primary=RuntimeError('CONTROL_READ'); errors={64:OSError('TX_CLOSE'),63:OSError('TX_ROOT_CLOSE')}
        ops=FakeOS(errors); ops.read=lambda *args:b'abc'
        before=info(); writer=SimpleNamespace(name='file',closed=True,original={'identity':rawref._signature(before)})
        chunk={'shard':'shards/one','transaction':'c'*32,'member':'file','bytes':3,
               'sha256':hashlib.sha256(b'abc').hexdigest(),'encoding':'identity','offset':0}
        batch=rawref.Batch.__new__(rawref.Batch); batch._live=lambda:None; batch._admit=lambda size:None
        batch._chunk_plan=lambda encoding:([],[[(writer,chunk)]])
        batch.writers=[writer]; batch.root=PurePosixPath('/owned'); batch.shards_fd=99; batch.original_fd=98
        batch.run={'source':'a'*64}; batch.budget=SimpleNamespace(allocation_unit=4096); batch.failed=False
        handle=SimpleNamespace(stage=lambda *a:None,finalize=lambda:None,close=lambda:None,release=lambda:None)
        with operations(ops),mock.patch.object(rawref,'_dir',side_effect=[60,61,64]),\
             mock.patch.object(rawref,'_open',return_value=(41,before)),\
             mock.patch.object(rawref,'_root',return_value=63),mock.patch.object(rawref,'_read',side_effect=primary),\
             mock.patch.object(store,'reservation',return_value={'required':0}),\
             mock.patch.object(store,'begin',return_value=handle),mock.patch.object(store,'restore',return_value=b'abc'):
            error=self.capture(lambda:batch.publish(encoding='identity'))
        self.assertEqual(ops.closes,[60,61,41,41,64,63]); self.assertTrue(batch.failed)
        for expected in (primary,*errors.values()): self.assertIn(expected,leaves(error))

    def test_publisher_pair_cleanup_poisoned_on_all_baseexception_failures(self):
        errors={31:OSError('PAIR_FIRST'),32:KeyboardInterrupt('PAIR_SECOND')}; ops=FakeOS(errors)
        ops.opens=[31,32]; ops.fstat=lambda fd:info(directory=False)
        p=publication.Publisher.__new__(publication.Publisher); p.fd=43; p.base_fd=44; p.directory='records'; p.failed=False
        p._live=p._allocation_bound=lambda:None; p.published={}
        p.counts={kind:0 for kind in publication.registry.LIMITS}; p.bytes=p.counts.copy()
        p.plan=SimpleNamespace(object_counts={kind:4 for kind in p.counts},
            object_bytes={kind:1024 for kind in p.counts},allocation_unit=4096)
        identity=hashlib.sha256(b'abc').hexdigest()
        p.directories={'original':45,'original/'+identity[:2]:46,'original/'+identity[:2]+'/'+identity[2:4]:47}
        with operations(ops,publication),mock.patch.object(publication,'_read_file',return_value=b'abc'):
            error=self.capture(lambda:p.publish('original',b'abc'))
        self.assertEqual(ops.closes,[31,32]); self.assertTrue(p.failed)
        for expected in errors.values(): self.assertIn(expected,leaves(error))


if __name__=='__main__': unittest.main()
