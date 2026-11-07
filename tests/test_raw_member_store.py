"""Synthetic raw-member controls; all fixtures stay in an exclusive owned root.

No global temporary directory, cleanup/deletion of evidence, process/network,
real data or mocked kernel/quota. Hooks inject named boundary exceptions only;
they are not claims of actual fsync/short-write/kernel fault reproduction.
"""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import stat
import sys
import unittest
import uuid

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPOSITORY/'scripts'))
import raw_member_store as store

ROOT = None
SOURCE = 'a'*64
COUNTER = 0
FIXTURE_PERSISTED_CAP = 16 << 20


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def member(name,raw,encoding='identity'):
    return store.Member(name,len(raw),sha(raw),encoding)


class BoundaryCrash(RuntimeError):
    pass


class PureContracts(unittest.TestCase):
    def test_flat_names_devices_case_and_aliases(self):
        for value in ('a','raw-0001.jsonl','stdout.bin','zero_0','a.b-c_d'):
            self.assertEqual(store.member_name(value),value)
        for value in ('','.', '..','A','a/escape','a\\escape','a:stream','trailing.',
                      'space name','con','con.txt','aux','nul','prn','com1','lpt9.bin',
                      'caf\u00e9','x'*65,None,False):
            with self.subTest(name=repr(value)), self.assertRaises(store.Refusal):
                store.member_name(value)

    def test_strict_scalar_caps_identity_and_preadmission(self):
        good = (member('a',b''),)
        plan = store.Plan(2<<20)
        bound = store.reservation(good,plan)
        self.assertGreaterEqual(bound['required'],bound['staging']+bound['packed_candidates']
                                +bound['metadata_and_finalization']+bound['failure_tail'])
        for value in (True,-1,store.MAX_MEMBER+1):
            with self.subTest(size=value), self.assertRaises(store.Refusal):
                store.reservation((store.Member('a',value,'0'*64),),plan)
        for bad in (store.Plan(True),store.Plan(-1),store.Plan(store.MAX_ALLOWANCE+1),
                    store.Plan(2<<20,True),store.Plan(2<<20,5000),
                    store.Plan(2<<20,4096,True),store.Plan(2<<20,4096,4097),store.Plan(0)):
            with self.subTest(plan=bad), self.assertRaises(store.Refusal):
                store.reservation(good,bad)
        for values in ([good[0]],(),good*2,tuple(store.Member('m%d'%i,1<<20,'0'*64) for i in range(5)),
                       (store.Member('a',1,'0'*64,'gzip'),)):
            with self.subTest(members=repr(values)), self.assertRaises(store.Refusal):
                store.reservation(values,plan)
        for bad_source,bad_tx in ((True,'1'*32),('bad','1'*32),(SOURCE,True),(SOURCE,'x'*32)):
            with self.assertRaises(store.Refusal):
                store._declaration(bad_source,bad_tx,good,plan)
        with self.assertRaises(store.Refusal):
            store.resume(ROOT,SOURCE,'1'*32,good,plan)

    def test_raw_original_protocol_and_boolean_alias_rejection(self):
        declaration,_,_ = store._declaration(SOURCE,'1'*32,(member('empty',b''),),store.Plan(2<<20))
        self.assertEqual(declaration['protocol'],'caller-raw-originals-v1')
        for field,value in (('version',True),('protocol','legacy-gzip'),('source','b'*63)):
            changed = dict(declaration)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(store.Refusal):
                store._load_declaration(store._canonical(changed))
        changed = json.loads(store._canonical(declaration))
        changed['reservation']['staging'] = False
        with self.assertRaises(store.Refusal):
            store._load_declaration(store._canonical(changed))
        with self.assertRaises(store.Refusal):
            store._decode(b'{"a":1,"a":2}\n')
        self.assertFalse(store._typed_equal({'version':True},{'version':1}))


def _owned_fixture_directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink()
            or getattr(info,'st_file_attributes',0)&0x400):
        raise RuntimeError('FIXTURE_DIRECTORY_TYPE_OR_REPARSE')
    if os.name == 'posix' and (info.st_uid != os.getuid() or info.st_mode&0o022):
        raise RuntimeError('FIXTURE_DIRECTORY_OWNERSHIP_OR_WRITE_ALIAS')


def _ensure_root():
    """Discovery-only bootstrap; no global temp, environment lookup or cleanup."""
    global ROOT
    if ROOT is not None:
        return ROOT
    parent = REPOSITORY/'.local'
    base = parent/'rms'
    for folder in (parent,base):
        try:
            folder.mkdir(mode=0o700)
        except FileExistsError:
            pass
        _owned_fixture_directory(folder)
    for _ in range(8):
        candidate = base/('r'+uuid.uuid4().hex[:8])
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        _owned_fixture_directory(candidate)
        ROOT = candidate
        return ROOT
    raise RuntimeError('EXCLUSIVE_FIXTURE_ROOT_COLLISION_BOUND')

class FixtureRoot(unittest.TestCase):
    def setUp(self):
        global COUNTER
        _ensure_root()
        COUNTER += 1
        self.base = ROOT/('c%03d'%COUNTER)
        self.base.mkdir(mode=0o700)
        self.handles = []

    def tearDown(self):
        for handle in self.handles:
            if not handle._released:
                handle.release()

    def create(self,raws,encodings=None,hook=None):
        if encodings is None:
            encodings = ['identity']*len(raws)
        members = tuple(member('m%d.raw'%i,raw,encoding) for i,(raw,encoding) in enumerate(zip(raws,encodings)))
        tx = '%032x'%COUNTER
        handle = store.begin(self.base,SOURCE,tx,members,store.Plan(8<<20),hook=hook)
        self.handles.append(handle)
        return handle,tx,members

    def txpath(self,tx):
        return self.base/('txn-'+tx)

    def report(self,tx):
        result = store.recover(self.base)
        return next(row for row in result['transactions'] if row['name'] == 'txn-'+tx)

    @unittest.skipUnless(os.name == 'nt','actual Windows closed-refusal control only')
    def test_actual_windows_directory_durability_refuses_before_begin(self):
        with self.assertRaisesRegex(store.Refusal,'DURABILITY_UNSUPPORTED'):
            store.begin(self.base,SOURCE,'1'*32,(member('a',b''),),store.Plan(2<<20))
        self.assertEqual(list(self.base.iterdir()),[])
        report = store.recover(self.base)
        self.assertFalse(report['committed_accepted'])
        self.assertFalse(report['inventory_complete'])


@unittest.skipUnless(sys.platform.startswith('linux'),'actual Linux POSIX directory-fsync durability gate')
class LinuxTransactions(FixtureRoot):
    def test_exact_raw_binary_empty_noncanonical_and_metadata_accounting(self):
        raws = (b'',b'\x00\xff\x80binary\r\n',b' { "x":1, "x":2 }\r\nnot-json\n')
        handle,tx,members = self.create(raws,['identity','xz','xz'])
        for item,raw in zip(members,raws):
            handle.stage(item.name,raw)
        committed = handle.finalize()
        self.assertGreater(committed['every_metadata_and_control_byte'],0)
        self.assertEqual(committed['all_file_bytes'],
                         committed['payload_file_bytes']+committed['every_metadata_and_control_byte'])
        uncertain = self.report(tx)
        self.assertFalse(uncertain['committed_accepted'])
        self.assertEqual(uncertain['state'],'COMMIT_RECORD_PRESENT_CLOSURE_OR_DURABILITY_UNCERTAIN')
        closed = handle.close()
        report = self.report(tx)
        self.assertTrue(report['committed_accepted'])
        self.assertEqual(report['missing_stage_members'],[])
        self.assertEqual(report['corrupt_stage_members'],[])
        self.assertEqual(report['accounting']['all_file_bytes'],closed['all_file_bytes'])
        self.assertEqual(len(report['declared_members']),len(raws))
        self.assertFalse(report['historical_fsync_independently_attested'])
        for item,raw in zip(members,raws):
            self.assertEqual((self.txpath(tx)/'stage'/item.name).read_bytes(),raw)
            self.assertEqual(store.restore(self.base,SOURCE,tx,item.name),raw)

    def test_existing_identity_never_overwrites_or_resumes(self):
        handle,tx,members = self.create((b'caller bytes',))
        before = (self.txpath(tx)/'transaction.json').read_bytes()
        for source in (SOURCE,'b'*64):
            with self.subTest(source=source), self.assertRaises((store.Refusal,FileExistsError)):
                store.begin(self.base,source,tx,members,store.Plan(8<<20))
            self.assertEqual((self.txpath(tx)/'transaction.json').read_bytes(),before)
        with self.assertRaises(store.Refusal):
            store.resume(self.base,'b'*64,tx,members,store.Plan(8<<20))
        self.assertEqual((self.txpath(tx)/'transaction.json').read_bytes(),before)

    def test_stage_cap_and_original_digest_refuse_without_shrinking_declaration(self):
        handle,tx,members = self.create((b'expected',b'second'))
        handle.stage(members[0].name,b'expected')
        with self.assertRaises(store.Refusal):
            handle.stage(members[1].name,b'wrong bytes')
        self.assertEqual((self.txpath(tx)/'stage'/members[0].name).read_bytes(),b'expected')
        report = self.report(tx)
        self.assertFalse(report['committed_accepted'])
        self.assertEqual(report['missing_stage_members'],[members[1].name])
        self.assertEqual(report['declared_members'],[item.name for item in members])

    def test_exact_max_member_and_plus_one_metadata_refusal(self):
        raw = b'x'*store.MAX_MEMBER
        handle,tx,members = self.create((raw,))
        handle.stage(members[0].name,raw)
        handle.finalize()
        handle.close()
        self.assertTrue(self.report(tx)['committed_accepted'])
        with self.assertRaises(store.Refusal):
            store.reservation((store.Member('too-big',store.MAX_MEMBER+1,'0'*64),),store.Plan(8<<20))

    def test_explicit_retirement_after_verified_commit_and_closed_writers(self):
        raws = (b'one\x00\xff'*100,b'two\r\n'*100)
        handle,tx,members = self.create(raws,['identity','xz'])
        for item,raw in zip(members,raws):
            handle.stage(item.name,raw)
        handle.finalize()
        handle.close()
        handle.retire_staging()
        report = self.report(tx)
        self.assertTrue(report['committed_accepted'])
        self.assertEqual(report['retirement'],'DONE_CONTENT_BOUND')
        self.assertEqual(report['missing_stage_members'],[item.name for item in members])
        self.assertEqual(len(report['declared_members']),2)
        self.assertEqual(list((self.txpath(tx)/'stage').iterdir()),[])
        for item,raw in zip(members,raws):
            self.assertEqual(store.restore(self.base,SOURCE,tx,item.name),raw)
        with self.assertRaises(store.Refusal):
            store.restore(self.base,'b'*64,tx,members[0].name)

    def test_retirement_without_closed_commit_refuses_and_keeps_every_stage(self):
        raw = b'not retired'
        handle,tx,members = self.create((raw,))
        handle.stage(members[0].name,raw)
        handle.finalize()
        with self.assertRaises(store.Refusal):
            handle.retire_staging()
        self.assertEqual((self.txpath(tx)/'stage'/members[0].name).read_bytes(),raw)
        self.assertFalse(self.report(tx)['committed_accepted'])

    def test_crash_after_first_stage_chunk_retains_partial_and_failure_tail(self):
        def hook(event):
            if event == 'after_stage_write':
                raise BoundaryCrash('controlled synthetic stage boundary')
        raw = b'p'*(2*store.CHUNK)
        handle,tx,members = self.create((raw,),hook=hook)
        with self.assertRaises(BoundaryCrash):
            handle.stage(members[0].name,raw)
        handle.failure_tail(b'bounded synthetic failure tail\x00\xff')
        partial = self.txpath(tx)/'stage'/members[0].name
        self.assertEqual(partial.stat().st_size,store.CHUNK)
        handle.release()
        report = self.report(tx)
        self.assertFalse(report['committed_accepted'])
        self.assertEqual(report['corrupt_stage_members'],[members[0].name])
        self.assertTrue((self.txpath(tx)/'failure-tail.bin').exists())

    def test_generator_write_cap_failure_retains_written_prefix(self):
        handle,tx,members = self.create((b'abcdef',))
        with self.assertRaises(store.Refusal):
            with handle._operation():
                handle._write(handle.stage_fd,members[0].name,iter((b'abc',b'overflow')),6)
        self.assertEqual((self.txpath(tx)/'stage'/members[0].name).read_bytes(),b'abc')
        self.assertFalse(self.report(tx)['committed_accepted'])

    def test_generator_failure_closes_handles_and_keeps_candidate_prefix(self):
        handle,tx,members = self.create((b'abcdef',))
        handle.stage(members[0].name,b'abcdef')
        def source():
            yield b'abc'
            raise BoundaryCrash('synthetic compressor-iterator boundary')
        with self.assertRaises(BoundaryCrash):
            with handle._operation():
                handle._write(handle.packed_fd,members[0].name,source(),6)
        self.assertEqual((self.txpath(tx)/'packed'/members[0].name).read_bytes(),b'abc')
        self.assertEqual((self.txpath(tx)/'stage'/members[0].name).read_bytes(),b'abcdef')
        self.assertFalse(self.report(tx)['committed_accepted'])

    def test_manifest_and_commit_boundary_crashes_never_auto_accept(self):
        for event in ('after_pack_write','after_manifest','after_commit_write','after_commit_fsync'):
            # Fresh explicitly owned child, all bytes retained.
            sub = self.base/event
            sub.mkdir(mode=0o700)
            def hook(current,selected=event):
                if current == selected:
                    raise BoundaryCrash('synthetic boundary')
            raw = b'boundary payload\x00\xff'*100
            item = member('raw',raw,'xz')
            tx = ('%032x'%COUNTER)
            handle = store.begin(sub,SOURCE,tx,(item,),store.Plan(8<<20),hook=hook)
            self.handles.append(handle)
            handle.stage('raw',raw)
            with self.subTest(event=event), self.assertRaises(BoundaryCrash):
                handle.finalize()
            handle.release()
            report = store.recover(sub)['transactions'][0]
            self.assertFalse(report['committed_accepted'])
            self.assertEqual((sub/('txn-'+tx)/'stage/raw').read_bytes(),raw)

    def test_no_clobber_commit_keeps_preexisting_torn_marker(self):
        raw = b'preexisting marker'
        handle,tx,members = self.create((raw,))
        handle.stage(members[0].name,raw)
        marker = self.txpath(tx)/'commit.json'
        marker.write_bytes(b'{"torn":')
        with self.assertRaises(FileExistsError):
            handle.finalize()
        self.assertEqual(marker.read_bytes(),b'{"torn":')
        self.assertEqual((self.txpath(tx)/'stage'/members[0].name).read_bytes(),raw)
        self.assertFalse(self.report(tx)['committed_accepted'])

    def test_unknown_and_torn_metadata_remain_visible_never_complete(self):
        handle,tx,members = self.create((b'original',))
        handle.stage(members[0].name,b'original')
        handle.finalize()
        handle.close()
        manifest = self.txpath(tx)/'manifest.json'
        manifest.write_bytes(manifest.read_bytes()[:17])
        report = self.report(tx)
        self.assertFalse(report['committed_accepted'])
        self.assertTrue(any(row['path'] == 'manifest.json' for row in report['inventory']))
        (self.txpath(tx)/'unknown.bin').write_bytes(b'unknown evidence')
        report = self.report(tx)
        self.assertIn('unknown.bin',report['unknown_evidence'])
        self.assertFalse(report['committed_accepted'])

    def test_boolean_commit_and_mixed_protocol_cannot_relabel_complete(self):
        handle,tx,members = self.create((b'original',),['xz'])
        handle.stage(members[0].name,b'original')
        handle.finalize()
        handle.close()
        commit = self.txpath(tx)/'commit.json'
        value = json.loads(commit.read_bytes())
        value['version'] = True
        commit.write_bytes(store._canonical(value))
        self.assertFalse(self.report(tx)['committed_accepted'])
        declaration = self.txpath(tx)/'transaction.json'
        value = json.loads(declaration.read_bytes())
        value['protocol'] = 'legacy-gzip'
        declaration.write_bytes(store._canonical(value))
        self.assertFalse(self.report(tx)['committed_accepted'])

    def test_packed_corruption_refuses_but_stage_original_is_retained(self):
        raw = b'corruption original'*100
        handle,tx,members = self.create((raw,),['xz'])
        handle.stage(members[0].name,raw)
        handle.finalize()
        handle.close()
        path = self.txpath(tx)/'packed'/members[0].name
        changed = path.read_bytes()
        path.write_bytes(changed[:len(changed)//2])
        self.assertFalse(self.report(tx)['committed_accepted'])
        self.assertEqual((self.txpath(tx)/'stage'/members[0].name).read_bytes(),raw)

    def test_real_symlink_hardlink_and_root_alias_refuse(self):
        raw = b'owned stage'
        handle,tx,members = self.create((raw,))
        handle.stage(members[0].name,raw)
        original = self.txpath(tx)/'stage'/members[0].name
        alias = self.base/'hardlink-evidence'
        os.link(original,alias)
        with self.assertRaises(store.Refusal):
            handle.finalize()
        report = self.report(tx)
        self.assertFalse(report['committed_accepted'])
        self.assertFalse(report['inventory_complete'])
        self.assertTrue(any(row['path'] == 'stage/'+members[0].name and not row['safe']
                            for row in report['inventory']))
        other = self.base/'safe-owned'
        other.mkdir(mode=0o700)
        link = self.base/'root-alias'
        link.symlink_to(other,target_is_directory=True)
        with self.assertRaises((OSError,store.Refusal)):
            store.begin(link,SOURCE,'f'*32,(member('a',b'a'),),store.Plan(2<<20))
        self.assertEqual(original.read_bytes(),raw)
        self.assertEqual(alias.read_bytes(),raw)

    def test_dangling_stage_link_visible_without_following(self):
        handle,tx,members = self.create((b'a',))
        (self.txpath(tx)/'stage/dangling').symlink_to(self.base/'missing')
        report = self.report(tx)
        self.assertFalse(report['committed_accepted'])
        self.assertTrue(any(row['path'] == 'stage/dangling' and not row['safe']
                            for row in report['inventory']))

    def test_one_handle_reentrant_writer_refuses_without_kernel_mock(self):
        attempted = []
        held = []
        def hook(event):
            if event == 'after_stage_write':
                try:
                    held[0].stage('m0.raw',b'raw')
                except store.Refusal as error:
                    attempted.append(str(error))
        handle,tx,members = self.create((b'raw',),hook=hook)
        held.append(handle)
        handle.stage(members[0].name,b'raw')
        self.assertEqual(attempted,['CONCURRENT_WRITER_REFUSED'])
        handle.finalize()
        handle.close()
        self.assertTrue(self.report(tx)['committed_accepted'])

    def test_xz_single_stream_raw_hash_and_output_bounds(self):
        raw = b'native binary\x00\xff\r\n'*100
        valid = lzma.compress(raw,format=lzma.FORMAT_XZ,preset=6)
        variants = (valid[:-1],valid+b'x',valid+valid,valid[:20]+bytes([valid[20]^1])+valid[21:],
                    lzma.compress(raw+b'excess',format=lzma.FORMAT_XZ,preset=6))
        fd = store._open_root(self.base)
        try:
            for index,encoded in enumerate(variants):
                name = 'case%d'%index
                (self.base/name).write_bytes(encoded)
                meta = {'name':name,'encoding':'xz','bytes':len(encoded),'sha256':sha(encoded)}
                with self.subTest(case=index), self.assertRaises(store.Refusal):
                    store._verify_payload(fd,member(name,raw,'xz'),meta)
        finally:
            os.close(fd)

    def test_partial_retirement_reports_exact_membership_and_remaining_bytes(self):
        count = [0]
        def hook(event):
            if event == 'after_retire_member':
                count[0] += 1
                if count[0] == 1:
                    raise BoundaryCrash('synthetic post-unlink retirement boundary')
        raws = (b'first original',b'second original')
        handle,tx,members = self.create(raws,['xz','identity'],hook=hook)
        for item,raw in zip(members,raws):
            handle.stage(item.name,raw)
        handle.finalize()
        handle.close()
        with self.assertRaises(BoundaryCrash):
            handle.retire_staging()
        report = self.report(tx)
        self.assertTrue(report['committed_accepted'])
        self.assertEqual(report['retirement'],'STARTED_MAY_BE_PARTIAL')
        self.assertEqual(len(report['missing_stage_members']),1)
        self.assertEqual(report['declared_members'],[item.name for item in members])
        self.assertTrue((self.txpath(tx)/'stage'/members[1].name).exists())


    def test_root_writer_claim_and_replaced_root_path_refuse(self):
        raw = b'first closed transaction'
        handle,tx,members = self.create((raw,))
        handle.stage(members[0].name,raw)
        handle.finalize()
        handle.close()
        before = sorted(path.name for path in self.base.iterdir())
        next_id = 'f'*32
        next_members = (member('next',b'next raw'),)
        with self.assertRaisesRegex(store.Refusal,'ROOT_WRITER_ACTIVE'):
            store.begin(self.base,SOURCE,next_id,next_members,store.Plan(2<<20))
        self.assertEqual(sorted(path.name for path in self.base.iterdir()),before)
        self.assertEqual(store.restore(self.base,SOURCE,tx,members[0].name),raw)
        handle.release()
        second = store.begin(self.base,SOURCE,next_id,next_members,store.Plan(2<<20))
        self.handles.append(second)
        second.stage('next',b'next raw')
        second.finalize()
        second.close()
        self.assertEqual(store.restore(self.base,SOURCE,next_id,'next'),b'next raw')
        moved = self.base.with_name(self.base.name+'-moved')
        self.base.rename(moved)
        self.base.mkdir(mode=0o700)
        with self.assertRaisesRegex(store.Refusal,'ROOT_PATH_BINDING_CHANGED'):
            second.retire_staging()
        self.assertEqual(list(self.base.iterdir()),[])
        original = moved/('txn-'+next_id)
        self.assertEqual((original/'stage'/'next').read_bytes(),b'next raw')
        self.assertFalse((original/'retirement-start.json').exists())

    def test_exact_32_root_slots_then_33_refuses_without_mutation(self):
        originals = []
        for index in range(1,store.MAX_TRANSACTIONS+1):
            tx = '%032x'%index
            raw = ('raw original %d'%index).encode()
            handle = store.begin(self.base,SOURCE,tx,(member('raw',raw),),store.Plan(2<<20))
            self.handles.append(handle)
            handle.stage('raw',raw)
            handle.finalize()
            handle.close()
            handle.release()
            originals.append((tx,raw))
        self.assertEqual(len(list(self.base.iterdir())),32)
        for tx,raw in originals:
            self.assertEqual(store.restore(self.base,SOURCE,tx,'raw'),raw)
        before = {path.relative_to(self.base).as_posix():path.read_bytes()
                  for path in self.base.rglob('*') if path.is_file()}
        with self.assertRaisesRegex(store.Refusal,'ROOT_SLOT_CAPACITY'):
            store.begin(self.base,SOURCE,'f'*32,(member('raw',b'refused'),),store.Plan(2<<20))
        after = {path.relative_to(self.base).as_posix():path.read_bytes()
                 for path in self.base.rglob('*') if path.is_file()}
        self.assertEqual(before,after)
        self.assertEqual(len(list(self.base.iterdir())),32)

    def test_foreign_root_overflow_refuses_retirement_before_any_unlink(self):
        raw = b'staging must survive a root-wide restore refusal'
        handle,tx,members = self.create((raw,))
        handle.stage(members[0].name,raw)
        handle.finalize()
        handle.close()
        for index in range(31):
            (self.base/('foreign-%02d'%index)).write_bytes(b'')
        self.assertEqual(store.restore(self.base,SOURCE,tx,members[0].name),raw)
        (self.base/'foreign-overflow').write_bytes(b'')
        with self.assertRaisesRegex(store.Refusal,'RETIRE_ROOT_RECOVERY_REFUSED'):
            handle.retire_staging()
        self.assertEqual((self.txpath(tx)/'stage'/members[0].name).read_bytes(),raw)
        self.assertFalse((self.txpath(tx)/'retirement-start.json').exists())
        self.assertEqual(len(list(self.base.iterdir())),33)
        with self.assertRaises(store.Refusal):
            store.restore(self.base,SOURCE,tx,members[0].name)

    def test_optional_failure_tail_exact_cap_wrong_kind_and_excess(self):
        for index,variant in enumerate(('valid','directory','oversized'),1):
            sub = self.base/variant
            sub.mkdir(mode=0o700)
            tx = '%032x'%index
            raw = b'exact stage retained'
            item = member('raw',raw)
            handle = store.begin(sub,SOURCE,tx,(item,),store.Plan(2<<20,4096,7))
            self.handles.append(handle)
            handle.stage(item.name,raw)
            if variant == 'valid':
                handle.failure_tail(b'x'*7)
            handle.finalize()
            handle.close()
            folder = sub/('txn-'+tx)
            tail = folder/'failure-tail.bin'
            if variant == 'directory':
                tail.mkdir(mode=0o700)
            elif variant == 'oversized':
                tail.write_bytes(b'x'*8)
            report = next(row for row in store.recover(sub)['transactions']
                          if row['name'] == 'txn-'+tx)
            if variant == 'valid':
                self.assertTrue(report['committed_accepted'])
                self.assertEqual(store.restore(sub,SOURCE,tx,item.name),raw)
                continue
            self.assertFalse(report['committed_accepted'])
            self.assertEqual(report['state'],'REFUSED_OR_PARTIAL_RETAIN_ALL')
            self.assertTrue(any(row['path']=='failure-tail.bin' for row in report['inventory']))
            with self.assertRaises(store.Refusal):
                store.restore(sub,SOURCE,tx,item.name)
            with self.assertRaisesRegex(store.Refusal,'RETIRE_RESTORABLE_CLOSED_COMMIT_REQUIRED'):
                handle.retire_staging()
            self.assertEqual((folder/'stage'/item.name).read_bytes(),raw)
            self.assertFalse((folder/'retirement-start.json').exists())
            self.assertTrue(tail.exists())


def persisted_size(root):
    total,count = 0,0
    pending = [(root,0)]
    while pending:
        path,depth = pending.pop()
        if depth > 6:
            raise RuntimeError('TEST_FIXTURE_DEPTH_BOUND')
        with os.scandir(path) as iterator:
            for entry in iterator:
                count += 1
                if count > 2048:
                    raise RuntimeError('TEST_FIXTURE_COUNT_BOUND')
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    pending.append((Path(entry.path),depth+1))
                elif stat.S_ISREG(info.st_mode):
                    total += info.st_size
                # Deliberate symlink fixtures are reported, never followed.
                if total > FIXTURE_PERSISTED_CAP:
                    raise RuntimeError('TEST_PERSISTED_FIXTURE_CAP')
    return total,count


def tearDownModule():
    # Discovery receives the same post-suite persisted-fixture cap as direct CLI.
    # Keep every fixture, including failed/torn/alias evidence.
    if ROOT is not None:
        persisted_size(ROOT)

def main():
    global ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-root',type=Path,required=True)
    args = parser.parse_args()
    if not args.test_root.is_absolute() or '..' in args.test_root.parts:
        parser.error('explicit absolute owned --test-root required')
    # Exclusive test root creation: never overwrite or clean a previous run.
    args.test_root.mkdir(mode=0o700)
    ROOT = args.test_root
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    size,count = persisted_size(ROOT)
    print(json.dumps({'scope':'SYNTHETIC_RAW_MEMBER_PRIMITIVE_ONLY','tests_run':result.testsRun,
                      'failures':len(result.failures),'errors':len(result.errors),
                      'explicit_skips':len(result.skipped),'persisted_fixture_bytes':size,
                      'persisted_entries':count,'fixture_cap_bytes':FIXTURE_PERSISTED_CAP,
                      'kernel_quota_or_fault_injection_claimed':False,
                      'scientific_or_release_qualification':False}))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
