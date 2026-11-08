"""Synthetic data-only fixture retention controls; no kernel fault claims.

Pure reader controls execute on Windows. Actual symlink/hardlink, directory
fsync and raw cleanup controls require POSIX. All disk fixtures are exclusive
and themselves sealed as evidence, including deliberately failed capsules.
No subprocess, network, environment lookup, global temp or mocked OS failure.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import unittest
import uuid

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPOSITORY/'scripts'))
import fixture_capsule as capsule
import clean_verify
import test_raw_member_store as raw_driver

PENDING = set()
SEALED = []


def encoded(raw):
    return base64.b64encode(raw).decode('ascii')


def document(raw=b'\x00\xff\x80\r\n {"x":1,"x":2}\n'):
    # Deliberately constructed without the production inventory/encoder.
    return {'version':1,'protocol':'synthetic-fixture-capsule-v1',
            'source_path':encoded(b'/synthetic/exclusive/container'),
            'raw_bytes':len(raw),'entries':[
                {'path':'','kind':'directory','mode':0o700,'dev':1,'ino':1},
                {'path':'raw.bin','kind':'file','mode':0o640,'dev':1,'ino':2,
                 'nlink':1,'bytes':len(raw),'data':encoded(raw),
                 'sha256':hashlib.sha256(raw).hexdigest()}]}


def wire(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')


class PureCapsuleContracts(unittest.TestCase):
    def test_independent_document_keeps_exact_binary_and_metadata(self):
        value=document()
        parsed=capsule.decode(wire(value))
        self.assertEqual(parsed,value)
        self.assertEqual(base64.b64decode(parsed['entries'][1]['data']),
                         b'\x00\xff\x80\r\n {"x":1,"x":2}\n')
        self.assertEqual(parsed['entries'][1]['mode'],0o640)
        self.assertEqual(capsule.decode(wire(document(b'')))['raw_bytes'],0)

    def test_unsafe_absolute_parent_and_non_utf8_link_targets_are_data(self):
        for target in (b'/outside/never-opened',b'../../never-followed',b'../\xff\x80'):
            value=document()
            value['entries'].append({'path':'link','kind':'symlink','mode':0o777,
                                     'dev':1,'ino':3,'target':encoded(target)})
            with self.subTest(target=target):
                parsed=capsule.decode(wire(value))
                self.assertEqual(base64.b64decode(parsed['entries'][-1]['target']),target)
        self.assertFalse(hasattr(capsule,'extract'))

    def test_exact_keys_and_boolean_integer_aliases_refuse(self):
        variants=[]
        for key,value in (('version',True),('protocol',True),('raw_bytes',False),
                          ('extra',0),('entries',{}),('source_path',False)):
            changed=document();changed[key]=value;variants.append(changed)
        for key,value in (('bytes',True),('mode',True),('dev',True),('ino',False),
                          ('nlink',True),('extra',None),('kind',False),('data',[]),('sha256',False)):
            changed=document();changed['entries'][1][key]=value;variants.append(changed)
        for changed in variants:
            with self.subTest(changed=repr(changed)[:150]), self.assertRaises(capsule.Refusal):
                capsule.decode(wire(changed))

    def test_duplicate_keys_nonfinite_invalid_json_and_truncation_refuse(self):
        valid=wire(document())
        duplicate=valid.replace(b'"version":1',b'"version":1,"version":1',1)
        self.assertEqual(capsule.decode(valid),document())
        cases=[duplicate,b'{"x":NaN}',b'{"x":Infinity}',
               b'[]',valid+b'x',b'\xff']
        cases += [valid[:index] for index in (0,1,7,len(valid)//2,len(valid)-2)]
        for raw in cases:
            with self.subTest(length=len(raw)), self.assertRaises(capsule.Refusal):
                capsule.decode(raw)

    def test_byte_hash_length_base64_and_total_corruption_refuse(self):
        for field,bad in (('data','AA=='),('data','!!!!'),('data','AB=='),
                          ('sha256','0'*64),('bytes',999),('bytes',-1),
                          ('bytes',capsule.MAX_FILE+1),('nlink',0),('mode',0o10000),
                          ('dev',-1),('ino',1<<128)):
            # AB== decodes to the SAME one zero byte as canonical AA==. Thus
            # length/hash remain valid and only base64 canonicality can refuse.
            value=document(b'\x00') if field=='data' and bad=='AB==' else document()
            value['entries'][1][field]=bad
            with self.subTest(field=field,bad=bad), self.assertRaises(capsule.Refusal):
                capsule.decode(wire(value))
        for total in (-1,1,capsule.MAX_RAW+1):
            value=document();value['raw_bytes']=total
            with self.subTest(total=total), self.assertRaises(capsule.Refusal):
                capsule.decode(wire(value))

    def test_path_identity_parent_kind_collisions_and_depth_refuse(self):
        for path in ('../x','/absolute','a//b','a\\b','a:stream','con.txt','a.',
                     'a/b/c/d/e/f/g','', 'raw.bin/child'):
            value=document();value['entries'][1]['path']=path
            with self.subTest(path=path), self.assertRaises(capsule.Refusal):
                capsule.decode(wire(value))
        value=document();duplicate=copy.deepcopy(value['entries'][1])
        duplicate.update(path='RAW.BIN',ino=3)
        value['entries'].append(duplicate);value['raw_bytes']*=2
        with self.assertRaises(capsule.Refusal):capsule.decode(wire(value))
        value=document();value['entries'][0]['kind']='file'
        with self.assertRaises(capsule.Refusal):capsule.decode(wire(value))

    def test_exact_depth_and_entry_count_boundaries(self):
        value=document(b'');value['entries']=value['entries'][:1]
        for index in range(1,7):
            value['entries'].append({'path':'/'.join(['d']*index),'kind':'directory',
                                     'mode':0o700,'dev':1,'ino':index+1})
        self.assertEqual(len(capsule.decode(wire(value))['entries']),7)
        value['entries'].append({'path':'/'.join(['d']*7),'kind':'directory',
                                 'mode':0o700,'dev':1,'ino':9})
        with self.assertRaises(capsule.Refusal):capsule.decode(wire(value))
        value=document(b'');template=value['entries'][1];value['entries']=value['entries'][:1]
        for index in range(capsule.MAX_ENTRIES-1):
            row=dict(template,path='f%04d'%index,ino=index+2)
            value['entries'].append(row)
        self.assertEqual(len(capsule.decode(wire(value))['entries']),capsule.MAX_ENTRIES)
        value['entries'].append(dict(template,path='one-more',ino=capsule.MAX_ENTRIES+1))
        with self.assertRaises(capsule.Refusal):capsule.decode(wire(value))

    def test_capsule_and_target_bounds_are_enforced_before_use(self):
        with self.assertRaises(capsule.Refusal):
            capsule.decode(b' '*(capsule.MAX_CAPSULE+1))
        for target in (b'',b'bad\x00target',b'x'*(capsule.MAX_TARGET+1)):
            value=document();value['entries'].append({'path':'link','kind':'symlink',
                'mode':0o777,'dev':1,'ino':3,'target':encoded(target)})
            with self.subTest(length=len(target)), self.assertRaises(capsule.Refusal):
                capsule.decode(wire(value))
        value=document();value['entries'].append({'path':'link','kind':'symlink',
            'mode':0o777,'dev':1,'ino':3,'target':encoded(b'x'*capsule.MAX_TARGET)})
        self.assertEqual(len(capsule.decode(wire(value))['entries']),3)

    def test_hardlink_group_count_and_complete_relation(self):
        value=document();value['entries'][1]['nlink']=2
        with self.assertRaisesRegex(capsule.Refusal,'HARDLINK'):
            capsule.decode(wire(value))
        alias=copy.deepcopy(value['entries'][1]);alias['path']='alias'
        value['entries'].append(alias);value['raw_bytes']*=2
        self.assertEqual(len(capsule.decode(wire(value))['entries']),3)
        for field,bad in (('mode',0o600),('nlink',3),('data',encoded(b'other'))):
            changed=copy.deepcopy(value);changed['entries'][2][field]=bad
            with self.subTest(field=field), self.assertRaises(capsule.Refusal):
                capsule.decode(wire(changed))
        value=document();value['entries'].append({'path':'link','kind':'symlink',
            'mode':0o777,'dev':1,'ino':2,'target':encoded(b'anything')})
        with self.assertRaises(capsule.Refusal):capsule.decode(wire(value))


class SuiteAccountingContracts(unittest.TestCase):
    def test_completed_originals_still_consume_the_aggregate_guard(self):
        result=raw_driver.aggregate_admission(16<<20,2048,0,0,100,7,2)
        self.assertEqual(result['original_fixture_bytes'],16<<20)
        self.assertEqual(result['original_fixture_entries'],2048)
        self.assertEqual(result['remaining_raw_bytes'],0)
        self.assertEqual(result['serialized_actual_bytes'],107)
        with self.assertRaisesRegex(RuntimeError,'CUMULATIVE_ORIGINAL'):
            raw_driver.aggregate_admission((16<<20)+1,1,0,0,0,0,0)
        with self.assertRaisesRegex(RuntimeError,'CUMULATIVE_ORIGINAL'):
            raw_driver.aggregate_admission(0,2049,0,0,0,0,0)

    def test_complete_partial_and_both_publication_copies_are_admitted(self):
        result=raw_driver.aggregate_admission(100,10,50,5,1000,200,2,300)
        self.assertEqual(result['serialized_complete_bytes'],1000)
        self.assertEqual(result['serialized_partial_bytes'],200)
        self.assertEqual(result['publication_duplicate_headroom_bytes'],600)
        self.assertEqual(result['serialized_with_publication_headroom_bytes'],1800)
        self.assertEqual(result['raw_and_serialized_with_headroom_bytes'],1850)
        exact=raw_driver.aggregate_admission(0,0,0,0,(24<<20)-2,0,1,1)
        self.assertEqual(exact['serialized_with_publication_headroom_bytes'],24<<20)
        with self.assertRaisesRegex(RuntimeError,'SERIALIZED_AND_PUBLICATION'):
            raw_driver.aggregate_admission(0,0,0,0,(24<<20)-1,0,1,1)
        with self.assertRaisesRegex(RuntimeError,'PEAK_CAP'):
            raw_driver.aggregate_admission(16<<20,1,16<<20,1,17<<20,0,1)
        with self.assertRaisesRegex(RuntimeError,'INTEGER'):
            raw_driver.aggregate_admission(True,0,0,0,0,0,0)

    def test_publication_file_slot_boundaries_include_empty_originals(self):
        self.assertEqual(capsule._output_slots(2046,2),2048)
        with self.assertRaises(capsule.Refusal):capsule._output_slots(2047,2)
        self.assertEqual(capsule._output_slots(2048,0),2048)
        # Original content can be empty, but its typed envelope still needs a
        # partial and final file. publication_bound=1 denotes nonzero envelope
        # headroom here; this is scalar admission, not a simulated filesystem.
        exact=raw_driver.aggregate_admission(0,0,0,0,0,0,2046,1)
        self.assertEqual(exact['publication_file_headroom'],2)
        self.assertEqual(exact['serialized_with_publication_file_headroom'],2048)
        with self.assertRaisesRegex(RuntimeError,'SERIALIZED_AND_PUBLICATION'):
            raw_driver.aggregate_admission(0,0,0,0,0,0,2047,1)
        full=raw_driver.aggregate_admission(0,0,0,0,0,0,2048,0)
        self.assertEqual(full['serialized_with_publication_file_headroom'],2048)


def _seal_control(root):
    evidence=REPOSITORY/'.local'/'evidence'
    try:evidence.mkdir(mode=0o700)
    except FileExistsError:pass
    output=evidence/('capsule-controls-'+uuid.uuid4().hex)
    output.mkdir(mode=0o700)
    record=capsule.preserve(root,output,'control')
    SEALED.append(record)
    PENDING.remove(root)


class OwnedFilesystemControls(unittest.TestCase):
    def setUp(self):
        for parent in (REPOSITORY/'.local',REPOSITORY/'.local'/'fixture-capsule-tests'):
            try:parent.mkdir(mode=0o700)
            except FileExistsError:pass
            capsule.checked_directory(parent)
        self.root=REPOSITORY/'.local'/'fixture-capsule-tests'/('r'+uuid.uuid4().hex)
        self.root.mkdir(mode=0o700)
        PENDING.add(self.root)
        self.raw=self.root/'raw';self.raw.mkdir(mode=0o700)
        self.output=self.root/'out';self.output.mkdir(mode=0o700)

    def tearDown(self):
        _seal_control(self.root)

    def test_binary_readback_and_portable_retention_scope(self):
        original=b'\x00\xff\x80\r\n {"x":1,"x":2}\n'
        (self.raw/'binary').write_bytes(original)
        (self.raw/'empty').write_bytes(b'')
        record=capsule.preserve(self.raw,self.output,'case',remove=False)
        self.assertFalse(record['raw_fixture_removed'])
        self.assertEqual(record['directory_durability'],os.name=='posix')
        self.assertEqual((self.raw/'binary').read_bytes(),original)
        parsed=capsule.read(self.output/'case.fcap')
        capsule.verify_source(parsed,self.raw)
        rows={row['path']:row for row in parsed['entries']}
        self.assertEqual(base64.b64decode(rows['binary']['data']),original)
        self.assertEqual(base64.b64decode(rows['empty']['data']),b'')
        self.assertFalse((self.output/'case.partial').exists())

    def test_owned_file_timestamp_update_keeps_exact_portable_readback(self):
        # This real owned-file metadata operation exercises the cross-API stat
        # seam without requiring ctime meanings to differ on every platform.
        # It is not evidence of an observed public ctime failure or power loss.
        path=self.raw/'timestamped'
        original=b'owned timestamp control\x00\xff\x80'
        path.write_bytes(original)
        requested_mtime=1_600_000_002_000_000_000
        os.utime(path,ns=(1_600_000_000_000_000_000,requested_mtime))
        before=path.lstat()
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0))
        try:
            opened=os.fstat(fd)
            self.assertEqual(capsule._read_file(path,before,capsule.MAX_FILE),original)
            self.assertEqual(capsule._signature(os.fstat(fd)),capsule._signature(opened))
        finally:os.close(fd)
        self.assertEqual(path.lstat().st_mtime_ns,requested_mtime)
        self.assertEqual(capsule._signature(path.lstat()),capsule._signature(before))
        result=capsule.preserve(self.raw,self.output,'timestamp',remove=False)
        self.assertFalse(result['raw_fixture_removed'])
        capsule.verify_source(capsule.read(self.output/'timestamp.fcap'),self.raw)
        row=next(row for row in capsule.read(self.output/'timestamp.fcap')['entries']
                 if row['path']=='timestamped')
        self.assertEqual(base64.b64decode(row['data']),original)

    def test_all_byte_values_crlf_ctrl_z_and_chunk_boundary_match_physical_original(self):
        # CR is byte65535 and LF is byte65536, crossing the reader's65536-byte
        # chunk boundary. Ctrl-Z occurs both early and after that boundary.
        # Path.read_bytes supplies an independent physical-byte oracle.
        original=(bytes(range(256))*255+b'p'*255+b'\r\n\x1a'+bytes(range(256))
                  +b'\r\nend\x1aafter-ctrl-z\x00\xff')
        path=self.raw/'all-bytes'
        path.write_bytes(original)
        physical=path.read_bytes()
        self.assertEqual(physical,original)
        self.assertEqual(physical[65535:65538],b'\r\n\x1a')
        self.assertEqual(path.lstat().st_size,len(physical))
        self.assertEqual(capsule._read_file(path,path.lstat(),capsule.MAX_FILE),physical)
        empty=self.raw/'empty'
        empty.write_bytes(b'')
        self.assertEqual(capsule._read_file(empty,empty.lstat(),0),b'')
        result=capsule.preserve(self.raw,self.output,'all-bytes',remove=False)
        self.assertFalse(result['raw_fixture_removed'])
        # Read the serialized envelope independently too; its declared length
        # and hash must refer to physical original bytes, not translated reads.
        parsed=capsule.decode((self.output/'all-bytes.fcap').read_bytes())
        rows={row['path']:row for row in parsed['entries']}
        self.assertEqual(base64.b64decode(rows['all-bytes']['data'],validate=True),physical)
        self.assertEqual(rows['all-bytes']['bytes'],len(physical))
        self.assertEqual(rows['all-bytes']['sha256'],hashlib.sha256(physical).hexdigest())
        self.assertEqual(rows['empty']['bytes'],0)
        self.assertEqual(base64.b64decode(rows['empty']['data'],validate=True),b'')
        self.assertEqual(parsed['raw_bytes'],len(physical))
        self.assertEqual(result['raw_bytes'],len(physical))
        self.assertEqual(path.read_bytes(),physical)

    def test_exclusive_names_and_preexisting_capsules_never_overwrite(self):
        (self.raw/'raw').write_bytes(b'original')
        final=self.output/'case.fcap';final.write_bytes(b'preexisting evidence')
        with self.assertRaises(capsule.Refusal):capsule.preserve(self.raw,self.output,'case')
        self.assertEqual(final.read_bytes(),b'preexisting evidence')
        partial=self.output/'other.partial';partial.write_bytes(b'preexisting partial')
        with self.assertRaises(capsule.Refusal):capsule.preserve(self.raw,self.output,'other')
        self.assertEqual(partial.read_bytes(),b'preexisting partial')
        self.assertEqual((self.raw/'raw').read_bytes(),b'original')

    def test_synthetic_boundary_exceptions_retain_raw_and_partials(self):
        (self.raw/'raw').write_bytes(b'complete original')
        for index,boundary in enumerate(('after_partial_fsync','after_independent_readback','after_final_readback')):
            def hook(event,selected=boundary):
                if event==selected:raise RuntimeError('synthetic boundary only')
            name='case%d'%index
            with self.subTest(boundary=boundary), self.assertRaisesRegex(RuntimeError,'synthetic boundary'):
                capsule.preserve(self.raw,self.output,name,synthetic_hook=hook)
            self.assertEqual((self.raw/'raw').read_bytes(),b'complete original')
            self.assertTrue((self.output/(name+'.partial')).is_file())
            self.assertEqual((self.output/(name+'.fcap')).exists(),boundary=='after_final_readback')

    def test_independent_readback_refuses_changed_partial_before_any_cleanup(self):
        (self.raw/'raw').write_bytes(b'original')
        def hook(event):
            if event=='after_partial_fsync':
                path=self.output/'case.partial'
                path.write_bytes(path.read_bytes()[:-7])
        with self.assertRaises(capsule.Refusal):
            capsule.preserve(self.raw,self.output,'case',synthetic_hook=hook)
        self.assertTrue((self.output/'case.partial').exists())
        self.assertFalse((self.output/'case.fcap').exists())
        self.assertEqual((self.raw/'raw').read_bytes(),b'original')

    def test_changed_source_refuses_and_keeps_both_observed_states(self):
        (self.raw/'raw').write_bytes(b'before source change')
        def hook(event):
            if event=='after_partial_fsync':(self.raw/'raw').write_bytes(b'after source change')
        with self.assertRaises(capsule.Refusal):
            capsule.preserve(self.raw,self.output,'case',synthetic_hook=hook)
        self.assertEqual((self.raw/'raw').read_bytes(),b'after source change')
        parsed=capsule.read(self.output/'case.partial')
        row=next(row for row in parsed['entries'] if row['path']=='raw')
        self.assertEqual(base64.b64decode(row['data']),b'before source change')

    @unittest.skipUnless(os.name=='posix','actual POSIX file/directory fsync and cleanup only')
    def test_durable_complete_readback_precedes_raw_cleanup(self):
        (self.raw/'raw').write_bytes(b'cleanup original')
        observed=[]
        def hook(event):
            if event=='before_raw_cleanup':
                self.assertTrue(self.raw.exists())
                self.assertTrue((self.output/'case.partial').exists())
                capsule.verify_source(capsule.read(self.output/'case.fcap'),self.raw)
                observed.append(event)
        result=capsule.preserve(self.raw,self.output,'case',synthetic_hook=hook)
        self.assertEqual(observed,['before_raw_cleanup'])
        self.assertTrue(result['directory_durability'])
        self.assertTrue(result['raw_fixture_removed'])
        self.assertFalse(self.raw.exists())
        self.assertEqual(capsule.read(self.output/'case.fcap')['raw_bytes'],len(b'cleanup original'))

    @unittest.skipUnless(os.name=='posix','actual POSIX cleanup boundary only')
    def test_cleanup_boundary_exception_retains_two_verified_copies_and_raw(self):
        (self.raw/'raw').write_bytes(b'retain on synthetic boundary')
        def hook(event):
            if event=='before_raw_cleanup':raise RuntimeError('synthetic cleanup boundary')
        with self.assertRaisesRegex(RuntimeError,'synthetic cleanup boundary'):
            capsule.preserve(self.raw,self.output,'case',synthetic_hook=hook)
        self.assertEqual((self.raw/'raw').read_bytes(),b'retain on synthetic boundary')
        for suffix in ('.partial','.fcap'):
            capsule.verify_source(capsule.read(self.output/('case'+suffix)),self.raw)

    @unittest.skipUnless(os.name=='posix','actual POSIX symlink target bytes and hardlinks only')
    def test_real_links_remain_data_and_internal_hardlink_groups_are_complete(self):
        raw=self.raw/'original';raw.write_bytes(b'hardlink bytes\x00\xff');raw.chmod(0o640)
        os.link(raw,self.raw/'alias')
        for name,target in (('absolute',b'/never-follow-this'),('parent',b'../../outside'),('binary',b'../\xff')):
            os.symlink(target,os.fsencode(self.raw/name))
        result=capsule.preserve(self.raw,self.output,'case')
        self.assertTrue(result['raw_fixture_removed'])
        rows={row['path']:row for row in capsule.read(self.output/'case.fcap')['entries']}
        self.assertEqual(rows['original']['mode'],0o640)
        self.assertEqual(rows['original']['nlink'],2)
        self.assertEqual(rows['original']['ino'],rows['alias']['ino'])
        self.assertEqual(base64.b64decode(rows['binary']['target']),b'../\xff')
        self.assertEqual(base64.b64decode(rows['absolute']['target']),b'/never-follow-this')
        self.assertFalse(any(path.is_symlink() for path in self.output.iterdir()))

    @unittest.skipUnless(os.name=='posix','actual POSIX hardlink external alias refusal only')
    def test_external_hardlink_refuses_and_keeps_original_and_partial(self):
        raw=self.raw/'original';raw.write_bytes(b'external alias evidence')
        os.link(raw,self.root/'external')
        with self.assertRaisesRegex(capsule.Refusal,'HARDLINK'):
            capsule.preserve(self.raw,self.output,'case')
        self.assertEqual(raw.read_bytes(),b'external alias evidence')
        self.assertEqual((self.root/'external').read_bytes(),b'external alias evidence')
        self.assertTrue((self.output/'case.partial').exists())
        self.assertFalse((self.output/'case.fcap').exists())

    def _clone_paths(self,suffix=''):
        temporary=self.root/('temporary'+suffix);temporary.mkdir(mode=0o700)
        clone=temporary/'source';clone.mkdir(mode=0o700)
        out=self.root/('retained'+suffix);out.mkdir(mode=0o700)
        return temporary,clone,out

    @unittest.skipUnless(os.name=='posix','actual complete destination ancestry fsync before rename only')
    def test_clean_clone_raw_case_guard_retains_whole_source(self):
        temporary,clone,out=self._clone_paths()
        pending=clone/'.local'/'rms'/'r1';pending.mkdir(parents=True,mode=0o700)
        (pending/'payload').write_bytes(b'unpreserved raw source')
        errors=[]
        clean_verify.dispose_clone(clone,out,temporary,errors)
        self.assertTrue(errors)
        retained=out/'retained-failed-source'
        self.assertEqual((retained/'.local/rms/r1/payload').read_bytes(),b'unpreserved raw source')
        self.assertFalse(clone.exists())
        self.assertTrue(temporary.exists())

    @unittest.skipUnless(os.name=='posix','actual complete destination ancestry fsync before rename only')
    def test_clean_clone_partial_without_final_blocks_disposal(self):
        temporary,clone,out=self._clone_paths()
        evidence=clone/'.local/evidence';evidence.mkdir(parents=True,mode=0o700)
        (evidence/'torn.partial').write_bytes(b'{"torn":')
        errors=[]
        clean_verify.dispose_clone(clone,out,temporary,errors)
        self.assertTrue(errors)
        retained=out/'retained-failed-source'
        self.assertEqual((retained/'.local/evidence/torn.partial').read_bytes(),b'{"torn":')

    @unittest.skipUnless(os.name=='posix','actual complete destination ancestry fsync before rename only')
    def test_clean_clone_corrupt_copy_blocks_disposal_and_preserves_source(self):
        temporary,clone,out=self._clone_paths()
        evidence=clone/'.local/evidence';evidence.mkdir(parents=True,mode=0o700)
        original=wire(document())
        (evidence/'fixture.fcap').write_bytes(original)
        copied=out/'evidence';copied.mkdir(mode=0o700)
        (copied/'fixture.fcap').write_bytes(original[:-4])
        errors=[]
        clean_verify.dispose_clone(clone,out,temporary,errors)
        self.assertTrue(errors)
        retained=out/'retained-failed-source'
        self.assertEqual((retained/'.local/evidence/fixture.fcap').read_bytes(),original)
        self.assertEqual((copied/'fixture.fcap').read_bytes(),original[:-4])

    @unittest.skipUnless(os.name=='posix','actual complete destination ancestry fsync before cleanup only')
    def test_clean_clone_verified_regular_capsule_copy_allows_cleanup(self):
        temporary,clone,out=self._clone_paths()
        evidence=clone/'.local/evidence';evidence.mkdir(parents=True,mode=0o700)
        original=wire(document());(evidence/'fixture.fcap').write_bytes(original)
        shutil.copytree(evidence,out/'evidence')
        self.assertEqual(clean_verify._retained_files(evidence),clean_verify._retained_files(out/'evidence'))
        errors=[]
        clean_verify.dispose_clone(clone,out,temporary,errors)
        self.assertEqual(errors,[])
        self.assertFalse(clone.exists())
        self.assertFalse(temporary.exists())
        self.assertEqual((out/'evidence/fixture.fcap').read_bytes(),original)

    def test_clean_clone_retention_never_overwrites_existing_destination(self):
        temporary,clone,out=self._clone_paths()
        (clone/'raw').write_bytes(b'original source')
        existing=out/'retained-failed-source';existing.mkdir(mode=0o700)
        (existing/'marker').write_bytes(b'prior retained source')
        errors=['synthetic prior retention refusal']
        clean_verify.dispose_clone(clone,out,temporary,errors)
        self.assertGreater(len(errors),1)
        self.assertEqual((clone/'raw').read_bytes(),b'original source')
        self.assertEqual((existing/'marker').read_bytes(),b'prior retained source')
        self.assertTrue(temporary.exists())

    @unittest.skipUnless(os.name=='posix','actual ordered POSIX publication seam; no power-loss claim')
    def test_terminal_and_complete_ancestor_sync_precede_source_removal(self):
        temporary,clone,out=self._clone_paths()
        evidence=clone/'.local/evidence';evidence.mkdir(parents=True,mode=0o700)
        original=wire(document());(evidence/'fixture.fcap').write_bytes(original)
        shutil.copytree(evidence,out/'evidence')
        terminals={name:clean_verify._terminal_file(out,name,raw) for name,raw in
                   (('stdout.txt',b'actual retained stdout\x00'),('stderr.txt',b'actual retained stderr\xff'))}
        events=[]
        def hook(event):
            if event=='before_clone_delete':
                self.assertTrue(clone.exists())
                for name in ('stdout.txt','stderr.txt'):
                    self.assertIn('destination_file_synced:'+name,events)
                for parent in (out,)+tuple(out.parents):
                    self.assertIn('destination_directory_synced:'+str(parent),events)
                self.assertIn('destination_readback_verified',events)
                self.assertIn('source_copy_readback_verified',events)
                self.assertEqual((out/'stdout.txt').read_bytes(),b'actual retained stdout\x00')
                self.assertEqual((out/'stderr.txt').read_bytes(),b'actual retained stderr\xff')
            events.append(event)
        errors=[]
        clean_verify.dispose_clone(clone,out,temporary,errors,terminal_files=terminals,synthetic_hook=hook)
        self.assertEqual(errors,[])
        self.assertIn('before_clone_delete',events)
        self.assertFalse(clone.exists())

    @unittest.skipUnless(os.name=='posix','synthetic pre-ancestor publication interruption, no OS fault claim')
    def test_interrupted_ancestor_publication_keeps_original_on_both_branches(self):
        for suffix,prior_errors in (('clean',[]),('failed',['synthetic prior retention error'])):
            temporary,clone,out=self._clone_paths(suffix)
            (clone/'raw').write_bytes(b'original source survives publication boundary')
            clean_verify._terminal_file(out,'stdout.txt',b'retained stdout')
            clean_verify._terminal_file(out,'stderr.txt',b'retained stderr')
            events=[]
            def hook(event):
                events.append(event)
                if event=='before_destination_ancestor_sync':
                    raise RuntimeError('synthetic publication boundary interruption')
            errors=list(prior_errors)
            clean_verify.dispose_clone(clone,out,temporary,errors,synthetic_hook=hook)
            with self.subTest(branch=suffix):
                self.assertTrue(errors)
                self.assertEqual((clone/'raw').read_bytes(),b'original source survives publication boundary')
                self.assertFalse((out/'retained-failed-source').exists())
                self.assertNotIn('before_clone_delete',events)
                self.assertNotIn('before_clone_rename',events)
                self.assertTrue(temporary.exists())

    @unittest.skipUnless(os.name=='nt','actual Windows directory durability refusal retains original clone')
    def test_windows_original_clone_is_retained_without_directory_durability(self):
        temporary,clone,out=self._clone_paths()
        (clone/'raw').write_bytes(b'Windows original source')
        clean_verify._terminal_file(out,'stdout.txt',b'Windows stdout')
        clean_verify._terminal_file(out,'stderr.txt',b'Windows stderr')
        errors=[]
        clean_verify.dispose_clone(clone,out,temporary,errors)
        self.assertTrue(any('DIRECTORY_DURABILITY_UNSUPPORTED' in error for error in errors))
        self.assertEqual((clone/'raw').read_bytes(),b'Windows original source')
        self.assertFalse((out/'retained-failed-source').exists())
        self.assertTrue(temporary.exists())


def tearDownModule():
    failures=[]
    for root in list(PENDING):
        try:_seal_control(root)
        except Exception as error:failures.append(type(error).__name__+': '+str(error))
    if failures:
        raise RuntimeError('CAPSULE_CONTROL_RETENTION_FAILED: '+'; '.join(failures))


if __name__=='__main__':unittest.main()
