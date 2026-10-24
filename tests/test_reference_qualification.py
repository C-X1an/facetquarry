"""Bounded proof-format controls; synthetic records are not guest measurements."""
import copy
import gzip
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import reference_qualification as q


class ReferenceQualificationControls(unittest.TestCase):
    def test_portable_relative_file_and_traversal_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'proof').mkdir();(root/'proof/data').write_bytes(b'original')
            self.assertEqual(q.safe_file(root,'proof/data').read_bytes(),b'original')
            for name in ('../data','proof/../data','/absolute','C:/data','proof\\data','proof//data','./proof/data',None):
                with self.subTest(name=name),self.assertRaises(ValueError):q.safe_file(root,name)

    def test_curated_metadata_requires_stored_and_decoded_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);raw=b'{"actual":"bounded synthetic control"}'
            compressed=gzip.compress(raw);(root/'data.gz').write_bytes(compressed)
            ref={'path':'data.gz','sha256':hashlib.sha256(compressed).hexdigest(),
                 'encoding':'gzip','decoded_sha256':hashlib.sha256(raw).hexdigest()}
            self.assertEqual(q.decoded_ref(ref,root),raw)
            for change in ({'sha256':'a'*64},{'decoded_sha256':'b'*64},{'encoding':'unknown'}):
                with self.subTest(change=change),self.assertRaises(ValueError):q.decoded_ref({**ref,**change},root)

    def test_gzip_expansion_has_a_real_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);compressed=gzip.compress(bytes(q.MAX_METADATA+1))
            (root/'oversized.gz').write_bytes(compressed)
            ref={'path':'oversized.gz','sha256':hashlib.sha256(compressed).hexdigest(),'encoding':'gzip'}
            with self.assertRaisesRegex(ValueError,'decoded metadata exceeds'):q.decoded_ref(ref,root)

    def test_frozen_profiles_have_exact_cells_and_targets(self):
        for readers in (1,4,16):
            config=q.frozen_config(readers);cells=q.analysis.expected_cells(config)
            self.assertEqual(len(cells),5400)
            targets=[c for c in cells.values() if c['n']==10000 and c['filter_label']=='all'
                     and c['mode']=='graph' and c['ef']==128]
            self.assertEqual(len(targets),45)
            self.assertEqual({c['seed'] for c in targets},{11,23,47,83,131})
        for readers in (True,0,2,'4',None):
            with self.subTest(readers=readers),self.assertRaises(ValueError):q.frozen_config(readers)

    def profiles(self):
        # This checks only cross-profile correspondence, with one synthetic
        # descriptor. Complete 5400-cell proof validation is a separate layer.
        result=[]
        for readers in (1,4,16):
            result.append({'concurrency':readers,'provenance':{'binaries':{'fixture':'same bytes'}},
                'cells':[{'cell':{'n':2,'seed':11,'concurrency':readers},
                          'corpus_sha256':'a'*64,'queries_sha256':'b'*64,'generation':'c'*64}]})
        return result

    def test_reader_profiles_are_unique_and_all_required(self):
        self.assertIsNone(q.validate_profiles(self.profiles()))
        for profiles in (self.profiles()[:2],[self.profiles()[0]]*3):
            with self.assertRaisesRegex(ValueError,'missing or duplicated'):q.validate_profiles(profiles)

    def test_corresponding_reader_inputs_and_binaries_must_match(self):
        for field in ('corpus_sha256','queries_sha256','generation'):
            profiles=self.profiles();profiles[2]['cells'][0][field]='d'*64
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'correspondence differs'):q.validate_profiles(profiles)
        profiles=self.profiles();profiles[1]['provenance']['binaries']={'fixture':'different bytes'}
        with self.assertRaisesRegex(ValueError,'executable provenance differs'):q.validate_profiles(profiles)

    def test_bare_qualification_booleans_cannot_replace_bundle(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError,'verified reference envelope missing'):
                q.validate_envelope({'status':'PASS','source':'a'*64,'reference_host_verified':True},Path(folder),'a'*64)

    def test_command_and_timestamp_refusals(self):
        record={'status':'PASS','exit_code':0,'termination_reason':None,'source_before':'a'*64,
                'source_after':'a'*64,'category':'reference-analysis','command':['python3','analyze_reference.py']}
        self.assertEqual(q.command_errors(record,'a'*64,'reference-analysis'),[])
        for change in ({'exit_code':False},{'exit_code':1},{'source_after':'b'*64},{'category':'other'}):
            self.assertTrue(q.command_errors({**record,**change},'a'*64,'reference-analysis'))
        self.assertIsNotNone(q.timestamp('2026-10-24T15:37:16.347595+00:00').tzinfo)
        for value in ('2026-10-24T15:37:16','not a time',None):
            with self.subTest(value=value),self.assertRaises(ValueError):q.timestamp(value)


if __name__=='__main__':unittest.main()
