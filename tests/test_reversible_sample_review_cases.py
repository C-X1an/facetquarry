"""Additional independent-review controls, authored before implementation repair."""
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zlib

import reversible_samples as subject
from test_reversible_samples import digest, gzip_fixture

SOURCE = 'a' * 64

def proposal_for(original, stdout, raw, status='PASS'):
    return subject.propose(original_samples_gzip=original, stdout_gzip=stdout,
        expected_samples_sha256=digest(original), expected_stdout_gzip_sha256=digest(stdout),
        expected_stdout_raw_sha256=digest(raw), expected_stdout_raw_bytes=len(raw),
        source_id=SOURCE, attempt_status=status)

def restore(recipe, original, stdout, raw, **changes):
    args = dict(recipe=recipe, stdout_gzip=stdout, expected_samples_sha256=digest(original),
        expected_samples_bytes=len(original), expected_stdout_gzip_sha256=digest(stdout),
        expected_stdout_raw_sha256=digest(raw), expected_stdout_raw_bytes=len(raw), expected_source_id=SOURCE)
    args.update(changes)
    return subject.reconstruct(**args)

def row(number=0):
    return {'query':number, 'repetition':0, 'nanoseconds':123+number,
            'response':{'hits':[{'id':'id'+str(number),'distance':0.125}], 'distance_evaluations':7},
            'retained_extra':'x'*160}

def fixture(rows=None, name=b'cell.samples.jsonl'):
    rows = [row()] if rows is None else rows
    raw = b''.join((json.dumps(r)+'\n').encode() for r in rows) + b'{"summary":true}\n'
    canonical = b''.join((json.dumps({**r,'recall_at_k':0.5},separators=(',',':'))+'\n').encode() for r in rows)
    return gzip_fixture(canonical,name=name), gzip_fixture(raw,name=b'stdout.txt'), raw, canonical

class ReviewCases(unittest.TestCase):
    def test_actual_gzip_open_text_writer_above_64k_all_declared_levels(self):
        rows = [row(i) for i in range(300)]
        _, stdout, raw, canonical = fixture(rows)
        self.assertGreater(len(canonical),65536)
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
            path = Path(directory)/'actual.samples.jsonl.gz'
            for level in (0,1,6,9):
                with self.subTest(level=level):
                    with gzip.open(path,'wt',compresslevel=level) as out:
                        for r in rows:
                            out.write(json.dumps({**r,'recall_at_k':0.5},separators=(',',':'))+'\n')
                    original = path.read_bytes()
                    result = proposal_for(original,stdout,raw)
                    self.assertEqual(result.mode,'derived',result.reason)
                    self.assertEqual(restore(result.recipe,original,stdout,raw),original)

    def test_real_gzip_without_filename_and_zero_mtime(self):
        _, stdout, raw, canonical = fixture()
        target = io.BytesIO()
        with gzip.GzipFile(fileobj=target,filename='',mode='wb',mtime=0) as out:
            out.write(canonical)
        original = target.getvalue()
        self.assertEqual(original[3],0)
        result = proposal_for(original,stdout,raw)
        self.assertEqual(result.mode,'derived',result.reason)
        self.assertEqual(restore(result.recipe,original,stdout,raw),original)

    def test_unsupported_optional_gzip_flag_and_padding_preserve_identity(self):
        original, stdout, raw, _ = fixture()
        extra = original[:3]+bytes([original[3]|4])+original[4:10]+b'\x02\x00ab'+original[10:]
        for candidate in (extra,original+b'\x00\x00'):
            with self.subTest(candidate=candidate[:20]):
                result = proposal_for(candidate,stdout,raw)
                self.assertEqual(result.mode,'identity')
                self.assertIs(result.original_samples_gzip,candidate)
                self.assertIsNone(result.recipe)

    def test_exact_filename_header_boundary_and_one_byte_excess(self):
        for length, expected in ((subject.MAX_HEADER_BYTES-11,'derived'),(subject.MAX_HEADER_BYTES-10,'identity')):
            with self.subTest(length=length):
                original,stdout,raw,_ = fixture(name=b'x'*length)
                result = proposal_for(original,stdout,raw)
                self.assertEqual(result.mode,expected,result.reason)
                self.assertIs(result.original_samples_gzip,original)
                if result.mode=='derived':
                    self.assertEqual(restore(result.recipe,original,stdout,raw),original)

    def test_duplicate_native_keys_and_existing_overlay_keep_benchmark_order(self):
        line = '{"query":0,"recall_at_k":"old","nanoseconds":1,"nanoseconds":4,"repetition":0,"response":null}'
        parsed = json.loads(line)
        parsed['recall_at_k']=None
        canonical = (json.dumps(parsed,separators=(',',':'))+'\n').encode()
        raw=(line+'\n'+json.dumps({'summary':True})+'\n').encode()
        original,stdout = gzip_fixture(canonical),gzip_fixture(raw)
        result = proposal_for(original,stdout,raw)
        self.assertEqual(result.mode,'derived',result.reason)
        self.assertEqual(restore(result.recipe,original,stdout,raw),original)

    def test_missing_duplicate_summaries_and_noncanonical_number_fall_back(self):
        original,stdout,raw,canonical = fixture()
        for changed in (raw.replace(b'{"summary":true}\n',b''),raw+b'{"summary":true}\n'):
            result = proposal_for(original,gzip_fixture(changed),changed)
            self.assertEqual(result.mode,'identity')
            self.assertIs(result.original_samples_gzip,original)
        changed = gzip_fixture(canonical.replace(b'"recall_at_k":0.5',b'"recall_at_k":0.50'))
        result = proposal_for(changed,stdout,raw)
        self.assertEqual(result.mode,'identity')
        self.assertIs(result.original_samples_gzip,changed)

    def test_truncated_or_invalid_failed_streams_never_derive_or_drop_original(self):
        original,stdout,raw,_ = fixture()
        invalid = b'not-json\n\xff'
        for candidate,original_raw in ((gzip_fixture(invalid),invalid),(stdout[:-4],raw)):
            result = proposal_for(original,candidate,original_raw,status='FAIL')
            self.assertIn(result.mode,('identity','refused'))
            self.assertIs(result.original_samples_gzip,original)
            self.assertIsNone(result.recipe)

    def test_every_trusted_binding_rejects_a_substitution(self):
        original,stdout,raw,_ = fixture()
        result=proposal_for(original,stdout,raw)
        self.assertEqual(result.mode,'derived')
        mutations=[{'expected_samples_sha256':'b'*64},{'expected_samples_bytes':len(original)+1},
            {'expected_stdout_gzip_sha256':'b'*64},{'expected_stdout_raw_sha256':'b'*64},
            {'expected_stdout_raw_bytes':len(raw)+1},{'expected_source_id':'b'*64}]
        for changes in mutations:
            with self.subTest(changes=changes),self.assertRaises(subject.Refusal):
                restore(result.recipe,original,stdout,raw,**changes)

    def test_recipe_duplicate_keys_and_gzip_type_tampering_refuse(self):
        original,stdout,raw,_=fixture()
        result=proposal_for(original,stdout,raw)
        duplicate=result.recipe.replace(b'{',b'{"version":1,',1)
        with self.assertRaises(subject.Refusal):
            restore(duplicate,original,stdout,raw)
        base=json.loads(result.recipe)
        for field,value in (('header_hex',[]),('trailer_hex','00'*8),('fname_hex','00'),('mtime',True)):
            changed=copy.deepcopy(base);changed['gzip'][field]=value
            with self.subTest(field=field),self.assertRaises(subject.Refusal):
                restore(json.dumps(changed).encode(),original,stdout,raw)

    def test_codec_numeric_types_must_match_recorded_environment(self):
        original,stdout,raw,_=fixture()
        result=proposal_for(original,stdout,raw)
        base=json.loads(result.recipe)
        for field,value in (('strategy',False),('mem_level',float(zlib.DEF_MEM_LEVEL)),('python',[True,*base['codec']['python'][1:]])):
            changed=copy.deepcopy(base);changed['codec'][field]=value
            with self.subTest(field=field),self.assertRaises(subject.Refusal):
                restore(json.dumps(changed).encode(),original,stdout,raw)

    def test_recipe_structure_depth_and_breadth_refuse_before_unbounded_parse(self):
        original,stdout,raw,_=fixture()
        result=proposal_for(original,stdout,raw)
        deep=b'['*40+b'0'+b']'*40
        broad=b'['+b'0,'*40000+b'0]'
        for payload in (deep,broad):
            with self.subTest(length=len(payload)),self.assertRaisesRegex(subject.Refusal,'JSON structural bound'):
                restore(payload,original,stdout,raw)

if __name__=='__main__':
    unittest.main()
