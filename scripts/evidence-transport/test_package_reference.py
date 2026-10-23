"""Small synthetic archive controls; no benchmark/engine claims."""
import gzip
import io
from pathlib import Path
import tempfile
import unittest
import zipfile
import package_reference as p

class TransportControls(unittest.TestCase):
    def package(self,folder,entries):
        source=folder/'input.zip';out=folder/'output.tar.xz'
        with zipfile.ZipFile(source,'w') as z:
            for name,data in entries:z.writestr(name,data)
        result=p.pack(source,out,p.file_sha(source),source.stat().st_size,'a'*64,123,456)
        return source,out,result

    def test_exact_identity_gzip_and_malformed_gzip_recovery(self):
        raw=io.BytesIO()
        with gzip.GzipFile(filename='sample.jsonl',fileobj=raw,mode='wb',mtime=123) as g:g.write(b'{"value":1}\n'*100)
        entries=[('plain.txt',b'hello'),('x.samples.jsonl.gz',raw.getvalue()),('broken.gz',b'not gzip')]
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source,bundle,result=self.package(root,entries)
            self.assertEqual(result['gzip_recipe_members'],1)
            self.assertEqual(p.verify(bundle)['member_count'],3)
            recovered=root/'recovered';p.verify(bundle,recovered)
            for name,data in entries:self.assertEqual((recovered/name).read_bytes(),data)
            self.assertTrue(source.is_file())

    def test_nonempty_directory_rejected_before_pack(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'directory'):
                self.package(Path(d),[('bad/',b'x')])

    def test_file_ancestor_conflict_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError,'ancestor|conflict'):
                self.package(Path(d),[('a',b'x'),('a/b',b'y')])

    def test_unsafe_and_windows_reserved_names_rejected(self):
        for name in ('../a','/a','a\\b','a:b','NUL.txt','a./b','a?/b'):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):p.safe_name(name)

    def test_corrupt_input_digest_and_bounded_output(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'input.zip';source.write_bytes(b'zip bytes')
            with self.assertRaisesRegex(ValueError,'size/SHA'):
                p.pack(source,Path(d)/'out', '0'*64,source.stat().st_size,'a'*64,123,456)
        target=io.BytesIO();writer=p.LimitedWriter(target,4)
        with self.assertRaisesRegex(ValueError,'limit'):writer.write(b'12345')
        self.assertEqual(target.getvalue(),b'')

    def test_extended_windows_paths_are_bounded_and_unc_is_correct(self):
        with self.assertRaisesRegex(ValueError,'bound'):p.safe_name(('x'*199+'/')*201+'a')
        self.assertEqual(p.extended_windows_path('C:\\data'),'\\\\?\\C:\\data')
        self.assertEqual(p.extended_windows_path('\\\\server\\share'),'\\\\?\\UNC\\server\\share')
        with self.assertRaisesRegex(ValueError,'bound'):p.extended_windows_path('C:\\'+'a'*33000)

if __name__=='__main__':unittest.main(verbosity=2)
