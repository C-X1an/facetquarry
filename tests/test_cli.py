"""Real executable integration: no mocked search, storage or process calls."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
BIN=ROOT/'bin/facetquarry'
class CLI(unittest.TestCase):
    def test_lifecycle_and_host_scope(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);index=p/'index.fq'
            def run(*args):return subprocess.run([str(BIN),*map(str,args)],text=True,capture_output=True,timeout=30)
            r=run('build','--input',ROOT/'examples/corpus.json','--output',index)
            self.assertEqual(r.returncode,0,r.stderr)
            r=run('search','--index',index,'--tenant','alpha','--query',ROOT/'examples/query.json')
            self.assertEqual(r.returncode,0,r.stderr);body=json.loads(r.stdout)
            self.assertEqual(body['hits'][0]['id'],'a1');self.assertTrue(body['exact'])
            query=json.loads((ROOT/'examples/query.json').read_text());query['tenant']='beta';q=p/'q.json';q.write_text(json.dumps(query))
            r=run('search','--index',index,'--tenant','alpha','--query',q)
            self.assertEqual(r.returncode,2);self.assertEqual(json.loads(r.stderr)['error']['code'],'E_INPUT');self.assertEqual(r.stdout,'')
            old=index.read_bytes();r=run('build','--input',ROOT/'examples/corpus.json','--output',index)
            self.assertNotEqual(r.returncode,0);self.assertEqual(index.read_bytes(),old)
            good=(ROOT/'examples/query.json').read_text().strip();lines=p/'queries.jsonl';lines.write_text(good+'\n'+json.dumps(query)+'\n')
            r=run('batch','--index',index,'--tenant','alpha','--queries',lines)
            self.assertEqual(r.returncode,2);responses=[json.loads(x) for x in r.stdout.splitlines()]
            self.assertTrue(responses[0]['exact']);self.assertIn('error',responses[1])
    def test_unknown_command_is_json_error(self):
        r=subprocess.run([str(BIN),'not-a-command'],text=True,capture_output=True,timeout=10)
        self.assertEqual(r.returncode,2);self.assertEqual(json.loads(r.stderr)['error']['code'],'E_INPUT')
if __name__=='__main__':unittest.main()
