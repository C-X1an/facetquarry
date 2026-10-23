"""Small mixed-profile selection control; never an engine/benchmark claim."""
import json,tempfile,unittest,zipfile
from pathlib import Path
import prepare_reference_analysis as p

SOURCE='4949a016d1fc650cc80f18583e18b0ed487820801091508ea34b0a6b658a7dfe'
GRID=Path(__file__).resolve().parents[2]/'public/benchmarks/grid.json'
if not GRID.exists():GRID=Path(__file__).resolve().parents[2]/'benchmarks/grid.json'

class PreparationControls(unittest.TestCase):
    def test_smoke_and_full_are_not_mixed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'input.zip'
            full=json.loads(GRID.read_text())['full'];smoke=json.loads(GRID.read_text())['smoke']
            with zipfile.ZipFile(source,'w') as z:
                for profile,config in [('smoke',smoke),('full',full)]:
                    prefix='source/.local/benchmarks/'+profile+'-example/'
                    z.writestr(prefix+'coverage.json',json.dumps({'profile':profile,'source':SOURCE,'config':config}))
                    z.writestr(prefix+'unexpected.summary.json','{"status":"FAIL"}')
                    z.writestr(prefix+'example.samples.jsonl.gz',b'gz control')
            p.prepare(source,root/'inputs')
            record=json.loads((root/'analysis-input.json').read_text())
            self.assertIn('full-example',record['folder'])
            self.assertEqual(record['selected_members'],3)
            self.assertEqual([x['profile'] for x in record['excluded_profiles']],['smoke'])
            self.assertTrue((Path(record['folder'])/'unexpected.summary.json').is_file())
            self.assertFalse(list((root/'inputs').rglob('smoke-example')))

    def test_multiple_full_candidates_are_rejected_regardless_of_outcome(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'input.zip';config=json.loads(GRID.read_text())['full']
            with zipfile.ZipFile(source,'w') as z:
                for name,status in [('full-a','PASS'),('full-b','FAIL')]:
                    z.writestr('source/.local/benchmarks/'+name+'/coverage.json',json.dumps({'profile':'full','source':SOURCE,'config':config,'status':status}))
            with self.assertRaisesRegex(ValueError,'exactly one'):p.prepare(source,root/'inputs')
            self.assertFalse((root/'inputs').exists())

    def test_failed_full_profile_is_retained_for_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'input.zip';config=json.loads(GRID.read_text())['full']
            with zipfile.ZipFile(source,'w') as z:z.writestr('source/.local/benchmarks/full-a/coverage.json',json.dumps({'profile':'full','source':SOURCE,'config':config,'status':'FAIL'}))
            p.prepare(source,root/'inputs')
            record=json.loads((root/'analysis-input.json').read_text())
            self.assertEqual(json.loads((Path(record['folder'])/'coverage.json').read_text())['status'],'FAIL')

if __name__=='__main__':unittest.main(verbosity=2)
