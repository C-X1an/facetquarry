"""Packaging-only orchestration. Measurement source and packaging source differ."""
import json,os,shutil,subprocess,sys
from pathlib import Path
from package_reference import file_sha,require
from download_reference import SHA,SIZE,ARTIFACT,RUN

MEASURED='4949a016d1fc650cc80f18583e18b0ed487820801091508ea34b0a6b658a7dfe'

def main():
    volume=Path(sys.argv[1]).resolve();root=Path.cwd().resolve();tool=root/'scripts/evidence-transport'
    require(root==volume/'source' and volume.is_dir(),'unexpected packaging root')
    source=volume/'original.zip';require(source.stat().st_size==SIZE and file_sha(source)==SHA,'original ZIP mismatch')
    results=volume/'results';results.mkdir(exist_ok=False)
    shutil.copy2(volume/'original-artifact-metadata.json',results)
    statuses={}
    def execute(label,args,timeout):
        code=subprocess.run([sys.executable,'scripts/evidence.py','--category',label,'--timeout',str(timeout),'--',*map(str,args)],check=False).returncode
        statuses[label]={'exit_code':code};return code
    inputs=volume/'analysis-input'
    prepare=execute('transport-analysis-input',[sys.executable,tool/'prepare_reference_analysis.py',source,inputs],300)
    if prepare==0:
        record=json.loads((volume/'analysis-input.json').read_text())
        execute('original-records-reanalysis',[sys.executable,tool/'analyze_reference.py',record['folder'],
            '--grid',root/'benchmarks/grid.json','--expected-source',MEASURED,'--output',results/'analysis'],1800)
        shutil.copy2(volume/'analysis-input.json',results)
        # Only our freshly extracted duplicates; original ZIP hash rechecked and retained.
        require(inputs.resolve()==volume/'analysis-input' and inputs.is_dir() and not inputs.is_symlink()
            and file_sha(source)==SHA,'refusing analysis duplicate cleanup')
        shutil.rmtree(inputs)
    packed=execute('lossless-member-packaging',[sys.executable,tool/'package_reference.py','pack',source,
        results/'reference-members.tar.xz','--expected-sha',SHA,'--expected-size',SIZE,'--measured-source',MEASURED,
        '--artifact-id',ARTIFACT,'--run-id',RUN],3600)
    if packed==0:
        execute('lossless-member-verification',[sys.executable,tool/'package_reference.py','verify',results/'reference-members.tar.xz'],1200)
    record={'schema_version':1,'status':'PASS' if statuses and all(x['exit_code']==0 for x in statuses.values()) else 'FAIL',
        'statuses':statuses,'measured_source':MEASURED,'packaging_commit':os.environ.get('GITHUB_SHA'),
        'original_zip_sha256':SHA,'original_zip_bytes':SIZE,'original_artifact_id':ARTIFACT,'original_run_id':RUN,
        'script_sha256':{p.name:file_sha(p) for p in tool.glob('*.py')},
        'scope':'Transport and reanalysis only; no engine measurements run, no outer ZIP reconstruction or reference-host approval.'}
    record['results_total_bytes']=sum(p.stat().st_size for p in results.rglob('*') if p.is_file())
    require(record['results_total_bytes']<425_000_000,'result artifact exceeds admitted wrapper margin')
    (results/'transport-result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record));return 0 if record['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
