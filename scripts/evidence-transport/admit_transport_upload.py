"""Admit the exact combined upload set, including receipts and failure outputs."""
import json,os,sys
from pathlib import Path
from package_reference import require,file_sha

LIMIT=450_000_000

def main():
    volume=Path(sys.argv[1]).resolve();report_path=volume/'upload-admission.json'
    roots=[volume/'results',volume/'source/.local/evidence',volume/'source/.local/transport-quota.json']
    files=[]
    for root in roots:
        if root.exists():
            require(not root.is_symlink(),'upload root is a link')
            for path in ([root] if root.is_file() else sorted(root.rglob('*'))):
                require(not path.is_symlink() and (path.resolve()==volume or volume in path.resolve().parents),'upload outside owned volume')
                if path.is_file():files.append(path)
    records=[{'path':p.relative_to(volume).as_posix(),'bytes':p.stat().st_size,'sha256':file_sha(p)} for p in files]
    total=sum(x['bytes'] for x in records);admitted=total+2_000_000<LIMIT
    excluded=[]
    if not admitted:
        # Preserve all diagnostic logs, receipts and analysis. Only omit an unusably
        # large transport bundle, explicitly recorded; original cloud data remains.
        excluded=[p for p in files if p.name.endswith(('.tar.xz','.tar.xz.partial'))]
        files=[p for p in files if p not in excluded]
        if sum(p.stat().st_size for p in files)+2_000_000>=LIMIT:
            excluded+=files;files=[]
    report={'schema_version':1,'status':'PASS' if admitted else 'FAIL','limit_bytes':LIMIT,
        'combined_requested_bytes':total,'all_requested_files':records,
        'excluded_paths':[p.relative_to(volume).as_posix() for p in excluded],
        'diagnostic_only':not admitted,'original_artifact_id':12519574083,'original_cloud_artifact_retained':True,
        'scope':'Combined exact upload files plus2MB metadata/ZIP margin; failure selection is explicit, never a successful full transfer claim.'}
    report_path.write_text(json.dumps(report,indent=2)+'\n');files.append(report_path)
    require(sum(p.stat().st_size for p in files)<LIMIT,'final upload selection exceeds admission')
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:
        out.write('paths<<FQ_UPLOAD_PATHS\n'+'\n'.join(map(str,files))+'\nFQ_UPLOAD_PATHS\n')
    print(json.dumps({k:report[k] for k in ('status','combined_requested_bytes','excluded_paths','diagnostic_only')}))
    return 0 if admitted else 1

if __name__=='__main__':raise SystemExit(main())
