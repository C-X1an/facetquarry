"""Extract only bounded, validated analysis inputs; original ZIP remains intact."""
import argparse,json,shutil,stat,zipfile
from pathlib import Path,PurePosixPath
from package_reference import require,validate_layout,MAX_MEMBER,file_sha

def prepare(source,output):
    require(not output.exists(),'analysis input already exists')
    with zipfile.ZipFile(source) as z:
        infos=z.infolist();require(0<len(infos)<=50000,'archive member count exceeds admission')
        records=[]
        for item in infos:
            kind=stat.S_IFMT(item.external_attr>>16)
            require(kind in (0,stat.S_IFREG,stat.S_IFDIR) and (kind!=stat.S_IFDIR or item.is_dir()),'unsupported ZIP type')
            records.append({'path':item.filename,'directory':item.is_dir(),'original_bytes':item.file_size})
        validate_layout(records)
        selected=[i for i in infos if '/benchmarks/' in '/'+i.filename and not i.is_dir() and
            (PurePosixPath(i.filename).name=='coverage.json' or i.filename.endswith(('.summary.json','.samples.jsonl.gz')))]
        require(bool(selected) and sum(i.file_size for i in selected)<=900_000_000,'selected analysis inputs exceed admission')
        require(shutil.disk_usage(output.parent).free>=sum(i.file_size for i in selected)+100_000_000,'analysis extraction lacks reserved space')
        output.mkdir()
        for item in selected:
            target=output.joinpath(*PurePosixPath(item.filename).parts);target.parent.mkdir(parents=True,exist_ok=True)
            with z.open(item) as f,target.open('xb') as out:
                count=0
                while chunk:=f.read(1024*1024):
                    count+=len(chunk);require(count<=item.file_size<=MAX_MEMBER,'selected member exceeds size');out.write(chunk)
            require(count==item.file_size,'selected member truncated')
    folders=list(output.rglob('coverage.json'));require(len(folders)==1,'expected exactly one coverage record')
    record={'status':'PASS','folder':str(folders[0].parent),'selected_members':len(selected),
        'selected_bytes':sum(i.file_size for i in selected),'original_zip_sha256':file_sha(source),
        'cleanup_scope':str(output.resolve()),'original_zip_retained':True}
    (output.parent/'analysis-input.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);a=p.parse_args();prepare(a.source,a.output)
