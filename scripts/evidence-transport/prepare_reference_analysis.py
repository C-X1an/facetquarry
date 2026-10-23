"""Extract only bounded, validated analysis inputs; original ZIP remains intact."""
import argparse,hashlib,json,shutil,stat,zipfile
from pathlib import Path,PurePosixPath
from package_reference import require,validate_layout,MAX_MEMBER,file_sha

MEASURED='4949a016d1fc650cc80f18583e18b0ed487820801091508ea34b0a6b658a7dfe'
GRID_SHA='37d376ffa53b54fd37849b0fb682a76b944cea029185a0da4771dc1d20420992'

def default_grid():
    for base in list(Path(__file__).resolve().parents)[:3]:
        for path in (base/'benchmarks/grid.json',base/'public/benchmarks/grid.json'):
            if path.is_file():return path
    raise ValueError('frozen grid unavailable')

def prepare(source,output,grid=None,expected_source=MEASURED):
    require(not output.exists(),'analysis input already exists')
    grid=grid or default_grid();require(file_sha(grid)==GRID_SHA,'frozen grid bytes differ')
    frozen=json.loads(grid.read_text())['full'];profiles=[]
    with zipfile.ZipFile(source) as z:
        infos=z.infolist();require(0<len(infos)<=50000,'archive member count exceeds admission')
        records=[]
        for item in infos:
            kind=stat.S_IFMT(item.external_attr>>16)
            require(kind in (0,stat.S_IFREG,stat.S_IFDIR) and (kind!=stat.S_IFDIR or item.is_dir()),'unsupported ZIP type')
            records.append({'path':item.filename,'directory':item.is_dir(),'original_bytes':item.file_size})
        validate_layout(records)
        coverages=[i for i in infos if '/benchmarks/' in '/'+i.filename and PurePosixPath(i.filename).name=='coverage.json']
        require(0<len(coverages)<=8,'coverage record count exceeds admission')
        for item in coverages:
            require(item.file_size<=2_000_000,'coverage metadata exceeds admission')
            raw=z.read(item);coverage=json.loads(raw);require(isinstance(coverage,dict),'coverage is not an object')
            config=coverage.get('config',{})
            profiles.append({'zip_path':item.filename,'profile':coverage.get('profile'),'source':coverage.get('source'),
                'config':config,'coverage_sha256':hashlib.sha256(raw).hexdigest()})
        candidates=[x for x in profiles if x['profile']=='full' and x['source']==expected_source
            and json.dumps(x['config'],sort_keys=True)==json.dumps(frozen,sort_keys=True)]
        require(len(candidates)==1,'expected exactly one full/current-source/frozen-config coverage candidate')
        chosen=candidates[0];prefix=chosen['zip_path'].rsplit('/',1)[0]+'/'
        selected=[i for i in infos if i.filename.startswith(prefix) and not i.is_dir() and
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
        'cleanup_scope':str(output.resolve()),'original_zip_retained':True,
        'selected_profile':chosen,'excluded_profiles':[x for x in profiles if x is not chosen],
        'selection_policy':'Exactly one full/current-source/frozen-config candidate, without checking outcome; every summary/sample in that folder retained, including failed/unexpected cells. Original other profiles retained in unchanged ZIP.'}
    (output.parent/'analysis-input.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('output',type=Path);a=p.parse_args();prepare(a.source,a.output)
