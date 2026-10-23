"""Bounded, lossless ZIP-member transport; never executes archive contents.

The original outer ZIP is identified, not reproduced. Every member byte is
recoverable and verified. Gzip recipes are used only after exact roundtrip proof.
"""
import argparse
import base64
import datetime
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import zipfile
import zlib

MAX_MEMBER=64*1024*1024
MAX_OUTPUT=400_000_000
MAX_TOTAL=24_000_000_000

def require(condition,message):
    if not condition:raise ValueError(message)

def sha(data):return hashlib.sha256(data).hexdigest()

def file_sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while data:=f.read(1024*1024):h.update(data)
    return h.hexdigest()

def safe_name(name):
    require(isinstance(name,str) and bool(name),'invalid member path type')
    p=PurePosixPath(name)
    require(not p.is_absolute() and '\\' not in name
            and ':' not in name and '..' not in p.parts and '\x00' not in name,'unsafe member path')
    require(all(part not in ('','.') for part in name.rstrip('/').split('/')),'noncanonical member path')
    require(len(name.encode('utf-16-le'))<=60000,'member path exceeds portable recovery bound')
    devices={'CON','PRN','AUX','NUL'}|{a+b for a in ('COM','LPT') for b in '123456789¹²³'}
    for part in p.parts:
        require(part[-1] not in '. ' and not any(ord(c)<32 or c in '<>"|?*' for c in part)
                and part.split('.')[0].upper() not in devices
                and len(part.encode('utf-16-le'))<=510 and len(part.encode('utf-8'))<=255,'nonportable member component')
    return p

def extended_windows_path(path):
    require(not path.startswith('\\\\?\\') and len(path.encode('utf-16-le'))<65000,'resolved Windows path exceeds recovery bound')
    return '\\\\?\\UNC\\'+path[2:] if path.startswith('\\\\') else '\\\\?\\'+path

def validate_layout(records):
    """Admit a recoverable layout before reading payloads or creating files."""
    names={}
    for record in records:
        path=safe_name(record['path']);directory=record['directory']
        require(type(directory) is bool and record['path'].endswith('/')==directory,'invalid directory flag/path')
        require(type(record['original_bytes']) is int and 0<=record['original_bytes']<=MAX_MEMBER,'recovery exceeds admission')
        if directory:require(record['original_bytes']==0 and record.get('payload_bytes',0)==0,'nonempty directory')
        key='/'.join(path.parts).casefold()
        require(key not in names,'duplicate/case-colliding file/directory conflict')
        names[key]=directory
    for key in names:
        parts=key.split('/')
        for i in range(1,len(parts)):
            require(names.get('/'.join(parts[:i]),True),'file ancestor conflict')

def gzip_header(raw):
    require(len(raw)>=18 and raw[:3]==b'\x1f\x8b\x08' and raw[3]&224==0,'unsupported gzip header')
    pos=10;flags=raw[3]
    if flags&4:
        require(len(raw)>=pos+2,'truncated gzip extra')
        pos+=2+int.from_bytes(raw[pos:pos+2],'little')
    for flag in (8,16):
        if flags&flag:
            pos=raw.index(b'\0',pos)+1
    if flags&2:pos+=2
    require(10<=pos<=4096 and pos<=len(raw)-8,'invalid gzip header length')
    return raw[:pos]

def encoded(raw,name):
    if not name.endswith('.gz'):return raw,{'encoding':'identity'}
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as f:payload=f.read(MAX_MEMBER+1)
        require(len(payload)<=MAX_MEMBER,'expanded gzip exceeds bound')
        header=gzip_header(raw);trailer=raw[-8:]
        c=zlib.compressobj(9,zlib.DEFLATED,-15)
        restored=header+c.compress(payload)+c.flush()+trailer
        require(restored==raw,'gzip compressor differs')
        return payload,{'encoding':'gzip-deflate-9','header':base64.b64encode(header).decode(),
                        'trailer':base64.b64encode(trailer).decode(),'zlib_version':zlib.ZLIB_VERSION}
    except (OSError,ValueError,EOFError,zlib.error):
        return raw,{'encoding':'identity'}

def decoded(payload,record):
    require(sha(payload)==record['payload_sha256'] and len(payload)==record['payload_bytes'],'payload digest/length mismatch')
    if record['encoding']=='identity':raw=payload
    elif record['encoding']=='gzip-deflate-9':
        header=base64.b64decode(record['header'],validate=True);trailer=base64.b64decode(record['trailer'],validate=True)
        require(len(header)<=4096 and len(trailer)==8,'gzip recipe bounds invalid')
        c=zlib.compressobj(9,zlib.DEFLATED,-15)
        raw=header+c.compress(payload)+c.flush()+trailer
    else:raise ValueError('unsupported payload encoding')
    require(len(raw)==record['original_bytes'] and sha(raw)==record['original_sha256'],
            'original member recovery mismatch (including compressor-version differences)')
    return raw

class LimitedWriter:
    def __init__(self,raw,limit):self.raw=raw;self.limit=limit;self.written=0
    def write(self,data):
        require(self.written+len(data)<=self.limit,'compressed output admission limit exceeded')
        count=self.raw.write(data);require(count==len(data),'short output write');self.written+=count;return count
    def flush(self):self.raw.flush()

def tar_item(archive,name,data):
    item=tarfile.TarInfo(name);item.size=len(data);item.mode=0o600;item.mtime=0
    archive.addfile(item,io.BytesIO(data))

def member_order(archive,infos):
    """Keep one workload's measurements together for bounded solid compression."""
    order={}
    for item in infos:
        if not item.filename.endswith('.summary.json') or '/benchmarks/' not in item.filename:continue
        try:
            summary=json.loads(archive.read(item));cell=summary['cell']
            group=(cell['n'],cell['distribution'],cell['correlation'],cell['seed'])
            cell_key=(cell['filter_label'],cell['mode'],cell['ef'])
            prefix=item.filename.rsplit('/',1)[0]+'/'
            stem=item.filename[:-len('.summary.json')]
            order[item.filename]=(1,group,cell_key,3,item.filename)
            order[stem+'.samples.jsonl.gz']=(1,group,cell_key,2,item.filename)
            for attempt in summary.get('attempts',[]):
                attempt_prefix=prefix+'attempts/'+attempt['attempt_id']+'/'
                key=(1,group,cell_key if attempt['stage']=='measurement' else ('', '', 0),0)
                for label in ('attempt.json','stdout.txt.gz','stderr.txt.gz'):
                    name=attempt_prefix+label;proposed=(*key,name)
                    if name not in order or proposed<order[name]:order[name]=proposed
        except (KeyError,ValueError,TypeError):continue
    return sorted(infos,key=lambda item:order.get(item.filename,(0,(),(),0,item.filename)))

def pack(source,output,expected_sha,expected_size,measured_source,artifact_id,run_id):
    require(not output.exists() and not output.with_suffix(output.suffix+'.partial').exists(),'output already exists')
    require(source.stat().st_size==expected_size and file_sha(source)==expected_sha,'original ZIP size/SHA mismatch')
    records=[];expanded=0;original_total=0
    with zipfile.ZipFile(source) as archive:
        infos=archive.infolist();require(0<len(infos)<=50000,'member count outside admission')
        for item in infos:
            kind=stat.S_IFMT(item.external_attr>>16)
            require(kind in (0,stat.S_IFREG,stat.S_IFDIR),'unsupported ZIP member type')
            require(kind!=stat.S_IFDIR or item.is_dir(),'ZIP directory metadata conflict')
            require(0<=item.file_size<=MAX_MEMBER,'ZIP member exceeds admitted bound')
            original_total+=item.file_size;require(original_total<=2_000_000_000,'ZIP expansion exceeds admission')
        validate_layout([{'path':x.filename,'directory':x.is_dir(),'original_bytes':x.file_size} for x in infos])
        infos=member_order(archive,infos)
        for index,item in enumerate(infos):
            raw=archive.read(item);payload,recipe=encoded(raw,item.filename)
            expanded+=len(payload);require(expanded<=MAX_TOTAL,'total streamed expansion exceeds admission')
            records.append({'path':item.filename,'directory':item.is_dir(),'original_bytes':len(raw),'original_sha256':sha(raw),
                            'payload_name':f'payload/{index:06d}','payload_bytes':len(payload),'payload_sha256':sha(payload),**recipe})
        manifest={'schema_version':1,'evidence_type':'lossless_member_transport','original_artifact_id':artifact_id,
                  'original_run_id':run_id,'original_zip_bytes':expected_size,'original_zip_sha256':expected_sha,
                  'measured_source':measured_source,'packaging_commit':os.environ.get('GITHUB_SHA'),
                  'codec_sha256':file_sha(Path(__file__)),'zlib_version':zlib.ZLIB_VERSION,'members':records,
                  'original_member_bytes':original_total,'streamed_payload_bytes':expanded,
                  'recovery_scope':'Exact bytes of every original ZIP member, verified by SHA-256. The outer ZIP container itself is identified but not reconstructed.',
                  'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
        partial=output.with_suffix(output.suffix+'.partial')
        with partial.open('xb') as raw_output:
            limited=LimitedWriter(raw_output,MAX_OUTPUT)
            with lzma.LZMAFile(limited,'wb',format=lzma.FORMAT_XZ,check=lzma.CHECK_SHA256,
                               filters=[{'id':lzma.FILTER_LZMA2,'preset':6,'dict_size':64*1024*1024}]) as compressed:
                with tarfile.open(fileobj=compressed,mode='w|') as tar:
                    tar_item(tar,'manifest.json',json.dumps(manifest,sort_keys=True,separators=(',',':')).encode())
                    for item,record in zip(infos,records):
                        raw=archive.read(item);require(sha(raw)==record['original_sha256'],'input member changed')
                        payload,_=encoded(raw,item.filename)
                        require(sha(payload)==record['payload_sha256'],'payload changed during second pass')
                        tar_item(tar,record['payload_name'],payload)
    require(file_sha(source)==expected_sha,'input ZIP changed during packaging')
    verify(partial)
    partial.replace(output)
    return {'status':'PASS','bundle_bytes':output.stat().st_size,'bundle_sha256':file_sha(output),
            'member_count':len(records),'original_member_bytes':original_total,'streamed_payload_bytes':expanded,
            'gzip_recipe_members':sum(x['encoding']!='identity' for x in records),'recovery_scope':manifest['recovery_scope']}

def verify(bundle,output=None):
    with tarfile.open(bundle,mode='r|xz') as tar:
        first=tar.next();require(first is not None and first.isfile() and first.name=='manifest.json' and first.size<=32*1024*1024,'invalid transport manifest')
        manifest=json.load(tar.extractfile(first));require(manifest['schema_version']==1 and 0<len(manifest['members'])<=50000,'invalid manifest schema/count')
        validate_layout(manifest['members'])
        if output is not None:
            require(not output.exists(),'recovery directory already exists')
            output=output.resolve()
            if os.name=='nt':
                for record in manifest['members']:
                    extended_windows_path(str(output.joinpath(*PurePosixPath(record['path']).parts)))
                output=Path(extended_windows_path(str(output)))
            output.mkdir()
        names=set();total=0
        for index,record in enumerate(manifest['members']):
            name=record['path'];safe_name(name);require(name.casefold() not in names,'duplicate recovery name');names.add(name.casefold())
            require(type(record['payload_bytes']) is int and 0<=record['payload_bytes']<=MAX_MEMBER,'payload exceeds admission')
            require(type(record['original_bytes']) is int and 0<=record['original_bytes']<=MAX_MEMBER,'recovery exceeds admission')
            item=tar.next();require(item is not None and item.isfile() and item.name==record['payload_name']==f'payload/{index:06d}' and item.size==record['payload_bytes'],'payload sequence/type mismatch')
            raw=decoded(tar.extractfile(item).read(MAX_MEMBER+1),record);total+=len(raw);require(total<=2_000_000_000,'recovery total exceeds admission')
            if output is not None:
                target=output.joinpath(*PurePosixPath(name).parts)
                if record['directory']:require(not raw,'nonempty directory');target.mkdir(parents=True,exist_ok=True)
                else:target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        require(tar.next() is None and total==manifest['original_member_bytes'],'unexpected extra payload or recovery total mismatch')
    return {'status':'PASS','member_count':len(names),'original_member_bytes':total,'measured_source':manifest['measured_source'],'original_zip_sha256':manifest['original_zip_sha256']}

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='action',required=True)
    a=sub.add_parser('pack');a.add_argument('source',type=Path);a.add_argument('output',type=Path)
    a.add_argument('--expected-sha',required=True);a.add_argument('--expected-size',type=int,required=True)
    a.add_argument('--measured-source',required=True);a.add_argument('--artifact-id',type=int,required=True);a.add_argument('--run-id',type=int,required=True)
    a=sub.add_parser('verify');a.add_argument('bundle',type=Path)
    a=sub.add_parser('recover');a.add_argument('bundle',type=Path);a.add_argument('output',type=Path)
    args=p.parse_args()
    result=pack(args.source,args.output,args.expected_sha,args.expected_size,args.measured_source,args.artifact_id,args.run_id) if args.action=='pack' else verify(args.bundle,getattr(args,'output',None))
    print(json.dumps(result))
if __name__=='__main__':main()
