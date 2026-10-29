"""Independent exhaustive semantic oracle over actual Go CLI subprocess results."""
from __future__ import annotations
import argparse
import base64
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import uuid
from common import ROOT, run, source_hash

# The generated corpus and successful CLI responses are small. These limits
# bound retained diagnostics, not common.run's in-memory capture or archived
# histories. Actual integration executes inside the admitted results quota.
MAX_CLI_STREAM_BYTES=4096

def retained_stream(value):
    raw=value.encode('utf-8') if isinstance(value,str) else (b'' if value is None else bytes(value))
    prefix=raw[:MAX_CLI_STREAM_BYTES]
    return {'base64':base64.b64encode(prefix).decode('ascii'),'observed_bytes':len(raw),
            'retained_bytes':len(prefix),'sha256':hashlib.sha256(raw).hexdigest(),
            'retained_sha256':hashlib.sha256(prefix).hexdigest(),'truncated':len(prefix)!=len(raw)}

def cli(command,row):
    """Keep command bytes before semantic parsing, including failed commands."""
    item={'command':list(command),'exit_code':None,'status':'FAIL'}
    row['commands'].append(item)
    try:
        result=run(command,text=False)
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as error:
        item.update(exception=type(error).__name__,exit_code=getattr(error,'returncode',None),
                    stdout=retained_stream(error.stdout),stderr=retained_stream(error.stderr))
        raise
    else:
        item.update(exit_code=result.returncode,stdout=retained_stream(result.stdout),
                    stderr=retained_stream(result.stderr))
        if item['stdout']['truncated'] or item['stderr']['truncated']:
            raise ValueError('CLI stream retention admission exceeded; bounded prefixes retained')
        item['status']='PASS'
        return result

def report(message,stream):
    """Console diagnostics never replace a retained result or original error."""
    try:print(message,file=stream)
    except BaseException:pass

def f32(x:float)->float:return struct.unpack('<f',struct.pack('<f',x))[0]

def prepare_records(records:list[dict])->list[dict]:
    """Round corpus coordinates once; preserve the independent Python calculation."""
    return [{**rec, 'vector': [f32(x) for x in rec['vector']]} for rec in records]


def expected_prepared(records:list[dict],query:dict,tenant:str)->list[dict]:
    q=[f32(x) for x in query['vector']]
    values=[]
    for rec in records:
        if rec['tenant']!=tenant or not all(rec['metadata'].get(k)==v for k,v in query['filter'].items()):continue
        d=sum((a-b)*(a-b) for a,b in zip(q,rec['vector']))
        values.append({'id':rec['id'],'distance':d})
    return sorted(values,key=lambda x:(x['distance'],x['id']))[:query['k']]


def expected(records:list[dict],query:dict,tenant:str)->list[dict]:
    return expected_prepared(prepare_records(records),query,tenant)

def main()->int:
    p=argparse.ArgumentParser();p.add_argument('--seeds',type=int,default=1000);a=p.parse_args()
    if not 1<=a.seeds<=1000:p.error('seed count must be1..1000')
    binary=str(ROOT/'bin/facetquarry'); results=[]
    out=ROOT/'.local/oracle';out.mkdir(parents=True,exist_ok=True)
    previous=[out/name for name in ('cases.jsonl','summary.json') if (out/name).exists()]
    if previous:
        history=out/('previous-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex)
        history.mkdir()
        for file in previous:
            if file.is_symlink() or not file.is_file():raise ValueError('oracle convenience output is not a regular file')
            target=history/file.name
            if not target.resolve().is_relative_to(out.resolve()):raise ValueError('oracle history escapes owned output')
            file.rename(target)
    finished=False;written=0;failure=None
    try:
        with (out/'cases.jsonl').open('x',encoding='utf-8') as retained, tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as d:
            tmp=Path(d)
            for seed in range(a.seeds):
                rng=random.Random(20261023+seed);dim=rng.randint(1,8);n=rng.randint(3,30)
                records=[]
                for tenant in ('alpha','beta'):
                    for i in range(n):
                        vector=[rng.randint(-8,8)/3 for _ in range(dim)]
                        if seed%7==0:vector=[0.0]*dim
                        records.append({'tenant':tenant,'id':f'r{i:03d}','vector':vector,'metadata':{'kind':str(i%3),'bucket':str(i%2)}})
                corpus={'schema_version':1,'dimension':dim,'m':4,'ef_construction':24,'seed':seed+1,'build_budget':2000000,'records':records}
                filter_={} if seed%4==0 else {'kind':str(seed%5)}
                if seed%4==3:filter_['bucket']='1'
                query={'vector':[rng.randint(-6,6)/3 for _ in range(dim)],'k':rng.randint(1,10),'ef':16,'budget':1000,'mode':'exact','filter':filter_}
                truth=expected(records,query,'alpha')
                row={'seed':seed,'generator_seed':20261023+seed,'dimension':dim,'records_per_tenant':n,
                     'hits':len(truth),'status':'FAIL','corpus':corpus,'query':query,
                     'actual':None,'independent_expected':truth,'commands':[]}
                results.append(row)
                try:
                    (tmp/'corpus.json').write_text(json.dumps(corpus));(tmp/'query.json').write_text(json.dumps(query))
                    snapshot=tmp/'index.fq';snapshot.unlink(missing_ok=True)
                    cli([binary,'build','--input',str(tmp/'corpus.json'),'--output',str(snapshot)],row)
                    r=cli([binary,'search','--index',str(snapshot),'--tenant','alpha','--query',str(tmp/'query.json')],row);actual=json.loads(r.stdout)
                    row['actual']=actual
                    if [x['id'] for x in actual['hits']]!=[x['id'] for x in truth]:raise AssertionError(f'ID mismatch seed={seed}')
                    for observed,want in zip(actual['hits'],truth):
                        if not math.isclose(observed['distance'],want['distance'],rel_tol=1e-12,abs_tol=1e-9):raise AssertionError(f'distance mismatch seed={seed}')
                    if not actual['exact'] or actual['status']!='complete':raise AssertionError(f'exact status seed={seed}')
                    row.update(status='PASS',generation=actual['generation'])
                except BaseException as error:
                    row['error']={'type':type(error).__name__,'message':str(error)[:4096]}
                    raise
                finally:
                    encoded=json.dumps(row,separators=(',',':'),ensure_ascii=True)+'\n'
                    size=len(encoded.encode())
                    if size>64000 or written+size>64000000:raise ValueError('raw oracle comparison admission exceeded')
                    retained.write(encoded);retained.flush();os.fsync(retained.fileno());written+=size
        finished=True
    except BaseException as error:
        failure={'type':type(error).__name__,'message':str(error)[:4096]}
        raise
    finally:
        try:
            summary={'schema_version':1,'evidence_type':'oracle_summary','source':source_hash(),
                     'seed_count':len(results),'status':'PASS' if failure is None and finished and len(results)==a.seeds and all(x['status']=='PASS' for x in results) else 'FAIL',
                     'failure':failure,'raw_comparison_bytes':written,'raw_comparisons':'cases.jsonl',
                     'scope':'finite exact semantic comparisons with retained generated inputs/actual/independent truth; not ANN recall or production scale'}
            (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
            report(json.dumps(summary),sys.stdout)
        except BaseException as finalizer_error:
            if failure is None:raise
            # Do not replace the original command/comparison failure. Absent or
            # incomplete summary never authorizes a passing oracle gate.
            report('Oracle summary retention failed: '+type(finalizer_error).__name__+': '+str(finalizer_error)[:1000],sys.stderr)
    return 0
if __name__=='__main__':raise SystemExit(main())
