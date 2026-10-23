"""Independent exhaustive semantic oracle over actual Go CLI subprocess results."""
from __future__ import annotations
import argparse
import json
import math
from pathlib import Path
import random
import struct
import tempfile
from common import ROOT, run, source_hash

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
    binary=str(ROOT/'bin/facetquarry'); results=[]
    out=ROOT/'.local/oracle';out.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT/'.cache/tmp') as d:
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
            (tmp/'corpus.json').write_text(json.dumps(corpus));(tmp/'query.json').write_text(json.dumps(query))
            snapshot=tmp/'index.fq';snapshot.unlink(missing_ok=True)
            run([binary,'build','--input',str(tmp/'corpus.json'),'--output',str(snapshot)])
            r=run([binary,'search','--index',str(snapshot),'--tenant','alpha','--query',str(tmp/'query.json')]);actual=json.loads(r.stdout)
            truth=expected(records,query,'alpha')
            if [x['id'] for x in actual['hits']]!=[x['id'] for x in truth]:raise AssertionError(f'ID mismatch seed={seed}')
            for observed,want in zip(actual['hits'],truth):
                if not math.isclose(observed['distance'],want['distance'],rel_tol=1e-12,abs_tol=1e-9):raise AssertionError(f'distance mismatch seed={seed}')
            if not actual['exact'] or actual['status']!='complete':raise AssertionError(f'exact status seed={seed}')
            results.append({'seed':seed,'dimension':dim,'records_per_tenant':n,'hits':len(truth),'status':'PASS','generation':actual['generation']})
    (out/'cases.jsonl').write_text(''.join(json.dumps(x,separators=(',',':'))+'\n' for x in results))
    summary={'schema_version':1,'evidence_type':'oracle_summary','source':source_hash(),'seed_count':len(results),'status':'PASS','scope':'finite exact semantic comparisons, not ANN recall or production scale'}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary));return 0
if __name__=='__main__':raise SystemExit(main())
