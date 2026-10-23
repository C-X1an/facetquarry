"""Resumable frozen-grid experiment; smoke is explicitly not full qualification.
Raw samples are compressed JSONL, including failures; coverage is checked against
expected cell IDs, not inferred from whatever files happened to be produced.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import itertools
import json
import math
from pathlib import Path
import random
import statistics
import time
from common import ROOT,run,source_hash
from oracle import expected

FACETS={0.2:'p20',0.05:'p05',0.01:'p01',0.001:'p001'}

def workload(n:int,dim:int,distribution:str,correlation:str,seed:int,query_count:int):
    rng=random.Random(seed*100003+n)
    records=[]
    for i in range(n):
        if distribution=='uniform':vector=[rng.uniform(-1,1) for _ in range(dim)]
        elif distribution=='clustered':
            center=(-3,0,3)[i%3];vector=[center+rng.gauss(0,0.3) for _ in range(dim)]
        else:vector=[float(i%5)]*dim
        records.append({'tenant':'alpha','id':f'r{i:06d}','vector':vector,'metadata':{'parity':str(i%2)}})
    order=list(range(n))
    if correlation=='independent':rng.shuffle(order)
    else:order.sort(key=lambda i:sum(x*x for x in records[i]['vector']),reverse=correlation=='negative')
    rank={idx:i for i,idx in enumerate(order)}
    for i,r in enumerate(records):
        for selectivity,key in FACETS.items():r['metadata'][key]='yes' if rank[i]<max(1,int(n*selectivity)) else 'no'
    vectors=[[rng.gauss(0,0.15) for _ in range(dim)] for _ in range(query_count)]
    return records,vectors

def percentile(values:list[int],q:float)->float:
    s=sorted(values);return float(s[max(0,math.ceil(q*len(s))-1)])

def main()->int:
    p=argparse.ArgumentParser();p.add_argument('--profile',choices=('smoke','full'),default='smoke');p.add_argument('--limit-cells',type=int,default=0);p.add_argument('--concurrency',type=int,choices=(1,4,16));a=p.parse_args()
    config=json.loads((ROOT/'benchmarks/grid.json').read_text())[a.profile]
    if a.concurrency:config['concurrency']=a.concurrency
    identity=source_hash();cfg_hash=hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()[:12]
    folder=ROOT/'.local/benchmarks'/f'{a.profile}-{identity[:12]}-{cfg_hash}';folder.mkdir(parents=True,exist_ok=True)
    expected_cells=[];expected_targets=[];summaries=[];completed_this_run=0;limited=False
    groups=itertools.product(config['n'],config['distributions'],config['correlations'],config['seeds'])
    for n,distribution,correlation,seed in groups:
        group={'n':n,'dimension':config['dimension'],'distribution':distribution,'correlation':correlation,'seed':seed}
        filters=[('all' if s==1 else FACETS[s],{} if s==1 else {FACETS[s]:'yes'}) for s in config['selectivities']]
        if config['two_facet']:filters.append(('and20',{'p20':'yes','parity':'0'}))
        cells=[]
        for label,filt in filters:
            for mode in ('exact','graph','postfilter','auto'):
                for ef in ([max(config['ef'])] if mode=='exact' else config['ef']):
                    cell={**group,'filter_label':label,'filter':filt,'mode':mode,'ef':ef,'concurrency':config['concurrency']}
                    cid=hashlib.sha256(json.dumps(cell,sort_keys=True).encode()).hexdigest()[:20]
                    cells.append((cid,cell));expected_cells.append(cid)
                    if n==10000 and label=='all' and mode=='graph' and ef==128:expected_targets.append(cid)
        rng=random.Random(seed);rng.shuffle(cells)
        pending=[(cid,c) for cid,c in cells if not (folder/f'{cid}.summary.json').exists()]
        if a.limit_cells and completed_this_run>=a.limit_cells:limited=True;continue
        if pending:
            if source_hash()!=identity:raise RuntimeError('source changed; refusing mixed-source benchmark')
            run(['python3','scripts/disk_guard.py','--reserve','500000000'])
            records,vectors=workload(n,config['dimension'],distribution,correlation,seed,config['queries'])
            corpus={'schema_version':1,'dimension':config['dimension'],'m':config['m'],'ef_construction':config['ef_construction'],'seed':seed,'build_budget':config['build_budget'],'records':records}
            corpus_path=folder/'active-corpus.json';index_path=folder/'active-index.fq';index_path.unlink(missing_ok=True);corpus_path.write_text(json.dumps(corpus,separators=(',',':')))
            start=time.perf_counter();build=run([str(ROOT/'bin/facetquarry'),'build','--input',str(corpus_path),'--output',str(index_path)],timeout=900,check=False);build_seconds=time.perf_counter()-start
            build_info=json.loads(build.stdout) if build.returncode==0 else None
            truths={}
            for cid,cell in pending:
                if a.limit_cells and completed_this_run>=a.limit_cells:limited=True;break
                if source_hash()!=identity:raise RuntimeError('source changed during experiment')
                if build.returncode!=0:
                    summary={'cell':cell,'source':identity,'status':'FAIL','stage':'build','exit_code':build.returncode,'stderr':build.stderr,'build_seconds':build_seconds}
                else:
                    qbase=[{'vector':v,'k':config['k'],'ef':cell['ef'],'budget':1000000,'mode':cell['mode'],'filter':cell['filter']} for v in vectors]
                    label=cell['filter_label']
                    if label not in truths:truths[label]=[expected(records,q,'alpha') for q in qbase]
                    eligible_ids={r['id'] for r in records if all(r['metadata'].get(k)==v for k,v in cell['filter'].items())}
                    query_path=folder/'active-queries.jsonl';query_path.write_text(''.join(json.dumps(q,separators=(',',':'))+'\n' for q in qbase))
                    command=[str(ROOT/'bin/fqbench'),'--index',str(index_path),'--tenant','alpha','--queries',str(query_path),'--warmup',str(config['warmup']),'--repetitions',str(config['repetitions']),'--concurrency',str(config['concurrency'])]
                    observed=run(command,timeout=900,check=False);samples=[];timings=[];recalls=[];work=[];meta={};errors=[]
                    for line in observed.stdout.splitlines():
                        item=json.loads(line)
                        if item.get('summary'):meta=item;continue
                        qid=item['query'];truth=truths[label][qid];target={x['id'] for x in truth}
                        response=item.get('response')
                        if response is None:errors.append(item.get('error','missing response'));recall=None
                        else:
                            ids={x['id'] for x in response['hits']};recall=len(ids & target)/len(target) if target else None
                            if not ids.issubset(eligible_ids):errors.append('filter violation')
                            if cell['mode']=='exact' and [x['id'] for x in response['hits']]!=[x['id'] for x in truth]:errors.append('exact oracle mismatch')
                            work.append(response['distance_evaluations'])
                        item['recall_at_k']=recall;samples.append(item);timings.append(item['nanoseconds'])
                        if recall is not None:recalls.append(recall)
                    with gzip.open(folder/f'{cid}.samples.jsonl.gz','wt') as f:
                        for item in samples:f.write(json.dumps(item,separators=(',',':'))+'\n')
                    ok=observed.returncode==0 and not errors and len(samples)==config['queries']*config['repetitions']
                    summary={'cell':cell,'source':identity,'status':'PASS' if ok else 'FAIL','stage':'measurement','sample_count':len(samples),'empty_denominator_samples':len(samples)-len(recalls),'mean_recall':statistics.mean(recalls) if recalls else None,'p50_search_ns':percentile(timings,.5) if timings else None,'p95_search_ns':percentile(timings,.95) if timings else None,'p99_search_ns':percentile(timings,.99) if timings else None,'mean_distance_evaluations':statistics.mean(work) if work else None,'build_process_seconds':build_seconds,'snapshot_bytes':index_path.stat().st_size,'generation':build_info['generation'],'native_metadata':meta,'errors':errors,'stderr':observed.stderr,'command':command}
                temp=folder/f'{cid}.summary.tmp';temp.write_text(json.dumps(summary,indent=2)+'\n');temp.replace(folder/f'{cid}.summary.json');completed_this_run+=1
            corpus_path.unlink(missing_ok=True);index_path.unlink(missing_ok=True);(folder/'active-queries.jsonl').unlink(missing_ok=True)
        for cid,_ in cells:
            path=folder/f'{cid}.summary.json'
            if path.exists():summaries.append(json.loads(path.read_text()))
    actual_ids={p.name.split('.')[0] for p in folder.glob('*.summary.json')}
    missing=sorted(set(expected_cells)-actual_ids);extra=sorted(actual_ids-set(expected_cells));failures=[s['cell'] for s in summaries if s['status']!='PASS']
    targets=[s for s in summaries if s['cell']['n']==10000 and s['cell']['filter_label']=='all' and s['cell']['mode']=='graph' and s['cell']['ef']==128]
    target_complete=bool(expected_targets) and len(targets)==len(expected_targets)
    target_pass=target_complete and all(s.get('status')=='PASS' and s.get('mean_recall',0)>=.95 for s in targets)
    report={'source':identity,'profile':a.profile,'config':config,'config_hash':cfg_hash,'expected_cells':len(expected_cells),'completed_cells':len(actual_ids),'missing_cells':missing,'unexpected_cells':extra,'failed_cells':failures,'limited':limited,'grid_complete':not missing and not extra,'reference_host_verified':False,'reference_recall_target':'PASS' if target_pass else 'NOT YET MEASURED' if not target_complete else 'FAIL','release_qualification':False,'scope':'synthetic experimental measurements; full grid and reference-host qualification are separate gates'}
    (folder/'coverage.json').write_text(json.dumps(report,indent=2)+'\n');(folder/'expected_cells.json').write_text(json.dumps(expected_cells)+'\n')
    print(json.dumps({'profile':a.profile,'folder':str(folder.relative_to(ROOT)),'cells':len(actual_ids),'expected':len(expected_cells),'failed_cells':len(failures),'scope':report['scope']}))
    return 0 if not missing and not extra and not failures else 1
if __name__=='__main__':raise SystemExit(main())
