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
import platform
import sys
import os
from pathlib import Path
import random
import statistics
import time
from common import ROOT,run,source_hash,executable
from oracle import expected_prepared,prepare_records
from benchmark_support import command_attempt,host_metadata,memory_bytes,utc_now,Progress

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

def binary_provenance(identity: str) -> dict:
    binaries = {}
    for name in ('facetquarry', 'fqbench'):
        path = executable(name, ROOT)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        result = run([str(path), 'version'], check=False)
        try:
            version = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise RuntimeError(name + ': missing embedded source; rebuild both executables')
        if result.returncode != 0 or version.get('source') != identity:
            raise RuntimeError(name + ': executable source differs; rebuild both executables')
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError(name + ': executable changed during verification')
        settings=run(['go','version','-m',str(path)],timeout=30,check=False)
        if settings.returncode != 0:raise RuntimeError(name + ': cannot inspect actual Go build settings')
        binaries[name] = {'sha256': digest, 'source': version['source'], 'go': version.get('go'),
                          'build_settings':settings.stdout}
    return {'schema_version': 1, 'source': identity, 'binaries': binaries,
            'host': {**host_metadata(), 'python':sys.version},
            'gomaxprocs_requested':os.environ.get('FQ_CPUS','2'),
            'declared_build_flags':['-trimpath','-ldflags','-X main.sourceID='+identity]}


def verify_binary_hashes(provenance: dict) -> None:
    for name, record in provenance['binaries'].items():
        if hashlib.sha256(executable(name, ROOT).read_bytes()).hexdigest() != record['sha256']:
            raise RuntimeError(name + ': executable changed during benchmark')


def collect_summaries(folder: Path, expected_cells: dict, identity: str, provenance: dict) -> tuple[list, set]:
    summaries = []
    actual = set()
    # Collect the whole persisted grid, independently of this invocation's work limit.
    for path in sorted(folder.glob('*.summary.json')):
        cid = path.name.split('.')[0]
        actual.add(cid)
        record = json.loads(path.read_text())
        if record.get('source') != identity or record.get('provenance') != provenance:
            raise RuntimeError(cid + ': cached summary has stale or missing provenance')
        if record.get('cell') != expected_cells.get(cid) or record.get('status') not in {'PASS', 'FAIL'}:
            raise RuntimeError(cid + ': invalid cached cell summary')
        if record.get('stage') == 'measurement':
            samples = folder / (cid + '.samples.jsonl.gz')
            if not samples.is_file() or hashlib.sha256(samples.read_bytes()).hexdigest() != record.get('samples_sha256'):
                raise RuntimeError(cid + ': raw samples missing or changed')
        elif record.get('stage') not in {'build','admission'} or record.get('status') != 'FAIL':
            raise RuntimeError(cid + ': invalid cached stage')
        summaries.append(record)
    return summaries, actual


def grid_groups(config):
    groups=[];cell_map={};targets=[]
    for n,distribution,correlation,seed in itertools.product(config['n'],config['distributions'],config['correlations'],config['seeds']):
        group={'n':n,'dimension':config['dimension'],'distribution':distribution,'correlation':correlation,'seed':seed}
        filters=[('all' if value==1 else FACETS[value],{} if value==1 else {FACETS[value]:'yes'}) for value in config['selectivities']]
        if config['two_facet']:filters.append(('and20',{'p20':'yes','parity':'0'}))
        cells=[]
        for label,filt in filters:
            for mode in ('exact','graph','postfilter','auto'):
                for ef in ([max(config['ef'])] if mode=='exact' else config['ef']):
                    cell={**group,'filter_label':label,'filter':filt,'mode':mode,'ef':ef,'concurrency':config['concurrency']}
                    cid=hashlib.sha256(json.dumps(cell,sort_keys=True).encode()).hexdigest()[:20]
                    cells.append((cid,cell));cell_map[cid]=cell
                    if n==10000 and label=='all' and mode=='graph' and ef==128:targets.append(cid)
        random.Random(seed).shuffle(cells);groups.append((group,cells))
    return groups,cell_map,targets


def measurement(stdout,truths,eligible_ids,cell,config,identity):
    samples=[];timings=[];recalls=[];work=[];meta={};errors=[];seen=set()
    for number,line in enumerate(stdout.splitlines()):
        try:
            item=json.loads(line)
            if not isinstance(item,dict):raise ValueError('sample must be an object')
            if item.get('summary') is True:
                if meta:raise ValueError('duplicate native summary')
                meta=item;continue
            qid=item['query'];repetition=item['repetition'];duration=item['nanoseconds']
            if type(qid) is not int or not 0<=qid<config['queries']:raise ValueError('query index invalid')
            if type(repetition) is not int or not 0<=repetition<config['repetitions']:raise ValueError('repetition invalid')
            if (qid,repetition) in seen:raise ValueError('duplicate sample')
            if type(duration) is not int or duration<0:raise ValueError('invalid duration')
            target={value['id'] for value in truths[qid]};response=item.get('response')
            if response is None:
                errors.append(str(item.get('error','missing response')));recall=None
            else:
                if not isinstance(response,dict) or not isinstance(response.get('hits'),list):raise ValueError('invalid response/hits')
                if any(not isinstance(value,dict) or not isinstance(value.get('id'),str) for value in response['hits']):raise ValueError('invalid hit')
                if type(response.get('distance_evaluations')) is not int or response['distance_evaluations']<0:raise ValueError('invalid distance work')
                ids={value['id'] for value in response['hits']};recall=len(ids & target)/len(target) if target else None
                if len(ids)!=len(response['hits']):errors.append('duplicate returned ID')
                if not ids.issubset(eligible_ids):errors.append('filter violation')
                if cell['mode']=='exact' and [value['id'] for value in response['hits']]!=[value['id'] for value in truths[qid]]:errors.append('exact oracle mismatch')
                work.append(response['distance_evaluations'])
            seen.add((qid,repetition));item['recall_at_k']=recall;samples.append(item);timings.append(duration)
            if recall is not None:recalls.append(recall)
        except (ValueError,TypeError,KeyError,IndexError) as failure:
            errors.append('native output line '+str(number+1)+': '+str(failure))
    if meta.get('source')!=identity:errors.append('native benchmark source mismatch or missing summary')
    if len(samples)!=config['queries']*config['repetitions']:errors.append('native sample coverage incomplete')
    clock=meta.get('clock')
    if not isinstance(clock,dict) or clock.get('monotonic') is not True or clock.get('fallback') is not False or not isinstance(clock.get('frequency_hz'),int) or clock['frequency_hz']<=0 or not isinstance(clock.get('calibration'),dict):errors.append('native clock metadata missing or invalid')
    if type(meta.get('measured_interval_ns')) is not int or meta['measured_interval_ns']<=0:errors.append('native measured interval missing or invalid')
    if meta.get('samples')!=len(samples) or meta.get('workers')!=config['concurrency']:errors.append('native summary sample/worker coverage mismatch')
    if meta.get('zero_duration_count')!=timings.count(0):errors.append('native zero-duration count mismatch')
    if type(meta.get('gomaxprocs')) is not int or meta['gomaxprocs']<1:errors.append('native GOMAXPROCS missing or invalid')
    return samples,timings,recalls,work,meta,errors


def main()->int:
    parser=argparse.ArgumentParser();parser.add_argument('--profile',choices=('smoke','full','diagnostic'),default='smoke');parser.add_argument('--limit-cells',type=int,default=0);parser.add_argument('--concurrency',type=int,choices=(1,4,16));args=parser.parse_args()
    if args.limit_cells<0:parser.error('--limit-cells must be nonnegative')
    config=json.loads((ROOT/'benchmarks/grid.json').read_text())['full' if args.profile=='diagnostic' else args.profile]
    if args.profile=='diagnostic':
        config.update(n=[10000],distributions=['ties'],correlations=['independent'],seeds=[131])
    if args.concurrency:config['concurrency']=args.concurrency
    identity=source_hash();provenance=binary_provenance(identity);cfg_hash=hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()[:12]
    folder=ROOT/'.local/benchmarks'/f'{args.profile}-{identity[:12]}-{cfg_hash}';folder.mkdir(parents=True,exist_ok=True)
    provenance_path=folder/'provenance.json'
    if provenance_path.exists():
        if json.loads(provenance_path.read_text())!=provenance:raise RuntimeError('resume executable provenance differs; preserve this run and start a new source-bound run')
    else:
        if any(folder.glob('*.summary.json')):raise RuntimeError('cached summaries have no run provenance; refusing to relabel historical measurements')
        provenance_path.write_text(json.dumps(provenance,indent=2)+'\n')
    groups,cell_map,expected_targets=grid_groups(config)
    progress=Progress(ROOT/'.local/reference-progress.json',identity,args.profile,config['concurrency'],len(cell_map))
    invocation={'started_at':utc_now(),'available_physical_ram_bytes':memory_bytes()[1],
                'arguments':vars(args),'source':identity}
    invocation_path=folder/('invocation-'+str(time.time_ns())+'.json')
    completed_this_run=0;limited=False;run_errors=[];summaries=[]
    try:
        collect_summaries(folder,cell_map,identity,provenance)
        for group,cells in groups:
            pending=[(cid,cell) for cid,cell in cells if not (folder/f'{cid}.summary.json').exists()]
            if args.limit_cells and completed_this_run>=args.limit_cells:
                limited=limited or bool(pending);continue
            if not pending:continue
            progress.phase('source_and_binary_proof',group=group,cell=None)
            if source_hash()!=identity:raise RuntimeError('source changed; refusing mixed-source benchmark')
            verify_binary_hashes(provenance)
            progress.phase('admission')
            admission,_,_=command_attempt(folder,'admission',['python3','scripts/disk_guard.py','--reserve','500000000'],run,120)
            if admission['status']!='PASS':
                # Refusal is terminal before generating vectors, preparing the
                # oracle, serializing inputs or starting a native builder.
                if source_hash()!=identity:raise RuntimeError('source changed during resource admission')
                verify_binary_hashes(provenance)
                for cid,cell in pending:
                    if args.limit_cells and completed_this_run>=args.limit_cells:limited=True;break
                    summary={'cell':cell,'source':identity,'provenance':provenance,'status':'FAIL',
                             'stage':'admission','errors':['resource admission command failed'],
                             'started_at':admission['started_at'],'ended_at':utc_now(),
                             'corpus_sha256':None,'queries_sha256':None,'attempts':[admission]}
                    temp=folder/f'{cid}.summary.tmp';temp.write_text(json.dumps(summary,indent=2)+'\n');temp.replace(folder/f'{cid}.summary.json');completed_this_run+=1
                    progress.cell_finished('FAIL')
                continue
            progress.phase('corpus_creation')
            records,vectors=workload(group['n'],config['dimension'],group['distribution'],group['correlation'],group['seed'],config['queries'])
            prepared=prepare_records(records)
            corpus={'schema_version':1,'dimension':config['dimension'],'m':config['m'],'ef_construction':config['ef_construction'],'seed':group['seed'],'build_budget':config['build_budget'],'records':records}
            corpus_path=folder/'active-corpus.json';index_path=folder/'active-index.fq';index_path.unlink(missing_ok=True)
            corpus_raw=json.dumps(corpus,separators=(',',':')).encode();corpus_path.write_bytes(corpus_raw)
            corpus_sha=hashlib.sha256(corpus_raw).hexdigest();build_info=None;build_error=None;build=None
            progress.phase('build')
            build,build_stdout,_=command_attempt(folder,'build',[str(executable('facetquarry',ROOT)),'build','--input',str(corpus_path),'--output',str(index_path)],run)
            if build['status']=='PASS':
                try:
                    build_info=json.loads(build_stdout)
                    if not isinstance(build_info,dict) or not isinstance(build_info.get('generation'),str) or not index_path.is_file():raise ValueError('build output/index missing')
                except (ValueError,TypeError) as failure:build_error='build_parse: '+str(failure)
            truths={}
            for cid,cell in pending:
                if args.limit_cells and completed_this_run>=args.limit_cells:limited=True;break
                progress.phase('source_proof',cell=cid)
                if source_hash()!=identity:raise RuntimeError('source changed during experiment')
                started=utc_now();qbase=[{'vector':vector,'k':config['k'],'ef':cell['ef'],'budget':1000000,'mode':cell['mode'],'filter':cell['filter']} for vector in vectors]
                query_raw=''.join(json.dumps(query,separators=(',',':'))+'\n' for query in qbase).encode()
                summary={'cell':cell,'source':identity,'provenance':provenance,'status':'FAIL','started_at':started,
                         'corpus_sha256':corpus_sha,'queries_sha256':hashlib.sha256(query_raw).hexdigest(),
                         'attempts':[admission]+([build] if build else [])}
                if build['status']!='PASS' or build_error:
                    summary.update(stage='build',errors=[build_error or 'build command failed'],build_seconds=build['duration_seconds'])
                else:
                    label=cell['filter_label']
                    progress.phase('oracle')
                    if label not in truths:truths[label]=[expected_prepared(prepared,query,'alpha') for query in qbase]
                    eligible_ids={record['id'] for record in records if all(record['metadata'].get(key)==value for key,value in cell['filter'].items())}
                    query_path=folder/'active-queries.jsonl';query_path.write_bytes(query_raw)
                    command=[str(executable('fqbench',ROOT)),'--index',str(index_path),'--tenant','alpha','--queries',str(query_path),'--warmup',str(config['warmup']),'--repetitions',str(config['repetitions']),'--concurrency',str(config['concurrency'])]
                    progress.phase('native_measurement')
                    observed,stdout,_=command_attempt(folder,'measurement',command,run)
                    progress.phase('sample_validation_and_compression')
                    samples,timings,recalls,work,meta,errors=measurement(stdout,truths[label],eligible_ids,cell,config,identity)
                    if observed['status']!='PASS':errors.append('measurement command failed: '+str(observed['termination_reason'] or observed['exit_code']))
                    with gzip.open(folder/f'{cid}.samples.jsonl.gz','wt') as output:
                        for sample in samples:output.write(json.dumps(sample,separators=(',',':'))+'\n')
                    summary['attempts'].append(observed)
                    summary.update(stage='measurement',status='PASS' if not errors else 'FAIL',sample_count=len(samples),
                        empty_denominator_samples=len(samples)-len(recalls),mean_recall=statistics.mean(recalls) if recalls else None,
                        p50_search_ns=percentile(timings,.5) if timings else None,p95_search_ns=percentile(timings,.95) if timings else None,
                        p99_search_ns=percentile(timings,.99) if timings else None,zero_duration_count=timings.count(0),
                        mean_distance_evaluations=statistics.mean(work) if work else None,build_process_seconds=build['duration_seconds'],
                        snapshot_bytes=index_path.stat().st_size,generation=build_info['generation'],
                        build_distance_evaluations=build_info.get('build_distance_evaluations'),native_metadata=meta,errors=errors,command=command,
                        samples_sha256=hashlib.sha256((folder/f'{cid}.samples.jsonl.gz').read_bytes()).hexdigest())
                progress.phase('publication_proof')
                verify_binary_hashes(provenance)
                if source_hash()!=identity:raise RuntimeError('source changed before summary publication')
                summary['ended_at']=utc_now()
                temp=folder/f'{cid}.summary.tmp';temp.write_text(json.dumps(summary,indent=2)+'\n');temp.replace(folder/f'{cid}.summary.json');completed_this_run+=1
                progress.cell_finished(summary['status'])
            corpus_path.unlink(missing_ok=True);index_path.unlink(missing_ok=True);(folder/'active-queries.jsonl').unlink(missing_ok=True)
    except Exception as failure:
        # Preserve attempts and make interrupted/unattempted cells explicit in coverage.
        run_errors.append(type(failure).__name__+': '+str(failure))
    progress.phase('final_collection')
    try:
        summaries,actual_ids=collect_summaries(folder,cell_map,identity,provenance)
    except Exception as failure:
        run_errors.append(type(failure).__name__+': '+str(failure));actual_ids={path.name.split('.')[0] for path in folder.glob('*.summary.json')}
    missing=sorted(set(cell_map)-actual_ids);extra=sorted(actual_ids-set(cell_map));failures=[summary['cell'] for summary in summaries if summary['status']!='PASS']
    targets=[summary for summary in summaries if summary['cell']['n']==10000 and summary['cell']['filter_label']=='all' and summary['cell']['mode']=='graph' and summary['cell']['ef']==128]
    target_complete=bool(expected_targets) and len(targets)==len(expected_targets)
    target_pass=target_complete and all(summary.get('status')=='PASS' and summary.get('mean_recall',0)>=.95 for summary in targets)
    report={'schema_version':1,'evidence_type':'benchmark_coverage','source':identity,'provenance':provenance,'profile':args.profile,'config':config,'config_hash':cfg_hash,
        'expected_cells':len(cell_map),'completed_cells':len(actual_ids),'missing_cells':missing,'unexpected_cells':extra,'failed_cells':failures,'run_errors':run_errors,'limited':limited,
        'grid_complete':not missing and not extra and not run_errors,'reference_host_verified':False,
        'reference_recall_target':'NOT QUALIFYING' if args.profile=='diagnostic' else 'PASS' if target_pass else 'NOT YET MEASURED' if not target_complete else 'FAIL',
        'release_qualification':False,'scope':'synthetic experimental measurements; full grid and reference-host qualification are separate gates'}
    report['status']='PASS' if not missing and not extra and not failures and not run_errors else 'FAIL'
    invocation.update(ended_at=utc_now(),status=report['status'],completed_this_invocation=completed_this_run,run_errors=run_errors)
    invocation_path.write_text(json.dumps(invocation,indent=2)+'\n')
    (folder/'coverage.json').write_text(json.dumps(report,indent=2)+'\n');(folder/'expected_cells.json').write_text(json.dumps(list(cell_map))+'\n')
    progress.phase('complete' if report['status']=='PASS' else 'failed',qualifying_profile=args.profile=='full')
    print(json.dumps({'profile':args.profile,'folder':str(folder.relative_to(ROOT)),'status':report['status'],'cells':len(actual_ids),'expected':len(cell_map),'failed_cells':len(failures),'run_errors':run_errors,'scope':report['scope']}))
    return 0 if report['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
