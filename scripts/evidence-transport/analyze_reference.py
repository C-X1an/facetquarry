"""Recompute recorded benchmark metrics without running an engine or changing data.

Standalone standard-library analysis, suitable for a reviewed evidence export.
The collector's independent Python oracle/filter checks remain distinct from
this reanalysis of exact-baseline responses, provenance, and recorded timings.
"""
from __future__ import annotations
import argparse
import collections
import csv
import datetime
import gzip
import hashlib
import itertools
import json
import math
from pathlib import Path
import random
import statistics

BOOTSTRAPS=2000
BOOTSTRAP_SEED=20261023
METRICS=('mean_recall','p50_search_ns','p95_search_ns','p99_search_ns',
         'mean_distance_evaluations','completed_queries_per_second','peak_rss_bytes')

def finite_number(value):
    if type(value) not in (int,float):return False
    try:return math.isfinite(value)
    except (OverflowError,TypeError):return False

def sha256_text(value):
    return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)

def require(condition,message):
    if not condition:raise ValueError(message)

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while data:=f.read(1024*1024):h.update(data)
    return h.hexdigest()

def nearest_rank(values,q):
    values=sorted(values)
    return values[max(0,math.ceil(q*len(values))-1)]

def interval(values,draws):
    if len(values)!=5 or not all(finite_number(v) for v in values):return None
    boot=[statistics.fmean(values[i] for i in indices) for indices in draws]
    return {'mean':statistics.fmean(values),'lower':nearest_rank(boot,.025),
            'upper':nearest_rank(boot,.975),'seeds':5,'bootstrap_replicates':len(draws)}

def expected_cells(config):
    facets={.2:'p20',.05:'p05',.01:'p01',.001:'p001'}
    result={}
    for n,dist,corr,seed in itertools.product(config['n'],config['distributions'],config['correlations'],config['seeds']):
        filters=[('all',{}) if s==1 else (facets[s],{facets[s]:'yes'}) for s in config['selectivities']]
        if config['two_facet']:filters.append(('and20',{'p20':'yes','parity':'0'}))
        for label,predicate in filters:
            for mode in ('exact','graph','postfilter','auto'):
                for ef in [max(config['ef'])] if mode=='exact' else config['ef']:
                    cell={'n':n,'dimension':config['dimension'],'distribution':dist,'correlation':corr,'seed':seed,
                          'filter_label':label,'filter':predicate,'mode':mode,'ef':ef,'concurrency':config['concurrency']}
                    cid=hashlib.sha256(json.dumps(cell,sort_keys=True).encode()).hexdigest()[:20]
                    if cid in result:raise ValueError('duplicate expected cell')
                    result[cid]=cell
    return result

def group_key(cell,seed=True,method=True):
    names=['n','dimension','distribution','correlation','filter_label','concurrency']
    if seed:names.append('seed')
    if method:names+=['mode','ef']
    return tuple(cell[n] for n in names)

def raw_samples(folder,cid,summary):
    path=folder/(cid+'.samples.jsonl.gz')
    if digest(path)!=summary.get('samples_sha256'):raise ValueError('raw compressed SHA mismatch')
    with gzip.open(path,'rt',encoding='utf-8') as f:
        while line:=f.readline(2_000_001):
            require(len(line)<=2_000_000,'sample line exceeds admitted bound')
            item=json.loads(line);require(isinstance(item,dict),'sample is not an object');yield item

def validate_summary(summary,cell,config,provenance,source):
    require(isinstance(summary,dict),'summary is not an object')
    require(summary.get('cell')==cell and summary.get('source')==source and summary.get('provenance')==provenance,
            'summary cell/source/provenance mismatch')
    require(summary.get('stage')=='measurement','summary is not a measurement')
    require(all(sha256_text(summary.get(k)) for k in ('generation','corpus_sha256','queries_sha256','samples_sha256')),
            'missing/invalid generation or input/sample SHA')
    require(type(summary.get('sample_count')) is int and summary['sample_count']==config['queries']*config['repetitions'],
            'summary sample count mismatch')
    require(isinstance(summary.get('errors'),list) and all(isinstance(v,str) for v in summary['errors']),
            'collector errors are malformed')
    require(summary.get('status')!='PASS' or summary['errors']==[],
            'PASS summary contains collector errors')
    require(finite_number(summary.get('build_process_seconds')) and summary['build_process_seconds']>=0,'invalid build time')
    require(type(summary.get('build_distance_evaluations')) is int and summary['build_distance_evaluations']>=0,'invalid build work')
    require(type(summary.get('snapshot_bytes')) is int and summary['snapshot_bytes']>0,'invalid snapshot bytes')
    meta=summary.get('native_metadata');require(isinstance(meta,dict),'native metadata is not an object')
    require(meta.get('source')==source and meta.get('go')=='go1.27.3','native source/toolchain mismatch')
    require(type(meta.get('workers')) is int and meta['workers']==config['concurrency'],'worker count mismatch')
    require(type(meta.get('gomaxprocs')) is int and meta['gomaxprocs']>0,'invalid GOMAXPROCS')
    require(type(meta.get('samples')) is int and meta['samples']==summary['sample_count'],'native sample count mismatch')
    require(type(meta.get('successful_queries')) is int and 0<=meta['successful_queries']<=meta['samples'],'invalid successful sample count')
    require(type(meta.get('peak_rss_bytes')) is int and meta['peak_rss_bytes']>0,'invalid native RSS')
    require(type(meta.get('measured_interval_ns')) is int and meta['measured_interval_ns']>0,'invalid measured interval')
    require(finite_number(meta.get('completed_queries_per_second')) and meta['completed_queries_per_second']>=0,'invalid native throughput')
    clock=meta.get('clock');require(isinstance(clock,dict),'invalid clock metadata')
    require(clock.get('monotonic') is True and clock.get('fallback') is False and type(clock.get('frequency_hz')) is int
            and clock['frequency_hz']>0 and isinstance(clock.get('calibration'),dict),'clock contract mismatch')

def response_values(response,cell,config,generation):
    require(isinstance(response,dict) and isinstance(response.get('hits'),list),'invalid response/hits')
    eligible=response.get('eligible');require(type(eligible) is int and 0<=eligible<=cell['n'],'invalid eligible count')
    hits=response['hits'];require(len(hits)<=min(config['k'],eligible),'excess returned hits')
    require(all(isinstance(h,dict) and isinstance(h.get('id'),str) and finite_number(h.get('distance')) for h in hits),'invalid hit')
    ids=[h['id'] for h in hits]
    require(all(len(x)==7 and x.startswith('r') and x[1:].isascii() and x[1:].isdigit() and 0<=int(x[1:])<cell['n'] for x in ids),
            'invalid/foreign synthetic ID')
    require(len(ids)==len(set(ids)),'duplicate returned ID')
    order=[(h['distance'],h['id']) for h in hits]
    require(order==sorted(order),'invalid hit ordering')
    require(response.get('generation')==generation and response.get('status')=='complete','response generation/status mismatch')
    count=response.get('distance_evaluations');require(type(count) is int and 0<=count<=1_000_000,'invalid/overspent work')
    return ids,order,eligible,count

def exact_truth(folder,cid,summary,expected_cell,config,provenance,source):
    validate_summary(summary,expected_cell,config,provenance,source)
    if summary.get('status')!='PASS' or summary.get('source')!=source or summary.get('provenance')!=provenance:
        raise ValueError('exact baseline is missing, failed or stale')
    truth={};seen=set()
    for item in raw_samples(folder,cid,summary):
        q=item['query'];rep=item['repetition'];r=item.get('response')
        if type(q) is not int or not 0<=q<config['queries'] or type(rep) is not int or not 0<=rep<config['repetitions'] or (q,rep) in seen:
            raise ValueError('exact baseline sample coverage invalid')
        seen.add((q,rep))
        if item.get('error') is not None or type(item.get('nanoseconds')) is not int or item['nanoseconds']<0:
            raise ValueError('exact baseline error/latency invalid')
        ids,order,eligible,count=response_values(r,expected_cell,config,summary['generation'])
        if r.get('exact') is not True or r.get('plan')!='exact' or len(ids)!=min(config['k'],eligible) or count!=eligible:
            raise ValueError('exact baseline did not complete exactly')
        value=(ids,eligible,order)
        if q in truth and truth[q]!=value:raise ValueError('exact baseline changed across repetitions')
        truth[q]=value
    if len(seen)!=config['queries']*config['repetitions']:raise ValueError('exact baseline incomplete')
    return {'queries':truth,'corpus_sha256':summary['corpus_sha256'],'generation':summary['generation']}

def analyze_cell(folder,cid,cell,summary,config,provenance,source,truth):
    errors=[];timings=[];recalls=[];work=[];seen=set();responses={};errors_calls=0;deficits=0;empty=0;invalid_ids=0
    row={'grid_id':cid,**{k:v for k,v in cell.items() if k!='filter'},'collector_status':summary.get('status','MISSING'),
         'collector_errors':summary.get('errors',[]),'stage':summary.get('stage'),'sample_count':0}
    if summary.get('cell')!=cell or summary.get('source')!=source or summary.get('provenance')!=provenance:
        errors.append('summary identity/config/provenance mismatch')
    if summary.get('status')!='PASS':errors.append('collector did not pass')
    if summary.get('stage')=='measurement':
        try:
            validate_summary(summary,cell,config,provenance,source)
            require(truth is not None,'complete exact baseline unavailable')
            require(summary['corpus_sha256']==truth['corpus_sha256'] and summary['generation']==truth['generation'],
                    'cell corpus/generation differs from exact baseline')
            for item in raw_samples(folder,cid,summary):
                q=item['query'];rep=item['repetition'];ns=item['nanoseconds']
                if type(q) is not int or not 0<=q<config['queries'] or type(rep) is not int or not 0<=rep<config['repetitions'] or (q,rep) in seen:
                    raise ValueError('invalid/duplicate query-repetition index')
                seen.add((q,rep))
                if type(ns) is not int or ns<0:raise ValueError('invalid latency')
                r=item.get('response')
                if item.get('error') is not None and r is not None:raise ValueError('sample has both response and error')
                if not isinstance(r,dict):errors_calls+=1;continue
                try:ids,order,eligible,count=response_values(r,cell,config,summary['generation'])
                except ValueError as failure:
                    if 'ID' in str(failure):invalid_ids+=1
                    raise
                signature=(order,r.get('eligible'),r.get('plan'),r.get('exact'))
                if q in responses and signature!=responses[q]:raise ValueError('answers changed across repetitions')
                responses[q]=signature
                target,expected_eligible,_=truth['queries'][q]
                if eligible!=expected_eligible:raise ValueError('eligible count differs from exact baseline')
                if len(target)!=min(config['k'],eligible):raise ValueError('exact denominator invalid')
                recall=len(set(ids)&set(target))/len(target) if target else None
                if item.get('recall_at_k')!=recall:raise ValueError('recorded recall differs from exact baseline intersection')
                if cell['mode']=='exact' and (ids!=target or r.get('exact') is not True):raise ValueError('exact baseline drift')
                deficits+=max(0,min(config['k'],eligible)-len(ids));empty+=not target
                timings.append(ns);work.append(count)
                if recall is not None:recalls.append(recall)
            if len(seen)!=config['queries']*config['repetitions']:errors.append('sample coverage incomplete')
        except (OSError,ValueError,KeyError,TypeError,IndexError) as failure:errors.append(str(failure))
    else:errors.append('no completed measurement stage')
    if errors_calls:errors.append('error calls excluded from successful-search latency')
    meta=summary.get('native_metadata',{})
    if not isinstance(meta,dict):meta={};errors.append('malformed native metadata')
    interval_ns=meta.get('measured_interval_ns');success=meta.get('successful_queries')
    if type(interval_ns) is not int or interval_ns<=0 or success!=len(timings) or meta.get('source')!=source:
        errors.append('native measured interval/success/source mismatch')
    throughput=success*1e9/interval_ns if type(interval_ns) is int and interval_ns>0 and type(success) is int else None
    if not finite_number(meta.get('completed_queries_per_second')) or not finite_number(throughput) or not math.isclose(meta['completed_queries_per_second'],throughput,rel_tol=1e-12,abs_tol=1e-9):
        errors.append('native throughput differs from completed/measured interval')
    values={'mean_recall':statistics.fmean(recalls) if recalls else None,
            'p50_search_ns':nearest_rank(timings,.5) if timings else None,
            'p95_search_ns':nearest_rank(timings,.95) if timings else None,
            'p99_search_ns':nearest_rank(timings,.99) if timings else None,
            'mean_distance_evaluations':statistics.fmean(work) if work else None,
            'completed_queries_per_second':throughput,'peak_rss_bytes':meta.get('peak_rss_bytes')}
    for name in ('mean_recall','p50_search_ns','p95_search_ns','p99_search_ns','mean_distance_evaluations'):
        old=summary.get(name);new=values[name]
        if old is None and new is None:continue
        if not finite_number(old) or not finite_number(new) or not math.isclose(old,new,rel_tol=1e-12,abs_tol=1e-9):errors.append('summary metric mismatch: '+name)
    row.update(values,sample_count=len(seen),successful_samples=len(timings),error_calls=errors_calls,
               empty_denominator_samples=empty,returned_count_deficit=deficits,invalid_foreign_ids=invalid_ids,
               collector_filter_violation_errors=sum('filter violation' in str(e) for e in summary.get('errors',[]) if isinstance(e,str)) if isinstance(summary.get('errors'),list) else None,
               zero_duration_count=timings.count(0),analysis_status='PASS' if not errors else 'FAIL',analysis_errors=errors,
               build_process_seconds=summary.get('build_process_seconds'),build_distance_evaluations=summary.get('build_distance_evaluations'),
               snapshot_bytes=summary.get('snapshot_bytes'),raw_samples_sha256=summary.get('samples_sha256'),
               corpus_sha256=summary.get('corpus_sha256'),queries_sha256=summary.get('queries_sha256'),generation=summary.get('generation'))
    return row

def target_status(row):
    if row['collector_status']=='MISSING' or row.get('stage')!='measurement':return 'NOT_RUN'
    if row['analysis_status']!='PASS' or not finite_number(row.get('mean_recall')):return 'INVALID'
    return 'PASS' if row['mean_recall']>=.95 else 'FAIL'

def target_outcome(rows):
    counts=dict(collections.Counter(r['recall_target_status'] for r in rows))
    if counts.get('FAIL',0):return 'FAIL',counts
    if counts.get('INVALID',0):return 'INVALID',counts
    if len(rows)!=45 or counts.get('NOT_RUN',0):return 'NOT_RUN',counts
    return 'PASS',counts

def validate_run(coverage,locked,source,profile):
    require(isinstance(coverage,dict) and isinstance(coverage.get('config'),dict),'invalid coverage/config')
    config=coverage['config']
    require({k:v for k,v in config.items() if k!='concurrency'}=={k:v for k,v in locked.items() if k!='concurrency'},'frozen configuration differs')
    require(type(config.get('concurrency')) is int and config['concurrency'] in (1,4,16) and coverage.get('profile')==profile,'profile/concurrency mismatch')
    provenance=coverage.get('provenance');require(isinstance(provenance,dict),'invalid provenance')
    require(sha256_text(source) and coverage.get('source')==source==provenance.get('source'),'run source mismatch')
    binaries=provenance.get('binaries');require(isinstance(binaries,dict) and set(binaries)=={'facetquarry','fqbench'},'binary set mismatch')
    require(all(isinstance(b,dict) and b.get('source')==source and b.get('go')=='go1.27.3' and sha256_text(b.get('sha256')) for b in binaries.values()),'binary source/toolchain/SHA mismatch')
    return config,provenance

def paired_effects(rows,config,draws):
    baselines={group_key(r,method=False):r for r in rows if r['mode']=='exact'}
    grouped=collections.defaultdict(list)
    for row in rows:
        if row['mode']!='exact':grouped[group_key(row,seed=False)].append(row)
    comparisons=[]
    for key,records in sorted(grouped.items()):
        records=sorted(records,key=lambda r:r['seed'])
        pairs=[(baselines.get(group_key(r,method=False)),r) for r in records]
        complete=(len(pairs)==5 and {r['seed'] for r in records}==set(config['seeds'])
                  and all(base is not None and base['analysis_status']==r['analysis_status']=='PASS'
                          and base['corpus_sha256']==r['corpus_sha256'] and base['generation']==r['generation'] for base,r in pairs))
        effects={}
        definitions={
            'recall_difference_method_minus_exact':lambda b,r:r['mean_recall']-b['mean_recall'],
            'distance_work_saved_exact_minus_method':lambda b,r:b['mean_distance_evaluations']-r['mean_distance_evaluations'],
            'p95_difference_method_minus_exact_ns':lambda b,r:r['p95_search_ns']-b['p95_search_ns'],
            'p95_ratio_exact_over_method':lambda b,r:b['p95_search_ns']/r['p95_search_ns'],
            'throughput_ratio_method_over_exact':lambda b,r:r['completed_queries_per_second']/b['completed_queries_per_second']}
        reasons={}
        for name,calculate in definitions.items():
            try:
                values=[calculate(base,r) for base,r in pairs] if complete else []
                effects[name]=interval(values,draws) if complete else None
                if effects[name] is None:reasons[name]='Incomplete five-seed valid pairs or missing/undefined metric; no seeds dropped.'
            except (TypeError,ValueError,ZeroDivisionError,OverflowError):
                effects[name]=None;reasons[name]='Undefined per-seed effect (including a real zero denominator); no interval substituted.'
        comparisons.append({'condition':dict(zip(['n','dimension','distribution','correlation','filter_label','concurrency','mode','ef'],key)),
                            'baseline':{'mode':'exact','ef':max(config['ef'])},'seed_ids':[r['seed'] for r in records],
                            'complete_five_seed_pairs':complete,'effects':effects,'unavailable_reasons':reasons,
                            'estimand':'Mean of five per-seed differences or ratios of per-cell summaries, with identical seed indices resampled jointly; not pooled/query-level speedup.'})
    return comparisons

def write_csv(path,rows):
    keys=list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=keys,lineterminator='\n');writer.writeheader()
        for row in rows:writer.writerow({k:json.dumps(v,separators=(',',':')) if isinstance(v,(dict,list,tuple)) else v for k,v in row.items()})

def main():
    p=argparse.ArgumentParser();p.add_argument('folder',type=Path);p.add_argument('--grid',type=Path,required=True)
    p.add_argument('--expected-source',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--historical-smoke-preview',action='store_true');a=p.parse_args()
    folder=a.folder;coverage=json.loads((folder/'coverage.json').read_text(encoding='utf-8'))
    profile='smoke' if a.historical_smoke_preview else 'full'
    locked=json.loads(a.grid.read_text(encoding='utf-8'))[profile]
    config,provenance=validate_run(coverage,locked,a.expected_source,profile)
    cells=expected_cells(config);summaries={};errors=[]
    for path in sorted(folder.glob('*.summary.json')):
        cid=path.name[:-len('.summary.json')];summary=json.loads(path.read_text(encoding='utf-8'))
        require(isinstance(summary,dict),cid+': summary is not an object');summaries[cid]=summary
    missing=sorted(set(cells)-set(summaries));unexpected=sorted(set(summaries)-set(cells));rows=[];truth_cache={}
    exact_ids={group_key(c,method=False):cid for cid,c in cells.items() if c['mode']=='exact'}
    for cid,cell in sorted(cells.items(),key=lambda pair:(group_key(pair[1],method=False),pair[1]['mode'],pair[1]['ef'])):
        key=group_key(cell,method=False)
        if key not in truth_cache:
            exact=exact_ids[key]
            try:truth_cache[key]=exact_truth(folder,exact,summaries[exact],cells[exact],config,provenance,a.expected_source)
            except (OSError,ValueError,KeyError,TypeError) as failure:truth_cache[key]=None;errors.append({'exact_cell':exact,'error':str(failure)})
        rows.append(analyze_cell(folder,cid,cell,summaries.get(cid,{}),config,provenance,a.expected_source,truth_cache[key]))
    rng=random.Random(BOOTSTRAP_SEED);draws=[[rng.randrange(5) for _ in range(5)] for _ in range(BOOTSTRAPS)]
    grouped=collections.defaultdict(list)
    for row in rows:grouped[group_key(row,seed=False)].append(row)
    groups=[]
    for key,records in sorted(grouped.items()):
        records=sorted(records,key=lambda r:r['seed']);complete=len(records)==5 and {r['seed'] for r in records}==set(config['seeds']) and all(r['analysis_status']=='PASS' for r in records)
        groups.append({'condition':dict(zip(['n','dimension','distribution','correlation','filter_label','concurrency','mode','ef'],key)),
                       'seed_ids':[r['seed'] for r in records],'complete_five_seed_interval':complete,
                       'metrics':{m:interval([r[m] for r in records],draws) if complete else None for m in METRICS}})
    target=[r for r in rows if r['n']==10000 and r['filter_label']=='all' and r['mode']=='graph' and r['ef']==128]
    for row in target:row['recall_target_status']=target_status(row)
    target_result,target_counts=target_outcome(target)
    comparisons=paired_effects(rows,config,draws)
    failed=[r['grid_id'] for r in rows if r['analysis_status']!='PASS']
    report={'schema_version':1,'evidence_type':'benchmark_reanalysis','source':a.expected_source,
            'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'profile':profile,'concurrency':config['concurrency'],
            'qualification':'HISTORICAL_SCHEMA_PREVIEW_ONLY' if a.historical_smoke_preview else 'RECORDED_RESULTS_REANALYSIS_NOT_REFERENCE_HOST_APPROVAL',
            'analysis_script_sha256':digest(Path(__file__)),'input_coverage_sha256':digest(folder/'coverage.json'),'locked_grid_sha256':digest(a.grid),
            'expected_cells':len(cells),'present_cells':len(summaries),'missing_cells':missing,'unexpected_cells':unexpected,
            'analysis_failed_cells':failed,'baseline_errors':errors,'sample_count':sum(r['sample_count'] for r in rows),
            'successful_samples':sum(r['successful_samples'] for r in rows),'error_calls':sum(r['error_calls'] for r in rows),
            'zero_duration_count':sum(r['zero_duration_count'] for r in rows),'five_seed_groups':len(groups),
            'complete_five_seed_groups':sum(g['complete_five_seed_interval'] for g in groups),
            'target_cells':len(target),'target_pass_cells':sum(r['recall_target_status']=='PASS' for r in target),
            'target_outcome':target_result,'target_status_counts':target_counts,'paired_comparison_groups':len(comparisons),
            'status':'PASS' if not missing and not unexpected and not failed and not errors else 'FAIL',
            'method':{'quantiles':'nearest rank ceil(q*N); per full cell ranks500/950/990 of1000timings',
                      'ci':'95% percentile bootstrap interval for mean of five per-seed statistic summaries; nearest-rank bootstrap endpoints',
                      'resampling_unit':'workload/build seed (joint corpus, queries and graph)','bootstrap_replicates':BOOTSTRAPS,'bootstrap_seed':BOOTSTRAP_SEED,
                      'ordering':'one shuffled cell order per group; five contiguous repetitions inside each cell',
                      'throughput':'successful queries / actual dispatch-to-completion interval including queue and streaming JSON backpressure'},
            'limitations':['Five seeds provide weak uncertainty estimates; repeated timings are not independent datasets.',
                           'Shared-host drift, power state and competing workload not controlled; no dedicated reference-host approval.',
                           'This reanalysis checks exact-baseline intersections. The collector independently enumerated exhaustive target IDs and checked exact ID/order and eligible-set membership. It did not compare returned distances with independent numerical distances; the separate oracle gate performs finite numerical-tolerance comparisons.',
                           'Invalid/foreign ID checks use frozen synthetic rNNNNNN IDs/range; collector filter violations remain separately reported.',
                           'Build metrics are one shared build per workload group, repeated in cell summaries; do not sum them across cells.',
                           'Methods pair within workload/build seed by frozen collector construction, shared corpus SHA and generation; query JSON hashes include method/ef and cannot directly establish vector identity. Never pair query indices across correlation conditions.']}
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'analysis.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    (a.output/'five-seed-intervals.json').write_text(json.dumps(groups,indent=2)+'\n',encoding='utf-8',newline='\n')
    (a.output/'paired-method-effects.json').write_text(json.dumps(comparisons,indent=2)+'\n',encoding='utf-8',newline='\n')
    write_csv(a.output/'per-seed-cells.csv',rows);write_csv(a.output/'reference-target-cells.csv',target)
    print(json.dumps({k:report[k] for k in ('status','qualification','expected_cells','present_cells','sample_count','analysis_failed_cells','target_outcome')}))
    return 0 if report['status']=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
