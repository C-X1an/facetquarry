"""UNEXECUTED source draft: explicit v2 samples through existing science checks.

The public legacy analyzer and compressed samples_sha256 semantics are intact.
This route derives its exact-truth/cell-metric loops from the pinned original;
the independently restored native/normalized adapter supplies the new reader.
It does not collect data or grant reference-host/release qualification.
"""
import collections
import math
import random
import statistics
from pathlib import Path

import analyze_reference as legacy
from analyze_reference import finite_number, sha256_text, require, nearest_rank
import scientific_capture_protocol as protocol
import scientific_execution_registry as registry
import scientific_analyzer_adapter as adapter


def response_values(response, cell, config, generation):
    ids, order, eligible, count = legacy.response_values(response, cell, config, generation)
    plan = 'exact' if eligible == 0 else (('exact' if eligible <= 256 else 'graph') if cell['mode'] == 'auto' else cell['mode'])
    require(response.get('plan') == plan and response.get('exact') is (plan == 'exact'),
            'plan/exact label differs from frozen mode/cardinality rule')
    if plan == 'exact':
        require(count == eligible and len(ids) == min(config['k'], eligible),
                'completed exact path did not exhaust eligible set')
    return ids, order, eligible, count


def validate_summary(summary,cell,config,provenance,source):
    require(isinstance(summary,dict),'summary is not an object')
    require(summary.get('evidence_format')==adapter.FORMAT and 'samples_sha256' not in summary,
            'explicit scientific v2 summary required; legacy compressed digest cannot be mixed')
    require(summary.get('cell')==cell and summary.get('source')==source and summary.get('provenance')==provenance,
            'summary cell/source/provenance mismatch')
    require(summary.get('stage')=='measurement','summary is not a measurement')
    require(all(sha256_text(summary.get(k)) for k in ('generation','corpus_sha256','queries_sha256','samples_original_sha256')),
            'missing/invalid generation or input/sample SHA')
    require(type(summary.get('sample_count')) is int and summary['sample_count']==1000==config['queries']*config['repetitions'],
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
    require(type(meta.get('measured_interval_ns')) is int and 0<meta['measured_interval_ns']<=(1<<63)-1,'invalid measured interval')
    require(finite_number(meta.get('completed_queries_per_second')) and meta['completed_queries_per_second']>=0,'invalid native throughput')
    clock=meta.get('clock');require(isinstance(clock,dict),'invalid clock metadata')
    require(clock.get('monotonic') is True and clock.get('fallback') is False and type(clock.get('frequency_hz')) is int
            and clock['frequency_hz']>0 and isinstance(clock.get('calibration'),dict),'clock contract mismatch')



def exact_truth(reader,cid,summary,expected_cell,config,provenance,source):
    validate_summary(summary,expected_cell,config,provenance,source)
    if summary.get('status')!='PASS' or summary.get('source')!=source or summary.get('provenance')!=provenance:
        raise ValueError('exact baseline is missing, failed or stale')
    truth={};seen=set()
    for item in reader.samples(cid,summary):
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



def analyze_cell(reader,cid,cell,summary,config,provenance,source,truth):
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
            for item in reader.samples(cid,summary):
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
                if r.get('plan')=='exact' and (ids!=target or r.get('exact') is not True):raise ValueError('exact baseline drift')
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
    interval_valid=type(interval_ns) is int and 0<interval_ns<=(1<<63)-1
    success_valid=type(success) is int and 0<=success<=1000
    if not interval_valid or not success_valid or success!=len(timings) or meta.get('source')!=source:
        errors.append('native measured interval/success/source mismatch')
    throughput=success*1e9/interval_ns if interval_valid and success_valid else None
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
               snapshot_bytes=summary.get('snapshot_bytes'),raw_samples_original_sha256=summary.get('samples_original_sha256'),evidence_format=adapter.FORMAT,
               corpus_sha256=summary.get('corpus_sha256'),queries_sha256=summary.get('queries_sha256'),generation=summary.get('generation'))
    return row


class ScientificSampleReader:
    """Real checked metadata and both restored originals, one invocation only.

    The process owner/caller supplies trusted root/expected-run/provenance. No
    receipt, class type or checksum is an authentication boundary. Filesystem
    memory and complete peak/failure admission remain external prerequisites.
    """
    def __init__(self, base, view, *, expected_run, provenance):
        require(type(view) is registry.ExecutionView, 'checked execution view required')
        protocol.validate_run(expected_run)
        self.run = protocol.decode(protocol.canonical(expected_run))
        self.provenance = protocol.decode(protocol.canonical(provenance))
        self.source = self.run['source']; self.config = self.run['config']
        legacy.validate_run({'config':self.config,'provenance':self.provenance,
                             'source':self.source,'profile':'full'},
                            protocol.frozen_config(self.config['concurrency']),self.source,'full')
        identity = registry.run_sha(self.run)
        require(view.root['invocation_coherence'] == 'one-original-invocation' and
                len(view.root['invocations']) == 1 and view.root['invocations'][0]['run_sha256'] == identity,
                'one original invocation required; resumed unions cannot become fresh')
        self.base, self.view = Path(base), view

    def summary(self, cell_id):
        try:
            return self.view.checked_cell(cell_id, expected_run=self.run).summary
        except registry.Refusal as error:
            if str(error) == 'CELL_NOT_PRESENT_IN_TRUSTED_ROOT':
                return {}
            raise

    def samples(self, cell_id, summary):
        checked = self.view.checked_cell(cell_id, expected_run=self.run)
        require(protocol.same(summary, checked.summary), 'analysis summary differs from checked original')
        linked = adapter.reconcile_checked_cell(self.base, self.view, cell_id, expected_run=self.run)
        require(linked.qualification == 'NOT_PERFORMED', 'linkage is not scientific qualification')
        return iter(linked.samples)


def analyze_execution(reader):
    """Reanalyze the complete frozen grid; report missing/failing cells explicitly.

    No files, subprocesses, fallback gzip reads, model/network calls, fixture
    answers, cleanup or reference-host approval. Consumers must separately bind
    the returned results to original command/host/transport evidence.
    """
    require(type(reader) is ScientificSampleReader, 'real scientific sample reader required')
    config, provenance, source = reader.config, reader.provenance, reader.source
    cells = legacy.expected_cells(config)
    require(len(cells) == 5400, 'complete frozen grid required')
    metadata_errors = []
    try:
        reader.view.require_single_fresh_layout(expected_run=reader.run)
    except registry.Refusal as error:
        metadata_errors.append(str(error))
    summaries = {cid:reader.summary(cid) for cid in cells}
    missing = sorted(cid for cid, summary in summaries.items() if not summary)
    rows, errors, truth_cache = [], [], {}
    exact_ids = {legacy.group_key(cell,method=False):cid for cid,cell in cells.items() if cell['mode']=='exact'}
    for cid, cell in sorted(cells.items(),key=lambda pair:(legacy.group_key(pair[1],method=False),pair[1]['mode'],pair[1]['ef'])):
        key = legacy.group_key(cell,method=False)
        if key not in truth_cache:
            exact = exact_ids[key]
            try:
                truth_cache[key] = exact_truth(reader,exact,summaries[exact],cells[exact],config,provenance,source)
            except (OSError,ValueError,KeyError,TypeError,IndexError) as error:
                truth_cache[key] = None
                errors.append({'exact_cell':exact,'error':str(error)})
        rows.append(analyze_cell(reader,cid,cell,summaries[cid],config,provenance,source,truth_cache[key]))
    rng = random.Random(legacy.BOOTSTRAP_SEED)
    draws = [[rng.randrange(5) for _ in range(5)] for _ in range(legacy.BOOTSTRAPS)]
    grouped = collections.defaultdict(list)
    for row in rows:
        grouped[legacy.group_key(row,seed=False)].append(row)
    groups = []
    for key, records in sorted(grouped.items()):
        records = sorted(records,key=lambda row:row['seed'])
        complete = len(records)==5 and {row['seed'] for row in records}==set(config['seeds']) and all(row['analysis_status']=='PASS' for row in records)
        groups.append({'condition':dict(zip(['n','dimension','distribution','correlation','filter_label','concurrency','mode','ef'],key)),
                       'seed_ids':[row['seed'] for row in records], 'complete_five_seed_interval':complete,
                       'metrics':{metric:legacy.interval([row[metric] for row in records],draws) if complete else None
                                  for metric in legacy.METRICS}})
    targets = [row for row in rows if row['n']==10000 and row['filter_label']=='all' and row['mode']=='graph' and row['ef']==128]
    for row in targets:
        row['recall_target_status'] = legacy.target_status(row)
    target_outcome, target_counts = legacy.target_outcome(targets)
    failed = [row['grid_id'] for row in rows if row['analysis_status']!='PASS']
    report = {'format':'scientific-recorded-results-analysis-v1','source':source,'profile':'full',
              'concurrency':config['concurrency'],'expected_cells':5400,'present_cells':5400-len(missing),
              'missing_cells':missing,'analysis_failed_cells':failed,'metadata_layout_errors':metadata_errors,
              'baseline_errors':errors,'sample_count':sum(row['sample_count'] for row in rows),
              'successful_samples':sum(row['successful_samples'] for row in rows),'error_calls':sum(row['error_calls'] for row in rows),
              'zero_duration_count':sum(row['zero_duration_count'] for row in rows),
              'target_cells':len(targets),'target_outcome':target_outcome,'target_status_counts':target_counts,
              'complete_five_seed_groups':sum(group['complete_five_seed_interval'] for group in groups),
              'execution_root_reference':protocol.decode(protocol.canonical(reader.view.root_reference)),
              'status':'PASS' if not missing and not failed and not errors and not metadata_errors else 'FAIL',
              'qualification':'RECORDED_SCIENTIFIC_ORIGINALS_REANALYSIS_NOT_REFERENCE_HOST_APPROVAL',
              'method':{'quantiles':'nearest rank ceil(q*N), no observations dropped',
                        'resampling_unit':'workload/build seed; all five fixed seeds required',
                        'bootstrap_replicates':legacy.BOOTSTRAPS,'bootstrap_seed':legacy.BOOTSTRAP_SEED,
                        'throughput':'successful native queries / actual dispatch-to-completion interval'},
              'limitations':['Reference host, source-built executables, original queries/corpus, command receipts, complete transport and release gates require separate qualification.',
                             'Raw sample digests identify restored original JSONL, not legacy compressed gzip bytes.',
                             'Exact-baseline intersections do not replace the separately implemented numerical oracle.',
                             'Five seeds give weak uncertainty estimates; repeated timings are not independent datasets.',
                             'Whole-member resolution and all decoded/cached structures need aggregate RAM admission.']}
    return {'report':report,'rows':rows,'five_seed_groups':groups,
            'paired_effects':legacy.paired_effects(rows,config,draws),'target_rows':targets}
