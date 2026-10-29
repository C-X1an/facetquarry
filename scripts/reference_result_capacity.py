"""Observe nested bytes/inodes and reserve the complete remaining job tail.

The historical full-output floor is an admission reference, not an upper bound
on new compressed output or a guarantee that a new full run will fit or pass.
Actual execution remains bounded by the unchanged filesystem quota.
"""
from __future__ import annotations
import argparse
import json
import math
import os
from pathlib import Path
import time

from common import ROOT
import reference_filesystem as filesystem
import reference_internal_transport as transport
import reference_results as results

# Existing complete4949 inventory:27544full-profile files; these are their
# independently summed4096-byte allocation rounding and attempt-directory count.
HISTORICAL_FILES=27_544
HISTORICAL_ROUNDED_FILE_BYTES=941_305_856
HISTORICAL_ATTEMPT_DIRECTORIES=5_580
ACTIVE_WORKING_ALLOWANCE=32_000_000
RECOVERY_ALLOWANCE=20_000_000
ENTRY_MARGIN=256
MEASUREMENT_SECONDS=15_840
ANALYSIS_SECONDS=480
ENTRY_SECONDS=100
TRANSITION_SECONDS=120
require=transport.require


def floor_plan(block_size):
    require(type(block_size) is int and block_size in (1024,2048,4096),'unsupported result allocation unit')
    # Conservatively keep the4096 rounding even on a smaller allocation unit.
    directories=(HISTORICAL_ATTEMPT_DIRECTORIES+4)*4096
    return {'historical_source_prefix':'4949a016','historical_full_logical_bytes':872_241_572,
            'historical_full_files':HISTORICAL_FILES,'historical_4096_rounded_file_bytes':HISTORICAL_ROUNDED_FILE_BYTES,
            'directory_allowance_bytes':directories,'active_working_allowance_bytes':ACTIVE_WORKING_ALLOWANCE,
            'recovery_allowance_bytes':RECOVERY_ALLOWANCE,
            'required_available_bytes':HISTORICAL_ROUNDED_FILE_BYTES+directories+ACTIVE_WORKING_ALLOWANCE+RECOVERY_ALLOWANCE,
            'required_available_inodes':HISTORICAL_FILES+HISTORICAL_ATTEMPT_DIRECTORIES+4+ENTRY_MARGIN,
            'guaranteed_current_output_upper_bound':False}


def decide(counters,profile):
    require(profile in ('full','smoke','diagnostic'),'unknown reference workload')
    keys=('f_frsize','f_blocks','f_bfree','f_bavail','f_files','f_ffree','f_favail')
    require(all(type(counters.get(key)) is int for key in keys),'missing actual result byte/inode counters')
    require(0<counters['f_blocks'] and 0<=counters['f_bavail']<=counters['f_bfree']<=counters['f_blocks']
            and counters['f_files']>0 and 0<=counters['f_favail']<=counters['f_ffree']<=counters['f_files'],
            'inconsistent result filesystem counters')
    plan=floor_plan(counters['f_frsize'])
    available=counters['f_bavail']*counters['f_frsize']
    enough=(available>=plan['required_available_bytes'] and counters['f_favail']>=plan['required_available_inodes'])
    return {'profile':profile,'available_bytes':available,'available_inodes':counters['f_favail'],
            'reference_floor':plan,'full_reference_floor_met':enough,
            'admission':'ALLOW' if profile!='full' or enough else 'REFUSE',
            'scope':'Initial nested capacity observation/reference floor only; no full-run fit or benchmark qualification.'}


def time_plan(started,now):
    require(type(started) is int and type(now) in (int,float) and math.isfinite(now)
            and started>0 and now>=started,'invalid actual reference job clock')
    required=MEASUREMENT_SECONDS+ANALYSIS_SECONDS+transport.PACK_TOTAL_SECONDS+transport.PACK_VERIFY_SECONDS+transport.FREEZE_SECONDS+transport.FAILURE_TAIL_SECONDS+ENTRY_SECONDS+TRANSITION_SECONDS
    remaining=started+transport.JOB_SECONDS-now
    return {'job_started_epoch':started,'observed_epoch':now,'remaining_seconds':remaining,
            'measurement_command_seconds':MEASUREMENT_SECONDS,'analysis_and_qualification_seconds':ANALYSIS_SECONDS,
            'pack_seconds':transport.PACK_TOTAL_SECONDS,'verify_seconds':transport.PACK_VERIFY_SECONDS,
            'freeze_seconds':transport.FREEZE_SECONDS,'complete_failure_tail_seconds':transport.FAILURE_TAIL_SECONDS,
            'admission_entry_seconds':ENTRY_SECONDS,'transition_allowance_seconds':TRANSITION_SECONDS,
            'required_remaining_seconds':required,'admission':'ALLOW' if remaining>required else 'REFUSE'}


def main():
    entered=time.monotonic()
    with filesystem.whole_entry(ENTRY_SECONDS,started=entered):
        parser=argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--volume',type=Path,required=True)
        parser.add_argument('--project',type=Path,required=True)
        args=parser.parse_args()
        p=transport.paths(args.volume,args.project,ROOT)
        ctx=transport.context(p['project'])
        require(transport.context(p['outer'])==ctx,'capacity source/outer execution differs')
        transport.closed_guest(p,ctx)
        output=p['local']/'reference-results-capacity.json'
        record={'status':'FAIL','source':ctx['source'],'run_context':ctx,'started_at':results.utc(),
                'scope':__doc__.strip()}
        try:
            before=results.identity(p['project']/'.local')[:5]
            stats=os.statvfs(p['project']/'.local')
            counters={key:getattr(stats,key) for key in ('f_frsize','f_blocks','f_bfree','f_bavail','f_files','f_ffree','f_favail')}
            record['capacity']=decide(counters,os.environ['FQ_BENCH_PROFILE'])
            record['statvfs']=counters
            raw=os.environ.get('FQ_REFERENCE_JOB_STARTED_EPOCH','')
            require(raw.isdecimal(),'actual job initialization timestamp missing')
            record['time_admission']=time_plan(int(raw),time.time())
            require(record['capacity']['admission']=='ALLOW','nested full-output reference floor not available')
            require(record['time_admission']['admission']=='ALLOW','complete remaining measurement/preservation tail not available')
            require(results.identity(p['project']/'.local')[:5]==before
                    and transport.context(p['project'])==ctx and transport.context(p['outer'])==ctx,
                    'nested mount/source changed during capacity observation')
            record['status']='PASS'
        except BaseException as error:
            record['error']=(type(error).__name__+': '+str(error))[:2000]
        record['ended_at']=results.utc()
        results.save(output,record,initial=True)
        # Retain identical data inside the scientific/fallback image as well.
        results.save(p['project']/'.local/reference-results-capacity.json',record,initial=True)
        print(json.dumps(record))
        return 0 if record['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
