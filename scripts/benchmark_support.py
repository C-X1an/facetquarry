"""Standard-library benchmark environment and retained subprocess attempts."""
from __future__ import annotations
import ctypes
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time
import uuid


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def memory_bytes():
    if os.name == 'nt':
        class MemoryStatus(ctypes.Structure):
            _fields_=[('length',ctypes.c_ulong),('load',ctypes.c_ulong)]+[(name,ctypes.c_ulonglong) for name in ('total_physical','available_physical','total_pagefile','available_pagefile','total_virtual','available_virtual','available_extended_virtual')]
        status=MemoryStatus();status.length=ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return status.total_physical,status.available_physical
    elif Path('/proc/meminfo').is_file():
        values={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.split(':')[0] in {'MemTotal','MemAvailable'}}
        return values.get('MemTotal'),values.get('MemAvailable')
    return None,None


def host_metadata():
    cpu=platform.processor() or None
    if os.name == 'nt':
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:
                cpu=winreg.QueryValueEx(key,'ProcessorNameString')[0].strip()
        except OSError:
            pass
    elif Path('/proc/cpuinfo').is_file():
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            if line.startswith('model name'):
                cpu=line.split(':',1)[1].strip();break
    total,_=memory_bytes()
    return {'system':platform.system(),'kernel':platform.release(),'os_version':platform.version(),
            'machine':platform.machine(),'cpu_model':cpu,'logical_cpu_count':os.cpu_count(),
            'physical_ram_bytes':total,'power_mode':'not measured',
            'competing_workload':'shared local host; competing activity not controlled'}


def text_output(value):
    if value is None:return ''
    if isinstance(value,bytes):return value.decode('utf-8',errors='replace')
    return value


def command_attempt(folder: Path, stage: str, command: list[str], runner, timeout=900):
    """A failed start/timeout retains genuine available streams and exact reason.

    runner enforces the stage timeout. subprocess.run kills and waits for its
    native child before TimeoutExpired is handled; no success samples are made.
    """
    attempt_id=str(time.time_ns())+'-'+uuid.uuid4().hex[:8]
    target=folder/'attempts'/attempt_id;target.mkdir(parents=True)
    started=utc_now();clock=time.perf_counter();termination=None;code=None;error=None
    try:
        result=runner(command,timeout=timeout,check=False,text=False)
        code=result.returncode;stdout=result.stdout;stderr=result.stderr
    except subprocess.TimeoutExpired as failure:
        termination='timeout';error=str(failure);stdout=failure.stdout;stderr=failure.stderr
    except OSError as failure:
        termination='start_error';error=type(failure).__name__+': '+str(failure);stdout=b'';stderr=b''
    streams={}
    for label,value in (('stdout',stdout),('stderr',stderr)):
        raw=value if isinstance(value,bytes) else text_output(value).encode()
        path=target/(label+'.txt.gz')
        with gzip.open(path,'wb') as output:output.write(raw)
        streams[label]={'path':path.relative_to(folder).as_posix(),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'raw_bytes':len(raw),'raw_sha256':hashlib.sha256(raw).hexdigest()}
    record={'attempt_id':attempt_id,'stage':stage,'command':command,'started_at':started,'ended_at':utc_now(),
            'duration_seconds':time.perf_counter()-clock,'timeout_seconds':timeout,'exit_code':code,
            'termination_reason':termination,'error':error,'status':'PASS' if code==0 and termination is None else 'FAIL',
            'streams':streams}
    (target/'attempt.json').write_text(json.dumps(record,indent=2)+'\n')
    return record,text_output(stdout),text_output(stderr)
