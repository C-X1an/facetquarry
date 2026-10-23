"""No-install capability inventory. Never boots a VM or changes permissions."""
import fcntl,json,os
from pathlib import Path
import platform,shutil,stat,subprocess

def command(args):
    try:
        r=subprocess.run(args,capture_output=True,text=True,timeout=10,check=False)
        return {'command':args,'exit_code':r.returncode,'stdout':r.stdout[:16000],'stderr':r.stderr[:16000]}
    except (OSError,subprocess.TimeoutExpired) as e:return {'command':args,'error':type(e).__name__}

def metadata(path):
    try:
        s=path.stat();return {'path':str(path),'bytes':s.st_size,'readable':os.access(path,os.R_OK),'type':stat.S_IFMT(s.st_mode)}
    except OSError as e:return {'path':str(path),'error':type(e).__name__}

def main():
    record={'schema_version':1,'evidence_type':'reference_capability_probe','status':'OBSERVED',
        'kernel':platform.release(),'machine':platform.machine(),'logical_cpus':os.cpu_count(),
        'cpu_affinity_count':len(os.sched_getaffinity(0)),'memtotal_line':next(x for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:')),
        'scope':'Existing capabilities only. No guest boot, installation, download, permission/module change or reference qualification.'}
    kvm=Path('/dev/kvm');record['kvm']=metadata(kvm)
    try:
        fd=os.open(kvm,os.O_RDWR|os.O_CLOEXEC)
        try:record['kvm']['api_version']=fcntl.ioctl(fd,0xAE00,0)
        finally:os.close(fd)
    except OSError as e:record['kvm']['api_query_error']=type(e).__name__
    candidates=[Path(p) for p in (shutil.which('qemu-system-x86_64'),) if p]
    android=os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
    if android:
        candidate=Path(android)/'emulator/qemu/linux-x86_64/qemu-system-x86_64'
        if candidate.is_file():candidates.append(candidate)
    record['qemu']=[{'file':metadata(p),'version':command([str(p),'--version']),'accelerators':command([str(p),'-accel','help'])} for p in dict.fromkeys(candidates)]
    record['boot_files']=[metadata(p) for p in sorted(Path('/boot').glob('*')) if p.name.startswith(('vmlinuz','initrd','initramfs'))]
    record['guest_userspace_candidates']=[metadata(Path(p)) for p in ('/bin/busybox','/usr/bin/busybox','/bin/sh','/usr/bin/python3') if Path(p).exists()]
    record['existing_packaging_commands']={n:shutil.which(n) for n in ('cpio','gzip','mkfs.ext4','mount','unshare')}
    record['kvm_api_and_candidate_files_present']=record['kvm'].get('api_version')==12 and bool(record['qemu']) and bool(record['boot_files'])
    record['reference_host_verified']=False
    out=Path('.local/reference-capability.json');out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2));return 0

if __name__=='__main__':raise SystemExit(main())
