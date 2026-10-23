"""Observe existing privileged KVM access; no guest memory, vCPUs or boot."""
import fcntl,json,os,platform,stat,subprocess
from pathlib import Path

def main():
    record={'schema_version':1,'evidence_type':'privileged_kvm_capability_probe','status':'OBSERVED',
        'uid':os.geteuid(),'kernel':platform.release(),'machine':platform.machine(),
        'reference_host_verified':False,
        'scope':'Existing noninteractive sudo only. Open KVM, query API and create/close one empty VM descriptor. No vCPU, memory registration, guest boot, download, package installation, permission/module change or benchmark.'}
    dev=vm=None
    try:
        st=Path('/dev/kvm').lstat()
        record['device']={'character_device':stat.S_ISCHR(st.st_mode),'major':os.major(st.st_rdev),'minor':os.minor(st.st_rdev)}
        if not stat.S_ISCHR(st.st_mode):raise ValueError('KVM path is not a character device')
        dev=os.open('/dev/kvm',os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW)
        actual=os.fstat(dev)
        if actual.st_rdev!=st.st_rdev or not stat.S_ISCHR(actual.st_mode):raise ValueError('KVM device changed')
        record['api_version']=fcntl.ioctl(dev,0xAE00,0)
        if record['api_version']!=12:raise ValueError('unsupported KVM API')
        vm=fcntl.ioctl(dev,0xAE01,0)
        if vm<0:raise ValueError('KVM did not return a VM descriptor')
        record['empty_vm_created']=True
    except (OSError,ValueError) as error:
        record['probe_error']={'type':type(error).__name__,'errno':getattr(error,'errno',None),'message':str(error)}
        record['empty_vm_created']=False
    finally:
        if vm is not None and vm>=0:os.close(vm)
        if dev is not None:os.close(dev)
        record['descriptors_closed']=True
    # Inspect installed package metadata only; no package-manager mutation.
    try:
        p=subprocess.run(['apt-cache','policy','qemu-system-x86','qemu-system-common'],capture_output=True,text=True,timeout=10,check=False)
        record['qemu_package_metadata']={'exit_code':p.returncode,'stdout':p.stdout[:16000],'stderr':p.stderr[:2000]}
    except (OSError,subprocess.TimeoutExpired) as error:record['qemu_package_metadata']={'error':type(error).__name__}
    dest=Path('.local/reference-kvm-privileged.json');dest.parent.mkdir(exist_ok=True)
    dest.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
    return 0

if __name__=='__main__':raise SystemExit(main())
