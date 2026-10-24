"""Owned-volume Linux KVM reference guest; no package installation or TCG fallback.

Run through scripts/evidence.py on the approved Ubuntu runner. Every download,
extraction, copied runtime and guest output stays in the caller's ext4 volume.
A smoke result proves boot/geometry/tools only, never benchmark qualification.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from urllib.parse import urlparse

from common import ROOT, source_hash

GUEST_RAM = 8_000_000_000
TMPFS_BYTES = 18 * 1024 * 1024
INITRD_MAX = 16 * 1024 * 1024
LOG_MAX = 16 * 1024 * 1024


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def allocated(root, package_links=None):
    total = 0
    def failed(error):
        raise error
    for parent, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        for name in dirs + files:
            p = Path(parent) / name
            info = p.lstat()
            if p.is_symlink():
                if package_links is None or not p.is_relative_to(package_links):
                    raise RuntimeError('owned guest setup contains a symlink: ' + str(p))
                # Trusted package extraction only. Never follow these links;
                # their names/targets are recorded and materialized before boot.
                total += max(info.st_size, getattr(info, 'st_blocks', 0) * 512)
            elif stat.S_ISREG(info.st_mode):
                total += max(info.st_size, getattr(info, 'st_blocks', 0) * 512)
            elif not stat.S_ISDIR(info.st_mode):
                raise RuntimeError('unexpected owned filesystem entry: ' + str(p))
    return total


class Setup:
    def __init__(self, args):
        self.args = args
        self.base = args.volume / 'reference-guest'
        self.base.mkdir(mode=0o700)  # Refuse reuse: preserve failed attempts.
        self.logs = self.base / 'commands'
        self.logs.mkdir()
        self.records = []
        self.package_links = None
        self.deadline = time.monotonic() + 600 + args.timeout
        self.manifest = {'schema_version': 1, 'scope': 'owned-volume KVM guest setup',
                         'source': source_hash(args.project), 'commands': self.records,
                         'download_trust': 'existing Ubuntu signed APT indexes; no authentication bypass',
                         'guest_ram_bytes': GUEST_RAM, 'tmpfs_limit_bytes': TMPFS_BYTES,
                         'initrd_uncompressed_limit_bytes': INITRD_MAX,
                         'reference_host_verified': False, 'status': 'PREPARING'}
        self.save()

    def save(self):
        write_json(self.base / 'setup.json', self.manifest)

    def check(self, growth=0):
        if time.monotonic() >= self.deadline:
            raise RuntimeError('overall guest setup/workload deadline exceeded')
        used = allocated(self.base, self.package_links)
        if used + growth > self.args.setup_max_bytes:
            raise RuntimeError('guest setup allocation ceiling exceeded')
        if shutil.disk_usage(self.base).free < growth + 500_000_000:
            raise RuntimeError('guest setup would consume the unchanged 500MB benchmark reserve')
        return used

    def run(self, command, *, timeout=120, env=None, check=True):
        timeout = min(timeout, max(1, int(self.deadline - time.monotonic())))
        self.check()
        number = len(self.records)
        out = self.logs / f'{number:03d}.stdout'
        err = self.logs / f'{number:03d}.stderr'
        record = {'command': command, 'timeout_seconds': timeout, 'exit_code': None}
        unit = None
        actual = command
        if command[:2] == ['sudo', '-n']:
            # The transient unit owns the root processes even if this unprivileged
            # wrapper is interrupted. Its own timer is independent of killpg.
            unit = 'facetquarry-owned-' + uuid.uuid4().hex
            actual = ['sudo', '-n', 'systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                      '--unit=' + unit, '--property=RuntimeMaxSec=' + str(timeout),
                      '--property=TimeoutStopSec=5', '--property=KillMode=control-group',
                      '--', *command[2:]]
            record.update(transient_unit=unit, actual_command=actual)
        self.records.append(record)
        self.save()
        started = time.monotonic()
        reason = None
        with out.open('wb') as stdout, err.open('wb') as stderr:
            proc = subprocess.Popen(actual, stdout=stdout, stderr=stderr, env=env,
                                    start_new_session=True)
            try:
                while proc.poll() is None:
                    if time.monotonic() - started > timeout:
                        reason = 'timeout'
                    elif out.stat().st_size + err.stat().st_size > LOG_MAX:
                        reason = 'output_limit'
                    if reason:
                        break
                    time.sleep(0.1)
            finally:
                if proc.poll() is None:
                    if unit is not None:
                        stopped = subprocess.run(['sudo', '-n', 'systemctl', 'stop', unit],
                                                 capture_output=True, timeout=15)
                        record['scoped_stop_exit_code'] = stopped.returncode
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except (ProcessLookupError, PermissionError):
                        pass
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            pass
                        proc.wait(timeout=10)
            code = proc.wait(timeout=10)
        record.update(exit_code=code, termination_reason=reason,
                      duration_seconds=time.monotonic() - started,
                      stdout=str(out.relative_to(self.base)), stderr=str(err.relative_to(self.base)),
                      stdout_sha256=digest(out), stderr_sha256=digest(err))
        self.save()
        if check and (code or reason):
            raise RuntimeError(f'command {number} failed; retained output: {err}')
        return out.read_text(errors='replace')


def official_uri(uri):
    parsed = urlparse(uri)
    host = parsed.hostname or ''
    return parsed.scheme in {'http', 'https'} and (
        host == 'ubuntu.com' or host.endswith('.ubuntu.com') or
        host == 'canonical.com' or host.endswith('.canonical.com'))


def package_stanza(raw, version):
    for section in raw.split('\n\n'):
        values = {}
        for line in section.splitlines():
            if ': ' in line and not line[0].isspace():
                key, value = line.split(': ', 1)
                values[key] = value
        if values.get('Version') == version and 'SHA256' in values:
            return values
    raise RuntimeError('APT signed-index size/SHA256 metadata missing')


def packages(setup):
    cache = setup.base / 'apt'
    cache.mkdir()
    (cache / 'partial').mkdir()
    extract = setup.base / 'packages'
    extract.mkdir()
    args = ['apt-get', '-o', 'Dir::Cache::archives=' + str(cache),
            '-o', 'Dir::State::extended_states=' + str(cache / 'extended_states'),
            '-o', 'Dir::Cache::pkgcache=' + str(cache / 'pkgcache.bin'),
            '-o', 'Dir::Cache::srcpkgcache=' + str(cache / 'srcpkgcache.bin'),
            '-o', 'Dir::Log=' + str(cache / 'log'),
            '-o', 'Dir::Log::History=history.log', '-o', 'Dir::Log::Terminal=terminal.log',
            '-o', 'APT::Sandbox::User=' + str(os.getuid()),
            '-o', 'Acquire::Retries=0', '-o', 'Acquire::http::Timeout=30',
            '-o', 'Acquire::https::Timeout=30', '--download-only', '--reinstall',
            '--no-install-recommends', '-y', 'install',
            'qemu-system-x86', 'qemu-system-common', 'busybox-static']
    # Print-URIs resolves the ordinary dependency set without downloading it.
    raw = setup.run(['sudo', '-n', *args[:1], '--print-uris', *args[1:]])
    planned = []
    for line in raw.splitlines():
        if not line.startswith("'"):
            continue
        fields = shlex.split(line)
        if len(fields) < 3 or not official_uri(fields[0]):
            raise RuntimeError('APT selected an unapproved archive URI: ' + line)
        planned.append({'uri': fields[0], 'filename': fields[1], 'size': int(fields[2])})
    if not planned:
        raise RuntimeError('APT produced no download plan')
    if sum(item['size'] for item in planned) > 200_000_000:
        raise RuntimeError('APT download plan exceeds 200MB admission')
    setup.check(sum(item['size'] for item in planned) * 3 + 100_000_000)
    setup.manifest['apt_download_plan'] = planned
    setup.run(['apt-cache', 'policy', 'qemu-system-x86', 'qemu-system-common', 'busybox-static'])
    setup.run(['apt-get', 'indextargets'])
    releases = setup.base / 'signed-indexes'
    releases.mkdir()
    for path in sorted(Path('/var/lib/apt/lists').glob('*InRelease')):
        shutil.copyfile(path, releases / path.name)
    if not any(releases.iterdir()):
        raise RuntimeError('no Ubuntu signed InRelease indexes retained')
    setup.run(['sudo', '-n', *args], timeout=300)
    expected = {item['filename']: item for item in planned}
    actual = sorted(cache.glob('*.deb'))
    if {p.name for p in actual} != set(expected):
        raise RuntimeError('APT archive set differs from admitted plan')
    records = []
    setup.package_links = extract
    for path in actual:
        identity = setup.run(['dpkg-deb', '-f', str(path), 'Package', 'Version', 'Architecture', 'Installed-Size'])
        values = dict(line.split(': ', 1) for line in identity.splitlines() if ': ' in line)
        package = values['Package']
        version = values['Version']
        metadata = package_stanza(setup.run(['apt-cache', 'show', package + '=' + version]), version)
        if path.stat().st_size != int(metadata['Size']) or digest(path) != metadata['SHA256']:
            raise RuntimeError('APT archive does not match signed-index size/SHA256: ' + path.name)
        if path.stat().st_size != expected[path.name]['size']:
            raise RuntimeError('APT archive size differs from admitted plan')
        expanded = int(values['Installed-Size']) * 1024
        setup.check(expanded + 4_000_000)
        records.append({**values, 'archive': path.name, 'bytes': path.stat().st_size,
                        'sha256': digest(path), 'signed_index': metadata})
        # Trusted official .deb payload only; no maintainer scripts are executed.
        setup.run(['dpkg-deb', '-x', str(path), str(extract)])
    # Package payloads include legitimate symlinks; turn them into owned regular
    # files so inventory never skips an attributable allocation or follows outside.
    link_records = []
    def failed(error):
        raise error
    for parent, dirs, files in os.walk(extract, followlinks=False, onerror=failed):
        for name in dirs + files:
            path = Path(parent) / name
            if path.is_symlink():
                target = os.readlink(path)
                resolved = (extract / target.lstrip('/')) if target.startswith('/') else path.parent / target
                resolved = resolved.resolve()
                if not resolved.is_relative_to(extract) or not resolved.is_file():
                    relative = path.relative_to(extract).as_posix()
                    if not relative.startswith(('usr/share/doc/', 'usr/share/man/')):
                        raise RuntimeError('unresolved required package link: ' + relative)
                    link_records.append({'path': relative, 'target': target,
                                         'action': 'removed optional documentation link; original target retained'})
                    path.unlink()
                    if name in dirs: dirs.remove(name)
                    continue
                setup.check(resolved.stat().st_size)
                data = resolved.read_bytes()
                mode = resolved.stat().st_mode & 0o777
                link_records.append({'path': path.relative_to(extract).as_posix(), 'target': target,
                                     'action': 'materialized exact target bytes', 'bytes': len(data),
                                     'sha256': hashlib.sha256(data).hexdigest()})
                path.unlink()
                path.write_bytes(data)
                path.chmod(mode)
    setup.package_links = None
    setup.check()
    setup.manifest['packages'] = records
    setup.manifest['package_link_materialization'] = link_records
    setup.save()
    return extract


def copy_runtime(setup, root, path, identities):
    path = Path(path)
    if not path.is_file():
        raise RuntimeError('required trusted host runtime is missing: ' + str(path))
    target = root / path.as_posix().lstrip('/')
    if target.exists():
        return
    setup.check(path.stat().st_size)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, target)
    target.chmod(path.stat().st_mode & 0o777)
    identities[str(path)] = {'sha256': digest(path), 'bytes': path.stat().st_size,
                             'resolved_host_path': str(path.resolve())}


def admitted_copy(setup, source, target, *, executable=False):
    setup.check(Path(source).stat().st_size + 4096)
    shutil.copyfile(source, target)
    Path(target).chmod(0o755 if executable else Path(source).stat().st_mode & 0o777)


def admitted_bytes(setup, target, data):
    setup.check(len(data) + 4096)
    Path(target).write_bytes(data)


def shared_libraries(setup, root, binary, identities, env=None):
    result = setup.run(['ldd', str(binary)], env=env, check=False)
    if 'not found' in result:
        raise RuntimeError('required dynamic runtime dependency not found: ' + str(binary))
    for line in result.splitlines():
        found = re.search(r'(?:=>\s*)?(/[^\s]+)', line)
        if found:
            copy_runtime(setup, root, found.group(1), identities)


def newc(entries):
    output = bytearray()
    for number, (name, data, mode) in enumerate([*entries, ('TRAILER!!!', b'', 0)]):
        raw = name.encode() + b'\0'
        fields = [number + 1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(raw), 0]
        output.extend(('070701' + ''.join(f'{value:08x}' for value in fields)).encode())
        output.extend(raw)
        output.extend(b'\0' * (-len(output) % 4))
        output.extend(data)
        output.extend(b'\0' * (-len(output) % 4))
    return bytes(output)


INIT = r'''#!/bin/busybox sh
set -eu
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs -o size=1048576 devtmpfs /dev
MODULES
/bin/busybox mount -t 9p -o trans=virtio,version=9p2000.L,cache=loose,ro rootfs /newroot
/bin/busybox mount -t proc -o nosuid,nodev,noexec proc /newroot/proc
/bin/busybox mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /newroot/sys
/bin/busybox mount -t devtmpfs -o size=1048576,nosuid devtmpfs /newroot/dev
/bin/busybox mount -t tmpfs -o size=16777216,mode=1777,nosuid,nodev tmpfs /newroot/tmp
/bin/busybox mount -t tmpfs -o size=1048576,mode=0755,nosuid,nodev tmpfs /newroot/run
/bin/busybox mount -t 9p -o trans=virtio,version=9p2000.L,cache=mmap,rw project /newroot/project
/bin/busybox mount -t 9p -o trans=virtio,version=9p2000.L,ro owned /newroot/owned
exec /bin/busybox switch_root /newroot /usr/bin/python3 /opt/guest.py
'''

GUEST = r'''import hashlib,json,os,pathlib,platform,subprocess,sys,time,traceback
root=pathlib.Path('/project');config=json.loads(pathlib.Path('/opt/config.json').read_text())
result={'schema_version':1,'source':config['source'],'status':'FAIL','mode':config['mode'],
        'reference_host_verified':False,'scope':'Actual KVM guest geometry and commands; no release claim'}
code=1
try:
    os.setgroups([]);os.setgid(config['gid']);os.setuid(config['uid'])
    os.chdir(root)
    env={'PATH':'/usr/bin:/bin:/opt/go/bin','HOME':'/tmp','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1',
         'PYTHONPYCACHEPREFIX':'/tmp/pycache','GOTOOLCHAIN':'local','GOROOT':'/opt/go',
         'FQ_CPUS':'4','FQ_WORKSPACE_ROOT':'/owned','GOMAXPROCS':'4','TMPDIR':'/project/.cache/tmp'}
    os.environ.clear();os.environ.update(env)
    sys.path.insert(0,str(root/'scripts'))
    from common import source_hash
    from benchmark_support import host_metadata
    if source_hash()!=config['source']:raise RuntimeError('guest source differs from host preboot source')
    mem=pathlib.Path('/proc/meminfo').read_text();cpu=pathlib.Path('/proc/cpuinfo').read_text()
    mountinfo=pathlib.Path('/proc/mounts').read_text()
    result.update(host=host_metadata(),proc_meminfo=mem,proc_cpuinfo=cpu,proc_mounts=mountinfo,
                  proc_cmdline=pathlib.Path('/proc/cmdline').read_text(),uid=os.getuid(),gid=os.getgid())
    # Linux reserves firmware/kernel/initramfs pages, so MemTotal is less than
    # QEMU's exact configured 8,000,000,000 bytes. Bound the observed discrepancy.
    total=int(next(line.split()[1] for line in mem.splitlines() if line.startswith('MemTotal:')))*1024
    if os.cpu_count()!=4 or not 7_500_000_000<=total<=8_000_000_000:raise RuntimeError('guest CPU/RAM geometry mismatch')
    rootline=next(line.split() for line in mountinfo.splitlines() if line.split()[1]=='/')
    if rootline[2]!='9p' or 'ro' not in rootline[3].split(','):raise RuntimeError('guest root is not read-only 9p')
    ram_backed=[]
    for line in mountinfo.splitlines():
        fields=line.split()
        if fields[2] in ('tmpfs','devtmpfs'):
            size=next((part[5:] for part in fields[3].split(',') if part.startswith('size=')),None)
            if size is None:raise RuntimeError('unbounded guest writable RAM filesystem')
            suffix=size[-1].lower(); multiplier={'k':1024,'m':1024**2,'g':1024**3}.get(suffix,1)
            count=int(size[:-1] if multiplier!=1 else size)*multiplier
            ram_backed.append({'mount':fields[1],'bytes':count})
    if sum(item['bytes'] for item in ram_backed)>33554432:raise RuntimeError('guest RAM-backed filesystem budget exceeded')
    result['ram_backed_filesystems']=ram_backed
    versions={}
    for name,command in [('python',[sys.executable,'--version']),('go',['go','version']),('git',['git','--version'])]:
        p=subprocess.run(command,text=True,capture_output=True,timeout=30)
        versions[name]={'command':command,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
        if p.returncode:raise RuntimeError('guest tool version failed: '+name)
    result['versions']=versions
    # Exercise the actual writable share before accepting its evidence stream.
    control=root/'.local/reference-guest-io.bin'
    with control.open('xb') as stream:
        stream.write(b'facetquarry-9p-');stream.flush();os.fsync(stream.fileno())
    with control.open('ab') as stream:
        stream.write(b'append-fsync\n');stream.flush();os.fsync(stream.fileno())
    if control.read_bytes()!=b'facetquarry-9p-append-fsync\n':raise RuntimeError('guest share append/readback differs')
    result['io_control_sha256']=hashlib.sha256(control.read_bytes()).hexdigest()
    if config['mode']=='smoke':
        command=['python3','scripts/evidence.py','--category','kvm-environment-smoke','--timeout','60','--',
                 'python3','-c','import os,platform; print(platform.platform()); print("logical_cpus",os.cpu_count())']
    else:
        command=['python3','scripts/evidence.py','--category','kvm-reference-benchmark','--requirements','AC-016,AC-017',
                 '--timeout',str(config['command_timeout']),'--','python3','scripts/benchmark.py','--profile',config['profile'],
                 '--concurrency',str(config['concurrency'])]
    result['command']=command
    p=subprocess.run(command,env=env,timeout=config['command_timeout']+15)
    result['command_exit_code']=p.returncode
    if source_hash()!=config['source']:raise RuntimeError('guest source changed')
    if p.returncode:raise RuntimeError('guest evidenced workload failed')
    result['status']='PASS';result['reference_host_verified']=True;code=0
except BaseException as failure:
    result['error']=str(failure);result['traceback']=traceback.format_exc()
finally:
    result['exit_code']=code
    try:
        path=root/'.local/reference-guest-result.json';path.write_text(json.dumps(result,indent=2)+'\n')
        with path.open('rb') as stream:os.fsync(stream.fileno())
        os.sync()
    finally:
        # init retains no host privilege; reset guest uid before using the
        # reboot syscall is impossible after dropping uid. PID1 exits, causing
        # a guest panic. QEMU -no-reboot plus panic=1 makes termination finite.
        print('FACETQUARRY_GUEST_RESULT '+json.dumps({'status':result['status'],'exit_code':code}),flush=True)
        os._exit(code)
'''


def runtime(setup, extract):
    root = setup.base / 'rootfs'
    root.mkdir()
    for name in ('proc', 'sys', 'dev', 'tmp', 'run', 'project', 'owned', 'opt/go/bin', 'usr/bin', 'bin'):
        (root / name).mkdir(parents=True, exist_ok=True)
    identities = {}
    python = Path(sys.executable).resolve()
    copy_runtime(setup, root, python, identities)
    # Keep the exact invocation path expected by evidence.py.
    admitted_copy(setup, python, root / 'usr/bin/python3', executable=True)
    shared_libraries(setup, root, python, identities)
    version = f'python{sys.version_info.major}.{sys.version_info.minor}'
    stdlib = Path('/usr/lib') / version
    if not stdlib.is_dir():
        raise RuntimeError('only Ubuntu system Python is supported')
    for parent, dirs, files in os.walk(stdlib, followlinks=False):
        dirs[:] = [name for name in dirs if name not in {'__pycache__', 'test', 'tests', 'ensurepip', 'idlelib', 'tkinter'}]
        for name in files:
            src = Path(parent) / name
            if src.suffix in {'.pyc', '.pyo'}:
                continue
            copy_runtime(setup, root, src, identities)
            if src.suffix == '.so':
                shared_libraries(setup, root, src, identities)
    git = Path(shutil.which('git') or '/missing/git').resolve()
    copy_runtime(setup, root, git, identities)
    if git != Path('/usr/bin/git'):
        admitted_copy(setup, git, root / 'usr/bin/git', executable=True)
    shared_libraries(setup, root, git, identities)
    go = Path(shutil.which('go') or '/missing/go').resolve()
    goroot = Path(setup.run([str(go), 'env', 'GOROOT']).strip())
    if not go.is_relative_to(setup.args.volume) or not goroot.is_relative_to(setup.args.volume):
        raise RuntimeError('pinned Go executable/GOROOT must already be inside the owned volume')
    admitted_copy(setup, go, root / 'opt/go/bin/go', executable=True)
    admitted_copy(setup, goroot / 'VERSION', root / 'opt/go/VERSION')
    identities[str(go)] = {'sha256': digest(go), 'bytes': go.stat().st_size}
    admitted_bytes(setup, root / 'opt/guest.py', GUEST.encode())
    config = {'source': source_hash(setup.args.project), 'uid': os.getuid(), 'gid': os.getgid(),
              'mode': setup.args.mode, 'profile': setup.args.profile, 'concurrency': setup.args.concurrency,
              'command_timeout': setup.args.timeout - 120}
    admitted_bytes(setup, root / 'opt/config.json', (json.dumps(config, indent=2)+'\n').encode())
    setup.manifest['trusted_host_runtime_files'] = identities
    setup.manifest['host_installed_package_versions'] = setup.run(['dpkg-query', '-W', '-f', '${Package}\t${Version}\t${Architecture}\n'])
    setup.save()
    return root


def kernel_initrd(setup, extract):
    release = platform.release()
    kernel = setup.base / 'vmlinuz'
    kernel_bytes = int(setup.run(['sudo', '-n', 'stat', '-c', '%s', '/boot/vmlinuz-' + release]).strip())
    if not 0 < kernel_bytes < 100_000_000:
        raise RuntimeError('host kernel exceeds admission')
    setup.check(kernel_bytes)
    setup.run(['sudo', '-n', 'cp', '--', '/boot/vmlinuz-' + release, str(kernel)])
    setup.run(['sudo', '-n', 'chown', str(os.getuid()) + ':' + str(os.getgid()), str(kernel)])
    config = setup.run(['sudo', '-n', 'cat', '/boot/config-' + release])
    (setup.base / 'kernel-config.txt').write_text(config)
    entries = [(name, b'', stat.S_IFDIR | 0o755) for name in ('bin', 'dev', 'proc', 'sys', 'newroot', 'modules')]
    busybox = extract / 'bin/busybox'
    if not busybox.is_file():
        busybox = extract / 'usr/bin/busybox'
    entries.append(('bin/busybox', busybox.read_bytes(), stat.S_IFREG | 0o755))
    paths = []
    module_records = []
    for module in ('virtio_pci', '9pnet_virtio', '9p'):
        raw = setup.run(['modprobe', '--set-version', release, '--show-depends', module])
        for line in raw.splitlines():
            if line.startswith('insmod '):
                path = Path(shlex.split(line)[1])
                if path not in paths:
                    paths.append(path)
            elif line and not line.startswith('builtin '):
                raise RuntimeError('unexpected module dependency declaration: ' + line)
    for number, path in enumerate(paths):
        raw = path.read_bytes()
        if path.suffix == '.zst':
            raw = subprocess.run(['zstd', '-dc', str(path)], capture_output=True, check=True, timeout=30).stdout
        elif path.suffix == '.xz':
            raw = lzma.decompress(raw)
        elif path.suffix == '.gz':
            raw = gzip.decompress(raw)
        name = f'modules/{number:03d}.ko'
        entries.append((name, raw, stat.S_IFREG | 0o644))
        module_records.append({'host_path': str(path), 'host_sha256': digest(path),
                               'uncompressed_bytes': len(raw), 'guest_path': '/' + name})
    commands = '\n'.join('/bin/busybox insmod ' + item['guest_path'] for item in module_records)
    entries.append(('init', INIT.replace('MODULES', commands).encode(), stat.S_IFREG | 0o755))
    raw = newc(entries)
    if len(raw) > INITRD_MAX:
        raise RuntimeError('initrd exceeds admitted uncompressed RAM allocation')
    setup.check(len(raw) + kernel.stat().st_size)
    initrd = setup.base / 'initrd.cpio.gz'
    initrd.write_bytes(gzip.compress(raw, mtime=0))
    setup.manifest.update(host_kernel_release=release, kernel_sha256=digest(kernel),
                          initrd_sha256=digest(initrd), initrd_uncompressed_bytes=len(raw), kernel_modules=module_records)
    setup.save()
    return kernel, initrd


def boot(setup, extract, root, kernel, initrd):
    qemu = extract / 'usr/bin/qemu-system-x86_64'
    libdirs = sorted({str(path.parent) for path in extract.rglob('*.so*') if path.is_file()})
    env_args = ['env', '-i', 'PATH=/usr/bin:/bin', 'LANG=C', 'LD_LIBRARY_PATH=' + ':'.join(libdirs),
                'QEMU_MODULE_DIR=' + str(extract / 'usr/lib/x86_64-linux-gnu/qemu')]
    setup.manifest['qemu_version'] = setup.run([*env_args, str(qemu), '--version'])
    command = ['sudo', '-n', *env_args, str(qemu), '-accel', 'kvm', '-machine', 'q35',
               '-cpu', 'host', '-smp', '4,sockets=1,cores=4,threads=1', '-m', '7812500K',
               '-nodefaults', '-no-user-config', '-display', 'none', '-monitor', 'none',
               '-serial', 'stdio', '-nic', 'none', '-no-reboot', '-kernel', str(kernel),
               '-initrd', str(initrd), '-append', 'console=ttyS0 rdinit=/init panic=1 oops=panic quiet',
               '-L', str(extract / 'usr/share/qemu')]
    bios = extract / 'usr/share/seabios/bios-256k.bin'
    if bios.is_file():
        command += ['-bios', str(bios)]
    for tag, path, readonly in [('rootfs', root, True), ('project', setup.args.project, False), ('owned', setup.args.volume, True)]:
        # Reject commas so the path cannot inject QEMU fsdev suboptions.
        if ',' in str(path):
            raise RuntimeError('QEMU share paths cannot contain commas')
        command += ['-fsdev', f'local,id={tag},path={path},security_model=none' + (',readonly=on' if readonly else ''),
                    '-device', f'virtio-9p-pci,fsdev={tag},mount_tag={tag}']
    result_path = setup.args.project / '.local/reference-guest-result.json'
    if result_path.exists():
        raise RuntimeError('refusing to overwrite previous guest result')
    setup.manifest['qemu_command'] = command
    setup.manifest['setup_allocated_bytes_before_boot'] = setup.check()
    setup.manifest['status'] = 'BOOTING'
    setup.save()
    setup.run(command, timeout=setup.args.timeout, check=False)
    if not result_path.is_file():
        raise RuntimeError('no guest result; QEMU exit alone does not prove success')
    result = json.loads(result_path.read_text())
    if result.get('source') != setup.manifest['source'] or result.get('exit_code') != 0 or result.get('status') != 'PASS':
        raise RuntimeError('actual guest reported failure or stale source')
    if source_hash(setup.args.project) != setup.manifest['source']:
        raise RuntimeError('host source changed during guest execution')
    control = setup.args.project / '.local/reference-guest-io.bin'
    if control.read_bytes() != b'facetquarry-9p-append-fsync\n' or digest(control) != result.get('io_control_sha256'):
        raise RuntimeError('host/guest append/fsync evidence differs')
    last = setup.records[-1]
    if last.get('termination_reason') or last.get('exit_code') != 0:
        raise RuntimeError('QEMU terminated abnormally; preserve guest and host evidence')
    setup.manifest.update(status='PASS', reference_host_verified=True, guest_result_sha256=digest(result_path),
                          scope='actual 4-vCPU/8GB KVM boot and requested commands; smoke never qualifies benchmarks')
    setup.save()
    print(json.dumps(setup.manifest, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volume', required=True, type=Path)
    parser.add_argument('--project', required=True, type=Path)
    parser.add_argument('--mode', choices=('smoke', 'benchmark'), default='smoke')
    parser.add_argument('--profile', choices=('smoke', 'full'), default='full')
    parser.add_argument('--concurrency', choices=(1, 4, 16), type=int, default=1)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--setup-max-bytes', type=int, default=800_000_000)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.getuid() == 0:
        parser.error('requires an ordinary Linux x86_64 runner user with existing sudo -n')
    args.volume = args.volume.resolve(strict=True)
    args.project = args.project.resolve(strict=True)
    if not args.project.is_relative_to(args.volume) or args.project == args.volume:
        parser.error('project must be a child of the owned volume')
    if args.project != ROOT or not (args.project / '.local').is_dir():
        parser.error('execute this helper from the supplied project with existing .local')
    if args.timeout < 180 or not 100_000_000 <= args.setup_max_bytes <= 1_000_000_000:
        parser.error('timeout/setup bounds are outside admitted range')
    # Require actual ext4 mountpoint, never fall back to the runner root filesystem.
    mount = subprocess.run(['findmnt', '--json', '--target', str(args.volume), '-o', 'TARGET,FSTYPE,SOURCE'],
                           capture_output=True, text=True, check=True, timeout=10)
    info = json.loads(mount.stdout)['filesystems'][0]
    if Path(info['target']).resolve() != args.volume or info['fstype'] != 'ext4' or not str(info['source']).startswith('/dev/loop'):
        parser.error('volume must be the already-created owned loop-mounted ext4 filesystem')
    setup = Setup(args)
    try:
        setup.manifest['mount'] = info
        setup.run(['sudo', '-n', 'true'])
        setup.run(['uname', '-a'])
        extract = packages(setup)
        root = runtime(setup, extract)
        kernel, initrd = kernel_initrd(setup, extract)
        boot(setup, extract, root, kernel, initrd)
        return 0
    except BaseException as failure:
        setup.manifest.update(status='FAIL', error=type(failure).__name__ + ': ' + str(failure))
        setup.save()
        raise


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise SystemExit('signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())
