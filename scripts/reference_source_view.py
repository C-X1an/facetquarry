"""Explicit, bounded tracked-checkout RAM view. Unit fixtures do not qualify Linux.

The original three QEMU exports remain unchanged. Only this named policy moves
the project mount, copies admitted regular tracked files plus the two native
binaries, and replaces /project with one read-only tmpfs mount. Science output
and cache paths remain narrow binds of the original bounded disk directories.
"""
from __future__ import annotations
import hashlib
from contextlib import contextmanager, ExitStack
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

LEGACY_POLICY = 'legacy'
SOURCE_POLICY = 'reference-tracked-source-tmpfs-v1'
POLICIES = (LEGACY_POLICY, SOURCE_POLICY)
SOURCE_BYTES = 24 * 1024 * 1024
TMP_BYTES = 4 * 1024 * 1024
RAM_BYTES = SOURCE_BYTES + TMP_BYTES + 2 * 1024 * 1024
SOURCE_INODES = 8192
MAX_FILES = 4096
ORIGIN = '/opt/source-origin'
BINDINGS = {'.local': 'rw', '.cache': 'rw', '.git': 'ro'}
BINARIES = ('bin/facetquarry', 'bin/fqbench')


def require(condition, message):
    if not condition:
        raise ValueError('source view: ' + message)


def policy(value=LEGACY_POLICY):
    require(value in POLICIES, 'unknown policy')
    return value


def canonical(name):
    require(isinstance(name, str) and 0 < len(name.encode()) <= 4096
            and not any(ord(c) < 32 or ord(c) == 127 or c in '\\:' for c in name), 'unsafe path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name
            and all(p not in ('', '.', '..') and len(p.encode()) <= 255 for p in name.split('/')),
            'noncanonical path')
    require(path.parts[0] not in ('.local', '.cache', '.git', '__pycache__')
            and (path.parts[0] != 'bin' or name in BINARIES), 'reserved path')
    return name


def git(root, *args):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS='0', GIT_CONFIG_NOSYSTEM='1')
    # Staging is UID0 over the ordinary account's checkout. Trust this exact
    # owned path, never a wildcard safe.directory or a persistent global edit.
    return subprocess.run(['/usr/bin/git' if os.name != 'nt' else 'git', '-c', 'safe.directory=' + str(root),
                           '-C', str(root), *args],
                          env=env, capture_output=True, check=True, timeout=30).stdout


def tracked(root):
    raw = git(root, 'ls-files', '--stage', '-z')
    require(0 < len(raw) <= 2 * 1024 * 1024, 'tracked index size outside bound')
    entries = {}
    for item in raw.split(b'\0')[:-1]:
        header, name = item.split(b'\t', 1)
        mode, oid, stage = header.decode('ascii').split()
        name = canonical(name.decode('utf-8'))
        require(mode in ('100644', '100755') and stage == '0'
                and re.fullmatch('[0-9a-f]{40,64}', oid) is not None
                and name not in entries and name not in BINARIES, 'unsupported/duplicate tracked entry')
        entries[name] = int(mode[-3:], 8)
    require(raw.endswith(b'\0') and 0 < len(entries) <= MAX_FILES - 2, 'incomplete tracked index')
    return entries


def directory(path, uid, gid):
    s = path.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == uid and s.st_gid == gid
            and not s.st_mode & 0o022, 'directory type/owner/mode differs: ' + str(path))
    return s


def fingerprint(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_uid,
            s.st_gid, s.st_mode, s.st_nlink, getattr(s, 'st_blocks', 0)]


@contextmanager
def opened_file(root, name, uid, gid):
    """Resolve every component without following links; recheck path identities."""
    canonical(name)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    require(hasattr(os, 'O_DIRECTORY') and os.open in os.supports_dir_fd,
            'native no-follow directory descriptors unavailable')
    with ExitStack() as cleanup:
        parent = root
        observed = []
        fd = os.open(root, flags | os.O_DIRECTORY)
        cleanup.callback(os.close, fd)
        original = directory(parent, uid, gid)
        require(fingerprint(os.fstat(fd)) == fingerprint(original), 'root directory changed while opening')
        observed.append((parent, fingerprint(original)))
        for component in PurePosixPath(name).parts[:-1]:
            child = os.open(component, flags | os.O_DIRECTORY, dir_fd=fd)
            cleanup.callback(os.close, child)
            parent /= component
            original = directory(parent, uid, gid)
            require(fingerprint(os.fstat(child)) == fingerprint(original), 'parent directory changed while opening')
            observed.append((parent, fingerprint(original)))
            fd = child
        leaf = PurePosixPath(name).name
        named = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISREG(named.st_mode), 'nonregular source entry: ' + name)
        file_fd = os.open(leaf, flags | getattr(os, 'O_NONBLOCK', 0), dir_fd=fd)
        stream = cleanup.enter_context(os.fdopen(file_fd, 'rb'))
        before = os.fstat(stream.fileno())
        require(fingerprint(before) == fingerprint(named), 'file changed while opening')
        require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and before.st_gid == gid
                and not before.st_mode & 0o022 and before.st_nlink == 1
                and stat.S_IMODE(before.st_mode) in (0o644, 0o755)
                and 0 <= before.st_size <= SOURCE_BYTES, 'file type/owner/mode/size differs: ' + name)
        require(fingerprint((root / name).lstat()) == fingerprint(before), 'opened pathname differs')
        yield stream, before
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before)
                and fingerprint((root / name).lstat()) == fingerprint(before), 'opened file identity changed')
        require(all(fingerprint(path.lstat()) == original for path, original in observed),
                'source directory changed during read')


def inspect_file(root, item, uid, gid):
    name = canonical(item['path'])
    h = hashlib.sha256()
    count = 0
    with opened_file(root, name, uid, gid) as (stream, before):
        require(before.st_size == item['bytes'] and stat.S_IMODE(before.st_mode) == item['mode'],
                'file size/mode differs: ' + name)
        header = stream.read(4)
        h.update(header); count += len(header)
        while block := stream.read(1024 * 1024):
            count += len(block)
            require(count <= item['bytes'], 'file grew while reading')
            h.update(block)
    require(count == item['bytes'] and h.hexdigest() == item['sha256'], 'file bytes changed: ' + name)
    if name in BINARIES:
        require(header == b'\x7fELF' and item['mode'] == 0o755, 'native Linux executable required')
    return {'path': name, 'sha256': h.hexdigest(), 'identity': fingerprint(before)}


def manifest_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_manifest(value, source, execution_id, context, uid, gid):
    require(isinstance(value, dict) and set(value) == {'schema_version', 'policy', 'source',
            'execution_id', 'run_context', 'uid', 'gid', 'files', 'tracked_count', 'tracked_index_sha256'},
            'manifest fields differ')
    require(value['schema_version'] == 1 and value['policy'] == SOURCE_POLICY
            and value['source'] == source and re.fullmatch('[0-9a-f]{64}', source) is not None
            and value['execution_id'] == execution_id and re.fullmatch('[0-9a-f]{32}', execution_id) is not None
            and value['run_context'] == context and value['uid'] == uid and value['gid'] == gid
            and type(uid) is int and uid > 0 and type(gid) is int and gid > 0, 'manifest execution binding differs')
    files = value['files']
    require(isinstance(files, list) and 2 < len(files) <= MAX_FILES
            and type(value['tracked_count']) is int and value['tracked_count'] == len(files) - 2
            and re.fullmatch('[0-9a-f]{64}', value['tracked_index_sha256']) is not None,
            'manifest count/index differs')
    names = []
    for item in files:
        require(isinstance(item, dict) and set(item) == {'path', 'bytes', 'sha256', 'mode'}, 'file fields differ')
        names.append(canonical(item['path']))
        require(type(item['bytes']) is int and 0 <= item['bytes'] <= SOURCE_BYTES
                and type(item['mode']) is int and item['mode'] in (0o644, 0o755)
                and re.fullmatch('[0-9a-f]{64}', item['sha256']) is not None, 'file admission differs')
        require(item['path'] not in BINARIES or item['mode'] == 0o755, 'binary is not executable')
    require(names == sorted(set(names)) and set(BINARIES).issubset(names)
            and sum(x['bytes'] for x in files) <= SOURCE_BYTES, 'duplicate/oversize/incomplete files')
    tracked_map = {item['path']: item['mode'] for item in files if item['path'] not in BINARIES}
    require(value['tracked_index_sha256'] == manifest_digest(tracked_map), 'tracked selection digest differs')
    directories = {'.local', '.cache', '.git'}
    for name in names:
        directories.update(p.as_posix() for p in PurePosixPath(name).parents if p.as_posix() != '.')
    require(not set(names) & directories and len(files) + len(directories) + 1 < SOURCE_INODES,
            'file/directory collision or inode bound')
    return directories


def create_manifest(root, source, execution_id, context, uid, gid):
    paths = tracked(root)
    require(git(root, 'status', '--porcelain') == b'', 'original checkout dirty')
    files = []
    for name in sorted([*paths, *BINARIES]):
        with opened_file(root, name, uid, gid) as (stream, s):
            data = stream.read(s.st_size + 1)
            require(len(data) == s.st_size, 'manifest source changed')
        item = {'path': name, 'bytes': s.st_size, 'mode': paths.get(name, 0o755),
                'sha256': hashlib.sha256(data).hexdigest()}
        inspect_file(root, item, uid, gid)
        files.append(item)
    value = {'schema_version': 1, 'policy': SOURCE_POLICY, 'source': source,
             'execution_id': execution_id, 'run_context': context, 'uid': uid, 'gid': gid,
             'files': files, 'tracked_count': len(paths),
             'tracked_index_sha256': manifest_digest(paths)}
    validate_manifest(value, source, execution_id, context, uid, gid)
    return value


def source_identity(root):
    # A distinct module name avoids caching common.ROOT at the temporary origin.
    spec = importlib.util.spec_from_file_location('_fq_source_view_common', root / 'scripts/common.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.source_hash(root)


def capacity(path):
    s = os.statvfs(path)
    return {'bytes': s.f_frsize * s.f_blocks, 'free_bytes': s.f_frsize * s.f_bavail,
            'block_bytes': s.f_frsize, 'inodes': s.f_files, 'free_inodes': s.f_favail}


def admit(manifest, directories, facts):
    require(all(type(facts.get(k)) is int and facts[k] > 0 for k in
                ('bytes', 'free_bytes', 'block_bytes', 'inodes', 'free_inodes'))
            and facts['bytes'] == SOURCE_BYTES and facts['inodes'] == SOURCE_INODES,
            'actual source tmpfs capacity differs')
    block = facts['block_bytes']
    needed = sum(((x['bytes'] + block - 1) // block) * block for x in manifest['files'])
    needed += (len(directories) + 1) * block  # Conservative directory/page admission.
    inodes = len(manifest['files']) + len(directories) + 1
    require(needed <= facts['free_bytes'] and inodes < facts['free_inodes'], 'actual block/inode admission exceeded')
    return {'needed_bytes': needed, 'needed_inodes': inodes}


def mounts(raw=None):
    rows = []
    for line in (raw if raw is not None else Path('/proc/self/mountinfo').read_text()).splitlines():
        left, right = line.split(' - ', 1)
        a, b = left.split(), right.split()
        require(len(a) >= 6 and len(b) == 3 and not any('\\' in x for x in (a[3], a[4])), 'unsupported mount path')
        rows.append({'device': a[2], 'root': a[3], 'mount': a[4], 'options': a[5].split(','),
                     'fstype': b[0], 'source': b[1], 'super_options': b[2].split(',')})
    return rows


def validate_mounts(rows):
    def one(path):
        values = [x for x in rows if x['mount'] == path]
        require(len(values) == 1, 'missing/duplicate mount: ' + path)
        return values[0]
    src = one('/project')
    require(src['fstype'] == 'tmpfs' and 'ro' in src['options']
            and {'nosuid', 'nodev'} <= set(src['options']), 'source is not read-only bounded tmpfs')
    require([x['mount'] for x in rows if x['device'] == src['device']] == ['/project'], 'source tmpfs alias')
    origin = one(ORIGIN)
    require(origin['fstype'] == '9p' and 'ro' in origin['options']
            and origin['source'] == 'project' and origin['root'] == '/',
            'original source is not the read-only complete project export')
    for name, access in BINDINGS.items():
        row = one('/project/' + name)
        require(row['fstype'] == '9p' and row['device'] == origin['device'] and row['source'] == 'project'
                and row['root'] == origin['root'].rstrip('/') + '/' + name
                and access in row['options'], 'disk binding differs: ' + name)
    allowed = {'/project', *('/project/' + name for name in BINDINGS)}
    require(all(x['mount'] in allowed for x in rows if x['mount'].startswith('/project/')),
            'unexpected project submount')
    require(all(x['mount'] in {'/project/.local', '/project/.cache'} for x in rows
                if x['fstype'] == '9p' and x['source'] == origin['source'] and 'rw' in x['options']),
            'unexpected writable original-source alias')
    return True


def stage(config):
    require(policy(config['source_policy']) == SOURCE_POLICY and os.getuid() == 0, 'staging requires explicit policy and UID0')
    value = config['source_view_manifest']
    uid, gid = config['uid'], config['gid']
    dirs = validate_manifest(value, config['source'], config['execution_id'], config['run_context'], uid, gid)
    root, origin = Path('/project'), Path(ORIGIN)
    mount = lambda *args: subprocess.run(['/bin/busybox', 'mount', *args], check=True, timeout=15,
                                        capture_output=True)
    mount('--move', str(root), str(origin))
    paths = tracked(origin)
    require(manifest_digest(paths) == value['tracked_index_sha256']
            and set(paths) == {x['path'] for x in value['files']} - set(BINARIES), 'tracked checkout differs')
    for name in BINDINGS:
        directory(origin / name, uid, gid)
    before = [inspect_file(origin, item, uid, gid) for item in value['files']]
    require(source_identity(origin) == config['source'] and git(origin, 'status', '--porcelain') == b'', 'original provenance differs')
    mount('-t', 'tmpfs', '-o', f'size={SOURCE_BYTES},nr_inodes={SOURCE_INODES},mode=0755,nosuid,nodev',
          'fq-tracked-source', str(root))
    os.chown(root, uid, gid)
    fs_before = capacity(root)
    admitted = admit(value, dirs, fs_before)
    for name in sorted(dirs, key=lambda x: (x.count('/'), x)):
        p = root / name
        p.mkdir(mode=0o755); os.chown(p, uid, gid)
    for item in value['files']:
        src, dst = origin / item['path'], root / item['path']
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(src, flags), 'rb') as source, dst.open('xb') as target:
            count = 0
            while block := source.read(1024 * 1024):
                count += len(block)
                require(count <= item['bytes'], 'copy exceeded admitted bytes')
                target.write(block)
            require(count == item['bytes'], 'short source copy')
        dst.chmod(item['mode']); os.chown(dst, uid, gid)
    copied = [inspect_file(root, item, uid, gid) for item in value['files']]
    after = [inspect_file(origin, item, uid, gid) for item in value['files']]
    require(before == after and source_identity(root) == source_identity(origin) == config['source'], 'source/copy identity changed')
    bindings = []
    for name, access in BINDINGS.items():
        src, dst = origin / name, root / name
        mount('--bind', str(src), str(dst))
        if access == 'ro':
            mount('-o', 'remount,bind,ro', str(dst))
        a, b = src.stat(), dst.stat()
        require((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'bound disk inode differs')
        bindings.append({'name': name, 'access': access, 'same_inode': True,
                         'uid': b.st_uid, 'gid': b.st_gid})
    mount('-o', 'remount,bind,ro', str(origin))
    mount('-o', 'remount,ro', str(root))
    rows = mounts()
    validate_mounts(rows)
    require(source_identity(root) == config['source'] and git(root, 'status', '--porcelain') == b''
            and git(root, 'rev-parse', 'HEAD').decode().strip() == config['run_context']['commit'], 'copied Git/source provenance differs')
    readonly_copied = [inspect_file(root, item, uid, gid) for item in value['files']]
    require(copied == readonly_copied, 'copy changed at read-only transition')
    return {'schema_version': 1, 'policy': SOURCE_POLICY, 'source': config['source'],
            'execution_id': config['execution_id'], 'run_context': config['run_context'],
            'manifest_sha256': manifest_digest(value), 'staging_uid': os.getuid(),
            'phase_order': ['root_original_verified', 'capacity_admitted', 'copied_verified',
                            'disk_bindings_verified', 'source_remounted_readonly', 'before_uid_drop'],
            'original_before': before, 'original_after': after, 'copied_before': copied,
            'copied_readonly': readonly_copied, 'source_before': config['source'],
            'source_after': source_identity(origin), 'copied_source': source_identity(root),
            'git_status': '', 'commit': config['run_context']['commit'],
            'capacity_before': fs_before, 'admission': admitted, 'capacity_readonly': capacity(root),
            'bindings': bindings, 'mounts': rows,
            'ram_capacities': {name: capacity(name)['bytes'] for name in ('/dev', '/tmp', '/run', '/project')}}


def finish(proof, config):
    value = config['source_view_manifest']
    uid, gid = config['uid'], config['gid']
    proof['original_final'] = [inspect_file(Path(ORIGIN), x, uid, gid) for x in value['files']]
    proof['copied_final'] = [inspect_file(Path('/project'), x, uid, gid) for x in value['files']]
    require(proof['original_final'] == proof['original_before']
            and proof['copied_final'] == proof['copied_before'], 'original/copied files changed during workload')
    proof['final_mounts'] = mounts()
    proof['final_ram_capacities'] = {name: capacity(name)['bytes'] for name in ('/dev', '/tmp', '/run', '/project')}
    validate_mounts(proof['final_mounts'])
    require(source_identity(Path(ORIGIN)) == source_identity(Path('/project')) == config['source']
            and git(Path('/project'), 'status', '--porcelain') == b'', 'final source/Git provenance differs')
    proof['workload_uid'] = os.getuid()
    proof['workload_gid'] = os.getgid()
    proof['status'] = 'PASS'


def validate_proof(setup, guest, source, execution_id, context, provenance=None):
    """Strict new-policy branch; legacy qualification remains a separate path."""
    require(setup.get('source_policy') == guest.get('source_policy') == SOURCE_POLICY, 'policy mismatch')
    uid, gid = guest['uid'], guest['gid']
    value = setup['source_view_manifest']
    dirs = validate_manifest(value, source, execution_id, context, uid, gid)
    p = guest['source_view']
    require(p.get('schema_version') == 1 and p.get('policy') == SOURCE_POLICY and p.get('status') == 'PASS'
            and p.get('source') == source and p.get('execution_id') == execution_id
            and p.get('run_context') == context and p.get('manifest_sha256') == manifest_digest(value)
            and p.get('staging_uid') == 0 and p.get('workload_uid') == uid and p.get('workload_gid') == gid,
            'stage privilege/execution binding differs')
    require(p.get('phase_order') == ['root_original_verified', 'capacity_admitted', 'copied_verified',
            'disk_bindings_verified', 'source_remounted_readonly', 'before_uid_drop'], 'stage order differs')
    require(p.get('source_before') == p.get('source_after') == p.get('copied_source') == source
            and p.get('git_status') == '' and p.get('commit') == context['commit'], 'source/Git proof differs')
    expected = {x['path']: x for x in value['files']}
    if provenance is not None:
        require(provenance.get('source') == source and all(
            provenance.get('binaries', {}).get(name, {}).get('sha256') == expected['bin/' + name]['sha256']
            and provenance['binaries'][name].get('source') == source for name in ('facetquarry', 'fqbench')),
            'native binary provenance differs from staged executable')
    for label in ('original_before', 'original_after', 'original_final', 'copied_before', 'copied_readonly', 'copied_final'):
        values = p[label]
        require(isinstance(values, list) and len(values) == len(expected)
                and [x['path'] for x in values] == sorted(expected), 'copy file set differs')
        for row in values:
            item, s = expected[row['path']], row['identity']
            require(row['sha256'] == item['sha256'] and isinstance(s, list) and len(s) == 10
                    and all(type(x) is int for x in s) and s[2] == item['bytes'] and s[5:7] == [uid, gid]
                    and s[0] >= 0 and s[1] > 0 and s[3] >= 0 and s[4] >= 0
                    and stat.S_ISREG(s[7]) and stat.S_IMODE(s[7]) == item['mode']
                    and s[8] == 1 and s[9] >= 0, 'copy inode/digest differs')
    require(p['original_before'] == p['original_after'] == p['original_final']
            and p['copied_before'] == p['copied_readonly'] == p['copied_final'], 'copy changed over workload')
    require(len({x['identity'][0] for x in p['original_before']}) == 1
            and len({x['identity'][0] for x in p['copied_before']}) == 1
            and p['original_before'][0]['identity'][0] != p['copied_before'][0]['identity'][0],
            'copy is not on a distinct filesystem')
    require(sum(x['identity'][9] * 512 for x in p['copied_before']) <= SOURCE_BYTES,
            'copied file block allocation exceeds source capacity')
    require(p['admission'] == admit(value, dirs, p['capacity_before']), 'block/inode admission proof differs')
    cap = p['capacity_readonly']
    require(cap['bytes'] == SOURCE_BYTES and cap['inodes'] == SOURCE_INODES
            and 0 <= cap['free_bytes'] <= p['capacity_before']['free_bytes']
            and 0 <= cap['free_inodes'] <= p['capacity_before']['free_inodes'], 'actual copied capacity differs')
    require(p['bindings'] == [{'name': name, 'access': access, 'same_inode': True, 'uid': uid, 'gid': gid}
                              for name, access in BINDINGS.items()], 'disk binding identity differs')
    validate_mounts(p['mounts']); validate_mounts(p['final_mounts'])
    ram = guest['ram_backed_filesystems']
    expected_ram = {'/dev': 1048576, '/tmp': TMP_BYTES, '/run': 1048576, '/project': SOURCE_BYTES}
    require(isinstance(ram, list) and len(ram) == 4 and {x['mount']: x['bytes'] for x in ram}
            == expected_ram
            and all(type(x['bytes']) is int for x in ram) and sum(x['bytes'] for x in ram) == RAM_BYTES
            and setup.get('tmpfs_limit_bytes') == RAM_BYTES, 'new-policy RAM mount set/capacity differs')
    require(p.get('ram_capacities') == p.get('final_ram_capacities') == expected_ram,
            'actual RAM filesystem capacity differs')
    for rows in (p['mounts'], p['final_mounts']):
        actual = {x['mount'] for x in rows if x['fstype'] in ('tmpfs', 'devtmpfs')}
        require(actual == {'/dev', '/tmp', '/run', '/project'}, 'unexpected RAM mount/alias')
    require(setup.get('source_view_host_after') == {'manifest_sha256': manifest_digest(value), 'status': 'PASS'},
            'original host post-execution proof missing')
