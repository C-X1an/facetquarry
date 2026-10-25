"""Remove enumerated, regenerable reference-run SDK/cache files after verification.

The production entry point requires an actual owned Linux loop-mounted ext4
volume. This does not preserve a usable native compiler installation. It retains
Go version/build inspection, benchmark binaries, fuzz data, and command evidence.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

from common import ROOT, source_hash

MAX_ENTRIES = 100_000
MAX_FILE_BYTES = 256_000_000
MAX_LOGICAL_BYTES = 4_000_000_000
MAX_MANIFEST_BYTES = 8_000_000  # atomic replacement reserves a second copy
SDK_NAMES = ('src', 'pkg', 'doc', 'test', 'lib')
REQUIRED_CATEGORIES = ('supported-reference-verification', 'clean-supported-reference',
                       'current-reference-online-security')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def descriptor_matches(info, expected):
    actual = stamp(info)
    # Windows exposes different legacy creation/change-time values through
    # fstat and lstat. Preserve every complete pathname stamp check and compare
    # all other descriptor fields, including inode, length, mtime and link count.
    # Production deletion remains Linux-only and retains the full comparison.
    if os.name == 'nt':
        return actual[:5] + actual[6:] == tuple(expected[:5]) + tuple(expected[6:])
    return actual == tuple(expected)


def checked(path, volume=None):
    """Inspect every lexical ancestor without resolving away a link."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'path must be absolute and normalized')
    if volume is not None:
        require(path != volume and path.is_relative_to(volume), 'path escapes owned volume')
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_reparse_tag', 0),
                'linked/reparse owned path: ' + str(part))
        require(stat.S_ISDIR(info.st_mode) or part == path and stat.S_ISREG(info.st_mode),
                'unexpected owned path type: ' + str(part))
    if volume is not None:
        require(info.st_dev == volume.lstat().st_dev, 'owned path crosses filesystem')
    return info


def file_sha(path, expected=None):
    info = checked(path)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'nonregular or hardlinked file')
    require(info.st_size <= MAX_FILE_BYTES, 'file exceeds bounded hashing admission')
    if expected is not None:
        require(stamp(info) == tuple(expected), 'file identity changed before hashing')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    descriptor = os.open(path, flags)
    try:
        require(descriptor_matches(os.fstat(descriptor), stamp(info)), 'file substituted while opening')
        digest = hashlib.sha256()
        count = 0
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            while block := stream.read(1024 * 1024):
                count += len(block)
                require(count <= MAX_FILE_BYTES, 'file grew beyond hashing admission')
                digest.update(block)
        require(count == info.st_size and descriptor_matches(os.fstat(descriptor), stamp(info)),
                'file changed while hashing')
        require(stamp(checked(path)) == stamp(info), 'file pathname substituted while hashing')
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def tree(volume, roots):
    entries = []
    ancestors = {}
    volume_identity = list(stamp(checked(volume)))[:3]
    for root in roots:
        checked(root, volume)
        for parent in root.parents:
            if parent == volume:
                break
            require(parent.is_relative_to(volume), 'tree root escapes volume')
            ancestors[parent.relative_to(volume).as_posix()] = list(stamp(checked(parent, volume)))[:3]
    seen = set()
    logical = 0
    allocated = 0
    stack = list(reversed(roots))
    while stack:
        path = stack.pop()
        info = checked(path, volume)
        key = (info.st_dev, info.st_ino)
        require(key not in seen, 'duplicate owned inode')
        seen.add(key)
        require(len(entries) < MAX_ENTRIES, 'manifest entry admission exceeded')
        item = {'path': path.relative_to(volume).as_posix(), 'identity': list(stamp(info)),
                'kind': 'directory' if stat.S_ISDIR(info.st_mode) else 'file'}
        if item['kind'] == 'file':
            logical += info.st_size
            allocated += max(info.st_size, getattr(info, 'st_blocks', 0) * 512)
            require(logical <= MAX_LOGICAL_BYTES, 'manifest logical byte admission exceeded')
            item.update(bytes=info.st_size, accounted_bytes=max(info.st_size, getattr(info, 'st_blocks', 0) * 512),
                        sha256=file_sha(path, item['identity']))
        else:
            with os.scandir(path) as children:
                names = sorted(child.name for child in children)
            require(len(names) + len(stack) + len(entries) <= MAX_ENTRIES, 'tree entry admission exceeded')
            stack.extend(path / name for name in reversed(names))
        entries.append(item)
    return {'entries': entries, 'ancestors': ancestors, 'volume_identity': volume_identity,
            'logical_bytes': logical, 'accounted_bytes': allocated}


def selected_roots(volume, project):
    checked(project, volume)
    require(project == volume / 'source', 'project is not the owned source checkout')
    sdk = volume / 'tools/go'
    checked(sdk, volume)
    roots = []
    for name in SDK_NAMES:
        path = sdk / name
        try:
            info = checked(path, volume)
        except FileNotFoundError:
            continue
        require(stat.S_ISDIR(info.st_mode), 'SDK trim candidate is not a directory')
        roots.append(path)
    cache = project / '.cache/go-build'
    checked(cache, volume)
    for path in sorted(cache.iterdir()):
        info = checked(path, volume)
        if re.fullmatch('[0-9a-f]{2}', path.name):
            require(stat.S_ISDIR(info.st_mode), 'Go cache shard is not a directory')
            roots.append(path)
        else:
            require(path.name == 'fuzz' and stat.S_ISDIR(info.st_mode)
                    or path.name in ('README', 'trim.txt') and stat.S_ISREG(info.st_mode),
                    'unexpected Go cache top-level entry: ' + path.name)
    return roots


def fuzz_state(volume, project):
    roots = []
    for path in (project / '.cache/go-build/fuzz', project / 'internal/engine/testdata/fuzz'):
        try:
            info = checked(path, volume)
        except FileNotFoundError:
            continue
        require(stat.S_ISDIR(info.st_mode), 'fuzz root is not a directory')
        roots.append(path)
    return tree(volume, roots)


def preserve_fuzz(volume, project):
    """Populate the bounded results copy before measurement can exhaust space."""
    output = project / '.local/reference-fuzz'
    require(not output.exists() and not output.is_symlink(), 'fuzz preservation output already exists')
    checked(output.parent, volume)
    output.mkdir()
    records = []
    for label, root in [('cache', project / '.cache/go-build/fuzz'),
                        ('engine-testdata', project / 'internal/engine/testdata/fuzz')]:
        if not root.exists(): continue
        manifest = tree(volume, [root])
        for item in manifest['entries']:
            source = volume / item['path']
            target = output / label / source.relative_to(root)
            if item['kind'] == 'directory':
                target.mkdir(parents=True, exist_ok=True)
                continue
            require(len(records) < 5000 and item['bytes'] <= 64*1024*1024,
                    'fuzz preservation count/member exceeded')
            require(sum(r['bytes'] for r in records) + item['bytes'] <= 100_000_000,
                    'fuzz preservation bytes exceeded')
            require(file_sha(source, item['identity']) == item['sha256'], 'fuzz changed before copy')
            shutil.copyfile(source, target)
            require(file_sha(target) == item['sha256'] and file_sha(source, item['identity']) == item['sha256'],
                    'fuzz copy differs')
            records.append({'path': label + '/' + source.relative_to(root).as_posix(),
                            'bytes': item['bytes'], 'sha256': item['sha256']})
    write_proof(output / 'manifest.json', {'files': records, 'scope': 'Byte-verified fuzz copies before reference measurement.'}, initial=True)
    return records


def validate_plan(volume, plan):
    require(list(stamp(checked(volume)))[:3] == plan['volume_identity'], 'volume inode changed')
    for relative, identity in plan['ancestors'].items():
        require(list(stamp(checked(volume / relative, volume)))[:3] == identity,
                'trim ancestor inode changed')
    for item in plan['entries']:
        info = checked(volume / item['path'], volume)
        require(stamp(info) == tuple(item['identity']), 'trim entry identity changed')
        if item['kind'] == 'file':
            require(file_sha(volume / item['path'], item['identity']) == item['sha256'],
                    'trim entry content changed')
    # A new entry must refuse the complete deletion before anything is removed.
    listed = {item['path'] for item in plan['entries']}
    for item in plan['entries']:
        if item['kind'] == 'directory':
            with os.scandir(volume / item['path']) as children:
                require(all((Path(item['path']) / child.name).as_posix() in listed for child in children),
                        'unlisted entry appeared in trim tree')


def delete_linux(volume, plan):
    """No following links or replacing a path check with a resolved pathname."""
    require(sys.platform == 'linux' and os.unlink in os.supports_dir_fd
            and hasattr(os, 'O_NOFOLLOW'), 'secure deletion requires Linux directory descriptors')
    validate_plan(volume, plan)
    identities = {**plan['ancestors'], **{item['path']: item['identity'] for item in plan['entries']}}
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    volume_info = checked(volume)
    anchor = os.open(volume, flags)
    try:
        require(stamp(os.fstat(anchor)) == stamp(volume_info)
                and list(stamp(volume_info))[:3] == plan['volume_identity'], 'volume substituted while opening')
        for item in reversed(plan['entries']):
            parts = Path(item['path']).parts
            descriptor = os.dup(anchor)
            try:
                for number, part in enumerate(parts[:-1]):
                    child = os.open(part, flags, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
                    relative = Path(*parts[:number+1]).as_posix()
                    expected = identities.get(relative)
                    current = os.fstat(descriptor)
                    # Parent directory size/timestamps change as children are
                    # removed; its filesystem/inode/type must remain identical.
                    if expected is not None:
                        require((current.st_dev, current.st_ino, current.st_mode) == tuple(expected[:3]),
                                'trim parent directory substituted')
                current = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
                expected = item['identity']
                if item['kind'] == 'file':
                    require(stamp(current) == tuple(expected), 'trim file substituted before unlink')
                    os.unlink(parts[-1], dir_fd=descriptor)
                else:
                    require((current.st_dev, current.st_ino, current.st_mode) == tuple(expected[:3]),
                            'trim directory substituted before rmdir')
                    os.rmdir(parts[-1], dir_fd=descriptor)
            finally:
                os.close(descriptor)
    finally:
        os.close(anchor)


def write_proof(path, value, *, initial=False):
    # A bounded streaming encoder avoids a second full manifest string.
    target = path if initial else path.with_suffix('.tmp')
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    count = 0
    with os.fdopen(descriptor, 'wb') as output:
        for part in json.JSONEncoder(sort_keys=True, separators=(',', ':')).iterencode(value):
            raw = part.encode()
            count += len(raw)
            require(count < MAX_MANIFEST_BYTES, 'trim proof exceeds byte admission')
            output.write(raw)
        output.write(b'\n')
        output.flush()
        os.fsync(output.fileno())
    if not initial:
        os.replace(target, path)


def verified_fuzz_summary(value):
    digest = hashlib.sha256()
    for part in json.JSONEncoder(sort_keys=True, separators=(',', ':')).iterencode(value):
        digest.update(part.encode())
    return {'sha256': digest.hexdigest(), 'entries': len(value['entries']),
            'logical_bytes': value['logical_bytes'], 'unchanged': True}


def admit_terminal_proof(proof):
    # Reserve the larger terminal schema before any deletion. Full original
    # manifests remain in PREPARED; equality checks produce a bounded digest.
    candidate = {**proof, 'status': 'FAIL', 'ended_at': '9' * 64,
                 'error': '\U0010ffff' * 4096,
                 'after_inspections': proof['before_inspections'],
                 'fuzz_after_verified': verified_fuzz_summary(proof['fuzz_before'])}
    count = sum(len(part.encode()) for part in
                json.JSONEncoder(sort_keys=True, separators=(',', ':')).iterencode(candidate)) + 1
    require(count < MAX_MANIFEST_BYTES, 'terminal trim proof exceeds predelete admission')
    return count


def capture(command, env):
    result = subprocess.run(command, capture_output=True, timeout=30, env=env)
    require(len(result.stdout) + len(result.stderr) <= 32768, 'inspection output exceeds admission')
    record = {'command': command, 'exit_code': result.returncode,
              'stdout': result.stdout.decode('utf-8'), 'stderr': result.stderr.decode('utf-8')}
    require(result.returncode == 0, 'Go inspection command failed')
    return record


def inspections(volume, project):
    go = volume / 'tools/go/bin/go'
    keep = [go, volume / 'tools/go/VERSION', volume / 'tools/go/go.env',
            project / 'bin/facetquarry', project / 'bin/fqbench']
    hashes = {path.relative_to(volume).as_posix(): file_sha(path) for path in keep}
    env = os.environ.copy()
    env.update(GOROOT=str(volume / 'tools/go'), GOTOOLCHAIN='local', GOTELEMETRY='off')
    commands = [[str(go), 'version']] + [[str(go), 'version', '-m', str(path)] for path in keep[-2:]]
    return {'retained_sha256': hashes, 'commands': [capture(command, env) for command in commands]}


def verified_receipts(project, identity):
    selected = {}
    candidates = sorted((project / '.local/evidence').glob('*/receipt.json'))
    require(len(candidates) <= 1000, 'receipt count exceeds admission')
    for path in candidates:
        info = checked(path)
        require(info.st_size <= 1_000_000, 'receipt exceeds byte admission')
        record = json.loads(path.read_text())
        category = record.get('category')
        if category in REQUIRED_CATEGORIES and record.get('status') == 'PASS' and record.get('exit_code') == 0 \
                and record.get('termination_reason') is None and record.get('source_before') == identity == record.get('source_after'):
            selected[category] = {'path': path.relative_to(project).as_posix(), 'sha256': file_sha(path, stamp(info))}
    require(set(selected) == set(REQUIRED_CATEGORIES), 'missing current-source supported/clean/online PASS receipts')
    return selected


def validate_mount(volume, observation):
    mounts = observation.get('filesystems', [])
    require(len(mounts) == 1, 'ambiguous owned mount observation')
    mount = mounts[0]
    require(mount.get('target') == str(volume) and mount.get('fstype') == 'ext4'
            and re.fullmatch(r'/dev/loop[0-9]+', str(mount.get('source', ''))) is not None,
            'volume is not actual owned loop ext4 mountpoint')
    return mount


def validate_ownership(volume, image, quota, mount, loops, context, owner):
    """Bind destructive work to the exact admitted image and current run."""
    checked(image)
    info = image.lstat()
    require(image == volume.with_name(volume.name + '.img')
            and image.parent == volume.parent, 'unexpected admitted image path')
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == owner,
            'image owner/type/link identity differs')
    require(0 < info.st_size == quota.get('volume_file_bytes') <= 3_300_000_000,
            'admitted image size differs')
    require(quota.get('run_context') == context and quota.get('mount') == mount
            and quota.get('volume_path') == str(volume) and quota.get('image_path') == str(image)
            and quota.get('hard_quota_enforced') is True
            and quota.get('oversized_allocation') == 'DENIED_ENOSPC'
            and quota.get('oversized_allocation_bytes', 0) > info.st_size,
            'admitted quota or run context differs')
    devices = loops.get('loopdevices', [])
    require(len(devices) == 1 and devices[0].get('name') == mount['source']
            and devices[0].get('back-file') == str(image), 'loop backing image differs')
    return {'image': str(image), 'image_identity': list(stamp(info)), 'quota': quota,
            'loop': devices[0]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volume', type=Path, required=True)
    parser.add_argument('--project', type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.getuid() != 0, 'requires ordinary Linux reference runner user')
    volume = args.volume
    project = args.project
    checked(volume)
    checked(project, volume)
    require(project == ROOT and project == volume / 'source', 'run helper from owned checkout')
    observed = subprocess.run(['findmnt', '--json', '--target', str(volume), '-o', 'TARGET,FSTYPE,SOURCE'],
                              capture_output=True, text=True, timeout=10, check=True)
    mount = validate_mount(volume, json.loads(observed.stdout))
    runner_temp = Path(os.environ['RUNNER_TEMP'])
    require(volume == runner_temp / 'facetquarry-reference', 'unexpected reference volume path')
    image = runner_temp / 'facetquarry-reference.img'
    quota_path = project / '.local/reference-quota.json'
    checked(quota_path, volume)
    quota = json.loads(quota_path.read_text())
    def git(*values):
        return subprocess.run(['git', '-C', str(project), *values], capture_output=True,
                              text=True, timeout=10, check=True).stdout.strip()
    context = {'commit': git('rev-parse', 'HEAD'), 'git_status': git('status', '--porcelain'),
               'github_run_id': os.environ['GITHUB_RUN_ID'],
               'github_run_attempt': os.environ['GITHUB_RUN_ATTEMPT']}
    require(not context['git_status'], 'source checkout is dirty before trim')
    loop = subprocess.run(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                           '--output', 'NAME,BACK-FILE'], capture_output=True, text=True,
                          timeout=10, check=True)
    ownership = validate_ownership(volume, image, quota, mount, json.loads(loop.stdout), context, os.getuid())
    proof_path = project / '.local/reference-preflight-trim.json'
    checked(proof_path.parent, volume)
    require(not proof_path.exists() and not proof_path.is_symlink(), 'refusing to overwrite trim proof')
    identity = source_hash(project)
    receipts = verified_receipts(project, identity)
    before = inspections(volume, project)
    fuzz = fuzz_state(volume, project)
    preserved_fuzz = preserve_fuzz(volume, project)
    roots = selected_roots(volume, project)
    plan = tree(volume, roots)
    proof = {'schema_version': 1, 'evidence_type': 'reference_preflight_trim', 'status': 'PREPARED',
             'source': identity, 'mount': mount, 'ownership': ownership,
             'volume': str(volume), 'project': str(project),
             'started_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'receipts': receipts,
             'before_inspections': before, 'fuzz_before': fuzz, 'removal_manifest': plan,
             'preserved_fuzz': preserved_fuzz,
             'scope': 'Owned regenerable SDK/cache trim; no native compiler capability claimed afterward.'}
    # This complete stream-hashed removal manifest exists durably before unlink.
    admit_terminal_proof(proof)
    write_proof(proof_path, proof, initial=True)
    try:
        require(inspections(volume, project) == before, 'retained files changed before trim')
        require(fuzz_state(volume, project) == fuzz, 'fuzz changed before trim')
        delete_linux(volume, plan)
        after = inspections(volume, project)
        fuzz_after = fuzz_state(volume, project)
        require(after == before, 'Go version/build metadata or retained bytes changed')
        require(fuzz_after == fuzz, 'fuzz file bytes/identities changed')
        require(source_hash(project) == identity, 'source changed during trim')
        proof.update(status='PASS', after_inspections=after,
                     fuzz_after_verified=verified_fuzz_summary(fuzz_after))
    except BaseException as failure:
        proof.update(status='FAIL', error=(type(failure).__name__ + ': ' + str(failure))[:4096])
        raise
    finally:
        proof['ended_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
        write_proof(proof_path, proof)
    print(json.dumps({'status': proof['status'], 'proof': str(proof_path),
                      'removed_entries': len(plan['entries']), 'accounted_bytes': plan['accounted_bytes']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
