"""Seal a bounded set of diagnostic files beside a still-mounted proof volume."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time


FORMAT = 'scientific-posix-off-mount-failure-custody-v1'
MANIFEST = 'off-mount-failure-manifest.json'
EXCLUDED = ['job/quota.img', 'job/volume']
EVIDENCE_ID = re.compile(r'[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}')
FILES = tuple(('recovery.json', 'control/context.json', 'control/controller-result.json',
    'control/recovery-status.json', 'control/controller-closure.json', 'control/recovery-closure.json',
    'control/host-before-upload.json', 'control/after-quota-image-metadata.json',
    'control/before-spi-image-metadata.json', 'control/after-spi-image-metadata.json',
    'control/before-spi-producers.json', 'control/after-spi-producers.json', 'control/support-before-spi.json',
    'job/control/quota-proof.json', 'job/control/quota-attempt-observation.json',
    'job/control/quota-saturation-fill.json', 'job/control/quota-saturation-release.json',
    'job/control/quota-saturation-release-intent.json', 'job/control/memory-proof.json',
    'job/control/original22-command-receipt.json', 'job/control/external-profile-control-proof.json',
    'job/control/lifecycle-admission.json', 'job/control/integration-admission.json',
    'job/control/lifecycle-receipt.json', 'job/exports/fixture.neutral', 'job/exports/fixture-copy.neutral',
    'control/commands/spi-supervisor-evidence/result.json',
    'control/commands/spi-supervisor-evidence/stdout.bin', 'control/commands/spi-supervisor-evidence/stderr.bin',
    'job/control/run/stdout.bin', 'job/control/run/stderr.bin'))
STREAMS = ('receipt.json', 'stdout.txt', 'stderr.txt')
EVIDENCE_PARTS = ('source', 'checkout', '.local', 'evidence')
EVIDENCE_DIR = '/'.join(EVIDENCE_PARTS)
MAX_EVIDENCE_DIRS = 8
MAX_MANIFEST = 256 << 10
KERNEL_BYTES = 256 << 10


def need(value, message):
    if not value:
        raise RuntimeError(message)


def kernel(path, maximum):
    with open(path, 'rb') as stream:
        raw = stream.read(maximum + 1)
    need(len(raw) <= maximum, 'OFF_MOUNT_KERNEL_RECORD_BOUND')
    return raw


def unescape(value):
    escapes = {r'\040': ' ', r'\011': '\t', r'\012': '\n', r'\134': '\\'}
    need(not re.search(r'\\(?!040|011|012|134)', value), 'OFF_MOUNT_UNKNOWN_KERNEL_PATH_ESCAPE')
    return re.sub(r'\\[0-7]{3}', lambda match: escapes[match[0]], value)


def mount_table(raw):
    result = {}
    for line in os.fsdecode(raw).split('\n'):
        if not line:
            continue
        fields = line.split()
        need(len(result) < 4096 and len(fields) >= 10 and '-' in fields[6:],
             'OFF_MOUNT_MOUNTINFO_SHAPE')
        split = fields.index('-', 6)
        ident, parent, device, root, target, opts = fields[:6]
        need(ident.isdecimal() and parent.isdecimal() and int(ident) not in result and
             re.fullmatch(r'[0-9]+:[0-9]+', device) and len(fields) == split + 4,
             'OFF_MOUNT_DISTINCT_MOUNT_RECORD_REQUIRED')
        root, target = PurePosixPath(unescape(root)), PurePosixPath(unescape(target))
        need(root.is_absolute() and target.is_absolute() and '..' not in root.parts + target.parts,
             'OFF_MOUNT_CANONICAL_KERNEL_PATH_REQUIRED')
        result[int(ident)] = (int(parent), device, root, target, set(opts.split(',')),
                              fields[split + 1], unescape(fields[split + 2]))
    return result


def fd_mount(fd):
    raw = kernel(f'/proc/self/fdinfo/{fd}', 4096)
    values = re.findall(rb'^mnt_id:\s+([0-9]+)$', raw, re.MULTILINE)
    need(len(values) == 1, 'OFF_MOUNT_EXACT_DESCRIPTOR_MOUNT_REQUIRED')
    return int(values[0])


def device_id(dev):
    return f'{os.major(dev)}:{os.minor(dev)}'


def namespace_mounts(rows, host_id, host_dev, container):
    host = rows[host_id]
    need(host[1] == host_dev and container.parent.is_relative_to(host[3]), 'OFF_MOUNT_HOST_FILESYSTEM_REQUIRED')
    physical_root = host[2] / container.relative_to(host[3])
    live = [ident for ident, row in rows.items() if row[3].is_relative_to(container)]
    need(not live or len(live) == 1 and rows[live[0]][3] == container / 'job' / 'volume',
         'OFF_MOUNT_EXACT_LOOP_WITHOUT_EXTRA_MOUNTS_REQUIRED')
    for ident, row in rows.items():
        if ident != host_id and row[1] == host_dev:
            need(not row[2].is_relative_to(physical_root) and not physical_root.is_relative_to(row[2]),
                 'OFF_MOUNT_EXTERNAL_PROOF_NAMESPACE_ALIAS')
    return live


def mount_binding(rows, host_id, host_dev, container, quota):
    need(host_dev != quota['major_minor'], 'OFF_MOUNT_HOST_FILESYSTEM_REQUIRED')
    live = namespace_mounts(rows, host_id, host_dev, container)
    expected = quota['mount_id']
    need(live == [expected] and [ident for ident, row in rows.items() if row[1] == quota['major_minor']] == live,
         'OFF_MOUNT_EXACT_LOOP_WITHOUT_EXTRA_MOUNTS_REQUIRED')
    owner, device, root, target, options, fs, source = rows[expected]
    need((owner, device, root, target, fs, source) ==
         (host_id, quota['major_minor'], PurePosixPath('/'), container / 'job' / 'volume', 'ext4', quota['source']) and
         {'nodev', 'nosuid', 'noexec'}.issubset(options), 'OFF_MOUNT_EXPECTED_EXT4_ATTACHMENT_REQUIRED')
    return {'mount_id': expected, 'host_mount_id': host_id, 'host_dev': host_dev,
            'loop_dev': device, 'loop_source': source, 'mountpoint': str(target), 'image': quota['image'],
            'image_identity': quota['image_identity']}


def canonical_name(relative):
    if relative in FILES:
        return True
    parts = relative.split('/')
    return (tuple(parts[:-2]) == EVIDENCE_PARTS and
            EVIDENCE_ID.fullmatch(parts[-2]) is not None and parts[-1] in STREAMS)


def file_identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


@contextmanager
def open_dirs(host, parts, host_id, uid, gid, *, seal=False, sealed=False):
    """Walk only named host directories, retaining descriptors until the leaf closes."""
    descriptors = []
    current = host
    try:
        for part in parts:
            need(re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', part) and part not in ('.', '..'),
                 'OFF_MOUNT_EXACT_DIRECTORY_COMPONENT_REQUIRED')
            current = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=current)
            descriptors.append(current)
            info = os.fstat(current)
            need(fd_mount(current) == host_id and info.st_dev == os.fstat(host).st_dev and
                 info.st_uid in (0, uid) and info.st_gid in (0, gid) and not info.st_mode & 0o022,
                 'OFF_MOUNT_OWNED_HOST_DIRECTORY_REQUIRED')
            if seal:
                os.fchown(current, 0, gid)
                os.fchmod(current, 0o750)
                info = os.fstat(current)
            if seal or sealed:
                need((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, gid, 0o750),
                     'OFF_MOUNT_ROOT_SEALED_DIRECTORY_REQUIRED')
        yield current
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def attachment(host, container, uid, gid, quota):
    host_id = fd_mount(host)
    info = os.fstat(host)
    need(info.st_uid == 0 and not info.st_mode & 0o022 and quota['image'] == str(container / EXCLUDED[0]),
         'OFF_MOUNT_ROOT_ANCHOR_REQUIRED')
    view = mount_binding(mount_table(kernel('/proc/self/mountinfo', KERNEL_BYTES)), host_id,
                         device_id(info.st_dev), container, quota)
    source = view['loop_source']
    need(re.fullmatch(r'/dev/loop[0-9]{1,5}', source), 'OFF_MOUNT_LOOP_DEVICE_NAME')
    loop = '/sys/block/' + source.rsplit('/', 1)[1]
    block = os.stat(source, follow_symlinks=False)
    need(stat.S_ISBLK(block.st_mode) and device_id(block.st_rdev) == view['loop_dev'] and
         kernel(loop + '/dev', 64).decode('ascii').strip() == view['loop_dev'] and
         kernel(loop + '/loop/backing_file', 2048).decode('ascii').strip() in
         (view['image'], view['image'].lstrip('/')), 'OFF_MOUNT_EXACT_KERNEL_BACKING_REQUIRED')
    with open_dirs(host, (container.name, 'job'), host_id, uid, gid) as directory:
        # A metadata-only observation, without opening the live backing file or volume.
        image = os.stat('quota.img', dir_fd=directory, follow_symlinks=False)
        need(stat.S_ISREG(image.st_mode) and not image.st_mode & 0o077 and image.st_dev == info.st_dev and
             [image.st_dev, image.st_ino, image.st_uid, image.st_nlink, image.st_size] == view['image_identity'],
             'OFF_MOUNT_EXACT_LIVE_BACKING_INODE_REQUIRED')
    return view


def namespace_live(container):
    host = os.open(container.parent, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        info = os.fstat(host)
        need(info.st_uid == 0 and not info.st_mode & 0o022, 'OFF_MOUNT_ROOT_ANCHOR_REQUIRED')
        return bool(namespace_mounts(mount_table(kernel('/proc/self/mountinfo', KERNEL_BYTES)),
                                     fd_mount(host), device_id(info.st_dev), container))
    finally:
        os.close(host)


def file_snapshot(host, container, relative, uid, gid, view, maximum, deadline, *, seal=False, capture=False):
    bits = relative.split('/')
    need(canonical_name(relative) or relative == MANIFEST, 'OFF_MOUNT_EXACT_SCOPE_FILE_REQUIRED')
    with open_dirs(host, [container.name, *bits[:-1]], view['host_mount_id'], uid, gid,
                   seal=seal, sealed=not seal) as directory:
        before = os.stat(bits[-1], dir_fd=directory, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022 and
             0 <= before.st_size <= maximum and before.st_blocks * 512 <= maximum + 4096 and
             before.st_uid in (0, uid) and before.st_gid in (0, gid) and
             (before.st_dev, before.st_ino) != tuple(view['image_identity'][:2]),
             'OFF_MOUNT_FILE_IDENTITY_OR_ALLOCATION_REFUSED')
        fd = os.open(bits[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            info = os.fstat(fd)
            need(fd_mount(fd) == view['host_mount_id'] and info.st_dev == os.fstat(host).st_dev and
                 file_identity(info) == file_identity(before), 'OFF_MOUNT_FILE_NOT_ON_EXPECTED_HOST_MOUNT')
            if seal:
                os.fchown(fd, 0, gid)
                os.fchmod(fd, 0o440)
                info = os.fstat(fd)
            need((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, gid, 0o440),
                 'OFF_MOUNT_ROOT_SEALED_FILE_REQUIRED')
            hashed, total, chunks = hashlib.sha256(), 0, []
            while True:
                need(time.monotonic() < deadline, 'OFF_MOUNT_READ_DEADLINE')
                raw = os.read(fd, 65536)
                if not raw:
                    break
                total += len(raw)
                need(total <= maximum, 'OFF_MOUNT_READ_BOUND')
                hashed.update(raw)
                if capture:
                    chunks.append(raw)
            measured = file_identity(os.fstat(fd))
            need(total == info.st_size and measured == file_identity(info) ==
                 file_identity(os.stat(bits[-1], dir_fd=directory, follow_symlinks=False)),
                 'OFF_MOUNT_FILE_CHANGED_DURING_READBACK')
            row = {'path': relative, 'identity': measured, 'bytes': total, 'sha256': hashed.hexdigest(),
                   'allocated_bytes': info.st_blocks * 512}
            return (row, b''.join(chunks)) if capture else row
        finally:
            os.close(fd)


def evidence_names(host, container, uid, gid, view):
    with open_dirs(host, [container.name, *EVIDENCE_PARTS], view['host_mount_id'], uid, gid,
                   seal=True) as directory:
        names, entries = [], 0
        with os.scandir(directory) as listing:
            for entry in listing:
                entries += 1
                need(entries <= MAX_EVIDENCE_DIRS, 'OFF_MOUNT_EVIDENCE_COUNT_BOUND')
                if EVIDENCE_ID.fullmatch(entry.name):
                    names.append(entry.name)
        return [f'{EVIDENCE_DIR}/{name}/{stream}' for name in sorted(names) for stream in STREAMS]


def publish(container, inputs, quota, transport, create, writers_terminal):
    """Seal selected original inodes under the root lease. The rest stay in place."""
    uid, gid = inputs['owner_uid'], inputs['owner_gid']
    deadline = time.monotonic() + 90
    host = os.open(container.parent, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        view = attachment(host, container, uid, gid, quota)
        writers_terminal()
        files, omissions = [], []
        try:
            names = [*FILES, *evidence_names(host, container, uid, gid, view)]
        except (OSError, ValueError, RuntimeError):
            names = FILES
            omissions.append({'path': EVIDENCE_DIR, 'why': 'DIRECTORY_UNAVAILABLE_OR_OUTSIDE_BOUND'})
        for relative in names:
            try:
                row = file_snapshot(host, container, relative, uid, gid, view,
                    transport.maximum_member_bytes(relative), deadline, seal=True)
            except FileNotFoundError:
                omissions.append({'path': relative, 'why': 'ABSENT'})
            except (OSError, ValueError, RuntimeError):
                omissions.append({'path': relative, 'why': 'UNREADABLE_UNSAFE_OR_OUTSIDE_BOUND'})
            else:
                files.append(row)
        need(any(row['path'] == 'control/recovery-status.json' and row['bytes'] > 0 for row in files) and
             time.monotonic() < deadline, 'OFF_MOUNT_NONEMPTY_BOUNDED_DIAGNOSTICS_REQUIRED')
        writers_terminal()
        need(attachment(host, container, uid, gid, quota) == view, 'OFF_MOUNT_ATTACHMENT_CHANGED')
        manifest = {'format': FORMAT, 'inputs': inputs, 'custody': 'INCOMPLETE', 'mount_binding': view,
                    'excluded_live_image_paths': EXCLUDED, 'complete_regular_file_inventory': False,
                    'omissions': omissions, 'files': files}
        raw = (json.dumps(manifest, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')
        measured = transport.validate_payload([(row['path'], row['bytes']) for row in files] +
            [(MANIFEST, len(raw))], require_complete_image=False)
        need(measured['exact_image_bytes'] is None, 'OFF_MOUNT_MUST_EXCLUDE_THE_BACKING_IMAGE')
        create(container / MANIFEST, raw, 0, gid, MAX_MANIFEST)
        row = file_snapshot(host, container, MANIFEST, uid, gid, view, MAX_MANIFEST, deadline, seal=True)
        need(row['sha256'] == hashlib.sha256(raw).hexdigest(), 'OFF_MOUNT_MANIFEST_SEAL_CHANGED')
        return row['sha256'], measured, len(files)
    finally:
        os.close(host)


def verify(container, inputs, digest, transport, decode):
    """Return only sealed literal paths after unprivileged exact readback."""
    uid, gid = inputs['owner_uid'], inputs['owner_gid']
    deadline = time.monotonic() + 90
    host = os.open(container.parent, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        initial = {'host_mount_id': fd_mount(host), 'image_identity': [-1, -1]}
        reference, raw = file_snapshot(host, container, MANIFEST, uid, gid, initial, MAX_MANIFEST,
                                        deadline, capture=True)
        need(reference['sha256'] == digest, 'OFF_MOUNT_ROOT_MANIFEST_DIGEST')
        manifest = decode(raw, MAX_MANIFEST)
        need(manifest['format'] == FORMAT and manifest['inputs'] == inputs and manifest['custody'] == 'INCOMPLETE' and
             manifest['excluded_live_image_paths'] == EXCLUDED and manifest['complete_regular_file_inventory'] is False,
             'OFF_MOUNT_FAILURE_ONLY_MANIFEST_REQUIRED')
        view = manifest['mount_binding']
        quota = {'mount_id': view['mount_id'], 'source': view['loop_source'], 'major_minor': view['loop_dev'],
                 'image': view['image'], 'image_identity': view['image_identity']}
        need(attachment(host, container, uid, gid, quota) == view, 'OFF_MOUNT_ATTACHMENT_CHANGED')
        files = manifest['files']
        need(0 < len(files) <= len(FILES) + MAX_EVIDENCE_DIRS * len(STREAMS), 'OFF_MOUNT_FILE_LIST_BOUND')
        for row in files:
            relative = row['path']
            need(canonical_name(relative) and file_snapshot(host, container, relative, uid, gid, view,
                 transport.maximum_member_bytes(relative), deadline) == row, 'OFF_MOUNT_SEALED_READBACK_MISMATCH')
        need(attachment(host, container, uid, gid, quota) == view, 'OFF_MOUNT_ATTACHMENT_CHANGED')
        transport.validate_payload([(row['path'], row['bytes']) for row in files] + [(MANIFEST, len(raw))],
                                   require_complete_image=False)
        return [{**row, 'path': str(container / row['path'])} for row in [*files, reference]]
    finally:
        os.close(host)
