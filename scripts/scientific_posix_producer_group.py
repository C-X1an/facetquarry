"""Place bounded POSIX commands and their independent sessions in one Linux cgroup."""

import os
from pathlib import Path
import re
import stat
import sys
import time


CGROUP_MOUNT = '/sys/fs/cgroup'
CGROUP_ROOT = Path(CGROUP_MOUNT)
MAX_OBSERVATION = 256 << 10


def read_file(parent, name, maximum):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        raw = bytearray()
        while len(raw) <= maximum:
            block = os.read(descriptor, min(4096, maximum + 1 - len(raw)))
            if not block:
                return bytes(raw)
            raw.extend(block)
        raise RuntimeError('kernel observation byte bound')
    finally:
        os.close(descriptor)


def mount_path_is_unified(raw):
    matches = []
    for row in raw.decode('ascii', 'strict').splitlines():
        main, delimiter, detail = row.partition(' - ')
        fields = main.split()
        if len(fields) >= 6 and fields[4] == CGROUP_MOUNT:
            matches.append(bool(delimiter and fields[3] == '/' and detail.split()[:1] == ['cgroup2']
                                and 'rw' in fields[5].split(',')))
    return matches == [True]


def populated(raw):
    rows = [line.split() for line in raw.decode('ascii', 'strict').splitlines()]
    values = [row[1:] for row in rows if row[:1] == ['populated']]
    if values not in ([['0']], [['1']]):
        raise RuntimeError('exact cgroup population observation required')
    return values == [['1']]


def root_fd():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('actual privileged Linux cgroup controller required')
    with open('/proc/self/mountinfo', 'rb') as stream:
        raw = stream.read(MAX_OBSERVATION + 1)
    if len(raw) > MAX_OBSERVATION or not mount_path_is_unified(raw):
        raise RuntimeError('writable unified cgroup2 at the known runner mount is required')
    return os.open(CGROUP_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def group_for(container):
    # The controller validates run and attempt before furnishing this namespace.
    if not re.fullmatch(r'/srv/fq-posix-proof-[0-9]{1,24}-[0-9]{1,8}', str(container)):
        raise ValueError('exact owned producer namespace required')
    return Path(container).name


def open_group(root, name, expected=None):
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
    try:
        actual = os.fstat(descriptor)
        identity = [actual.st_dev, actual.st_ino]
        if (actual.st_uid != 0 or actual.st_mode & 0o077 or
                os.fstat(root).st_dev != actual.st_dev or (expected is not None and identity != expected)):
            raise RuntimeError('root-owned same-device private cgroup identity required')
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def create(container):
    """A new empty group must exist before any image-producing child can launch."""
    name, root = group_for(container), root_fd()
    try:
        os.mkdir(name, 0o700, dir_fd=root)
        group, identity = open_group(root, name)
        try:
            if populated(read_file(group, 'cgroup.events', 1024)) or read_file(group, 'cgroup.procs', 1024):
                raise RuntimeError('new producer cgroup was not empty')
        finally:
            os.close(group)
        return {'format': 'scientific-posix-private-producer-cgroup-v1', 'name': name, 'identity': identity}
    finally:
        os.close(root)


def observe(container, record):
    """`populated` includes descendants in new POSIX sessions and nested cgroups."""
    name, root = group_for(container), root_fd()
    try:
        if (type(record) is not dict or set(record) != {'format', 'name', 'identity'} or
                record['format'] != 'scientific-posix-private-producer-cgroup-v1' or record['name'] != name):
            raise RuntimeError('exact retained group record required')
        group, identity = open_group(root, name, record['identity'])
        try:
            raw = read_file(group, 'cgroup.events', 1024)
            return {'identity': identity, 'populated': populated(raw), 'cgroup_events': raw.decode('ascii')}
        finally:
            os.close(group)
    finally:
        os.close(root)


def enter(container, record):
    """Migrate only the calling child, then check the kernel's membership record."""
    snapshot = observe(container, record)
    if snapshot['populated']:
        raise RuntimeError('previous producer processes remain')
    name, root = group_for(container), root_fd()
    try:
        group, _ = open_group(root, name, snapshot['identity'])
        try:
            control = os.open('cgroup.procs', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=group)
            try:
                if not stat.S_ISREG(os.fstat(control).st_mode) or os.write(control, b'0\n') != 2:
                    raise RuntimeError('cgroup self-migration write failed')
            finally:
                os.close(control)
        finally:
            os.close(group)
        with open('/proc/self/cgroup', 'rb') as stream:
            if stream.read(4097) != ('0::/' + name + '\n').encode('ascii'):
                raise RuntimeError('kernel did not confirm the exact cgroup membership')
    finally:
        os.close(root)


def stop_remaining(container, record):
    """End only this admitted producer group after the driver lease is held."""
    before = observe(container, record)
    if not before['populated']:
        return {'before': before, 'after': before, 'kill_requested': False}
    name, root = group_for(container), root_fd()
    try:
        group, _ = open_group(root, name, before['identity'])
        try:
            fd = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=group)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode) or os.write(fd, b'1\n') != 2:
                    raise RuntimeError('exact owned process-group cleanup could not be requested')
            finally:
                os.close(fd)
        finally:
            os.close(group)
    finally:
        os.close(root)
    until = time.monotonic() + 15
    while time.monotonic() < until:
        after = observe(container, record)
        if not after['populated']:
            return {'before': before, 'after': after, 'kill_requested': True}
        time.sleep(0.1)
    raise RuntimeError('owned cgroup has not reached terminal state after bounded cleanup')
