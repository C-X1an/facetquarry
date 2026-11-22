"""SOURCE ONLY: exclusive POSIX immutable record-pair publisher.

Every failure retains partials/finals. release() closes descriptors only.
No copy, move, delete, retirement, subprocess, quota configuration or auto root.
The explicit finite reservation is arithmetic admission, NOT an OS quota.
Source controls for POSIX publication have NOT been authored/executed here.
"""
from dataclasses import dataclass
import base64
import ctypes
from functools import lru_cache
import hashlib
import os
from pathlib import Path
import stat
import sys

import scientific_execution_registry as registry

SOURCE_EXTENTS = ('originals', 'primitive_staging', 'packed_candidates', 'catalog_pairs',
                  'registry_pairs', 'nonqualifying', 'outer_artifacts')
EXTENTS = (*SOURCE_EXTENTS, 'failure_transport')
PLAN_FORMAT = 'scientific-execution-storage-plan-v1'
_AT_EMPTY_PATH = 0x1000  # Linux uapi/linux/fcntl.h
_MAX_FILE_HANDLE_BYTES = 128  # Linux MAX_HANDLE_SZ


class _FileHandle(ctypes.Structure):
    # Linux struct file_handle with storage for its flexible byte array.
    _fields_ = [('size', ctypes.c_uint), ('kind', ctypes.c_int),
                ('payload', ctypes.c_ubyte * _MAX_FILE_HANDLE_BYTES)]


@lru_cache(maxsize=1)
def _name_to_handle_at():
    registry.need(sys.platform == 'linux' and ctypes.sizeof(ctypes.c_int) == 4 and
                  ctypes.sizeof(ctypes.c_uint) == 4 and _FileHandle.payload.offset == 8,
                  'LINUX_DIRECTORY_FILE_HANDLE_REQUIRED')
    query = getattr(ctypes.CDLL(None, use_errno=True), 'name_to_handle_at', None)
    registry.need(query is not None, 'LINUX_DIRECTORY_FILE_HANDLE_REQUIRED')
    query.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.POINTER(_FileHandle),
                      ctypes.POINTER(ctypes.c_int), ctypes.c_int)
    query.restype = ctypes.c_int
    return query


def _directory_handle(fd, name=None):
    """Compare opaque filesystem identities without acquiring a descriptor."""
    handle = _FileHandle(size=_MAX_FILE_HANDLE_BYTES)
    mount = ctypes.c_int()
    flags = _AT_EMPTY_PATH if name is None else 0
    path = b'' if name is None else os.fsencode(name)
    if _name_to_handle_at()(fd, path, ctypes.byref(handle), ctypes.byref(mount), flags) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), name)
    registry.need(0 < handle.size <= _MAX_FILE_HANDLE_BYTES and mount.value > 0 and handle.kind > 0,
                  'BOUNDED_DIRECTORY_FILE_HANDLE_REQUIRED')
    return mount.value, handle.kind, bytes(handle.payload[:handle.size])


def _release_descriptors(fds):
    """Consume caller-owned numbers once and retain every close failure."""
    primary = sys.exception()
    failures, seen = [], set()
    for fd in fds:
        if fd is None or fd in seen:
            continue
        seen.add(fd)
        try:
            os.close(fd)
        except BaseException as error:
            failures.append(error)
    if failures:
        raise BaseExceptionGroup('DESCRIPTOR_RELEASE_FAILED',
            ([primary] if primary is not None else []) + failures) from None


def publication_leaf(identity, kind):
    """Encode remaining240digest bits in48portable base32 characters."""
    registry.digest(identity)
    registry.need(kind in registry.LIMITS, 'PUBLISH_OBJECT_KIND')
    encoded = base64.b32encode(bytes.fromhex(identity[4:])).decode('ascii').lower()
    return encoded + ('.raw' if kind == 'original' else '.json')


def publication_reference(directory, kind, raw):
    """Prevalidate both pair paths; retain bounded2hex/2hex directory fanout."""
    registry.call(registry.rawref.component, directory)
    registry.need(kind in registry.LIMITS and type(raw) is bytes and len(raw) <= registry.LIMITS[kind] and
                  (kind == 'original' or len(raw) > 0), 'PUBLISH_OBJECT_KIND_OR_BOUND')
    identity = registry.sha(raw)
    path = '/'.join((directory, kind, identity[:2], identity[2:4], publication_leaf(identity, kind)))
    ref = {'kind': kind, 'path': path, 'bytes': len(raw), 'sha256': identity}
    registry.reference(ref, kind)
    return ref


@dataclass(frozen=True)
class StoragePlan:
    """All-attributable peak allocation reservation, including failure copies.

    Each extent is {data_bytes,entries}. data_bytes is SUM of logical lengths,
    entries includes files AND directories, and 2 allocation units per entry
    cover rounding/directory blocks plus parent entry headroom. Larger measured
    allocation geometry refuses. registry_pairs includes both publication copies
    and bounded failed prefixes. failure_transport reserves >=2 full byte-for-
    byte source copies AND their entries without assuming compression/cleanup.
    Global baseline, all other growth, runtime/logs/tools and >=2GB reserve stay
    explicit. The caller must independently establish inventory freshness, real
    hard enforcement and the absence of unbounded native/archiver growth.
    """
    global_baseline_bytes: int
    global_other_growth_bytes: int
    global_reserve_bytes: int
    extents: dict
    object_counts: dict
    object_bytes: dict
    allocation_unit: int = 4096
    ceiling_bytes: int = 12_000_000_000
    transport_copies: int = 2

    def document(self):
        return {'format': PLAN_FORMAT, 'global_baseline_bytes': self.global_baseline_bytes,
                'global_other_growth_bytes': self.global_other_growth_bytes,
                'global_reserve_bytes': self.global_reserve_bytes, 'extents': registry.clone(self.extents),
                'object_counts': registry.clone(self.object_counts), 'object_bytes': registry.clone(self.object_bytes),
                'allocation_unit': self.allocation_unit, 'ceiling_bytes': self.ceiling_bytes,
                'transport_copies': self.transport_copies}

    def validate(self):
        registry.integer(self.global_baseline_bytes, 0, 15_000_000_000)
        registry.integer(self.global_other_growth_bytes, 0, 15_000_000_000)
        registry.integer(self.global_reserve_bytes, 2_000_000_000, 15_000_000_000)
        registry.integer(self.ceiling_bytes, 1, 12_000_000_000)
        registry.integer(self.transport_copies, 2, 4)
        registry.integer(self.allocation_unit, 4096, 65536)
        registry.need(self.allocation_unit & (self.allocation_unit - 1) == 0, 'ALLOCATION_UNIT_POWER_OF_TWO')
        registry.exact(self.extents, EXTENTS)
        registry.exact(self.object_counts, registry.LIMITS)
        registry.exact(self.object_bytes, registry.LIMITS)
        for row in self.extents.values():
            registry.exact(row, ('data_bytes', 'entries'))
            registry.integer(row['data_bytes'], 0, 15_000_000_000)
            registry.integer(row['entries'], 0, registry.MAX_ROWS * registry.MAX_TRANSPORT_PAGES)
        count = payload = 0
        for kind, maximum in registry.LIMITS.items():
            registry.integer(self.object_counts[kind], 0, registry.MAX_OBJECTS)
            registry.integer(self.object_bytes[kind], 0, self.object_counts[kind] * maximum)
            if kind != 'original':
                registry.need(self.object_bytes[kind] >= self.object_counts[kind], 'NONEMPTY_RECORD_RESERVATION')
            count += self.object_counts[kind]
            payload += self.object_bytes[kind]
        registry.need(count <= registry.MAX_OBJECTS, 'PLANNED_OBJECT_COUNT_BOUND')
        # Two file copies plus up to TWO hash-prefix directories per object;
        # all kind directories/root are charged even if construction fails.
        registry.need(self.extents['registry_pairs']['entries'] >= 4 * count + len(registry.LIMITS) + 1 and
                      self.extents['registry_pairs']['data_bytes'] >= 2 * payload,
                      'ALL_METADATA_PARTIAL_FINAL_AND_DIRECTORY_RESERVATION')
        source_bytes = sum(self.extents[name]['data_bytes'] for name in SOURCE_EXTENTS)
        source_entries = sum(self.extents[name]['entries'] for name in SOURCE_EXTENTS)
        registry.need(self.extents['failure_transport']['data_bytes'] >= self.transport_copies * source_bytes and
                      self.extents['failure_transport']['entries'] >= self.transport_copies * source_entries,
                      'COMPLETE_FAILURE_TRANSPORT_AND_OVERLAP_NOT_RESERVED')
        allocation = sum(row['data_bytes'] + 2 * self.allocation_unit * row['entries']
                         for row in self.extents.values())
        total = self.global_baseline_bytes + self.global_other_growth_bytes + self.global_reserve_bytes + allocation
        registry.need(total < self.ceiling_bytes, 'ALL_ATTRIBUTABLE_PEAK_RESERVATION_REFUSED')
        return {'plan_sha256': registry.sha(registry.canonical(self.document())),
                'reserved_peak_bytes': total, 'kernel_quota': 'NOT_ESTABLISHED_BY_NUMERIC_PLAN'}


def _platform():
    registry.need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY') and
                  hasattr(os, 'geteuid') and os.open in os.supports_dir_fd and
                  os.stat in os.supports_dir_fd and os.mkdir in os.supports_dir_fd,
                  'POSIX_NOFOLLOW_DIRFD_REQUIRED')


def _directory(info, *, private):
    registry.need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'REGULAR_DIRECTORY_REQUIRED')
    if private:
        registry.need(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, 'EXCLUSIVE_OWNED_PRIVATE_DIRECTORY')
    else:
        registry.need(info.st_uid in (0, os.geteuid()) and info.st_mode & 0o022 == 0,
                      'TRUSTED_NONWRITABLE_ANCESTOR_DIRECTORY')


def _file(info):
    registry.need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                  info.st_mode & 0o077 == 0, 'EXCLUSIVE_OWNED_UNIQUE_REGULAR_FILE')


def _directory_id(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_stamp(info, path, handle):
    identity = (*_directory_id(info), handle)
    # Every shard link is covered by its parent's stable namespace stamp.
    # Leaf contents can change without changing the link, including when an
    # exclusive final creation encounters a preexisting collision.
    namespace = _signature(info) if path.count('/') < 2 else None
    return identity, namespace


def _owned_base(path):
    _platform()
    path = Path(path)
    registry.need(path.is_absolute() and len(path.parts) > 1 and '..' not in path.parts, 'ABSOLUTE_EXPLICIT_OWNED_BASE')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
    try:
        _directory(os.fstat(fd), private=False)
        for index, part in enumerate(path.parts[1:]):
            before = os.stat(part, dir_fd=fd, follow_symlinks=False)
            private = index == len(path.parts[1:]) - 1
            _directory(before, private=private)
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), dir_fd=fd)
            try:
                current = os.fstat(child)
                _directory(current, private=private)
                registry.need(_directory_id(current) == _directory_id(before) ==
                              _directory_id(os.stat(part, dir_fd=fd, follow_symlinks=False)), 'OWNED_ANCESTOR_PATH_BINDING')
            except BaseException:
                _release_descriptors((child,))
                raise
            parent, fd = fd, child
            _release_descriptors((parent,))
        return fd
    except BaseException:
        _release_descriptors((fd,))
        raise


def _open_child(parent, name):
    registry.call(registry.rawref.component, name)
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _directory(before, private=True)
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), dir_fd=parent)
    try:
        _directory(os.fstat(fd), private=True)
        registry.need(_directory_id(os.fstat(fd)) == _directory_id(before) ==
                      _directory_id(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'CHILD_DIRECTORY_PATH_BINDING')
        return fd
    except BaseException:
        _release_descriptors((fd,))
        raise


def _read_file(parent, name, maximum, *, expected_fd=None):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    _file(before)
    registry.need(before.st_size <= maximum, 'BOUNDED_READBACK_SIZE')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), dir_fd=parent)
    try:
        _file(os.fstat(fd))
        registry.need(_signature(os.fstat(fd)) == _signature(before), 'FILE_OPEN_PATH_BINDING')
        if expected_fd is not None:
            registry.need(_signature(os.fstat(expected_fd)) == _signature(before), 'WRITER_READER_SAME_LIVE_FILE')
        pieces, used = [], 0
        while True:
            raw = os.read(fd, min(1 << 20, maximum - used + 1))
            if not raw:
                break
            used += len(raw)
            registry.need(used <= maximum, 'BOUNDED_READBACK_GROWTH')
            pieces.append(raw)
        registry.need(used == before.st_size and _signature(os.fstat(fd)) == _signature(before) ==
                      _signature(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'COMPLETE_STABLE_READBACK')
        return b''.join(pieces)
    finally:
        _release_descriptors((fd,))


class Publisher:
    """A fresh, explicit one-component metadata namespace on an owned base.

    plan is validated BEFORE mkdir. Every write reserves BOTH files in the
    immutable pair and their entries. Files/directories are exclusive/no-follow;
    descriptors are rebound to live paths. Shard descriptors are scoped to
    each operation or verification walk. The Linux filesystem must expose
    stable opaque file handles for identity checks. Failure poisons the
    publisher and preserves every byte. Recovery requires a NEW publisher
    namespace; old records can be adopted by read_execution/accept_* without
    rewriting.
    """
    def __init__(self, owned_base, directory, plan):
        _platform()
        registry.call(registry.rawref.component, directory)
        registry.need(type(plan) is StoragePlan, 'EXPLICIT_STORAGE_PLAN')
        self.plan = StoragePlan(plan.global_baseline_bytes, plan.global_other_growth_bytes,
                                plan.global_reserve_bytes, registry.clone(plan.extents),
                                registry.clone(plan.object_counts), registry.clone(plan.object_bytes),
                                plan.allocation_unit, plan.ceiling_bytes, plan.transport_copies)
        self.admission = self.plan.validate()
        self.base_path, self.directory = Path(owned_base), directory
        self.base_fd = self.fd = None
        self.directories = {}
        self.directory_stamps = {}
        self.counts = {kind: 0 for kind in registry.LIMITS}
        self.bytes = {kind: 0 for kind in registry.LIMITS}
        self.failed = False
        self.published = {}
        try:
            self.base_fd = _owned_base(self.base_path)
            self.base_id = _directory_id(os.fstat(self.base_fd))
            try:
                registry.need(_directory_handle(self.base_fd) == _directory_handle(self.base_fd, '.'),
                              'LINUX_DIRECTORY_FILE_HANDLE_REQUIRED')
            except OSError as error:
                raise registry.Refusal('LINUX_DIRECTORY_FILE_HANDLE_REQUIRED') from error
            geometry = os.fstatvfs(self.base_fd)
            registry.need(0 < max(geometry.f_frsize, geometry.f_bsize) <= self.plan.allocation_unit,
                          'ADMITTED_ALLOCATION_GEOMETRY')
            os.mkdir(directory, mode=0o700, dir_fd=self.base_fd)
            os.fsync(self.base_fd)
            self.fd = _open_child(self.base_fd, directory)
            self.root_id = _directory_id(os.fstat(self.fd))
            os.fsync(self.fd)
            self.directory_stamps[''] = self._verify_directory(self.fd, self.base_fd, directory, '', None)
            self._live()
            self._allocation_bound()
        except BaseException:
            self.failed = True
            self.release()
            raise

    def _live(self):
        registry.need(not self.failed and self.fd is not None and self.base_fd is not None, 'PUBLISHER_FAILED_OR_RELEASED')
        current = _owned_base(self.base_path)
        try:
            registry.need(_directory_id(os.fstat(current)) == self.base_id == _directory_id(os.fstat(self.base_fd)),
                          'PUBLISHER_BASE_REPLACED')
            registry.need(_directory_id(os.fstat(self.fd)) == self.root_id ==
                          _directory_id(os.stat(self.directory, dir_fd=self.base_fd, follow_symlinks=False)),
                          'PUBLISHER_ROOT_REPLACED')
            _directory(os.fstat(self.fd), private=True)
        finally:
            _release_descriptors((current,))
        children = {}
        for path in self.directory_stamps:
            if path:
                parent_path, _, name = path.rpartition('/')
                children.setdefault(parent_path, []).append((path, name))

        def verify(fd, parent, name, path):
            stamp = self.directory_stamps[path]
            self._verify_directory(fd, parent, name, path, stamp)
            for child_path, child_name in children.get(path, ()):
                active = self.directories.get(child_path)
                if active is not None:
                    verify(active, fd, child_name, child_path)
                    continue
                child = _open_child(fd, child_name)
                try:
                    verify(child, fd, child_name, child_path)
                finally:
                    _release_descriptors((child,))
            if path in children:
                self._verify_directory(fd, parent, name, path, stamp)

        verify(self.fd, self.base_fd, self.directory, '')

    def _verify_directory(self, fd, parent, name, path, expected):
        info = os.fstat(fd)
        _directory(info, private=True)
        stamp = _directory_stamp(info, path, _directory_handle(fd))
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        registry.need(stamp == _directory_stamp(named, path, _directory_handle(parent, name)) and
                      (expected is None or stamp == expected), 'PUBLISHER_KIND_DIRECTORY_REPLACED')
        self._bound_directory(info)
        return stamp

    def _bound_directory(self, info):
        registry.need(max(info.st_size, info.st_blocks * 512) <= self.plan.allocation_unit,
                      'DIRECTORY_ALLOCATION_EXCEEDS_RESERVED_UNIT')

    def _allocation_bound(self):
        for fd in (self.fd, *self.directories.values()):
            self._bound_directory(os.fstat(fd))

    def _path(self, components, opened, *, create):
        parent, grandparent = self.fd, self.base_fd
        parent_path, parent_name = '', self.directory
        for component in components:
            path = parent_path + '/' + component if parent_path else component
            fd = self.directories.get(path)
            if fd is None:
                stamp = self.directory_stamps.get(path)
                if stamp is None:
                    registry.need(create, 'OWN_PUBLISHED_OBJECT_REFERENCE')
                    parent_stamp = self.directory_stamps[parent_path]
                    self._verify_directory(parent, grandparent, parent_name, parent_path, parent_stamp)
                    before = set(os.listdir(parent))
                    self._verify_directory(parent, grandparent, parent_name, parent_path, parent_stamp)
                    os.mkdir(component, mode=0o700, dir_fd=parent)
                    os.fsync(parent)
                fd = _open_child(parent, component)
                opened[path] = self.directories[path] = fd
                if stamp is None:
                    os.fsync(fd)
                observed = self._verify_directory(fd, parent, component, path, stamp)
                if stamp is None:
                    updated = self._verify_directory(parent, grandparent, parent_name, parent_path, None)
                    registry.need(updated[0] == parent_stamp[0] and
                                  set(os.listdir(parent)) == before | {component},
                                  'PUBLISHER_UNEXPECTED_DIRECTORY_MUTATION')
                    self._verify_directory(parent, grandparent, parent_name, parent_path, updated)
                    self.directory_stamps[parent_path] = updated
                    self.directory_stamps[path] = observed
            grandparent, parent = parent, fd
            parent_path, parent_name = path, component
        return parent, parent_path

    def _release_path(self, writers, opened):
        for path in opened:
            del self.directories[path]
        try:
            _release_descriptors((*writers, *reversed(opened.values())))
        except BaseException:
            self.failed = True
            raise

    def publish(self, kind, raw):
        """Return {kind,path,bytes,sha256} after durable complete pair readback."""
        self._live()
        registry.need(kind in registry.LIMITS and type(raw) is bytes and len(raw) <= registry.LIMITS[kind] and
                      (kind == 'original' or len(raw) > 0), 'PUBLISH_OBJECT_KIND_OR_BOUND')
        if kind != 'original':
            registry.decode(raw, registry.LIMITS[kind])
        ref = publication_reference(self.directory, kind, raw)
        identity = registry.sha(raw)
        registry.need((kind, identity) not in self.published, 'IMMUTABLE_OBJECT_NEVER_REOPENED')
        registry.need(self.counts[kind] < self.plan.object_counts[kind] and
                      self.bytes[kind] + len(raw) <= self.plan.object_bytes[kind], 'OBJECT_PREWRITE_WHOLE_PAIR_RESERVATION')
        # Consume the reservation before the first filesystem mutation. A failed
        # write is a bounded prefix of these fully reserved retained candidates.
        self.counts[kind] += 1
        self.bytes[kind] += len(raw)
        writers, opened = [], {}
        try:
            parent, relative = self._path((kind, identity[:2], identity[2:4]), opened, create=True)
            name = publication_leaf(identity, kind)
            for candidate in (name + '.partial', name):
                self._live()
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                             getattr(os, 'O_CLOEXEC', 0), 0o600, dir_fd=parent)
                writers.append(fd)
                _file(os.fstat(fd))
                offset = 0
                while offset < len(raw):
                    count = os.write(fd, raw[offset:offset + (1 << 20)])
                    registry.need(count > 0, 'SHORT_EXCLUSIVE_WRITE')
                    offset += count
                os.fsync(fd)
                os.fsync(parent)
                registry.need(_read_file(parent, candidate, len(raw), expected_fd=fd) == raw,
                              'PUBLICATION_FILE_READBACK')
                info = os.fstat(fd)
                rounded = ((len(raw) + self.plan.allocation_unit - 1) // self.plan.allocation_unit) * self.plan.allocation_unit
                registry.need(info.st_blocks * 512 <= rounded + self.plan.allocation_unit,
                              'FILE_PHYSICAL_ALLOCATION_EXCEEDS_RESERVATION')
                self._allocation_bound()
            os.fsync(parent)
            os.fsync(self.fd)
            os.fsync(self.base_fd)
            self._live()
            registry.need(_read_file(parent, name, len(raw)) == raw and _read_file(parent, name + '.partial', len(raw)) == raw,
                          'DURABLE_PAIR_DIRECTORY_READBACK')
            registry.need(ref['path'] == self.directory + '/' + relative + '/' + name,
                          'PREVALIDATED_PUBLICATION_PATH')
            registry.reference(ref, kind)
            self.published[(kind, identity)] = ref
            return registry.clone(ref)
        except BaseException:
            self.failed = True
            raise
        finally:
            self._release_path(writers, opened)

    def read(self, ref):
        self._live()
        registry.reference(ref)
        parts = registry.call(registry.rawref.relative, ref['path'])
        leaf = '/'.join(parts[1:4])
        registry.need(len(parts) == 5 and parts[0] == self.directory and leaf in self.directory_stamps and
                      parts[1] == ref['kind'] and parts[2] == ref['sha256'][:2] and
                      parts[3] == ref['sha256'][2:4] and
                      parts[4] == publication_leaf(ref['sha256'], ref['kind']),
                      'OWN_PUBLISHED_OBJECT_REFERENCE')
        opened = {}
        try:
            parent, _ = self._path(parts[1:4], opened, create=False)
            raw = _read_file(parent, parts[4], registry.LIMITS[ref['kind']])
            registry.check_object(ref, raw)
            registry.need(_read_file(parent, parts[4] + '.partial', len(raw)) == raw,
                          'PUBLISHED_PAIR_STILL_EXACT')
            self._live()
            return raw
        finally:
            self._release_path((), opened)

    def retire(self, *args, **kwargs):
        raise registry.Refusal('NO_VERSIONED_POST_RETIREMENT_STATE_RETAIN_ALL_NATIVE_CALLER_AND_STAGING_BYTES')

    def release(self):
        fds = list(self.directories.values())
        self.directories.clear()
        self.directory_stamps = {}
        for attribute in ('fd', 'base_fd'):
            fds.append(getattr(self, attribute, None))
            setattr(self, attribute, None)
        self.failed = True
        _release_descriptors(fds)


def snapshot_owned_base(owned_base, *, maximum_entries, maximum_file_bytes, allocation_unit):
    """Read-only inventory after ALL producer/writer descriptors are quiescent.

    Every entry is included or traversal refuses; no symlink/hardlink/type skip.
    This is bounded content observation, not scientific reachability or proof of
    historic durability. Failure transport must preserve refused/partial trees
    through a separately admitted strict collector rather than drop evidence.
    """
    registry.integer(maximum_entries, 1, registry.MAX_ROWS * registry.MAX_TRANSPORT_PAGES)
    registry.integer(maximum_file_bytes, 0, 15_000_000_000)
    registry.integer(allocation_unit, 4096, 65536)
    registry.need(allocation_unit & (allocation_unit - 1) == 0, 'INVENTORY_ALLOCATION_POWER')
    fd = _owned_base(owned_base)
    root_id = device = None
    rows, seen, total = [], set(), 0
    def walk(folder, prefix, depth):
        nonlocal total
        registry.need(depth <= registry.rawref.MAX_TREE_DEPTH, 'INVENTORY_DEPTH_BOUND')
        before = os.fstat(folder)
        _directory(before, private=True)
        registry.need(max(before.st_size, before.st_blocks * 512) <= allocation_unit,
                      'INVENTORY_DIRECTORY_GEOMETRY')
        names = sorted(os.listdir(folder))
        for name in names:
            registry.call(registry.rawref.component, name)
            registry.need(len(rows) < maximum_entries, 'INVENTORY_ENTRY_BOUND')
            path = prefix + name
            registry.call(registry.rawref.relative, path)
            info = os.stat(name, dir_fd=folder, follow_symlinks=False)
            identity = (info.st_dev, info.st_ino)
            registry.need(info.st_dev == device and identity not in seen, 'INVENTORY_DEVICE_OR_IDENTITY_ALIAS')
            seen.add(identity)
            if stat.S_ISDIR(info.st_mode):
                child = _open_child(folder, name)
                try:
                    registry.need(_directory_id(os.fstat(child)) == _directory_id(info), 'INVENTORY_CHILD_CHANGED')
                    rows.append({'path': path, 'kind': 'directory', 'bytes': 0, 'sha256': None})
                    total += 2 * allocation_unit
                    walk(child, path + '/', depth + 1)
                finally:
                    _release_descriptors((child,))
            else:
                _file(info)
                registry.need(info.st_size <= maximum_file_bytes, 'INVENTORY_FILE_BYTE_BOUND')
                file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), dir_fd=folder)
                try:
                    registry.need(_signature(os.fstat(file_fd)) == _signature(info), 'INVENTORY_OPEN_FILE_BINDING')
                    used, digest = 0, hashlib.sha256()
                    while True:
                        part = os.read(file_fd, 1 << 20)
                        if not part:
                            break
                        used += len(part)
                        registry.need(used <= maximum_file_bytes, 'INVENTORY_FILE_GREW_BEYOND_BOUND')
                        digest.update(part)
                    registry.need(used == info.st_size and _signature(os.fstat(file_fd)) == _signature(info) ==
                                  _signature(os.stat(name, dir_fd=folder, follow_symlinks=False)), 'INVENTORY_COMPLETE_STABLE_FILE')
                    rows.append({'path': path, 'kind': 'file', 'bytes': used, 'sha256': digest.hexdigest()})
                    rounded = ((used + allocation_unit - 1) // allocation_unit) * allocation_unit
                    registry.need(info.st_blocks * 512 <= rounded + allocation_unit, 'INVENTORY_FILE_GEOMETRY')
                    total += max(rounded, info.st_blocks * 512) + allocation_unit
                finally:
                    _release_descriptors((file_fd,))
            registry.need(total <= 15_000_000_000, 'INVENTORY_TOTAL_ALLOCATION_BOUND')
        after = os.fstat(folder)
        registry.need(_signature(before) == _signature(after) and names == sorted(os.listdir(folder)), 'INVENTORY_TREE_CHANGED')
    try:
        root_id = _directory_id(os.fstat(fd))
        device = os.fstat(fd).st_dev
        walk(fd, '', 1)
        current = _owned_base(owned_base)
        try:
            registry.need(_directory_id(os.fstat(current)) == root_id == _directory_id(os.fstat(fd)), 'INVENTORY_ROOT_REPLACED')
        finally:
            _release_descriptors((current,))
        return {'members': sorted(rows, key=lambda row: row['path']), 'observed_allocation_bytes': total,
                'scientific_qualification': registry.QUALIFICATION, 'kernel_quota': 'NOT_ESTABLISHED_BY_INVENTORY'}
    finally:
        _release_descriptors((fd,))
