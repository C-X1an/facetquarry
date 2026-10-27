"""Preserve the complete current corpus after the caller proves writers closed.

This is a byte-retention helper, not evidence that any fuzz campaign ran. The
capacity caller authenticates the live run and retains errors and diagnostics.
Linux operations use owned directory descriptors; Windows supports tiny local
fixture controls and does not qualify the production Linux capacity workflow.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import reference_preflight as preflight

MAX_BYTES = 35_000_000
LEGACY_MAX_BYTES = 100_000_000
MAX_FILES = 2999
MAX_ENTRIES = 9999
MAX_MEMBER = 64 * 1024 * 1024
MAX_MANIFEST = 6_000_000
MAX_PATH = 4096
ROOTS = (('cache', '.cache/go-build/fuzz'),
         ('engine-testdata', 'internal/engine/testdata/fuzz'))
OUTPUT = '.local/reference-capacity-fuzz'
SCOPE = ('Complete current corpus bytes only; no campaign execution, historical '
         'corpus recovery or AC-015 qualification is established by this helper.')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _uid():
    return os.getuid() if hasattr(os, 'getuid') else 0


def _normalized(value):
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts
            and path == Path(os.path.normpath(str(path))),
            'fuzz path must be absolute and normalized')
    return path


def _context(value):
    require(type(value) is dict, 'fuzz run context must be a complete capacity context')
    required = {'repository', 'repository_id', 'commit', 'git_status', 'source',
                'github_run_id', 'github_run_attempt', 'job', 'profile'}
    require(set(value) == required
            and value.get('repository') == 'C-X1an/facetquarry'
            and type(value.get('repository_id')) is int and value['repository_id'] == 1430604581
            and value.get('job') == 'reference_capacity'
            and value.get('profile') == 'supported-verification-capacity-v1'
            and value.get('git_status') == '', 'fuzz capacity context identity differs')
    for key, pattern in (('commit', '[0-9a-f]{40}'), ('source', '[0-9a-f]{64}'),
                         ('github_run_id', '[1-9][0-9]*'), ('github_run_attempt', '[1-9][0-9]*')):
        require(type(value[key]) is str and re.fullmatch(pattern, value[key]),
                'fuzz capacity context field differs: ' + key)
    raw = _encode(value)
    require(len(raw) <= 4096, 'fuzz capacity context exceeds bound')
    return json.loads(raw)


def _identity(info):
    return [*preflight.stamp(info), info.st_uid,
            getattr(info, 'st_file_attributes', 0), getattr(info, 'st_reparse_tag', 0)]


def _key(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            getattr(info, 'st_file_attributes', 0), getattr(info, 'st_reparse_tag', 0))


def _descriptor_key_matches(info, expected):
    # Windows fstat does not expose every pathname attribute. Path checks retain
    # all attributes; the production Linux descriptor comparison remains exact.
    actual, wanted = _key(info), _key(expected)
    return actual[:4] == wanted[:4] if os.name == 'nt' else actual == wanted


def _encode(value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
    require(len(raw) <= MAX_MANIFEST, 'fuzz manifest exceeds byte bound')
    return raw


class _Binding:
    def __init__(self, volume, project):
        self.volume, self.project = _normalized(volume), _normalized(project)
        temporary = _normalized(os.environ.get('RUNNER_TEMP', ''))
        require(self.volume == temporary / 'facetquarry-capacity'
                and self.project == self.volume / 'source',
                'fuzz requires the exact owned capacity volume/source paths')
        self.owner, self.known = _uid(), {}
        try:
            self.device = preflight.checked(self.volume).st_dev
        except RuntimeError as error:
            raise ValueError(str(error)) from error
        for path in (self.volume, self.project, self.project / '.local'):
            require(stat.S_ISDIR(self.check(path).st_mode), 'fuzz owned root is not a directory')

    def check(self, path):
        path = _normalized(path)
        require(path == self.volume or path.is_relative_to(self.volume), 'fuzz path escapes owned volume')
        try:
            preflight.checked(path)
        except RuntimeError as error:
            raise ValueError(str(error)) from error
        parts = path.relative_to(self.volume).parts
        current = self.volume
        for number in range(len(parts) + 1):
            if number:
                current = current / parts[number - 1]
            info = current.lstat()
            require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_reparse_tag', 0)
                    and not getattr(info, 'st_file_attributes', 0) & 0x400,
                    'linked/reparse fuzz path refused')
            require(info.st_dev == self.device and info.st_uid == self.owner,
                    'fuzz path device or UID differs from owned volume')
            require(stat.S_ISDIR(info.st_mode) or current == path and stat.S_ISREG(info.st_mode),
                    'fuzz path is not a directory or regular file')
            require(not stat.S_ISREG(info.st_mode) or info.st_nlink == 1,
                    'hardlinked fuzz member refused')
            expected = self.known.setdefault(str(current), _key(info))
            require(_key(info) == expected, 'fuzz path identity substituted')
        return info

    @contextmanager
    def parent(self, path):
        """Keep each Linux parent anchored; never traverse a substituted link."""
        self.check(path.parent)
        secure = os.name == 'posix' and os.open in os.supports_dir_fd and hasattr(os, 'O_NOFOLLOW')
        if not secure:
            require(os.name == 'nt', 'secure fuzz directory descriptors unavailable')
            yield None
            self.check(path.parent)
            return
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(self.volume, flags)
        try:
            require(_key(os.fstat(descriptor)) == _key(self.check(self.volume)),
                    'fuzz volume substituted while opening')
            current = self.volume
            for name in path.parent.relative_to(self.volume).parts:
                current = current / name
                expected = self.check(current)
                child = os.open(name, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                require(_key(os.fstat(descriptor)) == _key(expected),
                        'fuzz directory substituted while opening')
            yield descriptor
            require(_key(os.fstat(descriptor)) == _key(self.check(path.parent)),
                    'fuzz directory pathname substituted')
        finally:
            os.close(descriptor)

    def mkdir(self, path):
        with self.parent(path) as parent:
            if parent is None:
                os.mkdir(path, 0o700)
            else:
                os.mkdir(path.name, 0o700, dir_fd=parent)
        require(stat.S_ISDIR(self.check(path).st_mode), 'fuzz output directory differs')

    @contextmanager
    def directory(self, path):
        info = self.check(path)
        require(stat.S_ISDIR(info.st_mode), 'fuzz enumeration path is not a directory')
        with self.parent(path) as parent:
            if parent is None:
                yield path
            else:
                descriptor = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=parent)
                try:
                    require(_key(os.fstat(descriptor)) == _key(info),
                            'fuzz enumeration directory substituted')
                    yield descriptor
                finally:
                    os.close(descriptor)
            require(_identity(self.check(path)) == _identity(info),
                    'fuzz directory changed during complete enumeration')

    @contextmanager
    def opened(self, path, *, original=None):
        flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) if original is not None else os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        if original is not None:
            require(_identity(self.check(path)) == _identity(original), 'fuzz file changed before opening')
        with self.parent(path) as parent:
            descriptor = os.open(path if parent is None else path.name, flags, 0o600,
                                 **({} if parent is None else {'dir_fd': parent}))
            try:
                info = os.fstat(descriptor)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and info.st_uid == self.owner and info.st_dev == self.device,
                        'fuzz descriptor is not an owned single-link regular file')
                if original is not None:
                    require(preflight.descriptor_matches(info, preflight.stamp(original)),
                            'fuzz file substituted while opening')
                yield descriptor
                observed = self.check(path)
                require(_descriptor_key_matches(os.fstat(descriptor), observed),
                        'fuzz file pathname substituted')
                if original is not None:
                    require(preflight.descriptor_matches(os.fstat(descriptor), preflight.stamp(original))
                            and _identity(observed) == _identity(original), 'fuzz file changed while reading')
            finally:
                os.close(descriptor)


def _read(binding, path, info, target=None):
    require(0 <= info.st_size <= MAX_MEMBER, 'fuzz member exceeds byte admission')
    digest, count = hashlib.sha256(), 0
    with ExitStack() as stack:
        source = stack.enter_context(binding.opened(path, original=info))
        destination = stack.enter_context(binding.opened(target)) if target is not None else None
        while block := os.read(source, min(65536, info.st_size - count + 1)):
            count += len(block)
            require(count <= info.st_size <= MAX_MEMBER, 'fuzz member grew beyond byte admission')
            digest.update(block)
            if destination is not None:
                view = memoryview(block)
                while view:
                    written = os.write(destination, view)
                    require(written > 0, 'fuzz copy made no write progress')
                    view = view[written:]
        require(count == info.st_size, 'fuzz member byte count changed')
        if destination is not None:
            os.fsync(destination)
    return digest.hexdigest()


def _snapshot(binding, roots, maximum):
    observations, entries, seen, total, count = [], [], set(), 0, 0
    stack = []
    for label, root in reversed(roots):
        try:
            info = binding.check(root)
        except FileNotFoundError:
            observations.append({'label': label, 'path': root.relative_to(binding.project).as_posix(), 'present': False})
            continue
        require(stat.S_ISDIR(info.st_mode), 'fuzz root is not a directory')
        observations.append({'label': label, 'path': root.relative_to(binding.project).as_posix(), 'present': True})
        stack.append((label, root, root))
    while stack:
        label, root, path = stack.pop()
        info = binding.check(path)
        name = label if path == root else label + '/' + path.relative_to(root).as_posix()
        require(len(name.encode('utf-8')) <= MAX_PATH and len(Path(name).parts) <= 64,
                'fuzz member path exceeds bound')
        require(len(entries) < MAX_ENTRIES and (info.st_dev, info.st_ino) not in seen,
                'fuzz complete entry bound exceeded or duplicate inode')
        seen.add((info.st_dev, info.st_ino))
        row = {'path': name, 'identity': _identity(info),
               'kind': 'directory' if stat.S_ISDIR(info.st_mode) else 'file'}
        if row['kind'] == 'directory':
            names = []
            with binding.directory(path) as directory, os.scandir(directory) as children:
                for child in children:
                    require(len(names) + len(stack) + len(entries) < MAX_ENTRIES,
                            'fuzz complete directory enumeration bound exceeded')
                    names.append(child.name)
            stack.extend((label, root, path / name) for name in reversed(sorted(names)))
        else:
            count += 1
            total += info.st_size
            require(count <= MAX_FILES and 0 <= info.st_size <= MAX_MEMBER and total <= maximum,
                    'fuzz complete corpus file/byte admission exceeded')
            row.update(bytes=info.st_size, sha256=_read(binding, path, info))
        entries.append(row)
    return {'roots': sorted(observations, key=lambda row: row['label']),
            'entries': entries, 'count': count, 'bytes': total}


def _content(snapshot):
    return ([(row['label'], row['present']) for row in snapshot['roots']],
            [(row['path'], row['kind'], row.get('bytes'), row.get('sha256'))
             for row in snapshot['entries']])


def _copy(binding, source, target, row):
    info = binding.check(source)
    require(_identity(info) == row['identity'], 'fuzz source identity changed before copy')
    require(_read(binding, source, info, target) == row['sha256'], 'fuzz copy source SHA differs')


def _output_layout(binding, output, snapshot, *, manifest=False):
    expected = {row['label'] for row in snapshot['roots'] if row['present']}
    if manifest:
        expected.add('manifest.json')
    found = set()
    with binding.directory(output) as directory, os.scandir(directory) as children:
        for child in children:
            require(child.name in expected and child.name not in found,
                    'unlisted fuzz preservation output member')
            binding.check(output / child.name)
            found.add(child.name)
    require(found == expected, 'complete fuzz preservation output membership differs')


def preserve(volume, project, *, closed_writer_proof, run_context, max_bytes=MAX_BYTES):
    """Return PASS only for complete stable current bytes; propagate every error.

    The caller must supply its current positive closed-writer observation and
    retain any raised failure while still capturing available .local diagnostics.
    Partial copies are deliberately left in place on failure, never overwritten.
    The cap includes copied corpus plus its manifest; the caller's existing
    aggregate metadata cap still applies independently to all diagnostics.
    """
    require(closed_writer_proof is True, 'fuzz preservation requires positive closed-writer proof')
    require(type(max_bytes) is int and 0 < max_bytes <= min(MAX_BYTES, LEGACY_MAX_BYTES),
            'fuzz maximum exceeds capacity/legacy byte admission')
    context = _context(run_context)
    binding = _Binding(volume, project)
    output = binding.project / OUTPUT
    require(not os.path.lexists(output), 'fuzz preservation output already exists')
    roots = [(label, binding.project / relative) for label, relative in ROOTS]
    before = _snapshot(binding, roots, max_bytes)
    binding.mkdir(output)
    root_by_label = dict(roots)
    for row in before['entries']:
        target = output / row['path']
        if row['kind'] == 'directory':
            binding.mkdir(target)
        else:
            parts = Path(row['path']).parts
            _copy(binding, root_by_label[parts[0]].joinpath(*parts[1:]), target, row)
    copied_roots = [(label, output / label) for label, _ in ROOTS]
    _output_layout(binding, output, before)
    copied = _snapshot(binding, copied_roots, max_bytes)
    require(_content(copied) == _content(before), 'preserved fuzz bytes or complete membership differ')
    require(_snapshot(binding, roots, max_bytes) == before,
            'live fuzz corpus identity/bytes/membership changed during preservation')
    manifest = {'schema_version': 1, 'evidence_type': 'reference_capacity_fuzz_snapshot',
                'run_context': context, 'closed_writer_proof': True,
                'volume': str(binding.volume), 'project': str(binding.project),
                'snapshot': before, 'preserved': copied, 'campaign_qualified': False, 'scope': SCOPE}
    raw = _encode(manifest)
    require(before['bytes'] + len(raw) <= max_bytes, 'complete fuzz copies and manifest exceed byte admission')
    manifest_path = output / 'manifest.json'
    with binding.opened(manifest_path) as descriptor:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, 'fuzz manifest made no write progress')
            view = view[written:]
        os.fsync(descriptor)
    manifest_sha = hashlib.sha256(raw).hexdigest()
    require(_read(binding, manifest_path, binding.check(manifest_path)) == manifest_sha,
            'fuzz manifest stored bytes differ')
    _output_layout(binding, output, before, manifest=True)
    require(_snapshot(binding, copied_roots, max_bytes) == copied,
            'preserved fuzz identity/bytes/membership changed')
    require(_snapshot(binding, roots, max_bytes) == before,
            'live fuzz corpus identity/bytes/membership changed before completion')
    return {'schema_version': 1, 'status': 'PASS', 'run_context': context,
            'closed_writer_proof': True, 'count': before['count'], 'bytes': before['bytes'],
            'retained_logical_bytes': before['bytes'] + len(raw),
            'manifest': manifest_path.relative_to(binding.project).as_posix(),
            'manifest_sha256': manifest_sha, 'snapshot_sha256': hashlib.sha256(_encode(before)).hexdigest(),
            'roots': before['roots'], 'corpus_observed': before['count'] > 0,
            'campaign_qualified': False, 'scope': SCOPE}
