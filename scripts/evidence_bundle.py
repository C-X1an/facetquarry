"""Bounded directory-member transport for operator-selected completed evidence.

Run after measurement, outside evidence.py to avoid self-inclusion. Then invoke
verify through evidence.py and upload that receipt separately. Selection is an
operator assertion of completion/public safety, not a content privacy audit.
Exact member bytes are recoverable; no original ZIP/container identity is claimed.
Only Python's standard library is used. Failed partial bundles are retained.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import zlib

MAX_MEMBER = 64 * 1024 * 1024
MAX_MEMBERS = 50_000
MAX_ORIGINAL = 2_000_000_000
MAX_PAYLOAD = 24_000_000_000
MAX_OUTPUT = 400_000_000
MAX_MANIFEST = 32 * 1024 * 1024
XZ_MEMORY = 128 * 1024 * 1024
SCHEMA = 'facetquarry.directory-evidence.v1'
SCOPE = 'Exact original directory member bytes; no outer ZIP reconstruction or original artifact identity.'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def safe_name(name):
    require(isinstance(name, str) and bool(name), 'invalid member path')
    p = PurePosixPath(name)
    require(not p.is_absolute() and '\\' not in name and ':' not in name
            and '\x00' not in name and '..' not in p.parts, 'unsafe member path')
    require(all(x not in ('', '.') for x in name.rstrip('/').split('/')), 'noncanonical member path')
    require(len(name.encode('utf-16-le')) <= 60000, 'member path exceeds recovery bound')
    devices = {'CON', 'PRN', 'AUX', 'NUL'} | {a + b for a in ('COM', 'LPT') for b in '123456789¹²³'}
    for part in p.parts:
        require(part[-1] not in '. ' and not any(ord(c) < 32 or c in '<>"|?*' for c in part)
                and part.split('.')[0].upper() not in devices
                and len(part.encode('utf-16-le')) <= 510 and len(part.encode()) <= 255,
                'nonportable member component')
    return p


def no_links(path):
    """lstat every ancestor: Windows junctions are reparse points, not symlinks."""
    path = Path(os.path.abspath(path))
    for entry in reversed((path, *path.parents)):
        s = entry.lstat()
        require(not stat.S_ISLNK(s.st_mode)
                and not getattr(s, 'st_file_attributes', 0) & 0x400, 'symlink/reparse point refused')
    return path


def signature(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns,
            getattr(s, 'st_file_attributes', 0))


def descriptor_matches(s, expected):
    actual = signature(s)
    # CPython/Windows fstat and lstat expose different legacy st_ctime values.
    # Keep complete path metadata checks around the read; compare the stable
    # descriptor fields here, and always prove original bytes with SHA-256.
    if os.name == 'nt':
        return actual[:5] + actual[6:] == expected[:5] + expected[6:]
    return actual == expected


def regular_stat(path):
    no_links(path)
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode), 'nonregular member refused')
    return s


def selections(paths):
    require(isinstance(paths, list) and 0 < len(paths) <= MAX_MEMBERS, 'selection count outside admission')
    keys = set()
    for name in paths:
        safe_name(name)
        require(not name.endswith('/'), 'selection must be canonical without trailing slash')
        require(name.casefold() not in keys, 'duplicate/case-colliding selection')
        keys.add(name.casefold())
    for name in keys:
        parts = name.split('/')
        require(not any('/'.join(parts[:i]) in keys for i in range(1, len(parts))), 'overlapping selection')
    return keys


def inventory(root, paths):
    selections(paths)
    entries = []
    total = 0

    def visit(path, name):
        nonlocal total
        s = regular_stat(path)
        directory = stat.S_ISDIR(s.st_mode)
        safe_name(name)
        require(not name.endswith('.partial'), 'active partial packaging output refused')
        size = 0 if directory else s.st_size
        require(0 <= size <= MAX_MEMBER, 'member exceeds admission')
        total += size
        require(total <= MAX_ORIGINAL and len(entries) < MAX_MEMBERS, 'original total/count exceeds admission')
        entries.append((name + ('/' if directory else ''), signature(s), size))
        if directory:
            with os.scandir(path) as children:
                names = sorted(child.name for child in children)
            for child in names:
                visit(path / child, name + '/' + child)

    for name in sorted(paths):
        visit(root.joinpath(*PurePosixPath(name).parts), name)
    validate_layout([{'path': name, 'directory': name.endswith('/'), 'original_bytes': size}
                     for name, _, size in entries])
    return entries


def validate_layout(records):
    require(isinstance(records, list) and 0 < len(records) <= MAX_MEMBERS, 'member count outside admission')
    names = {}
    spellings = {}
    total = 0
    for r in records:
        p = safe_name(r['path'])
        require(type(r['directory']) is bool and r['path'].endswith('/') == r['directory'], 'invalid directory layout')
        require(type(r['original_bytes']) is int and 0 <= r['original_bytes'] <= MAX_MEMBER, 'original member exceeds admission')
        require(not r['directory'] or r['original_bytes'] == 0, 'nonempty directory')
        total += r['original_bytes']
        require(total <= MAX_ORIGINAL, 'original total exceeds admission')
        key = '/'.join(p.parts).casefold()
        require(key not in names, 'duplicate/case-colliding layout')
        names[key] = r['directory']
        for i in range(1, len(p.parts) + 1):
            prefix = '/'.join(p.parts[:i])
            require(spellings.setdefault(prefix.casefold(), prefix) == prefix, 'case-colliding ancestor layout')
    for key in names:
        parts = key.split('/')
        for i in range(1, len(parts)):
            require(names.get('/'.join(parts[:i]), True), 'file ancestor conflict')


def read_original(root, entry):
    name, expected, size = entry
    path = root.joinpath(*PurePosixPath(name).parts)
    s = regular_stat(path)
    require(signature(s) == expected, 'input metadata changed')
    if name.endswith('/'):
        return b''
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        require(descriptor_matches(os.fstat(stream.fileno()), expected), 'input changed before read')
        raw = stream.read(MAX_MEMBER + 1)
        require(len(raw) == size and descriptor_matches(os.fstat(stream.fileno()), expected), 'input changed during read')
    require(signature(regular_stat(path)) == expected, 'input changed after read')
    return raw


def gzip_header(raw):
    require(len(raw) >= 18 and raw[:3] == b'\x1f\x8b\x08' and raw[3] & 224 == 0, 'unsupported gzip header')
    pos, flags = 10, raw[3]
    if flags & 4:
        require(len(raw) >= pos + 2, 'truncated gzip extra')
        pos += 2 + int.from_bytes(raw[pos:pos + 2], 'little')
    for flag in (8, 16):
        if flags & flag:
            pos = raw.index(b'\0', pos) + 1
    if flags & 2:
        pos += 2
    require(10 <= pos <= 4096 and pos <= len(raw) - 8, 'invalid gzip header length')
    return raw[:pos]


def encoded(raw, name):
    if not name.endswith('.gz'):
        return raw, {'encoding': 'identity'}
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            payload = stream.read(MAX_MEMBER + 1)
        require(len(payload) <= MAX_MEMBER, 'expanded gzip exceeds bound')
        header, trailer = gzip_header(raw), raw[-8:]
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        require(header + c.compress(payload) + c.flush() + trailer == raw, 'gzip compressor differs')
        return payload, {'encoding': 'gzip-deflate-9', 'header': base64.b64encode(header).decode(),
                         'trailer': base64.b64encode(trailer).decode(), 'zlib_version': zlib.ZLIB_VERSION}
    except (OSError, ValueError, EOFError, zlib.error):
        return raw, {'encoding': 'identity'}


def decoded(payload, r):
    require(len(payload) == r['payload_bytes'] and sha(payload) == r['payload_sha256'], 'payload digest/length mismatch')
    if r['encoding'] == 'identity':
        raw = payload
    elif r['encoding'] == 'gzip-deflate-9':
        require(isinstance(r['header'], str) and len(r['header']) <= 5464
                and isinstance(r['trailer'], str) and len(r['trailer']) == 12, 'gzip recipe bounds invalid')
        header = base64.b64decode(r['header'], validate=True)
        trailer = base64.b64decode(r['trailer'], validate=True)
        require(len(header) <= 4096 and len(trailer) == 8, 'gzip recipe bounds invalid')
        c = zlib.compressobj(9, zlib.DEFLATED, -15)
        raw = header + c.compress(payload) + c.flush() + trailer
        require(gzip_header(raw) == header, 'invalid gzip recipe header')
    else:
        raise ValueError('unsupported payload encoding')
    require(len(raw) == r['original_bytes'] and sha(raw) == r['original_sha256'],
            'original member recovery mismatch (including compressor-version differences)')
    return raw


class LimitedWriter:
    def __init__(self, raw, limit):
        self.raw, self.limit, self.written = raw, limit, 0

    def write(self, data):
        require(self.written + len(data) <= self.limit, 'compressed output admission limit exceeded')
        count = self.raw.write(data)
        require(count == len(data), 'short output write')
        self.written += count
        return count

    def flush(self):
        self.raw.flush()


class XZReader:
    """Limit decoder memory, streamed bytes, and reject concatenated/trailing XZ."""
    def __init__(self, raw):
        self.raw = raw
        self.decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=XZ_MEMORY)
        self.total = 0

    def read(self, size):
        require(size >= 0, 'unbounded archive read refused')
        result = bytearray()
        while len(result) < size and not self.decoder.eof:
            chunk = self.raw.read(65536) if self.decoder.needs_input else b''
            require(chunk or not self.decoder.needs_input, 'truncated XZ stream')
            result.extend(self.decoder.decompress(chunk, max_length=size - len(result)))
        self.total += len(result)
        require(self.total <= MAX_PAYLOAD + MAX_MANIFEST + (MAX_MEMBERS + 1) * 1024 + 10240,
                'archive expansion exceeds admission')
        if self.decoder.eof:
            require(not self.decoder.unused_data and not self.raw.read(1), 'trailing compressed data')
        return bytes(result)


def tar_item(tar, name, data):
    item = tarfile.TarInfo(name)
    item.size, item.mode, item.mtime = len(data), 0o600, 0
    tar.addfile(item, io.BytesIO(data))


def identity(source, commit, run_id):
    require(isinstance(source, str) and re.fullmatch('[0-9a-f]{64}', source), 'source must be a SHA-256 identity')
    require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', commit), 'commit must be a full Git identity')
    require(isinstance(run_id, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', run_id), 'invalid run identity')


def pack(inputroot, output, source, commit, run_id, paths, preset=6):
    identity(source, commit, run_id)
    require(type(preset) is int and preset in (1, 3, 6), 'unsupported compression preset')
    root = no_links(inputroot)
    require(root.is_dir(), 'input root is not a directory')
    output = Path(os.path.abspath(output))
    no_links(output.parent)
    partial = output.with_name(output.name + '.partial')
    diagnostics = output.with_name(output.name + '.failure.json')
    require(not any(os.path.lexists(p) for p in (output, partial, diagnostics)), 'output already exists')
    entries = inventory(root, paths)
    for name in paths:
        selected = root.joinpath(*PurePosixPath(name).parts)
        require(not output.is_relative_to(selected) and not partial.is_relative_to(selected)
                and not diagnostics.is_relative_to(selected), 'output must be outside selected input paths')
    records, total_payload = [], 0
    for index, entry in enumerate(entries):
        name, _, size = entry
        raw = read_original(root, entry)
        payload, recipe = encoded(raw, name)
        total_payload += len(payload)
        require(total_payload <= MAX_PAYLOAD, 'payload total exceeds admission')
        records.append({'path': name, 'directory': name.endswith('/'), 'original_bytes': size,
                        'original_sha256': sha(raw), 'payload_name': f'payload/{index:06d}',
                        'payload_bytes': len(payload), 'payload_sha256': sha(payload), **recipe})
    manifest = {'schema': SCHEMA, 'evidence_type': 'lossless_directory_member_transport',
                'source': source, 'commit': commit, 'run_id': run_id, 'selected_paths': sorted(paths),
                'selection_assertion': 'Operator selected completed public-safe result paths.',
                'codec_sha256': file_sha(Path(__file__)), 'zlib_version': zlib.ZLIB_VERSION,
                'compression': {'preset': preset, 'dictionary_bytes': (16 if preset < 6 else 64) * 1024 * 1024},
                'members': records, 'original_member_bytes': sum(e[2] for e in entries),
                'streamed_payload_bytes': total_payload, 'recovery_scope': SCOPE,
                'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    metadata = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    require(len(metadata) <= MAX_MANIFEST, 'manifest exceeds admission')
    try:
        with partial.open('xb') as raw_output:
            with lzma.LZMAFile(LimitedWriter(raw_output, MAX_OUTPUT), 'wb', check=lzma.CHECK_SHA256,
                               filters=[{'id': lzma.FILTER_LZMA2, 'preset': preset, 'dict_size': (16 if preset < 6 else 64) * 1024 * 1024}]) as compressed:
                with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                    tar_item(tar, 'manifest.json', metadata)
                    for entry, record in zip(entries, records):
                        raw = read_original(root, entry)
                        require(sha(raw) == record['original_sha256'], 'input SHA changed between passes')
                        payload, recipe = encoded(raw, entry[0])
                        require(sha(payload) == record['payload_sha256'] and recipe['encoding'] == record['encoding'],
                                'payload changed between passes')
                        tar_item(tar, record['payload_name'], payload)
        require(inventory(root, paths) == entries, 'selected input layout/metadata changed')
        verify(partial)
        # Hard-link promotion has no overwrite race; unlike replace/rename on POSIX.
        os.link(partial, output)
        partial.unlink()
    except Exception as exc:
        with diagnostics.open('x', encoding='utf-8') as stream:
            json.dump({'status': 'FAIL', 'error_type': type(exc).__name__, 'error': str(exc),
                       'partial_bundle': partial.name, 'originals_deleted': False}, stream)
        raise
    return {'status': 'PASS', 'bundle_bytes': output.stat().st_size, 'bundle_sha256': file_sha(output),
            'member_count': len(records), 'original_member_bytes': manifest['original_member_bytes'],
            'streamed_payload_bytes': total_payload,
            'gzip_recipe_members': sum(r['encoding'] != 'identity' for r in records), 'recovery_scope': SCOPE}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate manifest key')
        result[key] = value
    return result


def transport_item(reader, name, limit):
    # Parse one fixed header ourselves. tarfile's general reader accepts hidden
    # PAX/GNU extension records and can allocate their attacker-declared sizes
    # before the caller sees a TarInfo. This transport emits only USTAR regulars.
    header = reader.read(512)
    require(len(header) == 512 and any(header), 'missing transport member')
    item = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
    require(item.type == tarfile.REGTYPE and item.name == name and not item.linkname
            and 0 <= item.size <= limit, 'payload sequence/type/size mismatch')
    data = reader.read(item.size)
    require(len(data) == item.size, 'truncated transport member')
    padding = reader.read((-item.size) % 512)
    require(not any(padding) and len(padding) == (-item.size) % 512, 'invalid member padding')
    return data


def selected_layout(paths, records):
    selections(paths)
    selected = set(paths)
    members = {r['path'].rstrip('/'): r['directory'] for r in records}
    require(all(name in members for name in paths), 'selected path missing from manifest')
    for name in members:
        parts = name.split('/')
        ancestors = ('/'.join(parts[:i]) for i in range(1, len(parts)))
        require(name in selected or any(a in selected and members[a] for a in ancestors),
                'member outside selected layout')


def verify_stream(reader, output):
    manifest = json.loads(transport_item(reader, 'manifest.json', MAX_MANIFEST), object_pairs_hook=unique_object)
    require(manifest['schema'] == SCHEMA and manifest['evidence_type'] == 'lossless_directory_member_transport'
            and manifest['recovery_scope'] == SCOPE, 'invalid manifest schema')
    identity(manifest['source'], manifest['commit'], manifest['run_id'])
    records = manifest['members']
    validate_layout(records)
    selected_layout(manifest['selected_paths'], records)
    total, payload_total = 0, 0
    # Admit all metadata/totals before recovery writes.
    for index, r in enumerate(records):
        require(type(r['payload_bytes']) is int and 0 <= r['payload_bytes'] <= MAX_MEMBER, 'payload exceeds admission')
        require(r['payload_name'] == f'payload/{index:06d}', 'invalid payload layout')
        require(all(isinstance(r[k], str) and re.fullmatch('[0-9a-f]{64}', r[k])
                    for k in ('payload_sha256', 'original_sha256')), 'invalid digest metadata')
        require(not r['directory'] or r['payload_bytes'] == 0, 'nonempty directory payload')
        total += r['original_bytes']
        payload_total += r['payload_bytes']
    require(type(manifest['original_member_bytes']) is int and total == manifest['original_member_bytes']
            and type(manifest['streamed_payload_bytes']) is int
            and payload_total == manifest['streamed_payload_bytes'] <= MAX_PAYLOAD, 'manifest total mismatch')
    if output is not None:
        output.mkdir()
    for r in records:
        raw = decoded(transport_item(reader, r['payload_name'], r['payload_bytes']), r)
        if output is not None:
            target = output.joinpath(*PurePosixPath(r['path']).parts)
            if r['directory']:
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:
                    stream.write(raw)
    require(reader.read(1024) == bytes(1024), 'unexpected extra payload or missing tar terminator')
    padding = 0
    while tail := reader.read(65536):
        padding += len(tail)
        require(padding <= 10240 and not any(tail), 'unexpected trailing archive data')
    return {'status': 'PASS', 'member_count': len(records), 'original_member_bytes': total,
            'streamed_payload_bytes': payload_total, 'source': manifest['source'],
            'commit': manifest['commit'], 'run_id': manifest['run_id'], 'recovery_scope': SCOPE}


def verify(bundle, output=None):
    bundle = no_links(bundle)
    require(bundle.is_file() and bundle.stat().st_size <= MAX_OUTPUT, 'bundle size exceeds admission')
    if output is not None:
        # Verify the full bundle before creating even a partial recovery tree.
        verify(bundle)
        output = Path(os.path.abspath(output))
        no_links(output.parent)
        require(not os.path.lexists(output), 'recovery directory already exists')
    with bundle.open('rb') as compressed:
        return verify_stream(XZReader(compressed), output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('pack')
    p.add_argument('inputroot', type=Path)
    p.add_argument('output', type=Path)
    for name in ('source', 'commit', 'run-id'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--preset', type=int, choices=(1, 3, 6), default=3)
    p.add_argument('--paths', nargs='+', required=True, help='Explicit relative completed result files/directories')
    for action in ('verify', 'recover'):
        p = sub.add_parser(action)
        p.add_argument('bundle', type=Path)
        if action == 'recover':
            p.add_argument('output', type=Path)
    args = parser.parse_args()
    result = (pack(args.inputroot, args.output, args.source, args.commit, args.run_id, args.paths, args.preset)
              if args.action == 'pack' else verify(args.bundle, getattr(args, 'output', None)))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
