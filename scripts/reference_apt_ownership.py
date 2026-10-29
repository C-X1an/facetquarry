"""Bounded ownership handoff for this producer's fresh, exact APT cache only.

APT's root coordinator can create metadata even when its downloader uses the
correct ordinary account. Never relax trim ownership: inspect all cache members
first, then fchown only individually pinned root:root members in this closed
policy. No deletion, recursive chown, links, installation or authentication change.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_ARCHIVES = 128
MAX_ENTRIES = MAX_ARCHIVES * 2 + 10
MAX_REQUEST_BYTES = 65_536
MAX_FILE_BYTES = 256_000_000
MAX_TOTAL_BYTES = 1_000_000_000
METADATA = {'partial': 'directory', 'log': 'directory', 'lock': 'file',
            'extended_states': 'file', 'pkgcache.bin': 'file', 'srcpkgcache.bin': 'file',
            'log/history.log': 'file', 'log/terminal.log': 'file', 'log/eipp.log.xz': 'file'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ordinary_account(*, uid=None, gid=None, euid=None, egid=None,
                     lookup_uid=None, lookup_name=None):
    if uid is None: uid = os.getuid()
    if gid is None: gid = os.getgid()
    if euid is None: euid = os.geteuid()
    if egid is None: egid = os.getegid()
    require(type(uid) is int and type(gid) is int and uid > 0 and gid > 0
            and uid == euid and gid == egid, 'APT requires matching ordinary real/effective UID/GID')
    if lookup_uid is None or lookup_name is None:
        import pwd
        lookup_uid, lookup_name = pwd.getpwuid, pwd.getpwnam
    try:
        record = lookup_uid(uid)
        name = record.pw_name
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}', name),
                'APT sandbox account name is unsafe or numeric')
        reverse = lookup_name(name)
        require(record.pw_uid == reverse.pw_uid == uid and record.pw_gid == reverse.pw_gid == gid
                and reverse.pw_name == name, 'APT sandbox account UID/GID roundtrip differs')
    except KeyError as error:
        raise ValueError('APT sandbox account is not present') from error
    return {'name': name, 'uid': uid, 'gid': gid}


def archive_policy(planned):
    require(isinstance(planned, list) and len(planned) <= MAX_ARCHIVES, 'APT archive count exceeds admission')
    policy = {}
    for item in planned:
        require(isinstance(item, dict), 'APT plan entry is not an object')
        name, size = item.get('filename'), item.get('size')
        require(isinstance(name, str) and len(name) <= 240
                and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+%:~\-]*\.deb', name)
                and name not in policy, 'APT archive basename is unsafe or repeated')
        require(type(size) is int and 0 < size <= 200_000_000, 'APT archive size is outside admission')
        policy[name] = size
    require(sum(policy.values()) <= 200_000_000, 'APT archive bytes exceed unchanged 200MB admission')
    return policy


def path_rule(path, archives):
    if path in METADATA:
        return METADATA[path], MAX_FILE_BYTES
    if path in archives:
        return 'file', archives[path]
    if path.startswith('partial/') and path[8:] in archives:
        return 'file', archives[path[8:]]
    raise ValueError('unexpected APT member: ' + str(path)[:300])


def facts(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': info.st_mode,
            'uid': info.st_uid, 'gid': info.st_gid, 'nlink': info.st_nlink,
            'bytes': info.st_size, 'allocated': getattr(info, 'st_blocks', 0) * 512,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def anchor_identity(node):
    return tuple(node[key] for key in ('device', 'inode', 'mode', 'uid', 'gid'))


def validate_node(path, node, archives, device, uid, gid, *, allow_root=True, partial_binding=None):
    kind, limit = path_rule(path, archives)
    require(node['device'] == device, 'APT member crosses filesystem: ' + path)
    require((stat.S_ISDIR(node['mode']) if kind == 'directory' else stat.S_ISREG(node['mode']))
            and (kind == 'directory' or node['nlink'] == 1), 'APT member type/link count refused: ' + path)
    require(not node['mode'] & 0o7022, 'APT member special/writable mode refused: ' + path)
    require(0 <= node['bytes'] <= limit and node['allocated'] >= 0, 'APT member exceeds size admission: ' + path)
    if (node['uid'], node['gid']) == (uid, gid):
        return False
    if allow_root and path == 'partial' and (node['uid'], node['gid']) == (uid, 0):
        pin = partial_binding
        require(isinstance(pin, dict) and stat.S_ISDIR(pin['mode'])
                and not pin['mode'] & 0o7022 and (pin['uid'], pin['gid']) == (uid, gid)
                and (pin['device'], pin['inode']) == (device, node['inode'])
                and pin['inode'] > 0 and pin['nlink'] == node['nlink'] == 2
                and stat.S_IMODE(node['mode']) == 0o700,
                'APT partial directory is not the pinned private ordinary inode')
        return True
    require(allow_root and (node['uid'], node['gid']) == (0, 0), 'APT member ownership refused: ' + path)
    return True


def apt_request(root, account, planned, max_bytes):
    root = Path(root)
    require(root.is_absolute() and root.name == 'apt' and root.parent.name == 'reference-guest'
            and '..' not in root.parts, 'APT root is not the exact fresh producer cache')
    require(type(max_bytes) is int and 0 < max_bytes <= MAX_TOTAL_BYTES, 'APT total admission is outside limit')
    # Capture before each APT command, never infer this pin from post-command
    # mixed ownership. A missing partial cannot authorize a later mixed inode.
    partial = root / 'partial'
    pin = facts(partial.lstat()) if os.path.lexists(partial) else None
    return {'schema_version': 1, 'root': str(root), 'account': dict(account), 'partial_binding': pin,
            'archives': archive_policy(planned), 'max_bytes': max_bytes,
            'anchors': {label: facts(path.lstat()) for label, path in
                        (('volume', root.parent.parent), ('parent', root.parent), ('root', root))}}


def require_root():
    require(sys.platform == 'linux' and os.geteuid() == 0
            and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
            and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'fchown'),
            'APT ownership handoff requires privileged Linux directory descriptors')


def verify_requested_account(account):
    require(isinstance(account, dict) and set(account) == {'name', 'uid', 'gid'}, 'APT account request differs')
    checked = ordinary_account(uid=account['uid'], gid=account['gid'],
                               euid=account['uid'], egid=account['gid'])
    require(checked == account, 'APT requested account name differs from system account')


def open_anchors(request):
    root = Path(request['root'])
    require(root.is_absolute() and root.name == 'apt' and root.parent.name == 'reference-guest'
            and '..' not in root.parts, 'APT root path differs')
    account = request['account']
    anchors = request['anchors']
    require(isinstance(anchors, dict) and set(anchors) == {'volume', 'parent', 'root'}, 'APT anchors differ')
    paths = {root.parent.parent: 'volume', root.parent: 'parent', root: 'root'}
    descriptors, opened = [], {}
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(root.anchor, flags)
        descriptors.append(descriptor)
        path = Path(root.anchor)
        for part in root.parts[1:]:
            descriptor = os.open(part, flags, dir_fd=descriptor)
            descriptors.append(descriptor)
            path /= part
            if path in paths:
                label = paths[path]
                observed = facts(os.fstat(descriptor))
                require(anchor_identity(observed) == anchor_identity(anchors[label]), 'APT anchor identity changed: ' + label)
                require((observed['uid'], observed['gid']) == (account['uid'], account['gid'])
                        and not observed['mode'] & 0o7022, 'APT anchor ownership/mode refused: ' + label)
                require(observed['device'] == anchors['volume']['device'], 'APT anchor crosses filesystem')
                if label == 'parent':
                    require(stat.S_IMODE(observed['mode']) == 0o700, 'APT setup parent is not private')
                opened[label] = descriptor
        require(set(opened) == set(paths.values()), 'APT anchor traversal incomplete')
        return descriptors, opened
    except BaseException:
        for descriptor in reversed(descriptors): os.close(descriptor)
        raise


def inventory(rootfd, request, output, *, allow_root):
    uid, gid = request['account']['uid'], request['account']['gid']
    device = request['anchors']['root']['device']
    charged = 0
    def visit(descriptor, prefix=''):
        nonlocal charged
        # Do not materialize an unbounded directory before applying the count.
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                require(len(output) + len(names) < MAX_ENTRIES, 'APT entry count exceeds admission')
                names.append(entry.name)
        for name in sorted(names):
            path = prefix + name
            node = facts(os.stat(name, dir_fd=descriptor, follow_symlinks=False))
            require(len(output) < MAX_ENTRIES, 'APT entry count exceeds admission')
            output.append({'path': path, **node})
            validate_node(path, node, request['archives'], device, uid, gid, allow_root=allow_root,
                          partial_binding=request.get('partial_binding'))
            charged += max(node['bytes'], node['allocated'])
            require(charged <= request['max_bytes'], 'APT cumulative bytes exceed admission')
            if stat.S_ISDIR(node['mode']):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    require(facts(os.fstat(child)) == node, 'APT directory substituted while opening: ' + path)
                    visit(child, path + '/')
                    require(facts(os.fstat(child)) == node, 'APT directory changed during inventory: ' + path)
                finally:
                    os.close(child)
    visit(rootfd)
    return charged


def open_member(rootfd, path, expected):
    descriptor, owned = rootfd, []
    parts = path.split('/')
    try:
        for index, name in enumerate(parts):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(parts) - 1 or stat.S_ISDIR(expected[path]['mode']):
                flags |= os.O_DIRECTORY
            child = os.open(name, flags, dir_fd=descriptor)
            owned.append(child)
            prefix = '/'.join(parts[:index + 1])
            require(facts(os.fstat(child)) == expected[prefix], 'APT descriptor substituted: ' + prefix)
            descriptor = child
        return descriptor, owned
    except BaseException:
        for descriptor in reversed(owned): os.close(descriptor)
        raise


def chown_descriptor(descriptor, before, uid, gid):
    require(facts(os.fstat(descriptor)) == before, 'APT inode changed before individual fchown')
    os.fchown(descriptor, uid, gid)
    after = facts(os.fstat(descriptor))
    require((after['uid'], after['gid']) == (uid, gid)
            and all(after[key] == before[key] for key in before if key not in ('uid', 'gid', 'ctime_ns')),
            'APT inode changed during individual fchown')
    return after


def normalize(request, result=None):
    require_root()
    require(isinstance(request, dict) and request.get('schema_version') == 1, 'APT request schema differs')
    verify_requested_account(request['account'])
    policy = archive_policy([{'filename': name, 'size': size} for name, size in request['archives'].items()])
    require(policy == request['archives'] and type(request['max_bytes']) is int
            and 0 < request['max_bytes'] <= MAX_TOTAL_BYTES, 'APT request admission differs')
    result = {} if result is None else result
    result.update(schema_version=1, status='PREPARING', before=[], normalized=[], after=[])
    descriptors, anchors = open_anchors(request)
    try:
        result['before_bytes'] = inventory(anchors['root'], request, result['before'], allow_root=True)
        expected = {entry['path']: {key: value for key, value in entry.items() if key != 'path'}
                    for entry in result['before']}
        uid, gid = request['account']['uid'], request['account']['gid']
        for entry in result['before']:
            path = entry['path']
            node = expected[path]
            if (node['uid'], node['gid']) == (uid, gid):
                continue
            # Reopen the absolute anchor chain before every mutation. The helper
            # independently verifies paths, ownership, device and pinned inodes.
            fresh, _ = open_anchors(request)
            for descriptor in reversed(fresh): os.close(descriptor)
            descriptor, owned = open_member(anchors['root'], path, expected)
            try:
                after = chown_descriptor(descriptor, node, uid, gid)
                expected[path] = after
                result['normalized'].append({'path': path, 'before': node, 'after': after})
            finally:
                for descriptor in reversed(owned): os.close(descriptor)
        fresh, _ = open_anchors(request)
        for descriptor in reversed(fresh): os.close(descriptor)
        result['after_bytes'] = inventory(anchors['root'], request, result['after'], allow_root=False)
        observed = {entry['path']: {key: value for key, value in entry.items() if key != 'path'}
                    for entry in result['after']}
        require(observed == expected, 'APT membership or inode facts changed after handoff')
        result['status'] = 'PASS'
        return result
    finally:
        for descriptor in reversed(descriptors): os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', required=True)
    args = parser.parse_args()
    result = {'schema_version': 1, 'status': 'FAIL'}
    try:
        require(len(args.request.encode()) <= MAX_REQUEST_BYTES, 'APT ownership request exceeds bound')
        normalize(json.loads(args.request), result)
    except Exception as error:
        result.update(status='FAIL', error=(type(error).__name__ + ': ' + str(error))[:1000])
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
