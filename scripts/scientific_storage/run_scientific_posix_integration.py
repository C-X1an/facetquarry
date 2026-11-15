"""Pre-import admission for an independently reviewed flat POSIX source packet.

This file is SOURCE ONLY. A context document is an explicit caller declaration,
not evidence that a kernel quota exists. The external runner must establish and
retain enforcement, all-allocation inventory, full failure transport and pins.
"""
import sys

# sys is already loaded by the interpreter. Refuse unsafe lookup BEFORE any
# stdlib name could be shadowed by an unverified source-packet member.
if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
    raise SystemExit('LAUNCH_WITH_PYTHON3_MINUS_I_MINUS_S_MINUS_B')

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


PROFILE = 'scientific-posix-integration-retain-all-v2'
RUNNER_CONTEXT = 'explicit-owned-quota-posix-v2'
SOURCE_BYTES = 167772160
SOURCE_ENTRIES = 4096
TOTAL_BYTES = 855638016
TOTAL_ENTRIES = 20608
MEMORY_BYTES = 536870912
PACKET_LIMIT = 16 << 20
ON_VOLUME_REQUIRED_BYTES = SOURCE_BYTES + PACKET_LIMIT + (16 << 20)
MAX_DOCUMENT = 256 << 10
MANIFEST_NAME = 'POSIX_SOURCE_MANIFEST.json'
PACKET_NAMES = {
    'run_scientific_posix_integration.py', 'scientific_posix_integration.py',
    'scientific_capture_protocol.py', 'scientific_raw_reference_v2.py',
    'scientific_execution_registry.py', 'scientific_registry_publication.py',
    'scientific_registry_transport.py', 'scientific_analyzer_adapter.py', 'raw_member_store.py',
    'README.md', 'BOUNDS.md', 'ADMISSION.template.json',
}


def need(value, code):
    if not value:
        raise RuntimeError(code)


def close_owned_descriptors(*descriptors):
    primary = sys.exception()
    failures, seen = [], set()
    for fd in descriptors:
        if fd is None or fd in seen:
            continue
        seen.add(fd)
        try:
            os.close(fd)
        except BaseException as error:
            failures.append(error)
    if failures:
        errors = ([primary] if primary is not None else []) + failures
        raise BaseExceptionGroup('EVERY_OWNED_DESCRIPTOR_CLOSE_ATTEMPTED', errors) from None


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'EXPLICIT_SHA256_REQUIRED')


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, 'TYPED_ADMISSION_INTEGER')


def decode(raw):
    def pairs(values):
        answer = {}
        for key, value in values:
            need(key not in answer, 'DUPLICATE_DOCUMENT_KEY')
            answer[key] = value
        return answer
    need(type(raw) is bytes and len(raw) <= MAX_DOCUMENT, 'DOCUMENT_BYTE_BOUND')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(RuntimeError('NONFINITE_DOCUMENT')))


def owned_directory(path, *, private_final):
    need(path.is_absolute() and len(path.parts) > 1 and '..' not in path.parts,
         'ABSOLUTE_EXPLICIT_OWNED_PATH')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for index, name in enumerate(path.parts[1:]):
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            private = private_final and index == len(path.parts[1:]) - 1
            need(stat.S_ISDIR(before.st_mode) and before.st_uid in (0, os.geteuid()) and
                 before.st_mode & (0o077 if private else 0o022) == 0 and
                 (not private or before.st_uid == os.geteuid()), 'OWNED_TRUSTED_DIRECTORY_CHAIN')
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                opened = os.fstat(child)
                after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                need((opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid) ==
                     (before.st_dev, before.st_ino, before.st_mode, before.st_uid) ==
                     (after.st_dev, after.st_ino, after.st_mode, after.st_uid),
                     'ADMISSION_DIRECTORY_PATH_CHANGED')
            except BaseException:
                close_owned_descriptors(child)
                raise
            parent, fd = fd, child
            close_owned_descriptors(parent)
        return fd
    except BaseException:
        close_owned_descriptors(fd)
        raise


def read_file(path, maximum):
    need(path.is_absolute() and '..' not in path.parts, 'EXPLICIT_FILE_PATH')
    parent = owned_directory(path.parent, private_final=True)
    fd = None
    try:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
             before.st_nlink == 1 and before.st_mode & 0o077 == 0 and before.st_size <= maximum,
             'OWNED_PRIVATE_UNIQUE_BOUNDED_INPUT')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        signature = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                                   info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        need(signature(before) == signature(os.fstat(fd)), 'INPUT_OPEN_BINDING')
        pieces, used = [], 0
        while True:
            raw = os.read(fd, min(65536, maximum - used + 1))
            if not raw:
                break
            used += len(raw)
            need(used <= maximum, 'INPUT_GROWTH_BOUND')
            pieces.append(raw)
        need(used == before.st_size and signature(before) == signature(os.fstat(fd)) ==
             signature(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'INPUT_COMPLETE_STABLE_READ')
        return b''.join(pieces)
    finally:
        close_owned_descriptors(fd, parent)


def check_manifest(packet, expected_sha):
    raw = read_file(packet / MANIFEST_NAME, MAX_DOCUMENT)
    need(hashlib.sha256(raw).hexdigest() == expected_sha, 'INDEPENDENT_MANIFEST_PIN_REQUIRED')
    manifest = decode(raw)
    need(type(manifest) is dict and manifest.get('format') == 'scientific-posix-source-packet-v1' and
         manifest.get('status') == 'SOURCE_ONLY_REQUIRES_INDEPENDENT_FIRST_FINDINGS' and
         type(manifest.get('packet_files')) is list, 'PINNED_PACKET_MANIFEST_SCHEMA')
    names, total = set(), len(raw)
    for row in manifest['packet_files']:
        need(type(row) is dict and set(row) == {'origin', 'name', 'bytes', 'sha256'} and
             type(row['name']) is str and row['name'] in PACKET_NAMES and row['name'] not in names,
             'EXACT_UNIQUE_FLAT_PACKET_FILE')
        digest(row['sha256'])
        integer(row['bytes'], 1, PACKET_LIMIT)
        value = read_file(packet / row['name'], row['bytes'])
        need(len(value) == row['bytes'] and hashlib.sha256(value).hexdigest() == row['sha256'],
             'COMPLETE_PREIMPORT_SOURCE_PIN_MISMATCH')
        names.add(row['name'])
        total += len(value)
    need(names == PACKET_NAMES and total <= PACKET_LIMIT, 'ALL_COMPLETE_PACKET_SOURCES_REQUIRED')
    # Isolated runner imports only this closed flat packet plus stdlib. Reject
    # stale .pyc, injected package trees and undeclared local Python modules.
    fd = owned_directory(packet, private_final=True)
    try:
        need(set(os.listdir(fd)) == PACKET_NAMES | {MANIFEST_NAME}, 'EXACT_PACKET_DIRECTORY_NO_UNPINNED_INPUTS')
    finally:
        close_owned_descriptors(fd)
    return raw


def check_admission(raw, expected_sha, root, manifest_sha):
    need(hashlib.sha256(raw).hexdigest() == expected_sha, 'INDEPENDENT_CONTEXT_PIN_REQUIRED')
    value = decode(raw)
    keys = {'format', 'profile', 'status', 'runner_context', 'test_root', 'source_manifest_sha256',
            'baseline_excluding_reserve_bytes', 'other_growth_bytes', 'global_reserve_bytes',
            'fresh_global_inventory_sha256', 'hard_quota_enforced', 'hard_quota_bytes',
            'hard_quota_evidence_sha256', 'memory_quota_enforced', 'memory_limit_bytes',
            'memory_quota_evidence_sha256', 'fixture_source_bytes', 'fixture_source_entries',
            'complete_failure_copies', 'total_reserved_bytes', 'total_reserved_entries',
            'external_complete_failure_transport_profile', 'external_transport_source_sha256',
            'external_transport_proof_sha256', 'all_allocations_including_external_copies_admitted',
            'no_other_heavy_process', 'independent_first_findings_sha256'}
    need(type(value) is dict and set(value) == keys, 'EXACT_VERSIONED_RUNNER_ADMISSION')
    need(value['format'] == 'scientific-posix-runner-admission-v2' and value['profile'] == PROFILE and
         value['status'] == 'AUTHORIZED_FOR_REVIEWED_SYNTHETIC_POSIX_ONLY' and
         value['runner_context'] == RUNNER_CONTEXT and value['test_root'] == str(root) and
         value['source_manifest_sha256'] == manifest_sha, 'EXPLICIT_REVIEWED_CONTEXT_AND_NEW_ROOT')
    for key in ('fresh_global_inventory_sha256', 'hard_quota_evidence_sha256', 'memory_quota_evidence_sha256',
                'external_transport_source_sha256', 'external_transport_proof_sha256',
                'independent_first_findings_sha256'):
        digest(value[key])
        need(value[key] != '0' * 64, 'REAL_EXTERNAL_EVIDENCE_PIN_REQUIRED')
    need(value['hard_quota_enforced'] is True and value['memory_quota_enforced'] is True and
         value['all_allocations_including_external_copies_admitted'] is True and
         value['no_other_heavy_process'] is True, 'EXTERNAL_ENFORCEMENT_AND_ALL_ALLOCATION_ADMISSION_REQUIRED')
    need(value['fixture_source_bytes'] == SOURCE_BYTES and value['fixture_source_entries'] == SOURCE_ENTRIES and
         value['complete_failure_copies'] == 4 and value['total_reserved_bytes'] == TOTAL_BYTES and
         value['total_reserved_entries'] == TOTAL_ENTRIES and value['memory_limit_bytes'] == MEMORY_BYTES and
         value['external_complete_failure_transport_profile'] == 'scientific-posix-complete-failure-copy-v1',
         'NEW_PROFILE_EXACT_BOUNDS_OLD_35MB_PROFILE_INCOMPATIBLE')
    # The image bounds source plus packet/control allocations on that volume.
    # The four retained external copies and image fallback are charged separately
    # through TOTAL_BYTES and explicit other_growth, never inside this minimum.
    integer(value['hard_quota_bytes'], ON_VOLUME_REQUIRED_BYTES, 2_000_000_000)
    integer(value['baseline_excluding_reserve_bytes'], 0, 15_000_000_000)
    integer(value['other_growth_bytes'], 0, 15_000_000_000)
    integer(value['global_reserve_bytes'], 2_000_000_000, 15_000_000_000)
    need(value['baseline_excluding_reserve_bytes'] + value['other_growth_bytes'] +
         value['global_reserve_bytes'] + TOTAL_BYTES < 12_000_000_000,
         'FRESH_ALL_ATTRIBUTABLE_GLOBAL_GROWTH_REFUSED')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-root', type=Path, required=True)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--runner-context', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--admission', type=Path, required=True)
    parser.add_argument('--admission-sha256', required=True)
    args = parser.parse_args()
    need(os.name == 'posix' and hasattr(os, 'geteuid') and hasattr(os, 'O_NOFOLLOW') and
         hasattr(os, 'O_DIRECTORY') and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd,
         'ACTUAL_POSIX_REQUIRED_NO_SKIP')
    need(sys.dont_write_bytecode and sys.flags.no_site and sys.flags.ignore_environment and sys.flags.isolated,
         'LAUNCH_WITH_PYTHON3_MINUS_I_MINUS_S_MINUS_B')
    need(args.profile == PROFILE and args.runner_context == RUNNER_CONTEXT, 'EXPLICIT_ADMITTED_RUNNER_CONTEXT')
    digest(args.manifest_sha256)
    digest(args.admission_sha256)
    root = args.test_root
    need(root.is_absolute() and len(root.parts) > 1 and '..' not in root.parts and
         re.fullmatch('[a-z0-9_.-]{1,64}', root.name) and root.name not in ('.', '..'),
         'NEW_EXPLICIT_OWNED_TEST_ROOT')
    packet = Path(__file__).absolute().parent
    need(packet not in root.parents and root != packet, 'FIXTURES_OUTSIDE_FROZEN_SOURCE_PACKET')
    manifest_raw = check_manifest(packet, args.manifest_sha256)
    admission_raw = read_file(args.admission, MAX_DOCUMENT)
    admission = check_admission(admission_raw, args.admission_sha256, root, args.manifest_sha256)
    parent = owned_directory(root.parent, private_final=True)
    try:
        geometry = os.fstatvfs(parent)
        need(0 < max(geometry.f_frsize, geometry.f_bsize) <= 8192, 'ADMITTED_ALLOCATION_GEOMETRY')
        try:
            os.stat(root.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError('TEST_ROOT_ALREADY_EXISTS_RETAIN_IT_AND_ADMIT_A_NEW_ROOT')
    finally:
        close_owned_descriptors(parent)
    os.umask(0o077)
    # Isolated startup excluded the unverified script directory. Admit this one
    # exact, fully pinned private packet only AFTER source/context checks.
    sys.path.insert(0, str(packet))
    from scientific_posix_integration import run_suite
    return run_suite(root, admission, manifest_raw=manifest_raw, admission_raw=admission_raw)


if __name__ == '__main__':
    raise SystemExit(main())
