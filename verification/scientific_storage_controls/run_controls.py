"""Source-only launcher for 114 synthetic controls; no POSIX or Go qualification.

Supply an independently trusted CONTROL_SOURCE_MANIFEST.json SHA256. Run this
file only after independent first findings and execution admission. Preserve all
outcomes with the repository's command-evidence wrapper. This launcher creates
no fixtures, silently skips no tests, and deletes no evidence.
"""
import sys

# sys is interpreter-loaded. Check isolation before any shadowable stdlib import.
if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode):
    raise SystemExit('LAUNCH_WITH_PYTHON3_MINUS_I_MINUS_S_MINUS_B')
if sys.version_info < (3, 11):
    raise SystemExit('PYTHON_3_11_OR_NEWER_REQUIRED')

import os

# Retain platform/locale/temp settings only, before importing the control graph.
# No value is printed. In particular, no credentials or Python import settings
# are forwarded, and this runner never starts a child process.
_ENV_KEYS = frozenset(('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR',
                       'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ'))
_ENVIRONMENT = {key: value for key, value in os.environ.items()
                if key.upper() in _ENV_KEYS}
os.environ.clear()
os.environ.update(_ENVIRONMENT)
_RETAINED_ENV_KEYS = sorted(key.upper() for key in _ENVIRONMENT)
del _ENVIRONMENT

import argparse
import hashlib
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import re
import stat
import traceback
import unittest


FORMAT = 'scientific-storage-control-source-v1'
PROFILE = 'scientific-storage-synthetic-controls-v1'
SOURCE_STATUS = 'SOURCE_ONLY_REQUIRES_INDEPENDENT_FIRST_FINDINGS'
MANIFEST_NAME = 'CONTROL_SOURCE_MANIFEST.json'
PACKET_PREFIX = 'public/scripts/scientific_storage/'
CONTROL_PREFIX = 'public/verification/scientific_storage_controls/'
PACKET_NAMES = frozenset((
    'scientific_posix_integration.py', 'run_scientific_posix_integration.py',
    'scientific_capture_protocol.py', 'raw_member_store.py',
    'scientific_raw_reference_v2.py', 'scientific_execution_registry.py',
    'scientific_registry_publication.py', 'scientific_registry_transport.py',
    'scientific_analyzer_adapter.py', 'README.md', 'BOUNDS.md',
    'ADMISSION.template.json',
))
CONTROL_NAMES = frozenset((
    'test_dependency_release_pure.py', 'test_fd_ownership_paths.py',
    'test_scientific_execution_registry.py', 'test_scientific_analyzer_adapter.py',
    'test_scientific_reference_analysis.py', 'scientific_reference_analysis.py',
))
MODULE_ORIGINS = {
    'scientific_capture_protocol': PACKET_PREFIX + 'scientific_capture_protocol.py',
    'raw_member_store': PACKET_PREFIX + 'raw_member_store.py',
    'scientific_raw_reference_v2': PACKET_PREFIX + 'scientific_raw_reference_v2.py',
    'scientific_execution_registry': PACKET_PREFIX + 'scientific_execution_registry.py',
    'scientific_registry_publication': PACKET_PREFIX + 'scientific_registry_publication.py',
    'scientific_registry_transport': PACKET_PREFIX + 'scientific_registry_transport.py',
    'scientific_analyzer_adapter': PACKET_PREFIX + 'scientific_analyzer_adapter.py',
    'run_scientific_posix_integration': PACKET_PREFIX + 'run_scientific_posix_integration.py',
    'analyze_reference': 'public/scripts/analyze_reference.py',
    'scientific_reference_analysis': CONTROL_PREFIX + 'scientific_reference_analysis.py',
    'test_dependency_release_pure': CONTROL_PREFIX + 'test_dependency_release_pure.py',
    'test_fd_ownership_paths': CONTROL_PREFIX + 'test_fd_ownership_paths.py',
    'test_scientific_execution_registry': CONTROL_PREFIX + 'test_scientific_execution_registry.py',
    'test_scientific_analyzer_adapter': CONTROL_PREFIX + 'test_scientific_analyzer_adapter.py',
    'test_scientific_reference_analysis': CONTROL_PREFIX + 'test_scientific_reference_analysis.py',
}
SUITES = {
    'test_dependency_release_pure': 17,
    'test_fd_ownership_paths': 20,
    'test_scientific_execution_registry': 41,
    'test_scientific_analyzer_adapter': 21,
    'test_scientific_reference_analysis': 15,
}
EXPECTED_FILES = (frozenset(PACKET_PREFIX + name for name in PACKET_NAMES) |
                  frozenset(CONTROL_PREFIX + name for name in CONTROL_NAMES) |
                  frozenset((PACKET_PREFIX + 'POSIX_SOURCE_MANIFEST.json',
                             CONTROL_PREFIX + 'run_controls.py',
                             'public/scripts/analyze_reference.py')))
CAPS = {'manifest_bytes': 65536, 'file_bytes': 131072,
        'selected_bytes': 750000, 'selected_files': 21, 'module_origins': 15,
        'tests': 114}
HISTORICAL_GO_SOURCE_CONTEXT = '0444490f17abd4b9e74def5f36046a2fa9c58b9306a0f658b8a3dbf4fed6b0fa'


def need(value, code):
    if not value:
        raise RuntimeError(code)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def is_digest(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns,
            hasattr(info, 'st_birthtime_ns'), getattr(info, 'st_birthtime_ns', None))


def cross_api_signature(info):
    full = signature(info)
    # This host's Windows path/FD APIs report different ctime values for the
    # same stable file. Keep ctime within each API's before/after comparison;
    # bind the two APIs with identity, size, mtime and available birthtime.
    # Presence is compared too, so asymmetric birthtime availability refuses.
    return full[:6] + full[7:] if os.name == 'nt' else full


def public_path(root, relative):
    need(type(relative) is str and relative.startswith('public/') and
         '\\' not in relative and ':' not in relative and
         all(part not in ('', '.', '..') for part in relative.split('/')),
         'EXPLICIT_PUBLIC_RELATIVE_PATH_REQUIRED')
    target = root.joinpath(*relative.split('/')[1:])
    current = root
    for part in (None, *relative.split('/')[1:]):
        if part is not None:
            current = current / part
        info = current.lstat()
        need(not stat.S_ISLNK(info.st_mode) and
             not getattr(current, 'is_junction', lambda: False)(),
             'NO_SYMLINK_OR_JUNCTION_SOURCE_PATH')
        if os.name == 'posix':
            need(info.st_uid in (0, os.geteuid()) and info.st_mode & 0o022 == 0,
                 'SOURCE_PATH_MUST_BE_OWNED_AND_NOT_SHARED_WRITABLE')
    need(target.resolve(strict=True).is_relative_to(root), 'PUBLIC_PATH_ESCAPE')
    return target


def read_stable(root, relative, maximum):
    target = public_path(root, relative)
    before = target.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         0 < before.st_size <= maximum, 'UNIQUE_REGULAR_BOUNDED_SOURCE_REQUIRED')
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(target, flags)
    try:
        opened = os.fstat(fd)
        need(cross_api_signature(before) == cross_api_signature(opened), 'SOURCE_OPEN_BINDING')
        pieces, used = [], 0
        while True:
            chunk = os.read(fd, min(65536, maximum - used + 1))
            if not chunk:
                break
            used += len(chunk)
            need(used <= maximum, 'SOURCE_READ_GROWTH_BOUND')
            pieces.append(chunk)
        after_fd = os.fstat(fd)
        after_path = public_path(root, relative).lstat()
        need(used == before.st_size and signature(before) == signature(after_path) and
             signature(opened) == signature(after_fd) and
             cross_api_signature(after_fd) == cross_api_signature(after_path), 'SOURCE_READ_BINDING_CHANGED')
        return b''.join(pieces)
    finally:
        os.close(fd)


def decode(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            need(key not in result, 'DUPLICATE_MANIFEST_KEY')
            result[key] = value
        return result
    def nonfinite(_):
        raise RuntimeError('NONFINITE_MANIFEST_VALUE')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=nonfinite)


def check_directories(root):
    expected = {
        PACKET_PREFIX.rstrip('/'): PACKET_NAMES | {'POSIX_SOURCE_MANIFEST.json'},
        CONTROL_PREFIX.rstrip('/'): CONTROL_NAMES |
            {'run_controls.py', MANIFEST_NAME, 'README.md'},
    }
    for relative, names in expected.items():
        directory = public_path(root, relative)
        need(stat.S_ISDIR(directory.lstat().st_mode), 'SOURCE_DIRECTORY_REQUIRED')
        need({entry.name for entry in directory.iterdir()} == names,
             'EXACT_SOURCE_DIRECTORY_NO_UNPINNED_MODULES_CACHES_OR_FIXTURES')
        for name in names:
            entry = public_path(root, relative + '/' + name)
            need(stat.S_ISREG(entry.lstat().st_mode), 'ONLY_REGULAR_SOURCE_MEMBERS')


def check_manifest(root, raw):
    value = decode(raw)
    required = {'format', 'profile', 'status', 'caps', 'files', 'module_origins',
                'suites', 'expected_tests', 'required_skips',
                'historical_go_source_context_sha256', 'scope', 'exclusions'}
    need(type(value) is dict and set(value) == required, 'EXACT_CONTROL_MANIFEST_SCHEMA')
    need(value['format'] == FORMAT and value['profile'] == PROFILE and
         value['status'] == SOURCE_STATUS, 'SOURCE_ONLY_CONTROL_MANIFEST_REQUIRED')
    need(value['caps'] == CAPS and all(type(number) is int for number in value['caps'].values()),
         'FIXED_SOURCE_AND_TEST_CAPS_REQUIRED')
    need(type(value['files']) is dict and set(value['files']) == EXPECTED_FILES and
         len(value['files']) == CAPS['selected_files'], 'EXACT_SELECTED_FILE_SET_REQUIRED')
    need(type(value['module_origins']) is dict and value['module_origins'] == MODULE_ORIGINS and
         len(value['module_origins']) == CAPS['module_origins'], 'EXACT_MODULE_ORIGINS_REQUIRED')
    need(type(value['suites']) is dict and value['suites'] == SUITES and
         all(type(count) is int for count in value['suites'].values()) and
         type(value['expected_tests']) is int and value['expected_tests'] == CAPS['tests'] and
         type(value['required_skips']) is int and value['required_skips'] == 0,
         'EXACT_114_METHODS_AND_ZERO_SKIPS_REQUIRED')
    need(value['historical_go_source_context_sha256'] == HISTORICAL_GO_SOURCE_CONTEXT,
         'HISTORICAL_GO_CONTEXT_REQUIRED')
    need(value['scope'] == 'Synthetic/fake-descriptor controls only; no POSIX, native Go, quota, RAM, custody, full-matrix or release qualification.' and
         value['exclusions'] == {
             'self': 'CONTROL_SOURCE_MANIFEST.json; caller supplies its exact trusted external SHA256.',
             'documentation': 'README.md; documents that digest without a self-hash cycle.',
             'historical_startup_controls': 'Four historical startup/local controls are outside this 114-test runner.'},
         'SOURCE_ONLY_SCOPE_AND_HASH_CYCLE_EXCLUSIONS_REQUIRED')
    for relative, row in value['files'].items():
        need(type(row) is dict and set(row) == {'bytes', 'sha256'} and
             type(row['bytes']) is int and 0 < row['bytes'] <= CAPS['file_bytes'] and
             is_digest(row['sha256']), 'TYPED_SOURCE_ROW_REQUIRED')
    return value


def collect(root, manifest):
    result, total = {}, 0
    check_directories(root)
    for relative, expected in manifest['files'].items():
        raw = read_stable(root, relative, expected['bytes'])
        actual = {'bytes': len(raw), 'sha256': sha256(raw)}
        need(actual == expected, 'COMPLETE_SELECTED_SOURCE_BYTE_PIN_MISMATCH')
        result[relative] = actual
        total += len(raw)
        need(total <= CAPS['selected_bytes'], 'TOTAL_SELECTED_SOURCE_BYTE_CAP')
    packet_raw = read_stable(root, PACKET_PREFIX + 'POSIX_SOURCE_MANIFEST.json',
                             CAPS['manifest_bytes'])
    packet = decode(packet_raw)
    need(type(packet) is dict and packet.get('format') == 'scientific-posix-source-packet-v1' and
         packet.get('status') == SOURCE_STATUS and
         type(packet.get('packet_revision')) is int and packet['packet_revision'] == 2 and
         packet.get('profile') == 'scientific-posix-integration-retain-all-v2' and
         type(packet.get('packet_files')) is list and len(packet['packet_files']) == 12,
         'EXACT_REVISION_2_SOURCE_PACKET_REQUIRED')
    names = set()
    for row in packet['packet_files']:
        need(type(row) is dict and set(row) == {'name', 'origin', 'bytes', 'sha256'} and
             type(row['name']) is str and row['name'] in PACKET_NAMES and
             row['name'] not in names and row['origin'] == PACKET_PREFIX + row['name'],
             'PUBLIC_FLAT_PACKET_ORIGIN_REQUIRED')
        need({'bytes': row['bytes'], 'sha256': row['sha256']} ==
             result[row['origin']], 'PACKET_AND_CONTROL_PINS_MUST_AGREE')
        names.add(row['name'])
    need(names == PACKET_NAMES, 'ALL_12_PACKET_MEMBERS_REQUIRED')
    return result


class PublicImportGuard(importlib.abc.MetaPathFinder):
    """Keep normal imports; refuse any additional unpinned public dependency."""
    def __init__(self, root):
        self.root = root

    def find_spec(self, fullname, path=None, target=None):
        spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        if fullname in MODULE_ORIGINS:
            need(spec is not None and spec.submodule_search_locations is None and
                 spec.origin is not None and
                 Path(spec.origin).resolve(strict=True) ==
                 public_path(self.root, MODULE_ORIGINS[fullname]),
                 'PUBLIC_IMPORT_ORIGIN_MISMATCH')
        elif spec is not None:
            locations = list(spec.submodule_search_locations or ())
            if spec.origin not in (None, 'built-in', 'frozen'):
                locations.append(spec.origin)
            need(not any(Path(location).resolve().is_relative_to(self.root)
                         for location in locations), 'UNPINNED_PUBLIC_IMPORT_REFUSED')
        # Delegate to the interpreter's normal importers, without aliases,
        # source rewriting, custom module loaders or production monkeypatches.
        return None


def module_origins(root):
    result = {}
    for name, relative in MODULE_ORIGINS.items():
        module = sys.modules.get(name)
        need(module is not None and getattr(module, '__file__', None) is not None and
             getattr(module, '__spec__', None) is not None and module.__spec__.origin is not None,
             'ALL_15_ACTUAL_MODULE_ORIGINS_REQUIRED')
        target = public_path(root, relative)
        need(Path(module.__file__).resolve(strict=True) == target and
             Path(module.__spec__.origin).resolve(strict=True) == target,
             'ACTUAL_MODULE_ORIGIN_CHANGED')
        result[name] = relative
    return result


def test_ids(suite):
    result = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            result.extend(test_ids(item))
        else:
            result.append(item.id())
        need(len(result) <= CAPS['tests'], 'TEST_DISCOVERY_COUNT_CAP')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-sha256', required=True,
                        help='Independently trusted exact CONTROL_SOURCE_MANIFEST.json SHA256')
    args = parser.parse_args()
    need(is_digest(args.manifest_sha256), 'EXPLICIT_TRUSTED_EXTERNAL_SHA256_REQUIRED')
    script = Path(__file__).absolute()
    need('..' not in script.parts, 'CANONICAL_LAUNCHER_PATH_REQUIRED')
    root = script.parents[2].resolve(strict=True)
    need(public_path(root, CONTROL_PREFIX + 'run_controls.py') == script,
         'EXPECTED_PUBLIC_CONTROL_LAUNCHER_REQUIRED')
    need(all(entry and not Path(entry).resolve().is_relative_to(root) for entry in sys.path),
         'ISOLATED_STDLIB_STARTUP_PATH_REQUIRED')
    need(not any(name in sys.modules for name in MODULE_ORIGINS),
         'NO_PRELOADED_PROJECT_MODULES_OR_ALIASES')
    manifest_relative = CONTROL_PREFIX + MANIFEST_NAME
    manifest_raw = read_stable(root, manifest_relative, CAPS['manifest_bytes'])
    need(sha256(manifest_raw) == args.manifest_sha256, 'TRUSTED_EXTERNAL_MANIFEST_PIN_MISMATCH')
    manifest = check_manifest(root, manifest_raw)
    report = {
        'format': 'scientific-storage-control-run-v1', 'status': 'FAIL',
        'profile': PROFILE, 'manifest_sha256': args.manifest_sha256,
        'expected_tests': CAPS['tests'], 'actual_tests': 0,
        'suite_methods': {}, 'failures': 0, 'errors': 0, 'skips': 0,
        'expected_failures': 0, 'unexpected_successes': 0,
        'before': {}, 'after': {}, 'module_origins_before': {}, 'module_origins_after': {},
        'environment_keys_retained': _RETAINED_ENV_KEYS,
        'filesystem_fixtures_created': False, 'evidence_deleted': False,
        'historical_go_source_context_sha256': HISTORICAL_GO_SOURCE_CONTEXT,
        'historical_context_is_current_public_checkout_identity': False,
        'actual_posix_native_go_quota_ram_custody_fullmatrix_release_qualification': False,
    }
    execution_ok = False
    try:
        report['before'] = collect(root, manifest)
        # The stdlib retains lookup priority. Among project paths the repaired
        # flat packet precedes controls, followed by the legacy analyzer path.
        sys.path.extend((str(root / 'scripts/scientific_storage'),
                         str(root / 'verification/scientific_storage_controls'),
                         str(root / 'scripts')))
        guard = PublicImportGuard(root)
        sys.meta_path.insert(0, guard)
        for name, relative in MODULE_ORIGINS.items():
            spec = importlib.util.find_spec(name)
            need(spec is not None and spec.origin is not None and
                 Path(spec.origin).resolve(strict=True) == public_path(root, relative) and
                 spec.submodule_search_locations is None,
                 'ALL_SELECTED_IMPORTS_MUST_RESOLVE_TO_PINNED_FILES')
        for name in MODULE_ORIGINS:
            importlib.import_module(name)
        report['module_origins_before'] = module_origins(root)
        need(collect(root, manifest) == report['before'], 'IMPORT_CHANGED_SOURCE_BYTES')
        loader, suite = unittest.TestLoader(), unittest.TestSuite()
        for name, expected in SUITES.items():
            selected = loader.loadTestsFromModule(sys.modules[name])
            actual = selected.countTestCases()
            need(actual == expected, 'EXACT_PER_SUITE_TEST_COUNT_REQUIRED')
            report['suite_methods'][name] = actual
            suite.addTests(selected)
        ids = test_ids(suite)
        need(not loader.errors and suite.countTestCases() == CAPS['tests'] and
             len(ids) == CAPS['tests'] and len(set(ids)) == CAPS['tests'],
             'EXACT_UNIQUE_114_TESTS_REQUIRED')
        result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
        report.update(actual_tests=result.testsRun, failures=len(result.failures),
                      errors=len(result.errors), skips=len(result.skipped),
                      expected_failures=len(result.expectedFailures),
                      unexpected_successes=len(result.unexpectedSuccesses))
        execution_ok = (result.wasSuccessful() and result.testsRun == CAPS['tests'] and
                        not result.skipped and not result.expectedFailures and
                        not result.unexpectedSuccesses)
    except BaseException as error:
        report['control_error_type'] = type(error).__name__
        traceback.print_exc(file=sys.stderr)
    finally:
        try:
            report['after'] = collect(root, manifest)
            need(report['after'] == report['before'], 'POST_RUN_SELECTED_SOURCE_BYTES_CHANGED')
            need(read_stable(root, manifest_relative, CAPS['manifest_bytes']) == manifest_raw,
                 'CONTROL_MANIFEST_CHANGED_DURING_RUN')
            report['module_origins_after'] = module_origins(root)
            need(report['module_origins_after'] == report['module_origins_before'],
                 'POST_RUN_MODULE_ORIGINS_CHANGED')
        except BaseException as error:
            execution_ok = False
            report['post_run_error_type'] = type(error).__name__
            traceback.print_exc(file=sys.stderr)
    report['status'] = 'PASS' if execution_ok else 'FAIL'
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if execution_ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
