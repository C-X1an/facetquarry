"""SOURCE-ONLY three-case POSIX integration candidate; all data are SYNTHETIC.

Normal imports require the externally pinned, reviewed flat source packet.
No product execution, scientific benchmark, cleanup or retirement is provided.
Use only run_scientific_posix_integration.py with a fresh explicit admission.
"""
import base64
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import unittest

import scientific_capture_protocol as protocol
import scientific_raw_reference_v2 as rawref
import scientific_execution_registry as registry
import scientific_registry_publication as publication
import scientific_registry_transport as transport
import scientific_analyzer_adapter as adapter


PROFILE = 'scientific-posix-integration-retain-all-v2'
UNIT = 8192
SOURCE_DATA_BYTES = 96 << 20
SOURCE_ENTRIES = 4096
SOURCE_BYTES = SOURCE_DATA_BYTES + 2 * UNIT * SOURCE_ENTRIES
FAILURE_COPIES = 4
PACKET_LOG_RUNNER_BYTES = 16 << 20
TOTAL_RESERVED_BYTES = (1 + FAILURE_COPIES) * SOURCE_BYTES + PACKET_LOG_RUNNER_BYTES
TOTAL_RESERVED_ENTRIES = (1 + FAILURE_COPIES) * SOURCE_ENTRIES + 128
MEMORY_LIMIT_BYTES = 512 << 20
MAX_FILE_BYTES = 8 << 20
CASE_BOUNDS = {
    'whole-path': {'data_bytes': 32 << 20, 'entries': 1280},
    'publication-collision': {'data_bytes': 4 << 20, 'entries': 256},
    'restore-corruption': {'data_bytes': 48 << 20, 'entries': 2048},
}
CASE_METHODS = (
    'test_real_synthetic_cell_publish_restore_registry_analyzer_and_transport',
    'test_real_exclusive_publication_collision_and_complete_failure_copy',
    'test_real_copied_packed_corruption_refuses_and_complete_failure_copy',
)


def need(value, code):
    if not value:
        raise RuntimeError(code)


def close_owned_descriptors(*descriptors):
    """Attempt each owned FD once; keep active and all close errors together."""
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


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def pretty(value):
    return (json.dumps(value, indent=2, allow_nan=False) + '\n').encode('utf-8')


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def create_file(base, relative, raw):
    """Owned bounded exclusive file; no parent discovery/creation or overwrite."""
    need(type(raw) is bytes and len(raw) <= MAX_FILE_BYTES, 'FIXED_FILE_BOUND')
    root = publication._owned_base(base)
    parent = None
    fd = None
    try:
        parent, name = rawref._at(root, relative)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        publication._file(os.fstat(fd))
        rawref._write_all(fd, raw)
        os.fsync(fd)
        os.fsync(parent)
        need(publication._read_file(parent, name, len(raw), expected_fd=fd) == raw,
             'EXCLUSIVE_FIXED_FILE_READBACK')
    finally:
        close_owned_descriptors(fd, parent, root)


class OwnedReader:
    """Actual bounded no-follow pair/catalog reader, also for copied metadata.

    This reader does not reopen a Publisher or rewrite historical inode fields.
    Source positive reconstruction uses the live Publisher.read directly.
    """
    def __init__(self, base):
        self.base = Path(base)
        self.fd = publication._owned_base(self.base)

    def raw(self, path, maximum):
        need(self.fd is not None and 0 <= maximum <= MAX_FILE_BYTES,
             'EXPLICIT_BOUNDED_LIVE_READER')
        parent, name = rawref._at(self.fd, path)
        try:
            return publication._read_file(parent, name, maximum)
        finally:
            close_owned_descriptors(parent)

    def read(self, ref):
        registry.reference(ref)
        parts = rawref.relative(ref['path'])
        need(len(parts) == 5 and parts[1] == ref['kind'] and
             parts[2] == ref['sha256'][:2] and parts[3] == ref['sha256'][2:4] and
             parts[4] == publication.publication_leaf(ref['sha256'], ref['kind']),
             'EXACT_COPIED_PUBLICATION_LAYOUT')
        raw = self.raw(ref['path'], ref['bytes'])
        registry.check_object(ref, raw)
        need(self.raw(ref['path'] + '.partial', ref['bytes']) == raw,
             'COPIED_PUBLICATION_PAIR_EXACT')
        return raw

    def catalog(self, store, expected_sha, maximum):
        rawref.relative(store)
        need(maximum <= rawref.MAX_CATALOG, 'BOUNDED_CATALOG_READER')
        raw = self.raw(store + '/catalog.json', maximum)
        need(hashlib.sha256(raw).hexdigest() == expected_sha and
             self.raw(store + '/catalog.partial', maximum) == raw,
             'ACTUAL_CATALOG_PAIR_READ')
        return raw

    def release(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            close_owned_descriptors(fd)


def snapshot(base, maximum_entries=SOURCE_ENTRIES):
    return publication.snapshot_owned_base(
        base, maximum_entries=maximum_entries,
        maximum_file_bytes=MAX_FILE_BYTES, allocation_unit=UNIT)


def rows_data(rows):
    return sum(row['bytes'] for row in rows if row['kind'] == 'file')


def assert_tree_bound(base, *, data_bytes, entries):
    observed = snapshot(base, entries)
    need(len(observed['members']) + 1 <= entries, 'ROOT_INCLUDED_ENTRY_BOUND')
    need(rows_data(observed['members']) <= data_bytes, 'CASE_LOGICAL_BYTE_BOUND')
    # snapshot charges every child; explicitly charge the containing root too.
    need(observed['observed_allocation_bytes'] + 2 * UNIT <= data_bytes + 2 * UNIT * entries,
         'CASE_RETAINED_ALLOCATION_BOUND')
    return observed


def copy_tree(source, destination):
    """Real finite regular-file copy, preserving source and every failed prefix.

    Both inventories must be exact; each new file must have a distinct current
    (device,inode). No metadata/history identity equivalence is inferred.
    The caller reserves the ENTIRE destination even if this operation fails.
    """
    before = snapshot(source, 640)['members']
    need(len(before) + 1 <= 640 and rows_data(before) <= 16 << 20,
         'ONE_COMPLETE_TREE_COPY_BOUND')
    destination.mkdir(mode=0o700)
    reader = OwnedReader(source)
    try:
        for row in before:
            parts = rawref.relative(row['path'])
            target = destination.joinpath(*parts)
            if row['kind'] == 'directory':
                target.mkdir(mode=0o700)
            else:
                raw = reader.raw(row['path'], row['bytes'])
                need(identity(raw) == {'bytes': row['bytes'], 'sha256': row['sha256']},
                     'COPY_SOURCE_STILL_HASH_BOUND')
                create_file(destination, row['path'], raw)
                current = target.stat(follow_symlinks=False)
                original = source.joinpath(*parts).stat(follow_symlinks=False)
                need((current.st_dev, current.st_ino) != (original.st_dev, original.st_ino),
                     'ACTUAL_UNIQUE_COPY_REQUIRED')
        need(snapshot(source, 640)['members'] == before, 'COPY_SOURCE_CHANGED')
        after = snapshot(destination, 640)['members']
        need(after == before, 'COMPLETE_COPIED_TREE_BYTES_TYPES_PATHS')
        return after
    finally:
        reader.release()


def synthetic_run_and_originals():
    """Fabricated trust input created BEFORE any captured/catalog output.

    These fixed source/binary/host strings are parser linkage controls only.
    No native executable, Go result, input generation or timestamp is measured.
    """
    provenance = {'source': 'a' * 64, 'synthetic': True, 'binaries': {
        'facetquarry': {'source': 'a' * 64, 'sha256': 'e' * 64, 'build_settings': 'SYNTHETIC'},
        'fqbench': {'source': 'a' * 64, 'sha256': 'f' * 64, 'build_settings': 'SYNTHETIC'}}}
    config = protocol.frozen_config(1)
    run = {'format': protocol.RUN_FORMAT, 'source': 'a' * 64, 'commit': 'b' * 40,
           'execution_id': 'c' * 32, 'invocation_id': 'd' * 32,
           'github_run_id': '1', 'github_run_attempt': '1', 'grid_sha256': protocol.GRID_SHA256,
           'config': config,
           'config_hash': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:12],
           'config_sha256': protocol.sha(protocol.canonical(config)),
           'provenance_sha256': protocol.sha(pretty(provenance)),
           'binaries': {'facetquarry': 'e' * 64, 'fqbench': 'f' * 64},
           'admission_script_sha256': '9' * 64}
    collector_command = ['python3', 'scripts/benchmark.py', '--profile', 'full', '--concurrency', '1',
                         '--evidence-format', registry.ROOT]
    arguments = {'profile': 'full', 'concurrency': 1, 'limit_cells': 0, 'evidence_format': registry.ROOT}
    start = {'format': registry.INVOCATION,
             **{key: run[key] for key in ('source', 'commit', 'execution_id', 'invocation_id')},
             'command': copy.deepcopy(collector_command), 'arguments': copy.deepcopy(arguments),
             'started_at': '2026-11-14T00:00:00Z'}
    originals = {'source_manifest': pretty({'synthetic': 'source-manifest', 'source': run['source']}),
                 'provenance': pretty(provenance),
                 'config_legacy': json.dumps(config, sort_keys=True).encode(),
                 'config_canonical': protocol.canonical(config),
                 'guest_context': pretty({'synthetic': 'guest-context'}),
                 'benchmark_start': pretty({'synthetic': 'benchmark-start'}),
                 'invocation_start': pretty(start)}
    expected = {tag: identity(raw) for tag, raw in originals.items()}
    need(all(len(raw) <= 16 << 10 for raw in originals.values()), 'SYNTHETIC_ORIGINAL_BOUND')
    return run, provenance, originals, expected, collector_command, arguments


def expected_command(run, stage):
    # Trusted synthetic specification, independently evaluated for each record
    # and reconstruction; never obtain expected argv from an attempt record.
    return {'admission': ['python3', 'scripts/disk_guard.py', '--reserve', '500000000'],
            'build': ['/synthetic-owned/facetquarry', 'build', '--input', '/synthetic-owned/corpus.json',
                      '--output', '/synthetic-owned/index.fq'],
            'measurement': ['/synthetic-owned/fqbench', '--index', '/synthetic-owned/index.fq',
                            '--tenant', 'alpha', '--queries', '/synthetic-owned/queries.jsonl',
                            '--warmup', '20', '--repetitions', '5',
                            '--concurrency', str(run['config']['concurrency'])]}[stage]


def synthetic_samples(run, cell):
    """Actual 1001 native/1000 normalized JSON lines, explicitly invented."""
    native, normalized = bytearray(), bytearray()
    for repetition in range(5):
        for query in range(200):
            row = {'query': query, 'repetition': repetition, 'nanoseconds': query + repetition,
                   'response': {'schema_version': 1, 'generation': '9' * 64,
                                'plan': 'exact', 'status': 'complete', 'exact': True,
                                'eligible': cell['n'], 'distance_evaluations': cell['n'],
                                'hits': [{'id': 'r%06d' % hit, 'distance': hit} for hit in range(10)]}}
            native.extend(encoded(row))
            normalized.extend(encoded({**row, 'recall_at_k': 1.0}))
    metadata = {'summary': True, 'source': run['source'], 'peak_rss_bytes': 10000000,
                'rss_measurement': 'SYNTHETIC parser input; not a measurement', 'goos': 'linux',
                'goarch': 'amd64', 'gomaxprocs': 4, 'go_runtime_sys_bytes': 8000000,
                'go': 'go1.27.3', 'workers': 1, 'samples': 1000, 'successful_queries': 1000,
                'zero_duration_count': 1,
                'clock': {'monotonic': True, 'fallback': False, 'frequency_hz': 1000000000,
                          'calibration': {'successive_read_pairs': 1000}},
                'measured_interval_ns': 1000000000, 'completed_queries_per_second': 1000.0,
                'throughput_measurement': 'SYNTHETIC arithmetic control',
                'measurement': 'SYNTHETIC integration input; no Go process was run'}
    native.extend(encoded(metadata))
    native, normalized = bytes(native), bytes(normalized)
    need(native.count(b'\n') == 1001 and normalized.count(b'\n') == 1000,
         'ACTUAL_SYNTHETIC_LINE_COUNTS')
    need(len(native) <= rawref.CHUNK and len(normalized) <= rawref.CHUNK,
         'FIXED_ONE_CHUNK_SCIENTIFIC_ORIGINALS')
    return native, normalized, metadata


def native_documents(run, group, scope, stage, number, payloads, *, outcome='success'):
    roles = ('stdout', 'stderr', 'samples') if stage == 'measurement' else ('stdout', 'stderr')
    need(set(payloads) == set(roles), 'FIXED_NATIVE_ROLE_SET')
    bindings = []
    for role in roles:
        binding = {'format': protocol.BINDING_FORMAT, 'run_sha256': registry.run_sha(run),
                   'scope': copy.deepcopy(scope), 'workload_seed': group['seed'], 'build_seed': group['seed'],
                   'attempt_id': '%d-1234abcd' % number, 'stage': stage, 'role': role, 'outcome': outcome,
                   'completeness': 'complete',
                   'origin': 'new-normalized-original' if role == 'samples' else 'new-native-original',
                   'generation': '9' * 64 if stage == 'measurement' else None,
                   'corpus_sha256': None if stage == 'admission' else '2' * 64,
                   'queries_sha256': '3' * 64 if stage == 'measurement' else None,
                   'producer': protocol.producer_for(stage, run)}
        protocol.validate_binding(binding, run)
        bindings.append((binding, payloads[role]))
    start = {'admission': 1, 'build': 3, 'measurement': 5}[stage]
    if outcome == 'failed':
        start = 7
    attempt = {'format': protocol.ATTEMPT_FORMAT, 'run_sha256': registry.run_sha(run),
               'scope': copy.deepcopy(scope), 'attempt_id': '%d-1234abcd' % number,
               'stage': stage, 'producer': protocol.producer_for(stage, run),
               'command': expected_command(run, stage), 'started_at': '2026-11-14T00:00:0%dZ' % start,
               'ended_at': '2026-11-14T00:00:0%dZ' % (start + 1), 'duration_seconds': 1,
               'timeout_seconds': 900, 'exit_code': 0 if outcome == 'success' else 1,
               'termination_reason': None, 'error': None,
               'status': 'PASS' if outcome == 'success' else 'FAIL',
               'captures': {binding['role']: protocol.sha(protocol.canonical(binding)) for binding, _ in bindings}}
    return attempt, bindings


def storage_plan(admission):
    """A conservative per-publisher plan, inside a separately admitted suite.

    Each source tree reserves <=16MiB logical/640 entries. The plan also
    reserves four complete source copies and conservatively double-charges its
    own allocation on top of the suite-wide global reservation.
    """
    counts = {kind: 0 for kind in registry.LIMITS}
    counts.update(original=8, anchor=1, catalog=1, attempt=4, cell=1, group=90,
                  root=1, retained=1, **{'transport-page': 8, 'transport': 1})
    sizes = {kind: count * (128 << 10 if kind == 'transport-page' else
                           32 << 10 if kind == 'root' else 16 << 10)
             for kind, count in counts.items()}
    extents = {name: {'data_bytes': 0, 'entries': 0} for name in publication.EXTENTS}
    extents['originals'] = {'data_bytes': 3 << 20, 'entries': 16}
    extents['primitive_staging'] = {'data_bytes': 3 << 20, 'entries': 40}
    extents['packed_candidates'] = {'data_bytes': 3 << 20, 'entries': 40}
    extents['catalog_pairs'] = {'data_bytes': 1 << 20, 'entries': 8}
    extents['registry_pairs'] = {'data_bytes': 2 * sum(sizes.values()),
                                 'entries': 4 * sum(counts.values()) + len(registry.LIMITS) + 1}
    extents['nonqualifying'] = {'data_bytes': 64 << 10, 'entries': 16}
    extents['outer_artifacts'] = {'data_bytes': 64 << 10, 'entries': 16}
    extents['failure_transport'] = {
        'data_bytes': FAILURE_COPIES * sum(extents[name]['data_bytes'] for name in publication.SOURCE_EXTENTS),
        'entries': FAILURE_COPIES * sum(extents[name]['entries'] for name in publication.SOURCE_EXTENTS)}
    return publication.StoragePlan(
        admission['baseline_excluding_reserve_bytes'],
        admission['other_growth_bytes'] + TOTAL_RESERVED_BYTES,
        admission['global_reserve_bytes'], extents, counts, sizes,
        allocation_unit=UNIT, transport_copies=FAILURE_COPIES)


class SyntheticExecution:
    """One actual filesystem graph with one selected fabricated sample cell."""
    def __init__(self, case, base):
        self.case, self.base = case, base
        base.mkdir(mode=0o700)
        run, provenance, originals, hashes, collector, arguments = synthetic_run_and_originals()
        self.run, self.provenance = run, provenance
        run_sha = registry.run_sha(run)
        self.trusted_originals = {run_sha: {**copy.deepcopy(hashes),
                                           'collector_command': copy.deepcopy(collector),
                                           'collector_arguments': copy.deepcopy(arguments)}}
        self.publisher = case.keep(publication.Publisher(base, 'records', storage_plan(case.context.admission)))
        self.state = registry.ExecutionRegistry(run, self.publisher.publish)
        self.state.record_invocation(run, originals, expected_originals=hashes,
                                     expected_command=collector, expected_arguments=arguments)
        self.group = protocol.all_groups(run)[0]
        self.cid, self.cell = next((cid, cell) for cid, cell in protocol.cells_for_group(self.group, run).items()
                                   if cell['mode'] == 'exact' and cell['filter_label'] == 'all')
        group_scope = registry.group_scope(self.group, run)
        cell_scope = {'kind': 'cell', 'group_id': protocol.group_id(self.group),
                      'cell_id': self.cid, 'cell': copy.deepcopy(self.cell)}
        self.native, self.normalized, metadata = synthetic_samples(run, self.cell)
        documents = [
            native_documents(run, self.group, group_scope, 'admission', 1,
                             {'stdout': b'SYNTHETIC admission\xff\x00\n', 'stderr': b''}),
            native_documents(run, self.group, group_scope, 'build', 2,
                             {'stdout': b'SYNTHETIC build\xfe\n', 'stderr': b''}),
            native_documents(run, self.group, cell_scope, 'measurement', 3,
                             {'stdout': self.native, 'stderr': b'', 'samples': self.normalized}),
            native_documents(run, self.group, cell_scope, 'measurement', 4,
                             {'stdout': b'SYNTHETIC failed native\xff', 'stderr': b'SYNTHETIC failure\x00',
                              'samples': b'{"synthetic_unselected_failure":true}\n'}, outcome='failed'),
        ]
        members = [member for _, items in documents for member in items]
        need(len(members) == 10 and sum(len(raw) for _, raw in members) <= 3 << 20,
             'EXACT_TEN_SMALL_REAL_CAPTURE_INPUTS')
        store = base / 'captures'
        store.mkdir(mode=0o700)
        batch = case.keep(rawref.Batch(
            store, run, rawref.Budget(case.context.admission['baseline_excluding_reserve_bytes'],
                                     case.context.admission['other_growth_bytes'] +
                                     case.context.admission['global_reserve_bytes'] + TOTAL_RESERVED_BYTES,
                                     64 << 20, allocation_unit=UNIT)))
        self.originals = []
        for binding, raw in members:
            writer = batch.capture(binding)
            for offset in range(0, len(raw), rawref.CHUNK):
                writer.write(raw[offset:offset + rawref.CHUNK])
            writer.close()
            self.originals.append((copy.deepcopy(binding), writer.id, raw))
        proof = batch.publish(encoding='identity')
        resolver = case.keep(rawref.Resolver(store, proof['catalog_sha256'], run))
        need(resolver.catalog_bytes <= 128 << 10 and len(resolver.catalog['transactions']) == 3 and
             len(resolver.catalog['references']) == 10, 'FIXED_REAL_CATALOG_GEOMETRY')
        self.historical_catalog = rawref.canonical(resolver.catalog)
        self.catalog = copy.deepcopy(resolver.catalog)
        self.selectors = {}
        for binding, reference_id, raw in self.originals:
            case.assertEqual(resolver.read_original(reference_id, binding, len(raw)), raw)
            selector = rawref.reference_for(resolver, reference_id, binding, 'captures')
            case.assertEqual(rawref.resolve_reference(base, selector, run, binding, len(raw)), raw)
            self.selectors[(binding['attempt_id'], binding['role'])] = selector
        self.state.record_resolver_catalog(resolver, 'captures', expected_run=run)
        self.commands, refs = {}, {}
        for document, _ in documents:
            trusted = expected_command(run, document['stage'])
            self.commands[(run_sha, document['attempt_id'])] = trusted
            refs[document['attempt_id']] = self.state.record_attempt(document, expected_command=trusted)
        sample = self.selectors[('3-1234abcd', 'samples')]
        summary = {'evidence_format': registry.SUMMARY, 'run_sha256': run_sha,
                   'scope': cell_scope, 'cell': copy.deepcopy(self.cell), 'source': run['source'],
                   'provenance': provenance, 'status': 'PASS', 'collector_status': 'PASS',
                   'stage': 'measurement', 'errors': [], 'sample_count': 1000,
                   'generation': '9' * 64, 'corpus_sha256': '2' * 64, 'queries_sha256': '3' * 64,
                   'dependencies': {'admission': refs['1-1234abcd'], 'build': refs['2-1234abcd'],
                                    'measurement': refs['3-1234abcd']},
                   'inputs': {'corpus': None, 'queries': None}, 'samples_reference': sample,
                   'samples_original_sha256': sample['sha256'], 'native_metadata': metadata,
                   'started_at': '2026-11-14T00:00:00Z', 'ended_at': '2026-11-14T00:00:06Z'}
        self.state.record_cell(pretty(summary))
        retained = base / 'retained'
        retained.mkdir(mode=0o700)
        create_file(base, 'retained/failure-tail.partial', b'SYNTHETIC retained interrupted tail\xff\x00')
        create_file(base, 'retained/unknown.bin', b'SYNTHETIC explicitly retained unknown member\xfe')
        unowned = {'run_sha256': None, 'group_id': None, 'attempt_id': None}
        failed_owner = {'run_sha256': run_sha, 'group_id': protocol.group_id(self.group),
                        'attempt_id': '4-1234abcd'}
        rows = []
        for row in snapshot(base)['members']:
            if row['path'] == 'retained' or row['path'].startswith('retained/'):
                rows.append({**row, 'membership': 'nonqualifying-retained',
                             'reason': 'SYNTHETIC complete tail/unknown retention control',
                             'owner': failed_owner if row['path'].endswith('.partial') else unowned})
        self.state.add_retained_members(rows)
        self.root_reference, self.root = self.state.finalize()
        # Batch release closes descriptors only; all original/stage/packed and
        # catalog files remain. No active producer FD enters a transport copy.
        for retained_owner in (batch, resolver):
            with case.assertRaisesRegex(rawref.Refusal, 'RETIREMENT_UNSUPPORTED'):
                retained_owner.retire()
        resolver.release()
        batch.release()
        self.reader = case.keep(OwnedReader(base))
        self.view = registry.read_execution(
            self.root_reference, self.publisher.read, self.reader.catalog, expected_run=run,
            expected_originals=self.trusted_originals, expected_commands=self.commands)

    def reconcile(self, base=None, view=None):
        return adapter.reconcile_checked_cell(
            self.base if base is None else base, self.view if view is None else view,
            self.cid, expected_run=self.run)

    def reconstruct(self, base):
        reader = self.case.keep(OwnedReader(base))
        return registry.read_execution(
            self.root_reference, reader.read, reader.catalog, expected_run=self.run,
            expected_originals=self.trusted_originals, expected_commands=self.commands)

    def normal_seal(self):
        envelope = self.case.keep(publication.Publisher(
            self.base, 'transport', storage_plan(self.case.context.admission)))
        before = snapshot(self.base, 640)['members']
        self.transport_reference, self.transport_document = transport.build_transport(
            self.view, before, envelope.publish, envelope_root='transport')
        report = transport.validate_transport(
            self.transport_reference, envelope.read, snapshot(self.base, 640)['members'],
            expected_execution_sha256=self.state.execution_sha256, view=self.view)
        self.case.assertFalse(report['failure_only'])
        self.case.assertEqual(report['qualification'], 'NOT_PERFORMED')
        self.case.assertEqual(report['retirement'], 'REFUSE')
        assert_tree_bound(self.base, data_bytes=16 << 20, entries=640)
        return self.transport_reference

    def assert_original_and_stage_retained(self, base=None):
        base = self.base if base is None else base
        reader = self.case.keep(OwnedReader(base))
        self.case.assertEqual(reader.raw('captures/catalog.json', 128 << 10), self.historical_catalog)
        self.case.assertEqual(reader.raw('captures/catalog.partial', 128 << 10), self.historical_catalog)
        by_id = {row['id']: row for row in self.catalog['references']}
        for _, reference_id, raw in self.originals:
            ref = by_id[reference_id]
            self.case.assertEqual(reader.raw('captures/' + ref['original']['path'], len(raw)), raw)
            chunks = []
            for chunk in ref['chunks']:
                path = '/'.join(('captures', chunk['shard'], 'txn-' + chunk['transaction'],
                                 'stage', chunk['member']))
                chunks.append(reader.raw(path, rawref.CHUNK))
            self.case.assertEqual(b''.join(chunks), raw)


class Context:
    def __init__(self, root, admission):
        self.root, self.admission = Path(root), admission
        self.claim = 'EXPLICIT_OWNED_QUOTA_CONTEXT_RECEIVED_NOT_ATTESTED_BY_HARNESS'


class PosixIntegrationContracts(unittest.TestCase):
    def __init__(self, methodName='runTest', *, context=None):
        super().__init__(methodName)
        self.context = context

    def setUp(self):
        need(os.name == 'posix' and type(self.context) is Context and
             self.context.admission['profile'] == PROFILE and
             self.context.admission['status'] == 'AUTHORIZED_FOR_REVIEWED_SYNTHETIC_POSIX_ONLY',
             'EXPLICIT_ADMITTED_POSIX_RUNNER_REQUIRED_NO_SKIP')
        self.handles = []
        self.addCleanup(self.release_all)
        names = dict(zip(CASE_METHODS, CASE_BOUNDS))
        self.case_name = names[self._testMethodName]
        self.base = self.context.root / self.case_name
        self.base.mkdir(mode=0o700)

    def keep(self, handle):
        self.handles.append(handle)
        return handle

    def release_all(self):
        primary = sys.exception()
        failures = []
        for handle in reversed(self.handles):
            try:
                handle.release()
            except BaseException as error:
                failures.append(error)
        # Attempt EVERY release even after one fails. Files are never removed,
        # sealed on cleanup, truncated, relocated, or omitted from the guard.
        if hasattr(self, 'base') and self.base.exists():
            try:
                assert_tree_bound(self.base, **CASE_BOUNDS[self.case_name])
            except BaseException as error:
                failures.append(error)
        if failures:
            errors = ([primary] if primary is not None else []) + failures
            raise BaseExceptionGroup('EVERY_DESCRIPTOR_RELEASE_ATTEMPTED_RETAINED', errors) from None

    def assert_linkage(self, result, fixture):
        self.assertEqual(len(result.samples), 1000)
        self.assertEqual(result.qualification, 'NOT_PERFORMED')
        self.assertEqual(result.native_stdout_original_sha256, identity(fixture.native)['sha256'])
        self.assertEqual(result.samples_original_sha256, identity(fixture.normalized)['sha256'])
        self.assertEqual({(row['query'], row['repetition']) for row in result.samples},
                         {(query, repetition) for query in range(200) for repetition in range(5)})

    def failure_seal_and_copy(self, base, execution_sha, reason, destination):
        envelope = self.keep(publication.Publisher(base, 'failure', storage_plan(self.context.admission)))
        ref, document = transport.build_failure_transport(
            execution_sha, snapshot(base, 640)['members'], envelope.publish,
            envelope_root='failure', reason=reason)
        self.assertIsNone(document['execution_root'])
        report = transport.validate_transport(
            ref, envelope.read, snapshot(base, 640)['members'], expected_execution_sha256=execution_sha)
        self.assertTrue(report['failure_only'])
        self.assertEqual(report['qualification'], 'NOT_PERFORMED')
        copied = copy_tree(base, destination)
        reader = self.keep(OwnedReader(destination))
        restored = transport.validate_transport(ref, reader.read, copied, expected_execution_sha256=execution_sha)
        self.assertEqual(restored, report)
        self.assertEqual(restored['retirement'], 'REFUSE')
        # A failure-only seal cannot be passed off as a readable execution root.
        with self.assertRaisesRegex(registry.Refusal, 'OBJECT_KIND'):
            registry.read_execution(ref, reader.read, reader.catalog, expected_run=synthetic_run_and_originals()[0],
                                    expected_originals={}, expected_commands={})
        return ref

    def test_real_synthetic_cell_publish_restore_registry_analyzer_and_transport(self):
        fixture = SyntheticExecution(self, self.base / 'source')
        self.assert_linkage(fixture.reconcile(), fixture)
        self.assertEqual(fixture.root['expected_groups'], 90)
        self.assertEqual(fixture.root['expected_cells'], 5400)
        self.assertEqual(fixture.root['present_cells'], 1)
        self.assertEqual(fixture.root['missing_cell_count'], 5399)
        self.assertEqual(fixture.root['declared_sample_count'], 1000)
        with self.assertRaisesRegex(registry.Refusal, 'ONE_FRESH_INVOCATION_LAYOUT_NOT_ESTABLISHED'):
            fixture.view.require_single_fresh_layout(expected_run=fixture.run)
        selected = fixture.view._registry.group_document(protocol.group_id(fixture.group))['captures']
        self.assertEqual(sum(row['membership'] == 'nonqualifying-retained' for row in selected), 3)
        # Duplicate publication refuses without changing either original pair.
        original = next(ref for ref in fixture.state.objects.values() if ref['kind'] == 'original')
        raw = fixture.publisher.read(original)
        before = snapshot(fixture.base)['members']
        with self.assertRaisesRegex(registry.Refusal, 'IMMUTABLE_OBJECT_NEVER_REOPENED'):
            fixture.publisher.publish('original', raw)
        self.assertEqual(snapshot(fixture.base)['members'], before)
        self.assertEqual(fixture.publisher.read(original), raw)
        for ref in fixture.state.objects.values():
            for path in registry.pair_paths(ref):
                parts = rawref.relative(path)
                self.assertTrue(all(len(part) <= 64 for part in parts))
            leaf = ref['path'].split('/')[-1].split('.')[0]
            self.assertEqual(ref['sha256'][:4] + base64.b32decode(leaf.upper()).hex(), ref['sha256'])
        seal = fixture.normal_seal()
        copied_rows = copy_tree(fixture.base, self.base / 'copy')
        copied_view = fixture.reconstruct(self.base / 'copy')
        self.assert_linkage(fixture.reconcile(self.base / 'copy', copied_view), fixture)
        reader = self.keep(OwnedReader(self.base / 'copy'))
        report = transport.validate_transport(seal, reader.read, copied_rows,
                                             expected_execution_sha256=fixture.state.execution_sha256,
                                             view=copied_view)
        self.assertFalse(report['failure_only'])
        fixture.assert_original_and_stage_retained()
        fixture.assert_original_and_stage_retained(self.base / 'copy')
        for owner in (fixture.state, fixture.publisher):
            with self.assertRaisesRegex(registry.Refusal, 'RETAIN_ALL'):
                owner.retire()

    def test_real_exclusive_publication_collision_and_complete_failure_copy(self):
        subject = self.base / 'source'
        subject.mkdir(mode=0o700)
        publisher = self.keep(publication.Publisher(subject, 'broken', storage_plan(self.context.admission)))
        # Pigeonhole gives a deterministic <=65537-iteration finite search for
        # TWO distinct synthetic originals sharing their first16 digest bits.
        # No SHA collision is alleged; all remaining digest bits stay in names.
        prefixes = {}
        prime = target = None
        for number in range(65537):
            raw = encoded({'synthetic_prefix_collision_control': number})
            prefix = hashlib.sha256(raw).hexdigest()[:4]
            if prefix in prefixes:
                prime, target = prefixes[prefix], raw
                break
            prefixes[prefix] = raw
        need(prime is not None and prime != target, 'FINITE_PREFIX_PAIR_REQUIRED')
        del prefixes
        first = publisher.publish('original', prime)
        expected = publication.publication_reference('broken', 'original', target)
        need(first['sha256'][:4] == expected['sha256'][:4] and first['sha256'] != expected['sha256'],
             'PREFIX_DIRECTORY_ALREADY_LIVE_WITH_DISTINCT_DIGESTS')
        sentinel = b'SYNTHETIC preexisting final must survive byte-for-byte\n'
        create_file(subject, expected['path'], sentinel)
        before = snapshot(subject)['members']
        with self.assertRaises(FileExistsError) as captured:
            publisher.publish('original', target)
        self.assertTrue(publisher.failed)
        self.assertEqual(captured.exception.errno, errno.EEXIST)
        reader = self.keep(OwnedReader(subject))
        self.assertEqual(reader.raw(expected['path'], len(sentinel)), sentinel)
        self.assertEqual(reader.raw(expected['path'] + '.partial', len(target)), target)
        self.assertEqual(reader.read(first), prime)
        now = snapshot(subject)['members']
        self.assertEqual([row for row in now if row['path'] != expected['path'] + '.partial'], before)
        with self.assertRaisesRegex(registry.Refusal, 'PUBLISHER_FAILED_OR_RELEASED'):
            publisher.read(first)
        create_file(subject, 'failure.json', encoded({
            'synthetic_control': True, 'observed_error_type': type(captured.exception).__name__,
            'observed_errno': captured.exception.errno, 'step': 'exclusive-final-create-after-written-partial',
            'target_reference': expected, 'retained_final': identity(sentinel),
            'retained_partial': identity(target), 'qualification': 'NOT_PERFORMED'}))
        execution_sha = registry.sha(registry.canonical(registry.execution_identity(synthetic_run_and_originals()[0])))
        self.failure_seal_and_copy(subject, execution_sha, 'ACTUAL_EEXIST_FINAL_RETAINED_PARTIAL_AND_OLD_FINAL',
                                   self.base / 'copy')

    def test_real_copied_packed_corruption_refuses_and_complete_failure_copy(self):
        fixture = SyntheticExecution(self, self.base / 'source')
        self.assert_linkage(fixture.reconcile(), fixture)
        seal = fixture.normal_seal()
        pristine = snapshot(fixture.base)['members']
        corrupt = self.base / 'corrupt'
        copy_tree(fixture.base, corrupt)
        view = fixture.reconstruct(corrupt)
        self.assert_linkage(fixture.reconcile(corrupt, view), fixture)
        selected = fixture.selectors[('3-1234abcd', 'samples')]
        reference = next(row for row in fixture.catalog['references'] if row['id'] == selected['reference_id'])
        chunk = reference['chunks'][0]
        path = '/'.join(('captures', chunk['shard'], 'txn-' + chunk['transaction'], 'packed', chunk['member']))
        reader = self.keep(OwnedReader(corrupt))
        old = reader.raw(path, rawref.CHUNK)
        need(bool(old), 'NONEMPTY_REAL_PACKED_SAMPLE')
        root = publication._owned_base(corrupt)
        parent = None
        fd = None
        try:
            parent, name = rawref._at(root, path)
            fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=parent)
            publication._file(os.fstat(fd))
            need(os.write(fd, bytes([old[0] ^ 1])) == 1, 'EXACT_ONE_BYTE_COPIED_CORRUPTION')
            os.fsync(fd)
            os.fsync(parent)
        finally:
            close_owned_descriptors(fd, parent, root)
        self.assertEqual(reader.raw(path, rawref.CHUNK), bytes([old[0] ^ 1]) + old[1:])
        with self.assertRaisesRegex(registry.Refusal, 'EVERY_STORE_MEMBER_STILL_EXACT') as captured:
            fixture.reconcile(corrupt, view)
        self.assertEqual(snapshot(fixture.base)['members'], pristine)
        fixture.assert_original_and_stage_retained()
        fixture.assert_original_and_stage_retained(corrupt)
        self.assert_linkage(fixture.reconcile(), fixture)
        with self.assertRaisesRegex(registry.Refusal, 'EVERY_TRANSPORTED_SUBJECT'):
            transport.validate_transport(seal, reader.read, snapshot(corrupt)['members'],
                                         expected_execution_sha256=fixture.state.execution_sha256, view=view)
        create_file(corrupt, 'failure.json', encoded({
            'synthetic_control': True, 'observed_error_type': type(captured.exception).__name__,
            'observed_refusal': str(captured.exception), 'step': 'actual-adapter-through-real-copied-rawref-resolver',
            'changed_path': path, 'before': identity(old),
            'after': identity(bytes([old[0] ^ 1]) + old[1:]),
            'original_and_staging_retained': True, 'qualification': 'NOT_PERFORMED'}))
        self.failure_seal_and_copy(corrupt, fixture.state.execution_sha256,
                                   'ACTUAL_PACKED_COPY_CORRUPTION_REFUSED_RETAIN_EVERY_OBSERVED_BYTE',
                                   self.base / 'failure-copy')
        failure_view = fixture.reconstruct(self.base / 'failure-copy')
        with self.assertRaisesRegex(registry.Refusal, 'EVERY_STORE_MEMBER_STILL_EXACT'):
            fixture.reconcile(self.base / 'failure-copy', failure_view)
        self.assertEqual(snapshot(fixture.base)['members'], pristine)


class BoundedResult(unittest.TextTestResult):
    """Bound retained exception text without altering success/failure status."""
    def _exc_info_to_string(self, err, test):
        value = super()._exc_info_to_string(err, test)
        if len(value.encode('utf-8')) > 65536:
            value = value[:8192] + '\n[retained traceback display bound reached]\n' + value[-8192:]
        return value


def run_suite(root, admission, *, manifest_raw, admission_raw):
    """Called only after the separate stdlib launcher's pre-import admission."""
    need(os.name == 'posix' and admission['profile'] == PROFILE and
         admission['fixture_source_bytes'] == SOURCE_BYTES and
         admission['fixture_source_entries'] == SOURCE_ENTRIES and
         admission['complete_failure_copies'] == FAILURE_COPIES and
         admission['total_reserved_bytes'] == TOTAL_RESERVED_BYTES and
         admission['total_reserved_entries'] == TOTAL_RESERVED_ENTRIES and
         admission['memory_limit_bytes'] == MEMORY_LIMIT_BYTES,
         'RUNNER_PROFILE_AND_MODULE_CONSTANTS_MUST_MATCH')
    root = Path(root)
    root.mkdir(mode=0o700)
    create_file(root, 'source-manifest.json', manifest_raw)
    create_file(root, 'runner-context.json', admission_raw)
    context = Context(root, admission)
    suite = unittest.TestSuite(PosixIntegrationContracts(name, context=context) for name in CASE_METHODS)
    result = unittest.TextTestRunner(verbosity=2, resultclass=BoundedResult).run(suite)
    guard_error = None
    observed = None
    try:
        observed = assert_tree_bound(root, data_bytes=SOURCE_DATA_BYTES, entries=SOURCE_ENTRIES)
    except BaseException as error:
        guard_error = {'type': type(error).__name__, 'reason': str(error)[:1024]}
    document = {'profile': PROFILE, 'scope': 'SYNTHETIC_FILESYSTEM_AND_LINKAGE_ONLY',
                'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
                'literal_skips': len(result.skipped), 'guard_error': guard_error,
                'observed_allocation_bytes_before_result': None if observed is None else
                    observed['observed_allocation_bytes'] + 2 * UNIT,
                'observed_entries_before_result': None if observed is None else len(observed['members']) + 1,
                'fixture_source_bytes_bound': SOURCE_BYTES, 'fixture_source_entries_bound': SOURCE_ENTRIES,
                'total_reserved_bytes_with_four_external_copies_and_overhead': TOTAL_RESERVED_BYTES,
                'admission_received': context.claim,
                'actual_kernel_quota_verified_by_harness': False,
                'four_external_failure_copies_created_by_harness': False,
                'qualification': 'NOT_PERFORMED', 'retirement': 'REFUSE',
                'unexpected_failure_transport': 'EXTERNAL_COMPLETE_RETAINED_TREE_COLLECTION_REQUIRED'}
    create_file(root, 'harness-result.json', encoded(document))
    print(json.dumps(document, sort_keys=True))
    successful = (result.wasSuccessful() and result.testsRun == 3 and not result.skipped and guard_error is None)
    return 0 if successful else 1
