"""UNEXECUTED pure metadata controls; no filesystem/native fixtures or skips.

The semantic catalogs use invented inode/control-file identities; their tiny
native/sample bytes are synthetic. Declared 1000 counts are NOT actual 1000
samples. These controls test schema/reachability/refusals, never restoration,
durability, POSIX behavior, quota, full benchmark or scientific qualification.
"""
import copy
import base64
import hashlib
import json
import stat
import unittest

import scientific_capture_protocol as protocol
import scientific_raw_reference_v2 as rawref
import scientific_execution_registry as registry
import scientific_registry_transport as transport
import scientific_registry_publication as publication


def pretty(value):
    return (json.dumps(value, indent=2) + '\n').encode('utf-8')


def run_document(readers=1, invocation='d' * 32):
    provenance = {'source': 'a' * 64, 'binaries': {
        'facetquarry': {'source': 'a' * 64, 'sha256': 'e' * 64, 'build_settings': 'SYNTHETIC'},
        'fqbench': {'source': 'a' * 64, 'sha256': 'f' * 64, 'build_settings': 'SYNTHETIC'}}}
    config = protocol.frozen_config(readers)
    value = {'format': protocol.RUN_FORMAT, 'source': 'a' * 64, 'commit': 'b' * 40,
             'execution_id': 'c' * 32, 'invocation_id': invocation,
             'github_run_id': '1', 'github_run_attempt': '1', 'grid_sha256': protocol.GRID_SHA256,
             'config': config, 'config_hash': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:12],
             'config_sha256': protocol.sha(protocol.canonical(config)), 'provenance_sha256': protocol.sha(pretty(provenance)),
             'binaries': {'facetquarry': 'e' * 64, 'fqbench': 'f' * 64}, 'admission_script_sha256': '9' * 64}
    return value, provenance


def invocation_originals(run, provenance):
    command = ['python3', 'scripts/benchmark.py', '--profile', 'full', '--concurrency', str(run['config']['concurrency']),
               '--evidence-format', registry.ROOT]
    arguments = {'profile': 'full', 'concurrency': run['config']['concurrency'], 'limit_cells': 0,
                 'evidence_format': registry.ROOT}
    start = {'format': registry.INVOCATION, **{key: run[key] for key in ('source', 'commit', 'execution_id', 'invocation_id')},
             'command': command, 'arguments': arguments, 'started_at': '2026-11-09T00:00:00Z'}
    originals = {'source_manifest': pretty({'source': run['source'], 'commit': run['commit'], 'synthetic': True}),
                 'provenance': pretty(provenance), 'config_legacy': json.dumps(run['config'], sort_keys=True).encode(),
                 'config_canonical': protocol.canonical(run['config']),
                 'guest_context': pretty({'synthetic': True, 'source': run['source']}),
                 'benchmark_start': pretty({'synthetic': True, 'source': run['source']}),
                 'invocation_start': pretty(start)}
    expected = {tag: {'bytes': len(raw), 'sha256': protocol.sha(raw)} for tag, raw in originals.items()}
    return originals, expected, command, arguments


class MemoryPublication:
    """In-memory byte mapping, explicitly NOT POSIX publication evidence."""
    def __init__(self, prefix='records'):
        self.prefix = prefix
        self.objects, self.refs, self.external, self.catalog_bytes, self.calls = {}, {}, {}, {}, []

    def sink(self, kind, raw):
        identity = protocol.sha(raw)
        leaf = base64.b32encode(bytes.fromhex(identity[4:])).decode('ascii').lower()
        path = self.prefix + '/' + kind + '/' + identity[:2] + '/' + identity[2:4] + '/' + leaf
        path += '.raw' if kind == 'original' else '.json'
        ref = {'kind': kind, 'path': path, 'bytes': len(raw), 'sha256': identity}
        if path not in self.objects:
            self.calls.append((kind, len(raw)))
        self.objects[path], self.refs[path] = raw, ref
        return copy.deepcopy(ref)

    def read(self, ref):
        return self.objects[ref['path']]

    def catalog(self, store, expected_sha, maximum):
        raw = self.catalog_bytes[store]
        if len(raw) > maximum or protocol.sha(raw) != expected_sha:
            raise registry.Refusal('FIXTURE_CATALOG_EXPECTATION')
        return raw

    def add_catalog_rows(self, store, raw):
        self.catalog_bytes[store] = raw
        catalog = json.loads(raw)
        self.external[store] = {'path': store, 'kind': 'directory', 'bytes': 0, 'sha256': None}
        for name in ('catalog.json', 'catalog.partial'):
            path = store + '/' + name
            self.external[path] = {'path': path, 'kind': 'file', 'bytes': len(raw), 'sha256': protocol.sha(raw)}
        for item in catalog['inventory']:
            path = store + '/' + item['path']
            self.external[path] = {'path': path, 'kind': item['kind'], 'bytes': item.get('bytes', 0), 'sha256': item.get('sha256')}

    def observed(self):
        rows = copy.deepcopy(self.external)
        for path, ref in self.refs.items():
            for candidate in (path, path + '.partial'):
                rows[candidate] = {'path': candidate, 'kind': 'file', 'bytes': ref['bytes'], 'sha256': ref['sha256']}
        for path in list(rows):
            parts = path.split('/')
            for count in range(1, len(parts)):
                parent = '/'.join(parts[:count])
                rows.setdefault(parent, {'path': parent, 'kind': 'directory', 'bytes': 0, 'sha256': None})
        return sorted(rows.values(), key=lambda row: row['path'])


def scope_document(run, stage, index=0, group_index=0):
    group = protocol.all_groups(run)[group_index]
    if stage != 'measurement':
        return registry.group_scope(group, run)
    cells = protocol.cells_for_group(group, run)
    cid = sorted(cells)[index]
    return {'kind': 'cell', 'group_id': protocol.group_id(group), 'cell_id': cid, 'cell': cells[cid]}


def expected_native_command(run, stage):
    return {'admission': ['python3', 'scripts/disk_guard.py', '--reserve', '500000000'],
            'build': ['/owned/facetquarry', 'build', '--input', '/owned/corpus.json', '--output', '/owned/index.fq'],
            'measurement': ['/owned/fqbench', '--index', '/owned/index.fq', '--tenant', 'alpha', '--queries', '/owned/queries.jsonl',
                            '--warmup', '20', '--repetitions', '5', '--concurrency', str(run['config']['concurrency'])]}[stage]


def native_documents(run, stage, number, *, index=0, outcome='success', group_index=0):
    scope = scope_document(run, stage, index, group_index)
    seed = (scope.get('group') or scope['cell'])['seed']
    roles = ('stdout', 'stderr', 'samples') if stage == 'measurement' else ('stdout', 'stderr')
    bindings, data = [], []
    for role in roles:
        raw = {'stdout': b'SYNTHETIC native\xff\n', 'stderr': b'', 'samples': b'{"synthetic":true}\n'}[role]
        binding = {'format': protocol.BINDING_FORMAT, 'run_sha256': registry.run_sha(run), 'scope': scope,
                   'workload_seed': seed, 'build_seed': seed, 'attempt_id': str(number) + '-1234abcd',
                   'stage': stage, 'role': role, 'outcome': outcome,
                   'completeness': 'complete' if outcome in ('success', 'failed') else 'available-partial',
                   'origin': 'new-normalized-original' if role == 'samples' else 'new-native-original',
                   'generation': '1' * 64 if stage == 'measurement' else None,
                   'corpus_sha256': None if stage == 'admission' else '2' * 64,
                   'queries_sha256': '3' * 64 if stage == 'measurement' else None,
                   'producer': protocol.producer_for(stage, run)}
        bindings.append(binding)
        data.append(raw)
    start = {'admission': 1, 'build': 3, 'measurement': 5}[stage]
    value = {'format': protocol.ATTEMPT_FORMAT, 'run_sha256': registry.run_sha(run), 'scope': scope,
             'attempt_id': bindings[0]['attempt_id'], 'stage': stage, 'producer': protocol.producer_for(stage, run),
             'command': expected_native_command(run, stage), 'started_at': '2026-11-09T00:00:0%dZ' % start,
             'ended_at': '2026-11-09T00:00:0%dZ' % (start + 1), 'duration_seconds': 1, 'timeout_seconds': 900,
             'exit_code': 0 if outcome == 'success' else 1 if outcome == 'failed' else None,
             'termination_reason': {'success': None, 'failed': None, 'timeout': 'timeout',
                                    'start-error': 'start_error', 'available-partial': 'available_partial'}[outcome],
             'error': None, 'status': 'PASS' if outcome == 'success' else 'FAIL',
             'captures': {binding['role']: protocol.sha(protocol.canonical(binding)) for binding in bindings}}
    return value, list(zip(bindings, data))


def catalog_fixture(run, members, number):
    """Independent tiny semantic fixture, not a mock successful resolver."""
    refs, transactions, rows = [], [], {}
    def directory(path):
        rows[path] = {'path': path, 'kind': 'directory', 'identity': [1, len(rows) + 1, stat.S_IFDIR | 0o700, 2]}
    def file(path, length=0, digest='a' * 64):
        rows[path] = {'path': path, 'kind': 'file', 'bytes': length, 'sha256': digest,
                      'identity': [1, len(rows) + 1, stat.S_IFREG | 0o600, 1, length, 0, 0]}
    directory('originals')
    directory('shards')
    directory('shards/s0000')
    for index, (binding, data) in enumerate(members):
        txindex = index // 4
        txid = '%032x' % (number * 1000 + txindex + 1)
        name = 'm%08d' % index
        original_id = '%032x' % (number * 1000 + index + 1)
        original_path = 'originals/' + original_id + '.raw'
        file(original_path, len(data), protocol.sha(data))
        member = {'name': name, 'bytes': len(data), 'sha256': protocol.sha(data), 'encoding': 'identity'}
        chunk = {'index': 0, 'offset': 0, 'bytes': len(data), 'sha256': protocol.sha(data), 'shard': 'shards/s0000',
                 'transaction': txid, 'member': name, 'encoding': 'identity'}
        refs.append({'format': rawref.FORMAT, 'id': original_id, 'binding': copy.deepcopy(binding),
                     'original': {'path': original_path, 'bytes': len(data), 'sha256': protocol.sha(data),
                                  'identity': rows[original_path]['identity']}, 'chunks': [chunk], 'writers_closed': True})
        if index % 4 == 0:
            transactions.append({'shard': 'shards/s0000', 'transaction': txid, 'members': [],
                                 'declaration_sha256': 'a' * 64, 'manifest_sha256': 'a' * 64,
                                 'commit_sha256': 'a' * 64, 'closed_sha256': 'a' * 64})
            base = 'shards/s0000/txn-' + txid
            directory(base)
            directory(base + '/stage')
            directory(base + '/packed')
            for control in ('.writer', 'transaction.json', 'manifest.json', 'commit.json', 'closed.json'):
                file(base + '/' + control)
        transactions[-1]['members'].append(member)
        base = 'shards/s0000/txn-' + txid
        file(base + '/stage/' + name, len(data), protocol.sha(data))
        file(base + '/packed/' + name, len(data), protocol.sha(data))
    value = {'version': 2, 'format': rawref.CATALOG_FORMAT, 'catalog_id': '%032x' % number, 'run': run,
             'references': refs, 'transactions': transactions, 'inventory': sorted(rows.values(), key=lambda row: row['path']),
             'retirement': 'unsupported-retain-all-original-and-primitive-staging',
             'scope': 'storage-only-no-scientific-quota-or-release-qualification'}
    return protocol.canonical(value)


class Fixture:
    def __init__(self, cell_count=1, *, native_outcome='success', collector_status='PASS', readers=1):
        self.run, self.provenance = run_document(readers)
        self.memory = MemoryPublication()
        self.state = registry.ExecutionRegistry(self.run, self.memory.sink)
        originals, expected, command, args = invocation_originals(self.run, self.provenance)
        self.expected_originals = {registry.run_sha(self.run): {**expected, 'collector_command': command, 'collector_arguments': args}}
        self.state.record_invocation(self.run, originals, expected_originals=expected, expected_command=command, expected_arguments=args)
        admission, admission_members = native_documents(self.run, 'admission', 1)
        build, build_members = native_documents(self.run, 'build', 2)
        measurements = [native_documents(self.run, 'measurement', 100 + index, index=index, outcome=native_outcome)
                        for index in range(cell_count)]
        members = admission_members + build_members + [member for _, items in measurements for member in items]
        self.catalog_number = 1
        for offset in range(0, len(members), 64):
            self.add_catalog(members[offset:offset + 64])
        self.commands, self.attempt_refs = {}, {}
        for attempt in [admission, build] + [item for item, _ in measurements]:
            expected_command = expected_native_command(self.run, attempt['stage'])
            self.commands[(registry.run_sha(self.run), attempt['attempt_id'])] = expected_command
            self.attempt_refs[attempt['attempt_id']] = self.state.record_attempt(attempt, expected_command=expected_command)
        self.summary_documents = []
        for index, (measurement, _) in enumerate(measurements):
            sample = self.state.captures[measurement['captures']['samples']]['selector']
            summary = {'evidence_format': registry.SUMMARY, 'run_sha256': registry.run_sha(self.run),
                       'scope': measurement['scope'], 'cell': measurement['scope']['cell'], 'source': self.run['source'],
                       'provenance': self.provenance, 'status': collector_status, 'collector_status': collector_status,
                       'stage': 'measurement', 'errors': [] if collector_status == 'PASS' else ['SYNTHETIC collector parse failure'],
                       'sample_count': 1000 if collector_status == 'PASS' else 0,
                       'generation': '1' * 64, 'corpus_sha256': '2' * 64, 'queries_sha256': '3' * 64,
                       'dependencies': {'admission': self.attempt_refs[admission['attempt_id']],
                                        'build': self.attempt_refs[build['attempt_id']],
                                        'measurement': self.attempt_refs[measurement['attempt_id']]},
                       'inputs': {'corpus': None, 'queries': None}, 'samples_reference': sample,
                       'samples_original_sha256': sample['sha256'], 'native_metadata': {'synthetic': True},
                       'started_at': '2026-11-09T00:00:04Z', 'ended_at': '2026-11-09T00:00:07Z'}
            self.summary_documents.append(copy.deepcopy(summary))
            self.state.record_cell(pretty(summary))

    def add_catalog(self, members, *, run=None, store=None):
        run = self.run if run is None else run
        raw = catalog_fixture(run, members, self.catalog_number)
        store = 'captures/b%04d' % self.catalog_number if store is None else store
        self.catalog_number += 1
        ref = self.state.record_catalog(raw, store, expected_run=run)
        self.memory.add_catalog_rows(store, raw)
        return ref, raw

    def freeze(self):
        self.root_ref, self.root = self.state.finalize()
        return self.read(self.root_ref)

    def read(self, ref):
        return registry.read_execution(ref, self.memory.read, self.memory.catalog, expected_run=self.run,
                                       expected_originals=self.expected_originals, expected_commands=self.commands)


def small_plan():
    counts = {kind: 0 for kind in registry.LIMITS}
    body = {kind: 0 for kind in registry.LIMITS}
    counts.update(original=8, anchor=1, catalog=3, attempt=3, cell=1, group=90, root=1, retained=1,
                  **{'transport-page': 8, 'transport': 1})
    for kind in counts:
        body[kind] = counts[kind] * min(registry.LIMITS[kind], 4096)
    extents = {name: {'data_bytes': 0, 'entries': 0} for name in publication.EXTENTS}
    extents['registry_pairs'] = {'data_bytes': 2 * sum(body.values()), 'entries': 4 * sum(counts.values()) + len(registry.LIMITS) + 1}
    extents['originals'] = {'data_bytes': 1 << 20, 'entries': 16}
    extents['primitive_staging'] = {'data_bytes': 1 << 20, 'entries': 32}
    extents['packed_candidates'] = {'data_bytes': 2 << 20, 'entries': 32}
    extents['catalog_pairs'] = {'data_bytes': 1 << 20, 'entries': 16}
    extents['nonqualifying'] = {'data_bytes': 1 << 20, 'entries': 16}
    extents['outer_artifacts'] = {'data_bytes': 1 << 20, 'entries': 16}
    extents['failure_transport'] = {'data_bytes': 2 * sum(extents[name]['data_bytes'] for name in publication.SOURCE_EXTENTS),
                                    'entries': 2 * sum(extents[name]['entries'] for name in publication.SOURCE_EXTENTS)}
    return publication.StoragePlan(1_000_000_000, 10_000_000, 2_000_000_000, extents, counts, body)


def premeasurement_summary(fixture, *, stage, dependencies, index=0):
    """Synthetic original summary; no native samples or process execution."""
    scope = scope_document(fixture.run, 'measurement', index)
    status = 'NOT_RUN' if stage == 'not-started' else 'FAIL'
    return {'evidence_format': registry.SUMMARY, 'run_sha256': registry.run_sha(fixture.run),
            'scope': scope, 'cell': scope['cell'], 'source': fixture.run['source'],
            'provenance': fixture.provenance, 'status': status, 'collector_status': status,
            'stage': stage, 'errors': [] if status == 'NOT_RUN' else ['SYNTHETIC premeasurement failure'],
            'sample_count': 0, 'generation': None, 'corpus_sha256': '2' * 64 if stage == 'build' else None,
            'queries_sha256': None, 'dependencies': dependencies, 'inputs': {'corpus': None, 'queries': None},
            'samples_reference': None, 'samples_original_sha256': None, 'native_metadata': None,
            'started_at': '2026-11-09T00:00:00Z', 'ended_at': '2026-11-09T00:00:07Z'}


class PureRegistryContracts(unittest.TestCase):
    def test_full_cell_count_metadata_paths_bound_first_two_prefix_fanouts(self):
        # Synthetic pathname arithmetic only: not 5400 native cells or a POSIX
        # allocation/durability/qualification result.
        first, second = set(), {}
        for number in range(5400):
            ref = publication.publication_reference('records', 'cell', protocol.canonical({'synthetic_cell': number}))
            parts = rawref.relative(ref['path'])
            first.add(parts[2]); second.setdefault(parts[2], set()).add(parts[3])
            self.assertTrue(all(len(part) <= 64 for part in rawref.relative(ref['path']+'.partial')))
        self.assertLessEqual(len(first), 256)
        self.assertTrue(all(len(children) <= 256 for children in second.values()))

    def test_pair_paths_fit_immutable_dependency_and_encode_entire_digest(self):
        for kind, raw in (('original', b'\x00\xff'), ('cell', protocol.canonical({'synthetic': True}))):
            with self.subTest(kind=kind):
                ref = publication.publication_reference('records', kind, raw)
                suffix = '.raw' if kind == 'original' else '.json'
                parts = rawref.relative(ref['path'])
                remaining = base64.b32decode(parts[4][:-len(suffix)].upper()).hex()
                self.assertEqual(parts[2]+parts[3]+remaining, protocol.sha(raw))
                self.assertTrue(all(len(part) <= 64 for part in parts))
                self.assertTrue(all(len(part) <= 64 for part in rawref.relative(ref['path']+'.partial')))
        accepted = {'kind': 'cell', 'path': 'records/'+'a'*51+'.json', 'bytes': 1, 'sha256': 'a'*64}
        self.assertEqual(registry.reference(accepted), accepted)
        rejected = {**accepted, 'path': 'records/'+'a'*52+'.json'}
        with self.assertRaisesRegex(registry.Refusal, 'PORTABLE_COMPONENT'):
            registry.reference(rejected)

    def test_preinput_and_prequery_identities_cannot_be_invented(self):
        for stage in ('not-started', 'admission', 'build'):
            keys = ('generation', 'corpus_sha256', 'queries_sha256') if stage != 'build' else ('generation', 'queries_sha256')
            for key in keys:
                with self.subTest(stage=stage, identity=key):
                    fixture = Fixture(cell_count=0)
                    deps = {'admission': None if stage == 'not-started' else fixture.attempt_refs['1-1234abcd'],
                            'build': fixture.attempt_refs['2-1234abcd'] if stage == 'build' else None,
                            'measurement': None}
                    summary = premeasurement_summary(fixture, stage=stage, dependencies=deps)
                    summary[key] = 'a'*64
                    with self.assertRaisesRegex(registry.Refusal, 'IDENTIT|UNAVAILABLE'):
                        fixture.state.record_cell(pretty(summary))

    def test_each_reader_keeps_ninety_disjoint_groups_and_exact_sixty_cells(self):
        reader_cells = []
        for readers in (1, 4, 16):
            run, _ = run_document(readers)
            groups = protocol.all_groups(run)
            cells = [cid for group in groups for cid in protocol.cells_for_group(group, run)]
            self.assertEqual((len(groups), len(cells), len(set(cells))), (90, 5400, 5400))
            reader_cells.append(set(cells))
        self.assertFalse(reader_cells[0] & reader_cells[1])
        self.assertFalse(reader_cells[1] & reader_cells[2])

    def test_shared_four_group_streams_serve_all_sixty_without_duplicate_bytes(self):
        fixture = Fixture(60)
        self.assertEqual(len(fixture.state.captures), 184)
        self.assertEqual(len(fixture.state.catalogs), 3)
        self.assertTrue(all(count <= 64 for count in [len(item['catalog']['references']) for item in fixture.state.catalogs.values()]))
        before = len(fixture.memory.calls)
        self.assertFalse(any(kind in ('group', 'root') for kind, _ in fixture.memory.calls))
        view = fixture.freeze()
        self.assertEqual(len(fixture.memory.calls) - before, 91)
        admission_refs = {protocol.sha(protocol.canonical(item['value']['dependencies']['admission'])) for item in fixture.state.cells.values()}
        build_refs = {protocol.sha(protocol.canonical(item['value']['dependencies']['build'])) for item in fixture.state.cells.values()}
        self.assertEqual((len(admission_refs), len(build_refs)), (1, 1))
        self.assertEqual(view.root['qualification'], 'NOT_PERFORMED')
        with self.assertRaises(registry.Refusal):
            view.require_single_fresh_layout(expected_run=fixture.run)

    def test_logical_conflicts_and_actual_attempt_owner_span_separate_catalogs(self):
        fixture = Fixture(0)
        _, conflict = native_documents(fixture.run, 'admission', 1, outcome='failed')
        with self.assertRaisesRegex(registry.Refusal, 'DUPLICATE_LOGICAL'):
            fixture.add_catalog(conflict[:1])
        _, foreign = native_documents(fixture.run, 'build', 1, group_index=1)
        with self.assertRaisesRegex(registry.Refusal, 'ONE_OWNER'):
            fixture.add_catalog(foreign[:1])
        self.assertEqual(len(fixture.state.captures), 4)

    def test_identical_selector_references_are_valid_but_catalog_reopen_refuses(self):
        fixture = Fixture(2)
        document = next(iter(fixture.state.catalogs.values()))
        raw = fixture.memory.catalog_bytes[document['document']['store']]
        with self.assertRaisesRegex(registry.Refusal, 'REOPEN'):
            fixture.state.record_catalog(raw, document['document']['store'], expected_run=fixture.run)
        self.assertEqual(len(fixture.state.cells), 2)

    def test_external_attempt_is_acyclic_and_not_a_catalog_member(self):
        fixture = Fixture()
        for item in fixture.state.attempts.values():
            raw = fixture.memory.read(item['ref'])
            self.assertEqual(protocol.sha(raw), item['ref']['sha256'])
            self.assertTrue(all(not item['ref']['path'].startswith(store + '/') for store in fixture.state.catalog_stores))
            self.assertEqual(set(item['value']['captures']), {'stdout', 'stderr', 'samples'} if item['value']['stage'] == 'measurement' else {'stdout', 'stderr'})
        self.assertTrue(all(item['binding']['role'] != 'attempt' for item in fixture.state.captures.values()))

    def test_native_success_can_be_collector_failure_and_stays_retained(self):
        fixture = Fixture(1, collector_status='FAIL')
        view = fixture.freeze()
        cid = next(iter(fixture.state.cells))
        cell = view.checked_cell(cid, expected_run=fixture.run)
        self.assertEqual((cell.measurement['status'], cell.record['collector_status']), ('PASS', 'FAIL'))
        self.assertIsNotNone(cell.samples_reference)
        self.assertEqual(cell.stdout_binding['attempt_id'], cell.samples_binding['attempt_id'])

    def test_failed_native_cannot_be_promoted_to_collector_pass(self):
        fixture = Fixture(1, native_outcome='timeout', collector_status='FAIL')
        changed = copy.deepcopy(fixture.summary_documents[0])
        changed.update(status='PASS', collector_status='PASS', errors=[], sample_count=1000)
        with self.assertRaisesRegex(registry.Refusal, 'FAILED_NATIVE'):
            fixture.state.record_cell(pretty(changed))
        owner = next(item for item in fixture.state.attempts.values() if item['value']['stage'] == 'measurement')
        changed_attempt = copy.deepcopy(owner['value'])
        changed_attempt.update(exit_code=0, termination_reason=None, status='PASS')
        with self.assertRaisesRegex(registry.Refusal, 'CAPTURE_BINDING'):
            fixture.state.record_attempt(changed_attempt, expected_command=expected_native_command(fixture.run, 'measurement'))

    def test_wrong_expected_command_and_replacement_native_outcome_refuse(self):
        fixture = Fixture()
        attempt = copy.deepcopy(next(item['value'] for item in fixture.state.attempts.values() if item['value']['stage'] == 'measurement'))
        attempt['command'] = ['true']
        with self.assertRaisesRegex(registry.Refusal, 'EXACT_STAGE_COMMAND'):
            fixture.state.record_attempt(attempt, expected_command=expected_native_command(fixture.run, 'measurement'))
        attempt['command'] = expected_native_command(fixture.run, 'measurement')
        attempt['exit_code'] = True
        with self.assertRaises(registry.Refusal):
            fixture.state.record_attempt(attempt, expected_command=expected_native_command(fixture.run, 'measurement'))

    def test_original_invocation_is_preserved_and_resume_union_is_never_fresh(self):
        fixture = Fixture()
        run2, provenance2 = run_document(invocation='8' * 32)
        originals, expected, command, args = invocation_originals(run2, provenance2)
        fixture.state.record_invocation(run2, originals, expected_originals=expected, expected_command=command, expected_arguments=args)
        fixture.expected_originals[registry.run_sha(run2)] = {**expected, 'collector_command': command, 'collector_arguments': args}
        _, reused_id = native_documents(run2, 'measurement', 100)
        with self.assertRaisesRegex(registry.Refusal, 'ONE_OWNER'):
            fixture.add_catalog(reused_id, run=run2)
        view = fixture.freeze()
        self.assertEqual(view.root['invocation_coherence'], 'multiple-or-no-original-invocations')
        cid = next(iter(fixture.state.cells))
        with self.assertRaisesRegex(registry.Refusal, 'CANNOT_BE_RELABELLED'):
            view.checked_cell(cid, expected_run=run2)
        with self.assertRaises(registry.Refusal):
            view.require_single_fresh_layout(expected_run=run2)

    def test_original_provenance_config_and_invocation_bytes_are_external_trust(self):
        run, provenance = run_document()
        originals, expected, command, args = invocation_originals(run, provenance)
        original = originals['provenance']
        originals['provenance'] = protocol.canonical(provenance)
        with self.assertRaisesRegex(registry.Refusal, 'TRUSTED_ORIGINAL'):
            registry.validate_originals(run, originals, expected, command, args)
        originals['provenance'] = original
        originals['config_legacy'] = originals['config_canonical']
        expected['config_legacy'] = {'bytes': len(originals['config_legacy']), 'sha256': protocol.sha(originals['config_legacy'])}
        with self.assertRaisesRegex(registry.Refusal, 'BOTH_ORIGINAL_CONFIG'):
            registry.validate_originals(run, originals, expected, command, args)

    def test_exact_missing_duplicate_foreign_and_wrong_reader_group_memberships(self):
        fixture = Fixture()
        view = fixture.freeze()
        row = next(row for row in fixture.root['groups'] if json.loads(fixture.memory.read(row['page']))['cells'][0]['record'] is not None)
        page = json.loads(fixture.memory.read(row['page']))
        variants = []
        missing = copy.deepcopy(page)
        missing['cells'].pop()
        variants.append(missing)
        duplicate = copy.deepcopy(page)
        duplicate['cells'][-1] = copy.deepcopy(duplicate['cells'][0])
        variants.append(duplicate)
        foreign = copy.deepcopy(page)
        foreign['cells'][-1]['cell_id'] = '0' * 20
        variants.append(foreign)
        wrong_reader = copy.deepcopy(page)
        wrong_reader['scope']['group']['concurrency'] = 4
        variants.append(wrong_reader)
        for mutated in variants:
            ref = fixture.memory.sink('group', protocol.canonical(mutated))
            root = copy.deepcopy(fixture.root)
            next(item for item in root['groups'] if item['group_id'] == row['group_id'])['page'] = ref
            root_ref = fixture.memory.sink('root', protocol.canonical(root))
            with self.assertRaises(registry.Refusal):
                fixture.read(root_ref)
        self.assertEqual(view.root['present_cells'], 1)

    def test_missing_catalog_selector_attempt_and_foreign_cell_record_refuse(self):
        fixture = Fixture()
        cat = next(iter(fixture.state.catalogs.values()))
        mutated = copy.deepcopy(cat['document'])
        mutated['selectors'].pop()
        ref = fixture.memory.sink('catalog', protocol.canonical(mutated))
        with self.assertRaisesRegex(registry.Refusal, 'EXACT_SELECTOR_MEMBERSHIP'):
            fixture.state.accept_catalog(mutated, ref, fixture.memory.catalog_bytes[cat['document']['store']])
        changed_summary = copy.deepcopy(fixture.summary_documents[0])
        changed_summary['dependencies']['measurement'] = None
        with self.assertRaises(registry.Refusal):
            fixture.state.record_cell(pretty(changed_summary))
        changed_summary = copy.deepcopy(fixture.summary_documents[0])
        changed_summary['samples_reference']['reference_id'] = '0' * 32
        with self.assertRaisesRegex(registry.Refusal, 'SAMPLE_REFERENCE'):
            fixture.state.record_cell(pretty(changed_summary))

    def test_root_missing_group_and_invented_complete_counts_refuse(self):
        fixture = Fixture()
        fixture.freeze()
        missing = copy.deepcopy(fixture.root)
        missing['groups'].pop()
        invented = copy.deepcopy(fixture.root)
        invented.update(present_cells=5400, missing_cell_count=0, declared_sample_count=5_400_000)
        for mutated in (missing, invented):
            ref = fixture.memory.sink('root', protocol.canonical(mutated))
            with self.assertRaises(registry.Refusal):
                fixture.read(ref)

    def test_new_summary_cannot_mix_legacy_gzip_hash_or_unknown_format(self):
        fixture = Fixture()
        for key, value in (('samples_sha256', 'a' * 64), ('evidence_format', 'legacy-gzip')):
            summary = copy.deepcopy(fixture.summary_documents[0])
            summary[key] = value
            with self.assertRaisesRegex(registry.Refusal, 'NEW_SUMMARY_NO_LEGACY_MIX'):
                fixture.state.record_cell(pretty(summary))

    def test_failed_unselected_and_unreferenced_captures_are_explicitly_nonqualifying(self):
        fixture = Fixture()
        failed, members = native_documents(fixture.run, 'measurement', 999, index=1, outcome='failed')
        fixture.add_catalog(members)
        fixture.state.record_attempt(failed, expected_command=expected_native_command(fixture.run, 'measurement'))
        fixture.commands[(registry.run_sha(fixture.run), failed['attempt_id'])] = expected_native_command(fixture.run, 'measurement')
        _, unknown_members = native_documents(fixture.run, 'measurement', 1000, index=2, outcome='available-partial')
        fixture.add_catalog(unknown_members)
        page = fixture.state.group_document(failed['scope']['group_id'])
        retained = [row for row in page['captures'] if row['membership'] == 'nonqualifying-retained']
        self.assertEqual(len(retained), 6)
        self.assertTrue(all(row['reason'] for row in retained))
        fixture.freeze()

    def test_batch_splitting_checks_both_caps_without_allocating_payloads(self):
        run, _ = run_document()
        items = []
        for index in range(65):
            _, members = native_documents(run, 'measurement', 100 + index, index=index % 60)
            items.append({'binding': members[0][0], 'bytes': 1})
        self.assertEqual([len(batch) for batch in protocol.split_batches(items, run)], [64, 1])
        items = items[:2]
        items[0]['bytes'] = protocol.MAX_BATCH_BYTES
        self.assertEqual([len(batch) for batch in protocol.split_batches(items, run)], [1, 1])
        items[0]['bytes'] += 1
        with self.assertRaises(protocol.Refusal):
            protocol.split_batches(items, run)

    def test_structural_token_string_and_object_bounds_precede_json_decoding(self):
        with self.assertRaisesRegex(registry.Refusal, 'DEPTH'):
            registry.decode(b'[' * 33 + b'0' + b']' * 33, 1024)
        with self.assertRaisesRegex(registry.Refusal, 'TOKEN'):
            registry.decode(b'[' + b'0,' * registry.MAX_JSON_TOKENS + b'0]', 1 << 20)
        with self.assertRaisesRegex(registry.Refusal, 'STRING'):
            registry.decode(b'"' + b'x' * (registry.MAX_JSON_STRING_BYTES + 1) + b'"', 1 << 20)
        with self.assertRaisesRegex(registry.Refusal, 'OBJECT_BYTE_BOUND'):
            registry.decode(b'{}\n', 2)

    def test_budget_requires_all_original_packed_staging_overlap_and_failure_copies(self):
        plan = small_plan()
        result = plan.validate()
        self.assertEqual(result['kernel_quota'], 'NOT_ESTABLISHED_BY_NUMERIC_PLAN')
        damaged = copy.deepcopy(plan.extents)
        damaged['failure_transport']['data_bytes'] -= 1
        bad = publication.StoragePlan(plan.global_baseline_bytes, plan.global_other_growth_bytes, plan.global_reserve_bytes,
                                      damaged, plan.object_counts, plan.object_bytes)
        with self.assertRaisesRegex(registry.Refusal, 'FAILURE_TRANSPORT'):
            bad.validate()
        damaged = copy.deepcopy(plan.extents)
        del damaged['primitive_staging']
        with self.assertRaises(registry.Refusal):
            publication.StoragePlan(0, 0, 2_000_000_000, damaged, plan.object_counts, plan.object_bytes).validate()
        with self.assertRaisesRegex(registry.Refusal, 'PEAK_RESERVATION'):
            publication.StoragePlan(11_000_000_000, 0, 2_000_000_000, plan.extents, plan.object_counts, plan.object_bytes).validate()

    def test_frozen_registry_and_all_retirement_apis_refuse(self):
        fixture = Fixture()
        fixture.freeze()
        with self.assertRaisesRegex(registry.Refusal, 'FROZEN'):
            fixture.state.record_cell(pretty(fixture.summary_documents[0]))
        with self.assertRaisesRegex(registry.Refusal, 'POST_RETIREMENT'):
            fixture.state.retire()

    def test_all_seven_originals_remain_exact_bytes_and_require_independent_hashes(self):
        fixture = Fixture(0)
        originals, expected, command, args = invocation_originals(fixture.run, fixture.provenance)
        anchor_ref = fixture.state.anchors[registry.run_sha(fixture.run)]
        anchor = json.loads(fixture.memory.read(anchor_ref))
        for tag in registry.ORIGINAL_TAGS:
            with self.subTest(tag=tag):
                self.assertEqual(fixture.memory.read(anchor['originals'][tag]), originals[tag])
                changed = dict(originals)
                changed[tag] += b'\n'
                with self.assertRaisesRegex(registry.Refusal, 'TRUSTED_ORIGINAL_' + tag):
                    registry.validate_originals(fixture.run, changed, expected, command, args)

    def test_persisted_invocation_cannot_supply_its_own_command_or_argument_expectation(self):
        run, provenance = run_document()
        originals, expected, command, args = invocation_originals(run, provenance)
        for field, changed_value in (('command', ['true']), ('arguments', {'profile': 'smoke'})):
            with self.subTest(field=field):
                changed = dict(originals)
                start = json.loads(changed['invocation_start'])
                start[field] = changed_value
                changed['invocation_start'] = pretty(start)
                # Even separately trusted replacement bytes cannot alter the
                # independently selected collector argv/argument semantics.
                changed_expected = copy.deepcopy(expected)
                changed_expected['invocation_start'] = {'bytes': len(changed['invocation_start']),
                                                         'sha256': protocol.sha(changed['invocation_start'])}
                with self.assertRaisesRegex(registry.Refusal, 'PERSISTED_ORIGINAL_INVOCATION'):
                    registry.validate_originals(run, changed, changed_expected, command, args)

    def test_not_started_cell_preserves_null_dependencies_and_zero_samples(self):
        fixture = Fixture(0)
        summary = premeasurement_summary(fixture, stage='not-started',
                                         dependencies={'admission': None, 'build': None, 'measurement': None})
        fixture.state.record_cell(pretty(summary))
        view = fixture.freeze()
        checked = view.checked_cell(summary['scope']['cell_id'], expected_run=fixture.run)
        self.assertEqual((checked.record['stage'], checked.record['collector_status'], checked.record['sample_count']),
                         ('not-started', 'NOT_RUN', 0))
        self.assertIsNone(checked.admission)
        self.assertIsNone(checked.measurement)
        self.assertIsNone(checked.samples_reference)
        self.assertEqual(view.root['missing_cell_count'], 5399)

    def test_failed_group_admission_is_shared_without_inventing_input_identities(self):
        fixture = Fixture(0)
        failed, members = native_documents(fixture.run, 'admission', 21, outcome='start-error')
        fixture.add_catalog(members)
        argv = expected_native_command(fixture.run, 'admission')
        failed_ref = fixture.state.record_attempt(failed, expected_command=argv)
        fixture.commands[(registry.run_sha(fixture.run), failed['attempt_id'])] = argv
        for index in (0, 1):
            summary = premeasurement_summary(fixture, stage='admission', index=index,
                                             dependencies={'admission': failed_ref, 'build': None, 'measurement': None})
            fixture.state.record_cell(pretty(summary))
        view = fixture.freeze()
        for cid in fixture.state.cells:
            checked = view.checked_cell(cid, expected_run=fixture.run)
            self.assertEqual(checked.admission['attempt_id'], failed['attempt_id'])
            self.assertEqual(checked.admission['termination_reason'], 'start_error')
            self.assertTrue(all(checked.record[key] is None for key in ('generation', 'corpus_sha256', 'queries_sha256')))
            self.assertIsNone(checked.build)
            self.assertIsNone(checked.measurement)
            self.assertIsNone(checked.samples_reference)
        selected = fixture.state._selected_capture_ids(failed['scope']['group_id'])
        self.assertEqual(selected, set(failed['captures'].values()))

    def test_failed_group_build_is_retained_without_cell_samples(self):
        fixture = Fixture(0)
        failed, members = native_documents(fixture.run, 'build', 22, outcome='failed')
        fixture.add_catalog(members)
        argv = expected_native_command(fixture.run, 'build')
        failed_ref = fixture.state.record_attempt(failed, expected_command=argv)
        fixture.commands[(registry.run_sha(fixture.run), failed['attempt_id'])] = argv
        admission = next(item['ref'] for item in fixture.state.attempts.values() if item['value']['stage'] == 'admission')
        summary = premeasurement_summary(fixture, stage='build',
                                         dependencies={'admission': admission, 'build': failed_ref, 'measurement': None})
        fixture.state.record_cell(pretty(summary))
        checked = fixture.freeze().checked_cell(summary['scope']['cell_id'], expected_run=fixture.run)
        self.assertEqual((checked.build['status'], checked.record['collector_status']), ('FAIL', 'FAIL'))
        self.assertEqual(checked.record['corpus_sha256'], '2' * 64)
        self.assertIsNone(checked.record['queries_sha256'])
        self.assertIsNone(checked.measurement)
        self.assertIsNone(checked.samples_reference)

    def test_cell_dependency_cannot_start_build_after_failed_admission(self):
        fixture = Fixture()
        failed, members = native_documents(fixture.run, 'admission', 23, outcome='failed')
        fixture.add_catalog(members)
        ref = fixture.state.record_attempt(failed, expected_command=expected_native_command(fixture.run, 'admission'))
        changed = copy.deepcopy(fixture.summary_documents[0])
        changed['dependencies']['admission'] = ref
        with self.assertRaisesRegex(registry.Refusal, 'BUILD_AFTER_FAILED_ADMISSION'):
            fixture.state.record_cell(pretty(changed))

    def test_cached_reconstruction_refuses_missing_and_corrupt_external_objects(self):
        fixture = Fixture()
        fixture.freeze()
        target = next(iter(fixture.state.cells.values()))['value']['summary']['path']
        def missing(ref):
            if ref['path'] == target:
                raise registry.Refusal('SYNTHETIC_MISSING_CACHED_OBJECT')
            return fixture.memory.read(ref)
        def corrupt(ref):
            raw = fixture.memory.read(ref)
            return raw + b'\n' if ref['path'] == target else raw
        for reader in (missing, corrupt):
            with self.subTest(reader=reader.__name__):
                with self.assertRaises(registry.Refusal):
                    registry.read_execution(fixture.root_ref, reader, fixture.memory.catalog, expected_run=fixture.run,
                                            expected_originals=fixture.expected_originals, expected_commands=fixture.commands)

    def test_cached_reconstruction_requires_every_independent_native_command(self):
        fixture = Fixture()
        fixture.freeze()
        for commands in ({}, {key: ['true'] for key in fixture.commands}):
            with self.assertRaises(registry.Refusal):
                registry.read_execution(fixture.root_ref, fixture.memory.read, fixture.memory.catalog, expected_run=fixture.run,
                                        expected_originals=fixture.expected_originals, expected_commands=commands)

    def test_cached_catalog_corruption_refuses_even_with_unchanged_external_metadata(self):
        fixture = Fixture()
        fixture.freeze()
        def corrupt_catalog(store, expected_sha, maximum):
            raw = fixture.memory.catalog(store, expected_sha, maximum)
            return raw[:-1] + bytes([raw[-1] ^ 1])
        with self.assertRaisesRegex(registry.Refusal, 'CATALOG_ORIGINAL_LENGTH_SHA'):
            registry.read_execution(fixture.root_ref, fixture.memory.read, corrupt_catalog, expected_run=fixture.run,
                                    expected_originals=fixture.expected_originals, expected_commands=fixture.commands)

    def test_explicit_retention_refuses_duplicate_memberships_and_unbounded_pages(self):
        fixture = Fixture(0)
        row = {'path': 'unselected.partial', 'kind': 'file', 'bytes': 1, 'sha256': protocol.sha(b'x'),
               'membership': 'nonqualifying-retained', 'reason': 'SYNTHETIC unknown tail',
               'owner': {'run_sha256': None, 'group_id': None, 'attempt_id': None}}
        fixture.state.add_retained_members([row])
        with self.assertRaisesRegex(registry.Refusal, 'DUPLICATE_RETAINED'):
            fixture.state.add_retained_members([row])
        with self.assertRaisesRegex(registry.Refusal, 'RETAINED_PAGE_BOUND'):
            fixture.state.add_retained_members([row] * (registry.MAX_ROWS + 1))
        changed = copy.deepcopy(row)
        changed['reason'] = ''
        with self.assertRaisesRegex(registry.Refusal, 'NONQUALIFYING_RETENTION'):
            registry.validate_retained_rows([changed])

    def test_numeric_plan_charges_directory_rounding_and_failed_record_pairs(self):
        plan = small_plan()
        charged = plan.validate()['reserved_peak_bytes']
        arithmetic = plan.global_baseline_bytes + plan.global_other_growth_bytes + plan.global_reserve_bytes
        arithmetic += sum(row['data_bytes'] + 2 * plan.allocation_unit * row['entries'] for row in plan.extents.values())
        self.assertEqual(charged, arithmetic)
        changed = copy.deepcopy(plan.extents)
        changed['registry_pairs']['entries'] -= 1
        with self.assertRaisesRegex(registry.Refusal, 'DIRECTORY_RESERVATION'):
            publication.StoragePlan(plan.global_baseline_bytes, plan.global_other_growth_bytes, plan.global_reserve_bytes,
                                    changed, plan.object_counts, plan.object_bytes).validate()
        changed = copy.deepcopy(plan.extents)
        changed['registry_pairs']['data_bytes'] -= 1
        with self.assertRaisesRegex(registry.Refusal, 'DIRECTORY_RESERVATION'):
            publication.StoragePlan(plan.global_baseline_bytes, plan.global_other_growth_bytes, plan.global_reserve_bytes,
                                    changed, plan.object_counts, plan.object_bytes).validate()

    def test_failed_sink_preserves_available_prefix_and_poison_prevents_retry(self):
        fixture = Fixture(0)
        retained_prefixes = []
        def failed_sink(kind, raw):
            retained_prefixes.append((kind, raw[:3]))
            raise registry.Refusal('SYNTHETIC_PUBLICATION_FAILURE')
        fixture.state.sink = failed_sink
        summary = premeasurement_summary(fixture, stage='not-started',
                                         dependencies={'admission': None, 'build': None, 'measurement': None})
        with self.assertRaisesRegex(registry.Refusal, 'SYNTHETIC_PUBLICATION_FAILURE'):
            fixture.state.record_cell(pretty(summary))
        self.assertTrue(fixture.state.io_failed)
        self.assertEqual(retained_prefixes, [('original', pretty(summary)[:3])])
        with self.assertRaisesRegex(registry.Refusal, 'PUBLICATION_FAILED'):
            fixture.state.record_cell(pretty(summary))
        self.assertEqual(len(retained_prefixes), 1)

    def test_numeric_plan_refuses_boolean_counts_nonpower_units_and_one_failure_copy(self):
        plan = small_plan()
        counts = copy.deepcopy(plan.object_counts)
        counts['cell'] = True
        with self.assertRaises(registry.Refusal):
            publication.StoragePlan(plan.global_baseline_bytes, plan.global_other_growth_bytes, plan.global_reserve_bytes,
                                    plan.extents, counts, plan.object_bytes).validate()
        for changes in ({'allocation_unit': 4097}, {'transport_copies': 1}):
            with self.assertRaises(registry.Refusal):
                publication.StoragePlan(plan.global_baseline_bytes, plan.global_other_growth_bytes, plan.global_reserve_bytes,
                                        plan.extents, plan.object_counts, plan.object_bytes, **changes).validate()


class PureTransportContracts(unittest.TestCase):
    def test_retained_attempt_cannot_name_a_different_known_group(self):
        for wrong in (False, True):
            fixture = Fixture()
            groups = protocol.all_groups(fixture.run)
            own = protocol.group_id(groups[0]); other = protocol.group_id(groups[1])
            member = {'path': 'unknown-tail.bin', 'kind': 'file', 'bytes': 1, 'sha256': protocol.sha(b'x'),
                      'membership': 'nonqualifying-retained', 'reason': 'synthetic failed tail',
                      'owner': {'run_sha256': registry.run_sha(fixture.run), 'group_id': other if wrong else own,
                                'attempt_id': '1-1234abcd'}}
            fixture.state.add_retained_members([member]); view = fixture.freeze()
            if wrong:
                with self.assertRaisesRegex(registry.Refusal, 'GROUP_OWNER_CONFLICT'):
                    transport.required_members(view)
            else:
                self.assertIn('unknown-tail.bin', {row['path'] for row in transport.required_members(view)})

    def test_unknown_tail_requires_explicit_retained_membership_and_exact_transport(self):
        fixture = Fixture()
        unknown = {'path': 'failed-attempt/failure-tail.bin', 'kind': 'file', 'bytes': 3, 'sha256': protocol.sha(b'bad')}
        fixture.memory.external[unknown['path']] = unknown
        # A valid source root alone cannot discover or bless an unknown file.
        view_without_retention = fixture.freeze()
        envelope = MemoryPublication('envelope')
        with self.assertRaisesRegex(registry.Refusal, 'EVERY_KNOWN_AND_UNKNOWN'):
            transport.build_transport(view_without_retention, fixture.memory.observed(), envelope.sink, envelope_root='envelope')
        # New source fixture; immutable old root/records are not rewritten.
        fixture = Fixture()
        fixture.memory.external[unknown['path']] = unknown
        retained = {**unknown, 'membership': 'nonqualifying-retained', 'reason': 'unknown failed native tail',
                    'owner': {'run_sha256': None, 'group_id': None, 'attempt_id': None}}
        fixture.state.add_retained_members([retained])
        view = fixture.freeze()
        ref, seal = transport.build_transport(view, fixture.memory.observed(), envelope.sink, envelope_root='envelope')
        observed = sorted(fixture.memory.observed() + envelope.observed(), key=lambda row: row['path'])
        result = transport.validate_transport(ref, envelope.read, observed,
                                              expected_execution_sha256=fixture.state.execution_sha256, view=view)
        self.assertEqual((result['transport_membership'], result['qualification']), ('CHECKED', 'NOT_PERFORMED'))
        self.assertNotIn('transport_sha256', fixture.root)
        self.assertEqual(seal['execution_root'], fixture.root_ref)

    def test_missing_partial_extra_file_corruption_and_missing_directory_refuse(self):
        fixture = Fixture()
        view = fixture.freeze()
        envelope = MemoryPublication('envelope')
        ref, _ = transport.build_transport(view, fixture.memory.observed(), envelope.sink, envelope_root='envelope')
        observed = sorted(fixture.memory.observed() + envelope.observed(), key=lambda row: row['path'])
        missing_partial = copy.deepcopy(observed)
        missing_partial.remove(next(row for row in missing_partial if row['path'].endswith('.partial')))
        extra = copy.deepcopy(observed)
        extra.append({'path': 'unknown.bin', 'kind': 'file', 'bytes': 0, 'sha256': protocol.sha(b'')})
        extra.sort(key=lambda row: row['path'])
        corrupt = copy.deepcopy(observed)
        next(row for row in corrupt if row['kind'] == 'file')['sha256'] = '0' * 64
        missing_dir = [row for row in observed if row['path'] != 'captures']
        for changed in (missing_partial, extra, corrupt, missing_dir):
            with self.assertRaises(registry.Refusal):
                transport.validate_transport(ref, envelope.read, changed,
                                             expected_execution_sha256=fixture.state.execution_sha256, view=view)

    def test_absent_root_failure_seal_retains_every_member_and_never_gains_normal_scope(self):
        source = MemoryPublication('failed')
        source.sink('original', b'preserved invalid utf8\xff')
        source.external['failed/torn.partial'] = {'path': 'failed/torn.partial', 'kind': 'file', 'bytes': 2, 'sha256': protocol.sha(b'xx')}
        envelope = MemoryPublication('failure-envelope')
        execution_sha = '7' * 64
        ref, seal = transport.build_failure_transport(execution_sha, source.observed(), envelope.sink,
                                                       envelope_root='failure-envelope', reason='no readable root after failure')
        observed = sorted(source.observed() + envelope.observed(), key=lambda row: row['path'])
        result = transport.validate_transport(ref, envelope.read, observed, expected_execution_sha256=execution_sha)
        self.assertIsNone(seal['execution_root'])
        self.assertTrue(result['failure_only'])
        self.assertEqual(result['qualification'], 'NOT_PERFORMED')
        with self.assertRaises(registry.Refusal):
            transport.validate_transport(ref, envelope.read, observed[:-1], expected_execution_sha256=execution_sha)

    def test_transport_page_corruption_and_semantic_reclassification_refuse(self):
        fixture = Fixture()
        view = fixture.freeze()
        envelope = MemoryPublication('envelope')
        ref, seal = transport.build_transport(view, fixture.memory.observed(), envelope.sink, envelope_root='envelope')
        first = seal['pages'][0]
        def corrupt(ref):
            raw = envelope.read(ref)
            return b'x' + raw[1:] if ref['path'] == first['path'] else raw
        observed = sorted(fixture.memory.observed() + envelope.observed(), key=lambda row: row['path'])
        with self.assertRaisesRegex(registry.Refusal, 'EXTERNAL_OBJECT_LENGTH_SHA'):
            transport.validate_transport(ref, corrupt, observed, expected_execution_sha256=fixture.state.execution_sha256, view=view)
        changed_page = json.loads(envelope.read(first))
        changed_page['members'][0]['membership'] = 'nonqualifying-retained'
        changed = copy.deepcopy(seal)
        changed['pages'][0] = envelope.sink('transport-page', protocol.canonical(changed_page))
        subjects = [row for page in changed['pages'] for row in json.loads(envelope.read(page))['members']]
        changed['subjects_sha256'] = protocol.sha(protocol.canonical(subjects))
        changed_ref = envelope.sink('transport', protocol.canonical(changed))
        # Semantic reachability refuses before comparing the deliberately
        # unreconciled synthetic publication envelope; this is not a restore.
        with self.assertRaisesRegex(registry.Refusal, 'SEMANTIC_GRAPH_SUBJECT_CLOSURE'):
            transport.validate_transport(changed_ref, envelope.read, observed,
                                         expected_execution_sha256=fixture.state.execution_sha256, view=view)

    def test_failure_seal_cannot_reclassify_any_subject_as_qualifying_metadata(self):
        source = MemoryPublication('failed')
        source.sink('original', b'SYNTHETIC failed original')
        envelope = MemoryPublication('failure-envelope')
        execution_sha = '7' * 64
        _, seal = transport.build_failure_transport(execution_sha, source.observed(), envelope.sink,
                                                     envelope_root='failure-envelope', reason='SYNTHETIC no root')
        changed = copy.deepcopy(seal)
        page = json.loads(envelope.read(changed['pages'][0]))
        page['members'][0]['membership'] = 'registry-record'
        changed['pages'][0] = envelope.sink('transport-page', protocol.canonical(page))
        changed['subjects_sha256'] = protocol.sha(protocol.canonical(page['members']))
        changed_ref = envelope.sink('transport', protocol.canonical(changed))
        observed = sorted(source.observed() + envelope.observed(), key=lambda row: row['path'])
        with self.assertRaisesRegex(registry.Refusal, 'NO_READABLE_ROOT_MEANS_FAILURE_ONLY_NONQUALIFYING'):
            transport.validate_transport(changed_ref, envelope.read, observed, expected_execution_sha256=execution_sha)


if __name__ == '__main__':
    unittest.main()
