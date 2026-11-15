"""SOURCE ONLY: bounded immutable execution registry above the frozen v2 store.

Normal future-colocated imports only. No legacy/gzip conversion, subprocess,
dynamic import, retirement, scientific qualification or publication of source.
Metadata closure is separate from restored-byte and scientific validation.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

import scientific_capture_protocol as protocol
import scientific_raw_reference_v2 as rawref

ANCHOR = 'scientific-execution-anchor-v1'
CATALOG = 'scientific-execution-catalog-v1'
CELL = 'scientific-execution-cell-v1'
GROUP = 'scientific-execution-group-v1'
ROOT = 'scientific-execution-root-v1'
SUMMARY = 'scientific-collector-summary-v2'
INVOCATION = 'scientific-invocation-start-v1'
RETAINED = 'scientific-retained-members-v1'
TRANSPORT_PAGE = 'scientific-execution-transport-page-v1'
TRANSPORT = 'scientific-execution-transport-v1'
ORIGINAL_TAGS = ('source_manifest', 'provenance', 'config_legacy', 'config_canonical',
                 'guest_context', 'benchmark_start', 'invocation_start')
LIMITS = {'original': 8 << 20, 'anchor': 64 << 10, 'catalog': 128 << 10,
          'attempt': 256 << 10, 'cell': 64 << 10, 'group': 1 << 20,
          'root': 128 << 10, 'retained': 256 << 10,
          'transport-page': 256 << 10, 'transport': 1 << 20}
MAX_RUNS = 16
MAX_CAPTURES = protocol.MAX_REFERENCES
MAX_CATALOGS = MAX_CAPTURES
MAX_ATTEMPTS = 12_000
MAX_GROUP_CATALOGS = 512
MAX_GROUP_ATTEMPTS = 256
MAX_GROUP_CAPTURES = 1024
MAX_OBJECTS = 65_536
MAX_RETAINED_PAGES = 4096
MAX_ROWS = 256
MAX_TRANSPORT_PAGES = 4096
MAX_DECLARED_SAMPLES = 1_000_000
MAX_JSON_DEPTH = 32
MAX_JSON_TOKENS = 262_144
MAX_JSON_STRING_BYTES = 131_072
QUALIFICATION = 'NOT_PERFORMED'


class Refusal(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Refusal(code)


def call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except (protocol.Refusal, rawref.Refusal) as error:
        raise Refusal(str(error)) from error


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys), 'EXACT_SCHEMA')


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, 'TYPED_INTEGER_BOUND')


def canonical(value):
    try:
        return protocol.canonical(value)
    except (ValueError, TypeError, RecursionError) as error:
        raise Refusal('CANONICAL_JSON_REQUIRED') from error


def sha(raw):
    need(type(raw) is bytes, 'EXACT_BYTES_REQUIRED')
    return hashlib.sha256(raw).hexdigest()


def clone(value):
    return call(protocol.decode, canonical(value))


def json_preflight(raw, maximum):
    """Bound parser allocation before json.loads; this is not a JSON parser."""
    need(type(raw) is bytes and 0 < len(raw) <= maximum, 'OBJECT_BYTE_BOUND')
    depth = tokens = string_start = 0
    in_string = escaped = False
    for offset, byte in enumerate(raw):
        if in_string:
            need(offset - string_start <= MAX_JSON_STRING_BYTES, 'JSON_STRING_BYTE_BOUND')
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                in_string = False
            continue
        if byte == 34:
            in_string, string_start = True, offset
            tokens += 1
        elif byte in (123, 91):
            depth += 1
            tokens += 1
            need(depth <= MAX_JSON_DEPTH, 'JSON_DEPTH_BOUND')
        elif byte in (125, 93):
            depth -= 1
            need(depth >= 0, 'JSON_STRUCTURE')
        elif byte in (44, 58):
            tokens += 1
        need(tokens <= MAX_JSON_TOKENS, 'JSON_TOKEN_BOUND')
    need(not in_string and depth == 0, 'JSON_STRUCTURE')


def original_json(raw, maximum=LIMITS['original']):
    json_preflight(raw, maximum)
    return call(protocol.decode, raw)


def decode(raw, maximum):
    json_preflight(raw, maximum)
    value = call(protocol.decode, raw)
    need(canonical(value) == raw, 'CANONICAL_REGISTRY_OBJECT')
    return value


def digest(value):
    call(protocol.digest, value)


def command(value):
    need(type(value) is list and 1 <= len(value) <= 64 and
         all(type(arg) is str and 0 < len(arg) <= 32768 and '\0' not in arg for arg in value),
         'BOUNDED_EXACT_COMMAND')
    return value


def reference(value, kind=None):
    exact(value, ('kind', 'path', 'bytes', 'sha256'))
    need(type(value['kind']) is str and value['kind'] in LIMITS and
         (kind is None or value['kind'] == kind), 'OBJECT_KIND')
    call(rawref.relative, value['path'])
    # Both retained publication members must satisfy the immutable dependency's
    # portable component bound before a publisher creates either one.
    call(rawref.relative, value['path'] + '.partial')
    integer(value['bytes'], 0 if value['kind'] == 'original' else 1, LIMITS[value['kind']])
    digest(value['sha256'])
    # Pair publication is explicit: partial bytes remain a second member.
    need(value['path'].endswith('.raw' if value['kind'] == 'original' else '.json'), 'OBJECT_SUFFIX')
    return value


def check_object(ref, raw, kind=None):
    reference(ref, kind)
    need(type(raw) is bytes and len(raw) == ref['bytes'] and sha(raw) == ref['sha256'],
         'EXTERNAL_OBJECT_LENGTH_SHA')
    return raw


def pair_paths(ref):
    reference(ref)
    return (ref['path'], ref['path'] + '.partial')


def execution_identity(run):
    call(protocol.validate_run, run)
    return {key: clone(value) for key, value in run.items() if key != 'invocation_id'}


def run_sha(run):
    call(protocol.validate_run, run)
    return sha(canonical(run))


def group_scope(group, run):
    value = {'kind': 'group', 'group_id': protocol.group_id(group), 'group': clone(group),
             'cell_ids': sorted(protocol.cells_for_group(group, run))}
    return call(protocol.validate_scope, value, run)


def _expected_originals(value):
    exact(value, ORIGINAL_TAGS)
    for row in value.values():
        exact(row, ('bytes', 'sha256'))
        integer(row['bytes'], 0, LIMITS['original'])
        digest(row['sha256'])


def validate_originals(run, originals, expected, expected_command, expected_arguments):
    """Expected hashes/argv/arguments are independent caller trust inputs.

    Source-manifest, guest-context and benchmark-start bytes are preserved and
    hash-bound here. Their build/host/freshness semantics remain qualifier work.
    """
    call(protocol.validate_run, run)
    exact(originals, ORIGINAL_TAGS)
    _expected_originals(expected)
    command(expected_command)
    need(type(expected_arguments) is dict and len(canonical(expected_arguments)) <= 16384,
         'TRUSTED_ARGUMENTS_BOUND')
    for tag in ORIGINAL_TAGS:
        raw = originals[tag]
        need(type(raw) is bytes and len(raw) == expected[tag]['bytes'] and
             sha(raw) == expected[tag]['sha256'], 'TRUSTED_ORIGINAL_' + tag)
        need(len(raw) <= LIMITS['original'], 'ORIGINAL_BYTE_BOUND')
        json_preflight(raw, LIMITS['original'])
    call(protocol.validate_provenance_bytes, originals['provenance'], run)
    legacy = json.dumps(run['config'], sort_keys=True).encode('utf-8')
    need(originals['config_legacy'] == legacy and originals['config_canonical'] == canonical(run['config']),
         'BOTH_ORIGINAL_CONFIG_SERIALIZATIONS')
    for tag in ('source_manifest', 'guest_context', 'benchmark_start'):
        need(type(original_json(originals[tag])) is dict, 'ORIGINAL_JSON_OBJECT_' + tag)
    start = original_json(originals['invocation_start'])
    need(type(start) is dict and start.get('format') == INVOCATION and
         all(start.get(key) == run[key] for key in ('source', 'commit', 'execution_id', 'invocation_id')) and
         protocol.same(start.get('command'), expected_command) and
         protocol.same(start.get('arguments'), expected_arguments), 'PERSISTED_ORIGINAL_INVOCATION')
    call(protocol._timestamp, start.get('started_at'))
    return start


def _binding_common(binding):
    return canonical({key: value for key, value in binding.items()
                      if key not in ('role', 'origin', 'completeness')})


def catalog_document(raw, store_relative, expected_run, execution_sha256):
    """Pure catalog->selector projection; it does NOT verify payload files."""
    call(rawref.relative, store_relative)
    need(type(raw) is bytes and len(raw) <= rawref.MAX_CATALOG, 'CATALOG_BYTE_BOUND')
    json_preflight(raw, rawref.MAX_CATALOG)
    catalog = call(rawref.validate_catalog, call(rawref.decode, raw))
    need(protocol.same(catalog['run'], expected_run), 'CATALOG_EXPECTED_RUN')
    group_ids = {row['binding']['scope']['group_id'] for row in catalog['references']}
    # This registry's bounded final page owns one group's immutable batches.
    # Collectors split at group boundaries as well as before 64 refs/256MiB.
    need(len(group_ids) == 1, 'REGISTRY_BATCH_MUST_BE_GROUP_LOCAL')
    selectors = []
    for row in catalog['references']:
        binding = row['binding']
        binding_sha = sha(canonical(binding))
        original = row['original']
        if binding['role'] in ('corpus', 'queries'):
            key = 'corpus_sha256' if binding['role'] == 'corpus' else 'queries_sha256'
            need(original['sha256'] == binding[key], 'ORIGINAL_INPUT_IDENTITY')
        selector = {'format': rawref.FORMAT, 'store': store_relative, 'catalog': 'catalog.json',
                    'catalog_sha256': sha(raw), 'catalog_bytes': len(raw),
                    'reference_id': row['id'], 'run_sha256': run_sha(expected_run),
                    'binding_sha256': binding_sha, 'bytes': original['bytes'], 'sha256': original['sha256']}
        call(rawref.validate_reference, selector)
        selectors.append(selector)
    value = {'format': CATALOG, 'execution_sha256': execution_sha256,
             'run_sha256': run_sha(expected_run), 'group_id': next(iter(group_ids)),
             'store': store_relative, 'catalog_id': catalog['catalog_id'],
             'catalog_sha256': sha(raw), 'catalog_bytes': len(raw),
             'selectors': sorted(selectors, key=lambda item: item['binding_sha256'])}
    need(len(canonical(value)) <= LIMITS['catalog'], 'CATALOG_RECORD_BOUND')
    return value, catalog


@dataclass(frozen=True)
class CheckedCell:
    """Copied metadata after execution closure; no scientific PASS implication."""
    run: dict
    record: dict
    summary: dict
    admission: dict | None
    build: dict | None
    measurement: dict | None
    samples_reference: dict | None
    samples_binding: dict | None
    stdout_reference: dict | None
    stdout_binding: dict | None
    stderr_reference: dict | None
    stderr_binding: dict | None


class ExecutionRegistry:
    """One bounded registry spans EVERY catalog of one execution/reader.

    Sink(kind, raw)->ObjectReference publishes immutable bytes. In-memory sinks
    are useful pure controls, not durability evidence. Actual POSIX publication
    is in scientific_registry_publication.py. No full histories are rewritten:
    small records are emitted once and 90 final group pages/root only at freeze.
    """
    def __init__(self, expected_run, sink):
        call(protocol.validate_run, expected_run)
        need(callable(sink), 'EXPLICIT_IMMUTABLE_SINK_REQUIRED')
        self.expected_run = clone(expected_run)
        self.identity = execution_identity(expected_run)
        self.execution_sha256 = sha(canonical(self.identity))
        self.sink = sink
        self.runs, self.anchors, self.starts, self.provenance = {}, {}, {}, {}
        self.catalogs, self.catalog_ids, self.catalog_stores = {}, set(), set()
        self.captures, self.logical_owners, self.native_owners = {}, {}, {}
        self.attempts, self.cells, self.retained = {}, {}, []
        self.objects, self.emitted = {}, {}
        self.frozen = False
        self.io_failed = False
        groups = protocol.all_groups(expected_run)
        self.groups = {protocol.group_id(group): group for group in groups}
        self.expected_cells = {}
        for gid, group in self.groups.items():
            for cid, cell in protocol.cells_for_group(group, expected_run).items():
                need(cid not in self.expected_cells, 'FROZEN_CELL_COLLISION')
                self.expected_cells[cid] = (gid, cell)
        need(len(self.groups) == 90 and len(self.expected_cells) == 5400, 'FROZEN_COUNTS')

    def _mutable(self):
        need(not self.frozen and not self.io_failed, 'REGISTRY_FROZEN_OR_PUBLICATION_FAILED')

    def _remember(self, ref, raw):
        check_object(ref, raw)
        existing = self.objects.get(ref['path'])
        need(existing is None or protocol.same(existing, ref), 'CONFLICTING_OBJECT_PATH')
        if existing is None:
            need(len(self.objects) < MAX_OBJECTS, 'EXECUTION_OBJECT_COUNT_BOUND')
        self.objects[ref['path']] = clone(ref)

    def _put(self, kind, raw):
        self._mutable()
        need(kind in LIMITS and type(raw) is bytes and len(raw) <= LIMITS[kind] and
             (kind == 'original' or len(raw) > 0), 'IMMUTABLE_RECORD_BYTE_BOUND')
        key = (kind, sha(raw))
        if key in self.emitted:
            ref = self.emitted[key]
            need(ref['bytes'] == len(raw), 'CONTENT_ADDRESS_LENGTH_CONFLICT')
            return clone(ref)
        try:
            ref = self.sink(kind, raw)
            check_object(ref, raw, kind)
            self._remember(ref, raw)
        except BaseException:
            # Any physical partial is preserved by the sink; no retry/overwrite
            # in this registry after a publication failure.
            self.io_failed = True
            raise
        self.emitted[key] = clone(ref)
        return clone(ref)

    def _run(self, identity):
        digest(identity)
        need(identity in self.runs, 'ORIGINAL_INVOCATION_ANCHOR_MISSING')
        return self.runs[identity]

    def accept_invocation(self, document, ref, originals, *, expected_originals,
                          expected_command, expected_arguments):
        """Read/adopt old immutable anchor, preserving its original invocation."""
        self._mutable()
        exact(document, ('format', 'execution_sha256', 'run_sha256', 'run', 'originals',
                         'collector_command', 'collector_arguments'))
        check_object(ref, canonical(document), 'anchor')
        run = document['run']
        identity = run_sha(run)
        need(document['format'] == ANCHOR and document['execution_sha256'] == self.execution_sha256 and
             protocol.same(execution_identity(run), self.identity) and document['run_sha256'] == identity,
             'ANCHOR_EXECUTION_OR_RUN')
        need(identity not in self.runs and len(self.runs) < MAX_RUNS and
             all(old['invocation_id'] != run['invocation_id'] for old in self.runs.values()),
             'DUPLICATE_OR_EXCESS_INVOCATION')
        need(protocol.same(document['collector_command'], expected_command) and
             protocol.same(document['collector_arguments'], expected_arguments), 'TRUSTED_COLLECTOR_INVOCATION')
        start = validate_originals(run, originals, expected_originals, expected_command, expected_arguments)
        exact(document['originals'], ORIGINAL_TAGS)
        for tag in ORIGINAL_TAGS:
            check_object(document['originals'][tag], originals[tag], 'original')
        for tag in ORIGINAL_TAGS:
            self._remember(document['originals'][tag], originals[tag])
        self._remember(ref, canonical(document))
        self.runs[identity], self.anchors[identity], self.starts[identity] = clone(run), clone(ref), clone(start)
        self.provenance[identity] = clone(call(protocol.decode, originals['provenance']))
        return clone(ref)

    def record_invocation(self, run, originals, *, expected_originals,
                          expected_command, expected_arguments):
        self._mutable()
        validate_originals(run, originals, expected_originals, expected_command, expected_arguments)
        need(protocol.same(execution_identity(run), self.identity), 'ORIGINAL_EXECUTION_OWNERSHIP')
        identity = run_sha(run)
        need(identity not in self.runs and len(self.runs) < MAX_RUNS and
             all(old['invocation_id'] != run['invocation_id'] for old in self.runs.values()), 'INVOCATION_ALREADY_ADOPTED')
        refs = {tag: self._put('original', originals[tag]) for tag in ORIGINAL_TAGS}
        value = {'format': ANCHOR, 'execution_sha256': self.execution_sha256,
                 'run_sha256': identity, 'run': clone(run), 'originals': refs,
                 'collector_command': clone(expected_command), 'collector_arguments': clone(expected_arguments)}
        ref = self._put('anchor', canonical(value))
        return self.accept_invocation(value, ref, originals, expected_originals=expected_originals,
                                      expected_command=expected_command, expected_arguments=expected_arguments)

    def accept_catalog(self, document, ref, catalog_raw):
        self._mutable()
        need(type(document) is dict and document.get('run_sha256') in self.runs, 'CATALOG_ANCHOR')
        run = self._run(document['run_sha256'])
        expected, catalog = catalog_document(catalog_raw, document.get('store'), run, self.execution_sha256)
        need(protocol.same(document, expected), 'CATALOG_RECORD_EXACT_SELECTOR_MEMBERSHIP')
        check_object(ref, canonical(document), 'catalog')
        identity, store = document['catalog_sha256'], document['store']
        need(identity not in self.catalogs and document['catalog_id'] not in self.catalog_ids and
             store not in self.catalog_stores and len(self.catalogs) < MAX_CATALOGS, 'PUBLISHED_BATCH_REOPEN_OR_DUPLICATE')
        for previous in self.catalog_stores:
            need(not (store.startswith(previous + '/') or previous.startswith(store + '/')), 'CATALOG_ROOT_OVERLAP')
        gid = document['group_id']
        need(gid in self.groups, 'CATALOG_FOREIGN_GROUP')
        group_cats = sum(item['document']['group_id'] == gid for item in self.catalogs.values())
        group_caps = sum(item['binding']['scope']['group_id'] == gid for item in self.captures.values())
        need(group_cats < MAX_GROUP_CATALOGS and group_caps + len(catalog['references']) <= MAX_GROUP_CAPTURES and
             len(self.captures) + len(catalog['references']) <= MAX_CAPTURES, 'CATALOG_GLOBAL_OR_GROUP_BOUND')
        pending, keys, owners = {}, {}, {}
        by_binding = {selector['binding_sha256']: selector for selector in document['selectors']}
        for member in catalog['references']:
            binding = member['binding']
            binding_sha = sha(canonical(binding))
            key = call(protocol.logical_key, binding, run)
            need(key not in self.logical_owners and key not in keys and binding_sha not in self.captures,
                 'CROSS_CATALOG_DUPLICATE_LOGICAL_CAPTURE')
            common, attempt_id = _binding_common(binding), binding['attempt_id']
            owner = self.native_owners.get(attempt_id, owners.get(attempt_id))
            need(owner is None or owner == common, 'EXECUTION_NATIVE_ATTEMPT_ID_HAS_ONE_OWNER')
            owners[attempt_id] = common
            keys[key] = binding_sha
            pending[binding_sha] = {'binding': clone(binding), 'selector': clone(by_binding[binding_sha]),
                                    'catalog_sha256': identity}
        self._remember(ref, canonical(document))
        self.catalogs[identity] = {'document': clone(document), 'ref': clone(ref), 'catalog': clone(catalog)}
        self.catalog_ids.add(document['catalog_id'])
        self.catalog_stores.add(store)
        self.captures.update(pending)
        self.logical_owners.update(keys)
        self.native_owners.update(owners)
        return clone(ref)

    def record_catalog(self, catalog_raw, store_relative, *, expected_run):
        self._mutable()
        self._run(run_sha(expected_run))
        value, _ = catalog_document(catalog_raw, store_relative, expected_run, self.execution_sha256)
        # accept_catalog validates cross-catalog ownership before publishing.
        # Use a dry projection on separate dictionaries, without touching the
        # published catalogs or protocol globals. A rejected catalog's caller
        # bytes remain outside this registry and require retained membership.
        self._check_catalog_admission(value, catalog_raw)
        ref = self._put('catalog', canonical(value))
        return self.accept_catalog(value, ref, catalog_raw)

    def _check_catalog_admission(self, document, raw):
        identity = document['catalog_sha256']
        need(identity not in self.catalogs and document['catalog_id'] not in self.catalog_ids and
             document['store'] not in self.catalog_stores, 'PUBLISHED_BATCH_REOPEN_OR_DUPLICATE')
        catalog = call(rawref.validate_catalog, call(rawref.decode, raw))
        temporary_keys, owners = set(), {}
        for member in catalog['references']:
            binding = member['binding']
            key = call(protocol.logical_key, binding, self._run(document['run_sha256']))
            need(key not in self.logical_owners and key not in temporary_keys, 'CROSS_CATALOG_DUPLICATE_LOGICAL_CAPTURE')
            temporary_keys.add(key)
            attempt_id, common = binding['attempt_id'], _binding_common(binding)
            previous = self.native_owners.get(attempt_id, owners.get(attempt_id))
            need(previous is None or previous == common, 'EXECUTION_NATIVE_ATTEMPT_ID_HAS_ONE_OWNER')
            owners[attempt_id] = common

    def record_resolver_catalog(self, resolver, store_relative, *, expected_run):
        """Actual store adapter: requires live v2 resolver closure, never gzip."""
        self._mutable()
        call(resolver._closure)
        need(protocol.same(resolver.catalog['run'], expected_run), 'LIVE_RESOLVER_EXPECTED_RUN')
        raw = rawref.canonical(resolver.catalog)
        need(len(raw) == resolver.catalog_bytes and sha(raw) == resolver.catalog_sha256, 'LIVE_CATALOG_SOURCE_BYTES')
        return self.record_catalog(raw, store_relative, expected_run=expected_run)

    def accept_attempt(self, raw, ref, *, expected_command):
        self._mutable()
        value = decode(raw, LIMITS['attempt'])
        check_object(ref, raw, 'attempt')
        need(type(value) is dict and value.get('run_sha256') in self.runs, 'ATTEMPT_ORIGINAL_INVOCATION')
        run = self._run(value['run_sha256'])
        bindings = {key: item['binding'] for key, item in self.captures.items()}
        call(protocol.validate_external_attempt, value, run, bindings, expected_command=expected_command)
        attempt_id = value['attempt_id']
        need(attempt_id not in self.attempts and len(self.attempts) < MAX_ATTEMPTS, 'DUPLICATE_OR_EXCESS_ATTEMPT_RECORD')
        need(attempt_id in self.native_owners, 'ATTEMPT_WITHOUT_CATALOG_CAPTURES')
        gid = value['scope']['group_id']
        need(sum(item['value']['scope']['group_id'] == gid for item in self.attempts.values()) < MAX_GROUP_ATTEMPTS,
             'GROUP_ATTEMPT_BOUND')
        need(call(protocol._timestamp, value['started_at']) >=
             call(protocol._timestamp, self.starts[value['run_sha256']]['started_at']), 'ATTEMPT_PRECEDES_OWN_INVOCATION')
        # External attempt metadata is an object outside every capture catalog.
        for store in self.catalog_stores:
            need(not ref['path'].startswith(store + '/'), 'ATTEMPT_METADATA_INSIDE_CAPTURE_CATALOG')
        self._remember(ref, raw)
        self.attempts[attempt_id] = {'value': clone(value), 'ref': clone(ref)}
        return clone(ref)

    def record_attempt(self, value, *, expected_command):
        self._mutable()
        raw = canonical(value)
        need(len(raw) <= LIMITS['attempt'], 'ATTEMPT_METADATA_BOUND')
        run = self._run(value.get('run_sha256'))
        call(protocol.validate_external_attempt, value, run,
             {key: item['binding'] for key, item in self.captures.items()}, expected_command=expected_command)
        need(value['attempt_id'] not in self.attempts, 'DUPLICATE_OR_EXCESS_ATTEMPT_RECORD')
        ref = self._put('attempt', raw)
        return self.accept_attempt(raw, ref, expected_command=expected_command)

    def _attempt_dependency(self, ref, run_identity, scope, stage):
        if ref is None:
            return None
        reference(ref, 'attempt')
        found = [item for item in self.attempts.values() if protocol.same(item['ref'], ref)]
        need(len(found) == 1, 'CELL_ATTEMPT_REFERENCE_REACHABILITY')
        value = found[0]['value']
        need(value['run_sha256'] == run_identity and value['stage'] == stage and
             value['scope']['group_id'] == scope['group_id'] and
             (stage != 'measurement' or protocol.same(value['scope'], scope)), 'CELL_ATTEMPT_OWNER_STAGE_OR_SCOPE')
        return value

    def _cell_inputs(self, value, run, build, measurement):
        inputs = value['inputs']
        exact(inputs, ('corpus', 'queries'))
        for role, owner in (('corpus', build), ('queries', measurement)):
            binding_sha = inputs[role]
            if binding_sha is None:
                continue
            digest(binding_sha)
            need(owner is not None and binding_sha in self.captures, 'CELL_INPUT_OWNER_OR_REACHABILITY')
            binding = self.captures[binding_sha]['binding']
            need(binding['run_sha256'] == run_sha(run) and binding['attempt_id'] == owner['attempt_id'] and
                 binding['role'] == role and binding['scope']['group_id'] == value['scope']['group_id'] and
                 (role != 'queries' or protocol.same(binding['scope'], value['scope'])), 'CELL_INPUT_EXACT_OWNERSHIP')

    def _validate_cell(self, value, summary_raw):
        exact(value, ('format', 'execution_sha256', 'run_sha256', 'scope', 'stage', 'collector_status', 'errors',
                      'sample_count', 'generation', 'corpus_sha256', 'queries_sha256', 'dependencies', 'inputs',
                      'samples_reference', 'samples_original_sha256', 'summary'))
        need(value['format'] == CELL and value['execution_sha256'] == self.execution_sha256, 'CELL_VERSION_EXECUTION')
        run = self._run(value['run_sha256'])
        scope = call(protocol.validate_scope, value['scope'], run)
        need(scope['kind'] == 'cell', 'CELL_TAGGED_SCOPE')
        need(value['stage'] in ('not-started', 'admission', 'build', 'measurement') and
             value['collector_status'] in ('PASS', 'FAIL', 'NOT_RUN'), 'CELL_STAGE_OR_COLLECTOR_STATUS')
        integer(value['sample_count'], 0, MAX_DECLARED_SAMPLES)
        need(type(value['errors']) is list and len(value['errors']) <= 128 and
             all(type(error) is str and len(error) <= 4096 for error in value['errors']), 'CELL_ERROR_BOUND')
        for key in ('generation', 'corpus_sha256', 'queries_sha256'):
            if value[key] is not None:
                digest(value[key])
        exact(value['dependencies'], ('admission', 'build', 'measurement'))
        dependencies = {stage: self._attempt_dependency(value['dependencies'][stage], value['run_sha256'], scope, stage)
                        for stage in ('admission', 'build', 'measurement')}
        admission, build, measurement = (dependencies[stage] for stage in ('admission', 'build', 'measurement'))
        stage = value['stage']
        if stage in ('not-started', 'admission'):
            need(all(value[key] is None for key in ('generation', 'corpus_sha256', 'queries_sha256')),
                 'PREINPUT_IDENTITIES_UNAVAILABLE')
        elif stage == 'build':
            need(value['generation'] is None and value['queries_sha256'] is None,
                 'PREMEASUREMENT_QUERY_AND_GENERATION_UNAVAILABLE')
        need((admission is not None) == (stage != 'not-started') and
             (build is not None) == (stage in ('build', 'measurement')) and
             (measurement is not None) == (stage == 'measurement'), 'EXACT_STAGE_DEPENDENCIES')
        if build is not None:
            need(admission['status'] == 'PASS', 'BUILD_AFTER_FAILED_ADMISSION')
            need(call(protocol._timestamp, admission['ended_at']) <= call(protocol._timestamp, build['started_at']),
                 'GROUP_ADMISSION_BUILD_TIME_ORDER')
            build_binding = self.captures[build['captures']['stdout']]['binding']
            need(value['corpus_sha256'] == build_binding['corpus_sha256'], 'CELL_GROUP_BUILD_CORPUS_IDENTITY')
        if measurement is not None:
            need(build['status'] == 'PASS', 'MEASUREMENT_AFTER_FAILED_BUILD')
            need(call(protocol._timestamp, build['ended_at']) <= call(protocol._timestamp, measurement['started_at']),
                 'BUILD_MEASUREMENT_TIME_ORDER')
            sample_id = measurement['captures']['samples']
            binding = self.captures[sample_id]['binding']
            selector = self.captures[sample_id]['selector']
            need(protocol.same(value['samples_reference'], selector) and
                 value['samples_original_sha256'] == selector['sha256'] and
                 all(value[key] == binding[key] for key in ('generation', 'corpus_sha256', 'queries_sha256')),
                 'MEASUREMENT_SAMPLE_REFERENCE_AND_INPUT_IDENTITIES')
            # Successful native execution is intentionally insufficient for
            # collector PASS. Failed/timeout native attempts never gain PASS.
            need(value['collector_status'] != 'PASS' or measurement['status'] == 'PASS', 'FAILED_NATIVE_CANNOT_GAIN_COLLECTOR_PASS')
        else:
            need(value['samples_reference'] is None and value['samples_original_sha256'] is None and
                 value['sample_count'] == 0, 'PREMEASUREMENT_HAS_NO_SAMPLES')
        need(value['collector_status'] != 'PASS' or stage == 'measurement' and not value['errors'] and
             value['sample_count'] == run['config']['queries'] * run['config']['repetitions'], 'DECLARED_PASS_FROZEN_SAMPLE_REQUIREMENTS')
        need(value['collector_status'] != 'NOT_RUN' or stage == 'not-started', 'NOT_RUN_WITH_NATIVE_ATTEMPTS')
        self._cell_inputs(value, run, build, measurement)
        # Preserve collector summary's complete ORIGINAL serialization outside
        # the samples catalog. No inherited samples_sha256 interpretation.
        check_object(value['summary'], summary_raw, 'original')
        summary = original_json(summary_raw)
        need(type(summary) is dict and summary.get('evidence_format') == SUMMARY and
             'samples_sha256' not in summary, 'EXPLICIT_NEW_SUMMARY_NO_LEGACY_MIX')
        need(protocol.same(summary.get('cell'), scope['cell']) and summary.get('source') == run['source'] and
             protocol.same(summary.get('provenance'), self.provenance[value['run_sha256']]) and
             summary.get('status') == value['collector_status'] and
             (type(summary.get('native_metadata')) is dict or measurement is None and summary.get('native_metadata') is None),
             'LEGACY_SCALAR_MEANINGS_IN_EXPLICIT_NEW_SUMMARY')
        begin, end = (call(protocol._timestamp, summary.get(key)) for key in ('started_at', 'ended_at'))
        need(call(protocol._timestamp, self.starts[value['run_sha256']]['started_at']) <= begin <= end,
             'CELL_ORIGINAL_INVOCATION_TIME_WINDOW')
        if measurement is not None:
            need(begin <= call(protocol._timestamp, measurement['started_at']) <=
                 call(protocol._timestamp, measurement['ended_at']) <= end, 'CELL_MEASUREMENT_TIME_WINDOW')
        for key in ('run_sha256', 'scope', 'stage', 'collector_status', 'errors', 'sample_count',
                    'generation', 'corpus_sha256', 'queries_sha256', 'dependencies', 'inputs',
                    'samples_reference', 'samples_original_sha256'):
            need(key in summary and protocol.same(summary[key], value[key]), 'ORIGINAL_SUMMARY_RECORD_BINDING_' + key)
        return summary

    def accept_cell(self, value, ref, summary_raw):
        self._mutable()
        check_object(ref, canonical(value), 'cell')
        summary = self._validate_cell(value, summary_raw)
        cid = value['scope']['cell_id']
        # One selected immutable result per frozen cell. Failed/retried attempts
        # stay indexed separately; a new developmental root can select a newer
        # result without editing or relabelling this historical record.
        need(cid not in self.cells and len(self.cells) < 5400, 'DUPLICATE_SELECTED_CELL')
        self._remember(value['summary'], summary_raw)
        self._remember(ref, canonical(value))
        self.cells[cid] = {'value': clone(value), 'ref': clone(ref), 'summary': clone(summary)}
        return clone(ref)

    def record_cell(self, summary_raw):
        self._mutable()
        need(type(summary_raw) is bytes and len(summary_raw) <= LIMITS['original'], 'ORIGINAL_SUMMARY_BYTE_BOUND')
        summary = original_json(summary_raw)
        need(type(summary) is dict and summary.get('evidence_format') == SUMMARY and
             'samples_sha256' not in summary, 'EXPLICIT_NEW_SUMMARY_NO_LEGACY_MIX')
        keys = ('run_sha256', 'scope', 'stage', 'collector_status', 'errors', 'sample_count',
                'generation', 'corpus_sha256', 'queries_sha256', 'dependencies', 'inputs',
                'samples_reference', 'samples_original_sha256')
        need(all(key in summary for key in keys), 'NEW_SUMMARY_FIELDS')
        value = {'format': CELL, 'execution_sha256': self.execution_sha256,
                 **{key: clone(summary[key]) for key in keys},
                 'summary': {'kind': 'original', 'path': 'validation-placeholder.raw',
                             'bytes': len(summary_raw), 'sha256': sha(summary_raw)}}
        self._validate_cell(value, summary_raw)
        need(value['scope']['cell_id'] not in self.cells, 'DUPLICATE_SELECTED_CELL')
        value['summary'] = self._put('original', summary_raw)
        ref = self._put('cell', canonical(value))
        return self.accept_cell(value, ref, summary_raw)

    def add_retained_members(self, rows):
        """Explicit nonqualifying membership for tails/unknowns/temporaries.

        This does not discover files. External failure collection MUST inventory
        every actual entry and feed bounded pages; unlisted files fail transport
        closure. Capture members not selected by cells are also automatically
        classified nonqualifying in final group pages.
        """
        self._mutable()
        need(type(rows) is list and 1 <= len(rows) <= MAX_ROWS and len(self.retained) < MAX_RETAINED_PAGES,
             'RETAINED_PAGE_BOUND')
        checked = validate_retained_rows(rows)
        previous = {row['path'] for page in self.retained for row in page['value']['members']}
        need(not previous.intersection(row['path'] for row in checked), 'DUPLICATE_RETAINED_MEMBERSHIP')
        value = {'format': RETAINED, 'execution_sha256': self.execution_sha256, 'members': checked}
        ref = self._put('retained', canonical(value))
        self.retained.append({'value': clone(value), 'ref': clone(ref)})
        return clone(ref)

    def accept_retained(self, value, ref):
        self._mutable()
        exact(value, ('format', 'execution_sha256', 'members'))
        need(value['format'] == RETAINED and value['execution_sha256'] == self.execution_sha256 and
             len(self.retained) < MAX_RETAINED_PAGES, 'RETAINED_VERSION_EXECUTION_BOUND')
        check_object(ref, canonical(value), 'retained')
        checked = validate_retained_rows(value['members'])
        previous = {row['path'] for page in self.retained for row in page['value']['members']}
        need(not previous.intersection(row['path'] for row in checked), 'DUPLICATE_RETAINED_MEMBERSHIP')
        self._remember(ref, canonical(value))
        self.retained.append({'value': clone(value), 'ref': clone(ref)})

    def _selected_capture_ids(self, gid):
        selected = set()
        for item in self.cells.values():
            value = item['value']
            if value['scope']['group_id'] != gid:
                continue
            selected.update(key for key in value['inputs'].values() if key is not None)
            for stage, ref in value['dependencies'].items():
                if ref is not None:
                    owner = self._attempt_dependency(ref, value['run_sha256'], value['scope'], stage)
                    selected.update(owner['captures'].values())
        return selected

    def group_document(self, gid):
        need(gid in self.groups, 'GROUP_ID')
        group = self.groups[gid]
        scope = group_scope(group, self.expected_run)
        catalogs = [item['ref'] for item in self.catalogs.values() if item['document']['group_id'] == gid]
        attempts = [item['ref'] for item in self.attempts.values() if item['value']['scope']['group_id'] == gid]
        selected = self._selected_capture_ids(gid)
        captures = []
        for identity, item in self.captures.items():
            if item['binding']['scope']['group_id'] == gid:
                used = identity in selected
                captures.append({'binding_sha256': identity,
                                 'membership': 'selected-dependency' if used else 'nonqualifying-retained',
                                 'reason': None if used else 'not-a-selected-cell-dependency'})
        cells = [{'cell_id': cid, 'record': clone(self.cells[cid]['ref']) if cid in self.cells else None}
                 for cid in scope['cell_ids']]
        value = {'format': GROUP, 'execution_sha256': self.execution_sha256, 'scope': scope,
                 'cells': cells, 'catalogs': sorted(clone(catalogs), key=lambda row: row['path']),
                 'attempts': sorted(clone(attempts), key=lambda row: row['path']),
                 'captures': sorted(captures, key=lambda row: row['binding_sha256']),
                 'qualification': QUALIFICATION}
        need(len(canonical(value)) <= LIMITS['group'], 'FINAL_GROUP_PAGE_BOUND')
        return value

    def root_document(self, group_refs):
        need(type(group_refs) is dict and set(group_refs) == set(self.groups), 'EXACT_NINETY_GROUP_PAGES')
        for ref in group_refs.values():
            reference(ref, 'group')
        selected_invocations = sorted({item['value']['run_sha256'] for item in self.cells.values()})
        missing = sorted(set(self.expected_cells) - set(self.cells))
        # Counts are metadata declarations, not reconstructed original samples.
        # No qualified status exists anywhere in this writer.
        value = {'format': ROOT, 'execution_sha256': self.execution_sha256,
                 'execution_identity': clone(self.identity),
                 'invocations': [{'run_sha256': key, 'anchor': clone(self.anchors[key])} for key in sorted(self.anchors)],
                 'groups': [{'group_id': gid, 'page': clone(group_refs[gid])} for gid in sorted(group_refs)],
                 'retained_pages': sorted([clone(item['ref']) for item in self.retained], key=lambda row: row['path']),
                 'expected_groups': 90, 'expected_cells': 5400, 'present_cells': len(self.cells),
                 'missing_cell_count': len(missing), 'missing_cells_sha256': sha(canonical(missing)),
                 'declared_sample_count': sum(item['value']['sample_count'] for item in self.cells.values()),
                 'catalog_count': len(self.catalogs), 'capture_count': len(self.captures), 'attempt_count': len(self.attempts),
                 'selected_run_sha256': selected_invocations,
                 'invocation_coherence': 'one-original-invocation' if len(self.runs) == 1 and len(selected_invocations) <= 1
                 else 'multiple-or-no-original-invocations',
                 'qualification': QUALIFICATION, 'original_payload_validation': 'REQUIRED_SEPARATELY',
                 'complete_transport': 'REQUIRED_EXTERNAL_ACYCLIC_SEAL', 'retirement': 'REFUSE'}
        need(len(canonical(value)) <= LIMITS['root'], 'ROOT_BYTE_BOUND')
        return value

    def finalize(self):
        self._mutable()
        pages = {gid: self._put('group', canonical(self.group_document(gid))) for gid in sorted(self.groups)}
        value = self.root_document(pages)
        ref = self._put('root', canonical(value))
        self.frozen = True
        return clone(ref), clone(value)

    def retire(self, *args, **kwargs):
        raise Refusal('NO_VERSIONED_POST_RETIREMENT_STATE_RETAIN_ALL_NATIVE_CALLER_AND_STAGING_BYTES')


class ExecutionView:
    """Trusted-root, complete metadata closure, including incomplete layouts."""
    def __init__(self, registry, root_reference, root):
        self._registry = registry
        self.root_reference, self.root = clone(root_reference), clone(root)

    def checked_cell(self, cell_id, *, expected_run):
        identity = run_sha(expected_run)
        need(cell_id in self._registry.cells, 'CELL_NOT_PRESENT_IN_TRUSTED_ROOT')
        item = self._registry.cells[cell_id]
        value = item['value']
        need(value['run_sha256'] == identity and identity in self._registry.runs and
             protocol.same(self._registry.runs[identity], expected_run), 'CELL_ORIGINAL_INVOCATION_CANNOT_BE_RELABELLED')
        deps = {stage: self._registry._attempt_dependency(ref, identity, value['scope'], stage)
                for stage, ref in value['dependencies'].items()}
        measurement = deps['measurement']
        sample = self._registry.captures[measurement['captures']['samples']] if measurement is not None else None
        stdout = self._registry.captures[measurement['captures']['stdout']] if measurement is not None else None
        stderr = self._registry.captures[measurement['captures']['stderr']] if measurement is not None else None
        return CheckedCell(clone(expected_run), clone(value), clone(item['summary']),
                           clone(deps['admission']), clone(deps['build']), clone(measurement),
                           clone(sample['selector']) if sample else None,
                           clone(sample['binding']) if sample else None,
                           clone(stdout['selector']) if stdout else None,
                           clone(stdout['binding']) if stdout else None,
                           clone(stderr['selector']) if stderr else None,
                           clone(stderr['binding']) if stderr else None)

    def require_single_fresh_layout(self, *, expected_run):
        """Necessary metadata precondition ONLY; never a qualification result."""
        identity = run_sha(expected_run)
        need(self.root['invocation_coherence'] == 'one-original-invocation' and
             self.root['selected_run_sha256'] == [identity] and self.root['present_cells'] == 5400 and
             self.root['missing_cell_count'] == 0 and self.root['declared_sample_count'] == 5_400_000,
             'ONE_FRESH_INVOCATION_LAYOUT_NOT_ESTABLISHED')
        for cid in self._registry.expected_cells:
            cell = self.checked_cell(cid, expected_run=expected_run)
            need(cell.record['collector_status'] == 'PASS' and cell.record['sample_count'] == 1000,
                 'FULL_LAYOUT_HAS_NONPASS_OR_PARTIAL_CELL')
        return {'metadata_layout': 'one-invocation-90-groups-5400-cells', 'qualification': QUALIFICATION}


def read_execution(root_reference, read_object, read_catalog, *, expected_run,
                   expected_originals, expected_commands):
    """Reconstruct all pages/records/catalog selectors from a trusted root ref.

    read_object(ref)->bytes must be bounded/owned by its caller; read_catalog
    (store_relative, expected_catalog_sha256, maximum_bytes)->original bytes.
    All returned bytes are checked again here. expected_originals[run_sha]
    has seven independently trusted hashes PLUS collector_command and
    collector_arguments. expected_commands[(run_sha,attempt_id)] is an exact
    independently derived argv; never derive it from the record under review.
    Extra unreferenced files cannot be discovered by this function: transport
    membership validation and owned inventory remain separate requirements.
    """
    reference(root_reference, 'root')
    need(callable(read_object) and callable(read_catalog), 'EXPLICIT_BOUNDED_READERS')
    registry = ExecutionRegistry(expected_run, lambda *_: (_ for _ in ()).throw(Refusal('READ_ONLY_RECONSTRUCTION')))
    loaded = {}
    def get(ref, kind):
        reference(ref, kind)
        key = ref['path']
        if key in loaded:
            need(protocol.same(loaded[key][0], ref), 'CROSS_PAGE_OBJECT_PATH_CONFLICT')
            return loaded[key][1]
        need(len(loaded) < MAX_OBJECTS, 'READER_OBJECT_COUNT_BOUND')
        raw = read_object(clone(ref))
        check_object(ref, raw, kind)
        loaded[key] = (clone(ref), raw)
        registry._remember(ref, raw)
        return raw
    root = decode(get(root_reference, 'root'), LIMITS['root'])
    root_keys = ('format', 'execution_sha256', 'execution_identity', 'invocations', 'groups', 'retained_pages',
                 'expected_groups', 'expected_cells', 'present_cells', 'missing_cell_count', 'missing_cells_sha256',
                 'declared_sample_count', 'catalog_count', 'capture_count', 'attempt_count', 'selected_run_sha256',
                 'invocation_coherence', 'qualification', 'original_payload_validation', 'complete_transport', 'retirement')
    exact(root, root_keys)
    need(root['format'] == ROOT and root['execution_sha256'] == registry.execution_sha256 and
         protocol.same(root['execution_identity'], registry.identity), 'TRUSTED_EXECUTION_ROOT')
    need(type(root['invocations']) is list and 1 <= len(root['invocations']) <= MAX_RUNS and
         type(root['groups']) is list and len(root['groups']) == 90 and
         type(root['retained_pages']) is list and len(root['retained_pages']) <= MAX_RETAINED_PAGES,
         'ROOT_MEMBERSHIP_BOUNDS')
    for row in root['invocations']:
        exact(row, ('run_sha256', 'anchor'))
        digest(row['run_sha256'])
        anchor = decode(get(row['anchor'], 'anchor'), LIMITS['anchor'])
        need(anchor.get('run_sha256') == row['run_sha256'] and row['run_sha256'] in expected_originals,
             'TRUSTED_INVOCATION_ORIGINALS_REQUIRED')
        original_refs = anchor.get('originals')
        exact(original_refs, ORIGINAL_TAGS)
        originals = {tag: get(original_refs[tag], 'original') for tag in ORIGINAL_TAGS}
        trust = expected_originals[row['run_sha256']]
        exact(trust, (*ORIGINAL_TAGS, 'collector_command', 'collector_arguments'))
        registry.accept_invocation(anchor, row['anchor'], originals,
                                   expected_originals={tag: trust[tag] for tag in ORIGINAL_TAGS},
                                   expected_command=trust['collector_command'], expected_arguments=trust['collector_arguments'])
    pages, group_refs = {}, {}
    catalogs, attempts, cells = {}, {}, {}
    for row in root['groups']:
        exact(row, ('group_id', 'page'))
        gid = row['group_id']
        need(type(gid) is str and gid in registry.groups and gid not in pages, 'DUPLICATE_OR_FOREIGN_GROUP_PAGE')
        page = decode(get(row['page'], 'group'), LIMITS['group'])
        exact(page, ('format', 'execution_sha256', 'scope', 'cells', 'catalogs', 'attempts', 'captures', 'qualification'))
        need(page['format'] == GROUP and page['execution_sha256'] == registry.execution_sha256 and
             protocol.same(page['scope'], group_scope(registry.groups[gid], expected_run)) and
             page['qualification'] == QUALIFICATION, 'EXACT_GROUP_PAGE_SCOPE')
        need(type(page['cells']) is list and len(page['cells']) == 60 and
             type(page['catalogs']) is list and len(page['catalogs']) <= MAX_GROUP_CATALOGS and
             type(page['attempts']) is list and len(page['attempts']) <= MAX_GROUP_ATTEMPTS and
             type(page['captures']) is list and len(page['captures']) <= MAX_GROUP_CAPTURES, 'GROUP_PAGE_BOUNDS')
        need([item.get('cell_id') for item in page['cells'] if type(item) is dict] == page['scope']['cell_ids'],
             'EXACT_SIXTY_CELL_PAGE_MEMBERSHIP')
        for item in page['cells']:
            exact(item, ('cell_id', 'record'))
            if item['record'] is not None:
                reference(item['record'], 'cell')
                need(item['cell_id'] not in cells, 'CELL_SELECTED_TWICE')
                cells[item['cell_id']] = item['record']
        for kind, target in (('catalogs', catalogs), ('attempts', attempts)):
            for ref in page[kind]:
                reference(ref, 'catalog' if kind == 'catalogs' else 'attempt')
                need(ref['path'] not in target, 'DUPLICATE_PAGE_CATALOG_OR_ATTEMPT')
                target[ref['path']] = (gid, ref)
        pages[gid], group_refs[gid] = page, row['page']
    need(set(pages) == set(registry.groups), 'MISSING_GROUP_PAGE')
    for gid, ref in catalogs.values():
        document = decode(get(ref, 'catalog'), LIMITS['catalog'])
        need(document.get('group_id') == gid, 'CATALOG_FOREIGN_PAGE')
        raw = read_catalog(document.get('store'), document.get('catalog_sha256'), rawref.MAX_CATALOG)
        need(type(raw) is bytes and len(raw) == document.get('catalog_bytes') and
             sha(raw) == document.get('catalog_sha256'), 'CATALOG_ORIGINAL_LENGTH_SHA')
        registry.accept_catalog(document, ref, raw)
    for gid, ref in attempts.values():
        raw = get(ref, 'attempt')
        value = decode(raw, LIMITS['attempt'])
        need(type(value.get('scope')) is dict and value['scope'].get('group_id') == gid, 'ATTEMPT_FOREIGN_PAGE')
        key = (value.get('run_sha256'), value.get('attempt_id'))
        need(key in expected_commands, 'INDEPENDENT_EXPECTED_NATIVE_COMMAND_REQUIRED')
        registry.accept_attempt(raw, ref, expected_command=expected_commands[key])
    for cid, ref in cells.items():
        value = decode(get(ref, 'cell'), LIMITS['cell'])
        need(type(value.get('scope')) is dict and value['scope'].get('cell_id') == cid, 'CELL_RECORD_FOREIGN_MEMBERSHIP')
        summary_raw = get(value.get('summary'), 'original')
        registry.accept_cell(value, ref, summary_raw)
    for ref in root['retained_pages']:
        value = decode(get(ref, 'retained'), LIMITS['retained'])
        registry.accept_retained(value, ref)
    for gid in pages:
        need(protocol.same(registry.group_document(gid), pages[gid]), 'GROUP_COMPLETE_CAPTURE_ATTEMPT_CELL_CLOSURE')
    need(protocol.same(registry.root_document(group_refs), root), 'ROOT_RECONSTRUCTED_MEMBERSHIP_OR_COUNTS_DIFFER')
    registry.frozen = True
    return ExecutionView(registry, root_reference, root)


def iter_cell_samples(base, checked_cell, *, expected_run):
    """Original bytes, with ALL store/reference closure BEFORE the first yield.

    Existing v2 resolve_reference performs bounded whole-member restoration and
    exhaustion, length/SHA and base binding. This conservative adapter buffers
    <=256MiB plus resolver/join copies; memory must be separately admitted.
    The analyzer must exhaust this iterator and independently parse/check all
    1000 samples. checked_lines provides strict incremental UTF-8 framing.
    """
    need(type(checked_cell) is CheckedCell and protocol.same(checked_cell.run, expected_run),
         'EXACT_CHECKED_CELL_EXPECTED_RUN')
    call(protocol.validate_run, expected_run)
    need(checked_cell.record.get('run_sha256') == run_sha(expected_run) and
         checked_cell.samples_reference is not None and checked_cell.samples_binding is not None,
         'MEASUREMENT_ORIGINAL_SAMPLE_REFERENCE_REQUIRED')
    selector, binding = checked_cell.samples_reference, checked_cell.samples_binding
    call(rawref.validate_reference, selector)
    call(protocol.validate_binding, binding, expected_run)
    need(binding['role'] == 'samples' and protocol.same(binding['scope'], checked_cell.record['scope']) and
         selector['sha256'] == checked_cell.record['samples_original_sha256'], 'CELL_SAMPLES_EXACT_BINDING')
    raw = call(rawref.resolve_reference, Path(base), selector, expected_run, binding, rawref.MAX_ORIGINAL)
    for start in range(0, len(raw), protocol.MAX_CHUNK):
        yield raw[start:start + protocol.MAX_CHUNK]


def iter_cell_native_stdout(base, checked_cell, *, expected_run):
    """Exact measurement stdout; independent analyzer compares native rows.

    This has the same full-member-memory admission as iter_cell_samples and
    returns <=1MiB chunks only after the complete resolver has been exhausted.
    Never pass its extra native summary line to the 1000 normalized-line route.
    """
    need(type(checked_cell) is CheckedCell and protocol.same(checked_cell.run, expected_run),
         'EXACT_CHECKED_CELL_EXPECTED_RUN')
    call(protocol.validate_run, expected_run)
    need(checked_cell.record.get('run_sha256') == run_sha(expected_run) and
         checked_cell.stdout_reference is not None and checked_cell.stdout_binding is not None and
         checked_cell.measurement is not None, 'MEASUREMENT_NATIVE_STDOUT_REQUIRED')
    selector, binding = checked_cell.stdout_reference, checked_cell.stdout_binding
    call(rawref.validate_reference, selector)
    call(protocol.validate_binding, binding, expected_run)
    need(binding['role'] == 'stdout' and protocol.same(binding['scope'], checked_cell.record['scope']) and
         binding['attempt_id'] == checked_cell.measurement['attempt_id'] and
         sha(canonical(binding)) == checked_cell.measurement['captures']['stdout'], 'CELL_NATIVE_STDOUT_EXACT_BINDING')
    raw = call(rawref.resolve_reference, Path(base), selector, expected_run, binding, rawref.MAX_ORIGINAL)
    for start in range(0, len(raw), protocol.MAX_CHUNK):
        yield raw[start:start + protocol.MAX_CHUNK]


def validate_retained_rows(rows):
    need(type(rows) is list and 1 <= len(rows) <= MAX_ROWS, 'RETAINED_ROWS_BOUND')
    paths = set()
    for row in rows:
        exact(row, ('path', 'kind', 'bytes', 'sha256', 'membership', 'reason', 'owner'))
        call(rawref.relative, row['path'])
        need(row['path'] not in paths, 'DUPLICATE_RETAINED_PATH')
        paths.add(row['path'])
        need(row['kind'] in ('file', 'directory') and row['membership'] == 'nonqualifying-retained' and
             type(row['reason']) is str and 1 <= len(row['reason']) <= 1024, 'EXPLICIT_NONQUALIFYING_RETENTION')
        integer(row['bytes'], 0, 15_000_000_000)
        if row['kind'] == 'file':
            digest(row['sha256'])
        else:
            need(row['bytes'] == 0 and row['sha256'] is None, 'DIRECTORY_RETENTION_ROW')
        exact(row['owner'], ('run_sha256', 'group_id', 'attempt_id'))
        if row['owner']['run_sha256'] is not None:
            digest(row['owner']['run_sha256'])
        if row['owner']['group_id'] is not None:
            need(type(row['owner']['group_id']) is str and re.fullmatch('[0-9a-f]{20}', row['owner']['group_id']), 'RETAINED_GROUP')
        if row['owner']['attempt_id'] is not None:
            need(type(row['owner']['attempt_id']) is str and re.fullmatch('[0-9]{1,24}-[0-9a-f]{8}', row['owner']['attempt_id']), 'RETAINED_ATTEMPT')
    need([row['path'] for row in rows] == sorted(paths), 'SORTED_RETAINED_MEMBERS')
    return clone(rows)
