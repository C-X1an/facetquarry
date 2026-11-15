"""Unexecuted v2 collector protocol building block; pure bounded metadata only.

This does not capture a subprocess, open a store, retire bytes, write an index,
run a benchmark or qualify measurements. Its tagged group/cell scopes and
external attempt records address independent first-integration findings.
Legacy gzip and the existing private raw-reference v1 remain unchanged.
"""
import codecs
import datetime as dt
import hashlib
import itertools
import json
import math
import re

RUN_FORMAT = 'scientific-collector-run-v2'
BINDING_FORMAT = 'scientific-capture-binding-v2'
ATTEMPT_FORMAT = 'scientific-external-attempt-v2'
GRID_SHA256 = '37d376ffa53b54fd37849b0fb682a76b944cea029185a0da4771dc1d20420992'
MAX_METADATA = 8 << 20
MAX_REFERENCES = 32_400
MAX_BATCH_REFERENCES = 64
MAX_BATCH_BYTES = 256 << 20
MAX_CHUNK = 1 << 20
MAX_CHUNKS = 4096
FROZEN = {
    'n': [2000, 10000], 'dimension': 64,
    'distributions': ['uniform', 'clustered', 'ties'],
    'correlations': ['independent', 'positive', 'negative'],
    'seeds': [11, 23, 47, 83, 131],
    'selectivities': [1.0, 0.2, 0.05, 0.01, 0.001], 'two_facet': True,
    'ef': [32, 128, 512], 'queries': 200, 'warmup': 20, 'repetitions': 5,
    'k': 10, 'm': 12, 'ef_construction': 96, 'build_budget': 200000000,
    'concurrency': 1,
}
FILTERS = (('all', {}), ('p20', {'p20': 'yes'}), ('p05', {'p05': 'yes'}),
           ('p01', {'p01': 'yes'}), ('p001', {'p001': 'yes'}),
           ('and20', {'p20': 'yes', 'parity': '0'}))


class Refusal(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Refusal(code)


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys), 'EXACT_SCHEMA')


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, 'INTEGER_BOUND')


def same(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(same(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(same(x, y) for x, y in zip(left, right))
    return left == right


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('utf-8')


def sha(raw):
    need(type(raw) is bytes, 'BYTE_DIGEST_REQUIRED')
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'SHA256')


def hex_id(value, length):
    need(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % length, value), 'HEX_ID')


def _unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'DUPLICATE_KEY')
        value[key] = item
    return value


def decode(raw):
    need(type(raw) is bytes and len(raw) <= MAX_METADATA, 'METADATA_BOUND')
    try:
        return json.loads(raw, object_pairs_hook=_unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal('NONFINITE')))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Refusal('METADATA_FORMAT') from error


def frozen_config(readers):
    need(type(readers) is int and readers in (1, 4, 16), 'READER_PROFILE')
    return {**json.loads(json.dumps(FROZEN)), 'concurrency': readers}


def validate_run(run):
    exact(run, ('format', 'source', 'commit', 'execution_id', 'invocation_id',
                'github_run_id', 'github_run_attempt', 'grid_sha256', 'config',
                'config_hash', 'config_sha256', 'binaries', 'provenance_sha256',
                'admission_script_sha256'))
    need(run['format'] == RUN_FORMAT, 'RUN_VERSION')
    for key in ('source', 'config_sha256', 'provenance_sha256', 'admission_script_sha256'):
        digest(run[key])
    hex_id(run['commit'], 40)
    hex_id(run['execution_id'], 32)
    hex_id(run['invocation_id'], 32)
    for key in ('github_run_id', 'github_run_attempt'):
        need(type(run[key]) is str and re.fullmatch('[1-9][0-9]{0,19}', run[key]), 'WORKFLOW_ID')
    need(run['grid_sha256'] == GRID_SHA256, 'LOCKED_GRID')
    need(type(run['config']) is dict and 'concurrency' in run['config'], 'CONFIG')
    need(same(run['config'], frozen_config(run['config']['concurrency'])), 'FROZEN_FULL_CONFIG')
    need(run['config_sha256'] == sha(canonical(run['config'])), 'CANONICAL_CONFIG_SHA')
    legacy = hashlib.sha256(json.dumps(run['config'], sort_keys=True).encode()).hexdigest()[:12]
    need(run['config_hash'] == legacy, 'LEGACY_CONFIG_HASH')
    exact(run['binaries'], ('facetquarry', 'fqbench'))
    for value in run['binaries'].values():
        digest(value)
    return run


def validate_provenance_bytes(raw, run):
    """Keep the original pretty-JSON file identity, never its reserialization."""
    validate_run(run)
    need(sha(raw) == run['provenance_sha256'], 'ORIGINAL_PROVENANCE_BYTES')
    value = decode(raw)
    need(type(value) is dict and value.get('source') == run['source'], 'PROVENANCE_SOURCE')
    binaries = value.get('binaries')
    exact(binaries, ('facetquarry', 'fqbench'))
    for name, expected in run['binaries'].items():
        record = binaries[name]
        need(type(record) is dict and record.get('sha256') == expected and
             record.get('source') == run['source'], 'FULL_PROVENANCE_BINARY_PAIR')
    return value  # Other host/build fields remain available to the existing qualifier.


def group_id(group):
    return sha(canonical(group))[:20]


def _group(group, run):
    exact(group, ('n', 'dimension', 'distribution', 'correlation', 'seed', 'concurrency'))
    config = run['config']
    for key in ('n', 'dimension', 'seed', 'concurrency'):
        integer(group[key], 1, 200_000_000)
    need(group['n'] in config['n'] and group['dimension'] == config['dimension'] and
         group['seed'] in config['seeds'] and group['concurrency'] == config['concurrency'] and
         group['distribution'] in config['distributions'] and
         group['correlation'] in config['correlations'], 'GROUP_AXES')
    return group


def cells_for_group(group, run):
    _group(group, run)
    result = {}
    for label, filt in FILTERS:
        for mode in ('exact', 'graph', 'postfilter', 'auto'):
            for ef in ([512] if mode == 'exact' else (32, 128, 512)):
                cell = {**group, 'filter_label': label, 'filter': dict(filt), 'mode': mode, 'ef': ef}
                # Deliberately keep the existing collector/analyzer cell-ID bytes.
                cid = hashlib.sha256(json.dumps(cell, sort_keys=True).encode()).hexdigest()[:20]
                need(cid not in result, 'CELL_ID_COLLISION')
                result[cid] = cell
    need(len(result) == 60, 'EXACT_SIXTY_CELLS')
    return result


def all_groups(run):
    validate_run(run)
    config = run['config']
    groups = []
    for n, distribution, correlation, seed in itertools.product(
            config['n'], config['distributions'], config['correlations'], config['seeds']):
        groups.append({'n': n, 'dimension': config['dimension'], 'distribution': distribution,
                       'correlation': correlation, 'seed': seed, 'concurrency': config['concurrency']})
    need(len(groups) == 90, 'EXACT_NINETY_GROUPS')
    return groups


def validate_scope(scope, run):
    need(type(scope) is dict and type(scope.get('kind')) is str, 'TAGGED_SCOPE')
    if scope['kind'] == 'group':
        exact(scope, ('kind', 'group_id', 'group', 'cell_ids'))
        group = _group(scope['group'], run)
        need(type(scope['cell_ids']) is list and
             scope['cell_ids'] == sorted(cells_for_group(group, run)), 'COMPLETE_GROUP_CELL_MEMBERSHIP')
    elif scope['kind'] == 'cell':
        exact(scope, ('kind', 'group_id', 'cell_id', 'cell'))
        cell = scope['cell']
        exact(cell, ('n', 'dimension', 'distribution', 'correlation', 'seed', 'concurrency',
                     'filter_label', 'filter', 'mode', 'ef'))
        group = {key: cell[key] for key in ('n', 'dimension', 'distribution', 'correlation', 'seed', 'concurrency')}
        expected = cells_for_group(group, run)
        need(type(scope['cell_id']) is str and scope['cell_id'] in expected and
             same(cell, expected[scope['cell_id']]), 'EXACT_CELL_SCOPE')
    else:
        raise Refusal('UNKNOWN_SCOPE_KIND')
    need(scope['group_id'] == group_id(group), 'RUN_BOUND_GROUP_ID')
    return scope


def producer_for(stage, run):
    if stage == 'admission':
        return {'kind': 'python-script', 'name': 'scripts/disk_guard.py',
                'sha256': run['admission_script_sha256']}
    need(stage in ('build', 'measurement'), 'STAGE')
    name = 'facetquarry' if stage == 'build' else 'fqbench'
    return {'kind': 'native-binary', 'name': name, 'sha256': run['binaries'][name]}


def validate_binding(binding, run):
    validate_run(run)
    exact(binding, ('format', 'run_sha256', 'scope', 'workload_seed', 'build_seed', 'attempt_id', 'stage',
                    'role', 'outcome', 'completeness', 'origin', 'generation', 'corpus_sha256',
                    'queries_sha256', 'producer'))
    need(binding['format'] == BINDING_FORMAT, 'BINDING_VERSION')
    digest(binding['run_sha256'])
    need(binding['run_sha256'] == sha(canonical(run)), 'EXACT_CAPTURE_RUN_IDENTITY')
    scope = validate_scope(binding['scope'], run)
    stage, role, outcome = binding['stage'], binding['role'], binding['outcome']
    need(type(stage) is str and stage in ('admission', 'build', 'measurement'), 'STAGE')
    need((scope['kind'] == 'cell') == (stage == 'measurement'), 'STAGE_SCOPE')
    group = scope['group'] if scope['kind'] == 'group' else scope['cell']
    for key in ('workload_seed', 'build_seed'):
        need(type(binding[key]) is int and binding[key] == group['seed'], 'EXPLICIT_SEED_BINDING')
    need(type(binding['attempt_id']) is str and re.fullmatch('[0-9]{1,24}-[0-9a-f]{8}', binding['attempt_id']), 'ATTEMPT_ID')
    origins = {'stdout': 'new-native-original', 'stderr': 'new-native-original',
               'samples': 'new-normalized-original', 'corpus': 'new-input-original', 'queries': 'new-input-original'}
    need(type(role) is str and role in origins and binding['origin'] == origins[role], 'ROLE_ORIGIN')
    need(role != 'samples' or stage == 'measurement', 'SAMPLES_CELL_ONLY')
    need(role != 'queries' or stage == 'measurement', 'QUERY_CELL_ONLY')
    need(role != 'corpus' or stage == 'build', 'CORPUS_GROUP_BUILD_ONLY')
    need(type(outcome) is str and outcome in ('success', 'failed', 'timeout', 'start-error', 'available-partial'), 'OUTCOME')
    complete = 'complete' if role in ('corpus', 'queries') or outcome in ('success', 'failed') else 'available-partial'
    need(binding['completeness'] == complete, 'HONEST_CAPTURE_COMPLETENESS')
    for key in ('generation', 'corpus_sha256', 'queries_sha256'):
        if binding[key] is not None:
            digest(binding[key])
    if stage == 'admission':
        need(all(binding[key] is None for key in ('generation', 'corpus_sha256', 'queries_sha256')), 'ADMISSION_PREINPUT_NULLS')
    elif stage == 'build':
        need(binding['corpus_sha256'] is not None and binding['queries_sha256'] is None, 'GROUP_BUILD_INPUT_IDENTITY')
    else:
        need(all(binding[key] is not None for key in ('generation', 'corpus_sha256', 'queries_sha256')), 'MEASUREMENT_INPUT_IDENTITIES')
    need(same(binding['producer'], producer_for(stage, run)), 'ACTUAL_STAGE_PRODUCER')
    return binding


def logical_key(binding, run):
    validate_binding(binding, run)
    scope = binding['scope']
    return (binding['run_sha256'], run['invocation_id'], scope['kind'], scope.get('cell_id', scope['group_id']),
            binding['attempt_id'], binding['stage'], binding['role'])


def validate_bindings(bindings, run):
    """Call once across every catalog/page, never reset at a batch boundary."""
    validate_run(run)
    need(type(bindings) is list and len(bindings) <= MAX_REFERENCES, 'GLOBAL_REFERENCE_COUNT')
    seen, attempts = set(), {}
    for binding in bindings:
        key = logical_key(binding, run)
        need(key not in seen, 'CROSS_CATALOG_DUPLICATE_LOGICAL_CAPTURE')
        seen.add(key)
        # Input originals may be complete even when the native process times
        # out. Their role-specific completeness was checked above. Native
        # stdout/stderr/normalized samples otherwise describe ONE outcome.
        common = {name: value for name, value in binding.items()
                  if name not in ('role', 'origin', 'completeness')}
        signature = canonical(common)
        # One attempts/<id> directory represents one native invocation, even
        # when its role references are distributed across catalog pages.
        attempt_key = (binding['run_sha256'], binding['attempt_id'])
        need(attempt_key not in attempts or attempts[attempt_key] == signature,
             'CROSS_CATALOG_CONTRADICTORY_ATTEMPT_SCOPE_STAGE_OR_PROVENANCE')
        attempts[attempt_key] = signature
    return seen


def split_batches(items, run):
    """Metadata allocation plan only; the caller must preadmit actual storage."""
    validate_run(run)
    need(type(items) is list and len(items) <= MAX_REFERENCES, 'ITEM_COUNT')
    bindings = []
    for item in items:
        exact(item, ('binding', 'bytes'))
        integer(item['bytes'], 0, MAX_BATCH_BYTES)
        bindings.append(item['binding'])
    validate_bindings(bindings, run)
    batches, current, used = [], [], 0
    for item in items:
        if current and (len(current) == MAX_BATCH_REFERENCES or used+item['bytes'] > MAX_BATCH_BYTES):
            batches.append(current)
            current, used = [], 0
        current.append(item)
        used += item['bytes']
    if current:
        batches.append(current)
    return batches


def native_outcome(exit_code, termination):
    need(termination in (None, 'timeout', 'start_error', 'available_partial'), 'TERMINATION_REASON')
    if exit_code is not None:
        integer(exit_code, -255, 255)
    need(termination != 'start_error' or exit_code is None, 'START_ERROR_HAS_NO_PROCESS_EXIT')
    if termination is not None:
        return {'timeout': 'timeout', 'start_error': 'start-error', 'available_partial': 'available-partial'}[termination]
    integer(exit_code, -255, 255)
    return 'success' if exit_code == 0 else 'failed'


def _timestamp(value):
    need(type(value) is str and len(value) <= 64, 'TIMESTAMP')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise Refusal('TIMESTAMP') from error
    need(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(0), 'UTC_TIMESTAMP')
    return parsed


def validate_external_attempt(value, run, captures, *, expected_command):
    """An external immutable member references captures; no enclosing hash.

    `captures` is the execution-wide mapping of binding hashes to bindings,
    already checked against catalogs by the future execution-index reader.
    `expected_command` is independently derived by the trusted collector or
    qualifier from owned paths/config; never pass value['command'] as its own
    expectation. This does not substitute for scientific reachability checks.
    """
    validate_run(run)
    exact(value, ('format', 'run_sha256', 'scope', 'attempt_id', 'stage', 'producer', 'command',
                  'started_at', 'ended_at', 'duration_seconds', 'timeout_seconds', 'exit_code',
                  'termination_reason', 'error', 'status', 'captures'))
    need(value['format'] == ATTEMPT_FORMAT and value['run_sha256'] == sha(canonical(run)), 'EXTERNAL_ATTEMPT_VERSION_RUN')
    validate_scope(value['scope'], run)
    need(_timestamp(value['started_at']) <= _timestamp(value['ended_at']), 'ATTEMPT_TIME_ORDER')
    duration = value['duration_seconds']
    # Bound the integer before math.isfinite can attempt float conversion.
    need(type(duration) in (int, float) and 0 <= duration <= 86400 and math.isfinite(duration), 'DURATION')
    integer(value['timeout_seconds'], 1, 3600)
    outcome = native_outcome(value['exit_code'], value['termination_reason'])
    need(value['status'] == ('PASS' if outcome == 'success' else 'FAIL'), 'NATIVE_STATUS_SEPARATE_FROM_SCIENCE')
    need(value['error'] is None or type(value['error']) is str and len(value['error']) <= 4096, 'ERROR_BOUND')
    need(type(value['command']) is list and 1 <= len(value['command']) <= 64 and
         all(type(arg) is str and 0 < len(arg) <= 32768 and '\0' not in arg for arg in value['command']), 'ARGV')
    need(type(expected_command) is list and same(value['command'], expected_command), 'TRUSTED_EXACT_STAGE_COMMAND')
    if value['stage'] == 'admission':
        need(value['command'] == ['python3', 'scripts/disk_guard.py', '--reserve', '500000000'], 'ACTUAL_ADMISSION_COMMAND')
    need(same(value['producer'], producer_for(value['stage'], run)), 'ATTEMPT_PRODUCER')
    roles = ('stdout', 'stderr', 'samples') if value['stage'] == 'measurement' else ('stdout', 'stderr')
    exact(value['captures'], roles)
    need(type(captures) is dict and len(captures) <= MAX_REFERENCES, 'CAPTURE_MAP_BOUND')
    for role, capture_id in value['captures'].items():
        digest(capture_id)
        need(capture_id in captures, 'UNREACHABLE_ATTEMPT_CAPTURE')
        binding = validate_binding(captures[capture_id], run)
        need(sha(canonical(binding)) == capture_id and same(binding['scope'], value['scope']) and
             binding['attempt_id'] == value['attempt_id'] and binding['stage'] == value['stage'] and
             binding['role'] == role and binding['outcome'] == outcome, 'ATTEMPT_CAPTURE_BINDING')
    validate_bindings([captures[capture_id] for capture_id in value['captures'].values()], run)
    return value


def checked_lines(chunks, *, maximum_bytes=MAX_BATCH_BYTES, maximum_lines=1000,
                  maximum_line_characters=2_000_000):
    """Exhaust the resolver before returning even the first accepted line.

    Strict incremental UTF-8 handles split code points. Returned text remains
    bounded by original byte/line limits; original byte captures are untouched.
    The analyzer must still perform every independent JSON/scientific check.
    """
    integer(maximum_bytes, 0, MAX_BATCH_BYTES)
    integer(maximum_lines, 0, 1000)
    integer(maximum_line_characters, 1, 2_000_000)
    decoder = codecs.getincrementaldecoder('utf-8')('strict')
    lines, pending, total = [], '', 0
    for count, raw in enumerate(chunks, 1):
        need(count <= MAX_CHUNKS and type(raw) is bytes and len(raw) <= MAX_CHUNK, 'RESOLVER_CHUNK_BOUND')
        total += len(raw)
        need(total <= maximum_bytes, 'RESOLVER_TOTAL_BOUND')
        pending += decoder.decode(raw, final=False)
        while '\n' in pending:
            line, pending = pending.split('\n', 1)
            need(len(line)+1 <= maximum_line_characters, 'SAMPLE_LINE_BOUND')
            lines.append(line+'\n')
            need(len(lines) <= maximum_lines, 'SAMPLE_COUNT_BOUND')
        need(len(pending) <= maximum_line_characters, 'UNFINISHED_LINE_BOUND')
    pending += decoder.decode(b'', final=True)
    if pending:
        need(len(pending) <= maximum_line_characters, 'SAMPLE_LINE_BOUND')
        lines.append(pending)
    need(len(lines) <= maximum_lines, 'SAMPLE_COUNT_BOUND')
    return tuple(lines)
