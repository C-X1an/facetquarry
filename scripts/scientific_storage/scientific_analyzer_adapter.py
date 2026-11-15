"""Source-only v2 original-byte linkage for the independent scientific analyzer.

This layer checks native/normalized linkage, not recall or qualification. The
existing analyzer must still validate exact ground truth, filters, generations,
work, repeated answers, metrics, paired seeds and every frozen grid cell.
Legacy compressed samples and their samples_sha256 meaning are untouched.
"""
from dataclasses import dataclass
import codecs
import hashlib
import json
import math
import re

import scientific_capture_protocol as protocol
import scientific_execution_registry as registry

FORMAT = 'scientific-collector-summary-v2'
LINKAGE = 'scientific-native-normalized-linkage-v1'
SAMPLES = 1000
NATIVE_LINES = SAMPLES+1
# Frozen k=10; response identifiers <=64 ASCII bytes. A complete successful
# native row is <4KiB even allowing whitespace/float representations. 16KiB
# also admits bounded error/summary text. Oversize/unknown rows remain retained
# raw originals and nonqualifying; they are never truncated or reserialized.
MAX_LINE = 16 << 10
MAX_STRING = 4096
MAX_DEPTH = 8
MAX_TOKENS = 2048
MAX_NUMBER = 64
MAX_OBJECT_KEYS = 64
MAX_ARRAY_ITEMS = 32
MAX_STREAM = NATIVE_LINES*MAX_LINE
RESPONSE_KEYS = ('schema_version', 'generation', 'plan', 'status', 'exact',
                 'eligible', 'distance_evaluations', 'hits')
NATIVE_KEYS = ('summary', 'source', 'peak_rss_bytes', 'rss_measurement', 'goos',
               'goarch', 'gomaxprocs', 'go_runtime_sys_bytes', 'go', 'workers',
               'samples', 'successful_queries', 'zero_duration_count', 'clock',
               'measured_interval_ns', 'completed_queries_per_second',
               'throughput_measurement', 'measurement')


class Refusal(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Refusal(code)


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, 'TYPED_INTEGER_BOUND')


def finite(value, low, high):
    need(type(value) in (int, float) and low <= value <= high and math.isfinite(value),
         'FINITE_NUMBER_BOUND')


def exact(value, keys):
    need(type(value) is dict and set(value) == set(keys), 'EXACT_JSON_SCHEMA')


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'SHA256')


def identity(value):
    exact(value, ('bytes', 'sha256'))
    integer(value['bytes'], 1, MAX_STREAM)
    digest(value['sha256'])
    return value


def preflight(raw):
    """Bound JSON structure BEFORE allocating its decoded object graph.

    Byte/string/number/token/depth caps apply even to invalid JSON. This is not
    the syntax parser. The strict decoder subsequently rejects duplicate keys,
    invalid UTF-8, nonfinite numbers, trailing JSON and malformed syntax.
    """
    need(type(raw) is bytes and 0 < len(raw) <= MAX_LINE, 'JSON_LINE_BYTE_BOUND')
    stack, quoted, escaped, string_bytes, atom_bytes, tokens = [], False, False, 0, 0, 0
    for byte in raw:
        if quoted:
            string_bytes += 1
            need(string_bytes <= MAX_STRING, 'JSON_STRING_ENCODED_BOUND')
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
            continue
        if byte == 34:
            quoted, escaped, string_bytes, atom_bytes = True, False, 0, 0
            tokens += 1
        elif byte in (123, 91):
            stack.append(byte); tokens += 1; atom_bytes = 0
            need(len(stack) <= MAX_DEPTH, 'JSON_DEPTH_BOUND')
        elif byte in (125, 93):
            need(stack and stack.pop() == (123 if byte == 125 else 91), 'JSON_CONTAINER_MISMATCH')
            tokens += 1; atom_bytes = 0
        elif byte in (44, 58):
            tokens += 1; atom_bytes = 0
        elif byte in (9, 10, 13, 32):
            atom_bytes = 0
        else:
            if atom_bytes == 0:
                tokens += 1
            atom_bytes += 1
            need(atom_bytes <= MAX_NUMBER, 'JSON_SCALAR_TOKEN_BOUND')
        need(tokens <= MAX_TOKENS, 'JSON_TOKEN_BOUND')
    need(not stack and not quoted, 'JSON_INCOMPLETE_STRUCTURE')


def _pairs(pairs):
    need(len(pairs) <= MAX_OBJECT_KEYS, 'JSON_OBJECT_KEY_BOUND')
    result = {}
    for key, value in pairs:
        need(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _float(value):
    need(len(value) <= MAX_NUMBER, 'JSON_NUMBER_TOKEN_BOUND')
    number = float(value)
    need(math.isfinite(number), 'NONFINITE_JSON_NUMBER')
    return number


def _nonfinite(_):
    raise Refusal('NONFINITE_JSON_NUMBER')


def decode_line(raw):
    preflight(raw)
    try:
        value = json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_pairs,
                           parse_float=_float, parse_constant=_nonfinite)
    except Refusal:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise Refusal('STRICT_JSON_FORMAT') from error
    pending, nodes = [value], 0
    while pending:
        item = pending.pop(); nodes += 1
        need(nodes <= MAX_TOKENS, 'DECODED_NODE_BOUND')
        if type(item) is dict:
            pending.extend(item.keys()); pending.extend(item.values())
        elif type(item) is list:
            need(len(item) <= MAX_ARRAY_ITEMS, 'JSON_ARRAY_ITEM_BOUND')
            pending.extend(item)
        elif type(item) is str:
            try:
                need(len(item.encode('utf-8', 'strict')) <= MAX_STRING, 'DECODED_STRING_BOUND')
            except UnicodeError as error:
                raise Refusal('INVALID_UNICODE_STRING') from error
        elif type(item) is float:
            need(math.isfinite(item), 'NONFINITE_JSON_NUMBER')
    need(type(value) is dict, 'JSON_ROW_MUST_BE_OBJECT')
    return value


def original_lines(chunks, expected_identity, *, maximum_lines):
    """Fully exhaust/hash originals before returning accepted line bytes.

    Resolver chunks may divide UTF-8 code points and lines anywhere. No stream
    digest is computed from replacement-decoded/reencoded text. Every line is
    retained here only under the source-derived stricter decoding bounds.
    """
    identity(expected_identity)
    need(type(maximum_lines) is int and maximum_lines in (SAMPLES, NATIVE_LINES), 'EXPLICIT_LINE_ROUTE')
    decoder = codecs.getincrementaldecoder('utf-8')('strict')
    lines, pending, total, hasher = [], b'', 0, hashlib.sha256()
    try:
        for count, raw in enumerate(chunks, 1):
            need(count <= protocol.MAX_CHUNKS and type(raw) is bytes and len(raw) <= protocol.MAX_CHUNK,
                 'RESOLVER_CHUNK_BOUND')
            total += len(raw)
            need(total <= expected_identity['bytes'] <= MAX_STREAM, 'ORIGINAL_STREAM_BYTE_BOUND')
            hasher.update(raw); decoder.decode(raw, final=False)
            parts = raw.split(b'\n')
            for part in parts[:-1]:
                need(len(pending)+len(part)+1 <= MAX_LINE, 'ORIGINAL_LINE_BYTE_BOUND')
                lines.append(pending+part+b'\n'); pending = b''
                need(len(lines) <= maximum_lines, 'ORIGINAL_LINE_COUNT_BOUND')
            need(len(pending)+len(parts[-1]) <= MAX_LINE, 'ORIGINAL_PENDING_LINE_BOUND')
            pending += parts[-1]
        decoder.decode(b'', final=True)
    except UnicodeError as error:
        raise Refusal('ORIGINAL_STRICT_UTF8') from error
    if pending:
        lines.append(pending)
    need(len(lines) <= maximum_lines, 'ORIGINAL_LINE_COUNT_BOUND')
    need(total == expected_identity['bytes'] and hasher.hexdigest() == expected_identity['sha256'],
         'ORIGINAL_LENGTH_OR_SHA_MISMATCH')
    return tuple(lines)


def response(value, cell):
    exact(value, RESPONSE_KEYS)
    integer(value['schema_version'], 1, 1); digest(value['generation'])
    need(value['plan'] in ('exact', 'graph', 'postfilter') and
         value['status'] in ('complete', 'budget_exhausted') and type(value['exact']) is bool,
         'RESPONSE_LABEL_TYPES')
    integer(value['eligible'], 0, cell['n'])
    integer(value['distance_evaluations'], 0, 1_000_000)
    need(type(value['hits']) is list and len(value['hits']) <= 10, 'FROZEN_HIT_BOUND')
    for hit in value['hits']:
        exact(hit, ('id', 'distance'))
        need(type(hit['id']) is str and re.fullmatch('[A-Za-z0-9_.-]{1,64}', hit['id']), 'HIT_ID_BOUND')
        finite(hit['distance'], 0, 1e34)


def sample(value, cell, *, normalized):
    need(type(value) is dict, 'SAMPLE_OBJECT')
    keys = {'query', 'repetition', 'nanoseconds'}
    success = 'response' in value
    keys.add('response' if success else 'error')
    if normalized:
        keys.add('recall_at_k')
    exact(value, keys)
    integer(value['query'], 0, 199); integer(value['repetition'], 0, 4)
    integer(value['nanoseconds'], 0, (1 << 63)-1)
    if success:
        response(value['response'], cell)
    else:
        need(type(value['error']) is str and 0 < len(value['error'].encode('utf-8')) <= MAX_STRING,
             'NATIVE_ERROR_BOUND')
    if normalized:
        recall = value['recall_at_k']
        if recall is not None:
            finite(recall, 0, 1)
        need(success or recall is None, 'FAILED_SAMPLE_RECALL_MUST_BE_NULL')
    return value['query'], value['repetition']


def native_metadata(value, run, samples):
    exact(value, NATIVE_KEYS)
    need(value['summary'] is True and value['source'] == run['source'] and value['go'] == 'go1.27.3',
         'NATIVE_SOURCE_SUPPORTED_TOOLCHAIN')
    integer(value['workers'], run['config']['concurrency'], run['config']['concurrency'])
    integer(value['gomaxprocs'], 1, 1024)
    integer(value['samples'], SAMPLES, SAMPLES)
    successes = sum('response' in row for row in samples)
    zeros = sum(row['nanoseconds'] == 0 for row in samples)
    integer(value['successful_queries'], successes, successes)
    integer(value['zero_duration_count'], zeros, zeros)
    integer(value['measured_interval_ns'], 1, (1 << 63)-1)
    finite(value['completed_queries_per_second'], 0, 1e15)
    throughput = successes*1e9/value['measured_interval_ns']
    need(math.isclose(value['completed_queries_per_second'], throughput, rel_tol=1e-12, abs_tol=1e-9),
         'NATIVE_THROUGHPUT_RECOMPUTATION')
    if value['peak_rss_bytes'] is not None:
        integer(value['peak_rss_bytes'], 0, (1 << 64)-1)
    integer(value['go_runtime_sys_bytes'], 0, (1 << 64)-1)
    need(type(value['clock']) is dict, 'NATIVE_CLOCK_OBJECT')
    for key in ('rss_measurement', 'goos', 'goarch', 'throughput_measurement', 'measurement'):
        need(type(value[key]) is str and 0 < len(value[key].encode('utf-8')) <= 2048,
             'NATIVE_METADATA_STRING')


@dataclass(frozen=True)
class ReconciledSamples:
    format: str
    samples: tuple
    native_summary: dict
    native_stdout_original_sha256: str
    samples_original_sha256: str
    qualification: str = 'NOT_PERFORMED'


def reconcile_originals(native_chunks, normalized_chunks, *, native_identity,
                        samples_identity, summary, expected_run, cell):
    """Pure decoder controls may call this with explicitly synthetic originals.

    Real analysis must use reconcile_checked_cell so the expected identities
    come from checked execution/catalog closure, not candidate output itself.
    No recall, exactness, ordering or per-seed performance claim follows here.
    """
    try:
        protocol.validate_run(expected_run)
    except protocol.Refusal as error:
        raise Refusal(str(error)) from error
    need(type(cell) is dict and type(summary) is dict and summary.get('evidence_format') == FORMAT and
         'samples_sha256' not in summary, 'EXPLICIT_V2_NO_LEGACY_DIGEST')
    need(summary.get('source') == expected_run['source'] and protocol.same(summary.get('cell'), cell) and
         summary.get('run_sha256') == protocol.sha(protocol.canonical(expected_run)), 'SUMMARY_RUN_CELL_BINDING')
    try:
        protocol.validate_scope(summary.get('scope'), expected_run)
    except protocol.Refusal as error:
        raise Refusal(str(error)) from error
    need(summary['scope']['kind'] == 'cell' and protocol.same(summary['scope']['cell'], cell), 'SUMMARY_CELL_SCOPE')
    need(summary.get('stage') == 'measurement' and summary.get('status') in ('PASS', 'FAIL') and
         type(summary.get('sample_count')) is int and summary['sample_count'] == SAMPLES,
         'MEASUREMENT_FULL_SAMPLE_ROUTE')
    need(summary.get('samples_original_sha256') == samples_identity.get('sha256'), 'SUMMARY_ORIGINAL_SAMPLE_SHA')
    native_lines = original_lines(native_chunks, native_identity, maximum_lines=NATIVE_LINES)
    normalized_lines = original_lines(normalized_chunks, samples_identity, maximum_lines=SAMPLES)
    need(len(native_lines) == NATIVE_LINES and len(normalized_lines) == SAMPLES, 'FULL_FROZEN_SAMPLE_COVERAGE')
    native_rows, normalized_rows, seen = [], [], set()
    for native_raw, normalized_raw in zip(native_lines[:-1], normalized_lines):
        original, normalized = decode_line(native_raw), decode_line(normalized_raw)
        pair = sample(original, cell, normalized=False)
        need(pair not in seen, 'DUPLICATE_NATIVE_SAMPLE_PAIR'); seen.add(pair)
        sample(normalized, cell, normalized=True)
        need(protocol.same(original, {key: value for key, value in normalized.items() if key != 'recall_at_k'}),
             'NORMALIZED_SAMPLE_DIFFERS_FROM_NATIVE_ORIGINAL')
        native_rows.append(original); normalized_rows.append(normalized)
    need(seen == {(query, repetition) for query in range(200) for repetition in range(5)},
         'EXACT_QUERY_REPETITION_COVERAGE')
    metadata = decode_line(native_lines[-1]); native_metadata(metadata, expected_run, native_rows)
    need(protocol.same(metadata, summary.get('native_metadata')), 'SUMMARY_NATIVE_METADATA_DIFFERS_FROM_ORIGINAL')
    return ReconciledSamples(LINKAGE, tuple(normalized_rows), metadata,
                             native_identity['sha256'], samples_identity['sha256'])


def checked_context(view, cell_id, *, expected_run):
    """Project the actual checked metadata schema without opening payloads."""
    need(type(view) is registry.ExecutionView, 'CHECKED_EXECUTION_VIEW_REQUIRED')
    checked = view.checked_cell(cell_id, expected_run=expected_run)
    need(checked.measurement is not None and checked.stdout_reference is not None and
         checked.samples_reference is not None, 'MEASUREMENT_REFERENCES_REQUIRED')
    need(protocol.same(checked.summary.get('samples_reference'), checked.samples_reference) and
         checked.record.get('samples_original_sha256') == checked.samples_reference['sha256'],
         'CHECKED_ORIGINAL_SAMPLE_REFERENCE')
    cell = checked.record['scope']['cell']
    need(protocol.same(cell, checked.summary['cell']), 'CHECKED_SCOPE_SUMMARY_CELL')
    return checked, cell


def reconcile_checked_cell(base, view, cell_id, *, expected_run):
    """Registry restoration and fully exhausted native/normalized verification.

    Full-member resolver memory (<=256MiB plus joins/copies) is a separate
    admission prerequisite. This bounded parser does not supply a RAM quota.
    Exceptions leave every original untouched and the analysis nonqualifying.
    """
    checked, cell = checked_context(view, cell_id, expected_run=expected_run)
    return reconcile_originals(
        registry.iter_cell_native_stdout(base, checked, expected_run=expected_run),
        registry.iter_cell_samples(base, checked, expected_run=expected_run),
        native_identity={key: checked.stdout_reference[key] for key in ('bytes', 'sha256')},
        samples_identity={key: checked.samples_reference[key] for key in ('bytes', 'sha256')},
        summary=checked.summary, expected_run=expected_run, cell=cell)
