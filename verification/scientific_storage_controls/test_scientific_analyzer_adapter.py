"""Synthetic full-count JSON decoder/linkage controls; no engine simulation claim.

No subprocess, file, archive, network, native benchmark or qualification. All
fixtures are explicitly fabricated parser input, not purported measurements.
"""
import copy
import hashlib
import json
import unittest

import scientific_capture_protocol as protocol
import scientific_analyzer_adapter as adapter


def encoded(value):
    return (json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False)+'\n').encode('utf-8')


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def chunks(raw, size=65536):
    return (raw[start:start+size] for start in range(0, len(raw), size))


class SyntheticOriginals:
    def __init__(self, readers=1, failed_sample=False, unicode_metadata=False):
        config = protocol.frozen_config(readers)
        self.run = {'format': protocol.RUN_FORMAT, 'source': '1'*64, 'commit': '2'*40,
                    'execution_id': '3'*32, 'invocation_id': '4'*32, 'github_run_id': '123',
                    'github_run_attempt': '1', 'grid_sha256': protocol.GRID_SHA256,
                    'config': config, 'config_hash': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:12],
                    'config_sha256': protocol.sha(protocol.canonical(config)),
                    'binaries': {'facetquarry': '5'*64, 'fqbench': '6'*64},
                    'provenance_sha256': '7'*64, 'admission_script_sha256': '8'*64}
        self.group = {'n': 2000, 'dimension': 64, 'distribution': 'uniform', 'correlation': 'independent', 'seed': 11,
                      'concurrency': readers}
        self.cid, self.cell = next((cid, cell) for cid, cell in protocol.cells_for_group(self.group, self.run).items()
                                   if cell['mode'] == 'exact' and cell['filter_label'] == 'all')
        self.native_rows = []
        for repetition in range(5):
            for query in range(200):
                row = {'query': query, 'repetition': repetition, 'nanoseconds': query+repetition,
                       'response': {'schema_version': 1, 'generation': '9'*64, 'plan': 'exact',
                                    'status': 'complete', 'exact': True, 'eligible': 2000,
                                    'distance_evaluations': 2000,
                                    'hits': [{'id': 'r%06d' % hit, 'distance': hit} for hit in range(10)]}}
                if failed_sample and query == repetition == 0:
                    del row['response']; row['error'] = 'synthetic decoder error'
                self.native_rows.append(row)
        successes = sum('response' in row for row in self.native_rows)
        self.metadata = {'summary': True, 'source': self.run['source'], 'peak_rss_bytes': 10000000,
                         'rss_measurement': 'synthetic decoder fixture, not a measurement', 'goos': 'linux',
                         'goarch': 'amd64', 'gomaxprocs': 4, 'go_runtime_sys_bytes': 8000000,
                         'go': 'go1.27.3', 'workers': readers, 'samples': 1000, 'successful_queries': successes,
                         'zero_duration_count': 1, 'clock': {'monotonic': True, 'fallback': False,
                         'frequency_hz': 1000000000, 'calibration': {'successive_read_pairs': 1000}},
                         'measured_interval_ns': 1000000000, 'completed_queries_per_second': float(successes),
                         'throughput_measurement': 'synthetic arithmetic control',
                         'measurement': 'synthetic Unicode: 測量' if unicode_metadata else 'synthetic decoder fixture'}
        self.normalized_rows = [{**copy.deepcopy(row), 'recall_at_k': 1.0 if 'response' in row else None}
                                for row in self.native_rows]
        self.summary = {'evidence_format': adapter.FORMAT, 'source': self.run['source'],
                        'run_sha256': protocol.sha(protocol.canonical(self.run)), 'cell': copy.deepcopy(self.cell),
                        'scope': {'kind': 'cell', 'group_id': protocol.group_id(self.group),
                                  'cell_id': self.cid, 'cell': copy.deepcopy(self.cell)},
                        'stage': 'measurement', 'status': 'FAIL' if failed_sample else 'PASS',
                        'sample_count': 1000, 'native_metadata': copy.deepcopy(self.metadata)}
        self.refresh()

    def refresh(self):
        self.native = b''.join(encoded(row) for row in self.native_rows)+encoded(self.metadata)
        self.normalized = b''.join(encoded(row) for row in self.normalized_rows)
        self.summary['samples_original_sha256'] = identity(self.normalized)['sha256']

    def reconcile(self, native=None, normalized=None, native_chunks=None, normalized_chunks=None):
        native = self.native if native is None else native
        normalized = self.normalized if normalized is None else normalized
        return adapter.reconcile_originals(
            chunks(native) if native_chunks is None else native_chunks,
            chunks(normalized) if normalized_chunks is None else normalized_chunks,
            native_identity=identity(native), samples_identity=identity(normalized),
            summary=self.summary, expected_run=self.run, cell=self.cell)


class PureOriginalLinkageContracts(unittest.TestCase):
    def test_checked_cell_projection_uses_actual_reconstructed_registry_schema(self):
        # This is pure metadata reconstruction, not payload restoration or a
        # mocked integration. The actual POSIX wrapper gate stays NOT RUN.
        from test_scientific_execution_registry import Fixture
        fixture = Fixture(); view = fixture.freeze()
        cid = fixture.summary_documents[0]['scope']['cell_id']
        checked, cell = adapter.checked_context(view, cid, expected_run=fixture.run)
        self.assertNotIn('cell', checked.record)
        self.assertEqual(cell, checked.record['scope']['cell'])
        self.assertEqual(cell, checked.summary['cell'])
        self.assertEqual(checked.samples_reference, checked.summary['samples_reference'])

    def test_full_1000_normalized_and_1001_native_lines_for_all_reader_profiles(self):
        for readers in (1, 4, 16):
            with self.subTest(readers=readers):
                fixture = SyntheticOriginals(readers)
                result = fixture.reconcile()
                self.assertEqual(len(result.samples), 1000)
                self.assertEqual(result.format, adapter.LINKAGE)
                self.assertEqual(result.qualification, 'NOT_PERFORMED')
                self.assertEqual(result.samples_original_sha256, identity(fixture.normalized)['sha256'])
                self.assertEqual(result.native_stdout_original_sha256, identity(fixture.native)['sha256'])

    def test_split_multibyte_codepoints_and_arbitrary_line_boundaries(self):
        fixture = SyntheticOriginals(unicode_metadata=True)
        offset = fixture.native.index('測'.encode('utf-8'))
        pieces = list(chunks(fixture.native[:offset]))
        pieces += [fixture.native[offset:offset+1], fixture.native[offset+1:offset+2]]
        pieces += list(chunks(fixture.native[offset+2:]))
        result = fixture.reconcile(native_chunks=iter(pieces), normalized_chunks=chunks(fixture.normalized, 1023))
        self.assertEqual(result.native_summary['measurement'], fixture.metadata['measurement'])

    def test_resolver_tail_error_never_returns_accepted_rows(self):
        fixture = SyntheticOriginals()
        exhausted = []
        def broken():
            yield from chunks(fixture.normalized)
            exhausted.append(True)
            raise RuntimeError('synthetic resolver closure error')
        with self.assertRaisesRegex(RuntimeError, 'resolver closure'):
            fixture.reconcile(normalized_chunks=broken())
        self.assertEqual(exhausted, [True])

    def test_exact_original_length_and_digest_are_required(self):
        raw = b'{"query":1}\n'
        for wrong in ({'bytes': len(raw)+1, 'sha256': identity(raw)['sha256']},
                      {'bytes': len(raw), 'sha256': '0'*64}):
            with self.subTest(wrong=wrong):
                with self.assertRaisesRegex(adapter.Refusal, 'LENGTH_OR_SHA'):
                    adapter.original_lines(iter([raw]), wrong, maximum_lines=1000)

    def test_native_summary_route_is_distinct_from_normalized_1000_line_limit(self):
        raw = b'{}\n'*1001
        self.assertEqual(len(adapter.original_lines(chunks(raw), identity(raw), maximum_lines=1001)), 1001)
        with self.assertRaisesRegex(adapter.Refusal, 'LINE_COUNT'):
            adapter.original_lines(chunks(raw), identity(raw), maximum_lines=1000)
        with self.assertRaisesRegex(adapter.Refusal, 'EXPLICIT_LINE_ROUTE'):
            adapter.original_lines(chunks(raw), identity(raw), maximum_lines=1002)

    def test_invalid_utf8_and_incomplete_final_codepoint_refuse(self):
        for raw in (b'{"x":"\xff"}\n', b'{"x":"'+b'\xe6\xb8'):
            with self.subTest(raw=repr(raw)):
                with self.assertRaisesRegex(adapter.Refusal, 'STRICT_UTF8'):
                    adapter.original_lines(chunks(raw), identity(raw), maximum_lines=1000)

    def test_nonbytes_chunks_oversize_chunks_and_too_many_chunks_refuse(self):
        raw = b'{}\n'
        for bad in ([bytearray(raw)], [raw.decode()], [b'x'*(protocol.MAX_CHUNK+1)],
                    [b'']*(protocol.MAX_CHUNKS+1)):
            with self.subTest(kind=type(bad[0]).__name__, chunks=len(bad)):
                with self.assertRaisesRegex(adapter.Refusal, 'CHUNK_BOUND'):
                    adapter.original_lines(iter(bad), identity(raw), maximum_lines=1000)

    def test_line_and_encoded_string_limits_refuse_before_json_decoding(self):
        with self.assertRaisesRegex(adapter.Refusal, 'LINE_BYTE_BOUND'):
            adapter.decode_line(b' '*adapter.MAX_LINE+b'{}')
        with self.assertRaisesRegex(adapter.Refusal, 'STRING_ENCODED_BOUND'):
            adapter.decode_line(b'{"x":"'+b'x'*(adapter.MAX_STRING+1)+b'"}')
        raw = b'x'*(adapter.MAX_LINE+1)
        with self.assertRaisesRegex(adapter.Refusal, 'PENDING_LINE_BOUND'):
            adapter.original_lines(chunks(raw), identity(raw), maximum_lines=1000)

    def test_depth_token_and_scalar_limits_apply_before_decoded_allocation(self):
        for raw, code in ((b'['*9+b'0'+b']'*9, 'DEPTH_BOUND'),
                          (b'['+b'0,'*1100+b'0]', 'TOKEN_BOUND'),
                          (b'{"x":'+b'9'*65+b'}', 'SCALAR_TOKEN_BOUND')):
            with self.subTest(code=code):
                with self.assertRaisesRegex(adapter.Refusal, code):
                    adapter.decode_line(raw)

    def test_duplicate_keys_trailing_json_nonfinite_and_surrogates_refuse(self):
        for raw in (b'{"x":1,"x":2}', b'{} {}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'{"x":1e400}', b'{"x":"\\ud800"}'):
            with self.subTest(raw=raw):
                with self.assertRaises(adapter.Refusal):
                    adapter.decode_line(raw)

    def test_object_and_array_decoded_shapes_have_separate_bounds(self):
        for value, code in (({str(n): n for n in range(65)}, 'OBJECT_KEY_BOUND'),
                            ({'x': list(range(33))}, 'ARRAY_ITEM_BOUND')):
            with self.subTest(code=code):
                with self.assertRaisesRegex(adapter.Refusal, code):
                    adapter.decode_line(encoded(value))

    def test_missing_native_summary_and_summary_out_of_order_refuse(self):
        fixture = SyntheticOriginals()
        with self.assertRaisesRegex(adapter.Refusal, 'FULL_FROZEN_SAMPLE_COVERAGE'):
            fixture.reconcile(native=b''.join(encoded(row) for row in fixture.native_rows))
        with self.assertRaises(adapter.Refusal):
            fixture.reconcile(native=encoded(fixture.metadata)+b''.join(encoded(row) for row in fixture.native_rows))

    def test_duplicate_sample_and_invalid_typed_query_refuse(self):
        for mutate in ('duplicate', 'bool', 'range'):
            fixture = SyntheticOriginals()
            if mutate == 'duplicate':
                fixture.native_rows[-1] = copy.deepcopy(fixture.native_rows[0])
                fixture.normalized_rows[-1] = copy.deepcopy(fixture.normalized_rows[0])
            else:
                value = True if mutate == 'bool' else 200
                fixture.native_rows[0]['query'] = fixture.normalized_rows[0]['query'] = value
            fixture.refresh()
            with self.subTest(mutate=mutate):
                with self.assertRaises(adapter.Refusal):
                    fixture.reconcile()

    def test_changed_normalized_answer_duration_order_and_numeric_types_refuse(self):
        for change in ('answer', 'duration', 'order', 'numeric-type'):
            fixture = SyntheticOriginals()
            if change == 'answer':
                fixture.normalized_rows[0]['response']['hits'][0]['id'] = 'r001999'
            elif change == 'duration':
                fixture.normalized_rows[0]['nanoseconds'] += 1
            elif change == 'order':
                fixture.normalized_rows[0], fixture.normalized_rows[1] = fixture.normalized_rows[1], fixture.normalized_rows[0]
            else:
                fixture.normalized_rows[0]['response']['hits'][0]['distance'] = 0.0
            fixture.refresh()
            with self.subTest(change=change):
                with self.assertRaisesRegex(adapter.Refusal, 'DIFFERS_FROM_NATIVE'):
                    fixture.reconcile()

    def test_forged_summary_metadata_and_native_throughput_refuse(self):
        fixture = SyntheticOriginals()
        fixture.summary['native_metadata']['peak_rss_bytes'] += 1
        with self.assertRaisesRegex(adapter.Refusal, 'METADATA_DIFFERS_FROM_ORIGINAL'):
            fixture.reconcile()
        fixture = SyntheticOriginals()
        fixture.metadata['completed_queries_per_second'] = 999.0
        fixture.summary['native_metadata'] = copy.deepcopy(fixture.metadata); fixture.refresh()
        with self.assertRaisesRegex(adapter.Refusal, 'THROUGHPUT_RECOMPUTATION'):
            fixture.reconcile()

    def test_wrong_native_source_toolchain_workers_and_counts_refuse(self):
        for key, value in (('source', '0'*64), ('go', 'go1.23.2'), ('workers', 4),
                           ('samples', 999), ('successful_queries', 999), ('zero_duration_count', 0)):
            fixture = SyntheticOriginals(); fixture.metadata[key] = value
            fixture.summary['native_metadata'] = copy.deepcopy(fixture.metadata); fixture.refresh()
            with self.subTest(key=key):
                with self.assertRaises(adapter.Refusal):
                    fixture.reconcile()

    def test_missing_recall_extra_native_fields_and_excess_hits_refuse(self):
        for change in ('missing-recall', 'native-recall', 'hits'):
            fixture = SyntheticOriginals()
            if change == 'missing-recall':
                del fixture.normalized_rows[0]['recall_at_k']
            elif change == 'native-recall':
                fixture.native_rows[0]['recall_at_k'] = 1.0
            else:
                extra = {'id': 'r000010', 'distance': 10}
                fixture.native_rows[0]['response']['hits'].append(extra)
                fixture.normalized_rows[0]['response']['hits'].append(copy.deepcopy(extra))
            fixture.refresh()
            with self.subTest(change=change):
                with self.assertRaises(adapter.Refusal):
                    fixture.reconcile()

    def test_legacy_format_and_legacy_digest_field_cannot_enter_v2_route(self):
        for change in ('version', 'digest'):
            fixture = SyntheticOriginals()
            if change == 'version':
                del fixture.summary['evidence_format']
            else:
                fixture.summary['samples_sha256'] = '0'*64
            with self.subTest(change=change):
                with self.assertRaisesRegex(adapter.Refusal, 'EXPLICIT_V2_NO_LEGACY_DIGEST'):
                    fixture.reconcile()

    def test_failed_native_sample_is_linked_and_remains_nonqualifying(self):
        fixture = SyntheticOriginals(failed_sample=True)
        result = fixture.reconcile()
        self.assertIn('error', result.samples[0])
        self.assertIsNone(result.samples[0]['recall_at_k'])
        self.assertEqual(result.native_summary['successful_queries'], 999)
        self.assertEqual(fixture.summary['status'], 'FAIL')
        self.assertEqual(result.qualification, 'NOT_PERFORMED')

    def test_wrong_run_cell_original_sha_and_unchecked_execution_view_refuse(self):
        for change in ('run', 'cell', 'digest'):
            fixture = SyntheticOriginals()
            if change == 'run':
                fixture.summary['run_sha256'] = '0'*64
            elif change == 'cell':
                fixture.summary['cell']['seed'] = 23
            else:
                fixture.summary['samples_original_sha256'] = '0'*64
            with self.subTest(change=change):
                with self.assertRaises(adapter.Refusal):
                    fixture.reconcile()
        with self.assertRaisesRegex(adapter.Refusal, 'CHECKED_EXECUTION_VIEW_REQUIRED'):
            adapter.reconcile_checked_cell(None, object(), '0'*20, expected_run=SyntheticOriginals().run)


if __name__ == '__main__':
    unittest.main()
