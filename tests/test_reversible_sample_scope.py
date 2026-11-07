"""Scope lifecycle, copied-context isolation and bounded ordered workers."""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reversible_samples as codec
import reference_derived_storage_probe as probe


RAW = b'{"query":0,"response":{"hits":[]}}\n{"summary":true}\n'
CHANGED = RAW.replace(b'"query":0', b'"query":1')


class ReversibleScopeTests(unittest.TestCase):
    def tearDown(self):
        self.assertIsNone(codec.reconstruction_scope_info())

    def test_unscoped_calls_parse_fresh_rows(self):
        first, second = codec._stdout_rows(RAW), codec._stdout_rows(RAW)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIsNone(codec.reconstruction_scope_info())

    def test_scope_hits_only_equal_full_raw_bytes_and_clears(self):
        with codec.reconstruction_scope() as state:
            first = codec._stdout_rows(RAW)
            self.assertIs(first, codec._stdout_rows(bytes(bytearray(RAW))))
            changed = codec._stdout_rows(CHANGED)
            self.assertNotEqual(first, changed)
            self.assertIs(changed, codec._stdout_rows(CHANGED))
            self.assertEqual(state.info()['counts']['row_hits'], 2)
            self.assertEqual(state.info()['counts']['row_evictions'], 1)
        self.assertTrue(state.info()['closed'])
        self.assertIsNone(state.raw_key)
        self.assertIsNone(state.raw_rows)
        self.assertFalse(state.overlays)

    def test_old_tree_released_before_replacement_parse(self):
        original = codec._stdout_rows_uncached
        seen = []
        with codec.reconstruction_scope() as state:
            def inspect(raw):
                seen.append(state.info()['row_entries'])
                return original(raw)
            with patch.object(codec, '_stdout_rows_uncached', inspect):
                codec._stdout_rows(RAW)
                codec._stdout_rows(CHANGED)
            self.assertEqual(seen, [0, 0])

    def test_failed_rows_and_overlay_exceptions_are_never_cached(self):
        with codec.reconstruction_scope() as state:
            for _ in range(2):
                with self.assertRaises(ValueError):
                    codec._stdout_rows(b'not-json\n')
                with self.assertRaises(ValueError):
                    codec._overlay('not-json')
            self.assertEqual(state.info()['counts']['row_misses'], 2)
            self.assertEqual(state.info()['counts']['overlay_misses'], 2)
            self.assertEqual(state.info()['row_entries'], 0)
            self.assertEqual(state.info()['overlay_entries'], 0)

    def test_limit_and_function_mutations_invalidate_before_cache_hit(self):
        with codec.reconstruction_scope():
            codec._stdout_rows(RAW)
            with patch.object(codec, 'MAX_LINES', 0), self.assertRaises(ValueError):
                codec._stdout_rows(RAW)
            codec._stdout_rows(RAW)
            with patch.object(codec, '_loads', side_effect=codec.Refusal('changed loader')):
                with self.assertRaises(ValueError):
                    codec._stdout_rows(RAW)
            codec._overlay('0.5')
            with patch.object(codec, '_dumps', return_value='changed serializer'):
                with self.assertRaises(ValueError):
                    codec._overlay('0.5')

    def test_nonadmitted_raw_falls_through_and_releases_previous_entry(self):
        with codec.reconstruction_scope() as state:
            codec._stdout_rows(RAW)
            self.assertEqual(codec._stdout_rows(bytearray(RAW)), codec._stdout_rows_uncached(bytearray(RAW)))
            self.assertIsNone(state.raw_key)
            codec._stdout_rows(RAW)
            with self.assertRaises(ValueError):
                codec._stdout_rows(b' ' * ((1 << 20) + 1))
            self.assertEqual(state.info()['row_entries'], 0)
            self.assertEqual(state.info()['counts']['row_bypass'], 2)

    def test_overlay_lru_is_bounded_and_does_not_retain_arbitrary_literals(self):
        with codec.reconstruction_scope() as state:
            for index in range(129):
                literal = json.dumps(float(index) / 1000, separators=(',', ':'))
                self.assertEqual(codec._overlay(literal), float(index) / 1000)
                self.assertLessEqual(len(state.overlays), 128)
            self.assertEqual(len(state.overlays), 128)
            self.assertNotIn('0.0', state.overlays)
            self.assertFalse(state.info()['parsed_memory_cap'])

    def test_nested_scope_restores_parent_and_exception_clears(self):
        with codec.reconstruction_scope() as parent:
            rows = codec._stdout_rows(RAW)
            with self.assertRaisesRegex(RuntimeError, 'intentional'):
                with codec.reconstruction_scope() as child:
                    codec._stdout_rows(CHANGED)
                    raise RuntimeError('intentional')
            self.assertTrue(child.info()['closed'])
            self.assertEqual(child.info()['row_entries'], 0)
            self.assertEqual(codec.reconstruction_scope_info()['scope_id'], parent.scope_id)
            self.assertIs(codec._stdout_rows(RAW), rows)

    def test_copied_active_context_falls_through_in_foreign_thread(self):
        with codec.reconstruction_scope() as parent:
            rows = codec._stdout_rows(RAW)
            codec._overlay('0.5')
            before = parent.info()
            overlays = tuple(parent.overlays.items())
            copied = copy_context()
            def foreign():
                self.assertNotEqual(threading.get_ident(), parent.owner_thread)
                self.assertIs(codec._SCOPE_STATE.get(), parent)
                self.assertIsNone(codec.reconstruction_scope_info())
                first, second = codec._stdout_rows(RAW), codec._stdout_rows(RAW)
                self.assertEqual(first, rows)
                self.assertEqual(second, rows)
                self.assertIsNot(first, second)
                self.assertIsNot(first, rows)
                self.assertEqual(codec._overlay('0.5'), 0.5)
                self.assertEqual(parent.info(), before)
                self.assertIs(parent.raw_key, RAW)
                self.assertIs(parent.raw_rows, rows)
                self.assertEqual(tuple(parent.overlays.items()), overlays)
                with codec.reconstruction_scope() as child:
                    self.assertNotEqual(child.owner_thread, parent.owner_thread)
                    self.assertEqual(codec._stdout_rows(CHANGED), codec._stdout_rows_uncached(CHANGED))
                self.assertTrue(child.info()['closed'])
                self.assertEqual(child.info()['row_entries'], 0)
                self.assertIs(codec._SCOPE_STATE.get(), parent)
                self.assertIsNone(codec.reconstruction_scope_info())
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(copied.run, foreign).result(timeout=5)
            self.assertEqual(parent.info(), before)
            self.assertIs(parent.raw_rows, rows)
            self.assertEqual(tuple(parent.overlays.items()), overlays)

    def test_whole_token_guard_keeps_bounds_around_strings_and_invalid_escapes(self):
        self.assertEqual(codec._loads(json.dumps('[{}],:' * 6000)), '[{}],:' * 6000)
        for raw in ('[' * 33 + '0' + ']' * 33, '[' + ','.join(['0'] * 32768) + ']'):
            with self.subTest(bound=raw[:20]), self.assertRaises(codec.Refusal):
                codec._loads(raw)
        for raw in ('"unfinished', '"bad\\q"', '[}', '{}[]'):
            with self.subTest(raw=raw), self.assertRaises(codec.Refusal):
                codec._loads(raw)
        self.assertEqual(codec._loads('{"a":1,"a":2}'), {'a': 2})
        with self.assertRaises(codec.Refusal):
            codec._loads('{"a":1,"a":2}', strict=True)

    def test_scoped_workers_keep_original_order_two_pending_and_clear_every_cell(self):
        barrier = threading.Barrier(2)
        observations = {}
        def cell(root, name, files):
            self.assertIsNotNone(codec.reconstruction_scope_info())
            rows = codec._stdout_rows(RAW if name != 'second' else CHANGED)
            if name in ('first', 'second'):
                barrier.wait(timeout=3)
            return {'path': name, 'mode': 'identity', 'query': rows[0][1]['query']}, None
        with patch.object(probe, 'derive_cell', cell):
            results = list(probe.scoped_cells(None, ['first', 'second', 'third'], {}, observations))
        self.assertEqual([name for name, _ in results], ['first', 'second', 'third'])
        self.assertEqual([result[0]['query'] for _, result in results], [0, 1, 0])
        self.assertEqual(observations['completed_cells'], 3)
        self.assertEqual(observations['checked_cleared_scopes'], 3)
        self.assertEqual(observations['peak_pending_futures'], 2)
        self.assertEqual(len(observations['worker_thread_ids']), 2)

    def test_worker_failure_propagates_and_worker_scope_still_clears(self):
        held = []
        def failing(root, name, files):
            held.append(codec._SCOPE_STATE.get())
            codec._stdout_rows(RAW)
            raise RuntimeError('intentional worker failure')
        with patch.object(probe, 'derive_cell', failing), self.assertRaisesRegex(RuntimeError, 'intentional worker'):
            list(probe.scoped_cells(None, ['first', 'second'], {}, {}))
        self.assertTrue(held)
        for state in held:
            self.assertTrue(state.info()['closed'])
            self.assertIsNone(state.raw_key)
            self.assertIsNone(state.raw_rows)


if __name__ == '__main__':
    unittest.main()
