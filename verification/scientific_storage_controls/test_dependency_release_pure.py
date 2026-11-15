"""UNEXECUTED pure fault controls for the explicitly selected dependency variants.

All descriptor numbers belong to fake handles. FakeOS never calls the OS. These
are unit controls, never POSIX/native/integration, file preservation or fsync
evidence. Normal colocated imports are required; no dynamic loader or alias is
used. Execute only after the separate source-closure and execution admission.
"""
import hashlib
import stat
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import raw_member_store as store
import scientific_raw_reference_v2 as rawref


class FakeOS:
    """Known owned numbers only; failures can model an already-consumed close."""
    def __init__(self, known, close_errors=None, fsync_errors=None, observer=None):
        self.known = set(known)
        self.close_errors = close_errors or {}
        self.fsync_errors = fsync_errors or {}
        self.observer = observer
        self.closes, self.syncs = [], []

    def close(self, fd):
        if fd not in self.known:
            raise AssertionError('UNOWNED_FAKE_DESCRIPTOR')
        self.closes.append(fd)
        if self.observer is not None:
            self.observer(fd)
        if fd in self.close_errors:
            raise self.close_errors[fd]

    def fsync(self, fd):
        if fd not in self.known:
            raise AssertionError('UNOWNED_FAKE_DESCRIPTOR')
        self.syncs.append(fd)
        if fd in self.fsync_errors:
            raise self.fsync_errors[fd]

    def fstat(self, fd):
        if fd not in self.known:
            raise AssertionError('UNOWNED_FAKE_DESCRIPTOR')
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=7000)

    def getuid(self):
        return 7000


def transaction():
    """Populate only a pure handle; no begin(), paths, files or native FDs."""
    tx = store.Transaction.__new__(store.Transaction)
    tx._writer, tx.packed_fd, tx.stage_fd, tx.fd, tx.root_fd = 101, 102, 103, 104, 105
    tx._lock = threading.Lock()
    tx._released = tx._failed = tx._closed = tx._committed = tx._retired = False
    tx._commit_sha = None
    tx._directory_links = ()
    tx._root_binding = lambda: None
    tx.declared = {'source': 'a' * 64, 'transaction': 'b' * 32}
    tx._declared_raw = store._canonical(tx.declared)
    tx.saved, tx.events = [], []
    tx._save = lambda *args: tx.saved.append(args)
    tx._event = lambda event: tx.events.append(event)
    return tx


def batch():
    result = rawref.Batch.__new__(rawref.Batch)
    result.original_fd, result.shards_fd, result.fd = 203, 204, 205
    result.failed = result.published = False
    result._live = lambda: None
    # A closed writer's number is stale, not owned. Its original seal survives.
    result.writers = [SimpleNamespace(fd=201, closed=False, original=None),
                      SimpleNamespace(fd=202, closed=False, original=None),
                      SimpleNamespace(fd=999, closed=True, original={'retained': True})]
    return result


def capture(result):
    writer = rawref.CaptureWriter.__new__(rawref.CaptureWriter)
    writer.batch, writer.fd, writer.closed = result, 201, False
    writer.original = None
    writer._path_binding = lambda: None
    writer.size, writer.hashing = 3, hashlib.sha256(b'abc')
    writer.name, writer.id = 'fake.raw', 'c' * 32
    result.writers = [writer]
    return writer


class DependencyReleasePure(unittest.TestCase):
    def fake_modules(self, ops):
        return mock.patch.multiple(store, os=ops), mock.patch.multiple(rawref, os=ops)

    def assert_transaction_consumed(self, tx):
        self.assertTrue(tx._released)
        self.assertEqual((tx._writer, tx.packed_fd, tx.stage_fd, tx.fd, tx.root_fd),
                         (None,) * 5)
        self.assertEqual(tx._directory_links, ())
        self.assertFalse(tx._lock.locked())
        self.assertFalse(tx._closed)
        self.assertEqual(tx.saved, [])
        self.assertEqual(tx.events, [])

    def assert_batch_consumed(self, result):
        self.assertEqual((result.original_fd, result.shards_fd, result.fd), (None,) * 3)
        self.assertTrue(all(writer.closed and writer.fd is None for writer in result.writers))
        self.assertFalse(result.published)

    def test_transaction_release_failure_at_each_position_still_attempts_every_owned_fd(self):
        for failed_fd in range(101, 106):
            with self.subTest(failed_fd=failed_fd):
                tx, error = transaction(), OSError('INJECTED_CLOSE')
                def consumed_before_attempt(_):
                    self.assertTrue(tx._released)
                    self.assertEqual((tx._writer, tx.packed_fd, tx.stage_fd, tx.fd, tx.root_fd),
                                     (None,) * 5)
                ops = FakeOS(range(101, 106), {failed_fd: error}, observer=consumed_before_attempt)
                with mock.patch.object(store, 'os', ops):
                    with self.assertRaises(BaseExceptionGroup) as caught:
                        tx.release()
                    self.assertEqual(caught.exception.exceptions, (error,))
                    tx.release()
                self.assertEqual(ops.closes, list(range(101, 106)))
                self.assert_transaction_consumed(tx)

    def test_transaction_success_is_idempotent_and_deduplicates_aliases(self):
        tx = transaction()
        tx.packed_fd, tx._writer = tx.stage_fd, None
        ops = FakeOS((103, 104, 105))
        with mock.patch.object(store, 'os', ops):
            tx.release()
            tx.release()
        self.assertEqual(ops.closes, [103, 104, 105])
        self.assert_transaction_consumed(tx)

    def test_transaction_aggregates_original_and_all_cleanup_errors_by_identity(self):
        tx = transaction()
        original, first, last = ValueError('ORIGINAL_OPERATION'), OSError('FIRST_CLOSE'), OSError('LAST_CLOSE')
        ops = FakeOS(range(101, 106), {101: first, 105: last})
        with mock.patch.object(store, 'os', ops):
            with self.assertRaises(BaseExceptionGroup) as caught:
                try:
                    raise original
                finally:
                    tx.release()
        self.assertEqual(caught.exception.exceptions, (original, first, last))
        self.assertEqual(caught.exception.message, 'DESCRIPTOR_RELEASE_FAILED')
        self.assertIsNotNone(original.__traceback__)
        self.assertEqual(ops.closes, list(range(101, 106)))
        self.assert_transaction_consumed(tx)

    def test_transaction_successful_cleanup_leaves_original_error_unchanged(self):
        tx, original = transaction(), ValueError('ORIGINAL_OPERATION')
        ops = FakeOS(range(101, 106))
        with mock.patch.object(store, 'os', ops):
            with self.assertRaises(ValueError) as caught:
                try:
                    raise original
                finally:
                    tx.release()
        self.assertIs(caught.exception, original)
        self.assertEqual(ops.closes, list(range(101, 106)))

    def test_transaction_concurrent_release_refuses_without_consuming_ownership(self):
        tx = transaction()
        ops = FakeOS(range(101, 106))
        tx._lock.acquire()
        with mock.patch.object(store, 'os', ops):
            try:
                with self.assertRaises(store.Refusal) as caught:
                    tx.release()
                self.assertEqual(caught.exception.args, ('CONCURRENT_RELEASE_REFUSED',))
                self.assertEqual(ops.closes, [])
                self.assertFalse(tx._released)
                self.assertEqual(tx._writer, 101)
            finally:
                tx._lock.release()
            tx.release()
        self.assertEqual(ops.closes, list(range(101, 106)))

    def test_base_exception_does_not_short_circuit_later_closes(self):
        tx, interrupted = transaction(), KeyboardInterrupt('INJECTED_INTERRUPT')
        ops = FakeOS(range(101, 106), {102: interrupted})
        with mock.patch.object(store, 'os', ops):
            with self.assertRaises(BaseExceptionGroup) as caught:
                tx.release()
        self.assertEqual(caught.exception.exceptions, (interrupted,))
        self.assertEqual(ops.closes, list(range(101, 106)))
        self.assert_transaction_consumed(tx)

    def test_batch_release_failure_at_each_position_still_attempts_every_owned_fd(self):
        for failed_fd in range(201, 206):
            with self.subTest(failed_fd=failed_fd):
                result, error = batch(), OSError('INJECTED_CLOSE')
                retained = result.writers[-1].original
                def consumed_before_attempt(_):
                    self.assert_batch_consumed(result)
                ops = FakeOS(range(201, 206), {failed_fd: error}, observer=consumed_before_attempt)
                with mock.patch.object(store, 'os', ops):
                    with self.assertRaises(BaseExceptionGroup) as caught:
                        result.release()
                    self.assertEqual(caught.exception.exceptions, (error,))
                    result.release()
                self.assertEqual(ops.closes, list(range(201, 206)))
                self.assertIs(result.writers[-1].original, retained)
                self.assertEqual(retained, {'retained': True})
                self.assert_batch_consumed(result)

    def test_batch_deduplicates_live_aliases_skips_closed_and_accepts_partial_fields(self):
        result = batch()
        result.writers[1].fd = result.writers[0].fd
        result.writers.append(SimpleNamespace(fd=None, closed=False, original=None))
        result.shards_fd = result.original_fd
        del result.fd
        ops = FakeOS((201, 203))
        with mock.patch.object(store, 'os', ops):
            result.release()
            result.release()
        self.assertEqual(ops.closes, [201, 203])
        self.assert_batch_consumed(result)

    def test_batch_aggregates_active_original_and_every_close_failure(self):
        result = batch()
        original, writer_error, root_error = RuntimeError('ORIGINAL_OPERATION'), OSError('WRITER_CLOSE'), OSError('ROOT_CLOSE')
        ops = FakeOS(range(201, 206), {201: writer_error, 205: root_error})
        with mock.patch.object(store, 'os', ops):
            with self.assertRaises(BaseExceptionGroup) as caught:
                try:
                    raise original
                finally:
                    result.release()
        self.assertEqual(caught.exception.exceptions, (original, writer_error, root_error))
        self.assertEqual(ops.closes, list(range(201, 206)))
        self.assert_batch_consumed(result)

    def test_batch_successful_cleanup_leaves_active_original_unchanged(self):
        result, original = batch(), RuntimeError('ORIGINAL_OPERATION')
        ops = FakeOS(range(201, 206))
        with mock.patch.object(store, 'os', ops):
            with self.assertRaises(RuntimeError) as caught:
                try:
                    raise original
                finally:
                    result.release()
        self.assertIs(caught.exception, original)
        self.assertEqual(ops.closes, list(range(201, 206)))

    def test_transaction_close_error_consumes_writer_and_refuses_later_success_seal(self):
        tx, error = transaction(), OSError('WRITER_CLOSE')
        def writer_consumed_before_close(fd):
            if fd == 101:
                self.assertIsNone(tx._writer)
                self.assertFalse(tx._closed)
        ops = FakeOS(range(101, 106), {101: error}, observer=writer_consumed_before_close)
        with mock.patch.object(store, 'os', ops), mock.patch.object(store, '_read', return_value=tx._declared_raw):
            with self.assertRaises(BaseExceptionGroup) as caught:
                tx.close()
            self.assertEqual(caught.exception.exceptions, (error,))
            self.assertTrue(tx._failed)
            self.assertFalse(tx._closed)
            self.assertFalse(tx._committed)
            self.assertIsNone(tx._writer)
            with self.assertRaises(store.Refusal) as refused:
                tx.close()
            self.assertEqual(refused.exception.args, ('WRITER_CLOSE_FAILED_RELEASE_REQUIRED',))
            tx.release()
        self.assertEqual(ops.closes, list(range(101, 106)))
        self.assert_transaction_consumed(tx)

    def test_transaction_fsync_error_keeps_unattempted_writer_owned_for_release(self):
        tx, error = transaction(), OSError('WRITER_FSYNC')
        ops = FakeOS(range(101, 106), fsync_errors={101: error})
        with mock.patch.object(store, 'os', ops), mock.patch.object(store, '_read', return_value=tx._declared_raw):
            with self.assertRaises(OSError) as caught:
                tx.close()
            self.assertIs(caught.exception, error)
            self.assertEqual(tx._writer, 101)
            self.assertEqual(ops.closes, [])
            self.assertFalse(tx._closed)
            tx.release()
        self.assertEqual(ops.closes, list(range(101, 106)))
        self.assert_transaction_consumed(tx)

    def test_transaction_success_keeps_existing_seal_and_flags_until_close_completes(self):
        tx = transaction()
        def before_close(fd):
            if fd == 101:
                self.assertIsNone(tx._writer)
                self.assertFalse(tx._closed)
                self.assertEqual(tx.saved, [])
        ops = FakeOS(range(101, 106), observer=before_close)
        with mock.patch.object(store, 'os', ops), mock.patch.object(store, '_read', return_value=tx._declared_raw), mock.patch.object(store, '_scan', return_value=[]):
            result = tx.close()
            self.assertTrue(tx._closed)
            self.assertFalse(tx._committed)
            self.assertFalse(tx._failed)
            self.assertEqual(tx.events, ['after_close'])
            self.assertEqual(tx.saved, [('closed.json', {'version': 1, 'source': 'a' * 64,
                'transaction': 'b' * 32, 'committed': False, 'commit_sha256': None, 'writers_closed': True})])
            self.assertTrue(result['every_observed_file_included'])
            tx.release()
        self.assertEqual(ops.closes, list(range(101, 106)))
        self.assertTrue(tx._closed)
        self.assertTrue(tx._released)

    def test_capture_close_error_consumes_writer_without_seal_or_later_retry(self):
        result, error = batch(), OSError('CAPTURE_CLOSE')
        writer = capture(result)
        def writer_consumed_before_close(fd):
            if fd == 201:
                self.assertIsNone(writer.fd)
                self.assertFalse(writer.closed)
                self.assertIsNone(writer.original)
        ops = FakeOS((201, 203, 204, 205), {201: error}, observer=writer_consumed_before_close)
        first, second = self.fake_modules(ops)
        with first, second:
            with self.assertRaises(BaseExceptionGroup) as caught:
                writer.close()
            self.assertEqual(caught.exception.exceptions, (error,))
            self.assertFalse(writer.closed)
            self.assertIsNone(writer.fd)
            self.assertIsNone(writer.original)
            with self.assertRaises(rawref.Refusal) as refused:
                writer.close()
            self.assertEqual(refused.exception.args, ('CAPTURE_ALREADY_CLOSED',))
            result.release()
            result.release()
        self.assertEqual(ops.closes, [201, 203, 204, 205])
        self.assertIsNone(writer.original)
        self.assert_batch_consumed(result)

    def test_capture_preserves_fsync_error_and_close_error_together(self):
        result = batch()
        writer = capture(result)
        original, cleanup = OSError('CAPTURE_FSYNC'), OSError('CAPTURE_CLOSE')
        ops = FakeOS((201, 203, 204, 205), {201: cleanup}, {201: original})
        first, second = self.fake_modules(ops)
        with first, second:
            with self.assertRaises(BaseExceptionGroup) as caught:
                writer.close()
            self.assertEqual(caught.exception.exceptions, (original, cleanup))
            self.assertFalse(writer.closed)
            self.assertIsNone(writer.fd)
            self.assertIsNone(writer.original)
            result.release()
        self.assertEqual(ops.closes, [201, 203, 204, 205])
        self.assert_batch_consumed(result)

    def test_capture_fsync_error_with_successful_close_leaves_original_error_unchanged(self):
        result, original = batch(), OSError('CAPTURE_FSYNC')
        writer = capture(result)
        ops = FakeOS((201, 203, 204, 205), fsync_errors={201: original})
        first, second = self.fake_modules(ops)
        with first, second:
            with self.assertRaises(OSError) as caught:
                writer.close()
            self.assertIs(caught.exception, original)
            self.assertIsNone(writer.fd)
            self.assertFalse(writer.closed)
            self.assertIsNone(writer.original)
            result.release()
        self.assertEqual(ops.closes, [201, 203, 204, 205])
        self.assert_batch_consumed(result)

    def test_capture_success_marks_closed_only_after_close_and_keeps_original_metadata(self):
        result = batch()
        writer = capture(result)
        def before_close(fd):
            if fd == 201:
                self.assertIsNone(writer.fd)
                self.assertFalse(writer.closed)
                self.assertIsNone(writer.original)
        ops = FakeOS((201, 203, 204, 205), observer=before_close)
        identity = ['PURE_FAKE_IDENTITY']
        first, second = self.fake_modules(ops)
        with first, second, mock.patch.object(rawref, '_hash', return_value=(3, writer.hashing.hexdigest(), identity)):
            self.assertEqual(writer.close(), writer.id)
            self.assertTrue(writer.closed)
            self.assertIsNone(writer.fd)
            self.assertEqual(writer.original, {'path': 'originals/fake.raw', 'bytes': 3,
                                              'sha256': writer.hashing.hexdigest(), 'identity': identity})
            result.release()
        self.assertEqual(ops.closes, [201, 203, 204, 205])
        self.assert_batch_consumed(result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
