"""Actual bounded subprocess byte-return contracts, not benchmark qualification.

Every attempt fixture, including failures, remains in an owned ignored .local
directory. The Python children only emit fixed literal bytes or sleep until
the real subprocess timeout; no model, network or product-answer mock is used.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import benchmark_support
import common

FIXTURES = None
OUTPUT = bytes.fromhex('00fffe616c7068610d0a')
ERROR = bytes.fromhex('80fe6572726f72000a')


def owned_case(name):
    global FIXTURES
    def directory(path):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise RuntimeError('OWNED_FIXTURE_ANCESTOR_REQUIRED')
    directory(ROOT)
    local = ROOT/'.local'
    if not os.path.lexists(local):
        local.mkdir(mode=0o700)
    directory(local)
    parent = ROOT/'.local'/'attempt-bytes'
    parent.mkdir(mode=0o700, exist_ok=True)
    parent_info = parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode) or getattr(parent_info, 'st_file_attributes', 0) & 0x400:
        raise RuntimeError('OWNED_FIXTURE_PARENT_REQUIRED')
    # Finite retained-suite admission, not an OS quota. Refuse growth rather
    # than deleting a previous success/failure. Literal outputs are <32B each.
    entries, logical = 0, 0
    def refused(error):
        raise error
    for directory, dirs, files in os.walk(parent, followlinks=False, onerror=refused):
        for component in dirs+files:
            path = Path(directory)/component
            info = path.lstat()
            if getattr(info, 'st_file_attributes', 0) & 0x400 or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise RuntimeError('FIXTURE_LINK_OR_TYPE_REFUSED')
            entries += 1
            logical += max(info.st_size, getattr(info, 'st_blocks', 0)*512)+8192
            if entries+32 > 4096 or logical+(1 << 20) > 32 << 20:
                raise RuntimeError('RETAINED_BYTE_FIXTURE_ADMISSION_REFUSED')
    if FIXTURES is None:
        FIXTURES = parent/uuid.uuid4().hex[:16]
        FIXTURES.mkdir(mode=0o700)
    case = FIXTURES/hashlib.sha256(name.encode('utf-8')).hexdigest()[:8]
    case.mkdir(mode=0o700)  # Exclusive; never reuse/clean an earlier fixture.
    return case


class NativeAttemptBytes(unittest.TestCase):
    def setUp(self):
        self.folder = owned_case(self._testMethodName)

    def command(self, suffix=''):
        code = ('import os,time;os.write(1,bytes.fromhex("'+OUTPUT.hex()+'"));'
                'os.write(2,bytes.fromhex("'+ERROR.hex()+'"));'+suffix)
        return [sys.executable, '-I', '-S', '-B', '-c', code]

    def verify_retained(self, record, stdout, stderr):
        for label, expected in (('stdout', stdout), ('stderr', stderr)):
            info = record['streams'][label]
            compressed = (self.folder/info['path']).read_bytes()
            self.assertEqual(hashlib.sha256(compressed).hexdigest(), info['sha256'])
            self.assertEqual(gzip.decompress(compressed), expected)
            self.assertEqual((info['raw_bytes'], info['raw_sha256']),
                             (len(expected), hashlib.sha256(expected).hexdigest()))
        metadata = self.folder/'attempts'/record['attempt_id']/'attempt.json'
        self.assertEqual(json.loads(metadata.read_bytes()), record)

    def test_real_success_returns_invalid_utf8_and_nul_bytes_exactly(self):
        record, stdout, stderr = benchmark_support.command_attempt(
            self.folder, 'measurement', self.command(), common.run, 10, return_bytes=True)
        self.assertEqual((record['status'], record['exit_code']), ('PASS', 0))
        self.assertEqual((stdout, stderr), (OUTPUT, ERROR))
        self.assertIs(type(stdout), bytes)
        self.assertIs(type(stderr), bytes)
        self.verify_retained(record, OUTPUT, ERROR)

    def test_real_nonzero_exit_retains_original_byte_streams(self):
        record, stdout, stderr = benchmark_support.command_attempt(
            self.folder, 'measurement', self.command('raise SystemExit(7)'), common.run, 10,
            return_bytes=True)
        self.assertEqual((record['status'], record['exit_code'], record['termination_reason']),
                         ('FAIL', 7, None))
        self.assertEqual((stdout, stderr), (OUTPUT, ERROR))
        self.verify_retained(record, OUTPUT, ERROR)

    def test_real_timeout_returns_available_partial_bytes_and_no_exit_code(self):
        record, stdout, stderr = benchmark_support.command_attempt(
            self.folder, 'measurement', self.command('time.sleep(10)'), common.run, 3,
            return_bytes=True)
        self.assertEqual((record['status'], record['exit_code'], record['termination_reason']),
                         ('FAIL', None, 'timeout'))
        self.assertEqual((stdout, stderr), (OUTPUT, ERROR))
        self.verify_retained(record, OUTPUT, ERROR)

    def test_real_start_error_keeps_empty_original_streams_and_failure_metadata(self):
        record, stdout, stderr = benchmark_support.command_attempt(
            self.folder, 'build', [str(self.folder/'absent-program')], common.run, 1,
            return_bytes=True)
        self.assertEqual((record['status'], record['exit_code'], record['termination_reason']),
                         ('FAIL', None, 'start_error'))
        self.assertIn('FileNotFoundError', record['error'])
        self.assertEqual((stdout, stderr), (b'', b''))
        self.verify_retained(record, b'', b'')

    def test_default_legacy_text_return_keeps_existing_record_and_raw_stream_meanings(self):
        record, stdout, stderr = benchmark_support.command_attempt(
            self.folder, 'measurement', self.command(), common.run, 10)
        self.assertEqual((stdout, stderr), (OUTPUT.decode('utf-8', errors='replace'),
                                          ERROR.decode('utf-8', errors='replace')))
        self.assertIs(type(stdout), str)
        self.assertIs(type(stderr), str)
        self.verify_retained(record, OUTPUT, ERROR)

    def test_byte_return_option_type_refuses_before_start_or_attempt_directory(self):
        marker = self.folder/'child-started'
        command = self.command('fd=os.open('+repr(str(marker))+',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)')
        with self.assertRaises(ValueError):
            benchmark_support.command_attempt(self.folder, 'measurement', command,
                                              common.run, 10, return_bytes='true')
        self.assertFalse(marker.exists())
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_actual_decoding_adapter_refuses_byte_return_with_legacy_evidence(self):
        command = [sys.executable, '-I', '-S', '-B', '-c',
                   "import os;os.write(1,b'ordinary\\r\\n');os.write(2,b'diagnostic')"]
        def decoded_runner(args, **kwargs):
            # A deliberately misconfigured adapter around a real child. This
            # is a return-contract control, never original-byte provenance.
            completed = common.run(args, **kwargs)
            completed.stdout = completed.stdout.decode('utf-8')
            completed.stderr = completed.stderr.decode('utf-8')
            return completed
        with self.assertRaisesRegex(TypeError, 'undecoded subprocess streams'):
            benchmark_support.command_attempt(self.folder, 'measurement', command,
                                              decoded_runner, 10, return_bytes=True)
        records = list((self.folder/'attempts').glob('*/attempt.json'))
        self.assertEqual(len(records), 1)
        record = json.loads(records[0].read_bytes())
        self.assertEqual((record['status'], record['exit_code']), ('PASS', 0))
        self.verify_retained(record, b'ordinary\r\n', b'diagnostic')
