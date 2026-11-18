"""Fault controls for the exact quota-attempt branch; no Linux or fixtures run.

The selected source AST executes with injected descriptor/resource operations.
These controls check diagnostics before the existing acceptance guard fails.
They provide no kernel, quota, memory, lifecycle or custody integration claim.
"""
import ast
import errno
import hashlib
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT/'scripts/scientific_lifecycle/scientific_posix_lifecycle.py'
MANIFEST = ROOT/'scripts/scientific_lifecycle/LIFECYCLE_SOURCE_MANIFEST.json'
GUARD = 'ACTUAL_ATOMIC_ENOSPC_DENIAL_REQUIRED_RETAIN_PROBE'


def selected_branch():
    raw = MODULE.read_bytes()
    rows = json.loads(MANIFEST.read_bytes())['packet_files']
    row = next(item for item in rows if item['name'] == MODULE.name)
    assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
    tree = ast.parse(raw)
    prepare = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'prepare_quota')
    branches = [node for node in prepare.body if isinstance(node, ast.Try) and
                any(isinstance(item, ast.Constant) and item.value == GUARD for item in ast.walk(node))]
    assert len(branches) == 1
    need = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'need')
    return compile(ast.Module(body=[need, branches[0]], type_ignores=[]), str(MODULE), 'exec')


class QuotaAttemptDiagnostics(unittest.TestCase):
    def exercise(self, error_number, size, blocks, accepts):
        events, records = [], []
        attempted = False

        class DescriptorOperations:
            O_RDWR, O_CREAT, O_EXCL, O_NOFOLLOW = 2, 64, 128, 256

            @staticmethod
            def open(name, flags, mode, *, dir_fd):
                self.assertEqual((name, dir_fd), ('enospc-probe.retained', 10))
                return 11

            @staticmethod
            def fchown(fd, uid, gid):
                self.assertEqual((fd, uid, gid), (11, 1001, 1001))

            @staticmethod
            def posix_fallocate(fd, offset, length):
                nonlocal attempted
                self.assertEqual((fd, offset, length), (11, 0, 268_435_456+8192))
                attempted = True
                if error_number is not None:
                    raise OSError(error_number, 'synthetic allocation failure')

            @staticmethod
            def fsync(fd):
                events.append('fsync-work' if fd == 10 else 'fsync-probe')

            @staticmethod
            def fstat(fd):
                self.assertEqual(fd, 11)
                return SimpleNamespace(st_size=size if attempted else 0, st_blocks=blocks if attempted else 0)

            @staticmethod
            def fstatvfs(fd):
                self.assertEqual(fd, 10)
                return SimpleNamespace(f_bavail=8192 if attempted else 16384, f_frsize=4096, f_blocks=65536)

        def create_file(path, raw, *, owner):
            self.assertEqual(path, PurePosixPath('/admitted/job/control/quota-attempt-observation.json'))
            self.assertEqual(owner, 1001)
            self.assertLessEqual(len(raw), 8192)
            records.append(json.loads(raw))
            events.append('observation-written')

        resources = SimpleNamespace(RLIMIT_FSIZE=1, RLIMIT_AS=2,
            getrlimit=lambda kind: (268_443_648, 268_443_648) if kind == 1 else (536_870_912, 536_870_912))
        namespace = {'os': DescriptorOperations, 'errno': errno, 'resource': resources,
            'job': PurePosixPath('/admitted/job'), 'work': 10, 'probe': None, 'denial': None,
            'uid': 1001, 'gid': 1001, 'IMAGE_BYTES': 268_435_456, 'UNIT': 8192,
            'life_manifest_sha': '1'*64, 'actual': {'filesystem': 'ext4', 'filesystem_capacity_bytes': 268_435_456},
            'error_record': lambda error, operation: {'errno': error.errno, 'operation': operation},
            'create_file': create_file, 'json_bytes': lambda value: (json.dumps(value)+'\n').encode(),
            'close_owned': lambda *fds: events.append('closed')}
        if accepts:
            exec(selected_branch(), namespace)
        else:
            with self.assertRaisesRegex(RuntimeError, GUARD):
                exec(selected_branch(), namespace)
        self.assertEqual(len(records), 1, 'attempt facts must survive the guard result')
        observed = records[0]
        self.assertEqual(observed['format'], 'scientific-posix-quota-attempt-observation-v1')
        self.assertEqual(observed['attempted_bytes'], 268_443_648)
        self.assertEqual(observed['probe_before'], {'bytes': 0, 'blocks_512': 0})
        self.assertEqual(observed['probe_after'], {'bytes': size, 'blocks_512': blocks})
        self.assertEqual(observed['attempt_error']['errno'] if observed['attempt_error'] else None, error_number)
        self.assertEqual(observed['limits_before']['RLIMIT_FSIZE'], [268_443_648]*2)
        self.assertEqual(observed['limits_after']['RLIMIT_AS'], [536_870_912]*2)
        self.assertEqual(observed['geometry_before']['available_bytes'], 67_108_864)
        self.assertEqual(observed['geometry_after']['available_bytes'], 33_554_432)
        self.assertLess(events.index('observation-written'), events.index('closed'))
        if accepts:
            self.assertLess(events.index('observation-written'), events.index('fsync-work'))

    def test_each_rejected_tuple_is_recorded_before_unchanged_guard_failure(self):
        for error_number, size, blocks in [(errno.ENOSPC, 0, 8), (errno.EFBIG, 0, 0), (None, 0, 0)]:
            with self.subTest(errno=error_number, bytes=size, blocks=blocks):
                self.exercise(error_number, size, blocks, False)

    def test_accepted_tuple_is_recorded_before_success_continues(self):
        self.exercise(errno.ENOSPC, 0, 0, True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
