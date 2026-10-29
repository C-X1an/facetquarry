"""Finite synthetic proof/byte controls. NOT actual mount, geometry or quota proof."""
import copy
from contextlib import ExitStack, nullcontext
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_filesystem as fs


class FilesystemPolicyTests(unittest.TestCase):
    def fixture(self, size=2_300_000_000):
        image, mount = PurePosixPath('/owned/reference.img'), PurePosixPath('/owned/mount')
        ctx = {'source': 'a' * 64, 'commit': 'b' * 40, 'git_status': '',
               'github_run_id': '17', 'github_run_attempt': '2'}
        stamp = '2026-10-28T18:00:00+00:00'
        ident = {'device': 2049, 'inode': 19, 'mode': stat.S_IFREG | 0o600, 'uid': 1001,
                 'gid': 1001, 'nlink': 1, 'size': size, 'device_major_minor': '8:1'}
        mi = {**ident, 'device': 1792, 'inode': 2, 'mode': stat.S_IFDIR | 0o755,
              'device_major_minor': '7:0'}
        del mi['size']
        geometry = {'uuid': '12345678-abcd-1234-abcd-123456789abc', 'block_size': 4096,
                    'block_count': size // 4096, 'reserved_blocks': 0}
        superblock = '\n'.join(['Filesystem UUID: ' + geometry['uuid'], 'Block size: 4096',
                                 'Block count: ' + str(geometry['block_count']), 'Reserved block count: 0']) + '\n'
        mounts = {'filesystems': [{'target': str(mount), 'fstype': 'ext4', 'source': '/dev/loop0',
                                  'uuid': geometry['uuid'], 'options': 'rw,relatime', 'maj:min': '7:0'}]}
        loops = {'loopdevices': [{'name': '/dev/loop0', 'back-file': str(image), 'back-ino': 19,
                                 'back-maj:min': '8:1', 'offset': 0, 'sizelimit': 0}]}

        def observation(argv, stdout='', stderr=''):
            captures = {key: {'bytes': len(raw.encode()), 'sha256': hashlib.sha256(raw.encode()).hexdigest()}
                        for key, raw in (('stdout', stdout), ('stderr', stderr))}
            return {'command': argv, 'started_at': stamp, 'ended_at': stamp, 'exit_code': 0,
                    'stdout': stdout, 'stderr': stderr,
                    'stdout_sha256': hashlib.sha256(stdout.encode()).hexdigest(),
                    'stderr_sha256': hashlib.sha256(stderr.encode()).hexdigest(),
                    'ownership': {'descendant_quiescence': {'quiescent': True, 'residual': []},
                                  'capture_complete': True, 'discarded_output_bytes': 0,
                                  'capture': captures, 'receipt_sha256': 'd' * 64,
                                  'receipt_path': str(Path(__file__).resolve().parent / 'synthetic-receipt.json')}}

        pi = {**ident, 'device': mi['device'], 'inode': 22, 'size': fs.PROBE_BYTES,
              'device_major_minor': mi['device_major_minor']}
        r = {'policy': fs.POLICY, 'limits': dict(fs.LIMITS), 'started_at': stamp, 'ended_at': stamp,
             'platform': 'linux', 'uid': 1001, 'gid': 1001, 'image_path': str(image),
             'mount_point': str(mount), 'image_bytes': size, 'run_context': ctx,
             'formatter_command': ['mkfs.ext4', '-F', '-q', '-m', '0', str(image)],
             'image_before': ident, 'image_after': dict(ident), 'mount_before': mi, 'mount_after': dict(mi),
             'geometry': geometry, 'observations': {
                 'version': observation(['mkfs.ext4', '-V'], stderr='mke2fs 1.47.0 (5-Feb-2023)\n'),
                 'superblock': observation(['dumpe2fs', '-h', str(image)], superblock, 'dumpe2fs 1.47.0\n'),
                 'mount': observation(['findmnt', '--json', '--mountpoint', str(mount), '-o',
                                       'TARGET,FSTYPE,SOURCE,UUID,OPTIONS,MAJ:MIN'], json.dumps(mounts)),
                 'loop': observation(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                                      '--output', 'NAME,BACK-FILE,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT'], json.dumps(loops))},
             'statvfs': {'observed_at': stamp, 'uid': 1001, 'gid': 1001, 'f_frsize': 4096,
                         'f_blocks': geometry['block_count'] - 10000,
                         'f_bfree': geometry['block_count'] - 20000, 'f_bavail': geometry['block_count'] - 20000},
             'probe': {'exclusive': True, 'cleaned': True, 'before': pi, 'after': dict(pi),
                       'sha256': hashlib.sha256(b'F' * fs.PROBE_BYTES).hexdigest()}}
        self.seal(r)
        return r, image, mount, size, copy.deepcopy(ctx)

    def seal(self, record):
        record['proof_sha256'] = fs.digest({k: v for k, v in record.items() if k != 'proof_sha256'})

    def reject(self, edit):
        args = self.fixture()
        edit(args[0])
        self.seal(args[0])
        with self.assertRaises(ValueError):
            fs.validate_policy(*args)

    def edit_json(self, record, name, edit):
        item = record['observations'][name]
        value = json.loads(item['stdout'])
        edit(value)
        item['stdout'] = json.dumps(value)
        item['stdout_sha256'] = hashlib.sha256(item['stdout'].encode()).hexdigest()
        item['ownership']['capture']['stdout'] = {'bytes': len(item['stdout'].encode()),
                                                'sha256': item['stdout_sha256']}

    def test_both_supported_dimensions_pure_only(self):
        for size in (2_300_000_000, 1_100_000_000):
            with self.subTest(size=size):
                fs.validate_policy(*self.fixture(size))

    def test_nonzero_reserved_and_missing_superblock_rejected(self):
        for text in ('Reserved block count: 1', 'Reserved count missing: 0'):
            def edit(r):
                item = r['observations']['superblock']
                item['stdout'] = item['stdout'].replace('Reserved block count: 0', text)
                item['stdout_sha256'] = hashlib.sha256(item['stdout'].encode()).hexdigest()
                item['ownership']['capture']['stdout'] = {'bytes': len(item['stdout'].encode()),
                                                        'sha256': item['stdout_sha256']}
                if text.endswith(': 1'):
                    r['geometry']['reserved_blocks'] = 1
            with self.subTest(text=text):
                self.reject(edit)

    def test_wrong_uuid_mount_backing_and_inode_rejected(self):
        controls = [('mount', 'filesystems', 'uuid', 'ffffffff-abcd-1234-abcd-123456789abc'),
                    ('mount', 'filesystems', 'target', '/owned/other'),
                    ('loop', 'loopdevices', 'back-file', '/owned/other.img'),
                    ('loop', 'loopdevices', 'back-ino', 20),
                    ('loop', 'loopdevices', 'back-maj:min', '8:2'),
                    ('loop', 'loopdevices', 'offset', 4096)]
        for name, group, key, value in controls:
            with self.subTest(key=key):
                self.reject(lambda r: self.edit_json(r, name, lambda x: x[group][0].update({key: value})))

    def test_inconsistent_geometry_counters_and_floor_rejected(self):
        for key, value in [('f_frsize', 1024), ('f_blocks', 999999999), ('f_bfree', -1),
                           ('f_bavail', 1), ('f_bavail', True)]:
            with self.subTest(key=key, value=value):
                self.reject(lambda r: r['statvfs'].update({key: value}))
        self.reject(lambda r: r['statvfs'].update(f_bfree=1, f_bavail=1))
        self.reject(lambda r: r['geometry'].update(block_count=1))

    def test_run28_ext4_available_and_total_free_are_distinct(self):
        # Actual run40871057615 counters, carried by a synthetic proof fixture.
        # This validates counter semantics, not a new mount or quota execution.
        for available in (530561, 126954):
            args = self.fixture()
            args[0]['statvfs'].update(f_blocks=534663, f_bfree=534657, f_bavail=available)
            self.seal(args[0])
            before = copy.deepcopy(args[0]['statvfs'])
            fs.validate_policy(*args)
            self.assertEqual(args[0]['statvfs'], before)
            self.assertLess(before['f_bavail'], before['f_bfree'])

    def test_available_free_order_and_ordinary_floor_stay_required(self):
        for counters in ({'f_blocks': 534663, 'f_bfree': 534657, 'f_bavail': 534658},
                         {'f_blocks': 534663, 'f_bfree': 534664, 'f_bavail': 530561},
                         {'f_blocks': 534663, 'f_bfree': 534657, 'f_bavail': 126953}):
            with self.subTest(counters=counters):
                self.reject(lambda r: r['statvfs'].update(counters))

    def test_ordinary_uid_gid_context_and_owned_identities_required(self):
        for edit in (lambda r: r.pop('uid'), lambda r: r.update(uid=0),
                     lambda r: r['statvfs'].update(uid=0), lambda r: r['run_context'].update(source='c' * 64),
                     lambda r: r['image_after'].update(inode=20), lambda r: r['image_before'].update(nlink=2),
                     lambda r: r['image_after'].update(size=1), lambda r: r['probe'].update(cleaned=False),
                     lambda r: r['probe']['after'].update(nlink=2)):
            self.reject(edit)

    def test_substituted_stream_hash_version_command_and_proof_rejected(self):
        for edit in (lambda r: r['observations']['version'].update(stderr='no actual version'),
                     lambda r: r['observations']['superblock'].update(stdout_sha256='0' * 64),
                     lambda r: r['observations']['loop']['command'].append('--raw'),
                     lambda r: r['observations']['mount'].update(exit_code=1),
                     lambda r: r.update(formatter_command=['mkfs.ext4', '-F', '-q', str(self.fixture()[1])]),
                     lambda r: r['limits'].update(global_reserve_bytes=0)):
            self.reject(edit)
        args = self.fixture()
        args[0]['proof_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            fs.validate_policy(*args)

    def test_stream_bytes_bound_and_duplicate_geometry_rejected(self):
        with self.assertRaises(ValueError):
            fs.geometry('Filesystem UUID: missing\n')
        with self.assertRaises(ValueError):
            fs.geometry(self.fixture()[0]['observations']['superblock']['stdout'] + 'Block size: 4096\n')
        with self.assertRaises(ValueError):
            fs.observe(['fixture-only'], lambda _: {'exit_code': 0, 'stdout': 'x' * (fs.MAX_STREAM + 1), 'stderr': ''})

    def test_all_mount_and_probe_devices_substituted_together_rejected(self):
        def edit(r):
            for item in (r['mount_before'], r['mount_after'], r['probe']['before'], r['probe']['after']):
                item.update(device=1793, device_major_minor='7:1')
        self.reject(edit)
        self.reject(lambda r: r['mount_before'].update(device=1793))

    def test_context_extras_bounded_and_unknown_oversized_fields_fail_before_json(self):
        args = self.fixture()
        args[0]['run_context']['legitimate_extra'] = {'profile': 'reference', 'budget': 2_000_000_000}
        args[-1].update(copy.deepcopy(args[0]['run_context']))
        self.seal(args[0])
        fs.validate_policy(*args)
        for edit in (lambda r: r.update(unknown='x' * (fs.MAX_STREAM + 1)),
                     lambda r: r.update(unknown={str(i): i for i in range(129)}),
                     lambda r: r.update(unknown=['x' * 30000] * 7),
                     lambda r: r['run_context'].update(extra='x' * 8193)):
            args = self.fixture()
            edit(args[0])
            with patch.object(fs.json, 'dumps', side_effect=AssertionError('serialization must not start')):
                with self.assertRaises(ValueError):
                    fs.validate_policy(*args)
        with patch.object(fs.json, 'dumps', side_effect=AssertionError('clone must not start')):
            with self.assertRaises(ValueError):
                fs.collect_policy(PurePosixPath('/image'), PurePosixPath('/mount'), 1_100_000_000,
                                  {'unknown': 'x' * 8193}, [])

    def test_default_runner_refuses_before_launch_or_path_observation(self):
        with patch.object(subprocess, 'Popen') as launch, patch.object(fs, 'checked') as check:
            with self.assertRaisesRegex(ValueError, 'durable owned runner'):
                fs.command(['not-executed'])
            args = self.fixture()
            with self.assertRaisesRegex(ValueError, 'durable owned runner'):
                fs.collect_policy(args[1], args[2], args[3], args[4], args[0]['formatter_command'])
            launch.assert_not_called()
            check.assert_not_called()

    def test_failed_observation_retains_bounded_streams_and_requires_quiescence(self):
        value = copy.deepcopy(self.fixture()[0]['observations']['version'])
        value['exit_code'] = 7
        with self.assertRaises(fs.ObservationFailure) as caught:
            fs.observe(['fixture-failure'], lambda _: value)
        self.assertEqual(caught.exception.observation['stderr'], value['stderr'])
        self.reject(lambda r: r['observations']['version']['ownership'].update(
            descendant_quiescence={'quiescent': False, 'residual': [{'pid': 1}]}))

    def synthetic_collection(self, failure):
        """Finite in-memory syscall controls; never actual filesystem evidence."""
        record, image, mount, size, context = self.fixture()
        for key, item in record['observations'].items():
            item['ownership']['receipt_path'] = '/owned/audit/' + key + '.json'
        retained = []
        class Runner:
            owned_durable = True
            def __call__(self, argv):
                item = next(x for x in record['observations'].values() if x['command'] == argv)
                return {key: copy.deepcopy(item[key]) for key in ('exit_code', 'stdout', 'stderr', 'ownership')}
            def checkpoint(self, value):
                retained.append(copy.deepcopy(value))
        def info(value):
            return SimpleNamespace(**{'st_' + key: value[key] for key in
                                      ('device', 'inode', 'mode', 'uid', 'gid', 'nlink', 'size')})
        # st_dev/st_ino are named differently from the proof's JSON keys.
        probe = info(record['probe']['before'])
        probe.st_dev, probe.st_ino = probe.st_device, probe.st_inode
        counters = SimpleNamespace(**record['statvfs'])
        if failure == 'floor':
            counters.f_bavail = 1
        calls = {'image': 0}
        def checked(path):
            if str(path) == str(image):
                calls['image'] += 1
                if failure == 'final_identity' and calls['image'] == 2:
                    raise OSError('synthetic final identity failure')
                return 'image'
            return 'mount'
        def geometry(raw):
            if failure == 'geometry':
                raise ValueError('synthetic geometry failure')
            return copy.deepcopy(record['geometry'])
        with ExitStack() as stack:
            controls = {
                'Path': PurePosixPath,
                'whole_entry': lambda *args, **kwargs: nullcontext(), 'checked': checked,
                'identity': lambda value: copy.deepcopy(record['probe']['before'] if value is probe
                                                        else record['image_before']),
                'mount_identity': lambda _: copy.deepcopy(record['mount_before']), 'geometry': geometry,
            }
            for key, value in controls.items():
                stack.enter_context(patch.object(fs, key, value))
            stack.enter_context(patch.object(fs.sys, 'platform', 'linux'))
            for key in ('getuid', 'getgid'):
                stack.enter_context(patch.object(fs.os, key, return_value=1001, create=True))
            for key, value in {'O_DIRECTORY': 0, 'O_NOFOLLOW': 0}.items():
                if not hasattr(fs.os, key):
                    stack.enter_context(patch.object(fs.os, key, value, create=True))
            for key, kwargs in {
                'open': {'side_effect': [17, 18]},
                'fstat': {'side_effect': lambda descriptor: probe if descriptor == 18 else 'mount'},
                'fstatvfs': {'return_value': counters}, 'stat': {'return_value': probe},
                'write': {'side_effect': OSError('synthetic write failure')} if failure == 'write'
                         else {'return_value': fs.PROBE_BYTES},
                'fsync': {'side_effect': OSError('synthetic fsync failure')} if failure == 'fsync' else {},
                'read': {'return_value': b'bad' if failure == 'readback' else b'F' * fs.PROBE_BYTES},
                'unlink': {'side_effect': OSError('synthetic cleanup failure')} if failure == 'cleanup' else {},
                'lseek': {}, 'close': {},
            }.items():
                stack.enter_context(patch.object(fs.os, key, create=True, **kwargs))
            if failure == 'validation':
                stack.enter_context(patch.object(fs, 'validate_policy', side_effect=ValueError('synthetic validation failure')))
            with self.assertRaises((ValueError, OSError)) as caught:
                fs.collect_policy(image, mount, size, context, record['formatter_command'], Runner())
        return caught.exception, retained

    def test_every_later_failure_retains_accumulated_structured_observations(self):
        for stage in ('geometry', 'floor', 'write', 'fsync', 'readback', 'cleanup', 'final_identity', 'validation'):
            with self.subTest(stage=stage):
                failure, retained = self.synthetic_collection(stage)
                partial = failure.partial_record
                self.assertEqual(set(partial['observations']), {'version', 'superblock', 'mount', 'loop'})
                self.assertEqual(partial['observations']['loop']['ownership']['receipt_sha256'], 'd' * 64)
                self.assertEqual(retained[-1], partial)
                if stage != 'geometry':
                    self.assertIn('statvfs', partial)
                if stage not in ('geometry', 'floor'):
                    self.assertIn('probe', partial)
                self.assertIn('failure', partial)

    def test_failure_compaction_retains_every_receipt_when_escaped_streams_exceed_budget(self):
        record = self.fixture()[0]
        record['observations']['version']['stdout'] = '\0' * fs.MAX_STREAM
        compact = fs.failure_partial(record)
        fs.bounded({'status': 'FAIL', 'partial_record': compact})
        self.assertEqual(set(compact['observations']), set(record['observations']))
        self.assertEqual(compact['geometry'], record['geometry'])
        for name, item in compact['observations'].items():
            self.assertNotIn('stdout', item)
            self.assertNotIn('stderr', item)
            self.assertTrue(item['raw_streams_in_owned_capture_only'])
            self.assertEqual(item['ownership'], record['observations'][name]['ownership'])

    def test_whole_entry_rejects_unrelated_alarm_and_has_hard_failure_tail(self):
        # Timer plumbing only. Actual Linux process controls remain separate.
        handlers, alarms = {}, []
        class HardExit(BaseException):
            pass
        def registration(sig, handler):
            old = handlers.get(sig, signal.SIG_DFL)
            handlers[sig] = handler
            return old
        import signal
        with ExitStack() as stack:
            stack.enter_context(patch.object(fs.sys, 'platform', 'linux'))
            stack.enter_context(patch.object(fs.time, 'monotonic', return_value=100))
            stack.enter_context(patch.object(fs.signal, 'SIGALRM', 14, create=True))
            stack.enter_context(patch.object(fs.signal, 'ITIMER_REAL', 0, create=True))
            stack.enter_context(patch.object(fs.signal, 'getsignal', side_effect=lambda s: handlers.get(s, signal.SIG_DFL)))
            stack.enter_context(patch.object(fs.signal, 'signal', side_effect=registration))
            stack.enter_context(patch.object(fs.signal, 'setitimer', side_effect=lambda *x: alarms.append(x), create=True))
            existing = stack.enter_context(patch.object(fs.signal, 'getitimer', return_value=(3.0, 0.0), create=True))
            stack.enter_context(patch.object(fs.os, '_exit', side_effect=HardExit))
            with self.assertRaisesRegex(ValueError, 'unrelated'):
                with fs.whole_entry(18):
                    self.fail('unrelated timer was replaced')
            existing.return_value = (0.0, 0.0)
            with fs.whole_entry(80):
                with self.assertRaises(fs.DeadlineExceeded):
                    with fs.whole_entry(18):
                        self.assertEqual(alarms[-1], (0, 16))
                        with patch.object(fs.time, 'monotonic', return_value=116):
                            handlers[14](14, None)
                self.assertEqual(alarms[-1], (0, 78))
            with self.assertRaises(HardExit):
                with fs.whole_entry(18):
                    with patch.object(fs.time, 'monotonic', return_value=116):
                        with self.assertRaises(fs.DeadlineExceeded):
                            handlers[14](14, None)
                    with patch.object(fs.time, 'monotonic', return_value=118):
                        handlers[14](14, None)
            self.assertEqual(alarms[-1], (0, 0))
            self.assertEqual(fs._DEADLINES, [])

    @unittest.skipUnless(sys.platform == 'linux', 'actual tiny process ownership requires Linux')
    def test_actual_hard_deadline_exits_during_stuck_failure_tail_without_quiescence_claim(self):
        # Finite 3s dedicated-process control; no mounts, root or quota claim.
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='filesystem-deadline-', dir=cache) as folder:
            pending = Path(folder) / 'pending.json'
            parent = ('import sys,time\nfrom pathlib import Path\n'
                      'sys.path.insert(0,' + repr(str(Path(fs.__file__).parent)) + ')\n'
                      'import reference_filesystem as f\n'
                      'with f.whole_entry(3):\n'
                      ' f.write_exclusive(Path(' + repr(str(pending)) + '),'
                      '{"status":"INCOMPLETE","descendant_quiescence":{"quiescent":False,"residual":None}})\n'
                      ' try:\n  time.sleep(60)\n'
                      ' except f.DeadlineExceeded:\n  time.sleep(60)\n')
            result = subprocess.run([sys.executable, '-c', parent], capture_output=True, timeout=6)
            self.assertEqual(result.returncode, 124, result.stderr.decode(errors='replace'))
            value = json.loads(pending.read_bytes())
            self.assertEqual(value['status'], 'INCOMPLETE')
            self.assertEqual(value['descendant_quiescence'], {'quiescent': False, 'residual': None})

    @unittest.skipUnless(sys.platform == 'linux', 'actual tiny process ownership requires Linux')
    def test_tiny_pipeholding_detached_child_owned_after_direct_parent_exit(self):
        # Fresh dedicated process: never enable subreaper in this test runner.
        # This controls process ownership only, not mount/quota capacity.
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='filesystem-process-', dir=cache) as folder:
            folder = Path(folder)
            marker, output = folder / 'child-pid', folder / 'result.json'
            payload = ('import os,time\npid=os.fork()\n'
                       'if pid == 0:\n os.setsid()\n print("detached-child",flush=True)\n'
                       ' open(' + repr(str(marker)) + ',"w").write(str(os.getpid()))\n time.sleep(60)\n'
                       'else:\n time.sleep(.15)\n print("direct-parent-exit",flush=True)\n os._exit(0)\n')
            parent = ('import sys,json\nfrom pathlib import Path\n'
                      'sys.path.insert(0,' + repr(str(Path(fs.__file__).parent)) + ')\n'
                      'import reference_filesystem as f\n'
                      'runner=f.OwnedRunner(Path(' + repr(str(folder / 'audit')) + '))\n'
                      'value=runner([sys.executable,"-c",' + repr(payload) + '])\n'
                      'f.write_exclusive(Path(' + repr(str(output)) + '),value)\n')
            result = subprocess.run([sys.executable, '-c', parent], capture_output=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            value = json.loads(output.read_bytes())
            self.assertEqual(value['ownership']['descendant_quiescence'], {'quiescent': True, 'residual': []})
            self.assertTrue(value['ownership']['capture_complete'])
            self.assertIn('detached-child', value['stdout'])
            self.assertIn('direct-parent-exit', value['stdout'])
            pid = int(marker.read_text())
            self.assertFalse(Path('/proc', str(pid)).exists(), 'detached pipeholder survived owned parent')
            receipt = Path(value['ownership']['receipt_path'])
            self.assertEqual(hashlib.sha256(receipt.read_bytes()).hexdigest(), value['ownership']['receipt_sha256'])


if __name__ == '__main__':
    unittest.main()
