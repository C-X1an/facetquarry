"""Exact selected source with injected operations; no ext4 or Linux claim."""
import ast
import errno
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
from types import SimpleNamespace
import unittest

MODULE = Path(__file__).resolve().parents[1]/'scripts/scientific_lifecycle/scientific_posix_lifecycle.py'
PIN = '8d0b4b4c7d07000cb78ef1b383b47474e4cc5ead0708fac9e45d86e64b159348'
IMAGE, UNIT, AVAILABLE = 268435456, 8192, 229199872
MOUNT = PurePosixPath('/admitted/job')
NAMES = ['successful-quota-reservation.scratch', 'enospc-probe.retained']


class InjectedFilesystem:
    O_RDONLY, O_RDWR, O_CREAT, O_EXCL, O_NOFOLLOW, O_CLOEXEC = 0, 2, 64, 128, 256, 512

    def __init__(self, test, outcome):
        self.test = test
        self.outcome = outcome
        self.available = AVAILABLE
        self.files = {}
        self.trace = []
        self.records = {}

    def open(self, name, flags, mode=0o777, *, dir_fd):
        if flags == self.O_RDONLY | self.O_NOFOLLOW | self.O_CLOEXEC:
            self.test.assertEqual((mode,dir_fd),(0o777,10))
            fd = 11 + NAMES.index(name)
            self.test.assertIn(fd,self.files)
            return fd
        self.test.assertEqual((flags, mode, dir_fd), (962, 0o600, 10))
        fd = 11 + len(self.files)
        self.test.assertEqual(name, NAMES[fd - 11])
        self.files[fd] = SimpleNamespace(st_dev=77, st_ino=fd + 88, st_mode=stat.S_IFREG | 0o600,
            st_uid=0, st_gid=0, st_nlink=1, st_size=0, st_blocks=0, st_mtime_ns=1, st_ctime_ns=1)
        self.trace.append(('open',fd))
        return fd

    def fchown(self, fd, uid, gid):
        self.test.assertEqual((uid,gid),(1001,1002))
        self.files[fd].st_uid = uid
        self.files[fd].st_gid = gid

    def fsync(self, fd):
        self.trace.append(('fsync',fd))
        if self.outcome == 'sync-after-release-failed' and fd == 11 and ('truncate',11,0) in self.trace:
            raise OSError(errno.EIO,'synthetic sync failure after release')

    def fstat(self, fd):
        return SimpleNamespace(st_dev=77) if fd == 10 else SimpleNamespace(**vars(self.files[fd]))

    def stat(self, name, *, dir_fd, follow_symlinks):
        self.test.assertEqual((dir_fd,follow_symlinks),(10,False))
        fd = 11 + NAMES.index(name)
        observed = self.fstat(fd)
        if self.outcome == 'wrong-reservation-identity' and fd == 11 and 'quota-attempt-observation.json' in self.records:
            observed.st_ino += 1
        return observed

    def fstatvfs(self, fd):
        self.test.assertEqual(fd,10)
        return SimpleNamespace(f_frsize=4096, f_blocks=57274,
            f_bavail=self.available//4096, f_bfree=self.available//4096+2)

    def posix_fallocate(self, fd, offset, size):
        self.trace.append(('allocate',fd,size))
        if fd == 11:
            self.test.assertEqual((offset,size),(0,AVAILABLE))
            self.test.assertEqual(set(self.files),{11,12})
            allocated = 4096 if self.outcome == 'partial-fill' else AVAILABLE
            self.files[fd].st_size = allocated
            self.files[fd].st_blocks = allocated//512
            self.available -= allocated
            if self.outcome == 'partial-fill':
                raise OSError(errno.ENOSPC,'synthetic fill failure')
            if self.outcome == 'not-full':
                self.available = 4096
            return
        self.test.assertEqual((fd,offset,size,self.available), (12,0,IMAGE+UNIT,0))
        if self.outcome == 'probe-partial':
            self.files[fd].st_size, self.files[fd].st_blocks = 4096,8
        if self.outcome == 'wrong-errno':
            raise OSError(errno.EIO,'synthetic wrong denial')
        if self.outcome == 'no-denial':
            return
        raise OSError(errno.ENOSPC,'synthetic quota denial')

    def ftruncate(self, fd, size):
        self.test.assertEqual((fd,size),(11,0))
        self.test.assertIn('quota-attempt-observation.json',self.records)
        self.trace.append(('truncate',fd,size))
        self.files[fd].st_size = self.files[fd].st_blocks = 0
        self.available = AVAILABLE if self.outcome != 'lost-headroom' else AVAILABLE-4096

    def record(self, path, raw, *, owner, maximum):
        self.test.assertEqual((path.parent,owner,maximum),(MOUNT/'control',1001,8192))
        self.test.assertLessEqual(len(raw),maximum)
        self.test.assertNotIn(path.name,self.records)
        self.trace.append(('record',path.name))
        self.records[path.name] = raw


class FullVolumeControl(unittest.TestCase):
    def candidate(self, outcome):
        raw = MODULE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),PIN)
        tree = ast.parse(raw)
        names = {'need','integer','sha','signature','json_bytes','quota_probe_geometry','quota_probe_file',
                 'quota_probe_state','prepare_quota_on_full_volume','verify_full_volume_quota_for_original22'}
        selected = [node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names]
        self.assertEqual({node.name for node in selected},names)
        fs = InjectedFilesystem(self,outcome)
        resource = SimpleNamespace(RLIMIT_FSIZE=1,RLIMIT_AS=2,
            getrlimit=lambda key:(536870912,536870912) if key==2 else (-1,-1))
        import re
        scope = {'os':fs,'stat':stat,'resource':resource,'errno':errno,'hashlib':hashlib,'json':json,'re':re,
            'time':SimpleNamespace(time=lambda:1794993600), 'IMAGE_BYTES':IMAGE, 'UNIT':UNIT,
            'ON_VOLUME_REQUIRED_BYTES':201326592,'initialize_quota_volume':lambda value,pin:(
                MOUNT,1001,1002,{}, {'filesystem':'ext4'}),
            'owned_dir':lambda path,owner:10, 'create_file':fs.record, 'explicit_path':PurePosixPath,
            'read_owned':lambda path,maximum,owner:fs.records[path.name],
            'json_load':lambda raw,maximum:json.loads(raw),
            'mount_observation':lambda mount,image,uid:{'filesystem':'ext4'},
            'close_owned':lambda *fds:fs.trace.append(('close',*fds)),
            'error_record':lambda error,operation:{'operation':operation,'errno':error.errno}}
        exec(compile(ast.Module(body=selected,type_ignores=[]),str(MODULE),'exec'),scope)
        fs.verify = lambda:scope['verify_full_volume_quota_for_original22'](MOUNT,'a'*64,1001,1002,{})
        stopped = lambda:(outcome == 'interrupt-after-intent' and 'quota-saturation-release-intent.json' in fs.records)
        return fs,lambda:scope['prepare_quota_on_full_volume']({},'a'*64,stop_requested=stopped)

    def test_success_records_raw_zero_probe_before_exact_release(self):
        fs,run = self.candidate('accepted')
        result = run()
        self.assertEqual(result['status'],'FULL_VOLUME_QUOTA_PREPARED_NOT_A_RUN_ADMISSION')
        self.assertEqual(list(fs.records),['quota-saturation-fill.json','quota-attempt-observation.json',
            'quota-saturation-release-intent.json','quota-saturation-release.json','quota-proof.json'])
        observed = json.loads(fs.records['quota-attempt-observation.json'])
        release = json.loads(fs.records['quota-saturation-release.json'])
        proof = json.loads(fs.records['quota-proof.json'])
        self.assertEqual(observed['attempt_error']['errno'],errno.ENOSPC)
        self.assertEqual(observed['probe_before'],observed['probe_after'])
        self.assertEqual(observed['geometry_before']['available_bytes'],0)
        self.assertEqual(observed['geometry_before']['free_bytes'],8192)
        self.assertEqual(release['after']['available_bytes'],AVAILABLE)
        self.assertEqual(proof['format'],'scientific-posix-quota-full-volume-denial-v1')
        self.assertEqual(proof['raw_observation_sha256'],hashlib.sha256(fs.records['quota-attempt-observation.json']).hexdigest())
        self.assertLess(fs.trace.index(('record','quota-attempt-observation.json')),fs.trace.index(('truncate',11,0)))
        self.assertFalse(any(row[0]=='truncate' and row[1]==12 for row in fs.trace))

    def test_failed_fill_or_insufficient_saturation_never_probes_or_reclaims(self):
        for outcome in ('partial-fill','not-full'):
            with self.subTest(outcome=outcome):
                fs,run = self.candidate(outcome)
                with self.assertRaisesRegex(RuntimeError,'SUCCESSFUL_OWNED_RESERVATION'):
                    run()
                self.assertEqual(list(fs.records),['quota-saturation-fill.json'])
                self.assertGreater(fs.files[11].st_size,0)
                self.assertFalse(any(row[0]=='truncate' or row[:2]==('allocate',12) for row in fs.trace))

    def test_rejected_raw_tuples_persist_before_any_reclaim(self):
        for outcome in ('probe-partial','wrong-errno','no-denial'):
            with self.subTest(outcome=outcome):
                fs,run = self.candidate(outcome)
                with self.assertRaisesRegex(RuntimeError,'ACTUAL_ATOMIC_ENOSPC_DENIAL'):
                    run()
                observed = json.loads(fs.records['quota-attempt-observation.json'])
                self.assertEqual(observed['probe_after']['bytes'],fs.files[12].st_size)
                self.assertNotIn('quota-proof.json',fs.records)
                self.assertFalse(any(row[0]=='truncate' for row in fs.trace))

    def test_substituted_reservation_is_never_reclaimed(self):
        fs,run = self.candidate('wrong-reservation-identity')
        with self.assertRaisesRegex(RuntimeError,'EXACT_OWNED_QUOTA_PROBE_FILE'):
            run()
        self.assertIn('quota-attempt-observation.json',fs.records)
        self.assertNotIn('quota-proof.json',fs.records)
        self.assertFalse(any(row[0]=='truncate' for row in fs.trace))

    def test_headroom_loss_records_release_and_refuses_proof(self):
        fs,run = self.candidate('lost-headroom')
        with self.assertRaisesRegex(RuntimeError,'FULL_VOLUME_HEADROOM'):
            run()
        self.assertIn('quota-saturation-release.json',fs.records)
        self.assertNotIn('quota-proof.json',fs.records)
        self.assertEqual(fs.files[12].st_size,0)

    def test_readback_binds_four_documents_and_actual_state_prior_to_controls(self):
        fs,run = self.candidate('accepted')
        run()
        bound = fs.verify()
        self.assertEqual(bound['proof_sha256'],hashlib.sha256(fs.records['quota-proof.json']).hexdigest())
        self.assertEqual(bound['profile'],'zero-caller-available-ext4-v1')
        raw = fs.records['quota-attempt-observation.json']
        fs.records['quota-attempt-observation.json'] = raw+b' '
        with self.assertRaisesRegex(RuntimeError,'FULL_VOLUME_QUOTA_RECORD_PIN_MISMATCH'):
            fs.verify()
        fs.records['quota-attempt-observation.json'] = raw
        fs.available -= 4096
        with self.assertRaisesRegex(RuntimeError,'FULL_VOLUME_QUOTA_LIVE_HEADROOM_CHANGED'):
            fs.verify()

    def test_release_intent_survives_interrupt_or_error_without_success_label(self):
        for outcome in ('interrupt-after-intent','sync-after-release-failed'):
            with self.subTest(outcome=outcome):
                fs,run=self.candidate(outcome)
                with self.assertRaises((RuntimeError,OSError)):
                    run()
                self.assertIn('quota-saturation-release-intent.json',fs.records)
                self.assertNotIn('quota-saturation-release.json',fs.records)
                self.assertNotIn('quota-proof.json',fs.records)
                self.assertEqual(fs.files[12].st_size,0)
                released=any(row[0]=='truncate' for row in fs.trace)
                self.assertEqual(released,outcome=='sync-after-release-failed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
