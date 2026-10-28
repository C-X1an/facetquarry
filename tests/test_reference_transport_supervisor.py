"""Tiny process controls and pure mount-observation fixtures, never quota proof.

Files stay below two MB per fixture under public/.cache/tmp. Native fixtures
mock every mount/loop observation and never call a mount or production deleter.
Linux-only process controls run a fresh dedicated parent with tiny deadlines.
Real ext4 interruption/recovery and upload remain separate hosted gates.
"""
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from common import source_hash
import reference_internal_transport as transport
import reference_transport_supervisor as supervisor


def fixture_context():
    return {'profile': transport.PROFILE, 'job': 'reference',
            'repository': transport.REPOSITORY, 'repository_id': transport.REPOSITORY_ID,
            'source': 'a' * 64, 'commit': 'b' * 40, 'git_status': '',
            'github_run_id': '1234567', 'github_run_attempt': '2'}


def production_startup_fixture(folder):
    """Real production parent/worker handshake, with synthetic identity only."""
    folder = Path(folder)
    volume, outer = folder / 'facetquarry-reference', folder / 'checkout'
    project = volume / 'source'
    (project / '.local').mkdir(parents=True)
    (outer / '.local').mkdir(parents=True)
    (outer / 'scripts').mkdir()
    p = {'volume': volume, 'project': project, 'outer': outer, 'local': outer / '.local',
         'image': folder / 'facetquarry-reference.img', 'data': volume / 'reference-transport',
         'package': volume / 'reference-transport/reference-members.tar.xz',
         'audit': outer / '.local/reference-transport'}
    ctx, published = fixture_context(), folder / 'durably-published'
    paths_literal = repr(json.dumps({key: str(value) for key, value in p.items()}))
    worker = ('import json,sys\nfrom pathlib import Path\n'
              'sys.path.insert(0,' + repr(str(Path(transport.__file__).parent)) + ')\n'
              'import reference_internal_transport as t\nimport reference_transport_supervisor as s\n'
              'p={key:Path(value) for key,value in json.loads(' + paths_literal + ').items()}\n'
              'ctx=' + repr(ctx) + '\n'
              'def fixture_pack(volume,project,root=t.ROOT,control=False):\n'
              ' s.require_active_worker(p,ctx,"pack")\n'
              ' assert Path(' + repr(str(published)) + ').read_bytes()==b"durable"\n'
              ' value={"status":"PASS","source":ctx["source"],"run_context":ctx}\n'
              ' t.write_small(p["audit"]/"pack-result.json",value)\n'
              ' return value\n'
              't.pack=fixture_pack\nraise SystemExit(t.main())\n')
    (outer / 'scripts/reference_internal_transport.py').write_text(worker)
    original_write = transport.write_small
    def delayed_publication(path, record, **kwargs):
        if Path(path) == p['audit'] / 'pack-supervisor.json' and record.get('state') == 'RUNNING':
            time.sleep(.35)  # On-disk parent state remains PREPARING here.
            original_write(path, record, **kwargs)
            with published.open('xb') as stream:
                stream.write(b'durable')
                stream.flush()
                os.fsync(stream.fileno())
        else:
            original_write(path, record, **kwargs)
    with patch.object(transport, 'paths', return_value=p), \
            patch.object(transport, 'context', return_value=ctx), \
            patch.object(transport, 'current_time_admission', return_value={'allowed': True}), \
            patch.object(transport, 'write_small', side_effect=delayed_publication):
        value = supervisor.supervise('pack', volume, project, outer)
    (folder / 'production-startup-result.json').write_text(json.dumps(value))


class PureTransportRepairs(unittest.TestCase):
    def setUp(self):
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='transport-repair-', dir=cache)
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name).absolute()
        self.volume, self.outer = self.folder / 'facetquarry-reference', self.folder / 'checkout'
        self.project = self.volume / 'source'
        (self.project / '.local').mkdir(parents=True)
        (self.outer / '.local').mkdir(parents=True)
        self.p = {'volume': self.volume, 'project': self.project, 'outer': self.outer,
                  'local': self.outer / '.local', 'image': self.folder / 'facetquarry-reference.img',
                  'data': self.volume / 'reference-transport',
                  'package': self.volume / 'reference-transport/reference-members.tar.xz',
                  'audit': self.outer / '.local/reference-transport'}
        self.ctx = fixture_context()

    def test_complete_external_control_boundary_and_separate_refusal_bound(self):
        ceiling, control = transport.artifacts.EXTERNAL_METADATA_ALLOCATION, transport.CONTROL_ALLOCATION
        with patch.object(transport.shutil, 'disk_usage', return_value=SimpleNamespace(free=control)):
            with patch.object(transport, 'physical_tree', return_value={'accounted_bytes': ceiling - control, 'entries': 1}):
                self.assertTrue(transport.external_admission(self.p)['allowed'])
            with patch.object(transport, 'physical_tree', return_value={'accounted_bytes': ceiling - control + 1, 'entries': 1}):
                admitted = transport.external_admission(self.p)
                self.assertFalse(admitted['allowed'])
                self.assertTrue(admitted['refusal_allowed'])
            with patch.object(transport, 'physical_tree', return_value={
                    'accounted_bytes': ceiling - transport.REFUSAL_ALLOCATION + 1, 'entries': 1}):
                admitted = transport.external_admission(self.p)
                self.assertFalse(admitted['allowed'])
                self.assertFalse(admitted['refusal_allowed'])

    def test_external_growth_refuses_before_audit_or_internal_package_mkdir(self):
        ceiling = transport.artifacts.EXTERNAL_METADATA_ALLOCATION
        with patch.object(transport, 'paths', return_value=self.p), \
                patch.object(transport, 'context', return_value=self.ctx), \
                patch.object(transport, 'physical_tree', return_value={
                    'accounted_bytes': ceiling - transport.CONTROL_ALLOCATION + 1, 'entries': 1}), \
                patch.object(transport.shutil, 'disk_usage', return_value=SimpleNamespace(free=100_000_000)), \
                patch.object(transport.artifacts, 'run_pack') as run:
            value = transport.pack(self.volume, self.project, self.outer)
        run.assert_not_called()
        self.assertEqual(value['status'], 'FAIL')
        self.assertFalse(self.p['audit'].exists())
        self.assertFalse(self.p['data'].exists())
        refusal = self.p['local'] / 'reference-transport-pack-refusal.json'
        self.assertLessEqual(refusal.stat().st_size, transport.REFUSAL_BYTES)
        self.assertEqual(json.loads(refusal.read_text())['run_context'], self.ctx)

    def test_explicit_parent_sidecar_reuse_requires_positive_quiescence_and_same_bytes(self):
        self.p['audit'].mkdir()
        self.p['data'].mkdir()
        source = self.p['package'].with_name(self.p['package'].name + '.failure.json')
        source.write_bytes(b'{"status":"FAIL","fixture":true}\n')
        first = transport.copy_failure_sidecar(self.p['package'], self.p['audit'], True)
        with self.assertRaisesRegex(ValueError, 'already exists'):
            transport.copy_failure_sidecar(self.p['package'], self.p['audit'], True)
        with self.assertRaisesRegex(ValueError, 'positive parent descendant quiescence'):
            transport.copy_failure_sidecar(self.p['package'], self.p['audit'], True,
                                           reuse_after_quiescence={'quiescent': False, 'residual': []})
        quiet = {'quiescent': True, 'residual': []}
        reused = transport.copy_failure_sidecar(self.p['package'], self.p['audit'], True,
                                                reuse_after_quiescence=quiet)
        self.assertEqual(first, reused)
        Path(first['audit_path']).write_bytes(b'changed completed copy')
        with self.assertRaisesRegex(ValueError, 'differs'):
            transport.copy_failure_sidecar(self.p['package'], self.p['audit'], True,
                                           reuse_after_quiescence=quiet)

    def test_cumulative_provenance_counts_root_synthesized_parents_and_all_controls(self):
        guest = self.volume / 'reference-guest'
        manifest = {'entries': [{'path': 'reference-guest/apt/log/history.log'}]}
        copied = 4  # Destination root, apt/, apt/log/, history.log.
        boundary = transport.PROVENANCE_ENTRIES - transport.CONTROL_ENTRIES - copied
        admitted = transport.provenance_entry_admission(boundary, manifest, guest)
        self.assertTrue(admitted['allowed'])
        self.assertEqual(admitted['external_provenance_new_entries'], copied)
        self.assertEqual(admitted['maximum_external_entries'], transport.PROVENANCE_ENTRIES)
        self.assertFalse(transport.provenance_entry_admission(boundary + 1, manifest, guest)['allowed'])
        maximum_manifest = {'entries': [{'path': 'reference-guest/' + str(index)}
                                       for index in range(transport.PROVENANCE_ENTRIES)]}
        self.assertFalse(transport.provenance_entry_admission(1, maximum_manifest, guest)['allowed'])
        (self.p['local'] / 'a').mkdir()
        (self.p['local'] / 'a/file').write_bytes(b'tiny')
        observed = transport.physical_tree(self.p['local'], include_entries=True)
        self.assertEqual(observed['entries'], 3)
        self.assertEqual(observed['accounted_bytes'], transport.physical_tree(self.p['local']))

    def test_cumulative_entry_refusal_precedes_any_copy_or_deletion(self):
        manifest = {'entries': [{'path': 'reference-guest/apt/log/history.log'}],
                    'accounted_bytes': 1, 'logical_bytes': 1}
        existing = transport.PROVENANCE_ENTRIES - transport.CONTROL_ENTRIES - 3
        with patch.object(transport.sys, 'platform', 'linux'), \
                patch.object(transport.os, 'getuid', return_value=1001, create=True), \
                patch.object(transport, 'closed_guest'), \
                patch.object(transport, 'guest_selections', return_value=([self.volume / 'payload'], [])), \
                patch.object(transport, 'owned_manifest', side_effect=[{'entries': []}, manifest]), \
                patch.object(transport, 'physical_tree', return_value={'accounted_bytes': 1, 'entries': existing}), \
                patch.object(transport, 'copy_manifest') as copied, \
                patch.object(transport.preflight, 'delete_linux') as deleted:
            with self.assertRaisesRegex(ValueError, 'cumulative external provenance/control entries'):
                transport.trim_guest.__wrapped__(self.p, self.ctx)
        copied.assert_not_called()
        deleted.assert_not_called()

    def test_refusal_itself_does_not_grow_without_its_own_reservation(self):
        admitted = {'allowed': False, 'refusal_allowed': False}
        value = transport.preserve_refusal(self.p, self.ctx, 'pack', admitted, 'fixture refusal')
        self.assertEqual(value['status'], 'FAIL')
        self.assertEqual(list(self.p['local'].iterdir()), [])

    def test_scandir_is_stopped_before_unbounded_materialization(self):
        observed = []
        @contextmanager
        def endless(path):
            def entries():
                for index in range(1_000_000):
                    observed.append(index)
                    yield SimpleNamespace(name=str(index))
            yield entries()
        with patch.object(transport.os, 'scandir', side_effect=endless):
            with self.assertRaisesRegex(ValueError, 'enumeration entry bound'):
                transport.bounded_children(self.volume, transport.EntryBudget(3))
        self.assertEqual(observed, [0, 1, 2, 3])

    def test_cumulative_pending_and_visited_bound_precedes_legacy_tree(self):
        root = self.volume / 'many'
        (root / 'a').mkdir(parents=True)
        (root / 'b').mkdir()
        for index in range(3):
            (root / 'a' / str(index)).write_bytes(b'tiny')
        with patch.object(transport.preflight, 'MAX_ENTRIES', 4), \
                patch.object(transport.preflight, 'tree') as legacy:
            with self.assertRaisesRegex(ValueError, 'enumeration entry bound'):
                transport.owned_manifest(self.volume, [root])
        legacy.assert_not_called()

    def test_bounded_source_digest_preserves_the_common_digest(self):
        (self.project / 'go.mod').write_bytes(b'module fixture\n')
        (self.project / 'sample.go').write_bytes(b'package fixture\n')
        (self.project / '.local/ignored.py').write_bytes(b'not source')
        (self.project / 'examples').mkdir()
        (self.project / 'examples/example.json').write_bytes(b'{"fixture":true}\n')
        self.assertEqual(transport.bounded_source_hash(self.project), source_hash(self.project))

    def test_direct_payload_and_old_pass_cannot_select_bundle(self):
        self.p['audit'].mkdir()
        transport.write_small(self.p['audit'] / 'pack-result.json',
                              {'status': 'PASS', 'source': self.ctx['source'], 'run_context': self.ctx})
        with patch.object(transport, 'paths', return_value=self.p), \
                patch.object(transport, 'context', return_value=self.ctx):
            with self.assertRaises((FileNotFoundError, ValueError)):
                transport.verified_candidate(self.volume, self.project, self.outer)
            with self.assertRaises((FileNotFoundError, ValueError)):
                transport.prior_phase_quiescence(self.p, self.ctx)

    def test_reconciliation_uses_the_already_reserved_failure_tail(self):
        start = 1_800_000_000
        boundary = start + transport.JOB_SECONDS - transport.FAILURE_TAIL_SECONDS
        value = transport.time_admission(start, boundary - 1, 'reconcile')
        self.assertTrue(value['allowed'])
        self.assertEqual(value['phase_seconds'], 180)
        self.assertEqual(value['required_remaining_seconds'], 1200)
        self.assertFalse(transport.time_admission(start, boundary, 'reconcile')['allowed'])

    @contextmanager
    def frozen_fixture(self, *, mounted):
        """Pure 4096-byte fixture: all device/mount observations are synthetic."""
        owned = transport.results.owned_paths(self.volume, self.project)
        owned['image'].write_bytes(b'x' * 4096)
        owned['outer_image'].write_bytes(b'outer fixture')
        owned['bootstrap'].mkdir()
        quota = owned['bootstrap'] / 'reference-quota.json'
        quota.write_bytes(b'{"fixture":true}\n')
        outer_binding = {'mount': {'source': '/dev/loop17'}}
        nested_binding = {'mount': {'source': '/dev/loop18'}}
        canonical = {'status': 'PASS', 'source': self.ctx['source'],
                     'run_context': transport.legacy_context(self.ctx),
                     'paths': {key: str(value) for key, value in owned.items()},
                     'image_bytes': 4096, 'oversized_allocation': 'DENIED_ENOSPC',
                     'image_identity': transport.results.identity(owned['image']),
                     'project_identity': transport.results.identity(self.project)[:5],
                     'mount_identity': transport.results.identity(owned['mount'])[:5],
                     'nested_binding': nested_binding,
                     'outer': {'binding': outer_binding,
                         'image_identity': transport.results.identity(owned['outer_image']),
                         'volume_identity': transport.results.identity(self.volume)[:5],
                         'quota_sha256': transport.file_sha(quota, 1000)}}
        transport.write_small(owned['proof'], canonical)
        reservation = {'profile': transport.PROFILE, 'binding': outer_binding, 'run_context': self.ctx}
        state = {'mounted': mounted, 'unmounts': 0}
        def ismount(path):
            return Path(path) == self.volume or Path(path) == owned['mount'] and state['mounted']
        def command(argv, **kwargs):
            if argv[0] == 'sync':
                return {'exit_code': 0, 'stdout': '', 'stderr': ''}
            if argv[:3] == ['sudo', '-n', 'umount']:
                state['mounted'] = False
                state['unmounts'] += 1
                return {'exit_code': 0, 'stdout': '', 'stderr': ''}
            if argv[0] == 'findmnt':
                return {'exit_code': 0 if state['mounted'] else 1,
                        'stdout': json.dumps({'filesystems': [nested_binding['mount']]}) if state['mounted'] else '',
                        'stderr': ''}
            if argv[:3] == ['sudo', '-n', 'losetup']:
                return {'exit_code': 0, 'stdout': json.dumps({'loopdevices': [{}] if state['mounted'] else []}),
                        'stderr': ''}
            raise AssertionError('unexpected fixture command ' + repr(argv))
        with ExitStack() as stack:
            stack.enter_context(patch.object(transport.artifacts, 'RESULTS_IMAGE', 4096))
            stack.enter_context(patch.object(transport.results, 'IMAGE_BYTES', 4096))
            stack.enter_context(patch.object(transport, 'context', return_value=self.ctx))
            stack.enter_context(patch.object(transport, 'observe_outer', return_value=reservation))
            stack.enter_context(patch.object(transport.os.path, 'ismount', side_effect=ismount))
            stack.enter_context(patch.object(transport, 'command', side_effect=command))
            stack.enter_context(patch.object(transport.results, 'observe_binding', return_value=nested_binding))
            stack.enter_context(patch.object(transport.shutil, 'disk_usage', return_value=SimpleNamespace(
                free=transport.FILESYSTEM_FLOOR + transport.CONTROL_ALLOCATION + 1_000_000)))
            stack.enter_context(patch.object(transport, 'prior_phase_quiescence', return_value={}))
            yield owned, canonical, state

    def test_interrupted_original_freezes_are_preserved_and_separately_reconciled(self):
        # Each interruption has its own tiny fixture; no native mount is used.
        for checkpoint in ('before_unmount', 'after_unmount', 'during_hashing'):
            with self.subTest(checkpoint=checkpoint):
                # Reuse the fixed paths only after removing our own tiny files.
                with self.frozen_fixture(mounted=True) as (owned, canonical, state):
                    def interrupt(name):
                        if name == checkpoint:
                            raise InterruptedError('fixture ' + name)
                    with patch.object(transport, 'freeze_checkpoint', side_effect=interrupt):
                        failed = transport._freeze_into(self.p, self.ctx, owned['freeze'], reconciled=False)
                    self.assertEqual(failed['status'], 'FAIL')
                    original_bytes = owned['freeze'].read_bytes()
                    original_sha = hashlib.sha256(original_bytes).hexdigest()
                    proof = self.volume / 'reference-results-reconciled-freeze.json'
                    recovered = transport._freeze_into(self.p, self.ctx, proof, reconciled=True)
                    self.assertEqual(recovered['status'], 'PASS', recovered.get('error'))
                    self.assertFalse(state['mounted'])
                    self.assertEqual(state['unmounts'], 1)
                    self.assertEqual(owned['freeze'].read_bytes(), original_bytes)
                    self.assertEqual(recovered['original_freeze']['sha256'], original_sha)
                    selected = transport.validate_frozen_proof(self.p, self.ctx, proof)
                    self.assertEqual(selected['image_sha256'], hashlib.sha256(b'x' * 4096).hexdigest())
                    self.assertEqual(selected['run_context'], transport.legacy_context(self.ctx))
                    self.assertEqual(selected['profile_context'], self.ctx)
                    with self.assertRaisesRegex(ValueError, 'blind retry'):
                        transport._freeze_into(self.p, self.ctx, proof, reconciled=True)
                for target in (self.volume / 'reference-results-reconciled-freeze.json',
                               self.volume / 'reference-results-freeze.json',
                               self.volume / 'reference-results-setup.json',
                               self.volume / 'reference-results.img', self.p['image']):
                    target.unlink()
                shutil.rmtree(self.volume / 'reference-results-bootstrap')

    def test_old_pass_is_rehashed_and_original_failure_sha_cannot_be_changed(self):
        with self.frozen_fixture(mounted=True) as (owned, canonical, state):
            original = transport._freeze_into(self.p, self.ctx, owned['freeze'], reconciled=False)
            self.assertEqual(original['status'], 'PASS', original.get('error'))
            transport.validate_frozen_proof(self.p, self.ctx, owned['freeze'])
            recovered_path = self.volume / 'reference-results-reconciled-freeze.json'
            recovered = transport._freeze_into(self.p, self.ctx, recovered_path, reconciled=True)
            self.assertEqual(recovered['status'], 'PASS', recovered.get('error'))
            owned['image'].write_bytes(b'y' * 4096)
            with self.assertRaisesRegex(ValueError, 'SHA or full current binding'):
                transport.validate_frozen_proof(self.p, self.ctx, owned['freeze'])
            owned['image'].write_bytes(b'x' * 4096)
            changed = {**original, 'extra': 'changed original proof'}
            transport.write_small(owned['freeze'], changed, replace=True)
            with self.assertRaisesRegex(ValueError, 'changed'):
                transport.validate_frozen_proof(self.p, self.ctx, recovered_path)

    def test_wrong_nested_binding_refuses_before_unmount(self):
        with self.frozen_fixture(mounted=True) as (owned, canonical, state):
            with patch.object(transport.results, 'observe_binding', return_value={'mount': {'source': '/dev/loop99'}}):
                value = transport._freeze_into(self.p, self.ctx, owned['freeze'], reconciled=False)
            self.assertEqual(value['status'], 'FAIL')
            self.assertTrue(state['mounted'])
            self.assertEqual(state['unmounts'], 0)


@unittest.skipUnless(sys.platform == 'linux', 'real tiny process ownership requires Linux /proc/subreaper')
class TinyLinuxParentControls(unittest.TestCase):
    def test_production_worker_waits_for_delayed_durable_parent_publication(self):
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='transport-startup-', dir=cache)
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name).absolute()
        code = ('import sys; sys.path.insert(0,' + repr(str(Path(__file__).parent)) + '); '
                'from test_reference_transport_supervisor import production_startup_fixture; '
                'production_startup_fixture(' + repr(str(folder)) + ')')
        observed = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=15)
        self.assertEqual(observed.returncode, 0, observed.stderr.decode(errors='replace'))
        value = json.loads((folder / 'production-startup-result.json').read_text())
        self.assertEqual(value['status'], 'PASS', value.get('errors', value.get('error')))
        self.assertTrue(value['startup_gate_released_after_durable_publication'])
        self.assertTrue(value['descendant_quiescence']['quiescent'])
        self.assertEqual(value['descendant_quiescence']['residual'], [])

    def run_fixture(self, body, *, cap=4096):
        cache = Path(__file__).resolve().parents[1] / '.cache/tmp'
        cache.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='transport-process-', dir=cache)
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name).absolute()
        scripts = str(Path(transport.__file__).parent)
        code = ('import json,pathlib,sys,time; sys.path.insert(0,' + repr(scripts) + '); '
                'import reference_transport_supervisor as s; p=pathlib.Path(' + repr(str(folder)) + '); '
                't=time.monotonic(); r=s.run_owned([sys.executable,"-c",' + repr(body) + '],'
                'p/"stdout",p/"stderr",started=t,total_seconds=10,cleanup_seconds=6,'
                'receipt_seconds=1,capture_bytes=' + str(cap) + '); '
                'r["fixture_duration_seconds"]=time.monotonic()-t; '
                '(p/"result.json").write_text(json.dumps(r)); '
                'sys.exit(0 if r["descendant_quiescence"]["quiescent"] else 1)')
        observed = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=15)
        self.assertEqual(observed.returncode, 0, observed.stderr.decode(errors='replace'))
        value = json.loads((folder / 'result.json').read_text())
        self.assertLess(value['fixture_duration_seconds'], 10)
        self.assertTrue(value['descendant_quiescence']['quiescent'])
        self.assertEqual(value['descendant_quiescence']['residual'], [])
        return value, folder

    def test_kill_owns_worker_that_catches_baseexception_and_ignores_term(self):
        body = ('import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                'exec("while True:\\n try: time.sleep(.05)\\n except BaseException: pass")')
        value, _ = self.run_fixture(body)
        self.assertEqual(value['status'], 'FAIL')
        self.assertEqual(value['termination_reason'], 'whole_phase_payload_cutoff')
        self.assertTrue(any(item['signal'] == 9 for item in value['descendant_quiescence']['signals']))

    def test_detached_grandchild_is_adopted_killed_and_reaped(self):
        orphan = 'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)'
        body = ('import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",' + repr(orphan)
                + '],start_new_session=True); time.sleep(.2)')
        value, _ = self.run_fixture(body)
        self.assertTrue(value['descendant_quiescence']['adopted'])
        self.assertTrue(any(item['signal'] == 9 for item in value['descendant_quiescence']['signals']))
        self.assertTrue(value['descendant_quiescence']['reaped'])

    def test_parent_capture_refuses_while_reading_at_its_tiny_limit(self):
        body = 'import os,time; os.write(1,b"x"*65536); time.sleep(60)'
        value, folder = self.run_fixture(body, cap=1024)
        self.assertEqual(value['status'], 'FAIL')
        self.assertEqual(value['termination_reason'], 'output_limit')
        self.assertFalse(value['capture_complete'])
        self.assertEqual(value['captured_output_bytes'], 1024)
        self.assertGreater(value['discarded_output_bytes'], 0)
        self.assertLessEqual((folder / 'stdout').stat().st_size + (folder / 'stderr').stat().st_size, 1024)


if __name__ == '__main__':
    unittest.main()
