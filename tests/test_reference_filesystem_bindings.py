"""Finite byte/contract controls; synthetic receipts never qualify a filesystem."""
from contextlib import ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_filesystem_bindings as bindings
import reference_filesystem as fs


class FilesystemBindingTests(unittest.TestCase):
    def context(self):
        return {'source': 'a' * 64, 'commit': 'b' * 40, 'git_status': '',
                'github_run_id': '17', 'github_run_attempt': '2'}

    def test_minimal_context_and_canonical_commands(self):
        context = self.context()
        bindings.context_shape(context)
        for edit in (lambda x: x.update(source='bad'), lambda x: x.update(git_status=' M x'),
                     lambda x: x.update(github_run_id='0'), lambda x: x.update(commit=None),
                     lambda x: x.update(extra='unbound')):
            value = copy.deepcopy(context)
            edit(value)
            with self.assertRaises(ValueError):
                bindings.context_shape(value)
        command = bindings.formatter_command(Path('image'))
        self.assertEqual(command, ['mkfs.ext4', '-F', '-q', '-m', '0', 'image'])
        self.assertEqual(bindings.actual_observation(command),
                         ['timeout', '--signal=TERM', '--kill-after=1s', '9s', *command])
        self.assertEqual(bindings.actual_observation(['sudo', '-n', 'losetup', '--list']),
                         ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=1s', '9s', 'losetup', '--list'])

    def test_live_mount_allows_legitimate_directory_growth_but_rejects_replacement(self):
        original = {'device': 1792, 'inode': 2, 'mode': stat.S_IFDIR | 0o755,
                    'uid': 1001, 'gid': 1001, 'device_major_minor': '7:0', 'nlink': 2, 'size': 4096}
        grown = {**original, 'nlink': 11, 'size': 8192}
        self.assertEqual(bindings.stable_mount(original), bindings.stable_mount(grown))
        for key, value in (('inode', 3), ('device', 1793), ('mode', stat.S_IFDIR | 0o777),
                           ('uid', 1002), ('gid', 1002), ('device_major_minor', '7:1')):
            with self.subTest(key=key):
                self.assertNotEqual(bindings.stable_mount(original), bindings.stable_mount({**grown, key: value}))

    def test_copied_audit_directory_cannot_rebase_canonical_live_root(self):
        root = Path(__file__).resolve().parents[1]
        temporary = root / '.cache' / 'synthetic-runner-temp'
        info = type('Directory', (), {'st_mode': stat.S_IFDIR | 0o700, 'st_uid': 1001})()
        with patch.object(bindings, 'ordinary'), patch.object(bindings, 'workspace', return_value=root), \
             patch.dict(os.environ, {'RUNNER_TEMP': str(temporary)}), \
             patch.object(fs, 'checked', return_value=info), \
             patch.object(os, 'getuid', return_value=1001, create=True):
            canonical = root / '.local' / 'reference-filesystem' / 'outer'
            image, mount = temporary / 'facetquarry-reference.img', temporary / 'facetquarry-reference'
            self.assertEqual(bindings.layout(canonical, image, 2_300_000_000, mount)[1], canonical)
            for directory, other_image, other_mount in (
                    (temporary / 'copied' / '.local' / 'reference-filesystem' / 'outer', image, mount),
                    (canonical, image.with_name('other.img'), mount),
                    (canonical, image, mount.with_name('other-mount'))):
                with self.assertRaisesRegex(ValueError, 'canonical'):
                    bindings.layout(directory, other_image, 2_300_000_000, other_mount)

    def test_current_execution_clean_git_and_both_source_copies_are_checked(self):
        import reference_internal_transport as transport
        context = self.context()
        root = Path(__file__).resolve().parents[1]
        copied = root / '.cache' / 'synthetic-source-copy'
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_SHA': context['commit'],
               'GITHUB_RUN_ID': '17', 'GITHUB_RUN_ATTEMPT': '2'}
        output = '# branch.oid ' + context['commit'] + '\n# branch.head main\n'
        with patch.object(bindings, 'ordinary'), patch.object(bindings, 'workspace', return_value=root), \
             patch.object(bindings, 'ROOT', copied), patch.dict(os.environ, env), \
             patch.object(transport, 'command', return_value={'stdout': output}) as command, \
             patch.object(transport, 'bounded_source_hash', return_value=context['source']) as source:
            bindings.current_context(context)
            self.assertEqual(command.call_count, 2)
            self.assertEqual([call.args[0] for call in source.call_args_list], [root, copied])
            command.return_value = {'stdout': output + '1 .M N... 100644 100644 100644 a b changed.py\n'}
            with self.assertRaisesRegex(ValueError, 'clean'):
                bindings.current_context(context)
            command.return_value = {'stdout': output}
            source.return_value = 'c' * 64
            with self.assertRaisesRegex(ValueError, 'source'):
                bindings.current_context(context)
            with patch.dict(os.environ, {'GITHUB_RUN_ATTEMPT': '3'}):
                with self.assertRaisesRegex(ValueError, 'execution'):
                    bindings.current_context(context)

    def byte_fixture(self, directory):
        requested = ['synthetic-command']
        actual = bindings.actual_observation(requested)
        stdout, stderr, receipt = (directory / name for name in ('out', 'err', 'receipt.json'))
        stdout.write_bytes(b'finite synthetic stdout\n')
        stderr.write_bytes(b'finite synthetic stderr\n')
        captures = {key: {'path': str(path), 'bytes': path.stat().st_size,
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                    for key, path in (('stdout', stdout), ('stderr', stderr))}
        value = {'status': 'PASS', 'worker_started': True, 'worker_exit_code': 0,
                 'worker_identity': {'pid': 123, 'ppid': 122, 'start_time_ticks': 9},
                 'termination_reason': None, 'errors': [],
                 'descendant_quiescence': {'quiescent': True, 'residual': []},
                 'capture_complete': True, 'discarded_output_bytes': 0, 'capture': captures,
                 'captured_output_bytes': sum(x['bytes'] for x in captures.values()),
                 'requested_command': requested, 'actual_command': actual}
        receipt.write_text(json.dumps(value), encoding='utf-8')
        return value, receipt, stdout, stderr, requested, actual

    def portable_file_checks(self, folder):
        # Real bounded byte reads, with only POSIX metadata made portable on
        # Windows. No live context, filesystem geometry or authenticity claim.
        stack = ExitStack()
        info = folder.stat()
        stack.enter_context(patch.object(os, 'getuid', return_value=info.st_uid, create=True))
        stack.enter_context(patch.object(os, 'getgid', return_value=info.st_gid, create=True))
        if not hasattr(os, 'O_NOFOLLOW'):
            stack.enter_context(patch.object(os, 'O_NOFOLLOW', 0, create=True))
        stack.enter_context(patch.object(fs, 'identity', side_effect=lambda st: {
            'device': st.st_dev, 'inode': st.st_ino, 'mode': st.st_mode, 'uid': st.st_uid,
            'gid': st.st_gid, 'nlink': st.st_nlink, 'size': st.st_size}))
        if os.name == 'nt':
            # Windows lstat/fstat expose different creation/change timestamps.
            # Normalize only this synthetic fixture's stamp; Linux production
            # still compares the full identity, mtime and ctime on every read.
            stack.enter_context(patch.object(bindings, 'stamp', side_effect=lambda st: (
                fs.identity(st), st.st_mtime_ns)))
            actual_checked = fs.checked
            def checked(path):
                st = actual_checked(path)
                return SimpleNamespace(**{key: getattr(st, key) for key in (
                    'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                    'st_size', 'st_mtime_ns', 'st_ctime_ns')},
                    st_blocks=(st.st_size + 4095) // 4096 * 8)
            stack.enter_context(patch.object(fs, 'checked', side_effect=checked))
        return stack

    def temporary_folder(self):
        cache = Path(__file__).resolve().parents[1] / '.cache' / 'tmp'
        cache.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(prefix='filesystem-binding-', dir=cache)

    def test_actual_bytes_of_synthetic_receipt_fail_closed_on_later_changes(self):
        with self.temporary_folder() as folder:
            folder = Path(folder)
            value, receipt, stdout, stderr, requested, actual = self.byte_fixture(folder)
            with self.portable_file_checks(folder):
                # Only this low-level integrity routine accepts the synthetic
                # local receipt. It cannot authorize validate()'s live context.
                _, digest, streams = bindings.verify_receipt(receipt, stdout, stderr, requested, actual)
                self.assertEqual(streams['stdout'], 'finite synthetic stdout\n')
                self.assertEqual(digest, hashlib.sha256(receipt.read_bytes()).hexdigest())
                stdout.write_bytes(b'changed synthetic bytes\n')
                with self.assertRaisesRegex(ValueError, 'capture'):
                    bindings.verify_receipt(receipt, stdout, stderr, requested, actual)
                stdout.unlink()
                with self.assertRaises(FileNotFoundError):
                    bindings.verify_receipt(receipt, stdout, stderr, requested, actual)

    def test_receipt_unknown_quiescence_truncation_argv_and_reference_hash_rejected(self):
        with self.temporary_folder() as folder:
            folder = Path(folder)
            original, receipt, stdout, stderr, requested, actual = self.byte_fixture(folder)
            with self.portable_file_checks(folder):
                for edit in (
                        lambda x: x.update(descendant_quiescence={'quiescent': False, 'residual': None}),
                        lambda x: x.update(capture_complete=False), lambda x: x.update(discarded_output_bytes=1),
                        lambda x: x.update(worker_exit_code=124), lambda x: x.update(errors=['cleanup failed']),
                        lambda x: x['actual_command'].append('unbound'),
                        lambda x: x['requested_command'].append('unbound'),
                        lambda x: x['capture']['stderr'].update(path=str(stdout)),
                        lambda x: x['worker_identity'].update(start_time_ticks=0)):
                    value = copy.deepcopy(original)
                    edit(value)
                    receipt.write_text(json.dumps(value), encoding='utf-8')
                    with self.assertRaises(ValueError):
                        bindings.verify_receipt(receipt, stdout, stderr, requested, actual)
                receipt.write_text(json.dumps(original), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'SHA'):
                    bindings.verify_receipt(receipt, stdout, stderr, requested, actual, expected_sha='0' * 64)

    def test_json_duplicate_keys_and_oversized_files_fail_before_validation(self):
        with self.temporary_folder() as folder:
            folder = Path(folder)
            path = folder / 'receipt.json'
            with self.portable_file_checks(folder):
                path.write_bytes(b'{"status":"PASS","status":"FAIL"}')
                with self.assertRaisesRegex(ValueError, 'duplicate'):
                    bindings.read_json(path)
                path.write_bytes(b'x' * (fs.MAX_PROOF + 1))
                with self.assertRaisesRegex(ValueError, 'bounded'):
                    bindings.read_json(path)

    def test_live_validator_has_no_fixture_fallback_for_missing_formatter_files(self):
        root = Path(__file__).resolve().parents[1]
        context = self.context()
        with self.temporary_folder() as folder:
            folder = Path(folder)
            image, mount = folder / 'image', folder / 'mount'
            with patch.object(bindings, 'layout', return_value=(root, folder, image, mount)), \
                 patch.object(bindings, 'current_context'), patch.object(bindings, 'envelope', return_value={}), \
                 patch.object(os.path, 'ismount', return_value=True):
                with self.assertRaises(FileNotFoundError):
                    bindings.validate(folder, image, mount, 2_300_000_000, context)

    def lifecycle_fixture(self, folder):
        """Real finite receipt files, with synthetic POSIX image/mount metadata.

        Neither this fixture nor the byte controls measure geometry or quota.
        The production validator and every canonical receipt read remain active.
        """
        from test_reference_filesystem import FilesystemPolicyTests
        root = Path(__file__).resolve().parents[1]
        directory = folder / 'audits' / 'nested'
        directory.mkdir(parents=True)
        image, mount = folder / 'image', folder / 'mount'
        image.write_bytes(b'finite synthetic image inode')
        mount.mkdir()
        proof, _, _, size, context = FilesystemPolicyTests().fixture(1_100_000_000)
        stamp = proof['started_at']
        proof.update(image_path=str(image), mount_point=str(mount),
                     formatter_command=bindings.formatter_command(image))
        original_image = {**proof['image_before'], 'inode': image.stat().st_ino}
        proof.update(image_before=original_image, image_after=dict(original_image))
        mount_identity = {**proof['mount_before'], 'inode': mount.stat().st_ino}
        proof.update(mount_before=mount_identity, mount_after=dict(mount_identity))
        context_path = directory / 'context.json'
        context_path.write_text(json.dumps(context), encoding='utf-8')

        def receipt(prefix, requested, stdout='', stderr='', actual=None, extra=None):
            prefix.parent.mkdir(parents=True, exist_ok=True)
            paths = {label: prefix.with_suffix('.' + label) for label in ('stdout', 'stderr')}
            for label, raw in (('stdout', stdout), ('stderr', stderr)):
                paths[label].write_bytes(raw.encode())
            captures = {label: {'path': str(path), 'bytes': path.stat().st_size,
                               'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                        for label, path in paths.items()}
            value = {'status': 'PASS', 'worker_started': True, 'worker_exit_code': 0,
                     'worker_identity': {'pid': 123, 'ppid': 122, 'start_time_ticks': 9},
                     'termination_reason': None, 'errors': [],
                     'descendant_quiescence': {'quiescent': True, 'residual': []},
                     'capture_complete': True, 'discarded_output_bytes': 0, 'capture': captures,
                     'captured_output_bytes': sum(x['bytes'] for x in captures.values()),
                     'requested_command': requested,
                     'actual_command': actual or bindings.actual_observation(requested), **(extra or {})}
            path = prefix.with_suffix('.json')
            path.write_text(json.dumps(value), encoding='utf-8')
            ownership = {key: value[key] for key in ('descendant_quiescence', 'capture_complete',
                                                    'discarded_output_bytes', 'capture')}
            ownership.update(receipt_path=str(path), receipt_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            return ownership

        for index, name in enumerate(('version', 'superblock', 'mount', 'loop')):
            item = proof['observations'][name]
            if name == 'superblock':
                item['command'] = ['dumpe2fs', '-h', str(image)]
            elif name == 'mount':
                item['command'][3] = str(mount)
                data = json.loads(item['stdout'])
                data['filesystems'][0]['target'] = str(mount)
                item['stdout'] = json.dumps(data)
            elif name == 'loop':
                item['command'][6] = str(image)
                data = json.loads(item['stdout'])
                data['loopdevices'][0].update({'back-file': str(image), 'back-ino': original_image['inode']})
                item['stdout'] = json.dumps(data)
            for label in ('stdout', 'stderr'):
                item[label + '_sha256'] = hashlib.sha256(item[label].encode()).hexdigest()
            item['ownership'] = receipt(directory / 'observations' / str(index), item['command'],
                                        item['stdout'], item['stderr'])
        format_command = bindings.formatter_command(image)
        format_item = {'command': format_command, 'exit_code': 0, 'started_at': stamp, 'ended_at': stamp,
                       'stdout': '', 'stderr': '', 'stdout_sha256': hashlib.sha256(b'').hexdigest(),
                       'stderr_sha256': hashlib.sha256(b'').hexdigest(),
                       'ownership': receipt(directory / 'formatter-audit' / '0', format_command)}
        formatter = {'kind': bindings.KIND, 'status': 'PASS', 'run_context': context,
                     'descendant_quiescence': {'quiescent': True, 'residual': []},
                     'directory': str(directory), 'image_path': str(image), 'image_bytes': size,
                     'image_before': original_image, 'image_after': dict(original_image),
                     'observation': format_item, 'started_at': stamp, 'ended_at': stamp}
        (directory / 'formatter.json').write_text(json.dumps(formatter), encoding='utf-8')
        FilesystemPolicyTests().seal(proof)
        proof_path = directory / 'proof.json'
        proof_path.write_text(json.dumps(proof), encoding='utf-8')
        requested = bindings.collector_command(root, image, mount, size, context_path, directory)
        actual = ['timeout', '--signal=TERM', '--kill-after=2s', '80s', *requested]
        receipt(directory / 'collector-supervisor', requested, actual=actual, extra={
            'kind': bindings.KIND, 'scope': 'process-supervision-only', 'run_context': context,
            'image_path': str(image), 'mount_point': str(mount), 'image_bytes': size,
            'directory': str(directory), 'context_path': str(context_path), 'started_at': stamp,
            'ended_at': stamp, 'duration_seconds': 1, 'total_seconds': bindings.PARENT_SECONDS,
            'entry_seconds': bindings.ENTRY_SECONDS, 'cleanup_seconds': 6, 'receipt_seconds': 2,
            'proof_file_sha256': hashlib.sha256(proof_path.read_bytes()).hexdigest()})
        return root, directory, image, mount, size, context, original_image, mount_identity

    def lifecycle_checks(self, fixture, mounted):
        root, directory, image, mount, size, context, image_info, mount_info = fixture
        stack = self.portable_file_checks(directory)
        stack.enter_context(patch.object(bindings, 'layout', return_value=(root, directory, image, mount)))
        stack.enter_context(patch.object(bindings, 'current_context'))
        # Use the actual inode on each observation, with only finite synthetic
        # device/size metadata standing in for an admitted Linux image.
        stack.enter_context(patch.object(bindings, 'image_identity', side_effect=lambda path, _: {
            **image_info, 'inode': path.stat().st_ino}))
        stack.enter_context(patch.object(fs, 'mount_identity', return_value=mount_info))
        stack.enter_context(patch.object(os.path, 'ismount', return_value=mounted))
        return stack

    def test_audit_growth_preserves_summary_but_changed_inode_or_bytes_do_not(self):
        with self.temporary_folder() as folder:
            folder = Path(folder)
            fixture = self.lifecycle_fixture(folder)
            _, directory, image, mount, size, context, *_ = fixture
            with self.lifecycle_checks(fixture, True):
                original = bindings.validate(directory, image, mount, size, context)
                allocation = bindings.envelope(directory.parent)
                (directory.parent / 'legitimate-outer-audit.json').write_bytes(b'finite audit growth')
                self.assertGreater(bindings.envelope(directory.parent)['entries'], allocation['entries'])
                self.assertEqual(bindings.validate(directory, image, mount, size, context), original)
                self.assertNotIn('audit_allocation', original)
                renamed = folder / 'original-image'
                image.rename(renamed)
                image.write_bytes(b'another finite inode')
                with self.assertRaisesRegex(ValueError, 'image/context binding'):
                    bindings.validate(directory, image, mount, size, context)
                image.unlink()
                renamed.rename(image)
                self.assertEqual(bindings.validate(directory, image, mount, size, context), original)
                stream = directory / 'observations/0.stderr'
                stream.write_bytes(b'changed canonical observation bytes')
                with self.assertRaisesRegex(ValueError, 'capture'):
                    bindings.validate(directory, image, mount, size, context)

    def test_retained_summary_equal_and_nested_receipt_deletion_rejected_in_both_states(self):
        import reference_internal_transport as transport
        for mounted in (True, False):
            with self.subTest(mounted=mounted), self.temporary_folder() as folder:
                fixture = self.lifecycle_fixture(Path(folder))
                _, directory, image, mount, size, context, *_ = fixture
                with self.lifecycle_checks(fixture, True):
                    original = bindings.validate(directory, image, mount, size, context)
                canonical = {'filesystem_policy': fs.POLICY, 'filesystem_proof': original}
                owned = {'image': image, 'mount': mount}
                with self.lifecycle_checks(fixture, mounted), patch.dict(os.environ, {
                        'FQ_FILESYSTEM_POLICY': fs.POLICY, 'GITHUB_WORKSPACE': str(fixture[0])}):
                    validator = bindings.validate if mounted else bindings.validate_retained
                    self.assertEqual(validator(directory, image, mount, size, context), original)
                    transport.validate_nested_filesystem(owned, canonical, context, live_mount=mounted)
                    (directory / 'observations/2.json').unlink()
                    with self.assertRaises(FileNotFoundError):
                        transport.validate_nested_filesystem(owned, canonical, context, live_mount=mounted)

    def test_wrong_live_or_retained_mount_state_and_growth_envelope_fail_closed(self):
        with self.temporary_folder() as folder:
            fixture = self.lifecycle_fixture(Path(folder))
            _, directory, image, mount, size, context, *_ = fixture
            for mounted, validator in ((True, bindings.validate_retained), (False, bindings.validate)):
                with self.lifecycle_checks(fixture, mounted):
                    with self.assertRaisesRegex(ValueError, 'mount state'):
                        validator(directory, image, mount, size, context)
            with self.lifecycle_checks(fixture, False):
                extra = directory.parent / 'oversized-audit'
                extra.write_bytes(b'x' * (bindings.ENVELOPE_BYTES + 1))
                with self.assertRaisesRegex(ValueError, '20MB envelope'):
                    bindings.validate_retained(directory, image, mount, size, context)
                extra.unlink()
                for index in range(128):
                    (directory.parent / ('extra-' + str(index))).write_bytes(b'')
                with self.assertRaisesRegex(ValueError, 'entry bound'):
                    bindings.validate_retained(directory, image, mount, size, context)


if __name__ == '__main__':
    unittest.main()
