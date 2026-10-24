"""Remove only an owned loop image after verifying its external evidence bundle.

Call from the original checkout. Every .local member must match the complete,
verified lossless bundle before the measured filesystem can be unmounted.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import time
import uuid

from common import ROOT, source_hash
import evidence_bundle


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def verify_live_members(source, manifest):
    require(manifest['selected_paths'] == ['.local'], 'bundle does not select the complete result directory')
    expected = {r['path']: r for r in manifest['members']}
    seen = set()
    stack = [source / '.local']
    while stack:
        path = stack.pop()
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode)
                and not getattr(info, 'st_file_attributes', 0) & 0x400, 'live result contains a link')
        name = path.relative_to(source).as_posix() + ('/' if stat.S_ISDIR(info.st_mode) else '')
        require(name in expected and name not in seen, 'live result missing or duplicated in bundle')
        seen.add(name)
        entry = expected[name]
        if stat.S_ISDIR(info.st_mode):
            require(entry['directory'] is True, 'bundle directory type differs')
            stack.extend(path.iterdir())
        else:
            require(stat.S_ISREG(info.st_mode) and entry['directory'] is False,
                    'live result is not a regular file')
            require(info.st_size == entry['original_bytes'] and digest(path) == entry['original_sha256'],
                    'live result bytes differ from verified bundle')
    require(seen == set(expected), 'bundle/live result membership differs')
    return len(seen)


def verify_fuzz(source, manifest):
    """Prove the workflow preserved every live generated fuzz member."""
    expected = {r['path']: r for r in manifest['files']}
    require(len(expected) == len(manifest['files']), 'duplicate fuzz preservation entry')
    seen = set()
    total = 0
    for label, root in [('cache', source / '.cache/go-build/fuzz'),
                        ('engine-testdata', source / 'internal/engine/testdata/fuzz')]:
        if not root.exists():
            continue
        evidence_bundle.no_links(root)
        for path in root.rglob('*'):
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode)
                    and not getattr(info, 'st_file_attributes', 0) & 0x400, 'linked fuzz data')
            if stat.S_ISDIR(info.st_mode):
                continue
            require(stat.S_ISREG(info.st_mode), 'nonregular fuzz data')
            name = label + '/' + path.relative_to(root).as_posix()
            require(name in expected and name not in seen, 'live fuzz member was not preserved')
            entry = expected[name]
            preserved = source / '.local/reference-fuzz' / name
            require(info.st_size == entry['bytes'] <= 64 * 1024 * 1024
                    and digest(path) == entry['sha256'] == digest(preserved),
                    'fuzz preservation bytes differ')
            seen.add(name)
            total += info.st_size
            require(len(seen) <= 5000 and total <= 100_000_000, 'fuzz preservation admission exceeded')
    require(seen == set(expected), 'preserved/live fuzz membership differs')
    return len(seen)


def verify_metadata(root, source, manifest):
    members = {r['path']: r for r in manifest['members'] if not r['directory']}
    index = json.loads((root / '.local/reference-metadata-manifest.json').read_text())
    seen = set()
    for entry in index['files']:
        name = entry['member']
        require(name in members and name not in seen, 'curated metadata membership differs')
        seen.add(name)
        path = root / entry['path']
        require(path.resolve().is_relative_to(root / '.local/reference-metadata'),
                'curated metadata escapes its owned directory')
        evidence_bundle.no_links(path)
        expected = members[name]
        require(path.is_file() and path.stat().st_size == entry['bytes'] == expected['original_bytes']
                and digest(path) == entry['sha256'] == expected['original_sha256'],
                'curated metadata differs from complete bundle')
    require(len(seen) > 0, 'no execution metadata was exported')
    return len(seen)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volume', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    require(platform.system() == 'Linux' and os.getuid() != 0, 'requires ordinary Linux runner user')
    parent = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    volume = args.volume.resolve(strict=True)
    image = Path(os.environ['FQ_IMAGE']).resolve(strict=True)
    bundle = args.bundle.resolve(strict=True)
    require(volume.parent == parent and volume.name == 'facetquarry-reference'
            and image == parent / 'facetquarry-reference.img', 'unexpected owned image/volume paths')
    require(not args.volume.is_symlink() and not Path(os.environ['FQ_IMAGE']).is_symlink()
            and image.is_file() and image.stat().st_uid == os.getuid()
            and image.stat().st_size == 3_300_000_000, 'owned image identity differs')
    require(not ROOT.is_relative_to(volume) and not Path.cwd().resolve().is_relative_to(volume),
            'retention must run outside the measured volume')
    require(bundle == ROOT / '.local/reference-transport/reference-members.tar.xz'
            and not args.bundle.is_symlink() and not bundle.is_relative_to(volume),
            'verified evidence must be outside the measured image')
    output = ROOT / '.local/reference-retention.json'
    require(not output.exists(), 'retention observation already exists')
    record = {'schema_version': 1, 'evidence_type': 'reference_retention', 'status': 'PREPARING',
              'source': source_hash(), 'github_run_id': os.environ['GITHUB_RUN_ID'],
              'github_run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'commit': os.environ['GITHUB_SHA'],
              'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'volume_path': str(volume), 'image_path': str(image), 'initial_image_bytes': image.stat().st_size,
              'bundle_path': str(bundle), 'bundle_sha256': digest(bundle), 'commands': []}
    initial_image = image.stat()

    def save():
        output.write_text(json.dumps(record, indent=2) + '\n')

    def run(command, accepted=(0,)):
        unit = None
        actual = command
        item = {'command': command, 'timeout_seconds': 30}
        if command[:2] == ['sudo', '-n']:
            unit = 'facetquarry-retention-' + uuid.uuid4().hex
            actual = ['sudo', '-n', 'systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                      '--unit=' + unit, '--property=RuntimeMaxSec=30', '--property=TimeoutStopSec=5',
                      '--property=KillMode=control-group', '--', *command[2:]]
            item.update(actual_command=actual, transient_unit=unit)
        record['commands'].append(item)
        proc = subprocess.Popen(actual, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True)
        stdout = stderr = ''
        try:
            stdout, stderr = proc.communicate(timeout=36)
        finally:
            if proc.poll() is None:
                if unit:
                    stopped = subprocess.run(['sudo', '-n', 'systemctl', 'stop', unit], capture_output=True, timeout=10)
                    item['scoped_stop_exit_code'] = stopped.returncode
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
                stdout, stderr = proc.communicate(timeout=5)
            item.update(exit_code=proc.returncode, stdout=stdout, stderr=stderr)
            save()
        require(len(stdout) + len(stderr) <= 1_000_000 and proc.returncode in accepted,
                'retention command failed or exceeded its output admission')
        return stdout

    try:
        save()
        verified = evidence_bundle.verify(bundle)
        with bundle.open('rb') as stream:
            raw = evidence_bundle.transport_item(evidence_bundle.XZReader(stream), 'manifest.json', evidence_bundle.MAX_MANIFEST)
        manifest = json.loads(raw)
        require(verified['commit'] == record['commit'] and verified['run_id'] == record['github_run_id']
                and verified['source'] == record['source'] == source_hash(volume / 'source'),
                'external bundle execution identity differs')
        require(digest(bundle) == record['bundle_sha256'], 'external bundle changed during verification')
        record['manifest_sha256'] = hashlib.sha256(raw).hexdigest()
        record['verified_member_count'] = verify_live_members(volume / 'source', manifest)
        record['verified_metadata_count'] = verify_metadata(ROOT, volume / 'source', manifest)
        fuzz = json.loads((volume / 'source/.local/reference-fuzz/manifest.json').read_text())
        record['verified_fuzz_count'] = verify_fuzz(volume / 'source', fuzz)
        mount = json.loads(run(['findmnt', '--json', '--target', str(volume), '-o', 'TARGET,FSTYPE,SOURCE']))['filesystems'][0]
        require(mount['target'] == str(volume) and mount['fstype'] == 'ext4'
                and mount['source'].startswith('/dev/loop'), 'actual owned mount differs')
        loops = json.loads(run(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                               '--output', 'NAME,BACK-FILE']))['loopdevices']
        require(len(loops) == 1 and loops[0]['name'] == mount['source']
                and Path(loops[0]['back-file']).resolve(strict=True) == image,
                'loop device does not back the exact owned image')
        record.update(mount=mount, loop_identity=loops[0])
        guest = volume / 'reference-guest'
        if guest.exists():
            setup_path = guest / 'setup.json'
            copied_setup = volume / 'source/.local/reference-guest-setup/setup.json'
            require(setup_path.is_file() and copied_setup.is_file()
                    and digest(setup_path) == digest(copied_setup),
                    'guest setup exists without identical preserved unit diagnostics')
            setup = json.loads(setup_path.read_text())
            for item in setup.get('commands', []):
                unit = item.get('transient_unit')
                if not unit:
                    continue
                require(re.fullmatch('facetquarry-owned-[0-9a-f]{32}', unit), 'unexpected guest unit identity')
                status = run(['systemctl', 'show', '--no-pager', '--property=LoadState', '--property=ActiveState', unit], accepted=(0, 1))
                properties = dict(line.split('=', 1) for line in status.splitlines() if '=' in line)
                require(properties.get('LoadState') == 'not-found' or properties.get('ActiveState') in ('inactive', 'failed'),
                        'guest privileged unit is still active')
        # Repeat the complete live comparison immediately before unmounting.
        verify_live_members(volume / 'source', manifest)
        save()
        run(['sudo', '-n', 'umount', '--', str(volume)])
        remaining = json.loads(run(['sudo', '-n', 'losetup', '--json', '--list', '--associated', str(image),
                                    '--output', 'NAME,BACK-FILE']))['loopdevices']
        require(remaining == [] and not os.path.ismount(volume), 'image is still mounted or associated')
        require(image.resolve() == parent / 'facetquarry-reference.img'
                and not image.is_symlink()
                and (image.stat().st_dev, image.stat().st_ino, image.stat().st_uid)
                == (initial_image.st_dev, initial_image.st_ino, initial_image.st_uid)
                and image.stat().st_size == record['initial_image_bytes']
                and digest(bundle) == record['bundle_sha256'], 'owned image or external evidence changed before removal')
        image.unlink()
        record.update(status='PASS', image_removed=True, retained_bundle_bytes=bundle.stat().st_size,
                      scope='Every completed .local member is preserved byte-for-byte in the verified external bundle; only the owned ephemeral image was removed.')
    except BaseException as error:
        record.update(status='FAIL', error=type(error).__name__ + ': ' + str(error), image_removed=not image.exists())
        raise
    finally:
        record['ended_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
        print(json.dumps({key: record.get(key) for key in ('status', 'image_removed', 'retained_bundle_bytes', 'verified_member_count', 'error')}))
    return 0


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise SystemExit('signal ' + str(signum))
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    raise SystemExit(main())
