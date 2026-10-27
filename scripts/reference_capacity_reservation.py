"""Capacity-only floor proof; the full-reference reservation remains separate.

This profile permits unchanged supported verification in its own fixed image.
It supplies no admission for the scientific matrix, packaging or a guest.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from common import ROOT, source_hash
from evidence_bundle import no_links
from reference_capacity import PROFILE, IMAGE_BYTES, PROBE_BYTES, context, growth_plan
from reference_reservation import bounded_json, require


def validate_documents(volume, image_bytes, mount, loops, quota, planned, ctx,
                       enospc, expected_baseline):
    image = volume.with_name(volume.name + '.img')
    require(volume.name == 'facetquarry-capacity' and quota.get('profile') == PROFILE
            and ctx.get('profile') == PROFILE and ctx.get('job') == 'reference_capacity'
            and ctx.get('repository') == 'C-X1an/facetquarry'
            and ctx.get('repository_id') == 1430604581,
            'capacity reservation belongs to another profile or job')
    require(image_bytes == IMAGE_BYTES and quota.get('volume_file_bytes') == IMAGE_BYTES
            and quota.get('oversized_allocation_bytes') == PROBE_BYTES
            and quota.get('oversized_allocation') == 'DENIED_ENOSPC'
            and quota.get('hard_quota_enforced') is True
            and quota.get('enospc_sha256') == hashlib.sha256(enospc).hexdigest()
            and b'No space left on device' in enospc,
            'actual capacity quota refusal proof differs')
    require(quota.get('run_context') == ctx and not ctx.get('git_status')
            and quota.get('volume_path') == str(volume) and quota.get('image_path') == str(image)
            and quota.get('mount') == mount and mount.get('target') == str(volume)
            and mount.get('fstype') == 'ext4'
            and re.fullmatch('/dev/loop[0-9]+', str(mount.get('source', ''))),
            'capacity floor belongs to another run or mount')
    devices = loops.get('loopdevices', [])
    require(len(devices) == 1 and devices[0].get('name') == mount['source']
            and devices[0].get('back-file') == str(image), 'capacity backing differs')
    expected = {**growth_plan(expected_baseline), 'run_context': ctx}
    require(planned == expected and expected['admission'] == 'ALLOW'
            and expected['data_upload_allowed'] is False,
            'capacity-only global reservation differs or is refused')
    return {'profile': PROFILE, 'global_reserved_growth_bytes': 2_000_000_000,
            'filesystem_free_floor_bytes': 500_000_000,
            'global_peak_bytes': expected['peak_bytes'], 'run_context': ctx,
            'scope': 'Supported verification capacity only. Fixed2GB image and500MB localfloor; global2GBreserve stays in the separately admitted baseline. No scientific-workload admission.'}


def validate_source_location(volume, project):
    for path in (volume, project, volume / 'source'): no_links(path)
    require(project.is_relative_to(volume) and project.lstat().st_dev == volume.lstat().st_dev
            and source_hash(project) == source_hash(volume / 'source'),
            'capacity source/clean clone is outside the same admitted image')


def verify(root, global_reserve, filesystem_floor):
    require(sys.platform == 'linux' and os.getuid() != 0,
            'capacity floor requires ordinary Linux runner')
    require(global_reserve == 2_000_000_000 and filesystem_floor == 500_000_000
            and os.environ.get('FQ_RESERVATION_PROFILE') == PROFILE,
            'unsupported capacity reserve override')
    volume = Path(os.environ['RUNNER_TEMP']) / 'facetquarry-capacity'
    require(root == volume and os.environ.get('FQ_WORKSPACE_ROOT') == str(volume),
            'capacity floor requires the exact owned volume root')
    validate_source_location(volume, ROOT)
    image = volume.with_name(volume.name + '.img'); no_links(image); before = image.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
            and before.st_size == IMAGE_BYTES, 'capacity image identity differs')

    def command(argv):
        result = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=10)
        require(len(result.stdout) + len(result.stderr) <= 32768,
                'capacity reservation query exceeds admission')
        return result.stdout.strip()

    ctx = context(volume / 'source')
    require(command(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']) == ctx['commit']
            and command(['git', '-C', str(ROOT), 'status', '--porcelain']) == '',
            'capacity clean clone revision differs')
    mount = json.loads(command(['findmnt', '--json', '--target', str(volume),
                                '-o', 'TARGET,FSTYPE,SOURCE']))['filesystems'][0]
    loops = json.loads(command(['sudo', '-n', 'losetup', '--json', '--list', '--associated',
                                str(image), '--output', 'NAME,BACK-FILE']))
    local = volume / 'source/.local'
    quota = bounded_json(local / 'capacity-quota.json')
    planned = bounded_json(local / 'capacity-admission.json')
    enospc_path = local / 'capacity-enospc.stderr'; no_links(enospc_path)
    require(enospc_path.stat().st_size <= 32768, 'capacity stderr exceeds producer bound')
    stable = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size]
    require(quota.get('backing_identity') == stable(before),
            'capacity quota backing changed since the actual refusal')
    result = validate_documents(volume, before.st_size, mount, loops, quota, planned, ctx,
                                enospc_path.read_bytes(), int(os.environ['FQ_ACCOUNTED_BASE_BYTES']))
    require(stable(before) == stable(image.lstat()), 'capacity backing changed during observation')
    return result
