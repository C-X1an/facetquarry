"""Validate a local filesystem floor separately from the global 2GB reserve."""
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
from reference_artifacts import growth_plan


def require(value, message):
    if not value: raise ValueError(message)


def validate_documents(volume, image_bytes, mount, loops, quota, planned, context, enospc, expected_baseline):
    image = volume.with_name(volume.name + '.img')
    require(image_bytes == 2_300_000_000 and quota.get('volume_file_bytes') == image_bytes
            and quota.get('oversized_allocation_bytes') == 2_400_000_000
            and quota.get('oversized_allocation') == 'DENIED_ENOSPC'
            and quota.get('hard_quota_enforced') is True
            and quota.get('enospc_sha256') == hashlib.sha256(enospc).hexdigest()
            and b'No space left on device' in enospc, 'actual local quota refusal proof differs')
    require(quota.get('run_context') == context and not context.get('git_status')
            and quota.get('volume_path') == str(volume) and quota.get('image_path') == str(image)
            and quota.get('mount') == mount and mount.get('target') == str(volume)
            and mount.get('fstype') == 'ext4'
            and re.fullmatch('/dev/loop[0-9]+', str(mount.get('source', ''))),
            'filesystem floor belongs to another run or mount')
    devices = loops.get('loopdevices', [])
    require(len(devices) == 1 and devices[0].get('name') == mount['source']
            and devices[0].get('back-file') == str(image), 'filesystem floor backing differs')
    require(planned.get('baseline_includes_global_reserve') == expected_baseline,
            'global reservation baseline differs from current accounted input')
    expected = growth_plan(expected_baseline, image_bytes)
    require(planned == expected and expected['admission'] == 'ALLOW',
            'global reserve or worst-case branch proof differs')
    return {'global_reserved_growth_bytes': 2_000_000_000,
            'filesystem_free_floor_bytes': 500_000_000,
            'global_peak_bytes': expected['peak_bytes'], 'run_context': context,
            'scope': '500MB free inside the fixed owned image; the global 2GB reserve remains in the separately admitted baseline.'}


def bounded_json(path):
    no_links(path); require(path.stat().st_size <= 1_000_000, 'reservation proof exceeds admission')
    return json.loads(path.read_text())


def verify(root, global_reserve, filesystem_floor):
    require(sys.platform == 'linux' and os.getuid() != 0, 'local floor override requires ordinary Linux runner')
    require(global_reserve == 2_000_000_000 and filesystem_floor == 500_000_000,
            'unsupported reserve override')
    volume = Path(os.environ['RUNNER_TEMP']) / 'facetquarry-reference'
    require(root == volume and os.environ.get('FQ_WORKSPACE_ROOT') == str(volume),
            'floor override requires exact owned volume root')
    for path in (volume, ROOT, volume / 'source'): no_links(path)
    require(ROOT.is_relative_to(volume) and ROOT.lstat().st_dev == volume.lstat().st_dev
            and source_hash(ROOT) == source_hash(volume / 'source'),
            'current source/clean clone is outside the same admitted image')
    image = volume.with_name(volume.name + '.img'); no_links(image); before = image.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid(),
            'floor override image identity differs')
    def command(argv):
        result = subprocess.run(argv, capture_output=True, text=True, check=True, timeout=10)
        require(len(result.stdout) + len(result.stderr) <= 32768, 'reservation query output exceeds admission')
        return result.stdout.strip()
    context = {'commit': command(['git','-C',str(volume / 'source'),'rev-parse','HEAD']),
               'git_status': command(['git','-C',str(volume / 'source'),'status','--porcelain']),
               'github_run_id': os.environ['GITHUB_RUN_ID'],
               'github_run_attempt': os.environ['GITHUB_RUN_ATTEMPT']}
    require(context['commit'] == os.environ['GITHUB_SHA'], 'floor override commit differs')
    require(command(['git','-C',str(ROOT),'rev-parse','HEAD']) == context['commit']
            and command(['git','-C',str(ROOT),'status','--porcelain']) == '',
            'current source/clean clone revision differs')
    mount = json.loads(command(['findmnt','--json','--target',str(volume),'-o','TARGET,FSTYPE,SOURCE']))['filesystems'][0]
    loops = json.loads(command(['sudo','-n','losetup','--json','--list','--associated',str(image),'--output','NAME,BACK-FILE']))
    local = volume / 'source/.local'
    quota = bounded_json(local / 'reference-quota.json')
    planned = bounded_json(local / 'reference-admission.json')
    enospc_path = local / 'enospc.stderr'; no_links(enospc_path)
    require(enospc_path.stat().st_size <= 32768, 'quota stderr exceeds producer bound')
    result = validate_documents(volume, before.st_size, mount, loops, quota, planned, context,
                                enospc_path.read_bytes(), int(os.environ['FQ_ACCOUNTED_BASE_BYTES']))
    after = image.lstat()
    require((before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_nlink,before.st_size)
            == (after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_nlink,after.st_size),
            'quota backing identity changed during observation')
    return result
