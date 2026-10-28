"""Export bounded diagnostics and admit independent reference artifact branches.

These observations never qualify a benchmark. Metadata can survive a refused
scientific artifact; a partial package is never an upload candidate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from common import ROOT, source_hash
import evidence_bundle as bundle
import reference_artifacts as artifacts

COPY_BYTES = 30_000_000
COPY_FILES = 2500
# The final<=1MB receipt is created after the allocation observation. Reserve
# its padded allocation from the existing50MB overhead, including refusals.
UPLOAD_RECEIPT_ALLOCATION = 1_100_000
FLAT_FOLDERS = ('files', 'outer', 'reference-guest-setup', 'host-diagnostics')
NAMES = ('evidence', 'reference-execution.json', 'reference-guest-result.json',
         'reference-benchmark-start.json', 'reference-quota.json', 'reference-guest-setup',
         'reference-analysis', 'clean-verify', 'test-failures', 'toolchain-download.json',
         'govulncheck-build.txt', 'reference-inventory.json', 'enospc.stderr',
         'reference-preflight-relocation.json', 'reference-fuzz/manifest.json',
         'reference-progress.json', 'reference-results-setup.json')


def require(value, message):
    if not value: raise ValueError(message)


def record_json(path, value):
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(len(raw) <= 1_000_000, 'pipeline receipt exceeds admission')
    bundle.no_links(path.parent)
    with path.open('xb') as stream: stream.write(raw)


def copy_one(path, target, budget, *, max_bytes=None):
    bundle.no_links(path); info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe diagnostic source')
    limit = COPY_BYTES if max_bytes is None else min(COPY_BYTES, max_bytes)
    require(info.st_size <= limit, 'diagnostic source exceeds complete-copy admission')
    if 'root' in budget:
        require(target.parent in {budget['root'], *(budget['root'] / name for name in FLAT_FOLDERS)},
                'diagnostic export must use fixed flat directories')
    ancestor = target.parent
    while not ancestor.exists(): ancestor = ancestor.parent
    bundle.no_links(ancestor)
    existed = os.path.lexists(target)
    if not existed:
        require(budget['files'] < COPY_FILES and budget['bytes'] + info.st_size <= COPY_BYTES,
                'complete diagnostic copy exceeds cumulative admission; originals are not declared preserved')
    data, digest = artifacts.read_metadata(path, info, info.st_size)
    target.parent.mkdir(parents=True, exist_ok=True); bundle.no_links(target.parent)
    if existed:
        bundle.no_links(target)
        require(target.is_file() and target.stat().st_size == info.st_size
                and bundle.file_sha(target) == digest, 'existing diagnostic copy differs')
    else:
        with target.open('xb') as stream: stream.write(data)
    require(bundle.file_sha(target) == digest, 'diagnostic copy digest differs')
    if not existed:
        budget['files'] += 1; budget['bytes'] += info.st_size
    return {'bytes': info.st_size, 'sha256': digest}


def copy_budget(output):
    budget = {'files': 0, 'bytes': 0, 'root': output}
    if not output.exists(): return budget
    bundle.no_links(output)
    for child in output.iterdir():
        bundle.no_links(child)
        if child.is_dir():
            require(child.name in FLAT_FOLDERS, 'unexpected external diagnostic directory')
            for entry in child.iterdir():
                bundle.no_links(entry)
                require(entry.is_file(), 'external diagnostic export must remain flat')
    for path, info in artifacts.metadata_files(output):
        require(info.st_nlink == 1, 'hardlinked diagnostic copy refused')
        budget['files'] += 1; budget['bytes'] += info.st_size
        require(budget['files'] <= COPY_FILES and budget['bytes'] <= COPY_BYTES,
                'existing cumulative diagnostic copies exceed admission')
    return budget


def diagnostics(volume, root=ROOT):
    """Copy host diagnostics externally first; child ENOSPC never loses them."""
    local = root / '.local'; local.mkdir(exist_ok=True)
    source = volume / 'reference-guest'
    result = {'status': 'PREPARING', 'files': [], 'errors': [],
              'scope': 'Available actual host guest diagnostics; no workload success or raw preservation claim.'}
    try:
        budget = copy_budget(local / 'reference-metadata')
        if source.exists():
            bundle.no_links(source)
            selections = sorted((p for p in source.iterdir() if p.name == 'commands'
                                or p.suffix in ('.json', '.log', '.txt')),
                                key=lambda path: (path.name != 'setup.json', path.name))
            for selected in selections:
                for path, info in artifacts.metadata_files(selected):
                    relative = path.relative_to(source)
                    target = local / 'reference-metadata' / (
                        'reference-guest-setup/setup.json' if relative.as_posix() == 'setup.json'
                        else 'host-diagnostics/' + hashlib.sha256(relative.as_posix().encode()).hexdigest()[:32] + '.bin')
                    item = {**copy_one(path, target, budget), 'path': str(relative)}
                    result['files'].append(item)
                    child = volume / 'source/.local/reference-guest-setup' / relative
                    if not result['errors']:
                        try: copy_one(path, child, {'files': 0, 'bytes': 0})
                        except (OSError, ValueError) as error:
                            result['errors'].append((type(error).__name__ + ': ' + str(error))[:1000])
        result['status'] = 'FAIL' if result['errors'] else 'PASS'
    except (OSError, ValueError) as error:
        result['status'] = 'FAIL'
        result['errors'].append((type(error).__name__ + ': ' + str(error))[:1000])
    finally: record_json(local / 'reference-diagnostics.json', result)
    return result


def export_metadata(volume, root=ROOT):
    local = root / '.local'; local.mkdir(exist_ok=True)
    source = volume / 'source'; output = local / 'reference-metadata'
    output.mkdir(exist_ok=True)
    result = {'status': 'PREPARING', 'files': [], 'outer_files': [],
              'scope': 'Complete selected convenience copies only. Full scientific preservation requires the separately verified complete bundle or frozen results image.'}
    try:
        budget = copy_budget(output)
        for name in NAMES:
            selected = source / '.local' / name
            if not os.path.lexists(selected): continue
            for path, info in artifacts.metadata_files(selected):
                relative = path.relative_to(source / '.local')
                target = output / ('reference-guest-setup/setup.json'
                    if relative.as_posix() == 'reference-guest-setup/setup.json'
                    else 'files/' + hashlib.sha256(relative.as_posix().encode()).hexdigest()[:32] + '.bin')
                result['files'].append({**copy_one(path, target, budget),
                    'member': path.relative_to(source).as_posix(),
                    'path': target.relative_to(root).as_posix()})
        for name in ('reference-results-setup.json', 'reference-guest-quiescence.json',
                     'reference-results-rescue.json'):
            path = volume / name
            if path.exists():
                target = output / 'outer' / name
                result['outer_files'].append({**copy_one(path, target, budget),
                    'source': str(path), 'path': target.relative_to(root).as_posix()})
        trim = source / '.local/reference-preflight-trim.json'
        if not trim.is_file(): trim = volume / 'reference-results-bootstrap/reference-preflight-trim.json'
        if trim.is_file():
            bundle.no_links(trim)
            require(trim.stat().st_size <= 8_000_000, 'trim proof exceeds admitted producer bound')
            value = json.loads(trim.read_text())
            record_json(local / 'reference-trim-summary.json', {
                'status': value.get('status'), 'source': value.get('source'),
                'complete_proof_bytes': trim.stat().st_size, 'complete_proof_sha256': bundle.file_sha(trim),
                'removed_entries': len(value.get('removal_manifest', {}).get('entries', [])),
                'removed_accounted_bytes': value.get('removal_manifest', {}).get('accounted_bytes'),
                'scope': 'Summary only; full trim manifest remains in results/bootstrap and requires separately retained scientific evidence.'})
        result.update(status='PASS', selected_bytes=budget['bytes'], selected_files=budget['files'])
    except (OSError, ValueError, RuntimeError) as error:
        result.update(status='FAIL', error=(type(error).__name__ + ': ' + str(error))[:1000])
    finally: record_json(local / 'reference-metadata-manifest.json', result)
    return result


def external_inventory(local):
    """Actual external originals, including an unsafe-to-delete partial package."""
    total, files, stack, entries = 0, 0, [local], 0
    while stack:
        path = stack.pop(); bundle.no_links(path); info = path.lstat(); entries += 1
        require(entries <= 10_000, 'external entry inventory bound exceeded')
        if stat.S_ISDIR(info.st_mode):
            total += getattr(info, 'st_blocks', 0) * 512
            with os.scandir(path) as children:
                for child in children:
                    require(len(stack) + entries < 10_000, 'external entry inventory bound exceeded')
                    stack.append(path / child.name)
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe external original')
            total += max(info.st_size, getattr(info, 'st_blocks', 0) * 512); files += 1
        require(total <= 15_000_000_000,
                'external allocation inventory exceeds bounded global contract')
    return total, files


def admission(base, image_bytes, external_bytes, selected_zip, *, profile=''):
    if profile == 'reference-inside-outer-v1':
        from reference_internal_transport import growth_plan
        plan = growth_plan(base)
        require(artifacts.OVERHEAD >= UPLOAD_RECEIPT_ALLOCATION,
                'upload receipt has no independent overhead reservation')
        require(type(image_bytes) is int and 0 <= image_bytes <= 2_300_000_000
                and type(external_bytes) is int and external_bytes >= 0
                and type(selected_zip) is int and 0 <= selected_zip <= artifacts.IMAGE_ZIP,
                'invalid internal upload allocation observation')
        metadata_peak = base + image_bytes + external_bytes + artifacts.PACKET_ALLOCATION + artifacts.METADATA_ZIP + artifacts.OVERHEAD
        data_peak = metadata_peak + selected_zip
        external_ok = external_bytes <= artifacts.EXTERNAL_METADATA_ALLOCATION
        return {'profile': profile, 'metadata_allowed': external_ok and metadata_peak < artifacts.CEILING,
                'data_allowed': external_ok and image_bytes == 2_300_000_000 and selected_zip > 0
                    and plan['admission'] == 'ALLOW' and data_peak <= plan['peak_bytes'] < artifacts.CEILING,
                'initial_scientific_admission': plan['admission'],
                'metadata_peak_bytes': metadata_peak, 'scientific_peak_bytes': data_peak,
                'selected_zip_upper_bound_bytes': selected_zip, 'external_original_bytes': external_bytes,
                'upload_receipt_reserved_bytes': UPLOAD_RECEIPT_ALLOCATION,
                'remaining_overhead_reserved_bytes': artifacts.OVERHEAD - UPLOAD_RECEIPT_ALLOCATION,
                'upload_receipt_reservation_source': 'Existing50MB overhead; not an extra allocation outside the plan.',
                'outer_image_retained_through_upload': True,
                'scope': 'Separately admitted internal transport; one verified bundle or exact unmounted results image. Package bytes remain inside the retained outer allocation.'}
    require(profile == '', 'unknown reference upload reservation profile')
    plan = artifacts.growth_plan(base, 2_300_000_000)
    require(type(image_bytes) is int and 0 <= image_bytes <= 15_000_000_000, 'invalid actual retained image size')
    require(0 <= external_bytes <= 15_000_000_000, 'invalid actual external original allocation')
    require(0 <= selected_zip <= artifacts.IMAGE_ZIP, 'scientific ZIP bound exceeds reserved branch')
    # Packet and its cloud ZIP are independent of scientific artifact admission.
    metadata_peak = base + image_bytes + external_bytes + artifacts.PACKET_ALLOCATION + artifacts.METADATA_ZIP + artifacts.OVERHEAD
    data_peak = metadata_peak + selected_zip
    return {'metadata_allowed': metadata_peak < artifacts.CEILING,
            'data_allowed': plan['admission'] == 'ALLOW' and image_bytes <= 2_300_000_000
                and external_bytes <= artifacts.PACKAGE_ALLOCATION + artifacts.EXTERNAL_METADATA_ALLOCATION
                and selected_zip > 0 and data_peak < artifacts.CEILING,
            'initial_scientific_admission': plan['admission'],
            'metadata_peak_bytes': metadata_peak, 'scientific_peak_bytes': data_peak,
            'selected_zip_upper_bound_bytes': selected_zip, 'external_original_bytes': external_bytes,
            'scope': 'Independent diagnostic admission; exactly one scientific artifact branch may be uploaded.'}


def assert_image_unmounted(volume, image):
    child = volume / 'source/.local'
    bundle.no_links(child); bundle.no_links(image)
    require(not os.path.ismount(child), 'results image is still mounted after freeze/recovery')
    result = subprocess.run(['sudo','-n','losetup','--json','--list','--associated',str(image),
                             '--output','NAME,BACK-FILE'],capture_output=True,text=True,timeout=10)
    require(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= 32768,
            'current image association could not be observed')
    observed = json.loads(result.stdout)
    require(observed.get('loopdevices') == [], 'results image still has a current loop association')
    return {'child_is_mountpoint': False, 'loopdevices': [], 'scope': 'Actual current observation after every recovery step.'}


def admit_uploads(volume, package_ok, root=ROOT, *, profile=''):
    local = root / '.local'; local.mkdir(exist_ok=True)
    result = {'status': 'FAIL', 'metadata_allowed': False, 'data_allowed': False,
              'kind': 'NONE', 'path': '', 'source': source_hash(root)}
    try:
        image = volume.with_name(volume.name + '.img')
        image_bytes = 0
        if os.path.lexists(image):
            bundle.no_links(image); info = image.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(), 'unsafe outer image')
            image_bytes = info.st_size
        selected, bound = '', 0
        package = local / 'reference-transport/reference-members.tar.xz'
        if profile == 'reference-inside-outer-v1':
            from reference_upload_candidate import evaluate
            evaluated = evaluate(volume, package_ok, root=root)
            result['candidate_evaluation'] = evaluated
            require(evaluated.get('status') == 'PASS'
                    and evaluated.get('descendant_quiescence', {}).get('quiescent') is True,
                    'scientific candidate evaluation failed or exceeded its bounded deadline')
            candidate = evaluated['candidate']
            require(candidate.get('source') == result['source'], 'candidate source differs from admission source')
            if package_ok:
                package = volume / 'reference-transport/reference-members.tar.xz'
                require(candidate.get('status') == 'PASS' and candidate.get('selected_path') == str(package)
                        and candidate.get('outer_image_retained_through_upload') is True,
                        'current complete internal verification is required for bundle selection')
                result['kind'], selected = 'BUNDLE', str(package)
                bound = candidate['bundle_bytes'] + 1_000_000
                require(0 < candidate['bundle_bytes'] <= bundle.MAX_OUTPUT,
                        'internal bundle exceeds its admitted size')
                result['internal_verification_sha256'] = candidate['verification_receipt_sha256']
            else:
                selected = str(volume / 'reference-results.img')
                require(candidate.get('status') == 'PASS' and candidate.get('selected_path') == selected
                        and candidate.get('image_unmounted') is True
                        and candidate.get('image_bytes') == artifacts.RESULTS_IMAGE
                        and candidate.get('zip_upper_bound_bytes') == artifacts.IMAGE_ZIP,
                        'current complete reconciled image is required for fallback selection')
                result['kind'], bound = 'IMAGE', artifacts.IMAGE_ZIP
                result['image_sha256'] = candidate['image_sha256']
        elif package_ok:
            attempt = json.loads((package.parent / 'pack-attempt.json').read_text())
            bundle.no_links(package)
            require(attempt.get('status') == 'PASS' and attempt.get('originals_unchanged') is True
                    and attempt.get('source') == result['source']
                    and attempt.get('commit') == os.environ['GITHUB_SHA']
                    and attempt.get('run_id') == os.environ['GITHUB_RUN_ID']
                    and attempt.get('run_attempt') == os.environ['GITHUB_RUN_ATTEMPT']
                    and package.is_file() and package.stat().st_size <= bundle.MAX_OUTPUT,
                    'verified packaging branch identity differs')
            result['kind'], selected = 'BUNDLE', str(package)
            bound = package.stat().st_size + 1_000_000
        else:
            frozen = volume / 'reference-results-freeze.json'
            rescued = volume / 'reference-results-rescue.json'
            if frozen.exists():
                value = json.loads(frozen.read_text())
                require(value.get('status') == 'PASS' and value.get('image_unmounted') is True
                        and value.get('source') == result['source']
                        and value.get('run_context') == {'commit': os.environ['GITHUB_SHA'], 'git_status': '',
                            'github_run_id': os.environ['GITHUB_RUN_ID'],
                            'github_run_attempt': os.environ['GITHUB_RUN_ATTEMPT']}, 'results freeze is not this execution')
                selected = str(volume / 'reference-results.img'); bundle.no_links(Path(selected))
                result['current_image_state'] = assert_image_unmounted(volume, Path(selected))
                info = Path(selected).lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == artifacts.RESULTS_IMAGE,
                        'frozen image has changed')
                require(bundle.file_sha(Path(selected)) == value['image_sha256'], 'frozen image digest differs before upload')
                result['kind'], bound = 'IMAGE', artifacts.IMAGE_ZIP
            elif rescued.exists():
                from reference_results import verify_rescue
                value = verify_rescue(volume, volume / 'source')
                selected = value['selected_path']; bound = value['zip_upper_bound_bytes']
                require(bound <= 350_000_000, 'bootstrap ZIP exceeds reserved subbranch')
                result['kind'] = 'BOOTSTRAP'
        if profile == 'reference-inside-outer-v1':
            from reference_internal_transport import physical_tree
            physical_tree(local)
        external, count = external_inventory(local)
        result.update(admission(int(os.environ['FQ_ACCOUNTED_BASE_BYTES']), image_bytes, external, bound, profile=profile))
        result.update(status='PASS', path=selected, external_files=count)
    except Exception as error:
        # A bad scientific candidate must not suppress independently admitted
        # diagnostics. Re-inventory only bounded external originals.
        result['error'] = (type(error).__name__ + ': ' + str(error))[:1000]
        try:
            if profile == 'reference-inside-outer-v1':
                from reference_internal_transport import physical_tree
                physical_tree(local)
            external, count = external_inventory(local)
            image = volume.with_name(volume.name + '.img')
            image_bytes = image.stat().st_size if image.is_file() else 0
            result.update(admission(int(os.environ['FQ_ACCOUNTED_BASE_BYTES']), image_bytes, external, 0, profile=profile))
        except Exception as secondary:
            result['metadata_error'] = (type(secondary).__name__ + ': ' + str(secondary))[:1000]
    record_json(local / 'reference-upload-admission.json', result)
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as stream:
            for key in ('metadata_allowed', 'data_allowed', 'kind', 'path'):
                value = str(result[key]).lower() if isinstance(result[key], bool) else str(result[key])
                require('\n' not in value and '\r' not in value, 'invalid workflow output')
                stream.write(key + '=' + value + '\n')
    return result


def final_state(volume, root=ROOT, *, profile=''):
    local = root / '.local'; local.mkdir(exist_ok=True)
    image = volume.with_name(volume.name + '.img')
    result = {'status': 'PASS', 'image_exists': image.is_file(),
              'image_bytes': image.stat().st_size if image.is_file() else 0,
              'run_id': os.environ['GITHUB_RUN_ID'], 'commit': os.environ['GITHUB_SHA']}
    early = Path(os.environ['RUNNER_TEMP']) / 'facetquarry-reference-enospc.stderr'
    if os.path.lexists(early):
        bundle.no_links(early); info = early.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size <= artifacts.CAPTURE_BYTES,
                'early ENOSPC diagnostic exceeds producer admission')
        copy_one(early, local / 'reference-enospc.stderr', {'files': 0, 'bytes': 0})
    for name in ('reference-results-control-before.json', 'reference-results-control-recovery.json'):
        path = volume / name
        if path.is_file():
            require(path.stat().st_size <= artifacts.CAPTURE_BYTES, 'complete image control proof exceeds packet producer bound')
            copy_one(path, local / name, {'files': 0, 'bytes': 0})
    for name in ('reference-results-freeze.json', 'reference-results-reconciled-freeze.json', 'reference-guest-quiescence.json',
                 'reference-results-rescue.json'):
        path = volume / name
        if profile == 'reference-inside-outer-v1' and name in (
                'reference-results-freeze.json', 'reference-results-reconciled-freeze.json'):
            if os.path.lexists(path):
                # Supervisor and candidate receipts bind the complete proof SHA.
                # Preserve its exact bytes; a field projection changes that SHA.
                copy_one(path, local / name, {'files': 0, 'bytes': 0},
                         max_bytes=artifacts.CAPTURE_BYTES)
        elif path.is_file():
            value = json.loads(path.read_text())
            record_json(local / name, {key: value.get(key) for key in
                ('status', 'source', 'run_context', 'image_path', 'image_bytes', 'image_sha256',
                 'image_unmounted', 'selected_path', 'zip_upper_bound_bytes', 'scope', 'error')})
    if profile == 'reference-inside-outer-v1':
        trim = local / 'reference-transport/guest-trim.json'
        if os.path.lexists(trim):
            bundle.no_links(trim); info = trim.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 8_000_000,
                    'internal trim proof exceeds admitted producer bound')
            raw, digest = artifacts.read_metadata(trim, info, info.st_size)
            value = json.loads(raw)
            record_json(local / 'reference-internal-trim-summary.json', {
                'status': value.get('status'), 'source': value.get('source'),
                'complete_proof_bytes': info.st_size, 'complete_proof_sha256': digest,
                'removed_entries': len(value.get('removal_manifest', {}).get('entries', [])),
                'removed_accounted_bytes': value.get('removal_manifest', {}).get('accounted_bytes'),
                'scope': 'Summary only. Complete external proof is retained; the full scientific proof and provenance require the separately retained verified bundle or exact results image.'})
    record_json(local / 'reference-job-state.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('diagnostics', 'export', 'state', 'admit'))
    parser.add_argument('--volume', type=Path, required=True)
    parser.add_argument('--package-ok', action='store_true'); args = parser.parse_args()
    actions = {'diagnostics': diagnostics, 'export': export_metadata, 'state': final_state}
    profile = os.environ.get('FQ_RESERVATION_PROFILE', '')
    if args.action == 'admit':
        result = admit_uploads(args.volume, args.package_ok, profile=profile)
    elif args.action == 'state':
        result = final_state(args.volume, profile=profile)
    else:
        result = actions[args.action](args.volume)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
