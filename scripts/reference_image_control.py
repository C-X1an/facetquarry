"""Actual nonqualifying frozen-image round trip, with no second image allocation."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from common import source_hash
import evidence_bundle as bundle
import reference_results as results

MAX_CONTROL_PROOF = 800_000
MAX_CONTROL_MEMBERS = 3000


def require(value, message):
    if not value: raise ValueError(message)


def member_manifest(project):
    entries = bundle.inventory(project, ['.local'])
    require(len(entries) <= MAX_CONTROL_MEMBERS, 'image control member bound exceeded')
    records = []
    for entry in entries:
        name, signature, size = entry
        records.append({'path': name, 'directory': name.endswith('/'), 'bytes': size,
            'mode': stat.S_IMODE(signature[2]),
            'sha256': None if name.endswith('/') else hashlib.sha256(bundle.read_original(project, entry)).hexdigest()})
    require(len(json.dumps(records, sort_keys=True, separators=(',', ':')).encode()) < MAX_CONTROL_PROOF - 32768,
            'image control complete manifest exceeds admission')
    return records


def same_members(project, expected):
    actual = member_manifest(project)
    require(actual == expected, 'read-only recovered membership, bytes or modes differ')
    return {'members': len(actual), 'original_bytes': sum(item['bytes'] for item in actual),
            'manifest_sha256': hashlib.sha256(json.dumps(actual, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}


def control_paths(volume, project):
    require(sys.platform == 'linux' and os.getuid() != 0, 'requires ordinary Linux reference runner')
    require(os.environ.get('FQ_PRESERVATION_CONTROL') == 'true'
            and os.environ.get('FQ_BENCH_PROFILE') == 'smoke', 'image recovery control requires explicit nonqualifying smoke')
    return results.owned_paths(Path(volume), Path(project))


def prepare(volume, project):
    paths = control_paths(volume, project)
    proof = paths['volume'] / 'reference-results-control-before.json'
    record = {'status': 'PREPARING', 'evidence_type': 'image_control_original_manifest',
              'source': source_hash(paths['project']), 'commands': [], 'started_at': results.utc(),
              'scope': 'Nonqualifying smoke originals before freezing; no cloud transfer or release qualification.'}
    results.save(proof, record, initial=True); runner = results.Commands(record, proof)
    try:
        setup = results.read_json(paths['proof'])
        require(setup.get('status') == 'PASS' and setup.get('source') == record['source'], 'image control setup differs')
        record['run_context'] = results.run_context(paths['project'], runner)
        require(record['run_context'] == setup['run_context'], 'image control run differs')
        require(results.observe_binding(paths['mount'], paths['image'], runner) == setup['nested_binding'],
                'image control backing differs')
        record['inactive_guest'] = results.assert_no_active_guest(paths['volume'], paths['project'], setup, runner)
        record['manifest'] = member_manifest(paths['project'])
        record.update(same_members(paths['project'], record['manifest']))
        require(source_hash(paths['project']) == record['source'], 'image control source changed')
        record['status'] = 'PASS'
    except BaseException as error:
        record.update(status='FAIL', error=(type(error).__name__ + ': ' + str(error))[:1000]); raise
    finally:
        record['ended_at'] = results.utc(); results.save(proof, record)
    return record


def recover(volume, project, *, profile=''):
    paths = control_paths(volume, project)
    before_path = paths['volume'] / 'reference-results-control-before.json'
    before = results.read_json(before_path)
    if profile == 'reference-inside-outer-v1':
        from reference_internal_transport import verified_frozen_candidate
        frozen = verified_frozen_candidate(paths['volume'], paths['project'])
    else:
        frozen = results.read_json(paths['freeze'])
    proof = paths['volume'] / 'reference-results-control-recovery.json'
    record = {'status': 'PREPARING', 'evidence_type': 'actual_readonly_image_recovery',
              'source': source_hash(paths['project']), 'commands': [], 'started_at': results.utc(),
              'complete_before_proof_sha256': results.file_sha(before_path),
              'scope': 'Same exact frozen image remounted read-only with no second image allocation; cloud download/recovery remains a separate check.'}
    results.save(proof, record, initial=True); runner = results.Commands(record, proof)
    mounted = attempted = body_ok = False
    try:
        setup = results.read_json(paths['proof'])
        record['run_context'] = results.run_context(paths['project'], runner)
        require(before.get('status') == frozen.get('status') == setup.get('status') == 'PASS'
                and before.get('source') == frozen.get('source') == setup.get('source') == record['source']
                and before.get('run_context') == frozen.get('run_context') == setup.get('run_context') == record['run_context'],
                'image recovery execution differs')
        require(frozen.get('image_unmounted') is True and not os.path.ismount(paths['mount'])
                and results.fixed_identity(paths['image']) == setup['image_identity'], 'image not frozen exactly')
        require(results.observe_binding(paths['volume'], paths['outer_image'], runner) == setup['outer']['binding'],
                'recovery outer image differs')
        digest = results.image_sha(paths['image'], setup['image_identity'])
        require(digest == frozen['image_sha256'], 'frozen image changed before read-only recovery')
        attempted = True
        runner(['sudo','-n','mount','-o','loop,ro,noload,nodev,nosuid',str(paths['image']),str(paths['mount'])],timeout=60)
        mounted = True
        binding = results.observe_binding(paths['mount'], paths['image'], runner)
        observed = runner(['findmnt','--json','--target',str(paths['mount']),'-o','TARGET,FSTYPE,SOURCE,OPTIONS'])
        mount = json.loads(observed['stdout'])['filesystems'][0]
        options = set(mount.get('options', '').split(','))
        require(mount.get('target') == str(paths['mount']) and mount.get('source') == binding['mount']['source']
                and 'ro' in options and 'rw' not in options and bool({'noload','norecovery'} & options),
                'actual recovered mount is not read-only without journal replay')
        record['readonly_mount'] = mount
        record.update(same_members(paths['project'], before['manifest']))
        require(record['manifest_sha256'] == before['manifest_sha256'], 'recovered original manifest differs')
        record['all_original_bytes_modes_and_membership_equal'] = True
        require(source_hash(paths['project']) == record['source']
                and results.file_sha(before_path) == record['complete_before_proof_sha256'],
                'recovery source or complete original proof changed')
        body_ok = True
    except BaseException as error:
        body_ok = False
        record.update(status='FAIL', error=(type(error).__name__ + ': ' + str(error))[:1000]); raise
    finally:
        try:
            if attempted and (mounted or os.path.ismount(paths['mount'])):
                # A timed-out mount may have completed. Positively bind this
                # exact child before any unmount, including exceptional paths.
                results.observe_binding(paths['mount'], paths['image'], runner)
                runner(['sudo','-n','umount','--',str(paths['mount'])],timeout=60)
            if attempted:
                loops = runner(['sudo','-n','losetup','--json','--list','--associated',str(paths['image']),'--output','NAME,BACK-FILE'])
                require(not os.path.ismount(paths['mount']) and json.loads(loops['stdout']).get('loopdevices') == [],
                        'read-only recovery image remains mounted')
                digest = results.image_sha(paths['image'], setup['image_identity'])
                require(digest == frozen['image_sha256'], 'read-only recovery altered exact frozen image bytes')
                record.update(image_sha256=digest, image_unmounted=True)
                if body_ok and record.get('all_original_bytes_modes_and_membership_equal'):
                    record['status'] = 'PASS'
        except BaseException as error:
            record.update(status='FAIL', cleanup_error=(type(error).__name__ + ': ' + str(error))[:1000]); raise
        finally:
            record['ended_at'] = results.utc(); results.save(proof, record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare','recover'))
    parser.add_argument('--volume',type=Path,required=True); parser.add_argument('--project',type=Path,required=True)
    args = parser.parse_args()
    record = prepare(args.volume, args.project) if args.action == 'prepare' else recover(
        args.volume, args.project, profile=os.environ.get('FQ_RESERVATION_PROFILE', ''))
    print(json.dumps({key:record.get(key) for key in ('status','members','original_bytes','manifest_sha256','image_sha256','scope')}))
    return 0


if __name__ == '__main__': raise SystemExit(main())
