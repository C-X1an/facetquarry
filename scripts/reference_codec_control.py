"""Nonqualifying full-size codec control over an immutable historical transport.

Run only in the authorized Actions job. Historical failures remain failures;
this measures packaging, never the current engine or a reference-host gate.
The legacy schema is decoded explicitly, without relabeling its qualification.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from common import ROOT, source_hash
import evidence_bundle as bundle
import reference_artifacts as artifacts
from reference_qualification import check_artifact_zip_directory

REPOSITORY = 'C-X1an/facetquarry'
REPOSITORY_ID = 1430604581
ARTIFACT_ID = 12523238011
TRANSPORT_RUN = 40002295390
TRANSPORT_HEAD = 'aafa1a51a8e33b29c6e2b96561ccbcad0b3cc2a7'
TRANSPORT_NAME = 'reference-transport-40002295390-1'
ZIP_BYTES = 354515159
ZIP_SHA = 'd2a16620d6c479963b0cb91c659dc6e4034ba401b679b3b25f225802ba0931ea'
INNER_NAME = 'results/reference-members.tar.xz'
INNER_BYTES = 354473852
INNER_SHA = '5f70197cd473d2f91f4a5a231c2ed0cffc520533512b38799d85f89f9e958716'
HISTORICAL_SOURCE = '4949a016d1fc650cc80f18583e18b0ed487820801091508ea34b0a6b658a7dfe'
HISTORICAL_COMMIT = '625582eb753e7bec76e057a8f368f62f6aaf3d1d'
HISTORICAL_RUN = 39973710730
HISTORICAL_ARTIFACT = 12519574083
HISTORICAL_ZIP_BYTES = 784433491
HISTORICAL_ZIP_SHA = 'f3de649b5ac186c5514c46d84372fba67af4a1b65c7c44176c7e14286b1b86b8'
HISTORICAL_MEMBERS = 27738
IMAGE_BYTES = 2_000_000_000
ENOSPC_BYTES = 2_100_000_000
PACK_SECONDS = 1800
PACK_PRESET = 6
PACK_DICTIONARY_BYTES = 64 * 1024 * 1024
EXTERNAL_METADATA = 200_000_000
PACKET_BYTES = 50_000_000
CLOUD_METADATA = 45_000_000
OUTPUT_BYTES = 401_000_000
OVERHEAD_BYTES = 50_000_000
CEILING = 12_000_000_000
ROW_BYTES = 900_000
NONQUALIFYING = 'NONQUALIFYING_HISTORICAL_FULL_SIZE_CODEC_CONTROL'
SCOPE = ('Current codec over retained historical full data only. No new engine measurements, '
         'no repaired-source benchmark, no scientific or release qualification. '
         'Historical full5400cells/5400000samples and33/45targetPASS/12FAIL remain historical.')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def context():
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY,
            'codec control requires its authorized same-repository Actions runtime')
    run, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    require(run.isdecimal() and attempt.isdecimal(), 'missing actual Actions run identity')
    commit = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                            capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    require(commit == os.environ.get('GITHUB_SHA') and re.fullmatch('[0-9a-f]{40}', commit),
            'checkout differs from current Actions source')
    return {'repository': REPOSITORY, 'github_run_id': run, 'github_run_attempt': attempt,
            'commit': commit, 'tool_source_sha256': source_hash()}


def paths():
    parent = bundle.no_links(Path(os.environ['RUNNER_TEMP']))
    require(parent.is_dir(), 'runner temporary directory is not regular')
    return {'volume': parent / 'facetquarry-codec-control',
            'image': parent / 'facetquarry-codec-control.img',
            'packet': parent / 'facetquarry-codec-metadata-packet',
            'local': ROOT / '.local',
            'metadata': ROOT / '.local/reference-metadata/codec',
            'output': ROOT / '.local/reference-transport/reference-members.tar.xz'}


def write(path, record, replace=False):
    artifacts.write_json(path, record, replace=replace)


def load(path, limit=bundle.MAX_MANIFEST):
    bundle.no_links(path)
    require(path.is_file() and path.stat().st_size <= limit, 'JSON input exceeds admission')
    return json.loads(path.read_bytes(), object_pairs_hook=bundle.unique_object)


def physical(root, maximum_entries=100_000):
    """Count every directory block and unique regular allocation; reject links."""
    if not os.path.lexists(root):
        return 0
    total, seen, stack, entries = 0, set(), [root], 0
    while stack:
        path = bundle.no_links(stack.pop()); info = path.lstat(); entries += 1
        require(entries <= maximum_entries, 'physical inventory entry bound exceeded')
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
                'physical inventory found unsupported file type')
        identity = info.st_dev, info.st_ino
        if identity not in seen:
            seen.add(identity)
            total += max(info.st_size, getattr(info, 'st_blocks', 0) * 512)
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as children:
                names = [child.name for child in children]
            require(len(names) + len(stack) + entries <= maximum_entries,
                    'physical inventory enumeration exceeds bound')
            stack.extend(path / name for name in names)
    return total


def growth_plan(base):
    require(type(base) is int and base >= 2_000_000_000,
            'fresh accounted baseline must include the global2GBreserve')
    reserved = {'owned_ext4_image': IMAGE_BYTES, 'external_output_and_partial': OUTPUT_BYTES,
                'external_metadata': EXTERNAL_METADATA, 'diagnostic_packet': PACKET_BYTES,
                'cloud_metadata_only': CLOUD_METADATA, 'overhead': OVERHEAD_BYTES}
    branches = {name: sum(reserved.values()) for name in
                ('download_and_recovery', 'packing_and_verification',
                 'failed_pack_with_unsafe_residual', 'metadata_upload_with_retained_image')}
    peak = base + max(branches.values())
    return {'schema_version': 1, 'qualification': NONQUALIFYING, 'scope': SCOPE,
            'baseline_includes_global_reserve': base, 'reservations': reserved,
            'branches': branches, 'maximum_new_stage_bytes': max(branches.values()),
            'peak_bytes': peak, 'ceiling_bytes': CEILING,
            'admission': 'ALLOW' if peak < CEILING else 'REFUSE',
            'data_upload_allowed': False,
            'input_policy': 'Existing authorized cloud transport only; ZIP, legacy bundle and all recovered members stay inside the owned image.'}


def plan():
    ctx, p = context(), paths()
    p['local'].mkdir(exist_ok=True)
    bundle.no_links(p['local'])
    require(all(0 < os.statvfs(path).f_frsize <= 4096 for path in (ROOT, p['image'].parent)),
            'physical reservations require allocation units no larger than4096bytes')
    record = {**growth_plan(int(os.environ['FQ_ACCOUNTED_BASE_BYTES'])), 'run_context': ctx,
              'created_at': stamp()}
    write(p['local'] / 'reference-admission.json', record)
    print(json.dumps(record, sort_keys=True), flush=True)
    require(record['admission'] == 'ALLOW', 'global codec growth admission refused')
    p['metadata'].mkdir(parents=True, exist_ok=True)
    p['output'].parent.mkdir()
    return record


def admitted():
    p = paths(); record = load(p['local'] / 'reference-admission.json')
    require(record['run_context'] == context() and record['admission'] == 'ALLOW'
            and record['qualification'] == NONQUALIFYING
            and record['baseline_includes_global_reserve'] == int(os.environ['FQ_ACCOUNTED_BASE_BYTES'])
            and record['maximum_new_stage_bytes'] == sum(growth_plan(int(os.environ['FQ_ACCOUNTED_BASE_BYTES']))['reservations'].values()),
            'codec admission is stale or does not bind this source/run/baseline')
    return p, record


def command(argv, name, timeout=90, accepted=(0,)):
    """Bound each real helper's streams and persist failures before raising."""
    p = paths(); folder = p['metadata'] / 'commands'; folder.mkdir(exist_ok=True)
    require(re.fullmatch('[a-z0-9-]{1,80}', name) and 1 <= timeout <= 1800,
            'invalid bounded helper identity or deadline')
    out, err, receipt = (folder / (name + suffix) for suffix in ('.stdout.txt', '.stderr.txt', '.json'))
    require(not any(os.path.lexists(path) for path in (out, err, receipt)), 'command state already exists')
    record = {'command': argv, 'started_at': stamp(), 'exit_code': None,
              'termination_actions': [], 'termination_reason': None, 'captured_bytes': 0,
              'discarded_bytes': 0, 'errors': [], 'qualification': NONQUALIFYING}
    tick, event, lock, readers, proc = time.monotonic(), threading.Event(), threading.Lock(), [], None

    def capture(pipe, path):
        try:
            with pipe, path.open('xb') as stream:
                while data := pipe.read(4096):
                    with lock:
                        kept = min(len(data), max(0, artifacts.CAPTURE_BYTES - record['captured_bytes']))
                        stream.write(data[:kept]); stream.flush()
                        record['captured_bytes'] += kept; record['discarded_bytes'] += len(data) - kept
                        if kept != len(data): event.set()
        except BaseException as error:
            record['errors'].append(type(error).__name__); event.set()

    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        for pipe, path in ((proc.stdout, out), (proc.stderr, err)):
            reader = threading.Thread(target=capture, args=(pipe, path), daemon=True)
            readers.append(reader); reader.start()
        while proc.poll() is None:
            if event.is_set() or time.monotonic() - tick >= timeout:
                record['termination_reason'] = 'capture_limit_or_error' if event.is_set() else 'timeout'
                break
            time.sleep(.05)
    except BaseException as error:
        record['errors'].append(type(error).__name__)
    finally:
        if proc is not None:
            stopped = artifacts.terminate_owned(proc, readers, record)
            record['exit_code'] = proc.poll()
        else:
            stopped = True
        record.update(ended_at=stamp(), duration_seconds=time.monotonic() - tick, child_stopped=stopped)
        record['status'] = ('PASS' if stopped and record['exit_code'] in accepted
                            and not record['termination_reason'] and not event.is_set() and not record['errors'] else 'FAIL')
        for label, path in (('stdout', out), ('stderr', err)):
            if path.is_file(): record[label + '_sha256'] = bundle.file_sha(path)
        write(receipt, record)
    require(record['status'] == 'PASS', 'recorded helper failed: ' + name)
    return out.read_bytes(), err.read_bytes(), record


def exact_remove(path, size, digest, proof_path, expected_identity=None):
    """Unlink only the admitted, stable, single-link owned regular file."""
    bundle.no_links(path); info = path.lstat(); expected = bundle.signature(info)
    require(expected_identity is None or expected == tuple(expected_identity),
            'verified owned file identity changed before removal')
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and info.st_size == size and bundle.file_sha(path) == digest,
            'owned removal identity/size/SHA proof failed')
    require(bundle.signature(path.lstat()) == expected, 'owned removal changed during hash')
    proof = {'status': 'PREPARED', 'path': str(path), 'bytes': size, 'sha256': digest,
             'identity': list(expected), 'run_context': context(), 'qualification': NONQUALIFYING,
             'scope': 'Exact regenerable owned file only; retained historical cloud originals are unchanged.'}
    write(proof_path, proof)
    artifacts.discard_partial(path, expected)
    proof.update(status='PASS', removed=not os.path.lexists(path), ended_at=stamp())
    write(proof_path, proof, replace=True)
    require(proof['removed'], 'owned removal did not remove exact target')
    return proof


def mounted(p, name):
    raw, _, _ = command(['findmnt', '--json', '--mountpoint', str(p['volume']), '-o',
                         'TARGET,FSTYPE,SOURCE,OPTIONS'], name)
    mounts = json.loads(raw)['filesystems']; require(len(mounts) == 1, 'ambiguous owned mount')
    mount = mounts[0]
    require(mount['target'] == str(p['volume']) and mount['fstype'] == 'ext4'
            and re.fullmatch('/dev/loop[0-9]+', mount['source']), 'unexpected owned filesystem mount')
    raw, _, _ = command(['sudo', '-n', 'losetup', '--json', '--list', '--output',
                         'NAME,BACK-FILE', mount['source']], name + '-loop')
    loops = json.loads(raw)['loopdevices']
    require(len(loops) == 1 and loops[0]['name'] == mount['source']
            and loops[0]['back-file'] == str(p['image']), 'loop device does not bind exact owned image')
    image = bundle.no_links(p['image']).lstat()
    require(stat.S_ISREG(image.st_mode) and image.st_nlink == 1 and image.st_uid == os.getuid()
            and image.st_size == IMAGE_BYTES, 'owned image identity or size mismatch')
    fs = os.statvfs(p['volume'])
    require(0 < fs.f_frsize <= 4096 and fs.f_blocks * fs.f_frsize <= IMAGE_BYTES,
            'mounted filesystem exceeds physical image ceiling')
    return mount, loops[0], image


def quota():
    p, _ = admitted()
    require(not os.path.lexists(p['image']) and not os.path.lexists(p['volume']),
            'refusing existing owned image or mount directory')
    p['volume'].mkdir()
    command(['fallocate', '-l', str(IMAGE_BYTES), str(p['image'])], 'allocate-image')
    command(['mkfs.ext4', '-F', '-q', str(p['image'])], 'format-image')
    command(['sudo', '-n', 'mount', '-o', 'loop,nodev,nosuid,noexec',
             str(p['image']), str(p['volume'])], 'mount-image')
    command(['sudo', '-n', 'chown', str(os.getuid()) + ':' + str(os.getgid()),
             str(p['volume']), str(p['volume'] / 'lost+found')], 'own-filesystem')
    mount, loop, image = mounted(p, 'quota-mount')
    probe = p['volume'] / 'codec-enospc-probe'
    _, stderr, observation = command(['fallocate', '-l', str(ENOSPC_BYTES), str(probe)],
                                      'enospc-proof', accepted=(1,))
    require(b'No space left on device' in stderr, 'oversized allocation lacked actual ENOSPC')
    bundle.no_links(probe); info = probe.lstat(); expected = bundle.signature(info)
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and 0 <= info.st_size <= ENOSPC_BYTES, 'unsafe known owned quota probe')
    artifacts.discard_partial(probe, expected)
    record = {'schema_version': 1, 'evidence_type': 'codec_control_actual_quota',
              'status': 'PASS', 'qualification': NONQUALIFYING, 'run_context': context(),
              'hard_quota_enforced': True, 'image_bytes': IMAGE_BYTES,
              'image_identity': list(bundle.signature(image)), 'image_path': str(p['image']),
              'volume_path': str(p['volume']), 'mount': mount, 'loop': loop,
              'oversized_allocation_bytes': ENOSPC_BYTES, 'oversized_allocation': 'DENIED_ENOSPC',
              'enospc_sha256': hashlib.sha256(stderr).hexdigest(), 'probe_removed': True,
              'probe_identity': list(expected), 'command_duration_seconds': observation['duration_seconds']}
    write(p['local'] / 'reference-quota.json', record)
    return record


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def artifact_metadata(metadata):
    run = metadata.get('workflow_run', {})
    api = f'https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{ARTIFACT_ID}'
    require(metadata.get('id') == ARTIFACT_ID and metadata.get('name') == TRANSPORT_NAME
            and metadata.get('size_in_bytes') == ZIP_BYTES and metadata.get('expired') is False
            and metadata.get('digest') == 'sha256:' + ZIP_SHA
            and metadata.get('url') == api and metadata.get('archive_download_url') == api + '/zip'
            and run.get('id') == TRANSPORT_RUN and run.get('repository_id') == REPOSITORY_ID
            and run.get('head_repository_id') == REPOSITORY_ID and run.get('head_sha') == TRANSPORT_HEAD,
            'actual REST artifact metadata differs from frozen authorized input')
    # Retain identity fields only; no request headers, tokens or delivery URLs.
    result = {key: metadata[key] for key in ('id', 'name', 'size_in_bytes', 'expired', 'digest',
              'created_at', 'updated_at', 'expires_at')}
    result['workflow_run'] = {key: run[key] for key in
                              ('id', 'repository_id', 'head_repository_id', 'head_sha')}
    return result


def artifact_destination(location):
    """Use only the exact official destination returned by authenticated API302.

    An unrecognized production endpoint is a retained refusal, never a reason
    to widen the allowlist automatically. The signed URL is never returned in
    receipts or exception text.
    """
    parsed = urllib.parse.urlsplit(location)
    require(parsed.scheme == 'https' and parsed.hostname is not None
            and re.fullmatch(r'productionresultssa[0-9]+\.blob\.core\.windows\.net', parsed.hostname)
            and parsed.netloc == parsed.hostname + (':443' if parsed.port == 443 else '')
            and parsed.port in (None, 443) and parsed.username is None
            and parsed.password is None and not parsed.fragment
            and parsed.path.startswith('/actions-results/') and bool(parsed.query)
            and not any(ord(character) <= 32 or ord(character) == 127 for character in location),
            'artifact destination is not the admitted official HTTPS production endpoint')
    return parsed.hostname


def fetch_artifact(target):
    token = os.environ.get('GITHUB_TOKEN', '')
    require(bool(token), 'missing ephemeral Actions token')
    opener = urllib.request.build_opener(NoRedirect())
    api = f'https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{ARTIFACT_ID}'

    def request(url):
        require(urllib.parse.urlsplit(url).scheme == 'https'
                and urllib.parse.urlsplit(url).netloc == 'api.github.com'
                and url in (api, api + '/zip'), 'API authentication destination differs')
        return urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})

    try:
        with opener.open(request(api), timeout=30) as response:
            raw = response.read(2_000_001)
        require(len(raw) <= 2_000_000, 'REST metadata admission exceeded')
        metadata = artifact_metadata(json.loads(raw, object_pairs_hook=bundle.unique_object))
        try:
            with opener.open(request(api + '/zip'), timeout=30):
                raise ValueError('expected authenticated GitHub artifact302redirect')
        except urllib.error.HTTPError as error:
            require(error.code == 302, 'GitHub artifact did not return expected302redirect')
            location = error.headers.get('Location', '')
        host = artifact_destination(location)
        # A separate opener/request has no API authorization or cookie state.
        # The Location is used byte-for-byte and redirects remain disabled.
        delivery = urllib.request.build_opener(NoRedirect())
        count, digest = 0, hashlib.sha256()
        with delivery.open(urllib.request.Request(location, headers={'Accept': 'application/octet-stream'}),
                           timeout=90) as response, target.open('xb') as stream:
            require(response.status == 200, 'unexpected unauthenticated artifact delivery response')
            while block := response.read(1024 * 1024):
                count += len(block); require(count <= ZIP_BYTES, 'download exceeds frozen input byte ceiling')
                stream.write(block); digest.update(block)
            stream.flush(); os.fsync(stream.fileno())
        require(count == ZIP_BYTES and digest.hexdigest() == ZIP_SHA, 'artifact ZIP size/SHA mismatch')
        return metadata, host
    except BaseException as error:
        # Network exception text/traceback can contain the signed URL. Do not emit it.
        raise RuntimeError('bounded authenticated artifact transfer failed: ' + type(error).__name__) from None


def download():
    p, _ = admitted(); mounted(p, 'input-mount')
    folder = p['volume'] / 'input'; folder.mkdir()
    transport, legacy = folder / 'transport.zip', folder / 'legacy-members.tar.xz'
    tick = time.monotonic(); metadata, host = fetch_artifact(transport)
    count = check_artifact_zip_directory(transport)  # Must precede ZipFile allocation.
    with zipfile.ZipFile(transport) as archive:
        infos = archive.infolist()
        require(len(infos) == count, 'ZIP reader directory differs from admitted directory')
        selected = [info for info in infos if info.filename == INNER_NAME]
        require(len(selected) == 1, 'ZIP must contain exactly one known legacy bundle member')
        info = selected[0]
        require(not info.is_dir() and not info.flag_bits & 1
                and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
                and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and info.file_size == INNER_BYTES and 0 <= info.compress_size <= ZIP_BYTES,
                'selected ZIP member type/size/encryption exceeds admission')
        digest, size = hashlib.sha256(), 0
        with archive.open(info) as source, legacy.open('xb') as output:
            while block := source.read(1024 * 1024):
                size += len(block); require(size <= INNER_BYTES, 'inner bundle expanded beyond frozen byte bound')
                digest.update(block); output.write(block)
            output.flush(); os.fsync(output.fileno())
        require(size == INNER_BYTES and digest.hexdigest() == INNER_SHA,
                'inner legacy bundle length/SHA mismatch')
    require(transport.stat().st_size == ZIP_BYTES and bundle.file_sha(transport) == ZIP_SHA,
            'transport changed during bounded member selection')
    record = {'status': 'PASS', 'qualification': NONQUALIFYING, 'run_context': context(),
              'rest_artifact_metadata': metadata, 'delivery_host': host,
              'transport_zip': {'bytes': ZIP_BYTES, 'sha256': ZIP_SHA, 'directory_members': count},
              'retained_inner': {'path': str(legacy), 'zip_member': INNER_NAME,
                                 'bytes': INNER_BYTES, 'sha256': INNER_SHA},
              'download_and_selection_seconds': time.monotonic() - tick,
              'scope': 'Exact known inner member selected with ZIP CRC and SHA; no archive path extraction and no new cloud data artifact.'}
    write(p['metadata'] / 'input-binding.json', record)
    exact_remove(transport, ZIP_BYTES, ZIP_SHA, p['metadata'] / 'input-wrapper-removal.json')
    return record


def legacy_manifest(raw):
    manifest = json.loads(raw, object_pairs_hook=bundle.unique_object)
    require(manifest.get('schema_version') == 1 and manifest.get('evidence_type') == 'lossless_member_transport'
            and manifest.get('measured_source') == HISTORICAL_SOURCE
            and manifest.get('original_artifact_id') == HISTORICAL_ARTIFACT
            and manifest.get('original_run_id') == HISTORICAL_RUN
            and manifest.get('original_zip_bytes') == HISTORICAL_ZIP_BYTES
            and manifest.get('original_zip_sha256') == HISTORICAL_ZIP_SHA
            and manifest.get('packaging_commit') == TRANSPORT_HEAD, 'legacy historical identity mismatch')
    records = manifest['members']; bundle.validate_layout(records)
    require(len(records) == HISTORICAL_MEMBERS, 'historical full member count differs')
    total, payload_total = 0, 0
    for index, record in enumerate(records):
        require(type(record['payload_bytes']) is int and 0 <= record['payload_bytes'] <= bundle.MAX_MEMBER
                and record['payload_name'] == 'payload/%06d' % index
                and all(isinstance(record.get(key), str) and re.fullmatch('[0-9a-f]{64}', record[key])
                        for key in ('original_sha256', 'payload_sha256'))
                and (not record['directory'] or record['payload_bytes'] == 0),
                'legacy payload metadata admission failed')
        total += record['original_bytes']; payload_total += record['payload_bytes']
    require(total == manifest['original_member_bytes'] <= bundle.MAX_ORIGINAL
            and payload_total == manifest['streamed_payload_bytes'] <= bundle.MAX_PAYLOAD,
            'legacy member/payload totals differ')
    return manifest


def rows_write(folder, name, rows):
    """Whole inventories are retained as small complete metadata members."""
    chunks, buffer, count, total, digest = [], bytearray(), 0, 0, hashlib.sha256()

    def flush():
        nonlocal buffer
        if not buffer: return
        path = folder / ('%s-%03d.jsonl' % (name, len(chunks)))
        with path.open('xb') as stream: stream.write(buffer)
        chunks.append({'name': path.name, 'bytes': len(buffer), 'sha256': hashlib.sha256(buffer).hexdigest()})
        buffer = bytearray()

    for row in rows:
        raw = (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
        require(len(raw) <= ROW_BYTES, 'inventory row exceeds metadata member ceiling')
        if len(buffer) + len(raw) > ROW_BYTES: flush()
        buffer.extend(raw); digest.update(raw); count += 1; total += len(raw)
        require(count <= bundle.MAX_MEMBERS and total <= 40_000_000, 'inventory metadata exceeds bound')
    flush()
    record = {'rows': count, 'bytes': total, 'sha256': digest.hexdigest(), 'chunks': chunks}
    write(folder / (name + '-index.json'), record)
    return record


def rows_read(folder, name):
    index = load(folder / (name + '-index.json'), 100_000)
    require(type(index['rows']) is int and 0 < index['rows'] <= bundle.MAX_MEMBERS
            and 0 < index['bytes'] <= 40_000_000 and len(index['chunks']) <= 50,
            'inventory index admission failed')
    rows, total, digest = [], 0, hashlib.sha256()
    for number, chunk in enumerate(index['chunks']):
        require(chunk['name'] == '%s-%03d.jsonl' % (name, number), 'inventory chunk path differs')
        path = bundle.no_links(folder / chunk['name']); info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and 0 < info.st_size <= ROW_BYTES, 'inventory chunk exceeds read admission')
        raw = path.read_bytes()
        require(len(raw) == chunk['bytes'] <= ROW_BYTES
                and hashlib.sha256(raw).hexdigest() == chunk['sha256']
                and bundle.signature(path.lstat()) == bundle.signature(info), 'inventory chunk differs')
        total += len(raw); digest.update(raw)
        rows.extend(json.loads(line, object_pairs_hook=bundle.unique_object) for line in raw.splitlines())
        require(len(rows) <= bundle.MAX_MEMBERS, 'inventory chunk row bound exceeded')
    require(len(rows) == index['rows'] and total == index['bytes']
            and digest.hexdigest() == index['sha256'], 'complete inventory digest/count differs')
    return rows, index


def snapshot(root):
    records = []
    for name, signature, size in bundle.inventory(root, ['.local']):
        records.append({'path': name, 'directory': name.endswith('/'), 'mode': stat.S_IMODE(signature[2]),
                        'identity': list(signature), 'original_bytes': size,
                        'original_sha256': bundle.sha(b'') if name.endswith('/') else
                            bundle.sha(bundle.read_original(root, (name, signature, size)))})
    return records


def recover():
    p, _ = admitted(); mounted(p, 'recovery-mount')
    ctx = context()
    binding = load(p['metadata'] / 'input-binding.json')
    legacy = p['volume'] / 'input/legacy-members.tar.xz'
    require(binding['run_context'] == context() and legacy.stat().st_size == INNER_BYTES
            and bundle.file_sha(legacy) == INNER_SHA, 'retained legacy input changed before recovery')
    data = p['volume'] / 'data'; data.mkdir(); output = data / '.local'
    tick = time.monotonic()
    with legacy.open('rb') as compressed:
        reader = bundle.XZReader(compressed)
        manifest_raw = bundle.transport_item(reader, 'manifest.json', bundle.MAX_MANIFEST)
        manifest = legacy_manifest(manifest_raw)
        # Keep the immutable original schema/paths inside the hard quota too.
        (p['volume'] / 'input/legacy-manifest.json').write_bytes(manifest_raw)
        output.mkdir()
        for record in manifest['members']:
            raw = bundle.decoded(bundle.transport_item(reader, record['payload_name'], record['payload_bytes']), record)
            target = output.joinpath(*bundle.safe_name(record['path']).parts)
            if record['directory']:
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream: stream.write(raw)
        require(reader.read(1024) == bytes(1024), 'legacy has extra payload or missing tar terminator')
        padding = 0
        while tail := reader.read(65536):
            padding += len(tail); require(padding <= 10240 and not any(tail), 'legacy trailing archive data')
    original_rows = [{'path': record['path'], 'mapped_path': '.local/' + record['path'],
                      'directory': record['directory'], 'mode': None,
                      'original_bytes': record['original_bytes'], 'original_sha256': record['original_sha256']}
                     for record in manifest['members']]
    originals = rows_write(p['metadata'], 'legacy-members', sorted(original_rows, key=lambda row: row['path']))
    complete = snapshot(data)
    actual = {row['path']: row for row in complete}
    original_keys = {row['mapped_path'] for row in original_rows}
    ancestor_dirs = set()
    for row in original_rows:
        parts = bundle.safe_name(row['mapped_path']).parts
        ancestor_dirs.update('/'.join(parts[:number]) + '/' for number in range(1, len(parts)))
        measured = actual.get(row['mapped_path'])
        require(measured is not None and all(measured[key] == row[key] for key in
                ('directory', 'original_bytes', 'original_sha256')), 'recovered historical member differs')
    synthetic = set(actual) - original_keys
    require(synthetic <= ancestor_dirs and all(actual[name]['directory'] for name in synthetic),
            'recovery contains an unexpected member')
    recovered = rows_write(p['metadata'], 'recovered-members', complete)
    scripts = data / 'scripts'; scripts.mkdir()
    tool_files = {}
    for name in ('evidence_bundle.py', 'common.py', 'reference_artifacts.py'):
        source = bundle.no_links(ROOT / 'scripts' / name); raw = source.read_bytes()
        require(len(raw) <= 1_000_000, 'current codec helper exceeds copy admission')
        with (scripts / name).open('xb') as stream: stream.write(raw)
        tool_files[name] = hashlib.sha256(raw).hexdigest()
    require(legacy.stat().st_size == INNER_BYTES and bundle.file_sha(legacy) == INNER_SHA,
            'retained legacy input changed during recovery')
    require(context() == ctx, 'current tool source changed during full recovery')
    record = {'status': 'PASS', 'qualification': NONQUALIFYING, 'scope': SCOPE, 'run_context': ctx,
              'original_manifest_sha256': hashlib.sha256(manifest_raw).hexdigest(),
              'original_manifest_bytes': len(manifest_raw), 'original_member_count': len(original_rows),
              'original_member_bytes': manifest['original_member_bytes'],
              'streamed_payload_bytes': manifest['streamed_payload_bytes'],
              'complete_recovered_member_count': len(complete), 'synthetic_ancestor_directories': len(synthetic),
              'path_transform': 'mapped_path = ".local/" + exact original path; inverse removes exactly this one prefix',
              'original_modes': 'UNKNOWN: historical transport did not record ZIP/filesystem modes',
              'recovered_mode_policy': 'Actual recovered modes measured separately and required unchanged',
              'legacy_inventory': originals, 'recovered_inventory': recovered, 'current_helper_sha256': tool_files,
              'historical_data_source': HISTORICAL_SOURCE, 'historical_data_commit': HISTORICAL_COMMIT,
              'historical_full_cells': 5400, 'historical_samples': 5400000,
              'historical_target_counts': {'PASS': 33, 'FAIL': 12},
              'full_recovery_and_hash_seconds': time.monotonic() - tick}
    write(p['metadata'] / 'recovery.json', record)
    return record


def pack():
    p, _ = admitted(); recovery = load(p['metadata'] / 'recovery.json')
    ctx = context()
    require(recovery['status'] == 'PASS' and recovery['run_context'] == ctx, 'unbound recovery proof')
    before, index = rows_read(p['metadata'], 'recovered-members')
    require(index == recovery['recovered_inventory'] and snapshot(p['volume'] / 'data') == before,
            'historical recovered originals or bound inventory changed before packaging')
    result = artifacts.run_pack(p['volume'] / 'data', p['output'], HISTORICAL_SOURCE,
                                HISTORICAL_COMMIT, 'codec-control-' + os.environ['GITHUB_RUN_ID'], PACK_SECONDS, PACK_PRESET,
                                progress=True)
    write(p['metadata'] / 'pack-result.json', {**result, 'qualification': NONQUALIFYING,
          'current_tool_run_context': context(), 'scope': SCOPE})
    require(context() == ctx, 'current tool source changed during actual packaging attempt')
    require(result['status'] == 'PASS', f'actual preset{PACK_PRESET} full-size codec attempt failed; receipt/streams retained')
    return result


def verify():
    p, _ = admitted(); tick = time.monotonic()
    ctx = context()
    recovery = load(p['metadata'] / 'recovery.json'); expected, expected_index = rows_read(p['metadata'], 'recovered-members')
    original, original_index = rows_read(p['metadata'], 'legacy-members')
    require(recovery['status'] == 'PASS' and recovery['run_context'] == ctx
            and expected_index == recovery['recovered_inventory']
            and original_index == recovery['legacy_inventory'],
            'verification recovery source/run or complete inventory proof differs')
    legacy = p['volume'] / 'input/legacy-members.tar.xz'
    legacy_raw = (p['volume'] / 'input/legacy-manifest.json').read_bytes()
    require(hashlib.sha256(legacy_raw).hexdigest() == recovery['original_manifest_sha256']
            and legacy.stat().st_size == INNER_BYTES and bundle.file_sha(legacy) == INNER_SHA,
            'retained input manifest or legacy bundle changed')
    bundle.no_links(p['output']); output_info = p['output'].lstat()
    require(stat.S_ISREG(output_info.st_mode) and output_info.st_nlink == 1
            and output_info.st_uid == os.getuid() and 0 < output_info.st_size <= bundle.MAX_OUTPUT,
            'new package is not an admitted owned single-link regular file')
    output_identity, output_digest = bundle.signature(output_info), bundle.file_sha(p['output'])
    require(bundle.signature(p['output'].lstat()) == output_identity,
            'new package changed during initial hash')
    # The current verifier reconstructs every original streaming, without another recovery directory.
    result = bundle.verify(p['output'])
    with p['output'].open('rb') as compressed:
        manifest_raw = bundle.transport_item(bundle.XZReader(compressed), 'manifest.json', bundle.MAX_MANIFEST)
    manifest = json.loads(manifest_raw, object_pairs_hook=bundle.unique_object)
    require(manifest['source'] == HISTORICAL_SOURCE and manifest['commit'] == HISTORICAL_COMMIT
            and manifest['run_id'] == 'codec-control-' + os.environ['GITHUB_RUN_ID']
            and manifest['codec_sha256'] == recovery['current_helper_sha256']['evidence_bundle.py'],
            'new bundle data identity/current codec differs')
    require(manifest['compression'] == {'preset': PACK_PRESET, 'dictionary_bytes': PACK_DICTIONARY_BYTES},
            'new bundle compression parameters differ')
    members = {row['path']: row for row in manifest['members']}
    require(len(members) == len(manifest['members']) == len(expected), 'new full directory inventory count differs')
    fields = ('path', 'directory', 'original_bytes', 'original_sha256')
    require(sorted(tuple(row[key] for key in fields) for row in expected)
            == sorted(tuple(row[key] for key in fields) for row in manifest['members']),
            'new full manifest differs from recovered complete original SHA/type/path/length set')
    for row in original:
        candidate = members.get(row['mapped_path'])
        require(candidate is not None and all(candidate[key] == row[key] for key in fields[1:])
                and row['mapped_path'][len('.local/'):] == row['path'] and row['mode'] is None,
                'legacy exact member mapping differs')
    require(len(original) == HISTORICAL_MEMBERS and snapshot(p['volume'] / 'data') == expected,
            'any original path/type/mode/metadata/SHA changed during packaging')
    for name, digest in recovery['current_helper_sha256'].items():
        require(bundle.file_sha(ROOT / 'scripts' / name) == digest
                and bundle.file_sha(p['volume'] / 'data/scripts' / name) == digest,
                'current copied codec helper changed')
    require(bundle.signature(p['output'].lstat()) == output_identity
            and bundle.file_sha(p['output']) == output_digest
            and bundle.signature(p['output'].lstat()) == output_identity and context() == ctx,
            'new package identity/SHA or current source changed during full verification')
    record = {'status': 'PASS', 'qualification': NONQUALIFYING, 'scope': SCOPE, 'run_context': ctx,
              'old_transport': {'artifact_id': ARTIFACT_ID, 'run_id': TRANSPORT_RUN,
                                'zip_bytes': ZIP_BYTES, 'zip_sha256': ZIP_SHA,
                                'bundle_bytes': INNER_BYTES, 'bundle_sha256': INNER_SHA},
              'new_transport': {'bytes': output_info.st_size, 'sha256': output_digest,
                                'identity': list(output_identity),
                                'manifest_sha256': hashlib.sha256(manifest_raw).hexdigest()},
              'original_manifest_sha256': recovery['original_manifest_sha256'],
              'all_original_members_compared': len(original), 'all_current_members_compared': len(expected),
              'legacy_inventory': original_index, 'recovered_inventory': expected_index,
              'original_modes': recovery['original_modes'], 'actual_recovered_modes_unchanged': True,
              'mode_scope': 'Actual recovered filesystem modes before and after packaging; historical modes remain UNKNOWN and the member codec makes no mode-reconstruction claim.',
              'current_verifier': result, 'verification_wall_seconds': time.monotonic() - tick,
              'preset': PACK_PRESET, 'dictionary_bytes': PACK_DICTIONARY_BYTES,
              'packer_child_deadline_seconds': PACK_SECONDS,
              'missing_members': [], 'unexpected_members': [], 'skipped_members': [],
              'scientific_qualification': False, 'new_cloud_data_artifact': False}
    write(p['metadata'] / 'verification.json', record)
    return record


def remove_output():
    p, _ = admitted(); verified = load(p['metadata'] / 'verification.json')
    require(verified['status'] == 'PASS' and verified['run_context'] == context()
            and verified['all_original_members_compared'] == HISTORICAL_MEMBERS,
            'no complete bound verification authorizes output removal')
    expected, index = rows_read(p['metadata'], 'recovered-members')
    require(index == verified['recovered_inventory'] and snapshot(p['volume'] / 'data') == expected,
            'recovered originals or bound complete inventory changed before output removal')
    legacy = p['volume'] / 'input/legacy-members.tar.xz'
    require(legacy.stat().st_size == INNER_BYTES and bundle.file_sha(legacy) == INNER_SHA,
            'retained legacy original changed before output removal')
    require(bundle.file_sha(p['volume'] / 'input/legacy-manifest.json')
            == verified['original_manifest_sha256'], 'retained original manifest changed before output removal')
    new = verified['new_transport']
    return exact_remove(p['output'], new['bytes'], new['sha256'],
                        p['metadata'] / 'verified-output-removal.json', new['identity'])


def unmount():
    p = paths()
    if not os.path.lexists(p['image']):
        return {'status': 'NOT RUN', 'reason': 'no owned image was created'}
    mounted(p, 'final-owned-mount')
    command(['sudo', '-n', 'umount', str(p['volume'])], 'unmount-owned-image')
    _, _, result = command(['findmnt', '--mountpoint', str(p['volume'])], 'confirm-unmounted', accepted=(1,))
    record = {'status': 'PASS', 'qualification': NONQUALIFYING, 'run_context': context(),
              'image_path': str(p['image']), 'image_retained_bytes': p['image'].stat().st_size,
              'exact_mount_closed': result['exit_code'] == 1,
              'scope': 'Only this positively bound mount was unmounted. Historical cloud inputs stay retained; local image remains counted until this disposable runner ends.'}
    write(p['metadata'] / 'unmount.json', record)
    return record


def metadata():
    """Small diagnostics have independent actual global admission after any failure."""
    p = paths(); p['local'].mkdir(exist_ok=True); bundle.no_links(p['local'])
    ctx = context(); base = int(os.environ['FQ_ACCOUNTED_BASE_BYTES'])
    require(base >= 2_000_000_000, 'diagnostics baseline must include the global reserve')
    actual_local = physical(p['local'])
    image_bytes = 0
    if os.path.lexists(p['image']):
        info = bundle.no_links(p['image']).lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == IMAGE_BYTES,
                'unexpected residual image refuses diagnostic admission')
        image_bytes = max(info.st_size, getattr(info, 'st_blocks', 0) * 512)
    # Count image once; its nested ZIP, legacy and recovered allocations are already inside it.
    require(actual_local <= EXTERNAL_METADATA + OUTPUT_BYTES,
            'actual external diagnostics/residual package exceeds reservation')
    peak = base + image_bytes + actual_local + PACKET_BYTES + CLOUD_METADATA + OVERHEAD_BYTES
    admission = {'schema_version': 1, 'qualification': NONQUALIFYING, 'scope': SCOPE,
                 'run_context': ctx, 'status': 'PASS' if peak < CEILING else 'FAIL',
                 'metadata_allowed': peak < CEILING, 'data_allowed': False,
                 'baseline_includes_global_reserve': base, 'actual_image_allocation_bytes': image_bytes,
                 'actual_external_allocation_bytes': actual_local,
                 'packet_reservation_bytes': PACKET_BYTES, 'cloud_metadata_reservation_bytes': CLOUD_METADATA,
                 'overhead_bytes': OVERHEAD_BYTES, 'peak_bytes': peak, 'ceiling_bytes': CEILING}
    write(p['local'] / 'reference-upload-admission.json', admission)
    require(admission['metadata_allowed'], 'actual global codec diagnostic upload admission refused')
    packet = artifacts.metadata_packet(p['local'], p['packet'])
    proof_required, proof_missing, proof_errors = [], [], []
    verification = p['metadata'] / 'verification.json'
    try:
        if os.path.lexists(verification):
            verified = load(verification)
            require(verified['status'] == 'PASS' and verified['run_context'] == ctx,
                    'diagnostic export found an unbound successful verification')
            proof_required = [p['metadata'] / name for name in
                              ('input-binding.json', 'recovery.json', 'verification.json',
                               'pack-result.json', 'unmount.json')]
            proof_required.extend(p['metadata'] / (name + '-stage.json') for name in
                                  ('plan', 'quota', 'download', 'recover', 'pack', 'verify', 'unmount'))
            proof_required.extend(p['local'] / name for name in
                                  ('reference-admission.json', 'reference-quota.json',
                                   'reference-upload-admission.json'))
            proof_required.extend(p['output'].parent / name for name in
                                  ('pack-attempt.json', 'pack-stdout.txt', 'pack-stderr.txt'))
            proof_required.extend(p['metadata'] / 'commands' / ('enospc-proof' + suffix)
                                  for suffix in ('.json', '.stdout.txt', '.stderr.txt'))
            for name, key in (('legacy-members', 'legacy_inventory'), ('recovered-members', 'recovered_inventory')):
                _, index = rows_read(p['metadata'], name)
                require(index == verified[key], 'proof export complete inventory index differs')
                proof_required.extend(p['metadata'] / part for part in
                                      [name + '-index.json', *(chunk['name'] for chunk in index['chunks'])])
            if os.path.lexists(p['metadata'] / 'verified-output-removal.json'):
                proof_required.append(p['metadata'] / 'verified-output-removal.json')
            exported = {entry['path']: entry for entry in packet['files']}
            for path in proof_required:
                entry = exported.get(path.relative_to(p['local']).as_posix())
                if entry is None or entry['transformation'] != 'identity' or not (
                        entry['original_bytes'] == entry['export_bytes'] == path.stat().st_size
                        and entry['original_sha256'] == entry['export_sha256'] == bundle.file_sha(path)):
                    proof_missing.append(path.relative_to(p['local']).as_posix())
    except Exception as error:
        # An invalid proof cannot prevent independently admitted diagnostics
        # from being retained, and cannot become a complete codec proof.
        proof_missing.append('proof-validation-failed')
        proof_errors.append(type(error).__name__)
    packet_complete = (packet.get('status') == 'PASS' and packet.get('enumeration_complete') is True
                       and not packet['failures'] and not packet['reductions'])
    if not packet_complete:
        proof_missing.append('diagnostic-packet-incomplete-or-reduced')
    proof = {'qualification': NONQUALIFYING, 'scientific_qualification': False,
             'current_tool_run_context': ctx, 'full_verification_present': bool(proof_required),
             'complete_codec_proof_metadata_export': bool(proof_required) and not proof_missing,
             'required_proof_files': len(proof_required), 'missing_or_reduced_proof_files': proof_missing,
             'proof_validation_errors': proof_errors,
             'packet_enumeration_complete': packet.get('enumeration_complete') is True,
             'packet_reductions': packet['reductions'], 'packet_failures': packet['failures'],
             'scope': 'Full codec proof requires complete inventory chunks and receipts. A reduced packet retains diagnostics only; historical cloud originals stay unchanged.'}
    write(p['packet'] / 'codec-control-proof-summary.json', proof)
    require(physical(p['packet'], 10_000) <= PACKET_BYTES, 'actual diagnostics packet exceeds physical reservation')
    if destination := os.environ.get('GITHUB_OUTPUT'):
        with open(destination, 'a', encoding='utf-8') as stream:
            stream.write('metadata_allowed=true\npacket_path=' + str(p['packet']) + '\n')
    return {'status': 'FAIL' if proof_missing else packet['status'], 'qualification': NONQUALIFYING,
            'metadata_allowed': True, 'scientific_qualification': False,
            'packet_files': len(packet['files']), 'packet_reductions': packet['reductions'],
            'packet_failures': packet['failures'], 'codec_proof_export': proof,
            'scope': 'Independently bounded diagnostics only. Packet success does not establish scientific preservation.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'quota', 'download', 'recover', 'pack', 'verify',
                                           'remove-output', 'unmount', 'metadata'))
    args = parser.parse_args(); tick = time.monotonic(); status = 'FAIL'
    saved_handlers, state_path, state, terminal_receipt_failed = {}, None, None, False

    def interrupted(signum, frame):
        raise SystemExit('received signal ' + str(signum))

    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            saved_handlers[sig] = signal.signal(sig, interrupted)
        # Tiny stage records have their own overhead admission before the heavy
        # plan. A refused 2GB image must still leave independently exportable
        # diagnostics when the small metadata branch fits the actual baseline.
        p = paths(); base = int(os.environ['FQ_ACCOUNTED_BASE_BYTES'])
        if base >= 2_000_000_000 and base + OVERHEAD_BYTES < CEILING:
            p['metadata'].mkdir(parents=True, exist_ok=True)
            bundle.no_links(p['metadata'])
            state_path = p['metadata'] / (args.action + '-stage.json')
            state = {'action': args.action, 'status': 'RUNNING', 'started_at': stamp(),
                     'qualification': NONQUALIFYING, 'scope': SCOPE, 'run_context': context()}
            write(state_path, state)
        result = globals()[args.action.replace('-', '_')]()
        status = 'FAIL' if result.get('status') == 'FAIL' else 'PASS'
        print(json.dumps({'action': args.action, 'qualification': NONQUALIFYING,
                          'wall_seconds': time.monotonic() - tick, 'result': result}, sort_keys=True), flush=True)
        return 0 if status == 'PASS' else 1
    except BaseException as error:
        record = {'status': 'FAIL', 'action': args.action, 'qualification': NONQUALIFYING,
                  'error_type': type(error).__name__, 'error': str(error)[:1000],
                  'wall_seconds': time.monotonic() - tick, 'ended_at': stamp(), 'scope': SCOPE}
        try:
            p = paths()
            if p['metadata'].is_dir(): write(p['metadata'] / (args.action + '-failure.json'), record)
        except BaseException:
            pass
        print(json.dumps(record, sort_keys=True), flush=True)
        return 1
    finally:
        if state_path is not None and state is not None:
            try:
                state.update(status=status, ended_at=stamp(), elapsed_seconds=time.monotonic() - tick)
                write(state_path, state, replace=True)
            except BaseException as error:
                # Do not replace an actual failure with a fabricated successful
                # terminal record. The final log identifies a missing receipt.
                print(json.dumps({'codec_control_stage_receipt': args.action, 'status': 'FAIL',
                                  'error_type': type(error).__name__}), flush=True)
                status, terminal_receipt_failed = 'FAIL', True
        for sig, handler in saved_handlers.items():
            signal.signal(sig, handler)
        print(json.dumps({'codec_control_stage': args.action, 'status': status,
                          'elapsed_seconds': time.monotonic() - tick,
                          'scope': 'Actual completed stage only; later stages remain NOT RUN until executed.'}), flush=True)
        if terminal_receipt_failed:
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
