"""Build source-bound Go binaries inside a named-host pilot's owned volume."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import urllib.request

from common import ROOT, source_hash
from reference_group_capacity import OUTER_IMAGE_BYTES, phase_space, require
from reference_preflight import checked, delete_linux, inspections, selected_roots, tree, write_proof
from reference_upload_candidate import run_readonly


VERSION = 'go1.27.3'
SDK_BYTES = 70_588_678
SDK_SHA256 = '65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40'
SDK_MEMBERS = 17_373
SDK_DECODED_BYTES = 244_139_206
SDK_URL = f'https://dl.google.com/go/{VERSION}.linux-amd64.tar.gz'
BUILD_ALLOWANCE_BYTES = 160_000_000
RECORD_BYTES = 8_000_000


def sdk_inventory(archive, *, block_size, decoded_limit, member_limit):
    require(type(block_size) is int and 0 < block_size <= 4096, 'unsupported SDK block size')
    decoded = allocated = 0
    files, directories, paths = {}, set(), set()
    for member in archive:
        path = PurePosixPath(member.name)
        require(path.parts and path.parts[0] == 'go' and path.as_posix() == member.name
                and '..' not in path.parts and '\\' not in member.name
                and member.name not in paths and len(paths) < member_limit
                and (member.isdir() or member.isreg()) and 0 <= member.size <= decoded_limit,
                'SDK member escapes its exact regular-file and path admission')
        paths.add(member.name)
        directories.update(parent.as_posix() for parent in path.parents if parent.parts)
        if member.isdir():
            require(member.size == 0, 'SDK directory with payload')
            directories.add(member.name)
        else:
            decoded += member.size
            allocated += ((member.size + block_size - 1) // block_size) * block_size
        require(decoded <= decoded_limit, 'SDK decoded bytes exceed admission')
        if member.isreg():
            with archive.extractfile(member) as content:
                files[member.name] = hashlib.file_digest(content, 'sha256').hexdigest()
    require(paths and not files.keys() & directories, 'SDK file and directory paths collide')
    return {'members': len(paths), 'decoded_bytes': decoded,
            'required_bytes': allocated + len(directories) * block_size,
            'required_inodes': len(files) + len(directories), 'content_sha256': installation_digest(files)}


def installation_digest(files):
    canonical = json.dumps(files, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(canonical).hexdigest()


def verify_installation(volume, tools, expected):
    inventory = tree(volume, [tools / 'go'])
    prefix = tools.relative_to(volume).as_posix() + '/'
    files = {row['path'].removeprefix(prefix): row['sha256'] for row in inventory['entries'] if row['kind'] == 'file'}
    require(len(inventory['entries']) == expected['required_inodes']
            and installation_digest(files) == expected['content_sha256'], 'installed SDK tree differs from verified archive')
    return {'members': len(inventory['entries']), 'content_sha256': expected['content_sha256']}


def download_sdk(path):
    digest = hashlib.sha256()
    count = 0
    with path.open('xb') as output, urllib.request.urlopen(SDK_URL, timeout=25) as response:
        require(response.geturl() == SDK_URL and response.status == 200
                and int(response.headers['Content-Length']) == SDK_BYTES, 'SDK download locator or length differs')
        while raw := response.read(1 << 20):
            count += len(raw)
            require(count <= SDK_BYTES, 'SDK download grew beyond the pinned archive')
            digest.update(raw)
            output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    require(count == SDK_BYTES and digest.hexdigest() == SDK_SHA256, 'SDK archive size or hash differs')
    return {'url': SDK_URL, 'bytes': count, 'sha256': digest.hexdigest()}


def admit(volume, phase, report, future_bytes, inodes=0):
    value = phase_space(os.statvfs(volume), phase, future_bytes=future_bytes, required_inodes=inodes)
    report['space'].append(value)
    require(value['status'] == 'ALLOW', 'owned caller free capacity or inode floor refused ' + phase)


def record_command(command, project, out, environment, report):
    require(Path.cwd() == project, 'pilot build command needs the exact checkout directory')
    index = len(report['commands'])
    paths = [out / f'{index:02}.{role}' for role in ('stdout', 'stderr')]
    actual = ['/usr/bin/env', '-i', *[f'{key}={value}' for key, value in environment.items()], *command]
    fact = {'command': command, 'actual_command': actual, 'exit_code': None}
    report['commands'].append(fact)
    result = run_readonly(actual, total_seconds=160)
    fact.update({key: value for key, value in result.items() if not key.endswith('_base64')})
    for role, path in zip(('stdout', 'stderr'), paths, strict=True):
        raw = base64.b64decode(result[role + '_base64'], validate=True)
        require(hashlib.sha256(raw).hexdigest() == result[role + '_sha256'], 'captured command bytes differ')
        with path.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        fact[role] = {'path': path.name, 'bytes': len(raw), 'sha256': result[role + '_sha256']}
    require(result['status'] == 'PASS', 'pinned source build or command custody failed')
    return paths[0].read_bytes()


def build(volume, project, out):
    require(os.name == 'posix' and os.getuid() != 0 and os.path.ismount(volume), 'owned ordinary Linux mount required')
    require(project == volume / 'source' and out == volume / 'bootstrap-proof', 'pilot build scope differs')
    require(stat.S_ISDIR(checked(volume).st_mode), 'pilot volume directory differs')
    out.mkdir(mode=0o700)
    report = {'status': 'FAIL', 'source': None, 'commands': [], 'space': [], 'go': VERSION, 'stage': 'initial_scope',
              'scope': 'Source-bound pinned benchmark build in the dedicated pilot volume.'}
    summary_path = out / 'build.json'
    failure = None
    try:
        require(stat.S_ISDIR(checked(project, volume).st_mode), 'pilot checkout directory differs')
        require((project / '.go-version').read_text(encoding='ascii').strip() == VERSION.removeprefix('go'),
                'tracked Go version differs from pinned pilot SDK')
        require(os.statvfs(volume).f_blocks * os.statvfs(volume).f_frsize <= OUTER_IMAGE_BYTES, 'pilot volume geometry differs')
        initial = source_hash(project)
        report.update(source=initial, stage='sdk_download')
        tools = volume / 'tools'
        tools.mkdir()
        archive = tools / 'sdk.tar.gz'
        admit(volume, 'sdk_unpack', report, SDK_BYTES)
        report['sdk_download'] = download_sdk(archive)
        report['stage'] = 'sdk_unpack'
        with tarfile.open(archive, mode='r:gz') as package:
            observed = sdk_inventory(package, block_size=os.statvfs(volume).f_frsize,
                                     decoded_limit=SDK_DECODED_BYTES, member_limit=SDK_MEMBERS)
            require((observed['decoded_bytes'], observed['members']) == (SDK_DECODED_BYTES, SDK_MEMBERS),
                    'SDK decoded archive layout differs')
            report['sdk_inventory'] = observed
        admit(volume, 'sdk_unpack', report, observed['required_bytes'], observed['required_inodes'] + 16)
        with tarfile.open(archive, mode='r:gz') as package:
            package.extractall(tools, filter='data')
        report['sdk_installed'] = verify_installation(volume, tools, observed)
        journal = out / 'verified-sdk.json'
        write_proof(journal, {**report['sdk_download'], **observed, 'installed': report['sdk_installed'],
                              'status': 'PASS'}, initial=True)
        archive.unlink()

        report['stage'] = 'build'
        goroot = tools / 'go'
        go = str(goroot / 'bin/go')
        for path in (project / 'bin', project / '.cache/go-build', project / '.cache/go-mod', project / '.cache/tmp'):
            path.mkdir(parents=True, exist_ok=False)
        environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'GOROOT': str(goroot),
                       'CGO_ENABLED': '0', 'GOCACHE': str(project / '.cache/go-build'),
                       'GOMODCACHE': str(project / '.cache/go-mod'), 'TMPDIR': str(project / '.cache/tmp'),
                       'GOTMPDIR': str(project / '.cache/tmp'), 'GOPROXY': 'off', 'GOSUMDB': 'off',
                       'GOTOOLCHAIN': 'local', 'GOENV': 'off', 'GOWORK': 'off', 'GOTELEMETRY': 'off', 'GOMAXPROCS': '2'}
        admit(volume, 'build', report, BUILD_ALLOWANCE_BYTES, 1800)
        version = record_command([go, 'version'], project, out, environment, report)
        require(version == f'go version {VERSION} linux/amd64\n'.encode(), 'actual compiler version differs')
        for name in ('facetquarry', 'fqbench'):
            require(source_hash(project) == initial, 'committed build inputs changed before compiler launch')
            binary = str(project / 'bin' / name)
            record_command([go, 'build', '-trimpath', '-ldflags', '-X main.sourceID=' + initial,
                            '-o', binary, './cmd/' + name], project, out, environment, report)
            announced = json.loads(record_command([binary, 'version'], project, out, environment, report))
            require(source_hash(project) == initial and announced['source'] == initial and announced['go'] == VERSION,
                    'compiled input or reported Go provenance differs')
        admit(volume, 'build', report, RECORD_BYTES)
        report['stage'] = 'trim'
        before = inspections(volume, project)
        plan = tree(volume, selected_roots(volume, project))
        trim_path = out / 'trim-intent.json'
        write_proof(trim_path, plan, initial=True)
        delete_linux(volume, plan)
        after = inspections(volume, project)
        require(before == after and source_hash(project) == initial, 'trim changed verified source or runtime binaries')
        report.update(retained_build=after, trim_entries=len(plan['entries']), trim_bytes=plan['accounted_bytes'])
        report['trim_manifest_sha256'] = hashlib.sha256(trim_path.read_bytes()).hexdigest()
        admit(volume, 'boot', report, RECORD_BYTES)
        report.update(status='PASS', stage='verified_build')
    except BaseException as error:
        failure = error
        report['error'] = f'{type(error).__name__}: {error}'[:2000]
        raise
    finally:
        try:
            write_proof(summary_path, report, initial=True)
        except (OSError, RuntimeError, ValueError) as error:
            print(json.dumps({'status': 'FAIL', 'bootstrap_proof_write': type(error).__name__}), file=sys.stderr)
            if failure is None:
                raise
    print(json.dumps({'status': report['status'], 'source': initial, 'go': VERSION,
                      'space': report['space'], 'restorable_build_binaries': len(report['retained_build']['commands']) - 1}),
          flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('volume', type=Path)
    args = parser.parse_args()
    volume = args.volume.resolve(strict=True)
    require(ROOT == volume / 'source', 'execute the candidate script directly from the exact owned checkout')
    build(volume, ROOT, volume / 'bootstrap-proof')


if __name__ == '__main__':
    main()
