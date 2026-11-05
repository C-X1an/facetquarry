"""Explicit outer-volume identities; legacy callers retain their exact geometry.

STRICT2.1GB is an unqualified capacity experiment, not a smaller workload.
Neither an observed size nor a growth estimate can select this profile.
"""
from __future__ import annotations
import os
import re
from pathlib import PurePosixPath

LEGACY = 'reference-inside-outer-v1'
STRICT_2100 = 'reference-inside-outer-2100-v1'
PROFILES = (LEGACY, STRICT_2100)
GEOMETRY = {LEGACY: (2_300_000_000, 2_400_000_000),
            STRICT_2100: (2_100_000_000, 2_200_000_000)}


def checked(profile):
    if type(profile) is not str or profile not in PROFILES:
        raise ValueError('unknown explicit inside-outer volume profile')
    return profile


def active(environ=None):
    environ = os.environ if environ is None else environ
    # Unset remains the old API default. An explicit unknown value fails closed.
    return checked(environ.get('FQ_RESERVATION_PROFILE', LEGACY))


def image_bytes(profile=LEGACY):
    return GEOMETRY[checked(profile)][0]


def probe_bytes(profile=LEGACY):
    return GEOMETRY[checked(profile)][1]


def filesystem_context(context, profile=None):
    profile = active() if profile is None else checked(profile)
    result = dict(context)
    if profile == STRICT_2100:
        result['outer_profile'] = profile
    elif 'outer_profile' in result:
        raise ValueError('legacy filesystem context cannot inherit another profile')
    return result


def filesystem_size(size, context):
    """Pure collector authorization requires the explicitly named context."""
    marker = context.get('outer_profile') if type(context) is dict else None
    if marker is None:
        return type(size) is int and size in (2_300_000_000, 1_100_000_000)
    return (marker == STRICT_2100 and type(size) is int
            and size in (2_100_000_000, 1_100_000_000))


def quota_geometry(quota, context=None):
    """Validate strict proof identity before permitting its new geometry.

    Legacy qualification also admits the existing 3.3GB historical proof.
    This function does not grant runtime admission or certify a quota.
    """
    size = quota.get('volume_file_bytes')
    profile = quota.get('profile')
    if profile == STRICT_2100:
        ctx = quota.get('profile_context', {})
        fields = {'profile', 'job', 'repository', 'repository_id', 'source', 'commit',
                  'git_status', 'github_run_id', 'github_run_attempt'}
        if (type(ctx) is not dict or set(ctx) != fields
                or any(type(ctx[key]) is not str for key in fields - {'repository_id'})
                or type(ctx['repository_id']) is not int
                or re.fullmatch('[0-9a-f]{64}', ctx['source']) is None
                or re.fullmatch('[0-9a-f]{40}', ctx['commit']) is None
                or ctx['git_status'] != ''
                or any(re.fullmatch('[1-9][0-9]{0,19}', ctx[key]) is None
                       for key in ('github_run_id', 'github_run_attempt'))):
            return False
        run = {key: ctx.get(key) for key in
               ('commit', 'git_status', 'github_run_id', 'github_run_attempt')}
        return (type(size) is int and size == image_bytes(profile)
                and type(quota.get('oversized_allocation_bytes')) is int
                and quota.get('oversized_allocation_bytes') == probe_bytes(profile)
                and ctx.get('profile') == profile
                and ctx.get('job') == 'reference'
                and ctx.get('repository') == 'C-X1an/facetquarry'
                and ctx.get('repository_id') == 1430604581
                and quota.get('run_context') == run
                and (context is None or run == context))
    return (profile in (None, LEGACY) and type(size) is int
            and size in (2_300_000_000, 3_300_000_000)
            and type(quota.get('oversized_allocation_bytes')) is int
            and quota['oversized_allocation_bytes'] == size + 100_000_000)


def validate_strict_filesystem_summary(quota, context, source):
    """Validate hashed retained summary schema/bindings, never a live mount.

    Runtime callers still authenticate canonical files and observations using
    reference_filesystem_bindings.validate. This pure check re-observes no OS.
    """
    import datetime as dt
    import reference_filesystem as fs

    def need(value, message):
        if not value:
            raise ValueError('strict outer filesystem summary: ' + message)

    need(quota.get('profile') == STRICT_2100 and quota_geometry(quota, context),
         'profile, context or geometry differs')
    need(type(source) is str and re.fullmatch('[0-9a-f]{64}', source)
         and quota['profile_context']['source'] == source, 'source differs')
    need(quota.get('filesystem_policy') == fs.POLICY, 'mandatory policy missing')
    proof = quota.get('filesystem_proof')
    need(type(proof) is dict, 'mandatory proof missing')
    fs.bounded(proof)
    keys = {'kind', 'policy', 'status', 'run_context', 'directory', 'image_path',
            'mount_point', 'image_bytes', 'proof_sha256', 'proof_file_sha256',
            'formatter_file_sha256', 'formatter_receipt_sha256',
            'collector_supervisor_sha256', 'observation_receipts_sha256',
            'files_sha256', 'geometry', 'statvfs'}
    need(set(proof) == keys and proof['kind'] == 'owned-filesystem-bindings-v1'
         and proof['policy'] == fs.POLICY and proof['status'] == 'PASS',
         'binding kind, policy, status or fields differ')
    need(proof['run_context'] == {**context, 'source': source, 'outer_profile': STRICT_2100}
         and type(proof['image_bytes']) is int and proof['image_bytes'] == image_bytes(STRICT_2100)
         and proof['image_path'] == quota.get('image_path')
         and proof['mount_point'] == quota.get('volume_path'), 'image, mount or execution differs')
    for key in ('directory', 'image_path', 'mount_point'):
        value = proof[key]
        need(type(value) is str and '\\' not in value and ':' not in value, 'nonportable path')
        path = PurePosixPath(value)
        need(path.is_absolute() and '..' not in path.parts and path.as_posix() == value,
             'noncanonical path')
    need(PurePosixPath(proof['directory']).parts[-3:] == ('.local', 'reference-filesystem', 'outer'),
         'noncanonical outer proof directory')
    geometry, counters = proof['geometry'], proof['statvfs']
    need(type(geometry) is dict and set(geometry) == {'uuid', 'block_size', 'block_count', 'reserved_blocks'},
         'geometry fields differ')
    need(type(geometry['uuid']) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', geometry['uuid'])
         and all(type(geometry[k]) is int for k in ('block_size', 'block_count', 'reserved_blocks')),
         'geometry types differ')
    block = geometry['block_size']
    need(block in (1024, 2048, 4096) and geometry['block_count'] > 0
         and 0 <= image_bytes(STRICT_2100) - block * geometry['block_count'] < block
         and geometry['reserved_blocks'] == 0, 'geometry dimensions or reserved blocks differ')
    need(type(counters) is dict and set(counters) == {'observed_at', 'uid', 'gid',
         'f_frsize', 'f_blocks', 'f_bfree', 'f_bavail'}, 'statvfs fields differ')
    need(all(type(counters[k]) is int for k in counters if k != 'observed_at')
         and counters['uid'] > 0 and counters['gid'] > 0
         and counters['f_frsize'] == block and 0 < counters['f_blocks'] <= geometry['block_count']
         and 0 <= counters['f_bavail'] <= counters['f_bfree'] <= counters['f_blocks']
         and counters['f_bavail'] * block >= 520_000_000, 'ordinary statvfs geometry/floor differs')
    need(type(counters['observed_at']) is str, 'statvfs timestamp type differs')
    try:
        need(dt.datetime.fromisoformat(counters['observed_at']).tzinfo is not None,
             'statvfs timestamp is not zoned')
    except ValueError as error:
        raise ValueError('strict outer filesystem summary: invalid observation timestamp') from error
    names = {'context.json', 'proof.json', 'formatter.json', 'formatter-audit/0.json',
             'collector-supervisor.json'}
    names.update(prefix + '.' + stream for prefix in ('formatter-audit/0', 'collector-supervisor')
                 for stream in ('stdout', 'stderr'))
    names.update('observations/' + str(index) + '.' + suffix for index in range(4)
                 for suffix in ('json', 'stdout', 'stderr'))
    files = proof['files_sha256']
    sha = lambda value: type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None
    need(type(files) is dict and set(files) == names and all(sha(v) for v in files.values()),
         'complete binding digest map differs')
    need(sha(proof['proof_sha256']), 'policy proof digest malformed')
    for key, name in (('proof_file_sha256', 'proof.json'), ('formatter_file_sha256', 'formatter.json'),
                      ('formatter_receipt_sha256', 'formatter-audit/0.json'),
                      ('collector_supervisor_sha256', 'collector-supervisor.json')):
        need(sha(proof[key]) and proof[key] == files[name], 'bound file digest differs')
    receipts = proof['observation_receipts_sha256']
    need(type(receipts) is dict and set(receipts) == {'version', 'superblock', 'mount', 'loop'},
         'observation digest set differs')
    for index, name in enumerate(('version', 'superblock', 'mount', 'loop')):
        need(sha(receipts[name]) and receipts[name] == files['observations/' + str(index) + '.json'],
             'bound observation digest differs')
    return proof
