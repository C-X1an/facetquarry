"""Byte admissions for the separate bounded frozen-group reference pilot."""

import argparse
import json
import os
from pathlib import Path


MIB = 1 << 20
OUTER_IMAGE_BYTES = 1_030_000_000
RESULT_IMAGE_BYTES = 64 * MIB
PACKET_BYTES = 64 * MIB
HOST_PROOF_BYTES = 24 * MIB
CLOSURE_BYTES = 4 * MIB
ARCHIVE_OVERHEAD_BYTES = 4 * MIB
ARTIFACT_BYTES = 96 * MIB
RUNNER_BYTES = 64 * MIB
GUEST_FILESYSTEM_AND_INITRD_BYTES = 48 * MIB
GLOBAL_RESERVE_BYTES = 2_000_000_000
ADMISSION_CEILING_BYTES = 12_000_000_000
OUTER_FREE_FLOOR_BYTES = 500_000_000
PHASES = {'checkout', 'sdk_unpack', 'build', 'boot', 'pack'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def growth_plan(accounted_base_bytes):
    require(type(accounted_base_bytes) is int and accounted_base_bytes >= GLOBAL_RESERVE_BYTES,
            'current accounted base must include the global reserve')
    new_bytes = OUTER_IMAGE_BYTES + ARTIFACT_BYTES + RUNNER_BYTES + GUEST_FILESYSTEM_AND_INITRD_BYTES
    peak = accounted_base_bytes + new_bytes
    return {'accounted_base_bytes': accounted_base_bytes, 'global_reserve_bytes': GLOBAL_RESERVE_BYTES,
            'outer_image_bytes': OUTER_IMAGE_BYTES, 'results_image_inside_outer_bytes': RESULT_IMAGE_BYTES,
            'external_runner_bytes': RUNNER_BYTES, 'guest_filesystems_and_initrd_bytes': GUEST_FILESYSTEM_AND_INITRD_BYTES,
            'maximum_artifact_bytes': ARTIFACT_BYTES, 'maximum_new_bytes': new_bytes,
            'admission_ceiling_bytes': ADMISSION_CEILING_BYTES, 'peak_bytes': peak,
            'admission': 'ALLOW' if peak < ADMISSION_CEILING_BYTES else 'REFUSE',
            'capacity_observed': False, 'release_qualification': False}


def phase_space(observation, phase, *, future_bytes, required_inodes=0):
    require(phase in PHASES, 'unknown group admission phase')
    require(type(future_bytes) is int and 0 <= future_bytes <= OUTER_IMAGE_BYTES
            and type(required_inodes) is int and 0 <= required_inodes <= 100_000,
            'invalid phase allocation')
    block, total, free, available, free_inodes = (getattr(observation, name) for name in (
        'f_frsize', 'f_blocks', 'f_bfree', 'f_bavail', 'f_favail',
    ))
    require(all(type(value) is int for value in (block, total, free, available, free_inodes))
            and 0 < block <= 4096 and 0 <= available <= free <= total
            and 0 < total * block <= OUTER_IMAGE_BYTES and free_inodes >= 0,
            'filesystem observation does not match bounded outer geometry')
    caller_bytes = available * block
    remaining = caller_bytes - future_bytes
    allowed = remaining >= OUTER_FREE_FLOOR_BYTES and required_inodes <= free_inodes
    return {'phase': phase, 'status': 'ALLOW' if allowed else 'REFUSE',
            'outer_filesystem_bytes': total * block, 'free_space_floor_bytes': OUTER_FREE_FLOOR_BYTES,
            'caller_available_bytes': caller_bytes, 'future_bytes': future_bytes,
            'unallocated_after_phase_bytes': remaining, 'available_inodes': free_inodes,
            'required_inodes': required_inodes}


def transport_limit(parts):
    require(isinstance(parts, dict), 'transport inventory must be a mapping')
    roles = set(parts) - {'host_proof', 'closure'}
    require(roles in ({'verified_bundle'}, {'frozen_results_image'}), 'one exclusive artifact payload is required')
    role, = roles
    require(all(type(parts.get(key)) is int and 0 < parts[key] <= bound for key, bound in (
        ('host_proof', HOST_PROOF_BYTES), ('closure', CLOSURE_BYTES),
    )), 'host proof or closure bytes exceed admission')
    payload = parts[role]
    require(type(payload) is int and (payload == RESULT_IMAGE_BYTES if role == 'frozen_results_image'
                                     else 0 < payload <= PACKET_BYTES), 'selected transport bytes exceed admission')
    maximum = sum(parts.values()) + ARCHIVE_OVERHEAD_BYTES
    require(maximum <= ARTIFACT_BYTES, 'total artifact ceiling exceeded')
    return {'selected': role, 'member_bytes': sum(parts.values()), 'zip_overhead_bytes': ARCHIVE_OVERHEAD_BYTES,
            'maximum_transport_bytes': maximum, 'artifact_ceiling_bytes': ARTIFACT_BYTES}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    operations = parser.add_subparsers(required=True, dest='operation')
    operations.add_parser('plan').add_argument('accounted_base_bytes', type=int)
    phase = operations.add_parser('phase')
    phase.add_argument('volume', type=Path)
    phase.add_argument('name', choices=sorted(PHASES))
    phase.add_argument('--future-bytes', required=True, type=int)
    phase.add_argument('--required-inodes', type=int, default=0)
    args = parser.parse_args()
    if args.operation == 'plan':
        result = growth_plan(args.accounted_base_bytes)
        status = result['admission']
    else:
        require(os.path.ismount(args.volume) and not args.volume.is_symlink(), 'owned mount point required')
        result = phase_space(os.statvfs(args.volume), args.name, future_bytes=args.future_bytes,
                             required_inodes=args.required_inodes)
        status = result['status']
    print(json.dumps(result, sort_keys=True))
    return int(status != 'ALLOW')


if __name__ == '__main__':
    raise SystemExit(main())
