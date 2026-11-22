"""Build paired admissions for the reviewed same-job full-volume POSIX scope."""

import hashlib
import json
from pathlib import PurePosixPath
import re


BASE_LIFECYCLE_BYTES = 1_493_172_224
SPI_BYTES = 855_638_016
SPI_ENTRIES = 20_608
MEMORY_BYTES = 536_870_912
IMAGE_BYTES = 268_435_456
PROTOCOL = 'scientific-posix-complete-failure-copy-v1'
SPI_PROFILE = 'scientific-posix-integration-retain-all-v2'
SPI_CONTEXT = 'explicit-owned-quota-posix-v2'
LIFECYCLE_PROFILE = 'scientific-posix-complete-failure-copy-full-volume-v1'
LIFECYCLE_ADMISSION = 'scientific-posix-lifecycle-full-volume-admission-v1'
REVIEWED_STATUS = 'AUTHORIZED_FOR_REVIEWED_SYNTHETIC_POSIX_ONLY'


def sha(value):
    if type(value) is not str or value == '0' * 64 or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('exact non-placeholder SHA-256 required')
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def require_admission(*, job, owner, runtime, attempt, envelope, pins):
    """Use the actual controller's independently pinned placement and proof bytes."""
    if type(job) is not str or re.fullmatch(r'/srv/fq-posix-proof-[0-9]{1,24}-[0-9]{1,8}/job', job) is None:
        raise ValueError('exact owned job root required')
    if type(attempt) is not str or re.fullmatch('[a-z0-9][a-z0-9-]{0,47}', attempt) is None:
        raise ValueError('exact bounded attempt id required')
    uid, gid = owner
    if any(type(identity) is not int or not 1 <= identity < 1 << 31 for identity in (uid, gid)):
        raise ValueError('positive owner uid and gid required')
    baseline, growth, reserve = (envelope[key] for key in ('baseline_excluding_reserve_bytes',
                                                           'other_growth_bytes', 'global_reserve_bytes'))
    if (any(type(size) is not int or not 0 <= size < 15_000_000_000 for size in (baseline, growth, reserve))
            or reserve != 2_000_000_000 or baseline + growth + reserve + BASE_LIFECYCLE_BYTES >= 12_000_000_000):
        raise ValueError('complete reserved growth exceeds admission ceiling')
    if envelope['all_attributable_allocations_admitted'] is not True or envelope['no_other_heavy_process'] is not True:
        raise ValueError('reviewed full placement and exclusive heavy-process reservation required')
    source = sha(pins['lifecycle_manifest_sha256'])
    integration_source = sha(pins['integration_manifest_sha256'])
    external_proof = sha(pins['external_profile_control_proof_sha256'])
    findings = sha(pins['independent_first_findings_sha256'])
    quota = sha(pins['quota_proof_sha256'])
    memory = sha(pins['memory_proof_sha256'])
    inventory = sha(envelope['fresh_global_inventory_sha256'])
    root = PurePosixPath(job) / 'volume' / 'work' / ('fixture-' + attempt)
    spi = {'format': 'scientific-posix-runner-admission-v2', 'profile': SPI_PROFILE,
           'status': REVIEWED_STATUS, 'runner_context': SPI_CONTEXT, 'test_root': str(root),
           'source_manifest_sha256': integration_source, 'baseline_excluding_reserve_bytes': baseline,
           'other_growth_bytes': growth + BASE_LIFECYCLE_BYTES - SPI_BYTES, 'global_reserve_bytes': reserve,
           'fresh_global_inventory_sha256': inventory, 'hard_quota_bytes': IMAGE_BYTES,
           'hard_quota_enforced': True, 'hard_quota_evidence_sha256': quota, 'memory_quota_enforced': True,
           'memory_limit_bytes': MEMORY_BYTES, 'memory_quota_evidence_sha256': memory,
           'fixture_source_bytes': 167_772_160, 'fixture_source_entries': 4096, 'complete_failure_copies': 4,
           'total_reserved_bytes': SPI_BYTES, 'total_reserved_entries': SPI_ENTRIES,
           'external_complete_failure_transport_profile': PROTOCOL, 'external_transport_source_sha256': source,
           'external_transport_proof_sha256': external_proof, 'all_allocations_including_external_copies_admitted': True,
           'no_other_heavy_process': True, 'independent_first_findings_sha256': findings}
    spi_raw = encoded(spi)
    lifecycle = {'format': LIFECYCLE_ADMISSION, 'status': REVIEWED_STATUS, 'profile': LIFECYCLE_PROFILE,
                 'attempt_id': attempt, 'owner_uid': uid, 'owner_gid': gid, 'job_root': job,
                 'integration_packet': str(PurePosixPath(job) / 'volume' / 'packet'), 'test_root': str(root),
                 'lifecycle_manifest_sha256': source, 'lifecycle_module_sha256': sha(pins['lifecycle_module_sha256']),
                 'integration_manifest_sha256': integration_source,
                 'integration_admission_sha256': hashlib.sha256(spi_raw).hexdigest(),
                 'quota_proof_sha256': quota, 'memory_proof_sha256': memory,
                 'original22_receipt_sha256': sha(pins['original22_receipt_sha256']),
                 'independent_first_findings_sha256': findings, 'external_profile_control_proof_sha256': external_proof,
                 'interpreter': runtime['python'], 'installed_tools': {name: runtime[name] for name in ('mke2fs', 'mount', 'umount')},
                 'fresh_global_inventory_sha256': inventory, 'baseline_excluding_reserve_bytes': baseline,
                 'other_growth_bytes': growth, 'global_reserve_bytes': reserve,
                 'reserved_job_bytes': BASE_LIFECYCLE_BYTES, 'reserved_job_entries': SPI_ENTRIES,
                 'image_capacity_bytes': IMAGE_BYTES, 'neutral_copy_equivalents': 4, 'raw_image_copy_equivalents': 2,
                 'control_overhead_bytes': 16 << 20, 'all_attributable_allocations_admitted': True,
                 'no_other_heavy_process': True}
    return encoded(lifecycle), spi_raw
