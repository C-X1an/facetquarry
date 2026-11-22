"""Bound all selected files for the prospective full-volume evidence upload."""

from pathlib import PurePosixPath
import re


IMAGE_NAME = 'job/quota.img'
IMAGE_BYTES = 268_435_456
NEUTRAL_NAMES = frozenset({'job/exports/fixture.neutral', 'job/exports/fixture-copy.neutral'})
NEUTRAL_BYTES = 109_070_351
RAW_BYTES = 495 << 20
ARCHIVE_BYTES = 512 << 20
OTHER_MEMBER_BYTES = 8 << 20
MAX_ENTRIES = 4096
MAX_PATH_BYTES = 768
# Leave generous space for local and central headers, extra fields, data
# descriptors and archive end records. Compression level zero is required.
ZIP_ENTRY_ALLOWANCE = 4096
ZIP_END_ALLOWANCE = 65536


def maximum_member_bytes(relative):
    if relative == IMAGE_NAME:
        return IMAGE_BYTES
    if relative in NEUTRAL_NAMES:
        return NEUTRAL_BYTES
    return OTHER_MEMBER_BYTES


def member_name(name):
    """Use an exact ZIP member name within the one admitted namespace."""
    if type(name) is not str or not 0 < len(name) <= MAX_PATH_BYTES:
        raise ValueError('transport name length')
    parts = name.split('/')
    if any(part in ('.', '..') or re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', part) is None for part in parts):
        raise ValueError('transport name components')
    return str(PurePosixPath(*parts))


def validate_payload(members, *, require_complete_image):
    """Admit measured bytes and bound the complete archive, including prefixes.

    `members` holds exact (namespace-relative name, byte count) pairs, including
    generated upload metadata and any fallback records. This check applies to
    an already collected inventory. The enclosing copy and archive placements
    require separate admission before the job.
    """
    if type(require_complete_image) is not bool:
        raise ValueError('image closure policy must be explicit')
    names, total, image_size = set(), 0, None
    for name, size in members:
        name = member_name(name)
        folded = name.casefold()
        if folded in names or len(names) >= MAX_ENTRIES:
            raise ValueError('duplicate member or member count')
        if type(size) is not int or not 0 <= size <= maximum_member_bytes(name):
            raise ValueError('member byte bound')
        if name == IMAGE_NAME:
            image_size = size
        total += size
        if total > RAW_BYTES:
            raise ValueError('uncompressed payload byte bound')
        names.add(folded)
    if any(prefix in names for name in names for prefix in parent_names(name)):
        raise ValueError('file and parent alias')
    if require_complete_image and image_size != IMAGE_BYTES:
        raise ValueError('complete quota image required')
    if not names:
        raise ValueError('empty transport')
    upper = total + ZIP_ENTRY_ALLOWANCE * len(names) + ZIP_END_ALLOWANCE
    if upper > ARCHIVE_BYTES:
        raise ValueError('uncompressed archive bound')
    return {'files': len(names), 'payload_bytes': total, 'archive_upper_bound_bytes': upper,
            'exact_image_bytes': image_size}


def parent_names(name):
    while '/' in name:
        name = name.rsplit('/', 1)[0]
        yield name
