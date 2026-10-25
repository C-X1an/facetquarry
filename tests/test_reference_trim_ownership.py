"""Admitted image/run binding before owned cache deletion; fixtures only."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import reference_preflight as trim


class TrimOwnership(unittest.TestCase):
    def test_exact_backing_and_run_binding(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder).absolute()
            volume = parent / 'facetquarry-reference'
            volume.mkdir()
            image = parent / 'facetquarry-reference.img'
            image.write_bytes(b'bounded image fixture')
            context = {'commit': 'a'*40, 'git_status': '', 'github_run_id': '123', 'github_run_attempt': '1'}
            mount = {'target': str(volume), 'source': '/dev/loop7', 'fstype': 'ext4'}
            quota = {'volume_file_bytes': image.stat().st_size, 'run_context': context,
                     'mount': mount, 'volume_path': str(volume), 'image_path': str(image),
                     'hard_quota_enforced': True, 'oversized_allocation': 'DENIED_ENOSPC',
                     'oversized_allocation_bytes': image.stat().st_size + 1}
            loops = {'loopdevices': [{'name': '/dev/loop7', 'back-file': str(image)}]}
            owner = image.stat().st_uid
            trim.validate_ownership(volume, image, quota, mount, loops, context, owner)
            for label, field, value in [('stale', 'run_context', {}), ('size', 'volume_file_bytes', 1),
                                       ('image', 'image_path', str(image) + '.other'),
                                       ('probe', 'oversized_allocation_bytes', image.stat().st_size),
                                       ('quota', 'hard_quota_enforced', False)]:
                with self.subTest(label=label):
                    changed = copy.deepcopy(quota); changed[field] = value
                    with self.assertRaises(RuntimeError):
                        trim.validate_ownership(volume, image, changed, mount, loops, context, owner)
            for changed in ({'loopdevices': []}, {'loopdevices': [{'name': '/dev/loop7', 'back-file': str(image) + '.other'}]},
                            {'loopdevices': [{'name': '/dev/loop8', 'back-file': str(image)}]}):
                with self.assertRaises(RuntimeError):
                    trim.validate_ownership(volume, image, quota, mount, changed, context, owner)


if __name__ == '__main__':
    unittest.main()
