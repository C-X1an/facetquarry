"""Synthetic proof contracts for both explicitly supported outer ceilings."""
import unittest
from test_reference_proof_contract import FullFormatFixture


class QuotaGeometry(unittest.TestCase):
    def test_supported_smaller_ceiling_preserves_all_other_bindings(self):
        fixture = FullFormatFixture()
        fixture.docs['quota']['volume_file_bytes'] = 2_300_000_000
        fixture.docs['quota']['oversized_allocation_bytes'] = 2_400_000_000
        argv = fixture.docs['setup']['qemu_command']
        argv[:] = [value.replace(',security_model=none', ',security_model=none,multidevs=remap')
                   if value.startswith('local,id=') else value for value in argv]
        fixture.check()

    def test_nested_geometry_requires_remap_on_all_three_exact_shares(self):
        for remapped in (0, 1, 2):
            fixture = FullFormatFixture()
            fixture.docs['quota']['volume_file_bytes'] = 2_300_000_000
            fixture.docs['quota']['oversized_allocation_bytes'] = 2_400_000_000
            argv = fixture.docs['setup']['qemu_command']
            remaining = remapped
            for index, value in enumerate(argv):
                if value.startswith('local,id=') and remaining:
                    argv[index] = value.replace(',security_model=none', ',security_model=none,multidevs=remap')
                    remaining -= 1
            with self.subTest(remapped=remapped), self.assertRaisesRegex(ValueError, 'actual guest shares'):
                fixture.check()

    def test_unspecified_geometry_and_inadequate_probe_refuse(self):
        for size, probe in [(1, 2), (2_300_000_000, 2_300_000_000),
                            (2_300_000_000, 2_300_000_001), (3_300_000_001, 3_400_000_001)]:
            with self.subTest(size=size, probe=probe):
                fixture = FullFormatFixture()
                fixture.docs['quota']['volume_file_bytes'] = size
                fixture.docs['quota']['oversized_allocation_bytes'] = probe
                with self.assertRaises(ValueError): fixture.check()


if __name__ == '__main__':
    unittest.main()
