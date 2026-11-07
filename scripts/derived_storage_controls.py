"""Run the storage codec/profile controls; report every platform skip explicitly."""
import argparse
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--actual-linux', action='store_true')
    args = parser.parse_args()
    if args.actual_linux and sys.platform != 'linux':
        parser.error('actual Linux physical-allocation control requires Linux')
    sys.path.insert(0, str(ROOT / 'scripts'))
    suite = unittest.TestSuite()
    for pattern in ('test_reversible*.py', 'test_derived*.py', 'test_reference_derived_storage_probe.py'):
        suite.addTests(unittest.TestLoader().discover(str(ROOT / 'tests'), pattern=pattern))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    # An actual Linux measurement cannot proceed on a green-with-skips result.
    # Original 50 methods plus 12 scope/ordering regressions; never accept a
    # shortened discovery or a Linux qualification with any skipped method.
    passed = result.wasSuccessful() and result.testsRun == 62 and (not args.actual_linux or not result.skipped)
    print(json.dumps({'status': 'PASS' if passed else 'FAIL', 'tests_run': result.testsRun,
                      'failures': len(result.failures), 'errors': len(result.errors),
                      'skipped': len(result.skipped), 'platform': sys.platform,
                      'scope': 'Storage controls only; no scientific or measured storage-savings qualification.'}))
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
