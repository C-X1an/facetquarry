"""Inspect prerequisites; do not mutate global environment or install unverified tools."""
import argparse
import json
import shutil
import subprocess
import sys
from common import ROOT, environment

def main():
    p=argparse.ArgumentParser();p.add_argument('--release',action='store_true');a=p.parse_args()
    missing=[x for x in ('go','git') if shutil.which(x) is None]
    if missing:print('Missing prerequisites: '+', '.join(missing));return 1
    version=subprocess.check_output(['go','version'],text=True).strip()
    current='go1.27.3' in version
    environment()
    print(json.dumps({'go':version,'python':sys.version.split()[0],
                     'reference_go':'go1.27.3','reference_toolchain_matches':current,
                     'qualification':'reference' if current else 'development-only',
                     'network_installs_performed':False},indent=2))
    if a.release and not current:return 1
    return 0
if __name__=='__main__':raise SystemExit(main())
