"""Conservative workspace admission monitor, NOT an OS hard-quota mechanism."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import sys

LIMIT = 15_000_000_000

def inventory(root: Path) -> dict:
    if root.is_symlink():
        return {'root': str(root), 'accounted_bytes': 0, 'symlinks_not_followed': [str(root)]}
    if root.is_file():
        s = root.stat()
        return {'root': str(root), 'accounted_bytes': max(s.st_size, getattr(s, 'st_blocks', 0)*512), 'symlinks_not_followed': []}
    if not root.is_dir():
        raise ValueError('inventory root must be an existing file or directory')
    total = 0; links = []; seen = set()
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            p = Path(parent)/name
            if p.is_symlink(): links.append(str(p)); continue
            s = p.stat(); key = (s.st_dev, s.st_ino)
            if key in seen: continue
            seen.add(key)
            if p.is_file(): total += max(s.st_size, getattr(s, 'st_blocks', 0)*512)
    return {'root': str(root), 'accounted_bytes': total, 'symlinks_not_followed': links}

def admission(total: int, reserve: int, free: int, unresolved_links: bool = False) -> bool:
    return total >= 0 and reserve >= 0 and total+reserve <= 12_000_000_000 and free >= reserve and not unresolved_links

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument('--root', type=Path)
    p.add_argument('--reserve', type=int, default=2_000_000_000)
    p.add_argument('--external', type=Path, help='JSON list of explicit attributable external paths')
    a=p.parse_args(); root=(a.root or Path(__file__).resolve().parents[1]).resolve()
    items=[inventory(root)]
    if a.external:
        for value in json.loads(a.external.read_text()):
            path=Path(value).resolve()
            if path == root or root in path.parents: continue
            if not path.exists(): raise SystemExit('external allocation missing; inventory is incomplete')
            items.append(inventory(path))
    total=sum(x['accounted_bytes'] for x in items)
    unresolved=any(x['symlinks_not_followed'] for x in items)
    denied=not admission(total,a.reserve,shutil.disk_usage(root).free,unresolved)
    report={'limit_bytes':LIMIT, 'admission_ceiling_bytes':12_000_000_000,
            'inventory':items, 'total_attributable_bytes':total,
            'reserved_growth_bytes':a.reserve, 'admission':'REFUSE' if denied else 'ALLOW',
            'warning':total>=10_000_000_000,
            'hard_quota_enforced':False,
            'caveat':'External app, VM, toolchain and cache allocations must be listed separately. Monitoring does not guarantee a hard cap.'}
    print(json.dumps(report,indent=2)); return 1 if denied else 0
if __name__=='__main__':raise SystemExit(main())
