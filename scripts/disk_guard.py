"""Conservative workspace admission monitor, NOT an OS hard-quota mechanism."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import sys

LIMIT = 15_000_000_000

def is_link(path: Path) -> bool:
    return path.is_symlink() or getattr(path, 'is_junction', lambda: False)()

def inventory(root: Path) -> dict:
    if is_link(root):
        return {'root': str(root), 'accounted_bytes': 0, 'symlinks_not_followed': [str(root)]}
    if root.is_file():
        s = root.stat()
        return {'root': str(root), 'accounted_bytes': max(s.st_size, getattr(s, 'st_blocks', 0)*512), 'symlinks_not_followed': []}
    if not root.is_dir():
        raise ValueError('inventory root must be an existing file or directory')
    total = 0; links = []; seen = set()
    def failed(error):
        raise error
    for parent, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        for name in dirs + files:
            p = Path(parent)/name
            if is_link(p): links.append(str(p)); continue
            s = p.stat(); key = (s.st_dev, s.st_ino)
            if key in seen: continue
            seen.add(key)
            if p.is_file(): total += max(s.st_size, getattr(s, 'st_blocks', 0)*512)
        dirs[:] = [name for name in dirs if not is_link(Path(parent)/name)]
    return {'root': str(root), 'accounted_bytes': total, 'symlinks_not_followed': links}

def admission(total: int, reserve: int, free: int, unresolved_links: bool = False) -> bool:
    return total >= 0 and reserve >= 0 and total+reserve <= 12_000_000_000 and free >= reserve and not unresolved_links

def inventory_roots(root: Path, external: Path | None) -> list[dict]:
    # These are operator-selected attribution roots, not client input. Do not
    # resolve links before inventory: doing so would conceal an unresolved link.
    roots = [Path(os.path.abspath(root))]
    if external:
        values = json.loads(external.read_text())
        if not isinstance(values, list) or not all(isinstance(x, str) and x for x in values):
            raise ValueError('external allocations must be a JSON list of paths')
        roots.extend(Path(os.path.abspath(value)) for value in values)
    selected = []
    for path in sorted(set(roots), key=lambda x: len(x.parts)):
        if any(path == parent or parent in path.parents for parent in selected):
            continue
        selected.append(path)
    return [inventory(path) for path in selected]

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument('--root', type=Path)
    p.add_argument('--reserve', type=int, default=2_000_000_000)
    p.add_argument('--external', type=Path, help='JSON list of explicit attributable external paths')
    a=p.parse_args(); root=a.root or Path(os.environ.get('FQ_WORKSPACE_ROOT', Path(__file__).resolve().parents[1]))
    external=a.external or (Path(os.environ['FQ_EXTERNAL_ALLOCATIONS']) if os.environ.get('FQ_EXTERNAL_ALLOCATIONS') else None)
    try:
        items=inventory_roots(root,external)
    except (OSError, ValueError) as error:
        print(json.dumps({'admission':'REFUSE','hard_quota_enforced':False,'error':str(error)}));return 1
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
