"""Conservative workspace admission monitor, NOT an OS hard-quota mechanism."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time

LIMIT = 15_000_000_000

def is_link(path: Path) -> bool:
    return path.is_symlink() or getattr(path, 'is_junction', lambda: False)()

def inventory(root: Path, progress=None) -> dict:
    total = 0; links = []; seen = set(); files = 0; directories = 0
    started = time.monotonic(); next_report = started

    def report(path, state, force=False):
        nonlocal next_report
        now = time.monotonic()
        if progress and (force or now >= next_report):
            progress({'root': str(root), 'path': str(path), 'state': state,
                      'files': files, 'directories': directories,
                      'accounted_bytes': total, 'elapsed_seconds': now - started})
            next_report = now + 10

    def visit(path, metadata):
        nonlocal total, files
        # lstat/DirEntry.stat never follows links. Inspect the returned metadata
        # instead of issuing repeated path queries across a network filesystem.
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, 'st_reparse_tag', 0) in (0xa0000003, 0xa000000c):
            links.append(str(path)); return False
        key = (metadata.st_dev, metadata.st_ino)
        if key in seen:
            return False
        seen.add(key)
        if stat.S_ISREG(metadata.st_mode):
            total += max(metadata.st_size, getattr(metadata, 'st_blocks', 0)*512)
            files += 1
            return False
        if stat.S_ISDIR(metadata.st_mode):
            return True
        raise ValueError('unsupported inventory entry: ' + str(path))

    report(root, 'started', True)
    stack = [root] if visit(root, root.lstat()) else []
    while stack:
        parent = stack.pop()
        directories += 1
        with os.scandir(parent) as entries:
            for entry in entries:
                report(entry.path, 'scanning')
                # Windows DirEntry.stat supplies zero file IDs; lstat supplies
                # real identities needed for hardlink/directory deduplication.
                metadata = Path(entry.path).lstat() if os.name == 'nt' else entry.stat(follow_symlinks=False)
                if visit(entry.path, metadata):
                    stack.append(Path(entry.path))
    report(root, 'complete', True)
    return {'root': str(root), 'accounted_bytes': total, 'symlinks_not_followed': links}

def admission(total: int, reserve: int, free: int, unresolved_links: bool = False) -> bool:
    return total >= 0 and reserve >= 0 and total+reserve <= 12_000_000_000 and free >= reserve and not unresolved_links

def inventory_roots(root: Path, external: Path | None, progress=None) -> list[dict]:
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
    return [inventory(path, progress) for path in selected]

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument('--root', type=Path)
    p.add_argument('--reserve', type=int, default=2_000_000_000)
    p.add_argument('--external', type=Path, help='JSON list of explicit attributable external paths')
    a=p.parse_args(); root=a.root or Path(os.environ.get('FQ_WORKSPACE_ROOT', Path(__file__).resolve().parents[1]))
    external=a.external or (Path(os.environ['FQ_EXTERNAL_ALLOCATIONS']) if os.environ.get('FQ_EXTERNAL_ALLOCATIONS') else None)
    try:
        items=inventory_roots(root,external,lambda record: print(json.dumps(record),file=sys.stderr,flush=True))
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
