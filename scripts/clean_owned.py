"""Remove only explicitly named regenerable paths owned by this project."""
from pathlib import Path
import shutil
ROOT=Path(__file__).resolve().parents[1]
for name in ('bin','.cache/tmp'):
    p=ROOT/name
    if p.is_symlink() or not p.resolve().is_relative_to(ROOT):raise SystemExit('refusing unsafe cleanup path')
    if p.exists():shutil.rmtree(p)
print('Removed owned binaries and temporary build files. Evidence, data, source and caches retained.')
