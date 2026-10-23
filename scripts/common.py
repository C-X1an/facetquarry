"""Shared paths, bounded subprocesses and source identity; no external packages."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'.git', '.cache', '.local', '__pycache__', 'bin', 'raw', 'published'}

def source_files(root: Path = ROOT) -> list[Path]:
    return sorted(p for p in root.rglob('*') if p.is_file()
                  and not any(x in EXCLUDED for x in p.relative_to(root).parts)
                  and (p.suffix in {'.go', '.py', '.mod', '.yml', '.yaml', '.toml'}
                       or p.name in {'Makefile', '.go-version', '.gitignore', 'go.sum', 'ACCEPTANCE_SPEC.md', 'phase_definitions.json', 'locks.json'}
                       or p.suffix == '.json' and p.relative_to(root).parts[0] in {'examples', 'benchmarks'}))

def source_hash(root: Path = ROOT) -> str:
    h = hashlib.sha256()
    for p in source_files(root):
        h.update(p.relative_to(root).as_posix().encode() + b'\0')
        h.update(hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()

def environment(root: Path = ROOT) -> dict[str, str]:
    env = os.environ.copy()
    for name, sub in {'GOCACHE': 'go-build', 'GOMODCACHE': 'go-mod',
                      'GOTMPDIR': 'tmp', 'TMPDIR': 'tmp'}.items():
        directory = root / '.cache' / sub
        directory.mkdir(parents=True, exist_ok=True)
        env[name] = str(directory)
    env['GOTOOLCHAIN'] = 'local'
    env['GOMAXPROCS'] = env.get('FQ_CPUS', '2')
    return env

def run(args: list[str], *, cwd: Path = ROOT, timeout: int = 120,
        check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, env=environment(ROOT), text=True,
                          capture_output=True, input=input_text, timeout=timeout, check=check)

if __name__ == '__main__':
    print(source_hash())
