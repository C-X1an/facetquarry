"""Shared paths, bounded subprocesses and source identity; no external packages."""
from __future__ import annotations
import hashlib
import os
import stat
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {'.git', '.cache', '.local', '__pycache__', 'bin', 'raw', 'published'}

def executable(name: str, root: Path = ROOT) -> Path:
    """Use the native Go executable suffix, including direct script invocations."""
    return root / 'bin' / (name + ('.exe' if os.name == 'nt' else ''))

def command_args(args: list[str]) -> list[str]:
    args = list(args)
    if args and args[0] == 'python3':
        args[0] = sys.executable
    if args and os.name == 'nt':
        path = Path(args[0])
        if path.parent.name == 'bin' and path.name in {'facetquarry', 'fqbench'}:
            args[0] = str(path.with_suffix('.exe'))
    return args

def source_files(root: Path = ROOT) -> list[Path]:
    files = []
    def failed(error):
        raise error
    for parent, dirs, names in os.walk(root, topdown=True, followlinks=False, onerror=failed):
        dirs[:] = [name for name in dirs if name not in EXCLUDED]
        for name in names:
            if name in EXCLUDED:
                continue
            p = Path(parent) / name
            if (p.suffix in {'.go', '.py', '.mod', '.yml', '.yaml', '.toml'}
                    or p.name in {'Makefile', '.go-version', '.gitignore', '.gitattributes', 'go.sum', 'ACCEPTANCE_SPEC.md', 'phase_definitions.json', 'locks.json'}
                    or p.suffix == '.json' and p.relative_to(root).parts[0] in {'examples', 'benchmarks'}):
                mode = p.stat().st_mode  # Do not silently shorten identity on stat failures.
                if stat.S_ISREG(mode):
                    files.append(p)
    return sorted(files)

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
        check: bool = True, input_text: str | None = None, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(command_args(args), cwd=cwd, env=environment(ROOT), text=text,
                          capture_output=True, input=input_text, timeout=timeout, check=check)

if __name__ == '__main__':
    print(source_hash())
