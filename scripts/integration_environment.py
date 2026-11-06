"""Run the complete Python fixture suite in its own profile environment."""
from __future__ import annotations
import os
import re
import shlex
import subprocess
import sys

from common import ROOT


def discovery_command(makefile_text):
    """Consume one real full-suite recipe; never execute Make text as a shell."""
    if type(makefile_text) is not str or len(makefile_text.encode('utf-8')) > 65536:
        raise ValueError('fixture command specification exceeds its text bound')
    lines = makefile_text.splitlines()
    targets = [i for i, line in enumerate(lines)
               if not line.lstrip().startswith('#')
               and 'python-fixtures' in line.partition(':')[0].split()]
    if len(targets) != 1 or lines[targets[0]] != 'python-fixtures:':
        raise ValueError('one unambiguous full-suite target is required')
    recipes = []
    for line in lines[targets[0] + 1:]:
        if line.startswith('\t'):
            recipes.append(line[1:])
        elif not line.strip() or line.lstrip().startswith('#'):
            continue
        elif re.fullmatch(r'[A-Za-z0-9_.%\-]+:[^:=]*', line):
            break
        else:
            raise ValueError('unsupported syntax inside the full-suite target')
    if len(recipes) != 1:
        raise ValueError('one literal full-suite recipe is required')
    tokens = shlex.split(recipes[0], comments=False, posix=True)
    expected = ['FQ_FILESYSTEM_POLICY=', 'FQ_NESTED_FILESYSTEM_POLICY=', '$(PYTHON)',
                '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_*.py', '-v']
    if tokens != expected:
        raise ValueError('fixture recipe must retain the complete fixed discovery command')
    return [sys.executable, *tokens[3:]]


def fixture_environment(environ):
    # Only the fixture subprocess uses neutral policy selection. Real build,
    # resource, capacity and transport gates retain their declared environment.
    env = dict(environ)
    for key in ('FQ_RESERVATION_PROFILE', 'FQ_FILESYSTEM_POLICY', 'FQ_NESTED_FILESYSTEM_POLICY'):
        env.pop(key, None)
    return env


def main():
    with (ROOT / 'Makefile').open(encoding='utf-8') as source:
        specification = source.read(65537)
    completed = subprocess.run(
        discovery_command(specification),
        cwd=ROOT, env=fixture_environment(os.environ), check=False)
    return completed.returncode


if __name__ == '__main__':
    raise SystemExit(main())
