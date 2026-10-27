"""Evaluate actual workflow selector expressions across all declared choices."""
import ast
import itertools
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


class CapacityWorkflow(unittest.TestCase):
    def test_selector_combinations_choose_one_branch_or_explicitly_refuse(self):
        text = (Path(__file__).resolve().parents[1] / '.github/workflows/release-evidence.yml').read_text()
        jobs = {}
        current = None
        for line in text.splitlines():
            if re.fullmatch(r'  [a-z_]+:', line): current = line.strip()[:-1]
            elif line.startswith('    if: ${{ '): jobs[current] = line[12:-3].strip()
        self.assertEqual(set(jobs), {'reference','codec','reference_capacity','conflicting_controls'})
        permitted = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not,
                     ast.Compare, ast.Eq, ast.NotEq, ast.Constant)
        for capacity, codec, preservation, profile, readers in itertools.product(
                (False, True), (False, True), (False, True), ('full','smoke','diagnostic'), ('1','4','16')):
            values = {'capacity_control': capacity, 'codec_control': codec,
                      'preservation_control': preservation, 'profile': profile, 'concurrency': readers}
            selected = []
            for name, expression in jobs.items():
                expression = re.sub(r'inputs\.([a-z_]+)', lambda m: repr(values[m[1]]), expression)
                expression = re.sub(r'!(?!=)', ' not ', expression).replace('&&',' and ').replace('||',' or ').strip()
                parsed = ast.parse(expression, mode='eval')
                self.assertTrue(all(isinstance(node, permitted) for node in ast.walk(parsed)))
                if eval(compile(parsed, '<actual-workflow-condition>', 'eval'), {'__builtins__': {}}):
                    selected.append(name)
            conflict = codec and preservation or capacity and (codec or preservation or profile != 'smoke' or readers != '1')
            expected = 'conflicting_controls' if conflict else 'reference_capacity' if capacity else 'codec' if codec else 'reference'
            with self.subTest(**values): self.assertEqual(selected, [expected])

    def test_capacity_slots_refuse_existing_dangling_links_before_fallocate(self):
        text = (Path(__file__).resolve().parents[1] / '.github/workflows/release-evidence.yml').read_text()
        capacity = text.split('\n  reference_capacity:\n', 1)[1]
        self.assertLess(capacity.index('test ! -L "$fq_image" && test ! -L "$fq_volume"'),
                        capacity.index('fallocate -l 2000000000 "$fq_image"'))

    @unittest.skipUnless(os.name == 'posix', 'actual Linux dangling-link/fallocate control runs on the supported runner')
    def test_dangling_image_slot_refuses_before_any_target_allocation(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / '.github/workflows/release-evidence.yml').read_text()
        body = text.split('\n  reference_capacity:\n', 1)[1]
        guards = '\n'.join(line.strip() for line in body.splitlines()
                           if line.strip().startswith(('test ! -e "$fq_image"', 'test ! -L "$fq_image"')))
        with tempfile.TemporaryDirectory(dir=root / '.cache/tmp') as folder:
            base = Path(folder); target = base / 'must-not-be-allocated'
            image = base / 'image.img'; image.symlink_to(target)
            result = subprocess.run(['bash','--noprofile','--norc','-c',
                'set -euo pipefail\n'+guards+'\nfallocate -l 4096 "$fq_image"\n'],
                env={**os.environ, 'fq_image':str(image), 'fq_volume':str(base / 'volume')},
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(target.exists())


if __name__ == '__main__': unittest.main()
