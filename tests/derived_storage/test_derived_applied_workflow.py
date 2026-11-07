"""Validate the deployed workflow, including selectors and actual guard shell."""
import ast
import itertools
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

if __package__:
    from .test_reference_derived_storage_probe import probe
else:
    from test_reference_derived_storage_probe import probe


def workflow():
    return (probe.ROOT / '.github/workflows/release-evidence.yml').read_text()


def evaluate(expression, values):
    expression = expression.removeprefix('${{').removesuffix('}}').strip()
    expression = re.sub(r'inputs\.([a-z_]+)', lambda match: repr(values[match[1]]), expression)
    expression = re.sub(r'steps\.[a-z_0-9]+\.outputs\.metadata_allowed', "'true'", expression)
    expression = re.sub(r'steps\.[a-z_0-9]+\.(?:outcome|conclusion)', "'success'", expression)
    expression = expression.replace('always()', 'True').replace('cancelled()', 'False').replace('success()', 'True')
    expression = re.sub(r'!(?!=)', ' not ', expression).replace('&&', ' and ').replace('||', ' or ').strip()
    tree = ast.parse(expression, mode='eval')
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not,
               ast.Compare, ast.Eq, ast.NotEq, ast.Constant)
    if not all(isinstance(node, allowed) for node in ast.walk(tree)): raise ValueError('unknown workflow expression')
    return bool(eval(compile(tree, '<actual-workflow-selector>', 'eval'), {'__builtins__': {}}))


def codec_steps(text):
    codec = text.split('\n  codec:\n', 1)[1].split('\n  conflicting_controls:\n', 1)[0]
    steps = []
    for line in codec.splitlines():
        if line.startswith('      - '): steps.append({'head': line[8:], 'lines': [], 'if': '${{ True }}'})
        if not steps: continue
        steps[-1]['lines'].append(line)
        if line.startswith('        if: '): steps[-1]['if'] = line[12:]
        if line.startswith('        timeout-minutes: '): steps[-1]['minutes'] = int(line.split(':', 1)[1])
    return steps


VALUES = {'codec_control': True, 'image_recovery': True, 'retained_image_probe': False,
          'derived_storage_probe': True, 'capacity_control': False, 'preservation_control': False,
          'trim_control': False, 'profile': 'smoke', 'concurrency': '1',
          'transport_profile': 'inside-outer-2100', 'accounted_base_bytes': '9000000000'}


class AppliedWorkflow(unittest.TestCase):
    def test_new_selector_is_false_optional_boolean_and_old_job_conditions_are_exact(self):
        text = workflow()
        block = text.split('      derived_storage_probe:\n', 1)[1].split('      transport_profile:\n', 1)[0]
        for value in ('        type: boolean\n', '        default: false\n', '        required: false\n'):
            self.assertIn(value, block)
        jobs = {}; current = None
        for line in text.splitlines():
            if re.fullmatch(r'  [a-z_]+:', line): current = line.strip()[:-1]
            elif line.startswith('    if: '): jobs[current] = line[8:]
        self.assertEqual(jobs, {
            'reference': '${{ !inputs.codec_control && !inputs.capacity_control }}',
            'codec': '${{ inputs.codec_control && !inputs.capacity_control && !inputs.preservation_control }}',
            'conflicting_controls': "${{ (inputs.codec_control && inputs.preservation_control) || (inputs.capacity_control && (inputs.codec_control || inputs.preservation_control || inputs.profile != 'smoke' || inputs.concurrency != '1')) }}",
            'reference_capacity': "${{ inputs.capacity_control && !inputs.codec_control && !inputs.preservation_control && inputs.profile == 'smoke' && inputs.concurrency == '1' }}"})
        self.assertEqual([name for name, expression in jobs.items() if evaluate(expression, VALUES)], ['codec'])
        self.assertIn('  group: reference-evidence\n  cancel-in-progress: false', text)

    def test_actual_selected_steps_fit_job_and_exclude_all_other_payloads(self):
        text = workflow(); steps = codec_steps(text)
        selected = [step for step in steps if evaluate(step['if'], VALUES)]
        derived = [step for step in selected if 'Derived storage byte-equivalence only - ' in step['head']]
        self.assertEqual([step['head'].rsplit(' - ', 1)[1] for step in derived], list(probe.STAGES))
        self.assertEqual(sum(step['minutes'] for step in selected), 59)
        for step in derived:
            action = step['head'].rsplit(' - ', 1)[1]
            self.assertIn('python3 scripts/reference_derived_storage_probe.py ' + action, '\n'.join(step['lines']))
            self.assertGreater(step['minutes'] * 60, probe.STAGES[action])
        allowed = ('Validate exclusive derived storage mode', 'Validate exclusive image mode before quota, installation or artifact download',
                   'uses: actions/checkout@', 'Derived storage byte-equivalence only - ',
                   'Retain complete bounded equivalence')
        self.assertTrue(all(any(marker in step['head'] for marker in allowed) for step in selected),
                        [step['head'] for step in selected])
        self.assertIn('    timeout-minutes: 60\n', text.split('\n  codec:\n', 1)[1].split('\n  conflicting_controls:\n', 1)[0])
        guard = next(i for i, step in enumerate(steps) if 'Validate exclusive derived storage mode' in step['head'])
        checkout = next(i for i, step in enumerate(steps) if 'uses: actions/checkout@' in step['head'])
        self.assertLess(guard, checkout)

    @unittest.skipUnless(sys.platform == 'linux', 'Actual deployed Bash selector guard; NOT RUN on this platform')
    def test_actual_guard_refuses_each_incompatible_control_before_any_growth(self):
        step = next(step for step in codec_steps(workflow()) if 'Validate exclusive derived storage mode' in step['head'])
        body = '\n'.join(line[10:] for line in step['lines'][step['lines'].index('        run: |') + 1:])
        cases = [VALUES, *({**VALUES, key: value} for key, value in
                 [('codec_control', False), ('image_recovery', False), ('retained_image_probe', True),
                  ('capacity_control', True), ('preservation_control', True), ('trim_control', True),
                  ('profile', 'full'), ('profile', 'diagnostic'), ('concurrency', '4'), ('concurrency', '16')])]
        with tempfile.TemporaryDirectory() as directory:
            for number, values in enumerate(cases):
                script = re.sub(r'\$\{\{ inputs\.([a-z_]+) \}\}',
                                lambda match: str(values[match[1]]).lower(), body)
                env = {'PATH': os.defpath, 'GITHUB_ENV': str(Path(directory) / str(number))}
                run = subprocess.run(['bash', '--noprofile', '--norc', '-c', script],
                                     env=env, capture_output=True, timeout=5)
                with self.subTest(case=number): self.assertEqual(run.returncode == 0, number == 0)


if __name__ == '__main__': unittest.main()
