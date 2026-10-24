"""Fail closed on typed, source-bound acceptance evidence, regardless of filename.

References have path/sha256/kind. Legacy command receipts are recognized by their
contents, never by basename. gate_evidence maps required global gates to refs;
booleans alone cannot establish review, resource or manual qualification.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from common import ROOT,source_hash
import reference_qualification

GATE_KINDS = {
    'supported_toolchain': 'toolchain',
    'independent_review_complete': 'review',
    'full_benchmark_complete': 'benchmark_coverage',
    'owner_walkthrough_complete': 'manual',
    'public_export_audited': 'export_audit',
    'fresh_checkout_complete': 'fresh_checkout',
    'resource_inventory_complete': 'resource',
}
SUMMARY_KINDS = {'oracle_summary', 'mutation_summary', 'benchmark_coverage',
                 'fresh_checkout', 'review', 'resource', 'manual', 'toolchain', 'export_audit'}


def nonempty(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_record(record: dict, kind: str, identity: str) -> list[str]:
    errors = []
    if not isinstance(record, dict):
        return ['evidence must be a JSON object']
    if record.get('status') != 'PASS':
        errors.append('evidence status is not PASS')
    if kind == 'command':
        if record.get('source_before') != identity or record.get('source_after') != identity:
            errors.append('command used different source')
        if type(record.get('exit_code')) is not int or record['exit_code'] != 0 or record.get('termination_reason') is not None:
            errors.append('command did not complete successfully')
        if not isinstance(record.get('command'), list) or not record['command'] or not all(nonempty(x) for x in record['command']):
            errors.append('command invocation missing')
        for key in ('stdout_sha256', 'stderr_sha256'):
            value = record.get(key)
            if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                errors.append('command output digest missing: ' + key)
        return errors
    if kind not in SUMMARY_KINDS:
        return ['unknown evidence kind']
    if record.get('schema_version') != 1 or record.get('evidence_type') != kind:
        errors.append('unsupported evidence schema/type')
    if record.get('source') != identity:
        errors.append('evidence belongs to a different technical source')
    if kind == 'oracle_summary' and (type(record.get('seed_count')) is not int or record['seed_count'] < 1000):
        errors.append('oracle seed coverage incomplete')
    if kind == 'mutation_summary':
        controls = record.get('controls', [])
        if not isinstance(controls, list) or {x.get('mutation') for x in controls if isinstance(x, dict)} != {'tenant', 'filter', 'exact-label', 'budget'}:
            errors.append('mutation controls incomplete')
        elif any(x.get('status') != 'PASS' or x.get('before_exit') != 0 or x.get('restored_exit') != 0 or not x.get('defect_exit') or x.get('expected_assertion_failed') is not True for x in controls):
            errors.append('mutation control failed')
    if kind == 'benchmark_coverage':
        if (record.get('profile') != 'full' or record.get('grid_complete') is not True
                or record.get('missing_cells') != [] or record.get('unexpected_cells') != []
                or record.get('failed_cells') != [] or record.get('limited') is not False
                or type(record.get('expected_cells')) is not int or record['expected_cells'] <= 0
                or record.get('completed_cells') != record['expected_cells']):
            errors.append('full benchmark grid incomplete or failed')
        if record.get('reference_host_verified') is not True or record.get('reference_recall_target') != 'PASS':
            errors.append('reference benchmark qualification missing')
        provenance = record.get('provenance', {})
        if provenance.get('source') != identity or set(provenance.get('binaries', {})) != {'facetquarry', 'fqbench'}:
            errors.append('benchmark executable provenance missing')
        elif any(v.get('source') != identity or not nonempty(v.get('sha256')) for v in provenance['binaries'].values()):
            errors.append('benchmark executable provenance stale')
    if kind == 'fresh_checkout':
        if record.get('exit_code') != 0 or record.get('clean_checkout') is not True or record.get('supported_toolchain') is not True or not nonempty(record.get('commit')):
            errors.append('fresh supported checkout qualification incomplete')
    if kind == 'review':
        if (record.get('initially_read_only') is not True or record.get('independent') is not True
                or not nonempty(record.get('reviewer')) or not nonempty(record.get('findings_artifact'))
                or record.get('unresolved_critical_high') != [] or record.get('fixes_verified') is not True):
            errors.append('independent review schema or disposition incomplete')
    if kind == 'resource':
        total = record.get('total_attributable_bytes')
        if (type(total) is not int or not 0 <= total < 15_000_000_000
                or not isinstance(record.get('inventory'), list) or not record['inventory']
                or record.get('external_allocations_complete') is not True
                or record.get('admission') != 'ALLOW'):
            errors.append('complete resource inventory missing')
        if record.get('hard_quota_enforced') is not True and record.get('approved_remote_runner') is not True:
            errors.append('hard quota or approved remote runner evidence missing')
        if not nonempty(record.get('enforcement_record')):
            errors.append('resource enforcement record missing')
        if any(not isinstance(x, dict) or x.get('symlinks_not_followed') != [] or type(x.get('accounted_bytes')) is not int or x['accounted_bytes'] < 0 for x in record.get('inventory', [])):
            errors.append('resource inventory unresolved')
    if kind == 'manual':
        if not nonempty(record.get('reviewer')) or not nonempty(record.get('notes')) or record.get('owner_walkthrough') != 'PASS' or record.get('keyboard_usability') != 'PASS':
            errors.append('manual walkthrough or usability evidence incomplete')
    if kind == 'toolchain':
        if record.get('go') != 'go1.27.3' or record.get('platform') != 'linux/amd64' or record.get('runtime_verified') is not True:
            errors.append('supported reference runtime not verified')
    if kind == 'export_audit':
        if record.get('findings') != [] or record.get('history_audited') is not True or record.get('allowlist_audited') is not True:
            errors.append('public export/history audit incomplete')
    return errors


def validate_reference(ref: dict, identity: str, root: Path, expected_kind: str | None = None,
                       bundle_cache: dict | None = None, benchmark_proofs: list | None = None) -> list[str]:
    try:
        if not isinstance(ref, dict) or not nonempty(ref.get('path')):
            return ['invalid evidence reference']
        file = root / ref['path']
        if not file.resolve().is_relative_to(root.resolve()):
            return ['evidence path escapes public root']
        raw = file.read_bytes()
        if hashlib.sha256(raw).hexdigest() != ref.get('sha256'):
            return ['evidence digest mismatch']
        record = json.loads(raw)
        # Renaming receipt.json cannot turn a failing command into a summary.
        command_record = isinstance(record, dict) and any(k in record for k in ('source_before', 'source_after', 'termination_reason'))
        kind = 'command' if command_record else ref.get('kind')
        if command_record and ref.get('kind', 'command') != 'command':
            return ['command evidence mislabeled']
        if expected_kind and kind != expected_kind:
            return ['required gate needs ' + expected_kind + ' evidence']
        errors = validate_record(record, kind, identity)
        if kind == 'benchmark_coverage' and not errors:
            proof = reference_qualification.validate_envelope(record, root, identity, bundle_cache)
            if benchmark_proofs is not None:
                benchmark_proofs.append(proof)
        return errors
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        return ['unreadable or invalid evidence: ' + str(error)]


def assess(data: dict, identity: str, root: Path = ROOT) -> list[str]:
    failures = []
    bundle_cache = {}
    if not isinstance(data, dict):
        return ['criterion assessment must be an object']
    if data.get('source') != identity:
        failures.append('criterion assessment belongs to a different technical source')
    criteria = data.get('criteria', [])
    if not isinstance(criteria, list):
        return failures + ['criterion set must be a list']
    expected = {f'AC-{i:03d}' for i in range(1,25)}
    if {c.get('id') for c in criteria if isinstance(c, dict)} != expected or len(criteria) != 24:
        failures.append('criterion set incomplete or duplicated')
    for criterion in criteria:
        if not isinstance(criterion, dict):
            failures.append('invalid criterion');continue
        label = str(criterion.get('id', 'unknown'))
        if criterion.get('status') != 'PASS':
            failures.append(label + ': ' + str(criterion.get('status', 'NOT RUN')))
        refs = criterion.get('receipts', [])
        if not isinstance(refs, list) or not refs:
            failures.append(label + ': no typed evidence');continue
        for ref in refs:
            failures.extend(label + ': ' + problem for problem in validate_reference(ref, identity, root, bundle_cache=bundle_cache))
    gates = data.get('gate_evidence', {})
    if not isinstance(gates, dict):
        gates = {}
    for key, kind in GATE_KINDS.items():
        if data.get(key) is not True:
            failures.append('required gate: ' + key)
        refs = gates.get(key, [])
        if not isinstance(refs, list) or not refs:
            failures.append(key + ': typed gate evidence missing');continue
        proofs = []
        for ref in refs:
            failures.extend(key + ': ' + problem for problem in validate_reference(ref, identity, root, kind,
                             bundle_cache=bundle_cache, benchmark_proofs=proofs))
        if key == 'full_benchmark_complete':
            try:
                reference_qualification.validate_profiles(proofs)
            except (ValueError, TypeError, KeyError) as error:
                failures.append(key + ': ' + str(error))
    return failures


def main():
    path = ROOT/'verification/criterion_status.json'
    if not path.exists():
        print('NOT RUN: criterion evidence not yet assembled');return 2
    try:
        failures = assess(json.loads(path.read_text()), source_hash())
    except (OSError, ValueError, TypeError) as error:
        failures = ['invalid assessment: ' + str(error)]
    print(json.dumps({'status': 'FAIL' if failures else 'PASS', 'failures': failures,
                      'note': 'Repository-local assessment is not third-party attestation; independently inspect linked evidence.'}, indent=2))
    return 1 if failures else 0
if __name__ == '__main__':raise SystemExit(main())
