"""Explicit transport time policies; pure/default APIs retain legacy bounds.

The longer verification policy changes time reservation only. It does not
remove comparisons, extend the benchmark, or establish measured completion.
"""
from __future__ import annotations

LEGACY = 'legacy'
VERIFY_600 = 'reference-verify-600s-v1'
POLICIES = (LEGACY, VERIFY_600)


def checked(policy):
    if type(policy) is not str or policy not in POLICIES:
        raise ValueError('unknown explicit transport time policy')
    return policy


def phase_seconds(phase, policy=LEGACY):
    checked(policy)
    if phase not in ('pack', 'verify', 'reconcile'):
        raise ValueError('unknown transport time phase')
    return {'pack': 1710, 'verify': 600 if policy == VERIFY_600 else 210,
            'reconcile': 180}[phase]


def receipt_policy(receipt, expected=None):
    """Recognize a receipt's fixed policy, optionally bind a caller's choice."""
    policy = checked(receipt.get('time_policy', LEGACY))
    if expected is not None and policy != checked(expected):
        raise ValueError('transport time policy differs from explicit selection')
    return policy


def keywords(policy):
    """Keep legacy call signatures usable by existing fixture adapters."""
    return {} if checked(policy) == LEGACY else {'time_policy': policy}
