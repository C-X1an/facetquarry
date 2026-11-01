"""Durable bounded substage observations, without verification authority."""
from __future__ import annotations

from contextlib import contextmanager
import os
import time

STAGES = ('admission', 'bundle_decode', 'manifest_read', 'first_comparison',
          'revalidation', 'second_comparison', 'freeze', 'retained_outer_validation')


class Progress:
    def __init__(self, path, record, write, utc):
        self.path, self.record, self.write, self.utc = path, record, write, utc
        self.next_stage = 0
        record['verification_stages'] = []
        record['active_verification_stage'] = None

    def publish(self):
        self.write(self.path, self.record, replace=True)
        if os.name == 'posix':
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)

    @contextmanager
    def stage(self, name):
        if (self.next_stage >= len(STAGES) or STAGES[self.next_stage] != name
                or len(self.record['verification_stages']) != self.next_stage
                or self.record['active_verification_stage'] is not None):
            raise ValueError('verification substage order differs')
        row = {'stage': name, 'state': 'RUNNING', 'started_at': self.utc()}
        self.record['verification_stages'].append(row)
        self.record['active_verification_stage'] = name
        self.publish()  # Before any operation belonging to this substage.
        started = time.monotonic()
        try:
            yield
        except BaseException:
            row.update(state='FAIL', ended_at=self.utc(), duration_seconds=time.monotonic() - started)
            self.publish()  # Active stage retained for both caught and hard cutoffs.
            raise
        else:
            row.update(state='COMPLETE', ended_at=self.utc(), duration_seconds=time.monotonic() - started)
            self.record['active_verification_stage'] = None
            self.next_stage += 1
            self.publish()


def complete(record):
    rows = record.get('verification_stages', [])
    return (type(rows) is list and len(rows) == len(STAGES)
            and record.get('active_verification_stage') is None
            and all(type(row) is dict and row.get('stage') == name
                    and row.get('state') == 'COMPLETE'
                    for name, row in zip(STAGES, rows)))
