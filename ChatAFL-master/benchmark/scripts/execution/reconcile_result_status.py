#!/usr/bin/env python3
"""Reconcile collected sample status with actual Docker state, without reruns."""

import argparse
import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile


def archive_present(path):
    """File completeness is distinct from scientific coverage acceptance."""
    if not path.is_file():
        return False
    try:
        with tarfile.open(path) as archive:
            names = [m.name for m in archive if m.isfile()]
        return (any(n.endswith('/fuzzer_stats') for n in names) and
                any(n.endswith('/cov_over_time.csv') for n in names) and
                sum(n.endswith(('/cov_over_time.csv.v4/terminal.json',
                                '/cov_over_time.csv.v5/terminal.json')) for n in names) == 1)
    except (OSError, tarfile.TarError):
        return False


def reconcile_values(previous, row, actual, complete):
    if actual['Id'] != row['container_id']:
        raise ValueError('Docker identity does not match manifest')
    state = actual['State']
    if state['Running'] or state['Status'] not in ('exited', 'dead'):
        return None
    code = state['ExitCode']
    passed = code == 0 and complete and not state['OOMKilled']
    return dict(previous, archive_name=row['archive_name'], container_id=actual['Id'],
                status='completed' if passed else 'failed',
                reason=('completed' if passed else
                        f'exit_code_{code}' if code else
                        'oom_killed' if state['OOMKilled'] else 'archive_incomplete_or_missing'),
                exit_code=str(code), oom_killed=str(state['OOMKilled']).lower(),
                finished_at=state['FinishedAt'], container_status=state['Status'],
                archive_files_complete=str(complete).lower())


def reconcile(directory):
    manifest = directory / '.result_manifest.tsv'
    with manifest.open() as stream:
        rows = list(csv.DictReader(stream, delimiter='\t'))
    report = []
    for row in rows:
        cid = row['container_id']
        try:
            result = subprocess.run(['docker', 'inspect', cid], text=True,
                                    capture_output=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            report.append(dict(archive=row['archive_name'], error='container inspection unavailable'))
            continue
        if result.returncode:
            report.append(dict(archive=row['archive_name'], error='container unavailable'))
            continue
        actual = json.loads(result.stdout)[0]
        path = directory / '.sample_status' / (row['archive_name'] + '.status')
        original = path.read_text() if path.exists() else ''
        previous = dict(line.split('=', 1) for line in original.splitlines() if '=' in line)
        values = reconcile_values(previous, row, actual,
                                  archive_present(directory / row['archive_name']))
        if values is None:
            report.append(dict(archive=row['archive_name'], action='running; unchanged'))
            continue
        content = ''.join(f'{key}={value}\n' for key, value in values.items())
        if original != content:
            path.parent.mkdir(exist_ok=True)
            backup = path.with_suffix(path.suffix + '.before-reconcile')
            if original and not backup.exists():
                backup.write_text(original)
            temporary = path.with_suffix(path.suffix + '.tmp')
            temporary.write_text(content)
            os.replace(temporary, path)
        report.append(dict(archive=row['archive_name'], status=values['status'],
                           reason=values['reason'], exit_code=values['exit_code']))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    arguments = parser.parse_args()
    report = reconcile(arguments.directory)
    print(json.dumps(report, indent=2))
    sys.exit(1 if any('error' in item for item in report) else 0)
