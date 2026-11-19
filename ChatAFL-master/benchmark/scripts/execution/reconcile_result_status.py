#!/usr/bin/env python3
"""Reconcile collected sample status with actual Docker state, without reruns."""

import argparse
import csv
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile


def archive_present(path, require_terminal=True):
    """File completeness is distinct from scientific coverage acceptance."""
    if not path.is_file():
        return False
    try:
        with tarfile.open(path) as archive:
            names = [m.name for m in archive if m.isfile()]
        terminal_count = sum(n.endswith(('/cov_over_time.csv.v4/terminal.json',
                                        '/cov_over_time.csv.v5/terminal.json')) for n in names)
        legacy = (not require_terminal and not any(
            re.search(r'/cov_over_time\.csv\.v[45]/', n) for n in names))
        return (any(n.endswith('/fuzzer_stats') for n in names) and
                any(n.endswith('/cov_over_time.csv') for n in names) and
                (terminal_count == 1 or legacy))
    except (OSError, tarfile.TarError):
        return False


def coverage_acceptance(path, allow_legacy=False):
    """Read the endpoint's acceptance; file collection alone is insufficient.

    This validates the terminal/scope contract, not the full coverage ledger.
    The coverage module's independent audit remains necessary for publication.
    """
    with tarfile.open(path) as archive:
        members = [member for member in archive if member.isfile()]
        terminals = [member for member in members if member.name.endswith(
            ('/cov_over_time.csv.v4/terminal.json',
             '/cov_over_time.csv.v5/terminal.json'))]
        if not terminals and allow_legacy and not any(
                re.search(r'/cov_over_time\.csv\.v[45]/', member.name) for member in members):
            return 'not_applicable'
        if len(terminals) != 1:
            raise ValueError('expected one coverage terminal')
        member = terminals[0]
        schema = ('loopfuzz-coverage-v5-sampled-checkpoints'
                  if '/cov_over_time.csv.v5/' in member.name else 'loopfuzz-coverage-v4')
        scopes = [item for item in members
                  if item.name == member.name.rsplit('/', 1)[0] + '/scope.json']
        if len(scopes) != 1:
            raise ValueError('expected one matching coverage scope')
        terminal = json.load(archive.extractfile(member))
        scope = json.load(archive.extractfile(scopes[0]))
        if not isinstance(terminal, dict) or not isinstance(scope, dict):
            raise ValueError('coverage terminal/scope must be objects')
        if terminal.get('schema_version') != schema or scope.get('schema_version') != schema:
            raise ValueError('coverage terminal/scope schema mismatch')
        scope_hash = terminal.get('scope_sha256')
        if (not isinstance(scope_hash, str) or not re.fullmatch('[0-9a-f]{64}', scope_hash)
                or scope.get('scope_sha256') != scope_hash):
            raise ValueError('coverage terminal/scope identity mismatch')
        if (not isinstance(terminal.get('covered_branch_ids'), list)
                or not isinstance(terminal.get('covered_line_ids'), list)):
            raise ValueError('coverage identity lists missing')
        n_replayed = terminal.get('n_replayed')
        if type(n_replayed) is not int or n_replayed < 0:
            raise ValueError('invalid replay count')
        complete = terminal.get('coverage_complete')
        acceptance = terminal.get('acceptance')
        if (type(complete) is not bool or acceptance not in ('complete', 'incomplete')
                or (acceptance == 'complete') != complete):
            raise ValueError('inconsistent coverage acceptance')
        return acceptance


def reconcile_values(previous, row, actual, complete, acceptance='unknown'):
    if actual['Id'] != row['container_id']:
        raise ValueError('Docker identity does not match manifest')
    state = actual['State']
    if state['Running'] or state['Status'] not in ('exited', 'dead'):
        return None
    code = state['ExitCode']
    coverage_ok = (acceptance == 'complete' or
                   acceptance == 'not_applicable' and row.get('fuzzer', 'loopfuzz') != 'loopfuzz')
    passed = code == 0 and complete and coverage_ok and not state['OOMKilled']
    return dict(previous, archive_name=row['archive_name'], container_id=actual['Id'],
                status='completed' if passed else 'failed',
                reason=('completed' if passed else
                        f'exit_code_{code}' if code else
                        'oom_killed' if state['OOMKilled'] else
                        'archive_incomplete_or_missing' if not complete else
                        'coverage_incomplete' if acceptance == 'incomplete' else
                        'coverage_evidence_invalid'),
                exit_code=str(code), oom_killed=str(state['OOMKilled']).lower(),
                finished_at=state['FinishedAt'], container_status=state['Status'],
                archive_files_complete=str(complete).lower(), coverage_acceptance=acceptance)


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
        archive_path = directory / row['archive_name']
        require_terminal = row.get('fuzzer', 'loopfuzz') == 'loopfuzz'
        complete = archive_present(archive_path, require_terminal)
        try:
            acceptance = coverage_acceptance(archive_path, not require_terminal) if complete else 'unknown'
        except (OSError, tarfile.TarError, ValueError, KeyError, TypeError):
            acceptance = 'invalid'
        values = reconcile_values(previous, row, actual, complete, acceptance)
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
    parser.add_argument('directory', type=Path, nargs='?')
    parser.add_argument('--archive-acceptance', type=Path,
                        help='print terminal acceptance without changing any files')
    parser.add_argument('--allow-legacy', action='store_true',
                        help='allow baseline archives without v4/v5 artifacts')
    arguments = parser.parse_args()
    if arguments.archive_acceptance:
        try:
            print(coverage_acceptance(arguments.archive_acceptance, arguments.allow_legacy))
        except (OSError, tarfile.TarError, ValueError, KeyError, TypeError) as error:
            print(str(error), file=sys.stderr)
            sys.exit(1)
        sys.exit(0)
    if arguments.directory is None:
        parser.error('directory or --archive-acceptance is required')
    report = reconcile(arguments.directory)
    print(json.dumps(report, indent=2))
    sys.exit(1 if any('error' in item for item in report) else 0)
