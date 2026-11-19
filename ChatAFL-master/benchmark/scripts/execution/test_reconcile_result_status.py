import io
import json
from pathlib import Path
import shlex
import subprocess
import tarfile
import tempfile
import unittest

from reconcile_result_status import archive_present, coverage_acceptance, reconcile_values


class ReconcileStatusTests(unittest.TestCase):
    def setUp(self):
        self.row = {'container_id': 'cid', 'archive_name': 'out-test_1.tar.gz'}
        self.actual = {'Id': 'cid', 'State': dict(Running=False, Status='exited',
                       ExitCode=137, OOMKilled=False, FinishedAt='2026-11-17T01:00:00Z')}

    def test_stale_running_is_failed_on_actual_nonzero_exit(self):
        result = reconcile_values({'status': 'running'}, self.row, self.actual, True)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['reason'], 'exit_code_137')
        self.assertEqual(result['oom_killed'], 'false')

    def test_exit_zero_with_missing_evidence_is_failed(self):
        self.actual['State']['ExitCode'] = 0
        result = reconcile_values({}, self.row, self.actual, False)
        self.assertEqual(result['reason'], 'archive_incomplete_or_missing')

    def test_live_container_is_never_finalized(self):
        self.actual['State'].update(Running=True, Status='running')
        self.assertIsNone(reconcile_values({}, self.row, self.actual, False))

    def test_wrong_container_cannot_supply_status(self):
        self.actual['Id'] = 'other'
        with self.assertRaises(ValueError):
            reconcile_values({}, self.row, self.actual, True)

    def test_oom_is_failed_even_if_docker_records_zero_exit(self):
        self.actual['State'].update(ExitCode=0, OOMKilled=True)
        result = reconcile_values({}, self.row, self.actual, True)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['reason'], 'oom_killed')

    def test_complete_archive_with_incomplete_coverage_is_failed(self):
        self.actual['State']['ExitCode'] = 0
        result = reconcile_values({'status': 'completed'}, self.row, self.actual,
                                  True, 'incomplete')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['reason'], 'coverage_incomplete')
        self.assertEqual(result['archive_files_complete'], 'true')
        self.assertEqual(result['coverage_acceptance'], 'incomplete')

    def test_missing_acceptance_never_promotes_a_sample(self):
        self.actual['State']['ExitCode'] = 0
        result = reconcile_values({}, self.row, self.actual, True)
        self.assertEqual(result['reason'], 'coverage_evidence_invalid')

    def test_complete_terminal_allows_completed_status(self):
        self.actual['State']['ExitCode'] = 0
        result = reconcile_values({}, self.row, self.actual, True, 'complete')
        self.assertEqual(result['status'], 'completed')


class ArchiveAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, version, complete=True, **overrides):
        schema = ('loopfuzz-coverage-v5-sampled-checkpoints' if version == 5
                  else 'loopfuzz-coverage-v4')
        terminal = dict(schema_version=schema, scope_sha256='a' * 64,
                        covered_branch_ids=[], covered_line_ids=[], n_replayed=2,
                        coverage_complete=complete,
                        acceptance='complete' if complete else 'incomplete')
        terminal.update(overrides)
        scope = dict(schema_version=schema, scope_sha256='a' * 64)
        archive_path = self.root / 'out-test_1.tar.gz'
        with tarfile.open(archive_path, 'w:gz') as stream:
            contents = {'out-test/fuzzer_stats': b'', 'out-test/cov_over_time.csv': b''}
            parent = f'out-test/cov_over_time.csv.v{version}'
            contents[parent + '/terminal.json'] = json.dumps(terminal).encode()
            contents[parent + '/scope.json'] = json.dumps(scope).encode()
            for name, value in contents.items():
                member = tarfile.TarInfo(name)
                member.size = len(value)
                stream.addfile(member, io.BytesIO(value))
        return archive_path

    def test_v4_and_v5_acceptance_and_file_completeness_are_distinct(self):
        for version in (4, 5):
            for complete in (True, False):
                with self.subTest(version=version, complete=complete):
                    archive = self.archive(version, complete)
                    self.assertTrue(archive_present(archive))
                    self.assertEqual(coverage_acceptance(archive),
                                     'complete' if complete else 'incomplete')

    def test_contradictory_acceptance_and_scope_identity_are_rejected(self):
        for overrides in (dict(coverage_complete=False), dict(scope_sha256='b' * 64),
                          dict(n_replayed=True), dict(covered_branch_ids=None)):
            with self.subTest(overrides=overrides):
                archive = self.archive(5, **overrides)
                with self.assertRaises(ValueError):
                    coverage_acceptance(archive)

    def test_runner_final_status_checks_terminal_not_just_exit_code(self):
        script_dir = Path(__file__).resolve().parent
        script = (script_dir / 'profuzzbench_exec_common_dev.sh').read_text().splitlines()
        definitions = []
        for name in ('archive_is_complete', 'finalize_sample_status'):
            start = script.index(name + '() {')
            end = next(index for index in range(start + 1, len(script)) if script[index] == '}')
            definitions.append('\n'.join(script[start:end + 1]))
        for complete in (True, False):
            with self.subTest(complete=complete):
                self.archive(5, complete)
                body = '\n'.join([
                    'set -euo pipefail',
                    'SCRIPT_DIR=' + shlex.quote(str(script_dir)),
                    'SAVETO=' + shlex.quote(str(self.root)),
                    'FUZZER=loopfuzz',
                    'source "$SCRIPT_DIR/archive_contract.sh"',
                    'cids=(cid)', 'archive_names=(out-test_1.tar.gz)',
                    'docker() { if [[ "$3" == *ExitCode* ]]; then echo 0; else echo false; fi; }',
                    'write_sample_status() { shift; printf "%s\\n" "$@"; }',
                    *definitions, 'finalize_sample_status'])
                result = subprocess.run(['bash', '-c', body], text=True,
                                        capture_output=True, check=True)
                values = dict(line.split('=', 1) for line in result.stdout.splitlines())
                self.assertEqual(values['status'], 'completed' if complete else 'failed')
                self.assertEqual(values['reason'], 'completed' if complete else 'coverage_incomplete')
                self.assertEqual(values['archive_files_complete'], 'true')

    def test_only_explicit_legacy_baseline_can_omit_terminal(self):
        archive_path = self.root / 'out-test_1.tar.gz'
        with tarfile.open(archive_path, 'w:gz') as stream:
            for name in ('out-test/fuzzer_stats', 'out-test/cov_over_time.csv'):
                stream.addfile(tarfile.TarInfo(name), io.BytesIO(b''))
        self.assertFalse(archive_present(archive_path))
        self.assertTrue(archive_present(archive_path, require_terminal=False))
        with self.assertRaises(ValueError):
            coverage_acceptance(archive_path)
        self.assertEqual(coverage_acceptance(archive_path, allow_legacy=True), 'not_applicable')


if __name__ == '__main__':
    unittest.main()
