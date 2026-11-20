import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
COMMON_SCRIPT = SCRIPT_DIR / 'profuzzbench_exec_common_dev.sh'
ALL_SCRIPT = SCRIPT_DIR / 'profuzzbench_exec_all_dev.sh'
DAAP_SCRIPT = SCRIPT_DIR / '../../subjects/DAAP/forked-daapd/run.sh'
RUN_SCRIPTS = [
    SCRIPT_DIR / '../../subjects/FTP/BFTPD/run.sh',
    SCRIPT_DIR / '../../subjects/FTP/ProFTPD/run.sh',
    SCRIPT_DIR / '../../subjects/FTP/LightFTP/run.sh',
    DAAP_SCRIPT,
]


def extract_function(script_path, function_name):
    lines = script_path.read_text().splitlines()
    start = lines.index(f'{function_name}() {{')
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == '}')
    return '\n'.join(lines[start:end + 1]) + '\n'


class ExecutionFailurePropagationTests(unittest.TestCase):
    def run_bash(self, body):
        return subprocess.run(['bash', '-c', body], text=True, capture_output=True)

    def common_harness(self, root, helper, manifest=True):
        result_dir = root / 'results'
        result_dir.mkdir(exist_ok=True)
        manifest_path = result_dir / '.result_manifest.tsv'
        if manifest:
            manifest_path.touch()
        else:
            manifest_path.unlink(missing_ok=True)
        return '\n'.join([
            'set -u',
            f'SCRIPT_DIR={str(SCRIPT_DIR)!r}',
            f'SAVETO={str(result_dir)!r}',
            f'RESULT_MANIFEST={str(manifest_path)!r}',
            f'RECOVERY_HELPER={str(helper)!r}',
            'LOG_TAG=test',
            'RUN_COMPLETED=0',
            'DELETE=',
            'COLLECTION_DONE=0',
            'COLLECTION_COMPLETE=0',
            'COLLECTION_STATUS=0',
            'fix_result_permissions() { :; }',
            extract_function(COMMON_SCRIPT, 'collect_results_with_recovery'),
        ])

    def test_common_recovery_failure_survives_repeated_collection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            helper = root / 'recover.sh'
            helper.write_text('exit 23\n')
            body = self.common_harness(root, helper) + '\n'.join([
                'for expected in 23 23; do',
                '  if collect_results_with_recovery; then exit 90; else actual=$?; fi',
                '  [[ "$actual" -eq "$expected" ]] || exit 91',
                'done',
                '[[ "$COLLECTION_STATUS" -eq 23 ]]',
            ])
            result = self.run_bash(body)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_common_success_is_cached_and_marks_collection_complete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            helper = root / 'recover.sh'
            helper.write_text('exit 0\n')
            body = self.common_harness(root, helper) + '\n'.join([
                'collect_results_with_recovery || exit 93',
                'collect_results_with_recovery || exit 94',
                '[[ "$COLLECTION_COMPLETE" -eq 1 && "$COLLECTION_STATUS" -eq 0 ]]',
            ])
            result = self.run_bash(body)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_common_final_exit_code_includes_recovery_failure(self):
        script = COMMON_SCRIPT.read_text()
        final_status = script.split('RUN_EXIT_STATUS=0\n', 1)[1].split('trap - EXIT INT TERM', 1)[0]
        for collection_status, expected in ((0, 0), (7, 1)):
            with self.subTest(collection_status=collection_status):
                body = '\n'.join([
                    f'COLLECTION_STATUS={collection_status}',
                    'archive_names=()',
                    'read_sample_status_value() { return 0; }',
                    'RUN_EXIT_STATUS=0',
                    final_status,
                    'exit "$RUN_EXIT_STATUS"',
                ])
                result = self.run_bash(body)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_common_missing_manifest_or_helper_is_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            missing_helper = root / 'missing.sh'
            for helper, manifest in ((missing_helper, True), (root / 'recover.sh', False)):
                with self.subTest(helper=helper.name, manifest=manifest):
                    body = self.common_harness(root, helper, manifest)
                    body += '\nif collect_results_with_recovery; then exit 92; else [[ $? -eq 1 ]]; fi'
                    result = self.run_bash(body)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_dev_final_recovery_failure_and_missing_helper_set_exec_fail(self):
        function = extract_function(ALL_SCRIPT, 'run_final_recovery_pass')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            result_dir = root / 'results-sample_test-run'
            result_dir.mkdir()
            fail_helper = root / 'recover-fail.sh'
            fail_helper.write_text('exit 17\n')
            ok_helper = root / 'recover-ok.sh'
            ok_helper.write_text('exit 0\n')
            for helper, expected in ((ok_helper, 0), (fail_helper, 1), (root / 'missing.sh', 1)):
                with self.subTest(helper=helper.name):
                    body = '\n'.join([
                        f'RESULTS_ROOT={str(root)!r}',
                        "TIMESTAMP='test-run'",
                        f'RECOVERY_HELPER={str(helper)!r}',
                        'EXEC_FAIL=0',
                        'fix_result_permissions() { :; }',
                        function,
                        'run_final_recovery_pass',
                        f'[[ "$EXEC_FAIL" -eq {expected} ]]',
                    ])
                    result = self.run_bash(body)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_dev_waits_for_fast_failed_jobs_by_saved_pid(self):
        text = ALL_SCRIPT.read_text()
        wait_block = text.split("EXEC_FAIL=0\n", 1)[1].split(
            "RECOVERY_HELPER=", 1)[0]
        launch_lines = [line for line in text.splitlines()
                        if 'EXEC_PIDS+=("$!")' in line]
        self.assertTrue(launch_lines)
        self.assertTrue(all('EXEC_PIDS+=("$!")' in line for line in launch_lines))
        body = '\n'.join([
            'EXEC_PIDS=()',
            'false & EXEC_PIDS+=("$!")',
            'sleep 0.05',
            'EXEC_FAIL=0',
            wait_block,
            '[[ "$EXEC_FAIL" -eq 1 ]]',
        ])
        result = self.run_bash(body)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_daap_replay_and_terminal_validation_require_successful_cd(self):
        text = DAAP_SCRIPT.read_text()
        section = text.split('#Step-2. Collect code coverage over time', 1)[1].split('#Step-3.', 1)[0]
        self.assertIn('if cd "$WORKDIR"; then', section)
        success_branch, failure_branch = section.split('\n  else\n', 1)
        self.assertIn('cov_script ', success_branch)
        self.assertIn('validate_loopfuzz_terminal ', success_branch)
        self.assertNotIn('cov_script ', failure_branch)
        self.assertNotIn('validate_loopfuzz_terminal ', failure_branch)

    def test_all_loopfuzz_subjects_accept_one_complete_v4_or_v5_terminal(self):
        for script in RUN_SCRIPTS:
            function = extract_function(script, 'validate_loopfuzz_terminal')
            with self.subTest(script=script):
                for version in (4, 5):
                    with tempfile.TemporaryDirectory() as temp:
                        root = Path(temp)
                        terminal_dir = root / f'cov_over_time.csv.v{version}'
                        terminal_dir.mkdir()
                        schema = ('loopfuzz-coverage-v5-sampled-checkpoints'
                                  if version == 5 else 'loopfuzz-coverage-v4')
                        terminal = terminal_dir / 'terminal.json'
                        terminal.write_text(
                            f'{{"schema_version":"{schema}",'
                            '"coverage_complete":true,"acceptance":"complete"}')
                        result = self.run_bash(
                            f'FUZZER=loopfuzz\n{function}\n'
                            f'validate_loopfuzz_terminal {str(root)!r}')
                        self.assertEqual(result.returncode, 0, result.stderr)

    def test_terminal_validator_rejects_duplicates_incomplete_and_wrong_schema(self):
        for script in RUN_SCRIPTS:
            function = extract_function(script, 'validate_loopfuzz_terminal')
            with self.subTest(script=script):
                for terminals in (
                    {},
                    {'v4': ('loopfuzz-coverage-v4', False, 'incomplete')},
                    {'v5': ('loopfuzz-coverage-v4', True, 'complete')},
                    {
                        'v4': ('loopfuzz-coverage-v4', True, 'complete'),
                        'v5': ('loopfuzz-coverage-v5-sampled-checkpoints', True, 'complete'),
                    },
                ):
                    with tempfile.TemporaryDirectory() as temp:
                        root = Path(temp)
                        for version, (schema, complete, acceptance) in terminals.items():
                            terminal_dir = root / f'cov_over_time.csv.{version}'
                            terminal_dir.mkdir()
                            (terminal_dir / 'terminal.json').write_text(
                                f'{{"schema_version":"{schema}",'
                                f'"coverage_complete":{str(complete).lower()},'
                                f'"acceptance":"{acceptance}"}}')
                        result = self.run_bash(
                            f'FUZZER=loopfuzz\n{function}\n'
                            f'validate_loopfuzz_terminal {str(root)!r}')
                        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
