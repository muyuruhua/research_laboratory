import unittest

from reconcile_result_status import reconcile_values


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


if __name__ == '__main__':
    unittest.main()
