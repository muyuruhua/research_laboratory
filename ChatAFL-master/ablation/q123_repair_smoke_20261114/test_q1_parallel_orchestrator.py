import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("q1_parallel_orchestrator.py")
SPEC = importlib.util.spec_from_file_location("q1_parallel_orchestrator", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ParallelAdmissionTests(unittest.TestCase):
    def test_reserves_peak_for_existing_and_new_target(self):
        admitted, free_mb, required_mb = MODULE.admission(
            avail_mb=46000, running_fuzzers=0, active_tasks=0,
            repeats=3, arms=1, estimate_mb=2048, reserve_mb=8192,
        )
        self.assertTrue(admitted)
        self.assertEqual(required_mb, 7168)
        self.assertEqual(free_mb, 37808)

    def test_reserves_not_yet_visible_containers_for_active_tasks(self):
        admitted, free_mb, required_mb = MODULE.admission(
            avail_mb=38000, running_fuzzers=3, active_tasks=4,
            repeats=3, arms=1, estimate_mb=2048, reserve_mb=8192,
        )
        self.assertFalse(admitted)
        self.assertEqual(required_mb, 7168)
        self.assertEqual(free_mb, 1136)

    def test_result_dirs_are_bound_to_target_and_arm(self):
        import tempfile

        text = (
            "[ABLATION:q1a1] 启动 → ablation/results-exim_ablation_q1a1_20261117T010203/\n"
            "[ABLATION:q1b1] 启动 → ablation/results-live555_ablation_q1b1_20261117T010203/\n"
            "[ABLATION:q1c1] 启动 → ablation/results-exim_ablation_q1c1_20261117T010203/\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "launch.log"
            log.write_text(text, encoding="utf-8")
            dirs = MODULE.parse_pinned_dirs(log, "exim")
        self.assertEqual(set(dirs), {"q1a1", "q1c1"})


if __name__ == "__main__":
    unittest.main()
