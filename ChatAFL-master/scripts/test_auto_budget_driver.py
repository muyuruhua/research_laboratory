"""Offline orchestration checks: no real gateway or Docker is contacted."""

import contextlib
from concurrent.futures import ThreadPoolExecutor
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "auto_budget_driver", Path(__file__).resolve().parents[1] / "run_ablation_auto_budget.py")
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


class AutoBudgetDriverTests(unittest.TestCase):
    def run_main(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return driver.main(args)

    def test_dry_run_never_launches_or_freezes(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(driver.subprocess, "Popen") as launch, \
                patch.object(driver.subprocess, "run") as command, patch.object(driver, "write_json") as write:
            self.assertEqual(self.run_main(["bftpd", "3", "60", "--dry-run"]), 0)
            launch.assert_not_called()
            command.assert_not_called()
            write.assert_not_called()

    def test_mock_and_non_three_repeat_are_rejected(self):
        for environment, args in [({"CHATAFL_MOCK_LLM": "1"}, ["bftpd", "3", "1440", "--dry-run"]),
                                  ({}, ["bftpd", "1", "1440", "--dry-run"])]:
            with patch.dict(os.environ, environment, clear=True), self.assertRaises(SystemExit):
                self.run_main(args)

    def test_failed_calibration_never_starts_formal(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(driver, "ROOT", Path(tmp)), \
                patch.dict(os.environ, {"KEY": "fixture-not-a-real-key"}, clear=True), \
                patch.object(driver, "context_hash", return_value="source-settings"), \
                patch.object(driver, "launch_phase", side_effect=RuntimeError("pilot failed")) as launch, \
                patch.object(driver, "audit_phase") as audit:
            self.assertEqual(self.run_main(["bftpd", "3", "1440", "-g", "q1a512"]), 1)
            self.assertEqual(launch.call_count, 1)
            audit.assert_not_called()
            directory = next((Path(tmp) / "ablation").iterdir())
            self.assertFalse((directory / "formal-manifest.json").exists())
            self.assertEqual(json.loads((directory / "completion.json").read_text())["status"], "failed")

    def test_frozen_budget_is_shared_and_formal_clock_uses_input(self):
        phases = []

        def launch(manifest, minutes, budget, environment, log):
            phases.append((manifest, minutes, budget))

        def calculate(command, **kwargs):
            path = Path(command[command.index("--output") + 1])
            driver.write_json(path, {"q1_common_call_budget": 123456, "target": "bftpd",
                                    "formal_duration_seconds": 3600})

        with tempfile.TemporaryDirectory() as tmp, patch.object(driver, "ROOT", Path(tmp)), \
                patch.dict(os.environ, {"KEY": "fixture-not-a-real-key"}, clear=True), \
                patch.object(driver, "context_hash", return_value="source-settings"), \
                patch.object(driver, "launch_phase", side_effect=launch), \
                patch.object(driver, "audit_phase"), \
                patch.object(driver.subprocess, "run", side_effect=calculate):
            self.assertEqual(self.run_main(["bftpd", "3", "60"]), 0)
            pilot, formal = phases
            self.assertEqual(pilot[2], driver.PILOT_CAP)
            self.assertNotIn("q1b512", pilot[0]["expected_arms"])
            self.assertEqual(formal[1:], (60, 123456))
            self.assertEqual(len(formal[0]["runs"]), 39)
            self.assertEqual(len(pilot[0]["runs"]), 36)
            self.assertNotEqual(pilot[0]["batch_id"], formal[0]["batch_id"])
            directory = next((Path(tmp) / "ablation").iterdir())
            self.assertNotIn("fixture-not-a-real-key", "".join(p.read_text() for p in directory.glob("*.json")))

    def test_reuse_requires_same_target_time_settings_and_live_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "budget.json"
            report = {"q1_common_call_budget": 123456, "target": "bftpd",
                      "formal_duration_seconds": 86400, "launch_context_sha256": "fingerprint",
                      "pilot_live_audit_passed": True}
            driver.write_json(path, report)
            self.assertEqual(driver.read_frozen_budget(path, "bftpd", 1440, "fingerprint"), 123456)
            for target, minutes, fingerprint in [("exim", 1440, "fingerprint"),
                                                 ("bftpd", 60, "fingerprint"),
                                                 ("bftpd", 1440, "other")]:
                with self.assertRaises(ValueError):
                    driver.read_frozen_budget(path, target, minutes, fingerprint)
            report["pilot_live_audit_passed"] = False
            driver.write_json(path, report)
            with self.assertRaises(ValueError):
                driver.read_frozen_budget(path, "bftpd", 1440, "fingerprint")

    @contextlib.contextmanager
    def cached_fixture(self, tmp):
        phases = []

        def launch(manifest, minutes, budget, environment, log):
            phases.append((manifest, minutes, budget))
            if manifest["batch_id"].startswith("formal-"):
                # A long formal campaign must not hold the calibration lock.
                for lock_path in (Path(tmp) / "ablation/budget-cache").glob("*.lock"):
                    with lock_path.open("a+") as lock:
                        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

        def calculate(command, **kwargs):
            path = Path(command[command.index("--output") + 1])
            manifest = json.loads(Path(command[command.index("--manifest") + 1]).read_text())
            driver.write_json(path, {"q1_common_call_budget": 123456, "target": manifest["target"],
                                    "formal_duration_seconds": manifest["formal_duration_seconds"]})

        with patch.object(driver, "ROOT", Path(tmp)), \
                patch.dict(os.environ, {"KEY": "fixture-not-a-real-key"}, clear=True), \
                patch.object(driver, "context_hash", side_effect=lambda target, minutes, env:
                             f"{target}-{minutes}-{env.get('SKIPCOUNT', '100')}"), \
                patch.object(driver, "launch_phase", side_effect=launch) as launch_mock, \
                patch.object(driver, "audit_phase") as audit_mock, \
                patch.object(driver.subprocess, "run", side_effect=calculate) as calculate_mock:
            yield phases, launch_mock, audit_mock, calculate_mock

    def test_shared_cache_first_calibrates_then_other_arm_reuses_exact_budget(self):
        with tempfile.TemporaryDirectory() as tmp, self.cached_fixture(tmp) as (phases, _, _, calculator):
            self.assertEqual(self.run_main(["bftpd", "3", "1500", "-g", "q1a512", "--reuse-or-calibrate"]), 0)
            cache = next((Path(tmp) / "ablation/budget-cache").glob("*.json"))
            frozen = json.loads(cache.read_text())["frozen_budget_file"]
            self.assertTrue(Path(frozen).is_absolute())
            self.assertEqual(self.run_main(["bftpd", "3", "1500", "-g", "q1c512", "--reuse-or-calibrate"]), 0)
            self.assertEqual(calculator.call_count, 1)
            self.assertEqual(len(phases), 3)
            self.assertEqual(phases[0][2], driver.PILOT_CAP)
            self.assertEqual([phase[2] for phase in phases[1:]], [123456, 123456])
            self.assertEqual([phase[0]["frozen_budget_file"] for phase in phases[1:]], [frozen, frozen])
            self.assertEqual(phases[-1][0]["expected_arms"], ["q1c512"])

    def test_shared_cache_failed_pilot_audit_does_not_publish_or_launch_formal(self):
        with tempfile.TemporaryDirectory() as tmp, self.cached_fixture(tmp) as (phases, _, audit, calculator):
            audit.side_effect = RuntimeError("pilot audit failed")
            self.assertEqual(self.run_main(["bftpd", "3", "1500", "--reuse-or-calibrate"]), 1)
            self.assertEqual(len(phases), 1)
            calculator.assert_not_called()
            self.assertEqual(list((Path(tmp) / "ablation/budget-cache").glob("*.json")), [])

    def test_shared_cache_failed_formal_preserves_audited_budget(self):
        with tempfile.TemporaryDirectory() as tmp, self.cached_fixture(tmp) as (phases, _, audit, calculator):
            audit.side_effect = [None, RuntimeError("formal audit failed"), None]
            self.assertEqual(self.run_main(["bftpd", "3", "1500", "-g", "q1a512", "--reuse-or-calibrate"]), 1)
            self.assertEqual(len(list((Path(tmp) / "ablation/budget-cache").glob("*.json"))), 1)
            self.assertEqual(self.run_main(["bftpd", "3", "1500", "-g", "q1c512", "--reuse-or-calibrate"]), 0)
            self.assertEqual(calculator.call_count, 1)
            self.assertEqual(len(phases), 3)

    def test_corrupt_cache_and_missing_frozen_file_fail_without_recalibration(self):
        for corrupt in ("invalid-json", "missing-budget", "invalid-budget", "changed-valid-budget"):
            with self.subTest(corrupt=corrupt), tempfile.TemporaryDirectory() as tmp, \
                    self.cached_fixture(tmp) as (_, launch, _, calculator):
                args = ["bftpd", "3", "1500", "--reuse-or-calibrate"]
                self.assertEqual(self.run_main(args), 0)
                cache = next((Path(tmp) / "ablation/budget-cache").glob("*.json"))
                entry = json.loads(cache.read_text())
                if corrupt == "invalid-json":
                    cache.write_text("broken")
                elif corrupt == "missing-budget":
                    Path(entry["frozen_budget_file"]).unlink()
                elif corrupt == "invalid-budget":
                    Path(entry["frozen_budget_file"]).write_text("[]")
                else:
                    frozen = Path(entry["frozen_budget_file"])
                    report = json.loads(frozen.read_text())
                    report["q1_common_call_budget"] += 1
                    driver.write_json(frozen, report)
                launch.reset_mock()
                calculator.reset_mock()
                self.assertEqual(self.run_main(args), 1)
                launch.assert_not_called()
                calculator.assert_not_called()

    def test_shared_cache_isolates_target_duration_and_effective_settings(self):
        with tempfile.TemporaryDirectory() as tmp, self.cached_fixture(tmp) as (_, _, _, calculator):
            for target, minutes, skipcount in [("bftpd", "1500", "100"), ("bftpd", "1440", "100"),
                                               ("exim", "1500", "100"), ("bftpd", "1500", "200")]:
                os.environ["SKIPCOUNT"] = skipcount
                self.assertEqual(self.run_main([target, "3", minutes, "--reuse-or-calibrate"]), 0)
            self.assertEqual(calculator.call_count, 4)
            self.assertEqual(len(list((Path(tmp) / "ablation/budget-cache").glob("*.json"))), 4)

    def test_pilot_duration_is_excluded_from_configuration_fingerprint(self):
        environment = {"SKIPCOUNT": "100", "LLM_MODEL": "fixture-model", "ABLATION_PILOT_MINUTES": "30"}
        initial = driver.context_hash("bftpd", 1500, environment)
        environment["ABLATION_PILOT_MINUTES"] = "60"
        self.assertEqual(initial, driver.context_hash("bftpd", 1500, environment))
        environment["SKIPCOUNT"] = "200"
        self.assertNotEqual(initial, driver.context_hash("bftpd", 1500, environment))
        self.assertNotEqual(initial, driver.context_hash("bftpd", 1440, environment))

    def test_shared_cache_dry_run_writes_nothing_and_explains_plan(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, patch.object(driver, "ROOT", Path(tmp)), \
                patch.dict(os.environ, {}, clear=True), patch.object(driver, "cached_budget") as cached, \
                patch.object(driver.subprocess, "run") as command, contextlib.redirect_stdout(output):
            self.assertEqual(driver.main(["bftpd", "3", "1500", "--reuse-or-calibrate", "--dry-run"]), 0)
            cached.assert_not_called()
            command.assert_not_called()
            self.assertEqual(list(Path(tmp).iterdir()), [])
            self.assertIn("invalid cache fails", json.loads(output.getvalue())["shared_cache_plan"])

    def test_concurrent_first_launches_publish_only_one_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            frozen = root / "first-budget.json"
            args = SimpleNamespace(target="bftpd", minutes=1500)
            started = threading.Event()
            release = threading.Event()

            def calibrate(*unused):
                started.set()
                self.assertTrue(release.wait(5))
                driver.write_json(frozen, {"q1_common_call_budget": 123456, "target": "bftpd",
                                  "formal_duration_seconds": 1500 * 60,
                                  "launch_context_sha256": "same-context", "pilot_live_audit_passed": True})
                return 123456, frozen

            with patch.object(driver, "ROOT", root), \
                    patch.object(driver, "calibrate_budget", side_effect=calibrate) as pilot, \
                    contextlib.redirect_stdout(io.StringIO()), ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(driver.cached_budget, args, {}, "same-context", "first", root)
                self.assertTrue(started.wait(5))
                second = pool.submit(driver.cached_budget, args, {}, "same-context", "second", root)
                release.set()
                self.assertEqual(first.result(timeout=5), (123456, frozen))
                self.assertEqual(second.result(timeout=5), (123456, frozen))
                self.assertEqual(pilot.call_count, 1)


if __name__ == "__main__":
    unittest.main()
