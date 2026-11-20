"""Offline regression checks for direct, elapsed-time ablation launches.

Run the real shell in an isolated temporary project. Fake external commands
record resource checks and side effects; fake run_dev records the actual child
arguments and environment. Nothing contacts a gateway or Docker daemon.
"""

import getpass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    "lightftp", "bftpd", "proftpd", "pure-ftpd", "exim", "live555",
    "kamailio", "forked-daapd", "lighttpd1",
)
UNCAPPED_ARMS = (
    "pvstop512", "salvage512", "nollm512", "wrapgate512", "native512",
    "calibrated512", "cal_ewma512", "cal_run_rate512", "ordmatch512",
    "q1a512", "q1c512", "q1d512",
)


class AblationShellWallclockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.shell = self.directory / "run_ablation.sh"
        shutil.copyfile(ROOT / "run_ablation.sh", self.shell)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.effects = self.directory / "effects.jsonl"
        self.children = self.directory / "children.jsonl"
        self.audits = self.directory / "audits.jsonl"
        # Every helper has an absolute interpreter so the fake python3 itself
        # can fail closed on any accidental automatic-budget dispatch.
        self.write_executable(self.bin / "python3", """
import json, os, pathlib, sys
with open(os.environ['TEST_SIDE_EFFECTS'], 'a') as output:
    output.write(json.dumps({'command': 'python3', 'args': sys.argv[1:]}) + '\\n')
if (os.environ.get('TEST_ALLOW_AUDITOR') == '1' and len(sys.argv) > 1
        and sys.argv[1].endswith('/audit_smoke.py')):
    with open(os.environ['TEST_AUDITS'], 'a') as output:
        output.write(json.dumps(sys.argv[1:]) + '\\n')
    print('offline auditor result')
    sys.exit(int(os.environ.get('TEST_AUDITOR_EXIT', '0')))
sys.exit(97)
""")
        for command in ("curl", "wget", "sudo", "ssh", "sleep"):
            self.write_executable(self.bin / command, self.recording_source(97))
        for command in ("docker", "chown", "chmod"):
            self.write_executable(self.bin / command, self.recording_source(0))
        self.write_executable(self.bin / "id", self.recording_source(0, "testgroup"))
        self.write_executable(self.bin / "mkdir", """
import json, os, pathlib, sys
with open(os.environ['TEST_SIDE_EFFECTS'], 'a') as output:
    output.write(json.dumps({'command': 'mkdir', 'args': sys.argv[1:]}) + '\\n')
for argument in sys.argv[1:]:
    if not argument.startswith('-'):
        pathlib.Path(argument).mkdir(parents=True, exist_ok=True)
""")
        self.write_executable(self.bin / "awk", """
import json, os, sys
with open(os.environ['TEST_SIDE_EFFECTS'], 'a') as output:
    output.write(json.dumps({'command': 'awk', 'args': sys.argv[1:]}) + '\\n')
program = sys.argv[1] if len(sys.argv) > 1 else ''
if 'MemTotal' in program:
    print(167772160)
elif 'MemAvailable' in program:
    print(147456 if 'int($2/1024)' in program else 150994944)
else:
    sys.exit(97)
""")
        self.write_executable(self.directory / "scripts" / "check_llm.sh",
                              self.recording_source(0))
        self.write_executable(self.directory / "run_dev.sh", """
import json, os, pathlib, sys
keys = ('CHATAFL_CAMPAIGN_CALL_BUDGET', 'CHATAFL_CAMPAIGN_STOP_MODE',
        'CHATAFL_CAMPAIGN_DURATION_SEC', 'CHATAFL_CAMPAIGN_STARTUP_TIMEOUT_SEC',
        'CHATAFL_ABLATION_THRESHOLD',
        'CHATAFL_Q1_DIRECT_SERVICE', 'CHATAFL_Q1_NO_REFLOW',
        'CHATAFL_Q1_REFLOW', 'CHATAFL_CODE_RETAIN', 'CHATAFL_NO_LLM', 'TIMESTAMP')
with open(os.environ['TEST_CHILDREN'], 'a') as output:
    output.write(json.dumps({'argv': sys.argv[1:],
        'environment': {key: os.environ.get(key) for key in keys}}) + '\\n')
if os.environ.get('TEST_CREATE_RESULTS') == '1':
    (pathlib.Path.cwd() / 'ablation' /
        ('results-' + sys.argv[3] + '_' + os.environ['TIMESTAMP'])).mkdir(parents=True)
sys.exit(int(os.environ.get('TEST_CHILD_EXIT', '0')))
""")
        self.environment = {
            "PATH": str(self.bin) + ":/usr/bin:/bin",
            "USER": getpass.getuser(),
            "TEST_SIDE_EFFECTS": str(self.effects),
            "TEST_CHILDREN": str(self.children),
            "TEST_AUDITS": str(self.audits),
            "ABLATION_PARALLEL": "1",
            "ABLATION_WALLCLOCK_AUDIT": "0",
            "SKIPCOUNT": "100",
        }

    @staticmethod
    def recording_source(return_code, output=""):
        return """
import json, os, pathlib, sys
with open(os.environ['TEST_SIDE_EFFECTS'], 'a') as output:
    output.write(json.dumps({'command': pathlib.Path(sys.argv[0]).name,
                             'args': sys.argv[1:]}) + '\\n')
print(%r) if %r else None
sys.exit(%d)
""" % (output, bool(output), return_code)

    def write_executable(self, path, source):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!" + sys.executable + "\n" + source)
        path.chmod(0o700)

    def launch(self, args, environment=None, dry_run=True):
        self.effects.unlink(missing_ok=True)
        self.children.unlink(missing_ok=True)
        self.audits.unlink(missing_ok=True)
        process_environment = dict(self.environment)
        if dry_run:
            process_environment["ABLATION_DRY_RUN"] = "1"
        process_environment.update(environment or {})
        return subprocess.run(
            ["/bin/bash", str(self.shell), *args], cwd=self.directory,
            env=process_environment, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10,
        )

    def assert_offline_no_effects(self):
        self.assertFalse(self.effects.exists(),
                         self.effects.read_text() if self.effects.exists() else "")
        self.assertFalse(self.children.exists())
        self.assertFalse((self.directory / "ablation").exists())

    def assert_dry_wallclock(self, result, minutes, budget=0):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("mode=wallclock", result.stdout)
        self.assertIn(f"duration_sec={minutes * 60}", result.stdout)
        self.assertIn(f"call_budget={budget}", result.stdout)
        if budget == 0:
            self.assertIn("basis=elapsed-time", result.stdout)
        self.assertNotIn("AUTO-BUDGET", result.stdout + result.stderr)
        self.assert_offline_no_effects()

    def recorded_children(self):
        return [json.loads(line) for line in self.children.read_text().splitlines()]

    def recorded_effects(self):
        return [json.loads(line) for line in self.effects.read_text().splitlines()]

    def test_nine_targets_and_twelve_arms_need_no_budget_or_credentials(self):
        for target in TARGETS:
            for arm in UNCAPPED_ARMS:
                with self.subTest(target=target, arm=arm):
                    result = self.launch([target, "3", "1440", "-g", arm])
                    self.assert_dry_wallclock(result, 1440)
                    self.assertIn(f"[ARM_SPEC] {arm}|", result.stdout)

    def test_explicit_wallclock_and_duration_follow_arguments(self):
        for minutes in (1, 25, 1440, 1500):
            with self.subTest(minutes=minutes):
                result = self.launch(["bftpd", "3", str(minutes), "-g", "q1c512"],
                                     {"ABLATION_STOP_MODE": "wallclock"})
                self.assert_dry_wallclock(result, minutes)

    def test_multiple_arms_and_long_option_remain_direct(self):
        result = self.launch(["bftpd", "3", "60", "--groups", ",".join(UNCAPPED_ARMS)])
        self.assert_dry_wallclock(result, 60)
        self.assertEqual(result.stdout.count("[ARM_SPEC]"), len(UNCAPPED_ARMS))

    def test_custom_positional_and_alternate_order(self):
        for args in (["bftpd", "3", "60", "custom", "q1a512,q1c512"],
                     ["3", "60", "bftpd", "custom", "q1a512,q1c512"]):
            with self.subTest(args=args):
                self.assert_dry_wallclock(self.launch(args), 60)

    def test_q1b_without_cap_rejects_before_any_preflight(self):
        for target in TARGETS:
            with self.subTest(target=target):
                result = self.launch([target, "3", "1440", "-g", "q1b512"],
                                     {"KEY": "offline-test-placeholder"}, dry_run=False)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("q1b", (result.stdout + result.stderr).lower())
                self.assert_offline_no_effects()
        result = self.launch(["bftpd", "3", "1440", "-g", "q1c512,q1b512"])
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assert_offline_no_effects()

    def test_explicit_zero_is_wallclock_only(self):
        self.assert_dry_wallclock(self.launch(
            ["bftpd", "3", "25", "-g", "q1c512"],
            {"Q1_COMMON_CALL_BUDGET": "0"}), 25)
        result = self.launch(["bftpd", "3", "25", "-g", "q1c512"],
                             {"Q1_COMMON_CALL_BUDGET": "0", "ABLATION_STOP_MODE": "call-budget"})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assert_offline_no_effects()

    def test_invalid_stop_mode_or_duration_rejects_before_preflight(self):
        for minutes, environment in (("0", {}), ("10081", {}), ("bad", {}),
                                     ("25", {"ABLATION_STOP_MODE": "bad"})):
            with self.subTest(minutes=minutes, environment=environment):
                result = self.launch(["bftpd", "3", minutes, "-g", "q1c512"], environment)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assert_offline_no_effects()

    def test_q1b_with_explicit_cap_remains_available(self):
        result = self.launch(["bftpd", "3", "25", "-g", "q1b512"],
                             {"Q1_COMMON_CALL_BUDGET": "123456"})
        self.assert_dry_wallclock(result, 25, budget=123456)

    def test_call_budget_q1_requires_positive_cap(self):
        for arm in ("q1a512", "q1b512", "q1c512", "q1d512"):
            with self.subTest(arm=arm):
                result = self.launch(["bftpd", "3", "25", "-g", arm],
                                     {"ABLATION_STOP_MODE": "call-budget"})
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("budget", (result.stdout + result.stderr).lower())
                self.assert_offline_no_effects()

    def test_manual_budget_name_and_legacy_alias_keep_explicit_value(self):
        for variable in ("Q1_COMMON_CALL_BUDGET", "ABLATION_CALL_BUDGET_OVERRIDE"):
            with self.subTest(variable=variable):
                result = self.launch(["bftpd", "3", "25", "-g", "q1c512"],
                                     {variable: "67890"})
                self.assert_dry_wallclock(result, 25, budget=67890)

    def test_invalid_explicit_budget_rejects_offline(self):
        for variable in ("Q1_COMMON_CALL_BUDGET", "ABLATION_CALL_BUDGET_OVERRIDE"):
            for value in ("bad", "-1", "100000001"):
                with self.subTest(variable=variable, value=value):
                    result = self.launch(["bftpd", "3", "25", "-g", "q1c512"],
                                         {variable: value})
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assert_offline_no_effects()

    def test_mock_and_old_arm_dry_runs_do_not_use_auto_dispatch(self):
        for arm, environment in (("q1c512", {"CHATAFL_MOCK_LLM": "1"}),
                                 ("q1c1", {}), ("q1c8", {}), ("full", {})):
            with self.subTest(arm=arm, environment=environment):
                self.assert_dry_wallclock(
                    self.launch(["bftpd", "3", "25", "-g", arm], environment), 25)

    def test_live_child_receives_zero_cap_exact_duration_and_grace(self):
        for minutes in (25, 1440, 1500):
            with self.subTest(minutes=minutes):
                result = self.launch(["bftpd", "3", str(minutes), "-g", "q1c512"],
                                     {"KEY": "offline-test-placeholder",
                                      "CHATAFL_CAMPAIGN_CALL_BUDGET": "5000"},
                                     dry_run=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                children = self.recorded_children()
                self.assertEqual(len(children), 1)
                child = children[0]
                self.assertEqual(child["argv"], ["3", str(minutes + 8), "bftpd", "loopfuzz"])
                self.assertEqual(child["environment"]["CHATAFL_CAMPAIGN_STOP_MODE"], "wallclock")
                self.assertEqual(child["environment"]["CHATAFL_CAMPAIGN_CALL_BUDGET"], "0")
                self.assertEqual(child["environment"]["CHATAFL_CAMPAIGN_DURATION_SEC"], str(minutes * 60))
                self.assertEqual(child["environment"]["CHATAFL_CAMPAIGN_STARTUP_TIMEOUT_SEC"], "360")
                self.assertEqual(child["environment"]["CHATAFL_Q1_REFLOW"], "1")
                commands = {row["command"] for row in self.recorded_effects()}
                self.assertNotIn("python3", commands)
                self.assertNotIn("sleep", commands)
                self.assertIn("check_llm.sh", commands)

    def test_live_child_keeps_explicit_cap_instead_of_old_hardcoded_value(self):
        result = self.launch(["exim", "3", "25", "-g", "q1a512"],
                             {"KEY": "offline-test-placeholder",
                              "Q1_COMMON_CALL_BUDGET": "321987"}, dry_run=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        child = self.recorded_children()[0]
        self.assertEqual(child["argv"], ["3", "33", "exim", "loopfuzz"])
        self.assertEqual(child["environment"]["CHATAFL_CAMPAIGN_CALL_BUDGET"], "321987")
        self.assertEqual(child["environment"]["CHATAFL_Q1_DIRECT_SERVICE"], "1")

    def test_wallclock_outer_timeout_tracks_startup_budget_and_shutdown_margin(self):
        for startup_seconds, extra_minutes in ((90, 4), (360, 8), (601, 13)):
            with self.subTest(startup_seconds=startup_seconds):
                result = self.launch(["bftpd", "3", "25", "-g", "q1c512"],
                                     {"KEY": "offline-test-placeholder",
                                      "CHATAFL_CAMPAIGN_STARTUP_TIMEOUT_SEC": str(startup_seconds)},
                                     dry_run=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                child = self.recorded_children()[0]
                self.assertEqual(child["argv"], ["3", str(25 + extra_minutes), "bftpd", "loopfuzz"])
                self.assertEqual(child["environment"]["CHATAFL_CAMPAIGN_STARTUP_TIMEOUT_SEC"],
                                 str(startup_seconds))

    def test_call_budget_child_keeps_dose_mode_without_wallclock_grace(self):
        result = self.launch(["bftpd", "3", "25", "-g", "q1d512"],
                             {"KEY": "offline-test-placeholder",
                              "ABLATION_STOP_MODE": "call-budget",
                              "Q1_COMMON_CALL_BUDGET": "765432"}, dry_run=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        child = self.recorded_children()[0]
        self.assertEqual(child["argv"], ["3", "25", "bftpd", "loopfuzz"])
        self.assertEqual(child["environment"]["CHATAFL_CAMPAIGN_STOP_MODE"], "call-budget")
        self.assertEqual(child["environment"]["CHATAFL_CAMPAIGN_CALL_BUDGET"], "765432")
        self.assertEqual(child["environment"]["CHATAFL_CODE_RETAIN"], "1")

    def test_default_audit_uses_exact_current_directories_and_formal_duration(self):
        old_directories = [self.directory / "ablation" / f"results-bftpd_ablation_{arm}_old-run"
                           for arm in ("q1a512", "q1c512")]
        for path in old_directories:
            path.mkdir(parents=True)
        result = self.launch(["bftpd", "3", "25", "-g", "q1a512,q1c512"],
                             {"KEY": "offline-test-placeholder", "ABLATION_WALLCLOCK_AUDIT": "",
                              "TEST_ALLOW_AUDITOR": "1", "TEST_CREATE_RESULTS": "1"},
                             dry_run=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        children = self.recorded_children()
        self.assertEqual(len(children), 2)
        stamps = [row["environment"]["TIMESTAMP"] for row in children]
        batch = stamps[0].removeprefix("ablation_q1a512_")
        self.assertTrue(batch.startswith("timed-"), batch)
        self.assertEqual(stamps[1], f"ablation_q1c512_{batch}")
        directories = [str(self.directory / "ablation" / f"results-bftpd_{stamp}")
                       for stamp in stamps]
        auditor_calls = [json.loads(line) for line in self.audits.read_text().splitlines()]
        self.assertEqual(auditor_calls, [[
            str(self.directory / "ablation/q123_repair_smoke_20261114/audit_smoke.py"),
            *directories, "--target", "bftpd", "--threshold", "512",
            "--timeout-min", "25", "--gateway", "live", "--profile", "arm-default",
            "--arms", "q1a512,q1c512",
        ]])
        self.assertTrue(all(Path(path).is_dir() for path in directories))
        self.assertTrue(all(str(path) not in auditor_calls[0] for path in old_directories))
        self.assertTrue(all(row["argv"][1] == "33" for row in children))
        audit_log = self.directory / "ablation" / f"wallclock-audit-bftpd-{batch}.log"
        self.assertEqual(audit_log.read_text().strip(), "offline auditor result")

    def test_audit_failure_makes_successful_launch_fail(self):
        result = self.launch(["exim", "3", "1440", "-g", "q1c512"],
                             {"KEY": "offline-test-placeholder", "ABLATION_WALLCLOCK_AUDIT": "",
                              "TEST_ALLOW_AUDITOR": "1", "TEST_AUDITOR_EXIT": "42"},
                             dry_run=False)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.recorded_children()), 1)
        auditor_calls = [json.loads(line) for line in self.audits.read_text().splitlines()]
        self.assertEqual(len(auditor_calls), 1)
        arguments = auditor_calls[0]
        self.assertEqual(arguments[arguments.index("--timeout-min") + 1], "1440")
        self.assertEqual(self.recorded_children()[0]["argv"][1], "1448")
        self.assertIn("offline auditor result", result.stdout)

    def test_explicit_audit_opt_out_skips_auditor_after_successful_launch(self):
        result = self.launch(["bftpd", "3", "25", "-g", "q1c512"],
                             {"KEY": "offline-test-placeholder", "ABLATION_WALLCLOCK_AUDIT": "0",
                              "TEST_ALLOW_AUDITOR": "1"}, dry_run=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.recorded_children()), 1)
        self.assertFalse(self.audits.exists())
        self.assertNotIn("python3", {row["command"] for row in self.recorded_effects()})


if __name__ == "__main__":
    unittest.main()
