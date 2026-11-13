#!/usr/bin/env python3
"""Exercise monitor collection against files, without Docker or campaigns.

Run with: python3 -m unittest discover -s scripts -p 'test_monitor*.py'
The fake Docker transport executes the real remote shell payloads in a
temporary filesystem. Only container paths are translated; directory
discovery, environment filtering, JSONL parsing, and label resolution run
unchanged.
"""

import json
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

import test_monitor_arms as arms


# Working directories used by each benchmark's run.sh before invoking -o.
TARGET_DIRECTORIES = {
    "lightftp": "LightFTP/Source/Release",
    "bftpd": "bftpd",
    "proftpd": "proftpd",
    "pure-ftpd": "pure-ftpd",
    "exim": "exim",
    "live555": "live/testProgs",
    "kamailio": "kamailio",
    "forked-daapd": "",
    "lighttpd1": "lighttpd1",
}


def config_for_environment(environment, target):
    """A run_config start record using the fuzzer's actual JSON field types."""
    calibration = environment.get("CHATAFL_CALIBRATION") == "1"
    native = environment.get("CHATAFL_ADMISSION_MODE") == "native"
    estimator = environment.get("CHATAFL_STATE_SELECT", "none")
    return {
        "event": "run_config", "phase": "start", "start_time_ms": 1000,
        "arm": ("loopfuzz-native-retention" if native else
                "loopfuzz-gated-calibrated" if calibration else "loopfuzz-gated-fixed"),
        "fuzzer": "loopfuzz", "target": target, "fuzzer_commit": "fixture1234",
        "calibration": calibration, "cal_gamma": 0.995,
        "state_select_override": estimator,
        "cal_estimator": "thompson" if estimator in ("none", "calibrated") else estimator,
        "threshold_resolved": int(environment["CHATAFL_ABLATION_THRESHOLD"]),
        "threshold_mode": "fixed", "no_adaptive": True,
        "hypothesis": environment.get("CHATAFL_HYPOTHESIS", "1") != "0",
        "plaintext_wrap_enabled": True,
        "salvage_enabled": environment.get("CHATAFL_SALVAGE") == "1",
        "no_llm": environment.get("CHATAFL_NO_LLM") == "1",
        "pv_early_stop_k": int(environment.get("CHATAFL_PV_EARLY_STOP", "0")),
        "scheduler_warmup_max_selections": 64,
    }


def stats_for_config(config):
    # Counters deliberately do not imply whether optional mechanisms are on.
    # E.g. a pvstop arm can have zero early stops throughout startup.
    values = {
        "start_time": 1, "bitmap_cvg": "1.5%", "paths_total": 7,
        "paths_favored": 4, "execs_done": 100, "execs_per_sec": 10,
        "unique_crashes": 0, "unique_hangs": 0, "cycles_done": 2,
        "pending_total": 3, "stability": "100%", "plateau_calls": 1,
        "llm_total_calls": 1, "llm_prompt_tokens": 20, "llm_completion_tok": 30,
        "plateau_threshold": config["threshold_resolved"], "arm": config["arm"],
        "calibration": int(config["calibration"]), "cal_gamma": 0.995,
        "plaintext_wrap_enabled": 1, "salvage_enabled": int(config["salvage_enabled"]),
        "no_llm_mode": int(config["no_llm"]), "pv_early_stops": 0,
        "cal_episodes": 0, "cal_eps_zero_mut": 0, "churn_fallback_used": 0,
        "seed_fallback_used": 0, "no_seed_stalls": 0, "provisional_admitted": 0,
        "provisional_converted": 0, "provisional_expired": 0,
        "llm_lineage_entries": 0, "llm_lineage_edge_gains": 0, "code_retain_admitted": 0,
    }
    return "\n".join(f"{key} : {value}" for key, value in values.items()) + "\n"


class MonitorCollectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.environments = arms.launcher_environments()

    def collect(self, target, arm, stage="runtime", *, directory=None,
                config_changes=None, config_text=None, stats_changes="",
                environment_changes=None, prefix=""):
        environment = dict(self.environments[arm])
        if environment_changes:
            environment.update(environment_changes)
        config = config_for_environment(self.environments[arm], target)
        config.update(config_changes or {})
        with tempfile.TemporaryDirectory(prefix="monitor-fixture-") as fixture:
            root = Path(fixture) / "experiments"
            outdir = root / (TARGET_DIRECTORIES[target] if directory is None else directory)
            outdir /= f"out-{target}-loopfuzz"
            outdir.mkdir(parents=True)
            env_file = Path(fixture) / "environ"
            env_file.write_bytes(b"\0".join(
                f"{key}={value}".encode() for key, value in environment.items()) + b"\0")
            if stage != "environment":
                (outdir / "run-config.jsonl").write_text(
                    json.dumps(config) + "\n" if config_text is None else config_text)
            if stage == "runtime":
                (outdir / "fuzzer_stats").write_text(stats_changes or stats_for_config(config))
                (outdir / "plot_data").write_text("1,0\n")
            (outdir / "ipsm.dot").write_text("digraph {\n0 -> 1;\n}\n")
            script = f"""
set --
source {shlex.quote(str(arms.MONITOR))}
fixture_root={shlex.quote(str(root))}
fixture_env={shlex.quote(str(env_file))}
fixture_target={shlex.quote(target)}
docker() {{
    if [[ "$1" == inspect ]]; then
        printf '/%s-loopfuzz-run-1\\n' "$fixture_target"
        return 0
    fi
    [[ "$1" == exec ]] || return 91
    shift
    [[ "${{1:-}}" != -i ]] || shift
    [[ "${{1:-}}" == fixture-container ]] || return 92
    shift
    local arg container_root=/home/ubuntu/experiments container_env=/proc/1/environ
    local -a translated=()
    for arg in "$@"; do
        arg="${{arg//$container_root/$fixture_root}}"
        arg="${{arg//$container_env/$fixture_env}}"
        translated+=("$arg")
    done
    "${{translated[@]}}"
}}
{prefix}
if row=$(collect_one fixture-container); then
    printf 'MAIN:%s\\n' "$row"
else
    exit 93
fi
mech_print_table() {{ printf 'MECH:%s\\n' "$@"; }}
mech_section fixture-container "$row"
"""
            completed = subprocess.run(["bash", "-c", script], check=False, text=True,
                                       capture_output=True, timeout=15)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            rows = {}
            for line in completed.stdout.splitlines():
                if line.startswith(("MAIN:", "MECH:")):
                    kind, row = line.split(":", 1)
                    rows[kind] = row.split("|")
            self.assertIn("MAIN", rows, completed.stdout)
            return rows

    def assert_identity(self, rows, target, arm):
        self.assertEqual(len(rows["MAIN"]), 33)
        self.assertEqual(rows["MAIN"][:3], ["fixture-container", target, "loopfuzz"])
        self.assertEqual(rows["MAIN"][-1], arm)
        self.assertIn("MECH", rows, "mechanism panel omitted an existing run")
        self.assertEqual(rows["MECH"][:2], [target, arm])

    def test_all_eight_arms_across_nine_targets_with_live_stats(self):
        for target in TARGET_DIRECTORIES:
            for arm in arms.PAPER_ARMS:
                with self.subTest(target=target, arm=arm):
                    rows = self.collect(target, arm)
                    self.assert_identity(rows, target, arm)
                    self.assertEqual(rows["MAIN"][7], "100")

    def test_all_eight_arms_across_nine_targets_during_config_only_startup(self):
        for target in TARGET_DIRECTORIES:
            for arm in arms.PAPER_ARMS:
                with self.subTest(target=target, arm=arm):
                    rows = self.collect(target, arm, "config")
                    self.assert_identity(rows, target, arm)
                    for field in (4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19, 20, 21, 22):
                        self.assertEqual(rows["MAIN"][field], "-", f"counter {field} invented at startup")
                    self.assertEqual(rows["MAIN"][25], "missing")

    def test_all_eight_arms_across_nine_targets_before_first_stats_or_config(self):
        for target in TARGET_DIRECTORIES:
            for arm in arms.PAPER_ARMS:
                with self.subTest(target=target, arm=arm):
                    rows = self.collect(target, arm, "environment")
                    self.assert_identity(rows, target, arm)
                    self.assertEqual(rows["MAIN"][7], "-")
                    self.assertEqual(rows["MECH"][6], "-")

    def test_deeper_directory_uses_same_target_and_arm_in_both_panels(self):
        rows = self.collect("forked-daapd", "cal_run_rate512", directory="extra/a/b/c")
        self.assert_identity(rows, "forked-daapd", "cal_run_rate512")

    def test_live_stats_override_conflicting_config_and_environment(self):
        stats = stats_for_config(config_for_environment(self.environments["wrapgate512"], "exim"))
        rows = self.collect("exim", "nollm512", stats_changes=stats)
        self.assert_identity(rows, "exim", "wrapgate512")

    def test_partial_stats_keep_live_counters_and_supplement_missing_identity(self):
        config = config_for_environment(self.environments["cal_run_rate512"], "exim")
        rows = self.collect("exim", "cal_ewma512", config_changes=config, stats_changes=(
            "start_time: 1\nexecs_done: 200\ncalibration: -\nplateau_threshold: -\n"))
        self.assert_identity(rows, "exim", "cal_run_rate512")
        self.assertEqual(rows["MAIN"][7], "200")

    def test_legacy_live_no_llm_alias_precedes_canonical_config_field(self):
        config = config_for_environment(self.environments["wrapgate512"], "exim")
        stats = stats_for_config(config)
        stats = "\n".join(line for line in stats.splitlines()
                          if not line.startswith("no_llm_mode")) + "\nno_llm: 0\n"
        rows = self.collect("exim", "nollm512", stats_changes=stats)
        self.assert_identity(rows, "exim", "wrapgate512")

    def test_live_estimator_override_precedes_config_estimator_alias(self):
        config = config_for_environment(self.environments["cal_ewma512"], "exim")
        stats = stats_for_config(config) + "state_select_override: ewma\n"
        rows = self.collect("exim", "calibrated512", stats_changes=stats)
        self.assert_identity(rows, "exim", "cal_ewma512")

    def test_run_config_boolean_and_estimator_override_conflicting_launch_environment(self):
        config = config_for_environment(self.environments["cal_run_rate512"], "exim")
        rows = self.collect("exim", "cal_ewma512", "config", config_changes=config)
        self.assert_identity(rows, "exim", "cal_run_rate512")
        config = config_for_environment(self.environments["wrapgate512"], "exim")
        rows = self.collect("exim", "calibrated512", "config", config_changes=config)
        self.assert_identity(rows, "exim", "wrapgate512")

    def test_truncated_config_append_keeps_last_complete_identity(self):
        config = config_for_environment(self.environments["cal_run_rate512"], "exim")
        text = json.dumps(config) + '\n{"event":"run_config","phase":"end","calibration":'
        rows = self.collect("exim", "cal_ewma512", "config", config_text=text)
        self.assert_identity(rows, "exim", "cal_run_rate512")

    def test_dynamic_hypothesis_fallback_preserves_all_eight_arms_across_nine_targets(self):
        # Grammar fallback can turn hypothesis_mode off after the start record.
        # This runtime transition is not a requested hypothesis ablation.
        for target in TARGET_DIRECTORIES:
            for arm in arms.PAPER_ARMS:
                start = dict(config_for_environment(self.environments[arm], target),
                             hypothesis=True)
                end = dict(start, phase="end", hypothesis=False)
                stats = stats_for_config(end) + "hypothesis: 0\n"
                for records in ((start, end), (end,)):
                    with self.subTest(target=target, arm=arm,
                                      records="start+end" if len(records) == 2 else "end-only"):
                        rows = self.collect(target, arm, config_text="\n".join(
                            map(json.dumps, records)), stats_changes=stats)
                        self.assert_identity(rows, target, arm)

    def test_explicit_start_hypothesis_ablation_is_not_standard_wrapped_arm(self):
        # nollm and pvstop intentionally keep their historical dominant-axis
        # labels; the other six standard arms require hypothesis configured on.
        for arm in arms.PAPER_ARMS:
            if arm in ("nollm512", "pvstop512"):
                continue
            with self.subTest(arm=arm):
                start = dict(config_for_environment(self.environments[arm], "exim"),
                             hypothesis=False)
                end = dict(start, phase="end", hypothesis=True)
                rows = self.collect("exim", arm, "config", config_text="\n".join(
                    map(json.dumps, (start, end))),
                    environment_changes={"CHATAFL_HYPOTHESIS": "1"})
                self.assertNotIn(rows["MAIN"][-1], arms.PAPER_ARMS)
                self.assert_identity(rows, "exim", rows["MAIN"][-1])

    def test_explicit_launch_hypothesis_ablation_survives_end_only_config(self):
        for arm in arms.PAPER_ARMS:
            if arm in ("nollm512", "pvstop512"):
                continue
            with self.subTest(arm=arm):
                end = dict(config_for_environment(self.environments[arm], "exim"),
                           phase="end", hypothesis=False)
                rows = self.collect("exim", arm, config_text=json.dumps(end),
                    stats_changes=stats_for_config(end) + "hypothesis: 0\n",
                    environment_changes={"CHATAFL_HYPOTHESIS": "0"})
                self.assertNotIn(rows["MAIN"][-1], arms.PAPER_ARMS)
                self.assert_identity(rows, "exim", rows["MAIN"][-1])

    def test_start_hypothesis_configuration_outranks_conflicting_launch_environment(self):
        for arm in arms.PAPER_ARMS:
            with self.subTest(arm=arm):
                start = dict(config_for_environment(self.environments[arm], "exim"),
                             hypothesis=True)
                end = dict(start, phase="end", hypothesis=False)
                rows = self.collect("exim", arm, "config", config_text="\n".join(
                    map(json.dumps, (start, end))),
                    environment_changes={"CHATAFL_HYPOTHESIS": "0"})
                self.assert_identity(rows, "exim", arm)

    def test_named_environment_transport_is_whitelisted(self):
        # A resolver extension observes the real transported snapshot. This
        # catches dropped classifier keys and accidental wholesale env dumps.
        prefix = """
transport_probe() {
    [[ "$6" != *CHATAFL_MONITOR_SECRET_SENTINEL=* ]] || { echo leaked; return 0; }
    [[ "$6" == *CHATAFL_STATE_SELECT=run_rate* ]] || { echo missing-selector; return 0; }
    [[ "$6" == *CHATAFL_ABLATION_THRESHOLD=512* ]] || { echo missing-threshold; return 0; }
    printf '%s\\n' transport_ok
}
MONITOR_ABLATION_RESOLVERS=(transport_probe "${MONITOR_ABLATION_RESOLVERS[@]}")
"""
        rows = self.collect("pure-ftpd", "cal_run_rate512", prefix=prefix,
                            environment_changes={"CHATAFL_MONITOR_SECRET_SENTINEL": "fixture-value"})
        self.assert_identity(rows, "pure-ftpd", "transport_ok")


class MonitorRunConfigTests(unittest.TestCase):
    def project(self, text):
        completed = subprocess.run(
            ["python3", str(arms.MONITOR.parent / "scripts" / "monitor_run_config.py")],
            input=text, check=False, text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return dict(line.split(": ", 1) for line in completed.stdout.splitlines())

    def test_json_false_remains_disabled_and_unknown_counters_are_not_created(self):
        output = self.project(json.dumps({
            "event": "run_config", "phase": "start", "calibration": False,
            "no_llm": False, "salvage_enabled": False, "plaintext_wrap_enabled": True,
            "threshold_resolved": 512, "start_time_ms": 12000,
        }))
        self.assertEqual(output, {
            "calibration": "0", "no_llm_mode": "0", "salvage_enabled": "0",
            "plaintext_wrap_enabled": "1", "plateau_threshold": "512", "start_time": "12",
        })

    def test_end_configuration_overrides_earlier_start_record(self):
        start = {"event": "run_config", "phase": "start", "calibration": False,
                 "threshold_resolved": 512, "cal_estimator": "thompson"}
        end = dict(start, phase="end", calibration=True, threshold_resolved=32,
                   cal_estimator="run_rate")
        text = "\n".join(map(json.dumps, (start, end, {"event": "candidate"})))
        output = self.project(text)
        self.assertEqual(output["calibration"], "1")
        self.assertEqual(output["plateau_threshold"], "32")
        self.assertEqual(output["cal_estimator"], "run_rate")

    def test_start_hypothesis_configuration_is_separate_from_dynamic_end_state(self):
        start = {"event": "run_config", "phase": "start", "hypothesis": True,
                 "pid": 101, "start_time_ms": 1000}
        end = dict(start, phase="end", hypothesis=False)
        output = self.project("\n".join(map(json.dumps, (start, end))))
        self.assertEqual(output["hypothesis_configured"], "1")
        self.assertEqual(output["hypothesis_runtime"], "0")
        self.assertNotIn("hypothesis", output)

    def test_end_only_hypothesis_does_not_invent_configuration(self):
        output = self.project(json.dumps({
            "event": "run_config", "phase": "end", "hypothesis": False,
            "pid": 101, "start_time_ms": 1000,
        }))
        self.assertEqual(output["hypothesis_runtime"], "0")
        self.assertNotIn("hypothesis_configured", output)
        self.assertNotIn("hypothesis", output)

    def test_explicit_start_hypothesis_zero_is_preserved_after_runtime_change(self):
        start = {"event": "run_config", "phase": "start", "hypothesis": False,
                 "pid": 101, "start_time_ms": 1000}
        end = dict(start, phase="end", hypothesis=True)
        output = self.project("\n".join(map(json.dumps, (start, end))))
        self.assertEqual(output["hypothesis_configured"], "0")
        self.assertEqual(output["hypothesis_runtime"], "1")

    def test_end_of_new_run_cannot_borrow_previous_runs_start_hypothesis(self):
        for changes in ({"pid": 202}, {"start_time_ms": 2000},
                        {"pid": 202, "start_time_ms": 2000}):
            with self.subTest(changes=changes):
                old_start = {"event": "run_config", "phase": "start", "hypothesis": True,
                             "pid": 101, "start_time_ms": 1000}
                new_end = dict(old_start, phase="end", hypothesis=False, **changes)
                output = self.project("\n".join(map(json.dumps, (old_start, new_end))))
                self.assertEqual(output["hypothesis_runtime"], "0")
                self.assertNotIn("hypothesis_configured", output)

    def test_latest_matching_start_replaces_previous_runs_hypothesis_configuration(self):
        old_start = {"event": "run_config", "phase": "start", "hypothesis": False,
                     "pid": 101, "start_time_ms": 1000}
        new_start = dict(old_start, pid=202, start_time_ms=2000, hypothesis=True)
        new_end = dict(new_start, phase="end", hypothesis=False)
        output = self.project("\n".join(map(json.dumps, (old_start, new_start, new_end))))
        self.assertEqual(output["hypothesis_configured"], "1")
        self.assertEqual(output["hypothesis_runtime"], "0")

    def test_unidentified_records_cannot_borrow_start_hypothesis(self):
        for identity in ({}, {"pid": None, "start_time_ms": None},
                         {"pid": False, "start_time_ms": False}):
            with self.subTest(identity=identity):
                start = dict(identity, event="run_config", phase="start", hypothesis=True)
                end = dict(start, phase="end", hypothesis=False)
                output = self.project("\n".join(map(json.dumps, (start, end))))
                self.assertNotIn("hypothesis_configured", output)
                # A complete start itself needs no cross-record association.
                output = self.project(json.dumps(start))
                self.assertEqual(output["hypothesis_configured"], "1")

    def test_truncated_append_and_non_object_records_do_not_hide_complete_config(self):
        config = {"event": "run_config", "calibration": True, "threshold_resolved": 512}
        output = self.project(json.dumps(config) + '\nnull\n[]\n{"event":"run_config",')
        self.assertEqual(output, {"calibration": "1", "plateau_threshold": "512"})

    def test_invalid_numeric_and_placeholder_values_remain_unknown(self):
        for threshold in (None, True, False, -1, 0, "-", "512"):
            with self.subTest(threshold=threshold):
                output = self.project(json.dumps({
                    "event": "run_config", "arm": "-", "cal_gamma": "-",
                    "threshold_resolved": threshold, "start_time_ms": False,
                }))
                self.assertEqual(output, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
