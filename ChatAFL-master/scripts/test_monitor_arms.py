#!/usr/bin/env python3
"""Regression tests for monitor.sh arm classification (no Docker required).

Run with: python3 scripts/test_monitor_arms.py
"""

import shlex
import subprocess
import unittest
from pathlib import Path


MONITOR = Path(__file__).resolve().parents[1] / "monitor.sh"
THRESHOLDS = (8, 16, 32, 64, 150, 200, 300, 512)


def legacy_flags(**changes):
    """The existing collector's 14-field public interface."""
    values = {
        "no_hyp": "0", "no_refine": "0", "no_frontier": "0",
        "no_adaptive": "0", "no_sp": "0", "no_admission": "0",
        "cal": "0", "gamma": "-", "threshold": "-", "mode": "-",
        "prov": "-", "shadow": "-", "state_select": "-", "retain": "0",
    }
    values.update({key: str(value) for key, value in changes.items()})
    return " ".join(values.values())


def extension_env(**values):
    return "\n".join(f"{key}={value}" for key, value in values.items())


def legacy9_flags(**changes):
    """Use the documented original format for pre-Phase-2 strategy groups."""
    return " ".join(legacy_flags(**changes).split()[:9])


class MonitorArmTests(unittest.TestCase):
    def shell(self, body):
        completed = subprocess.run(
            ["bash", "-c", f"set --\nsource {shlex.quote(str(MONITOR))}\n{body}"],
            check=False, text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return completed.stdout.strip()

    def resolve(self, arm="", cal="", gamma="", flags="NONE", stats="", env="",
                *, legacy=False, prefix="", four_args=False):
        args = (arm, cal, gamma, flags)
        if not four_args:
            args += (stats, env)
        name = "resolve_ablation_label" if legacy else "monitor_resolve_ablation_label"
        return self.shell(prefix + "\n" + name + " " + shlex.join(args))

    def wrapped(self, family="wrapgate", threshold=8, *, stats=None, env_changes=None,
                flags_changes=None, arm=None, cal="0"):
        mode = "direct" if family == "wrapdirect" else "gate"
        env = {
            "CHATAFL_ADMISSION_MODE": mode,
            "CHATAFL_PLAINTEXT_WRAP": "1",
            "CHATAFL_NO_ADAPTIVE": "1",
            "CHATAFL_ABLATION_THRESHOLD": str(threshold),
        }
        if family == "salvage":
            env["CHATAFL_SALVAGE"] = "1"
        if env_changes:
            for key, value in env_changes.items():
                if value is None:
                    env.pop(key, None)
                else:
                    env[key] = str(value)
        flags = {"mode": mode, "no_adaptive": 1, "threshold": threshold}
        if flags_changes:
            flags.update(flags_changes)
        if stats is None:
            stats = (
                f"salvage_enabled : {int(family == 'salvage')}\n"
                "plaintext_wrap_enabled: 1\n"
                f"plateau_threshold : {threshold}\n"
            )
        if arm is None:
            arm = "loopfuzz-direct" if mode == "direct" else "loopfuzz-gated-fixed"
        return self.resolve(arm, cal, "0.9950", legacy_flags(**flags), stats,
                            extension_env(**env))

    def test_source_does_not_start_monitor_or_docker(self):
        completed = subprocess.run(
            ["bash", "-c", "set --\n"
             "docker() { echo unexpected-docker-invocation >&2; return 99; }\n"
             f"source {shlex.quote(str(MONITOR))}\n"
             "printf '%s\\n' source-ok"],
            check=False, text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "source-ok")
        self.assertNotIn("unexpected-docker-invocation", completed.stderr)

    def test_all_launcher_wrapped_groups(self):
        for family in ("wrapdirect", "wrapgate", "salvage"):
            for threshold in THRESHOLDS:
                with self.subTest(family=family, threshold=threshold):
                    self.assertEqual(self.wrapped(family, threshold), f"{family}{threshold}")

    def test_missing_runtime_fields_fall_back_to_environment(self):
        for family in ("wrapdirect", "wrapgate", "salvage"):
            with self.subTest(family=family):
                self.assertEqual(self.wrapped(family, stats="", arm=""), f"{family}8")

    def test_runtime_disabled_flags_override_enabled_environment(self):
        self.assertEqual(
            self.wrapped("salvage", stats="salvage_enabled: 0\nplaintext_wrap_enabled: 1\nplateau_threshold: 8"),
            "wrapgate8",
        )
        self.assertEqual(
            self.wrapped("salvage", stats="salvage_enabled: 1\nplaintext_wrap_enabled: 0\nplateau_threshold: 8"),
            "gate",
        )

    def test_runtime_enabled_flags_override_disabled_environment(self):
        self.assertEqual(self.wrapped("salvage", env_changes={
            "CHATAFL_PLAINTEXT_WRAP": "0", "CHATAFL_SALVAGE": "0",
        }), "salvage8")

    def test_runtime_arm_overrides_environment_for_new_groups(self):
        self.assertEqual(self.wrapped("wrapgate", arm="loopfuzz-direct"), "wrapdirect8")
        self.assertEqual(self.wrapped("wrapdirect", arm="loopfuzz-gated-fixed"), "wrapgate8")

    def test_runtime_calibration_overrides_environment_for_new_groups(self):
        self.assertEqual(self.wrapped("salvage", cal="0", env_changes={
            "CHATAFL_CALIBRATION": "1",
        }, flags_changes={"cal": 1}), "salvage8")

    def test_runtime_threshold_overrides_launch_threshold(self):
        self.assertEqual(self.wrapped("wrapgate", 8, stats=(
            "salvage_enabled: 0\nplaintext_wrap_enabled: 1\nplateau_threshold: 32"
        )), "wrapgate32")
        self.assertEqual(self.wrapped("wrapgate", 64, stats=(
            "salvage_enabled: 0\nplaintext_wrap_enabled: 1"
        )), "wrapgate64")

    def test_adaptive_run_does_not_claim_fixed_wrapped_group(self):
        self.assertEqual(self.wrapped("wrapgate", env_changes={
            "CHATAFL_NO_ADAPTIVE": None,
        }, flags_changes={"no_adaptive": 0}), "gate")

    def test_no_adaptive_matches_fuzzer_presence_semantics(self):
        for value in ("0", "", "false"):
            with self.subTest(value=value):
                self.assertEqual(self.wrapped("wrapgate", env_changes={
                    "CHATAFL_NO_ADAPTIVE": value,
                }, flags_changes={"no_adaptive": 0}), "wrapgate8")

    def test_wrap_and_salvage_environment_match_fuzzer_truth_semantics(self):
        for value in ("true", "2", "false"):
            with self.subTest(value=value):
                self.assertEqual(self.wrapped("salvage", stats="", env_changes={
                    "CHATAFL_PLAINTEXT_WRAP": value, "CHATAFL_SALVAGE": value,
                }), "salvage8")
        for value in ("0", ""):
            with self.subTest(disabled_value=value):
                self.assertEqual(self.wrapped("salvage", stats="", env_changes={
                    "CHATAFL_SALVAGE": value,
                }), "wrapgate8")
                self.assertEqual(self.wrapped("wrapgate", stats="", env_changes={
                    "CHATAFL_PLAINTEXT_WRAP": value,
                }), "gate")

    def test_changed_gate_configuration_does_not_claim_canonical_group(self):
        for flag, env_name, value in (
            ("prov", "CHATAFL_PROVISIONAL", "0"),
            ("shadow", "CHATAFL_SHADOW", "0"),
            ("retain", "CHATAFL_CODE_RETAIN", "1"),
            ("no_hyp", "CHATAFL_HYPOTHESIS", "0"),
            ("no_refine", "CHATAFL_NO_REFINEMENT", "1"),
            ("no_frontier", "CHATAFL_NO_FRONTIER", "1"),
            ("no_sp", "CHATAFL_NO_STATE_PROMPT", "1"),
        ):
            with self.subTest(env_name=env_name):
                flag_value = 1 if flag.startswith("no_") else value
                actual = self.wrapped("salvage", env_changes={env_name: value},
                                      flags_changes={flag: flag_value})
                self.assertNotEqual(actual, "salvage8")
        self.assertNotEqual(self.wrapped("salvage", cal="1"), "salvage8")

    def test_legacy_groups_and_four_argument_api_are_unchanged(self):
        cases = [
            ("", "", "", "NONE", "-"),
            ("loopfuzz-direct", "0", "", legacy_flags(), "direct"),
            ("loopfuzz-native-retention", "0", "", legacy_flags(), "native"),
            ("", "0", "", legacy_flags(mode="native"), "native"),
            ("", "0", "", legacy_flags(retain=1), "code_retain"),
            ("loopfuzz-gated-fixed", "0", "", legacy_flags(prov=0, shadow=0), "gate_only"),
            ("loopfuzz-gated-fixed", "0", "", legacy_flags(prov=1, shadow=0), "gate_prov"),
            ("loopfuzz-gated-fixed", "0", "", legacy_flags(prov=1, shadow=1), "gate"),
            ("loopfuzz-gated-calibrated", "1", "0.995", legacy_flags(), "calibrated"),
            ("loopfuzz-gated-calibrated", "1", "0.99", legacy_flags(), "cal_gamma099"),
            ("loopfuzz-gated-calibrated", "1", "1.0", legacy_flags(), "cal_gamma100"),
            ("", "1", "", legacy_flags(state_select="ewma"), "cal_ewma"),
            ("", "1", "", legacy_flags(state_select="run_rate"), "cal_run_rate"),
            ("", "0", "", legacy9_flags(), "gated_fixed"),
            ("", "0", "", legacy9_flags(no_hyp=1), "wo_hypothesis"),
            ("", "0", "", legacy9_flags(no_refine=1), "wo_refinement"),
            ("", "0", "", legacy9_flags(no_frontier=1), "wo_frontier"),
            ("", "0", "", legacy9_flags(no_sp=1), "wo_state_prompt"),
            ("", "0", "", legacy9_flags(no_adaptive=1, threshold=512), "wo_adaptive"),
            ("", "0", "", legacy9_flags(no_adaptive=1, threshold=8), "fixed8"),
            ("", "0", "", legacy9_flags(no_hyp=1, no_refine=1), "wo_hypothesis+wo_refinement"),
            ("", "0", "", legacy9_flags(no_hyp=1, no_refine=1, no_frontier=1,
                                         no_adaptive=1, no_sp=1), "wo_all"),
        ]
        for arm, cal, gamma, flags, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(self.resolve(arm, cal, gamma, flags, four_args=True), expected)
                self.assertEqual(self.resolve(arm, cal, gamma, flags, legacy=True,
                                              four_args=True), expected)

    def test_future_group_registers_without_changing_dispatcher(self):
        prefix = """
future_arm() {
    [[ "$1" == "future-runtime-arm" ]] || return 1
    printf '%s\\n' future_family
}
MONITOR_ABLATION_RESOLVERS=(future_arm "${MONITOR_ABLATION_RESOLVERS[@]}")
MONITOR_ABLATION_ENV_KEYS+=(CHATAFL_FUTURE_ARM)
"""
        self.assertEqual(self.resolve("future-runtime-arm", prefix=prefix), "future_family")
        self.assertEqual(self.resolve("loopfuzz-direct", prefix=prefix), "direct")

    def test_older_nine_field_flags_remain_supported(self):
        for flags, expected in (
            ("0 0 0 0 0 0 0 - -", "gated_fixed"),
            ("0 0 0 1 0 0 0 - 8", "fixed8"),
            ("0 0 0 0 0 1 0 - -", "direct"),
            ("0 0 0 0 0 0 1 0.99 -", "cal_gamma099"),
        ):
            with self.subTest(flags=flags):
                self.assertEqual(self.resolve(flags=flags, four_args=True), expected)

    def collect_mock(self, family, *, prefix=""):
        mode = "direct" if family == "wrapdirect" else "gate"
        arm = "loopfuzz-direct" if mode == "direct" else "loopfuzz-gated-fixed"
        environment = {
            "CHATAFL_ADMISSION_MODE": mode, "CHATAFL_PLAINTEXT_WRAP": "1",
            "CHATAFL_SALVAGE": str(int(family == "salvage")),
            "CHATAFL_NO_ADAPTIVE": "0", "CHATAFL_ABLATION_THRESHOLD": "512",
            "CHATAFL_TEST_EXTENSION": "future",
        }
        # Execute the actual remote env collector with only /proc/1/environ
        # mocked. This checks the registry's named-key transport as well as the
        # collector-to-resolver connection, without requiring Docker.
        env_words = shlex.join([f"{key}={value}" for key, value in environment.items()])
        fixture = f"""
cat() {{
    if [[ "$1" == "/proc/1/environ" ]]; then
        printf '%s\\0' {env_words}
    else
        command cat "$@"
    fi
}}
export -f cat
docker() {{
    [[ "$1" == "exec" ]] || return 91
    shift 2
    case "$1" in
        cat)
            command cat <<'STATS'
start_time: 1
bitmap_cvg: 1.5%
paths_total: 7
paths_favored: 4
execs_done: 100
execs_per_sec: 10
unique_crashes: 0
unique_hangs: 0
cycles_done: 2
pending_total: 3
stability: 100%
plateau_calls: 1
llm_total_calls: 1
llm_prompt_tokens: 20
llm_completion_tok: 30
hypothesis_count: 2
hypothesis_avg_fitness: 1
plateau_threshold: 8
oracle_unique_violations: 0
mqtt_diff_obs: 0
mqtt_diff_pos: 0
mqtt_diff_avg: 0
mqtt_diff_last: 0
arm: {arm}
calibration: 0
cal_gamma: 0.9950
plaintext_wrap_enabled: 1
salvage_enabled: {int(family == "salvage")}
STATS
            ;;
        bash)
            if [[ "$3" == *"/proc/1/environ"* ]]; then
                command "$@"
            else
                printf '%s\\n' /home/ubuntu/experiments/out-bftpd-loopfuzz
            fi
            ;;
        grep) printf '%s\\n' 1 ;;
        tail) printf '%s\\n' 1,0 ;;
        *) return 92 ;;
    esac
}}
{prefix}
if row=$(collect_one mock-container); then
    printf '%s\\n' "$row"
else
    exit 93
fi
"""
        return self.shell(fixture)

    def test_collect_one_uses_runtime_identity_and_named_environment(self):
        for family in ("wrapdirect", "wrapgate", "salvage"):
            with self.subTest(family=family):
                fields = self.collect_mock(family).split("|")
                self.assertEqual(len(fields), 33)
                self.assertEqual(fields[:3], ["mock-container", "bftpd", "loopfuzz"])
                self.assertEqual(fields[-1], f"{family}8")
                self.assertEqual(fields[25], "exact")

    def test_collect_one_transports_registered_future_environment_key(self):
        prefix = """
future_arm() {
    [[ "$6" == *CHATAFL_TEST_EXTENSION=future* ]] || return 1
    printf '%s\\n' future_family
}
MONITOR_ABLATION_RESOLVERS=(future_arm "${MONITOR_ABLATION_RESOLVERS[@]}")
MONITOR_ABLATION_ENV_KEYS+=(CHATAFL_TEST_EXTENSION)
"""
        fields = self.collect_mock("wrapgate", prefix=prefix).split("|")
        self.assertEqual(fields[-1], "future_family")

    def test_mechanism_panel_reuses_the_collected_arm_label(self):
        output = self.shell("""
mech_collect_one() {
    printf '%s\\n' 'bftpd|loopfuzz-gated-fixed|commit|0|0|default|100|7'
}
mech_print_table() { printf '%s\\n' "$@"; }
mech_section mock-container 'mock-container|other-fields|salvage8'
""")
        self.assertEqual(output.split("|")[:3], ["bftpd", "salvage8", "commit"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
