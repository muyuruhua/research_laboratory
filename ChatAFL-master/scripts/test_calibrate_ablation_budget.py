#!/usr/bin/env python3
"""Offline synthetic-archive contract tests; no targets or gateways are run."""
import copy
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import calibrate_ablation_budget as cb


class BudgetCalibrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.manifest = {
            "schema_version": 1, "target": "bftpd", "batch_id": "pilot-test",
            "pilot_duration_seconds": 60, "formal_duration_seconds": 86400,
            "temporary_call_cap": 100, "expected_arms": ["nollm512"], "runs": [],
        }
        self.evidence = {}
        self.add_arm("nollm512", [3, 3, 3])

    def tearDown(self):
        self.temp.cleanup()

    def add_arm(self, arm, counts):
        if arm not in self.manifest["expected_arms"]:
            self.manifest["expected_arms"].append(arm)
        for repeat, calls in enumerate(counts, 1):
            stamp = f"ablation_{arm}_pilot-test"
            archive = self.root / f"results-bftpd_{stamp}" / f"out-bftpd-loopfuzz_{repeat}.tar.gz"
            run = {"arm": arm, "repeat": repeat, "target": "bftpd", "archive": str(archive), "expected_timestamp": stamp}
            self.manifest["runs"].append(run)
            cfg = {
                "event": "run_config", "phase": "start", "campaign_id": f"{arm}-{repeat}",
                "config_hash": f"config-{arm}", "target": "bftpd", "protocol_name": "FTP",
                "target_sha256": "target-hash", "fuzzer_sha256": "fuzzer-hash", "loopfuzz_source_sha256": "source-hash",
                "seeds_sha256": "seed-hash", "image_digest": "image-hash", "rng_seed": repeat, "afl_rng_seed": repeat + 100,
                "campaign_call_budget": 100, "campaign_stop_mode": "wallclock", "campaign_duration_sec": 60,
                "threshold_resolved": 512, "scheduler_warmup_max_selections": 64, "episode_energy_cap": 512,
                "cal_reward_window_invocations": 0, "no_llm": arm == "nollm512", "mock_gateway": None,
                "endpoint": "https://gateway.invalid/v1/chat/completions", "model": "synthetic-model",
                "top_p": 1, "max_output_tokens": 4096, "llm_total_call_cap": -1, "token_cap": 0,
                "token_cap_enforced": -1, "q1_policy": "none", "admission_mode": "gate",
                "start_time_ms": 1_000_000, "end_time_ms": 1_000_000,
            }
            if arm == "native512":
                cfg.update(admission_mode="native", provisional_enabled=False, shadow_enabled=False)
            end = dict(cfg, phase="end", end_time_ms=1_060_000, termination_reason="wallclock-duration",
                       campaign_budget_censored=False, campaign_budget_exhausted_time_ms=0)
            executions = []
            for call in range(calls):
                row = {"event": "invocation_start", "campaign_id": cfg["campaign_id"], "attempt_id": call + 1,
                       "invocation_id": call + 1, "execution_id_before": call, "execution_id_after": call, "executed": True}
                executions.extend([row, dict(row, event="invocation_end", execution_id_after=call + 1)])
            data = {
                "run-config.jsonl": [cfg, end], "execution-events.jsonl": executions,
                "fuzzer_stats": {"campaign_call_budget": 100, "campaign_charged_calls": calls, "campaign_budget_exhausted": 0,
                    "no_llm_mode": int(arm == "nollm512"), "llm_total_calls": 0, "llm_prompt_tokens": 0, "llm_completion_tok": 0},
                "q1-budget-flow.jsonl": [{"kind": "campaign-final", "campaign_id": cfg["campaign_id"],
                    "charged_invocations": calls, "saved_total": 0, "idle_total": 0,
                    "reflow_consumed": 0, "reflow_pool_left": 0, "effective_cap": 100}],
                "llm-calls.jsonl": [],
            }
            if arm != "nollm512":
                data["llm-calls.jsonl"] = [{"request_id": "10-1", "pid": 10, "seq": 1, "status": "ok",
                    "endpoint": cfg["endpoint"], "model_requested": cfg["model"], "model_served": "synthetic-version",
                    "archived": True, "prompt_tokens": 2, "completion_tokens": 3}]
                data["llm-archive/10-1.req"] = {"model": cfg["model"], "max_tokens": 4096, "top_p": 1,
                    "messages": [{"role": "user", "content": "synthetic fixture"}]}
                data["llm-archive/10-1.resp"] = {"model": "synthetic-version", "usage": {"prompt_tokens": 2, "completion_tokens": 3},
                    "choices": [{"message": {"content": "synthetic fixture reply"}}]}
            self.evidence[(arm, repeat)] = data

    def materialize(self, duplicate_member=False):
        for run in self.manifest["runs"]:
            data = self.evidence[(run["arm"], run["repeat"])]
            path = Path(run["archive"])
            path.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(path, "w:gz") as tf:
                for name, value in data.items():
                    if name == "fuzzer_stats":
                        raw = "".join(f"{k} : {v}\n" for k, v in value.items()).encode()
                    elif name.endswith(".jsonl"):
                        raw = "".join(json.dumps(row) + "\n" for row in value).encode()
                    else:
                        raw = json.dumps(value).encode()
                    entry = tarfile.TarInfo("out-bftpd-loopfuzz/" + name)
                    entry.size = len(raw)
                    tf.addfile(entry, io.BytesIO(raw))
                    if duplicate_member and name == "fuzzer_stats":
                        tf.addfile(entry, io.BytesIO(raw))

    def reject(self):
        self.materialize()
        with self.assertRaises(cb.CalibrationError):
            cb.calibrate(self.manifest)

    def test_zero_variance_positive_rate_is_valid(self):
        self.materialize()
        report = cb.calibrate(self.manifest)
        self.assertEqual(report["q1_common_call_budget"], 4320)
        self.assertEqual(report["arms"]["nollm512"]["sample_sd"], 0)
        self.assertFalse(report["mechanism_sufficiency_assessed"])

    def test_no_llm_ledger_may_be_absent_with_zero_stats(self):
        for repeat in (1, 2, 3):
            del self.evidence[("nollm512", repeat)]["llm-calls.jsonl"]
        self.materialize()
        self.assertEqual(cb.calibrate(self.manifest)["q1_common_call_budget"], 4320)

    def test_no_llm_missing_zero_counters_is_rejected(self):
        del self.evidence[("nollm512", 1)]["fuzzer_stats"]["llm_total_calls"]
        self.reject()

    def test_no_llm_nonzero_counter_is_rejected(self):
        self.evidence[("nollm512", 1)]["fuzzer_stats"]["llm_prompt_tokens"] = 1
        self.reject()

    def test_max_arm_student_t_upper_bound_uses_actual_elapsed(self):
        self.add_arm("native512", [3, 6, 9])
        self.materialize()
        report = cb.calibrate(self.manifest)
        expected = cb.math.ceil(86400 * (0.1 + cb.T95_DF2 * 0.05 / cb.math.sqrt(3)))
        self.assertEqual(report["q1_common_call_budget"], expected)

    def test_short_pilot_is_rejected(self):
        self.evidence[("nollm512", 1)]["run-config.jsonl"][1]["end_time_ms"] -= 1
        self.reject()

    def test_reached_temporary_cap_is_rejected(self):
        data = self.evidence[("nollm512", 1)]
        data["fuzzer_stats"].update(campaign_charged_calls=100, campaign_budget_exhausted=1)
        self.reject()

    def test_bad_charged_count_is_rejected(self):
        self.evidence[("nollm512", 1)]["fuzzer_stats"]["campaign_charged_calls"] += 1
        self.reject()

    def test_mock_configuration_is_rejected(self):
        for row in self.evidence[("nollm512", 1)]["run-config.jsonl"]:
            row["mock_gateway"] = {"port": 12345}
        self.reject()

    def test_live_arm_requires_raw_successful_response(self):
        self.add_arm("native512", [3, 3, 3])
        del self.evidence[("native512", 1)]["llm-archive/10-1.resp"]
        self.reject()

    def test_trial_only_or_premature_end_is_rejected(self):
        self.evidence[("nollm512", 1)]["run-config.jsonl"].pop()
        self.reject()

    def test_duplicate_campaign_is_rejected(self):
        data = self.evidence[("nollm512", 2)]
        for name in ("run-config.jsonl", "execution-events.jsonl", "q1-budget-flow.jsonl"):
            for row in data[name]:
                row["campaign_id"] = "nollm512-1"
        self.reject()

    def test_duplicate_archive_member_is_rejected(self):
        self.materialize(duplicate_member=True)
        with self.assertRaises(cb.CalibrationError):
            cb.calibrate(self.manifest)

    def test_duplicate_repeat_is_rejected(self):
        self.manifest["runs"][1] = copy.deepcopy(self.manifest["runs"][0])
        self.reject()

    def test_missing_repeat_is_rejected(self):
        self.manifest["runs"].pop()
        self.reject()

    def test_old_batch_path_is_rejected(self):
        self.manifest["runs"][0]["expected_timestamp"] = "ablation_nollm512_old-pilot"
        self.reject()

    def test_reused_rng_seed_is_rejected(self):
        for row in self.evidence[("nollm512", 2)]["run-config.jsonl"]:
            row["rng_seed"] = 1
        self.reject()

    def test_missing_terminal_quota_record_is_rejected(self):
        self.evidence[("nollm512", 1)]["q1-budget-flow.jsonl"] = []
        self.reject()

    def test_shared_build_mismatch_is_rejected(self):
        for row in self.evidence[("nollm512", 2)]["run-config.jsonl"]:
            row["fuzzer_sha256"] = "other-build"
        self.reject()

    def test_q1b_park_is_excluded_from_rate_estimation(self):
        self.manifest["expected_arms"] = ["q1b512"]
        self.reject()

    def test_oversized_budget_fails_instead_of_clamping(self):
        self.manifest["formal_duration_seconds"] = 3_000_000_000
        self.reject()

    def test_cli_writes_freeze_atomically(self):
        self.materialize()
        manifest = self.root / "manifest.json"
        output = self.root / "frozen.json"
        manifest.write_text(json.dumps(self.manifest))
        with redirect_stdout(io.StringIO()):
            code = cb.main(["--manifest", str(manifest), "--output", str(output)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.read_text())["q1_common_call_budget"], 4320)

    def test_cli_does_not_echo_malformed_payload_or_write_budget(self):
        manifest = self.root / "bad.json"
        output = self.root / "no-budget.json"
        manifest.write_text('SENSITIVE_SENTINEL_NOT_TO_ECHO')
        stderr = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(io.StringIO()):
            code = cb.main(["--manifest", str(manifest), "--output", str(output)])
        self.assertEqual(code, 1)
        self.assertNotIn("SENSITIVE_SENTINEL", stderr.getvalue())
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
