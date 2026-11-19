#!/usr/bin/env python3
"""Project a bounded run-config JSONL snapshot into monitor identity fields.

Only explicit values are emitted. Missing counters remain unknown, and a
partially appended JSONL record does not hide the last complete configuration.
This runs on the monitor host, so target images need no extra dependencies.
"""

import json
import sys


FIELDS = {
    "arm": "arm",
    "calibration": "calibration",
    "cal_gamma": "cal_gamma",
    "plaintext_wrap_enabled": "plaintext_wrap_enabled",
    "salvage_enabled": "salvage_enabled",
    "no_llm": "no_llm_mode",
    "cal_estimator": "cal_estimator",
    "state_select_override": "state_select_override",
    "pv_early_stop_k": "pv_early_stop_k",
    "request_gate": "request_gate_enabled",
    "state_retain": "state_retain_enabled",
    "admission_mode": "admission_mode",
    # This is a dynamic mode: grammar fallback can disable it after startup.
    "hypothesis": "hypothesis_runtime",
    "no_admission": "no_admission",
    "no_adaptive": "no_adaptive",
    "no_refinement": "no_refinement",
    "no_frontier": "no_frontier",
    "no_state_prompt": "no_state_prompt",
    "no_grammar": "no_grammar",
    "no_enrich": "no_enrich",
    "no_plateau": "no_plateau",
    "provisional_enabled": "provisional_enabled",
    "shadow_enabled": "shadow_enabled",
    "code_retain": "code_retain",
    "q1_policy": "q1_policy",
    "ordinary_budget": "ordinary_budget",
    "u_policy": "u_policy_name",
    "scheduler_warmup_max_selections": "scheduler_warmup_max_selections",
    "fuzzer_commit": "fuzzer_commit",
}


def project(lines):
    config = None
    startup = None
    for line in lines:
        try:
            row = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(row, dict) and row.get("event") == "run_config":
            config = row
            if row.get("phase") == "start":
                startup = row
    if config is None:
        return {}

    result = {}
    for source, target in FIELDS.items():
        value = config.get(source)
        if isinstance(value, bool):
            value = int(value)
        if isinstance(value, (str, int, float)) and str(value) not in ("", "-"):
            # Preserve the one-field-per-line compatibility interface.
            result[target] = str(value).replace("\n", " ").replace("\r", " ")
    # Arm identity uses the configured switch, not the mode left at shutdown.
    # A bounded tail may contain only an end record, or an earlier run's start;
    # in either case leave this unset so the launch environment can supply it.
    identity_keys = ("pid", "start_time_ms")
    same_run = startup is config
    if startup is not None and not same_run:
        same_run = any(
            type(startup.get(key)) is int and startup[key] > 0
            for key in identity_keys
        ) and all(startup.get(key) == config.get(key) for key in identity_keys)
    if startup is not None and same_run:
        value = startup.get("hypothesis")
        if isinstance(value, bool):
            value = int(value)
        if isinstance(value, (str, int)) and str(value) in ("0", "1"):
            result["hypothesis_configured"] = str(value)
    threshold = config.get("threshold_resolved")
    if isinstance(threshold, int) and not isinstance(threshold, bool) and threshold > 0:
        result["plateau_threshold"] = str(threshold)
    started = config.get("start_time_ms")
    if isinstance(started, int) and not isinstance(started, bool) and started > 0:
        result["start_time"] = str(started // 1000)
    return result


if __name__ == "__main__":
    for name, value in project(sys.stdin).items():
        print(f"{name}: {value}")
