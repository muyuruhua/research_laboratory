#!/usr/bin/env python3
"""Audit three-repeat Q2 salvage-vs-ordinary-match archive pairs.

This layer compares two collections.  The single-archive Q1–Q3 telemetry
auditor remains responsible for checking each root's admit/terminal/
productivity linkage; this program applies the cross-arm configuration,
sample-floor, and delivered-dose gates needed for Q2 answerability.
"""

from __future__ import annotations

import argparse
import json
import statistics
import tarfile
from collections import defaultdict
from pathlib import Path
from typing import Any

import audit_q123_telemetry as telemetry


REPEAT_IDS = (1, 2, 3)
MIN_LINKED_POSITIVE_ROOTS = 10
DOSE_RATIO_LOW = 0.80
DOSE_RATIO_HIGH = 1.25

# Values that identify a run rather than its experimental configuration, or
# that deliberately differ between the salvage and ordinary-match treatments.
CONFIG_FIELDS_IGNORED_FOR_SHARED_MATCH = {
    "phase", "pid", "start_time_ms", "end_time_ms", "monotonic_ms",
    "campaign_id", "config_hash", "rng_seed", "afl_rng_seed",
    "arm", "ordinary_budget", "ordinary_rate",
}

TERMINAL_KIND_TO_OUTCOME = {
    "convert": "convert",
    "expire": "expire",
    "ordinary-close": "ordinary-close",
    "censor": "censor",
}


def _is_int(value: Any, *, positive: bool = False) -> bool:
    return type(value) is int and (value > 0 if positive else value >= 0)


def _is_nonnegative_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0


def _all_equal(values: list[Any]) -> bool:
    return bool(values) and all(value == values[0] for value in values[1:])


def _load_repeat(path: Path, expected_repeat: int) -> dict[str, Any]:
    if path.is_file():
        data, errors, label = telemetry._read_tar(path)
    elif path.is_dir():
        data, errors, label = telemetry._read_dir(path)
    else:
        raise FileNotFoundError(path)

    report = telemetry._report(data, errors, label)
    cfg_rows = data.get("run-config.jsonl", [])
    start_cfg = next((r for r in cfg_rows if r.get("phase") == "start"), {})
    end_cfg = next((r for r in reversed(cfg_rows) if r.get("phase") == "end"), {})
    stats_rows = data.get("fuzzer_stats", [])
    stats = stats_rows[0] if stats_rows else {}

    report_repeat = telemetry._repeat_index(path)
    repeat_matches = report_repeat == expected_repeat
    q2 = report.get("Q2_provisional_productivity_and_salvage", {})
    base_lifecycle_ok = (
        q2.get("root_identity_audit", {}).get("identity_fields_complete") is True
        and q2.get("root_identity_audit", {}).get("lifecycle_matches_by_id") is True
        and q2.get("dose_audit", {}).get("descendant_invocation_fields_complete") is True
        and q2.get("salvage_route_audit", {}).get("mapping_complete") is True
    )
    cohort_classification_errors = _cohort_classification_errors(data)
    local_lifecycle_ok = base_lifecycle_ok and not cohort_classification_errors
    linked = _linked_positive_doses(data, local_lifecycle_ok)
    outcomes, outcome_fields_complete = _linked_positive_q2_outcomes(data, local_lifecycle_ok)
    return {
        "path": str(path),
        "repeat_index": report_repeat,
        "repeat_index_matches_expected": repeat_matches,
        "data": data,
        "errors": errors,
        "report": report,
        "config": start_cfg,
        "end_config": end_cfg,
        "stats": stats,
        "linked_positive_doses": linked,
        "linked_positive_q2_outcomes": outcomes,
        "q2_outcome_fields_complete": outcome_fields_complete,
        "local_lifecycle_ok": local_lifecycle_ok,
        "cohort_classification_errors": cohort_classification_errors,
        "campaign_complete": (
            end_cfg.get("phase") == "end"
            and end_cfg.get("termination_reason") == "campaign-call-budget"
            and _is_int(start_cfg.get("campaign_call_budget"), positive=True)
            and stats.get("campaign_call_budget") == start_cfg.get("campaign_call_budget")
            and stats.get("campaign_charged_calls") == start_cfg.get("campaign_call_budget")
            and stats.get("campaign_budget_exhausted") == 1
        ),
    }


def _cohort_classification_errors(data: dict[str, list[dict[str, Any]]]) -> list[str]:
    """Reject a linked root if its admission flag and productivity cohort disagree."""
    provisional = data.get("provisional-events.jsonl", [])
    productivity = data.get("productivity-events.jsonl", [])
    admits = [row for row in provisional if row.get("kind") == "admit"]
    terminals = [row for row in provisional if row.get("kind") in TERMINAL_KIND_TO_OUTCOME]
    stages: dict[str, dict[tuple[int, int], list[dict[str, Any]]]] = {
        "admit": defaultdict(list), "terminal": defaultdict(list), "productivity": defaultdict(list),
    }
    for name, rows, root_field in (
        ("admit", admits, "queue_entry"),
        ("terminal", terminals, "queue_entry"),
        ("productivity", productivity, "root_queue_id"),
    ):
        for row in rows:
            identity = telemetry._q2_root_identity(row, root_field)
            if identity is not None:
                stages[name][identity].append(row)

    errors: list[str] = []
    for identity in set().union(*(set(group) for group in stages.values())):
        a = stages["admit"].get(identity, [])
        t = stages["terminal"].get(identity, [])
        p = stages["productivity"].get(identity, [])
        if len(a) != 1 or len(t) != 1 or len(p) != 1:
            continue  # The independent lifecycle gate reports cardinality failures.
        cohort = p[0].get("cohort")
        if cohort == "ordinary_match":
            cohort = "ordinary-match"
        ordinary_flag = a[0].get("ordinary_match") is True
        if cohort not in ("provisional", "ordinary-match") or ordinary_flag != (cohort == "ordinary-match"):
            errors.append(telemetry._q2_identity_label(identity))
    return sorted(errors)


def _linked_positive_doses(
    data: dict[str, list[dict[str, Any]]], lifecycle_ok: bool,
) -> dict[str, list[int]]:
    """Return positive descendant doses only for uniquely linked roots."""
    if not lifecycle_ok:
        return {"provisional": [], "ordinary-match": []}

    provisional = data.get("provisional-events.jsonl", [])
    productivity = data.get("productivity-events.jsonl", [])
    admits = [row for row in provisional if row.get("kind") == "admit"]
    terminals = [row for row in provisional if row.get("kind") in TERMINAL_KIND_TO_OUTCOME]
    stages: dict[str, dict[tuple[int, int], list[dict[str, Any]]]] = {
        "admit": defaultdict(list), "terminal": defaultdict(list), "productivity": defaultdict(list),
    }
    for name, rows, root_field in (
        ("admit", admits, "queue_entry"),
        ("terminal", terminals, "queue_entry"),
        ("productivity", productivity, "root_queue_id"),
    ):
        for row in rows:
            identity = telemetry._q2_root_identity(row, root_field)
            if identity is not None:
                stages[name][identity].append(row)

    doses: dict[str, list[int]] = {"provisional": [], "ordinary-match": []}
    all_ids = set().union(*(set(group) for group in stages.values()))
    for identity in all_ids:
        a = stages["admit"].get(identity, [])
        t = stages["terminal"].get(identity, [])
        p = stages["productivity"].get(identity, [])
        if len(a) != 1 or len(t) != 1 or len(p) != 1:
            continue
        dose = p[0].get("descendant_invocations")
        cohort = p[0].get("cohort")
        if cohort == "ordinary_match":
            cohort = "ordinary-match"
        if (
            TERMINAL_KIND_TO_OUTCOME.get(t[0].get("kind")) != p[0].get("outcome")
            or t[0].get("descendant_execs") != dose
            or not _is_int(dose, positive=True)
            or (a[0].get("ordinary_match") is True) != (cohort == "ordinary-match")
            or cohort not in doses
        ):
            continue
        doses[cohort].append(dose)
    return doses


def _linked_positive_q2_outcomes(
    data: dict[str, list[dict[str, Any]]], lifecycle_ok: bool,
) -> tuple[dict[str, list[dict[str, Any]]], bool]:
    """Collect outcome fields for uniquely linked roots with delivered dose.

    The numerator is baseline-valid conversion beyond-baseline AFL bitmap
    slots. The denominator includes all linked positive-dose descendant calls.
    """
    outcomes: dict[str, list[dict[str, Any]]] = {"provisional": [], "ordinary-match": []}
    if not lifecycle_ok:
        return outcomes, False

    provisional = data.get("provisional-events.jsonl", [])
    productivity = data.get("productivity-events.jsonl", [])
    admits = [row for row in provisional if row.get("kind") == "admit"]
    terminals = [row for row in provisional if row.get("kind") in TERMINAL_KIND_TO_OUTCOME]
    stages: dict[str, dict[tuple[int, int], list[dict[str, Any]]]] = {
        "admit": defaultdict(list), "terminal": defaultdict(list), "productivity": defaultdict(list),
    }
    for name, rows, root_field in (
        ("admit", admits, "queue_entry"),
        ("terminal", terminals, "queue_entry"),
        ("productivity", productivity, "root_queue_id"),
    ):
        for row in rows:
            identity = telemetry._q2_root_identity(row, root_field)
            if identity is not None:
                stages[name][identity].append(row)

    fields_complete = True
    all_ids = set().union(*(set(group) for group in stages.values()))
    for identity in all_ids:
        a = stages["admit"].get(identity, [])
        t = stages["terminal"].get(identity, [])
        p = stages["productivity"].get(identity, [])
        if len(a) != 1 or len(t) != 1 or len(p) != 1:
            fields_complete = False
            continue
        row = p[0]
        dose = row.get("descendant_invocations")
        cohort = row.get("cohort")
        if cohort == "ordinary_match":
            cohort = "ordinary-match"
        if (
            TERMINAL_KIND_TO_OUTCOME.get(t[0].get("kind")) != row.get("outcome")
            or t[0].get("descendant_execs") != dose
            or not _is_int(dose)
            or (a[0].get("ordinary_match") is True) != (cohort == "ordinary-match")
            or cohort not in outcomes
        ):
            fields_complete = False
            continue
        if dose == 0:
            continue
        baseline_valid = row.get("baseline_valid")
        slots = row.get("beyond_baseline_slots")
        conversion_class = row.get("conversion_class")
        if (
            not isinstance(baseline_valid, bool)
            or not _is_int(conversion_class)
            or conversion_class not in (0, 1, 2)
            or (baseline_valid and row.get("outcome") == "convert" and not _is_nonnegative_number(slots))
        ):
            fields_complete = False
            continue
        if baseline_valid and row.get("outcome") == "convert" and ((conversion_class == 2) != (slots > 0)):
            fields_complete = False
            continue
        outcomes[cohort].append({
            "descendant_invocations": dose,
            "outcome": row.get("outcome"),
            "baseline_valid": baseline_valid,
            "conversion_class": conversion_class,
            "beyond_baseline_slots": (
                slots if baseline_valid and row.get("outcome") == "convert" else 0
            ),
        })
    return outcomes, fields_complete


def _q2_outcome_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    descendant_calls = sum(row["descendant_invocations"] for row in rows)
    beyond_baseline_slots = sum(row["beyond_baseline_slots"] for row in rows)
    conversions = [row for row in rows if row["outcome"] == "convert"]
    baseline_valid_conversions = [row for row in conversions if row["baseline_valid"]]
    beyond_trial_conversions = [row for row in baseline_valid_conversions if row["conversion_class"] == 2]
    return {
        "linked_positive_roots": len(rows),
        "descendant_calls": descendant_calls,
        "conversions": len(conversions),
        "baseline_valid_conversions": len(baseline_valid_conversions),
        "beyond_trial_conversions": len(beyond_trial_conversions),
        "beyond_baseline_bitmap_slots": beyond_baseline_slots,
        "beyond_baseline_bitmap_slots_per_1000_descendant_calls": (
            beyond_baseline_slots * 1000.0 / descendant_calls if descendant_calls else None
        ),
    }


def _discover_three(inputs: list[Path], role: str) -> tuple[dict[int, Path], list[str]]:
    samples = telemetry.discover(inputs)
    by_repeat: dict[int, Path] = {}
    errors: list[str] = []
    for sample in samples:
        repeat = telemetry._repeat_index(sample)
        if repeat not in REPEAT_IDS:
            errors.append(f"{role}: cannot map sample to repeat 1–3: {sample}")
            continue
        if repeat in by_repeat:
            errors.append(f"{role}: duplicate archive for repeat {repeat}: {by_repeat[repeat]} and {sample}")
            continue
        by_repeat[repeat] = sample
    missing = sorted(set(REPEAT_IDS) - set(by_repeat))
    if missing:
        errors.append(f"{role}: missing repeats {missing}")
    return by_repeat, errors


def _shared_config(config: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in config.items()
        if key not in CONFIG_FIELDS_IGNORED_FOR_SHARED_MATCH
    }


def _pair_repeat(
    repeat: int,
    salvage: dict[str, Any],
    ordinary: dict[str, Any],
) -> dict[str, Any]:
    scfg, ocfg = salvage["config"], ordinary["config"]
    sstats, ostats = salvage["stats"], ordinary["stats"]
    salvage_doses = salvage["linked_positive_doses"]["provisional"]
    ordinary_doses = ordinary["linked_positive_doses"]["ordinary-match"]

    shared_config_match = bool(scfg) and _shared_config(scfg) == _shared_config(ocfg)
    target_match = scfg.get("target") == ocfg.get("target") and bool(scfg.get("target"))
    budget_values = (
        scfg.get("campaign_call_budget"), ocfg.get("campaign_call_budget"),
        sstats.get("campaign_call_budget"), ostats.get("campaign_call_budget"),
    )
    campaign_budget_match = (
        _is_int(budget_values[0], positive=True)
        and _all_equal(budget_values)
    )
    root_cap_values = (scfg.get("provisional_budget"), ocfg.get("provisional_budget"))
    root_cap_scope_values = (scfg.get("provisional_budget_scope"), ocfg.get("provisional_budget_scope"))
    root_cap_match = (
        _is_int(root_cap_values[0], positive=True)
        and _all_equal(list(root_cap_values))
        and bool(root_cap_scope_values[0])
        and _all_equal(list(root_cap_scope_values))
    )
    per_root_doses_within_cap = (
        _is_int(root_cap_values[0], positive=True)
        and all(dose <= root_cap_values[0] for dose in salvage_doses + ordinary_doses)
    )
    salvage_report_q2 = salvage["report"].get("Q2_provisional_productivity_and_salvage", {})
    ordinary_report_q2 = ordinary["report"].get("Q2_provisional_productivity_and_salvage", {})
    treatment_labels_valid = (
        scfg.get("ordinary_budget") is False
        and scfg.get("salvage_enabled") is True
        and salvage_report_q2.get("salvage_admitted_roots") == salvage_report_q2.get("admitted_roots")
        and salvage_report_q2.get("ordinary_match_admitted_roots") == 0
        and ocfg.get("ordinary_budget") is True
        and ocfg.get("salvage_enabled") is True
        and ordinary_report_q2.get("ordinary_match_admitted_roots", 0) >= MIN_LINKED_POSITIVE_ROOTS
    )
    lifecycle_valid = salvage["local_lifecycle_ok"] and ordinary["local_lifecycle_ok"]
    outcome_fields_complete = (
        salvage.get("q2_outcome_fields_complete") is True
        and ordinary.get("q2_outcome_fields_complete") is True
    )
    campaign_complete = salvage["campaign_complete"] and ordinary["campaign_complete"]
    min_roots_met = (
        len(salvage_doses) >= MIN_LINKED_POSITIVE_ROOTS
        and len(ordinary_doses) >= MIN_LINKED_POSITIVE_ROOTS
    )
    salvage_median = statistics.median(salvage_doses) if salvage_doses else None
    ordinary_median = statistics.median(ordinary_doses) if ordinary_doses else None
    dose_ratio = (
        salvage_median / ordinary_median
        if salvage_median is not None and ordinary_median is not None and ordinary_median > 0
        else None
    )
    dose_ratio_ok = (
        dose_ratio is not None
        and DOSE_RATIO_LOW <= dose_ratio <= DOSE_RATIO_HIGH
    )
    parse_ok = not salvage["errors"] and not ordinary["errors"]
    consistency_ok = (
        salvage["report"].get("telemetry_consistency_status") == "consistent"
        and ordinary["report"].get("telemetry_consistency_status") == "consistent"
        and not salvage["report"].get("required_but_missing_telemetry_files")
        and not ordinary["report"].get("required_but_missing_telemetry_files")
    )
    gates = {
        "repeat_index_matches": salvage["repeat_index_matches_expected"] and ordinary["repeat_index_matches_expected"],
        "parse_and_telemetry_consistency": parse_ok and consistency_ok,
        "target_matches": target_match,
        "shared_configuration_matches": shared_config_match,
        "campaign_budget_matches": campaign_budget_match,
        "per_root_provisional_cap_matches": root_cap_match,
        "linked_root_doses_within_provisional_cap": per_root_doses_within_cap,
        "expected_treatment_configs": treatment_labels_valid,
        "campaign_cap_reached_in_both_arms": campaign_complete,
        "unique_admit_terminal_productivity_links_and_dose_agreement": lifecycle_valid,
        "at_least_10_positive_linked_roots_in_each_arm": min_roots_met,
        "median_descendant_dose_ratio_0.80_to_1.25": dose_ratio_ok,
    }

    salvage_outcome = _q2_outcome_summary(
        salvage.get("linked_positive_q2_outcomes", {}).get("provisional", [])
    )
    ordinary_outcome = _q2_outcome_summary(
        ordinary.get("linked_positive_q2_outcomes", {}).get("ordinary-match", [])
    )
    salvage_rate = salvage_outcome["beyond_baseline_bitmap_slots_per_1000_descendant_calls"]
    ordinary_rate = ordinary_outcome["beyond_baseline_bitmap_slots_per_1000_descendant_calls"]

    def arm_result(row: dict[str, Any], doses: list[int], cohort: str) -> dict[str, Any]:
        return {
            "archive": row["path"],
            "cohort": cohort,
            "linked_positive_roots": len(doses),
            "descendant_dose_sum": sum(doses),
            "median_descendant_dose": statistics.median(doses) if doses else None,
            "campaign_call_budget": row["config"].get("campaign_call_budget"),
            "campaign_charged_calls": row["stats"].get("campaign_charged_calls"),
            "campaign_termination_reason": row["end_config"].get("termination_reason"),
            "target_sha256": row["config"].get("target_sha256"),
            "threshold_requested": row["config"].get("threshold_requested"),
            "provisional_budget": row["config"].get("provisional_budget"),
            "provisional_budget_scope": row["config"].get("provisional_budget_scope"),
            "local_lifecycle_ok": row["local_lifecycle_ok"],
            "cohort_classification_errors": row["cohort_classification_errors"],
        }

    return {
        "repeat": repeat,
        "status": "ready" if all(gates.values()) else "unresolved",
        "salvage": arm_result(salvage, salvage_doses, "provisional"),
        "ordinary_match": arm_result(ordinary, ordinary_doses, "ordinary-match"),
        "median_descendant_dose_ratio_salvage_over_ordinary_match": dose_ratio,
        "q2_outcomes": {
            "status": "ready" if outcome_fields_complete and salvage_rate is not None and ordinary_rate is not None else "unresolved",
            "metric_definition": "baseline-valid conversion beyond-baseline AFL bitmap slots per 1,000 descendant invocations; denominator includes all uniquely linked positive-dose roots in the cohort",
            "salvage": salvage_outcome,
            "ordinary_match": ordinary_outcome,
            "salvage_minus_ordinary_match_slots_per_1000_calls": (
                salvage_rate - ordinary_rate
                if salvage_rate is not None and ordinary_rate is not None else None
            ),
        },
        "gates": gates,
    }


def _all_repeat_gates(runs: list[dict[str, Any]]) -> dict[str, bool]:
    configs = [row["config"] for row in runs]
    stats = [row["stats"] for row in runs]
    if len(runs) != 2 * len(REPEAT_IDS) or not all(configs):
        return {
            "all_six_runs_share_configuration": False,
            "all_six_runs_share_target": False,
            "all_six_runs_share_campaign_budget": False,
            "all_six_runs_share_per_root_provisional_cap": False,
            "all_six_runs_respect_per_root_provisional_cap": False,
        }
    targets = [cfg.get("target") for cfg in configs]
    budgets = [cfg.get("campaign_call_budget") for cfg in configs]
    stat_budgets = [stat.get("campaign_call_budget") for stat in stats]
    root_caps = [cfg.get("provisional_budget") for cfg in configs]
    root_cap_scopes = [cfg.get("provisional_budget_scope") for cfg in configs]
    roots_respect_caps = all(
        _is_int(cfg.get("provisional_budget"), positive=True)
        and all(
            dose <= cfg["provisional_budget"]
            for cohort_doses in row["linked_positive_doses"].values()
            for dose in cohort_doses
        )
        for cfg, row in zip(configs, runs)
    )
    canonical_shared = {
        json.dumps(_shared_config(cfg), sort_keys=True, separators=(",", ":"))
        for cfg in configs
    }
    return {
        "all_six_runs_share_configuration": len(canonical_shared) == 1,
        "all_six_runs_share_target": isinstance(targets[0], str) and bool(targets[0]) and _all_equal(targets),
        "all_six_runs_share_campaign_budget": (
            _is_int(budgets[0], positive=True)
            and _all_equal(budgets)
            and _all_equal(stat_budgets)
            and stat_budgets == budgets
        ),
        "all_six_runs_share_per_root_provisional_cap": (
            _is_int(root_caps[0], positive=True)
            and _all_equal(root_caps)
            and bool(root_cap_scopes[0])
            and _all_equal(root_cap_scopes)
        ),
        "all_six_runs_respect_per_root_provisional_cap": roots_respect_caps,
    }


def audit_q2_pair(salvage_inputs: list[Path], ordinary_inputs: list[Path]) -> dict[str, Any]:
    salvage_paths, salvage_discovery_errors = _discover_three(salvage_inputs, "salvage")
    ordinary_paths, ordinary_discovery_errors = _discover_three(ordinary_inputs, "ordinary-match")
    discovery_errors = salvage_discovery_errors + ordinary_discovery_errors

    salvage_runs: dict[int, dict[str, Any]] = {}
    ordinary_runs: dict[int, dict[str, Any]] = {}
    for repeat, path in salvage_paths.items():
        salvage_runs[repeat] = _load_repeat(path, repeat)
    for repeat, path in ordinary_paths.items():
        ordinary_runs[repeat] = _load_repeat(path, repeat)

    all_runs = [*salvage_runs.values(), *ordinary_runs.values()]
    global_gates = _all_repeat_gates(all_runs)
    all_global_gates_pass = all(global_gates.values())
    pairs = [
        _pair_repeat(repeat, salvage_runs[repeat], ordinary_runs[repeat])
        for repeat in REPEAT_IDS
        if repeat in salvage_runs and repeat in ordinary_runs
    ]
    for pair in pairs:
        pair["gates"].update(global_gates)
        if not all_global_gates_pass:
            pair["status"] = "unresolved"
        if pair["status"] != "ready":
            pair["q2_outcomes"]["status"] = "unresolved"
    ready = (
        not discovery_errors and len(pairs) == len(REPEAT_IDS)
        and all_global_gates_pass and all(p["status"] == "ready" for p in pairs)
    )
    ratios = [
        p["median_descendant_dose_ratio_salvage_over_ordinary_match"]
        for p in pairs
        if isinstance(p["median_descendant_dose_ratio_salvage_over_ordinary_match"], (int, float))
    ]
    outcome_differences = [
        p["q2_outcomes"]["salvage_minus_ordinary_match_slots_per_1000_calls"]
        for p in pairs if p["q2_outcomes"]["status"] == "ready"
    ]
    return {
        "comparison": "salvage vs ordinary-match (Q2 answerability gate)",
        "status": "ready" if ready else "unresolved",
        "scope": {
            "repeat_indices": list(REPEAT_IDS),
            "minimum_linked_positive_roots_per_arm_per_repeat": MIN_LINKED_POSITIVE_ROOTS,
            "allowed_median_dose_ratio_salvage_over_ordinary_match": [DOSE_RATIO_LOW, DOSE_RATIO_HIGH],
            "dose_ratio_definition": "median linked descendant invocations in salvage cohort / median linked descendant invocations in ordinary-match cohort",
            "configuration_matching": "all run-config fields must match except run identity and the declared ordinary-budget treatment fields",
            "repeat_alignment": "archives aligned by repeat index; RNG seeds are reported by source telemetry but need not match",
        },
        "discovery_errors": discovery_errors,
        "all_repeat_prerequisites": global_gates,
        "repeat_pairs": pairs,
        "dose_ratio_summary": {
            "count": len(ratios),
            "mean": statistics.fmean(ratios) if ratios else None,
            "sample_sd": statistics.stdev(ratios) if len(ratios) >= 2 else None,
            "all_repeat_directions": ratios,
        },
        "q2_outcome_summary": {
            "count": len(outcome_differences),
            "mean_salvage_minus_ordinary_match_slots_per_1000_calls": (
                statistics.fmean(outcome_differences) if outcome_differences else None
            ),
            "sample_sd_of_repeat_differences": (
                statistics.stdev(outcome_differences) if len(outcome_differences) >= 2 else None
            ),
            "repeat_differences": outcome_differences,
            "interpretation": "descriptive three-repeat mock-smoke evidence; positive values favor salvage on this dose-normalized bitmap-slot measure, not a significance claim",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--salvage", required=True, nargs="+", type=Path, help="salvage arm archive(s), extracted run(s), or result collection")
    parser.add_argument("--ordinary-match", required=True, nargs="+", type=Path, help="ordinary-match arm archive(s), extracted run(s), or result collection")
    parser.add_argument("--output", type=Path, help="write the JSON audit report to this path")
    args = parser.parse_args()
    try:
        result = audit_q2_pair(args.salvage, args.ordinary_match)
    except (FileNotFoundError, OSError, ValueError, KeyError, tarfile.ReadError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0 if result["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
