#!/usr/bin/env python3
"""Print raw, per-repeat Q1–Q3 mechanism telemetry from LoopFuzz archives.

Inputs may be result directories, extracted ``out-*`` directories, tarballs,
or a parent directory containing either. The reader only opens files and
never extracts or modifies archives.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import re
import statistics
import sys
import tarfile
from pathlib import Path
from typing import Any


JSONL_FILES = (
    "run-config.jsonl",
    "execution-events.jsonl",
    "q1-budget-flow.jsonl",
    "provisional-events.jsonl",
    "productivity-events.jsonl",
    "candidate-events.jsonl",
    "admission-events.jsonl",
    "scheduler-selections.jsonl",
    "state-episodes.jsonl",
    "calibration-windows.jsonl",
)

# Kinds emitted by q1_log_flow_event() in LoopFuzz/afl-fuzz.c. A release can
# be parked in the idle ledger or returned to the ordinary-mutation pool,
# depending on the campaign's Q1 policy.
Q1_FLOW_DESTINATIONS = {
    "validation-closed-unused": {"idle", "ordinary-pool"},
    "ordinary-window-closed-unused": {"idle", "ordinary-pool"},
    "validation-converted-unused": {"idle", "ordinary-pool"},
    "candidate-unallocated": {"idle", "ordinary-pool"},
    "consumed": {"ordinary-mutation"},
    "campaign-final": {"none"},
}

Q2_BASELINE_SOURCES = {"saved-session-probe", "original-candidate-trial"}


def _decode_jsonl(raw: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for number, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
            else:
                errors.append(f"line {number}: JSON value is not an object")
        except json.JSONDecodeError as exc:
            errors.append(f"line {number}: {exc.msg}")
    return rows, errors


def _read_tar(path: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[str]], str]:
    data: dict[str, list[dict[str, Any]]] = {}
    errors: dict[str, list[str]] = {}
    with tarfile.open(path, "r:*") as archive:
        members: dict[str, list[tarfile.TarInfo]] = collections.defaultdict(list)
        for member in archive.getmembers():
            basename = Path(member.name).name
            if basename in JSONL_FILES and member.isfile():
                members[basename].append(member)
            elif basename == "fuzzer_stats" and member.isfile():
                members[basename].append(member)
        for filename in JSONL_FILES:
            matches = members.get(filename, [])
            if len(matches) > 1:
                errors[filename] = [f"archive contains {len(matches)} matching members"]
                continue
            if matches:
                stream = archive.extractfile(matches[0])
                if stream is not None:
                    rows, file_errors = _decode_jsonl(stream.read())
                    data[filename] = rows
                    if file_errors:
                        errors[filename] = file_errors
        stats_matches = members.get("fuzzer_stats", [])
        if len(stats_matches) == 1:
            stream = archive.extractfile(stats_matches[0])
            if stream is not None:
                data["fuzzer_stats"] = _parse_stats(stream.read().decode("utf-8", errors="replace"))
        elif len(stats_matches) > 1:
            errors["fuzzer_stats"] = [f"archive contains {len(stats_matches)} matching members"]
    return data, errors, path.name


def _parse_stats(raw: str) -> list[dict[str, Any]]:
    # Represent this key/value file as one row to reuse the report logic.
    result: dict[str, Any] = {}
    for line in raw.splitlines():
        match = re.match(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$", line)
        if not match:
            continue
        key, value = match.groups()
        try:
            result[key.strip()] = int(value)
        except ValueError:
            try:
                result[key.strip()] = float(value)
            except ValueError:
                result[key.strip()] = value
    return [result]


def _read_dir(path: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[str]], str]:
    data: dict[str, list[dict[str, Any]]] = {}
    errors: dict[str, list[str]] = {}
    for filename in JSONL_FILES:
        matches = [candidate for candidate in path.rglob(filename) if candidate.is_file()]
        if len(matches) > 1:
            # A result directory can contain multiple repeats; callers should
            # point at each extracted out-* directory in that case.
            errors[filename] = [f"directory contains {len(matches)} matching files; choose one repeat directory"]
            continue
        if matches:
            rows, file_errors = _decode_jsonl(matches[0].read_bytes())
            data[filename] = rows
            if file_errors:
                errors[filename] = file_errors
    stats_matches = [candidate for candidate in path.rglob("fuzzer_stats") if candidate.is_file()]
    if len(stats_matches) == 1:
        data["fuzzer_stats"] = _parse_stats(stats_matches[0].read_text(errors="replace"))
    elif len(stats_matches) > 1:
        errors["fuzzer_stats"] = [f"directory contains {len(stats_matches)} matching files; choose one repeat directory"]
    return data, errors, str(path)


def discover(inputs: list[Path]) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            found.append(path)

    for path in inputs:
        if path.is_file() and tarfile.is_tarfile(path):
            add(path)
        elif path.is_dir():
            direct_archives = sorted(path.glob("*.tar")) + sorted(path.glob("*.tar.gz")) + sorted(path.glob("*.tgz"))
            if direct_archives:
                for archive in direct_archives:
                    add(archive)
                continue
            # Prefer independently extracted repeat roots to avoid reading a
            # whole result directory as if it were one sample.
            out_dirs = sorted(p for p in path.rglob("out-*") if p.is_dir() and any((p / n).is_file() for n in JSONL_FILES))
            if out_dirs:
                for out_dir in out_dirs:
                    add(out_dir)
                continue
            nested_archives = sorted(path.rglob("*.tar.gz")) + sorted(path.rglob("*.tgz")) + sorted(path.rglob("*.tar"))
            if nested_archives:
                for archive in nested_archives:
                    add(archive)
            else:
                add(path)
        else:
            raise FileNotFoundError(path)
    return found


def _collection_identity(sample: Path) -> tuple[Path | None, dict[str, Any] | None]:
    pattern = re.compile(
        r"^results-(?P<target>.+?)_ablation_(?P<arm_alias>.+?)(?P<threshold>\d+)_(?P<timestamp>\d{8}T\d+)$"
    )
    for parent in (sample, *sample.parents):
        match = pattern.fullmatch(parent.name)
        if match:
            identity = match.groupdict()
            identity["threshold"] = int(identity["threshold"])
            return parent, identity
    return None, None


def _repeat_index(sample: Path) -> int | None:
    match = re.search(r"_(\d+)(?:\.tar(?:\.gz)?)?$", sample.name)
    return int(match.group(1)) if match else None


def _count(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    return dict(sorted(collections.Counter(str(row.get(field)) for row in rows if field in row).items()))


def _sum_field(rows: list[dict[str, Any]], field: str) -> int:
    return sum(value for row in rows if isinstance((value := row.get(field)), (int, float)))


def _numeric_distribution(values: list[int | float]) -> dict[str, int | float | None]:
    ordered = sorted(values)
    if not ordered:
        return {"count": 0, "sum": 0, "min": None, "median": None, "mean": None, "p95_nearest_rank": None, "max": None}
    return {
        "count": len(ordered),
        "sum": sum(ordered),
        "min": ordered[0],
        "median": statistics.median(ordered),
        "mean": round(statistics.fmean(ordered), 3),
        "p95_nearest_rank": ordered[math.ceil(0.95 * len(ordered)) - 1],
        "max": ordered[-1],
    }


def _truth_count(rows: list[dict[str, Any]], field: str) -> int:
    return sum(row.get(field) is True for row in rows)


def _config_value(config: dict[str, Any], key: str, default: Any = None) -> Any:
    return config[key] if key in config else default


def _positive_stat(stats: dict[str, Any], *keys: str) -> bool | None:
    """Return whether any available counter is positive, or None if none exist."""
    values = [stats[key] for key in keys if isinstance(stats.get(key), (int, float))]
    return any(value > 0 for value in values) if values else None


def _telemetry_applicability(
    data: dict[str, list[dict[str, Any]]],
    config: dict[str, Any],
    stats: dict[str, Any],
) -> dict[str, dict[str, str]]:
    """Classify event streams using effective switches and independent counters.

    LoopFuzz creates JSONL files lazily. A file is required only when its
    feature is enabled and an upstream counter proves the event happened.
    Missing run-config or fuzzer_stats leaves that determination unresolved.
    """
    config_present = bool(data.get("run-config.jsonl"))
    stats_present = bool(data.get("fuzzer_stats"))
    rows_present = {name: bool(data.get(name)) for name in JSONL_FILES}
    result: dict[str, dict[str, str]] = {}

    def record(name: str, state: str, reason: str) -> None:
        if rows_present.get(name, False):
            state = "recorded"
            reason = "the JSONL stream contains records"
        result[name] = {"state": state, "reason": reason}

    if config_present:
        record("run-config.jsonl", "recorded", "effective run configuration is present")
    else:
        record("run-config.jsonl", "unresolved", "missing config; event logging may have been disabled or failed")
    if stats_present:
        result["fuzzer_stats"] = {"state": "recorded", "reason": "independent run counters are present"}
    else:
        result["fuzzer_stats"] = {"state": "unresolved", "reason": "missing counters prevent event-opportunity checks"}

    if not config_present:
        for name in JSONL_FILES:
            if name != "run-config.jsonl":
                record(name, "unresolved", "missing run-config prevents applicability checks")
        return result

    # A run-config row can only be emitted while global event logging is on.
    # The global switch itself is not serialized, but its presence establishes
    # that this archive did not intentionally suppress all event streams.
    if _config_value(config, "execution_log") is False:
        record("execution-events.jsonl", "disabled", "execution_log=false")
    elif "execution_log" not in config:
        record("execution-events.jsonl", "unresolved", "execution_log is absent from this config schema")
    elif not stats_present:
        record("execution-events.jsonl", "unresolved", "fuzzer_stats is missing")
    elif _positive_stat(stats, "campaign_charged_calls"):
        record("execution-events.jsonl", "required_missing", "charged run_target calls prove invocation events should exist")
    else:
        record("execution-events.jsonl", "enabled_no_trigger", "no charged invocation is recorded")

    q1_policy = config.get("q1_policy")
    if q1_policy not in ("reflow", "no-reflow"):
        record("q1-budget-flow.jsonl", "not_applicable", f"q1_policy={q1_policy!r} does not use the quota-flow ledger")
    elif not stats_present:
        record("q1-budget-flow.jsonl", "unresolved", "fuzzer_stats is missing")
    elif _positive_stat(stats, "q1_saved_quota", "q1_idle_quota", "q1_reflow_consumed"):
        record("q1-budget-flow.jsonl", "required_missing", "quota counters prove a flow event should exist")
    else:
        record("q1-budget-flow.jsonl", "enabled_no_trigger", "the configured flow policy recorded no quota movement")

    provisional_on = config.get("provisional_enabled") is True
    provisional_off = (
        config.get("provisional_enabled") is False
        or config.get("admission_mode") in ("direct", "native")
    )
    if provisional_off:
        reason = "provisional retention is disabled by the effective admission configuration"
        record("provisional-events.jsonl", "disabled", reason)
        record("productivity-events.jsonl", "disabled", reason)
    elif not provisional_on:
        record("provisional-events.jsonl", "unresolved", "effective provisional_enabled switch is absent")
        record("productivity-events.jsonl", "unresolved", "effective provisional_enabled switch is absent")
    elif not stats_present:
        record("provisional-events.jsonl", "unresolved", "fuzzer_stats is missing")
        record("productivity-events.jsonl", "unresolved", "fuzzer_stats is missing")
    else:
        roots = _positive_stat(stats, "provisional_admitted")
        if roots:
            record("provisional-events.jsonl", "required_missing", "provisional_admitted proves root lifecycle events should exist")
            terminal = _positive_stat(stats, "provisional_converted", "provisional_expired", "provisional_censored", "ordinary_match_closed")
            if terminal:
                record("productivity-events.jsonl", "required_missing", "terminal root counters prove productivity events should exist")
            elif config.get("phase") == "end":
                record("productivity-events.jsonl", "required_missing", "clean end config requires remaining roots to be censored")
            else:
                record("productivity-events.jsonl", "unresolved", "roots exist but this archive has no clean end marker")
        else:
            record("provisional-events.jsonl", "enabled_no_trigger", "no provisional roots were admitted")
            record("productivity-events.jsonl", "enabled_no_trigger", "no provisional roots were admitted")

    # Candidate and admission evidence is event-driven. fuzzer_stats records
    # both successful LLM calls and whether admission accounting was enabled.
    no_llm = config.get("no_llm", stats.get("no_llm_mode") == 1)
    if no_llm is True:
        record("candidate-events.jsonl", "disabled", "no_llm=true")
        record("admission-events.jsonl", "disabled", "no_llm=true")
    elif not stats_present:
        record("candidate-events.jsonl", "unresolved", "fuzzer_stats is missing")
        record("admission-events.jsonl", "unresolved", "fuzzer_stats is missing")
    else:
        calls = _positive_stat(stats, "llm_total_calls")
        if calls:
            record("candidate-events.jsonl", "required_missing", "successful LLM calls prove candidate-source logging should have records")
        else:
            record("candidate-events.jsonl", "enabled_no_trigger", "no successful LLM call is recorded")
        accounting = stats.get("admission_accounting")
        evaluated = _positive_stat(stats, "admission_candidate_total")
        if accounting == 0:
            record("admission-events.jsonl", "disabled", "admission_accounting=0")
        elif accounting == 1 and evaluated:
            record("admission-events.jsonl", "required_missing", "admission_candidate_total proves evaluated candidates should be logged")
        elif accounting == 1:
            record("admission-events.jsonl", "enabled_no_trigger", "admission accounting is on but no candidates were evaluated")
        else:
            record("admission-events.jsonl", "unresolved", "admission_accounting is absent from fuzzer_stats")

    # Every finalized state-selection episode is preceded by a scheduler
    # selection. These streams are independent of whether calibration is on.
    if not stats_present:
        record("scheduler-selections.jsonl", "unresolved", "fuzzer_stats is missing")
        record("state-episodes.jsonl", "unresolved", "fuzzer_stats is missing")
    elif _positive_stat(stats, "cal_episodes_jsonl", "no_seed_stalls", "churn_fallback_used", "campaign_budget_exhausted"):
        record("scheduler-selections.jsonl", "required_missing", "episode or scheduler-fallback counters prove selection events should exist")
        if _positive_stat(stats, "cal_episodes_jsonl"):
            record("state-episodes.jsonl", "required_missing", "cal_episodes_jsonl proves episode records should exist")
        else:
            record("state-episodes.jsonl", "enabled_no_trigger", "no state-selection episode was finalized")
    elif _positive_stat(stats, "cal_episodes_jsonl"):
        record("state-episodes.jsonl", "required_missing", "cal_episodes_jsonl proves episode records should exist")
    else:
        record("scheduler-selections.jsonl", "enabled_no_trigger", "no finalized state-selection episode is recorded")
        record("state-episodes.jsonl", "enabled_no_trigger", "no finalized state-selection episode is recorded")

    window_width = config.get("cal_reward_window_invocations", stats.get("cal_reward_window_invocations", 0))
    if not isinstance(window_width, (int, float)):
        record("calibration-windows.jsonl", "unresolved", "reward-window width is not interpretable")
    elif window_width <= 0:
        record("calibration-windows.jsonl", "not_applicable", "episode-Bernoulli mode does not emit fixed-window rows")
    elif not stats_present:
        record("calibration-windows.jsonl", "unresolved", "fuzzer_stats is missing")
    elif _positive_stat(stats, "cal_training_windows"):
        record("calibration-windows.jsonl", "required_missing", "completed training windows are recorded in fuzzer_stats")
    else:
        record("calibration-windows.jsonl", "enabled_no_trigger", "no complete training window is recorded")
    return result


def _equal_if_available(left: Any, right: Any) -> bool | None:
    return left == right if left is not None and right is not None else None


def _nonnegative_int(value: Any) -> bool:
    """Accept JSON integer counters, excluding bool (which subclasses int)."""
    return type(value) is int and value >= 0


def _q2_root_identity(row: dict[str, Any], root_field: str) -> tuple[int, int] | None:
    """Use the stable candidate/root pair shared by provisional and productivity logs."""
    candidate_id = row.get("candidate_id")
    root_id = row.get(root_field)
    if type(candidate_id) is not int or candidate_id <= 0 or not _nonnegative_int(root_id):
        return None
    return candidate_id, root_id


def _q2_identity_label(identity: tuple[int, int]) -> str:
    return f"candidate_id={identity[0]},root_queue_id={identity[1]}"


def _posterior_advanced_for_positive_reward(row: dict[str, Any]) -> bool:
    """Check the logged positive Beta update, while rejecting absent/non-finite values."""
    before = row.get("alpha_before")
    after = row.get("alpha_after")
    return (
        isinstance(before, (int, float)) and not isinstance(before, bool) and math.isfinite(before)
        and isinstance(after, (int, float)) and not isinstance(after, bool) and math.isfinite(after)
        and after > before
    )


def _q1_invalid_flow_pairs(
    rows: list[dict[str, Any]], policy: Any,
) -> list[dict[str, Any]]:
    """List Q1 flow rows with an unknown pair or a policy-incompatible release."""
    invalid: list[dict[str, Any]] = []
    policy_release_destination = {
        "no-reflow": "idle",
        "reflow": "ordinary-pool",
    }.get(policy)
    release_kinds = {
        "validation-closed-unused", "ordinary-window-closed-unused",
        "validation-converted-unused", "candidate-unallocated",
    }
    for index, row in enumerate(rows):
        kind, destination = row.get("kind"), row.get("destination")
        allowed = Q1_FLOW_DESTINATIONS.get(kind)
        reason = None
        if allowed is None or destination not in allowed:
            reason = "unknown_kind_destination_pair"
        elif kind in release_kinds and policy_release_destination is not None and destination != policy_release_destination:
            reason = "release_destination_conflicts_with_q1_policy"
        if reason:
            invalid.append({
                "row_index": index,
                "kind": kind,
                "destination": destination,
                "reason": reason,
            })
    return invalid


def _report(data: dict[str, list[dict[str, Any]]], errors: dict[str, list[str]], source: str) -> dict[str, Any]:
    configs = data.get("run-config.jsonl", [])
    # The end record carries the same effective switches plus termination
    # status; prefer it when an archive contains both lifecycle records.
    start_config = next((r for r in reversed(configs) if r.get("phase") == "end"),
                        next((r for r in configs if r.get("phase") == "start"), configs[0] if configs else {}))
    stats_rows = data.get("fuzzer_stats", [])
    stats = stats_rows[0] if stats_rows else {}
    applicability = _telemetry_applicability(data, start_config, stats)
    executions = data.get("execution-events.jsonl", [])
    flows = data.get("q1-budget-flow.jsonl", [])
    provisional = data.get("provisional-events.jsonl", [])
    productivity = data.get("productivity-events.jsonl", [])
    admissions = data.get("admission-events.jsonl", [])
    selections = data.get("scheduler-selections.jsonl", [])
    episodes = data.get("state-episodes.jsonl", [])
    windows = data.get("calibration-windows.jsonl", [])

    starts = [row for row in executions if row.get("event") == "invocation_start"]
    executed_starts = [row for row in starts if row.get("executed") is True]
    q1_flow_groups: dict[str, dict[str, Any]] = {}
    for row in flows:
        key = f"{row.get('kind', '<missing>')} -> {row.get('destination', '<missing>')}"
        group = q1_flow_groups.setdefault(key, {"events": 0, "amount_sum": 0, "flow_ids": []})
        group["events"] += 1
        group["amount_sum"] += row.get("amount", 0) if isinstance(row.get("amount"), (int, float)) else 0
        flow_id = row.get("flow_id")
        if flow_id and flow_id not in group["flow_ids"]:
            group["flow_ids"].append(flow_id)
    q1_invalid_flow_pairs = _q1_invalid_flow_pairs(flows, start_config.get("q1_policy"))
    final_flow_rows = [row for row in flows if row.get("kind") == "campaign-final"]
    last_flow = flows[-1] if flows else {}
    final_flow = final_flow_rows[-1] if final_flow_rows else {}
    configured_budget = start_config.get("campaign_call_budget")
    idle_quota = stats.get("q1_idle_quota")
    effective_cap_from_stats = (
        max(0, configured_budget - idle_quota)
        if isinstance(configured_budget, int) and configured_budget > 0 and isinstance(idle_quota, int)
        else configured_budget if isinstance(configured_budget, int) and configured_budget > 0
        else None
    )
    q1_budget = {
        "policy": start_config.get("q1_policy"),
        "configured_campaign_call_budget": configured_budget,
        "effective_cap_logged": final_flow.get("effective_cap") if final_flow_rows else last_flow.get("effective_cap"),
        "effective_cap_from_stats": effective_cap_from_stats,
        "campaign_final_rows": len(final_flow_rows),
        "campaign_final_is_last_flow_event": bool(flows) and last_flow.get("kind") == "campaign-final",
        "charged_invocations_logged": stats.get("campaign_charged_calls", len(executed_starts) if executions else None),
        "invocation_event_counts": {
            "start": sum(row.get("event") == "invocation_start" for row in executions),
            "end": sum(row.get("event") == "invocation_end" for row in executions),
            "refused": sum(row.get("event") == "invocation_refused" for row in executions),
            "executed_start": len(executed_starts),
            "q1_flow_tagged_start": sum(bool(row.get("q1_flow_id")) for row in executed_starts),
            "executed_by_kind": _count(executed_starts, "execution_kind"),
        } if executions else None,
        "flow_event_counts": _count(flows, "kind") if flows else None,
        "flow_by_kind_destination": q1_flow_groups if flows else None,
        "invalid_flow_kind_destination_pairs": q1_invalid_flow_pairs if flows else None,
        "final_flow_ledger": {
            key: last_flow.get(key) for key in (
                "saved_total", "idle_total", "reflow_consumed", "reflow_pool_left",
                "charged_invocations", "effective_cap", "idle_uncredited_total",
            )
        } if final_flow_rows else None,
        "fuzzer_stats": {
            key: stats.get(key) for key in (
                "campaign_call_budget", "campaign_charged_calls", "campaign_budget_exhausted",
                "q1_saved_quota", "q1_idle_quota", "q1_idle_quota_uncredited",
                "q1_reflow_consumed", "q1_reflow_pool_left",
            ) if key in stats
        } or None,
    }

    provisional_kind_counts = _count(provisional, "kind")
    prov_admits = [row for row in provisional if row.get("kind") == "admit"]
    # Ordinary-match admissions rewrite the reason field. On those rows,
    # salvage provenance is countable only when baseline_source is present.
    salvage_roots = [
        row for row in prov_admits
        if row.get("baseline_source") == "saved-session-probe"
        or ("baseline_source" not in row and row.get("reason") == "salvage")
    ]
    salvage_route_unknown = [
        row for row in prov_admits
        if row.get("baseline_source") not in Q2_BASELINE_SOURCES
        and (
            row.get("ordinary_match") is True
            or "ordinary-match cohort" in str(row.get("reason", ""))
            or ("baseline_source" not in row and "reason" not in row)
        )
    ]
    salvage_route_mapping_complete = not salvage_route_unknown
    terminal_provisional = [row for row in provisional if row.get("kind") in ("convert", "expire", "ordinary-close", "censor")]
    productive_roots = [row for row in productivity if row.get("cohort") in ("provisional", "ordinary_match", "ordinary-match")]
    converted = [row for row in provisional if row.get("kind") == "convert"]
    productive_conversions = [row for row in productive_roots if row.get("outcome") == "convert"]
    baseline_valid_conversions = [row for row in productive_conversions if row.get("baseline_valid") is True]
    beyond_baseline_conversions = [
        row for row in baseline_valid_conversions
        if isinstance(row.get("beyond_baseline_slots"), (int, float)) and row["beyond_baseline_slots"] > 0
    ]
    served_productivity_roots = [
        row for row in productive_roots
        if isinstance(row.get("descendant_invocations"), (int, float)) and row["descendant_invocations"] > 0
    ]
    served_doses_by_cohort: dict[str, list[int | float]] = collections.defaultdict(list)
    served_doses_by_outcome: dict[str, list[int | float]] = collections.defaultdict(list)
    for row in served_productivity_roots:
        dose = row["descendant_invocations"]
        served_doses_by_cohort[str(row.get("cohort", "<missing>"))].append(dose)
        served_doses_by_outcome[str(row.get("outcome", "<missing>"))].append(dose)

    q2_identity_errors: list[dict[str, Any]] = []
    q2_stage_rows: dict[str, dict[tuple[int, int], list[dict[str, Any]]]] = {
        "admit": collections.defaultdict(list),
        "terminal": collections.defaultdict(list),
        "productivity": collections.defaultdict(list),
    }
    identity_fields = {
        "admit": (prov_admits, "queue_entry"),
        "terminal": (terminal_provisional, "queue_entry"),
        "productivity": (productivity, "root_queue_id"),
    }
    for stage, (rows, root_field) in identity_fields.items():
        for row_index, row in enumerate(rows):
            identity = _q2_root_identity(row, root_field)
            if identity is None:
                q2_identity_errors.append({
                    "stage": stage,
                    "row_index": row_index,
                    "candidate_id": row.get("candidate_id"),
                    root_field: row.get(root_field),
                    "reason": "missing_or_invalid_stable_root_identity",
                })
            else:
                q2_stage_rows[stage][identity].append(row)

    q2_root_mismatches: list[dict[str, Any]] = []
    q2_all_identities = set().union(*(set(stage_rows) for stage_rows in q2_stage_rows.values()))
    terminal_outcome_for_kind = {
        "convert": "convert",
        "expire": "expire",
        "ordinary-close": "ordinary-close",
        "censor": "censor",
    }
    for identity in sorted(q2_all_identities):
        admit_rows = q2_stage_rows["admit"].get(identity, [])
        terminal_rows = q2_stage_rows["terminal"].get(identity, [])
        productivity_rows = q2_stage_rows["productivity"].get(identity, [])
        mismatch: dict[str, Any] = {"root": _q2_identity_label(identity)}
        if len(admit_rows) != 1:
            mismatch["admit_rows"] = len(admit_rows)
        if len(terminal_rows) != 1:
            mismatch["terminal_rows"] = len(terminal_rows)
        if len(productivity_rows) != 1:
            mismatch["productivity_rows"] = len(productivity_rows)
        if len(terminal_rows) == 1 and len(productivity_rows) == 1:
            expected_outcome = terminal_outcome_for_kind.get(terminal_rows[0].get("kind"))
            observed_outcome = productivity_rows[0].get("outcome")
            if expected_outcome != observed_outcome:
                mismatch["terminal_kind"] = terminal_rows[0].get("kind")
                mismatch["productivity_outcome"] = observed_outcome
            terminal_dose = terminal_rows[0].get("descendant_execs")
            productivity_dose = productivity_rows[0].get("descendant_invocations")
            if (
                not _nonnegative_int(terminal_dose)
                or not _nonnegative_int(productivity_dose)
                or terminal_dose != productivity_dose
            ):
                mismatch["terminal_descendant_execs"] = terminal_dose
                mismatch["productivity_descendant_invocations"] = productivity_dose
        if len(mismatch) > 1:
            q2_root_mismatches.append(mismatch)
    q2_ids_complete = not q2_identity_errors
    q2_lifecycle_matches_by_id = (
        q2_ids_complete and not q2_root_mismatches
        if "provisional-events.jsonl" in data and "productivity-events.jsonl" in data
        else None
    )
    # Count only roots whose stable identity has exactly one admission,
    # terminal event, and productivity row, with matching outcome and dose.
    # The Q2 sample floor is per cohort; a large cohort must not mask a sparse
    # comparison cohort. Normalize the historical underscore spelling too.
    q2_linked_positive_roots_by_cohort: dict[str, set[tuple[int, int]]] = {
        "provisional": set(),
        "ordinary-match": set(),
    }
    for identity in q2_all_identities:
        admit_rows = q2_stage_rows["admit"].get(identity, [])
        terminal_rows = q2_stage_rows["terminal"].get(identity, [])
        productivity_rows = q2_stage_rows["productivity"].get(identity, [])
        if len(admit_rows) != 1 or len(terminal_rows) != 1 or len(productivity_rows) != 1:
            continue
        terminal_row = terminal_rows[0]
        productivity_row = productivity_rows[0]
        expected_outcome = terminal_outcome_for_kind.get(terminal_row.get("kind"))
        terminal_dose = terminal_row.get("descendant_execs")
        productivity_dose = productivity_row.get("descendant_invocations")
        if (
            expected_outcome != productivity_row.get("outcome")
            or not _nonnegative_int(terminal_dose)
            or not _nonnegative_int(productivity_dose)
            or terminal_dose != productivity_dose
            or productivity_dose <= 0
        ):
            continue
        cohort = productivity_row.get("cohort")
        if cohort == "ordinary_match":
            cohort = "ordinary-match"
        if cohort not in q2_linked_positive_roots_by_cohort:
            continue
        # The admission flag and productivity cohort must agree before a root
        # contributes to either cohort's answerability floor.
        admitted_as_ordinary_match = admit_rows[0].get("ordinary_match") is True
        if admitted_as_ordinary_match != (cohort == "ordinary-match"):
            continue
        q2_linked_positive_roots_by_cohort[cohort].add(identity)
    q2_linked_positive_root_counts_by_cohort = {
        cohort: len(identities)
        for cohort, identities in q2_linked_positive_roots_by_cohort.items()
    }
    q2_salvage_counter_match = (
        _equal_if_available(len(salvage_roots), stats.get("salvage_succeeded"))
        if "provisional-events.jsonl" in data and salvage_route_mapping_complete
        else None
    )
    admitted_roots_by_reason = _count(prov_admits, "reason") if provisional else None
    positive_dose_roots_by_cohort = {
        cohort: sum(
            ("ordinary-match" if row.get("cohort") == "ordinary_match" else row.get("cohort")) == cohort
            and isinstance(row.get("descendant_invocations"), int)
            and not isinstance(row.get("descendant_invocations"), bool)
            and row["descendant_invocations"] > 0
            for row in productivity
        )
        for cohort in ("provisional", "ordinary-match")
    } if productivity else None
    q2_dose_fields_complete = (
        all(_nonnegative_int(row.get("descendant_invocations")) for row in productive_roots)
        and all(_nonnegative_int(row.get("descendant_execs")) for row in terminal_provisional)
        if productivity or provisional else None
    )
    q2 = {
        "provisional_event_counts_by_kind": provisional_kind_counts if provisional else None,
        "admitted_roots": len(prov_admits) if provisional else None,
        "admitted_roots_by_reason": admitted_roots_by_reason,
        "salvage_admitted_roots": (
            len(salvage_roots) if provisional and salvage_route_mapping_complete else None
        ),
        "salvage_route_audit": {
            "mapping_complete": salvage_route_mapping_complete if provisional else None,
            "unknown_route_admit_rows": [
                {
                    "candidate_id": row.get("candidate_id"),
                    "queue_entry": row.get("queue_entry"),
                    "reason": row.get("reason"),
                    "ordinary_match": row.get("ordinary_match"),
                }
                for row in salvage_route_unknown
            ],
        } if provisional else None,
        "ordinary_match_admitted_roots": sum(row.get("ordinary_match") is True for row in prov_admits) if provisional else None,
        "ordinary_match_flagged_roots": sum(row.get("ordinary_match") is True for row in prov_admits) if provisional else None,
        "terminal_root_events": {
            "convert": sum(row.get("kind") == "convert" for row in terminal_provisional),
            "expire": sum(row.get("kind") == "expire" for row in terminal_provisional),
            "ordinary_close": sum(row.get("kind") == "ordinary-close" for row in terminal_provisional),
            "censor": sum(row.get("kind") == "censor" for row in terminal_provisional),
        } if provisional else None,
        "conversion_classes": _count(converted, "conversion_class_name") if provisional else None,
        "conversion_class_2_events": sum(
            row.get("conversion_class") == 2 or row.get("conversion_class_name") == "contains-beyond-trial-slots"
            for row in converted
        ) if provisional else None,
        "productive_converted_roots_with_valid_baseline": len(baseline_valid_conversions) if productivity else None,
        "productive_converted_roots_without_valid_baseline": (
            sum(row.get("baseline_valid") is not True for row in productive_conversions) if productivity else None
        ),
        "productive_converted_roots_with_beyond_baseline_slots": (
            len(beyond_baseline_conversions) if productivity else None
        ),
        "valid_beyond_baseline_slots_sum": (
            _sum_field(beyond_baseline_conversions, "beyond_baseline_slots") if productivity else None
        ),
        "conversion_class_counts_from_productivity": (
            _count(productive_conversions, "conversion_class") if productivity else None
        ),
        "provisional_terminal_descendant_invocations": _sum_field(terminal_provisional, "descendant_execs") if provisional else None,
        "productivity_event_count": len(productivity) if productivity else (0 if "productivity-events.jsonl" in data else None),
        "productivity_cohorts": _count(productivity, "cohort") if productivity else None,
        "productivity_outcomes": _count(productivity, "outcome") if productivity else None,
        "productivity_rows": [
            {
                "cohort": row.get("cohort"), "candidate_id": row.get("candidate_id"),
                "outcome": row.get("outcome"), "descendant_invocations": row.get("descendant_invocations"),
                "root_queue_id": row.get("root_queue_id"), "converted": row.get("converted"),
                "baseline_valid": row.get("baseline_valid"), "baseline_new_edge_slots": row.get("baseline_new_edge_slots"),
                "beyond_baseline_slots": row.get("beyond_baseline_slots"),
                "conversion_class": row.get("conversion_class"), "censored": row.get("censored"),
            }
            for row in productivity
        ] if productivity else None,
        "productivity_descendant_invocations_sum": _sum_field(productive_roots, "descendant_invocations") if productivity else None,
        "productivity_descendant_invocations_per_root": (
            _sum_field(productive_roots, "descendant_invocations") / len(productive_roots)
            if productive_roots else None
        ) if productivity else None,
        "served_roots_with_descendant_execution": len(served_productivity_roots) if productivity else None,
        "productivity_roots_without_descendant_execution": (
            sum(
                isinstance(row.get("descendant_invocations"), (int, float))
                and row["descendant_invocations"] == 0
                for row in productive_roots
            ) if productivity else None
        ),
        "served_root_descendant_invocation_distribution": (
            _numeric_distribution([row["descendant_invocations"] for row in served_productivity_roots])
            if productivity else None
        ),
        "served_root_dose_distribution_by_cohort": (
            {key: _numeric_distribution(values) for key, values in sorted(served_doses_by_cohort.items())}
            if productivity else None
        ),
        "served_root_dose_distribution_by_outcome": (
            {key: _numeric_distribution(values) for key, values in sorted(served_doses_by_outcome.items())}
            if productivity else None
        ),
        "served_root_doses": [
            {
                "cohort": row.get("cohort"), "candidate_id": row.get("candidate_id"),
                "root_queue_id": row.get("root_queue_id"), "outcome": row.get("outcome"),
                "descendant_invocations": row.get("descendant_invocations"),
            }
            for row in served_productivity_roots
        ] if productivity else None,
        "root_identity_audit": {
            "identity_fields": {
                "provisional_events": "candidate_id + queue_entry",
                "productivity_events": "candidate_id + root_queue_id",
            },
            "identity_fields_complete": q2_ids_complete if provisional or productivity else None,
            "lifecycle_matches_by_id": q2_lifecycle_matches_by_id,
            "identity_errors": q2_identity_errors,
            "root_mismatches": q2_root_mismatches,
        },
        "dose_audit": {
            "descendant_invocation_fields_complete": q2_dose_fields_complete,
            "positive_dose_roots_by_cohort": positive_dose_roots_by_cohort,
            "roots_without_positive_dose": sum(
                isinstance(row.get("descendant_invocations"), int)
                and not isinstance(row.get("descendant_invocations"), bool)
                and row["descendant_invocations"] == 0
                for row in productive_roots
            ) if productivity else None,
        },
        "salvage_counters_from_fuzzer_stats": {
            key: stats.get(key) for key in (
                "salvage_enabled", "salvage_attempted", "salvage_succeeded", "salvage_recoveries",
                "ordinary_match_admits", "ordinary_match_closed", "ordinary_match_converted",
                "provisional_admitted", "provisional_converted", "provisional_expired", "provisional_censored",
                "prov_conv_immediate_only", "prov_conv_beyond_trial", "prov_conv_unclassified",
            ) if key in stats
        } or None,
        "admission_decisions_by_intended_disposition": _count(
            [row for row in admissions if row.get("event") == "admission_decision"], "intended_disposition"
        ) if admissions else None,
        "admission_trials_by_disposition": _count(
            [row for row in admissions if row.get("event") == "admission_trial"], "disposition"
        ) if admissions else None,
    }

    provisional_enabled = start_config.get("provisional_enabled") is True
    q2_mechanism_triggered = bool(prov_admits) if provisional else None
    if start_config.get("provisional_enabled") is False or start_config.get("admission_mode") in ("direct", "native"):
        q2_answerability = {
            "status": "not_applicable",
            "mechanism_triggered": False,
            "reason": "provisional-root mechanism is disabled by the effective run configuration",
        }
    elif not provisional_enabled:
        q2_answerability = {
            "status": "unresolved",
            "mechanism_triggered": q2_mechanism_triggered,
            "reason": "effective provisional_enabled switch is absent or not true",
        }
    else:
        q2_cohort_floor_met = (
            all(count >= 10 for count in q2_linked_positive_root_counts_by_cohort.values())
            if provisional and productivity else None
        )
        prerequisites = {
            "at_least_one_root_admitted": bool(prov_admits),
            "root_ids_complete": q2_ids_complete,
            "admit_terminal_productivity_lifecycle_matches": q2_lifecycle_matches_by_id,
            "salvage_route_mapping_complete": salvage_route_mapping_complete if provisional else None,
            "descendant_dose_fields_complete": q2_dose_fields_complete,
            "at_least_10_uniquely_linked_positive_dose_roots_in_each_cohort": q2_cohort_floor_met,
        }
        run_local_ready = all(value is True for value in prerequisites.values())
        q2_answerability = {
            # This input is one archive. It cannot establish cross-arm config,
            # budget, or median-dose matching, so never label the Q2 comparison
            # answerable at this layer.
            "status": "unresolved",
            "single_archive_status": "ready" if run_local_ready else "unresolved",
            "mechanism_triggered": q2_mechanism_triggered,
            "prerequisites": prerequisites,
            "per_repeat_counts_and_dose": {
                "admitted_roots_total": len(prov_admits) if provisional else None,
                "salvage_source_roots": (
                    len(salvage_roots) if provisional and salvage_route_mapping_complete else None
                ),
                "ordinary_match_roots": sum(row.get("ordinary_match") is True for row in prov_admits) if provisional else None,
                "terminal_roots": len(terminal_provisional) if provisional else None,
                "productivity_roots": len(productive_roots) if productivity else None,
                "positive_dose_roots_by_cohort": positive_dose_roots_by_cohort,
                "uniquely_linked_positive_dose_roots_by_cohort": (
                    q2_linked_positive_root_counts_by_cohort if provisional and productivity else None
                ),
                "descendant_invocation_dose": q2["served_root_descendant_invocation_distribution"],
            },
            "paired_arm_prerequisites": {
                "target_configuration_campaign_budget_match": None,
                "median_descendant_dose_ratio_in_0.80_1.25": None,
                "status": "not_evaluated_by_single_archive_audit",
            },
            "reason": "per-archive root prerequisites are present; the paired-arm configuration, budget, and median-dose checks remain unevaluated" if run_local_ready else
                      "one or more per-repeat root lifecycle or delivered-dose prerequisites are absent",
        }
    q2["answerability_prerequisites"] = q2_answerability

    weighted = [row for row in selections if row.get("reason") == "weighted-eligible"]
    positive_weighted = [
        row for row in weighted
        if isinstance(row.get("weight_total"), (int, float))
        and not isinstance(row.get("weight_total"), bool)
        and row["weight_total"] > 0
    ]

    def has_bool_field(row: dict[str, Any], field: str) -> bool:
        return row.get(field) is True or row.get(field) is False

    selection_applied = [row for row in selections if row.get("calibration_applied") is True]
    selection_not_applied = [row for row in selections if row.get("calibration_applied") is False]
    selection_missing_applied = [
        row for row in selections if row.get("calibration_applied") is not True
        and row.get("calibration_applied") is not False
    ]
    selection_applied_with_changed = [
        row for row in selection_applied if has_bool_field(row, "calibration_changed_selection")
    ]
    selection_applied_missing_changed = [
        row for row in selection_applied if not has_bool_field(row, "calibration_changed_selection")
    ]

    positive_weighted_applied = [row for row in positive_weighted if row.get("calibration_applied") is True]
    positive_weighted_not_applied = [row for row in positive_weighted if row.get("calibration_applied") is False]
    positive_weighted_missing_applied = [
        row for row in positive_weighted if row.get("calibration_applied") is not True
        and row.get("calibration_applied") is not False
    ]
    positive_weighted_applied_with_changed = [
        row for row in positive_weighted_applied if has_bool_field(row, "calibration_changed_selection")
    ]
    positive_weighted_missing_changed = [
        row for row in positive_weighted_applied if not has_bool_field(row, "calibration_changed_selection")
    ]
    positive_weighted_missing_any_calibration_field = [
        row for row in positive_weighted
        if not has_bool_field(row, "calibration_applied")
        or (row.get("calibration_applied") is True
            and not has_bool_field(row, "calibration_changed_selection"))
    ]
    positive_weighted_with_applicable_calibration_fields = [
        row for row in positive_weighted
        if has_bool_field(row, "calibration_applied")
        and (row.get("calibration_applied") is False
             or has_bool_field(row, "calibration_changed_selection"))
    ]
    selection_fields_complete = bool(selections) and all(
        has_bool_field(row, "calibration_applied")
        and (row.get("calibration_applied") is False
             or has_bool_field(row, "calibration_changed_selection"))
        for row in selections
    )
    episode_fields = ("train_eligible", "completed", "posterior_updated")
    episode_fields_complete = bool(episodes) and all(all(field in row for field in episode_fields) for row in episodes)
    has_windows = "calibration-windows.jsonl" in data
    has_selections = "scheduler-selections.jsonl" in data
    has_episodes = "state-episodes.jsonl" in data
    episode_reward_fields = (
        "selected_state", "training_observations", "training_rewarded_observations",
    )
    episode_reward_fields_complete = bool(episodes) and all(
        all(field in row for field in episode_reward_fields) for row in episodes
    )
    configured_window_width = start_config.get(
        "cal_reward_window_invocations", stats.get("cal_reward_window_invocations")
    )

    def episode_training_evidence(row: dict[str, Any]) -> tuple[str | None, int | None]:
        """Return reward mode and posterior-relevant evidence for one episode."""
        revision = row.get("calibration_revision")
        window_width = row.get("cal_reward_window_invocations", configured_window_width)
        if revision == "fixed-invocation-window-v1" or (
            revision is None and isinstance(window_width, (int, float)) and window_width > 0
        ):
            mode, field = "fixed-window", "training_observations"
        elif revision == "episode-bernoulli-v1" or (
            revision is None and isinstance(window_width, (int, float)) and window_width == 0
        ):
            mode, field = "episode-bernoulli", "training_invocations"
        else:
            return None, None
        value = row.get(field)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return mode, value
        return mode, None

    episode_evidence = [episode_training_evidence(row) for row in episodes]
    episode_posterior_evidence_complete = bool(episodes) and all(
        mode is not None and value is not None for mode, value in episode_evidence
    )
    episode_training_by_state: dict[str, dict[str, int]] = collections.defaultdict(
        lambda: {"training_observations": 0, "training_rewarded_observations": 0, "episode_rows": 0}
    )
    for row in episodes:
        if not all(field in row for field in episode_reward_fields):
            continue
        by_state = episode_training_by_state[str(row["selected_state"])]
        by_state["training_observations"] += row["training_observations"] if isinstance(row["training_observations"], int) else 0
        by_state["training_rewarded_observations"] += (
            row["training_rewarded_observations"] if isinstance(row["training_rewarded_observations"], int) else 0
        )
        by_state["episode_rows"] += 1
    window_training_by_state: dict[str, dict[str, int]] = collections.defaultdict(
        lambda: {"window_rows": 0, "positive_reward_windows": 0}
    )
    for row in windows:
        if "selected_state" not in row:
            continue
        by_state = window_training_by_state[str(row["selected_state"])]
        by_state["window_rows"] += 1
        by_state["positive_reward_windows"] += row.get("reward") == 1
    state_keys = sorted(set(episode_training_by_state) | set(window_training_by_state))
    window_posterior_link_by_state = {
        state: {
            **window_training_by_state.get(state, {"window_rows": 0, "positive_reward_windows": 0}),
            **episode_training_by_state.get(state, {
                "training_observations": 0,
                "training_rewarded_observations": 0,
                "episode_rows": 0,
            }),
            "window_count_matches_episode_training_observations": (
                window_training_by_state.get(state, {"window_rows": 0})["window_rows"]
                == episode_training_by_state.get(state, {"training_observations": 0})["training_observations"]
            ),
            "positive_windows_match_episode_rewarded_observations": (
                window_training_by_state.get(state, {"positive_reward_windows": 0})["positive_reward_windows"]
                == episode_training_by_state.get(state, {"training_rewarded_observations": 0})["training_rewarded_observations"]
            ),
        }
        for state in state_keys
    } if episode_reward_fields_complete and windows else None
    eligible_completed_missing_update = sum(
        row.get("train_eligible") is True
        and row.get("completed") is True
        and mode is not None
        and value is not None
        and value > 0
        and row.get("posterior_updated") is not True
        for row, (mode, value) in zip(episodes, episode_evidence)
    )
    posterior_evidence_missing_update = sum(
        value is not None and value > 0
        and (mode == "fixed-window" or (
            mode == "episode-bernoulli"
            and row.get("train_eligible") is True and row.get("completed") is True
        ))
        and row.get("posterior_updated") is not True
        for row, (mode, value) in zip(episodes, episode_evidence)
    )
    posterior_update_without_training_evidence = sum(
        row.get("posterior_updated") is True
        and (mode is None or value is None or value == 0
             or (mode == "fixed-window" and row.get("train_eligible") is not True)
             or (mode == "episode-bernoulli" and not (
                 row.get("train_eligible") is True and row.get("completed") is True
             )))
        for row, (mode, value) in zip(episodes, episode_evidence)
    )
    q3 = {
        "scheduler_selection_rows": len(selections) if has_selections else None,
        "selection_reasons": _count(selections, "reason") if has_selections else None,
        "weighted_eligible_rows": len(weighted) if has_selections else None,
        "weighted_rows_with_positive_weight_total": len(positive_weighted) if has_selections else None,
        "weighted_positive_rows_with_applicable_calibration_fields": (
            len(positive_weighted_with_applicable_calibration_fields) if has_selections else None
        ),
        "weighted_positive_rows_missing_calibration_applied_field": (
            len(positive_weighted_missing_applied) if has_selections else None
        ),
        "weighted_positive_rows_missing_calibration_changed_selection_field": (
            len(positive_weighted_missing_changed) if has_selections else None
        ),
        "weighted_positive_rows_missing_either_calibration_field": (
            len(positive_weighted_missing_any_calibration_field) if has_selections else None
        ),
        "calibration_applied_rows_all": len(selection_applied) if has_selections else None,
        "calibration_not_applicable_rows_all": len(selection_not_applied) if has_selections else None,
        "selection_rows_missing_calibration_applied_field": len(selection_missing_applied) if has_selections else None,
        "calibration_applied_rows_with_changed_selection_field": (
            len(selection_applied_with_changed) if has_selections else None
        ),
        "calibration_applied_rows_missing_changed_selection_field": (
            len(selection_applied_missing_changed) if has_selections else None
        ),
        "calibration_changed_selection_true_rows_applied": (
            sum(row.get("calibration_changed_selection") is True for row in selection_applied_with_changed)
            if has_selections else None
        ),
        "calibration_changed_selection_rate_applied_rows_with_field": (
            sum(row.get("calibration_changed_selection") is True for row in selection_applied_with_changed)
            / len(selection_applied_with_changed) if selection_applied_with_changed else None
        ),
        "weighted_applied_changed_intersection": sum(
            row.get("calibration_applied") is True
            and row.get("calibration_changed_selection") is True
            for row in positive_weighted_applied_with_changed
        ) if positive_weighted_applied_with_changed else None,
        "weighted_positive_applied_rows": sum(
            row.get("calibration_applied") is True for row in positive_weighted
        ) if has_selections else None,
        "weighted_positive_not_applicable_rows": len(positive_weighted_not_applied) if has_selections else None,
        "weighted_positive_rows_missing_calibration_applied_field": (
            len(positive_weighted_missing_applied) if has_selections else None
        ),
        "weighted_positive_applied_rows_with_changed_selection_field": (
            len(positive_weighted_applied_with_changed) if has_selections else None
        ),
        "weighted_positive_applied_rows_missing_changed_selection_field": (
            len(positive_weighted_missing_changed) if has_selections else None
        ),
        "weighted_positive_changed_selection_true_rows": (
            sum(row.get("calibration_changed_selection") is True for row in positive_weighted_applied_with_changed)
            if has_selections else None
        ),
        "weighted_positive_changed_selection_rate_applied_rows_with_field": (
            sum(row.get("calibration_changed_selection") is True for row in positive_weighted_applied_with_changed)
            / len(positive_weighted_applied_with_changed) if positive_weighted_applied_with_changed else None
        ),
        "weighted_positive_changed_rows": sum(
            row.get("calibration_changed_selection") is True for row in positive_weighted_applied_with_changed
        ) if positive_weighted_applied_with_changed else None,
        "weighted_intersection_breakdown": {
            "weighted_positive_applied_rows": len(positive_weighted_applied),
            "weighted_positive_not_applicable_rows": len(positive_weighted_not_applied),
            "weighted_positive_applied_rows_with_changed_field": len(positive_weighted_applied_with_changed),
            "weighted_positive_applied_rows_missing_changed_field": len(positive_weighted_missing_changed),
            "weighted_positive_and_changed": sum(
                row.get("calibration_changed_selection") is True for row in positive_weighted_applied_with_changed
            ),
            "weighted_positive_applied_and_changed": sum(
                row.get("calibration_changed_selection") is True for row in positive_weighted_applied_with_changed
            ),
            "rows_missing_either_field": len(positive_weighted_missing_any_calibration_field),
        } if has_selections else None,
        "scheduler_calibration_fields_complete": selection_fields_complete if has_selections else None,
        "positive_weighted_scheduler_calibration_fields_complete": (
            all(row in positive_weighted_with_applicable_calibration_fields for row in positive_weighted)
            if has_selections and positive_weighted else None
        ),
        "episode_rows": len(episodes) if has_episodes else None,
        "episode_flag_counts": {
            "train_eligible": _truth_count(episodes, "train_eligible"),
            "completed": _truth_count(episodes, "completed"),
            "posterior_updated": _truth_count(episodes, "posterior_updated"),
            "eligible_completed_updated_intersection": sum(
                row.get("train_eligible") is True and row.get("completed") is True and row.get("posterior_updated") is True
                for row in episodes
            ),
        } if episode_fields_complete else None,
        "episode_training_and_posterior_fields_complete": episode_fields_complete if has_episodes else None,
        "episode_posterior_evidence_fields_complete": (
            episode_posterior_evidence_complete if has_episodes else None
        ),
        "episode_reward_link_fields_complete": episode_reward_fields_complete if has_episodes else None,
        "calibration_window_posterior_link_by_state": window_posterior_link_by_state,
        "calibration_windows_total": len(windows) if has_windows else None,
        "episode_training_observations_total": (
            _sum_field(episodes, "training_observations") if has_episodes and episode_reward_fields_complete else None
        ),
        "episode_training_rewarded_observations_total": (
            _sum_field(episodes, "training_rewarded_observations") if has_episodes and episode_reward_fields_complete else None
        ),
        "positive_reward_windows_total": (
            sum(row.get("reward") == 1 for row in windows) if has_windows else None
        ),
        "eligible_completed_episodes_missing_posterior_update": (
            eligible_completed_missing_update if has_episodes else None
        ),
        "posterior_updates_without_training_evidence": (
            posterior_update_without_training_evidence if has_episodes else None
        ),
        "episodes_with_training_evidence_missing_posterior_update": (
            posterior_evidence_missing_update if has_episodes else None
        ),
        "configured_reward_window_invocations": start_config.get("cal_reward_window_invocations"),
        "reward_window_rows": len(windows) if has_windows else None,
        "reward_window_width_histogram": dict(sorted(collections.Counter(
            str(row.get("training_invocations")) for row in windows
        ).items())) if has_windows and windows else {} if has_windows else None,
        "fixed_width_rows": (
            sum(row.get("training_invocations") == start_config.get("cal_reward_window_invocations") for row in windows)
            if has_windows and isinstance(start_config.get("cal_reward_window_invocations"), int) else None
        ),
        "reward_window_reward_counts": _count(windows, "reward") if has_windows else None,
        "episode_configured_reward_window_histogram": dict(sorted(collections.Counter(
            str(row.get("cal_reward_window_invocations")) for row in episodes
        ).items())) if has_episodes and episodes else {} if has_episodes else None,
        "episode_reward_counts": _count(episodes, "reward") if has_episodes else None,
    }

    q3_mechanism_trigger_rows = [
        row for row in positive_weighted
        if row.get("calibration_applied") is True
        and row.get("calibration_changed_selection") is True
    ]
    q3_positive_reward_updated_episodes: list[dict[str, Any]] = []
    for row, (mode, exposure) in zip(episodes, episode_evidence):
        if row.get("train_eligible") is not True or row.get("completed") is not True:
            continue
        if row.get("posterior_updated") is not True or not _posterior_advanced_for_positive_reward(row):
            continue
        if mode == "fixed-window":
            rewarded = row.get("training_rewarded_observations")
            if (
                exposure is not None and exposure > 0
                and _nonnegative_int(rewarded) and rewarded > 0
            ):
                q3_positive_reward_updated_episodes.append(row)
        elif mode == "episode-bernoulli":
            if exposure is not None and exposure > 0 and row.get("reward") == 1:
                q3_positive_reward_updated_episodes.append(row)

    q3_mechanism_triggered = bool(q3_mechanism_trigger_rows) if has_selections else None
    q3_positive_update_evidence = (
        bool(q3_positive_reward_updated_episodes)
        if has_episodes and episode_posterior_evidence_complete
        else None
    )
    configured_reward_window = start_config.get("cal_reward_window_invocations")
    fixed_window_mode = (
        type(configured_reward_window) is int and configured_reward_window > 0
    )
    if fixed_window_mode:
        fixed_episode_rows = [
            row for row, (mode, _) in zip(episodes, episode_evidence)
            if mode == "fixed-window"
        ]
        fixed_width_episode_rows_match = bool(fixed_episode_rows) and all(
            type(row.get("cal_reward_window_invocations")) is int
            and row["cal_reward_window_invocations"] == configured_reward_window
            for row in fixed_episode_rows
        )
        fixed_width_window_rows_match = (
            has_windows and bool(windows) and all(
                type(row.get("training_invocations")) is int
                and row["training_invocations"] == configured_reward_window
                for row in windows
            )
        )
        fixed_width_positive_reward_window_for_updated_episode = any(
            row.get("selected_state") == episode.get("selected_state")
            and row.get("reward") == 1
            and type(row.get("training_invocations")) is int
            and row["training_invocations"] == configured_reward_window
            for episode in q3_positive_reward_updated_episodes
            for row in windows
        )
        q3_fixed_window_config_matches = (
            fixed_width_episode_rows_match
            and fixed_width_window_rows_match
            and fixed_width_positive_reward_window_for_updated_episode
        )
    elif type(configured_reward_window) is int and configured_reward_window == 0:
        # Episode-Bernoulli mode has no fixed-width window rows by design.
        q3_fixed_window_config_matches = True
    else:
        q3_fixed_window_config_matches = None
    if start_config.get("calibration") is False:
        q3_answerability = {
            "status": "not_applicable",
            "mechanism_triggered": False,
            "reason": "calibration is disabled by the effective run configuration",
        }
    elif start_config.get("calibration") is not True:
        q3_answerability = {
            "status": "unresolved",
            "mechanism_triggered": q3_mechanism_triggered,
            "reason": "effective calibration switch is absent or not boolean",
        }
    else:
        prerequisites = {
            "positive_weight_calibrated_selection_changed": q3_mechanism_triggered,
            "eligible_completed_positive_reward_updated_posterior": q3_positive_update_evidence,
            "fixed_reward_window_matches_configured_width": q3_fixed_window_config_matches,
        }
        ready = all(value is True for value in prerequisites.values())
        q3_answerability = {
            "status": "ready" if ready else "unresolved",
            "mechanism_triggered": q3_mechanism_triggered,
            "prerequisites": prerequisites,
            "per_repeat_counts": {
                "positive_weight_calibration_applied_and_changed_selections": (
                    len(q3_mechanism_trigger_rows) if has_selections else None
                ),
                "eligible_completed_positive_reward_posterior_updates": (
                    len(q3_positive_reward_updated_episodes)
                    if has_episodes and episode_posterior_evidence_complete else None
                ),
                "configured_reward_window_invocations": configured_reward_window,
                "fixed_width_episode_rows_match_config": (
                    fixed_width_episode_rows_match if fixed_window_mode else None
                ),
                "fixed_width_window_rows_match_config": (
                    fixed_width_window_rows_match if fixed_window_mode else None
                ),
            },
            "reason": "selection, reward update, and configured window-width evidence are recorded" if ready else
                      "selection effect, qualified positive posterior-update evidence, or configured window-width evidence is absent or inconsistent",
        }
    q3["answerability_prerequisites"] = q3_answerability

    campaigns = {row.get("campaign_id") for filename in JSONL_FILES for row in data.get(filename, []) if row.get("campaign_id")}
    run_campaign = start_config.get("campaign_id")
    consistent_campaign = bool(run_campaign) and campaigns == {run_campaign}
    budget_enabled = _nonnegative_int(configured_budget) and configured_budget > 0
    q1_end_boundary = start_config.get("phase") == "end"
    q1_policy = start_config.get("q1_policy")
    q1_accounting_applicable = q1_policy != "none"
    q1_flow_policy = q1_policy in ("no-reflow", "reflow")
    if q1_flow_policy and not budget_enabled:
        applicability["q1-terminal-boundary"] = {
            "state": "unresolved",
            "reason": "Q1 quota policy is configured but campaign_call_budget is missing or invalid",
        }
    elif q1_policy == "none":
        applicability["q1-terminal-boundary"] = {
            "state": "not_applicable",
            "reason": "q1_policy='none' does not allocate or conserve Q1 quota",
        }
    elif budget_enabled and q1_flow_policy and not q1_end_boundary:
        applicability["q1-terminal-boundary"] = {
            "state": "unresolved",
            "reason": "run-config has no phase=end record; the campaign may still be running",
        }
    elif budget_enabled and q1_flow_policy and q1_end_boundary and not final_flow_rows:
        applicability["q1-terminal-boundary"] = {
            "state": "required_missing",
            "reason": "completed budgeted run must end with one campaign-final ledger row",
        }
    elif budget_enabled and q1_flow_policy and q1_end_boundary:
        applicability["q1-terminal-boundary"] = {
            "state": "recorded",
            "reason": "completed run has a campaign-final ledger row",
        }
    if (
        "provisional-events.jsonl" in data
        and "salvage_succeeded" in stats
        and not salvage_route_mapping_complete
    ):
        applicability["q2-salvage-route-counter"] = {
            "state": "unresolved",
            "reason": "ordinary-match admission reason hides salvage route and this row lacks baseline_source",
        }
    expected_cap = (
        max(0, configured_budget - stats.get("q1_idle_quota", 0))
        if start_config.get("q1_policy") == "no-reflow" else configured_budget
    ) if budget_enabled else None
    release_flow_rows = [row for row in flows if row.get("kind") not in ("consumed", "campaign-final")]
    consumed_flow_rows = [row for row in flows if row.get("kind") == "consumed"]
    flow_snapshot_fields = (
        "saved_total", "idle_total", "idle_uncredited_total", "reflow_consumed",
        "reflow_pool_left", "charged_invocations", "effective_cap",
    )
    flow_amount_fields = ("amount", "requested_amount", "uncredited_amount")
    flow_rows_schema_complete = all(
        isinstance(row.get("campaign_id"), str) and bool(row.get("campaign_id"))
        and isinstance(row.get("event"), str) and row.get("event") == "q1_budget_flow"
        and isinstance(row.get("kind"), str) and bool(row.get("kind"))
        and isinstance(row.get("destination"), str) and bool(row.get("destination"))
        and all(_nonnegative_int(row.get(key)) for key in flow_amount_fields + flow_snapshot_fields)
        and row["requested_amount"] == row["amount"] + row["uncredited_amount"]
        for row in flows
    )
    flow_campaigns_match = (
        all(row.get("campaign_id") == run_campaign for row in flows) if run_campaign else None
    )
    flow_saved = sum(row["amount"] for row in release_flow_rows) if flow_rows_schema_complete else None
    flow_uncredited = sum(row["uncredited_amount"] for row in release_flow_rows) if flow_rows_schema_complete else None
    flow_consumed = sum(row["amount"] for row in consumed_flow_rows) if flow_rows_schema_complete else None
    q1_counters_present = q1_accounting_applicable and all(_nonnegative_int(stats.get(key)) for key in (
        "campaign_call_budget", "campaign_charged_calls", "q1_saved_quota", "q1_idle_quota",
        "q1_idle_quota_uncredited", "q1_reflow_consumed", "q1_reflow_pool_left",
    ))
    if budget_enabled and q1_policy == "none":
        applicability["q1-counter-fields"] = {
            "state": "not_applicable", "reason": "q1_policy='none' does not use Q1 quota counters",
        }
    elif budget_enabled:
        if not stats:
            applicability["q1-counter-fields"] = {
                "state": "unresolved", "reason": "fuzzer_stats is missing",
            }
        elif not q1_counters_present:
            applicability["q1-counter-fields"] = {
                "state": "required_missing", "reason": "budgeted run is missing one or more Q1 accounting counters",
            }
        else:
            applicability["q1-counter-fields"] = {
                "state": "recorded", "reason": "Q1 accounting counters are present",
            }
    q1_charged = stats.get("campaign_charged_calls")
    q1_saved = stats.get("q1_saved_quota")
    q1_idle = stats.get("q1_idle_quota")
    q1_uncredited = stats.get("q1_idle_quota_uncredited")
    q1_reflow_used = stats.get("q1_reflow_consumed")
    q1_reflow_left = stats.get("q1_reflow_pool_left")
    if not budget_enabled or q1_policy == "none":
        quota_invariants = None
    elif not q1_counters_present:
        quota_invariants = None
    elif q1_policy == "no-reflow":
        quota_invariants = (
            q1_saved == q1_idle and q1_reflow_used == 0 and q1_reflow_left == 0
            and q1_charged <= max(0, configured_budget - q1_idle)
            and q1_charged + q1_idle <= configured_budget
        )
    elif q1_policy == "reflow":
        quota_invariants = (
            q1_idle == 0 and q1_uncredited == 0
            and q1_saved == q1_reflow_used + q1_reflow_left
            and q1_charged <= configured_budget
        )
    elif q1_policy in ("direct-service", "none"):
        quota_invariants = (
            q1_saved == 0 and q1_idle == 0 and q1_uncredited == 0
            and q1_reflow_used == 0 and q1_reflow_left == 0
            and q1_charged <= configured_budget
        )
    else:
        quota_invariants = False
    consistency = {
        "campaign_identity_matches_start_config": consistent_campaign if campaigns else None,
        "campaign_ids_seen": sorted(campaigns),
        "q1_stats_budget_matches_config": (
            _equal_if_available(stats.get("campaign_call_budget"), configured_budget)
            if budget_enabled else None
        ),
        "q1_flow_rows_schema_complete": (
            flow_rows_schema_complete if flows else False if budget_enabled and q1_flow_policy and q1_end_boundary else None
        ),
        "q1_flow_kind_destination_pairs_valid": (
            not q1_invalid_flow_pairs if flows
            else False if budget_enabled and q1_flow_policy and q1_end_boundary
            else None
        ),
        "q1_flow_campaign_ids_match_start_config": (
            flow_campaigns_match if flows else False if budget_enabled and q1_flow_policy and q1_end_boundary else None
        ),
        "q1_flow_final_saved_matches_stats": (
            _equal_if_available(last_flow.get("saved_total"), stats.get("q1_saved_quota"))
            if flow_rows_schema_complete and flows else False if budget_enabled and q1_flow_policy and q1_end_boundary else None
        ),
        "q1_flow_final_idle_matches_stats": (
            _equal_if_available(last_flow.get("idle_total"), stats.get("q1_idle_quota"))
            if flow_rows_schema_complete and flows else False if budget_enabled and q1_flow_policy and q1_end_boundary else None
        ),
        "q1_flow_final_reflow_consumed_matches_stats": (
            _equal_if_available(last_flow.get("reflow_consumed"), stats.get("q1_reflow_consumed"))
            if flow_rows_schema_complete and flows else False if budget_enabled and q1_flow_policy and q1_end_boundary else None
        ),
        "q1_campaign_final_row_unique_and_last": (
            len(final_flow_rows) == 1 and bool(flows) and flows[-1].get("kind") == "campaign-final"
            if budget_enabled and q1_flow_policy and q1_end_boundary else None
        ),
        "q1_final_charged_matches_stats": _equal_if_available(
            final_flow.get("charged_invocations") if final_flow_rows else None,
            q1_charged if budget_enabled else None,
        ),
        "q1_final_uncredited_matches_stats": _equal_if_available(
            final_flow.get("idle_uncredited_total") if final_flow_rows else None,
            q1_uncredited if budget_enabled else None,
        ),
        "q1_final_effective_cap_matches_policy": (
            final_flow.get("effective_cap") == expected_cap
            if budget_enabled and final_flow_rows and _nonnegative_int(stats.get("q1_idle_quota"))
            else False if budget_enabled and q1_flow_policy and q1_end_boundary and not final_flow_rows
            else None
        ),
        "q1_final_quota_fields_match_stats": (
            all(final_flow.get(flow_key) == stats.get(stat_key) for flow_key, stat_key in (
                ("saved_total", "q1_saved_quota"), ("idle_total", "q1_idle_quota"),
                ("reflow_consumed", "q1_reflow_consumed"), ("reflow_pool_left", "q1_reflow_pool_left"),
            )) if budget_enabled and final_flow_rows and q1_counters_present
            else False if budget_enabled and q1_flow_policy and q1_end_boundary and not final_flow_rows
            else None
        ),
        "q1_quota_invariants_hold": quota_invariants,
        "q1_release_flow_sum_matches_stats": (
            flow_saved == q1_saved
            if budget_enabled and q1_counters_present and flow_rows_schema_complete
            else False if budget_enabled and q1_flow_policy and q1_end_boundary and q1_counters_present else None
        ),
        "q1_uncredited_flow_sum_matches_stats": (
            flow_uncredited == q1_uncredited
            if budget_enabled and q1_counters_present and flow_rows_schema_complete
            else False if budget_enabled and q1_flow_policy and q1_end_boundary and q1_counters_present else None
        ),
        "q1_consumed_flow_sum_matches_stats": (
            flow_consumed == q1_reflow_used
            if budget_enabled and q1_counters_present and flow_rows_schema_complete
            else False if budget_enabled and q1_flow_policy and q1_end_boundary and q1_counters_present else None
        ),
        "q1_executed_starts_match_campaign_charged_calls": (
            len(executed_starts) == q1_charged
            if budget_enabled and start_config.get("execution_log") is True and _nonnegative_int(q1_charged)
            else _equal_if_available(len(executed_starts), q1_charged)
            if budget_enabled and executions else None
        ),
        "q2_admitted_roots_match_stats": _equal_if_available(len(prov_admits) if "provisional-events.jsonl" in data else None, stats.get("provisional_admitted")),
        "q2_salvage_roots_match_success_counter": q2_salvage_counter_match,
        "q2_root_lifecycle_matches_by_id": q2_lifecycle_matches_by_id,
        "q2_ordinary_close_events_match_stats": _equal_if_available(sum(row.get("kind") == "ordinary-close" for row in provisional) if "provisional-events.jsonl" in data else None, stats.get("ordinary_match_closed")),
        "q2_productivity_roots_match_terminal_events": _equal_if_available(
            len(productive_roots) if "productivity-events.jsonl" in data else None,
            len(terminal_provisional) if "provisional-events.jsonl" in data else None,
        ),
        "q3_windows_match_stats": _equal_if_available(len(windows) if has_windows else None, stats.get("cal_training_windows")),
        "q3_episode_rows_match_stats": _equal_if_available(len(episodes) if has_episodes else None, stats.get("cal_episodes_jsonl")),
        "q3_window_count_matches_episode_training_observations": (
            _equal_if_available(
                len(windows) if has_windows else None,
                _sum_field(episodes, "training_observations") if has_episodes and episode_reward_fields_complete else None,
            )
        ),
        "q3_positive_window_rewards_match_episode_rewarded_observations": (
            _equal_if_available(
                sum(row.get("reward") == 1 for row in windows) if has_windows else None,
                _sum_field(episodes, "training_rewarded_observations") if has_episodes and episode_reward_fields_complete else None,
            )
        ),
        "q3_state_level_window_posterior_link_matches": (
            all(
                row["window_count_matches_episode_training_observations"]
                and row["positive_windows_match_episode_rewarded_observations"]
                for row in window_posterior_link_by_state.values()
            ) if window_posterior_link_by_state is not None else None
        ),
        "q3_eligible_completed_episodes_updated_posterior": (
            eligible_completed_missing_update == 0
            if has_episodes and episode_fields_complete and episode_posterior_evidence_complete
            and start_config.get("calibration") is True else None
        ),
        "q3_posterior_updates_have_training_evidence": (
            posterior_update_without_training_evidence == 0
            if has_episodes and episode_fields_complete and episode_posterior_evidence_complete
            and start_config.get("calibration") is True else None
        ),
        "q3_posterior_updates_match_training_evidence": (
            posterior_evidence_missing_update == 0 and posterior_update_without_training_evidence == 0
            if has_episodes and episode_fields_complete and episode_posterior_evidence_complete
            and start_config.get("calibration") is True else None
        ),
        "q3_fixed_width_rows_equal_total_windows": (
            sum(row.get("training_invocations") == start_config.get("cal_reward_window_invocations") for row in windows) == len(windows)
            if has_windows and windows and isinstance(start_config.get("cal_reward_window_invocations"), int) else None
        ),
        "q3_scheduler_calibration_fields_complete": (
            selection_fields_complete if has_selections else None
        ),
        "q3_episode_training_fields_complete": (
            episode_fields_complete if has_episodes else None
        ),
        "q3_episode_posterior_evidence_fields_complete": (
            episode_posterior_evidence_complete if has_episodes else None
        ),
    }

    consistency_values = [
        value for key, value in consistency.items()
        if key not in ("campaign_ids_seen", "q3_episode_posterior_evidence_fields_complete")
    ]
    incomplete_states = {"unresolved", "required_missing"}
    applicability_incomplete = any(
        item["state"] in incomplete_states for item in applicability.values()
    )
    episode_evidence_incomplete = consistency.get("q3_episode_posterior_evidence_fields_complete") is False
    consistency_status = (
        "inconsistent" if any(value is False for value in consistency_values)
        else "incomplete" if applicability_incomplete or errors or episode_evidence_incomplete
        else "consistent"
    )
    return {
        "report_generation_status": "generated",
        "telemetry_consistency_status": consistency_status,
        "default_exit_code_semantics": "exit 0 means the descriptive report was generated; inspect telemetry_consistency_status for data consistency",
        "source": source,
        "run": {
            "target": start_config.get("target"), "arm": start_config.get("arm"),
            "threshold_requested": start_config.get("threshold_requested"),
            "threshold_resolved": start_config.get("threshold_resolved"),
            "campaign_id": start_config.get("campaign_id"), "config_hash": start_config.get("config_hash"),
            "phase_records": len(configs) if configs else None,
        },
        "Q1_flow_and_accounting": q1_budget,
        "Q2_provisional_productivity_and_salvage": q2,
        "Q3_scheduler_and_reward_training": q3,
        "telemetry_consistency": consistency,
        "telemetry_applicability": applicability,
        "parse_errors": errors or None,
        "missing_telemetry_files": [name for name in JSONL_FILES if name not in data],
        "required_but_missing_telemetry_files": [
            name for name, item in applicability.items() if item["state"] == "required_missing"
        ],
        "unresolved_telemetry_files": [
            name for name, item in applicability.items() if item["state"] == "unresolved"
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Default exit 0 means report generation succeeded, not that telemetry is consistent. "
               "Use --fail-on-consistency-issue to return nonzero for incomplete or inconsistent samples.",
    )
    parser.add_argument("inputs", nargs="+", type=Path, help="result dir, extracted repeat dir, tarball, or parent directory")
    parser.add_argument("--fail-on-parse-error", action="store_true", help="exit nonzero if a telemetry file contains malformed JSONL or duplicate matches")
    parser.add_argument("--fail-on-consistency-issue", action="store_true", help="exit nonzero if any sample is incomplete or inconsistent")
    args = parser.parse_args()
    try:
        samples = discover(args.inputs)
    except (FileNotFoundError, OSError) as exc:
        parser.error(str(exc))
    if not samples:
        parser.error("no archives or extracted run directories found")

    failed = False
    loaded: list[tuple[Path, dict[str, Any], dict[str, list[str]]]] = []
    for sample in samples:
        if sample.is_file():
            data, errors, label = _read_tar(sample)
        else:
            data, errors, label = _read_dir(sample)
        report = _report(data, errors, label)
        collection_path, identity = _collection_identity(sample)
        report["collection"] = {
            "directory": str(collection_path) if collection_path else None,
            "arm_alias": identity.get("arm_alias") if identity else None,
            "expected_target": identity.get("target") if identity else None,
            "expected_threshold": identity.get("threshold") if identity else None,
            "repeat_index": _repeat_index(sample),
            "configured_arm": report["run"].get("arm"),
        }
        loaded.append((sample, report, errors))
        if errors:
            failed = True

    campaign_counts = collections.Counter(
        report["run"].get("campaign_id")
        for _, report, _ in loaded
        if report["run"].get("campaign_id")
    )
    by_collection: dict[str, list[tuple[Path, dict[str, Any], dict[str, list[str]]]]] = collections.defaultdict(list)
    for row in loaded:
        collection_name = row[1]["collection"].get("directory")
        if collection_name:
            by_collection[collection_name].append(row)

    for sample, report, _ in loaded:
        collection_name = report["collection"].get("directory")
        siblings = by_collection.get(collection_name, []) if collection_name else []
        _, identity = _collection_identity(sample)
        repeat_ids = [item[1]["collection"].get("repeat_index") for item in siblings]
        run_identity_tuples = {
            (item[1]["run"].get("target"), item[1]["run"].get("threshold_requested"), item[1]["run"].get("arm"))
            for item in siblings
        }
        arm_aliases = {item[1]["collection"].get("arm_alias") for item in siblings}
        config_identity_match = (
            report["run"].get("target") == identity.get("target")
            and report["run"].get("threshold_requested") == identity.get("threshold")
            if identity else None
        )
        repeat_index_unique = (
            all(value is not None for value in repeat_ids) and len(repeat_ids) == len(set(repeat_ids))
            if siblings else None
        )
        run_identity_consistent = len(run_identity_tuples) == 1 if siblings else None
        campaign_id = report["run"].get("campaign_id")
        campaign_unique = campaign_counts[campaign_id] == 1 if campaign_id else None
        cross_checks = {
            "campaign_id_unique_across_inputs": campaign_unique,
            "repeat_index_unique_within_collection": repeat_index_unique,
            "configured_target_threshold_match_collection_name": config_identity_match,
            "configured_target_threshold_arm_consistent_with_collection_repeats": run_identity_consistent,
            "collection_has_one_arm_alias": len(arm_aliases) == 1 if siblings else None,
        }
        report["cross_sample_consistency"] = cross_checks
        cross_values = list(cross_checks.values())
        cross_status = (
            "inconsistent" if any(value is False for value in cross_values)
            else "incomplete" if any(value is None for value in cross_values)
            else "consistent"
        )
        report["cross_sample_consistency_status"] = cross_status
        status_values = [report["telemetry_consistency_status"], cross_status]
        report["overall_audit_status"] = (
            "inconsistent" if "inconsistent" in status_values
            else "incomplete" if "incomplete" in status_values
            else "consistent"
        )
        if args.fail_on_consistency_issue and report["overall_audit_status"] != "consistent":
            failed = True
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 1 if failed and (args.fail_on_parse_error or args.fail_on_consistency_issue) else 0


if __name__ == "__main__":
    raise SystemExit(main())
