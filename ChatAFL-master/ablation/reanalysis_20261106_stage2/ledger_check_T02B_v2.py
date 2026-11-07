#!/usr/bin/env python3
"""Run-level ledger checker for the stage-2 archives.

The original checker keyed its output by arm, so the second and third
replicates overwrote the first one.  This checker treats one archive as one
unit and reports an explicit ``INCONCLUSIVE`` result when a requested proof
cannot be made from the events (for example, a provisional run without root
identities).  It is intentionally read-only.
"""
from __future__ import annotations

import argparse
import io
import json
import tarfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ALLOWED_KINDS = {"calibration", "mutation", "candidate", "shadow", "prov-annotate"}
Q1_POLICIES = {"direct-service", "no-reflow", "reflow"}
ALLOWED_EVENTS = {"invocation_start", "invocation_end", "invocation_refused"}


def _jsonl(tf: tarfile.TarFile, member: str) -> list[dict[str, Any]]:
    try:
        fp = tf.extractfile(member)
    except KeyError:
        return []
    if fp is None:
        return []
    out: list[dict[str, Any]] = []
    for raw in io.TextIOWrapper(fp):
        if not raw.strip():
            continue
        try:
            val = json.loads(raw)
        except json.JSONDecodeError:
            out.append({"__bad_json__": True})
            continue
        if isinstance(val, dict):
            out.append(val)
    return out


def _run_config(tf: tarfile.TarFile) -> dict[str, Any]:
    rows = _jsonl(tf, "out-bftpd-loopfuzz/run-config.jsonl")
    starts = [r for r in rows if r.get("event") == "run_config" and r.get("phase") == "start"]
    if not starts:
        return {}
    # Duplicate start records are a contract violation, not a reason to pick
    # the last record silently.
    if len(starts) != 1:
        return {"__duplicate_start__": len(starts), **starts[-1]}
    return starts[0]


def _run_config_end(tf: tarfile.TarFile) -> dict[str, Any]:
    rows = _jsonl(tf, "out-bftpd-loopfuzz/run-config.jsonl")
    ends = [r for r in rows if r.get("event") == "run_config" and r.get("phase") == "end"]
    return ends[-1] if ends else {}


def _fuzzer_stats(tf: tarfile.TarFile) -> dict[str, str]:
    """Read the scalar ``fuzzer_stats`` contract when an archive has one."""
    try:
        fp = tf.extractfile("out-bftpd-loopfuzz/fuzzer_stats")
    except KeyError:
        return {}
    if fp is None:
        return {}
    result: dict[str, str] = {}
    for raw in io.TextIOWrapper(fp):
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        result[key.strip()] = value.strip()
    return result


def _stat_int(stats: dict[str, str], key: str) -> int | None:
    value = stats.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _flow_check(tf: tarfile.TarFile, execution_rows: list[dict[str, Any]] | None = None,
                expected_campaign_id: str | None = None) -> tuple[str, list[str], dict[str, Any]]:
    rows = _jsonl(tf, "out-bftpd-loopfuzz/q1-budget-flow.jsonl")
    if not rows:
        return "NOT_APPLICABLE", [], {"events": 0}
    problems: list[str] = []
    saved = 0
    previous_consumed = 0
    previous_idle = 0
    previous_pool = 0
    counter_mode: str | None = None
    # Keep the saved reservation identities until their last unit is
    # consumed.  A flow aggregate alone cannot prove that an ordinary
    # invocation received quota from the particular rejected candidate.
    reservations: dict[int, dict[str, int]] = {}
    consumed_by_flow: Counter[int] = Counter()
    consumed_receivers: set[int] = set()
    execution_ends = {
        row.get("invocation_id"): row
        for row in (execution_rows if execution_rows is not None else _jsonl(tf, "out-bftpd-loopfuzz/execution-events.jsonl"))
        if row.get("event") == "invocation_end"
    }
    for i, row in enumerate(rows):
        if row.get("__bad_json__"):
            problems.append(f"bad-flow-json:{i}")
            continue
        if row.get("event") != "q1_budget_flow":
            problems.append(f"unexpected-flow-event:{i}")
        if expected_campaign_id is not None and row.get("campaign_id") != expected_campaign_id:
            problems.append(f"flow-campaign-mismatch:{i}")
        amount = row.get("amount")
        if not isinstance(amount, int) or amount <= 0:
            problems.append(f"invalid-flow-amount:{i}")
            amount = 0
        kind = row.get("kind")
        if kind == "saved":
            saved += amount
            if row.get("saved_total") != saved:
                problems.append(f"saved-total-mismatch:{i}")
            destination = row.get("destination")
            flow_id = row.get("flow_id")
            source = row.get("candidate_id")
            if not isinstance(source, int) or source <= 0:
                problems.append(f"saved-missing-source-candidate:{i}")
            if destination == "ordinary-pool":
                if not isinstance(flow_id, int) or flow_id <= 0:
                    problems.append(f"saved-missing-flow-id:{i}")
                elif flow_id in reservations:
                    problems.append(f"duplicate-saved-flow-id:{i}")
                else:
                    reservations[flow_id] = {
                        "source_candidate_id": source if isinstance(source, int) else -1,
                        "amount": amount,
                    }
                if row.get("remaining") != amount:
                    problems.append(f"saved-remaining-mismatch:{i}")
                if row.get("receiver_invocation_id") not in (0, None):
                    problems.append(f"saved-has-receiver-id:{i}")
            elif destination == "idle":
                if flow_id not in (0, None):
                    problems.append(f"idle-has-flow-id:{i}")
        elif kind == "consumed":
            if row.get("saved_total") != saved:
                problems.append(f"consumed-saved-total-mismatch:{i}")
            flow_id = row.get("flow_id")
            if not isinstance(flow_id, int) or flow_id <= 0:
                problems.append(f"consumed-missing-flow-id:{i}")
            receiver = row.get("receiver_invocation_id")
            if not isinstance(receiver, int) or receiver <= 0:
                problems.append(f"consumed-missing-receiver-id:{i}")
            elif receiver in consumed_receivers:
                problems.append(f"duplicate-consumed-receiver-id:{i}")
            else:
                consumed_receivers.add(receiver)
            if row.get("destination") != "ordinary-mutation":
                problems.append(f"invalid-consumed-destination:{i}")
            if amount != 1:
                problems.append(f"invalid-consumed-amount:{i}")
            reservation = reservations.get(flow_id)
            if reservation is None:
                problems.append(f"consumed-unknown-flow-id:{i}")
            else:
                consumed = consumed_by_flow[flow_id] + amount
                consumed_by_flow[flow_id] = consumed
                expected_remaining = reservation["amount"] - consumed
                if expected_remaining < 0:
                    problems.append(f"flow-over-consumed:{i}")
                if row.get("candidate_id") != reservation["source_candidate_id"]:
                    problems.append(f"consumed-source-mismatch:{i}")
                if row.get("remaining") != expected_remaining:
                    problems.append(f"consumed-remaining-mismatch:{i}")
                if consumed == reservation["amount"]:
                    del reservations[flow_id]
            end = execution_ends.get(receiver)
            if end is None:
                problems.append(f"consumed-receiver-not-in-execution-ledger:{i}")
            else:
                if end.get("execution_kind") != "mutation":
                    problems.append(f"consumed-receiver-kind-mismatch:{i}")
                if end.get("q1_flow_id") != flow_id:
                    problems.append(f"consumed-receiver-flow-mismatch:{i}")
                if end.get("q1_flow_source_candidate") != row.get("candidate_id"):
                    problems.append(f"consumed-receiver-source-mismatch:{i}")
        else:
            problems.append(f"invalid-flow-kind:{i}")
        consumed = row.get("reflow_consumed", 0)
        idle = row.get("idle_total", 0)
        pool = row.get("reflow_pool_left", 0)
        if not all(isinstance(x, int) and x >= 0 for x in (consumed, idle, pool)):
            problems.append(f"negative-or-numeric-counter:{i}")
            continue
        if consumed < previous_consumed or idle < previous_idle or pool > previous_pool + amount:
            problems.append(f"nonmonotone-flow-counter:{i}")
        if consumed > saved:
            problems.append(f"consumed-over-saved:{i}")
        destination = row.get("destination")
        # The counters are emitted immediately before this save is applied:
        # idle_total (or consumed+pool) excludes the current amount.
        if destination == "idle":
            # The producer logs after parking the amount.  Require the
            # post-state identity; accepting the old pre-state convention
            # would make a partially written event look valid.
            current_mode = "post" if idle == saved and consumed == 0 and pool == 0 else "bad"
            if current_mode == "bad":
                problems.append(f"idle-total-mismatch:{i}")
            elif kind == "saved":
                if counter_mode is None:
                    counter_mode = current_mode
                elif counter_mode != current_mode:
                    problems.append(f"mixed-counter-convention:{i}")
        if destination in {"ordinary-pool", "ordinary-mutation"} and idle != 0:
            problems.append(f"ordinary-idle-nonzero:{i}")
        if destination in {"ordinary-pool", "ordinary-mutation"}:
            total = consumed + pool
            if total != saved:
                problems.append(f"ordinary-pool-total-mismatch:{i}")
        if destination not in {"idle", "ordinary-pool", "ordinary-mutation"}:
            problems.append(f"invalid-flow-destination:{i}")
        previous_consumed, previous_idle, previous_pool = consumed, idle, pool
    last = rows[-1]
    stats = {
        "events": len(rows),
        "saved_total": last.get("saved_total"),
        "reflow_consumed": last.get("reflow_consumed"),
        "idle_total": last.get("idle_total"),
        "reflow_pool_left": last.get("reflow_pool_left"),
        "flow_closed": not bool(reservations),
        "open_reservations": len(reservations),
    }
    # A smoke archive may end before all saved quota is served; that is a
    # measurable unserved opportunity, not malformed accounting.  Keep it in
    # stats so the experiment analysis can report it instead of silently
    # treating the aggregate as fully consumed.
    return ("FAIL" if problems else "PASS"), problems, stats


def check_archive(path: str | Path) -> dict[str, Any]:
    """Check one archive and return a run-level, JSON-serialisable result."""
    result: dict[str, Any] = {"archive": str(path), "status": "PASS", "failures": [], "inconclusive": []}
    try:
        tf = tarfile.open(path, "r:gz")
    except (OSError, tarfile.TarError) as exc:
        result.update(status="FAIL", failures=[f"archive-open:{exc}"])
        return result
    with tf:
        rows = _jsonl(tf, "out-bftpd-loopfuzz/execution-events.jsonl")
        cfg = _run_config(tf)
        cfg_end = _run_config_end(tf)
        stats = _fuzzer_stats(tf)
        event_campaigns = {
            r.get("campaign_id") for r in rows
            if r.get("event") in ALLOWED_EVENTS and r.get("campaign_id")
        }
        event_campaign = next(iter(event_campaigns), None) if len(event_campaigns) == 1 else None
        config_campaign = cfg.get("campaign_id")
        result["campaign_id"] = config_campaign or event_campaign
        result["q1_policy"] = cfg.get("q1_policy")
        starts = [r for r in rows if r.get("event") == "invocation_start"]
        ends = [r for r in rows if r.get("event") == "invocation_end"]
        refused = [r for r in rows if r.get("event") == "invocation_refused"]
        result["counts"] = {"starts": len(starts), "ends": len(ends), "refused": len(refused)}
        failures: list[str] = []
        bad_json = sum(1 for r in rows if r.get("__bad_json__"))
        if bad_json:
            failures.append("bad-json-line")
        if cfg.get("__duplicate_start__"):
            failures.append("duplicate-run-config-start")
        if len(event_campaigns) > 1:
            failures.append("multiple-campaign-ids")
        if config_campaign and event_campaign and config_campaign != event_campaign:
            failures.append("config-event-campaign-mismatch")
        for row in rows:
            if row.get("event") not in ALLOWED_EVENTS and not row.get("__bad_json__"):
                failures.append("unknown-event:" + str(row.get("event")))

        start_ids = [r.get("invocation_id") for r in starts]
        end_ids = [r.get("invocation_id") for r in ends]
        if any(x is None for x in start_ids + end_ids):
            failures.append("missing-invocation-id")
        if len(start_ids) != len(set(start_ids)):
            failures.append("duplicate-start-invocation-id")
        if len(end_ids) != len(set(end_ids)):
            failures.append("duplicate-end-invocation-id")
        if set(start_ids) != set(end_ids):
            failures.append("unmatched-or-extra-end-id")

        start_by_id = {r.get("invocation_id"): r for r in starts}
        end_by_id = {r.get("invocation_id"): r for r in ends}
        for iid in set(start_by_id) & set(end_by_id):
            s, e = start_by_id[iid], end_by_id[iid]
            if s.get("execution_kind") != e.get("execution_kind"):
                failures.append(f"kind-mismatch:{iid}")
            if s.get("attempt_id") != e.get("attempt_id"):
                failures.append(f"attempt-mismatch:{iid}")
            if s.get("campaign_id") != e.get("campaign_id"):
                failures.append(f"campaign-mismatch:{iid}")
            for field in ("candidate_id", "parent_queue_id", "q1_flow_id",
                          "q1_flow_source_candidate"):
                if field in s or field in e:
                    if s.get(field) != e.get(field):
                        failures.append(f"{field}-mismatch:{iid}")
        kinds = Counter(r.get("execution_kind") for r in starts)
        unknown = sorted(k for k in kinds if k not in ALLOWED_KINDS)
        if unknown:
            failures.append("unknown-execution-kind:" + ",".join(map(str, unknown)))
        attempts = [r.get("attempt_id") for r in starts]
        if any(x is None for x in attempts):
            failures.append("missing-attempt-id")
        if len(attempts) != len(set(attempts)):
            failures.append("duplicate-start-attempt-id")
        refused_attempts = [r.get("attempt_id") for r in refused]
        if any(x is None for x in refused_attempts):
            failures.append("missing-refused-attempt-id")
        all_attempts = attempts + refused_attempts
        if len(all_attempts) != len(set(all_attempts)):
            failures.append("duplicate-attempt-id-across-events")
        for row in refused:
            if row.get("invocation_id") not in (None, 0):
                failures.append("refused-has-invocation-id")

        budget = cfg.get("campaign_call_budget")
        if isinstance(budget, bool) or not isinstance(budget, (int, float)) or budget < 0:
            if budget is not None:
                failures.append("invalid-campaign-budget")
        elif len(starts) > budget:
            failures.append("starts-over-campaign-budget")
        result["kinds"] = dict(kinds)
        result["campaign_call_budget"] = budget

        # A completed archive must bind its scalar accounting to the event
        # ledger.  Synthetic fixtures without fuzzer_stats remain useful for
        # unit tests, while real archives get the stronger check.
        if stats:
            result["fuzzer_stats"] = {
                k: _stat_int(stats, k) for k in (
                    "execs_done", "campaign_call_budget",
                    "campaign_charged_calls", "campaign_budget_exhausted",
                    "q1_saved_quota", "q1_idle_quota",
                    "q1_reflow_consumed", "q1_reflow_pool_left")
                if _stat_int(stats, k) is not None
            }
            charged = _stat_int(stats, "campaign_charged_calls")
            if charged is not None and charged != len(starts):
                failures.append("charged-start-count-mismatch")
            stats_budget = _stat_int(stats, "campaign_call_budget")
            if budget is not None and stats_budget is not None and stats_budget != budget:
                failures.append("stats-config-budget-mismatch")
            idle = _stat_int(stats, "q1_idle_quota")
            saved = _stat_int(stats, "q1_saved_quota")
            consumed = _stat_int(stats, "q1_reflow_consumed")
            pool = _stat_int(stats, "q1_reflow_pool_left")
            exhausted = _stat_int(stats, "campaign_budget_exhausted")
            if all(x is not None for x in (saved, idle, consumed, pool)):
                if saved != idle + consumed + pool:
                    failures.append("q1-saved-conservation-mismatch")
                if cfg.get("q1_policy") == "no-reflow" and (consumed != 0 or pool != 0):
                    failures.append("q1-no-reflow-has-pool")
                if cfg.get("q1_policy") == "reflow" and idle != 0:
                    failures.append("q1-reflow-has-idle")
                if budget is not None and charged is not None and charged + idle > budget:
                    failures.append("q1-charged-plus-idle-over-budget")
                if exhausted == 1 and budget is not None and charged + idle != budget:
                    failures.append("q1-effective-budget-not-closed")
            if exhausted == 1:
                termination = cfg_end.get("termination_reason")
                if termination and termination != "campaign-call-budget":
                    failures.append("budget-exhausted-wrong-termination")
                if not refused:
                    failures.append("budget-exhausted-without-refusal")

        # Root cap is a proof obligation only when root identity is present.
        # The 64-call contract applies to provisional mutation service.  A
        # root can also appear on calibration/ordinary events for accounting;
        # counting those would report a false cap violation.
        rooted = [
            r for r in starts
            if r.get("provisional_root_queue_id") is not None
            and r.get("execution_kind") == "mutation"
            and r.get("episode_selection_reason") == "forced-provisional-candidate"
        ]
        root_counts = Counter(r.get("provisional_root_queue_id") for r in rooted)
        over = {str(k): n for k, n in root_counts.items() if n > 64}
        if over:
            failures.append("root-over-64")
        root_required = cfg.get("q1_policy") in Q1_POLICIES or any(r.get("execution_kind") == "prov-annotate" for r in starts)
        if root_required and not rooted:
            result["root_cap_status"] = "INCONCLUSIVE"
            result["inconclusive"].append("missing-provisional-root-identity")
        else:
            result["root_cap_status"] = "PASS" if not over else "FAIL"
        result["root_counts"] = {str(k): n for k, n in root_counts.items()}

        flow_status, flow_failures, flow_stats = _flow_check(
            tf, rows, expected_campaign_id=result.get("campaign_id"))
        result["q1_flow_status"] = flow_status
        result["q1_flow"] = flow_stats
        failures.extend("q1-" + x for x in flow_failures)
        if cfg.get("q1_policy") in {"no-reflow", "reflow"}:
            saved_stat = _stat_int(stats, "q1_saved_quota") if stats else None
            if saved_stat is not None and saved_stat > 0 and flow_status == "NOT_APPLICABLE":
                failures.append("q1-saved-without-flow-ledger")
        result["failures"] = sorted(set(failures))
        if failures:
            result["status"] = "FAIL"
        elif result["inconclusive"]:
            result["status"] = "INCONCLUSIVE"
    return result


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("index", type=Path, help="index JSON containing runs[].archive")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    idx = json.loads(args.index.read_text())
    runs = idx.get("runs", [])
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    duplicate_keys: list[str] = []
    for pos, run in enumerate(runs):
        archive = str(run.get("archive", ""))
        run_id = str(run.get("run_id") or run.get("stage2_id") or f"run-{pos:04d}")
        key = f"{run_id}@{archive}"
        if key in seen:
            duplicate_keys.append(key)
        seen.add(key)
        result = check_archive(archive) if Path(archive).exists() else {"status": "FAIL", "failures": ["archive-missing"], "archive": archive}
        result.update({"run_index": pos, "run_id": run_id, "arm": run.get("arm")})
        out.append(result)
    payload = {"schema_version": 2, "runs": out, "duplicate_run_keys": duplicate_keys}
    if duplicate_keys:
        payload["status"] = "FAIL"
    elif any(r.get("status") == "FAIL" for r in out):
        payload["status"] = "FAIL"
    elif any(r.get("status") == "INCONCLUSIVE" for r in out):
        payload["status"] = "INCONCLUSIVE"
    else:
        payload["status"] = "PASS"
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(f"{payload['status']}: {len(out)} run-level records -> {args.output}")
    return 0 if payload["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
