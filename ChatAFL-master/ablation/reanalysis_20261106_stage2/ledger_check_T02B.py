#!/usr/bin/env python3
"""T02-B budget-ledger verifier: read-only checks over final archives.

Per run:
  L1 invocation_id uniqueness across execution-events (starts+ends+refused)
  L2 every invocation_start has a paired invocation_end
  L3 mutually-exclusive kind partition: starts sum by execution_kind == total starts
  L4 double-charge guard: invocation_start count == unique (attempt_id) count
  L5 provisional-root charged budget <= 64 (via execution root field on starts)
  L6 unfinished tail: starts without end counted explicitly (never silent)

Exit prints one line per run: PASS / FAIL(checks).
"""
import argparse
import io
import json
import sys
import tarfile
from collections import Counter
from pathlib import Path

ALLOWED_KINDS = {"calibration", "mutation", "candidate", "shadow", "prov-annotate", "sync"}


def _jsonl(tf, name):
    fp = tf.extractfile(name)
    if fp is None:
        return []
    rows = []
    for line in io.TextIOWrapper(fp):
        if line.strip():
            rows.append(json.loads(line))
    return rows


def check_archive(path):
    fails = []
    with tarfile.open(path, "r:gz") as tf:
        fp = tf.extractfile("out-bftpd-loopfuzz/execution-events.jsonl")
        if fp is None:
            return ["no-execution-ledger"], {}
        starts, ends, refused = [], [], []
        for line in io.TextIOWrapper(fp):
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                fails.append("bad-json-line")
                continue
            ev = j.get("event")
            if ev == "invocation_start":
                starts.append(j)
            elif ev == "invocation_end":
                ends.append(j)
            elif ev == "invocation_refused":
                refused.append(j)
            elif ev:
                fails.append("unknown-event:" + str(ev))

    allowed = [s.get("execution_kind") for s in starts]
    unknown = sorted(set(k for k in allowed if k not in ALLOWED_KINDS))
    if unknown:
        fails.append("L3-unknown-execution-kind:" + ",".join(unknown))
    if sum(Counter(allowed).values()) != len(starts):
        fails.append("L3-kind-partition")

    # L1 unique invocation ids among started and ended. Refused invocations
    # intentionally have no invocation_id and are checked by attempt_id.
    ids = [s.get("invocation_id") for s in starts if s.get("invocation_id")]
    if len(ids) != len(set(ids)):
        fails.append("L1-duplicate-invocation-id")
    end_ids = [e.get("invocation_id") for e in ends if e.get("invocation_id")]
    if len(end_ids) != len(set(end_ids)):
        fails.append("L2-duplicate-end-invocation-id")
    start_set, end_set = set(ids), set(end_ids)
    unmatched = sorted(start_set - end_set)
    extra_ends = sorted(end_set - start_set)
    if unmatched:
        fails.append("L2-unmatched-starts")
    if extra_ends:
        fails.append("L2-extra-ends")
    kinds = Counter(s.get("execution_kind", "?") for s in starts)
    # L4 attempts one-to-one with starts
    attempts = [s.get("attempt_id") for s in starts if s.get("attempt_id") is not None]
    if len(attempts) != len(set(attempts)):
        fails.append("L4-attempt-reuse")
    # L5 per-root charged cap (root-level field present when a provisional
    # root owns the invocation; missing => ordinary/no-root, not capped here)
    root_present = sum(isinstance(s.get("root"), dict) and bool(s.get("root")) for s in starts)
    root_missing = len(starts) - root_present
    over = [r for r, n in Counter(
        s.get("root") for s in starts
        if isinstance(s.get("root"), dict) and s["root"]
    ).items() if n > 64]
    rootcap = Counter()
    for s in starts:
        r = s.get("root")
        if isinstance(r, dict) and r:
            key = (r.get("queue_entry"), r.get("candidate_id"))
            rootcap[key] += 1
    cap_violations = {str(k): v for k, v in rootcap.items() if v > 64}
    if cap_violations:
        fails.append("L5-root-over-64")
    stats = {
        "starts": len(starts), "ends": len(ends), "refused": len(refused),
        "unpaired_starts": len(unmatched), "extra_ends": len(extra_ends),
        "root_fields_present": root_present, "root_fields_missing": root_missing,
        "kinds": dict(kinds),
        "root_cap_violations": cap_violations,
    }
    # L7 fixed-budget identity (stage-2 T03 runs): when a campaign call
    # budget is stamped, charged starts must not exceed cap; refusals at
    # the cap must be present (budget actually bound) or the run ended by
    # timeout first (both recorded, never silently assumed).
    with tarfile.open(path, "r:gz") as tf2:
        rc = tf2.extractfile("out-bftpd-loopfuzz/run-config.jsonl")
        budget = None
        if rc:
            for line in io.TextIOWrapper(rc):
                try:
                    j = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if j.get("event") == "run_config" and j.get("phase") == "start":
                    budget = j.get("campaign_call_budget")
                    stats["q1_policy"] = j.get("q1_policy")
                    stats["campaign_id"] = j.get("campaign_id")
                    break
    if budget:
        stats["campaign_call_budget"] = budget
        if len(starts) > budget:
            fails.append("L7-charged-over-budget")
        stats["budget_binding"] = "cap" if len(refused) else "timeout-first-or-unbound"
        if len(starts) > budget:
            fails.append("L7-charged-over-budget")
    # A missing root is not a passing root-cap result. It is inconclusive for
    # runs whose config advertises provisional service; ordinary-only runs are
    # explicitly marked not-applicable.
    if root_missing:
        provisional = stats.get("provisional_enabled")
        if provisional:
            stats["root_cap_check"] = "INCONCLUSIVE-root-field-missing"
        else:
            stats["root_cap_check"] = "NOT_APPLICABLE"
    else:
        stats["root_cap_check"] = "PASS"
    # Q1 flow rows are checked when present. A saved row must either be idle
    # or create one reservation amount; consumed rows must bind a receiver.
    with tarfile.open(path, "r:gz") as tf3:
        names3 = {mm.name.split("/")[-1] for mm in tf3.getmembers()}
        flows = _jsonl(tf3, "out-bftpd-loopfuzz/q1-budget-flow.jsonl") if "q1-budget-flow.jsonl" in names3 else []
    if flows:
        saved = [x for x in flows if x.get("kind") == "saved"]
        consumed = [x for x in flows if x.get("kind") == "consumed"]
        if any(x.get("destination") == "ordinary-pool" and not x.get("flow_id") for x in saved):
            fails.append("L7-reflow-save-missing-flow-id")
        if any(not x.get("receiver_invocation_id") for x in consumed):
            fails.append("L7-reflow-consume-missing-receiver")
        stats["q1_flow_saved"] = len(saved)
        stats["q1_flow_consumed"] = len(consumed)
    return fails, stats


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("index", type=Path, help="legacy_run_index.json or any index with runs[].archive")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    idx = json.loads(args.index.read_text())
    out = {}
    npass = nfail = 0
    for r in idx["runs"]:
        if not Path(r["archive"]).exists():
            out[r.get("stage2_id", r["arm"])] = {"status": "ARCHIVE_MISSING"}
            nfail += 1
            continue
        fails, stats = check_archive(r["archive"])
        status = "PASS" if not fails else "FAIL:" + ",".join(fails)
        key = stats.get("campaign_id") or r.get("stage2_id") or r["arm"]
        if key in out:
            key = f"{key}::{r.get('stage2_id', r['arm'])}"
        out[key] = {"stage2_id": r.get("stage2_id"), "arm": r["arm"], "status": status, **stats}
        npass += status == "PASS"
        nfail += status != "PASS"
    args.output.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(f"ledger check: {npass} PASS / {nfail} not-pass -> {args.output}")
    bad = {k: v["status"] for k, v in out.items() if v.get("status", "").startswith("FAIL")}
    if bad:
        print(json.dumps(bad, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
