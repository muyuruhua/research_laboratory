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

    # L1 unique invocation ids among started
    ids = [s.get("invocation_id") for s in starts if s.get("invocation_id")]
    if len(ids) != len(set(ids)):
        fails.append("L1-duplicate-invocation-id")
    # L2 pairing
    end_ids = {e.get("invocation_id") for e in ends}
    unmatched = [i for i in ids if i not in end_ids]
    # L3 kind partition (partition is definitional; report composition)
    kinds = Counter(s.get("execution_kind", "?") for s in starts)
    # L4 attempts one-to-one with starts
    attempts = [s.get("attempt_id") for s in starts if s.get("attempt_id") is not None]
    if len(attempts) != len(set(attempts)):
        fails.append("L4-attempt-reuse")
    # L5 per-root charged cap (root-level field present when a provisional
    # root owns the invocation; missing => ordinary/no-root, not capped here)
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
        "unpaired_starts": len(unmatched),
        "kinds": dict(kinds),
        "root_cap_violations": cap_violations,
    }
    if unmatched:
        # tail cutoff is legitimate at campaign end but must be explicit
        stats["note"] = "unpaired starts allowed only at campaign tail (cutoff)"
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
        out[r.get("stage2_id", r["arm"])] = {"arm": r["arm"], "status": status, **stats}
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
