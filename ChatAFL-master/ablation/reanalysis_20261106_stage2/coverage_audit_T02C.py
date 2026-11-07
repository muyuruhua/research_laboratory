#!/usr/bin/env python3
"""Audit coverage evidence without treating a zero gcov baseline as a seed set.

The archive's terminal file records a replay-union measurement.  A numeric
``terminal - baseline`` delta is reported only when the baseline contains an
explicit branch identity set or the terminal contains the branch union of
identified initial seeds.  A gcovr report whose counters are all zero is not
such a set, so old archives without the explicit seed union remain
``INCONCLUSIVE``.  New archives must also carry per-input hash witnesses that
join to the replay plan and checkpoint ledger.
"""
from __future__ import annotations

import argparse
import json
import tarfile
from pathlib import Path
from typing import Any


def _read(tf: tarfile.TarFile, name: str) -> dict[str, Any] | None:
    try:
        fp = tf.extractfile(name)
    except KeyError:
        return None
    if fp is None:
        return None
    try:
        value = json.loads(fp.read())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _read_jsonl(tf: tarfile.TarFile, name: str) -> list[dict[str, Any]]:
    try:
        fp = tf.extractfile(name)
    except KeyError:
        return []
    if fp is None:
        return []
    text = fp.read().decode("utf-8")
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        document = None
    if isinstance(document, list):
        return [item for item in document if isinstance(item, dict)]
    rows = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def _branch_ids(doc: dict[str, Any], key: str = "covered_branch_ids") -> set[tuple[str, int, int]]:
    result: set[tuple[str, int, int]] = set()
    for item in doc.get(key, []):
        if isinstance(item, list) and len(item) == 3:
            try:
                result.add((str(item[0]), int(item[1]), int(item[2])))
            except (TypeError, ValueError):
                continue
    return result


def audit_archive(path: str | Path) -> dict[str, Any]:
    out: dict[str, Any] = {
        "archive": str(path),
        "status": "PASS",
        "measurement": "retained-corpus-replay-union",
        "failures": [],
        "inconclusive": [],
    }
    try:
        tf = tarfile.open(path, "r:gz")
    except (OSError, tarfile.TarError) as exc:
        return {**out, "status": "FAIL", "failures": [f"archive-open:{exc}"]}
    with tf:
        terminal = _read(tf, "out-bftpd-loopfuzz/cov_over_time.csv.v4/terminal.json")
        baseline = _read(tf, "out-bftpd-loopfuzz/cov_over_time.csv.v4/baseline.json")
        plan = _read_jsonl(tf, "out-bftpd-loopfuzz/cov_over_time.csv.v4/replay-plan.json")
        checkpoints = _read_jsonl(tf, "out-bftpd-loopfuzz/cov_over_time.csv.v4/checkpoints.jsonl")
    if terminal is None:
        out["failures"].append("missing-or-invalid-terminal")
        return {**out, "status": "FAIL"}
    if baseline is None:
        out["failures"].append("missing-or-invalid-baseline")
        return {**out, "status": "FAIL"}
    if terminal.get("acceptance") != "complete" or terminal.get("coverage_complete") is not True:
        out["failures"].append("terminal-not-complete")
    if terminal.get("n_unreplayable_ledger_entries", 0) != 0:
        out["failures"].append("unreplayable-ledger-entries")
    anomalies = terminal.get("replay_anomalies")
    anomalies_nonzero = not (anomalies in (None, [], {}) or (isinstance(anomalies, dict) and anomalies.get("total", 0) == 0))
    if anomalies_nonzero:
        out["failures"].append("replay-anomalies")
    terminal_ids = _branch_ids(terminal)
    baseline_ids = _branch_ids(baseline)
    # Current coverage-v4 writes a real seed baseline from replayed initial
    # queue inputs.  This is distinct from gcovr's reset report, which may have
    # no branch IDs when no gcda existed before replay.
    seed_ids = _branch_ids(terminal, "seed_covered_branch_ids")
    seed_replayed = terminal.get("n_seed_replayed")
    # An empty field is not evidence of a seed baseline.  The producer emits
    # the field for every run, including runs whose queue replay did not carry
    # an identifiable initial seed.  Require both a positive seed replay count
    # and a non-empty branch identity set before treating subtraction as proven.
    seed_proof = (isinstance(seed_replayed, int) and not isinstance(seed_replayed, bool)
                  and seed_replayed > 0 and bool(seed_ids))
    out["terminal_branch_ids"] = len(terminal_ids)
    out["baseline_branch_ids"] = len(baseline_ids)
    out["seed_baseline_branch_ids"] = len(seed_ids)
    out["n_replayed"] = terminal.get("n_replayed")
    if seed_proof:
        out["terminal_minus_baseline_branch_ids"] = len(terminal_ids - seed_ids)
        out["seed_subtraction_proven"] = True
        out["seed_baseline_source"] = "initial-queue replay union"
    elif baseline_ids:
        out["terminal_minus_baseline_branch_ids"] = len(terminal_ids - baseline_ids)
        out["seed_subtraction_proven"] = True
        out["seed_baseline_source"] = "gcovr baseline"
    else:
        # gcovr's files/lines counters with count=0 describe a reset state;
        # they do not identify the branches exercised by the initial corpus.
        out["seed_subtraction_proven"] = False
        out["inconclusive"].append("baseline-has-no-explicit-branch-identities")
        out["terminal_minus_baseline_branch_ids"] = None
    # Cross-check the queue and snapshot hashes recorded for every replayed
    # input.  A count alone is insufficient: the witness must join to the
    # immutable replay plan and checkpoint event.
    witnesses = terminal.get("executed_input_witnesses")
    witness_ok = isinstance(witnesses, list) and len(witnesses) == terminal.get("n_replayed")
    if witness_ok:
        plan_by_name = {r.get("filename"): r for r in plan}
        checkpoint_by_name = {r.get("filename"): r for r in checkpoints}
        if (len(plan_by_name) != len(plan) or len(checkpoint_by_name) != len(checkpoints)
                or len(checkpoints) != terminal.get("n_replayed")):
            witness_ok = False
        seen_names = set()
        seen_indices = set()
        for witness in witnesses:
            name = witness.get("filename") if isinstance(witness, dict) else None
            idx = witness.get("idx") if isinstance(witness, dict) else None
            if not name or name in seen_names or idx in seen_indices:
                witness_ok = False
                break
            seen_names.add(name)
            seen_indices.add(idx)
            planned = plan_by_name.get(name)
            checkpoint = checkpoint_by_name.get(name)
            if planned is None or checkpoint is None:
                witness_ok = False
                break
            for key in ("idx", "input_sha256", "snapshot_sha256"):
                if witness.get(key) != (checkpoint.get(key) if key != "idx" else checkpoint.get("idx")):
                    witness_ok = False
                    break
            if not witness_ok:
                break
            if witness.get("input_sha256") != planned.get("input_sha256"):
                witness_ok = False
                break
    out["executed_input_union_proven"] = witness_ok
    if not witness_ok:
        out["inconclusive"].append("no-ever-seen-input-witness-proof")
    if out["failures"]:
        out["status"] = "FAIL"
    elif out["inconclusive"]:
        out["status"] = "INCONCLUSIVE"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("index", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    idx = json.loads(args.index.read_text())
    rows = []
    for pos, run in enumerate(idx.get("runs", [])):
        archive = str(run.get("archive", ""))
        row = audit_archive(archive) if Path(archive).exists() else {"archive": archive, "status": "FAIL", "failures": ["archive-missing"]}
        row.update({"run_index": pos, "run_id": run.get("run_id") or run.get("stage2_id") or f"run-{pos:04d}", "arm": run.get("arm")})
        rows.append(row)
    status = "FAIL" if any(r["status"] == "FAIL" for r in rows) else ("INCONCLUSIVE" if any(r["status"] == "INCONCLUSIVE" for r in rows) else "PASS")
    payload = {"schema_version": 1, "status": status, "runs": rows}
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(f"{status}: {len(rows)} coverage records -> {args.output}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
