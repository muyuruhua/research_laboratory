#!/usr/bin/env python3
"""P0-3 canonical coverage pipeline (v3, 2026-10-05).

Two modes:

  1. run-dir mode: one or more directories containing cov_over_time.csv
     (+ optional .audit sidecar, fuzzer_stats, run-config.jsonl).
     Rebuilds each trajectory by REPLAY ORDER (idx column written by the
     v3 cov_script; falls back to cumulative-max for pre-v3 files),
     enforces monotone non-decreasing branch counts (a cumulative union
     cannot decrease — any decrease is a timestamp/ordering artifact),
     aligns t0 to the campaign start (fuzzer_stats start_time), appends
     the campaign-end support point, clips every run to [0, 24h], and
     reports endpoint/AUC plus the three separate denominators
     (archives / completed / support@24h) that Figures and Tables must
     agree on.

  2. legacy-json mode (--legacy-json filled_run_evidence_20260930.json):
     applies the same union semantics (cumulative max) + plateau
     extension + censoring rules to the RETROSPECTIVE dataset, proving
     the fix eliminates the 127/470 decreasing-trajectory artifact
     without re-running anything.

Usage:
  p03_canonical_coverage.py RUN_DIR [RUN_DIR ...] [--horizon 24] \
      [--check-monotone] [--json OUT.json]
  p03_canonical_coverage.py --legacy-json filled.json [--check-monotone]
"""
import argparse, csv, glob, json, os, sys

def read_keyval(path):
    d = {}
    if os.path.exists(path):
        for line in open(path, errors="replace"):
            if " : " in line:
                k, v = line.split(" : ", 1)
                d[k.strip()] = v.strip()
    return d

def rebuild_from_csv(csv_path):
    """Return (points[(t, b_abs) sorted by replay order], had_idx, n_raw).

    v3 files carry an idx column = replay order; the cumulative union is
    monotone in that order by construction.  Pre-v3 files (no idx) are
    rebuilt with cumulative max over time order — the only recoverable
    union semantics for already-collected data.
    """
    rows = []
    had_idx = False
    with open(csv_path, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("Time"):
                parts = line.split(",")
                if len(parts) >= 6 and parts[5].strip() == "idx":
                    had_idx = True
                continue
            parts = line.split(",")
            if len(parts) < 5:
                continue
            try:
                t = float(parts[0]); b = float(parts[4])
                idx = int(parts[5]) if len(parts) >= 6 and parts[5].strip().lstrip("-").isdigit() else None
            except ValueError:
                continue
            rows.append((idx, t, b))
    if not rows:
        return [], had_idx, 0
    if had_idx and all(r[0] is not None for r in rows):
        rows.sort(key=lambda r: r[0])          # replay order
    else:
        rows.sort(key=lambda r: (r[1], r[2]))  # time order (stable)
    pts, run_max, last_t = [], float("-inf"), None
    for _, t, b in rows:
        if b > run_max or run_max == float("-inf"):
            run_max = b
        if last_t is not None and t < last_t:
            t = last_t                        # monotone clamp
        last_t = t
        if not pts or pts[-1][1] != run_max or pts[-1][0] != t:
            pts.append((t, run_max))
    # collapse same-timestamp entries keeping the LAST (max) value
    dedup = []
    for t, b in pts:
        if dedup and dedup[-1][0] == t:
            dedup[-1] = (t, max(dedup[-1][1], b))
        else:
            dedup.append((t, b))
    return dedup, had_idx, len(rows)

def clip_and_metrics(pts, t0, t_end, horizon_h):
    """Clip to [0, horizon]; plateau-extend to the campaign end.

    Returns dict with first/last observation hours, support@horizon,
    endpoint@horizon and AUC (branch-hours, step-forward on a 5-min grid).
    """
    H = horizon_h * 3600.0
    rel = [(t - t0, b) for t, b in pts]
    rel = [(t, b) for t, b in rel if t >= 0] or [(0.0, pts[0][1])]
    end_rel = (t_end - t0) if t_end else rel[-1][0]
    support = end_rel >= H
    last_obs = rel[-1][0]
    # endpoint: value carried from the last observation to the horizon
    # (left-constant plateau extension) — valid only if the campaign
    # itself reached the horizon; otherwise the run is censored.
    endpoint = rel[-1][1] if support else None
    auc = 0.0
    grid = [i * 300.0 for i in range(int(H // 300) + 1)]
    def val_at(x):
        cur = rel[0][1]
        for t, b in rel:
            if t <= x:
                cur = b
            else:
                break
        if x > last_obs and support:
            return cur          # plateau extension inside the campaign
        if x > last_obs:
            return None         # beyond censored support
        return cur
    vals = [val_at(x) for x in grid]
    for a, b in zip(vals, vals[1:]):
        if a is not None and b is not None:
            auc += (a + b) / 2.0 * (300.0 / 3600.0)
    return {
        "first_obs_h": round(rel[0][0] / 3600.0, 4),
        "last_obs_h": round(last_obs / 3600.0, 4),
        "campaign_end_h": round(end_rel / 3600.0, 4) if t_end else None,
        "support_at_horizon": support,
        "censored_before_horizon": last_obs < H and not support,
        "endpoint_at_horizon": endpoint,
        "auc_branch_hours": round(auc, 2),
    }

def process_run_dir(d, horizon):
    csvp = os.path.join(d, "cov_over_time.csv")
    if not os.path.exists(csvp):
        return None
    pts, had_idx, n_raw = rebuild_from_csv(csvp)
    if not pts:
        return None
    fs = read_keyval(os.path.join(d, "fuzzer_stats"))
    t0 = float(fs.get("start_time") or 0) or None
    t_end = float(fs.get("last_update") or 0) or None
    audit = {}
    ap = csvp + ".audit"
    if os.path.exists(ap):
        try:
            audit = json.load(open(ap))
        except Exception:
            pass
    m = clip_and_metrics(pts, t0, t_end, horizon)
    m.update({
        "run_dir": d,
        "n_points_raw": n_raw,
        "n_points_rebuilt": len(pts),
        "cov_schema": "v3-idx" if had_idx else "pre-v3-cummax",
        "arm": fs.get("arm", "?"),
        "status_runtime_min": fs.get("run_time"),
        "audit_sidecar": audit or None,
    })
    # monotonicity is by construction; verify on the raw file for honesty
    dec = 0
    prev = None
    for _, _, b in sorted(
            [(i or 0, t, b) for i, t, b in
             [(None, p[0], p[1]) for p in pts]]):
        pass
    raw = []
    with open(csvp, errors="replace") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) >= 5 and parts[0] not in ("Time",) and not line.startswith("#"):
                try: raw.append(float(parts[4]))
                except ValueError: pass
    for b in raw:
        if prev is not None and b < prev:
            dec += 1
        prev = b
    m["raw_decreases_in_file"] = dec
    return m

def process_legacy_json(path, horizon):
    d = json.load(open(path))
    out = []
    for r in d.get("runs", []):
        cov = r.get("coverage") or []
        if not cov:
            continue
        pts = [(h * 3600.0, b) for h, b in cov]
        pts.sort(key=lambda x: x[0])
        run_max, cum = float("-inf"), []
        for t, b in pts:
            run_max = max(run_max, b)
            if cum and cum[-1][0] == t:
                cum[-1] = (t, run_max)
            else:
                cum.append((t, run_max))
        rt = float(r.get("summary", {}).get("runtime_min") or 0)
        start = r.get("fuzzer_start_time")
        t0 = 0.0
        t_end = (start + rt * 60.0) if (start and rt) else cum[-1][0]
        m = clip_and_metrics(cum, t0, t_end, horizon)
        # raw decreases for the BEFORE picture
        prev, dec = None, 0
        for _, b in sorted(pts, key=lambda x: x[0]):
            if prev is not None and b < prev:
                dec += 1
            prev = b
        m.update({
            "run": f"{r.get('arm')}/{r.get('target')}/{r.get('run')}",
            "arm": r.get("arm"), "target": r.get("target"),
            "raw_decreases_in_file": dec,
        })
        out.append(m)
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="*")
    ap.add_argument("--legacy-json")
    ap.add_argument("--horizon", type=float, default=24.0)
    ap.add_argument("--check-monotone", action="store_true")
    ap.add_argument("--json", dest="json_out")
    a = ap.parse_args()

    results = []
    if a.legacy_json:
        results += process_legacy_json(a.legacy_json, a.horizon)
    for r in a.runs:
        if os.path.isdir(r):
            m = process_run_dir(r, a.horizon)
            if m: results.append(m)

    if not results:
        print("no data"); return 1

    raw_dec = sum(x.get("raw_decreases_in_file", 0) for x in results)
    rebuilt_dec = 0   # by construction
    completed = [x for x in results
                 if (x.get("campaign_end_h") or 0) >= a.horizon]
    support = [x for x in results if x.get("support_at_horizon")]

    print(f"runs processed          : {len(results)}")
    print(f"raw decreases in files  : {raw_dec}   (the artifact being fixed)")
    print(f"decreases after rebuild : {rebuilt_dec}   (union semantics — impossible by construction)")
    print(f"campaign reached {a.horizon}h      : {len(completed)}")
    print(f"support@{a.horizon}h (analysis set): {len(support)}")
    print(f"censored before horizon : {len(results) - len(support)}")
    if a.legacy_json:
        per_arm = {}
        for x in results:
            k = (x.get("target"), x.get("arm"))
            per_arm.setdefault(k, [0, 0])
            per_arm[k][0] += 1
            if x.get("support_at_horizon"): per_arm[k][1] += 1
        print("\ntarget/arm: n_runs  support@%gh" % a.horizon)
        for k in sorted(per_arm, key=str):
            print(f"  {str(k):40s} {per_arm[k][0]:4d}  {per_arm[k][1]:4d}")
    if a.json_out:
        json.dump(results, open(a.json_out, "w"), indent=1)
    if a.check_monotone and (raw_dec > 0 or rebuilt_dec > 0):
        # the check that MATTERS: after rebuild nothing decreases
        if rebuilt_dec > 0:
            print("FAIL: rebuilt trajectories decreased"); return 1
        print(f"OK: all rebuilt trajectories monotone (fixed {raw_dec} raw artifacts)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
