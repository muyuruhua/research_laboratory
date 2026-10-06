#!/usr/bin/env python3
"""P0-4 offline mapping validation: bitmap new-edge events vs source-level
branch growth (gcov), within one run.

The online reward counts AFL bitmap new-EDGE events (hnb==2).  The paper's
primary coverage measure is source-level branches (gcov b_abs from
cov_over_time.csv).  This script aligns both cumulative curves on the
campaign timeline and reports:
  - Pearson/Spearman correlation of increments over aligned windows,
  - the ratio  Δsource-branches / Δbitmap-edges  per window (mapping scale),
  - windows where bitmap grew but source did not (and vice versa) — the
    honesty metric for calling the online signal "code edges", never
    "source-level branches".

Usage: bitmap_source_mapping.py RUN_DIR [--window-min 10]
"""
import argparse, json, os, sys

def load_jsonl(p):
    rows = []
    if os.path.exists(p):
        for line in open(p, errors="replace"):
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows

def read_cov(p):
    """cov_over_time.csv -> [(unix_s, b_abs)] sorted by idx/time."""
    rows = []
    if not os.path.exists(p):
        return rows
    for line in open(p, errors="replace"):
        parts = line.strip().split(",")
        if len(parts) >= 5 and parts[0] not in ("Time",) and not line.startswith("#"):
            try:
                rows.append((float(parts[0]), float(parts[4])))
            except ValueError:
                pass
    rows.sort(key=lambda r: r[0])
    # cumulative max (union)
    out, m = [], float("-inf")
    for t, b in rows:
        m = max(m, b)
        if out and out[-1][0] == t:
            out[-1] = (t, m)
        else:
            out.append((t, m))
    return out

def series_from_episodes(eps, key_new, key_time):
    """cumulative count of per-episode increments -> [(unix_s, cum)]"""
    pts, cum = [], 0
    for e in eps:
        cum += e.get(key_new, 0)
        pts.append((e.get(key_time, 0) / 1000.0, cum))
    return pts

def value_at(pts, x):
    cur = 0.0
    for t, v in pts:
        if t <= x:
            cur = v
        else:
            break
    return cur

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--window-min", type=float, default=10.0)
    a = ap.parse_args()
    d = a.run_dir
    eps = load_jsonl(os.path.join(d, "state-episodes.jsonl"))
    cov = read_cov(os.path.join(d, "cov_over_time.csv"))
    if not eps or not cov:
        print("insufficient data (episodes or cov missing)"); return 1
    t0 = min(cov[0][0], eps[0].get("time_ms", 0) / 1000.0)
    t_end = max(cov[-1][0], eps[-1].get("time_ms", 0) / 1000.0)
    W = a.window_min * 60.0

    bitmap = series_from_episodes(eps, "new_code_edges", "time_ms")
    wins = []
    x = t0 + W
    prev_b, prev_s = 0.0, value_at(cov, t0)
    while x <= t_end + W:
        b = value_at(bitmap, x)
        s = value_at(cov, x)
        wins.append((b - prev_b, s - prev_s))
        prev_b, prev_s = b, s
        x += W

    db = [w[0] for w in wins]; ds = [w[1] for w in wins]
    n = len(wins)
    mean = lambda v: sum(v) / len(v) if v else 0
    def pearson(x, y):
        if n < 2: return None
        mx, my = mean(x), mean(y)
        num = sum((a - mx) * (b - my) for a, b in zip(x, y))
        den = (sum((a - mx) ** 2 for a in x) * sum((b - my) ** 2 for b in y)) ** 0.5
        return num / den if den else None
    both = sum(1 for b, s in wins if b > 0 and s > 0)
    b_only = sum(1 for b, s in wins if b > 0 and s == 0)
    s_only = sum(1 for b, s in wins if b == 0 and s > 0)
    tb, ts = sum(db), sum(ds)
    print(f"run: {d}")
    print(f"windows ({a.window_min:g} min): {n}   campaign "
          f"[{0:.1f}, {(t_end-t0)/3600:.1f}]h")
    print(f"total bitmap new-edge events : {int(tb)}")
    print(f"total source-branch growth   : {int(ts)}")
    if tb:
        print(f"mapping ratio Δsource/Δbitmap : {ts/tb:.2f} "
              f"(source branches per bitmap edge)")
    r = pearson(db, ds)
    print(f"increment correlation (pearson): {'n/a' if r is None else f'{r:.3f}'}")
    print(f"windows: both grew {both} | bitmap-only {b_only} | source-only {s_only}")
    # Verdict is correlation-driven: bitmap-only windows are EXPECTED (the
    # online reward fires instantly; gcov b_abs is sampled every `step`
    # testcases) and are reported above as the honesty caveat.  The claim
    # to police is the reverse direction (calling bitmap edges "source
    # branches"); the printed ratio is the honest conversion factor.
    print("verdict:", f"consistent proxy (r={'n/a' if r is None else f'{r:.2f}'}); "
          f"report online signal as bitmap/code edges with ratio "
          f"{(ts/tb if tb else 0):.1f} source-branches/edge, never as source-level branches"
          if (r or 0) > 0.5 else
          "WEAK mapping — do not treat bitmap-edge reward as code progress")
    return 0

if __name__ == "__main__":
    sys.exit(main())
