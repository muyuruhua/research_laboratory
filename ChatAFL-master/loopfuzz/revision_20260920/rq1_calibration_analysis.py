#!/usr/bin/env python3
"""P0-5 + P0-4 analysis: RQ1 linked episode-level analysis and
calibration baselines (v1, 2026-10-05).

Implements the expert-required redesign directly on execution-level
linked data (state-episodes.jsonl, schema v3) instead of A-vs-D
endpoint differences:

  RQ1 (state/code alignment, within-run):
    - P(new code edge | state-novel episode) vs P(new code edge |
      state-non-novel episode), over completed episodes only;
    - same contrast split by campaign phase (first/middle/last third);
    - lagged variant: does state novelty at episode t predict code gain
      in the NEXT k episodes (t+1..t+3)?
    - motivating-case signatures (overestimation / underestimation /
      saturation) evaluated from the same table.

  Calibration baselines (Table 12 additions required by P0-4):
    - BS of the logged pre-update posterior mean (the model);
    - BS of a prequential base-rate predictor (past same-run rewards,
      Beta(1,1) smoothing);
    - BS of an energy-only predictor (prequential reward rate of the
      energy tercile) — the confound check;
    calibration is only "effective" if the model beats BOTH baselines.

Usage:
  rq1_calibration_analysis.py RUN_DIR [RUN_DIR ...] [--lag 3] [--json OUT]
"""
import argparse, json, os, sys
from collections import defaultdict

def load_jsonl(path):
    rows = []
    if os.path.exists(path):
        for line in open(path, errors="replace"):
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows

def brier(preds, outs):
    n = len(preds)
    if n == 0:
        return None
    return sum((p - o) ** 2 for p, o in zip(preds, outs)) / n

def analyse_run(run_dir, lag):
    eps = load_jsonl(os.path.join(run_dir, "state-episodes.jsonl"))
    if not eps:
        return None
    # v3 gating: only completed episodes with >=1 mutation define the
    # analysis set; incomplete ones (reward=-1) are excluded.
    comp = [e for e in eps if e.get("completed") and e.get("mutations", 0) > 0]
    out = {"run_dir": run_dir, "episodes_total": len(eps),
           "episodes_completed": len(comp),
           "episodes_excluded": len(eps) - len(comp)}

    # ---- RQ1: contemporaneous contrast -----------------------------
    def block(rows):
        n_novel = [r for r in rows if r.get("new_state_edges", 0) > 0]
        n_plain = [r for r in rows if r.get("new_state_edges", 0) == 0]
        g = lambda rs: (sum(1 for r in rs if r.get("new_code_edges", 0) > 0) / len(rs)) if rs else None
        return {"n_novel": len(n_novel), "n_plain": len(n_plain),
                "p_code_given_novel": g(n_novel),
                "p_code_given_plain": g(n_plain)}
    out["rq1_overall"] = block(comp)

    # phase split (thirds of the completed-episode sequence)
    k = len(comp) // 3 or 1
    out["rq1_by_phase"] = {
        "early": block(comp[:k]),
        "middle": block(comp[k:2 * k]),
        "late": block(comp[2 * k:]),
    }

    # lagged: novelty at t -> code gain within the next `lag` episodes
    novel_hit, novel_n, plain_hit, plain_n = 0, 0, 0, 0
    for i, e in enumerate(comp):
        window = comp[i + 1:i + 1 + lag]
        if not window:
            continue
        gain = any(w.get("new_code_edges", 0) > 0 for w in window)
        if e.get("new_state_edges", 0) > 0:
            novel_n += 1; novel_hit += gain
        else:
            plain_n += 1; plain_hit += gain
    out["rq1_lagged"] = {
        "lag": lag,
        "p_code_next_given_novel": (novel_hit / novel_n) if novel_n else None,
        "n_novel": novel_n,
        "p_code_next_given_plain": (plain_hit / plain_n) if plain_n else None,
        "n_plain": plain_n,
    }

    # motivating-case signatures (within-run)
    o = out["rq1_overall"]
    pn, pp = o["p_code_given_novel"], o["p_code_given_plain"]
    case = None
    if pn is not None and pp is not None and o["n_novel"] >= 3:
        if pn < pp - 0.05:
            case = "overestimation (state-novel episodes LESS code-productive)"
        elif pn > pp + 0.05:
            case = "state-novel episodes more productive (alignment holds)"
        else:
            case = "no clear divergence"
    out["rq1_case_signature"] = case

    # ---- Calibration baselines (P0-4 / Table 12) -------------------
    upd = [e for e in comp if e.get("posterior_updated")]
    model_preds, base_preds, energy_preds, outs_ = [], [], [], []
    past_rewards = []                       # prequential base rate
    energy_hist = defaultdict(lambda: [0, 0])  # tercile -> [hits, n]
    energies = sorted(e.get("energy_used", 0) for e in upd)
    def tercile(v):
        if len(energies) < 3 or v is None:
            return 0
        return 0 if v <= energies[len(energies)//3 - 1] else (
               1 if v <= energies[2*len(energies)//3 - 1] else 2)
    for e in upd:
        p = e.get("posterior_mean_before")
        r = 1 if e.get("reward", 0) > 0 else 0
        if p is None:
            continue
        br = (sum(past_rewards) + 1) / (len(past_rewards) + 2)  # Beta(1,1)
        tb = tercile(e.get("energy_used", 0))
        h, n = energy_hist[tb]
        eb = (h + 1) / (n + 2)
        model_preds.append(p); outs_.append(r)
        base_preds.append(br); energy_preds.append(eb)
        past_rewards.append(r)
        energy_hist[tb][0] += r; energy_hist[tb][1] += 1
    bs_model = brier(model_preds, outs_)
    bs_base = brier(base_preds, outs_)
    bs_energy = brier(energy_preds, outs_)
    out["calibration"] = {
        "n_updated_episodes": len(upd),
        "reward_rate": (sum(outs_) / len(outs_)) if outs_ else None,
        "bs_model": round(bs_model, 4) if bs_model is not None else None,
        "bs_prequential_base_rate": round(bs_base, 4) if bs_base is not None else None,
        "bs_energy_only": round(bs_energy, 4) if bs_energy is not None else None,
        "model_beats_baselines":
            None if bs_model is None or bs_base is None else
            (bs_model < bs_base and (bs_energy is None or bs_model < bs_energy)),
    }
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="+")
    ap.add_argument("--lag", type=int, default=3)
    ap.add_argument("--json", dest="json_out")
    a = ap.parse_args()
    results = [r for r in (analyse_run(d, a.lag) for d in a.runs) if r]
    for r in results:
        print("=" * 64)
        print(f"run: {r['run_dir']}   episodes {r['episodes_completed']}/"
              f"{r['episodes_total']} completed ({r['episodes_excluded']} excluded)")
        o = r["rq1_overall"]
        fmt = lambda v: "n/a" if v is None else f"{v:.3f}"
        print(f"  RQ1  P(code|state-novel)={fmt(o['p_code_given_novel'])} (n={o['n_novel']})  "
              f"P(code|plain)={fmt(o['p_code_given_plain'])} (n={o['n_plain']})")
        for ph in ("early", "middle", "late"):
            b = r["rq1_by_phase"][ph]
            print(f"       {ph:6s} novel:{fmt(b['p_code_given_novel'])}(n={b['n_novel']}) "
                  f"plain:{fmt(b['p_code_given_plain'])}(n={b['n_plain']})")
        L = r["rq1_lagged"]
        print(f"       lagged(+{L['lag']}): novel->{fmt(L['p_code_next_given_novel'])}(n={L['n_novel']}) "
              f"plain->{fmt(L['p_code_next_given_plain'])}(n={L['n_plain']})")
        print(f"  case: {r['rq1_case_signature']}")
        c = r["calibration"]
        print(f"  CAL  n={c['n_updated_episodes']} reward_rate={fmt(c['reward_rate'])}")
        print(f"       BS model={c['bs_model']}  base-rate={c['bs_prequential_base_rate']}  "
              f"energy-only={c['bs_energy_only']}")
        verdict = c["model_beats_baselines"]
        print(f"       model beats baselines: "
              f"{'YES' if verdict else ('NO — drop the effectiveness claim' if verdict is False else 'n/a (insufficient episodes)')}")
    if a.json_out:
        json.dump(results, open(a.json_out, "w"), indent=1)
    return 0

if __name__ == "__main__":
    sys.exit(main())
