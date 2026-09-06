#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evidence_report.py — LoopFuzz evidence-controller offline metrics (paper §十一).

Reads the append-only JSONL event trails produced by afl-fuzz:
    run-config.jsonl        (arm / matched LLM config)
    candidate-events.jsonl  (generation: prompt/reply hashes, tokens)
    admission-events.jsonl  (trials: P/U/R/G_code/G_state, disposition)
    provisional-events.jsonl(two-tier queue lifecycle)
    state-episodes.jsonl    (state-selection episodes + posterior)
    bug-events.jsonl        (crash/hang records)

and prints the paper metrics:
  - disposition distribution + P/U/R/G_code/G_state failure rates
  - provisional conversion / expiration, downstream Precision@H
  - calibration quality from PRE-update predictions (Brier, ECE, bins,
    predicted-vs-observed productivity; no post-update leakage)

Usage:
    ./evidence_report.py OUT_DIR [OUT_DIR2 ...]      # one or more out-* dirs
    ./evidence_report.py --json OUT_DIR              # machine-readable
"""

import json
import os
import sys
from collections import defaultdict

SCHEMA = 2


def load_jsonl(path):
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def fmt_pct(x, total):
    return "100.0%" if total and x == total else ("%5.1f%%" % (100.0 * x / total if total else 0.0))


def report_outdir(outdir, as_json=False):
    r = {
        "outdir": outdir,
        "run_config": load_jsonl(os.path.join(outdir, "run-config.jsonl")),
        "candidates": load_jsonl(os.path.join(outdir, "candidate-events.jsonl")),
        "trials": load_jsonl(os.path.join(outdir, "admission-events.jsonl")),
        "provisional": load_jsonl(os.path.join(outdir, "provisional-events.jsonl")),
        "episodes": load_jsonl(os.path.join(outdir, "state-episodes.jsonl")),
        "bugs": load_jsonl(os.path.join(outdir, "bug-events.jsonl")),
    }
    if as_json:
        return r

    lines = []
    add = lines.append
    add("=" * 72)
    add("Evidence report: %s" % outdir)
    add("=" * 72)

    # ── run_config ──────────────────────────────────────────────
    rc_start = next((x for x in r["run_config"] if x.get("phase") == "start"), None)
    rc_end = next((x for x in reversed(r["run_config"]) if x.get("phase") == "end"), None)
    if rc_start:
        add("arm               : %s" % rc_start.get("arm"))
        add("target / commit   : %s / %s" % (rc_start.get("target"), rc_start.get("fuzzer_commit")))
        add("model             : %s (top_p=%s, max_tokens=%s, call_cap=%s)" % (
            rc_start.get("model"), rc_start.get("top_p"),
            rc_start.get("max_output_tokens"), rc_start.get("call_cap")))
        add("calibration       : gamma=%s epsilon=%s" % (
            rc_start.get("cal_gamma"), rc_start.get("cal_epsilon")))
        add("provisional       : budget=%s ttl_ms=%s max_live=%s" % (
            rc_start.get("provisional_budget"), rc_start.get("provisional_ttl_ms"),
            rc_start.get("provisional_max_live")))
    if rc_end:
        add("termination       : %s (end_time_ms=%s)" % (
            rc_end.get("termination_reason"), rc_end.get("end_time_ms")))

    # ── admission trials ────────────────────────────────────────
    trials = r["trials"]
    if trials:
        n = len(trials)
        cnt = lambda k: sum(1 for t in trials if not t.get(k, True))
        dis = defaultdict(int)
        for t in trials:
            dis[t.get("disposition", "?")] += 1
        add("")
        add("─ admission trials (%d) " % n)
        add("  P/U/R/G_code/G_state fail : %d / %d / %d / %d / %d  (%s / %s / %s / %s / %s)" % (
            cnt("p_pass"), cnt("u_pass"), cnt("r_pass"), cnt("g_code_pass"), cnt("g_state_pass"),
            fmt_pct(cnt("p_pass"), n), fmt_pct(cnt("u_pass"), n), fmt_pct(cnt("r_pass"), n),
            fmt_pct(cnt("g_code_pass"), n), fmt_pct(cnt("g_state_pass"), n)))
        add("  disposition               : durable=%d provisional=%d reject=%d" % (
            dis.get("durable", 0), dis.get("provisional", 0), dis.get("reject", 0)))
        add("  native_promoted / forced  : %d / %d" % (
            sum(1 for t in trials if t.get("native_promoted")),
            sum(1 for t in trials if t.get("forced_promoted"))))
        # D-arm-only: how many direct-force entries never produced any gain?
        zero_gain_forced = sum(1 for t in trials
                               if t.get("forced_promoted") and t.get("bitmap_delta", 0) == 0)
        add("  forced entries w/o bitmap gain (queue-pollution candidates, arm C): %d"
            % zero_gain_forced)

    # ── provisional lifecycle ───────────────────────────────────
    prov = r["provisional"]
    if prov:
        admits = sum(1 for p in prov if p.get("kind") == "admit")
        convs = sum(1 for p in prov if p.get("kind") == "convert")
        expires = defaultdict(int)
        for p in prov:
            if p.get("kind") == "expire":
                expires[p.get("reason", "?")] += 1
        total_exp = sum(expires.values())
        add("")
        add("─ provisional queue (%d events)" % len(prov))
        add("  admitted=%d converted=%d expired=%d (conv rate %s)" % (
            admits, convs, total_exp, fmt_pct(convs, admits)))
        for reason, c in sorted(expires.items(), key=lambda kv: -kv[1]):
            add("    expire reason %-20s : %d" % (reason, c))
        if admits:
            conv_lat = [p.get("conversion_time_ms", 0) for p in prov
                        if p.get("kind") == "convert"]
            if conv_lat:
                conv_lat.sort()
                med = conv_lat[len(conv_lat) // 2]
                add("  median conversion latency : %s ms" % med)
            # Downstream Precision@H: fraction of admitted provisionals that
            # converted within the validation budget (default H=64).
            budget = rc_start.get("provisional_budget", 64) if rc_start else 64
            within = sum(1 for p in prov if p.get("kind") == "convert"
                         and p.get("descendant_execs", 1 << 30) <= budget)
            add("  Precision@%d (provisional→durable within budget): %s" % (
                budget, fmt_pct(within, admits)))

    # ── calibration quality (PRE-update predictions) ────────────
    eps = r["episodes"]
    if eps:
        n = len(eps)
        rewards = sum(1 for e in eps if e.get("reward"))
        add("")
        add("─ state-selection episodes (%d)" % n)
        add("  rewarded episodes : %d (%s)  — reward = new code edge discovered" % (
            rewards, fmt_pct(rewards, n)))

        # Per-state reliability: predicted mean_before vs observed rate.
        per_state = defaultdict(lambda: {"n": 0, "s": 0, "brier": 0.0})
        for e in eps:
            st = str(e.get("selected_state"))
            p = min(1.0, max(0.0, float(e.get("posterior_mean_before", 0.5))))
            y = int(e.get("reward", 0))
            d = per_state[st]
            d["n"] += 1
            d["s"] += y
            d["brier"] += (p - y) ** 2
        # Weighted Brier + ECE over all episodes
        brier = sum(d["brier"] for d in per_state.values()) / max(1, n)
        bins = defaultdict(lambda: [0, 0.0, 0])  # bin -> [count, sum_p, sum_y]
        for e in eps:
            p = min(1.0, max(0.0, float(e.get("posterior_mean_before", 0.5))))
            y = int(e.get("reward", 0))
            b = min(9, int(p * 10))
            bins[b][0] += 1
            bins[b][1] += p
            bins[b][2] += y
        ece = 0.0
        for b, (c, sp, sy) in sorted(bins.items()):
            if c:
                ece += (c / n) * abs(sy / c - sp / c)
        add("  Brier score      : %.4f  (0=perfect, 0.25=coin)" % brier)
        add("  Expected Calibration Error (10 bins): %.4f" % ece)
        add("  reliability bins (predicted → observed, n):")
        for b, (c, sp, sy) in sorted(bins.items()):
            if c:
                add("    [%.1f–%.1f) → %.3f  (n=%d)" % (
                    b / 10.0, (b + 1) / 10.0, sy / c, c))
        # state-edge / code-gain alignment (RQ1)
        se = sum(e.get("new_state_edges", 0) for e in eps)
        ce = sum(e.get("new_code_edges", 0) for e in eps)
        add("  episode gains    : state_edges=%d code_edges=%d (ratio %.2f)" % (
            se, ce, (se / ce) if ce else float("inf") if se else 0.0))
        # Top edge-rich/branch-poor states (misalignment evidence)
        mism = []
        for st, d in per_state.items():
            s_edges = sum(e.get("new_state_edges", 0) for e in eps
                          if str(e.get("selected_state")) == st)
            if s_edges >= 2 and d["n"] >= 5 and d["s"] == 0:
                mism.append((s_edges, d["n"], st))
        mism.sort(reverse=True)
        for s_edges, nep, st in mism[:5]:
            add("    branch-poor state %s: %d state edges, 0 rewards in %d eps" % (
                st, s_edges, nep))

    # ── bugs ────────────────────────────────────────────────────
    bugs = r["bugs"]
    if bugs:
        kinds = defaultdict(int)
        for b in bugs:
            kinds[b.get("kind", "?")] += 1
        add("")
        add("─ bug events: %s" % dict(kinds))

    return "\n".join(lines)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    if not args:
        print(__doc__)
        sys.exit(1)
    outs = []
    for a in args:
        if os.path.isdir(a):
            outs.append(a)
    if as_json:
        print(json.dumps([report_outdir(o, as_json=True) for o in outs], indent=1))
    else:
        for o in outs:
            print(report_outdir(o))
            print()


if __name__ == "__main__":
    main()
