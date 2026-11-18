#!/usr/bin/env python3
"""Round-10 verifier cases (codex round-10): positives + negatives."""
import json, shutil, subprocess, sys, tarfile, tempfile
from pathlib import Path
BASE = Path("/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master")
SRC = BASE / "ablation/results-proftpd_ablation_pvstop1_20261115T181353/out-proftpd-loopfuzz_1.tar.gz"
VER = BASE / "ablation/q123_repair_smoke_20261114/verify_q1_repeat.py"

def rebuild(mutate_stats=None, drop=None, duplicate=None, mutate_flow=None, mutate_config=None):
    tmp = Path(tempfile.mkdtemp()); work = tmp / "w"
    with tarfile.open(SRC) as tf: tf.extractall(work)
    root = next(work.iterdir())
    stats_path = next(root.rglob("fuzzer_stats"))
    lines = stats_path.read_text().splitlines()
    def set_stat(key, value):
        out, seen = [], False
        for line in lines:
            if line.split(":", 1)[0].strip() == key:
                out.append(f"{key:<24}: {value}"); seen = True
            else: out.append(line)
        if not seen: out.append(f"{key:<24}: {value}")
        return out
    if mutate_stats:
        for key, value in mutate_stats.items():
            lines = [l for l in lines if l.split(":", 1)[0].strip() != key] if value is None else set_stat(key, value)
        stats_path.write_text("\n".join(lines) + "\n")
    if drop:
        t = next(root.rglob(drop), None)
        if t: t.unlink()
    if duplicate:
        s = next(root.rglob(duplicate)); d = root / "out-x"; d.mkdir(exist_ok=True)
        shutil.copy(s, d / duplicate)
    if mutate_flow:
        fp = next(root.rglob("q1-budget-flow.jsonl"), None)
        if fp:
            rows = [json.loads(l) for l in fp.read_text().splitlines() if l.strip()]
            rows[-1].update(mutate_flow)
            fp.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    if mutate_config:
        cp = next(root.rglob("run-config.jsonl"))
        rows = [json.loads(l) for l in cp.read_text().splitlines() if l.strip()]
        extra = dict(mutate_config)
        if mutate_stats and mutate_stats.get("campaign_call_budget") is not None:
            extra["campaign_call_budget"] = mutate_stats["campaign_call_budget"]
        for row in rows:
            for k, v in extra.items(): row[k] = v
        cp.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    tgz = tmp / "case.tar.gz"
    subprocess.run(["tar","czf",str(tgz),"-C",str(work),"."],check=True)
    return tgz, tmp

def run_case(name, expect_rc, expect_class=None, expect_error=None, **build):
    tgz, tmp = rebuild(**build)
    try:
        r = subprocess.run(["python3",str(VER),str(tgz)],capture_output=True,text=True,timeout=120)
        lines=[l for l in r.stdout.splitlines() if l.strip()]
        ok=(r.returncode==expect_rc) and len(lines)==1
        detail=f"rc={r.returncode} lines={len(lines)}"
        if ok and expect_rc==0:
            data=json.loads(lines[0])
            if expect_class is not None:
                ok=data.get("classification")==expect_class; detail+=f" class={data.get('classification')}"
            if build.get("mutate_flow") and "effective_cap" in data:
                detail+=f" eff_cap={data['effective_cap']}"
                if build.get("mutate_stats", {}).get("q1_idle_quota") == 5000: ok=ok and data["effective_cap"]==0
        elif ok and expect_error:
            ok=expect_error in lines[0]; detail+=f" err~{expect_error!r}"
        print(f"{name}: {detail} -> {'PASS' if ok else 'FAIL'}")
        return ok
    finally:
        shutil.rmtree(tmp,ignore_errors=True)

BS={"campaign_call_budget":5000,"campaign_charged_calls":5000,"campaign_budget_exhausted":1}
results=[
 run_case("pos-healthy-uncapped",0,"unknown"),
 run_case("pos-budget-exhausted",0,"budget-exhausted",mutate_stats=BS,mutate_config={"termination_reason":"campaign-call-budget"},mutate_flow={"effective_cap":5000}),
 run_case("ambiguous-signal-or-timeout",0,"unknown",mutate_stats={**BS,"campaign_charged_calls":3000,"campaign_budget_exhausted":0},mutate_config={"termination_reason":"signal-or-timeout"},mutate_flow={"effective_cap":5000}),
 run_case("pos-unknown-reason",0,"unknown",mutate_stats={**BS,"campaign_charged_calls":3000,"campaign_budget_exhausted":0},mutate_config={"termination_reason":None}),
 run_case("pos-zero-effective-cap",0,"budget-exhausted",mutate_stats={**BS,"campaign_charged_calls":0,"q1_idle_quota":5000},mutate_flow={"effective_cap":5000},mutate_config={"termination_reason":"campaign-call-budget"}),
 run_case("neg-charged-vs-execs",0,"unknown",mutate_stats={**BS,"campaign_charged_calls":3,"campaign_budget_exhausted":1,"execs_done":6000},mutate_flow={"effective_cap":5000},mutate_config={"campaign_call_budget":5000}),
 run_case("neg-budget-reason-inconsistent",0,"unknown",mutate_stats={**BS,"campaign_charged_calls":3},mutate_config={"termination_reason":"campaign-call-budget"},mutate_flow={"effective_cap":5000}),
 run_case("neg-invalid-effective-cap",3,expect_error="invalid effective_cap",mutate_flow={"effective_cap":"5000"}),
 run_case("neg-missing-stats",3,expect_error="fuzzer_stats",drop="fuzzer_stats"),
 run_case("neg-duplicate-stats",3,expect_error="fuzzer_stats",duplicate="fuzzer_stats"),
 run_case("neg-budget-mismatch",3,expect_error="budget disagreement",mutate_stats={**BS,"campaign_call_budget":4999}),
 run_case("neg-missing-counter",3,expect_error="required campaign counter",mutate_stats={**BS,"campaign_charged_calls":None}),
]
sys.exit(0 if all(results) else 1)
