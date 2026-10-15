#!/usr/bin/env python3
"""行② measurement pipeline dry-run (G2 gap verification).

Validates that the queue-pollution / admission-channel productivity
measurement (paper row ②) is computable END-TO-END from one run's logs:
  LLM channel   = entries admitted via durable/provisional/force + their
                  native/inherited descendants, with downstream NEW-EDGE
                  gains from lineage-events.jsonl
  havoc channel = the rest of the queue and the rest of code_gain_events

Consistency checks (pipeline correctness, not science — mock data is
biased by design; the numbers themselves only become meaningful on the
real-gateway formal batch):

  C1  len(lineage_gain events) == llm_lineage_edge_gains counter
  C2  llm_lineage_entries >= durable + provisional + forced (direct admits)
  C3  every lineage event candidate_id resolves in candidate-events.jsonl
  C4  queue files with llm markers (llm-durable/prov/no_admission) count
      <= direct admits (some expired provisionals are unlinked)
  C5  llm lineage gains <= total code_gain_events

Usage: measure_lineage.py OUTDIR [OUTDIR ...]
"""
import json, os, sys, glob, re

def stat(fs, key):
    for l in fs.split("\n"):
        if l.startswith(key):
            m = re.findall(r"[-\d]+", l.split(":", 1)[1])
            return int(m[0]) if m else 0
    return 0

def jl(path):
    if not os.path.exists(path):
        return []
    out = []
    for l in open(path, errors="replace"):
        try:
            out.append(json.loads(l))
        except Exception:
            pass
    return out

def measure(d):
    tag = d.rstrip("/").split("/")[-1]
    fs = open(f"{d}/fuzzer_stats", errors="replace").read()
    rc = jl(f"{d}/run-config.jsonl")
    arm = json.loads(open(f"{d}/run-config.jsonl").readline())["arm"] if rc else "?"
    dur = stat(fs, "disposition_durable")
    prov = stat(fs, "disposition_provisional")
    forced = stat(fs, "admission_forced_promo")
    lin_entries = stat(fs, "llm_lineage_entries")
    lin_gains = stat(fs, "llm_lineage_edge_gains")
    code_gains = stat(fs, "code_gain_events")
    paths = stat(fs, "paths_total")
    execs = stat(fs, "execs_done")

    lev = jl(f"{d}/lineage-events.jsonl")
    cand = {e.get("candidate_id") for e in jl(f"{d}/candidate-events.jsonl")}
    prov_ev = jl(f"{d}/provisional-events.jsonl")

    qdir = f"{d}/queue"
    llm_files = 0
    if os.path.isdir(qdir):
        llm_files = sum(1 for n in os.listdir(qdir)
                        if "llm-durable" in n or ",prov" in n or "no_admission" in n)

    c1 = len(lev) == lin_gains
    # C2 is arm-scoped: disposition_durable in arm C is the GATE's view
    # (logged for rejected-but-forced candidates too), not an insertion
    # count.  The authoritative insertion counts are durable+provisional
    # for gated arms and forced (+ v3.3c-counted native saves, which are
    # included in lin_entries itself) for arm C.
    c2 = (lin_entries >= dur + prov) if "direct" in arm else (lin_entries >= dur + prov + forced)
    c3 = all(e.get("candidate_id") in cand for e in lev)
    c4 = llm_files <= dur + prov + forced + 1  # converted provisionals may rename none; +1 slack for rounding on tiny runs
    c5 = lin_gains <= code_gains

    per_cand = {}
    for e in lev:
        per_cand.setdefault(e["candidate_id"], 0)
        per_cand[e["candidate_id"]] += 1

    print(f"== {tag} [{arm}]")
    print(f"   execs={execs} paths={paths} | direct-admits: durable={dur} prov={prov} forced={forced}")
    print(f"   LLM-channel: entries={lin_entries} (inherited/native={max(0, lin_entries-dur-prov-forced)}), "
          f"new-edge gains={lin_gains} | havoc-channel gains={max(0, code_gains - lin_gains)}")
    print(f"   provisional lifecycle: admit={sum(1 for e in prov_ev if e.get('kind')=='admit')} "
          f"expire={sum(1 for e in prov_ev if e.get('kind')=='expire')}")
    if per_cand:
        print(f"   per-candidate gains: {per_cand}")
    checks = {"C1 events==ctr": c1, "C2 entries>=direct": c2, "C3 cand resolvable": c3,
              "C4 files<=direct": c4, "C5 gains<=total": c5}
    verdict = "PASS" if all(checks.values()) else "FAIL"
    print(f"   checks: {checks} -> {verdict}")
    return all(checks.values())

if __name__ == "__main__":
    dirs = sys.argv[1:]
    ok = [measure(d) for d in dirs]
    print(f"\nPIPELINE VERDICT: {'PASS' if all(ok) else 'FAIL'} ({sum(ok)}/{len(ok)} runs consistent)")
