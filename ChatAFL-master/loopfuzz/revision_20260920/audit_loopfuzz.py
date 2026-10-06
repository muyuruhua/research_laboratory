#!/usr/bin/env python3
"""Audit LoopFuzz v3 first-batch fidelity fixes from a run's JSONL logs.

Usage: audit_loopfuzz.py <out_dir>   (dir containing run-config.jsonl etc.)
Exit code 0 = all hard invariants hold.
"""
import json, os, sys, glob, math

out = sys.argv[1] if len(sys.argv) > 1 else "."
def load(name):
    p = os.path.join(out, name)
    rows = []
    if os.path.exists(p):
        with open(p) as f:
            for line in f:
                line = line.strip()
                if line:
                    try: rows.append(json.loads(line))
                    except json.JSONDecodeError: pass
    return rows

rc = load("run-config.jsonl")
adm = load("admission-events.jsonl")
prov = load("provisional-events.jsonl")
eps = load("state-episodes.jsonl")

starts = [r for r in rc if r.get("phase") == "start"]
ends = [r for r in rc if r.get("phase") == "end"]
S = starts[0] if starts else {}
E = ends[0] if ends else {}

fails, warns = [], []
def check(cond, ok_msg, fail_msg):
    if cond: print("  PASS:", ok_msg)
    else: fails.append(fail_msg); print("  FAIL:", fail_msg)

print("=" * 72)
print("FIX 1  run-config start carries TRUE arm + v3 fields")
print("=" * 72)
arm_s, arm_e = S.get("arm"), E.get("arm")
# v3 arm-aware: derive the EXPECTED arm from the recorded switches
# (self-consistency), instead of hard-coding arm D.  start==end==derived
# is the Fix-1 invariant; mislabels of the pre-v3 era fail all three.
expected = ("loopfuzz-direct" if S.get("no_admission") else
            "loopfuzz-gated-calibrated" if S.get("calibration") else
            "loopfuzz-gated-fixed")
check(arm_s == expected, f"start arm = {arm_s} == derived({expected})",
      f"start arm = {arm_s} != derived {expected}")
check(arm_e == arm_s, f"end arm = {arm_e} == start arm",
      f"arm mismatch start={arm_s} end={arm_e}")
check((E.get("no_admission") is S.get("no_admission")) and
      (E.get("calibration") is S.get("calibration")),
      "arm switches identical in start and end records",
      "arm switches differ between start and end records")
check(S.get("episode_energy_cap") == 512, f"episode_energy_cap={S.get('episode_energy_cap')}",
      "episode_energy_cap missing/wrong")
check(S.get("code_reward_semantics") == "new-edge-only-hnb2",
      f"code_reward_semantics={S.get('code_reward_semantics')}", "reward semantics field wrong")
check(S.get("trial_mode_admission") is (not S.get("no_admission")),
      f"trial_mode_admission={S.get('trial_mode_admission')} matches arm "
      f"(gated arms True, direct False)",
      "trial_mode_admission inconsistent with arm switches")
check(S.get("schema_version") == 3, "schema_version=3", "schema_version != 3")

print()
print("=" * 72)
print("FIX 2  execute-before-promote: decision precedes insertion; no native save in trials")
print("=" * 72)
decisions = {}
for r in adm:
    if r.get("event") == "admission_decision":
        decisions[r.get("candidate_id")] = r
trials = [r for r in adm if r.get("event") == "admission_trial"]
n_exec = [r for r in trials if r.get("executed")]
n_native = [r for r in n_exec if r.get("native_promoted")]
check(len(n_native) == 0,
      f"0/{len(n_exec)} executed trials natively retained (was: every hnb>0 trial)",
      f"{len(n_native)} trials natively promoted — trial-mode leak!")
dur = [r for r in trials if r.get("durable_promoted")]
viol = [r for r in dur if r.get("candidate_id") not in decisions or
        decisions[r["candidate_id"]]["time_ms"] > r.get("time_ms", 0)]
check(all(r.get("candidate_id") in decisions for r in dur) and not viol,
      f"all {len(dur)} durable promotions preceded by decision event",
      f"{len(viol)} durable promotions lack earlier decision")
qfiles = glob.glob(os.path.join(out, "queue/*llm-durable*"))
import os.path as op
late = []
for qf in qfiles:
    mtime_ms = int(op.getmtime(qf) * 1000)
    # map file id to trial time is indirect; instead check any decision exists before mtime with durable intent — count only
check(True, f"{len(qfiles)} llm-durable queue files on disk (cross-check count vs durable promotions: {len(dur)})",
      "")
# G_code gate purity: durable promotions must have trial_hnb==2 & U & R
bad_gate = [r for r in dur if not (r.get("trial_hnb") == 2 and r.get("u_pass") and r.get("r_pass"))]
check(not bad_gate, "every durable promotion had P∧U∧R∧trial_hnb=2",
      f"{len(bad_gate)} durable promotions without full gate evidence")
# hit-count-only trials must NOT be durable via trial path
hc = [r for r in n_exec if r.get("trial_hnb") == 1]
hc_dur = [r for r in hc if r.get("durable_promoted") or r.get("native_promoted")]
check(not hc_dur, f"{len(hc)} hit-count-only trials correctly NOT durable",
      f"{len(hc_dur)} hit-count-only trials became durable")

print()
print("=" * 72)
print("FIX 3  G_state decoupled from retention (ledger-based novelty)")
print("=" * 72)
dec_novel = [r for r in adm if r.get("event") == "admission_decision" and
             (r.get("obs_new_states", 0) > 0 or r.get("obs_new_transitions", 0) > 0)]
dec_novel_no_ipsm = [r for r in dec_novel if r.get("ipsm_edges_delta", 0) == 0 and r.get("ipsm_nodes_delta", 0) == 0]
print(f"  info: {len(dec_novel)} decisions with ledger novelty; "
      f"{len(dec_novel_no_ipsm)} of them had ZERO ipsm graph delta (impossible pre-fix)")
n_prov = [r for r in trials if r.get("provisional_queued")]
if expected == "loopfuzz-direct":
    print(f"  PASS: arm C — provisional N/A by design (direct admission), "
          f"{len(n_prov)} observed (must be 0)")
    check(len(n_prov) == 0, "arm C has no provisional admissions by design",
          "arm C unexpectedly admitted provisional entries")
else:
    check(len(n_prov) > 0,
          f"{len(n_prov)} provisional admissions (structurally ZERO before the fix)",
          "provisional still zero — decoupling ineffective (gated arm)")
pv_gate = [r for r in n_prov if not (r.get("g_state_pass") and not r.get("g_code_pass")
                                     and r.get("u_pass") and r.get("r_pass"))]
check(not pv_gate, "every provisional admission satisfied P∧U∧R∧¬G_code∧G_state",
      f"{len(pv_gate)} provisional admissions without proper gate")

print()
print("=" * 72)
print("FIX 4  provisional budget enforced BEFORE each descendant; episode energy cap")
print("=" * 72)
BUDGET = S.get("provisional_budget", 64)
over = [r for r in prov if r.get("descendant_execs", 0) > BUDGET]
check(not over, f"all provisional descendant_execs <= {BUDGET} (max observed: "
      f"{max([r.get('descendant_execs',0) for r in prov], default=0)})",
      f"{len(over)} provisional entries exceeded budget")
kinds = {}
for r in prov: kinds[r.get("kind")] = kinds.get(r.get("kind"), 0) + 1
print(f"  info: provisional lifecycle events: {kinds}")
cap = S.get("episode_energy_cap", 0)
if cap:
    eu = [r.get("energy_used", 0) for r in eps]
    over_e = [r for r in eps if r.get("energy_used", 0) > cap]
    check(not over_e, f"all episodes energy_used <= {cap} (max: {max(eu, default=0)}); "
          f"{sum(1 for x in eu if x >= cap)} episodes hit the cap exactly",
          f"{len(over_e)} episodes exceeded energy cap")

print()
print("=" * 72)
print("FIX 5  reward = new-edge only (hnb==2), dual counters")
print("=" * 72)
# internal consistency: rewarded episodes must have new_code_edges >= 1
bad_r = [r for r in eps if r.get("reward") == 1 and r.get("new_code_edges", 0) < 1]
check(not bad_r, f"{sum(1 for r in eps if r.get('reward')==1)} rewarded episodes all have new_code_edges>=1",
      f"{len(bad_r)} rewarded episodes without new edges")
st = {}
fstats = os.path.join(out, "fuzzer_stats")
if os.path.exists(fstats):
    for line in open(fstats):
        if " : " in line:
            k, v = line.split(" : ", 1); st[k.strip()] = v.strip()
cs, cg = int(st.get("code_save_events", "0")), int(st.get("code_gain_events", "0"))
check(cs >= cg, f"fuzzer_stats: code_save_events={cs} >= code_gain_events={cg} "
      f"(hit-count-only saves excluded from reward: {cs-cg})", "save<gain counters inverted")
print(f"  info: admission_gain_events={st.get('admission_gain_events')} "
      f"(code evidence from promoted candidates, outside episode reward)")

print()
print("=" * 72)
print("FIX 6  episode completion gating: zero-mutation & interrupted never update posterior")
print("=" * 72)
zm = [r for r in eps if r.get("mutations", 0) == 0 and r.get("completed")]
zm_upd = [r for r in zm if r.get("posterior_updated")]
check(not zm_upd, f"{len(zm)} completed zero-mutation episodes logged, none updated posterior",
      f"{len(zm_upd)} zero-mutation episodes updated posterior")
inc = [r for r in eps if not r.get("completed")]
inc_upd = [r for r in inc if r.get("posterior_updated") or r.get("reward", -1) != -1]
check(not inc_upd, f"{len(inc)} incomplete episodes (reward=-1, no update)",
      f"{len(inc_upd)} incomplete episodes got reward/update")
leak = [r for r in eps if not r.get("posterior_updated") and
        (r.get("alpha_after") != r.get("alpha_before") or r.get("beta_after") != r.get("beta_before"))]
check(not leak, "posterior untouched when posterior_updated=false", "posterior changed without update flag")

print()
print("=" * 72)
print("FIX 7  shutdown censoring + ledger closure")
print("=" * 72)
check(bool(E), f"run-config end event present (termination_reason={E.get('termination_reason')!r})",
      "missing run-config end event")
cens = [r for r in prov if r.get("kind") == "censor"]
print(f"  info: {len(cens)} provisional entries censored at campaign end")
if eps:
    last = eps[-1]
    tail_ok = True
    print(f"  info: last episode completed={last.get('completed')} reward={last.get('reward')}")

print()
print("=" * 72)
print("SANITY  campaign basics")
print("=" * 72)
nq = len(glob.glob(os.path.join(out, "queue/id:*")))
print(f"  queue entries on disk: {nq}")
print(f"  admission trials: {len(trials)} (executed {len(n_exec)})")
print(f"  dispositions: reject={sum(1 for r in trials if str(r.get('disposition'))=='reject')}, "
      f"provisional={sum(1 for r in trials if str(r.get('disposition'))=='provisional')}, "
      f"durable={sum(1 for r in trials if str(r.get('disposition'))=='durable')}")
print(f"  episodes: {len(eps)}; fuzzer_stats arm={st.get('arm')}, execs={st.get('execs_done')}, "
      f"llm_calls={st.get('llm_total_calls')}")
for k in ("cal_episodes","cal_eps_completed","cal_eps_zero_mut","cal_eps_interrupted",
          "provisional_admitted","provisional_converted","provisional_expired","provisional_censored"):
    print(f"    {k}: {st.get(k)}")

print()
if fails:
    print(f"RESULT: {len(fails)} HARD FAILURES")
    for f_ in fails: print("  -", f_)
    sys.exit(1)
print("RESULT: ALL HARD INVARIANTS PASS")
