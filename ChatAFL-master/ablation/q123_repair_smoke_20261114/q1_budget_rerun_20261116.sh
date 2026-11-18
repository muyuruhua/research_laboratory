#!/bin/bash
# Q1 supplementary rerun: explicit four-arm audit, launcher-bound manifest.
#  - batch identity: unique batch ID + per-arm dir manifest captured after
#    each launch; audits read the manifest only (no re-glob, no hardcoded date,
#    master-era dirs can never be selected).
#  - budget acceptance: per-repeat verification that the container received
#    and recorded campaign_call_budget=5000; actual calls, effective cap and
#    stop reason are read from each archive and reported. 5000 is a CAP: runs
#    ambiguous signal-or-timeout stops remain unknown; q1b's parked quota
#    lowers its effective cap and is reported separately.
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
WAITER_ID="q1wait-$(date +%Y%m%dT%H%M%S)-$$"
LOG="$OUT/q1_budget_wait_${WAITER_ID}.log"
Q="q1a1,q1b1,q1c1,q1d1"
: > "$LOG"
log(){ echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOG"; }

CHECK=$(ABLATION_DRY_RUN=1 ABLATION_CALL_BUDGET_OVERRIDE=5000 bash "$BASE/run_ablation.sh" proftpd 1 15 --groups q1a1 2>&1 | grep "SHARED_OVERRIDES" | grep -o "call_budget=5000")
if [ "$CHECK" != "call_budget=5000" ]; then
  log "PRE-LAUNCH CHECK FAILED"; exit 2
fi
log "pre-launch check ok: call_budget=5000 in shared overrides (dry-run)"

START_TS=$(date +%Y%m%dT%H%M%S)
BATCH_ID="q1budget-${START_TS}-$$"
LOG="$OUT/q1_budget_rerun_${BATCH_ID}.log"
MANIFEST="$OUT/q1_rerun_manifest_${BATCH_ID}.jsonl"
: > "$MANIFEST"
log "batch=$BATCH_ID window starts START_TS=$START_TS; targets wait independently"

wait_target_idle(){
  local t=$1
  while [ "$(docker ps --format '{{.Names}}' | grep -c "^${t}-loopfuzz-run" || true)" -gt 0 ]; do
    log "WAIT[$t] primary target containers still running"
    sleep 30
  done
}

verify_repeat(){ # archive -> one classified JSON line per repeat (exit 3 on structural error)
  python3 "$OUT/verify_q1_repeat.py" "$1"
}

launch_q1(){ # target port tag — pins the dirs the launcher itself printed
  local t=$1 p=$2 tag=$3 rc arm d launchlog count
  launchlog="$OUT/q1_launch_${BATCH_ID}_${t}.log"
  log "LAUNCH[$tag] $t arms=$Q cap=5000 (launcher output captured)"
  ( cd "$BASE" && env ABLATION_THRESHOLD_OVERRIDE=1 ABLATION_WARMUP_MAX_OVERRIDE=8 \
      ABLATION_EPISODE_ENERGY_OVERRIDE=32 ABLATION_CAL_REWARD_WINDOW_OVERRIDE=16 \
      ABLATION_CALL_BUDGET_OVERRIDE=5000 \
      ABLATION_MEM_PER_FUZZER=2 ABLATION_DOCKER_MEM_CAP=2g ABLATION_PARALLEL=1 ABLATION_SHUFFLE=1 \
      CHATAFL_MOCK_LLM=1 MOCK_PORT=$p MOCK_LATENCY=1 MOCK_ERROR_RATE=1.5 MOCK_SEED=20261102 \
      KEY=loopfuzz-mock-key SKIPCOUNT=40 \
      ./run_ablation.sh "$t" 3 15 --groups "$Q" ) > "$launchlog" 2>&1
  rc=$?
  cat "$launchlog" >> "$LOG"
  log "DONE[$tag] $t rc=$rc"
  for arm in q1a1 q1b1 q1c1 q1d1; do
    count=$(grep -cE "ABLATION:${arm}\\] 启动" "$launchlog" || true)
    if [ "$count" -ne 1 ]; then
      log "PIN-FAIL $t/$arm (launcher printed $count start lines)"
      continue
    fi
    d=$(grep -E "ABLATION:${arm}\] 启动" "$launchlog" | grep -o "ablation/results-[^ ]*" | tail -1 | sed "s|^ablation/|$BASE/ablation/|")
    if [ -n "$d" ] && [ -d "$d" ]; then
      printf '{"target":"%s","arm":"%s","dir":"%s","batch":"%s"}\n' "$t" "$arm" "$d" "$BATCH_ID" >> "$MANIFEST"
      log "PIN $t/$arm -> $d (from launcher output)"
    else
      log "PIN-FAIL $t/$arm (launcher printed no dir)"
    fi
  done
  return $rc
}

audit_q1(){ # target — manifest-only; per-repeat budget/calls/reason checks
  local t=$1 dirs="" row arm rc budget calls reason eff cls bad=0 seen="" all_ids=""
  for arm in q1a1 q1b1 q1c1 q1d1; do
    row=$(grep "\"target\":\"$t\"" "$MANIFEST" | grep "\"arm\":\"$arm\"" | tail -1 | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['dir'])" 2>/dev/null)
    if [ -z "$row" ]; then log "AUDIT[$t] MISSING $arm (not pinned)"; return 2; fi
    case " $seen " in *" $row "*) log "AUDIT[$t] DUPLICATE-DIR $row"; return 2;; esac
    seen="$seen $row"
    local n; n=$(ls "$row"/out-*.tar.gz 2>/dev/null | wc -l)
    if [ "$n" -ne 3 ]; then log "AUDIT[$t] $arm repeats=$n (need exactly 3)"; return 2; fi
    # per-repeat identity: each archive must carry a unique campaign_id that
    # matches its run-config target/arm window and the manifest binding
    local ids=""
    for tgz in "$row"/out-*.tar.gz; do
      cid=$(python3 "$OUT/verify_q1_identity.py" "$tgz" "$t" "$arm" 2>&1) || {
        log "AUDIT[$t] $arm repeat-identity FAIL $tgz $cid"; return 2;
      }
      case "$cid" in BADCFG|NOCID|"") log "AUDIT[$t] $arm repeat-identity FAIL $tgz cid=$cid"; return 2;; esac
      case " $ids " in *" $cid "*) log "AUDIT[$t] $arm DUPLICATE-CID $cid"; return 2;; esac
      case " $all_ids " in *" $cid "*) log "AUDIT[$t] DUPLICATE-CID across arms $cid"; return 2;; esac
      ids="$ids $cid"
      all_ids="$all_ids $cid"
    done
    log "IDENTITY $t/$arm cids=$ids"
    dirs="$dirs $row"
  done
  ( cd "$OUT" && python3 audit_smoke.py --target "$t" --arms q1 $dirs ) \
    > "$OUT/audit_${t}_q1_${BATCH_ID}.txt" 2>&1
  rc=$?
  log "AUDIT[$t] rc=$rc"
  for d in $dirs; do
    for tgz in "$d"/out-*.tar.gz; do
      out=$(verify_repeat "$tgz")
      if [ $? -ne 0 ]; then log "VERIFY-FAIL $tgz $out"; bad=1; continue; fi
      budget=$(printf '%s' "$out" | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['budget'])")
      calls=$(printf '%s' "$out" | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['charged_calls'])") || { log "VERIFY-FAIL malformed output $tgz"; bad=1; continue; }
      reason=$(printf '%s' "$out" | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['reason'])")
      eff=$(printf '%s' "$out" | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['effective_cap'])")
      cls=$(printf '%s' "$out" | python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['classification'])")
      [ "$budget" = "5000" ] || { log "BUDGET-FAIL $tgz cap=$budget"; bad=1; }
      log "REPEAT $(basename "$tgz") cap=$budget eff_cap=$eff charged_calls=$calls reason=$reason class=$cls"
    done
  done
  [ "$rc" -eq 0 ] && [ "$bad" -eq 0 ]
}

FAILS=0
declare -A PORTS=( [proftpd]=18131 [pure-ftpd]=18132 [bftpd]=18105 [exim]=18125 [live555]=18120 [lightftp]=18104 [kamailio]=18126 [forked-daapd]=18123 [lighttpd1]=18122 )
for t in proftpd pure-ftpd bftpd exim live555 lightftp kamailio forked-daapd lighttpd1; do
  wait_target_idle "$t"
  launch_q1 "$t" "${PORTS[$t]}" "Q-$t" || FAILS=$((FAILS+1))
  wait_target_idle "$t"
  audit_q1 "$t" || FAILS=$((FAILS+1))
done
log "=== Q1 rerun batch=$BATCH_ID finished fails=$FAILS ==="
[ "$FAILS" -eq 0 ]
