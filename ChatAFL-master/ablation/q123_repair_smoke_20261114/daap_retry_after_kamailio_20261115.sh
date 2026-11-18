#!/bin/bash
# DAAP 3-arm retry (pvstop1/wrapgate1/native1) once kamailio drains:
# the 21:06 attempt failed with "All test cases time out" — CPU starvation
# from 9 simultaneous compiles on top of 18 kamailio replay containers.
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
LOG=$OUT/daap_3arm_retry_20261115.log
: > "$LOG"
log(){ echo "[$(date '+%H:%M:%S')] $*" >> "$LOG"; }
while [ "$(docker ps --format '{{.Names}}' | grep -c -- '-loopfuzz-run')" -gt 0 ]; do sleep 60; done
log "host drained; launching DAAP 3-arm retry"
cd "$BASE" && env ABLATION_THRESHOLD_OVERRIDE=1 ABLATION_WARMUP_MAX_OVERRIDE=8 \
  ABLATION_EPISODE_ENERGY_OVERRIDE=32 ABLATION_CAL_REWARD_WINDOW_OVERRIDE=16 \
  ABLATION_MEM_PER_FUZZER=2 ABLATION_DOCKER_MEM_CAP=2g ABLATION_PARALLEL=3 \
  CHATAFL_MOCK_LLM=1 MOCK_PORT=18123 MOCK_LATENCY=1 MOCK_ERROR_RATE=1.5 \
  MOCK_SEED=20261102 KEY=loopfuzz-mock-key SKIPCOUNT=40 \
  ./run_ablation.sh forked-daapd 3 15 --groups pvstop1,wrapgate1,native1 >> "$LOG" 2>&1
log "retry rc=$?"
while [ "$(docker ps --format '{{.Names}}' | grep -c -- '-loopfuzz-run')" -gt 0 ]; do sleep 30; done
dirs=""
for arm in pvstop1 salvage1 nollm1 wrapgate1 native1 calibrated1 cal_ewma1 cal_run_rate1; do
  best=""
  for d in "$BASE"/ablation/results-forked-daapd_ablation_${arm}_20261115T2*; do
    [[ -d "$d" ]] || continue
    ts=$(basename "$d" | sed -n "s/.*_\(20261115T[0-9]\{6\}\)$/\1/p"); [[ -z "$ts" ]] && continue
    [[ "$ts" < "20261115T181353" ]] && continue
    n=$(ls "$d"/out-*.tar.gz 2>/dev/null | wc -l); [[ -f "$d/run_summary.csv" ]] || continue
    (( n < 3 )) && continue
    if [[ -z "$best" || "$d" > "$best" ]]; then best="$d"; fi
  done
  [[ -z "$best" ]] && { log "MISSING $arm"; exit 2; }
  dirs="$dirs $best"
done
( cd "$OUT" && python3 audit_smoke.py --target forked-daapd $dirs ) \
  > "$OUT/audit_forked-daapd_final_fp5f818ed7_20261115.txt" 2>&1
log "re-audit rc=$?"
