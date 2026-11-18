#!/bin/bash
# final_rerun_all6_20261115.sh — six-target rerun on the fixed source
# (fingerprint 5f818ed7...: adds the stop_soon guard on the per-exchange
# helper FATAL so the 900s campaign TERM cannot abort kamailio runs).
# All prior audit files are preserved; finals are written as
# audit_<target>_final_fp5f818ed7_20261115.txt.
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
LOG=$OUT/final_rerun_all6_20261115.log
CORE_ARMS="pvstop1,salvage1,nollm1,wrapgate1,native1,calibrated1,cal_ewma1,cal_run_rate1"
FP=5f818ed7
START_TS=$(date +%Y%m%dT%H%M%S)
: > "$LOG"
log() { echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOG"; }

fuzz_containers() { docker ps --format '{{.Names}}' 2>/dev/null | grep -c -- '-loopfuzz-run' || true; }
drain() { while [ "$(fuzz_containers)" -gt 0 ]; do sleep 30; done; }

launch_target() {  # $1=target $2=port $3=parallel $4=tag
  local t=$1 p=$2 par=$3 tag=$4
  log "LAUNCH[$tag] target=$t port=$p parallel=$par arms=$CORE_ARMS"
  (
    cd "$BASE" && \
    env ABLATION_THRESHOLD_OVERRIDE=1 \
        ABLATION_WARMUP_MAX_OVERRIDE=8 \
        ABLATION_EPISODE_ENERGY_OVERRIDE=32 \
        ABLATION_CAL_REWARD_WINDOW_OVERRIDE=16 \
        ABLATION_MEM_PER_FUZZER=2 ABLATION_DOCKER_MEM_CAP=2g \
        ABLATION_PARALLEL="$par" ABLATION_SHUFFLE=1 \
        CHATAFL_MOCK_LLM=1 MOCK_PORT="$p" \
        MOCK_LATENCY=1 MOCK_ERROR_RATE=1.5 MOCK_SEED=20261102 \
        KEY=loopfuzz-mock-key SKIPCOUNT=40 \
    ./run_ablation.sh "$t" 3 15 --groups "$CORE_ARMS"
  ) >> "$LOG" 2>&1
  log "DONE[$tag] target=$t rc=$?"
}

audit_target() {  # $1=target — newest complete dir per arm within this run window
  local t=$1
  local dirs=() arm d ts n best
  for arm in ${CORE_ARMS//,/ }; do
    best=""
    for d in "$BASE"/ablation/results-${t}_ablation_${arm}_20261115T*; do
      [[ -d "$d" ]] || continue
      ts=$(basename "$d" | sed -n "s/.*_\(20261115T[0-9]\{6\}\)$/\1/p")
      [[ -z "$ts" ]] && continue
      [[ "$ts" < "$START_TS" ]] && continue
      n=$(ls "$d"/out-*.tar.gz 2>/dev/null | wc -l)
      [[ -f "$d/run_summary.csv" ]] || continue
      (( n < 3 )) && continue
      if [[ -z "$best" || "$d" > "$best" ]]; then best="$d"; fi
    done
    if [ -z "$best" ]; then log "AUDIT[$t] arm $arm missing complete dir"; dirs+=("MISSING_${arm}"); else dirs+=("$best"); fi
  done
  for d in "${dirs[@]}"; do
    [[ "$d" == MISSING_* ]] && { log "AUDIT[$t] ABORT missing arms"; return 2; }
  done
  log "AUDIT[$t] dirs: ${dirs[*]}"
  ( cd "$OUT" && python3 audit_smoke.py --target "$t" "${dirs[@]}" ) \
    > "$OUT/audit_${t}_final_fp${FP}_20261115.txt" 2>&1
  log "AUDIT[$t] rc=$?"
}

log "=== final rerun start START_TS=$START_TS fp=$FP ==="

# Phase 1: proftpd + pure-ftpd
launch_target proftpd   18131 6 F1-proftpd &
P1=$!
sleep 150
launch_target pure-ftpd 18132 6 F1-pureftpd &
P2=$!
wait $P1; wait $P2; drain
log "Phase 1 complete"
audit_target proftpd
audit_target pure-ftpd

# Phase 2: exim + live555
launch_target exim    18125 6 F2-exim &
P1=$!
sleep 240
launch_target live555 18120 6 F2-live555 &
P2=$!
wait $P1; wait $P2; drain
log "Phase 2 complete"
audit_target exim
audit_target live555

# Phase 3: kamailio + forked-daapd
launch_target kamailio     18126 6 F3-kamailio &
P1=$!
sleep 240
launch_target forked-daapd 18123 6 F3-daap &
P2=$!
wait $P1; wait $P2; drain
log "Phase 3 complete"
audit_target kamailio
audit_target forked-daapd

log "=== final rerun finished ==="
