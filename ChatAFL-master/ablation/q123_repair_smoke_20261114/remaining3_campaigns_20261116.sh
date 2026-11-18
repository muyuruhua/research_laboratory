#!/bin/bash
# bftpd + lightftp + lighttpd1: same-fingerprint (5f818ed7) 8-arm x 3-repeat
# smoke so ALL nine targets share the current-source validation standard.
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
LOG=$OUT/remaining3_campaigns_20261116.log
CORE_ARMS="pvstop1,salvage1,nollm1,wrapgate1,native1,calibrated1,cal_ewma1,cal_run_rate1"
START_TS=$(date +%Y%m%dT%H%M%S)
: > "$LOG"
log(){ echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOG"; }
launch(){ # target port tag
  local t=$1 p=$2 tag=$3
  log "LAUNCH[$tag] $t port=$p"
  ( cd "$BASE" && env ABLATION_THRESHOLD_OVERRIDE=1 ABLATION_WARMUP_MAX_OVERRIDE=8 \
      ABLATION_EPISODE_ENERGY_OVERRIDE=32 ABLATION_CAL_REWARD_WINDOW_OVERRIDE=16 \
      ABLATION_MEM_PER_FUZZER=2 ABLATION_DOCKER_MEM_CAP=2g ABLATION_PARALLEL=6 ABLATION_SHUFFLE=1 \
      CHATAFL_MOCK_LLM=1 MOCK_PORT=$p MOCK_LATENCY=1 MOCK_ERROR_RATE=1.5 MOCK_SEED=20261102 \
      KEY=loopfuzz-mock-key SKIPCOUNT=40 \
      ./run_ablation.sh "$t" 3 15 --groups "$CORE_ARMS" ) >> "$LOG" 2>&1
  log "DONE[$tag] rc=$?"
}
audit(){ # target
  local t=$1 dirs="" arm d best ts n
  for arm in ${CORE_ARMS//,/ }; do
    best=""
    for d in "$BASE"/ablation/results-${t}_ablation_${arm}_2026111[56]T*; do
      [[ -d "$d" ]] || continue
      ts=$(basename "$d" | sed -n "s/.*_\(2026111[56]T[0-9]\{6\}\)$/\1/p"); [[ -z "$ts" ]] && continue
      [[ "$ts" < "$START_TS" ]] && continue
      n=$(ls "$d"/out-*.tar.gz 2>/dev/null | wc -l); [[ -f "$d/run_summary.csv" ]] || continue
      (( n < 3 )) && continue
      [[ -z "$best" || "$d" > "$best" ]] && best="$d"
    done
    [[ -z "$best" ]] && { log "AUDIT[$t] missing $arm"; return 2; }
    dirs="$dirs $best"
  done
  ( cd "$OUT" && python3 audit_smoke.py --target "$t" $dirs ) \
    > "$OUT/audit_${t}_final_fp5f818ed7_20261115.txt" 2>&1
  log "AUDIT[$t] rc=$?"
}
log "=== remaining3 start START_TS=$START_TS ==="
launch bftpd 18105 R3-bftpd &
B=$!
sleep 180
launch lightftp 18104 R3-lightftp &
L=$!
wait $B; wait $L
while [ "$(docker ps --format '{{.Names}}' | grep -c -- '-loopfuzz-run')" -gt 0 ]; do sleep 30; done
audit bftpd; audit lightftp
launch lighttpd1 18122 R3-lighttpd1
while [ "$(docker ps --format '{{.Names}}' | grep -c -- '-loopfuzz-run')" -gt 0 ]; do sleep 30; done
audit lighttpd1
log "=== remaining3 finished ==="
