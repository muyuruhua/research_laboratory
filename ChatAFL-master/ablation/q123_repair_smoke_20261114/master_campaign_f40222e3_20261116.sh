#!/bin/bash
# Master mock campaign on the fixed fuzzer (fingerprint f40222e3...):
# 9 targets x 13 arms (8 core + q1a1-d1 + ordmatch1) x 3 repeats,
# threshold-1, 15-min, mock per container. GLM53 plan section 5.4.
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
LOG=$OUT/master_campaign_f40222e3_20261116.log
CORE="pvstop1,salvage1,nollm1,wrapgate1,native1,calibrated1,cal_ewma1,cal_run_rate1"
Q="q1a1,q1b1,q1c1,q1d1,ordmatch1"
ARMS="$CORE,$Q"
START_TS=$(date +%Y%m%dT%H%M%S)
: > "$LOG"
log(){ echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOG"; }
launch(){ # target port tag
  local t=$1 p=$2 tag=$3
  log "LAUNCH[$tag] $t port=$p arms=$ARMS"
  ( cd "$BASE" && env ABLATION_THRESHOLD_OVERRIDE=1 ABLATION_WARMUP_MAX_OVERRIDE=8 \
      ABLATION_EPISODE_ENERGY_OVERRIDE=32 ABLATION_CAL_REWARD_WINDOW_OVERRIDE=16 \
      ABLATION_MEM_PER_FUZZER=2 ABLATION_DOCKER_MEM_CAP=2g ABLATION_PARALLEL=6 ABLATION_SHUFFLE=1 \
      CHATAFL_MOCK_LLM=1 MOCK_PORT=$p MOCK_LATENCY=1 MOCK_ERROR_RATE=1.5 MOCK_SEED=20261102 \
      KEY=loopfuzz-mock-key SKIPCOUNT=40 \
      ./run_ablation.sh "$t" 3 15 --groups "$ARMS" ) >> "$LOG" 2>&1
  log "DONE[$tag] rc=$?"
}
audit(){ # target arms-csv outfile-suffix
  local t=$1 arms_csv=$2 dirs="" arm d best ts n
  IFS=',' read -ra A <<< "$arms_csv"
  for arm in "${A[@]}"; do
    best=""
    for d in "$BASE"/ablation/results-${t}_ablation_${arm}_20261116T*; do
      [[ -d "$d" ]] || continue
      ts=$(basename "$d" | sed -n "s/.*_\(20261116T[0-9]\{6\}\)$/\1/p"); [[ -z "$ts" ]] && continue
      [[ "$ts" < "$START_TS" ]] && continue
      n=$(ls "$d"/out-*.tar.gz 2>/dev/null | wc -l); [[ -f "$d/run_summary.csv" ]] || continue
      (( n < 3 )) && continue
      [[ -z "$best" || "$d" > "$best" ]] && best="$d"
    done
    [[ -n "$best" ]] && dirs="$dirs $best"
  done
  [ -z "$dirs" ] && { log "AUDIT[$t] no dirs"; return 2; }
  ( cd "$OUT" && python3 audit_smoke.py --target "$t" $dirs ) \
    > "$OUT/audit_${t}_master_f40222e3_20261116.txt" 2>&1
  log "AUDIT[$t] rc=$?"
}
log "=== master campaign start START_TS=$START_TS fp=f40222e3 ==="
launch proftpd 18131 M1-proftpd & P1=$!; sleep 150
launch pure-ftpd 18132 M1-pureftpd & P2=$!; sleep 150
launch bftpd 18105 M1-bftpd & P3=$!
wait $P1 $P2 $P3
while [ "$(docker ps --format '{{.Names}}' | grep -c -- '-loopfuzz-run')" -gt 0 ]; do sleep 30; done
log "phase1 done"; audit proftpd "$ARMS"; audit pure-ftpd "$ARMS"; audit bftpd "$CORE"
launch exim 18125 M2-exim & P1=$!; sleep 240
launch live555 18120 M2-live555 & P2=$!; sleep 150
launch lightftp 18104 M2-lightftp & P3=$!
wait $P1 $P2 $P3
while [ "$(docker ps --format '{{.Names}}' | grep -c -- '-loopfuzz-run')" -gt 0 ]; do sleep 30; done
log "phase2 done"; audit exim "$ARMS"; audit live555 "$ARMS"; audit lightftp "$CORE"
launch kamailio 18126 M3-kamailio & P1=$!; sleep 240
launch forked-daapd 18123 M3-daap & P2=$!; sleep 150
launch lighttpd1 18122 M3-lighttpd1 & P3=$!
wait $P1 $P2 $P3
while [ "$(docker ps --format '{{.Names}}' | grep -c -- '-loopfuzz-run')" -gt 0 ]; do sleep 30; done
log "phase3 done"; audit kamailio "$ARMS"; audit forked-daapd "$ARMS"; audit lighttpd1 "$CORE"
log "=== master campaign finished ==="
