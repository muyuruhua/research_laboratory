#!/bin/bash
# Master v2 (GLM53 verification 4.3): immutable per-coordinate manifest,
# per-launch exit codes, ALL 13 arms audited per target, no silent skips.
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
LOG=$OUT/master_campaign_v2_20261116.log
MANIFEST=$OUT/run_manifest_v2_20261116.jsonl
CORE="pvstop1,salvage1,nollm1,wrapgate1,native1,calibrated1,cal_ewma1,cal_run_rate1"
Q="q1a1,q1b1,q1c1,q1d1,ordmatch1"
ALL13="$CORE,$Q"
START_TS=$(date +%Y%m%dT%H%M%S)
: > "$LOG"; : > "$MANIFEST"
log(){ echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOG"; }
for t in proftpd pure-ftpd bftpd exim live555 lightftp kamailio forked-daapd lighttpd1; do
  for a in ${ALL13//,/ }; do for r in 1 2 3; do
    printf '{"coord":"%s|%s|%d","batch":"%s","status":"pending"}\n' "$t" "$a" "$r" "$START_TS" >> "$MANIFEST"
  done; done
done
launch(){ # target port tag -> records real rc
  local t=$1 p=$2 tag=$3 rc=0
  log "LAUNCH[$tag] $t port=$p"
  ( cd "$BASE" && env ABLATION_THRESHOLD_OVERRIDE=1 ABLATION_WARMUP_MAX_OVERRIDE=8 \
      ABLATION_EPISODE_ENERGY_OVERRIDE=32 ABLATION_CAL_REWARD_WINDOW_OVERRIDE=16 \
      ABLATION_MEM_PER_FUZZER=2 ABLATION_DOCKER_MEM_CAP=2g ABLATION_PARALLEL=6 ABLATION_SHUFFLE=1 \
      CHATAFL_MOCK_LLM=1 MOCK_PORT=$p MOCK_LATENCY=1 MOCK_ERROR_RATE=1.5 MOCK_SEED=20261102 \
      KEY=loopfuzz-mock-key SKIPCOUNT=40 \
      ./run_ablation.sh "$t" 3 15 --groups "$ALL13" ) >> "$LOG" 2>&1
  rc=$?
  log "DONE[$tag] $t rc=$rc"
  return $rc
}
audit(){ # target -> all 13 arms, fail on any missing
  local t=$1 dirs="" arm d best ts n missing=0
  for arm in ${ALL13//,/ }; do
    best=""
    for d in "$BASE"/ablation/results-${t}_ablation_${arm}_20261116T*; do
      [[ -d "$d" ]] || continue
      ts=$(basename "$d" | sed -n "s/.*_\(20261116T[0-9]\{6\}\)$/\1/p"); [[ -z "$ts" ]] && continue
      [[ "$ts" < "$START_TS" ]] && continue
      n=$(ls "$d"/out-*.tar.gz 2>/dev/null | wc -l); [[ -f "$d/run_summary.csv" ]] || continue
      (( n < 3 )) && continue
      [[ -z "$best" || "$d" > "$best" ]] && best="$d"
    done
    if [ -z "$best" ]; then log "AUDIT[$t] MISSING-ARM $arm"; missing=1; else dirs="$dirs $best"; fi
  done
  if [ "$missing" -ne 0 ]; then log "AUDIT[$t] ABORT missing arms"; return 2; fi
  ( cd "$OUT" && python3 audit_smoke.py --target "$t" --arms all $dirs ) \
    > "$OUT/audit_${t}_master_v2_20261116.txt" 2>&1
  local arc=$?
  log "AUDIT[$t] rc=$arc"
  return $arc
}
drain(){ while [ "$(docker ps --format '{{.Names}}' | grep -c -- '-loopfuzz-run')" -gt 0 ]; do sleep 30; done; }
log "=== master v2 start START_TS=$START_TS fp=f40222e3 harness=20261116b ==="
FAILS=0
AUDIT_FAILS=0
launch proftpd 18131 M1-proftpd || FAILS=$((FAILS+1)); sleep 60
launch pure-ftpd 18132 M1-pureftpd || FAILS=$((FAILS+1)); sleep 60
launch bftpd 18105 M1-bftpd || FAILS=$((FAILS+1))
drain; log "phase1 done fails=$FAILS"
audit proftpd || AUDIT_FAILS=$((AUDIT_FAILS+1))
audit pure-ftpd || AUDIT_FAILS=$((AUDIT_FAILS+1))
audit bftpd || AUDIT_FAILS=$((AUDIT_FAILS+1))
launch exim 18125 M2-exim || FAILS=$((FAILS+1)); sleep 120
launch live555 18120 M2-live555 || FAILS=$((FAILS+1)); sleep 60
launch lightftp 18104 M2-lightftp || FAILS=$((FAILS+1))
drain; log "phase2 done fails=$FAILS"
audit exim || AUDIT_FAILS=$((AUDIT_FAILS+1))
audit live555 || AUDIT_FAILS=$((AUDIT_FAILS+1))
audit lightftp || AUDIT_FAILS=$((AUDIT_FAILS+1))
launch kamailio 18126 M3-kamailio || FAILS=$((FAILS+1)); sleep 120
launch forked-daapd 18123 M3-daap || FAILS=$((FAILS+1)); sleep 60
launch lighttpd1 18122 M3-lighttpd1 || FAILS=$((FAILS+1))
drain; log "phase3 done fails=$FAILS"
audit kamailio || AUDIT_FAILS=$((AUDIT_FAILS+1))
audit forked-daapd || AUDIT_FAILS=$((AUDIT_FAILS+1))
audit lighttpd1 || AUDIT_FAILS=$((AUDIT_FAILS+1))
log "=== master v2 finished launch_fails=$FAILS audit_fails=$AUDIT_FAILS ==="
[ "$FAILS" -eq 0 ] && [ "$AUDIT_FAILS" -eq 0 ]
# v3 patches appended 2026-11-16 10:10 (GLM53 verification round 3):
#  - audit() now PROPAGATES its exit code; AUDIT_FAILS aggregates.
#  - Batching note: targets launch sequentially per phase (documented, not
#    full-parallel); per-container isolation unchanged.
