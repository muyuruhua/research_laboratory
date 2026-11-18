#!/bin/bash
# exim_live555_wave1_rerun_20261115.sh
# The proptpd policy patch landed (13:29) between Phase C's wave-1 snapshots
# (exim 13:07, live555 13:11: old REPLAY_HARNESS_VERSION) and wave-2 snapshots
# (13:40/13:43: new version), splitting each target's batch identity
# (scope_sha256 + replay_harness_version). Forward-fix: rerun the 12 wave-1
# arms on the patched module so each target is uniformly on the new version;
# the already-passing wave-2 dirs are kept.
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
ORCH_LOG=$OUT/smoke_rerun_orchestrator_20261115.log
PROFTPD_LOG=$OUT/proftpd_rerun_v2_20261115.log
LOG=$OUT/exim_live555_wave1_rerun_20261115.log
: > "$LOG"
log() { echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOG"; }

# Wait for the orchestrator AND the proftpd v2 rerun to fully finish.
while ! grep -q "=== Orchestrator finished ===" "$ORCH_LOG" 2>/dev/null; do sleep 60; done
log "orchestrator finished"
while ! grep -q "AUDIT rc=" "$PROFTPD_LOG" 2>/dev/null; do sleep 60; done
log "proftpd v2 rerun finished"
while [ "$(docker ps --format '{{.Names}}' 2>/dev/null | grep -c -- '-loopfuzz-run')" -gt 0 ]; do
  sleep 30
done

run_batch() {  # target port arms parallel tag
  local t=$1 p=$2 arms=$3 par=$4 tag=$5
  log "LAUNCH[$tag] target=$t arms=$arms port=$p parallel=$par"
  (
    cd "$BASE" && \
    env ABLATION_THRESHOLD_OVERRIDE=1 \
        ABLATION_WARMUP_MAX_OVERRIDE=8 \
        ABLATION_EPISODE_ENERGY_OVERRIDE=32 \
        ABLATION_CAL_REWARD_WINDOW_OVERRIDE=16 \
        ABLATION_MEM_PER_FUZZER=2 ABLATION_DOCKER_MEM_CAP=2g \
        ABLATION_PARALLEL=$par ABLATION_SHUFFLE=1 \
        CHATAFL_MOCK_LLM=1 MOCK_PORT=$p \
        MOCK_LATENCY=1 MOCK_ERROR_RATE=1.5 MOCK_SEED=20261102 \
        KEY=loopfuzz-mock-key SKIPCOUNT=40 \
    ./run_ablation.sh "$t" 3 15 --groups "$arms"
  ) >> "$LOG" 2>&1
  log "DONE[$tag] rc=$?"
}

LAUNCH_TS=$(date +%Y%m%dT%H%M%S)
log "launch window opens at $LAUNCH_TS"
run_batch exim 18125 "pvstop1,salvage1,nollm1,wrapgate1,native1,cal_ewma1" 6 E-wave1 &
E=$!
sleep 150
run_batch live555 18120 "pvstop1,salvage1,nollm1,native1,cal_ewma1,cal_run_rate1" 6 L-wave1 &
L=$!
wait $E; wait $L
while [ "$(docker ps --format '{{.Names}}' 2>/dev/null | grep -c -- '-loopfuzz-run')" -gt 0 ]; do
  sleep 30
done

audit() {  # target kept-arms-csv
  local t=$1; shift
  local dirs=() arm d best
  # Dirs on the patched module only: cutoff 13:35 is after the last module
  # edit (13:29/13:30) and covers the kept Phase C wave-2 dirs (13:40/13:43)
  # plus this rerun's dirs; the split wave-1 dirs (13:07/13:11) are excluded.
  local cutoff=20261115T133500
  for arm in pvstop1 salvage1 nollm1 wrapgate1 native1 calibrated1 cal_ewma1 cal_run_rate1; do
    best=""
    for d in "$BASE"/ablation/results-${t}_ablation_${arm}_20261115T*; do
      [[ -d "$d" ]] || continue
      ts=$(basename "$d" | sed -n "s/.*_\(20261115T[0-9]\{6\}\)$/\1/p")
      [[ -z "$ts" ]] && continue
      [[ "$ts" < "$cutoff" ]] && continue
      n=$(ls "$d"/out-*.tar.gz 2>/dev/null | wc -l)
      [[ -f "$d/run_summary.csv" ]] || continue
      (( n < 3 )) && continue
      if [[ -z "$best" || "$d" > "$best" ]]; then best="$d"; fi
    done
    if [ -z "$best" ]; then log "AUDIT[$t] arm $arm has no complete dir in window"; dirs+=("MISSING_${arm}"); else dirs+=("$best"); fi
  done
  for d in "${dirs[@]}"; do
    [[ "$d" == MISSING_* ]] && { log "AUDIT[$t] aborted (missing arms)"; return 2; }
  done
  log "AUDIT[$t] dirs: ${dirs[*]}"
  ( cd "$OUT" && python3 audit_smoke.py --target "$t" "${dirs[@]}" ) \
    > "$OUT/audit_${t}_rerun_strict_20261115.txt" 2>&1
  log "AUDIT[$t] rc=$?"
}

audit exim
audit live555
log "wave1 rerun script finished"
