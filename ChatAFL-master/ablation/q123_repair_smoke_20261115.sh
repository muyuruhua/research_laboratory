#!/bin/bash
# smoke_rerun_orchestrator_20261115.sh — full restart after stopping all prior containers
#
# Six failed targets (per strict matrix audit 2026-11-15) rerun with the CURRENT
# source (fingerprint frozen at 5dce0ecc...; do NOT edit LoopFuzz/*.c|*.h|Makefile
# or loopfuzz/llm_mock_v5.py while this runs). Threshold-1, 8 core arms, 3 repeats,
# 15-minute wall-clock smoke, uncapped call budget, mock gateway llm_mock_v5.py
# container-local per run (netns port isolation). All arms of a target run in
# parallel waves (ABLATION_PARALLEL=6; memory admission may tighten further).
# After each phase, audit_smoke.py strict audit runs on ONLY the dirs produced
# by this orchestrator (name-TS gate) with complete artifacts (3 archives +
# run_summary.csv); incomplete arms fail visibly instead of falling back.
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
LOG=$OUT/smoke_rerun_orchestrator_20261115.log
CORE_ARMS="pvstop1,salvage1,nollm1,wrapgate1,native1,calibrated1,cal_ewma1,cal_run_rate1"
START_TS=$(date +%Y%m%dT%H%M%S)
START_EPOCH=$(date +%s)
: > "$LOG"

log() { echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOG"; }

fuzz_containers() { docker ps --format '{{.Names}}' 2>/dev/null | grep -c -- '-loopfuzz-run' || true; }

drain() {
  while [ "$(fuzz_containers)" -gt 0 ]; do sleep 30; done
}

launch_target() {  # $1=target $2=port $3=arms $4=parallel $5=phase-tag
  local t=$1 p=$2 arms=$3 par=$4 tag=$5
  log "LAUNCH[$tag] target=$t port=$p parallel=$par arms=$arms"
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
    ./run_ablation.sh "$t" 3 15 --groups "$arms" >> "$LOG" 2>&1
  )
  local rc=$?
  log "DONE[$tag] target=$t rc=$rc"
}

audit_target() {  # $1=target — only dirs from THIS orchestrator run, complete artifacts
  local t=$1
  local dirs=() arm d ts
  IFS=',' read -ra ARM_ARR <<< "$CORE_ARMS"
  for arm in "${ARM_ARR[@]}"; do
    local best=""
    for d in "$BASE"/ablation/results-${t}_ablation_${arm}_2*T*; do
      [[ -d "$d" ]] || continue
      ts=$(basename "$d" | sed -n "s/.*_\([0-9]\{8\}T[0-9]\{6\}\)$/\1/p")
      [[ -z "$ts" ]] && continue
      # only dirs launched by this orchestrator run
        [[ "$ts" < "$START_TS" ]] && continue
      # require complete artifacts: 3 archives + run_summary
      local n_archives
      n_archives=$(ls "$d"/out-*.tar.gz 2>/dev/null | wc -l)
      [[ -f "$d/run_summary.csv" ]] || continue
      (( n_archives < 3 )) && continue
      if [[ -z "$best" || "$d" > "$best" ]]; then best="$d"; fi
    done
    if [ -z "$best" ]; then
      log "AUDIT[$t] INCOMPLETE-MISSING dir for arm $arm (no complete dir since $START_TS)"
      dirs+=("MISSING_${arm}")
    else
      dirs+=("$best")
    fi
  done
  # fail visibly if any arm lacked a complete dir
  for d in "${dirs[@]}"; do
    if [[ "$d" == MISSING_* ]]; then
      log "AUDIT[$t] rc=2 (incomplete arms present)"
      { echo "audit aborted: incomplete arms: ${dirs[*]}"; } > "$OUT/audit_${t}_rerun_strict_20261115.txt"
      return 2
    fi
  done
  local audit_out="$OUT/audit_${t}_rerun_strict_20261115.txt"
  ( cd "$OUT" && python3 audit_smoke.py --target "$t" "${dirs[@]}" ) > "$audit_out" 2>&1
  local rc=$?
  log "AUDIT[$t] rc=$rc output=$audit_out"
  return $rc
}

log "=== Orchestrator start START_TS=$START_TS ==="

# ── Phase B: proftpd + pure-ftpd, all 8 core arms each ────────────────
log "=== Phase B start ==="
launch_target proftpd   18131 "$CORE_ARMS" 6 B-proftpd &
B1=$!
sleep 150
launch_target pure-ftpd 18132 "$CORE_ARMS" 6 B-pureftpd &
B2=$!
wait $B1; R1=$?
wait $B2; R2=$?
drain
log "Phase B complete rc_proftpd=$R1 rc_pureftpd=$R2"
audit_target proftpd;   AP=$?; log "Phase B audit proftpd rc=$AP"
audit_target pure-ftpd; AU=$?; log "Phase B audit pure-ftpd rc=$AU"

# ── Phase C: exim + live555 ───────────────────────────────────────────
log "=== Phase C start ==="
launch_target exim    18125 "$CORE_ARMS" 6 C-exim &
C1=$!
sleep 240
launch_target live555 18120 "$CORE_ARMS" 6 C-live555 &
C2=$!
wait $C1; R1=$?
wait $C2; R2=$?
drain
log "Phase C complete rc_exim=$R1 rc_live555=$R2"
audit_target exim;    AE=$?; log "Phase C audit exim rc=$AE"
audit_target live555; AL=$?; log "Phase C audit live555 rc=$AL"

# ── Phase D: kamailio + forked-daapd ──────────────────────────────────
log "=== Phase D start ==="
launch_target kamailio     18126 "$CORE_ARMS" 6 D-kamailio &
D1=$!
sleep 240
launch_target forked-daapd 18123 "$CORE_ARMS" 6 D-daap &
D2=$!
wait $D1; R1=$?
wait $D2; R2=$?
drain
log "Phase D complete rc_kamailio=$R1 rc_daap=$R2"
audit_target kamailio;     AK=$?; log "Phase D audit kamailio rc=$AK"
audit_target forked-daapd; AD=$?; log "Phase D audit forked-daapd rc=$AD"

log "=== Orchestrator finished audits: proftpd=$AP pure-ftpd=$AU exim=$AE live555=$AL kamailio=$AK daap=$AD ==="
