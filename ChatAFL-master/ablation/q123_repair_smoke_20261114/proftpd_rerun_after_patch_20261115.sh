#!/bin/bash
# proftpd_rerun_after_patch_20261115.sh
# Rerun the 8 core arms of proftpd with the patched coverage_v4 module
# (proftpd-ready-client-graceful-exit-v2: harness-SIGTERM shutdown whose gcov
# listener dies -11 during teardown is accepted only with full joint evidence).
# Launches staggered ~5 min after the orchestrator's Phase D start to avoid
# compile storms, then archives the v1 failing audit and re-audits strictly.
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
ORCH_LOG=$OUT/smoke_rerun_orchestrator_20261115.log
LOG=$OUT/proftpd_rerun_v2_20261115.log
CORE_ARMS="pvstop1,salvage1,nollm1,wrapgate1,native1,calibrated1,cal_ewma1,cal_run_rate1"
: > "$LOG"
log() { echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOG"; }

# Wait for the orchestrator to start Phase D, then stagger 5 minutes.
while ! grep -q "=== Phase D start ===" "$ORCH_LOG" 2>/dev/null; do sleep 60; done
log "Phase D detected; staggering 300s"
sleep 300

LAUNCH_TS=$(date +%Y%m%dT%H%M%S)
log "LAUNCH proptpd v2-policy rerun arms=$CORE_ARMS launch_ts=$LAUNCH_TS"
(
  cd "$BASE" && \
  env ABLATION_THRESHOLD_OVERRIDE=1 \
      ABLATION_WARMUP_MAX_OVERRIDE=8 \
      ABLATION_EPISODE_ENERGY_OVERRIDE=32 \
      ABLATION_CAL_REWARD_WINDOW_OVERRIDE=16 \
      ABLATION_MEM_PER_FUZZER=2 ABLATION_DOCKER_MEM_CAP=2g \
      ABLATION_PARALLEL=6 ABLATION_SHUFFLE=1 \
      CHATAFL_MOCK_LLM=1 MOCK_PORT=18131 \
      MOCK_LATENCY=1 MOCK_ERROR_RATE=1.5 MOCK_SEED=20261102 \
      KEY=loopfuzz-mock-key SKIPCOUNT=40 \
  ./run_ablation.sh proftpd 3 15 --groups "$CORE_ARMS"
) >> "$LOG" 2>&1
RC=$?
log "run_ablation rc=$RC"

while [ "$(docker ps --format '{{.Names}}' 2>/dev/null | grep -c -- '-loopfuzz-run')" -gt 0 ]; do
  sleep 30
done

dirs=()
for arm in ${CORE_ARMS//,/ }; do
  best=""
  for d in "$BASE"/ablation/results-proftpd_ablation_${arm}_20261115T*; do
    [[ -d "$d" ]] || continue
    ts=$(basename "$d" | sed -n "s/.*_\(20261115T[0-9]\{6\}\)$/\1/p")
    [[ -z "$ts" ]] && continue
    # only dirs launched by this v2 rerun
    [[ "$ts" < "$LAUNCH_TS" ]] && continue
    n=$(ls "$d"/out-*.tar.gz 2>/dev/null | wc -l)
    [[ -f "$d/run_summary.csv" ]] || continue
    (( n < 3 )) && continue
    if [[ -z "$best" || "$d" > "$best" ]]; then best="$d"; fi
  done
  if [ -z "$best" ]; then
    log "MISSING complete dir for arm $arm"
    dirs+=("MISSING_${arm}")
  else
    dirs+=("$best")
  fi
done
for d in "${dirs[@]}"; do
  if [[ "$d" == MISSING_* ]]; then
    log "AUDIT aborted: incomplete arms present"
    exit 2
  fi
done
log "auditing: ${dirs[*]}"
# Preserve the v1 failing audit (old failure evidence is never overwritten).
if [ -f "$OUT/audit_proftpd_rerun_strict_20261115.txt" ]; then
  cp -n "$OUT/audit_proftpd_rerun_strict_20261115.txt" \
        "$OUT/audit_proftpd_rerun_v1_shutdownsegv_incomplete_20261115.txt"
fi
( cd "$OUT" && python3 audit_smoke.py --target proftpd "${dirs[@]}" ) \
  > "$OUT/audit_proftpd_rerun_strict_20261115.txt" 2>&1
log "AUDIT rc=$?"
