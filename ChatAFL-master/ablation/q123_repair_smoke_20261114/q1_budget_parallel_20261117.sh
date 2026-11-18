#!/bin/bash
# Q1 fast integrity smoke: all targets and all four Q1 arms enter the queue
# concurrently. A global resource token pool bounds the number of active
# three-repeat groups, because each run_ablation process has its own preflight.
# This is intentionally separate from q1_budget_rerun_20261116.sh so the old
# serial queue remains available as an immutable record. A 15-minute smoke is
# time-censored: its audit can establish telemetry/reset/coverage integrity,
# but it is not a fixed-dose 5000-call comparison unless the ledger exhausts.
set -u

BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
Q=q1a1,q1b1,q1c1,q1d1
BATCH_ID="q1parallel-$(date +%Y%m%dT%H%M%S)-$$"
LOG_DIR="$OUT/q1_parallel_${BATCH_ID}"
mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/summary.log"
: > "$SUMMARY"
SLOT_DIR="$LOG_DIR/slots"
mkdir -p "$SLOT_DIR"
RUNS=3
MEMORY_PER_FUZZER_GB=2
BROKER_RESERVE_GB=1
HEADROOM_GB=8

declare -A PORTS=(
  [proftpd]=18131 [pure-ftpd]=18132 [bftpd]=18105 [exim]=18125
  [live555]=18120 [lightftp]=18104 [kamailio]=18126
  [forked-daapd]=18123 [lighttpd1]=18122
)
TARGETS=(proftpd pure-ftpd bftpd exim live555 lightftp kamailio forked-daapd lighttpd1)
PIDS=()
AUDIT_PIDS=()

log() { printf '[%s] %s\n' "$(date '+%m-%d %H:%M:%S')" "$*" | tee -a "$SUMMARY"; }

if docker ps --format '{{.Names}}' | grep -q -- '-loopfuzz-run'; then
  log 'ABORT: existing fuzz containers are still running; refusing to mix batches'
  exit 2
fi

fuzz_actual_usage_mb() {
  local total_kb=0 id kb
  for id in $(docker ps -q --no-trunc 2>/dev/null); do
    kb=$(awk '{print int($1/1024)}' "/sys/fs/cgroup/memory/docker/${id}/memory.usage_in_bytes" 2>/dev/null)
    [[ -n "$kb" ]] && total_kb=$((total_kb + kb))
  done
  echo $((total_kb / 1024))
}

compute_slot_count() {
  local total_mb avail_mb used_mb budget_mb usable_mb per_group_mb by_budget by_avail
  total_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
  used_mb=$(fuzz_actual_usage_mb)
  budget_mb=$((total_mb * 3 / 4))
  usable_mb=$((budget_mb - used_mb))
  by_avail=$((avail_mb - HEADROOM_GB * 1024))
  ((by_avail < usable_mb)) && usable_mb=$by_avail
  per_group_mb=$((RUNS * MEMORY_PER_FUZZER_GB * 1024 + BROKER_RESERVE_GB * 1024))
  by_budget=$((usable_mb / per_group_mb))
  ((by_budget < 1)) && by_budget=1
  echo "$by_budget"
  log "RESOURCE total=${total_mb}MB available=${avail_mb}MB container_usage=${used_mb}MB reserved_per_group=${per_group_mb}MB global_slots=${by_budget}" >&2
}

resource_slot_available() {
  local total_mb avail_mb used_mb budget_mb per_group_mb
  total_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
  avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
  used_mb=$(fuzz_actual_usage_mb)
  budget_mb=$((total_mb * 3 / 4))
  per_group_mb=$((RUNS * MEMORY_PER_FUZZER_GB * 1024 + BROKER_RESERVE_GB * 1024))
  (( used_mb + per_group_mb <= budget_mb )) || return 1
  (( avail_mb >= HEADROOM_GB * 1024 + per_group_mb )) || return 1
}

SLOT_COUNT=$(compute_slot_count)
for ((i=1; i<=SLOT_COUNT; i++)); do : > "$SLOT_DIR/slot_${i}.lock"; done

acquire_slot() {
  local i fd
  while :; do
    for ((i=1; i<=SLOT_COUNT; i++)); do
      exec {fd}>"$SLOT_DIR/slot_${i}.lock"
      if flock -n "$fd" && resource_slot_available; then
        SLOT_FD=$fd
        SLOT_ID=$i
        return 0
      fi
      flock -u "$fd" 2>/dev/null || true
      exec {fd}>&-
    done
    sleep 5
  done
}

release_slot() {
  if [[ -n "${SLOT_FD:-}" ]]; then
    flock -u "$SLOT_FD" || true
    eval "exec ${SLOT_FD}>&-"
    SLOT_FD=""
    SLOT_ID=""
  fi
}

audit_target() {
  local t=$1 manifest="$LOG_DIR/${t}.manifest.jsonl" audit="$LOG_DIR/audit_${t}.txt"
  local dirs=() arm d n
  for arm in q1a1 q1b1 q1c1 q1d1; do
    d=$(grep -m1 "\"arm\":\"$arm\"" "$manifest" 2>/dev/null \
      | python3 -c 'import json,sys; row=sys.stdin.readline(); print(json.loads(row)["dir"] if row else "")' 2>/dev/null || true)
    if [ -z "$d" ] || [ ! -d "$d" ]; then
      log "AUDIT[$t] missing pinned directory for $arm"
      return 2
    fi
    n=$(find "$d" -maxdepth 1 -name 'out-*.tar.gz' -type f | wc -l)
    if [ "$n" -ne 3 ]; then
      log "AUDIT[$t] $arm has $n repeats (expected 3)"
      return 2
    fi
    dirs+=("$d")
  done

  (cd "$OUT" && python3 audit_smoke.py --timeout-min 15 --target "$t" --arms q1 "${dirs[@]}") \
    > "$audit" 2>&1
  local rc=$?
  log "AUDIT[$t] rc=$rc report=$audit"
  for d in "${dirs[@]}"; do
    for archive in "$d"/out-*.tar.gz; do
      python3 "$OUT/verify_q1_repeat.py" "$archive" >> "$LOG_DIR/verify_${t}.jsonl" 2>&1 || \
        log "VERIFY[$t] failed archive=$archive"
    done
  done
  return "$rc"
}

launch_arm() {
  local t=$1 arm=$2 p=${PORTS[$1]}
  local launchlog="$LOG_DIR/launch_${t}_${arm}.log" manifest="$LOG_DIR/${t}.manifest.jsonl"
  acquire_slot
  trap 'release_slot' EXIT TERM INT
  log "LAUNCH[$t/$arm] port=$p slot=$SLOT_ID active_limit=$SLOT_COUNT"
  (
    cd "$BASE" || exit 1
    env ABLATION_THRESHOLD_OVERRIDE=1 ABLATION_WARMUP_MAX_OVERRIDE=8 \
      ABLATION_EPISODE_ENERGY_OVERRIDE=32 ABLATION_CAL_REWARD_WINDOW_OVERRIDE=16 \
      ABLATION_CALL_BUDGET_OVERRIDE=5000 ABLATION_MEM_PER_FUZZER=2 \
      ABLATION_DOCKER_MEM_CAP=2g ABLATION_PARALLEL=1 ABLATION_SHUFFLE=1 \
      ABLATION_KILL_GRACE_SEC=30 \
      CHATAFL_MOCK_LLM=1 MOCK_PORT="$p" MOCK_LATENCY=1 MOCK_ERROR_RATE=1.5 \
      MOCK_SEED=20261102 KEY=loopfuzz-mock-key SKIPCOUNT=500 \
      COVERAGE_V4_SAMPLED_CHECKPOINTS=1 \
      COVERAGE_V4_SMOKE=1 COVERAGE_V4_MAX_REPLAY_INPUTS=32 \
      ./run_ablation.sh "$t" "$RUNS" 15 --groups "$arm"
  ) > "$launchlog" 2>&1
  local launch_rc=$?

  local count d fd
  count=$(grep -cE "ABLATION:${arm}\\] 启动" "$launchlog" || true)
  d=$(grep -E "ABLATION:${arm}\\] 启动" "$launchlog" \
    | grep -o 'ablation/results-[^ ]*' | tail -1 \
    | sed "s|^ablation/|$BASE/ablation/|")
  if [ "$count" -eq 1 ] && [ -d "$d" ]; then
    exec {fd}>"$manifest.lock"
    flock "$fd"
    printf '{"target":"%s","arm":"%s","dir":"%s","batch":"%s"}\n' \
      "$t" "$arm" "$d" "$BATCH_ID" >> "$manifest"
    flock -u "$fd"
    eval "exec ${fd}>&-"
  else
    log "PIN[$t/$arm] failed count=$count dir=$d"
  fi
  log "DONE[$t/$arm] launcher_rc=$launch_rc"
  release_slot
  trap - EXIT TERM INT
  return "$launch_rc"
}

target_worker() {
  local t=$1 arm rc=0
  : > "$LOG_DIR/${t}.manifest.jsonl"
  for arm in q1a1 q1b1 q1c1 q1d1; do
    launch_arm "$t" "$arm" || rc=$((rc + 1))
  done
  audit_target "$t" || rc=$((rc + 1))
  printf '%s\n' "$rc" > "$LOG_DIR/${t}.worker.rc"
  return "$rc"
}

log "=== parallel Q1 smoke start batch=$BATCH_ID targets=${#TARGETS[@]} arms=4 ==="
for t in "${TARGETS[@]}"; do
  target_worker "$t" &
  PIDS+=("$!")
done

FAILS=0
for pid in "${PIDS[@]}"; do
  wait "$pid" || FAILS=$((FAILS + 1))
done

log "=== parallel Q1 smoke finished batch=$BATCH_ID failures=$FAILS ==="
exit "$FAILS"
