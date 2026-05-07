#!/bin/bash
set -uo pipefail

if [[ $# -lt 6 ]]; then
  echo "Usage: $0 <container-id> <workdir> <outdir> <results-dir> <archive-name> <log-tag>" >&2
  exit 1
fi

CONTAINER_ID="$1"
WORKDIR="$2"
OUTDIR="$3"
RESULTS_DIR="$4"
ARCHIVE_NAME="$5"
LOG_TAG="$6"

POLL_SEC="${CHATAFL_STALL_POLL_SEC:-30}"
STALL_SEC="${CHATAFL_STALL_THRESHOLD_SEC:-300}"
ENABLE_GDB="${CHATAFL_STALL_GDB:-1}"
STALL_CONFIRM_ROUNDS="${CHATAFL_STALL_CONFIRM_ROUNDS:-3}"
STALL_CONFIRM_SLEEP_SEC="${CHATAFL_STALL_CONFIRM_SLEEP_SEC:-20}"
STALL_ACTION="${CHATAFL_STALL_ACTION:-stop}"
STATUS_DIR="${RESULTS_DIR}/.sample_status"
FORENSICS_ROOT="${RESULTS_DIR}/.forensics"
STATUS_FILE="${STATUS_DIR}/${ARCHIVE_NAME}.status"
FORENSICS_DIR="${FORENSICS_ROOT}/${ARCHIVE_NAME%.tar.gz}"

if ! [[ "$POLL_SEC" =~ ^[0-9]+$ && "$STALL_SEC" =~ ^[0-9]+$ && "$STALL_CONFIRM_ROUNDS" =~ ^[0-9]+$ && "$STALL_CONFIRM_SLEEP_SEC" =~ ^[0-9]+$ ]]; then
  echo "[WATCHDOG] invalid numeric watchdog config" >&2
  exit 1
fi

if [[ "$STALL_ACTION" != "stop" && "$STALL_ACTION" != "diagnose" ]]; then
  echo "[WATCHDOG] invalid CHATAFL_STALL_ACTION=${STALL_ACTION}, expected: stop|diagnose" >&2
  exit 1
fi

mkdir -p "$STATUS_DIR" "$FORENSICS_ROOT"

write_status_file() {
  local tmp="${STATUS_FILE}.tmp"
  {
    printf 'archive_name=%s\n' "$ARCHIVE_NAME"
    printf 'container_id=%s\n' "$CONTAINER_ID"
    for kv in "$@"; do
      printf '%s\n' "$kv"
    done
  } > "$tmp"
  mv "$tmp" "$STATUS_FILE"
}

get_container_running() {
  docker inspect --format '{{.State.Running}}' "$CONTAINER_ID" 2>/dev/null || echo false
}

get_fuzzer_stat() {
  local key="$1"
  docker exec "$CONTAINER_ID" /bin/bash -lc "grep '^${key}[[:space:]]*:' '${WORKDIR}/${OUTDIR}/fuzzer_stats' 2>/dev/null | head -n1 | awk -F: '{print \$2}' | tr -d ' '" 2>/dev/null
}

collect_forensics() {
  local stale_seconds="$1"
  local reason="${2:-fuzzer_no_progress_confirmed}"
  local detected_at
  detected_at="$(date -Iseconds)"

  mkdir -p "$FORENSICS_DIR"

  docker inspect "$CONTAINER_ID" > "${FORENSICS_DIR}/docker_inspect.json" 2>&1 || true
  docker logs "$CONTAINER_ID" > "${FORENSICS_DIR}/docker_logs.full.txt" 2>&1 || true
  docker logs --tail 200 "$CONTAINER_ID" > "${FORENSICS_DIR}/docker_logs.tail.txt" 2>&1 || true

  docker exec "$CONTAINER_ID" /bin/bash -lc "cp '${WORKDIR}/${OUTDIR}/fuzzer_stats' /tmp/fuzzer_stats.watchdog 2>/dev/null && cat /tmp/fuzzer_stats.watchdog" \
    > "${FORENSICS_DIR}/fuzzer_stats.txt" 2>&1 || true
  docker exec "$CONTAINER_ID" /bin/bash -lc "test -f '${WORKDIR}/${OUTDIR}/plot_data' && tail -n 200 '${WORKDIR}/${OUTDIR}/plot_data'" \
    > "${FORENSICS_DIR}/plot_data.tail.txt" 2>&1 || true

  docker exec "$CONTAINER_ID" /bin/bash -lc "ps -eo pid,ppid,stat,etime,pcpu,comm,args" \
    > "${FORENSICS_DIR}/ps.txt" 2>&1 || true

  local afl_pid
  afl_pid="$(docker exec "$CONTAINER_ID" /bin/bash -lc "pgrep -xo afl-fuzz" 2>/dev/null || true)"
  if [[ -n "$afl_pid" ]]; then
    docker exec "$CONTAINER_ID" /bin/bash -lc "ps -L -p ${afl_pid} -o pid,tid,stat,pcpu,psr,comm,wchan:32" \
      > "${FORENSICS_DIR}/ps_threads.txt" 2>&1 || true
    docker exec "$CONTAINER_ID" /bin/bash -lc "cat /proc/${afl_pid}/status" \
      > "${FORENSICS_DIR}/proc_status.txt" 2>&1 || true
    docker exec "$CONTAINER_ID" /bin/bash -lc "cat /proc/${afl_pid}/wchan" \
      > "${FORENSICS_DIR}/proc_wchan.txt" 2>&1 || true
    docker exec "$CONTAINER_ID" /bin/bash -lc "for task in /proc/${afl_pid}/task/*; do tid=\$(basename \"\$task\"); printf '=== TID=%s ===\n' \"\$tid\"; cat \"\$task/wchan\" 2>/dev/null || true; done" \
      > "${FORENSICS_DIR}/task_wchan.txt" 2>&1 || true

    if [[ "$ENABLE_GDB" == "1" ]]; then
      docker exec -u 0 "$CONTAINER_ID" /bin/bash -lc "command -v gdb >/dev/null 2>&1 && gdb -q -batch -ex 'set pagination off' -ex 'thread apply all bt' -p ${afl_pid}" \
        > "${FORENSICS_DIR}/gdb_thread_bt.txt" 2>&1 || true
    fi
  fi

  write_status_file \
    "status=stalled" \
    "reason=${reason}" \
    "detected_at=${detected_at}" \
    "stale_seconds=${stale_seconds}" \
    "stall_action=${STALL_ACTION}" \
    "diagnostics_dir=${FORENSICS_DIR}"

  printf '\n%s: [WATCHDOG] Freeze detected for %s (stale=%ss). Diagnostics: %s\n' \
    "$LOG_TAG" "$CONTAINER_ID" "$stale_seconds" "$FORENSICS_DIR" >&2
}

stop_frozen_container() {
  docker stop -t 10 "$CONTAINER_ID" >/dev/null 2>&1 || docker kill "$CONTAINER_ID" >/dev/null 2>&1 || true
}

confirm_stall() {
  local baseline_update="$1"
  local baseline_execs="$2"
  local round current_update current_execs

  for round in $(seq 1 "$STALL_CONFIRM_ROUNDS"); do
    sleep "$STALL_CONFIRM_SLEEP_SEC"

    if [[ "$(get_container_running)" != "true" ]]; then
      return 1
    fi

    current_update="$(get_fuzzer_stat last_update)"
    current_execs="$(get_fuzzer_stat execs_done)"

    if [[ -n "$current_update" && -n "$current_execs" ]]; then
      if [[ "$current_update" != "$baseline_update" || "$current_execs" != "$baseline_execs" ]]; then
        return 1
      fi
    fi
  done

  return 0
}

write_status_file \
  "status=running" \
  "reason=" \
  "detected_at=" \
  "stale_seconds=0" \
  "diagnostics_dir="

last_update=""
last_execs=""
last_change_epoch="$(date +%s)"

while true; do
  if [[ "$(get_container_running)" != "true" ]]; then
    exit 0
  fi

  current_update="$(get_fuzzer_stat last_update)"
  current_execs="$(get_fuzzer_stat execs_done)"

  if [[ -n "$current_update" && -n "$current_execs" ]]; then
    if [[ "$current_update" != "$last_update" || "$current_execs" != "$last_execs" ]]; then
      last_update="$current_update"
      last_execs="$current_execs"
      last_change_epoch="$(date +%s)"
    else
      now_epoch="$(date +%s)"
      stale_for=$((now_epoch - last_change_epoch))
      if (( stale_for >= STALL_SEC )); then
        if confirm_stall "$current_update" "$current_execs"; then
          collect_forensics "$stale_for" "fuzzer_no_progress_confirmed"
          if [[ "$STALL_ACTION" == "stop" ]]; then
            stop_frozen_container
            exit 0
          fi

          # Diagnose-only mode: keep container alive and continue monitoring.
          last_change_epoch="$(date +%s)"
        else
          last_update="$current_update"
          last_execs="$current_execs"
          last_change_epoch="$(date +%s)"
        fi
      fi
    fi
  fi

  sleep "$POLL_SEC"
done
