#!/bin/bash
# coverage_v4 verified per-input reset for forked-daapd.
# Persistent state (forked-daapd.conf): sqlite library db, cache db, logfile.
# The MP3 media directory is library SOURCE, not runtime state — never touched.
set -u
TARGET=forked-daapd
fail() { echo "reset-and-validate[${TARGET}]: FAIL: $*" >&2; exit 1; }
log()  { echo "reset-and-validate[${TARGET}]: $*"; }

[ "$(id -un)" = "ubuntu" ] || fail "expected user ubuntu, got $(id -un 2>/dev/null || unknown)"
[ "${HOME:-}" = "/home/ubuntu" ] || fail "unexpected HOME=${HOME:-unset}"

EXP="${WORKDIR:-/home/ubuntu/experiments}"
DB_DIR="$EXP/db"
LOG="$EXP/forked-daapd.log"

stop_process() {
  local name="$1" rc
  pkill -x "$name" 2>/dev/null; rc=$?
  [ "$rc" -le 1 ] || fail "pkill ${name} error rc=${rc}"
  for _ in 1 2 3 4 5; do pgrep -x "$name" >/dev/null 2>&1 || return 0; sleep 0.2; done
  pkill -9 -x "$name" 2>/dev/null
  sleep 0.3
  pgrep -x "$name" >/dev/null 2>&1 && fail "leftover ${name} process survives SIGKILL"
}

stop_process forked-daapd

[ -d "$DB_DIR" ] || mkdir -p "$DB_DIR" || fail "cannot create $DB_DIR"
rm -f "$DB_DIR/songs3.db" "$DB_DIR/cache.db" "$LOG" || fail "cannot remove db/log state"
# Journal/WAL sidecars of the sqlite databases.
rm -f "$DB_DIR"/*.db-wal "$DB_DIR"/*.db-shm 2>/dev/null

[ ! -e "$DB_DIR/songs3.db" ] || fail "songs3.db still exists"
[ ! -e "$DB_DIR/cache.db" ] || fail "cache.db still exists"
[ ! -e "$LOG" ] || fail "logfile still exists"
[ -w "$DB_DIR" ] || fail "db dir not writable"
[ -f "$EXP/forked-daapd.conf" ] || fail "missing forked-daapd.conf"

log "ok (no forked-daapd process; songs3/cache db + log cleared) input=${COVERAGE_V4_INPUT:-unset}"
exit 0
