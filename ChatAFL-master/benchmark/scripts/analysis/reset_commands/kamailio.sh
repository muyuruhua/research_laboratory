#!/bin/bash
# coverage_v4 verified per-input reset for kamailio (UDP replay profile).
# Persistent state: the kamailio runtime dir (unix sockets, pid files) passed
# as -Y ./kamailio-gcov/runtime_dir/ by the replay server command, plus any
# leftover kamailio process. TCP replay is refused by the pipeline itself.
set -u
TARGET=kamailio
fail() { echo "reset-and-validate[${TARGET}]: FAIL: $*" >&2; exit 1; }
log()  { echo "reset-and-validate[${TARGET}]: $*"; }

[ "$(id -un)" = "ubuntu" ] || fail "expected user ubuntu, got $(id -un 2>/dev/null || unknown)"
[ "${HOME:-}" = "/home/ubuntu" ] || fail "unexpected HOME=${HOME:-unset}"

EXP="${WORKDIR:-/home/ubuntu/experiments}"
RUNTIME="$EXP/kamailio-gcov/runtime_dir"

stop_process() {
  local name="$1" rc
  pkill -x "$name" 2>/dev/null; rc=$?
  [ "$rc" -le 1 ] || fail "pkill ${name} error rc=${rc}"
  for _ in 1 2 3 4 5; do pgrep -x "$name" >/dev/null 2>&1 || return 0; sleep 0.2; done
  pkill -9 -x "$name" 2>/dev/null
  sleep 0.3
  pgrep -x "$name" >/dev/null 2>&1 && fail "leftover ${name} process survives SIGKILL"
}

stop_process kamailio

rm -rf "$RUNTIME" || fail "cannot remove runtime dir $RUNTIME"
[ ! -e "$RUNTIME" ] || fail "runtime dir still exists after removal"
[ -f "$EXP/kamailio-basic.cfg" ] || fail "missing kamailio-basic.cfg"
[ -d "$EXP/kamailio-gcov/src" ] || fail "missing gcov build tree"

log "ok (no kamailio process; runtime_dir cleared) input=${COVERAGE_V4_INPUT:-unset}"
exit 0
