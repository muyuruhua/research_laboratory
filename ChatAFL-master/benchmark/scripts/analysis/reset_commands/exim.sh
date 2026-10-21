#!/bin/bash
# coverage_v4 verified per-input reset for exim (replay context, no
# forkserver present, so process termination by pidfile/pattern is safe).
# Persistent state: leftover exim daemon from a timed-out replay plus its
# pidfile. Per-connection children exit on their own and flush gcda.
set -u
TARGET=exim
fail() { echo "reset-and-validate[${TARGET}]: FAIL: $*" >&2; exit 1; }
log()  { echo "reset-and-validate[${TARGET}]: $*"; }

case "$(id -un 2>/dev/null)" in root|ubuntu) ;; *) fail "unexpected user $(id -un 2>/dev/null || unknown)" ;; esac

PIDFILE=/var/lock/exim.pid
stop_daemon() {
  local pid
  if [ -f "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE" 2>/dev/null || true)
    case "$pid" in
      ''|*[!0-9]*) ;;
      *) kill "$pid" 2>/dev/null; sleep 0.3; kill -9 "$pid" 2>/dev/null ;;
    esac
  fi
  pkill -x exim 2>/dev/null
  local rc=$?
  [ "$rc" -le 1 ] || fail "pkill exim error rc=${rc}"
  for _ in 1 2 3 4 5; do pgrep -x exim >/dev/null 2>&1 || break; sleep 0.2; done
  pkill -9 -x exim 2>/dev/null
  sleep 0.3
  pgrep -x exim >/dev/null 2>&1 && fail "leftover exim process survives SIGKILL"
}
stop_daemon
rm -f "$PIDFILE" 2>/dev/null || fail "cannot remove $PIDFILE"
[ ! -e "$PIDFILE" ] || fail "pidfile still present"
[ -x ./src/build-Linux-x86_64/exim ] || fail "missing gcov exim binary"
log "ok (no exim process; pidfile cleared) input=${COVERAGE_V4_INPUT:-unset}"
exit 0
