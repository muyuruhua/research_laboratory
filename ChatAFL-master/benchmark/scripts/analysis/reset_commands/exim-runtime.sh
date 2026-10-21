#!/bin/bash
# Per-invocation exim state reset (fuzzer -c cleanup script).
# The historic image clean script is a bare `pkill -F /var/lock/exim.pid`,
# which exits 1 whenever the pidfile is missing or stale (fresh container,
# or the daemonized child of a previous invocation is already gone) — phase-2
# treats a nonzero cleanup as fatal, so it must be replaced by this
# idempotent, self-validating variant.
#
# Safety: never kill by process name — the AFL forkserver is itself an exim
# process. Only the pid recorded in the pidfile is killed, and never when it
# equals the idle forkserver pid the fuzzer declares via
# PHASE2_ALLOWED_FORKSERVER_PID.
set -u
fail() { echo "exim-runtime-reset: FAIL: $*" >&2; exit 1; }

PIDFILE=/var/lock/exim.pid
ALLOWED="${PHASE2_ALLOWED_FORKSERVER_PID:-}"

if [ -f "$PIDFILE" ]; then
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  case "$pid" in
    ''|*[!0-9]*) ;;  # corrupt/empty pidfile: drop it below
    *)
      if [ -n "$ALLOWED" ] && [ "$pid" = "$ALLOWED" ]; then
        :  # the pidfile names the live forkserver; never touch it
      elif kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        for _ in 1 2 3 4 5; do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
        if kill -0 "$pid" 2>/dev/null; then
          kill -9 "$pid" 2>/dev/null
          sleep 0.2
        fi
        kill -0 "$pid" 2>/dev/null && fail "recorded exim pid $pid survives SIGKILL"
      fi
      ;;
  esac
  rm -f "$PIDFILE" || fail "cannot remove $PIDFILE"
fi

[ ! -e "$PIDFILE" ] || fail "pidfile still present after reset"
exit 0
