#!/bin/bash
# coverage_v4 verified per-input reset for lighttpd1.
# The served document root is /tmp (server.document-root in lighttpd.conf)
# and the replay config defines no upload/access-log state; the only
# persistent between-input state is a leftover server process.
set -u
TARGET=lighttpd1
fail() { echo "reset-and-validate[${TARGET}]: FAIL: $*" >&2; exit 1; }
log()  { echo "reset-and-validate[${TARGET}]: $*"; }

[ "$(id -un)" = "ubuntu" ] || fail "expected user ubuntu, got $(id -un 2>/dev/null || unknown)"
[ "${HOME:-}" = "/home/ubuntu" ] || fail "unexpected HOME=${HOME:-unset}"

stop_process() {
  local name="$1" rc
  pkill -x "$name" 2>/dev/null; rc=$?
  [ "$rc" -le 1 ] || fail "pkill ${name} error rc=${rc}"
  for _ in 1 2 3 4 5; do pgrep -x "$name" >/dev/null 2>&1 || return 0; sleep 0.2; done
  pkill -9 -x "$name" 2>/dev/null
  sleep 0.3
  pgrep -x "$name" >/dev/null 2>&1 && fail "leftover ${name} process survives SIGKILL"
}

stop_process lighttpd

CONF="${WORKDIR:-/home/ubuntu/experiments}/lighttpd.conf"
[ -f "$CONF" ] || fail "missing config $CONF"
grep -q '^server\.document-root *= *"/tmp"' "$CONF" || fail "document-root drifted from /tmp"

log "ok (no lighttpd process; document-root intact) input=${COVERAGE_V4_INPUT:-unset}"
exit 0
