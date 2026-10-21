#!/bin/bash
# coverage_v4 verified per-input reset for live555 (replay context).
# Persistent state is a leftover testOnDemandRTSPServer from a timed-out
# replay; the server itself keeps no on-disk state between inputs.
set -u
TARGET=live555
fail() { echo "reset-and-validate[${TARGET}]: FAIL: $*" >&2; exit 1; }
log()  { echo "reset-and-validate[${TARGET}]: $*"; }

[ "$(id -un 2>/dev/null)" = "ubuntu" ] || fail "expected user ubuntu, got $(id -un 2>/dev/null || unknown)"

stop_process() {
  local name="$1" rc
  pkill -x "$name" 2>/dev/null; rc=$?
  [ "$rc" -le 1 ] || fail "pkill ${name} error rc=${rc}"
  for _ in 1 2 3 4 5; do pgrep -x "$name" >/dev/null 2>&1 || return 0; sleep 0.2; done
  pkill -9 -x "$name" 2>/dev/null
  sleep 0.3
  pgrep -x "$name" >/dev/null 2>&1 && fail "leftover ${name} process survives SIGKILL"
}

# comm is truncated to 15 chars: testOnDemandRTSPServer -> testOnDemandRTS
stop_process testOnDemandRTS

[ -x ./testOnDemandRTSPServer ] || fail "missing gcov testOnDemandRTSPServer binary"

log "ok (no leftover RTSP server) input=${COVERAGE_V4_INPUT:-unset}"
exit 0
