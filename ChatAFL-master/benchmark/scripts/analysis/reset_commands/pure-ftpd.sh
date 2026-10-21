#!/bin/bash
# coverage_v4 verified per-input reset for pure-ftpd (replay context).
# pure-ftpd chroots to /home/fuzzing and writes gcda under the GCOV_PREFIX
# mirror there; the pipeline re-stages the object tree after this reset, so
# wiping the chroot here is safe.
set -u
TARGET=pure-ftpd
fail() { echo "reset-and-validate[${TARGET}]: FAIL: $*" >&2; exit 1; }
log()  { echo "reset-and-validate[${TARGET}]: $*"; }

case "$(id -un 2>/dev/null)" in root|ubuntu) ;; *) fail "unexpected user $(id -un 2>/dev/null || unknown)" ;; esac

CHROOT=/home/fuzzing
stop_process() {
  local name="$1" rc
  pkill -x "$name" 2>/dev/null; rc=$?
  [ "$rc" -le 1 ] || fail "pkill ${name} error rc=${rc}"
  for _ in 1 2 3 4 5; do pgrep -x "$name" >/dev/null 2>&1 || return 0; sleep 0.2; done
  pkill -9 -x "$name" 2>/dev/null
  sleep 0.3
  pgrep -x "$name" >/dev/null 2>&1 && fail "leftover ${name} process survives SIGKILL"
}

stop_process pure-ftpd

[ -d "$CHROOT" ] || mkdir -p "$CHROOT" || fail "cannot create $CHROOT"
find "$CHROOT" -mindepth 1 -delete || fail "cannot clean $CHROOT"
[ -z "$(ls -A "$CHROOT")" ] || fail "chroot not empty after cleanup"
[ -w "$CHROOT" ] || fail "chroot not writable"
[ -x "${WORKDIR:-/home/ubuntu/experiments}/pure-ftpd-gcov/src/pure-ftpd" ] || fail "missing gcov pure-ftpd binary"

log "ok (no pure-ftpd process; chroot clean+writable) input=${COVERAGE_V4_INPUT:-unset}"
exit 0
