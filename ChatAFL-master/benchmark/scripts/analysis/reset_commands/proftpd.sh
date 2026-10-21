#!/bin/bash
# coverage_v4 verified per-input reset for proftpd (replay context).
# Mirrors the historic per-input cleanup: terminate leftover servers, clear
# the FTP share, and re-provision ownership/permissions on the gcov object
# directories (proftpd drops privileges and the next replay must be able to
# write gcda there again).
set -u
TARGET=proftpd
fail() { echo "reset-and-validate[${TARGET}]: FAIL: $*" >&2; exit 1; }
log()  { echo "reset-and-validate[${TARGET}]: $*"; }

case "$(id -un 2>/dev/null)" in root|ubuntu) ;; *) fail "unexpected user $(id -un 2>/dev/null || unknown)" ;; esac

GCOV_ROOT="${WORKDIR:-/home/ubuntu/experiments}/proftpd-gcov"
JAIL=/home/ubuntu/ftpshare

stop_process() {
  local name="$1" rc
  pkill -x "$name" 2>/dev/null; rc=$?
  [ "$rc" -le 1 ] || fail "pkill ${name} error rc=${rc}"
  for _ in 1 2 3 4 5; do pgrep -x "$name" >/dev/null 2>&1 || return 0; sleep 0.2; done
  pkill -9 -x "$name" 2>/dev/null
  sleep 0.3
  pgrep -x "$name" >/dev/null 2>&1 && fail "leftover ${name} process survives SIGKILL"
}

stop_process proftpd

[ -d "$JAIL" ] || mkdir -p "$JAIL" || fail "cannot create $JAIL"
find "$JAIL" -mindepth 1 -delete || fail "cannot clean $JAIL"
[ -z "$(ls -A "$JAIL")" ] || fail "ftpshare not empty after cleanup"

for sub in src lib modules; do
  [ -d "$GCOV_ROOT/$sub" ] || fail "missing gcov dir $GCOV_ROOT/$sub"
  chown -R ubuntu:ubuntu "$GCOV_ROOT/$sub" 2>/dev/null || fail "cannot chown $GCOV_ROOT/$sub"
  chmod -R go+rw "$GCOV_ROOT/$sub" 2>/dev/null || fail "cannot chmod $GCOV_ROOT/$sub"
  [ -w "$GCOV_ROOT/$sub" ] || fail "$GCOV_ROOT/$sub not writable"
done
[ -x "$GCOV_ROOT/proftpd" ] || fail "missing gcov proftpd binary"
[ -f "${WORKDIR:-/home/ubuntu/experiments}/basic.conf" ] || fail "missing basic.conf"

log "ok (no proftpd process; ftpshare clean; gcov dirs re-provisioned) input=${COVERAGE_V4_INPUT:-unset}"
exit 0
