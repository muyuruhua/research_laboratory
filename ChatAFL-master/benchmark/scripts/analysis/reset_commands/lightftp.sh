#!/bin/bash
# coverage_v4 verified per-input reset for lightftp.
# Contract (COVERAGE_V4.md): exit 0 only when the target-specific files and
# service state are actually cleared; any failure must stop replay.
# Runs inside the subject container as user ubuntu before every replay input.
set -u
TARGET=lightftp
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

stop_process fftp

[ -d "$HOME/ftpshare" ] || mkdir -p "$HOME/ftpshare" || fail "cannot create $HOME/ftpshare"
find "$HOME/ftpshare" -mindepth 1 -delete || fail "cannot clean $HOME/ftpshare"
rm -f "$HOME/fftplog" || fail "cannot remove $HOME/fftplog"

[ -z "$(ls -A "$HOME/ftpshare")" ] || fail "ftpshare not empty after cleanup"
[ ! -e "$HOME/fftplog" ] || fail "fftplog still exists after cleanup"
[ -w "$HOME/ftpshare" ] || fail "ftpshare not writable"

log "ok (no fftp process; ftpshare empty; no fftplog) input=${COVERAGE_V4_INPUT:-unset}"
exit 0
