#!/bin/bash
# coverage_v4 verified per-input reset for bftpd.
# Contract (COVERAGE_V4.md): must provision writable chroot paths and the
# intended AUTO_CHDIR configuration, and verify service state; exit 0 only
# when every check passes. The replay pipeline re-stages the gcov object
# tree under the chroot AFTER this reset, so wiping it here is safe.
# NOTE: the bftpd image ends its Dockerfile with USER root (chroot/login
# needs it); the jail lives at /home/ubuntu/ftpshare regardless, so paths
# here are absolute and both root and ubuntu execution are accepted.
set -u
TARGET=bftpd
fail() { echo "reset-and-validate[${TARGET}]: FAIL: $*" >&2; exit 1; }
log()  { echo "reset-and-validate[${TARGET}]: $*"; }

case "$(id -un 2>/dev/null)" in root|ubuntu) ;; *) fail "unexpected user $(id -un 2>/dev/null || unknown)" ;; esac

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

stop_process bftpd

# Provision the chroot jail (DO_CHROOT=yes → user home) and wipe stale content.
[ -d "$JAIL" ] || mkdir -p "$JAIL" || fail "cannot create $JAIL"
find "$JAIL" -mindepth 1 -delete || fail "cannot clean $JAIL"

# The intended retention-independent AUTO_CHDIR configuration must be intact.
CONF="${WORKDIR:-/home/ubuntu/experiments}/basic.conf"
[ -f "$CONF" ] || fail "missing config $CONF"
grep -qE '^[[:space:]]*AUTO_CHDIR="/"' "$CONF" || fail "AUTO_CHDIR drifted from \"/\" in $CONF"
grep -qE '^[[:space:]]*DO_CHROOT="yes"' "$CONF" || fail "DO_CHROOT drifted from \"yes\" in $CONF"

[ -z "$(ls -A "$JAIL")" ] || fail "ftpshare not empty after cleanup"
[ -w "$JAIL" ] || fail "ftpshare (chroot jail) not writable"

log "ok (no bftpd process; chroot jail empty+writable; AUTO_CHDIR/DO_CHROOT intact) input=${COVERAGE_V4_INPUT:-unset}"
exit 0
