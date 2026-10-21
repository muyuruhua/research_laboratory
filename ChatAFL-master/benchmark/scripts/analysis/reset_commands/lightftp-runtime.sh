#!/bin/bash
# Per-invocation target-state cleanup for lightftp (fuzzer -c cleanup script).
# Phase-2 semantics: the fuzzer runs this before the forkserver and before
# every target invocation and REQUIRES exit 0 (a failed reset aborts the
# campaign), so unlike the historic image ftpclean this must be idempotent
# on a fresh container: every rm tolerates missing files.
#
# NEVER kill processes in a fuzzer-side cleanup: the AFL forkserver is itself
# a copy of the fftp binary, so `pkill -x fftp` would kill the forkserver
# mid-campaign. Process cleanup belongs to the coverage-replay reset
# (lightftp.sh), which runs without a forkserver present.
set -u
fail() { echo "lightftp-runtime-reset: FAIL: $*" >&2; exit 1; }

[ "${HOME:-}" = "/home/ubuntu" ] || fail "unexpected HOME=${HOME:-unset}"

[ -d "$HOME/ftpshare" ] || mkdir -p "$HOME/ftpshare" || fail "cannot create ftpshare"
find "$HOME/ftpshare" -mindepth 1 -delete || fail "cannot clean ftpshare"
rm -f "$HOME/fftplog" || fail "cannot remove fftplog"

[ -z "$(ls -A "$HOME/ftpshare")" ] || fail "ftpshare not empty after cleanup"
exit 0
