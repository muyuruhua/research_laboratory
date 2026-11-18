#!/bin/bash
source /tmp/coverage-v4-src/fuzz_runtime/common.sh
fuzz_reset_check_processes pure-ftpd pure-ftpd
CHROOT=/home/fuzzing
fuzz_reset_clean_dir "$CHROOT"
[ -x "${WORKDIR:-/home/ubuntu/experiments}/pure-ftpd/src/pure-ftpd" ] || \
  fuzz_reset_fail "missing fuzzing binary"
