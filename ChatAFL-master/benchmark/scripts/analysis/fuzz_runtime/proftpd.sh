#!/bin/bash
source /tmp/coverage-v4-src/fuzz_runtime/common.sh
fuzz_reset_check_processes proftpd proftpd
EXP="${WORKDIR:-/home/ubuntu/experiments}"
JAIL=/home/ubuntu/ftpshare
[ -f "$EXP/basic.conf" ] || fuzz_reset_fail "missing $EXP/basic.conf"
fuzz_reset_clean_dir "$JAIL"
