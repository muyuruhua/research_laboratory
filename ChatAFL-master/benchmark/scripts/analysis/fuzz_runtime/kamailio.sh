#!/bin/bash
source /tmp/coverage-v4-src/fuzz_runtime/common.sh
fuzz_reset_check_processes kamailio kamailio
EXP="${WORKDIR:-/home/ubuntu/experiments}"
RUNTIME="$EXP/kamailio/runtime_dir"
fuzz_reset_clean_dir "$RUNTIME"
[ -f "$EXP/kamailio-basic.cfg" ] || fuzz_reset_fail "missing kamailio-basic.cfg"
if [ "${KAMAILIO_TCP:-0}" = 1 ]; then
  fuzz_reset_check_port_free tcp 5060
  fuzz_reset_check_port_free udp 5060
else
  fuzz_reset_check_port_free udp 5060
fi
