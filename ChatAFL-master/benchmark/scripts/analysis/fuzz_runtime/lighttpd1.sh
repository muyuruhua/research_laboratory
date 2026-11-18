#!/bin/bash
source /tmp/coverage-v4-src/fuzz_runtime/common.sh
fuzz_reset_check_processes lighttpd lighttpd
fuzz_reset_check_port_free tcp 8080
EXP="${WORKDIR:-/home/ubuntu/experiments}"
[ -x "$EXP/lighttpd1/src/lighttpd" ] || fuzz_reset_fail "missing lighttpd binary"
CONF="$EXP/lighttpd.conf"
[ -f "$CONF" ] || fuzz_reset_fail "missing $CONF"
grep -q '^server\.document-root *= *"/tmp"' "$CONF" || \
  fuzz_reset_fail "document-root must remain /tmp"
