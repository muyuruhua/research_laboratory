#!/bin/bash
source /tmp/coverage-v4-src/fuzz_runtime/common.sh
fuzz_reset_check_processes bftpd bftpd
EXP="${WORKDIR:-/home/ubuntu/experiments}"
JAIL=/home/ubuntu/ftpshare
CONF="$EXP/basic.conf"
[ -f "$CONF" ] || fuzz_reset_fail "missing $CONF"
grep -qE '^[[:space:]]*AUTO_CHDIR="/"' "$CONF" || fuzz_reset_fail "AUTO_CHDIR must remain /"
grep -qE '^[[:space:]]*DO_CHROOT="yes"' "$CONF" || fuzz_reset_fail "DO_CHROOT must remain yes"
fuzz_reset_clean_dir "$JAIL"
[ ! -L /home/ubuntu/bftpdutmp ] || fuzz_reset_fail "refusing symlink /home/ubuntu/bftpdutmp"
rm -f /home/ubuntu/bftpdutmp || fuzz_reset_fail "cannot clear bftpdutmp"
fuzz_reset_truncate_file /home/ubuntu/bftplog
