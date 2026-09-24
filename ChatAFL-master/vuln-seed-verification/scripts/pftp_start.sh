#!/bin/bash
# Start campaign ProFTPD (ASAN build) with campaign basic.conf + optional env tweaks
# Usage: pftp_start.sh <logfile> [extra_conf_line]
LOG="$1"; EXTRA="$2"
CONF=/tmp/proftpd-verify.conf
cp /home/ubuntu/experiments/basic.conf $CONF
if [ -n "$EXTRA" ]; then sed -i "16a $EXTRA" $CONF; fi
cd /home/ubuntu/experiments/proftpd || exit 1
exec env ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=0" \
  ./proftpd -n -c $CONF -X > "$LOG" 2>&1
