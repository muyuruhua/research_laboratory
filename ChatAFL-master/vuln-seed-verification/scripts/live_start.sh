#!/bin/bash
# Start campaign live555 testOnDemandRTSPServer (ASAN build) for trigger verification
cd /home/ubuntu/experiments/live/testProgs || exit 1
exec env ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=0" \
  ./testOnDemandRTSPServer 8554 > /tmp/live.log 2>&1
