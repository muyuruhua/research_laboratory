#!/bin/bash
source /tmp/coverage-v4-src/fuzz_runtime/common.sh
# Linux comm is truncated to 15 bytes for testOnDemandRTSPServer.
fuzz_reset_check_processes testOnDemandRTS testOnDemandRTSPServer
fuzz_reset_check_port_free tcp 8554
[ -x "${WORKDIR:-/home/ubuntu/experiments}/live/testProgs/testOnDemandRTSPServer" ] || \
  fuzz_reset_fail "missing RTSP server binary"
