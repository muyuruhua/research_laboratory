#!/bin/bash
source /tmp/coverage-v4-src/fuzz_runtime/common.sh
fuzz_reset_check_processes fftp fftp
fuzz_reset_clean_dir /home/ubuntu/ftpshare
fuzz_reset_truncate_file /home/ubuntu/fftplog
