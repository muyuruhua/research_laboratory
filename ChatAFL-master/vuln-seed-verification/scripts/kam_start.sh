#!/bin/bash
# Start campaign Kamailio with TCP listener (vuln is in tcp_read_headers)
cd /home/ubuntu/experiments/kamailio || exit 1
mkdir -p /tmp/kamrun
exec ./src/kamailio -f /tmp/kam-tcp.cfg -L src/modules -Y /tmp/kamrun -n 1 -D -E
