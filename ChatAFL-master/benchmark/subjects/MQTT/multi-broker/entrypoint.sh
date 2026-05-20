#!/bin/bash
# Multi-broker entrypoint — Mosquitto v2.0.18 (sync MBFuzzer)
set -e
MOSQ="/usr/local/sbin/mosquitto"
for bin in "$MOSQ" /usr/sbin/mosquitto /usr/bin/mosquitto; do
  [ -x "$bin" ] && { MOSQ="$bin"; break; }
done
echo "[multibroker] Mosquitto v2.0.18 — starting A on :1883 and B on :1884..."
"$MOSQ" -c /etc/mosquitto/broker_a.conf -d 2>/dev/null && echo "[multibroker] OK Broker A :1883"
"$MOSQ" -c /etc/mosquitto/broker_b.conf -d 2>/dev/null && echo "[multibroker] OK Broker B :1884"
sleep 1
for p in 1883 1884; do
  nc -z 127.0.0.1 $p 2>/dev/null && echo "[multibroker] Port $p OK" || echo "[multibroker] Port $p FAILED"
done
echo "[multibroker] Ready."
exec tail -f /dev/null
