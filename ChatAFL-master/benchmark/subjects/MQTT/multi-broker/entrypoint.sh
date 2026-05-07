#!/bin/bash
set -e
echo "[multibroker] Starting Mosquitto A on :1883 and Mosquitto B on :1884..."
mosquitto -c /etc/mosquitto/broker_a.conf -d 2>/dev/null && echo "[multibroker] ✓ Broker A :1883"
mosquitto -c /etc/mosquitto/broker_b.conf -d 2>/dev/null && echo "[multibroker] ✓ Broker B :1884"
sleep 1
for p in 1883 1884; do
  nc -z 127.0.0.1 $p 2>/dev/null && echo "[multibroker] Port $p OK" || echo "[multibroker] Port $p FAILED"
done
echo "[multibroker] Ready."
exec tail -f /dev/null
