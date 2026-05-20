#!/bin/bash
# build_broker_images.sh — Build all 6 MQTT broker images matching MBFuzzer versions
# Run from: benchmark/scripts/execution/dockerfiles/
#
# MBFuzzer version references:
#   Mosquitto v2.0.18  (built via profuzzbench Mosquitto target, not here)
#   NanoMQ    236c9c5   (git commit)
#   EMQX      v5.6.0    (official release)
#   FlashMQ   d82cba5   (git commit, v1.12.1)
#   VerneMQ   f0e6dc15  (git commit, 2.0.0-rc1)
#   HiveMQ    v4.24.0   (Enterprise release)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Building MQTT broker images (MBFuzzer version sync) ==="

echo ""
echo "[1/5] NanoMQ @ 236c9c5 ..."
docker build -t chatafl-nanomq:236c9c5 "$SCRIPT_DIR/nanomq/"

echo ""
echo "[2/5] EMQX @ 5.6.0 ..."
docker build -t chatafl-emqx:5.6.0 "$SCRIPT_DIR/emqx/"

echo ""
echo "[3/5] FlashMQ @ d82cba5 ..."
docker build -t chatafl-flashmq:d82cba5 "$SCRIPT_DIR/flashmq/"

echo ""
echo "[4/5] VerneMQ @ f0e6dc15 (2.0.0-rc1, EXACT MBFuzzer) ..."
docker build -t chatafl-vernemq:f0e6dc15 "$SCRIPT_DIR/vernemq/"

echo ""
echo "[5/5] HiveMQ @ 4.24.0 ..."
docker build -t chatafl-hivemq:4.24.0 "$SCRIPT_DIR/hivemq/"

echo ""
echo "=== All images built. Verify with: docker images | grep chatafl- ==="
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | grep "chatafl-"
