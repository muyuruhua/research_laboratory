#!/usr/bin/env bash
set -euo pipefail

echo 'export CHATAFL_MQTT_BROKERS="mosquitto@tcp://127.0.0.1:1883,emqx@tcp://127.0.0.1:1884,vernemq@tcp://127.0.0.1:1885,nanomq@tcp://127.0.0.1:1886"'
echo 'export CHATAFL_MQTT_DIFF_PROBE_PERIOD="8"'
