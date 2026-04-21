#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# O8: Heterogeneous MQTT Broker Cluster Manager
#
# Launches N lightweight, non-instrumented MQTT broker containers from
# different implementations for cross-implementation differential testing.
#
# Usage (called from profuzzbench_exec_common_dev.sh):
#   source mqtt_heterogeneous_brokers.sh
#   mqtt_hetero_launch "$MQTT_AUTO_NETWORK" "$DOCIMAGE"
#   # → sets MQTT_HETERO_BROKER_CSV  (e.g. "nanomq@tcp://nanomq-ref:1883,...")
#   # → sets MQTT_HETERO_CONTAINERS  (space-separated container IDs)
#   mqtt_hetero_cleanup
#
# Each broker:
#   - Runs vanilla (no ASAN, no instrumentation) to minimize resource use
#   - Limited to --cpus=0.3 --memory=128m
#   - Joins the caller's Docker network with a predictable hostname
#   - Listens on port 1883
#
# Supported images (pulled from Docker Hub on first use):
#   nanomq/nanomq:latest          — NanoMQ   (C, EMQ)
#   flashmq/flashmq:latest        — FlashMQ  (C++)
#   emqx/emqx:5.0.12              — EMQX     (Erlang)
#   vernemq/vernemq:1.12.0        — VerneMQ  (Erlang)
#   hivemq/hivemq-ce:2023.9       — HiveMQ CE (Java)
#
# Design: OCP-compliant extension — does not modify any existing script.
# profuzzbench_exec_common_dev.sh sources this file and calls the
# functions; if this file is absent, the caller falls back to the
# existing single-stable-broker path.
# ═══════════════════════════════════════════════════════════════════════

# ── Configuration ─────────────────────────────────────────────────────
# Which heterogeneous brokers to launch.  Each entry:
#   IMPL_NAME:DOCKER_IMAGE:HOSTNAME_ALIAS
# The user can override via CHATAFL_HETERO_BROKERS env var (same format,
# comma-separated).

_MQTT_HETERO_DEFAULT_BROKERS=(
  "nanomq:emqx/nanomq:latest:nanomq-ref"
  "emqx:emqx/emqx:5.0.12:emqx-ref"
  "vernemq:vernemq/vernemq:latest:vernemq-ref"
)

# Resource limits per secondary broker
_MQTT_HETERO_CPUS="${CHATAFL_HETERO_CPUS:-0.3}"
_MQTT_HETERO_MEM="${CHATAFL_HETERO_MEM:-128m}"
_MQTT_HETERO_STARTUP_TIMEOUT="${CHATAFL_HETERO_STARTUP_TIMEOUT:-30}"

# ── State ─────────────────────────────────────────────────────────────
MQTT_HETERO_BROKER_CSV=""
MQTT_HETERO_CONTAINERS=""
declare -a _MQTT_HETERO_CIDS=()

# ── Internal helpers ──────────────────────────────────────────────────

_mqtt_hetero_parse_brokers() {
  local -a result=()
  if [[ -n "${CHATAFL_HETERO_BROKERS:-}" ]]; then
    IFS=',' read -ra result <<< "$CHATAFL_HETERO_BROKERS"
  else
    result=("${_MQTT_HETERO_DEFAULT_BROKERS[@]}")
  fi
  echo "${result[@]}"
}

_mqtt_hetero_wait_port() {
  local cid="$1"
  local port="${2:-1883}"
  local timeout="${3:-$_MQTT_HETERO_STARTUP_TIMEOUT}"
  local elapsed=0

  while [[ $elapsed -lt $timeout ]]; do
    if docker exec "$cid" sh -c "cat < /dev/tcp/127.0.0.1/$port >/dev/null 2>&1 || nc -z 127.0.0.1 $port 2>/dev/null || true" 2>/dev/null | grep -q ''; then
      # Try a simple TCP probe from outside
      :
    fi
    # External probe via docker network
    if docker exec "$cid" sh -c "echo '' | timeout 1 nc 127.0.0.1 $port 2>/dev/null" 2>/dev/null; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

# ── Public API ────────────────────────────────────────────────────────

# Launch heterogeneous broker containers on the given Docker network.
# Args:
#   $1 — Docker network name (must already exist)
#   $2 — Primary target Docker image name (e.g. "mosquitto-v2.1.2")
#        Used to determine which Mosquitto version is primary (avoid dup)
#
# Sets:
#   MQTT_HETERO_BROKER_CSV — comma-separated "impl@tcp://host:1883" list
#   MQTT_HETERO_CONTAINERS — space-separated container IDs
mqtt_hetero_launch() {
  local network="$1"
  local primary_target="$2"
  local log_tag="${3:-O8-HETERO}"

  if [[ -z "$network" ]]; then
    echo "[$log_tag] ERROR: no Docker network provided"
    return 1
  fi

  local -a broker_defs
  read -ra broker_defs <<< "$(_mqtt_hetero_parse_brokers)"

  local csv_parts=()
  _MQTT_HETERO_CIDS=()

  for entry in "${broker_defs[@]}"; do
    IFS=':' read -r impl image_part1 image_part2 alias <<< "$entry"
    local image="${image_part1}:${image_part2}"

    if [[ -z "$impl" || -z "$image" || -z "$alias" ]]; then
      echo "[$log_tag] WARN: malformed broker entry: $entry (skipping)"
      continue
    fi

    # Construct unique container name
    local container_name="${network}-hetero-${impl}"

    # Remove any stale container with same name
    docker rm -f "$container_name" >/dev/null 2>&1 || true

    echo "[$log_tag] Launching $impl ($image) as $alias..."

    # Build broker-specific run command
    local run_cmd=""
    case "$impl" in
      nanomq)
        run_cmd="nanomq start --conf /etc/nanomq.conf 2>/dev/null || nanomq start 2>/dev/null || nanomq broker start"
        ;;
      emqx)
        run_cmd="emqx foreground"
        ;;
      vernemq)
        # VerneMQ needs DOCKER_VERNEMQ_ACCEPT_EULA
        run_cmd="vernemq start && tail -f /dev/null"
        ;;
      hivemq)
        run_cmd="/opt/hivemq/bin/run.sh"
        ;;
      flashmq)
        run_cmd="flashmq"
        ;;
      mosquitto-ref)
        run_cmd="mosquitto -c /mosquitto/config/mosquitto.conf"
        ;;
      *)
        run_cmd="sleep infinity"
        ;;
    esac

    # Broker-specific env vars
    local extra_env=""
    case "$impl" in
      vernemq)
        extra_env="-e DOCKER_VERNEMQ_ACCEPT_EULA=yes -e DOCKER_VERNEMQ_ALLOW_ANONYMOUS=on"
        ;;
      emqx)
        extra_env="-e EMQX_ALLOW_ANONYMOUS=true -e EMQX_LISTENER__TCP__EXTERNAL=0.0.0.0:1883"
        ;;
      nanomq)
        extra_env="-e NANOMQ_BROKER_URL=nmq-tcp://0.0.0.0:1883"
        ;;
    esac

    local cid
    cid=$(docker run -d \
      --cpus="$_MQTT_HETERO_CPUS" \
      --memory="$_MQTT_HETERO_MEM" \
      --network "$network" \
      --name "$container_name" \
      --hostname "$alias" \
      --network-alias "$alias" \
      --restart=unless-stopped \
      $extra_env \
      "$image" \
      sh -c "$run_cmd" 2>&1)

    if [[ $? -ne 0 ]]; then
      echo "[$log_tag] WARN: failed to launch $impl: $cid"
      continue
    fi

    _MQTT_HETERO_CIDS+=("$cid")
    csv_parts+=("${impl}@tcp://${alias}/1883")
    echo "[$log_tag] Started $impl → ${cid:0:12}"
  done

  # Wait for all brokers to be ready
  local ready_count=0
  for i in "${!_MQTT_HETERO_CIDS[@]}"; do
    local cid="${_MQTT_HETERO_CIDS[$i]}"
    IFS=':' read -r impl _ _ alias <<< "${broker_defs[$i]}"

    if _mqtt_hetero_wait_port "$cid" 1883 "$_MQTT_HETERO_STARTUP_TIMEOUT"; then
      echo "[$log_tag] ✓ $impl ready on ${alias}:1883"
      ready_count=$((ready_count + 1))
    else
      echo "[$log_tag] WARN: $impl not ready after ${_MQTT_HETERO_STARTUP_TIMEOUT}s (keeping container for retry)"
    fi
  done

  MQTT_HETERO_BROKER_CSV="$(IFS=','; echo "${csv_parts[*]}")"
  MQTT_HETERO_CONTAINERS="${_MQTT_HETERO_CIDS[*]}"

  echo "[$log_tag] Heterogeneous cluster: ${ready_count}/${#_MQTT_HETERO_CIDS[@]} brokers ready"
  echo "[$log_tag] MQTT_HETERO_BROKER_CSV=$MQTT_HETERO_BROKER_CSV"

  return 0
}

# Stop and remove all heterogeneous broker containers.
mqtt_hetero_cleanup() {
  for cid in "${_MQTT_HETERO_CIDS[@]}"; do
    docker rm -f "$cid" >/dev/null 2>&1 || true
  done
  _MQTT_HETERO_CIDS=()
  MQTT_HETERO_BROKER_CSV=""
  MQTT_HETERO_CONTAINERS=""
}
