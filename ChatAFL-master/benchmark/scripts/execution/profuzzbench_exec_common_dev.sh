#!/bin/bash

DOCIMAGE=$1   #name of the docker image
RUNS=$2       #number of runs
SAVETO=$3     #path to folder keeping the results

FUZZER=$4     #fuzzer name (e.g., aflnet) -- this name must match the name of the fuzzer folder inside the Docker container
OUTDIR=$5     #name of the output folder created inside the docker container
OPTIONS=$6    #all configured options for fuzzing
TIMEOUT=$7    #time for fuzzing
SKIPCOUNT=$8  #used for calculating coverage over time. e.g., SKIPCOUNT=5 means we run gcovr after every 5 test cases
DELETE=$9

WORKDIR="/home/ubuntu/experiments"

RESULT_OWNER="${SUDO_USER:-$USER}"
RESULT_GROUP="$(id -gn "${RESULT_OWNER}")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECOVERY_HELPER="${SCRIPT_DIR}/recover_result_archives.sh"
WATCHDOG_HELPER="${SCRIPT_DIR}/fuzz_stall_watchdog.sh"
RESULT_MANIFEST="${SAVETO}/.result_manifest.tsv"
STATUS_DIR="${SAVETO}/.sample_status"
FORENSICS_DIR="${SAVETO}/.forensics"
COLLECTION_DONE=0
CLEANUP_DONE=0
RUN_COMPLETED=0
WATCHDOG_DONE=0

fix_result_permissions() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  chown -R "${RESULT_OWNER}:${RESULT_GROUP}" "$path"
  chmod -R u+rwX "$path"
}

init_result_manifest() {
  mkdir -p "${SAVETO}"
  if [[ ! -f "$RESULT_MANIFEST" ]]; then
    printf 'run\tcontainer_id\tcontainer_name\timage\tfuzzer\toutdir\tarchive_name\n' > "$RESULT_MANIFEST"
  fi
  fix_result_permissions "$SAVETO"
}

append_result_manifest() {
  local run_index="$1"
  local container_id="$2"
  local container_name="${3:--}"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$run_index" "$container_id" "$container_name" "$DOCIMAGE" "$FUZZER" "$OUTDIR" "${OUTDIR}_${run_index}.tar.gz" >> "$RESULT_MANIFEST"
}

sample_status_file() {
  local archive_name="$1"
  printf '%s/%s.status' "$STATUS_DIR" "$archive_name"
}

init_sample_status_dir() {
  mkdir -p "$STATUS_DIR" "$FORENSICS_DIR"
  fix_result_permissions "$STATUS_DIR"
  fix_result_permissions "$FORENSICS_DIR"
}

write_sample_status() {
  local archive_name="$1"
  shift
  local status_file
  local tmp_file

  status_file="$(sample_status_file "$archive_name")"
  tmp_file="${status_file}.tmp"

  {
    printf 'archive_name=%s\n' "$archive_name"
    for kv in "$@"; do
      printf '%s\n' "$kv"
    done
  } > "$tmp_file"

  mv "$tmp_file" "$status_file"
  fix_result_permissions "$status_file"
}

read_sample_status_value() {
  local archive_name="$1"
  local key="$2"
  local status_file

  status_file="$(sample_status_file "$archive_name")"
  [[ -f "$status_file" ]] || return 0
  awk -F'=' -v want="$key" '$1 == want { print substr($0, index($0, "=") + 1); exit }' "$status_file"
}

mark_completed_samples() {
  local idx archive_name container_id current_status exit_code

  for idx in "${!cids[@]}"; do
    archive_name="${archive_names[$idx]}"
    container_id="${cids[$idx]}"
    current_status="$(read_sample_status_value "$archive_name" status)"

    if [[ -z "$current_status" || "$current_status" == "running" ]]; then
      exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$container_id" 2>/dev/null || true)"
      write_sample_status "$archive_name" \
        "container_id=${container_id}" \
        "status=completed" \
        "reason=completed" \
        "finished_at=$(date -Iseconds)" \
        "exit_code=${exit_code}"
    fi
  done
}

cleanup_watchdogs() {
  local pid

  if [[ $WATCHDOG_DONE -eq 1 ]]; then
    return 0
  fi
  WATCHDOG_DONE=1

  for pid in "${watchdog_pids[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done

  for pid in "${watchdog_pids[@]}"; do
    wait "$pid" >/dev/null 2>&1 || true
  done
}

launch_watchdog() {
  local container_id="$1"
  local archive_name="$2"

  if [[ "${CHATAFL_ENABLE_WATCHDOG:-0}" != "1" ]]; then
    return 0
  fi

  if [[ ! -x "$WATCHDOG_HELPER" ]]; then
    if [[ -f "$WATCHDOG_HELPER" ]]; then
      chmod +x "$WATCHDOG_HELPER" >/dev/null 2>&1 || true
    fi
  fi

  if [[ -x "$WATCHDOG_HELPER" ]]; then
    bash "$WATCHDOG_HELPER" \
      "$container_id" \
      "$WORKDIR" \
      "$OUTDIR" \
      "$SAVETO" \
      "$archive_name" \
      "$LOG_TAG" &
    watchdog_pids+=("$!")
  else
    printf "\n%s: [WARN] Watchdog helper not executable: %s\n" "$LOG_TAG" "$WATCHDOG_HELPER"
  fi
}

generate_run_summary() {
  local results_dir="$1"
  local summary_py="${SCRIPT_DIR}/../analysis/run_summary.py"
  local output_file="$(cd "$results_dir" 2>/dev/null && pwd)/run_summary.csv"

  if [[ ! -f "$summary_py" ]]; then
    printf "\n${LOG_TAG}: [WARN] run_summary.py not found at %s, skipping summary generation\n" "$summary_py"
    return 0
  fi

  local tarball_count
  tarball_count=$(find "$results_dir" -maxdepth 1 -name '*.tar.gz' 2>/dev/null | wc -l)
  if [[ $tarball_count -eq 0 ]]; then
    printf "\n${LOG_TAG}: [WARN] No tarballs found in %s, skipping summary generation\n" "$results_dir"
    return 0
  fi

  local timeout_min=$(( TIMEOUT / 60 ))
  printf "\n${LOG_TAG}: Generating run_summary.csv (%d tarballs, timeout=%d min)...\n" "$tarball_count" "$timeout_min"
  if python3 "$summary_py" "$results_dir" -o "$output_file" --timeout-min "$timeout_min" 2>&1; then
    fix_result_permissions "$output_file"
    printf "${LOG_TAG}: ✓ run_summary.csv written to %s\n" "$output_file"
  else
    printf "${LOG_TAG}: [WARN] run_summary.py exited with error; summary may be incomplete\n"
  fi
}

collect_results_with_recovery() {
  local helper_status=0
  local delete_flag=""

  if [[ $COLLECTION_DONE -eq 1 ]]; then
    return 0
  fi
  COLLECTION_DONE=1

  printf "\n${LOG_TAG}: Collecting results and save them to ${SAVETO}"
  mkdir -p "${SAVETO}"
  fix_result_permissions "${SAVETO}"

  if [[ $RUN_COMPLETED -eq 1 && -n "$DELETE" ]]; then
    delete_flag="--delete"
  fi

  if [[ -f "$RESULT_MANIFEST" && -f "$RECOVERY_HELPER" ]]; then
    bash "$RECOVERY_HELPER" "$SAVETO" ${delete_flag:+$delete_flag}
    helper_status=$?
    if [[ $helper_status -ne 0 ]]; then
      printf "\n${LOG_TAG}: [WARN] Recovery helper reported missing outputs; containers are kept for manual inspection"
    fi
  else
    printf "\n${LOG_TAG}: [WARN] Recovery helper or manifest missing; skipping result collection"
  fi

  fix_result_permissions "${SAVETO}"
  return 0
}

cleanup_mqtt_resources() {
  if [[ $CLEANUP_DONE -eq 1 ]]; then
    return 0
  fi
  CLEANUP_DONE=1

  if [[ -n "$MQTT_AUTO_NETWORK" ]]; then
    if [[ -n "${MQTT_STABLE_CONTAINER:-}" ]]; then
      printf "\n${LOG_TAG}: Stopping stable reference broker...\n"
      docker rm -f "$MQTT_STABLE_CONTAINER" >/dev/null 2>&1 || true
    fi
    # B3: Also clean up multi-broker fleet container
    if [[ -n "${MQTT_MULTI_CONTAINER:-}" ]]; then
      printf "${LOG_TAG}: Stopping multi-broker fleet...\n"
      docker rm -f "$MQTT_MULTI_CONTAINER" >/dev/null 2>&1 || true
    fi
    # P0: Clean up heterogeneous broker containers
    if [[ ${#HETERO_CONTAINERS[@]} -gt 0 ]]; then
      printf "${LOG_TAG}: Stopping heterogeneous brokers...\n"
      for _hc in "${HETERO_CONTAINERS[@]}"; do
        docker rm -f "$_hc" >/dev/null 2>&1 || true
      done
    fi
    # Force-disconnect any remaining containers from the network before removal
    for _cid in $(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$MQTT_AUTO_NETWORK" 2>/dev/null); do
      docker network disconnect -f "$MQTT_AUTO_NETWORK" "$_cid" >/dev/null 2>&1 || true
    done
    docker network rm "$MQTT_AUTO_NETWORK" >/dev/null 2>&1 || true
    if docker network inspect "$MQTT_AUTO_NETWORK" >/dev/null 2>&1; then
      printf "${LOG_TAG}: [WARN] Network %s still exists, retrying after container removal...\n" "$MQTT_AUTO_NETWORK"
    fi
  fi
}

on_exit() {
  # If containers are still running (e.g. Ctrl+C during docker wait),
  # wait for them to finish so cov_script completes and tar includes cov_over_time.csv.
  if [[ $RUN_COMPLETED -eq 0 && ${#cids[@]} -gt 0 ]]; then
    printf "\n${LOG_TAG}: [TRAP] Interrupted – waiting for containers to finish (cov_script must complete)...\n"
    printf "${LOG_TAG}: [TRAP] Press Ctrl+C again to force-collect without waiting.\n"
    local _force_collected=0
    trap '_force_collected=1; printf "\n${LOG_TAG}: [TRAP] Force-collecting now (data may be incomplete)...\n"' INT
    for id in "${cids[@]}"; do
      [[ $_force_collected -eq 1 ]] && break
      docker wait "$id" >/dev/null 2>&1 || true
    done
    if [[ $_force_collected -eq 0 ]]; then
      RUN_COMPLETED=1
    else
      # Force-collected: containers may still be running.
      # Allow COLLECTION_DONE to be reset so recovery can re-run later.
      printf "${LOG_TAG}: [TRAP] Containers may still be running – collected archives may be incomplete.\n"
      printf "${LOG_TAG}: [TRAP] After containers finish, re-run: bash %s %s\n" "$RECOVERY_HELPER" "$SAVETO"
    fi
    trap '' INT
  fi
  if [[ $RUN_COMPLETED -eq 1 ]]; then
    mark_completed_samples
  fi
  cleanup_watchdogs
  collect_results_with_recovery
  # Remove fuzzer containers before network cleanup
  for id in "${cids[@]}"; do
    docker rm -f "$id" >/dev/null 2>&1 || true
  done
  cleanup_mqtt_resources
  # Final safety net for network
  if [[ -n "${MQTT_AUTO_NETWORK:-}" ]] && docker network inspect "$MQTT_AUTO_NETWORK" >/dev/null 2>&1; then
    docker network rm "$MQTT_AUTO_NETWORK" >/dev/null 2>&1 || true
  fi
  generate_run_summary "${SAVETO}" || true
}

trap on_exit EXIT INT TERM
cids=()
archive_names=()
watchdog_pids=()

# 获取项目根目录
PROJECT_ROOT="${PROJECT_ROOT:-$PWD/../..}"

# Log tag: FUZZER(target) e.g. loopfuzz(bftpd)
LOG_TAG="${FUZZER^^}(${DOCIMAGE})"

init_result_manifest
init_sample_status_dir

is_mqtt_target() {
  case "$1" in
    mosquitto|mosquitto-v2.0.18|mosquitto-v2.1.2) return 0 ;;
    *) return 1 ;;
  esac
}

sanitize_docker_name() {
  local name
  name=$(echo "$1" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9_.-' '-')
  name=$(echo "$name" | sed 's/^-*//; s/-*$//')
  if [[ -z "$name" ]]; then
    name="mqtt-auto"
  fi
  echo "$name"
}

docker_name_hash() {
  local value="$1"
  if command -v sha1sum >/dev/null 2>&1; then
    printf '%s' "$value" | sha1sum | awk '{print substr($1, 1, 12)}'
  elif command -v md5sum >/dev/null 2>&1; then
    printf '%s' "$value" | md5sum | awk '{print substr($1, 1, 12)}'
  else
    printf '%s' "$value" | cksum | awk '{print $1}'
  fi
}

build_unique_docker_name() {
  local raw_name="$1"
  local max_len="${2:-63}"
  local sanitized hash suffix keep_len base

  sanitized=$(sanitize_docker_name "$raw_name")
  hash=$(docker_name_hash "$sanitized")
  suffix="-${hash}"
  keep_len=$((max_len - ${#suffix}))
  if (( keep_len < 1 )); then
    printf '%s' "${hash:0:max_len}"
    return 0
  fi

  base="${sanitized:0:keep_len}"
  base=$(echo "$base" | sed 's/-*$//')
  if [[ -z "$base" ]]; then
    base="mqtt-auto"
  fi

  printf '%s%s' "$base" "$suffix"
}

remove_existing_named_container() {
  local container_name="$1"
  [[ -n "$container_name" ]] || return 0

  if docker container inspect "$container_name" >/dev/null 2>&1; then
    printf "\n${LOG_TAG}: [DEV] Removing stale container with exact name: %s\n" "$container_name"
    docker rm -f "$container_name" >/dev/null 2>&1 || return 1
  fi

  return 0
}

recreate_named_network() {
  local network_name="$1"
  local err_file
  [[ -n "$network_name" ]] || return 1

  if docker network inspect "$network_name" >/dev/null 2>&1; then
    printf "\n${LOG_TAG}: [DEV] Removing stale network with exact name: %s\n" "$network_name"
    docker network rm "$network_name" >/dev/null 2>&1 || return 1
  fi

  err_file=$(mktemp)
  if docker network create "$network_name" >/dev/null 2>"$err_file"; then
    rm -f "$err_file"
    return 0
  fi

  if grep -q 'available, non-overlapping IPv4 address pool' "$err_file" 2>/dev/null; then
    printf "\n${LOG_TAG}: [DEV] Docker bridge address pool exhausted, pruning unused loopfuzz-mqtt-* networks...\n" >&2
    while IFS= read -r stale_network; do
      [[ -n "$stale_network" ]] || continue
      if [[ "$(docker network inspect --format '{{len .Containers}}' "$stale_network" 2>/dev/null || echo 1)" == "0" ]]; then
        docker network rm "$stale_network" >/dev/null 2>&1 || true
      fi
    done < <(docker network ls --format '{{.Name}}' | grep '^loopfuzz-mqtt-' || true)

    if docker network create "$network_name" >/dev/null 2>"$err_file"; then
      rm -f "$err_file"
      return 0
    fi

    # ── 3rd attempt: fall back to 10.0.0.0/8 with explicit --subnet ──
    # Docker's default pool (172.16.0.0/12 → 192.168.0.0/16) is exhausted
    # and prune found zero empty networks to recycle.  Pick a random /16
    # from 10.0.0.0/8 (RFC 1918, 16M+ addresses) to keep existing
    # containers untouched — no Docker daemon restart required.
    if grep -q 'available, non-overlapping IPv4 address pool' "$err_file" 2>/dev/null; then
      printf "\n${LOG_TAG}: [DEV] Address pool still exhausted after prune, falling back to 10.0.0.0/8...\n" >&2
      local _existing_subnets _second_octet _subnet _fallback_attempt _fallback_ok
      _existing_subnets="$(docker network ls -q 2>/dev/null | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null | grep -v '^$' | sort || true)"
      _fallback_attempt=0
      _fallback_ok=0
      while [[ $_fallback_attempt -lt 20 ]]; do
        _second_octet=$(( RANDOM % 256 ))
        _subnet="10.${_second_octet}.0.0/16"
        if echo "$_existing_subnets" | grep -qFx "$_subnet" 2>/dev/null; then
          _fallback_attempt=$((_fallback_attempt + 1))
          continue
        fi
        if docker network create --subnet="$_subnet" "$network_name" >/dev/null 2>"$err_file"; then
          printf "${LOG_TAG}: [DEV] Created network %s with fallback subnet %s\n" "$network_name" "$_subnet"
          _fallback_ok=1
          break
        fi
        _fallback_attempt=$((_fallback_attempt + 1))
      done
      if [[ $_fallback_ok -eq 1 ]]; then
        rm -f "$err_file"
        return 0
      fi
      printf "${LOG_TAG}: [DEV] Fallback subnet allocation also failed after %d attempts\n" "$_fallback_attempt" >&2
    fi
  fi

  printf "\n${LOG_TAG}: [ERROR] docker network create %s failed: %s\n" "$network_name" "$(tr '\n' ' ' < "$err_file")" >&2
  rm -f "$err_file"
  return 1
}

require_container_id() {
  local container_id="$1"
  local context="$2"

  if [[ -z "$container_id" ]] || [[ ! "$container_id" =~ ^[a-f0-9]{12,64}$ ]]; then
    printf "\n${LOG_TAG}: [ERROR] Failed to start %s\n" "$context" >&2
    exit 1
  fi
}

# Subject directory mapping: docker image name → host subject directory
# Volume mount run.sh，改宿主机的 run.sh / cov_script.sh 不用重建镜像
get_subject_dir() {
    local target=$1
    local base="${PROJECT_ROOT}/benchmark/subjects"
    case "$target" in
        lightftp)      echo "${base}/FTP/LightFTP" ;;
        bftpd)         echo "${base}/FTP/BFTPD" ;;
        proftpd)       echo "${base}/FTP/ProFTPD" ;;
        pure-ftpd)     echo "${base}/FTP/PureFTPD" ;;
        exim)          echo "${base}/SMTP/Exim" ;;
        live555)       echo "${base}/RTSP/Live555" ;;
        kamailio)      echo "${base}/SIP/Kamailio" ;;
        forked-daapd)  echo "${base}/DAAP/forked-daapd" ;;
        lighttpd1)     echo "${base}/HTTP/Lighttpd1" ;;
        mosquitto)     echo "${base}/MQTT/Mosquitto" ;;
      mosquitto-v2.0.18) echo "${base}/MQTT/Mosquitto-v2.0.18" ;;
      mosquitto-v2.1.2) echo "${base}/MQTT/Mosquitto-v2.1.2" ;;
        *) echo "" ;;
    esac
}

SUBJECT_DIR=$(get_subject_dir "$DOCIMAGE")
if [[ -n "$SUBJECT_DIR" ]] && [[ -d "$SUBJECT_DIR" ]]; then
    printf "\n${LOG_TAG}: [DEV] Subject dir mounted: ${SUBJECT_DIR}\n"
    SUBJECT_MOUNT="-v ${SUBJECT_DIR}:/tmp/subject-src:ro"
    SUBJECT_COPY="cp -f /tmp/subject-src/run.sh ${WORKDIR}/run && chmod +x ${WORKDIR}/run && "
    if is_mqtt_target "$DOCIMAGE" && [[ -f "${SUBJECT_DIR}/mosquitto.conf" ]]; then
      SUBJECT_COPY+="cp -f /tmp/subject-src/mosquitto.conf ${WORKDIR}/mosquitto.conf && "
    fi
else
    printf "\n${LOG_TAG}: [WARN] No subject dir for ${DOCIMAGE}, using image-embedded run.sh\n"
    SUBJECT_MOUNT=""
    SUBJECT_COPY=""
fi

MQTT_AUTO_NETWORK=""
MQTT_AUTO_BROKER_LIST=""
MQTT_STABLE_CONTAINER=""
MQTT_STABLE_ALIAS=""
MQTT_STABLE_ALIAS_HASH=""
MQTT_MULTI_CONTAINER=""
MQTT_MULTI_ALIAS=""
declare -a MQTT_AUTO_CONTAINER_NAMES=()
declare -a MQTT_AUTO_BROKER_ALIASES=()

if [[ -z "${CHATAFL_MQTT_BROKERS:-}" ]] && is_mqtt_target "$DOCIMAGE"; then
  MQTT_AUTO_NETWORK="$(build_unique_docker_name "loopfuzz-mqtt-${DOCIMAGE}-${FUZZER}-${TIMESTAMP:-manual}-${$}")"
  if ! recreate_named_network "$MQTT_AUTO_NETWORK"; then
    echo "[ERROR] Failed to create MQTT auto network: ${MQTT_AUTO_NETWORK}"
    exit 1
  fi

  for idx in $(seq 1 "$RUNS"); do
    auto_container_name="${MQTT_AUTO_NETWORK}-broker-${idx}"
    auto_broker_alias="mqttb${idx}"
    MQTT_AUTO_CONTAINER_NAMES+=("$auto_container_name")
    MQTT_AUTO_BROKER_ALIASES+=("$auto_broker_alias")
  done

  # ── Launch a stable (non-fuzzed) reference broker for differential testing ──
  # Each fuzzer container's mosquitto is killed/restarted ~6/sec by afl-fuzz,
  # making cross-container differential probes fail >99% of the time.
  # A dedicated stable broker solves this: fuzzer compares its own fuzzed
  # mosquitto against the stable reference to detect behavioural divergence.
  MQTT_STABLE_CONTAINER="${MQTT_AUTO_NETWORK}-stable"
  MQTT_STABLE_ALIAS_HASH="$(docker_name_hash "${MQTT_AUTO_NETWORK}-stable-alias")"
  MQTT_STABLE_ALIAS="mqtt-stable-${MQTT_STABLE_ALIAS_HASH:0:8}"
  printf "\n${LOG_TAG}: [DEV] Launching stable reference broker (%s)...\n" "$MQTT_STABLE_ALIAS"
  remove_existing_named_container "$MQTT_STABLE_CONTAINER" || {
    echo "[ERROR] Failed to remove stale MQTT stable container: ${MQTT_STABLE_CONTAINER}"
    exit 1
  }

  stable_id=$(docker run --cpus=0.5 --memory=256m \
    --network "$MQTT_AUTO_NETWORK" \
    --name "$MQTT_STABLE_CONTAINER" \
    --hostname "$MQTT_STABLE_ALIAS" \
    --network-alias "$MQTT_STABLE_ALIAS" \
    --network-alias mqtt-stable \
    --restart=unless-stopped \
    ${SUBJECT_MOUNT} \
    -d "$DOCIMAGE" /bin/bash -c \
    "cat > /tmp/mosquitto-stable.conf <<'STABLE_EOF'
listener 1883 0.0.0.0
allow_anonymous true
max_connections -1
log_type none
persistence false
user root
STABLE_EOF
     exec /home/ubuntu/experiments/mosquitto-gcov/src/mosquitto -c /tmp/mosquitto-stable.conf")
  require_container_id "$stable_id" "MQTT stable broker container ${MQTT_STABLE_CONTAINER}"

  # Wait for stable broker to be ready (up to 30 sec)
  _stable_ok=0
  for _w in $(seq 1 60); do
    if docker exec "$MQTT_STABLE_CONTAINER" bash -c "nc -z 127.0.0.1 1883" 2>/dev/null; then
      _stable_ok=1; break
    fi
    sleep 0.5
  done
  if [[ $_stable_ok -eq 1 ]]; then
    printf "${LOG_TAG}: [DEV] ✓ Stable broker ready on %s:1883\n" "$MQTT_STABLE_ALIAS"
  else
    printf "${LOG_TAG}: [ERROR] Stable broker is not reachable on %s:1883; aborting this run to avoid invalid differential metrics\n" "$MQTT_STABLE_ALIAS"
    exit 1
  fi

  # ── B3: Multi-broker differential fleet (MBFuzzer-style 6-impl support) ──
  # When CHATAFL_MULTI_BROKER=1 and chatafl-multibroker image exists, launch
  # a container running 2 Mosquitto instances (different configs) for differential testing
  # alongside the existing stable reference broker.
  #
  # Architecture:
  #   Entry 0: tcp://127.0.0.1/1883                 (fuzzed broker, AFL fork-server)
  #   Entry 1: mosquitto@tcp://mqtt-stable/1883      (stable reference, same impl)
  #   Entry 2: mosquitto@tcp://multibroker/1883       (Broker A, default config)
  #   Entry 3: mosquitto-b@tcp://multibroker/1884     (Broker B, restricted config)
  #
  # Enable via:  export CHATAFL_MULTI_BROKER=1
  # Build image: cd benchmark/subjects/MQTT/multi-broker && docker build -t chatafl-multibroker .
  MQTT_MULTI_ALIAS=""
  MQTT_MULTI_CONTAINER=""
  if [[ "${CHATAFL_MULTI_BROKER:-0}" == "1" ]] && docker image inspect chatafl-multibroker >/dev/null 2>&1; then
    MQTT_MULTI_CONTAINER="${MQTT_AUTO_NETWORK}-multibroker"
    _multi_hash="$(docker_name_hash "${MQTT_AUTO_NETWORK}-multi-alias")"
    MQTT_MULTI_ALIAS="multibroker-${_multi_hash:0:8}"
    printf "${LOG_TAG}: [DEV] Launching multi-broker fleet (%s)...\n" "$MQTT_MULTI_ALIAS"
    remove_existing_named_container "$MQTT_MULTI_CONTAINER" || true

    multi_id=$(docker run --cpus=1 --memory=1g \
      --network "$MQTT_AUTO_NETWORK" \
      --name "$MQTT_MULTI_CONTAINER" \
      --hostname "$MQTT_MULTI_ALIAS" \
      --network-alias "$MQTT_MULTI_ALIAS" \
      --restart=unless-stopped \
      -d chatafl-multibroker)

    if [[ -n "$multi_id" ]]; then
      # Wait for at least mosquitto (port 1883) to be ready
      _multi_ok=0
      for _w in $(seq 1 30); do
        if docker exec "$MQTT_MULTI_CONTAINER" bash -c "nc -z 127.0.0.1 1883" 2>/dev/null; then
          _multi_ok=1; break
        fi
        sleep 0.5
      done
      if [[ $_multi_ok -eq 1 ]]; then
        printf "${LOG_TAG}: [DEV] ✓ Multi-broker fleet ready on %s:1883-1887\n" "$MQTT_MULTI_ALIAS"
      else
        printf "${LOG_TAG}: [WARN] Multi-broker fleet not ready; continuing with stable-only mode\n"
        docker rm -f "$MQTT_MULTI_CONTAINER" >/dev/null 2>&1 || true
        MQTT_MULTI_ALIAS=""
        MQTT_MULTI_CONTAINER=""
      fi
    else
      MQTT_MULTI_ALIAS=""
      MQTT_MULTI_CONTAINER=""
    fi
  elif [[ "${CHATAFL_MULTI_BROKER:-0}" == "1" ]]; then
    printf "${LOG_TAG}: [WARN] CHATAFL_MULTI_BROKER=1 but chatafl-multibroker image not found.\n"
    printf "${LOG_TAG}: [WARN] Build it: cd benchmark/subjects/MQTT/multi-broker && docker build -t chatafl-multibroker .\n"
  fi

  # ── P0: Heterogeneous broker fleet (NanoMQ, EMQX, VerneMQ) ──
  # Launch lightweight containers from locally available images for
  # cross-implementation differential testing (MBFuzzer-style).
  # Each broker listens on default port 1883 within the Docker network.
  # The fuzzer reaches them via hostname aliases on the shared network.
  HETERO_BROKER_SPECS=""  # will be appended to _brokers
  HETERO_CONTAINERS=()    # for cleanup tracking

  # _launch_hetero_broker IMAGE NAME ALIAS PORT CMD EXTRA_DOCKER_ARGS TIMEOUT_SEC
  _launch_hetero_broker() {
    local _img="$1" _name="$2" _alias="$3" _port="${4:-1883}" _cmd="$5"
    local _extra_args="$6" _timeout="${7:-60}"
    local _cname="${MQTT_AUTO_NETWORK}-${_name}"
    local _iters=$(( _timeout * 2 ))   # sleep 0.5 per iter
    if ! docker image inspect "$_img" >/dev/null 2>&1; then
      printf "${LOG_TAG}: [P0] Image %s not found, skipping %s\n" "$_img" "$_name"
      return 1
    fi
    remove_existing_named_container "$_cname" 2>/dev/null || true
    local _hid _mem="256m"
    # Heavy brokers get more memory
    case "$_name" in emqx|hivemq) _mem="512m";; vernemq) _mem="384m";; esac
    _hid=$(docker run --cpus=0.5 --memory="$_mem" \
      --network "$MQTT_AUTO_NETWORK" \
      --name "$_cname" \
      --hostname "$_alias" \
      --network-alias "$_alias" \
      --restart=unless-stopped \
      $_extra_args \
      -d "$_img" $_cmd 2>/dev/null)
    if [[ -z "$_hid" ]]; then
      printf "${LOG_TAG}: [P0] Failed to start %s\n" "$_name"
      return 1
    fi
    # Wait for port ready with multiple probe strategies
    local _ok=0
    # Brief initial wait for container init to accept exec (esp. Java-based brokers)
    sleep 2
    for _w in $(seq 1 "$_iters"); do
      # Strategy 1: bash /dev/tcp (built-in, no extra package needed)
      if docker exec "$_cname" bash -c "echo >/dev/tcp/127.0.0.1/$_port" 2>/dev/null; then
        _ok=1; break
      fi
      # Strategy 2: nc -z (works if netcat installed)
      if docker exec "$_cname" sh -c "nc -z 127.0.0.1 $_port" 2>/dev/null; then
        _ok=1; break
      fi
      # Progress every 30s
      if (( _w % 60 == 0 )); then
        printf "${LOG_TAG}: [P0] %s still starting... (%ds/%ds)\n" "$_name" $(( (_w+4)/2 )) "$_timeout"
      fi
      sleep 0.5
    done
    if [[ $_ok -eq 1 ]]; then
      printf "${LOG_TAG}: [P0] ✓ %s ready on %s:%s (took ~%ds)\n" "$_name" "$_alias" "$_port" $((_w/2))
      HETERO_CONTAINERS+=("$_cname")
      HETERO_BROKER_SPECS="${HETERO_BROKER_SPECS},${_name}@tcp://${_alias}/${_port}"
      return 0
    else
      printf "${LOG_TAG}: [P0] %s not ready after %ds, removing\n" "$_name" "$_timeout"
      docker rm -f "$_cname" >/dev/null 2>&1 || true
      return 1
    fi
  }

  # Launch available heterogeneous brokers (EXACT match with MBFuzzer's 6 implementations)
  # MBFuzzer refs: Mosquitto=v2.0.18, NanoMQ=236c9c5, EMQX=v5.6.0, FlashMQ=d82cba5, VerneMQ=f0e6dc15, HiveMQ=v4.24.0
  # All images are built locally from benchmark/scripts/execution/dockerfiles/
  # Build with:  for d in nanomq emqx flashmq vernemq hivemq; do
  #                docker build -t chatafl-${d}:<tag> benchmark/scripts/execution/dockerfiles/${d}/
  #              done
  # ABLATION: set CHATAFL_NO_HETERO_BROKERS=1 to skip hetero fleet (saves ~2 GB/group).
  # In parallel ablation runs, 6× hetero fleets cause kernel-level OOM from memory overcommit.
  if [[ "${CHATAFL_NO_HETERO_BROKERS:-0}" != "1" ]]; then
  # 1. NanoMQ — MBFuzzer git:236c9c5; built from source at exact commit
  _launch_hetero_broker "chatafl-nanomq:236c9c5" "nanomq" "mqtt-nanomq" "1883" "" "" "60"
  # 2. EMQX — MBFuzzer v5.6.0; wrapper around emqx/emqx:5.6.0 with anonymous auth
  _launch_hetero_broker "chatafl-emqx:5.6.0" "emqx" "mqtt-emqx" "1883" "" "" "180"
  # 3. FlashMQ — MBFuzzer git:d82cba5 (v1.12.1); built from synced source
  _launch_hetero_broker "chatafl-flashmq:d82cba5" "flashmq" "mqtt-flashmq" "1883" "" "" "60"
  # 4. VerneMQ — MBFuzzer EXACT: 2.0.0-rc1-5-gf0e6dc15 (extracted from LFS tarball)
  _launch_hetero_broker "chatafl-vernemq:f0e6dc15" "vernemq" "mqtt-vernemq" "1883" "" \
    "-e DOCKER_VERNEMQ_ALLOW_ANONYMOUS=on -e DOCKER_VERNEMQ_ACCEPT_EULA=yes" "180"
  # 5. HiveMQ — MBFuzzer v4.24.0 Enterprise; wrapper around hivemq/hivemq4:4.24.0
  _launch_hetero_broker "chatafl-hivemq:4.24.0" "hivemq" "mqtt-hivemq" "1883" "" "" "180"
  fi
  # (6th = Mosquitto itself, the SUT, already running as the primary target)

  if [[ ${#HETERO_CONTAINERS[@]} -gt 0 ]]; then
    printf "${LOG_TAG}: [P0] Heterogeneous fleet: %d brokers launched\n" "${#HETERO_CONTAINERS[@]}"
  fi

  printf "${LOG_TAG}: [DEV] MQTT auto network: %s\n" "$MQTT_AUTO_NETWORK"
  if [[ -n "$MQTT_MULTI_ALIAS" ]]; then
    printf "${LOG_TAG}: [DEV] Architecture: each fuzzer → tcp://<self>/1883 + tcp://%s/1883 + broker-b on %s:1884%s\n" "$MQTT_STABLE_ALIAS" "$MQTT_MULTI_ALIAS" "$HETERO_BROKER_SPECS"
  else
    printf "${LOG_TAG}: [DEV] Architecture: each fuzzer → tcp://<self>/1883 + tcp://%s/1883%s\n" "$MQTT_STABLE_ALIAS" "$HETERO_BROKER_SPECS"
  fi
fi

#keep all container ids
cids=()

DIAG_PTRACE_FLAGS=""
if [[ "${CHATAFL_ENABLE_DIAG_PTRACE:-1}" == "1" ]]; then
  DIAG_PTRACE_FLAGS=" --cap-add SYS_PTRACE --security-opt seccomp=unconfined"
fi


short_container_id() {
  local container_id="$1"
  printf '%s' "${container_id:0:12}"
}

#create one container for each run
for i in $(seq 1 $RUNS); do
  run_index=$((i-1))
  archive_name="${OUTDIR}_${i}.tar.gz"
  container_name=""
  MQTT_RUN_FLAGS=""
  if [[ -n "$MQTT_AUTO_NETWORK" ]] && [[ ${#MQTT_AUTO_CONTAINER_NAMES[@]} -gt $run_index ]]; then
    remove_existing_named_container "${MQTT_AUTO_CONTAINER_NAMES[$run_index]}" || {
      echo "[ERROR] Failed to remove stale MQTT broker container: ${MQTT_AUTO_CONTAINER_NAMES[$run_index]}"
      exit 1
    }
    MQTT_RUN_FLAGS=" --network ${MQTT_AUTO_NETWORK} --name ${MQTT_AUTO_CONTAINER_NAMES[$run_index]} --hostname ${MQTT_AUTO_BROKER_ALIASES[$run_index]} --network-alias ${MQTT_AUTO_BROKER_ALIASES[$run_index]}"
    container_name="${MQTT_AUTO_CONTAINER_NAMES[$run_index]}"
  fi

  # Build ablation env-var flags for loopfuzz containers.
  # If the host exports CHATAFL_NO_REFINEMENT / NO_FRONTIER / NO_ADAPTIVE
  # / NO_STATE_PROMPT / ABLATION_THRESHOLD / CHATAFL_HYPOTHESIS,
  # they are forwarded into the container via -e.
  # Docker's -e follows last-value-wins: if CHATAFL_HYPOTHESIS is passed
  # here, it overrides the hardcoded -e CHATAFL_HYPOTHESIS=1 below.
  ABLATION_FLAGS=""
  [[ -n "${CHATAFL_HYPOTHESIS:-}" ]]       && ABLATION_FLAGS+=" -e CHATAFL_HYPOTHESIS=${CHATAFL_HYPOTHESIS}"
  [[ -n "${CHATAFL_NO_REFINEMENT}" ]]      && ABLATION_FLAGS+=" -e CHATAFL_NO_REFINEMENT=1"
  [[ -n "${CHATAFL_NO_FRONTIER}" ]]        && ABLATION_FLAGS+=" -e CHATAFL_NO_FRONTIER=1"
  [[ -n "${CHATAFL_NO_ADAPTIVE}" ]]        && ABLATION_FLAGS+=" -e CHATAFL_NO_ADAPTIVE=1"
  [[ -n "${CHATAFL_NO_STATE_PROMPT}" ]]    && ABLATION_FLAGS+=" -e CHATAFL_NO_STATE_PROMPT=1"
  [[ -n "${CHATAFL_NO_ADMISSION}" ]]       && ABLATION_FLAGS+=" -e CHATAFL_NO_ADMISSION=1"
  [[ -n "${CHATAFL_ADMISSION_LOG}" ]]      && ABLATION_FLAGS+=" -e CHATAFL_ADMISSION_LOG=${CHATAFL_ADMISSION_LOG}"
  [[ -n "${CHATAFL_ABLATION_THRESHOLD}" ]] && ABLATION_FLAGS+=" -e CHATAFL_ABLATION_THRESHOLD=${CHATAFL_ABLATION_THRESHOLD}"

  TOKEN_FLAGS=""
  [[ -n "${CHATAFL_MAX_TOKENS:-}" ]]       && TOKEN_FLAGS+=" -e CHATAFL_MAX_TOKENS=${CHATAFL_MAX_TOKENS}"

  # Per-container MQTT broker list: local broker + stable reference + multi-broker fleet
  MQTT_FLAGS=""
  if [[ -n "${MQTT_STABLE_ALIAS:-}" ]] && [[ -n "$MQTT_AUTO_NETWORK" ]]; then
    _brokers="tcp://127.0.0.1/1883,mosquitto@tcp://${MQTT_STABLE_ALIAS}/1883"
    # B3: Append multi-broker fleet endpoints when available
    if [[ -n "${MQTT_MULTI_ALIAS:-}" ]]; then
      _brokers="${_brokers},mosquitto@tcp://${MQTT_MULTI_ALIAS}/1883"
      _brokers="${_brokers},mosquitto-b@tcp://${MQTT_MULTI_ALIAS}/1884"
    fi
    # P0: Append heterogeneous broker endpoints
    if [[ -n "${HETERO_BROKER_SPECS:-}" ]]; then
      _brokers="${_brokers}${HETERO_BROKER_SPECS}"
    fi
    MQTT_FLAGS=" -e CHATAFL_MQTT_BROKERS=${_brokers}"
  elif [[ -n "${CHATAFL_MQTT_BROKERS:-}" ]]; then
    MQTT_FLAGS=" -e CHATAFL_MQTT_BROKERS=${CHATAFL_MQTT_BROKERS}"
  fi

  # Enable Grammar Hypothesis system only for loopfuzz
  if [[ "$FUZZER" == "loopfuzz" ]]; then
    # Volume挂载本地代码并在容器内重新编译
	    # --memory: 6g (6 groups × 6g + 6 × 0.25g brokers + 2g overhead ≈ 39.5 GB, safe with 44 GB host)
    # NOTE: 消融并行运行时6组×hetero broker fleet会引发kernel OOM，
    id=$(docker run --cpus=1 --memory=6g --memory-swap=6g \
      ${DIAG_PTRACE_FLAGS} \
      -e KEY="${KEY}" \
      -e LLM_MODEL="${LLM_MODEL:-gpt-5.4-mini}" \
      -e CHATAFL_HYPOTHESIS=1 \
      ${ABLATION_FLAGS} \
      ${TOKEN_FLAGS} \
      ${MQTT_FLAGS} \
      ${MQTT_RUN_FLAGS} \
      -v "${PROJECT_ROOT}/LoopFuzz:/tmp/loopfuzz-src:ro" \
      ${SUBJECT_MOUNT} \
      -d -it $DOCIMAGE /bin/bash -c "\
        ${SUBJECT_COPY}\
        echo '[DEV] Copying and compiling updated code...' && \
        if [ ! -d /home/ubuntu/loopfuzz ]; then cp -a /tmp/loopfuzz-src /home/ubuntu/loopfuzz; fi && \
        cp -f /tmp/loopfuzz-src/*.c /tmp/loopfuzz-src/*.h /tmp/loopfuzz-src/Makefile /home/ubuntu/loopfuzz/ 2>/dev/null || true && \
        cd /home/ubuntu/loopfuzz && make clean && make -j\$(nproc) && \
        echo '[DEV] Compilation complete, MD5: '\$(md5sum grammar-hypothesis.c | cut -d' ' -f1) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}; R=\$?; [ \$R -eq 139 ] && R=0; exit \$R")
  elif [[ "$FUZZER" == "chatafl" ]]; then
    id=$(docker run --cpus=1 --memory=6g --memory-swap=6g \
      ${DIAG_PTRACE_FLAGS} \
      -e KEY="${KEY}" \
      ${TOKEN_FLAGS} \
      ${MQTT_FLAGS} \
      ${MQTT_RUN_FLAGS} \
      -v "${PROJECT_ROOT}/ChatAFL:/tmp/chatafl-src:ro" \
      ${SUBJECT_MOUNT} \
      -d -it $DOCIMAGE /bin/bash -c "\
        ${SUBJECT_COPY}\
        cp -f /tmp/chatafl-src/*.c /tmp/chatafl-src/*.h /home/ubuntu/chatafl/ && \
        cd /home/ubuntu/chatafl && make clean && make -j\$(nproc) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}; R=\$?; [ \$R -eq 139 ] && R=0; exit \$R")
  elif [[ "$FUZZER" == "chatafl-cl1" ]]; then
    id=$(docker run --cpus=1 --memory=6g --memory-swap=6g \
      ${DIAG_PTRACE_FLAGS} \
      -e KEY="${KEY}" \
      ${MQTT_FLAGS} \
      ${MQTT_RUN_FLAGS} \
      -v "${PROJECT_ROOT}/ChatAFL-CL1:/tmp/chatafl-cl1-src:ro" \
      ${SUBJECT_MOUNT} \
      -d -it $DOCIMAGE /bin/bash -c "\
        ${SUBJECT_COPY}\
        cp -f /tmp/chatafl-cl1-src/*.c /tmp/chatafl-cl1-src/*.h /home/ubuntu/chatafl-cl1/ && \
        cd /home/ubuntu/chatafl-cl1 && make clean && make -j\$(nproc) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}; R=\$?; [ \$R -eq 139 ] && R=0; exit \$R")
  elif [[ "$FUZZER" == "chatafl-cl2" ]]; then
    id=$(docker run --cpus=1 --memory=6g --memory-swap=6g \
      ${DIAG_PTRACE_FLAGS} \
      -e KEY="${KEY}" \
      ${MQTT_FLAGS} \
      ${MQTT_RUN_FLAGS} \
      -v "${PROJECT_ROOT}/ChatAFL-CL2:/tmp/chatafl-cl2-src:ro" \
      ${SUBJECT_MOUNT} \
      -d -it $DOCIMAGE /bin/bash -c "\
        ${SUBJECT_COPY}\
        cp -f /tmp/chatafl-cl2-src/*.c /tmp/chatafl-cl2-src/*.h /home/ubuntu/chatafl-cl2/ && \
        cd /home/ubuntu/chatafl-cl2 && make clean && make -j\$(nproc) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}; R=\$?; [ \$R -eq 139 ] && R=0; exit \$R")
  else
    id=$(docker run --cpus=1 --memory=6g --memory-swap=6g ${DIAG_PTRACE_FLAGS} -e KEY="${KEY}" ${TOKEN_FLAGS} ${MQTT_FLAGS} ${MQTT_RUN_FLAGS} ${SUBJECT_MOUNT} -d -it $DOCIMAGE /bin/bash -c "${SUBJECT_COPY}cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}; R=\$?; [ \$R -eq 139 ] && R=0; exit \$R")
  fi
  require_container_id "$id" "fuzz container run #${i}"
  cids+=("$id")
  archive_names+=("$archive_name")
  append_result_manifest "$i" "$id" "$container_name"
  write_sample_status "$archive_name" \
    "container_id=${id}" \
    "status=running" \
    "reason=" \
    "started_at=$(date -Iseconds)"
  launch_watchdog "$id" "$archive_name"
  sleep 5
done

dlist="" #docker list
short_dlist=""
for id in ${cids[@]}; do
  dlist+=" ${id}"
  short_dlist+=" $(short_container_id "$id")"
done

#wait until all these dockers are stopped
printf "\n${LOG_TAG}: Fuzzing in progress ..."
printf "\n${LOG_TAG}: Waiting for the following containers to stop:${short_dlist}"
for id in ${cids[@]}; do
  printf "\n${LOG_TAG}: You can check logs by: docker logs -f %s" "$(short_container_id "$id")"
done
printf "\n${LOG_TAG}: You can stop all containers by: docker stop%s\n" "${short_dlist}"
if [ -n "${dlist}" ]; then
  docker wait ${dlist} > /dev/null
fi
wait
RUN_COMPLETED=1
mark_completed_samples
cleanup_watchdogs

collect_results_with_recovery

# Remove fuzzing containers FIRST (so network can be cleaned)
for id in "${cids[@]}"; do
  docker rm -f "$id" >/dev/null 2>&1 || true
done

# Now clean up MQTT infra (stable broker, hetero brokers, network)
cleanup_mqtt_resources

# Final safety net: if the network somehow survived, force-remove it
if [[ -n "${MQTT_AUTO_NETWORK:-}" ]] && docker network inspect "$MQTT_AUTO_NETWORK" >/dev/null 2>&1; then
  printf "${LOG_TAG}: [CLEANUP] Force-removing residual network %s\n" "$MQTT_AUTO_NETWORK"
  docker network rm "$MQTT_AUTO_NETWORK" >/dev/null 2>&1 || true
fi

printf "\n${LOG_TAG}: I am done!\n"
