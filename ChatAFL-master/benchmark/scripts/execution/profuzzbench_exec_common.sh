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

  if [[ ! -x "$WATCHDOG_HELPER" && -f "$WATCHDOG_HELPER" ]]; then
    chmod +x "$WATCHDOG_HELPER" >/dev/null 2>&1 || true
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

  # P0: Clean up heterogeneous broker containers
  if [[ ${#HETERO_CONTAINERS[@]} -gt 0 ]]; then
    printf "\n${LOG_TAG}: Stopping heterogeneous broker fleet...\n"
    for _hc in "${HETERO_CONTAINERS[@]}"; do
      docker rm -f "$_hc" >/dev/null 2>&1 || true
    done
  fi

  if [[ -n "$MQTT_AUTO_NETWORK" ]]; then
    if [[ -n "${MQTT_STABLE_CONTAINER:-}" ]]; then
      printf "\n${LOG_TAG}: Stopping stable reference broker...\n"
      docker rm -f "$MQTT_STABLE_CONTAINER" >/dev/null 2>&1 || true
    fi
    docker network rm "$MQTT_AUTO_NETWORK" >/dev/null 2>&1 || true
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
  cleanup_mqtt_resources
}

trap on_exit EXIT INT TERM
cids=()
archive_names=()
watchdog_pids=()

# Log tag: FUZZER(target) e.g. loopfuzz(bftpd)
LOG_TAG="${FUZZER^^}(${DOCIMAGE})"

init_result_manifest
init_sample_status_dir

# ── MQTT bridge-mode support (mirrors dev-mode logic) ──
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
  [[ -z "$name" ]] && name="mqtt-auto"
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
    printf "\n${LOG_TAG}: Removing stale container with exact name: %s\n" "$container_name"
    docker rm -f "$container_name" >/dev/null 2>&1 || return 1
  fi

  return 0
}

recreate_named_network() {
  local network_name="$1"
  local err_file
  [[ -n "$network_name" ]] || return 1

  if docker network inspect "$network_name" >/dev/null 2>&1; then
    printf "\n${LOG_TAG}: Removing stale network with exact name: %s\n" "$network_name"
    docker network rm "$network_name" >/dev/null 2>&1 || return 1
  fi

  err_file=$(mktemp)
  if docker network create "$network_name" >/dev/null 2>"$err_file"; then
    rm -f "$err_file"
    return 0
  fi

  if grep -q 'available, non-overlapping IPv4 address pool' "$err_file" 2>/dev/null; then
    printf "\n${LOG_TAG}: Docker bridge address pool exhausted, pruning unused loopfuzz-mqtt-* networks...\n" >&2
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

# ── P0: Heterogeneous broker fleet launcher (sync MBFuzzer's 6 implementations) ──
# _launch_hetero_broker IMAGE NAME ALIAS PORT CMD EXTRA_DOCKER_ARGS TIMEOUT_SEC
_launch_hetero_broker() {
  local _img="$1" _name="$2" _alias="$3" _port="${4:-1883}" _cmd="$5"
  local _extra_args="$6" _timeout="${7:-60}"
  local _cname="${MQTT_AUTO_NETWORK}-${_name}"
  local _iters=$(( _timeout * 2 ))
  if ! docker image inspect "$_img" >/dev/null 2>&1; then
    printf "${LOG_TAG}: [P0] Image %s not found, skipping %s\n" "$_img" "$_name"
    return 1
  fi
  remove_existing_named_container "$_cname" 2>/dev/null || true
  local _hid _mem="256m"
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
  local _ok=0
  # Brief initial wait for container init to accept exec (esp. Java-based brokers)
  sleep 2
  for _w in $(seq 1 "$_iters"); do
    # Strategy 1: bash built-in /dev/tcp (works on most Linux images)
    if docker exec "$_cname" bash -c "echo >/dev/tcp/127.0.0.1/$_port" 2>/dev/null; then
      _ok=1; break
    fi
    # Strategy 2: nc (more portable, fallback)
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

MQTT_AUTO_NETWORK=""
MQTT_STABLE_CONTAINER=""
MQTT_STABLE_ALIAS=""
MQTT_STABLE_ALIAS_HASH=""
declare -a MQTT_AUTO_CONTAINER_NAMES=()
declare -a MQTT_AUTO_BROKER_ALIASES=()
HETERO_BROKER_SPECS=""
declare -a HETERO_CONTAINERS=()

if [[ -z "${CHATAFL_MQTT_BROKERS:-}" ]] && is_mqtt_target "$DOCIMAGE"; then
  MQTT_AUTO_NETWORK="$(build_unique_docker_name "loopfuzz-mqtt-${DOCIMAGE}-${FUZZER}-${TIMESTAMP:-manual}-${$}")"
  if ! recreate_named_network "$MQTT_AUTO_NETWORK"; then
    echo "[ERROR] Failed to create MQTT auto network: ${MQTT_AUTO_NETWORK}"
    exit 1
  fi

  for idx in $(seq 1 "$RUNS"); do
    MQTT_AUTO_CONTAINER_NAMES+=("${MQTT_AUTO_NETWORK}-broker-${idx}")
    MQTT_AUTO_BROKER_ALIASES+=("mqttb${idx}")
  done

  # Launch a stable (non-fuzzed) reference broker for bridge/differential testing
  MQTT_STABLE_CONTAINER="${MQTT_AUTO_NETWORK}-stable"
  MQTT_STABLE_ALIAS_HASH="$(docker_name_hash "${MQTT_AUTO_NETWORK}-stable-alias")"
  MQTT_STABLE_ALIAS="mqtt-stable-${MQTT_STABLE_ALIAS_HASH:0:8}"
  printf "\n${LOG_TAG}: Launching stable reference broker (%s)...\n" "$MQTT_STABLE_ALIAS"
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
    printf "${LOG_TAG}: ✓ Stable broker ready on %s:1883\n" "$MQTT_STABLE_ALIAS"
  else
    printf "${LOG_TAG}: [ERROR] Stable broker is not reachable on %s:1883; aborting this run to avoid invalid differential metrics\n" "$MQTT_STABLE_ALIAS"
    exit 1
  fi

  printf "${LOG_TAG}: MQTT auto network: %s\n" "$MQTT_AUTO_NETWORK"

  # ── P0: Launch heterogeneous broker fleet (sync MBFuzzer's 6 implementations) ──
  # MBFuzzer refs: NanoMQ=236c9c5, EMQX=v5.6.0, FlashMQ=d82cba5, VerneMQ=f0e6dc15, HiveMQ=v4.24.0
  # Build with: cd benchmark/scripts/execution/dockerfiles/ && ./build_broker_images.sh
  # SKIP with: CHATAFL_NO_HETERO_BROKERS=1 (saves ~2 GB per group for parallel ablation)
  if [[ "${CHATAFL_NO_HETERO_BROKERS:-0}" != "1" ]]; then
  _launch_hetero_broker "chatafl-nanomq:236c9c5" "nanomq" "mqtt-nanomq" "1883" "" "" "60"
  _launch_hetero_broker "chatafl-emqx:5.6.0" "emqx" "mqtt-emqx" "1883" "" "" "180"
  _launch_hetero_broker "chatafl-flashmq:d82cba5" "flashmq" "mqtt-flashmq" "1883" "" "" "60"
  _launch_hetero_broker "chatafl-vernemq:f0e6dc15" "vernemq" "mqtt-vernemq" "1883" "" \
    "-e DOCKER_VERNEMQ_ALLOW_ANONYMOUS=on -e DOCKER_VERNEMQ_ACCEPT_EULA=yes" "180"
  _launch_hetero_broker "chatafl-hivemq:4.24.0" "hivemq" "mqtt-hivemq" "1883" "" "" "180"
  fi
  if [[ ${#HETERO_CONTAINERS[@]} -gt 0 ]]; then
    printf "${LOG_TAG}: [P0] Heterogeneous fleet: %d brokers launched\n" "${#HETERO_CONTAINERS[@]}"
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

  # MQTT network flags
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
  [[ -n "${CHATAFL_ABLATION_THRESHOLD}" ]] && ABLATION_FLAGS+=" -e CHATAFL_ABLATION_THRESHOLD=${CHATAFL_ABLATION_THRESHOLD}"

  # Per-container MQTT broker list: local + stable + heterogeneous fleet
  MQTT_FLAGS=""
  if [[ -n "${MQTT_STABLE_ALIAS:-}" ]] && [[ -n "$MQTT_AUTO_NETWORK" ]]; then
    _brokers="tcp://127.0.0.1/1883,tcp://${MQTT_STABLE_ALIAS}/1883"
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
    id=$(docker run --cpus=1 --memory=8g --memory-swap=8g ${DIAG_PTRACE_FLAGS} -e KEY="${KEY}" -e CHATAFL_HYPOTHESIS=1 ${ABLATION_FLAGS} ${MQTT_FLAGS} ${MQTT_RUN_FLAGS} -d --init $DOCIMAGE /bin/bash -c "cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}; R=\$?; [ \$R -eq 139 ] && R=0; exit \$R")
  else
    id=$(docker run --cpus=1 --memory=8g --memory-swap=8g ${DIAG_PTRACE_FLAGS} -e KEY="${KEY}" ${MQTT_FLAGS} ${MQTT_RUN_FLAGS} -d --init $DOCIMAGE /bin/bash -c "cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}; R=\$?; [ \$R -eq 139 ] && R=0; exit \$R")
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
printf "\n"
if [ -n "${dlist}" ]; then
  docker wait ${dlist} > /dev/null
fi
wait
RUN_COMPLETED=1
mark_completed_samples
cleanup_watchdogs

collect_results_with_recovery
cleanup_mqtt_resources

# ── Auto-generate run_summary.csv ──
generate_run_summary() {
  local results_dir="$1"
  local summary_py="${SCRIPT_DIR}/../analysis/run_summary.py"
  local output_file="$(cd "$results_dir" 2>/dev/null && pwd)/run_summary.csv"

  if [[ ! -f "$summary_py" ]]; then
    printf "\n${LOG_TAG}: [WARN] run_summary.py not found at %s, skipping summary generation\n" "$summary_py"
    return 0
  fi

  # Ensure at least one tarball exists before running
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

generate_run_summary "${SAVETO}"

printf "\n${LOG_TAG}: I am done!\n"
