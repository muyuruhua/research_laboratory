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

fix_result_permissions() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  chown -R "${RESULT_OWNER}:${RESULT_GROUP}" "$path"
  chmod -R u+rwX "$path"
}

# 获取项目根目录
PROJECT_ROOT="${PROJECT_ROOT:-$PWD/../..}"

# Log tag: FUZZER(target) e.g. CHATAFL-OPT(bftpd)
LOG_TAG="${FUZZER^^}(${DOCIMAGE})"

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
declare -a MQTT_AUTO_CONTAINER_NAMES=()
declare -a MQTT_AUTO_BROKER_ALIASES=()

if [[ -z "${CHATAFL_MQTT_BROKERS:-}" ]] && is_mqtt_target "$DOCIMAGE"; then
  MQTT_AUTO_NETWORK="$(sanitize_docker_name "chatafl-mqtt-${DOCIMAGE}-${FUZZER}-${TIMESTAMP:-manual}-${$}")"
  MQTT_AUTO_NETWORK="${MQTT_AUTO_NETWORK:0:63}"
  MQTT_AUTO_NETWORK="$(echo "$MQTT_AUTO_NETWORK" | sed 's/-*$//')"
  if ! docker network inspect "$MQTT_AUTO_NETWORK" >/dev/null 2>&1; then
    docker network create "$MQTT_AUTO_NETWORK" >/dev/null
    if [[ $? -ne 0 ]]; then
      echo "[ERROR] Failed to create MQTT auto network: ${MQTT_AUTO_NETWORK}"
      exit 1
    fi
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
  MQTT_STABLE_ALIAS="mqtt-stable"
  printf "\n${LOG_TAG}: [DEV] Launching stable reference broker (%s)...\n" "$MQTT_STABLE_ALIAS"
  docker run --cpus=0.5 --memory=256m \
    --network "$MQTT_AUTO_NETWORK" \
    --name "$MQTT_STABLE_CONTAINER" \
    --hostname "$MQTT_STABLE_ALIAS" \
    --network-alias "$MQTT_STABLE_ALIAS" \
    --restart=unless-stopped \
    ${SUBJECT_MOUNT} \
    -d "$DOCIMAGE" /bin/bash -c \
    "if [ -f /tmp/subject-src/mosquitto.conf ]; then cp -f /tmp/subject-src/mosquitto.conf /home/ubuntu/experiments/mosquitto.conf; fi && \
     exec /home/ubuntu/experiments/mosquitto-gcov/src/mosquitto -c /home/ubuntu/experiments/mosquitto.conf"

  # Wait for stable broker to be ready (up to 15 sec)
  _stable_ok=0
  for _w in $(seq 1 30); do
    if docker exec "$MQTT_STABLE_CONTAINER" bash -c "nc -z 127.0.0.1 1883" 2>/dev/null; then
      _stable_ok=1; break
    fi
    sleep 0.5
  done
  if [[ $_stable_ok -eq 1 ]]; then
    printf "${LOG_TAG}: [DEV] ✓ Stable broker ready on %s:1883\n" "$MQTT_STABLE_ALIAS"
  else
    printf "${LOG_TAG}: [WARN] Stable broker may not be ready yet\n"
  fi

  printf "${LOG_TAG}: [DEV] MQTT auto network: %s\n" "$MQTT_AUTO_NETWORK"
  printf "${LOG_TAG}: [DEV] Architecture: each fuzzer → tcp://<self>/1883 + tcp://%s/1883\n" "$MQTT_STABLE_ALIAS"
fi

#keep all container ids
cids=()

#create one container for each run
for i in $(seq 1 $RUNS); do
  run_index=$((i-1))
  MQTT_RUN_FLAGS=""
  if [[ -n "$MQTT_AUTO_NETWORK" ]] && [[ ${#MQTT_AUTO_CONTAINER_NAMES[@]} -gt $run_index ]]; then
    MQTT_RUN_FLAGS=" --network ${MQTT_AUTO_NETWORK} --name ${MQTT_AUTO_CONTAINER_NAMES[$run_index]} --hostname ${MQTT_AUTO_BROKER_ALIASES[$run_index]} --network-alias ${MQTT_AUTO_BROKER_ALIASES[$run_index]}"
  fi

  # Build ablation env-var flags for chatafl-opt containers.
  # If the host exports CHATAFL_NO_REFINEMENT / NO_FRONTIER / NO_ADAPTIVE,
  # they are forwarded into the container via -e.
  ABLATION_FLAGS=""
  [[ -n "${CHATAFL_NO_REFINEMENT}" ]]      && ABLATION_FLAGS+=" -e CHATAFL_NO_REFINEMENT=1"
  [[ -n "${CHATAFL_NO_FRONTIER}" ]]        && ABLATION_FLAGS+=" -e CHATAFL_NO_FRONTIER=1"
  [[ -n "${CHATAFL_NO_ADAPTIVE}" ]]        && ABLATION_FLAGS+=" -e CHATAFL_NO_ADAPTIVE=1"
  [[ -n "${CHATAFL_NO_STATE_PROMPT}" ]]    && ABLATION_FLAGS+=" -e CHATAFL_NO_STATE_PROMPT=1"
  [[ -n "${CHATAFL_ABLATION_THRESHOLD}" ]] && ABLATION_FLAGS+=" -e CHATAFL_ABLATION_THRESHOLD=${CHATAFL_ABLATION_THRESHOLD}"

  # Per-container MQTT broker list: local broker + stable reference
  MQTT_FLAGS=""
  if [[ -n "${MQTT_STABLE_ALIAS:-}" ]] && [[ -n "$MQTT_AUTO_NETWORK" ]]; then
    _local_alias="${MQTT_AUTO_BROKER_ALIASES[$run_index]}"
    _brokers="tcp://${_local_alias}/1883,tcp://${MQTT_STABLE_ALIAS}/1883"
    MQTT_FLAGS=" -e CHATAFL_MQTT_BROKERS=${_brokers}"
  elif [[ -n "${CHATAFL_MQTT_BROKERS:-}" ]]; then
    MQTT_FLAGS=" -e CHATAFL_MQTT_BROKERS=${CHATAFL_MQTT_BROKERS}"
  fi

  # Enable Grammar Hypothesis system only for chatafl-opt
  if [[ "$FUZZER" == "chatafl-opt" ]]; then
    # Volume挂载本地代码并在容器内重新编译
    id=$(docker run --cpus=1 \
      -e KEY="${KEY}" \
      -e CHATAFL_HYPOTHESIS=1 \
      ${ABLATION_FLAGS} \
      ${MQTT_FLAGS} \
      ${MQTT_RUN_FLAGS} \
      -v "${PROJECT_ROOT}/ChatAFL-Opt:/tmp/chatafl-opt-src:ro" \
      ${SUBJECT_MOUNT} \
      -d -it $DOCIMAGE /bin/bash -c "\
        ${SUBJECT_COPY}\
        echo '[DEV] Copying and compiling updated code...' && \
        cp -f /tmp/chatafl-opt-src/*.c /tmp/chatafl-opt-src/*.h /tmp/chatafl-opt-src/Makefile /home/ubuntu/chatafl-opt/ 2>/dev/null || true && \
        cd /home/ubuntu/chatafl-opt && make clean && make -j\$(nproc) && \
        echo '[DEV] Compilation complete, MD5: '\$(md5sum grammar-hypothesis.c | cut -d' ' -f1) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  elif [[ "$FUZZER" == "chatafl" ]]; then
    id=$(docker run --cpus=1 \
      -e KEY="${KEY}" \
      ${MQTT_FLAGS} \
      ${MQTT_RUN_FLAGS} \
      -v "${PROJECT_ROOT}/ChatAFL:/tmp/chatafl-src:ro" \
      ${SUBJECT_MOUNT} \
      -d -it $DOCIMAGE /bin/bash -c "\
        ${SUBJECT_COPY}\
        cp -f /tmp/chatafl-src/*.c /tmp/chatafl-src/*.h /home/ubuntu/chatafl/ && \
        cd /home/ubuntu/chatafl && make clean && make -j\$(nproc) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  elif [[ "$FUZZER" == "chatafl-cl1" ]]; then
    id=$(docker run --cpus=1 \
      -e KEY="${KEY}" \
      ${MQTT_FLAGS} \
      ${MQTT_RUN_FLAGS} \
      -v "${PROJECT_ROOT}/ChatAFL-CL1:/tmp/chatafl-cl1-src:ro" \
      ${SUBJECT_MOUNT} \
      -d -it $DOCIMAGE /bin/bash -c "\
        ${SUBJECT_COPY}\
        cp -f /tmp/chatafl-cl1-src/*.c /tmp/chatafl-cl1-src/*.h /home/ubuntu/chatafl-cl1/ && \
        cd /home/ubuntu/chatafl-cl1 && make clean && make -j\$(nproc) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  elif [[ "$FUZZER" == "chatafl-cl2" ]]; then
    id=$(docker run --cpus=1 \
      -e KEY="${KEY}" \
      ${MQTT_FLAGS} \
      ${MQTT_RUN_FLAGS} \
      -v "${PROJECT_ROOT}/ChatAFL-CL2:/tmp/chatafl-cl2-src:ro" \
      ${SUBJECT_MOUNT} \
      -d -it $DOCIMAGE /bin/bash -c "\
        ${SUBJECT_COPY}\
        cp -f /tmp/chatafl-cl2-src/*.c /tmp/chatafl-cl2-src/*.h /home/ubuntu/chatafl-cl2/ && \
        cd /home/ubuntu/chatafl-cl2 && make clean && make -j\$(nproc) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  else
    id=$(docker run --cpus=1 -e KEY="${KEY}" ${MQTT_FLAGS} ${MQTT_RUN_FLAGS} ${SUBJECT_MOUNT} -d -it $DOCIMAGE /bin/bash -c "${SUBJECT_COPY}cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  fi
  cids+=(${id::12}) #store only the first 12 characters of a container ID
done

dlist="" #docker list
for id in ${cids[@]}; do
  dlist+=" ${id}"
done

#wait until all these dockers are stopped
printf "\n${LOG_TAG}: Fuzzing in progress ..."
printf "\n${LOG_TAG}: Waiting for the following containers to stop:${dlist}"
for id in ${cids[@]}; do
  printf "\n${LOG_TAG}: You can check logs by: docker logs -f ${id}"
done
printf "\n"
if [ -n "${dlist}" ]; then
  docker wait ${dlist} > /dev/null
fi
wait

#collect the fuzzing results from the containers
printf "\n${LOG_TAG}: Collecting results and save them to ${SAVETO}"
mkdir -p "${SAVETO}"
fix_result_permissions "${SAVETO}"
index=1
for id in ${cids[@]}; do
  printf "\n${LOG_TAG}: Collecting results from container ${id}"
  if docker cp ${id}:/home/ubuntu/experiments/${OUTDIR}.tar.gz ${SAVETO}/${OUTDIR}_${index}.tar.gz > /dev/null; then
    fix_result_permissions "${SAVETO}/${OUTDIR}_${index}.tar.gz"
    if [ ! -z "$DELETE" ]; then
      printf "\nDeleting ${id}"
      docker rm ${id} > /dev/null # Remove container now that we don't need it
    fi
  else
    printf "\n${LOG_TAG}: [ERROR] Failed to collect ${OUTDIR}_${index}.tar.gz from ${id}; container is kept for manual recovery"
  fi
  index=$((index+1))
done

fix_result_permissions "${SAVETO}"

if [[ -n "$MQTT_AUTO_NETWORK" ]]; then
  if [[ -n "${MQTT_STABLE_CONTAINER:-}" ]]; then
    printf "\n${LOG_TAG}: Stopping stable reference broker...\n"
    docker rm -f "$MQTT_STABLE_CONTAINER" >/dev/null 2>&1 || true
  fi
  docker network rm "$MQTT_AUTO_NETWORK" >/dev/null 2>&1 || true
fi

printf "\n${LOG_TAG}: I am done!\n"
