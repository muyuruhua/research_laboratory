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

# Log tag: FUZZER(target) e.g. CHATAFL-OPT(bftpd)
LOG_TAG="${FUZZER^^}(${DOCIMAGE})"

#keep all container ids
cids=()

#create one container for each run
for i in $(seq 1 $RUNS); do
  # Build ablation env-var flags for chatafl-opt containers.
  # If the host exports CHATAFL_NO_REFINEMENT / NO_FRONTIER / NO_ADAPTIVE / NO_STATE_PROMPT,
  # they are forwarded into the container via -e.
  ABLATION_FLAGS=""
  [[ -n "${CHATAFL_NO_REFINEMENT}" ]]      && ABLATION_FLAGS+=" -e CHATAFL_NO_REFINEMENT=1"
  [[ -n "${CHATAFL_NO_FRONTIER}" ]]        && ABLATION_FLAGS+=" -e CHATAFL_NO_FRONTIER=1"
  [[ -n "${CHATAFL_NO_ADAPTIVE}" ]]        && ABLATION_FLAGS+=" -e CHATAFL_NO_ADAPTIVE=1"
  [[ -n "${CHATAFL_NO_STATE_PROMPT}" ]]    && ABLATION_FLAGS+=" -e CHATAFL_NO_STATE_PROMPT=1"
  [[ -n "${CHATAFL_ABLATION_THRESHOLD}" ]] && ABLATION_FLAGS+=" -e CHATAFL_ABLATION_THRESHOLD=${CHATAFL_ABLATION_THRESHOLD}"

  MQTT_FLAGS=""
  [[ -n "${CHATAFL_MQTT_BROKERS}" ]] && MQTT_FLAGS+=" -e CHATAFL_MQTT_BROKERS=${CHATAFL_MQTT_BROKERS}"

  # Enable Grammar Hypothesis system only for chatafl-opt
  if [[ "$FUZZER" == "chatafl-opt" ]]; then
    id=$(docker run --cpus=1 -e KEY="${KEY}" -e CHATAFL_HYPOTHESIS=1 ${ABLATION_FLAGS} ${MQTT_FLAGS} -d -it $DOCIMAGE /bin/bash -c "cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  else
    id=$(docker run --cpus=1 -e KEY="${KEY}" ${MQTT_FLAGS} -d -it $DOCIMAGE /bin/bash -c "cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
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

printf "\n${LOG_TAG}: I am done!\n"
