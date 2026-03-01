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

# 获取项目根目录
PROJECT_ROOT="${PROJECT_ROOT:-$PWD/../..}"

# Log tag: FUZZER(target) e.g. CHATAFL-OPT(bftpd)
LOG_TAG="${FUZZER^^}(${DOCIMAGE})"

#keep all container ids
cids=()

#create one container for each run
for i in $(seq 1 $RUNS); do
  # Enable Grammar Hypothesis system only for chatafl-opt
  if [[ "$FUZZER" == "chatafl-opt" ]]; then
    # Volume挂载本地代码并在容器内重新编译
    id=$(docker run --cpus=1 \
      -e KEY="${KEY}" \
      -e CHATAFL_HYPOTHESIS=1 \
      -v "${PROJECT_ROOT}/ChatAFL-Opt:/tmp/chatafl-opt-src:ro" \
      -d -it $DOCIMAGE /bin/bash -c "\
        echo '[DEV] Copying and compiling updated code...' && \
        cp -f /tmp/chatafl-opt-src/*.c /tmp/chatafl-opt-src/*.h /tmp/chatafl-opt-src/Makefile /home/ubuntu/chatafl-opt/ 2>/dev/null || true && \
        cd /home/ubuntu/chatafl-opt && make clean && make -j\$(nproc) && \
        echo '[DEV] Compilation complete, MD5: '\$(md5sum grammar-hypothesis.c | cut -d' ' -f1) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  elif [[ "$FUZZER" == "chatafl" ]]; then
    id=$(docker run --cpus=1 \
      -e KEY="${KEY}" \
      -v "${PROJECT_ROOT}/ChatAFL:/tmp/chatafl-src:ro" \
      -d -it $DOCIMAGE /bin/bash -c "\
        cp -f /tmp/chatafl-src/*.c /tmp/chatafl-src/*.h /home/ubuntu/chatafl/ && \
        cd /home/ubuntu/chatafl && make clean && make -j\$(nproc) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  elif [[ "$FUZZER" == "chatafl-cl1" ]]; then
    id=$(docker run --cpus=1 \
      -e KEY="${KEY}" \
      -v "${PROJECT_ROOT}/ChatAFL-CL1:/tmp/chatafl-cl1-src:ro" \
      -d -it $DOCIMAGE /bin/bash -c "\
        cp -f /tmp/chatafl-cl1-src/*.c /tmp/chatafl-cl1-src/*.h /home/ubuntu/chatafl-cl1/ && \
        cd /home/ubuntu/chatafl-cl1 && make clean && make -j\$(nproc) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  elif [[ "$FUZZER" == "chatafl-cl2" ]]; then
    id=$(docker run --cpus=1 \
      -e KEY="${KEY}" \
      -v "${PROJECT_ROOT}/ChatAFL-CL2:/tmp/chatafl-cl2-src:ro" \
      -d -it $DOCIMAGE /bin/bash -c "\
        cp -f /tmp/chatafl-cl2-src/*.c /tmp/chatafl-cl2-src/*.h /home/ubuntu/chatafl-cl2/ && \
        cd /home/ubuntu/chatafl-cl2 && make clean && make -j\$(nproc) && \
        cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  else
    id=$(docker run --cpus=1 -e KEY="${KEY}" -d -it $DOCIMAGE /bin/bash -c "cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
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
  printf "\n${LOG_TAG}: You can check logs by: docker logs -f ${id}\n"
done
if [ -n "${dlist}" ]; then
  docker wait ${dlist} > /dev/null
fi
wait

#collect the fuzzing results from the containers
printf "\n${LOG_TAG}: Collecting results and save them to ${SAVETO}"
index=1
for id in ${cids[@]}; do
  printf "\n${LOG_TAG}: Collecting results from container ${id}"
  docker cp ${id}:/home/ubuntu/experiments/${OUTDIR}.tar.gz ${SAVETO}/${OUTDIR}_${index}.tar.gz > /dev/null
  if [ ! -z $DELETE ]; then
    printf "\nDeleting ${id}"
    docker rm ${id} # Remove container now that we don't need it
  fi
  index=$((index+1))
done

printf "\n${LOG_TAG}: I am done!\n"
