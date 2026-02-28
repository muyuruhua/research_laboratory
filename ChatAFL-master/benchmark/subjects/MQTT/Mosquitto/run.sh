#!/bin/bash

FUZZER=$1     #fuzzer name (e.g., aflnet) -- this name must match the name of the fuzzer folder inside the Docker container
OUTDIR=$2     #name of the output folder
OPTIONS=$3    #all configured options -- to make it flexible, we only fix some options (e.g., -i, -o, -N) in this script
TIMEOUT=$4    #time for fuzzing
SKIPCOUNT=$5  #used for calculating cov over time. e.g., SKIPCOUNT=5 means we run gcovr after every 5 test cases

strstr() {
  [ "${1#*$2*}" = "$1" ] && return 1
  return 0
}

#Commands for afl-based fuzzers (e.g., aflnet, chatafl, chatafl-opt)
if $(strstr $FUZZER "afl") || $(strstr $FUZZER "llm"); then

  # Run fuzzer-specific commands (if any)
  if [ -e ${WORKDIR}/run-${FUZZER} ]; then
    source ${WORKDIR}/run-${FUZZER}
  fi

  TARGET_DIR=${TARGET_DIR:-"mosquitto"}
  INPUTS=${INPUTS:-${WORKDIR}"/in-mqtt"}

  #Step-1. Do Fuzzing
  cd $WORKDIR

  timeout -k 2s --preserve-status $TIMEOUT /home/ubuntu/${FUZZER}/afl-fuzz \
    -d -i ${INPUTS} -o $OUTDIR \
    -N tcp://127.0.0.1/1883 \
    $OPTIONS \
    ${WORKDIR}/${TARGET_DIR}/src/mosquitto \
    -c ${WORKDIR}/mosquitto.conf

  STATUS=$?

  #Step-2. Collect code coverage over time
  cd $WORKDIR

  if [ $FUZZER = "aflnwe" ]; then
    cov_script ${WORKDIR}/${OUTDIR}/ 1883 ${SKIPCOUNT} ${WORKDIR}/${OUTDIR}/cov_over_time.csv 0
  else
    cov_script ${WORKDIR}/${OUTDIR}/ 1883 ${SKIPCOUNT} ${WORKDIR}/${OUTDIR}/cov_over_time.csv 1
  fi

  cd $WORKDIR/mosquitto-gcov
  gcovr -r . --html --html-details -o index.html
  mkdir -p ${WORKDIR}/${OUTDIR}/cov_html/
  cp *.html ${WORKDIR}/${OUTDIR}/cov_html/ 2>/dev/null || true

  #Step-3. Save the result
  cd ${WORKDIR}
  tar -zcvf ${WORKDIR}/${OUTDIR}.tar.gz ${OUTDIR}

  exit $STATUS
fi
