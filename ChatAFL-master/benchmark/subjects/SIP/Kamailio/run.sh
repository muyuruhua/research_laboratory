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

FUZZER_DIR="$FUZZER"
if [ "$FUZZER" = "loopfuzz" ]; then
  FUZZER_DIR="loopfuzz"
fi

#Commands for afl-based fuzzers (e.g., aflnet, aflnwe)
if strstr "$FUZZER" "afl" || strstr "$FUZZER" "llm" || [ "$FUZZER" = "loopfuzz" ]; then

  # Run fuzzer-specific commands (if any)
  if [ -e ${WORKDIR}/run-${FUZZER} ]; then
    source ${WORKDIR}/run-${FUZZER}
  fi

  TARGET_DIR=${TARGET_DIR:-"kamailio"}
  INPUTS=${INPUTS:-${WORKDIR}"/in-sip"}

  # ── KAMAILIO_TCP=1: TCP arm (2026-09-24) ─────────────────────────
  # The tcp_read_headers Content-Length signed-overflow is only reachable
  # over TCP. Default (unset/0) keeps the original UDP arm byte-identical
  # so historical campaign data stays comparable. TCP needs: fork=yes
  # (no-fork mode never starts tcp_main), no -D (which forces no-fork),
  # and a wider exec timeout (daemonizing startup exceeds 5 s under
  # load). Validated: ~28 execs/s, state machine forms, S1 shapes reach
  # the vulnerable path, log fingerprint confirmed.
  if [ "${KAMAILIO_TCP:-0}" = "1" ]; then
    sed -e 's/^fork=no/fork=yes/' \
        -e 's/^disable_tcp=yes/disable_tcp=no/' \
        -e 's|^listen=udp:127.0.0.1:5060|listen=udp:127.0.0.1:5060\nlisten=tcp:127.0.0.1:5060|' \
        ${WORKDIR}/kamailio-basic.cfg > ${WORKDIR}/kamailio-tcp.cfg
    KAM_NET="-N tcp://127.0.0.1/5060"
    KAM_CFG="-f ${WORKDIR}/kamailio-tcp.cfg"
    KAM_EXTRA_TMO="-t 12000+"
    KAM_NODAEMON=""
  else
    KAM_NET="-N udp://127.0.0.1:5060"
    KAM_CFG="-f ${WORKDIR}/kamailio-basic.cfg"
    KAM_EXTRA_TMO=""
    KAM_NODAEMON="-D"
  fi

  #Step-1. Do Fuzzing
  #Move to fuzzing folder
  export KAMAILIO_MODULES="src/modules"
  export KAMAILIO_RUNTIME_DIR="runtime_dir"

  cd $WORKDIR/${TARGET_DIR}

  timeout -k 2s --preserve-status $TIMEOUT /home/ubuntu/${FUZZER_DIR}/afl-fuzz -d -i ${INPUTS} -o $OUTDIR ${KAM_NET} $OPTIONS ${KAM_EXTRA_TMO} -c ${WORKDIR}/run_pjsip ./src/kamailio ${KAM_CFG} -L $KAMAILIO_MODULES -Y $KAMAILIO_RUNTIME_DIR -n 1 ${KAM_NODAEMON} -E

  STATUS=$?

  #Step-2. Collect code coverage over time
  #Move to gcov folder
  cd $WORKDIR

  #The last argument passed to cov_script should be 0 if the fuzzer is afl/nwe and it should be 1 if the fuzzer is based on aflnet
  #0: the test case is a concatenated message sequence -- there is no message boundary
  #1: the test case is a structured file keeping several request messages
  if [ $FUZZER = "aflnwe" ]; then
    cov_script ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/ 5060 ${SKIPCOUNT} ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_over_time.csv 0
  else
    cov_script ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/ 5060 ${SKIPCOUNT} ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_over_time.csv 1
  fi

  cd $WORKDIR/kamailio-gcov
  gcovr -r . --html --html-details -o index.html
  mkdir ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_html/
  cp *.html ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_html/

  #Step-3. Save the result to the ${WORKDIR} folder
  #Tar all results to a file
  cd ${WORKDIR}/${TARGET_DIR}
  tar -zcvf ${WORKDIR}/${OUTDIR}.tar.gz ${OUTDIR}

  exit $STATUS
fi
