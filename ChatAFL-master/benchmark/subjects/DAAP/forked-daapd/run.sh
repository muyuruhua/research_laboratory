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

#Network deamons needed by forked-daapd
sudo /etc/init.d/dbus start
sudo /etc/init.d/avahi-daemon start

sudo /etc/init.d/dbus status
if [ $? -ne 0 ]
then
  echo "Unable to run DBUS"
  exit 1
fi

sudo /etc/init.d/avahi-daemon status
if [ $? -ne 0 ]
then
  echo "Unable to run AVAHI daemon"
  exit 1
fi

#Commands for afl-based fuzzers (e.g., aflnet, aflnwe)
if strstr "$FUZZER" "afl" || strstr "$FUZZER" "llm" || [ "$FUZZER" = "loopfuzz" ]; then

  # Run fuzzer-specific commands (if any)
  if [ -e ${WORKDIR}/run-${FUZZER} ]; then
    source ${WORKDIR}/run-${FUZZER}
  fi

  TARGET_DIR=${TARGET_DIR:-"forked-daapd"}
  INPUTS=${INPUTS:-${WORKDIR}"/in-daap"}

  # StateAFL arm: forked-daapd's socket I/O happens inside libevent (not
  # instrumented by StateAFL's LLVM pass), so no protocol states can be
  # inferred from memory dumps; the threaded target also crashes the
  # unsynchronized tracer hooks. Disable the target-side tracer entirely
  # (see stateafl/llvm_mode kill switch) — this arm runs coverage-guided.
  if [ "$FUZZER" = "stateafl" ]; then
    export STATEAFL_DISABLE_TRACER=1
  fi

  #Step-1. Do Fuzzing
  #Move to fuzzing folder
  cd $WORKDIR

  # StateAFL on forked-daapd still hits an upstream AFLNet-lineage list-
  # management bug (amplified by the generic length-prefix parser) that can
  # abort afl-fuzz mid-campaign. Restart afl-fuzz in AFL resume mode (-i-)
  # until the campaign time is exhausted; the queue/IPSM state on disk is
  # preserved across restarts, so only wall-clock is lost.
  if [ "$FUZZER" = "stateafl" ]; then
    END_AT=$(( $(date +%s) + TIMEOUT ))
    FIRST=1
    while [ "$(date +%s)" -lt "$END_AT" ]; do
      REMAIN=$(( END_AT - $(date +%s) ))
      if [ "$FIRST" = "1" ]; then
        SEED_ARG="-i ${INPUTS}"; FIRST=0
      else
        SEED_ARG="-i-"
      fi
      timeout -k 2s --preserve-status $REMAIN /home/ubuntu/${FUZZER_DIR}/afl-fuzz -d ${SEED_ARG} -o $OUTDIR -N tcp://127.0.0.1/3689 $OPTIONS ${WORKDIR}/${TARGET_DIR}/src/forked-daapd -d 0 -c ${WORKDIR}/forked-daapd.conf -f
      [ "$STOP_ON_ERR" = "1" ] && break
      # a crashed fuzzer leaks its target child holding port 3689; clean up
      # so the resumed instance can bind again
      pkill -x forked-daapd 2>/dev/null
      sleep 2
    done
    STATUS=0
  else
    timeout -k 2s --preserve-status $TIMEOUT /home/ubuntu/${FUZZER_DIR}/afl-fuzz -d -i ${INPUTS} -o $OUTDIR -N tcp://127.0.0.1/3689 $OPTIONS ${WORKDIR}/${TARGET_DIR}/src/forked-daapd -d 0 -c ${WORKDIR}/forked-daapd.conf -f
    STATUS=$?
  fi

  #Step-2. Collect code coverage over time
  #Move to gcov folder
  cd $WORKDIR

  #The last argument passed to cov_script should be 0 if the fuzzer is afl/nwe and it should be 1 if the fuzzer is based on aflnet
  #0: the test case is a concatenated message sequence -- there is no message boundary
  #1: the test case is a structured file keeping several request messages
  if [ $FUZZER = "aflnwe" ]; then
    cov_script ${WORKDIR}/${OUTDIR}/ 3689 ${SKIPCOUNT} ${WORKDIR}/${OUTDIR}/cov_over_time.csv 0
  else
    cov_script ${WORKDIR}/${OUTDIR}/ 3689 ${SKIPCOUNT} ${WORKDIR}/${OUTDIR}/cov_over_time.csv 1
  fi

  cd $WORKDIR/forked-daapd-gcov
  gcovr -r . --html --html-details -o index.html
  mkdir ${WORKDIR}/${OUTDIR}/cov_html/
  cp *.html ${WORKDIR}/${OUTDIR}/cov_html/

  #Step-3. Save the result to the ${WORKDIR} folder
  #Tar all results to a file
  cd ${WORKDIR}
  tar -zcvf ${WORKDIR}/${OUTDIR}.tar.gz ${OUTDIR}

  exit $STATUS
fi
