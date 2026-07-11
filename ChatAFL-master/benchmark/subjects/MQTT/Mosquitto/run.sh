#!/bin/bash

FUZZER=$1     #fuzzer name (e.g., aflnet) -- this name must match the name of the fuzzer folder inside the Docker container
OUTDIR=$2     #name of the output folder
OPTIONS=$3    #all configured options -- to make it flexible, we only fix some options (e.g., -i, -o, -N) in this script
TIMEOUT=$4    #time for fuzzing
SKIPCOUNT=$5  #used for calculating cov over time. e.g., SKIPCOUNT=5 means we run gcovr after every 5 test cases

BROKER_PID=""

cleanup_mqtt_broker() {
  if [ -n "$BROKER_PID" ]; then
    kill -TERM "$BROKER_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$BROKER_PID" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$BROKER_PID" 2>/dev/null || true
    wait "$BROKER_PID" 2>/dev/null || true
  fi
}

start_mqtt_broker_if_needed() {
  if nc -z 127.0.0.1 1883 >/dev/null 2>&1; then
    return 0
  fi

  "$WORKDIR/${TARGET_DIR}/src/mosquitto" -c "$WORKDIR/mosquitto.conf" >/tmp/mqtt-broker.log 2>&1 &
  BROKER_PID=$!

  for _ in $(seq 1 100); do
    if nc -z 127.0.0.1 1883 >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done

  echo "[ERROR] MQTT broker failed to start on 127.0.0.1:1883"
  cleanup_mqtt_broker
  exit 1
}

strstr() {
  [ "${1#*$2*}" = "$1" ] && return 1
  return 0
}

FUZZER_DIR="$FUZZER"
if [ "$FUZZER" = "loopfuzz" ]; then
  FUZZER_DIR="loopfuzz"
fi

#Commands for afl-based fuzzers (e.g., aflnet, chatafl, loopfuzz)
if strstr "$FUZZER" "afl" || strstr "$FUZZER" "llm" || [ "$FUZZER" = "loopfuzz" ]; then

  # Run fuzzer-specific commands (if any)
  if [ -e ${WORKDIR}/run-${FUZZER} ]; then
    source ${WORKDIR}/run-${FUZZER}
  fi

  TARGET_DIR=${TARGET_DIR:-"mosquitto"}
  INPUTS=${INPUTS:-${WORKDIR}"/in-mqtt"}

  # Do NOT pre-start a standalone broker here.
  # afl-fuzz launches the instrumented mosquitto target itself;
  # pre-starting another broker on 1883 would lock coverage on startup-failure paths.

  #Step-1. Do Fuzzing
  cd $WORKDIR

  STATUS=0
  CRASH_COUNT=0
  MAX_RESTARTS=5
  START_TIME=$(date +%s)
  END_TIME=$(( START_TIME + TIMEOUT ))

  while true; do
    REMAINING=$(( END_TIME - $(date +%s) ))
    [ $REMAINING -le 0 ] && { STATUS=0; break; }

    echo "[run] Starting afl-fuzz (remaining=${REMAINING}s, restart=${CRASH_COUNT})..."

    timeout -k 2s --preserve-status $REMAINING /home/ubuntu/${FUZZER_DIR}/afl-fuzz \
      -d -i ${INPUTS} -o $OUTDIR \
      -N tcp://127.0.0.1/1883 \
      $OPTIONS \
      ${WORKDIR}/${TARGET_DIR}/src/mosquitto \
      -c ${WORKDIR}/mosquitto.conf

    STATUS=$?

    # SIGSEGV/ABRT/BUS — afl-fuzz crashed, not the target.
    # Save partial results and restart from the saved queue.
    if [ $STATUS -eq 139 ] || [ $STATUS -eq 134 ] || [ $STATUS -eq 135 ]; then
      CRASH_COUNT=$(( CRASH_COUNT + 1 ))
      if [ $CRASH_COUNT -gt $MAX_RESTARTS ]; then
        echo "[run] afl-fuzz crashed $MAX_RESTARTS times, giving up (status=$STATUS)"
        break
      fi
      echo "[run] afl-fuzz crashed (status=$STATUS), collecting partial coverage & restarting (${CRASH_COUNT}/${MAX_RESTARTS})..."
      # Save incremental coverage so far
      pkill -TERM -f "mosquitto.*mosquitto.conf" 2>/dev/null || true
      for _w in $(seq 1 20); do nc -z 127.0.0.1 1883 2>/dev/null || break; sleep 0.1; done
      pkill -KILL -f "mosquitto.*mosquitto.conf" 2>/dev/null || true

      cov_script ${WORKDIR}/${OUTDIR}/ 1883 ${SKIPCOUNT} ${WORKDIR}/${OUTDIR}/cov_over_time.csv 1 2>/dev/null || true
      # Backup current state
      cp ${WORKDIR}/${OUTDIR}/fuzzer_stats ${WORKDIR}/${OUTDIR}/fuzzer_stats.crash_${CRASH_COUNT} 2>/dev/null || true
      # Resume from existing queue (-i- = reuse output dir, don't re-scan seeds)
      INPUTS="-"
      # Brief pause to let the kernel release crashed child processes
      sleep 2
      continue
    fi

    # Normal exit, timeout, or ctrl-c — done.
    break
  done

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
