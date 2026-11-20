#!/bin/bash

FUZZER=$1     #fuzzer name (e.g., aflnet) -- this name must match the name of the fuzzer folder inside the Docker container
OUTDIR=$2     #name of the output folder
OPTIONS=$3    #all configured options -- to make it flexible, we only fix some options (e.g., -i, -o, -N) in this script
TIMEOUT=$4    #time for fuzzing
SKIPCOUNT=$5  #used for calculating cov over time. e.g., SKIPCOUNT=5 means we run gcovr after every 5 test cases

# forked-daapd exposes DAAP endpoints over an HTTP/1.x server.  ``DAAP`` is
# the benchmark directory/feature name, not an AFLNet parser name.  Enforce
# the wire parser at the target boundary as well as in the host launcher so a
# direct invocation cannot silently produce DAAP-misattributed archives.
_wire_protocol=""
read -r -a _option_tokens <<< "$OPTIONS"
for ((_i = 0; _i < ${#_option_tokens[@]}; _i++)); do
  case "${_option_tokens[$_i]}" in
    -P)
      if ((_i + 1 < ${#_option_tokens[@]})); then
        _wire_protocol="${_option_tokens[$((_i + 1))]}"
      fi
      break
      ;;
    -P*)
      _wire_protocol="${_option_tokens[$_i]#-P}"
      break
      ;;
  esac
done
if [[ "$_wire_protocol" != "HTTP" ]]; then
  echo "[ERROR] forked-daapd requires AFLNet wire protocol '-P HTTP' (got '${_wire_protocol:-missing}')" >&2
  exit 2
fi

strstr() {
  [ "${1#*$2*}" = "$1" ] && return 1
  return 0
}

POSTPROCESS_STATUS=0
record_postprocess_failure() {
  local step="$1" rc="$2"
  if [ "$rc" -ne 0 ]; then
    echo "[ERROR] ${step} failed (exit ${rc})" >&2
    [ "$POSTPROCESS_STATUS" -ne 0 ] || POSTPROCESS_STATUS=$rc
  fi
}

validate_loopfuzz_terminal() {
  [ "$FUZZER" = "loopfuzz" ] || return 0
  local output_dir="$1" terminal="" candidate count=0
  for candidate in "$output_dir/cov_over_time.csv.v4/terminal.json" \
                   "$output_dir/cov_over_time.csv.v5/terminal.json"; do
    if [ -e "$candidate" ]; then
      terminal="$candidate"
      count=$((count + 1))
    fi
  done
  [ "$count" -eq 1 ] && [ -s "$terminal" ] || {
    echo "[ERROR] expected exactly one non-empty LoopFuzz v4/v5 terminal under: $output_dir" >&2
    return 1
  }
  python3 -c 'import json,sys; p=sys.argv[1]; v=5 if "/cov_over_time.csv.v5/" in p else 4; s="loopfuzz-coverage-v5-sampled-checkpoints" if v == 5 else "loopfuzz-coverage-v4"; t=json.load(open(p)); sys.exit(0 if isinstance(t,dict) and t.get("schema_version")==s and t.get("coverage_complete") is True and t.get("acceptance")=="complete" else 1)' "$terminal" || {
    echo "[ERROR] LoopFuzz terminal is incomplete: $terminal" >&2
    return 1
  }
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
  cd "$WORKDIR" || { echo "[ERROR] missing fuzz working directory" >&2; exit 2; }
  RESET_ARGS=()
  if [ "$FUZZER" = "loopfuzz" ]; then
    RESET_ARGS=(-c "bash /tmp/coverage-v4-src/fuzz_runtime/forked-daapd.sh")
    [ -f /tmp/coverage-v4-src/fuzz_runtime/forked-daapd.sh ] || { echo "missing live reset script" >&2; exit 2; }
  fi

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
      timeout -k 30s --preserve-status $REMAIN /home/ubuntu/${FUZZER_DIR}/afl-fuzz -d ${SEED_ARG} -o $OUTDIR -N tcp://127.0.0.1/3689 $OPTIONS ${WORKDIR}/${TARGET_DIR}/src/forked-daapd -d 0 -c ${WORKDIR}/forked-daapd.conf -f
      [ "$STOP_ON_ERR" = "1" ] && break
      # a crashed fuzzer leaks its target child holding port 3689; clean up
      # so the resumed instance can bind again
      pkill -x forked-daapd 2>/dev/null
      sleep 2
    done
    STATUS=0
  else
    timeout -k 30s --preserve-status $TIMEOUT /home/ubuntu/${FUZZER_DIR}/afl-fuzz -d -i ${INPUTS} -o $OUTDIR -N tcp://127.0.0.1/3689 $OPTIONS "${RESET_ARGS[@]}" ${WORKDIR}/${TARGET_DIR}/src/forked-daapd -d 0 -c ${WORKDIR}/forked-daapd.conf -f
    STATUS=$?
  fi

  #Step-2. Collect code coverage over time
  #Move to gcov folder
  if cd "$WORKDIR"; then
    #The last argument passed to cov_script should be 0 if the fuzzer is afl/nwe and it should be 1 if the fuzzer is based on aflnet
    #0: the test case is a concatenated message sequence -- there is no message boundary
    #1: the test case is a structured file keeping several request messages
    if [ $FUZZER = "aflnwe" ]; then
      cov_script ${WORKDIR}/${OUTDIR}/ 3689 ${SKIPCOUNT} ${WORKDIR}/${OUTDIR}/cov_over_time.csv 0
    else
      cov_script ${WORKDIR}/${OUTDIR}/ 3689 ${SKIPCOUNT} ${WORKDIR}/${OUTDIR}/cov_over_time.csv 1
    fi > "${WORKDIR}/${OUTDIR}/coverage.log" 2>&1
    COVERAGE_STATUS=$?
    cat "${WORKDIR}/${OUTDIR}/coverage.log"
    record_postprocess_failure "coverage replay" "$COVERAGE_STATUS"
    validate_loopfuzz_terminal "${WORKDIR}/${OUTDIR}"
    TERMINAL_STATUS=$?
    record_postprocess_failure "coverage terminal validation" "$TERMINAL_STATUS"
  else
    COVERAGE_STATUS=$?
    record_postprocess_failure "coverage working-directory change" "$COVERAGE_STATUS"
  fi

  if cd "$WORKDIR/forked-daapd-gcov"; then
    gcovr -r . --html --html-details -o index.html
    GCOVR_STATUS=$?
    record_postprocess_failure "gcovr report" "$GCOVR_STATUS"
    mkdir -p "${WORKDIR}/${OUTDIR}/cov_html/"
    MKDIR_STATUS=$?
    record_postprocess_failure "coverage report directory creation" "$MKDIR_STATUS"
    cp *.html "${WORKDIR}/${OUTDIR}/cov_html/"
    COPY_STATUS=$?
    record_postprocess_failure "coverage report copy" "$COPY_STATUS"
  else
    GCOVR_STATUS=$?
    record_postprocess_failure "coverage report working-directory change" "$GCOVR_STATUS"
  fi

  #Step-3. Save the result to the ${WORKDIR} folder
  #Tar all results to a file
  if cd "$WORKDIR"; then
    tar -zcvf "${WORKDIR}/${OUTDIR}.tar.gz" "$OUTDIR"
    TAR_STATUS=$?
  else
    TAR_STATUS=$?
  fi
  record_postprocess_failure "result archive" "$TAR_STATUS"

  [ "$STATUS" -ne 0 ] || STATUS=$POSTPROCESS_STATUS
  exit "$STATUS"
fi
