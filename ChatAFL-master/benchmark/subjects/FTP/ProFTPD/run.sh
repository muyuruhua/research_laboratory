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

#Commands for afl-based fuzzers (e.g., aflnet, aflnwe)
if strstr "$FUZZER" "afl" || strstr "$FUZZER" "llm" || [ "$FUZZER" = "loopfuzz" ]; then

  # Run fuzzer-specific commands (if any)
  if [ -e ${WORKDIR}/run-${FUZZER} ]; then
    source ${WORKDIR}/run-${FUZZER}
  fi

  TARGET_DIR=${TARGET_DIR:-"proftpd"}
  INPUTS=${INPUTS:-${WORKDIR}"/in-ftp"}

  # Visibility unlock for the make_ftp_cmd OOB-read bug class: with the
  # default CommandBufferSize (512) the escape-run overshoot stays inside
  # the shared cmd pool block, so ASAN never sees it. 65535 makes cmd_buf
  # its own ~64KB pool allocation. Applies to every fuzzer equally (shared
  # basic.conf); benchmark arms must re-run all fuzzers under this env.
  grep -q '^CommandBufferSize' ${WORKDIR}/basic.conf 2>/dev/null || \
    sed -i '/^Port[[:space:]]/a CommandBufferSize\t65535' ${WORKDIR}/basic.conf

  #Step-1. Do Fuzzing
  #Move to fuzzing folder
  cd "$WORKDIR/${TARGET_DIR}" || { echo "[ERROR] missing fuzz working directory" >&2; exit 2; }
  CLEANUP="${WORKDIR}/clean"
  if [ "$FUZZER" = "loopfuzz" ]; then
    CLEANUP="bash /tmp/coverage-v4-src/fuzz_runtime/proftpd.sh"
    [ -f /tmp/coverage-v4-src/fuzz_runtime/proftpd.sh ] || { echo "missing live reset script" >&2; exit 2; }
  fi
  timeout -k 30s --preserve-status $TIMEOUT /home/ubuntu/${FUZZER_DIR}/afl-fuzz -d -i ${INPUTS} -o $OUTDIR -x ${WORKDIR}/ftp.dict -N tcp://127.0.0.1/21 $OPTIONS -c "$CLEANUP" ./proftpd -n -c ${WORKDIR}/basic.conf -X

  STATUS=$?

  #Step-2. Collect code coverage over time
  #Move to gcov folder
  if cd "$WORKDIR/proftpd-gcov"; then

  #The last argument passed to cov_script should be 0 if the fuzzer is afl/nwe and it should be 1 if the fuzzer is based on aflnet
  #0: the test case is a concatenated message sequence -- there is no message boundary
  #1: the test case is a structured file keeping several request messages
  if [ $FUZZER = "aflnwe" ]; then
    cov_script ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/ 21 ${SKIPCOUNT} ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_over_time.csv 0
  else
    cov_script ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/ 21 ${SKIPCOUNT} ${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_over_time.csv 1
  fi > "${WORKDIR}/${TARGET_DIR}/${OUTDIR}/coverage.log" 2>&1
  COVERAGE_STATUS=$?
  cat "${WORKDIR}/${TARGET_DIR}/${OUTDIR}/coverage.log"
  record_postprocess_failure "coverage replay" "$COVERAGE_STATUS"
  validate_loopfuzz_terminal "${WORKDIR}/${TARGET_DIR}/${OUTDIR}"
  TERMINAL_STATUS=$?
  record_postprocess_failure "coverage terminal validation" "$TERMINAL_STATUS"

  gcovr -r . --html --html-details -o index.html
  GCOVR_STATUS=$?
  record_postprocess_failure "gcovr report" "$GCOVR_STATUS"
  mkdir -p "${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_html/"
  MKDIR_STATUS=$?
  record_postprocess_failure "coverage report directory creation" "$MKDIR_STATUS"
  cp *.html "${WORKDIR}/${TARGET_DIR}/${OUTDIR}/cov_html/"
  COPY_STATUS=$?
  record_postprocess_failure "coverage report copy" "$COPY_STATUS"
  else
    COVERAGE_STATUS=$?
    record_postprocess_failure "coverage working-directory change" "$COVERAGE_STATUS"
  fi

  #Step-3. Save the result to the ${WORKDIR} folder
  #Tar all results to a file
  if cd "$WORKDIR/${TARGET_DIR}"; then
    tar -zcvf "${WORKDIR}/${OUTDIR}.tar.gz" "$OUTDIR"
    TAR_STATUS=$?
  else
    TAR_STATUS=$?
  fi
  record_postprocess_failure "result archive" "$TAR_STATUS"

  [ "$STATUS" -ne 0 ] || STATUS=$POSTPROCESS_STATUS
  exit "$STATUS"
fi
