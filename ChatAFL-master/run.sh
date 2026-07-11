#!/bin/bash

PFBENCH="$PWD/benchmark"
cd $PFBENCH

PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis
NUM_CONTAINERS=$1
TIMEOUT=$(( ${2:-1440} * 60))
SKIPCOUNT="${SKIPCOUNT:-1}"
TEST_TIMEOUT="${TEST_TIMEOUT:-5000}"

export TARGET_LIST=$3
export FUZZER_LIST=$4

if [[ "x$NUM_CONTAINERS" == "x" ]] || [[ "x$TIMEOUT" == "x" ]] || [[ "x$TARGET_LIST" == "x" ]] || [[ "x$FUZZER_LIST" == "x" ]]
then
    echo "Usage: $0 NUM_CONTAINERS TIMEOUT TARGET FUZZER"
    echo "Known fuzzers: aflnet,chatafl,chatafl-cl1,chatafl-cl2,loopfuzz,all"
    exit 1
fi

normalize_fuzzer_list() {
    local raw="$1" item canon out=""
    for item in $(echo "$raw" | tr ',' ' '); do
        case "$item" in
            loopfuzz|LoopFuzz) canon="loopfuzz" ;;
            aflnet|chatafl|chatafl-cl1|chatafl-cl2|all) canon="$item" ;;
            "")
                continue
                ;;
            *)
                echo "[ERROR] Unknown fuzzer: $item" >&2
                echo "[ERROR] Known fuzzers: aflnet,chatafl,chatafl-cl1,chatafl-cl2,loopfuzz,all" >&2
                exit 2
                ;;
        esac
        out="${out:+$out,}$canon"
    done
    if [[ -z "$out" ]]; then
        echo "[ERROR] Empty fuzzer list" >&2
        exit 2
    fi
    echo "$out"
}

validate_target_list() {
    local raw="$1" item
    for item in $(echo "$raw" | tr ',' ' '); do
        case "$item" in
            lightftp|bftpd|proftpd|pure-ftpd|exim|live555|kamailio|forked-daapd|lighttpd1|mosquitto|mosquitto-v2.0.18|mosquitto-v2.1.2|all)
                ;;
            "")
                continue
                ;;
            *)
                echo "[ERROR] Unknown target: $item" >&2
                echo "[ERROR] Known targets: lightftp,bftpd,proftpd,pure-ftpd,exim,live555,kamailio,forked-daapd,lighttpd1,mosquitto,mosquitto-v2.0.18,mosquitto-v2.1.2,all" >&2
                exit 2
                ;;
        esac
    done
}

validate_target_list "$TARGET_LIST"
FUZZER_LIST="$(normalize_fuzzer_list "$FUZZER_LIST")" || exit $?
export FUZZER_LIST

PFBENCH=$PFBENCH PATH=$PATH NUM_CONTAINERS=$NUM_CONTAINERS TIMEOUT=$TIMEOUT SKIPCOUNT=$SKIPCOUNT TEST_TIMEOUT=$TEST_TIMEOUT KEY="$KEY" \
  CHATAFL_NO_REFINEMENT="${CHATAFL_NO_REFINEMENT}" \
  CHATAFL_NO_FRONTIER="${CHATAFL_NO_FRONTIER}" \
  CHATAFL_NO_ADAPTIVE="${CHATAFL_NO_ADAPTIVE}" \
  CHATAFL_NO_STATE_PROMPT="${CHATAFL_NO_STATE_PROMPT}" \
  CHATAFL_ABLATION_THRESHOLD="${CHATAFL_ABLATION_THRESHOLD}" \
  scripts/execution/profuzzbench_exec_all.sh ${TARGET_LIST} ${FUZZER_LIST}
