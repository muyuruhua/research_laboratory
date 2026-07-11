#!/bin/bash

# Volume挂载开发模式的执行包装脚本
# 基于profuzzbench_exec_all.sh，但使用profuzzbench_exec_common_dev.sh

export NUM_CONTAINERS="${NUM_CONTAINERS:-10}"
export TIMEOUT="${TIMEOUT:-86400}"
export SKIPCOUNT="${SKIPCOUNT:-1}"
export TEST_TIMEOUT="${TEST_TIMEOUT:-20000}"
export PROJECT_ROOT="${PROJECT_ROOT:-$PWD/..}"
export RESULTS_ROOT="${RESULTS_ROOT:-.}"
RESULT_OWNER="${SUDO_USER:-$USER}"
RESULT_GROUP="$(id -gn "${RESULT_OWNER}")"

fix_result_permissions() {
    local path="$1"
    [[ -e "$path" ]] || return 0
    chown -R "${RESULT_OWNER}:${RESULT_GROUP}" "$path"
    chmod -R u+rwX "$path"
}

# Generate timestamp for results directory
# Allow caller to pre-set TIMESTAMP (e.g., ablation scripts inject label here)
export TIMESTAMP=${TIMESTAMP:-$(date "+%b-%d_%H-%M-%S")}

export TARGET_LIST=$1
export FUZZER_LIST=$2

if [[ "x$TARGET_LIST" == "x" ]] || [[ "x$FUZZER_LIST" == "x" ]]
then
    echo "Usage: $0 TARGET FUZZER"
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

echo
echo "=========================================="
echo "Volume挂载开发模式"
echo "=========================================="
echo "# NUM_CONTAINERS: ${NUM_CONTAINERS}"
echo "# TIMEOUT: ${TIMEOUT} s"
echo "# SKIPCOUNT: ${SKIPCOUNT}"
echo "# TEST TIMEOUT: ${TEST_TIMEOUT} ms"
echo "# TARGET LIST: ${TARGET_LIST}"
echo "# FUZZER LIST: ${FUZZER_LIST}"
echo "# PROJECT_ROOT: ${PROJECT_ROOT}"
echo "=========================================="
echo

for TARGET in $(echo $TARGET_LIST | sed "s/,/ /g")
do

    for FUZZER in $(echo $FUZZER_LIST | sed "s/,/ /g")
    do

        echo
        echo "***** RUNNING $FUZZER ON $TARGET (Volume Mode) *****"
        echo

##### FTP #####

        if [[ $TARGET == "lightftp" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-lightftp_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh lightftp $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-lightftp-aflnet "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh lightftp $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-lightftp-chatafl "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh lightftp $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-lightftp-chatafl_cl1 "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh lightftp $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-lightftp-chatafl_cl2 "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh lightftp $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-lightftp-loopfuzz "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### BFTPD #####

        if [[ $TARGET == "bftpd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-bftpd_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh bftpd $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-bftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh bftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-bftpd-chatafl "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh bftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-bftpd-chatafl_cl1 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh bftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-bftpd-chatafl_cl2 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh bftpd $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-bftpd-loopfuzz "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### PROFTPD #####

        if [[ $TARGET == "proftpd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-proftpd_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh proftpd $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-proftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh proftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-proftpd-chatafl "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh proftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-proftpd-chatafl_cl1 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh proftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-proftpd-chatafl_cl2 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh proftpd $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-proftpd-loopfuzz "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### PURE-FTPD #####

        if [[ $TARGET == "pure-ftpd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-pure-ftpd_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh pure-ftpd $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-pure-ftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh pure-ftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-pure-ftpd-chatafl "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh pure-ftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-pure-ftpd-chatafl_cl1 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh pure-ftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-pure-ftpd-chatafl_cl2 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh pure-ftpd $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-pure-ftpd-loopfuzz "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### SMTP #####

        if [[ $TARGET == "exim" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-exim_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh exim $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-exim-aflnet "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh exim $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-exim-chatafl "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh exim $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-exim-chatafl_cl1 "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh exim $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-exim-chatafl_cl2 "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh exim $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-exim-loopfuzz "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### RTSP #####

        if [[ $TARGET == "live555" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-live555_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh live555 $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-live555-aflnet "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh live555 $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-live555-chatafl "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh live555 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-live555-chatafl_cl1 "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh live555 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-live555-chatafl_cl2 "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh live555 $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-live555-loopfuzz "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### SIP #####

        if [[ $TARGET == "kamailio" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-kamailio_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh kamailio $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-kamailio-aflnet "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh kamailio $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-kamailio-chatafl "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh kamailio $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-kamailio-chatafl_cl1 "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh kamailio $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-kamailio-chatafl_cl2 "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh kamailio $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-kamailio-loopfuzz "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### DAAP #####

        if [[ $TARGET == "forked-daapd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-forked-daapd_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh forked-daapd $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-forked-daapd-aflnet "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh forked-daapd $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-forked-daapd-chatafl "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh forked-daapd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-forked-daapd-chatafl_cl1 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh forked-daapd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-forked-daapd-chatafl_cl2 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh forked-daapd $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-forked-daapd-loopfuzz "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### HTTP #####

        if [[ $TARGET == "lighttpd1" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-lighttpd1_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh lighttpd1 $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-lighttpd1-aflnet "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh lighttpd1 $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-lighttpd1-chatafl "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh lighttpd1 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-lighttpd1-chatafl_cl1 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh lighttpd1 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-lighttpd1-chatafl_cl2 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh lighttpd1 $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-lighttpd1-loopfuzz "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi


##### MQTT #####

        if [[ $TARGET == "mosquitto" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-mosquitto_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-mosquitto-aflnet "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-mosquitto-chatafl "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-mosquitto-chatafl_cl1 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-mosquitto-chatafl_cl2 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-mosquitto-loopfuzz "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

        if [[ $TARGET == "mosquitto-v2.0.18" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-mosquitto-v2.0.18_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto-v2.0.18 $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-mosquitto-v2.0.18-aflnet "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto-v2.0.18 $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-mosquitto-v2.0.18-chatafl "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto-v2.0.18 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-mosquitto-v2.0.18-chatafl_cl1 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto-v2.0.18 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-mosquitto-v2.0.18-chatafl_cl2 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto-v2.0.18 $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-mosquitto-v2.0.18-loopfuzz "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

        if [[ $TARGET == "mosquitto-v2.1.2" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-mosquitto-v2.1.2_${TIMESTAMP}"
            RESULTS_DIR="${RESULTS_ROOT}/${RESULTS_DIR}"
            mkdir -p "${RESULTS_DIR}"
            chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_DIR}"

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto-v2.1.2 $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-mosquitto-v2.1.2-aflnet "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto-v2.1.2 $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-mosquitto-v2.1.2-chatafl "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto-v2.1.2 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-mosquitto-v2.1.2-chatafl_cl1 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto-v2.1.2 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-mosquitto-v2.1.2-chatafl_cl2 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "loopfuzz" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh mosquitto-v2.1.2 $NUM_CONTAINERS ${RESULTS_DIR} loopfuzz out-mosquitto-v2.1.2-loopfuzz "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

        # Brief pause so background process startup messages print in order
        # before the next fuzzer's messages begin (docker run -d returns in <1s)
        sleep 2

    done

done

# 等待所有后台任务完成（移到这里实现并行执行）
wait

RECOVERY_HELPER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/recover_result_archives.sh"
for RESULTS_DIR in "${RESULTS_ROOT}"/results-*_"${TIMESTAMP}"; do
    [[ -d "$RESULTS_DIR" ]] || continue
    if [[ -f "$RECOVERY_HELPER" ]]; then
        bash "$RECOVERY_HELPER" "$RESULTS_DIR" || \
          echo "[WARN] Recovery pass failed for $RESULTS_DIR (exit $?)" >&2
    fi
    fix_result_permissions "$RESULTS_DIR"
done

echo
echo "=========================================="
echo "✅ Volume挂载模式测试完成"
echo "=========================================="
