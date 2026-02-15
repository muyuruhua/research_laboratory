#!/bin/bash

# Volume挂载开发模式的执行包装脚本
# 基于profuzzbench_exec_all.sh，但使用profuzzbench_exec_common_dev.sh

export NUM_CONTAINERS="${NUM_CONTAINERS:-10}"
export TIMEOUT="${TIMEOUT:-86400}"
export SKIPCOUNT="${SKIPCOUNT:-1}"
export TEST_TIMEOUT="${TEST_TIMEOUT:-20000}"
export PROJECT_ROOT="${PROJECT_ROOT:-$PWD/..}"

# Generate timestamp for results directory
export TIMESTAMP=$(date "+%b-%d_%H-%M-%S")

export TARGET_LIST=$1
export FUZZER_LIST=$2

if [[ "x$TARGET_LIST" == "x" ]] || [[ "x$FUZZER_LIST" == "x" ]]
then
    echo "Usage: $0 TARGET FUZZER"
    exit 1
fi

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

for FUZZER in $(echo $FUZZER_LIST | sed "s/,/ /g")
do

    for TARGET in $(echo $TARGET_LIST | sed "s/,/ /g")
    do

        echo
        echo "***** RUNNING $FUZZER ON $TARGET (Volume Mode) *****"
        echo

##### FTP #####

        if [[ $TARGET == "lightftp" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-lightftp_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

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

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh lightftp $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-lightftp-chatafl_opt "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### BFTPD #####

        if [[ $TARGET == "bftpd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-bftpd_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

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

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common_dev.sh bftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-bftpd-chatafl_opt "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

    done

done

# 等待所有后台任务完成（移到这里实现并行执行）
wait

echo
echo "=========================================="
echo "✅ Volume挂载模式测试完成"
echo "=========================================="
