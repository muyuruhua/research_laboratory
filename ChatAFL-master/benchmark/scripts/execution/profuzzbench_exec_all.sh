#!/bin/bash

export NUM_CONTAINERS="${NUM_CONTAINERS:-10}"
export TIMEOUT="${TIMEOUT:-86400}"
export SKIPCOUNT="${SKIPCOUNT:-1}"
export TEST_TIMEOUT="${TEST_TIMEOUT:-20000}"
RESULT_OWNER="${SUDO_USER:-$USER}"
RESULT_GROUP="$(id -gn "${RESULT_OWNER}")"

fix_result_permissions() {
    local path="$1"
    [[ -e "$path" ]] || return 0
    chown -R "${RESULT_OWNER}:${RESULT_GROUP}" "$path"
    chmod -R u+rwX "$path"
}

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
echo "标准模式"
echo "=========================================="
echo "# NUM_CONTAINERS: ${NUM_CONTAINERS}"
echo "# TIMEOUT: ${TIMEOUT} s"
echo "# SKIPCOUNT: ${SKIPCOUNT}"
echo "# TEST TIMEOUT: ${TEST_TIMEOUT} ms"
echo "# TARGET LIST: ${TARGET_LIST}"
echo "# FUZZER LIST: ${FUZZER_LIST}"
echo "=========================================="
echo

for TARGET in $(echo $TARGET_LIST | sed "s/,/ /g")
do

    for FUZZER in $(echo $FUZZER_LIST | sed "s/,/ /g")
    do

        echo
        echo "***** RUNNING $FUZZER ON $TARGET *****"
        echo

##### FTP #####

        if [[ $TARGET == "lightftp" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-lightftp_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lightftp $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-lightftp-aflnet "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lightftp $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-lightftp-chatafl "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lightftp $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-lightftp-chatafl_cl1 "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lightftp $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-lightftp-chatafl_cl2 "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lightftp $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-lightftp-chatafl_opt "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi


        if [[ $TARGET == "bftpd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-bftpd_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh bftpd $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-bftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh bftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-bftpd-chatafl "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi
            
            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh bftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-bftpd-chatafl_cl1 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh bftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-bftpd-chatafl_cl2 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh bftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-bftpd-chatafl_opt "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi


        if [[ $TARGET == "proftpd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-proftpd_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh proftpd $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-proftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh proftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-proftpd-chatafl "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh proftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-proftpd-chatafl_cl1 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh proftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-proftpd-chatafl_cl2 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh proftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-proftpd-chatafl_opt "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

        if [[ $TARGET == "pure-ftpd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-pure-ftpd_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh pure-ftpd $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-pure-ftpd-aflnet "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh pure-ftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-pure-ftpd-chatafl "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh pure-ftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-pure-ftpd-chatafl_cl1 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh pure-ftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-pure-ftpd-chatafl_cl2 "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh pure-ftpd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-pure-ftpd-chatafl_opt "-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi


##### SMTP #####

        if [[ $TARGET == "exim" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-exim_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh exim $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-exim-aflnet "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh exim $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-exim-chatafl "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh exim $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-exim-chatafl_cl1 "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh exim $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-exim-chatafl_cl2 "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh exim $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-exim-chatafl_opt "-P SMTP -D 10000 -q 3 -s 3 -E -K -W 100 -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi


##### RTSP #####

        if [[ $TARGET == "live555" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-live555_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh live555 $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-live555-aflnet "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh live555 $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-live555-chatafl "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh live555 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-live555-chatafl_cl1 "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh live555 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-live555-chatafl_cl2 "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh live555 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-live555-chatafl_opt "-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi


##### SIP #####

        if [[ $TARGET == "kamailio" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-kamailio_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh kamailio $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-kamailio-aflnet "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi
            
            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh kamailio $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-kamailio-chatafl "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh kamailio $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-kamailio-chatafl_cl1 "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh kamailio $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-kamailio-chatafl_cl2 "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh kamailio $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-kamailio-chatafl_opt "-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### DAAPD #####

        if [[ $TARGET == "forked-daapd" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-forked-daapd_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh forked-daapd $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-forked-daapd-aflnet "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh forked-daapd $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-forked-daapd-chatafl "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh forked-daapd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-forked-daapd-chatafl_cl1 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh forked-daapd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-forked-daapd-chatafl_cl2 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh forked-daapd $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-forked-daapd-chatafl_opt "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### HTTP #####

        if [[ $TARGET == "lighttpd1" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-lighttpd1_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lighttpd1 $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-lighttpd1-aflnet "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lighttpd1 $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-lighttpd1-chatafl "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lighttpd1 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-lighttpd1-chatafl_cl1 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lighttpd1 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-lighttpd1-chatafl_cl2 "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh lighttpd1 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-lighttpd1-chatafl_opt "-P HTTP -D 200000 -m none -q 3 -s 3 -E -K -R -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

##### MQTT #####

        if [[ $TARGET == "mosquitto" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-mosquitto_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-mosquitto-aflnet "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-mosquitto-chatafl "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-mosquitto-chatafl_cl1 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-mosquitto-chatafl_cl2 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-mosquitto-chatafl_opt "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

        if [[ $TARGET == "mosquitto-v2.0.18" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-mosquitto-v2.0.18_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto-v2.0.18 $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-mosquitto-v2.0.18-aflnet "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto-v2.0.18 $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-mosquitto-v2.0.18-chatafl "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto-v2.0.18 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-mosquitto-v2.0.18-chatafl_cl1 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto-v2.0.18 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-mosquitto-v2.0.18-chatafl_cl2 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto-v2.0.18 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-mosquitto-v2.0.18-chatafl_opt "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

        if [[ $TARGET == "mosquitto-v2.1.2" ]] || [[ $TARGET == "all" ]]
        then

            cd $PFBENCH
            RESULTS_DIR="results-mosquitto-v2.1.2_${TIMESTAMP}"
            mkdir -p ${RESULTS_DIR}

            if [[ $FUZZER == "aflnet" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto-v2.1.2 $NUM_CONTAINERS ${RESULTS_DIR} aflnet out-mosquitto-v2.1.2-aflnet "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto-v2.1.2 $NUM_CONTAINERS ${RESULTS_DIR} chatafl out-mosquitto-v2.1.2-chatafl "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl1" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto-v2.1.2 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl1 out-mosquitto-v2.1.2-chatafl_cl1 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-cl2" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto-v2.1.2 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-cl2 out-mosquitto-v2.1.2-chatafl_cl2 "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

            if [[ $FUZZER == "chatafl-opt" ]] || [[ $FUZZER == "all" ]]
            then
                profuzzbench_exec_common.sh mosquitto-v2.1.2 $NUM_CONTAINERS ${RESULTS_DIR} chatafl-opt out-mosquitto-v2.1.2-chatafl_opt "-P MQTT -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
            fi

        fi

        # Brief pause so background process startup messages print in order
        # before the next fuzzer's messages begin (docker run -d returns in <1s)
        sleep 2

    done

done

# 等待所有后台任务完成
wait

for RESULTS_DIR in results-*; do
    [[ -d "$RESULTS_DIR" ]] || continue
    fix_result_permissions "$RESULTS_DIR"
done

echo
echo "=========================================="
echo "✅ 标准模式测试完成"
echo "=========================================="

