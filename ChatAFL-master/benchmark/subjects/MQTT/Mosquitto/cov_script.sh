#!/bin/bash

QUEUE_DIR=$1
PORT=$2
SKIPCOUNT=$3
OUTPUT_FILE=$4
IS_AFLNET=$5

#cd to gcov folder
cd $WORKDIR/mosquitto-gcov

index=0
for f in ${QUEUE_DIR}queue/id*; do
  # Only keep every SKIPCOUNT-th file
  if [ $(( $index % $SKIPCOUNT )) -eq 0 ]; then
    # Start mosquitto server
    ${WORKDIR}/mosquitto/src/mosquitto -c ${WORKDIR}/mosquitto.conf &
    SERVER_PID=$!
    sleep 0.5

    if [ $IS_AFLNET -eq 0 ]; then
      # Single message
      nc -q1 127.0.0.1 $PORT < $f > /dev/null 2>&1
    else
      # Replay via aflnet-replay
      /home/ubuntu/aflnet/aflnet-replay $f TCP 127.0.0.1 $PORT 1 > /dev/null 2>&1
    fi

    kill -9 $SERVER_PID 2>/dev/null
    sleep 0.2
  fi
  index=$((index+1))
done

# Collect coverage
gcovr -r . 2>/dev/null | grep -E "^(TOTAL|branches)" | tail -1 | \
  awk '{print "'$index',"$4}' >> $OUTPUT_FILE
