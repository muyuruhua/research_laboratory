#!/bin/bash

folder=$1   #fuzzer result folder
pno=$2      #port number
step=$3     #step to skip running gcovr and outputting data to covfile
            #e.g., step=5 means we run gcovr after every 5 test cases
covfile=$4  #path to coverage file
fmode=$5    #file mode -- structured or not
            #fmode = 0: the test case is a concatenated message sequence -- no message boundary
            #fmode = 1: the test case is a structured file keeping several request messages

#delete the existing coverage file
rm $covfile > /dev/null 2>&1; touch $covfile

#clear gcov data
cd $WORKDIR/mosquitto-gcov
gcovr -r . -s -d > /dev/null 2>&1

#output the header of the coverage file which is in the CSV format
#Time: timestamp, l_per/b_per and l_abs/b_abs: line/branch coverage in percentage and absolute number
echo "Time,l_per,l_abs,b_per,b_abs" >> $covfile

#files stored in replayable-* folders are structured
#in such a way that messages are separated
if [ $fmode -eq "1" ]; then
  testdir="replayable-queue"
  replayer="aflnet-replay"
else
  testdir="queue"
  replayer="afl-replay"
fi

#process initial seed corpus first
shopt -s nullglob
seed_files=($folder/$testdir/*.raw)
shopt -u nullglob

for f in "${seed_files[@]}"; do
  [ -f "$f" ] || continue
  time=$(stat -c %Y "$f" 2>/dev/null || echo "0")

  # Start gcov-instrumented mosquitto server
  $WORKDIR/mosquitto-gcov/src/mosquitto -c $WORKDIR/mosquitto.conf &
  SERVER_PID=$!
  sleep 0.5

  # Replay the test case
  if [ $fmode -eq "0" ]; then
    nc -q1 127.0.0.1 $pno < "$f" > /dev/null 2>&1
  else
    /home/ubuntu/aflnet/aflnet-replay "$f" MQTT $pno 1 > /dev/null 2>&1
  fi

  sleep 0.2
  kill -TERM $SERVER_PID 2>/dev/null
  # Wait for graceful shutdown (gcov flush needs this)
  for _i in $(seq 1 20); do
    kill -0 $SERVER_PID 2>/dev/null || break
    sleep 0.1
  done
  kill -9 $SERVER_PID 2>/dev/null
  wait $SERVER_PID 2>/dev/null

  cov_data=$(gcovr -r . -s | grep "[lb][a-z]*:")
  l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | rev | cut -c2- | rev)
  l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | cut -c2-)
  b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | rev | cut -c2- | rev)
  b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | cut -c2-)

  # Fallback to 0 for any empty values
  echo "${time:-0},${l_per:-0},${l_abs:-0},${b_per:-0},${b_abs:-0}" >> $covfile
done

#process fuzzer-generated testcases
count=0
shopt -s nullglob
id_files=($folder/$testdir/id*)
shopt -u nullglob

for f in "${id_files[@]}"; do
  [ -f "$f" ] || continue
  time=$(stat -c %Y "$f" 2>/dev/null || echo "0")

  # Start gcov-instrumented mosquitto server
  $WORKDIR/mosquitto-gcov/src/mosquitto -c $WORKDIR/mosquitto.conf &
  SERVER_PID=$!
  sleep 0.5

  # Replay the test case
  if [ $fmode -eq "0" ]; then
    nc -q1 127.0.0.1 $pno < "$f" > /dev/null 2>&1
  else
    /home/ubuntu/aflnet/aflnet-replay "$f" MQTT $pno 1 > /dev/null 2>&1
  fi

  sleep 0.2
  kill -TERM $SERVER_PID 2>/dev/null
  # Wait for graceful shutdown (gcov flush needs this)
  for _i in $(seq 1 20); do
    kill -0 $SERVER_PID 2>/dev/null || break
    sleep 0.1
  done
  kill -9 $SERVER_PID 2>/dev/null
  wait $SERVER_PID 2>/dev/null

  count=$(expr $count + 1)
  rem=$(expr $count % $step)
  if [ "$rem" != "0" ]; then continue; fi

  cov_data=$(gcovr -r . -s | grep "[lb][a-z]*:")
  l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | rev | cut -c2- | rev)
  l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | cut -c2-)
  b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | rev | cut -c2- | rev)
  b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | cut -c2-)

  echo "${time:-0},${l_per:-0},${l_abs:-0},${b_per:-0},${b_abs:-0}" >> $covfile
done

#output cov data for the last testcase(s) if step > 1
if [[ $step -gt 1 ]] && [[ ${#id_files[@]} -gt 0 ]]
then
  f="${id_files[-1]}"
  time=$(stat -c %Y "$f" 2>/dev/null || echo "0")
  cov_data=$(gcovr -r . -s | grep "[lb][a-z]*:")
  l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | rev | cut -c2- | rev)
  l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | cut -c2-)
  b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | rev | cut -c2- | rev)
  b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | cut -c2-)

  echo "${time:-0},${l_per:-0},${l_abs:-0},${b_per:-0},${b_abs:-0}" >> $covfile
fi
