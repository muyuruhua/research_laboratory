#!/bin/bash

folder=$1   #fuzzer result folder
pno=$2      #port number
step=$3     #step to skip running gcovr and outputting data to covfile
            #e.g., step=5 means we run gcovr after every 5 test cases
covfile=$4  #path to coverage file
fmode=$5    #file mode -- structured or not
            #fmode = 0: the test case is a concatenated message sequence -- there is no message boundary
            #fmode = 1: the test case is a structured file keeping several request messages

#delete the existing coverage file
rm $covfile > /dev/null 2>&1; touch $covfile

#clear gcov data
gcovr -r forked-daapd-gcov -s -d > /dev/null 2>&1

#output the header of the coverage file which is in the CSV format
#Time: timestamp, l_per/b_per and l_abs/b_abs: line/branch coverage in percentage and absolutate number
echo "Time,l_per,l_abs,b_per,b_abs,idx" >> $covfile
idx=0
prev_t=0
first_t=0

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
for f in $(echo $folder/$testdir/*.raw); do 
  time=$(stat -c %Y $f)
  # v3 (P0-3): timestamps must be monotone; idx = replay order.
  [ "$time" -lt "$prev_t" ] && time=$prev_t
  prev_t=$time
  [ "$first_t" -eq 0 ] && first_t=$time
  idx=$(expr $idx + 1)

  (sleep 1 && $replayer $f HTTP $pno 100 10000 > /dev/null 2>&1) &
  timeout -k 1s -s SIGUSR1 10s ./forked-daapd-gcov/src/forked-daapd -d 0 -c ./forked-daapd.conf -f > /dev/null 2>&1
  
  wait
  cov_data=$(gcovr -r forked-daapd-gcov -s | grep "[lb][a-z]*:")
  l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | rev | cut -c2- | rev)
  l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | cut -c2-)
  b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | rev | cut -c2- | rev)
  b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | cut -c2-)
  
  echo "$time,$l_per,$l_abs,$b_per,$b_abs,$idx" >> $covfile
done

#process fuzzer-generated testcases
count=0
for f in $(echo $folder/$testdir/id*); do 
  time=$(stat -c %Y $f)
  # v3 (P0-3): timestamps must be monotone; idx = replay order.
  [ "$time" -lt "$prev_t" ] && time=$prev_t
  prev_t=$time
  [ "$first_t" -eq 0 ] && first_t=$time
  idx=$(expr $idx + 1)

  (sleep 1 && $replayer $f HTTP $pno 100 10000 > /dev/null 2>&1) &
  timeout -k 1s -s SIGUSR1 10s ./forked-daapd-gcov/src/forked-daapd -d 0 -c ./forked-daapd.conf -f > /dev/null 2>&1

  wait
  count=$(expr $count + 1)
  rem=$(expr $count % $step)
  if [ "$rem" != "0" ]; then continue; fi
  cov_data=$(gcovr -r forked-daapd-gcov -s | grep "[lb][a-z]*:")
  l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | rev | cut -c2- | rev)
  l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | cut -c2-)
  b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | rev | cut -c2- | rev)
  b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | cut -c2-)
  
  echo "$time,$l_per,$l_abs,$b_per,$b_abs,$idx" >> $covfile
done

#ouput cov data for the last testcase(s) if step > 1
if [[ $step -gt 1 ]]
then
  time=$(stat -c %Y $f)
  [ "$time" -lt "$prev_t" ] && time=$prev_t
  prev_t=$time
  cov_data=$(gcovr -r forked-daapd-gcov -s | grep "[lb][a-z]*:")
  l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | rev | cut -c2- | rev)
  l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | cut -c2-)
  b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | rev | cut -c2- | rev)
  b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | cut -c2-)
  
  echo "$time,$l_per,$l_abs,$b_per,$b_abs,$idx" >> $covfile
fi

# ── v3 (P0-3) campaign-end terminal row + audit sidecar ─────────────
end_ts=$(grep -a "^last_update" "$folder/fuzzer_stats" 2>/dev/null | head -1 | tr -dc '0-9')
start_ts=$(grep -a "^start_time" "$folder/fuzzer_stats" 2>/dev/null | head -1 | tr -dc '0-9')
if [ -n "$end_ts" ] && [ "$end_ts" -ge "$prev_t" ] 2>/dev/null; then
  cov_data=$(gcovr -r . -s | grep "[lb][a-z]*:")
  l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | rev | cut -c2- | rev)
  l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | cut -c2-)
  b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | rev | cut -c2- | rev)
  b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | cut -c2-)
  echo "$end_ts,$l_per,$l_abs,$b_per,$b_abs,$idx" >> $covfile
fi
printf '{"cov_script_schema":"v3","n_replayed":%s,"first_mtime":%s,"last_mtime":%s,"campaign_start":%s,"campaign_end":%s,"step":%s,"fmode":%s}\n' \
  "$idx" "$first_t" "$prev_t" "$start_ts" "$end_ts" "$step" "$fmode" > "${covfile}.audit"
