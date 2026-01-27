#!/bin/bash

# ============================================================================
# Parallel Coverage Collection Wrapper (OCP-Compliant)
# ============================================================================
# Design Principle: Open-Closed Principle (OCP)
# - Closed for modification: Original cov_script.sh remains untouched
# - Open for extension: Adds parallel processing capability via wrapper pattern
#
# Architecture: Strategy Pattern + Graceful Degradation
# - Detects GNU parallel availability at runtime
# - Falls back to original serial cov_script.sh if parallel not available
# - Zero performance impact when disabled
#
# Usage:
#   ./parallel_cov_wrapper.sh <folder> <port> <skipcount> <covfile> <fmode>
#
# Environment Variables:
#   PARALLEL_MODE=0     : Force disable parallel mode
#   PARALLEL_JOBS=N     : Override parallel job count (default: 8)
#   SKIPCOUNT=N         : Skip every N test cases (default: 1)
# ============================================================================

folder=$1   # fuzzer result folder
pno=$2      # port number
step=$3     # step to skip running gcovr
covfile=$4  # path to coverage file
fmode=$5    # file mode (0=concatenated, 1=structured)

# ============================================================================
# Phase 1: Environment Detection and Validation
# ============================================================================

# Check if parallel mode is explicitly disabled
if [ "${PARALLEL_MODE:-1}" = "0" ]; then
  echo "[INFO] Parallel mode disabled via PARALLEL_MODE=0, falling back to serial"
  exec ./cov_script.sh "$@"
  exit $?
fi

# Check GNU parallel availability
if ! command -v parallel &> /dev/null; then
  echo "[WARNING] GNU parallel not found, falling back to serial mode"
  echo "[HINT] Install with: sudo apt install parallel"
  exec ./cov_script.sh "$@"
  exit $?
fi

# Validate input parameters
if [ -z "$folder" ] || [ -z "$pno" ] || [ -z "$step" ] || [ -z "$covfile" ] || [ -z "$fmode" ]; then
  echo "[ERROR] Missing required parameters"
  echo "Usage: $0 <folder> <port> <skipcount> <covfile> <fmode>"
  exit 1
fi

# ============================================================================
# Phase 2: Parallel Processing Configuration
# ============================================================================

PARALLEL_JOBS=${PARALLEL_JOBS:-8}
TEMP_DIR=$(mktemp -d /tmp/parallel_cov.XXXXXX)
trap "rm -rf $TEMP_DIR" EXIT

echo "[INFO] Parallel coverage collection enabled"
echo "[INFO] Jobs: $PARALLEL_JOBS | SKIPCOUNT: $step | Mode: $fmode"

# Delete existing coverage file and initialize
rm "$covfile" > /dev/null 2>&1
touch "$covfile"

# Clear gcov data
gcovr -r mosquitto-gcov -s -d > /dev/null 2>&1

# Output CSV header
echo "Time,l_per,l_abs,b_per,b_abs" >> "$covfile"

# Determine test directory and replayer based on file mode
if [ "$fmode" -eq "1" ]; then
  testdir="replayable-queue"
  replayer="aflnet-replay"
else
  testdir="queue"
  replayer="afl-replay"
fi

# ============================================================================
# Phase 3: Process Initial Seed Corpus (Serial - typically small)
# ============================================================================

echo "[INFO] Processing initial seed corpus (serial)..."
seed_count=0
for f in $(echo $folder/$testdir/*.raw 2>/dev/null); do
  if [ ! -f "$f" ]; then continue; fi
  
  time=$(stat -c %Y "$f")
  
  $replayer "$f" MQTT $pno 1 > /dev/null 2>&1 &
  timeout -k 1s -s SIGTERM 3s ./mosquitto-gcov/src/mosquitto -c ./mosquitto.conf -p $pno > /dev/null 2>&1
  
  wait
  cov_data=$(gcovr -r mosquitto-gcov -s | grep "[lb][a-z]*:")
  l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | rev | cut -c2- | rev)
  l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | cut -c2-)
  b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | rev | cut -c2- | rev)
  b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | cut -c2-)
  
  echo "$time,$l_per,$l_abs,$b_per,$b_abs" >> "$covfile"
  seed_count=$((seed_count + 1))
done

echo "[INFO] Processed $seed_count seed files"

# ============================================================================
# Phase 4: Parallel Processing of Fuzzer-Generated Test Cases
# ============================================================================

# Generate list of test cases to process (applying SKIPCOUNT filter)
testcase_list="$TEMP_DIR/testcases.txt"
count=0
> "$testcase_list"

for f in $(echo $folder/$testdir/id* 2>/dev/null); do
  if [ ! -f "$f" ]; then continue; fi
  
  count=$((count + 1))
  rem=$((count % step))
  
  if [ "$rem" = "0" ]; then
    echo "$f" >> "$testcase_list"
  fi
done

# Handle last test case if step > 1
if [ "$step" -gt 1 ]; then
  last_file=$(ls -1 $folder/$testdir/id* 2>/dev/null | tail -1)
  if [ -n "$last_file" ] && [ -f "$last_file" ]; then
    if ! grep -Fxq "$last_file" "$testcase_list"; then
      echo "$last_file" >> "$testcase_list"
    fi
  fi
fi

total_tasks=$(wc -l < "$testcase_list")
echo "[INFO] Processing $total_tasks fuzzer-generated test cases in parallel..."

if [ "$total_tasks" -eq 0 ]; then
  echo "[INFO] No fuzzer-generated test cases to process"
  exit 0
fi

# ============================================================================
# Phase 5: Parallel Execution with GNU Parallel
# ============================================================================

# Define the processing function for each test case
process_testcase() {
  local testfile=$1
  local port=$2
  local mode=$3
  local replayer=$4
  local job_id=$5
  
  # Get timestamp
  local timestamp=$(stat -c %Y "$testfile")
  
  # Run test case
  $replayer "$testfile" MQTT $port 1 > /dev/null 2>&1 &
  timeout -k 1s -s SIGTERM 3s ./mosquitto-gcov/src/mosquitto -c ./mosquitto.conf -p $port > /dev/null 2>&1
  
  wait
  
  # Collect coverage
  local cov_data=$(gcovr -r mosquitto-gcov -s 2>/dev/null | grep "[lb][a-z]*:")
  local l_per=$(echo "$cov_data" | grep lines | cut -d" " -f2 | rev | cut -c2- | rev)
  local l_abs=$(echo "$cov_data" | grep lines | cut -d" " -f3 | cut -c2-)
  local b_per=$(echo "$cov_data" | grep branch | cut -d" " -f2 | rev | cut -c2- | rev)
  local b_abs=$(echo "$cov_data" | grep branch | cut -d" " -f3 | cut -c2-)
  
  # Output result
  echo "$timestamp,$l_per,$l_abs,$b_per,$b_abs"
}

# Export function and variables for parallel
export -f process_testcase
export pno replayer fmode

# Run parallel processing with progress bar
cat "$testcase_list" | \
  parallel --jobs "$PARALLEL_JOBS" \
           --line-buffer \
           --tagstring "[Job {%}]" \
           --bar \
           process_testcase {} "$pno" "$fmode" "$replayer" {%} \
  >> "$TEMP_DIR/parallel_results.csv"

# ============================================================================
# Phase 6: Merge Results and Sort by Timestamp
# ============================================================================

echo "[INFO] Merging parallel results..."

# Sort by timestamp (first column) and append to coverage file
if [ -f "$TEMP_DIR/parallel_results.csv" ]; then
  sort -t, -k1 -n "$TEMP_DIR/parallel_results.csv" >> "$covfile"
  result_count=$(wc -l < "$TEMP_DIR/parallel_results.csv")
  echo "[INFO] Merged $result_count coverage data points"
else
  echo "[WARNING] No parallel results generated"
fi

# ============================================================================
# Phase 7: Summary and Cleanup
# ============================================================================

total_lines=$(wc -l < "$covfile")
echo "[INFO] Parallel coverage collection complete"
echo "[INFO] Total data points: $((total_lines - 1))"  # Exclude header
echo "[INFO] Coverage file: $covfile"

# Cleanup temp directory (handled by trap)
exit 0
