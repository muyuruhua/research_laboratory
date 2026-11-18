#!/bin/bash
# replay_verify_batch_20261116.sh — replay-only verification of saved campaign
# corpora under the corrected replay harness (proptpd v3 natural-exit + frame
# completeness; pure-ftpd trailing-421 transcript extension). No mutation, no
# LLM; each container replays one archived corpus and runs the second-pass
# artifact audit (audition.md §3-4 pattern, cf. pureftpd_replay_policy_verified).
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
ANALYSIS=$BASE/benchmark/scripts/analysis
LOG=$OUT/replay_verify_batch_20261116.log
BATCH=$OUT/replay_verify_fp5f818ed7_20261116
CORE_ARMS="pvstop1 salvage1 nollm1 wrapgate1 native1 calibrated1 cal_ewma1 cal_run_rate1"
: > "$LOG"
log(){ echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOG"; }
mkdir -p "$BATCH"

# Wait for the remaining3 campaign batch to fully drain the host.
while pgrep -f "remaining3_campaigns_2026111[6]" >/dev/null 2>&1; do sleep 60; done
while [ "$(docker ps --format '{{.Names}}' | grep -c -- '-loopfuzz-run')" -gt 0 ]; do sleep 60; done
log "host drained; starting replay verification"

newest_dir(){ # target arm -> newest complete dir in final window
  local t=$1 arm=$2 best="" d ts n
  for d in "$BASE"/ablation/results-${t}_ablation_${arm}_20261115T*; do
    [[ -d "$d" ]] || continue
    ts=$(basename "$d" | sed -n "s/.*_\(20261115T[0-9]\{6\}\)$/\1/p"); [[ -z "$ts" ]] && continue
    [[ "$ts" < "20261115T181353" ]] && continue
    n=$(ls "$d"/out-*.tar.gz 2>/dev/null | wc -l); [[ -f "$d/run_summary.csv" ]] || continue
    (( n < 3 )) && continue
    [[ -z "$best" || "$d" > "$best" ]] && best="$d"
  done
  printf '%s' "$best"
}

run_replay(){ # target image gcovdir archive outsub
  local t=$1 image=$2 gcov=$3 archive=$4 outsub=$5
  local inbox="/tmp/rvin-$outsub"
  local outdir="$BATCH/$outsub"
  rm -rf "$inbox" "$outdir" && mkdir -p "$inbox" "$outdir"
  if ! tar xzf "$archive" -C "$inbox"; then log "EXTRACT-FAIL $outsub"; return 1; fi
  cat > "$outdir/run-replay-and-audit.sh" << RUNNER
#!/bin/bash
set -u
cd $gcov || exit 90
python3 /opt/analysis/coverage_v4.py replay --target $t --folder /replay-input/out-$t-loopfuzz \
  --port 21 --step 1 --mode 1 --require-coordinates --output /replay-out/cov.csv \
  > /replay-out/replay.stdout 2> /replay-out/replay.stderr
rc=\$?
printf '%s\n' "\$rc" > /replay-out/replay.exit-code
python3 /opt/analysis/coverage_v4.py audit /replay-out/cov.csv > /replay-out/audit.stdout 2> /replay-out/audit.stderr
arc=\$?
printf '%s\n' "\$arc" > /replay-out/audit.exit-code
[ "\$rc" -eq 0 ] && [ "\$arc" -eq 0 ]
RUNNER
  local image_id
  image_id=$(docker image inspect "$image" --format '{{.Id}}' 2>/dev/null) || { log "IMAGE-FAIL $image"; return 1; }
  printf '%s\n' "$image_id" > "$outdir/image-id.txt"
  sha256sum "$archive" | awk '{print $1}' > "$outdir/input-archive.sha256"
  docker rm -f "rv-$outsub" >/dev/null 2>&1
  docker create --name "rv-$outsub" --user root --network none \
    --workdir "$gcov" \
    --env "WORKDIR=/home/ubuntu/experiments" \
    --env "COVERAGE_V4_RESET_COMMAND_JSON=[\"bash\",\"/opt/analysis/reset_commands/$t.sh\"]" \
    --volume "$ANALYSIS:/opt/analysis:ro" \
    --volume "$inbox:/replay-input:ro" \
    --volume "$outdir:/replay-out" \
    "$image" /bin/bash /replay-out/run-replay-and-audit.sh >/dev/null || { log "CREATE-FAIL $outsub"; return 1; }
  docker start "rv-$outsub" >/dev/null || { log "START-FAIL $outsub"; return 1; }
}

pids=()
for arm in $CORE_ARMS; do
  d=$(newest_dir proftpd "$arm")
  [ -z "$d" ] && { log "no dir for proftpd/$arm"; continue; }
  for r in 1 2 3; do
    run_replay proftpd proftpd /home/ubuntu/experiments/proftpd-gcov \
      "$d/out-proftpd-loopfuzz_${r}.tar.gz" "proftpd_${arm}_run${r}" &
    pids+=($!)
    while [ "$(jobs -rp | wc -l)" -ge 12 ]; do sleep 20; done
  done
done
d=$(newest_dir pure-ftpd nollm1)
if [ -n "$d" ]; then
  for r in 1 2 3; do
    run_replay pure-ftpd pure-ftpd /home/ubuntu/experiments/pure-ftpd-gcov \
      "$d/out-pure-ftpd-loopfuzz_${r}.tar.gz" "pureftpd_nollm1_run${r}" &
    pids+=($!)
  done
fi
for p in "${pids[@]}"; do wait "$p"; done
while [ "$(docker ps --format '{{.Names}}' | grep -c '^rv-')" -gt 0 ]; do sleep 30; done

log "=== replay verification results ==="
for sub in "$BATCH"/*/; do
  name=$(basename "$sub")
  rc1=$(cat "$sub/replay.exit-code" 2>/dev/null || echo missing)
  rc2=$(cat "$sub/audit.exit-code" 2>/dev/null || echo missing)
  acc=$(python3 -c "
import json,sys
try:
    t=json.load(open('$sub/cov.csv.v4/terminal.json'))
    print(t.get('acceptance'), t.get('replay_anomalies',{}).get('total'))
except Exception as e: print('no-terminal')" 2>/dev/null)
  log "$name replay_rc=$rc1 audit_rc=$rc2 acceptance=$acc"
done
docker rm -f $(docker ps -aq --filter name='^rv-') >/dev/null 2>&1
log "=== replay verify finished ==="
