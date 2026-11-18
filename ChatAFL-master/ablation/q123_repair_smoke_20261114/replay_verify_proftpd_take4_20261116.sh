#!/bin/bash
# take4: inputs pre-copied to .rv_work/archives (host path-resolution anomaly
# workaround); containers mount the extracted copies.
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
ANALYSIS=$BASE/benchmark/scripts/analysis
BATCH=$OUT/replay_verify_proftpd_fp5f818ed7_20261116
WORK=$BASE/ablation/.rv_work
LOG=$OUT/replay_verify_proftpd_take4_20261116.log
CORE_ARMS="pvstop1 salvage1 nollm1 wrapgate1 native1 calibrated1 cal_ewma1 cal_run_rate1"
: > "$LOG"
log(){ echo "[$(date '+%H:%M:%S')] $*" >> "$LOG"; }
mkdir -p "$BATCH"
for arm in $CORE_ARMS; do
  for r in 1 2 3; do
    (
      outsub="proftpd_${arm}_run${r}"
      inbox="$WORK/inbox-$outsub"; outdir="$BATCH/$outsub"
      rm -rf "$inbox" "$outdir"; mkdir -p "$inbox" "$outdir"
      tar xzf "$WORK/archives/${outsub}.tar.gz" -C "$inbox" 2>>"$LOG.err" || { log "TAR-FAIL $outsub"; exit 1; }
      find "$inbox" -maxdepth 2 -type d -name replayable-queue | grep -q . || { log "NO-QUEUE $outsub"; exit 1; }
      cat > "$outdir/run-replay-and-audit.sh" << RUNNER
#!/bin/bash
set -u
cd /home/ubuntu/experiments/proftpd-gcov || exit 90
python3 /opt/analysis/coverage_v4.py replay --target proftpd --folder /replay-input/out-proftpd-loopfuzz \
  --port 21 --step 1 --mode 1 --require-coordinates --output /replay-out/cov.csv \
  > /replay-out/replay.stdout 2> /replay-out/replay.stderr
rc=\$?
printf '%s\n' "\$rc" > /replay-out/replay.exit-code
python3 /opt/analysis/coverage_v4.py audit /replay-out/cov.csv > /replay-out/audit.stdout 2> /replay-out/audit.stderr
arc=\$?
printf '%s\n' "\$arc" > /replay-out/audit.exit-code
[ "\$rc" -eq 0 ] && [ "\$arc" -eq 0 ]
RUNNER
      docker rm -f "rvk-$outsub" >/dev/null 2>&1
      docker create --name "rvk-$outsub" --user root \
        --add-host "$(hostname):127.0.0.1" \
        --workdir /home/ubuntu/experiments/proftpd-gcov \
        --env "WORKDIR=/home/ubuntu/experiments" \
        --env "COVERAGE_V4_RESET_COMMAND_JSON=[\"bash\",\"/opt/analysis/reset_commands/proftpd.sh\"]" \
        --volume "$ANALYSIS:/opt/analysis:ro" \
        --volume "$inbox:/replay-input:ro" \
        --volume "$outdir:/replay-out" \
        proftpd /bin/bash /replay-out/run-replay-and-audit.sh >/dev/null && \
      docker start "rvk-$outsub" >/dev/null || log "START-FAIL $outsub"
    ) &
    while [ "$(jobs -rp | wc -l)" -ge 12 ]; do sleep 20; done
  done
done
wait
while [ "$(docker ps --format '{{.Names}}' | grep -c '^rvk-')" -gt 0 ]; do sleep 30; done
log "=== take4 results ==="
for sub in "$BATCH"/*/; do
  name=$(basename "$sub")
  rc1=$(cat "$sub/replay.exit-code" 2>/dev/null || echo missing)
  rc2=$(cat "$sub/audit.exit-code" 2>/dev/null || echo missing)
  acc=$(python3 -c "
import json
try:
    t=json.load(open('$sub/cov.csv.v4/terminal.json'))
    print(t.get('acceptance'), t.get('replay_anomalies',{}).get('total'))
except Exception: print('no-terminal')" 2>/dev/null)
  log "$name replay_rc=$rc1 audit_rc=$rc2 acceptance=$acc"
done
docker rm -f $(docker ps -aq --filter "name=^rvk-") >/dev/null 2>&1
log "=== take4 finished ==="
