#!/bin/bash
# proptpd replay-verify, take 3: workspace paths (the host /tmp cleaner ate
# the previous inputs), fresh output batch dir (root-owned files from take 1
# made host-side rm fail), rvk- container names.
set -u
BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
ANALYSIS=$BASE/benchmark/scripts/analysis
BATCH=$OUT/replay_verify_proftpd_fp5f818ed7_20261116
WORK=$BASE/ablation/.rv_work
LOG=$OUT/replay_verify_proftpd_v3_20261116.log
CORE_ARMS="pvstop1 salvage1 nollm1 wrapgate1 native1 calibrated1 cal_ewma1 cal_run_rate1"
: > "$LOG"
log(){ echo "[$(date '+%H:%M:%S')] $*" >> "$LOG"; }
mkdir -p "$BATCH" "$WORK"
for arm in $CORE_ARMS; do
  best=""
  for d in "$BASE"/ablation/results-proftpd_ablation_${arm}_20261115T*; do
    [[ -d "$d" ]] || continue
    ts=$(basename "$d" | sed -n "s/.*_\(20261115T[0-9]\{6\}\)$/\1/p"); [[ -z "$ts" ]] && continue
    [[ "$ts" < "20261115T181353" ]] && continue
    n=$(ls "$d"/out-*.tar.gz 2>/dev/null | wc -l); [[ -f "$d/run_summary.csv" ]] || continue
    (( n < 3 )) && continue
    [[ -z "$best" || "$d" > "$best" ]] && best="$d"
  done
  [ -z "$best" ] && { log "no dir $arm"; continue; }
  for r in 1 2 3; do
    (
      outsub="proftpd_${arm}_run${r}"
      inbox="$WORK/inbox-$outsub"; outdir="$BATCH/$outsub"
      rm -rf "$inbox" "$outdir"; mkdir -p "$inbox" "$outdir"
      src_tgz="$best/out-proptpd-loopfuzz_${r}.tar.gz"
      extracted=1
      for attempt in $(seq 1 60); do
        [ -f "$src_tgz" ] || { sleep 10; continue; }
        if tar xzf "$src_tgz" -C "$inbox"; then extracted=0; break; fi
        sleep 10
      done
      [ "$extracted" -eq 0 ] || { log "TAR-FAIL $outsub"; exit 1; }
      [ -d "$inbox/out-proptpd-loopfuzz/replayable-queue" ] || { log "NO-QUEUE $outsub"; exit 1; }
      cat > "$outdir/run-replay-and-audit.sh" << RUNNER
#!/bin/bash
set -u
cd /home/ubuntu/experiments/proftpd-gcov || exit 90
python3 /opt/analysis/coverage_v4.py replay --target proftpd --folder /replay-input/out-proptpd-loopfuzz \
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
log "=== proptpd replay-verify results ==="
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
log "=== take3 finished ==="
