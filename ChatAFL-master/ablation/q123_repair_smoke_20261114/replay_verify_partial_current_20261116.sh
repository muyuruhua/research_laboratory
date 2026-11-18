#!/bin/bash
set -euo pipefail

BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
ANALYSIS=$BASE/benchmark/scripts/analysis
OUT=$BASE/ablation/q123_repair_smoke_20261114
BATCH=$OUT/replay_verify_partial_masterv2_20261116T1945_v3
WINDOW_START=20261116T102347
LOG=$OUT/replay_verify_partial_masterv2_20261116T1945_v3.log
PARALLEL=4
PARTIAL_TARGET=${PARTIAL_TARGET:-all}
REPLAYER_BINARY=${PARTIAL_REPLAYER_BINARY:-$OUT/proftpd_loopfuzz_frame_ledger/aflnet-replay}

mkdir -p "$BATCH"
: > "$LOG"
log(){ echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }
[[ -x "$REPLAYER_BINARY" ]] || { log "missing frame-ledger replayer: $REPLAYER_BINARY"; exit 2; }

newest_dir(){
  local target=$1 arm=$2 best="" d ts n
  for d in "$BASE"/ablation/results-${target}_ablation_${arm}_20261116T*; do
    [[ -d "$d" ]] || continue
    ts=$(basename "$d" | sed -n 's/.*_\(20261116T[0-9]\{6\}\)$/\1/p')
    [[ -n "$ts" && "$ts" > "$WINDOW_START" ]] || continue
    n=$(find "$d" -maxdepth 1 -name "out-${target}-loopfuzz_*.tar.gz" | wc -l)
    [[ "$n" -eq 3 && -f "$d/run_summary.csv" ]] || continue
    [[ -z "$best" || "$d" > "$best" ]] && best="$d"
  done
  printf '%s' "$best"
}

run_replay(){
  local target=$1 image=$2 gcov=$3 port=$4 archive=$5 outsub=$6 run_user=$7
  local inbox=$BATCH/inputs-$outsub outdir=$BATCH/$outsub name=rvpartial-$outsub
  mkdir -p "$inbox" "$outdir"
  tar xzf "$archive" -C "$inbox"
  cat > "$outdir/run-replay-and-audit.sh" << RUNNER
#!/bin/bash
set -u
cd $gcov || exit 90
python3 /opt/analysis/coverage_v4.py replay --target $target --folder /replay-input/out-$target-loopfuzz \\
  --port $port --step 1 --mode 1 --require-coordinates --output /replay-out/cov.csv \\
  > /replay-out/replay.stdout 2> /replay-out/replay.stderr
rc=\$?
printf '%s\\n' "\$rc" > /replay-out/replay.exit-code
python3 /opt/analysis/coverage_v4.py audit /replay-out/cov.csv > /replay-out/audit.stdout 2> /replay-out/audit.stderr
arc=\$?
printf '%s\\n' "\$arc" > /replay-out/audit.exit-code
[ "\$rc" -eq 0 ] && [ "\$arc" -eq 0 ]
RUNNER
  sha256sum "$archive" | awk '{print $1}' > "$outdir/input-archive.sha256"
  docker create --name "$name" --user "$run_user" \
    --cpus=0.75 --memory=1g --memory-swap=1536m \
    --workdir "$gcov" \
    --env "WORKDIR=/home/ubuntu/experiments" \
    --env "COVERAGE_V4_RESET_COMMAND_JSON=[\"bash\",\"/opt/analysis/reset_commands/$target.sh\"]" \
    --env "COVERAGE_V4_LOOPFUZZ_REPLAYER=/tmp/loopfuzz-replayer/aflnet-replay" \
    --volume "$ANALYSIS:/opt/analysis:ro" \
    --volume "$REPLAYER_BINARY:/tmp/loopfuzz-replayer/aflnet-replay:ro" \
    --volume "$inbox:/replay-input:ro" \
    --volume "$outdir:/replay-out" \
    "$image" /bin/bash /replay-out/run-replay-and-audit.sh >/dev/null
  docker start "$name" >/dev/null
  log "START $outsub source=$(basename "$(dirname "$archive")")"
}

wait_for_slot(){
  while [ "$(docker ps --format '{{.Names}}' | grep -c '^rvpartial-' || true)" -ge "$PARALLEL" ]; do
    sleep 10
  done
}

pure=""
live=""
if [[ "$PARTIAL_TARGET" == all || "$PARTIAL_TARGET" == pureftpd ]]; then
  pure=$(newest_dir pure-ftpd nollm1)
  [[ -n "$pure" ]] || { log "missing current Pure-FTPd source archive directory"; exit 2; }
fi
if [[ "$PARTIAL_TARGET" == all || "$PARTIAL_TARGET" == live555 ]]; then
  live=$(newest_dir live555 calibrated1)
  [[ -n "$live" ]] || { log "missing current Live555 source archive directory"; exit 2; }
fi
if [[ "$PARTIAL_TARGET" != all && "$PARTIAL_TARGET" != pureftpd && "$PARTIAL_TARGET" != live555 ]]; then
  log "unknown PARTIAL_TARGET=$PARTIAL_TARGET"
  exit 2
fi
if [[ "$PARTIAL_TARGET" == all || "$PARTIAL_TARGET" == pureftpd ]]; then
  for repeat in 1 2 3; do
    wait_for_slot
    run_replay pure-ftpd pure-ftpd /home/ubuntu/experiments/pure-ftpd-gcov 21 \
      "$pure/out-pure-ftpd-loopfuzz_${repeat}.tar.gz" "pureftpd_nollm1_run${repeat}" root
  done
fi
if [[ "$PARTIAL_TARGET" == all || "$PARTIAL_TARGET" == live555 ]]; then
  wait_for_slot
  run_replay live555 live555 /home/ubuntu/experiments/live-gcov/testProgs 8554 \
    "$live/out-live555-loopfuzz_3.tar.gz" "live555_calibrated1_run3" ubuntu
fi

while [ "$(docker ps --format '{{.Names}}' | grep -c '^rvpartial-' || true)" -gt 0 ]; do sleep 20; done
docker rm $(docker ps -aq --filter 'name=^rvpartial-') >/dev/null 2>&1 || true
for outdir in "$BATCH"/pureftpd_nollm1_run* "$BATCH"/live555_calibrated1_run3; do
  [[ -d "$outdir" ]] || continue
  replay_rc=$(cat "$outdir/replay.exit-code" 2>/dev/null || echo missing)
  audit_rc=$(cat "$outdir/audit.exit-code" 2>/dev/null || echo missing)
  acceptance=$(python3 - "$outdir/cov.csv.v4/terminal.json" <<'PY'
import json,sys
try: print(json.load(open(sys.argv[1])).get("acceptance", "missing"))
except Exception: print("missing")
PY
)
  log "RESULT $(basename "$outdir") replay_rc=$replay_rc audit_rc=$audit_rc acceptance=$acceptance"
done
