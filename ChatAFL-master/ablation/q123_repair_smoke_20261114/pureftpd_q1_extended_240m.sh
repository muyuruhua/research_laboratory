#!/bin/bash
# Pure-FTPd Q1 fixed-dose rerun with a 240-minute wall-clock allowance.
# This is intentionally a single-target driver so it cannot overlap another
# target in the main Q1 queue and its manifest stays independent of that queue.
set -u

BASE=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
OUT=$BASE/ablation/q123_repair_smoke_20261114
TARGET=pure-ftpd
ARMS=q1a1,q1b1,q1c1,q1d1
START_TS=$(date +%Y%m%dT%H%M%S)
BATCH_ID="pureq1-240-${START_TS}-$$"
LAUNCH_LOG="$OUT/pureftpd_q1_extended_${BATCH_ID}.launch.log"
RUN_LOG="$OUT/pureftpd_q1_extended_${BATCH_ID}.log"
MANIFEST="$OUT/pureftpd_q1_extended_${BATCH_ID}.manifest.jsonl"
AUDIT_LOG="$OUT/audit_pure-ftpd_q1_${BATCH_ID}.txt"
VERIFY_LOG="$OUT/verify_pure-ftpd_q1_${BATCH_ID}.jsonl"

exec > >(tee -a "$RUN_LOG") 2>&1
echo "batch=$BATCH_ID target=$TARGET arms=$ARMS runs=3 timeout_min=240 call_budget=5000"
echo "command=env ABLATION_THRESHOLD_OVERRIDE=1 ABLATION_WARMUP_MAX_OVERRIDE=8 ABLATION_EPISODE_ENERGY_OVERRIDE=32 ABLATION_CAL_REWARD_WINDOW_OVERRIDE=16 ABLATION_CALL_BUDGET_OVERRIDE=5000 ABLATION_MEM_PER_FUZZER=2 ABLATION_DOCKER_MEM_CAP=2g ABLATION_PARALLEL=1 ABLATION_SHUFFLE=1 CHATAFL_MOCK_LLM=1 MOCK_PORT=18132 MOCK_LATENCY=1 MOCK_ERROR_RATE=1.5 MOCK_SEED=20261102 KEY=loopfuzz-mock-key SKIPCOUNT=40 ./run_ablation.sh pure-ftpd 3 240 --groups q1a1,q1b1,q1c1,q1d1"

if docker ps --format '{{.Names}}' | grep -q '^pure-ftpd-loopfuzz-run'; then
  echo "REFUSED: pure-ftpd containers are already running; no same-target overlap allowed" >&2
  exit 3
fi

CHECK=$(ABLATION_DRY_RUN=1 ABLATION_CALL_BUDGET_OVERRIDE=5000 \
  bash "$BASE/run_ablation.sh" "$TARGET" 1 240 --groups q1a1 2>&1 |
  grep 'SHARED_OVERRIDES' | grep -o 'call_budget=5000' || true)
if [ "$CHECK" != "call_budget=5000" ]; then
  echo "REFUSED: pre-launch budget check failed" >&2
  exit 2
fi
echo "pre-launch check ok: call_budget=5000, timeout=240"

(
  cd "$BASE" || exit 1
  env ABLATION_THRESHOLD_OVERRIDE=1 ABLATION_WARMUP_MAX_OVERRIDE=8 \
    ABLATION_EPISODE_ENERGY_OVERRIDE=32 ABLATION_CAL_REWARD_WINDOW_OVERRIDE=16 \
    ABLATION_CALL_BUDGET_OVERRIDE=5000 ABLATION_MEM_PER_FUZZER=2 \
    ABLATION_DOCKER_MEM_CAP=2g ABLATION_PARALLEL=1 ABLATION_SHUFFLE=1 \
    CHATAFL_MOCK_LLM=1 MOCK_PORT=18132 MOCK_LATENCY=1 MOCK_ERROR_RATE=1.5 \
    MOCK_SEED=20261102 KEY=loopfuzz-mock-key SKIPCOUNT=40 \
    ./run_ablation.sh "$TARGET" 3 240 --groups "$ARMS"
) > "$LAUNCH_LOG" 2>&1
LAUNCH_RC=$?
cat "$LAUNCH_LOG"
echo "launcher_rc=$LAUNCH_RC"

: > "$MANIFEST"
declare -a DIRS=()
for arm in q1a1 q1b1 q1c1 q1d1; do
  count=$(grep -cE "ABLATION:${arm}\] 启动" "$LAUNCH_LOG" || true)
  if [ "$count" -ne 1 ]; then
    echo "PIN-FAIL $TARGET/$arm: launcher printed $count start lines" >&2
    continue
  fi
  d=$(grep -E "ABLATION:${arm}\] 启动" "$LAUNCH_LOG" |
      grep -o 'ablation/results-[^ ]*' | tail -1 |
      sed "s|^ablation/|$BASE/ablation/|")
  if [ -z "$d" ] || [ ! -d "$d" ]; then
    echo "PIN-FAIL $TARGET/$arm: result directory missing: $d" >&2
    continue
  fi
  printf '{"target":"%s","arm":"%s","dir":"%s","batch":"%s"}\n' \
    "$TARGET" "$arm" "$d" "$BATCH_ID" >> "$MANIFEST"
  DIRS+=("$d")
  echo "PIN $TARGET/$arm -> $d"
done

if [ "${#DIRS[@]}" -ne 4 ]; then
  echo "AUDIT-REFUSED: expected four pinned Q1 directories, got ${#DIRS[@]}" >&2
  exit 4
fi

(
  cd "$OUT" || exit 1
  python3 audit_smoke.py --target "$TARGET" --timeout-min 240 --protocol FTP \
    --arms q1 "${DIRS[@]}"
) > "$AUDIT_LOG" 2>&1
AUDIT_RC=$?
cat "$AUDIT_LOG"

: > "$VERIFY_LOG"
VERIFY_RC=0
for d in "${DIRS[@]}"; do
  for tgz in "$d"/out-*.tar.gz; do
    out=$(python3 "$OUT/verify_q1_repeat.py" "$tgz") || {
      echo "VERIFY-FAIL $tgz $out" | tee -a "$VERIFY_LOG" >&2
      VERIFY_RC=1
      continue
    }
    printf '%s\n' "$out" | tee -a "$VERIFY_LOG"
    classification=$(printf '%s\n' "$out" | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["classification"])')
    charged=$(printf '%s\n' "$out" | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["charged_calls"])')
    [ "$classification" = "budget-exhausted" ] || {
      echo "VERIFY-FAIL $tgz classification=$classification charged_calls=$charged" >&2
      VERIFY_RC=1
    }
  done
done

echo "result_manifest=$MANIFEST"
echo "audit_log=$AUDIT_LOG"
echo "verify_log=$VERIFY_LOG"
echo "finished launcher_rc=$LAUNCH_RC audit_rc=$AUDIT_RC verify_rc=$VERIFY_RC"
[ "$LAUNCH_RC" -eq 0 ] && [ "$AUDIT_RC" -eq 0 ] && [ "$VERIFY_RC" -eq 0 ]
