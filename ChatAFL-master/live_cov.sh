#!/bin/bash
# ─── live_cov.sh ─────────────────────────────────────────────────────────────
# Real-time l_abs / b_abs snapshot for running fuzzer containers.
# Runs INSIDE the container via: docker exec <CID> bash /path/to/live_cov.sh
#
# Approach: replay all queue files through mosquitto-gcov on an ALT port (1884)
# so the running fuzzer on port 1883 is not disturbed.
#
# Usage:
#   docker exec <CID> bash -c 'cat > /tmp/live_cov.sh' < live_cov.sh
#   docker exec <CID> bash /tmp/live_cov.sh [step]
#
#   step (optional): only run gcovr every N test cases (default=1, i.e. every file)
#                    Use step=1 for final accuracy, step=5+ for speed.
# ─────────────────────────────────────────────────────────────────────────────

set -e

STEP=${1:-1}
ALT_PORT=1884
WORKDIR="${WORKDIR:-/home/ubuntu/experiments}"
GCOV_DIR="$WORKDIR/mosquitto-gcov"
MOSQUITTO_GCOV="$GCOV_DIR/src/mosquitto"
AFL_REPLAY="/home/ubuntu/aflnet/afl-replay"
AFLNET_REPLAY="/home/ubuntu/aflnet/aflnet-replay"
OUTDIR=$(ls -d "$WORKDIR"/out-* 2>/dev/null | head -1)
REPLAY_QUEUE_DIR="$OUTDIR/replayable-queue"

if [[ -z "$OUTDIR" ]]; then
    echo "ERROR: No out-* directory found in $WORKDIR" >&2
    exit 1
fi

# Determine replay mode: prefer replayable-queue (structured, more accurate)
if [[ -d "$REPLAY_QUEUE_DIR" ]] && [[ $(ls "$REPLAY_QUEUE_DIR"/ 2>/dev/null | wc -l) -gt 0 ]]; then
    QUEUE_DIR="$REPLAY_QUEUE_DIR"
    FMODE=1  # structured files → use aflnet-replay
else
    QUEUE_DIR="$OUTDIR/queue"
    FMODE=0  # raw concatenated → use nc (matches cov_script behavior)
fi
TOTAL_FILES=$(ls "$QUEUE_DIR"/ 2>/dev/null | wc -l)

REPLAY_METHOD="nc (raw)"
[[ $FMODE -eq 1 ]] && REPLAY_METHOD="aflnet-replay (structured)"

echo "════════════════════════════════════════════════════════════════"
echo "  live_cov.sh — Real-time gcov coverage snapshot"
echo "  Queue dir : $QUEUE_DIR"
echo "  Replay    : $REPLAY_METHOD"
echo "  Files     : $TOTAL_FILES"
echo "  Step      : $STEP (gcovr every $STEP replays)"
echo "  Alt port  : $ALT_PORT"
echo "  Time      : $(date '+%Y-%m-%d %H:%M:%S')"
echo "════════════════════════════════════════════════════════════════"

# ─── Create alt-port config ──────────────────────────────────────────────────
ALT_CONF="/tmp/mosquitto-gcov-alt.conf"
cat > "$ALT_CONF" <<EOF
listener $ALT_PORT 127.0.0.1
allow_anonymous true
max_connections -1
log_type none
persistence false
user root
EOF

# ─── Clear all previous gcov data ───────────────────────────────────────────
cd "$GCOV_DIR"
find . -name '*.gcda' -delete 2>/dev/null || true
gcovr -r . -s -d > /dev/null 2>&1 || true

# ─── Helper: start mosquitto-gcov, replay one file, kill ────────────────────
replay_one() {
    local f="$1"

    # Start gcov-instrumented mosquitto on alt port (suppress warnings)
    "$MOSQUITTO_GCOV" -c "$ALT_CONF" 2>/dev/null &
    local pid=$!
    sleep 0.3  # need enough time for TCP listener to be ready

    # Replay: use nc for raw queue files, aflnet-replay for structured
    if [[ $FMODE -eq 0 ]]; then
        # Raw concatenated message — pipe through nc (matches cov_script)
        nc -q1 127.0.0.1 "$ALT_PORT" < "$f" > /dev/null 2>&1 || true
    else
        # Structured (replayable-queue) — protocol-aware replay
        "$AFLNET_REPLAY" "$f" MQTT "$ALT_PORT" 1 > /dev/null 2>&1 || true
    fi

    sleep 0.1

    # Graceful shutdown → SIGTERM first (needed to flush gcov data via __gcov_flush)
    kill -TERM "$pid" 2>/dev/null || true
    local i
    for i in $(seq 1 10); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.05
    done
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

# ─── Replay all queue files ─────────────────────────────────────────────────
count=0
t_start=$(date +%s)

# Process *.raw seed files first (if any)
shopt -s nullglob
for f in "$QUEUE_DIR"/*.raw; do
    replay_one "$f"
    ((count++)) || true
    if (( count % 10 == 0 )); then
        elapsed=$(( $(date +%s) - t_start ))
        printf "\r  [%d/%d] replaying seeds... %ds elapsed    " "$count" "$TOTAL_FILES" "$elapsed"
    fi
done

# Process id:* fuzzer-generated files
for f in "$QUEUE_DIR"/id:*; do
    replay_one "$f"
    ((count++)) || true

    # Progress indicator
    if (( count % 10 == 0 )); then
        elapsed=$(( $(date +%s) - t_start ))
        rate="?"
        if (( elapsed > 0 )); then
            rate=$(awk "BEGIN{printf \"%.1f\", $count/$elapsed}")
        fi
        printf "\r  [%d/%d] %.0f%% — %s files/sec — %ds elapsed    " \
            "$count" "$TOTAL_FILES" \
            "$(awk "BEGIN{printf \"%.0f\", $count*100/$TOTAL_FILES}")" \
            "$rate" "$elapsed"
    fi
done
shopt -u nullglob

t_replay=$(( $(date +%s) - t_start ))
echo ""
echo "  ✓ Replay done: $count files in ${t_replay}s"

# ─── Final gcovr ─────────────────────────────────────────────────────────────
echo "  Running gcovr..."
t_gcovr_start=$(date +%s)
cov_output=$(gcovr -r . -s 2>&1)
t_gcovr=$(( $(date +%s) - t_gcovr_start ))

# Parse results
l_per=$(echo "$cov_output" | grep "lines:" | awk '{print $2}' | tr -d '%')
l_abs=$(echo "$cov_output" | grep "lines:" | awk '{print $3}' | tr -d '()')
b_per=$(echo "$cov_output" | grep "branch" | awk '{print $2}' | tr -d '%')
b_abs=$(echo "$cov_output" | grep "branch" | awk '{print $3}' | tr -d '()')

t_total=$(( $(date +%s) - t_start ))

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  📊 REAL-TIME COVERAGE SNAPSHOT                             ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  %-20s %10s  (%6s%%)                  ║\n" "l_abs (lines):" "${l_abs:-0}" "${l_per:-0}"
printf "║  %-20s %10s  (%6s%%)                  ║\n" "b_abs (branches):" "${b_abs:-0}" "${b_per:-0}"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  Queue files: %-6s  Replay: %3ds  gcovr: %3ds  Total: %3ds ║\n" \
    "$count" "$t_replay" "$t_gcovr" "$t_total"
echo "║  Timestamp: $(date '+%Y-%m-%d %H:%M:%S')                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Also output machine-readable line for scripting
echo ""
echo "CSV: $(date +%s),$(date '+%Y-%m-%d %H:%M:%S'),$l_per,$l_abs,$b_per,$b_abs,$count,$t_total"
