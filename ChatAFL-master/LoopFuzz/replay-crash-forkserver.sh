#!/bin/bash
# replay-crash-forkserver.sh — Replay a crash input using AFL's afl-showmap
# to reproduce ASAN-only crashes that depend on fork-server state accumulation.
#
# Usage: ./replay-crash-forkserver.sh <crash_file> <target> <protocol> <port>
#
# Example:
#   ./replay-crash-forkserver.sh /tmp/crash.bin bftpd FTP 21
#
# This script uses afl-showmap which runs the target under AFL's fork server,
# preserving the same execution model as during fuzzing (shared memory bitmap,
# deferred fork, etc.). This is critical for reproducing ASAN crashes that
# only trigger under fork-server state accumulation.

set -e

CRASH_FILE="${1:?Usage: $0 <crash_file> <target> <protocol> <port>}"
TARGET="${2:-bftpd}"
PROTOCOL="${3:-FTP}"
PORT="${4:-21}"

if [ ! -f "$CRASH_FILE" ]; then
    echo "ERROR: Crash file not found: $CRASH_FILE"
    exit 1
fi

echo "=== Fork-Server Crash Replay ==="
echo "Crash file: $CRASH_FILE"
echo "Target: $TARGET"
echo "Protocol: $PROTOCOL / Port: $PORT"
echo ""

# Determine image and paths based on target
case "$TARGET" in
    bftpd)
        IMAGE="bftpd"
        WORKDIR="/home/ubuntu/experiments"
        SERVER_CMD="./bftpd -D -c ${WORKDIR}/basic.conf"
        FUZZER_DIR="/home/ubuntu/loopfuzz"
        CLEAN_SCRIPT="${WORKDIR}/clean"
        ;;
    proftpd)
        IMAGE="proftpd"
        WORKDIR="/home/ubuntu/experiments"
        SERVER_CMD="./proftpd -n -c ${WORKDIR}/basic.conf"
        FUZZER_DIR="/home/ubuntu/loopfuzz"
        CLEAN_SCRIPT="${WORKDIR}/clean"
        ;;
    *)
        echo "ERROR: Unknown target '$TARGET'. Supported: bftpd, proftpd"
        exit 1
        ;;
esac

echo "--- Method 1: afl-showmap (fork-server mode) ---"
docker run --rm \
    -v "$(realpath "$CRASH_FILE"):/tmp/crash_input" \
    -e "ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0" \
    "$IMAGE" /bin/bash -c "
cd ${WORKDIR}/${TARGET}
export AFL_MAP_SIZE=65536

# Use afl-showmap which exercises the fork server path
# -o /dev/null = discard coverage map, we only care about crashes
# -t 5000 = 5 second timeout
${FUZZER_DIR}/afl-showmap -o /dev/null -t 5000 \
    -N tcp://127.0.0.1/${PORT} \
    -c ${CLEAN_SCRIPT} \
    -- ${SERVER_CMD} < /tmp/crash_input 2>&1 || true

echo 'EXIT_CODE='\$?
" 2>&1

echo ""
echo "--- Method 2: Rapid sequential replay (64x) ---"
docker run --rm \
    -v "$(realpath "$CRASH_FILE"):/tmp/crash_input" \
    -e "ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0:log_path=/tmp/asan" \
    "$IMAGE" /bin/bash -c "
cd ${WORKDIR}/${TARGET}
${SERVER_CMD} &
SERVER_PID=\$!
sleep 1

CRASHED=0
for rep in \$(seq 1 64); do
    ${FUZZER_DIR}/aflnet-replay /tmp/crash_input ${PROTOCOL} ${PORT} 0 >/dev/null 2>&1
    if ! kill -0 \$SERVER_PID 2>/dev/null; then
        wait \$SERVER_PID 2>/dev/null
        EC=\$?
        SIG=\$((EC - 128))
        echo \"CRASH on replay #\$rep! exit=\$EC signal=\$SIG\"
        CRASHED=1
        break
    fi
done

if [ \$CRASHED -eq 0 ]; then
    kill \$SERVER_PID 2>/dev/null
    wait \$SERVER_PID 2>/dev/null
    echo 'NO CRASH after 64 sequential replays'
fi

echo '=== ASAN logs ==='
cat /tmp/asan.* 2>/dev/null | head -40 || echo 'No ASAN output'
" 2>&1

echo ""
echo "=== Done ==="
