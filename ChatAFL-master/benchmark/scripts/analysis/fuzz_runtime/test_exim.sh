#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../../../.." && pwd)

if [ "${FUZZ_RUNTIME_TEST_IN_CONTAINER:-0}" != 1 ]; then
  docker run --rm --network none --entrypoint /bin/bash \
    -v "$SCRIPT_DIR:/tmp/coverage-v4-src/fuzz_runtime:ro" \
    -v "$SCRIPT_DIR/test_exim.sh:/tmp/test_exim_runtime.sh:ro" \
    -e FUZZ_RUNTIME_TEST_IN_CONTAINER=1 \
    exim /tmp/test_exim_runtime.sh
  exit $?
fi

TMP=$(mktemp -d)
PIDS=()
cleanup() {
  local pid
  for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

spawn_named_exim() {
  python3 -c 'import ctypes,time; ctypes.CDLL(None).prctl(15,b"exim",0,0,0); time.sleep(120)' &
  SPAWNED=$!
  PIDS+=("$SPAWNED")
  for _ in $(seq 1 50); do
    [ -r "/proc/$SPAWNED/comm" ] && [ "$(cat "/proc/$SPAWNED/comm")" = exim ] && return 0
    sleep 0.02
  done
  echo "test helper failed to start exim-named worker pid=$SPAWNED" >&2
  return 1
}

spawn_zombie_exim() {
  local pid_fifo="$TMP/zombie.pid" state
  mkfifo "$pid_fifo"
  python3 - "$pid_fifo" <<'PY' &
import ctypes
import os
import signal
import sys
import time

child = os.fork()
if child == 0:
    ctypes.CDLL(None).prctl(15, b"exim", 0, 0, 0)
    os._exit(0)

def reap_child(_signum, _frame):
    try:
        os.waitpid(child, 0)
    except ChildProcessError:
        pass
    raise SystemExit(0)

signal.signal(signal.SIGTERM, reap_child)
with open(sys.argv[1], "w", encoding="ascii") as out:
    out.write(str(child) + "\n")
while True:
    time.sleep(1)
PY
  ZOMBIE_PARENT=$!
  PIDS+=("$ZOMBIE_PARENT")
  read -r ZOMBIE < "$pid_fifo"
  for _ in $(seq 1 50); do
    state=$(awk '$1 == "State:" { print $2; exit }' "/proc/$ZOMBIE/status" 2>/dev/null || true)
    [ "$state" = Z ] && return 0
    sleep 0.02
  done
  echo "test helper failed to leave exim child as zombie pid=$ZOMBIE" >&2
  return 1
}

mkdir -p "$TMP/spool"/{input,msglog,db,log}
printf 'stale\n' > "$TMP/spool/input/stale-message"
spawn_named_exim
FORKSERVER=$SPAWNED
spawn_named_exim
ORPHAN=$SPAWNED

FUZZ_RESET_EXIM_BIN=$(command -v python3) \
FUZZ_RESET_EXIM_PIDFILE="$TMP/exim.pid" \
FUZZ_RESET_EXIM_SPOOL="$TMP/spool" \
PHASE2_ALLOWED_FORKSERVER_PID="$FORKSERVER" \
  bash /tmp/coverage-v4-src/fuzz_runtime/exim.sh
kill -0 "$FORKSERVER"
wait "$ORPHAN" 2>/dev/null || true
if kill -0 "$ORPHAN" 2>/dev/null; then
  echo "orphan exim pid $ORPHAN survived reset" >&2
  exit 1
fi
[ -z "$(find "$TMP/spool" -mindepth 2 -print -quit)" ]
echo "PASS: retains forkserver, stops orphan, and clears spool"

# Reproduce the Exim race shape: kill -0 still succeeds, comm remains exim,
# and /proc/<pid>/exe is empty while the parent has not reaped the child.
spawn_zombie_exim
kill -0 "$ZOMBIE"
[ "$(cat "/proc/$ZOMBIE/comm")" = exim ]
[ -z "$(readlink "/proc/$ZOMBIE/exe" 2>/dev/null || true)" ]
echo "$ZOMBIE" > "$TMP/exim.pid"
env FUZZ_RESET_EXIM_BIN="$(command -v python3)" FUZZ_RESET_EXIM_PIDFILE="$TMP/exim.pid" FUZZ_RESET_EXIM_SPOOL="$TMP/spool" PHASE2_ALLOWED_FORKSERVER_PID=0 bash /tmp/coverage-v4-src/fuzz_runtime/exim.sh
[ "$(awk '$1 == "State:" { print $2; exit }' "/proc/$ZOMBIE/status")" = Z ]
kill "$ZOMBIE_PARENT"
wait "$ZOMBIE_PARENT" 2>/dev/null || true
PIDS=("${PIDS[@]/$ZOMBIE_PARENT}")
echo "PASS: treats a zombie Exim PID with an empty exe link as stopped"

# Simulate a live Exim whose /proc/<pid>/exe lookup is transiently empty while
# its process state remains inspectable. The reset should retry identity once
# within its bounded grace period, then stop the matching process.
spawn_named_exim
TRANSIENT=$SPAWNED
mkdir -p "$TMP/fake-bin"
cat > "$TMP/fake-bin/readlink" <<'SH'
#!/bin/bash
if [ "$1" = -f ] && [ "$2" = "/proc/$RESET_RACE_PID/exe" ]; then
  count=$(cat "$RESET_RACE_COUNT")
  count=$((count + 1))
  printf '%s\n' "$count" > "$RESET_RACE_COUNT"
  if [ "$count" -eq 1 ]; then exit 0; fi
fi
exec /usr/bin/readlink "$@"
SH
chmod +x "$TMP/fake-bin/readlink"
printf '0\n' > "$TMP/readlink.count"
PATH="$TMP/fake-bin:$PATH" RESET_RACE_PID="$TRANSIENT" RESET_RACE_COUNT="$TMP/readlink.count" \
  FUZZ_RESET_EXIM_BIN="$(command -v python3)" FUZZ_RESET_EXIM_PIDFILE="$TMP/exim.pid" \
  FUZZ_RESET_EXIM_SPOOL="$TMP/spool" PHASE2_ALLOWED_FORKSERVER_PID=0 \
  bash /tmp/coverage-v4-src/fuzz_runtime/exim.sh
wait "$TRANSIENT" 2>/dev/null || true
PIDS=("${PIDS[@]/$TRANSIENT}")
[ "$(cat "$TMP/readlink.count")" -ge 2 ]
echo "PASS: retries a transient empty exe link, then stops the matching Exim process"

spawn_named_exim
MISMATCHED=$SPAWNED
if FUZZ_RESET_EXIM_BIN=/bin/sleep \
    FUZZ_RESET_EXIM_PIDFILE="$TMP/exim.pid" \
    FUZZ_RESET_EXIM_SPOOL="$TMP/spool" \
    PHASE2_ALLOWED_FORKSERVER_PID=0 \
    bash /tmp/coverage-v4-src/fuzz_runtime/exim.sh >"$TMP/mismatch.out" 2>&1; then
  echo "reset accepted an exim-named process with a different executable" >&2
  exit 1
fi
grep -q "exe=.*expected /bin/sleep" "$TMP/mismatch.out"
kill -0 "$MISMATCHED"
echo "PASS: rejects and reports an exim-named process with a different executable"
