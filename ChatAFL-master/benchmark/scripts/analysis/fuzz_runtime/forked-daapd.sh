#!/bin/bash
source /tmp/coverage-v4-src/fuzz_runtime/common.sh
fuzz_reset_check_processes forked-daapd forked-daapd
EXP="${WORKDIR:-/home/ubuntu/experiments}"
DB_DIR="$EXP/db"
CONF="$EXP/forked-daapd.conf"
[ -f "$CONF" ] || fuzz_reset_fail "missing $CONF"
grep -Fq "db_path = \"$DB_DIR/songs3.db\"" "$CONF" || fuzz_reset_fail "songs3 db path drifted"
grep -Fq "cache_path = \"$DB_DIR/cache.db\"" "$CONF" || fuzz_reset_fail "cache db path drifted"
grep -Fq "logfile = \"$EXP/forked-daapd.log\"" "$CONF" || fuzz_reset_fail "log path drifted"
[ ! -L "$DB_DIR" ] || fuzz_reset_fail "refusing symlink $DB_DIR"
[ -d "$DB_DIR" ] || mkdir -p "$DB_DIR" || fuzz_reset_fail "cannot create $DB_DIR"
PRISTINE="$DB_DIR/songs3.db.pristine"
if [ "${CHATAFL_DAAPD_PREWARM:-1}" = "1" ] && [ -f "$PRISTINE" ]; then
  # Steady state (every invocation): restore the pristine library DB instead
  # of forcing forked-daapd to re-scan the MP3 library from scratch. The old
  # per-invocation wipe+rescan stalls under batch load (39 x --cpus=1 sibling
  # compile storms + leftover coverage replays): the scan crawls past the 5s
  # dry-run window, every seed times out and afl-fuzz aborts ("All test cases
  # time out"; reproduced 2026-11-23 19:01 and 22:19 batches, DB frozen at
  # 6/15 files scanned). Restoring a pristine copy returns the target to the
  # identical per-invocation initial state at ms cost. Disable the whole
  # mechanism with CHATAFL_DAAPD_PREWARM=0 to get the legacy wipe+rescan.
  for path in "$DB_DIR/songs3.db" "$DB_DIR/songs3.db-journal" \
              "$DB_DIR/songs3.db-wal" "$DB_DIR/songs3.db-shm"; do
    rm -f -- "$path" || fuzz_reset_fail "cannot remove $path"
  done
  cp -- "$PRISTINE" "$DB_DIR/songs3.db" || fuzz_reset_fail "cannot restore pristine library db"
  rm -f -- "$DB_DIR/cache.db" "$EXP/forked-daapd.log"
  exit 0
fi
for path in "$DB_DIR/songs3.db" "$DB_DIR/cache.db" \
            "$DB_DIR/songs3.db-journal" "$DB_DIR/cache.db-journal" \
            "$DB_DIR/songs3.db-wal" "$DB_DIR/songs3.db-shm" \
            "$DB_DIR/cache.db-wal" "$DB_DIR/cache.db-shm" \
            "$EXP/forked-daapd.log"; do
  [ ! -L "$path" ] || fuzz_reset_fail "refusing symlink state file $path"
  rm -f -- "$path" || fuzz_reset_fail "cannot remove $path"
done
[ -w "$DB_DIR" ] || fuzz_reset_fail "$DB_DIR is not writable"
[ -d "$EXP/MP3" ] || fuzz_reset_fail "missing MP3 media source"
if [ "${CHATAFL_DAAPD_PREWARM:-1}" != "1" ]; then
  exit 0
fi
# First invocation in this container: build the pristine library DB once.
# Boot the target with the exact fork-server argv, wait until it answers
# HTTP (the library scan runs during this boot), stop it cleanly and keep
# both the warm DB and a pristine copy for the per-invocation restore above.
BIN="$EXP/forked-daapd/src/forked-daapd"
[ -x "$BIN" ] || fuzz_reset_fail "missing daapd binary $BIN"
PW_STARTED=$(date +%s)
PW_BOUND=300
PW_DEADLINE=$(( PW_STARTED + PW_BOUND ))
"$BIN" -d 0 -c "$CONF" -f >/dev/null 2>&1 &
PW_PID=$!
PW_OK=0
while [ "$(date +%s)" -lt "$PW_DEADLINE" ]; do
  if ! kill -0 "$PW_PID" 2>/dev/null; then
    break
  fi
  if printf 'GET /api/player HTTP/1.1\r\nHost: prewarm\r\n\r\n' \
      | timeout 1 nc -q 1 127.0.0.1 3689 2>/dev/null | head -c 20 | grep -q 'HTTP/'; then
    PW_OK=1
    break
  fi
  sleep 0.25
done
if [ "$PW_OK" = "1" ]; then
  echo "fuzz-runtime-prewarm: forked-daapd ready in $(( $(date +%s) - PW_STARTED ))s; keeping warm library DB"
else
  echo "fuzz-runtime-prewarm: WARN: daapd not HTTP-ready within ${PW_BOUND}s (dead or stalled); continuing without pristine db" >&2
fi
kill "$PW_PID" 2>/dev/null
# SIGKILL cannot reap a D-state process stuck in sqlite fsync under I/O
# storms; poll until it is really gone before the fork server spawns.
for _ in $(seq 1 150); do
  kill -0 "$PW_PID" 2>/dev/null || break
  sleep 0.2
done
kill -9 "$PW_PID" 2>/dev/null
wait "$PW_PID" 2>/dev/null
if pgrep -x forked-daapd >/dev/null 2>&1; then
  pkill -9 -x forked-daapd 2>/dev/null
  sleep 1
  pgrep -x forked-daapd >/dev/null 2>&1 && fuzz_reset_fail "prewarm left a live forked-daapd process"
fi
if [ "$PW_OK" = "1" ] && [ -s "$DB_DIR/songs3.db" ]; then
  cp -- "$DB_DIR/songs3.db" "$PRISTINE" || fuzz_reset_fail "cannot save pristine library db"
fi
exit 0
