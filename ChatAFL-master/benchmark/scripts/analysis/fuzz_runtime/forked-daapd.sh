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
