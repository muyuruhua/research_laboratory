#!/bin/bash
source /tmp/coverage-v4-src/fuzz_runtime/common.sh
PIDFILE=${FUZZ_RESET_EXIM_PIDFILE:-/var/lock/exim.pid}
SPOOL=${FUZZ_RESET_EXIM_SPOOL:-/var/spool/exim}
EXIM_BIN=${FUZZ_RESET_EXIM_BIN:-/usr/exim/bin/exim}
ALLOWED="${PHASE2_ALLOWED_FORKSERVER_PID:-0}"
[ ! -L "$PIDFILE" ] || fuzz_reset_fail "refusing symlink $PIDFILE"

stop_exim_pid() {
  local pid="$1" label="$2" actual_exe expected_exe stopped_rc
  [ "$pid" != "$ALLOWED" ] || return 0
  fuzz_reset_pid_stopped "$pid"; stopped_rc=$?
  [ "$stopped_rc" -eq 0 ] && return 0
  [ "$stopped_rc" -eq 1 ] || fuzz_reset_fail "cannot inspect $label pid $pid state"
  if [ ! -r "/proc/$pid/comm" ]; then
    fuzz_reset_pid_stopped "$pid"; stopped_rc=$?
    [ "$stopped_rc" -eq 0 ] && return 0
    fuzz_reset_fail "$label pid $pid has no readable process comm"
  fi
  if [ "$(cat "/proc/$pid/comm")" != exim ]; then
    fuzz_reset_pid_stopped "$pid"; stopped_rc=$?
    [ "$stopped_rc" -eq 0 ] && return 0
    fuzz_reset_fail "$label pid $pid is not exim"
  fi
  actual_exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
  expected_exe=$(readlink -f "$EXIM_BIN" 2>/dev/null || true)
  if [ -z "$expected_exe" ] || [ "$actual_exe" != "$expected_exe" ]; then
    # A just-exiting Exim worker can briefly retain /proc state while its exe
    # link has already disappeared. Give that transition a bounded grace
    # period; still reject a live process whose executable does not match.
    if [ -n "$expected_exe" ] && [ -z "$actual_exe" ]; then
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        fuzz_reset_pid_stopped "$pid"; stopped_rc=$?
        [ "$stopped_rc" -eq 0 ] && return 0
        [ "$stopped_rc" -eq 1 ] || fuzz_reset_fail "cannot inspect $label pid $pid state"
        sleep 0.05
        actual_exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
        [ -n "$actual_exe" ] && break
      done
    fi
    fuzz_reset_pid_stopped "$pid"; stopped_rc=$?
    [ "$stopped_rc" -eq 0 ] && return 0
    [ "$stopped_rc" -eq 1 ] || fuzz_reset_fail "cannot inspect $label pid $pid state"
    [ -n "$expected_exe" ] && [ "$actual_exe" = "$expected_exe" ] ||
      fuzz_reset_fail "$label pid $pid exe=$actual_exe, expected $EXIM_BIN"
  fi

  kill "$pid" 2>/dev/null || fuzz_reset_fail "cannot stop $label exim pid $pid"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    fuzz_reset_pid_stopped "$pid"; stopped_rc=$?
    [ "$stopped_rc" -eq 0 ] && return 0
    [ "$stopped_rc" -eq 1 ] || fuzz_reset_fail "cannot inspect $label exim pid $pid after SIGTERM"
    sleep 0.1
  done
  kill -9 "$pid" 2>/dev/null || fuzz_reset_fail "cannot force-stop $label exim pid $pid"
  # A daemon that sits in uninterruptible I/O (D state, e.g. spool/db fsync)
  # cannot act on SIGKILL until the syscall returns; 0.5 s was observed to
  # be too tight once (2026-11-21: pid survived, afl-fuzz aborted the whole
  # campaign). Give D-state exits a 10 s ceiling; only a still-runnable
  # process after that is a genuine anomaly.
  local post_kill_state=""
  for _ in $(seq 1 100); do
    fuzz_reset_pid_stopped "$pid"; stopped_rc=$?
    [ "$stopped_rc" -eq 0 ] && return 0
    [ "$stopped_rc" -eq 1 ] || fuzz_reset_fail "cannot inspect $label exim pid $pid after SIGKILL"
    post_kill_state=$(fuzz_reset_pid_state "$pid" 2>/dev/null || true)
    case "$post_kill_state" in
      D) sleep 0.1 ;;
      *) sleep 0.1 ;;
    esac
  done
  fuzz_reset_fail "$label exim pid $pid survives SIGKILL (state=$post_kill_state)"
}

if [ -f "$PIDFILE" ]; then
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  case "$pid" in
    ''|*[!0-9]*) ;;
    *)
      stop_exim_pid "$pid" recorded
      ;;
  esac
  rm -f "$PIDFILE" || fuzz_reset_fail "cannot remove $PIDFILE"
fi
[ ! -e "$PIDFILE" ] || fuzz_reset_fail "$PIDFILE remains after reset"

# Exim may leave an SMTP worker or a daemon behind after a testcase. Preserve
# only AFL's validated idle forkserver and stop other processes from this
# exact Exim executable before validating the process set again.
for pid in $(pgrep -x exim 2>/dev/null || true); do
  stop_exim_pid "$pid" leftover
done
fuzz_reset_check_processes exim "$EXIM_BIN"

# SMTP can persist queued mail and retry hints between invocations. Keep the
# image-created spool parent and its ownership. The image does not create all
# state subdirectories, so bootstrap missing children as the spool owner; Exim
# drops privileges to that account before opening queue/log files.
[ ! -L "$SPOOL" ] || fuzz_reset_fail "refusing symlink spool directory $SPOOL"
[ -d "$SPOOL" ] || fuzz_reset_fail "missing spool directory $SPOOL"
SPOOL_UID=$(stat -c '%u' "$SPOOL") || fuzz_reset_fail "cannot read owner of $SPOOL"
SPOOL_GID=$(stat -c '%g' "$SPOOL") || fuzz_reset_fail "cannot read group of $SPOOL"
for state in input msglog db log; do
  path="$SPOOL/$state"
  [ ! -L "$path" ] || fuzz_reset_fail "refusing symlink spool state $path"
  if [ ! -e "$path" ]; then
    install -d -m 0750 -o "$SPOOL_UID" -g "$SPOOL_GID" -- "$path" ||
      fuzz_reset_fail "cannot create spool directory $path"
  fi
  [ -d "$path" ] || fuzz_reset_fail "spool state is not a directory: $path"
  fuzz_reset_clean_dir "$path"
done
