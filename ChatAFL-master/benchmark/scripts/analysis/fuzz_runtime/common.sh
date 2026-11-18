#!/bin/bash
# Shared helpers for live LoopFuzz resets. Coverage replay reset_commands/
# intentionally has different process semantics and must not be sourced here.
set -u

fuzz_reset_fail() {
  echo "fuzz-runtime-reset: FAIL: $*" >&2
  exit 1
}

# `kill -0` and `pgrep` also see zombies until their parent reaps them. A
# zombie cannot execute or retain sockets, so treat it as stopped. Return 1
# only when the PID vanished; return 2 if /proc still exists but cannot be
# inspected, so callers fail closed rather than silently accepting a process.
fuzz_reset_pid_state() {
  local pid="$1" proc_dir="/proc/$1" state
  case "$pid" in ''|*[!0-9]*) return 2 ;; esac
  [ -d "$proc_dir" ] || return 1
  state=$(awk '$1 == "State:" { print $2; exit }' "$proc_dir/status" 2>/dev/null || true)
  if [ -z "$state" ]; then
    [ -d "$proc_dir" ] && return 2
    return 1
  fi
  printf '%s\n' "$state"
}

fuzz_reset_pid_stopped() {
  local state rc
  state=$(fuzz_reset_pid_state "$1"); rc=$?
  case "$rc" in
    1) return 0 ;;
    2) return 2 ;;
  esac
  case "$state" in Z|X) return 0 ;; esac
  return 1
}

fuzz_reset_check_processes() {
  local comm="$1" executable="$2" allowed="${PHASE2_ALLOWED_FORKSERVER_PID:-0}"
  case "$allowed" in ''|*[!0-9]*) fuzz_reset_fail "invalid allowed forkserver pid '$allowed'" ;; esac
  if [ "$allowed" -gt 0 ]; then
    [ -r "/proc/$allowed/comm" ] || fuzz_reset_fail "idle forkserver pid $allowed is missing"
    local actual_comm actual_exe actual_exe_path expected_exe_path allowed_state
    allowed_state=$(fuzz_reset_pid_state "$allowed") || fuzz_reset_fail "cannot inspect idle forkserver pid $allowed"
    case "$allowed_state" in
      Z|X) fuzz_reset_fail "idle forkserver pid $allowed is stopped (state=$allowed_state)" ;;
    esac
    actual_comm=$(cat "/proc/$allowed/comm")
    actual_exe_path=$(readlink -f "/proc/$allowed/exe" 2>/dev/null || true)
    [ "$actual_comm" = "$comm" ] || fuzz_reset_fail "allowed pid $allowed comm=$actual_comm, expected $comm"
    if [[ "$executable" == */* ]]; then
      # Some packages expose a stable executable symlink while /proc/<pid>/exe
      # reports the versioned target (Exim does this). Compare canonical paths
      # only when the caller explicitly supplies a path; existing callers keep
      # the stricter basename check below.
      expected_exe_path=$(readlink -f "$executable" 2>/dev/null || true)
      [ -n "$actual_exe_path" ] && [ -n "$expected_exe_path" ] && [ -x "$expected_exe_path" ] ||
        fuzz_reset_fail "cannot resolve allowed pid executable path (actual=$actual_exe_path expected=$executable)"
      [ "$actual_exe_path" = "$expected_exe_path" ] ||
        fuzz_reset_fail "allowed pid $allowed exe=$actual_exe_path, expected path $expected_exe_path"
    else
      actual_exe=$(basename "$actual_exe_path")
      [ "$actual_exe" = "$executable" ] || fuzz_reset_fail "allowed pid $allowed exe=$actual_exe, expected $executable"
    fi
  fi
  local pid pid_state pid_state_rc
  for pid in $(pgrep -x "$comm" 2>/dev/null || true); do
    pid_state=$(fuzz_reset_pid_state "$pid"); pid_state_rc=$?
    case "$pid_state_rc" in
      1) continue ;; # The process exited between pgrep and reading /proc.
      2) fuzz_reset_fail "cannot inspect $comm process pid=$pid" ;;
    esac
    case "$pid_state" in Z|X) continue ;; # pgrep includes unreaped zombies.
    esac
    [ "$pid" = "$allowed" ] || fuzz_reset_fail "unexpected $comm process pid=$pid (allowed forkserver=$allowed)"
  done
}

fuzz_reset_check_port_free() {
  local protocol="$1" port="$2"
  python3 - "$protocol" "$port" <<'PY' || fuzz_reset_fail "$protocol port $port is still bound"
import sys
kind, port = sys.argv[1], int(sys.argv[2])
tables = ("/proc/net/tcp", "/proc/net/tcp6") if kind == "tcp" else ("/proc/net/udp", "/proc/net/udp6")
expected_state = "0A" if kind == "tcp" else "07"
for table in tables:
    try:
        rows = open(table, encoding="ascii").read().splitlines()[1:]
    except OSError:
        continue
    for row in rows:
        fields = row.split()
        local_port = int(fields[1].rsplit(":", 1)[1], 16)
        if local_port == port and fields[3] == expected_state:
            raise SystemExit(1)
PY
}

fuzz_reset_clean_dir() {
  local path="$1"
  [ ! -L "$path" ] || fuzz_reset_fail "refusing symlink state directory $path"
  [ -d "$path" ] || mkdir -p "$path" || fuzz_reset_fail "cannot create $path"
  find "$path" -mindepth 1 -delete || fuzz_reset_fail "cannot clear $path"
  [ -z "$(ls -A "$path")" ] || fuzz_reset_fail "$path is not empty after reset"
  [ -w "$path" ] || fuzz_reset_fail "$path is not writable"
}

fuzz_reset_truncate_file() {
  local path="$1"
  [ ! -L "$path" ] || fuzz_reset_fail "refusing symlink state file $path"
  if [ -e "$path" ]; then
    [ -f "$path" ] || fuzz_reset_fail "$path is not a regular file"
    : > "$path" || fuzz_reset_fail "cannot truncate $path"
  else
    : > "$path" || fuzz_reset_fail "cannot create $path"
  fi
}
