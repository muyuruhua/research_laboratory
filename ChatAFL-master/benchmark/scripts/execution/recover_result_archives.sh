#!/bin/bash
set -uo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <results-dir> [--delete]"
  exit 1
fi

RESULTS_DIR="$1"
DELETE_MODE="${2:-}"
WORKDIR="/home/ubuntu/experiments"
MANIFEST_FILE="${RESULTS_DIR}/.result_manifest.tsv"
RESULT_OWNER="${SUDO_USER:-$USER}"
RESULT_GROUP="$(id -gn "${RESULT_OWNER}")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/archive_contract.sh"

fix_result_permissions() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  chown -R "${RESULT_OWNER}:${RESULT_GROUP}" "$path" 2>/dev/null || true
  chmod -R u+rwX "$path" 2>/dev/null || true
}

# Required top-level result files.  Coverage completeness also requires a
# structurally valid v4/v5 terminal artifact (checked separately below).
REQUIRED_FILES="fuzzer_stats cov_over_time.csv"

coverage_terminal_acceptance() {
  local tarball="$1"
  python3 - "$tarball" <<'PY'
import json
import re
import sys
import tarfile

path = sys.argv[1]
try:
    with tarfile.open(path, "r:gz") as archive:
        members = [m for m in archive.getmembers() if m.isfile()]
        terminals = [m for m in members if
            m.name.endswith("/cov_over_time.csv.v4/terminal.json") or
            m.name.endswith("/cov_over_time.csv.v5/terminal.json")]
        if len(terminals) != 1:
            raise ValueError("expected exactly one v4/v5 terminal.json")
        terminal_member = terminals[0]
        version = "v5" if "/cov_over_time.csv.v5/terminal.json" in terminal_member.name else "v4"
        expected_schema = ("loopfuzz-coverage-v5-sampled-checkpoints" if version == "v5"
                           else "loopfuzz-coverage-v4")
        parent = terminal_member.name.rsplit("/", 1)[0]
        scope_name = parent + "/scope.json"
        scopes = [m for m in members if m.name == scope_name]
        if len(scopes) != 1:
            raise ValueError("terminal has no unique matching scope.json")
        terminal = json.load(archive.extractfile(terminal_member))
        scope = json.load(archive.extractfile(scopes[0]))
        if not isinstance(terminal, dict) or not isinstance(scope, dict):
            raise ValueError("terminal and scope must be JSON objects")
        if terminal.get("schema_version") != expected_schema or scope.get("schema_version") != expected_schema:
            raise ValueError("terminal/scope schema does not match its v4/v5 directory")
        scope_hash = terminal.get("scope_sha256")
        if (not isinstance(scope_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", scope_hash)
                or scope.get("scope_sha256") != scope_hash):
            raise ValueError("terminal scope hash does not match scope.json")
        if (not isinstance(terminal.get("covered_branch_ids"), list)
                or not isinstance(terminal.get("covered_line_ids"), list)):
            raise ValueError("terminal is missing coverage identity lists")
        n_replayed = terminal.get("n_replayed")
        if isinstance(n_replayed, bool) or not isinstance(n_replayed, int) or n_replayed < 0:
            raise ValueError("terminal has an invalid n_replayed value")
        complete = terminal.get("coverage_complete")
        acceptance = terminal.get("acceptance")
        if not isinstance(complete, bool) or acceptance not in ("complete", "incomplete"):
            raise ValueError("terminal is missing coverage acceptance status")
        if (acceptance == "complete") != complete:
            raise ValueError("terminal acceptance disagrees with coverage_complete")
        print(acceptance)
except Exception as error:
    print(str(error), file=sys.stderr)
    sys.exit(1)
PY
}

tarball_is_complete() {
  local tarball="$1"
  archive_tar_is_structurally_complete "$tarball" || return 1
  # A CSV alone cannot establish that coverage replay produced a terminal
  # record.  The terminal acceptance may be "incomplete" and still make the
  # archive file-complete; scientific acceptance remains a separate audit.
  coverage_terminal_acceptance "$tarball" >/dev/null 2>&1 || return 1
  return 0
}

# Explicit remote candidates for the campaign output directory.
# Rationale: this docker daemon's `docker cp` does NOT expand globs on the
# remote path (the previous glob-based strategy-2 never matched anything),
# and the outdir lives at subject-specific depth. Table keyed by the target
# name embedded in outdir (out-<target>-loopfuzz). Order matters: cheapest
# (flattest) first.
outdir_remote_candidates() {
  local outdir="$1" target
  target=$(printf '%s' "$outdir" | sed -E 's/^out-//; s/-loopfuzz$//')
  case "$target" in
    lightftp)       printf '%s\n' "LightFTP/Source/Release" ;;
    live555)        printf '%s\n' "live/testProgs" ;;
    *)              printf '%s\n' "$target" ;;
  esac
  # generic fallbacks
  printf '%s\n' "" ".."
}

collect_from_container() {
  local container_id="$1"
  local outdir="$2"
  local destination="$3"
  local tmp_file="${destination}.partial"
  local extracted_root=""

  # Atomic swap-in: rotate any existing final to a timestamped .incomplete
  # backup ONLY after the replacement on $1 has verified complete, then move
  # the replacement into place. Interrupting anywhere between the two mv's
  # leaves either the old or the new final present, never neither.
  swap_in() {
    local rotated=""
    if [[ -s "$destination" && ! -f "${destination}.salvaged" ]]; then
      rotated="${destination}.incomplete.$(date +%s)"
      mv "$destination" "$rotated" 2>/dev/null || rotated=""
    fi
    mv "$1" "$destination"
    fix_result_permissions "$destination"
    # The replacement was verified complete BEFORE this swap, and it is now
    # in place: the rotated backup has no remaining crash-safety role and is
    # byte-redundant — remove it so successful collections leave no
    # .incomplete.<ts> sidecars. A crash between the two mv's still leaves
    # either the old or the new final present (never neither); a crash
    # before this rm leaves one stale sidecar, which the end-of-run
    # sweeper removes on the next collection.
    [[ -n "$rotated" ]] && rm -f "$rotated"
  }

  rm -f "$tmp_file"

  # A stopped container's inner tar.gz is frozen: fetch it once and check
  # completeness immediately. The settle-polling loop below only helps while
  # the container is still gzipping (i.e. running) — on a dead container it
  # burns 3 × ~5 min per archive for bytes that can never change.
  local container_running
  container_running=$(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null || echo unknown)
  local attempts=3
  [[ "$container_running" != "true" ]] && attempts=1

  # Strategy 1: copy the container-internal tar.gz produced by the run script
  # (this is the most reliable source — created after fuzzing + cov_script complete).
  # Try the root location plus each subject-specific parent (explicit paths:
  # this daemon's docker cp does not glob remote paths).
  local attempt parent_cand
  for attempt in 1 2 3; do
    [[ "$attempt" -gt "$attempts" ]] && break
    for parent_cand in "" $(outdir_remote_candidates "$outdir"); do
      if docker cp "${container_id}:${WORKDIR}/${parent_cand:+$parent_cand/}${outdir}.tar.gz" "$tmp_file" >/dev/null 2>&1; then
        if tarball_is_complete "$tmp_file"; then
          swap_in "$tmp_file"
          return 0
        fi
        if [[ "$container_running" != "true" ]]; then
          # Frozen yet incomplete inner tar (container died mid-gzip): retrying
          # and polling cannot change the bytes. Try the next location, then
          # fall through to strategy 2.
          continue
        fi
        break  # running container: settle-poll this location
      fi
    done
    if [[ -s "$tmp_file" ]]; then
      if [[ "$container_running" == "true" ]]; then
        # Hour-scale archives take minutes to gzip: poll the FETCHED copy until
        # it stops growing on two consecutive polls AND passes completeness
        # (up to ~5 minutes), then accept.
        local prev=-1 stable=0 cur
        for _ in $(seq 1 30); do
          cur=$(stat -c %s "$tmp_file" 2>/dev/null || echo 0)
          if [[ "$cur" == "$prev" && "$cur" -gt 0 ]]; then stable=$((stable+1)); else stable=0; fi
          prev="$cur"
          if [[ "$stable" -ge 2 ]] && tarball_is_complete "$tmp_file"; then
            swap_in "$tmp_file"
            return 0
          fi
          sleep 10
        done
        echo "[recover] [WARN] inner tar.gz exists but is incomplete after settle polling, retrying..." >&2
      else
        echo "[recover] inner tar.gz frozen-incomplete on stopped container, using raw-dir fallback" >&2
      fi
      rm -f "$tmp_file"
    fi
    sleep "$attempt"
  done

  # Strategy 2: copy the raw output directory and tar it locally.  The
  # outdir is relative to the subject's build directory, not always to
  # WORKDIR (e.g. lightftp's run.sh cds into LightFTP/Source/Release), so
  # probe the explicit candidate parents — this daemon's docker cp does NOT
  # expand remote globs, the previous glob-based probing never matched.
  extracted_root=$(mktemp -d "${TMPDIR:-/tmp}/recover-${outdir}-XXXXXX")
  # NOTE: remote_dir must be initialized — an unset local under `set -u`
  # aborts the whole loop subshell on the [[ -n ]] test (this was the
  # invisible crash behind every "silent" recovery failure).
  local remote_dir=""
  for parent_cand in "" $(outdir_remote_candidates "$outdir"); do
    if docker cp "${container_id}:${WORKDIR}/${parent_cand:+$parent_cand/}${outdir}" "${extracted_root}/" >/dev/null 2>&1; then
      remote_dir="$outdir"
      break
    fi
  done
  if [[ -n "$remote_dir" ]]; then
    tar -czf "$tmp_file" -C "$extracted_root" "$outdir"
    rm -rf "$extracted_root"
    if tarball_is_complete "$tmp_file"; then
      swap_in "$tmp_file"
      return 0
    fi
    # Raw-dir fallback produced the same incompleteness (e.g. coverage never
    # ran): still better than nothing — swap it in so the dir keeps its best
    # available archive, and let the caller's patch path try to fill holes.
    echo "[recover] [WARN] raw-dir fallback also missing required files" >&2
    swap_in "$tmp_file"
    return 0
  fi

  rm -rf "$extracted_root"
  rm -f "$tmp_file"
  # Post-mortem preservation: the container holds the only copy of the
  # measurements and of the failure's error text; dump its logs next to the
  # destination so the cause survives any later container removal.
  docker logs "$container_id" > "${destination}.container-$(printf '%s' "$container_id" | cut -c1-12).log" 2>&1 || true
  return 1
}

if [[ ! -d "$RESULTS_DIR" ]]; then
  echo "[recover] results dir not found: $RESULTS_DIR" >&2
  exit 1
fi

if [[ ! -f "$MANIFEST_FILE" ]]; then
  echo "[recover] no manifest found in $RESULTS_DIR, nothing to do"
  exit 0
fi

overall_status=0
mkdir -p "$RESULTS_DIR"
fix_result_permissions "$RESULTS_DIR"

short_container_id() {
  local container_id="$1"
  printf '%s' "${container_id:0:12}"
}

# NOTE: bash 'read' with IFS=$'\t' collapses consecutive tabs (empty fields).
# Use awk to emit pipe-delimited rows so read handles them correctly.
_status_file=$(mktemp "${TMPDIR:-/tmp}/recover-status-XXXXXX")
echo 0 > "$_status_file"

awk -F'\t' 'NR>1 && NF>=7 { print $1"|"$2"|"$3"|"$4"|"$5"|"$6"|"$7 }' "$MANIFEST_FILE" |
while IFS='|' read -r run_index container_id container_name image_name fuzzer_name outdir archive_name; do
  [[ -n "$archive_name" ]] || continue

  # Treat '-' placeholder as empty
  [[ "$container_name" == "-" ]] && container_name=""

  destination="${RESULTS_DIR}/${archive_name}"

  # P1 fix: acquire an exclusive lock on this archive to prevent concurrent
  # recovery / manual salvage from racing each other. Non-blocking; if locked,
  # another process is already handling this archive.
  # ROOT FIX: `exec N>file 2>/dev/null` without a command makes EVERY
  # redirection on the line permanent for the shell — the 2>/dev/null was
  # silencing all later stderr (xtrace, "failed to collect", docker errors),
  # hiding collection failures. Scope it to a group so only the exec's own
  # diagnostics are suppressed.
  _lock="${destination}.lock"
  if ! { exec 200>"$_lock"; } 2>/dev/null; then
    echo "[recover] SKIP (cannot open lock): ${archive_name}"
    printf '%s\n' "$archive_name" >> "${RESULTS_DIR}/.collect-pending"
    continue
  fi
  if ! flock -w 300 200 2>/dev/null; then
    echo "[recover] SKIP (locked by another process): ${archive_name} — queued for retry"
    printf '%s\n' "$archive_name" >> "${RESULTS_DIR}/.collect-pending"
    exec 200>&-
    continue
  fi

  # Check if existing tarball is complete; if incomplete, try to upgrade it
  # P0-1 fix: a .salvaged marker means a human already recovered this archive
  # from a container via docker cp; the recovery script must NOT rename or
  # overwrite it (this caused data loss when the driver's retry logic
  # clobbered manually salvaged TARs).
  if [[ -f "${destination}.salvaged" ]]; then
    if [[ -s "$destination" ]] && tarball_is_complete "$destination"; then
      acceptance=$(coverage_terminal_acceptance "$destination" 2>/dev/null || echo unknown)
      echo "[recover] ✓ archive files complete (salvaged; coverage acceptance=${acceptance}): ${archive_name}"
    else
      echo "[recover] [WARN] salvaged archive is incomplete and preserved (manual marker prevents replacement): ${archive_name}" >&2
      echo 1 > "$_status_file"
    fi
    flock -u 200 2>/dev/null || true
    exec 200>&-
    rm -f "$_lock"
    continue
  fi
  if [[ -s "$destination" ]]; then
    if tarball_is_complete "$destination"; then
      acceptance=$(coverage_terminal_acceptance "$destination" 2>/dev/null || echo unknown)
      echo "[recover] ✓ archive files complete (coverage acceptance=${acceptance}): ${archive_name}"
      flock -u 200 2>/dev/null || true
      exec 200>&-
      rm -f "$_lock"
      # If it's complete AND has a .salvaged marker, it was manually verified
      # too — create the marker for idempotency.
      continue
    fi
    # Existing final is incomplete: fetch a REPLACEMENT first; the old copy is
    # only rotated to a .incomplete.<ts> backup inside the atomic swap, after
    # the new copy has verified complete. A failed fetch therefore never
    # leaves the dir without its best-available archive (the old code renamed
    # the final away up front — combined with a failed fetch the dir ended up
    # with NO final at all).
    echo "[recover] [WARN] ${archive_name} is incomplete (required result or v4/v5 terminal artifacts missing/invalid), fetching replacement..."
  fi

  label="$container_id"
  [[ -n "$container_name" ]] && label="$container_name"
  [[ -z "$container_name" ]] && label="$(short_container_id "$container_id")"
  echo "[recover] collecting ${archive_name} from ${label}"

  if collect_from_container "$container_id" "$outdir" "$destination"; then
    echo "[recover] collected ${archive_name}"
    # Validate completeness of the collected tarball
    if ! tarball_is_complete "$destination"; then
      echo "[recover] [WARN] ${archive_name} is incomplete after collection" >&2
      # Try to patch missing files directly from the container
      _dest_listing=$(tar tzf "$destination" 2>/dev/null) || _dest_listing=""
      for req in $REQUIRED_FILES; do
        if ! grep -qE "(^|/)${req//./\\.}$" <<< "$_dest_listing"; then
          _src="${WORKDIR}/${outdir}/${req}"
          _tmp_file=$(mktemp)
          if docker cp "${container_id}:${_src}" "$_tmp_file" >/dev/null 2>&1 && [[ -s "$_tmp_file" ]]; then
            _tmp_extract=$(mktemp -d)
            tar xzf "$destination" -C "$_tmp_extract"
            cp "$_tmp_file" "$_tmp_extract/${outdir}/${req}"
            # Re-tar to a temp file and swap atomically — rewriting the
            # destination in place truncates it if interrupted here.
            _tmp_tar=$(mktemp)
            tar czf "$_tmp_tar" -C "$_tmp_extract" "$outdir"
            rm -rf "$_tmp_extract"
            if [[ -s "$_tmp_tar" ]]; then
              if [[ -s "$destination" && ! -f "${destination}.salvaged" ]]; then
                mv "$destination" "${destination}.incomplete.$(date +%s)" 2>/dev/null || true
              fi
              mv "$_tmp_tar" "$destination"
              fix_result_permissions "$destination"
              echo "[recover] patched ${req} into ${archive_name}"
            fi
          fi
          rm -f "$_tmp_file"
        fi
      done
      # Final check
      if tarball_is_complete "$destination"; then
        acceptance=$(coverage_terminal_acceptance "$destination" 2>/dev/null || echo unknown)
        echo "[recover] ✓ ${archive_name} archive files complete after patching (coverage acceptance=${acceptance})"
      else
        echo "[recover] [WARN] ${archive_name} still lacks valid archive artifacts including a v4/v5 terminal; no terminal was synthesized or patched" >&2
        echo 1 > "$_status_file"
      fi
    else
      acceptance=$(coverage_terminal_acceptance "$destination" 2>/dev/null || echo unknown)
      echo "[recover] archive files complete after collection (coverage acceptance=${acceptance}): ${archive_name}"
    fi
    if [[ "$DELETE_MODE" == "--delete" ]] && tarball_is_complete "$destination"; then
      docker rm "$container_id" >/dev/null 2>&1 || true
    fi
  else
    echo "[recover] failed to collect ${archive_name} from ${label}" >&2
    echo 1 > "$_status_file"
  fi

  # P1 fix: release the per-archive lock; on success drop any stale retry note
  flock -u 200 2>/dev/null || true
  exec 200>&-
  # Lock-file lifecycle fix (2026-11-08): with the fd closed and the final
  # verified complete, the 0-byte .lock has no purpose — remove it so
  # successful runs leave a clean results dir. Concurrent collectors on the
  # SAME archive are excluded by the flock we just held; different runners
  # use different results dirs, so no cross-runner race exists on this path.
  if tarball_is_complete "$destination" 2>/dev/null; then
    rm -f "$_lock"
  fi
  if [[ -f "${RESULTS_DIR}/.collect-pending" ]] && tarball_is_complete "$destination" 2>/dev/null; then
    grep -vxF "$archive_name" "${RESULTS_DIR}/.collect-pending" > "${RESULTS_DIR}/.collect-pending.tmp" 2>/dev/null \
      && mv "${RESULTS_DIR}/.collect-pending.tmp" "${RESULTS_DIR}/.collect-pending" || rm -f "${RESULTS_DIR}/.collect-pending.tmp"
  fi
done

overall_status=$(cat "$_status_file")
rm -f "$_status_file"

# Stale-sidecar sweeper (2026-11-08): leftovers from previously interrupted
# collections (.incomplete.<ts> rotation backups, orphan .lock files) are
# removed for every archive whose final tarball verifies complete. Finals
# that are missing or incomplete keep their sidecars (they may be the only
# recoverable copy — collect_pending_archives.sh tier 2 promotes them).
swept=0
for final in "${RESULTS_DIR}"/out-*.tar.gz; do
  [[ -s "$final" ]] || continue
  tarball_is_complete "$final" 2>/dev/null || continue
  for stale in "${final}.lock" "${final}".incomplete.* "${final}.partial"; do
    [[ -e "$stale" ]] || continue
    rm -f "$stale" && swept=$((swept+1))
  done
done
(( swept > 0 )) && echo "[recover] swept ${swept} stale sidecar file(s) for complete archives"

fix_result_permissions "$RESULTS_DIR"
if ! python3 "${SCRIPT_DIR}/reconcile_result_status.py" "$RESULTS_DIR"; then
  echo "[recover] failed to reconcile sample status with Docker state" >&2
  overall_status=1
fi
exit "$overall_status"
