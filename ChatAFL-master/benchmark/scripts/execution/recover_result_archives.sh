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

fix_result_permissions() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  chown -R "${RESULT_OWNER}:${RESULT_GROUP}" "$path" 2>/dev/null || true
  chmod -R u+rwX "$path" 2>/dev/null || true
}

# Required files that must be present in a complete tarball.
REQUIRED_FILES="fuzzer_stats cov_over_time.csv"

tarball_is_complete() {
  local tarball="$1"
  [[ -s "$tarball" ]] || return 1
  local listing
  listing=$(tar tzf "$tarball" 2>/dev/null) || return 1
  for req in $REQUIRED_FILES; do
    if [[ "$listing" != *"$req"* ]]; then
      return 1
    fi
  done
  return 0
}

collect_from_container() {
  local container_id="$1"
  local outdir="$2"
  local destination="$3"
  local tmp_file="${destination}.partial"
  local extracted_root=""

  rm -f "$tmp_file"

  # Strategy 1: copy the container-internal tar.gz produced by the run script
  # (this is the most reliable source — created after fuzzing + cov_script complete)
  for attempt in 1 2 3; do
    if docker cp "${container_id}:${WORKDIR}/${outdir}.tar.gz" "$tmp_file" >/dev/null 2>&1; then
      if tarball_is_complete "$tmp_file"; then
        mv "$tmp_file" "$destination"
        fix_result_permissions "$destination"
        return 0
      fi
      echo "[recover] [WARN] inner tar.gz exists but is incomplete, retrying..." >&2
      rm -f "$tmp_file"
    fi
    sleep "$attempt"
  done

  # Strategy 2: copy the raw output directory and tar it locally
  extracted_root=$(mktemp -d "${TMPDIR:-/tmp}/recover-${outdir}-XXXXXX")
  if docker cp "${container_id}:${WORKDIR}/${outdir}" "${extracted_root}/" >/dev/null 2>&1; then
    tar -czf "$tmp_file" -C "$extracted_root" "$outdir"
    mv "$tmp_file" "$destination"
    rm -rf "$extracted_root"
    fix_result_permissions "$destination"
    return 0
  fi

  rm -rf "$extracted_root"
  rm -f "$tmp_file"
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

  # Check if existing tarball is complete; if incomplete, try to upgrade it
  if [[ -s "$destination" ]]; then
    if tarball_is_complete "$destination"; then
      echo "[recover] ✓ complete: ${archive_name}"
      continue
    fi
    # Existing tarball is incomplete — rename it as backup and re-collect
    _bak="${destination}.incomplete.$(date +%s)"
    echo "[recover] [WARN] ${archive_name} is incomplete (missing required files), re-collecting..."
    mv "$destination" "$_bak"
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
        if [[ "$_dest_listing" != *"$req"* ]]; then
          _src="${WORKDIR}/${outdir}/${req}"
          _tmp_file=$(mktemp)
          if docker cp "${container_id}:${_src}" "$_tmp_file" >/dev/null 2>&1 && [[ -s "$_tmp_file" ]]; then
            _tmp_extract=$(mktemp -d)
            tar xzf "$destination" -C "$_tmp_extract"
            cp "$_tmp_file" "$_tmp_extract/${outdir}/${req}"
            tar czf "$destination" -C "$_tmp_extract" "$outdir"
            rm -rf "$_tmp_extract"
            echo "[recover] patched ${req} into ${archive_name}"
          fi
          rm -f "$_tmp_file"
        fi
      done
      # Final check
      if tarball_is_complete "$destination"; then
        echo "[recover] ✓ ${archive_name} now complete after patching"
      else
        echo "[recover] [WARN] ${archive_name} still incomplete – container may still be running" >&2
      fi
    fi
    if [[ "$DELETE_MODE" == "--delete" ]]; then
      docker rm "$container_id" >/dev/null 2>&1 || true
    fi
  else
    echo "[recover] failed to collect ${archive_name} from ${label}" >&2
    echo 1 > "$_status_file"
  fi
done

overall_status=$(cat "$_status_file")
rm -f "$_status_file"

fix_result_permissions "$RESULTS_DIR"
exit "$overall_status"
exit "$overall_status"