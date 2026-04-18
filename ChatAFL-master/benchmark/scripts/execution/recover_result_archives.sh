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

collect_from_container() {
  local container_id="$1"
  local outdir="$2"
  local destination="$3"
  local tmp_file="${destination}.partial"
  local extracted_root=""

  rm -f "$tmp_file"

  for attempt in 1 2 3; do
    if docker cp "${container_id}:${WORKDIR}/${outdir}.tar.gz" "$tmp_file" >/dev/null 2>&1; then
      mv "$tmp_file" "$destination"
      fix_result_permissions "$destination"
      return 0
    fi
    sleep "$attempt"
  done

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
  if [[ -s "$destination" ]]; then
    echo "[recover] exists: ${archive_name}"
    continue
  fi

  label="$container_id"
  [[ -n "$container_name" ]] && label="$container_name"
  [[ -z "$container_name" ]] && label="$(short_container_id "$container_id")"
  echo "[recover] collecting ${archive_name} from ${label}"

  if collect_from_container "$container_id" "$outdir" "$destination"; then
    echo "[recover] collected ${archive_name}"
    # Validate that cov_over_time.csv is present in the tarball
    if ! tar tzf "$destination" 2>/dev/null | grep -q "cov_over_time.csv"; then
      echo "[recover] [WARN] ${archive_name} missing cov_over_time.csv – coverage data may be incomplete" >&2
      # Try to recover cov_over_time.csv directly from container
      local cov_src="${WORKDIR}/${outdir}/cov_over_time.csv"
      local tmp_cov=$(mktemp)
      if docker cp "${container_id}:${cov_src}" "$tmp_cov" >/dev/null 2>&1 && [[ -s "$tmp_cov" ]]; then
        local tmp_extract=$(mktemp -d)
        tar xzf "$destination" -C "$tmp_extract"
        cp "$tmp_cov" "$tmp_extract/${outdir}/cov_over_time.csv"
        tar czf "$destination" -C "$tmp_extract" "$outdir"
        rm -rf "$tmp_extract"
        echo "[recover] patched cov_over_time.csv into ${archive_name}"
      fi
      rm -f "$tmp_cov"
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