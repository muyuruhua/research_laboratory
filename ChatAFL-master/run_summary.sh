#!/bin/bash
set -euo pipefail

# run_summary.sh — Generate/rebuild run_summary.csv for results directories
#
# Usage:
#   ./run_summary.sh <results-dir>              → dedup + renumber + regenerate csv
#   ./run_summary.sh <results-dir> <min_min>    → dedup + filter short runs + renumber + regenerate csv
#   ./run_summary.sh <parent-dir>               → process all results dirs under parent
#   ./run_summary.sh <parent-dir> <min_min>     → process all + dedup + filter + renumber + regenerate
#
# Dedup rule: within the same target+fuzzer group, if two tarballs have identical
# MD5 checksums (byte-for-byte duplicates from merge), keep the first and remove
# the rest.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GET_RT_PY="$SCRIPT_DIR/scripts/get_rt.py"

log()  { echo "[$(date +%H:%M:%S)] $*"; }
warn() { echo "[$(date +%H:%M:%S)] WARN: $*" >&2; }
die()  { echo "[$(date +%H:%M:%S)] ERROR: $*" >&2; exit 1; }

resolve_results_dir() {
  local raw="$1"
  for candidate in "$raw" "benchmark/$raw" "../benchmark/$raw"; do
    if [[ -d "$candidate" ]]; then
      (cd "$candidate" && pwd) && return 0
    fi
  done
  die "results directory not found: $raw"
}

resolve_summary_py() {
  for candidate in "$SCRIPT_DIR/benchmark/scripts/analysis/run_summary.py"; do
    [[ -f "$candidate" ]] && { echo "$candidate"; return 0; }
  done
  die "cannot find run_summary.py"
}

is_direct_results_dir() {
  local dir="$1"
  [[ -d "$dir" ]] || return 1
  ls "$dir"/out-*.tar.gz >/dev/null 2>&1
}

get_fuzzer() {
  echo "$1" | sed -E 's/^out-.+-([a-z0-9_-]+)_[0-9]+\.tar\.gz$/\1/'
}

get_runtime_min() {
  python3 "$GET_RT_PY" "$1" 2>/dev/null || echo -2
}

# Deduplicate tarballs by MD5 within the same fuzzer group.
# Keeps the first occurrence, removes subsequent duplicates.
dedup_dir() {
  local dir="$1"
  local dedup_count=0

  # Group files by fuzzer first
  declare -A fuzzer_lists
  for f in "$dir"/out-*.tar.gz; do
    [[ -e "$f" ]] || continue
    local fuzzer
    fuzzer=$(get_fuzzer "$(basename "$f")")
    fuzzer_lists[$fuzzer]="${fuzzer_lists[$fuzzer]:-} $f"
  done

  for fuzzer in "${!fuzzer_lists[@]}"; do
    declare -A seen_md5
    for f in $(echo "${fuzzer_lists[$fuzzer]}" | tr ' ' '\n' | sort -V); do
      [[ -z "$f" ]] && continue
      local md5
      md5=$(md5sum "$f" | awk '{print $1}')
      if [[ -n "${seen_md5[$md5]:-}" ]]; then
        log "  dedup: $(basename "$f") = duplicate of ${seen_md5[$md5]}"
        rm -f "$f"
        dedup_count=$((dedup_count + 1))
      else
        seen_md5[$md5]=$(basename "$f")
      fi
    done
    unset seen_md5
  done

  [ "$dedup_count" -gt 0 ] && log "  dedup: removed $dedup_count duplicate(s)"
  return 0
}

# Filter by runtime + dedup + renumber + report
process_tarballs() {
  local dir="$1"
  local min_minutes="${2:-0}"
  log "Processing: $dir"

  local rename_list="/tmp/rs_renames_$$.txt"
  rm -f "$rename_list"

  # ── Step 1: Filter by runtime ──
  local total_filtered=0
  if [[ "$min_minutes" -gt 0 ]]; then
    for f in "$dir"/out-*.tar.gz; do
      [[ -e "$f" ]] || continue
      local rt
      rt=$(get_runtime_min "$f")
      if [[ "$rt" -ge 0 && "$rt" -lt "$min_minutes" ]]; then
        log "  filter: $(basename "$f") (${rt}min < ${min_minutes}min)"
        rm -f "$f"
        total_filtered=$((total_filtered + 1))
      elif [[ "$rt" -lt 0 ]]; then
        warn "  no runtime: $(basename "$f") (keeping)"
      fi
    done
  fi

  # ── Step 2: Dedup by MD5 ──
  dedup_dir "$dir"

  # ── Step 3: Renumber per fuzzer ──
  declare -A fuzzer_files
  local total_kept=0

  for f in "$dir"/out-*.tar.gz; do
    [[ -e "$f" ]] || continue
    local fuzzer
    fuzzer=$(get_fuzzer "$(basename "$f")")
    fuzzer_files[$fuzzer]="${fuzzer_files[$fuzzer]:-} $f"
    total_kept=$((total_kept + 1))
  done

  for fuzzer in "${!fuzzer_files[@]}"; do
    local counter=0
    for f in $(echo "${fuzzer_files[$fuzzer]}" | tr ' ' '\n' | sort -V); do
      [[ -z "$f" ]] && continue
      local fname prefix new_name tmp_name
      fname=$(basename "$f")
      prefix="${fname%_*}"
      counter=$((counter + 1))
      new_name="${prefix}_${counter}.tar.gz"
      if [[ "$fname" != "$new_name" ]]; then
        tmp_name="${prefix}_tmpren_${counter}.tar.gz"
        mv "$f" "$dir/$tmp_name"
        echo "$dir/$tmp_name $dir/$new_name" >> "$rename_list"
      fi
    done
    log "  $fuzzer: $counter runs"
  done

  # Two-phase rename to avoid collisions
  if [[ -s "$rename_list" ]]; then
    while read -r tmp final; do
      [[ -z "$tmp" ]] && continue
      mv "$tmp" "$final" 2>/dev/null || warn "rename failed: $tmp"
    done < "$rename_list"
  fi
  rm -f "$rename_list"

  log "  result: kept=$total_kept filtered=$total_filtered"
}

generate_summary() {
  local dir="$1"
  local summary_py="$2"
  python3 "$summary_py" "$dir" -o "$dir/run_summary.csv"
  log "  csv: $dir/run_summary.csv"
}

process_dir() {
  local dir="$1"
  local summary_py="$2"
  local min_minutes="${3:-0}"
  process_tarballs "$dir" "$min_minutes"
  generate_summary "$dir" "$summary_py"
}

# ── Main ──
if [[ $# -lt 1 ]]; then
  echo "Usage: ./run_summary.sh <results-dir-or-parent> [min_minutes]"
  echo "  <dir>           dedup + renumber + regenerate run_summary.csv"
  echo "  <dir> <min>     dedup + filter runs < min minutes + renumber + regenerate"
  echo "  Known fuzzers: aflnet chatafl loopfuzz"
  exit 1
fi

SUMMARY_PY="$(resolve_summary_py)"
RAW_DIR="$1"
MIN_MINUTES="${2:-0}"
[[ "$MIN_MINUTES" =~ ^[0-9]+$ ]] || die "invalid min_minutes: $MIN_MINUTES"
RESOLVED="$(resolve_results_dir "$RAW_DIR")"

if is_direct_results_dir "$RESOLVED"; then
  process_dir "$RESOLVED" "$SUMMARY_PY" "$MIN_MINUTES"
else
  log "Scanning parent: $RESOLVED"
  n=0
  for child in "$RESOLVED"/*/; do
    child="${child%/}"
    is_direct_results_dir "$child" || continue
    n=$((n + 1))
    process_dir "$child" "$SUMMARY_PY" "$MIN_MINUTES"
  done
  [[ "$n" -eq 0 ]] && warn "no results dirs found under $RESOLVED"
  [[ "$n" -gt 0 ]] && log "Processed $n directories"
fi
