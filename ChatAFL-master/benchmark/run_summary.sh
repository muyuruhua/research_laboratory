#!/bin/bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: ./run_summary.sh <results-dir-or-parent> [<results-dir-or-parent> ...]"
  echo ""
  echo "  Each argument can be either:"
  echo "    • A direct results directory (contains out-*.tar.gz or out-*/ dirs)"
  echo "      → generates run_summary.csv inside it"
  echo "    • A parent directory containing multiple results directories"
  echo "      → generates run_summary.csv inside each qualifying child"
  echo ""
  echo "  Examples:"
  echo "    ./run_summary.sh benchmark/results-mosquitto_full"
  echo "    ./run_summary.sh results_ablation/               # auto-discover all children"
  echo "    ./run_summary.sh results-a results-b results-c"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Path resolution ──────────────────────────────────────────────

resolve_results_dir() {
  local raw="$1"
  local resolved=""

  for candidate in \
    "$raw" \
    "benchmark/$raw" \
    "../benchmark/$raw" \
    "./benchmark/$raw"; do
    if [[ -d "$candidate" ]]; then
      resolved="$candidate"
      break
    fi
  done

  if [[ -z "$resolved" ]]; then
    echo "Error: results directory not found: $raw" >&2
    return 1
  fi

  (cd "$resolved" && pwd)
}

resolve_summary_py() {
  # SCRIPT_DIR is .../benchmark/, so scripts/ is directly below
  for candidate in \
    "$SCRIPT_DIR/scripts/analysis/run_summary.py" \
    "$SCRIPT_DIR/../benchmark/scripts/analysis/run_summary.py"; do
    if [[ -f "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done

  echo "Error: cannot find benchmark/scripts/analysis/run_summary.py" >&2
  return 1
}

# ── Detection ────────────────────────────────────────────────────

# A "direct results directory" contains at least one entry matching
# the pattern that run_summary.py scans: out-<subject>-<fuzzer>_<N>.tar.gz
# or an extracted out-<subject>-<fuzzer>-<N>/ directory.
is_direct_results_dir() {
  local dir="$1"
  [[ -d "$dir" ]] || return 1

  local found
  found=$(
    cd "$dir" 2>/dev/null || exit 1
    ls -1 2>/dev/null
  ) || return 1

  # Match either packed tarballs or extracted run directories
  echo "$found" | grep -qE '^out-.+_[0-9]+\.tar\.gz$|^out-.+-[0-9]+/$'
}

# Discover qualifying child results directories under a parent.
discover_children() {
  local parent="$1"
  [[ -d "$parent" ]] || return 1

  for child in "$parent"/*/; do
    child="${child%/}"                       # strip trailing /
    if is_direct_results_dir "$child"; then
      echo "$child"
    fi
  done
}

# ── Core ─────────────────────────────────────────────────────────

process_results_dir() {
  local results_dir="$1"
  local summary_py="$2"
  local output_file="$results_dir/run_summary.csv"

  python3 "$summary_py" "$results_dir" -o "$output_file"
  echo "Generated: $output_file"
}

# Orchestrator: given a resolved path, decide whether it's a single
# results dir or a parent, then generate summaries accordingly.
process_path() {
  local resolved="$1"
  local summary_py="$2"

  if is_direct_results_dir "$resolved"; then
    # ── Case 1: Direct results directory ──
    process_results_dir "$resolved" "$summary_py"
    return 0
  fi

  # ── Case 2: Parent directory → discover children ──
  local children
  children=$(discover_children "$resolved")

  if [[ -z "$children" ]]; then
    echo "Warning: No results directories found under $resolved — skipping" >&2
    return 0
  fi

  local count
  count=$(echo "$children" | wc -l)
  echo "[$resolved] Discovered $count results director$( (( count != 1 )) && echo 'ies'):"
  echo "$children" | sed 's/^/  /'

  while IFS= read -r child; do
    process_results_dir "$child" "$summary_py"
  done <<< "$children"
}

# ── Main ─────────────────────────────────────────────────────────

SUMMARY_PY="$(resolve_summary_py)"

for raw_arg in "$@"; do
  resolved="$(resolve_results_dir "$raw_arg")"  # aborts on failure (set -e)
  process_path "$resolved" "$SUMMARY_PY"
done
