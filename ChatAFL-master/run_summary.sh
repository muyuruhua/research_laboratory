#!/bin/bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: ./run_summary.sh <results-dir> [<results-dir> ...]"
  echo "Example: ./run_summary.sh benchmark/results-bftpd_Mar-16_23-10-02_ten"
  echo "Example: ./run_summary.sh results-a results-b results-c"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

resolve_results_dir() {
  local raw_results_dir="$1"
  local results_dir=""

  for candidate in \
    "$raw_results_dir" \
    "benchmark/$raw_results_dir" \
    "../benchmark/$raw_results_dir" \
    "./benchmark/$raw_results_dir"; do
    if [[ -d "$candidate" ]]; then
      results_dir="$candidate"
      break
    fi
  done

  if [[ -z "$results_dir" ]]; then
    echo "Error: results directory not found: $raw_results_dir" >&2
    return 1
  fi

  (cd "$results_dir" && pwd)
}

resolve_summary_py() {
  local summary_py=""

  for candidate in \
    "$SCRIPT_DIR/benchmark/scripts/analysis/run_summary.py" \
    "$SCRIPT_DIR/../benchmark/scripts/analysis/run_summary.py"; do
    if [[ -f "$candidate" ]]; then
      summary_py="$candidate"
      break
    fi
  done

  if [[ -z "$summary_py" ]]; then
    echo "Error: cannot find benchmark/scripts/analysis/run_summary.py" >&2
    return 1
  fi

  echo "$summary_py"
}

process_results_dir() {
  local raw_results_dir="$1"
  local summary_py="$2"
  local results_dir=""
  local output_file=""

  results_dir="$(resolve_results_dir "$raw_results_dir")"
  output_file="$results_dir/run_summary.csv"

  python3 "$summary_py" "$results_dir" -o "$output_file"
  echo "Generated: $output_file"
}

SUMMARY_PY="$(resolve_summary_py)"

for raw_results_dir in "$@"; do
  process_results_dir "$raw_results_dir" "$SUMMARY_PY"
done