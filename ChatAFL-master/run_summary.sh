#!/bin/bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: ./run_summary.sh <results-dir>"
  echo "Example: ./run_summary.sh benchmark/results-bftpd_Mar-16_23-10-02_ten"
  exit 1
fi

RAW_RESULTS_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RESULTS_DIR=""
for candidate in \
  "$RAW_RESULTS_DIR" \
  "benchmark/$RAW_RESULTS_DIR" \
  "../benchmark/$RAW_RESULTS_DIR" \
  "./benchmark/$RAW_RESULTS_DIR"; do
  if [[ -d "$candidate" ]]; then
    RESULTS_DIR="$candidate"
    break
  fi
done

if [[ -z "$RESULTS_DIR" ]]; then
  echo "Error: results directory not found: $RAW_RESULTS_DIR"
  exit 1
fi

OUTPUT_FILE="$(cd "$RESULTS_DIR" && pwd)/run_summary.csv"

SUMMARY_PY=""
for candidate in \
  "$SCRIPT_DIR/benchmark/scripts/analysis/run_summary.py" \
  "$SCRIPT_DIR/../benchmark/scripts/analysis/run_summary.py"; do
  if [[ -f "$candidate" ]]; then
    SUMMARY_PY="$candidate"
    break
  fi
done

if [[ -z "$SUMMARY_PY" ]]; then
  echo "Error: cannot find benchmark/scripts/analysis/run_summary.py"
  exit 1
fi

python3 "$SUMMARY_PY" "$RESULTS_DIR" -o "$OUTPUT_FILE"
