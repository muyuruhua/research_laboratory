#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./run_crash_analysis.sh <results-dir> [--verbose] [extra crash_analysis.py args]

Examples:
  ./run_crash_analysis.sh results-kamailio_Mar-16_23-10-02_ten
  ./run_crash_analysis.sh benchmark/results-kamailio_Mar-16_23-10-02_ten --verbose
  ./run_crash_analysis.sh /abs/path/to/results-mosquitto_Mar-31_22-28-13 -v

Notes:
  - The first argument must be a results-* directory.
  - Remaining arguments are passed through to crash_analysis.py unchanged.
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 0
fi

RAW_RESULTS_DIR="$1"
shift
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RESULTS_DIR=""
for candidate in \
  "$RAW_RESULTS_DIR" \
  "$SCRIPT_DIR/$RAW_RESULTS_DIR" \
  "$SCRIPT_DIR/benchmark/$RAW_RESULTS_DIR" \
  "$SCRIPT_DIR/../benchmark/$RAW_RESULTS_DIR" \
  "$SCRIPT_DIR/./$RAW_RESULTS_DIR"; do
  if [[ -d "$candidate" ]]; then
    RESULTS_DIR="$(cd "$candidate" && pwd)"
    break
  fi
done

if [[ -z "$RESULTS_DIR" ]]; then
  echo "Error: results directory not found: $RAW_RESULTS_DIR" >&2
  usage >&2
  exit 1
fi

RESULTS_BASENAME="$(basename "$RESULTS_DIR")"
if [[ "$RESULTS_BASENAME" != results-* ]]; then
  echo "Error: expected a results-* directory, got: $RESULTS_BASENAME" >&2
  exit 1
fi

ANALYSIS_PY=""
for candidate in \
  "$SCRIPT_DIR/scripts/analysis/crash_analysis.py" \
  "$SCRIPT_DIR/benchmark/scripts/analysis/crash_analysis.py" \
  "$SCRIPT_DIR/../benchmark/scripts/analysis/crash_analysis.py"; do
  if [[ -f "$candidate" ]]; then
    ANALYSIS_PY="$candidate"
    break
  fi
done

if [[ -z "$ANALYSIS_PY" ]]; then
  echo "Error: cannot find scripts/analysis/crash_analysis.py" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is not available in PATH" >&2
  exit 1
fi

echo "[INFO] Results directory : $RESULTS_DIR"
echo "[INFO] Analysis script   : $ANALYSIS_PY"
echo "[INFO] Python executable : $(command -v python3)"

python3 "$ANALYSIS_PY" "$RESULTS_DIR" "$@"
