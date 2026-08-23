#!/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./run_vuln_triage.sh <results-dir> [--verbose]

Examples:
  ./run_vuln_triage.sh results-live555_Aug-19_23-16-33
  ./run_vuln_triage.sh benchmark/results-proftpd_Aug-19_23-16-33 -v
  ./run_vuln_triage.sh /abs/path/to/results-bftpd_Aug-19_23-16-33

Notes:
  - The first argument must be a results-* directory.
  - Scans teardown-crashes/, replayable-hangs/, replayable-violations/
    and merges crash_analysis.csv in every out-* run dir.
  - Writes <results-dir>/vuln_triage_report.csv.
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

TRIAGE_PY=""
for candidate in \
  "$SCRIPT_DIR/scripts/analysis/vuln_triage.py" \
  "$SCRIPT_DIR/benchmark/scripts/analysis/vuln_triage.py" \
  "$SCRIPT_DIR/../benchmark/scripts/analysis/vuln_triage.py"; do
  if [[ -f "$candidate" ]]; then
    TRIAGE_PY="$candidate"
    break
  fi
done

if [[ -z "$TRIAGE_PY" ]]; then
  echo "Error: cannot find scripts/analysis/vuln_triage.py" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is not available in PATH" >&2
  exit 1
fi

echo "[INFO] Results directory : $RESULTS_DIR"
echo "[INFO] Triage script     : $TRIAGE_PY"
echo "[INFO] Python executable : $(command -v python3)"

python3 "$TRIAGE_PY" "$RESULTS_DIR" "$@"
