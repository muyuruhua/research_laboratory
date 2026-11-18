#!/bin/bash
set -euo pipefail

module=${COVERAGE_V4_MODULE:-${WORKDIR:-}/coverage_v4/coverage_v4.py}
if [[ ! -f "$module" ]]; then
  module="$(dirname "${BASH_SOURCE[0]}")/../../../scripts/analysis/coverage_v4.py"
fi
if [[ ! -f "$module" ]]; then
  echo "coverage-v4: install the shared module and set COVERAGE_V4_MODULE" >&2
  exit 2
fi
flags=()
if [[ ${COVERAGE_V4_REQUIRE_COORDINATES:-1} == 1 ]]; then
  flags+=(--require-coordinates)
fi
if [[ ${COVERAGE_V4_SMOKE:-0} == 1 ]]; then
  flags+=(--smoke)
fi
if [[ -n ${COVERAGE_V4_MAX_REPLAY_INPUTS:-} ]]; then
  [[ ${COVERAGE_V4_SMOKE:-0} == 1 ]] || {
    echo "coverage-v4: COVERAGE_V4_MAX_REPLAY_INPUTS requires COVERAGE_V4_SMOKE=1" >&2
    exit 2
  }
  flags+=(--max-replay-inputs "$COVERAGE_V4_MAX_REPLAY_INPUTS")
fi
exec python3 "$module" replay --target pure-ftpd --folder "$1" --port "$2" \
  --step "$3" --output "$4" --mode "$5" "${flags[@]}"
