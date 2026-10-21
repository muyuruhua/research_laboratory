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
exec python3 "$module" replay --target forked-daapd --folder "$1" --port "$2" \
  --step "$3" --output "$4" --mode "$5" "${flags[@]}"
