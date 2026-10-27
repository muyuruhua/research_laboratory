#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
default_root="$(cd -- "$script_dir/../../.." && pwd)"
analysis_root="${1:-$default_root}"
analysis_output="${2:-$script_dir/..}"
mkdir -p "$analysis_output/data" "$analysis_output/figures"
python3 "$script_dir/analyze_workload.py" --root "$analysis_root" --output "$analysis_output/data/workload"
python3 "$script_dir/audit_provisional.py" --root "$analysis_root" --output "$analysis_output/data/provisional"
python3 "$script_dir/analyze_coverage.py" --root "$analysis_root" --output "$analysis_output/data/coverage"
python3 "$script_dir/assemble.py" --root "$analysis_root" --output "$analysis_output"
