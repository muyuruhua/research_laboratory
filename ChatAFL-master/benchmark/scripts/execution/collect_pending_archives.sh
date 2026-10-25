#!/bin/bash
# Serial collection orchestrator (repo-owned replacement for ad-hoc recovery).
# Tiers, in order:
#   1. existing final archive that verifies complete  -> nothing to do
#   2. a verifiable .partial / .incomplete.<ts> sidecar on disk
#      (gzip OK + fuzzer_stats + cov_over_time.csv)   -> atomic promote
#   3. per-dir recovery script (fetches from container if it still exists)
# Idempotent; safe to re-run; never deletes a final that verifies complete.
# Usage: collect_pending_archives.sh [results-glob] [max-passes]
set -uo pipefail
cd "$(dirname "$0")/../../" || exit 1   # benchmark/
PATTERN="${1:-results-*}"
MAX_PASSES="${2:-3}"

verify_complete() {
  local t="$1" listing
  [[ -s "$t" ]] || return 1
  listing=$(tar tzf "$t" 2>/dev/null) || return 1
  printf '%s\n' "$listing" | grep -qE '(^|/)fuzzer_stats$' || return 1
  printf '%s\n' "$listing" | grep -qE '(^|/)cov_over_time\.csv$' || return 1
  return 0
}

promote_sidecar() { # dir archive-basename -> 0 if promoted
  local d="$1" arch="$2" cand promoted=""
  for cand in "${d}/${arch}.partial" "${d}"/${arch}.incomplete.*; do
    [[ -s "$cand" ]] || continue
    if verify_complete "$cand"; then
      if [[ -s "${d}/${arch}" && ! -f "${d}/${arch}.salvaged" ]]; then
        mv "${d}/${arch}" "${d}/${arch}.incomplete.$(date +%s)" 2>/dev/null || true
      fi
      mv "$cand" "${d}/${arch}"
      echo "[collect] promoted $(basename "$cand") -> ${arch} (${d})"
      promoted=1
    fi
  done
  [[ -n "$promoted" ]]
}

pass_num=0
while (( pass_num < MAX_PASSES )); do
  pass_num=$((pass_num+1))
  acted=0
  echo "=== pass ${pass_num} ($(date '+%H:%M:%S')) ==="
  for d in $PATTERN; do
    [[ -d "$d" && -f "$d/.result_manifest.tsv" ]] || continue
    # dirs whose containers are gone and no sidecar exists are skipped fast
    while IFS=$'\t' read -r _ _ _ _ _ _ arch; do
      [[ "$arch" == archive_name || -z "$arch" ]] && continue
      if [[ -s "$d/$arch" ]] && verify_complete "$d/$arch"; then continue; fi
      if [[ -f "$d/${arch}.salvaged" && -s "$d/$arch" ]]; then continue; fi
      if promote_sidecar "$d" "$arch"; then acted=$((acted+1)); continue; fi
      # no disk-side candidate: try container recovery (works only if the
      # container still exists; otherwise reports failure visibly)
      echo "[collect] recovering $d ($arch)"
      timeout 900 bash scripts/execution/recover_result_archives.sh "./$d" || true
      acted=$((acted+1))
    done < <(tail -n +2 "$d/.result_manifest.tsv")
  done
  echo "pass ${pass_num}: ${acted} cells acted on"
  (( acted == 0 )) && break
done

# Final inventory
total=0; complete=0; missing=""
for d in $PATTERN; do
  [[ -d "$d" && -f "$d/.result_manifest.tsv" ]] || continue
  while IFS=$'\t' read -r _ _ _ _ _ _ arch; do
    [[ "$arch" == archive_name || -z "$arch" ]] && continue
    total=$((total+1))
    if [[ -s "$d/$arch" ]] && verify_complete "$d/$arch"; then complete=$((complete+1));
    else missing="${missing}${d}/${arch}\n"; fi
  done < <(tail -n +2 "$d/.result_manifest.tsv")
done
echo "=== INVENTORY: ${complete}/${total} archives complete ==="
[[ -n "$missing" ]] && { echo "仍缺失:"; printf "$missing"; exit 1; }
exit 0
