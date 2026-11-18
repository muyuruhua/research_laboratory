#!/usr/bin/env bash
# Shared structural archive contract for LoopFuzz result collection.
# Structural completeness requires the campaign stats/CSV and a terminal
# record from coverage replay. The terminal's acceptance field is checked by
# the scientific audit; its presence alone does not imply complete coverage.

archive_listing_has_member() {
  local listing="$1" member="$2"
  grep -qE "(^|/)${member//./\\.}$" <<< "$listing"
}

archive_listing_has_coverage_terminal() {
  local listing="$1"
  grep -qE '(^|/)cov_over_time\.csv\.v[45]/terminal\.json$' <<< "$listing"
}

archive_tar_is_structurally_complete() {
  local archive="$1" listing
  [[ -s "$archive" ]] || return 1
  listing=$(tar tzf "$archive" 2>/dev/null) || return 1
  archive_listing_has_member "$listing" 'fuzzer_stats' || return 1
  archive_listing_has_member "$listing" 'cov_over_time.csv' || return 1
  archive_listing_has_coverage_terminal "$listing" || return 1
  return 0
}
