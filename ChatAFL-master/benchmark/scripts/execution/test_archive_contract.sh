#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/archive_contract.sh"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

make_archive() {
  local name="$1" terminal="$2" csv="${3:-yes}"
  local root="${TMP_DIR}/tree-${name}"
  mkdir -p "${root}/out/cov_over_time.csv.v${terminal}"
  : > "${root}/out/fuzzer_stats"
  [[ "$csv" == yes ]] && : > "${root}/out/cov_over_time.csv"
  printf '{"acceptance":"incomplete"}\n' > "${root}/out/cov_over_time.csv.v${terminal}/terminal.json"
  tar czf "${TMP_DIR}/${name}.tar.gz" -C "$root" out
}

make_archive v4 4
make_archive v5 5
make_archive no_terminal 4
rm "${TMP_DIR}/tree-no_terminal/out/cov_over_time.csv.v4/terminal.json"
tar czf "${TMP_DIR}/no_terminal.tar.gz" -C "${TMP_DIR}/tree-no_terminal" out
make_archive no_csv 4 no
printf 'not a tar archive\n' > "${TMP_DIR}/invalid.tar.gz"

archive_tar_is_structurally_complete "${TMP_DIR}/v4.tar.gz"
archive_tar_is_structurally_complete "${TMP_DIR}/v5.tar.gz"
! archive_tar_is_structurally_complete "${TMP_DIR}/no_terminal.tar.gz"
! archive_tar_is_structurally_complete "${TMP_DIR}/no_csv.tar.gz"
! archive_tar_is_structurally_complete "${TMP_DIR}/invalid.tar.gz"

echo "archive contract: v4/v5 terminals accepted; missing terminal/CSV and invalid tar rejected"
