#!/bin/bash
# Salvage a fuzzer result directory from a stopped container and protect it
# from being overwritten by the recovery script.
#
# Usage: salvage_from_container.sh <container_id> <target> <result_dir>
#
# Creates <result_dir>/out-<target>-loopfuzz_1.tar.gz plus a .salvaged marker
# that tells recover_result_archives.sh to skip this archive.
set -euo pipefail

CONTAINER_ID="$1"
TARGET="$2"
RESULT_DIR="$3"

[[ -n "$CONTAINER_ID" && -n "$TARGET" && -n "$RESULT_DIR" ]] || {
  echo "Usage: $0 <container_id> <target> <result_dir>" >&2; exit 1
}

TAR="${RESULT_DIR}/out-${TARGET}-loopfuzz_1.tar.gz"
MARKER="${RESULT_DIR}/out-${TARGET}-loopfuzz_1.tar.gz.salvaged"

# Already salvaged?
if [[ -f "$MARKER" ]]; then
  echo "[salvage] already salvaged: $TAR"
  exit 0
fi

# Try known outdir layouts (1-3 levels below WORKDIR)
WORKDIR="/home/ubuntu/experiments"
OUTDIR_NAME="out-${TARGET}-loopfuzz"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/salvage-${TARGET}-XXXXXX")
FOUND=""

for layout in \
  "${WORKDIR}/${OUTDIR_NAME}" \
  "${WORKDIR}/${TARGET}/${OUTDIR_NAME}" \
  "${WORKDIR}/${TARGET}/src/${OUTDIR_NAME}" \
  "${WORKDIR}/*/Source/Release/${OUTDIR_NAME}" \
  "${WORKDIR}/${TARGET}-gcov/src/${OUTDIR_NAME}" \
  "${WORKDIR}/LightFTP/Source/Release/${OUTDIR_NAME}" \
  "${WORKDIR}/live-gcov/testProgs/${OUTDIR_NAME}"; do

  docker cp "${CONTAINER_ID}:${layout}" "$TMP/" >/dev/null 2>&1
  if [[ -d "$TMP/$(basename "$OUTDIR_NAME")" ]]; then
    FOUND="$TMP/$(basename "$OUTDIR_NAME")"
    break
  fi
  # docker cp preserves the full path; check nested
  if [[ -d "$TMP/$layout" ]]; then
    # Extract just the outdir from the nested path
    REL="${layout#$WORKDIR/}"
    mkdir -p "$TMP/flat/$(dirname "$REL")"
    mv "$TMP/$layout" "$TMP/flat/$REL"
    FOUND="$TMP/flat/$REL"
    break
  fi
done

if [[ -z "$FOUND" ]]; then
  # Fallback: search for it
  OUTDIR=$(docker logs "$CONTAINER_ID" 2>&1 | grep -oE "${WORKDIR}/[^ ]*/out-${TARGET}-loopfuzz" | head -1)
  if [[ -n "$OUTDIR" ]]; then
    docker cp "${CONTAINER_ID}:${OUTDIR}" "$TMP/" >/dev/null 2>&1
    [[ -d "$TMP/$(basename "$OUTDIR")" ]] && FOUND="$TMP/$(basename "$OUTDIR")"
  fi
fi

if [[ -z "$FOUND" ]]; then
  echo "[salvage] FAIL: could not find outdir in container ${CONTAINER_ID}" >&2
  rm -rf "$TMP"
  exit 1
fi

# Create the TAR with the correct structure (top-level dir = out-<target>-loopfuzz)
mkdir -p "$RESULT_DIR"
tar -czf "$TAR" -C "$(dirname "$FOUND")" "$(basename "$FOUND")"

# Create the protection marker
touch "$MARKER"

# Validate: does the TAR have fuzzer_stats?
if ! tar -tzf "$TAR" 2>/dev/null | grep -q fuzzer_stats; then
  echo "[salvage] WARN: TAR created but fuzzer_stats not found (may be partial)" >&2
fi

echo "[salvage] ✓ salvaged ${TAR} (marker: ${MARKER})"
rm -rf "$TMP"
