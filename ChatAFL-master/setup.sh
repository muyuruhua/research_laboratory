#!/bin/bash

set -euo pipefail

SYNC_ONLY=0
if [[ "${1:-}" == "--sync-only" ]]; then
  SYNC_ONLY=1
fi

if [ -z "${KEY:-}" ]; then
  if [[ "$SYNC_ONLY" -eq 1 ]]; then
    echo "[WARN] KEY not set; skipping OPENAI_TOKEN update (sync-only mode)."
  else
    echo "NO OPENAI API KEY PROVIDED! Please set the KEY environment variable"
    exit 0
  fi
fi

# Update the openAI key
if [ -n "${KEY:-}" ]; then
  for x in ChatAFL ChatAFL-CL1 ChatAFL-CL2 ChatAFL-Enhanced;
  do
    sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$KEY\"/" $x/chat-llm.h
  done
fi

# Copy the different versions of ChatAFL to the benchmark directories
USER_NAME="$(id -un)"
GROUP_NAME="$(id -gn)"
CHOWN_HINT="sudo chown -R ${USER_NAME}:${GROUP_NAME} benchmark/subjects"

check_writable_or_die() {
  local path="$1"
  if [[ -e "$path" && ! -w "$path" ]]; then
    echo "[ERROR] '$path' is not writable (often caused by root-owned files created during Docker builds)."
    echo "[ERROR] Fix ownership/permissions, then re-run setup. Suggested command:"
    echo "        ${CHOWN_HINT}"
    exit 1
  fi
}

for subject in ./benchmark/subjects/*/*; do
  check_writable_or_die "$subject/aflnet"
  rm -rf "$subject/aflnet" >/dev/null 2>&1 || true
  cp -r aflnet "$subject/aflnet"

  check_writable_or_die "$subject/chatafl"
  rm -rf "$subject/chatafl" >/dev/null 2>&1 || true
  cp -r ChatAFL "$subject/chatafl"
  
  check_writable_or_die "$subject/chatafl-cl1"
  rm -rf "$subject/chatafl-cl1" >/dev/null 2>&1 || true
  cp -r ChatAFL-CL1 "$subject/chatafl-cl1"
  
  check_writable_or_die "$subject/chatafl-cl2"
  rm -rf "$subject/chatafl-cl2" >/dev/null 2>&1 || true
  cp -r ChatAFL-CL2 "$subject/chatafl-cl2"
  
  check_writable_or_die "$subject/chatafl-enhanced"
  rm -rf "$subject/chatafl-enhanced" >/dev/null 2>&1 || true
  cp -r ChatAFL-Enhanced "$subject/chatafl-enhanced"
done;

# Build the docker images (optional)
if [[ "$SYNC_ONLY" -ne 1 ]]; then
  PFBENCH="$PWD/benchmark"
  cd $PFBENCH
  PFBENCH=$PFBENCH scripts/execution/profuzzbench_build_all.sh
else
  echo "[OK] Synced sources into benchmark/subjects (sync-only)."
fi