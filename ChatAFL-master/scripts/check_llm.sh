#!/usr/bin/env bash
# Build and exercise the real LoopFuzz client with the caller's environment.
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PREFLIGHT_BUILD="$(mktemp -d "${TMPDIR:-/tmp}/loopfuzz-llm-preflight.XXXXXXXX")"
trap 'rm -rf -- "$PREFLIGHT_BUILD"' EXIT

"${CC:-gcc}" -O1 -g -ffunction-sections -fdata-sections -Wno-unused-result \
  -I "$PROJECT_ROOT/LoopFuzz" \
  "$PROJECT_ROOT/LoopFuzz/chat-llm.c" \
  "$PROJECT_ROOT/LoopFuzz/llm_preflight.c" \
  -o "$PREFLIGHT_BUILD/llm-preflight" \
  -Wl,--gc-sections -lcurl -ljson-c -lpcre2-8 -lpthread -lm

# The gateway can transiently time out on a single 30 s probe (observed
# 2026-11-22: one arm's preflight failed while twelve launched in the same
# minute all passed). The probe itself is a cheap one-shot completion, so
# retry it a bounded number of times with a short backoff before declaring
# the environment broken; a genuinely down gateway still fails in ~2 min.
PREFLIGHT_ATTEMPTS="${CHATAFL_LLM_PREFLIGHT_ATTEMPTS:-3}"
PREFLIGHT_BACKOFF_SEC="${CHATAFL_LLM_PREFLIGHT_BACKOFF_SEC:-5}"
for _attempt in $(seq 1 "$PREFLIGHT_ATTEMPTS"); do
  if "$PREFLIGHT_BUILD/llm-preflight"; then
    exit 0
  fi
  echo "[LLM preflight] attempt $_attempt/$_attempt failed" >&2
  if [[ "$_attempt" -lt "$PREFLIGHT_ATTEMPTS" ]]; then
    sleep "$PREFLIGHT_BACKOFF_SEC"
  fi
done
exit 1
