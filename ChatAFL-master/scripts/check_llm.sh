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

"$PREFLIGHT_BUILD/llm-preflight"
