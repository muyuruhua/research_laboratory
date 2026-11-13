#!/bin/bash
# Cross-host environment verification: compare this machine against a manifest.
# Usage: bash verify_cross_host.sh <path-to-cross_host_manifest.json>
# Run from ChatAFL-master root. Exit 0 = all match, exit 1 = mismatches.

set -euo pipefail
MANIFEST="${1:?Usage: $0 <cross_host_manifest.json>}"
cd "$(dirname "$0")"
PASS=0; FAIL=0; WARN=0

check() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "  ✓ $desc"
    PASS=$((PASS+1))
  else
    echo "  ✗ $desc: expected=${expected:0:16}… actual=${actual:0:16}…"
    FAIL=$((FAIL+1))
  fi
}

warn() { echo "  ⚠ $1"; WARN=$((WARN+1)); }

echo "═══ Cross-Host Environment Verification ═══"
echo "Manifest: $MANIFEST"
echo ""

# ── 1. Git commit ──
echo "── Git Commit ──"
EXPECTED_COMMIT=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['git_commit'])" 2>/dev/null || echo "")
ACTUAL_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
if [[ -n "$EXPECTED_COMMIT" ]]; then
  check "git commit" "$EXPECTED_COMMIT" "$ACTUAL_COMMIT"
else
  warn "manifest has no git_commit"
fi
echo ""

# ── 2. Docker images ──
echo "── Docker Images ──"
for TARGET in bftpd exim kamailio live555; do
  EXPECTED_ID=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['images'].get('$TARGET',''))" 2>/dev/null)
  ACTUAL_ID=$(docker inspect --format '{{.Id}}' "${TARGET}:latest" 2>/dev/null || echo "missing")
  if [[ "$ACTUAL_ID" == "missing" ]]; then
    echo "  ✗ ${TARGET}:latest — image not found (build from benchmark/subjects/ Dockerfile)"
    FAIL=$((FAIL+1))
  elif [[ -n "$EXPECTED_ID" && "$EXPECTED_ID" != "$ACTUAL_ID" ]]; then
    echo "  ✗ ${TARGET}:latest — digest mismatch"
    echo "    expected: $EXPECTED_ID"
    echo "    actual:   $ACTUAL_ID"
    FAIL=$((FAIL+1))
  else
    echo "  ✓ ${TARGET}:latest ($ACTUAL_ID)"
    PASS=$((PASS+1))
  fi
done
echo ""

# ── 3. Target binaries (inside containers) ──
echo "── Target Binaries ──"
while IFS='|' read -r KEY EXPECTED_SHA; do
  TARGET="${KEY%%:*}"; BIN="${KEY##*:}"
  CID=$(docker run -d "${TARGET}:latest" sleep 15 2>/dev/null) || { warn "cannot start $TARGET"; continue; }
  ACTUAL_SHA=$(docker exec "$CID" sha256sum "/home/ubuntu/experiments/${TARGET}-gcov/${BIN}" 2>/dev/null | awk '{print $1}' || echo "not-found")
  docker stop "$CID" >/dev/null 2>&1
  if [[ "$ACTUAL_SHA" == "not-found" ]]; then
    # try finding it
    FOUND=$(docker run --rm "${TARGET}:latest" find /home/ubuntu -maxdepth 4 -name "$BIN" -type f 2>/dev/null | head -1)
    if [[ -n "$FOUND" ]]; then
      ACTUAL_SHA=$(docker run --rm "${TARGET}:latest" sha256sum "$FOUND" 2>/dev/null | awk '{print $1}')
    fi
  fi
  check "$KEY" "$EXPECTED_SHA" "$ACTUAL_SHA"
done < <(python3 -c "
import json
m = json.load(open('$MANIFEST'))
for k, v in m.get('target_binaries', {}).items():
    print(f'{k}|{v}')
" 2>/dev/null)
echo ""

# ── 4. Seed corpora ──
echo "── Seed Corpora ──"
while IFS='|' read -r DIR EXPECTED_SHA EXPECTED_COUNT; do
  FULL="benchmark/subjects/$DIR"
  if [[ ! -d "$FULL" ]]; then
    echo "  ✗ $DIR — directory not found"
    FAIL=$((FAIL+1)); continue
  fi
  ACTUAL_COUNT=$(ls "$FULL" | wc -l)
  ACTUAL_SHA=$(python3 -c "
import hashlib, os
d = '$FULL'
h = hashlib.sha256()
for f in sorted(os.listdir(d)):
    h.update(open(os.path.join(d,f),'rb').read())
print(h.hexdigest())
" 2>/dev/null)
  if [[ "$ACTUAL_SHA" == "$EXPECTED_SHA" && "$ACTUAL_COUNT" == "$EXPECTED_COUNT" ]]; then
    echo "  ✓ $DIR ($ACTUAL_COUNT seeds)"
    PASS=$((PASS+1))
  else
    echo "  ✗ $DIR — hash or count mismatch (expected $EXPECTED_COUNT, got $ACTUAL_COUNT)"
    FAIL=$((FAIL+1))
  fi
done < <(python3 -c "
import json
m = json.load(open('$MANIFEST'))
for k, v in m.get('seeds', {}).items():
    print(f'{k}|{v[\"sha256\"]}|{v[\"count\"]}')
" 2>/dev/null)
echo ""

# ── 5. Protocol dictionaries ──
echo "── Protocol Dictionaries ──"
while IFS='|' read -r DICT EXPECTED_SHA; do
  FULL="benchmark/subjects/$DICT"
  if [[ ! -f "$FULL" ]]; then
    echo "  ✗ $DICT — not found"; FAIL=$((FAIL+1)); continue
  fi
  ACTUAL_SHA=$(sha256sum "$FULL" | awk '{print $1}')
  check "$DICT" "$EXPECTED_SHA" "$ACTUAL_SHA"
done < <(python3 -c "
import json
m = json.load(open('$MANIFEST'))
for k, v in m.get('dicts', {}).items():
    print(f'{k}|{v}')
" 2>/dev/null)
echo ""

# ── 6. Fuzzer source ──
echo "── Fuzzer Source ──"
EXPECTED_SRC=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['fuzzer_source']['sha256'])" 2>/dev/null)
EXPECTED_N=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['fuzzer_source']['files'])" 2>/dev/null)
ACTUAL_SHA=$(python3 -c "
import hashlib, glob
files = sorted(glob.glob('LoopFuzz/*.c') + glob.glob('LoopFuzz/*.h') + ['LoopFuzz/Makefile'])
h = hashlib.sha256()
for f in files: h.update(open(f,'rb').read())
print(h.hexdigest())
" 2>/dev/null)
ACTUAL_N=$(ls LoopFuzz/*.c LoopFuzz/*.h LoopFuzz/Makefile 2>/dev/null | wc -l)
check "LoopFuzz source ($ACTUAL_N files)" "$EXPECTED_SRC" "$ACTUAL_SHA"
echo ""

# ── 7. Runner scripts ──
echo "── Runner Scripts ──"
for SCRIPT in run_ablation.sh benchmark/scripts/execution/profuzzbench_exec_common_dev.sh; do
  EXPECTED_SHA=$(python3 -c "import json; print(json.load(open('$MANIFEST')).get('$SCRIPT',''))" 2>/dev/null)
  if [[ -f "$SCRIPT" && -n "$EXPECTED_SHA" ]]; then
    ACTUAL_SHA=$(sha256sum "$SCRIPT" | awk '{print $1}')
    check "$SCRIPT" "$EXPECTED_SHA" "$ACTUAL_SHA"
  fi
done
echo ""

# ── Summary ──
echo "═══ Summary: $PASS PASS / $FAIL FAIL / $WARN WARN ═══"
if [[ $FAIL -gt 0 ]]; then
  echo "❌ Environment mismatch — fix the failures above before running experiments."
  echo "   Common fixes:"
  echo "   • Image mismatch: rebuild with 'cd benchmark/subjects/<PROTO>/<TARGET> && docker build -t <target>:latest .'"
  echo "   • Source mismatch: 'git checkout <commit>' and verify working tree is clean"
  echo "   • Seeds mismatch: verify benchmark/subjects/ directory is complete"
  exit 1
else
  echo "✅ Environment verified — safe to run experiments on this host."
  exit 0
fi
