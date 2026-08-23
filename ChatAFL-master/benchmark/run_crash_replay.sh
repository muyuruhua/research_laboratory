#!/bin/bash
# ==============================================================================
# A2 (2026-08-23): Automatic P1 crash-replay sweep for a results-* batch.
#
# Reads vuln_triage_report.csv (run vuln_triage.py first if absent), takes
# every P1 row — both "P1" and "P1-no-replay" — and replays its seed N times
# (CHATAFL_REPLAY_N, default 20) against a freshly restarted containerized
# target, exactly the way replay_crash_universal.sh does, counting how many
# attempts reproduce a fatal-signal death.  Output: crash_replay_report.csv
# with one row per seed:
#
#   run, file, replays, crashes, rate, verdict
#   verdict = confirmed        (rate >= 10%)
#           = non-replayable   (0/N)
#           = low-rate         (0 < rate < 10%)
#           = sampled          (more P1 seeds than CHATAFL_REPLAY_MAX)
#           = error            (seed missing / target unknown)
#
# The report is merged by vuln_triage.py as reference rows on its next run.
# Observer-side only: touches nothing in the fuzzer.
#
# Usage:   ./run_crash_replay.sh <results-dir> [subject]
#          subject is inferred from the results-dir name (results-<subject>_*)
#          and may be given explicitly for nonstandard directory names.
# Env:     CHATAFL_REPLAY_N   replays per seed      (default 20)
#          CHATAFL_REPLAY_MAX max seeds swept       (default 50; excess marked
#                                                   'sampled', priority: race-
#                                                   tagged > asan sidecar > id)
# ==============================================================================
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./run_crash_replay.sh <results-dir> [subject]

Examples:
  ./run_crash_replay.sh results-bftpd_Aug-19_23-16-33
  ./run_crash_replay.sh /abs/path/results-proftpd_EFF2_Aug-22_20-40-00 proftpd

Env:
  CHATAFL_REPLAY_N     replays per P1 seed (default 20)
  CHATAFL_REPLAY_MAX   max seeds swept before marking 'sampled' (default 50)
EOF
}

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 1
fi

RAW_RESULTS_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -- resolve results dir (same candidate-path scheme as run_crash_analysis.sh)
RESULTS_DIR=""
for candidate in \
  "$RAW_RESULTS_DIR" \
  "$SCRIPT_DIR/$RAW_RESULTS_DIR" \
  "$SCRIPT_DIR/benchmark/$RAW_RESULTS_DIR" \
  "$SCRIPT_DIR/../benchmark/$RAW_RESULTS_DIR"; do
  if [[ -d "$candidate" ]]; then
    RESULTS_DIR="$(cd "$candidate" && pwd)"
    break
  fi
done
if [[ -z "$RESULTS_DIR" ]]; then
  echo "Error: results directory not found: $RAW_RESULTS_DIR" >&2
  exit 1
fi
RESULTS_BASENAME="$(basename "$RESULTS_DIR")"
if [[ "$RESULTS_BASENAME" != results-* ]]; then
  echo "Error: expected a results-* directory, got: $RESULTS_BASENAME" >&2
  exit 1
fi

# -- subject: explicit arg wins, else strip results- prefix and first _ boundary
SUBJECT="${2:-}"
if [[ -z "$SUBJECT" ]]; then
  SUBJECT="${RESULTS_BASENAME#results-}"
  SUBJECT="${SUBJECT%%_*}"
fi

REPLAY_N="${CHATAFL_REPLAY_N:-20}"
REPLAY_MAX="${CHATAFL_REPLAY_MAX:-50}"

TRIAGE_CSV="$RESULTS_DIR/vuln_triage_report.csv"
if [[ ! -f "$TRIAGE_CSV" ]]; then
  echo "[INFO] no vuln_triage_report.csv under $RESULTS_BASENAME — running vuln_triage.py"
  TRIAGE_PY=""
  for candidate in \
    "$SCRIPT_DIR/scripts/analysis/vuln_triage.py" \
    "$SCRIPT_DIR/benchmark/scripts/analysis/vuln_triage.py"; do
    if [[ -f "$candidate" ]]; then TRIAGE_PY="$candidate"; break; fi
  done
  [[ -n "$TRIAGE_PY" ]] || { echo "Error: cannot find vuln_triage.py" >&2; exit 1; }
  python3 "$TRIAGE_PY" "$RESULTS_DIR" >/dev/null
fi
[[ -f "$TRIAGE_CSV" ]] || { echo "Error: vuln_triage_report.csv missing" >&2; exit 1; }

# -- replay engine: reuse the universal tool's target DB for validation only
REPLAY_UNIVERSAL=""
for candidate in \
  "$SCRIPT_DIR/../replay_crash_universal.sh" \
  "$SCRIPT_DIR/../../replay_crash_universal.sh"; do
  if [[ -f "$candidate" ]]; then
    REPLAY_UNIVERSAL="$(cd "$(dirname "$candidate")" && pwd)/$(basename "$candidate")"
    break
  fi
done
[[ -n "$REPLAY_UNIVERSAL" ]] || {
  echo "Error: cannot find replay_crash_universal.sh (expected next to benchmark/)" >&2
  exit 1
}

# aflnet-replay binary: images don't ship /home/ubuntu/loopfuzz; mount the
# host LoopFuzz dir read-only exactly like the batch exec script does
# (-v <root>/LoopFuzz:/home/ubuntu/loopfuzz:ro) and use its aflnet-replay.
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOOPFUZZ_DIR=""
for candidate in "$PROJECT_ROOT/LoopFuzz" "$SCRIPT_DIR/../LoopFuzz"; do
  if [[ -x "$candidate/aflnet-replay" ]]; then
    LOOPFUZZ_DIR="$(cd "$candidate" && pwd)"
    break
  fi
done
[[ -n "$LOOPFUZZ_DIR" ]] || {
  echo "Error: aflnet-replay not found (expected $PROJECT_ROOT/LoopFuzz/aflnet-replay)" >&2
  exit 1
}

echo "[INFO] Results dir : $RESULTS_DIR"
echo "[INFO] Subject     : $SUBJECT"
echo "[INFO] Replays/seed: $REPLAY_N   max seeds: $REPLAY_MAX"

# -- collect P1 rows (quoted CSV is safe here: no embedded newlines in the report)
mapfile -t P1_ROWS < <(python3 - "$TRIAGE_CSV" <<'PYEOF'
import csv, sys
rows = csv.DictReader(open(sys.argv[1], newline=""))
for r in rows:
    if r.get("priority", "").startswith("P1") and r.get("run") != "SUMMARY":
        print("\t".join([r["run"], r["file"], r["race_tagged"], r["kind"]]))
PYEOF
)
TOTAL_P1="${#P1_ROWS[@]}"
echo "[INFO] P1 seeds found: $TOTAL_P1"
if [[ "$TOTAL_P1" -eq 0 ]]; then
  echo "[INFO] nothing to replay — writing empty report"
fi

# -- priority order: race-tagged first, then asan-evidence, then rest
sorted_rows() {
  printf '%s\n' "${P1_ROWS[@]}" 2>/dev/null | sort -t$'\t' \
    -k3,3r -k4,4 || true
}

OUT_CSV="$RESULTS_DIR/crash_replay_report.csv"
echo "run,file,replays,crashes,rate,verdict" > "$OUT_CSV"

SWEPT=0
while IFS=$'\t' read -r RUN REL_FILE RACE KIND; do
  [[ -z "$RUN" || -z "$REL_FILE" ]] && continue
  SEED="$RESULTS_DIR/$RUN/$REL_FILE"
  if [[ ! -f "$SEED" ]]; then
    echo "\"$RUN\",\"$REL_FILE\",0,0,0.000,error" >> "$OUT_CSV"
    echo "[WARN] seed missing: $SEED"
    continue
  fi
  if [[ "$SWEPT" -ge "$REPLAY_MAX" ]]; then
    echo "\"$RUN\",\"$REL_FILE\",0,0,0.000,sampled" >> "$OUT_CSV"
    continue
  fi
  SWEPT=$((SWEPT + 1))

  # Flatten the whole relative path: seed names carry colons/commas that
  # break docker -v and shell quoting, dirs add slashes.
  TAG="$(echo "$REL_FILE" | tr ':,=/,' '____')"
  RLOG_DIR="$RESULTS_DIR/crash_replay_logs"
  mkdir -p "$RLOG_DIR"
  RLOG="$RLOG_DIR/${RUN}_${TAG}.log"

  # Stage a flat, colon-free copy of the seed for the docker -v mount
  # (same trick replay_crash_universal.sh uses).
  STAGED_SEED="$RLOG_DIR/${RUN}_${TAG}.seed"
  cp "$SEED" "$STAGED_SEED"

  echo "[REPLAY] $RUN/$REL_FILE (${KIND}${RACE:+,race})"
  # One docker run per seed: inside, restart the target before each of the
  # N attempts (same per-attempt-restart semantics as replay_crash_universal
  # .sh, which is essential for ASAN crashes that depend on initial heap
  # state) and count fatal-signal deaths.
  CRASHES="$(docker run --rm --network host --cap-add SYS_PTRACE \
    -v "$STAGED_SEED:/tmp/crash_seed:ro" \
    -v "$LOOPFUZZ_DIR:/home/ubuntu/loopfuzz:ro" \
    "$SUBJECT" /bin/bash -c '
set +e
export ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0
cd /home/ubuntu/experiments 2>/dev/null || cd /
hits=0
for rep in $(seq 1 '"$REPLAY_N"'); do
  case "'"$SUBJECT"'" in
    kamailio)       cd /home/ubuntu/experiments/kamailio; killall kamailio 2>/dev/null; ./src/kamailio -f /home/ubuntu/experiments/kamailio-basic.cfg -L src/modules -Y runtime_dir -n 1 -D -E & ;;
    exim)           mkdir -p /var/lock /var/log /usr/exim/bin; killall exim 2>/dev/null; cd /home/ubuntu/experiments/exim; cp ./src/build-Linux-x86_64/exim /usr/exim/bin/exim 2>/dev/null; exim -bd -d -oX 25 -oP /var/lock/exim.pid & ;;
    live555)        killall testOnDemandRTSPServer 2>/dev/null; cd /home/ubuntu/experiments/live/testProgs; ./testOnDemandRTSPServer 8554 & ;;
    pure-ftpd)      cd /home/ubuntu/experiments/pure-ftpd; src/pure-ftpd -A & ;;
    bftpd)          cd /home/ubuntu/experiments/bftpd; ./bftpd -D -c /home/ubuntu/experiments/basic.conf & ;;
    proftpd)        cd /home/ubuntu/experiments/proftpd; sed -i "s/MaxInstances.*1/MaxInstances 10/" /home/ubuntu/experiments/basic.conf; ./proftpd -n -c /home/ubuntu/experiments/basic.conf & ;;
    lightftp)       cd /home/ubuntu/experiments/LightFTP/Source/Release; ./fftp fftp.conf 2200 & ;;
    lighttpd1)      cd /home/ubuntu/experiments/lighttpd1; ./src/lighttpd -D -f /home/ubuntu/experiments/lighttpd.conf -m ./src/.libs & ;;
    forked-daapd)   cd /home/ubuntu/experiments; HOME=/home/ubuntu ./forked-daapd/src/forked-daapd -d 0 -c /home/ubuntu/experiments/forked-daapd.conf -f & ;;
    mosquitto*)     cd /home/ubuntu/experiments; ./mosquitto-gcov/src/mosquitto -c /home/ubuntu/experiments/mosquitto.conf & ;;
    *)              echo "UNKNOWN_TARGET"; exit 3 ;;
  esac
  SPID=$!
  # per-target port + readiness probe (UDP targets use /dev/udp; proftpd
  # binds lazily so probe liveness instead; lightftp lacks nc-visible bind
  # timing so netstat).  $HC uses eval — keep it free of host-side quotes.
  # NOTE: this whole script block is single-quoted at the host level, so it
  # must not contain raw single quotes — hence double quotes inside.
  case "'"$SUBJECT"'" in
    kamailio)       PORT=5060; HC="echo >/dev/udp/127.0.0.1/5060" ;;
    exim)           PORT=25; HC="nc -z 127.0.0.1 25" ;;
    live555)        PORT=8554; HC="nc -z 127.0.0.1 8554" ;;
    pure-ftpd)      PORT=21; HC="nc -z 127.0.0.1 21" ;;
    bftpd)          PORT=21; HC="nc -z 127.0.0.1 21" ;;
    proftpd)        PORT=21; HC="sleep 2; kill -0 \$SPID" ;;
    lightftp)       PORT=2200; HC="netstat -tln 2>/dev/null | grep -q :2200" ;;
    lighttpd1)      PORT=8080; HC="nc -z 127.0.0.1 8080" ;;
    forked-daapd)   PORT=3689; HC="nc -z 127.0.0.1 3689" ;;
    mosquitto*)     PORT=1883; HC="nc -z 127.0.0.1 1883" ;;
  esac
  READY=0
  for a in $(seq 1 30); do
    if eval "$HC" 2>/dev/null; then READY=1; break; fi
    if ! kill -0 $SPID 2>/dev/null; then break; fi
    sleep 0.5
  done
  if [ $READY -eq 0 ]; then
    kill $SPID 2>/dev/null; wait $SPID 2>/dev/null
    continue
  fi
  case "'"$SUBJECT"'" in
    kamailio)     PROTO=SIP ;;
    exim)         PROTO=SMTP ;;
    live555)      PROTO=RTSP ;;
    pure-ftpd|bftpd|proftpd|lightftp) PROTO=FTP ;;
    lighttpd1|forked-daapd) PROTO=HTTP ;;
    mosquitto*)   PROTO=MQTT ;;
  esac
  /home/ubuntu/loopfuzz/aflnet-replay /tmp/crash_seed $PROTO $PORT 0 >/dev/null 2>&1
  if ! kill -0 $SPID 2>/dev/null; then
    wait $SPID 2>/dev/null
    EC=$?
    if [ $EC -gt 128 ]; then
      hits=$((hits+1))
      echo "CRASH rep=$rep exit=$EC"
    fi
  fi
  kill $SPID 2>/dev/null; wait $SPID 2>/dev/null
done
echo "HITS=$hits"
' 2>&1 | tee "$RLOG" | grep -c '^CRASH ' || true)"

  CRASHES="${CRASHES:-0}"
  if [[ "$CRASHES" -eq 0 ]] && grep -q "UNKNOWN_TARGET" "$RLOG" 2>/dev/null; then
    echo "\"$RUN\",\"$REL_FILE\",0,0,0.000,error" >> "$OUT_CSV"
    continue
  fi
  if [[ "$CRASHES" -eq 0 ]] && ! grep -q "HITS=" "$RLOG" 2>/dev/null; then
    echo "\"$RUN\",\"$REL_FILE\",0,0,0.000,error" >> "$OUT_CSV"
    continue
  fi

  RATE="$(python3 -c "print('%.3f' % ($CRASHES / $REPLAY_N))")"
  if [[ "$CRASHES" -eq 0 ]]; then
    VERDICT="non-replayable"
  elif python3 -c "import sys; sys.exit(0 if $CRASHES * 10 >= $REPLAY_N else 1)"; then
    VERDICT="confirmed"
  else
    VERDICT="low-rate"
  fi
  echo "\"$RUN\",\"$REL_FILE\",$REPLAY_N,$CRASHES,$RATE,$VERDICT" >> "$OUT_CSV"
  echo "         -> $CRASHES/$REPLAY_N ($RATE) $VERDICT"
done < <(sorted_rows)

echo ""
echo "[INFO] report written: $OUT_CSV"
python3 - "$OUT_CSV" <<'PYEOF'
import csv, sys
rows = [r for r in csv.DictReader(open(sys.argv[1], newline=""))
        if r.get("verdict")]
vc = {}
for r in rows:
    vc[r["verdict"]] = vc.get(r["verdict"], 0) + 1
print("[INFO] verdicts: " + (" ".join("%s=%d" % kv for kv in sorted(vc.items()))
                             if vc else "(none)"))
PYEOF
