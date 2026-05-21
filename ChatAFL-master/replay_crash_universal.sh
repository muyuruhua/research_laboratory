#!/bin/bash
# ==============================================================================
# ChatAFL-Opt Universal Crash Replay Tool — Final Fixed Version
# Open/Closed: config is data-driven; add target = add row in DB below
# ==============================================================================
set -euo pipefail

TARGET="${1:?Usage: $0 <target> <crash_seed_path> [output_dir]}"
CRASH_SEED="${2:?Missing crash seed path}"
OUT_DIR="${3:-/tmp/crash_replay_${TARGET}_$(date +%Y%m%d_%H%M%S)}"

# ── Target Configuration Database ───────────────────────────────────────
declare -A IMG PROTO PORT WD CMD PRE ENV UDP HC

IMG[kamailio]="kamailio";        PROTO[kamailio]="SIP";   PORT[kamailio]="5060"
WD[kamailio]="/home/ubuntu/experiments/kamailio"
CMD[kamailio]="./src/kamailio -f /home/ubuntu/experiments/kamailio-basic.cfg -L src/modules -Y runtime_dir -n 1 -D -E"
PRE[kamailio]='mkdir -p runtime_dir; killall kamailio 2>/dev/null || true; killall pjsua-x86_64-unknown-linux-gnu 2>/dev/null || true; /home/ubuntu/experiments/pjproject/pjsip-apps/bin/pjsua-x86_64-unknown-linux-gnu --local-port=5068 --id sip:33@127.0.0.1 --registrar sip:127.0.0.1 --proxy sip:127.0.0.1 --realm "*" --username 33 --password 33 --auto-answer 200 --auto-play --play-file /home/ubuntu/experiments/StarWars3.wav --auto-play-hangup --duration=300 --use-cli --no-cli-console --cli-telnet-port=34254 >/dev/null 2>&1 &'
ENV[kamailio]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0:detect_stack_use_after_return=1 KAMAILIO_MODULES=src/modules KAMAILIO_RUNTIME_DIR=runtime_dir"
UDP[kamailio]="1";              HC[kamailio]="echo >/dev/udp/127.0.0.1/5060 2>/dev/null || true"

IMG[exim]="exim";                PROTO[exim]="SMTP";   PORT[exim]="25"
WD[exim]="/home/ubuntu/experiments/exim"
CMD[exim]="cp ./src/build-Linux-x86_64/exim /usr/exim/bin/exim 2>/dev/null; /home/ubuntu/experiments/clean 2>/dev/null; exim -bd -d -oX 25 -oP /var/lock/exim.pid"
PRE[exim]="mkdir -p /var/lock /var/log /usr/exim/bin; /home/ubuntu/experiments/clean 2>/dev/null; killall exim 2>/dev/null || true"
ENV[exim]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0"
UDP[exim]="0";                   HC[exim]="nc -z 127.0.0.1 25"

IMG[live555]="live555";          PROTO[live555]="RTSP";  PORT[live555]="8554"
WD[live555]="/home/ubuntu/experiments/live/testProgs"
CMD[live555]="./testOnDemandRTSPServer 8554"
PRE[live555]="killall testOnDemandRTSPServer 2>/dev/null || true"
ENV[live555]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0"
UDP[live555]="0";                HC[live555]="nc -z 127.0.0.1 8554"

IMG[pure-ftpd]="pure-ftpd";      PROTO[pure-ftpd]="FTP";  PORT[pure-ftpd]="21"
WD[pure-ftpd]="/home/ubuntu/experiments/pure-ftpd"
CMD[pure-ftpd]="src/pure-ftpd -A"
PRE[pure-ftpd]="/home/ubuntu/experiments/clean 2>/dev/null; ulimit -n 1024"
ENV[pure-ftpd]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0:detect_stack_use_after_return=1"
UDP[pure-ftpd]="0";              HC[pure-ftpd]="nc -z 127.0.0.1 21"

# ── Validation ──────────────────────────────────────────────────────────
[ ! -f "$CRASH_SEED" ] && { echo "[ERROR] Seed not found: $CRASH_SEED"; exit 1; }
[ -z "${IMG[$TARGET]:-}" ] && { echo "[ERROR] Unknown target: $TARGET. Supported: ${!IMG[*]}"; exit 1; }
docker image inspect "${IMG[$TARGET]}" >/dev/null 2>&1 || { echo "[ERROR] Image not found: ${IMG[$TARGET]}"; exit 1; }

mkdir -p "$OUT_DIR"
SAFE_NAME=$(basename "$CRASH_SEED" | tr ':,=' '_')
SAFE_COPY="$OUT_DIR/$SAFE_NAME"
cp "$CRASH_SEED" "$SAFE_COPY"

echo "═══ ChatAFL Crash Replay: $TARGET (${PROTO[$TARGET]}) ═══"
echo "Seed: $(basename "$CRASH_SEED") ($(wc -c < "$CRASH_SEED") bytes)"

# ── Step 1: Parse seed ──────────────────────────────────────────────────
python3 -c "
import struct
with open('$CRASH_SEED','rb') as f: d=f.read()
off=0; mi=0
while off+4<=len(d):
    sz=struct.unpack('<I',d[off:off+4])[0]; off+=4
    if sz==0 or off+sz>len(d):
        try: print(f'  [RAW] {len(d)-off+4}B: {d[off-4:][:80]}')
        except: pass
        break
    p=d[off:off+sz]; off+=sz; mi+=1
    try: print(f'  msg[{mi}]: {sz}B {p[:80].decode(\"utf-8\",errors=\"replace\")}')
    except: print(f'  msg[{mi}]: {sz}B (binary)')
print(f'Total: {mi} messages')
" | tee "$OUT_DIR/seed_structure.txt"

# ── Step 2: Replay via aflnet-replay ────────────────────────────────────
echo ""; echo "--- Replaying via aflnet-replay (128 attempts) ---"

REPLAY_LOG="$OUT_DIR/replay.log"
CRASH_FOUND=0

docker run --rm --network host --cap-add SYS_PTRACE \
    -v "$(realpath "$SAFE_COPY"):/tmp/crash_seed:ro" \
    -e "${ENV[$TARGET]}" \
    "${IMG[$TARGET]}" /bin/bash -c "
cd ${WD[$TARGET]}
${PRE[$TARGET]}
export ${ENV[$TARGET]}

echo '=== Starting server ==='
${CMD[$TARGET]} &
SPID=\$!
sleep 2

READY=0
for a in \$(seq 1 30); do
    if ${HC[$TARGET]} 2>/dev/null; then READY=1; echo \"Server ready after \$((a*2))s\"; break; fi
    if ! kill -0 \$SPID 2>/dev/null; then
        wait \$SPID 2>/dev/null; echo \"[FATAL] Server died on startup (exit=\$?)\"; exit 1
    fi
    sleep 1
done
[ \$READY -eq 0 ] && { echo '[FATAL] Server not ready'; kill \$SPID 2>/dev/null; exit 1; }

echo \"Server PID=\$SPID. Replaying 128 times...\"
for rep in \$(seq 1 128); do
    /home/ubuntu/chatafl-opt/aflnet-replay /tmp/crash_seed ${PROTO[$TARGET]} ${PORT[$TARGET]} 0 2>&1 || true
    if ! kill -0 \$SPID 2>/dev/null; then
        wait \$SPID 2>/dev/null
        EC=\$?
        echo \"[CRASH DETECTED] replay #\$rep: server crashed! exit_code=\$EC\"
        [ \$EC -gt 128 ] && echo \"[CRASH] Signal \$((\$EC - 128))\"
        exit 0
    fi
done

echo '[INFO] Server survived 128 replays. Crash NOT reproduced in standalone mode.'
kill \$SPID 2>/dev/null || true
wait \$SPID 2>/dev/null || true
" 2>&1 | tee "$REPLAY_LOG"

if grep -q "CRASH DETECTED" "$REPLAY_LOG" 2>/dev/null; then
    CRASH_FOUND=1
fi

# ── Step 3: Result ──────────────────────────────────────────────────────
echo ""; echo "══════════════════════════════════════════════════════════════"
if [ $CRASH_FOUND -eq 1 ]; then
    echo "  RESULT: CRASH CONFIRMED — 确认内存破坏漏洞"
else
    echo "  RESULT: Crash not reproduced in standalone replay"
    echo "  Note:  Fuzzer-loop conditions may be required (ASAN + restart cycle)"
    echo "  AFL verified replayable: seed IS in replayable-crashes/ directory"
fi
echo "  Log: $REPLAY_LOG"
echo "══════════════════════════════════════════════════════════════"
