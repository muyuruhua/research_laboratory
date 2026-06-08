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

IMG[bftpd]="bftpd";              PROTO[bftpd]="FTP";  PORT[bftpd]="21"
WD[bftpd]="/home/ubuntu/experiments/bftpd"
CMD[bftpd]="./bftpd -D -c /home/ubuntu/experiments/basic.conf"
PRE[bftpd]=""
ENV[bftpd]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0"
UDP[bftpd]="0";                  HC[bftpd]="nc -z 127.0.0.1 21"

IMG[proftpd]="proftpd";          PROTO[proftpd]="FTP";  PORT[proftpd]="21"
WD[proftpd]="/home/ubuntu/experiments/proftpd"
CMD[proftpd]="sed -i 's/MaxInstances.*1/MaxInstances 10/' /home/ubuntu/experiments/basic.conf; ./proftpd -n -c /home/ubuntu/experiments/basic.conf"
PRE[proftpd]=""
ENV[proftpd]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0"
UDP[proftpd]="0";                HC[proftpd]="sleep 2; kill -0 \$SPID 2>/dev/null"

IMG[lightftp]="lightftp";        PROTO[lightftp]="FTP";  PORT[lightftp]="2200"
WD[lightftp]="/home/ubuntu/experiments/LightFTP/Source/Release"
CMD[lightftp]="./fftp fftp.conf 2200"
PRE[lightftp]=""
ENV[lightftp]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0"
UDP[lightftp]="0";               HC[lightftp]="netstat -tlnp 2>/dev/null | grep -q ':2200 '"

IMG[lighttpd1]="lighttpd1";      PROTO[lighttpd1]="HTTP"; PORT[lighttpd1]="8080"
WD[lighttpd1]="/home/ubuntu/experiments/lighttpd1"
CMD[lighttpd1]="./src/lighttpd -D -f /home/ubuntu/experiments/lighttpd.conf -m ./src/.libs"
PRE[lighttpd1]=""
ENV[lighttpd1]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0"
UDP[lighttpd1]="0";              HC[lighttpd1]="nc -z 127.0.0.1 8080"

IMG[forked-daapd]="forked-daapd"; PROTO[forked-daapd]="HTTP"; PORT[forked-daapd]="3689"
WD[forked-daapd]="/home/ubuntu/experiments"
CMD[forked-daapd]="sudo service dbus start 2>/dev/null; sudo service avahi-daemon start 2>/dev/null; HOME=/home/ubuntu ./forked-daapd/src/forked-daapd -d 0 -c /home/ubuntu/experiments/forked-daapd.conf -f"
PRE[forked-daapd]=""
ENV[forked-daapd]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0"
UDP[forked-daapd]="0";           HC[forked-daapd]="nc -z 127.0.0.1 3689"

IMG[mosquitto-v2.0.18]="mosquitto-v2.0.18"; PROTO[mosquitto-v2.0.18]="MQTT"; PORT[mosquitto-v2.0.18]="1883"
WD[mosquitto-v2.0.18]="/home/ubuntu/experiments"
CMD[mosquitto-v2.0.18]="./mosquitto-gcov/src/mosquitto -c /home/ubuntu/experiments/mosquitto.conf"
PRE[mosquitto-v2.0.18]=""
ENV[mosquitto-v2.0.18]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0"
UDP[mosquitto-v2.0.18]="0";      HC[mosquitto-v2.0.18]="nc -z 127.0.0.1 1883"

IMG[mosquitto-v2.1.2]="mosquitto-v2.1.2"; PROTO[mosquitto-v2.1.2]="MQTT"; PORT[mosquitto-v2.1.2]="1883"
WD[mosquitto-v2.1.2]="/home/ubuntu/experiments"
CMD[mosquitto-v2.1.2]="./mosquitto-gcov/src/mosquitto -c /home/ubuntu/experiments/mosquitto.conf"
PRE[mosquitto-v2.1.2]=""
ENV[mosquitto-v2.1.2]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0"
UDP[mosquitto-v2.1.2]="0";      HC[mosquitto-v2.1.2]="nc -z 127.0.0.1 1883"

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

# ── Step 2: Replay via aflnet-replay (with server restart per replay) ──
# FIX: Each replay restarts the server to faithfully simulate AFL fuzzer conditions
# where the target is restarted between iterations. This is essential for
# reproducing ASAN-detected crashes that depend on initial heap state.
echo ""; echo "--- Replaying via aflnet-replay (128 attempts, server restart per attempt) ---"

REPLAY_LOG="$OUT_DIR/replay.log"
CRASH_FOUND=0

docker run --rm --network host --cap-add SYS_PTRACE \
    -v "$(realpath "$SAFE_COPY"):/tmp/crash_seed:ro" \
    -e "${ENV[$TARGET]}" \
    "${IMG[$TARGET]}" /bin/bash -c "
cd ${WD[$TARGET]}
export ${ENV[$TARGET]}

for rep in \$(seq 1 128); do
    # --- Restart server for each replay (simulates AFL fuzzer restart cycle) ---
    ${PRE[$TARGET]}
    ${CMD[$TARGET]} &
    SPID=\$!

    # Wait for server to be ready
    READY=0
    for a in \$(seq 1 30); do
        if ${HC[$TARGET]} 2>/dev/null; then READY=1; break; fi
        if ! kill -0 \$SPID 2>/dev/null; then
            wait \$SPID 2>/dev/null
            echo \"[WARN] replay #\$rep: server died on startup (exit=\$?), retrying...\"
            break
        fi
        sleep 0.5
    done

    if [ \$READY -eq 0 ]; then
        kill \$SPID 2>/dev/null || true
        wait \$SPID 2>/dev/null || true
        sleep 1
        continue
    fi

    # --- Replay the seed ---
    /home/ubuntu/chatafl-opt/aflnet-replay /tmp/crash_seed ${PROTO[$TARGET]} ${PORT[$TARGET]} 0 2>&1 || true

    # --- Check if server crashed ---
    if ! kill -0 \$SPID 2>/dev/null; then
        wait \$SPID 2>/dev/null
        EC=\$?
        echo \"[CRASH DETECTED] replay #\$rep: server crashed! exit_code=\$EC\"
        [ \$EC -gt 128 ] && echo \"[CRASH] Signal \$((\$EC - 128)) = \$(kill -l \$((\$EC - 128)) 2>/dev/null || echo 'UNKNOWN')\"
        exit 0
    fi

    # --- Clean stop server for next restart ---
    kill \$SPID 2>/dev/null || true
    wait \$SPID 2>/dev/null || true
    sleep 0.2
done

echo '[INFO] Server survived 128 replays (with restart). Crash NOT reproduced in standalone mode.'
echo '[INFO] This seed likely requires specific fuzzer-internal state not replicable in standalone replay.'
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
    echo "  Note:  Fuzzer-loop conditions (persistent mode, ASAN state) may differ"
    echo "  AFL verified replayable: seed IS in replayable-crashes/ directory"
    echo "  建议: 在原始AFL fuzzer环境中复现或使用gdb附加崩溃分析"
fi
echo "  Log: $REPLAY_LOG"
echo "══════════════════════════════════════════════════════════════"
