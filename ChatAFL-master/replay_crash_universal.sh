#!/bin/bash
# ==============================================================================
# ChatAFL-Opt Universal Crash Replay Tool
# ==============================================================================
# 基于 AFLNet 种子格式 (4-byte size prefix + message data) 精确重放 crash
#
# 原理:
#   ChatAFL-Opt 种子文件格式: 每个请求由 4字节(uint32)长度前缀 + 消息体组成
#   例如: [00 00 00 05][48 45 4C 4C 4F] 表示 5 字节消息 "HELLO"
#   aflnet-replay 读取这个格式,逐一发送每个请求到服务器,并收集响应
#
# 用法:
#   ./replay_crash_universal.sh <target> <crash_seed_path>
#   ./replay_crash_universal.sh bftpd /tmp/crash_seed.bin
#   ./replay_crash_universal.sh mosquitto-v2.0.18 /tmp/crash_seed.bin
#
# Crash 复现方法:
#   1. aflnet-replay: 发送种子中的请求序列,观察服务器是否崩溃
#   2. afl-showmap: 使用 AFL fork-server 模式重放(捕获 ASAN-only crash)
#   3. docker exec + seed: 直接进入容器用种子启动服务器
# ==============================================================================

set -euo pipefail

TARGET="${1:?Usage: $0 <target> <crash_seed_path> [output_dir]}"
CRASH_SEED="${2:?Missing crash seed path}"
OUT_DIR="${3:-/tmp/crash_replay_${TARGET}_$(date +%Y%m%d_%H%M%S)}"

# ── Target Configuration Database ──────────────────────────────────────
declare -A TARGET_IMAGE TARGET_PROTO TARGET_PORT TARGET_SERVER_CMD TARGET_WORKDIR TARGET_CLEAN_CMD

TARGET_IMAGE[bftpd]="bftpd"
TARGET_PROTO[bftpd]="FTP"
TARGET_PORT[bftpd]="21"
TARGET_SERVER_CMD[bftpd]="./bftpd -D -c /home/ubuntu/experiments/basic.conf"
TARGET_WORKDIR[bftpd]="/home/ubuntu/experiments/bftpd"

TARGET_IMAGE[lightftp]="lightftp"
TARGET_PROTO[lightftp]="FTP"
TARGET_PORT[lightftp]="2200"
TARGET_SERVER_CMD[lightftp]="./fftp -c /home/ubuntu/experiments/fftp.conf"
TARGET_WORKDIR[lightftp]="/home/ubuntu/experiments/lightftp"

TARGET_IMAGE[proftpd]="proftpd"
TARGET_PROTO[proftpd]="FTP"
TARGET_PORT[proftpd]="21"
TARGET_SERVER_CMD[proftpd]="./proftpd -n -c /home/ubuntu/experiments/basic.conf"
TARGET_WORKDIR[proftpd]="/home/ubuntu/experiments/proftpd"

TARGET_IMAGE[pure-ftpd]="pure-ftpd"
TARGET_PROTO[pure-ftpd]="FTP"
TARGET_PORT[pure-ftpd]="21"
TARGET_SERVER_CMD[pure-ftpd]="./pure-ftpd -c /home/ubuntu/experiments/pure-ftpd.conf"
TARGET_WORKDIR[pure-ftpd]="/home/ubuntu/experiments/pure-ftpd"

TARGET_IMAGE[exim]="exim"
TARGET_PROTO[exim]="SMTP"
TARGET_PORT[exim]="25"
TARGET_SERVER_CMD[exim]="./exim -bd -d -C /home/ubuntu/experiments/exim.conf"
TARGET_WORKDIR[exim]="/home/ubuntu/experiments/exim"

TARGET_IMAGE[live555]="live555"
TARGET_PROTO[live555]="RTSP"
TARGET_PORT[live555]="8554"
TARGET_SERVER_CMD[live555]="./live555ProxyServer"
TARGET_WORKDIR[live555]="/home/ubuntu/experiments/live555"

TARGET_IMAGE[kamailio]="kamailio"
TARGET_PROTO[kamailio]="SIP"
TARGET_PORT[kamailio]="5060"
TARGET_SERVER_CMD[kamailio]="./kamailio -f /home/ubuntu/experiments/kamailio.cfg"
TARGET_WORKDIR[kamailio]="/home/ubuntu/experiments/kamailio"

TARGET_IMAGE[forked-daapd]="forked-daapd"
TARGET_PROTO[forked-daapd]="DAAP"
TARGET_PORT[forked-daapd]="3689"
TARGET_SERVER_CMD[forked-daapd]="./forked-daapd -f -c /home/ubuntu/experiments/forked-daapd.conf"
TARGET_WORKDIR[forked-daapd]="/home/ubuntu/experiments/forked-daapd"

TARGET_IMAGE[lighttpd1]="lighttpd1"
TARGET_PROTO[lighttpd1]="HTTP"
TARGET_PORT[lighttpd1]="80"
TARGET_SERVER_CMD[lighttpd1]="./lighttpd -D -f /home/ubuntu/experiments/lighttpd.conf"
TARGET_WORKDIR[lighttpd1]="/home/ubuntu/experiments/lighttpd"

TARGET_IMAGE[mosquitto-v2.0.18]="mosquitto-v2.0.18"
TARGET_PROTO[mosquitto-v2.0.18]="MQTT"
TARGET_PORT[mosquitto-v2.0.18]="1883"
TARGET_SERVER_CMD[mosquitto-v2.0.18]="./src/mosquitto -c /home/ubuntu/experiments/mosquitto.conf"
TARGET_WORKDIR[mosquitto-v2.0.18]="/home/ubuntu/experiments/mosquitto"

TARGET_IMAGE[mosquitto-v2.1.2]="mosquitto-v2.1.2"
TARGET_PROTO[mosquitto-v2.1.2]="MQTT"
TARGET_PORT[mosquitto-v2.1.2]="1883"
TARGET_SERVER_CMD[mosquitto-v2.1.2]="./src/mosquitto -c /home/ubuntu/experiments/mosquitto.conf"
TARGET_WORKDIR[mosquitto-v2.1.2]="/home/ubuntu/experiments/mosquitto"

# ── Validation ──────────────────────────────────────────────────────────
if [ ! -f "$CRASH_SEED" ]; then
    echo "[ERROR] Crash seed not found: $CRASH_SEED"
    exit 1
fi

if [ -z "${TARGET_IMAGE[$TARGET]:-}" ]; then
    echo "[ERROR] Unknown target: $TARGET"
    echo "Supported: ${!TARGET_IMAGE[*]}"
    exit 1
fi

IMAGE="${TARGET_IMAGE[$TARGET]}"
PROTO="${TARGET_PROTO[$TARGET]}"
PORT="${TARGET_PORT[$TARGET]}"
SERVER_CMD="${TARGET_SERVER_CMD[$TARGET]}"
WORKDIR="${TARGET_WORKDIR[$TARGET]}"

# Check image exists
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[ERROR] Docker image '$IMAGE' not found. Build it first."
    exit 1
fi

mkdir -p "$OUT_DIR"
CRASH_BASENAME=$(basename "$CRASH_SEED")
CRASH_COPY="$OUT_DIR/${CRASH_BASENAME}"

cp "$CRASH_SEED" "$CRASH_COPY"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ChatAFL-Opt Universal Crash Replay                         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Target   : $TARGET"
echo "║  Protocol : $PROTO"
echo "║  Port     : $PORT"
echo "║  Image    : $IMAGE"
echo "║  Seed     : $CRASH_BASENAME ($(wc -c < "$CRASH_SEED") bytes)"
echo "║  Output   : $OUT_DIR"
echo "╚══════════════════════════════════════════════════════════════╝"

# ── Step 1: Parse seed structure (AFLNet format) ────────────────────────
echo ""
echo "━━━ Step 1: Seed Structure Analysis ━━━"
python3 -c "
import struct, sys
with open('$CRASH_SEED', 'rb') as f:
    data = f.read()
offset = 0
msg_idx = 0
while offset + 4 <= len(data):
    size = struct.unpack('<I', data[offset:offset+4])[0]
    offset += 4
    if offset + size > len(data):
        print(f'  [WARN] msg {msg_idx}: truncated (need {size}, have {len(data)-offset})')
        break
    payload = data[offset:offset+size]
    preview = repr(payload[:80])
    print(f'  msg[{msg_idx}]: size={size:5d}  payload={preview}')
    offset += size
    msg_idx += 1
print(f'  Total messages: {msg_idx}')
" 2>&1 | tee "$OUT_DIR/seed_structure.txt"

# ── Step 2: Method 1 - aflnet-replay (直接重放) ─────────────────────────
echo ""
echo "━━━ Step 2: Method 1 - aflnet-replay (sequential replay) ━━━"

REPLAY_OUT="$OUT_DIR/replay_method1.log"
docker run --rm \
    --network host \
    -v "$(realpath "$CRASH_COPY"):/tmp/crash_seed:ro" \
    -e "ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0" \
    "$IMAGE" /bin/bash -c "
cd $WORKDIR

echo '=== Starting server ==='
$SERVER_CMD &
SERVER_PID=\$!
sleep 1

# Verify server is running
if ! kill -0 \$SERVER_PID 2>/dev/null; then
    echo '[FATAL] Server failed to start!'
    exit 1
fi
echo 'Server PID: ' \$SERVER_PID

echo '=== Replaying crash seed ==='
for rep in \$(seq 1 128); do
    /home/ubuntu/chatafl-opt/aflnet-replay /tmp/crash_seed $PROTO $PORT 0 2>&1 || true

    if ! kill -0 \$SERVER_PID 2>/dev/null; then
        wait \$SERVER_PID 2>/dev/null || true
        EC=\$?
        echo \"[CRASH DETECTED] replay #\$rep: server crashed! exit_code=\$EC\"
        exit 0
    fi
done

echo '[INFO] Server survived 128 replays. Crash NOT reproduced via aflnet-replay.'
kill \$SERVER_PID 2>/dev/null || true
wait \$SERVER_PID 2>/dev/null || true
" 2>&1 | tee "$REPLAY_OUT"

# ── Step 3: Method 2 - afl-showmap (fork-server 模式) ────────────────────
echo ""
echo "━━━ Step 3: Method 2 - afl-showmap (fork-server mode) ━━━"

SHOWMAP_OUT="$OUT_DIR/replay_method2_showmap.log"
docker run --rm \
    --network host \
    -v "$(realpath "$CRASH_COPY"):/tmp/crash_seed:ro" \
    -e "ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0" \
    "$IMAGE" /bin/bash -c "
cd $WORKDIR
export AFL_MAP_SIZE=65536

echo '=== Replaying via afl-showmap (fork-server path) ==='
/home/ubuntu/chatafl-opt/afl-showmap -o /tmp/showmap_out -t 5000 \
    -N tcp://127.0.0.1/$PORT \
    -- $SERVER_CMD < /tmp/crash_seed 2>&1 || true
EC=\$?

echo \"afl-showmap exit code: \$EC\"
if [ \$EC -gt 128 ]; then
    SIG=\$((EC - 128))
    echo \"[CRASH] Signal \$SIG detected!\"
fi

# Check ASAN output
if ls /tmp/asan.* 2>/dev/null; then
    echo '=== ASAN Report ==='
    cat /tmp/asan.* | head -60
fi
" 2>&1 | tee "$SHOWMAP_OUT"

# ── Step 4: Method 3 - Interactive (进入容器手动调试) ────────────────────
echo ""
echo "━━━ Step 4: Summary ━━━"
echo "Results saved to: $OUT_DIR"
echo ""
echo "To debug interactively inside the container:"
echo "  docker run --rm -it --network host \\"
echo "    -v $(realpath "$CRASH_COPY"):/tmp/crash_seed:ro \\"
echo "    -e \"ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0\" \\"
echo "    $IMAGE /bin/bash"
echo ""
echo "Then inside the container:"
echo "  cd $WORKDIR"
echo "  # Start server manually with GDB:"
echo "  gdb --args $SERVER_CMD"
echo "  # In another terminal, replay:"
echo "  /home/ubuntu/chatafl-opt/aflnet-replay /tmp/crash_seed $PROTO $PORT 0"
echo ""
echo "━━━ Done ━━━"
