#!/bin/bash
# ==============================================================================
# ChatAFL-Opt Container-Based Seed Verification Framework
# ==============================================================================
# 针对触发漏洞的种子启动独立容器进行精确验证
#
# 设计原则:
#   1. 每个验证在独立容器中运行 (隔离性)
#   2. 使用与原fuzzing相同的环境 (可复现性)
#   3. 收集完整的请求/响应/ASAN日志 (取证完整性)
#   4. 支持 crash 和 非crash逻辑漏洞 两种验证模式
#   5. 覆盖所有协议: FTP/SMTP/RTSP/SIP/DAAP/HTTP/MQTT
#
# 用法:
#   ./verify_seed_container.sh <target> <seed_path> [verify_mode]
#   verify_mode: crash | logical | full (default: full)
#
# 示例:
#   ./verify_seed_container.sh bftpd ./crash_seed.bin crash
#   ./verify_seed_container.sh mosquitto-v2.0.18 ./mqueue_seed.bin logical
# ==============================================================================

set -euo pipefail

TARGET="${1:?Usage: $0 <target> <seed_path> [verify_mode]}"
SEED_PATH="${2:?Missing seed path}"
VERIFY_MODE="${3:-full}"  # crash | logical | full

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_DIR="/tmp/verify_${TARGET}_${TIMESTAMP}"
CONTAINER_NAME="verify_${TARGET}_${TIMESTAMP}"

# ═══════════════════════════════════════════════════════════════════════
# Target Configuration Database (完整覆盖所有协议)
# ═══════════════════════════════════════════════════════════════════════

declare -A TARGET_IMAGE TARGET_PROTO TARGET_PORT TARGET_SERVER_CMD TARGET_WORKDIR
declare -A TARGET_VERIFY_SCRIPT TARGET_CLEAN_CMD

# ── FTP servers ──
TARGET_IMAGE[bftpd]="bftpd"
TARGET_PROTO[bftpd]="FTP"
TARGET_PORT[bftpd]="21"
TARGET_SERVER_CMD[bftpd]="./bftpd -D -c /home/ubuntu/experiments/basic.conf"
TARGET_WORKDIR[bftpd]="/home/ubuntu/experiments/bftpd"
TARGET_CLEAN_CMD[bftpd]="rm -rf /home/ubuntu/ftpshare/*"

TARGET_IMAGE[lightftp]="lightftp"
TARGET_PROTO[lightftp]="FTP"
TARGET_PORT[lightftp]="2200"
TARGET_SERVER_CMD[lightftp]="./fftp -c /home/ubuntu/experiments/fftp.conf"
TARGET_WORKDIR[lightftp]="/home/ubuntu/experiments/lightftp"
TARGET_CLEAN_CMD[lightftp]="rm -rf /home/ubuntu/ftpshare/*"

TARGET_IMAGE[proftpd]="proftpd"
TARGET_PROTO[proftpd]="FTP"
TARGET_PORT[proftpd]="21"
TARGET_SERVER_CMD[proftpd]="./proftpd -n -c /home/ubuntu/experiments/basic.conf"
TARGET_WORKDIR[proftpd]="/home/ubuntu/experiments/proftpd"
TARGET_CLEAN_CMD[proftpd]="rm -rf /home/ubuntu/ftpshare/*"

TARGET_IMAGE[pure-ftpd]="pure-ftpd"
TARGET_PROTO[pure-ftpd]="FTP"
TARGET_PORT[pure-ftpd]="21"
TARGET_SERVER_CMD[pure-ftpd]="./pure-ftpd -c /home/ubuntu/experiments/pure-ftpd.conf"
TARGET_WORKDIR[pure-ftpd]="/home/ubuntu/experiments/pure-ftpd"
TARGET_CLEAN_CMD[pure-ftpd]="rm -rf /tmp/ftpdir/*"

# ── SMTP server ──
TARGET_IMAGE[exim]="exim"
TARGET_PROTO[exim]="SMTP"
TARGET_PORT[exim]="25"
TARGET_SERVER_CMD[exim]="./exim -bd -d -C /home/ubuntu/experiments/exim.conf"
TARGET_WORKDIR[exim]="/home/ubuntu/experiments/exim"
TARGET_CLEAN_CMD[exim]="rm -rf /var/spool/exim/*"

# ── RTSP server ──
TARGET_IMAGE[live555]="live555"
TARGET_PROTO[live555]="RTSP"
TARGET_PORT[live555]="8554"
TARGET_SERVER_CMD[live555]="./live555ProxyServer"
TARGET_WORKDIR[live555]="/home/ubuntu/experiments/live555"
TARGET_CLEAN_CMD[live555]="pkill live555ProxyServer || true"

# ── SIP server ──
TARGET_IMAGE[kamailio]="kamailio"
TARGET_PROTO[kamailio]="SIP"
TARGET_PORT[kamailio]="5060"
TARGET_SERVER_CMD[kamailio]="./kamailio -f /home/ubuntu/experiments/kamailio.cfg"
TARGET_WORKDIR[kamailio]="/home/ubuntu/experiments/kamailio"
TARGET_CLEAN_CMD[kamailio]="pkill kamailio || true"

# ── DAAP server ──
TARGET_IMAGE[forked-daapd]="forked-daapd"
TARGET_PROTO[forked-daapd]="DAAP"
TARGET_PORT[forked-daapd]="3689"
TARGET_SERVER_CMD[forked-daapd]="./forked-daapd -f -c /home/ubuntu/experiments/forked-daapd.conf"
TARGET_WORKDIR[forked-daapd]="/home/ubuntu/experiments/forked-daapd"
TARGET_CLEAN_CMD[forked-daapd]="pkill forked-daapd || true"

# ── HTTP server ──
TARGET_IMAGE[lighttpd1]="lighttpd1"
TARGET_PROTO[lighttpd1]="HTTP"
TARGET_PORT[lighttpd1]="80"
TARGET_SERVER_CMD[lighttpd1]="./lighttpd -D -f /home/ubuntu/experiments/lighttpd.conf"
TARGET_WORKDIR[lighttpd1]="/home/ubuntu/experiments/lighttpd"
TARGET_CLEAN_CMD[lighttpd1]="pkill lighttpd || true"

# ── MQTT brokers ──
TARGET_IMAGE[mosquitto-v2.0.18]="mosquitto-v2.0.18"
TARGET_PROTO[mosquitto-v2.0.18]="MQTT"
TARGET_PORT[mosquitto-v2.0.18]="1883"
TARGET_SERVER_CMD[mosquitto-v2.0.18]="./src/mosquitto -c /home/ubuntu/experiments/mosquitto.conf"
TARGET_WORKDIR[mosquitto-v2.0.18]="/home/ubuntu/experiments/mosquitto"
TARGET_CLEAN_CMD[mosquitto-v2.0.18]="pkill mosquitto || true"

TARGET_IMAGE[mosquitto-v2.1.2]="mosquitto-v2.1.2"
TARGET_PROTO[mosquitto-v2.1.2]="MQTT"
TARGET_PORT[mosquitto-v2.1.2]="1883"
TARGET_SERVER_CMD[mosquitto-v2.1.2]="./src/mosquitto -c /home/ubuntu/experiments/mosquitto.conf"
TARGET_WORKDIR[mosquitto-v2.1.2]="/home/ubuntu/experiments/mosquitto"
TARGET_CLEAN_CMD[mosquitto-v2.1.2]="pkill mosquitto || true"

# ═══════════════════════════════════════════════════════════════════════
# Validation
# ═══════════════════════════════════════════════════════════════════════

if [ -z "${TARGET_IMAGE[$TARGET]:-}" ]; then
    echo "[ERROR] Unknown target: $TARGET"
    echo "Supported targets: ${!TARGET_IMAGE[*]}"
    exit 1
fi

if [ ! -f "$SEED_PATH" ]; then
    echo "[ERROR] Seed file not found: $SEED_PATH"
    exit 1
fi

IMAGE="${TARGET_IMAGE[$TARGET]}"
PROTO="${TARGET_PROTO[$TARGET]}"
PORT="${TARGET_PORT[$TARGET]}"
SERVER_CMD="${TARGET_SERVER_CMD[$TARGET]}"
WORKDIR="${TARGET_WORKDIR[$TARGET]}"
CLEAN_CMD="${TARGET_CLEAN_CMD[$TARGET]:-true}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "[ERROR] Docker image '$IMAGE' not found."
    echo "Available images:"
    docker images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' | head -20
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════════
# Prepare
# ═══════════════════════════════════════════════════════════════════════

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"/{logs,asan,responses,verification}
cp "$SEED_PATH" "$OUT_DIR/seed.bin"

# Analyze seed structure
python3 << PYEOF > "$OUT_DIR/seed_analysis.txt"
import struct, os, sys

seed = '$OUT_DIR/seed.bin'
with open(seed, 'rb') as f:
    data = f.read()

print(f"Seed file: {os.path.basename(seed)}")
print(f"Total size: {len(data)} bytes")
print()

# AFLNet format: [4-byte size][payload] repeated
offset = 0
msg_idx = 0
while offset + 4 <= len(data):
    size = struct.unpack('<I', data[offset:offset+4])[0]
    offset += 4
    if offset + size > len(data):
        print(f"[WARN] msg[{msg_idx}]: truncated (need {size}B, have {len(data)-offset}B)")
        break
    payload = data[offset:offset+size]
    printable = ''.join(chr(b) if 32 <= b < 127 else f'\\x{b:02x}' for b in payload[:100])
    if len(payload) > 100:
        printable += '...'
    print(f"  msg[{msg_idx:03d}]: size={size:5d} | {printable}")
    offset += size
    msg_idx += 1

print(f"\nTotal messages: {msg_idx}")
print(f"Bytes remaining (unparsed): {len(data) - offset}")
PYEOF

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Container-Based Seed Verification                          ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Target   : $TARGET ($PROTO)"
echo "║  Image    : $IMAGE"
echo "║  Seed     : $(basename "$SEED_PATH") ($(wc -c < "$SEED_PATH") bytes, $(grep -c '^  msg\[' "$OUT_DIR/seed_analysis.txt" || echo 0) messages)"
echo "║  Mode     : $VERIFY_MODE (crash | logical | full)"
echo "║  Output   : $OUT_DIR"
echo "╚══════════════════════════════════════════════════════════════╝"

# ═══════════════════════════════════════════════════════════════════════
# Verification Script (inside container)
# ═══════════════════════════════════════════════════════════════════════

VERIFY_SCRIPT="/tmp/verify_seed_in_container.py"
cat > /tmp/verify_seed_in_container.py << 'PYEOF'
#!/usr/bin/env python3
"""
Universal seed verification script - runs INSIDE the Docker container.
Performs structured replay of AFLNet-format seeds and collects evidence.
"""
import socket
import struct
import sys
import os
import time
import signal
import subprocess
import json
from datetime import datetime

# ── Configuration (passed via env) ──
PROTO = os.environ.get('PROTO', 'FTP')
PORT = int(os.environ.get('PORT', '21'))
SEED_FILE = os.environ.get('SEED_FILE', '/tmp/seed.bin')
OUT_DIR = os.environ.get('OUT_DIR', '/tmp/verify_out')
WORKDIR = os.environ.get('WORKDIR', '/tmp')
SERVER_CMD = os.environ.get('SERVER_CMD', '')
VERIFY_MODE = os.environ.get('VERIFY_MODE', 'full')
FUZZER_BIN = os.environ.get('FUZZER_BIN', '/home/ubuntu/chatafl-opt')

results = {
    'target': os.environ.get('TARGET', 'unknown'),
    'protocol': PROTO,
    'verify_mode': VERIFY_MODE,
    'timestamp': datetime.now().isoformat(),
    'server_crashed': False,
    'crash_signal': None,
    'crash_exit_code': None,
    'asan_output': None,
    'responses': [],
    'security_violations': [],
    'replay_successful': False,
}

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def read_seed_messages(seed_path):
    """Parse AFLNet-format seed into individual messages"""
    with open(seed_path, 'rb') as f:
        data = f.read()

    msgs = []
    offset = 0
    while offset + 4 <= len(data):
        size = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        if offset + size > len(data):
            log(f"WARN: Truncated message at offset {offset}")
            break
        msgs.append(data[offset:offset+size])
        offset += size

    log(f"Parsed {len(msgs)} messages from seed")
    return msgs

def start_server():
    """Start target server as subprocess"""
    log(f"Starting server: {SERVER_CMD}")
    env = os.environ.copy()
    env['ASAN_OPTIONS'] = 'abort_on_error=1:symbolize=1:detect_leaks=0:log_path=/tmp/asan/verify'

    proc = subprocess.Popen(
        SERVER_CMD, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, cwd=WORKDIR, preexec_fn=os.setsid
    )

    # Wait for server to be ready
    for _ in range(100):
        time.sleep(0.1)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex(('127.0.0.1', PORT)) == 0:
                sock.close()
                break
            sock.close()
        except:
            pass
    else:
        log("WARN: Server may not have started on port")

    return proc

def replay_messages(msgs, proto, port):
    """Replay AFLNet seed messages to server, collect responses"""
    if not msgs:
        log("No messages to replay")
        return []

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)

    try:
        sock.connect(('127.0.0.1', port))
        log(f"Connected to 127.0.0.1:{port}")
    except Exception as e:
        log(f"Connection failed: {e}")
        return []

    responses = []

    # Read banner (protocol-specific greeting)
    try:
        sock.settimeout(1)
        banner = sock.recv(8192)
        if banner:
            responses.append(banner)
            log(f"Banner: {len(banner)} bytes")
    except socket.timeout:
        log("No banner received (or protocol doesn't send one)")

    # Send each message and collect response
    for i, msg in enumerate(msgs):
        try:
            sock.settimeout(3)
            sock.sendall(msg)
            log(f"Sent msg[{i}]: {len(msg)} bytes")

            # Wait for response
            time.sleep(0.1)
            resp_chunks = []
            try:
                while True:
                    sock.settimeout(0.5)
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    resp_chunks.append(chunk)
                    if len(b''.join(resp_chunks)) > 65536:  # Max 64KB per response
                        break
            except socket.timeout:
                pass

            full_resp = b''.join(resp_chunks)
            responses.append(full_resp)
            log(f"Resp[{i}]: {len(full_resp)} bytes")

        except (socket.error, BrokenPipeError, ConnectionResetError) as e:
            log(f"Connection error on msg[{i}]: {e}")
            break

    sock.close()
    log(f"Replay complete: {len(responses)} response blocks collected")
    return responses

def extract_ftp_response_codes(responses):
    """Extract response codes from FTP responses"""
    codes = []
    for resp in responses:
        for line in resp.decode('latin-1', errors='replace').split('\n'):
            line = line.strip()
            if len(line) >= 3 and line[:3].isdigit():
                codes.append(int(line[:3]))
    return codes

def check_security_violations(msgs, responses, proto):
    """Protocol-specific security violation checks"""
    violations = []

    if proto == 'FTP':
        violations.extend(check_ftp_violations(msgs, responses))
    elif proto == 'MQTT':
        violations.extend(check_mqtt_violations(msgs, responses))
    elif proto == 'SMTP':
        violations.extend(check_smtp_violations(msgs, responses))
    elif proto == 'HTTP':
        violations.extend(check_http_violations(msgs, responses))
    elif proto == 'RTSP':
        violations.extend(check_rtsp_violations(msgs, responses))
    elif proto == 'SIP':
        violations.extend(check_sip_violations(msgs, responses))

    return violations

def check_ftp_violations(msgs, responses):
    v = []
    codes = extract_ftp_response_codes(responses)
    authenticated = False
    has_user = False
    has_rnfr = False

    for i, msg in enumerate(msgs):
        req = msg.decode('latin-1', errors='replace').upper()

        if req.startswith('USER '):
            has_user = True
        if req.startswith('PASS ') and has_user:
            # Check if response indicates success
            authenticated = True
            for r in responses[min(i+1, len(responses)-1):]:
                if b'230' in r:
                    authenticated = True
                    break

        if req.startswith('RNFR '):
            has_rnfr = True

        # Auth bypass: data commands without auth
        if not authenticated:
            data_cmds = ['RETR ', 'STOR ', 'LIST', 'NLST', 'MKD ', 'RMD ', 'DELE ', 'APPE ']
            if any(req.startswith(c) for c in data_cmds):
                if i < len(codes):
                    code = codes[min(i+1, len(codes)-1)]
                    if code < 400:
                        v.append({
                            'severity': 'HIGH',
                            'type': 'AUTH_BYPASS',
                            'desc': f'Data command without auth got response {code}',
                            'msg_index': i,
                            'cve_pattern': 'CVE-2024-42645'
                        })

        # State violation: RNTO without RNFR
        if req.startswith('RNTO ') and not has_rnfr:
            if i < len(codes):
                code = codes[min(i+1, len(codes)-1)]
                if code and code < 400:
                    v.append({
                        'severity': 'MEDIUM',
                        'type': 'STATE_VIOLATION',
                        'desc': f'RNTO without RNFR got response {code}',
                        'msg_index': i
                    })

        # Path traversal
        if b'../' in msg or b'..\\' in msg:
            if i < len(codes):
                code = codes[min(i+1, len(codes)-1)]
                if code and 150 <= code <= 250:
                    v.append({
                        'severity': 'HIGH',
                        'type': 'PATH_TRAVERSAL',
                        'desc': f"Path traversal '../' got response {code}",
                        'msg_index': i,
                        'cve_pattern': 'CVE-2024-3935'
                    })

    return v

def check_mqtt_violations(msgs, responses):
    v = []
    has_connect = False

    for i, msg in enumerate(msgs):
        if len(msg) < 2:
            continue
        pkt_type = (msg[0] >> 4) & 0x0F

        # Verify CONNECT packet signature
        if pkt_type == 1:
            # Check for "MQTT" or "MQIsdp" protocol name
            rl_bytes = 0
            rem_len = 0
            multiplier = 1
            idx = 1
            while idx < min(len(msg), 5):
                rem_len += (msg[idx] & 0x7F) * multiplier
                multiplier *= 128
                rl_bytes += 1
                if not (msg[idx] & 0x80):
                    break
                idx += 1

            vh_off = 1 + rl_bytes
            if vh_off + 8 <= len(msg):
                proto_len = (msg[vh_off] << 8) | msg[vh_off + 1]
                proto_name = msg[vh_off + 2:vh_off + 2 + proto_len]
                if proto_name in (b'MQTT', b'MQIsdp'):
                    has_connect = True

        # Auth bypass: PUBLISH/SUBSCRIBE without CONNECT
        if pkt_type == 3 and not has_connect:  # PUBLISH
            v.append({
                'severity': 'HIGH',
                'type': 'AUTH_BYPASS',
                'desc': 'PUBLISH without CONNECT',
                'msg_index': i,
                'cve_pattern': 'CVE-2023-34488'
            })
        if pkt_type == 8 and not has_connect:  # SUBSCRIBE
            v.append({
                'severity': 'HIGH',
                'type': 'AUTH_BYPASS',
                'desc': 'SUBSCRIBE without CONNECT',
                'msg_index': i,
                'cve_pattern': 'CVE-2023-34488'
            })

        # ACL bypass: $SYS topic access
        if b'$SYS' in msg:
            v.append({
                'severity': 'MEDIUM',
                'type': 'ACL_BYPASS',
                'desc': 'Access to $SYS topic',
                'msg_index': i,
                'cve_pattern': 'CVE-2017-7650'
            })

        # Retained message flooding
        if (msg[0] & 0x01) and pkt_type == 3:
            v.append({
                'severity': 'INFO',
                'type': 'RESOURCE_EXHAUST',
                'desc': 'Retained message (potential resource exhaustion)',
                'msg_index': i,
                'cve_pattern': 'CVE-2023-3592'
            })

    return v

def check_smtp_violations(msgs, responses):
    v = []
    has_ehlo = has_auth = has_mail = False
    for i, msg in enumerate(msgs):
        req = msg.decode('latin-1', errors='replace').upper()
        if req.startswith('EHLO ') or req.startswith('HELO '):
            has_ehlo = True
        if req.startswith('AUTH '):
            has_auth = True
        if req.startswith('MAIL FROM:'):
            has_mail = True
        if req.startswith('RCPT TO:') and has_mail and not has_auth:
            v.append({
                'severity': 'HIGH',
                'type': 'AUTH_BYPASS',
                'desc': 'Open relay: RCPT TO without AUTH',
                'msg_index': i,
                'cve_pattern': 'CVE-2023-42117'
            })
        if req.startswith('DATA') and not has_mail:
            v.append({
                'severity': 'MEDIUM',
                'type': 'STATE_VIOLATION',
                'desc': 'DATA without MAIL FROM',
                'msg_index': i
            })
    return v

def check_http_violations(msgs, responses):
    v = []
    for i, msg in enumerate(msgs):
        if b'../' in msg or b'..\\' in msg or b'%2e%2e' in msg:
            v.append({
                'severity': 'HIGH',
                'type': 'PATH_TRAVERSAL',
                'desc': 'Path traversal attempt in URL',
                'msg_index': i,
                'cve_pattern': 'CVE-2021-41773'
            })
        if b'Content-Length:' in msg and b'Transfer-Encoding:' in msg:
            v.append({
                'severity': 'HIGH',
                'type': 'REQUEST_SMUGGLING',
                'desc': 'Both CL and TE headers (smuggling risk)',
                'msg_index': i,
                'cve_pattern': 'CVE-2023-25690'
            })
    return v

def check_rtsp_violations(msgs, responses):
    v = []
    has_setup = False
    for i, msg in enumerate(msgs):
        req = msg.decode('latin-1', errors='replace').upper()
        if req.startswith('SETUP '):
            has_setup = True
        if req.startswith('PLAY ') and not has_setup:
            v.append({
                'severity': 'HIGH',
                'type': 'STATE_VIOLATION',
                'desc': 'PLAY before SETUP',
                'msg_index': i,
                'cve_pattern': 'CVE-2021-38382'
            })
    return v

def check_sip_violations(msgs, responses):
    v = []
    has_invite = has_auth = False
    for i, msg in enumerate(msgs):
        req = msg.decode('latin-1', errors='replace').upper()
        if req.startswith('INVITE '):
            has_invite = True
        if b'Authorization:' in msg or b'Proxy-Authorization:' in msg:
            has_auth = True
        if req.startswith('BYE ') and not has_invite:
            v.append({
                'severity': 'MEDIUM',
                'type': 'STATE_VIOLATION',
                'desc': 'BYE before INVITE',
                'msg_index': i
            })
        if has_invite and not has_auth:
            v.append({
                'severity': 'HIGH',
                'type': 'AUTH_BYPASS',
                'desc': 'INVITE without Authorization header',
                'msg_index': i,
                'cve_pattern': 'CVE-2023-49323'
            })
    return v

# ── Main ──
def main():
    log(f"Starting verification: {PROTO} on port {PORT}")
    log(f"Mode: {VERIFY_MODE}")

    msgs = read_seed_messages(SEED_FILE)
    if not msgs:
        log("FATAL: No messages parsed from seed")
        sys.exit(1)

    # Save parsed messages
    os.makedirs(f'{OUT_DIR}/messages', exist_ok=True)
    for i, msg in enumerate(msgs):
        with open(f'{OUT_DIR}/messages/msg_{i:03d}.bin', 'wb') as f:
            f.write(msg)

    # Start server
    server = start_server()
    time.sleep(1)

    # Check if server started
    if server.poll() is not None:
        stdout, stderr = server.communicate()
        log(f"Server died immediately! stdout={stdout[:200]} stderr={stderr[:200]}")
        results['server_crashed'] = True
        results['crash_exit_code'] = server.returncode
        with open(f'{OUT_DIR}/server_crash.log', 'w') as f:
            f.write(f"STDOUT:\n{stdout.decode('latin-1', errors='replace')}\n\nSTDERR:\n{stderr.decode('latin-1', errors='replace')}")
        return

    # Replay messages
    results['replay_successful'] = True
    responses = replay_messages(msgs, PROTO, PORT)

    # Save responses
    with open(f'{OUT_DIR}/responses.bin', 'wb') as f:
        for i, r in enumerate(responses):
            f.write(f"=== Response {i} ({len(r)} bytes) ===\n".encode())
            f.write(r)
            f.write(b'\n')

    # Check for security violations
    if VERIFY_MODE in ('logical', 'full'):
        results['security_violations'] = check_security_violations(msgs, responses, PROTO)

    # Check if server crashed during replay
    if server.poll() is not None:
        server.wait()
        results['server_crashed'] = True
        results['crash_exit_code'] = server.returncode
        if server.returncode > 128:
            results['crash_signal'] = server.returncode - 128
        log(f"Server CRASHED! exit={server.returncode} signal={results['crash_signal']}")
    else:
        # Graceful shutdown
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=5)
        except:
            server.kill()

    # Collect ASAN logs
    asan_dir = '/tmp/asan'
    if os.path.exists(asan_dir):
        for f in os.listdir(asan_dir):
            asan_path = os.path.join(asan_dir, f)
            if os.path.isfile(asan_path):
                with open(asan_path) as af:
                    results['asan_output'] = af.read()[:4096]

    # Save results
    with open(f'{OUT_DIR}/verification_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)

    # Summary
    log("=" * 60)
    log(f"VERIFICATION COMPLETE")
    log(f"  Server crashed: {results['server_crashed']}")
    if results['crash_signal']:
        log(f"  Crash signal: SIG{results['crash_signal']}")
    log(f"  Security violations: {len(results['security_violations'])}")
    for v in results['security_violations']:
        log(f"    [{v['severity']}] {v['type']}: {v['desc']} (msg #{v['msg_index']})")
    log("=" * 60)

if __name__ == '__main__':
    main()
PYEOF

# ═══════════════════════════════════════════════════════════════════════
# Execute verification in container
# ═══════════════════════════════════════════════════════════════════════

echo ""
echo "━━━ Launching verification container ━━━"

docker run --rm \
    --name "$CONTAINER_NAME" \
    --network host \
    -v "$(realpath "$OUT_DIR"):/tmp/verify_out" \
    -v "$(realpath "$SEED_PATH"):/tmp/seed.bin:ro" \
    -v "/tmp/verify_seed_in_container.py:/tmp/verify_seed_in_container.py:ro" \
    -e "TARGET=$TARGET" \
    -e "PROTO=$PROTO" \
    -e "PORT=$PORT" \
    -e "SEED_FILE=/tmp/seed.bin" \
    -e "OUT_DIR=/tmp/verify_out" \
    -e "WORKDIR=$WORKDIR" \
    -e "SERVER_CMD=$SERVER_CMD" \
    -e "VERIFY_MODE=$VERIFY_MODE" \
    -e "FUZZER_BIN=/home/ubuntu/chatafl-opt" \
    -e "ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0:log_path=/tmp/asan/verify" \
    "$IMAGE" /bin/bash -c "
mkdir -p /tmp/asan /tmp/verify_out/{messages,responses}

# Clean state
$CLEAN_CMD 2>/dev/null || true

# Run verification
cd $WORKDIR
python3 /tmp/verify_seed_in_container.py 2>&1
" 2>&1 | tee "$OUT_DIR/container_output.log"

# ═══════════════════════════════════════════════════════════════════════
# Report results
# ═══════════════════════════════════════════════════════════════════════

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Verification Complete                                      ║"
echo "╠══════════════════════════════════════════════════════════════╣"

if [ -f "$OUT_DIR/verification/verification_results.json" ]; then
    python3 << PYEOF
import json
with open('$OUT_DIR/verification/verification_results.json') as f:
    r = json.load(f)
print(f"║  Server crashed:     {r['server_crashed']}")
print(f"║  Replay successful:  {r['replay_successful']}")
print(f"║  Violations found:   {len(r['security_violations'])}")
for v in r['security_violations']:
    print(f"║    [{v['severity']}] {v['type']}: {v['desc'][:50]}")
if r.get('crash_signal'):
    print(f"║  Crash signal:       SIG{r['crash_signal']}")
if r.get('asan_output'):
    print(f"║  ASAN output:        {r['asan_output'][:100]}...")
print(f"╚══════════════════════════════════════════════════════════════╝")
PYEOF
else
    echo "║  WARNING: Verification results not found"
    echo "╚══════════════════════════════════════════════════════════════╝"
fi

echo ""
echo "Full output: $OUT_DIR"
echo "  - seed_analysis.txt        : Seed structure analysis"
echo "  - container_output.log     : Full container output"
echo "  - verification_results.json: Structured results"
echo "  - messages/                : Individual parsed messages"
echo "  - responses.bin            : Server responses"
echo ""
echo "To manually debug:"
echo "  docker run --rm -it --network host \\"
echo "    -v $(realpath "$OUT_DIR"):/tmp/verify_out \\"
echo "    -v $(realpath "$SEED_PATH"):/tmp/seed.bin:ro \\"
echo "    -e \"ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0\" \\"
echo "    $IMAGE /bin/bash"
echo ""
echo "━━━ Done ━━━"
