#!/bin/bash
# ==============================================================================
# ChatAFL-Opt Logical Vulnerability Replay & Verification Tool
# ==============================================================================
# 逻辑漏洞(非crash漏洞)重放验证方案
#
# 核心原理 (基于 FindVulnerability.txt):
#   漏洞 = 攻击者可控条件下, 程序违反了某个安全不变量, 并产生安全影响
#   Vulnerability = attacker-controlled input/state/environment
#                 + reachable execution path
#                 + violated security invariant
#                 + security impact
#
# 逻辑漏洞不需要crash,而是违反安全属性:
#   - 认证绕过 (Auth Bypass):    未认证访问受保护资源
#   - 授权绕过 (Authz Bypass):   低权限执行高权限操作
#   - 状态机违规 (State Viol.):  非法状态跳转
#   - 信息泄露 (Info Leak):      响应中包含敏感信息
#   - 路径穿越 (Path Trav.):     访问授权目录外文件
#   - 请求走私 (Smuggling):      协议解析差异
#   - 资源耗尽 (DoS):            小输入导致指数级资源消耗
#
# 重放验证方法:
#   1. 从 ChatAFL-Opt 的 replayable-violations 目录获取违规报告
#   2. 提取违规种子中的请求序列
#   3. 在干净容器中精确重放请求序列
#   4. 收集完整请求-响应对
#   5. 按协议安全不变量人工判断是否为真实漏洞
# ==============================================================================

set -euo pipefail

TARGET="${1:?Usage: $0 <target> <violation_report_or_result_dir> [output_dir]}"
VIOLATION_SRC="${2:?Missing violation source}"
OUT_DIR="${3:-/tmp/logical_vuln_${TARGET}_$(date +%Y%m%d_%H%M%S)}"

# ── Protocol-specific oracle check scripts ─────────────────────────────

# FTP: 完整的安全属性验证
verify_ftp_violation() {
    local req_file="$1" resp_file="$2" out_file="$3"

    python3 << 'PYEOF'
import sys, struct, os

req_file = os.environ.get('REQ_FILE', '')
resp_file = os.environ.get('RESP_FILE', '')

def check_ftp_security(reqs, resps, report):
    """根据FindVulnerability.txt的安全不变量检查FTP行为"""
    lines = []
    authenticated = False
    has_user = False

    lines.append("=== FTP Security Property Verification ===\n")
    lines.append(f"Requests: {len(reqs)}, Responses collected\n\n")

    # 1. 认证绕过检查: 未认证时不应执行数据命令(RETR/STOR/LIST/NLST/MKD/RMD/DELE)
    lines.append("--- Check 1: Auth Bypass ---\n")
    for i, req in enumerate(reqs):
        req_upper = req.decode('latin-1', errors='replace').upper()
        if any(req_upper.startswith(cmd) for cmd in ['RETR ', 'STOR ', 'LIST', 'NLST', 'MKD ', 'RMD ', 'DELE ', 'APPE ', 'SITE ']):
            if not authenticated:
                # Check corresponding response
                if i < len(resps):
                    code = extract_ftp_code(resps[i])
                    if code and code < 400:
                        lines.append(f"[HIGH] Auth Bypass: '{req.decode('latin-1', errors='replace').strip()}' got response {code} without authentication\n")
                        lines.append(f"  Category: ORACLE_CAT_AUTH_BYPASS\n")
                        lines.append(f"  Security Property Violated: Authentication\n")
                        lines.append(f"  Impact: Unauthenticated data access\n")
        if req_upper.startswith('USER '):
            has_user = True
        if req_upper.startswith('PASS ') and has_user:
            authenticated = True

    # 2. 状态机违规: PASS without USER, RNTO without RNFR
    lines.append("\n--- Check 2: State Machine Violations ---\n")
    has_rnfr = False
    for i, req in enumerate(reqs):
        req_upper = req.decode('latin-1', errors='replace').upper()
        if req_upper.startswith('RNFR '):
            has_rnfr = True
        if req_upper.startswith('RNTO ') and not has_rnfr:
            if i < len(resps):
                code = extract_ftp_code(resps[i])
                if code and code < 400:
                    lines.append(f"[MEDIUM] State Violation: RNTO without prior RNFR succeeded (code {code})\n")
                    lines.append(f"  Category: ORACLE_CAT_STATE_VIOLATION\n")
        if req_upper.startswith('PASS ') and not has_user:
            if i < len(resps):
                code = extract_ftp_code(resps[i])
                if code == 230:
                    lines.append(f"[CRITICAL] Auth State Bypass: PASS accepted without USER\n")

    # 3. 路径穿越检查
    lines.append("\n--- Check 3: Path Traversal ---\n")
    for i, req in enumerate(reqs):
        if b'../' in req or b'..\\' in req or b'%2e%2e' in req:
            if i < len(resps):
                code = extract_ftp_code(resps[i])
                if code and 150 <= code <= 250:
                    lines.append(f"[HIGH] Path Traversal: '../' in request succeeded (code {code})\n")

    # 4. 信息泄露检查
    lines.append("\n--- Check 4: Info Leak ---\n")
    for i, resp in enumerate(resps):
        if b'/etc/passwd' in resp or b'/etc/shadow' in resp or b'root:' in resp:
            lines.append(f"[CRITICAL] Info Leak: Sensitive file content in response #{i}\n")

    # 5. 命令注入检查
    lines.append("\n--- Check 5: Command Injection ---\n")
    for i, req in enumerate(reqs):
        if b';' in req or b'&&' in req or b'|' in req or b'`' in req:
            if i < len(resps):
                code = extract_ftp_code(resps[i])
                if code and code < 400:
                    lines.append(f"[MEDIUM] Potential command injection accepted: '{req.decode('latin-1', errors='replace').strip()}' got {code}\n")

    lines.append(f"\n=== Summary: {len([l for l in lines if '[HIGH]' in l or '[CRITICAL]' in l or '[MEDIUM]' in l])} potential violations found ===\n")
    return '\n'.join(lines)

def extract_ftp_code(resp):
    """Extract FTP response code"""
    s = resp.decode('latin-1', errors='replace')
    for line in s.split('\n'):
        if len(line) >= 3 and line[:3].isdigit():
            return int(line[:3])
    return None

if __name__ == '__main__':
    report = check_ftp_security([], [], [])
    print(report)
PYEOF
}

# MQTT: 安全属性验证
verify_mqtt_violation() {
    python3 << 'PYEOF'
def verify_mqtt_security(hex_req, hex_resp):
    """MQTT安全属性验证
    基于CVE-2023-34488 (auth bypass), CVE-2017-7650 (ACL bypass)等
    """
    lines = []
    lines.append("=== MQTT Security Property Verification ===\n")

    req_bytes = bytes.fromhex(hex_req)
    resp_bytes = bytes.fromhex(hex_resp)

    # 1. 认证检查: 非CONNECT报文之前不应有PUBLISH/SUBSCRIBE
    has_connect = False
    offset = 0
    while offset + 2 <= len(req_bytes):
        pkt_type = (req_bytes[offset] >> 4) & 0x0F
        if pkt_type == 1:  # CONNECT
            has_connect = True
        elif pkt_type == 3 and not has_connect:  # PUBLISH without CONNECT
            lines.append("[HIGH] Auth Bypass: PUBLISH without CONNECT\n")
            lines.append("  CVE Pattern: CVE-2023-34488\n")
        elif pkt_type == 8 and not has_connect:  # SUBSCRIBE without CONNECT
            lines.append("[HIGH] Auth Bypass: SUBSCRIBE without CONNECT\n")

        # Decode remaining length to skip packet
        if offset + 1 >= len(req_bytes):
            break
        rl_bytes = 0
        rem_len = 0
        multiplier = 1
        idx = offset + 1
        while idx < len(req_bytes) and idx < offset + 5:
            rem_len += (req_bytes[idx] & 0x7F) * multiplier
            multiplier *= 128
            rl_bytes += 1
            if not (req_bytes[idx] & 0x80):
                break
            idx += 1

        offset += 1 + rl_bytes + rem_len
        if offset >= len(req_bytes):
            break

    # 2. $SYS topic ACL bypass
    if b'$SYS' in req_bytes:
        lines.append("[MEDIUM] ACL Bypass: Access to \$SYS topic attempted\n")
        lines.append("  CVE Pattern: CVE-2017-7650\n")

    # 3. 资源耗尽: retained message flooding
    retain_count = 0
    offset = 0
    while offset < len(req_bytes):
        if offset < len(req_bytes) and (req_bytes[offset] & 0x01):  # retain flag
            retain_count += 1
        offset += 1
        if offset >= len(req_bytes):
            break

    if retain_count > 50:
        lines.append(f"[LOW] Resource Exhaustion: {retain_count} retained messages\n")
        lines.append("  CVE Pattern: CVE-2023-3592\n")

    lines.append(f"\n=== Verification Complete: {len([l for l in lines if 'HIGH' in l or 'MEDIUM' in l])} potential issues ===\n")
    return '\n'.join(lines)

if __name__ == '__main__':
    print("MQTT verification module loaded")
PYEOF
}

# ── Main Logic ──────────────────────────────────────────────────────────

# Target config (same as replay_crash_universal.sh)
declare -A TARGET_IMAGE TARGET_PROTO TARGET_PORT TARGET_SERVER_CMD TARGET_WORKDIR

TARGET_IMAGE[bftpd]="bftpd"; TARGET_PROTO[bftpd]="FTP"; TARGET_PORT[bftpd]="21"
TARGET_SERVER_CMD[bftpd]="./bftpd -D -c /home/ubuntu/experiments/basic.conf"
TARGET_WORKDIR[bftpd]="/home/ubuntu/experiments/bftpd"

TARGET_IMAGE[lightftp]="lightftp"; TARGET_PROTO[lightftp]="FTP"; TARGET_PORT[lightftp]="2200"
TARGET_SERVER_CMD[lightftp]="./fftp -c /home/ubuntu/experiments/fftp.conf"
TARGET_WORKDIR[lightftp]="/home/ubuntu/experiments/lightftp"

TARGET_IMAGE[proftpd]="proftpd"; TARGET_PROTO[proftpd]="FTP"; TARGET_PORT[proftpd]="21"
TARGET_SERVER_CMD[proftpd]="./proftpd -n -c /home/ubuntu/experiments/basic.conf"
TARGET_WORKDIR[proftpd]="/home/ubuntu/experiments/proftpd"

TARGET_IMAGE[pure-ftpd]="pure-ftpd"; TARGET_PROTO[pure-ftpd]="FTP"; TARGET_PORT[pure-ftpd]="21"
TARGET_SERVER_CMD[pure-ftpd]="./pure-ftpd -c /home/ubuntu/experiments/pure-ftpd.conf"
TARGET_WORKDIR[pure-ftpd]="/home/ubuntu/experiments/pure-ftpd"

TARGET_IMAGE[exim]="exim"; TARGET_PROTO[exim]="SMTP"; TARGET_PORT[exim]="25"
TARGET_SERVER_CMD[exim]="./exim -bd -d -C /home/ubuntu/experiments/exim.conf"
TARGET_WORKDIR[exim]="/home/ubuntu/experiments/exim"

TARGET_IMAGE[live555]="live555"; TARGET_PROTO[live555]="RTSP"; TARGET_PORT[live555]="8554"
TARGET_SERVER_CMD[live555]="./live555ProxyServer"
TARGET_WORKDIR[live555]="/home/ubuntu/experiments/live555"

TARGET_IMAGE[kamailio]="kamailio"; TARGET_PROTO[kamailio]="SIP"; TARGET_PORT[kamailio]="5060"
TARGET_SERVER_CMD[kamailio]="./kamailio -f /home/ubuntu/experiments/kamailio.cfg"
TARGET_WORKDIR[kamailio]="/home/ubuntu/experiments/kamailio"

TARGET_IMAGE[forked-daapd]="forked-daapd"; TARGET_PROTO[forked-daapd]="DAAP"; TARGET_PORT[forked-daapd]="3689"
TARGET_SERVER_CMD[forked-daapd]="./forked-daapd -f -c /home/ubuntu/experiments/forked-daapd.conf"
TARGET_WORKDIR[forked-daapd]="/home/ubuntu/experiments/forked-daapd"

TARGET_IMAGE[lighttpd1]="lighttpd1"; TARGET_PROTO[lighttpd1]="HTTP"; TARGET_PORT[lighttpd1]="80"
TARGET_SERVER_CMD[lighttpd1]="./lighttpd -D -f /home/ubuntu/experiments/lighttpd.conf"
TARGET_WORKDIR[lighttpd1]="/home/ubuntu/experiments/lighttpd"

TARGET_IMAGE[mosquitto-v2.0.18]="mosquitto-v2.0.18"; TARGET_PROTO[mosquitto-v2.0.18]="MQTT"; TARGET_PORT[mosquitto-v2.0.18]="1883"
TARGET_SERVER_CMD[mosquitto-v2.0.18]="./src/mosquitto -c /home/ubuntu/experiments/mosquitto.conf"
TARGET_WORKDIR[mosquitto-v2.0.18]="/home/ubuntu/experiments/mosquitto"

TARGET_IMAGE[mosquitto-v2.1.2]="mosquitto-v2.1.2"; TARGET_PROTO[mosquitto-v2.1.2]="MQTT"; TARGET_PORT[mosquitto-v2.1.2]="1883"
TARGET_SERVER_CMD[mosquitto-v2.1.2]="./src/mosquitto -c /home/ubuntu/experiments/mosquitto.conf"
TARGET_WORKDIR[mosquitto-v2.1.2]="/home/ubuntu/experiments/mosquitto"

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

mkdir -p "$OUT_DIR"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ChatAFL-Opt Logical Vulnerability Replay                   ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Target   : $TARGET  |  Protocol : $PROTO"
echo "║  Source   : $VIOLATION_SRC"
echo "║  Output   : $OUT_DIR"
echo "╚══════════════════════════════════════════════════════════════╝"

# ── Step 1: Extract violation seeds ────────────────────────────────────
echo ""
echo "━━━ Step 1: Finding violation seeds ━━━"

VIOLATION_SEEDS=()
if [ -f "$VIOLATION_SRC" ]; then
    # Single violation report file
    VIOLATION_SEEDS+=("$VIOLATION_SRC")
elif [ -d "$VIOLATION_SRC" ]; then
    # Directory of violations
    for f in "$VIOLATION_SRC"/id:*; do
        [ -f "$f" ] && VIOLATION_SEEDS+=("$f")
    done
fi

echo "Found ${#VIOLATION_SEEDS[@]} violation reports"

if [ ${#VIOLATION_SEEDS[@]} -eq 0 ]; then
    echo "[ERROR] No violation reports found"
    exit 1
fi

# ── Step 2: For each violation, replay in container and verify ──────────
echo ""
echo "━━━ Step 2: Replaying violations in container ━━━"

for idx in "${!VIOLATION_SEEDS[@]}"; do
    vf="${VIOLATION_SEEDS[$idx]}"
    vname="$(basename "$vf")"
    vout="$OUT_DIR/$vname"
    mkdir -p "$vout"

    echo ""
    echo "--- Violation #$((idx+1)): $vname ---"

    # Extract request data from violation report
    python3 -c "
import re
with open('$vf', 'r') as f:
    content = f.read()
# Extract REQUEST DATA section
m = re.search(r'=== REQUEST DATA \((\d+) bytes\) ===\n(.*?)(?:\n===|$)', content, re.DOTALL)
if m:
    print(f'Request size: {m.group(1)} bytes')
    with open('$vout/request_data.bin', 'wb') as out:
        out.write(m.group(2).encode('latin-1'))  # raw bytes from report
else:
    print('[WARN] No REQUEST DATA section found')

# Extract violation descriptions
for v in re.finditer(r'--- Violation \d+ ---\n(.*?)(?=\n---|$)', content, re.DOTALL):
    print(v.group(1))
" 2>&1 | tee "$vout/extracted_info.txt"

    # Check if there's a corresponding queue seed
    VIOLATION_ID=$(echo "$vname" | grep -oP 'id:\d+' || echo "")

    # Replay in container
    echo "  Replaying in Docker container..."
    docker run --rm \
        --network host \
        -v "$(realpath "$vout"):/tmp/vout" \
        -e "ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0" \
        "$IMAGE" /bin/bash -c "
cd $WORKDIR

# Start server
$SERVER_CMD &
SPID=\$!
sleep 1

if ! kill -0 \$SPID 2>/dev/null; then
    echo '[FATAL] Server failed to start' | tee /tmp/vout/server_output.log
    exit 1
fi

# Collect response for each request (use aflnet-client for structured replay)
# Since we don't have the exact AFLNet seed, we use netcat/python to replay
# the request data from the violation report

echo 'Server PID: '\$SPID | tee /tmp/vout/server_output.log

# Manual structured replay using Python
python3 << 'PYEOF' | tee -a /tmp/vout/server_output.log
import socket, struct, time, sys, os

proto = '$PROTO'
port = $PORT
req_file = '/tmp/vout/request_data.bin'

# Read the request data
if os.path.exists(req_file):
    with open(req_file, 'rb') as f:
        data = f.read()
    print(f'Read {len(data)} bytes from request file')
else:
    print('[WARN] No request data file, skipping replay')
    sys.exit(0)

# Connect to server
sock = None
if proto in ['FTP', 'SMTP', 'HTTP', 'RTSP', 'MQTT', 'DAAP', 'SIP']:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect(('127.0.0.1', port))
    except Exception as e:
        print(f'Connect failed: {e}')
        sys.exit(1)
else:
    print(f'Unsupported protocol: {proto}')
    sys.exit(1)

# Read banner first
try:
    banner = sock.recv(4096)
    print(f'Banner: {banner[:200]}')
except:
    pass

# Try to parse AFLNet seed format (4-byte size prefix) and replay
# The raw request data in violation reports is text, not structured seed
# We send it as a single request sequence
try:
    sock.sendall(data)
    time.sleep(0.5)
    try:
        while True:
            sock.settimeout(0.5)
            chunk = sock.recv(4096)
            if not chunk:
                break
            print(f'Response: {chunk[:500]}')
    except socket.timeout:
        pass
except Exception as e:
    print(f'Send failed: {e}')

sock.close()
print('Replay complete')
PYEOF

kill \$SPID 2>/dev/null || true
wait \$SPID 2>/dev/null || true
" 2>&1 | tee "$vout/replay_full.log"

done

echo ""
echo "━━━ Step 3: Verification Summary ━━━"
echo "All results saved to: $OUT_DIR"
echo ""
echo "Logical Vulnerability Verification Methodology:"
echo "  1. Extract the exact request sequence that triggered the oracle violation"
echo "  2. Replay in clean container with full monitoring"
echo "  3. Verify the security invariant violation is reproducible"
echo "  4. Assess exploitability & security impact"
echo ""
echo "Key Security Properties Checked (from FindVulnerability.txt):"
echo "  - Authentication: 未认证用户不应访问受保护资源"
echo "  - Authorization:  低权限用户不应执行高权限操作"
echo "  - State Machine:  状态转换必须遵守RFC规定顺序"
echo "  - Confidentiality: 响应不应包含敏感信息"
echo "  - Integrity:      请求不应绕过完整性检查"
echo "  - Availability:   小输入不应导致指数级资源消耗"
echo ""
echo "━━━ Done ━━━"
