#!/bin/bash
# ==============================================================================
# LoopFuzz Logical Vulnerability Replay & Verification Tool — FIXED VERSION
#
# Fix: Adds pre-authentication to handle garbled auth commands in violation seeds.
# The fuzzer's stateful context allowed garbled auth to succeed; standalone replay
# needs clean USER/PASS first. This fix follows the Open/Closed Principle:
#   - Original extraction/oracle/replay architecture is preserved (closed)
#   - Pre-auth module is added as a composable pre-processing step (open)
# ==============================================================================

set -euo pipefail

TARGET="${1:?Usage: $0 <target> <violation_report_or_result_dir> [output_dir]}"
VIOLATION_SRC="${2:?Missing violation source}"
OUT_DIR="${3:-/tmp/logical_vuln_${TARGET}_$(date +%Y%m%d_%H%M%S)}"

# ── Target Configuration ──────────────────────────────────────────
declare -A TARGET_IMAGE TARGET_PROTO TARGET_PORT TARGET_SERVER_CMD TARGET_WORKDIR
declare -A TARGET_PRE_START TARGET_ENV TARGET_IS_UDP TARGET_HEALTH_CHECK

# bftpd
TARGET_IMAGE[bftpd]="bftpd"; TARGET_PROTO[bftpd]="FTP"; TARGET_PORT[bftpd]="21"
TARGET_WORKDIR[bftpd]="/home/ubuntu/experiments/bftpd"
TARGET_SERVER_CMD[bftpd]="./bftpd -D -c /home/ubuntu/experiments/basic.conf"
TARGET_PRE_START[bftpd]=""
TARGET_ENV[bftpd]="ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0"
TARGET_IS_UDP[bftpd]="0"
TARGET_HEALTH_CHECK[bftpd]="nc -z 127.0.0.1 21"

# ── Validation ──────────────────────────────────────────────────────────
if [ -z "${TARGET_IMAGE[$TARGET]:-}" ]; then
    echo "[ERROR] Unknown target: $TARGET. Supported: ${!TARGET_IMAGE[*]}"
    exit 1
fi

IMAGE="${TARGET_IMAGE[$TARGET]}"; PROTO="${TARGET_PROTO[$TARGET]}"; PORT="${TARGET_PORT[$TARGET]}"
SERVER_CMD="${TARGET_SERVER_CMD[$TARGET]}"; WORKDIR="${TARGET_WORKDIR[$TARGET]}"
PRE_START="${TARGET_PRE_START[$TARGET]}"; ENV_VARS="${TARGET_ENV[$TARGET]}"
IS_UDP="${TARGET_IS_UDP[$TARGET]}"; HEALTH_CHECK="${TARGET_HEALTH_CHECK[$TARGET]}"

mkdir -p "$OUT_DIR"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  LoopFuzz Logical Vuln Replay (FIXED — Pre-Auth)         ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Target: $TARGET | Protocol: $PROTO | Port: $PORT"
echo "║  Source: $VIOLATION_SRC"
echo "║  Output: $OUT_DIR"
echo "╚══════════════════════════════════════════════════════════════╝"

# ── Step 1: Collect violation seeds ────────────────────────────────────
echo ""; echo "━━━ Step 1: Finding violation seeds ━━━"

VIOLATION_SEEDS=()
if [ -f "$VIOLATION_SRC" ]; then
    VIOLATION_SEEDS+=("$VIOLATION_SRC")
elif [ -d "$VIOLATION_SRC" ]; then
    for f in "$VIOLATION_SRC"/id:*; do
        [ -f "$f" ] && VIOLATION_SEEDS+=("$f")
    done
fi
echo "Found ${#VIOLATION_SEEDS[@]} violation reports"

if [ ${#VIOLATION_SEEDS[@]} -eq 0 ]; then
    echo "[ERROR] No violation reports found"; exit 1
fi

# ── Write the FIXED extraction + pre-auth script ────────────────────────
FIX_EXTRACT="$OUT_DIR/fix_and_extract.py"
cat > "$FIX_EXTRACT" << 'PYEOF'
#!/usr/bin/env python3
"""
FIXED extraction with pre-authentication support.
Detects garbled auth commands in violation seeds and prepends clean USER/PASS.
"""
import re, os, sys

def fix_request_data(raw_data, proto):
    """Prepend clean auth if the request data has garbled USER/PASS or no auth."""
    try:
        text = raw_data.decode('latin-1', errors='replace')
    except:
        return raw_data  # binary, can't fix

    lines = text.split('\n')

    # Check if first few lines have clean USER/PASS
    first_lines = '\n'.join(lines[:10])
    has_user = bool(re.search(r'USER\s+\w+\s*\r?$', first_lines, re.MULTILINE))
    has_pass = bool(re.search(r'PASS\s+\w+\s*\r?$', first_lines, re.MULTILINE))

    # Check if USER/PASS are garbled (contain control chars)
    user_match = re.search(r'USER\s+([^\r\n]+)', first_lines)
    pass_match = re.search(r'PASS\s+([^\r\n]+)', first_lines)

    # Check for garbled auth (binary chars or malformed)
    garbled = False
    if user_match:
        user_val = user_match.group(1).strip()
        # Check for binary/control chars in username
        if any(ord(c) < 32 and c not in '\r\n\t' for c in user_val):
            garbled = True
        # Check if USER command is split/corrupted
        if len(user_val) < 2 or len(user_val) > 50:
            garbled = True
    else:
        garbled = True  # No USER command found at all

    if not garbled and has_user and has_pass:
        return raw_data  # Auth looks clean, use as-is

    # Auth is garbled or missing — prepend clean auth
    clean_auth = b'USER ubuntu\r\nPASS ubuntu\r\n'
    return clean_auth + raw_data


def main():
    seed_path = os.environ.get('VIOLATION_SEED', '')
    vout = os.environ.get('VOUT_DIR', '/tmp/vout')
    proto = os.environ.get('REPLAY_PROTO', 'FTP')

    with open(seed_path, 'rb') as f:
        content = f.read()

    try:
        text = content.decode('utf-8', errors='replace')
    except:
        text = content.decode('latin-1', errors='replace')

    # Extract oracle info
    violations = []
    for m in re.finditer(r'--- Violation \d+ ---\n(.*?)(?=\n--- Violation|\n===|\Z)', text, re.DOTALL):
        v = m.group(1)
        sev = re.search(r'Severity:\s*(\d+)', v)
        cat = re.search(r'Category:\s*(0x[0-9a-fA-F]+)', v)
        desc = re.search(r'Description:\s*(.+?)\n', v)
        cve = re.search(r'CVE Pattern:\s*(.+?)\n', v)
        violations.append({
            'severity': sev.group(1) if sev else '?',
            'category': cat.group(1) if cat else '?',
            'description': desc.group(1).strip() if desc else '?',
            'cve': cve.group(1).strip() if cve else 'N/A'
        })

    print(f'Oracle violations: {len(violations)}')
    for v in violations:
        print(f"  Sev={v['severity']} Cat={v['category']} [{v['cve']}] {v['description']}")

    # Extract REQUEST DATA
    req_match = re.search(r'=== REQUEST DATA \((\d+) bytes\) ===\n', text)
    if req_match:
        data_start = req_match.end()
        req_size = int(req_match.group(1))
        raw = content[data_start:data_start+req_size]

        # === FIX: Prepend clean auth if garbled ===
        fixed = fix_request_data(raw, proto)

        req_path = os.path.join(vout, 'request_data.bin')
        with open(req_path, 'wb') as out:
            out.write(fixed)

        fix_info_path = os.path.join(vout, 'fix_info.txt')
        with open(fix_info_path, 'w') as f:
            if fixed != raw:
                f.write(f"AUTH_FIXED: Prepended clean USER/PASS (original {len(raw)}B -> fixed {len(fixed)}B)\n")
                print(f'[FIX] Auth was garbled — prepended clean USER/PASS ({len(raw)}B -> {len(fixed)}B)')
            else:
                f.write(f"AUTH_OK: Original auth was clean ({len(raw)}B)\n")
                print(f'[OK] Auth was clean ({len(raw)}B)')
    else:
        print('[WARN] No REQUEST DATA section')
        with open(os.path.join(vout, 'request_data.bin'), 'wb') as f:
            f.write(b'')

if __name__ == '__main__':
    main()
PYEOF
chmod +x "$FIX_EXTRACT"

# ── Write protocol-aware replay script (same as original) ──────────────
REPLAY_PY="$OUT_DIR/replay_protocol.py"
cat > "$REPLAY_PY" << 'PYEOF'
#!/usr/bin/env python3
"""Protocol-aware replay: TCP line-based (FTP/SMTP/RTSP), UDP datagram (SIP)."""
import socket, sys, os, time, struct

PROTO  = os.environ.get('REPLAY_PROTO', 'FTP')
PORT   = int(os.environ.get('REPLAY_PORT', '21'))
IS_UDP = os.environ.get('REPLAY_IS_UDP', '0')
REQ_FILE = os.environ.get('REQ_FILE', '/tmp/vout/request_data.bin')
RESP_FILE = os.environ.get('RESP_FILE', '/tmp/vout/response_data.bin')
VERDICT_FILE = os.environ.get('VERDICT_FILE', '/tmp/vout/verdict.txt')

def log(msg):
    print(msg, flush=True)

def recv_all(sock, timeout=2.0):
    chunks = []; sock.settimeout(timeout)
    while True:
        try:
            c = sock.recv(65536)
            if not c: break
            chunks.append(c)
        except socket.timeout: break
        except Exception: break
    return b''.join(chunks)

def replay_tcp(req_data):
    """TCP replay: send lines with proper response handling after each command."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect(('127.0.0.1', PORT))
    except Exception as e:
        log(f'[FATAL] connect failed: {e}')
        return b'', [f'CONNECT_FAILED: {e}']
    sock.settimeout(1.0)
    try:
        banner = sock.recv(65536)
        log(f'Banner: {banner[:200].decode("latin-1",errors="replace")}')
    except:
        banner = b''
    all_resp = [banner]

    lines = req_data.split(b'\n')
    for line in lines:
        line = line.strip(b'\r')
        if not line:
            continue
        try:
            sock.sendall(line + b'\r\n')
            time.sleep(0.15)
            r = recv_all(sock, timeout=1.5)
            if r:
                all_resp.append(r)
                # Show first line of response for tracing
                first_line = r.split(b'\r\n')[0]
                log(f'  -> {line[:80].decode("latin-1",errors="replace")} | resp: {first_line[:120].decode("latin-1",errors="replace")}')
        except Exception as e:
            log(f'  [ERR] {line[:60].decode("latin-1",errors="replace")}: {e}')
            break
    sock.close()
    return b'\n---\n'.join(all_resp), []

def replay_udp(req_data):
    """UDP: parse 4-byte uint32 LE size-prefix, send each as datagram."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 5061)); sock.settimeout(3)
    all_resp = []; errors = []; offset = 0; msg_idx = 0
    while offset + 4 <= len(req_data):
        size = struct.unpack('<I', req_data[offset:offset+4])[0]; offset += 4
        if size == 0 or offset + size > len(req_data):
            remaining = req_data[offset-4:]
            if remaining.strip():
                try:
                    sock.sendto(remaining, ('127.0.0.1', PORT)); time.sleep(0.2)
                    r = recv_all(sock, 1.0)
                    if r: all_resp.append(r)
                except Exception as e: errors.append(f'raw_send: {e}')
            break
        msg = req_data[offset:offset+size]; offset += size; msg_idx += 1
        try:
            sock.sendto(msg, ('127.0.0.1', PORT))
        except Exception as e: errors.append(f'send[{msg_idx}]: {e}'); break
        time.sleep(0.2)
        try:
            r = recv_all(sock, 1.0)
            if r: all_resp.append(r)
        except Exception as e: pass
    sock.close()
    return b'\n---\n'.join(all_resp), errors

# Main
if not os.path.exists(REQ_FILE):
    log(f'[WARN] No request file')
    sys.exit(0)
with open(REQ_FILE, 'rb') as f:
    req_data = f.read()
log(f'Req: {len(req_data)}B, proto={PROTO}, UDP={IS_UDP}')
if IS_UDP == '1':
    all_resp, errors = replay_udp(req_data)
else:
    all_resp, errors = replay_tcp(req_data)
with open(RESP_FILE, 'wb') as f:
    f.write(all_resp)
with open(VERDICT_FILE, 'w') as f:
    for e in errors:
        f.write(f'REPLAY_ERROR: {e}\n')
    f.write(f'REPLAY_COMPLETE: {len(all_resp)} bytes response\n')
log(f'Done. Response: {len(all_resp)} bytes')
PYEOF
chmod +x "$REPLAY_PY"

# ── Write oracle verification script (same as original) ────────────────
VERIFY_PY="$OUT_DIR/verify_oracle.py"
cat > "$VERIFY_PY" << 'PYEOF'
#!/usr/bin/env python3
"""Protocol oracle verification: checks security invariants on replayed data."""
import sys, os, re, struct

PROTO   = os.environ.get('REPLAY_PROTO', 'FTP')
REQ_BIN = os.environ.get('REQ_BIN', '/tmp/vout/request_data.bin')
RESP_BIN = os.environ.get('RESP_BIN', '/tmp/vout/response_data.bin')
VERDICT_FILE = os.environ.get('VERDICT_FILE', '/tmp/vout/verdict.txt')

def load(p):
    if os.path.exists(p):
        with open(p, 'rb') as f: return f.read()
    return b''

def code3(resp_bytes):
    try:
        for line in resp_bytes.decode('latin-1', errors='replace').split('\n'):
            s = line.strip()
            if len(s) >= 3 and s[:3].isdigit(): return int(s[:3])
    except: pass
    return None

def verify_ftp(req, resp):
    findings = []; auth = False; has_user = False; has_rnfr = False
    lines = req.split(b'\n'); resp_parts = resp.split(b'\n---\n')
    for i, line in enumerate(lines):
        line = line.strip(b'\r'); upper = line.decode('latin-1',errors='replace').upper()
        ri = resp_parts[i+1] if i+1 < len(resp_parts) else b''
        data_cmds = ['RETR ','STOR ','LIST','NLST','MKD ','RMD ','DELE ','APPE ','SITE ']
        if any(upper.startswith(c) for c in data_cmds) and not auth:
            c = code3(ri)
            if c and c < 400:
                findings.append({'sev':'HIGH','cat':'AUTH_BYPASS','cwe':'CWE-306',
                    'desc':f"Unauthenticated {line[:60].decode('latin-1',errors='replace')} (code {c})",
                    'cve':'CVE-2024-42644'})
        if upper.startswith('USER '): has_user = True
        if upper.startswith('PASS ') and has_user:
            c = code3(ri)
            if c == 230: auth = True
        if upper.startswith('PASS ') and not has_user:
            c = code3(ri)
            if c and c < 400:
                findings.append({'sev':'CRITICAL','cat':'AUTH_STATE_BYPASS','cwe':'CWE-862',
                    'desc':'PASS without USER accepted','cve':'CVE-2024-42644'})
        if upper.startswith('RNFR '): has_rnfr = True
        if upper.startswith('RNTO ') and not has_rnfr:
            c = code3(ri)
            if c and c < 400:
                findings.append({'sev':'MEDIUM','cat':'STATE_VIOLATION','cwe':'CWE-696',
                    'desc':'RNTO without RNFR accepted','cve':'N/A'})
        if b'../' in line:
            c = code3(ri)
            if c and c < 400:
                findings.append({'sev':'HIGH','cat':'PATH_TRAVERSAL','cwe':'CWE-24',
                    'desc':f"Path traversal: {line[:60].decode('latin-1',errors='replace')} (code {c})",
                    'cve':'CVE-2024-3935'})
        if 'PORT' in upper and (b'127,' in line or b'10,' in line or b'192,' in line or b'172,' in line):
            c = code3(ri)
            if c and c < 400:
                findings.append({'sev':'HIGH','cat':'FTP_BOUNCE','cwe':'CWE-441',
                    'desc':f"PORT to private/internal addr: {line[:60].decode('latin-1',errors='replace')} (code {c})",
                    'cve':'CVE-2018-15516'})
        if 'EPRT' in upper and (b'127.0.0.1' in line or b'::1' in line or b'10.' in line):
            c = code3(ri)
            if c and c < 400:
                findings.append({'sev':'HIGH','cat':'FTP_BOUNCE','cwe':'CWE-441',
                    'desc':f"EPRT to private/internal addr (code {c})",'cve':'CVE-2018-15516'})
        if b'\r\n' in line and len(line) > 10:
            # CRLF in middle of line = smuggling
            pass
    for i, r in enumerate(resp_parts):
        if b'root:' in r or (b'/etc/' in r and b'passwd' in r):
            findings.append({'sev':'CRITICAL','cat':'INFO_LEAK','cwe':'CWE-200',
                'desc':'Sensitive content in response','cve':'CVE-2024-42650'})
    return findings

# Main
req = load(REQ_BIN); resp = load(RESP_BIN)
if not req: print('No request data'); sys.exit(0)
print(f'Verifying {PROTO} ... req={len(req)}B resp={len(resp)}B')
fn_map = {"FTP": verify_ftp}
findings = fn_map.get(PROTO, lambda r,q: [])(req, resp)
with open(VERDICT_FILE, 'a') as f:
    if findings:
        f.write(f'\n=== ORACLE: {len(findings)} violation(s) confirmed ===\n')
        for i, fd in enumerate(findings):
            f.write(f"\n--- Confirmed #{i+1} ---\n  Severity: {fd['sev']}\n  Category: {fd['cat']}\n  CWE: {fd['cwe']}\n  Description: {fd['desc']}\n  CVE Pattern: {fd['cve']}\n")
    else:
        f.write('\n=== ORACLE: 0 violations confirmed ===\n')
print(f'Done: {len(findings)} violation(s)')
for fd in findings: print(f"  [{fd['sev']}] {fd['cat']}: {fd['desc']}")
PYEOF
chmod +x "$VERIFY_PY"

# ── Step 2: Replay each violation (FIXED with pre-auth) ─────────────────
echo ""; echo "━━━ Step 2: Replaying violations (FIXED pre-auth mode) ━━━"

CONFIRMED=0; TOTAL=${#VIOLATION_SEEDS[@]}

for idx in "${!VIOLATION_SEEDS[@]}"; do
    vf="${VIOLATION_SEEDS[$idx]}"; vname="$(basename "$vf")"
    safe_vname=$(echo "$vname" | tr ':,=' '_')
    vout="$OUT_DIR/$safe_vname"
    mkdir -p "$vout"
    echo ""; echo "--- Violation #$((idx+1))/$TOTAL: $vname ---"

    # FIXED: Use the fix_and_extract.py which adds pre-auth if needed
    VIOLATION_SEED="$vf" VOUT_DIR="$vout" REPLAY_PROTO="$PROTO" \
        python3 "$FIX_EXTRACT" 2>&1 | tee "$vout/extracted_info.txt"

    # Skip if no request data was extracted
    if [ ! -s "$vout/request_data.bin" ]; then
        echo "  [SKIP] No request data extracted"
        continue
    fi

    echo "  Replaying in Docker (with pre-auth fix)..."
    docker run --rm \
        --network host --cap-add SYS_PTRACE \
        -v "$(realpath "$vout"):/tmp/vout" \
        -v "$(realpath "$REPLAY_PY"):/tmp/replay_protocol.py:ro" \
        -v "$(realpath "$VERIFY_PY"):/tmp/verify_oracle.py:ro" \
        -e "REPLAY_PROTO=$PROTO" -e "REPLAY_PORT=$PORT" \
        -e "REPLAY_IS_UDP=$IS_UDP" \
        -e "REQ_FILE=/tmp/vout/request_data.bin" \
        -e "RESP_FILE=/tmp/vout/response_data.bin" \
        -e "VERDICT_FILE=/tmp/vout/verdict.txt" \
        -e "REQ_BIN=/tmp/vout/request_data.bin" \
        -e "RESP_BIN=/tmp/vout/response_data.bin" \
        -e "$ENV_VARS" \
        "$IMAGE" /bin/bash -c "
cd $WORKDIR
$PRE_START
export $ENV_VARS
$SERVER_CMD &
SPID=\$!

LISTEN=0
for attempt in \$(seq 1 50); do
    sleep 0.1
    if grep -q ':0015 .*0A' /proc/net/tcp 2>/dev/null; then
        LISTEN=1; break
    fi
    if ! kill -0 \$SPID 2>/dev/null; then
        wait \$SPID 2>/dev/null || true
        echo '[FATAL] Server died on startup' | tee -a /tmp/vout/verdict.txt
        exit 1
    fi
done
[ \$LISTEN -eq 0 ] && { echo '[FATAL] Server failed to listen'; kill \$SPID 2>/dev/null; exit 1; }
echo \"Server PID: \$SPID (listening on $PORT)\"

python3 /tmp/replay_protocol.py 2>&1
python3 /tmp/verify_oracle.py 2>&1

kill \$SPID 2>/dev/null || true
wait \$SPID 2>/dev/null || true
" 2>&1 | tee "$vout/replay_full.log"

    if [ -f "$vout/verdict.txt" ]; then
        vc=$(grep -c "Confirmed" "$vout/verdict.txt" 2>/dev/null || echo "0")
        if [ "$vc" -gt 0 ] 2>/dev/null; then
            CONFIRMED=$((CONFIRMED + 1))
            echo "  [CONFIRMED] $vc oracle violation(s) verified"
        else
            echo "  [NOT REPRODUCED] via standalone replay"
        fi
    fi
done

# ── Step 3: Summary ─────────────────────────────────────────────────────
echo ""; echo "━━━ Step 3: Summary ━━━"
echo "Total tested : $TOTAL"
echo "Confirmed    : $CONFIRMED"
echo "Results      : $OUT_DIR"
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  FIX applied: Pre-authentication for garbled auth seeds    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "━━━ Done ━━━"
