#!/usr/bin/env python3
"""Fixed Protocol oracle verification — aligned with protocol-oracle.c logic.
Checks security invariants on replayed data for FTP, SMTP, RTSP, SIP, MQTT, HTTP, DAAP."""
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
    """Extract first 3-digit response code from bytes."""
    try:
        for line in resp_bytes.decode('latin-1', errors='replace').split('\n'):
            s = line.strip()
            if len(s) >= 3 and s[:3].isdigit(): return int(s[:3])
    except: pass
    return None

# ═══════════════════════════════════════════════════════════════════
# FTP Oracle — aligned with protocol-oracle.c oracle_check_ftp()
# ═══════════════════════════════════════════════════════════════════

def verify_ftp(req, resp):
    """FTP oracle verification — aligned with protocol-oracle.c logic."""
    findings = []; auth = False; has_user = False; has_rnfr = False
    failed_auth_no_user = 0
    lines_raw = req.split(b'\n')  # keep raw bytes
    resp_parts = resp.split(b'\n---\n')

    def resp_code_for(idx):
        if idx < len(resp_parts):
            c = code3(resp_parts[idx])
            if c: return c
        return None

    # ── Phase 1: State tracking ──
    for i in range(len(lines_raw)):
        line_raw = lines_raw[i]
        line = line_raw.strip(b'\r')
        upper = line.decode('latin-1', errors='replace').upper()
        rc = resp_code_for(i)

        if upper.startswith('USER ') and rc == 331:
            has_user = True; auth = False

        if upper.startswith('PASS '):
            if has_user:
                if rc == 230: auth = True
            else:
                if rc == 230:
                    findings.append({'sev':'HIGH','cat':'AUTH_BYPASS','cwe':'CWE-862',
                        'desc':'FTP: PASS accepted without USER (auth state bypass)',
                        'cve':'CVE-2024-42644'})
                elif rc and rc >= 500:
                    failed_auth_no_user += 1

        if rc == 230: auth = True
        if upper.startswith('RNFR '): has_rnfr = True

        if upper.startswith('RNTO ') and not has_rnfr:
            if rc is None or rc < 500:
                findings.append({'sev':'MEDIUM','cat':'STATE_VIOLATION','cwe':'CWE-696',
                    'desc':'FTP: RNTO without prior RNFR accepted by server','cve':'N/A'})

        data_cmds = ['RETR ','STOR ','LIST','NLST','MKD ','RMD ','DELE ','APPE ','SITE ']
        if any(upper.startswith(c) for c in data_cmds) and not auth:
            if rc in (150, 225, 226):
                findings.append({'sev':'CRITICAL','cat':'AUTH_BYPASS','cwe':'CWE-306',
                    'desc':f"FTP: Data command succeeded without auth: {str(line[:60])} (code {rc})",
                    'cve':'CVE-2024-42645'})

        if b'../' in line_raw or b'..\\\\' in line_raw or b'%2e%2e' in line_raw.lower():
            if rc is not None and 150 <= rc <= 250:
                findings.append({'sev':'HIGH','cat':'PATH_TRAVERSAL','cwe':'CWE-22',
                    'desc':f"FTP: Path traversal accepted: {str(line[:60])} (code {rc})",
                    'cve':'CVE-2024-3935'})

    # ── Phase 2: CRLF injection (scan raw line after first space for \\r\\n) ──
    for line_raw in lines_raw:
        space_idx = line_raw.find(b' ')
        if space_idx > 0 and space_idx + 2 < len(line_raw):
            if line_raw[space_idx+1:].find(b'\r\n') >= 0:
                findings.append({'sev':'HIGH','cat':'INJECTION','cwe':'CWE-93',
                    'desc':'FTP: CRLF injection in command arguments (FTP command smuggling)',
                    'cve':'CVE-2026-39983'})
                break

    # ── Phase 3: PORT bounce (sscanf-like regex) ──
    port_re = re.compile(r'PORT\s+(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})', re.I)
    for line in lines_raw:
        try: text = line.decode('latin-1', errors='replace')
        except: continue
        m = port_re.search(text)
        if m:
            h1,h2,h3,h4 = int(m.group(1)),int(m.group(2)),int(m.group(3)),int(m.group(4))
            if (h1==10 or (h1==172 and 16<=h2<=31) or (h1==192 and h2==168) or h1==127 or (h1==169 and h2==254)):
                findings.append({'sev':'MEDIUM','cat':'ISOLATION','cwe':'CWE-441',
                    'desc':'FTP: PORT command specifies private/internal address (FTP bounce risk)',
                    'cve':'CVE-2018-15516'})
                break

    # ── Phase 4: Format string (>=3 specifiers) ──
    for line in lines_raw:
        cnt = sum(line.count(s) for s in [b'%n',b'%s',b'%x',b'%d',b'%p'])
        if cnt >= 3:
            findings.append({'sev':'MEDIUM','cat':'INJECTION','cwe':'CWE-134',
                'desc':f"FTP: Multiple format string specifiers (count={cnt})",
                'cve':'CVE-2006-6750'})
            break

    # ── Phase 5: Resource exhaustion (>20 failed PASS w/o USER) ──
    if failed_auth_no_user > 20:
        findings.append({'sev':'LOW','cat':'RESOURCE_EXHAUSTION','cwe':'CWE-307',
            'desc':f'FTP: Excessive failed auth attempts ({failed_auth_no_user}) without rate limiting',
            'cve':'CVE-2026-41324'})

    # ── Phase 6: Info leak ──
    for i, r in enumerate(resp_parts):
        if b'root:' in r or b'/etc/passwd' in r or b'/etc/shadow' in r:
            findings.append({'sev':'CRITICAL','cat':'INFO_LEAK','cwe':'CWE-200',
                'desc':f'FTP: Sensitive file content leaked in response #{i}',
                'cve':'CVE-2024-42650'})
        if b'LightFTP server' in r or b'Server version' in r or b'/home/' in r:
            findings.append({'sev':'INFO','cat':'INFO_LEAK','cwe':'CWE-200',
                'desc':'FTP: Server version/internal path disclosed','cve':'N/A'})

    return findings

# ═══════════════════════════════════════════════════════════════════
# Other protocol oracles (SMTP, RTSP, SIP, MQTT, HTTP — unchanged)
# ═══════════════════════════════════════════════════════════════════

def verify_smtp(req, resp):
    findings = []; mail_from = False
    lines = req.split(b'\n'); resp_parts = resp.split(b'\n---\n')
    for i, line in enumerate(lines):
        line = line.strip(b'\r'); upper = line.decode('latin-1',errors='replace').upper()
        ri = resp_parts[i] if i < len(resp_parts) else b''
        if (upper.startswith('RCPT TO:') or upper.startswith('DATA')) and not mail_from:
            c = code3(ri)
            if c and c < 400: findings.append({'sev':'HIGH','cat':'AUTH_BYPASS','cwe':'CWE-306',
                'desc':f"Open relay: {str(line[:50])} code {c}",'cve':'CVE-2023-42117'})
        if upper.startswith('MAIL FROM:'): mail_from = True
        if upper.startswith('RCPT TO:') and not mail_from:
            c = code3(ri)
            if c and c < 400: findings.append({'sev':'MEDIUM','cat':'STATE_VIOLATION','cwe':'CWE-696',
                'desc':'RCPT before MAIL FROM','cve':'N/A'})
        if b'\r\n' in line and (b'MAIL FROM:' in upper.encode() or b'RCPT TO:' in upper.encode()):
            findings.append({'sev':'HIGH','cat':'SMUGGLING','cwe':'CWE-93',
                'desc':f"CRLF in addr: {str(line[:50])}",'cve':'CVE-2023-42117'})
    return findings

def verify_rtsp(req, resp):
    findings = []; setup_urls = set()
    lines = req.split(b'\n'); resp_parts = resp.split(b'\n---\n')
    for i, line in enumerate(lines):
        line = line.strip(b'\r'); upper = line.decode('latin-1',errors='replace').upper()
        ri = resp_parts[i] if i < len(resp_parts) else b''
        if upper.startswith('SETUP '):
            parts = line.split()
            if len(parts) >= 2:
                url = parts[1].decode('latin-1',errors='replace')
                if url in setup_urls:
                    c = code3(ri)
                    if c and c < 400: findings.append({'sev':'HIGH','cat':'DUPLICATE_SETUP','cwe':'CWE-416',
                        'desc':f'Duplicate SETUP: {url}','cve':'CVE-2019-7314'})
                else: setup_urls.add(url)
        if upper.startswith('PLAY ') and not setup_urls:
            c = code3(ri)
            if c and c < 400: findings.append({'sev':'HIGH','cat':'STATE_VIOLATION','cwe':'CWE-696',
                'desc':'PLAY before SETUP','cve':'CVE-2021-38382'})
    return findings

def verify_mqtt(req, resp):
    findings = []
    req_text = req.decode("latin-1", errors="replace")
    resp_text = resp.decode("latin-1", errors="replace")
    if "$SYS" in req_text:
        findings.append({"sev":"HIGH","cat":"ACL_BYPASS","cwe":"CWE-284",
            "desc":"Access to $SYS topic attempted","cve":"CVE-2017-7650"})
    if resp_text.count("$SYS/broker/") > 3:
        findings.append({"sev":"HIGH","cat":"INFO_LEAK","cwe":"CWE-200",
            "desc":f"$SYS system data leaked in response ({resp_text.count('$SYS/broker/')} topics)","cve":"N/A"})
    return findings

def verify_sip(req, resp):
    findings = []; invite_seen = False; via_count = 0
    resp_parts = resp.split(b'\n---\n')
    msgs = []; offset = 0
    while offset + 4 <= len(req):
        size = struct.unpack('<I', req[offset:offset+4])[0]; offset += 4
        if size == 0 or offset + size > len(req):
            r = req[offset-4:]
            if r.strip(): msgs.append(r)
            break
        msgs.append(req[offset:offset+size]); offset += size
    for mi, msg in enumerate(msgs):
        try: text = msg.decode('latin-1',errors='replace')
        except: text = ''
        upper = text.upper(); ri = resp_parts[mi] if mi < len(resp_parts) else b''
        if upper.startswith('MESSAGE ') and 'AUTHORIZATION:' not in upper:
            findings.append({'sev':'HIGH','cat':'AUTH_BYPASS','cwe':'CWE-862',
                'desc':'MESSAGE without Authorization','cve':'CVE-2021-37624'})
        via_count += text.count('Via:')
        if via_count > 20: findings.append({'sev':'MEDIUM','cat':'DOS_AMPLIFICATION','cwe':'CWE-770',
            'desc':f'Excessive Via headers ({via_count})','cve':'CVE-2020-28361'})
        if upper.startswith('ACK ') and not invite_seen: findings.append({'sev':'LOW','cat':'STATE_VIOLATION','cwe':'CWE-696',
            'desc':'ACK without INVITE','cve':'N/A'})
        if upper.startswith('INVITE '): invite_seen = True
    return findings

def verify_http(req, resp):
    findings = []
    resp_parts = resp.split(b'\n---\n')
    lines = req.split(b'\n'); ri_idx = 0
    for i, line in enumerate(lines):
        line_s = line.strip(b'\r'); upper = line_s.decode('latin-1',errors='replace').upper()
        ri = resp_parts[ri_idx] if ri_idx < len(resp_parts) else b''
        if b'/../' in line_s or b'..%2f' in line_s.lower() or b'%2e%2e' in line_s.lower():
            c = code3(ri)
            if c and c < 400:
                findings.append({'sev':'HIGH','cat':'PATH_TRAVERSAL','cwe':'CWE-22',
                    'desc':f"Path traversal: {str(line_s[:80])} (code {c})",'cve':'CVE-2021-42013'})
        cnt_cl = sum(1 for l2 in lines if l2.strip(b'\r').decode('latin-1',errors='replace').upper().startswith('CONTENT-LENGTH:'))
        if cnt_cl > 1:
            findings.append({'sev':'HIGH','cat':'SMUGGLING','cwe':'CWE-444',
                'desc':f"Multiple Content-Length headers ({cnt_cl})",'cve':'CVE-2023-25690'})
        has_cl = any(l.strip(b'\r').decode('latin-1',errors='replace').upper().startswith('CONTENT-LENGTH:') for l in lines)
        has_te = any(l.strip(b'\r').decode('latin-1',errors='replace').upper().startswith('TRANSFER-ENCODING:') for l in lines)
        if has_cl and has_te:
            findings.append({'sev':'HIGH','cat':'SMUGGLING','cwe':'CWE-444',
                'desc':'Both Content-Length and Transfer-Encoding present','cve':'CVE-2023-44487'})
        if line_s and not line_s.startswith(b' '): ri_idx += 1
    return findings

verify_daap = verify_http

# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

req = load(REQ_BIN); resp = load(RESP_BIN)
if not req:
    print('No request data'); sys.exit(0)
print(f'Verifying {PROTO} ... req={len(req)}B resp={len(resp)}B')
fn_map = {"FTP": verify_ftp, "SMTP": verify_smtp, "RTSP": verify_rtsp,
          "SIP": verify_sip, "MQTT": verify_mqtt, "HTTP": verify_http, "DAAP": verify_http}
findings = fn_map.get(PROTO, lambda r,q: [])(req, resp)
with open(VERDICT_FILE, 'a') as f:
    if findings:
        f.write(f'\n=== ORACLE: {len(findings)} violation(s) confirmed ===\n')
        for i, fd in enumerate(findings):
            f.write(f"\n--- Confirmed #{i+1} ---\n  Severity: {fd['sev']}\n  Category: {fd['cat']}\n  CWE: {fd['cwe']}\n  Description: {fd['desc']}\n  CVE Pattern: {fd['cve']}\n")
    else:
        f.write('\n=== ORACLE: 0 violations confirmed ===\n')
        f.write('Request did not violate protocol security invariants in standalone replay.\n')
print(f'Done: {len(findings)} violation(s)')
for fd in findings: print(f"  [{fd['sev']}] {fd['cat']}: {fd['desc']}")
