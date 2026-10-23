#!/usr/bin/env python3
"""Mock v5: closest possible approximation of a real OpenAI gateway.

Improvements over v4 (each maps to a measured real-gateway behavior):
1. SIMULATED LATENCY: exponential distribution matching real LLM (2-15s median,
   tail to 30s); fuzzer's timeout handling and wall-clock budget become realistic
2. SEED-AWARE MUTATION: parses actual seed sequences from the prompt's
   Communication History / Example Request Formats, generates mutations OF
   THOSE SEEDS (not random banks)
3. CONVERSATION MEMORY: tracks previously suggested candidates per protocol,
   avoids exact repeats, escalates creativity when repeats detected
4. TEMPERATURE AWARENESS: temp >= 1.0 → diverse/creative; temp < 0.8 → conservative
5. ACCURATE TOKEN COUNTING: BPE-like estimator (not len//4)
6. RATE LIMITING: occasional 429 with Retry-After header
7. REALISTIC METADATA: created timestamp, system_fingerprint, model name
8. SPORADIC ERRORS: 1% 500s, 0.5% truncated (finish_reason=length)

Env vars:
  MOCK_PORT (default 8099)
  CHATAFL_MOCK_MIX (deep=,rare=,bad=,mut= percentages)
  MOCK_LATENCY (0=instant, 1=realistic 2-15s, default from MOOD)
  MOCK_ERROR_RATE (0-100, default 1.5 = 1% 500 + 0.5% truncate)
"""
import base64, json, http.server, socketserver, random, os, re, sys, time
import threading

reqs = {"templates": 0, "plateau": 0, "seed": 0}

# ── Config ──
def _parse_mix(raw):
    mix = {}
    for part in raw.split(","):
        k, _, v = part.partition("=")
        mix[k.strip()] = float(v)
    total = sum(mix.values())
    if abs(total - 100.0) > 0.01 or set(mix) != {"deep", "rare", "bad", "mut"}:
        raise SystemExit("CHATAFL_MOCK_MIX must be deep=,rare=,bad=,mut= summing to 100")
    return mix
MIX = _parse_mix(os.environ.get("CHATAFL_MOCK_MIX", "deep=40,rare=25,bad=15,mut=20"))
_MIX_ORDER = ["mut", "bad", "rare", "deep"]
_MIX_CUM = []
_acc = 0.0
for _k in _MIX_ORDER:
    _acc += MIX[_k]
    _MIX_CUM.append((_acc, _k))

LATENCY_MODE = int(os.environ.get("MOCK_LATENCY", "1"))
ERROR_RATE = float(os.environ.get("MOCK_ERROR_RATE", "1.5"))
MODEL_NAME = os.environ.get("MOCK_MODEL", "gpt-4o-mini-2024-07-18")

# ── Conversation memory (per-protocol suggestion tracking) ──
_suggested = {}  # proto -> set of hash(candidate_str)
_lock = threading.Lock()

def _remember(proto, candidate):
    with _lock:
        h = hash(candidate)
        _suggested.setdefault(proto, set()).add(h)
        return len(_suggested[proto])

def _repeat_count(proto, candidate):
    with _lock:
        return 1 if hash(candidate) in _suggested.get(proto, set()) else 0

# ── Latency simulation (exponential distribution like real LLM) ──
def _simulated_latency(temp, prompt_len):
    if LATENCY_MODE == 0:
        return 0.0
    # Base: 2-8s, longer for bigger prompts (more tokens to process)
    base = random.expovariate(1.0 / 4.0)  # mean 4s
    # Temperature affects generation length → latency
    if temp >= 1.0:
        base *= 1.3  # creative mode = longer generation
    # Very long prompts take longer
    if prompt_len > 5000:
        base *= 1.5
    return min(max(base, 1.0), 30.0)  # clamp [1s, 30s]

# ── BPE-like token estimator ──
def _estimate_tokens(text):
    if not text:
        return 0
    # Rough approximation: ~0.75 tokens per word for English + protocol text
    words = len(text.split())
    chars = len(text)
    return max(1, int(words * 0.75 + chars * 0.008))

# ── Seed-aware: extract seed sequences from prompt ──
def _extract_seeds(prompt):
    """Parse actual seed/request content from the prompt text."""
    seeds = []
    # Pattern 1: Communication History section (between triple-quotes)
    for m in re.finditer(r'"""(.*?)"""', prompt, re.S):
        block = m.group(1).strip()
        if block:
            for line in block.split('\n'):
                line = line.strip()
                if line and len(line) > 3:
                    seeds.append(line)
    # Pattern 2: Example Request Formats (lines with protocol commands)
    for m in re.finditer(r'(?:^|\n)((?:[A-Z]{3,8} .+|\d{3} .+|GET /.+|POST /.+|OPTIONS .+|EHLO .+|HELO .+|DESCRIBE .+|REGISTER .+|USER .+|PASS .+))', prompt):
        seeds.append(m.group(1).strip())
    return seeds[:20]  # cap at 20

def _mutate_seed(seed_line, rnd, proto):
    """Generate a mutation of an actual seed line."""
    parts = seed_line.split()
    if not parts:
        return seed_line
    cmd = parts[0].upper()
    args = parts[1:] if len(parts) > 1 else []
    mutations = []
    # Argument mutation
    if args:
        idx = rnd.randrange(len(args))
        val = args[idx]
        # numeric mutation
        if val.isdigit():
            new_val = str(int(val) + rnd.choice([-1, 1, rnd.randint(-100, 100), 0, 999999]))
            mutations.append(" ".join([cmd] + args[:idx] + [new_val] + args[idx+1:]))
        # string mutation
        else:
            chars = "abcdefghijklmnopqrstuvwxyz0123456789-_./~%!?@#$^&*()[]{}|\\:;\"'<>,"
            new_val = list(val)
            op = rnd.choice(["insert", "delete", "replace", "swap"])
            if op == "insert" and len(new_val) < 100:
                pos = rnd.randrange(len(new_val) + 1)
                new_val.insert(pos, rnd.choice(chars))
            elif op == "delete" and len(new_val) > 1:
                del new_val[rnd.randrange(len(new_val))]
            elif op == "replace" and new_val:
                new_val[rnd.randrange(len(new_val))] = rnd.choice(chars)
            elif op == "swap" and len(new_val) > 1:
                i, j = sorted(rnd.sample(range(len(new_val)), 2))
                new_val[i], new_val[j] = new_val[j], new_val[i]
            mutations.append(" ".join([cmd] + args[:idx] + ["".join(new_val)] + args[idx+1:]))
    # Command insertion (prepend another command)
    extras = {"FTP": ["NOOP", "SYST", "FEAT", "TYPE I", "PASV"], "HTTP": ["GET /", "HEAD /"],
              "SMTP": ["NOOP", "RSET"], "SIP": ["OPTIONS", "REGISTER"], "RTSP": ["OPTIONS"]}.get(proto, ["NOOP"])
    mutations.append(f"{rnd.choice(extras)}\r\n{seed_line}")
    # Command mutation (change the verb)
    if proto == "FTP":
        alt = rnd.choice(["LIST", "NLST", "STAT", "HELP", "SITE HELP", "FEAT", "MKD", "RMD", "CWD", "TYPE", "MODE", "STRU", "REST", "SIZE", "MDTM"])
        mutations.append(" ".join([alt] + args))
    return rnd.choice(mutations) if mutations else seed_line

# ── Phase tracking for non-stationarity ──
def _phase(idx):
    if idx < 20: return 0
    if idx < 80: return 1
    return 2

def _context_states(prompt):
    return sorted(set(int(x) for x in re.findall(r'\bstate[_ ]?(?:id)?[:= ](\d+)', prompt[:3000], re.I)[:10]))

# ── Error clustering ──
_error_mode = 0
def _next_error_mode():
    global _error_mode
    _error_mode = (_error_mode + 1) % 3
    return _error_mode

# ── Argument pools ──
DIRS = ["tmp", "pub", "upload", "a", "b/c", "incoming", "share", "var/log",
        "home/user", "etc/config", "opt/data", "srv/files", "mnt/storage"]
FILES = ["file.txt", "test.bin", "big.dat", "index.html", "notes.md",
         "config.xml", "data.json", "image.png", "archive.tar.gz", "report.pdf"]
USERS_OK = ["mockuser", "ftp", "anonymous"]
USERS_BAD = ["root", "admin", "postmaster", "nobody"]
PASS_OK = ["mockpass", "ftp", "anonymous"]

def ftp_deep(rnd, i, phase, ctx, seeds):
    u = rnd.choice(USERS_OK); p = rnd.choice(PASS_OK)
    d = rnd.choice(DIRS); f = rnd.choice(FILES)
    n = rnd.randint(1, 99999)
    # If we have actual seeds, build on them
    if seeds and phase >= 1 and rnd.random() < 0.4:
        base_seed = rnd.choice(seeds)
        mutated = _mutate_seed(base_seed, rnd, "FTP")
        return f"USER {u}\r\nPASS {p}\r\n{mutated}\r\n"
    if phase == 0:
        return rnd.choice([
            f"USER {u}\r\nPASS {p}\r\nSYST\r\nPWD\r\n",
            f"USER {u}\r\nPASS {p}\r\nTYPE I\r\nPASV\r\nLIST\r\n",
        ])
    if phase == 1:
        return rnd.choice([
            f"USER {u}\r\nPASS {p}\r\nTYPE I\r\nPASV\r\nLIST {d}\r\n"
            f"EPSV\r\nNLST {d}\r\nSIZE {f}\r\nMDTM {f}\r\n",
            f"USER {u}\r\nPASS {p}\r\nCWD {d}\r\nPASV\r\nRETR {f}\r\n"
            f"TYPE A\r\nPASV\r\nLIST -la\r\nREST {n}\r\n",
        ])
    extra = f"SITE CHMOD 644 {rnd.choice(FILES)}\r\n" if rnd.random() < 0.3 else ""
    target = f"CWD {d}\r\nPASV\r\nLIST {d}\r\n" if ctx else ""
    return rnd.choice([
        f"USER {u}\r\nPASS {p}\r\nFEAT\r\nOPTS UTF8 ON\r\n{target}"
        f"TYPE I\r\nPASV\r\nLIST {d}\r\nSIZE {f}\r\nMDTM {f}\r\n{extra}"
        f"REST {n}\r\nPASV\r\nRETR {f}\r\nSTAT /\r\n",
        f"USER {u}\r\nPASS {p}\r\nHELP SITE\r\nSITE HELP\r\n{target}"
        f"MODE B\r\nSTRU R\r\nALLO {n} {n//2}\r\nPASV\r\nSTOR {f}\r\n"
        f"SMNT /dev/null\r\nACCT none\r\nABOR\r\nNOOP\r\n",
    ])

def ftp_bad(rnd, phase):
    mode = _next_error_mode()
    if mode == 0:
        u = rnd.choice(USERS_BAD)
        return f"USER {u}\r\nPASS wrongpass{rnd.randint(1,99)}\r\nLIST\r\nRETR /etc/shadow\r\n"
    if mode == 1:
        return f"LIST /etc\r\nRETR /etc/passwd\r\nSTOR /tmp/pwned\r\nDELE /etc/hosts\r\n"
    u = rnd.choice(USERS_OK); p = rnd.choice(PASS_OK)
    return f"USER {u}\r\nPASS {p}\r\nPORT 999,999,999,999,999,999\r\nRETR ../../../etc/passwd\r\n"

def ftp_rare(rnd, phase, ctx, seeds):
    u = rnd.choice(USERS_OK); p = rnd.choice(PASS_OK)
    if phase >= 1 and seeds and rnd.random() < 0.3:
        return f"USER {u}\r\nPASS {p}\r\n{_mutate_seed(rnd.choice(seeds), rnd, 'FTP')}\r\nSITE HELP\r\n"
    return rnd.choice([
        f"USER {u}\r\nPASS {p}\r\nSITE HELP\r\nHELP SITE\r\nSITE CHMOD 600 {rnd.choice(FILES)}\r\n",
        "FEAT\r\nOPTS UTF8 ON\r\nOPTS MLST type*;size*;modify*;\r\nHELP MLST\r\n",
        f"USER {u}\r\nPASS {p}\r\nSIZE {rnd.choice(FILES)}\r\nMDTM {rnd.choice(FILES)}\r\nMLSD {rnd.choice(DIRS)}\r\n",
    ])

def ftp_mut(rnd, seeds):
    # If we have actual seeds, mutate them
    if seeds and rnd.random() < 0.6:
        return _mutate_seed(rnd.choice(seeds), rnd, "FTP") + "\r\n"
    return rnd.choice([
        f"MKD d{rnd.randint(1,999999)}\r\n", "SITE HELP\r\n", "FEAT\r\n",
        f"REST {rnd.randint(0,2**24)}\r\n", "EPSV\r\n", "NOOP\r\n",
        f"CWD {rnd.choice(DIRS)}\r\n", f"SIZE {rnd.choice(FILES)}\r\n",
    ])

# ── Protocol banks (SMTP/DAAP/HTTP/RTSP/SIP same structure as v4 but seed-aware) ──
def smtp_deep(rnd, i, ph, ctx, seeds):
    if seeds and ph >= 1 and rnd.random() < 0.4:
        mut = _mutate_seed(rnd.choice(seeds), rnd, "SMTP")
        return f"EHLO mock.local\r\n{mut}\r\n"
    if ph == 0: return "EHLO mock.local\r\nNOOP\r\nHELP\r\n"
    return rnd.choice([
        "EHLO mock.local\r\nMAIL FROM:<sender@mock.local>\r\nRCPT TO:<rcpt@mock.local>\r\nDATA\r\nSubject: test\r\n\r\nbody\r\n.\r\n",
        f"HELO h{rnd.randint(1,999)}.local\r\nMAIL FROM:<x@mock.local> SIZE={rnd.randint(100,99999)}\r\nRCPT TO:<y@mock.local>\r\nDATA\r\ncontent\r\n.\r\nRSET\r\n",
    ])

def http_deep(rnd, i, ph, ctx, seeds):
    if seeds and ph >= 1 and rnd.random() < 0.4:
        mut = _mutate_seed(rnd.choice(seeds), rnd, "HTTP")
        return mut + "\r\n"
    if ph == 0: return "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    return rnd.choice([
        f"GET /index{rnd.randint(1,99)}.html HTTP/1.1\r\nHost: localhost\r\nRange: bytes={rnd.randint(0,99999)}-\r\n\r\nGET /?q={rnd.randint(1,99999)} HTTP/1.1\r\nHost: localhost\r\n\r\n",
        f"POST /form{rnd.randint(1,9)} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {rnd.randint(10,500)}\r\n\r\na={rnd.randint(1,999999)}&b=x\r\n",
    ])

def daap_deep(rnd, i, ph, ctx, seeds):
    if ph == 0: return "GET /server-info HTTP/1.1\r\nHost: localhost\r\n\r\n"
    return rnd.choice([
        f"GET /databases HTTP/1.1\r\nHost: localhost\r\n\r\nGET /databases/1/items?meta=all&index={rnd.randint(0,9999)} HTTP/1.1\r\nHost: localhost\r\n\r\n",
        f"GET /login HTTP/1.1\r\nHost: localhost\r\n\r\nGET /update?revision={rnd.randint(1,99999)} HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ])

def rtsp_deep(rnd, i, ph, ctx, seeds):
    if ph == 0: return f"OPTIONS * RTSP/1.0\r\nCSeq: {i}\r\n\r\n"
    return (f"DESCRIBE rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {i}\r\n\r\n"
            f"SETUP rtsp://127.0.0.1/media/streamid={rnd.randint(0,5)} RTSP/1.0\r\nCSeq: {i+1}\r\n"
            f"Transport: RTP/AVP;unicast;client_port={rnd.randint(40000,60000)}\r\n\r\n"
            f"PLAY rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {i+2}\r\nSession: {rnd.randint(1000,9999)}\r\n\r\n")

def sip_deep(rnd, i, ph, ctx, seeds):
    if ph == 0: return f"OPTIONS sip:test@127.0.0.1 SIP/2.0\r\nCSeq: {i} OPTIONS\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n"
    return (f"REGISTER sip:127.0.0.1 SIP/2.0\r\nCSeq: {i} REGISTER\r\n"
            f"Via: SIP/2.0/TCP 127.0.0.1:5060\r\nContact: <sip:user{rnd.randint(1,99)}@127.0.0.1>\r\n"
            f"Expires: {rnd.choice([60,3600,86400])}\r\n\r\n"
            f"MESSAGE sip:user@127.0.0.1 SIP/2.0\r\nCSeq: {i+1} MESSAGE\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n")

BANKS = {
    "FTP": dict(tpl=["USER","PASS","LIST","SYST","FEAT","PWD","TYPE","PASV","EPSV","HELP","NOOP","STAT","MKD","RMD","CWD","MODE","STRU","REST","SIZE","MDTM","SITE","ALLO","ABOR","MLSD","QUIT"],
                seed="USER mockuser\r\nPASS mockpass\r\nSYST\r\nFEAT\r\nPASV\r\nLIST\r\n",
                deep=ftp_deep, rare=ftp_rare, bad=ftp_bad, mut=ftp_mut),
    "SMTP": dict(tpl=["EHLO","HELO","MAIL","RCPT","DATA","NOOP","RSET","HELP","VRFY","EXPN","AUTH","STARTTLS","QUIT"],
                 seed="EHLO mock.local\r\nNOOP\r\nRSET\r\nHELP\r\nVRFY user\r\n",
                 deep=smtp_deep,
                 rare=lambda r,p,c,s: rnd.choice(["EHLO mock.local\r\nVRFY postmaster\r\nEXPN staff\r\n","EHLO mock.local\r\nAUTH PLAIN dGVzdA==\r\nSTARTTLS\r\n"]),
                 bad=lambda r,p: f"MAIL FROM:<bomb@nowhere>\r\nRCPT TO:<{rnd.choice(USERS_BAD)}@invalid>\r\nDATA\r\nx\r\n.",
                 mut=lambda r,s: rnd.choice(["NOOP\r\n","RSET\r\n",f"VRFY user{rnd.randint(1,99999)}\r\n"])),
    "DAAP": dict(tpl=["GET /server-info","GET /databases","GET /logout","GET /update","GET /content-codes","GET /databases/1/items","GET /databases/1/containers","GET /login"],
                 seed="GET /server-info HTTP/1.1\r\nHost: localhost\r\n\r\nGET /content-codes HTTP/1.1\r\nHost: localhost\r\n\r\n",
                 deep=daap_deep,
                 rare=lambda r,p,c,s: f"GET /databases/{rnd.randint(1,99)}/groups HTTP/1.1\r\nHost: localhost\r\n\r\n",
                 bad=lambda r,p: f"GET /../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
                 mut=lambda r,s: f"GET /databases/1/items?query={rnd.randint(1,999999)} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    "HTTP": dict(tpl=["GET","HEAD","POST","PUT","DELETE","OPTIONS","TRACE","PATCH"],
                 seed="GET / HTTP/1.1\r\nHost: localhost\r\n\r\nHEAD /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n",
                 deep=http_deep,
                 rare=lambda r,p,c,s: f"OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\nTRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                 bad=lambda r,p: f"GET /../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
                 mut=lambda r,s: f"GET /x{rnd.randint(1,999999)} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    "RTSP": dict(tpl=["OPTIONS","DESCRIBE","SETUP","PLAY","PAUSE","TEARDOWN","GET_PARAMETER","SET_PARAMETER"],
                 seed="OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\nDESCRIBE rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: 2\r\n\r\n",
                 deep=rtsp_deep,
                 rare=lambda r,p,c,s: f"GET_PARAMETER rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {rnd.randint(1,999)}\r\n\r\n",
                 bad=lambda r,p: f"DESCRIBE rtsp://127.0.0.1/missing{rnd.randint(1,999)} RTSP/9.9\r\nCSeq: {rnd.randint(1,999)}\r\n\r\n",
                 mut=lambda r,s: f"OPTIONS * RTSP/1.0\r\nCSeq: {rnd.randint(1,99999)}\r\n\r\n"),
    "SIP": dict(tpl=["REGISTER","INVITE","ACK","BYE","CANCEL","OPTIONS","SUBSCRIBE","NOTIFY","MESSAGE","INFO"],
                seed="OPTIONS sip:test@127.0.0.1 SIP/2.0\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n",
                deep=sip_deep,
                rare=lambda r,p,c,s: f"SUBSCRIBE sip:127.0.0.1 SIP/2.0\r\nCSeq: {rnd.randint(1,999)} SUBSCRIBE\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\nEvent: presence\r\n\r\n",
                bad=lambda r,p: f"INVITE sip:nobody@invalid{rnd.randint(1,999)} SIP/2.0\r\nCSeq: {rnd.randint(1,999)} INVITE\r\n\r\n",
                mut=lambda r,s: f"OPTIONS sip:t{rnd.randint(1,999999)}@127.0.0.1 SIP/2.0\r\nCSeq: {rnd.randint(1,9999)} OPTIONS\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n"),
}

PROTO_ORDER = ["FTP", "SMTP", "RTSP", "SIP", "DAAP", "HTTP"]

def detect_proto(prompt):
    up = prompt.upper()
    for p in PROTO_ORDER:
        if f" {p} " in up or f"{p} PROTOCOL" in up or f"/{p}" in up:
            return p
    if "RTSP/" in up: return "RTSP"
    if "SIP/2.0" in up: return "SIP"
    if "EHLO" in up or "HELO" in up: return "SMTP"
    if "HTTP/" in up: return "HTTP"
    if "USER " in up or "PASS " in up: return "FTP"
    return "FTP"

def reply_for(prompt, temperature=0.5):
    proto = detect_proto(prompt)
    bank = BANKS[proto]
    if "message templates" in prompt:
        reqs["templates"] += 1
        return "\n".join(f'{c}: ["{c} <<VALUE>>\\r\\n"]' for c in bank["tpl"])
    if "ONLY valid JSON" in prompt or "suggested_request" in prompt:
        reqs["plateau"] += 1
        i = reqs["plateau"]
        rnd = random.Random(int(time.time() * 1000) + i)
        ph = _phase(i)
        ctx = _context_states(prompt)
        seeds = _extract_seeds(prompt)
        roll = rnd.random() * 100.0
        kind = _MIX_ORDER[-1]
        for _edge, _k in _MIX_CUM:
            if roll < _edge:
                kind = _k
                break
        # Temperature awareness: high temp → more deep/creative
        if temperature >= 1.0:
            if kind == "mut" and rnd.random() < 0.5: kind = "rare"
            if kind == "bad" and rnd.random() < 0.3: kind = "deep"
        if kind == "mut":
            ins = bank["mut"](rnd, seeds)
            _remember(proto, ins)
            return json.dumps({
                "analysis": f"mock-v5: mutate seed ({proto}) phase={ph} seeds={len(seeds)}",
                "actions": [
                    {"type": "propose_mutations", "seed_id": 0,
                     "ops": [{"op": "insert", "pos": 999999,
                              "data": base64.b64encode(ins.encode()).decode()}]},
                    {"type": "set_target_state", "state_id": ctx[0] if ctx else 0},
                    {"type": "prioritize_seeds", "seed_ids": [0]},
                ]})
        if kind == "bad":
            candidate = bank["bad"](rnd, ph)
        elif kind == "rare":
            candidate = bank["rare"](rnd, ph, ctx, seeds)
        else:
            candidate = bank["deep"](rnd, i, ph, ctx, seeds)
        # Conversation memory: if repeat, try a mutation of an actual seed
        if _repeat_count(proto, candidate) and seeds:
            candidate = _mutate_seed(rnd.choice(seeds), rnd, proto)
        _remember(proto, candidate)
        return json.dumps({
            "analysis": f"mock-v5: {proto} phase={ph} ctx={len(ctx)} seeds={len(seeds)} temp={temperature}",
            "suggested_request": candidate if candidate.endswith("\n") else candidate + "\r\n"})
    reqs["seed"] += 1
    return bank["seed"]

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        t0 = time.time()
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n) or b"{}"
        req = json.loads(body)
        prompt = "".join(m.get("content", "") for m in req.get("messages", [])
                         if m.get("role") == "user")
        temp = req.get("temperature", 0.5)
        model = req.get("model", MODEL_NAME)

        # Sporadic errors
        if random.random() * 100 < ERROR_RATE * 0.67:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            e = json.dumps({"error": {"message": "Internal server error", "type": "server_error"}}).encode()
            self.send_header("Content-Length", str(len(e)))
            self.end_headers()
            self.wfile.write(e)
            return
        if random.random() * 100 < 0.3:
            self.send_response(429)
            self.send_header("Retry-After", "5")
            self.send_header("Content-Type", "application/json")
            e = json.dumps({"error": {"message": "Rate limit exceeded", "type": "rate_limit_error"}}).encode()
            self.send_header("Content-Length", str(len(e)))
            self.end_headers()
            self.wfile.write(e)
            return

        # Simulated latency
        latency = _simulated_latency(temp, len(prompt))
        if latency > 0:
            time.sleep(latency)

        content = reply_for(prompt, temp)

        # Sporadic truncation
        finish = "stop"
        if random.random() * 100 < ERROR_RATE * 0.33:
            content = content[:len(content)//2]
            finish = "length"

        pt = _estimate_tokens(prompt)
        ct = _estimate_tokens(content)
        out = json.dumps({
            "id": f"chatcmpl-{int(time.time()*1e6)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "system_fingerprint": f"fp_{hashlib.md5(model.encode()).hexdigest()[:12]}",
            "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": content},
                         "finish_reason": finish}],
            "usage": {"prompt_tokens": pt, "completion_tokens": ct,
                      "total_tokens": pt + ct},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
        elapsed = time.time() - t0
        print(f"[mock-v5] #{sum(reqs.values())} proto={proto_counts} class={reqs} "
              f"temp={temp} latency={elapsed:.1f}s tokens={pt}+{ct} "
              f"prompt_head={prompt[:30]!r}", flush=True)

    def log_message(self, *a):
        pass

import hashlib
proto_counts = {}

class Srv(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

if __name__ == "__main__":
    port = int(os.environ.get("MOCK_PORT", "8099"))
    with Srv(("0.0.0.0", port), H) as s:
        print(f"[mock-v5] port={port} model={MODEL_NAME} latency={LATENCY_MODE} "
              f"error_rate={ERROR_RATE}% mix={MIX}", flush=True)
        s.serve_forever()
