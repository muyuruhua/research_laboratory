#!/usr/bin/env python3
"""Mock v4: addresses every gap identified in the mock-vs-real analysis.

Improvements over v3:
1. NON-STATIONARITY: candidates evolve — early campaign gets conservative
   probes, later gets sophisticated deep sequences (mimics LLM learning)
2. CONTEXT AWARENESS: parses prompt for state IDs / target states and
   generates candidates that target those specific states
3. ERROR CLUSTERING: bad candidates cluster by failure mode (auth, sequence,
   parameter) instead of uniform junk
4. HIGHER QUALITY: expanded deep-session banks with protocol-specific
   multi-step sequences that exercise real code paths
5. LONG-TAIL DIVERSITY: combinatorial argument generation prevents saturation

Same reply contract as v2/v3 (chat completions, configurable port & mix).
"""
import base64, json, http.server, socketserver, random, os, re, sys

reqs = {"templates": 0, "plateau": 0, "seed": 0}

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

# ── Non-stationarity: candidate sophistication scales with campaign progress ──
def _phase(idx):
    """0=early(conservative), 1=mid(exploring), 2=late(sophisticated)"""
    if idx < 20: return 0
    if idx < 80: return 1
    return 2

# ── Context awareness: extract state hints from prompt ──
def _context_states(prompt):
    """Extract numeric state IDs mentioned in the prompt."""
    return sorted(set(int(x) for x in re.findall(r'\bstate[_ ]?(?:id)?[:= ](\d+)', prompt[:3000], re.I)[:10]))

# ── Error clustering: pick a failure mode and stick with it for consecutive candidates ──
_error_mode = 0
def _next_error_mode():
    global _error_mode
    _error_mode = (_error_mode + 1) % 3  # cycle: auth -> sequence -> parameter
    return _error_mode

# ── Long-tail diversity: combinatorial argument generation ──
DIRS = ["tmp", "pub", "upload", "a", "b/c", "incoming", "share", "var/log",
        "home/user", "etc/config", "opt/data", "srv/files", "mnt/storage"]
FILES = ["file.txt", "test.bin", "big.dat", "index.html", "notes.md",
         "config.xml", "data.json", "image.png", "archive.tar.gz", "report.pdf"]
USERS_OK = ["mockuser", "ftp", "anonymous"]
USERS_BAD = ["root", "admin", "postmaster", "nobody"]
PASS_OK = ["mockpass", "ftp", "anonymous"]

def ftp_deep(rnd, i, phase, ctx_states):
    u = rnd.choice(USERS_OK); p = rnd.choice(PASS_OK)
    d = rnd.choice(DIRS); f = rnd.choice(FILES)
    n = rnd.randint(1, 99999)
    if phase == 0:  # early: simple login + one command
        return rnd.choice([
            f"USER {u}\r\nPASS {p}\r\nSYST\r\nPWD\r\n",
            f"USER {u}\r\nPASS {p}\r\nTYPE I\r\nPASV\r\nLIST\r\n",
        ])
    if phase == 1:  # mid: multi-step with transfers
        return rnd.choice([
            f"USER {u}\r\nPASS {p}\r\nTYPE I\r\nPASV\r\nLIST {d}\r\n"
            f"EPSV\r\nNLST {d}\r\nSIZE {f}\r\nMDTM {f}\r\n",
            f"USER {u}\r\nPASS {p}\r\nCWD {d}\r\nPASV\r\nRETR {f}\r\n"
            f"TYPE A\r\nPASV\r\nLIST -la\r\nREST {n}\r\n",
            f"USER {u}\r\nPASS {p}\r\nMODE S\r\nSTRU F\r\nALLO {n}\r\n"
            f"PASV\r\nSTOR {f}\r\nPASV\r\nAPPE {f}\r\nSTAT\r\n",
        ])
    # late: sophisticated sequences with rare commands + state targeting
    extra = f"SITE CHMOD 644 {rnd.choice(FILES)}\r\n" if rnd.random() < 0.3 else ""
    target = f"CWD {d}\r\nPASV\r\nLIST {d}\r\n" if ctx_states else ""
    return rnd.choice([
        f"USER {u}\r\nPASS {p}\r\nFEAT\r\nOPTS UTF8 ON\r\n{target}"
        f"TYPE I\r\nPASV\r\nLIST {d}\r\nSIZE {f}\r\nMDTM {f}\r\n{extra}"
        f"REST {n}\r\nPASV\r\nRETR {f}\r\nSTAT /\r\n",
        f"USER {u}\r\nPASS {p}\r\nHELP SITE\r\nSITE HELP\r\n{target}"
        f"MODE B\r\nSTRU R\r\nALLO {n} {n//2}\r\nPASV\r\nSTOR {f}\r\n"
        f"SMNT /dev/null\r\nACCT none\r\nABOR\r\nNOOP\r\n",
        f"USER {u}\r\nPASS {p}\r\nLPRT 4,4,127,0,0,1,2,{n%20000+20000},{n%256}\r\n"
        f"LPSV\r\n{target}TYPE L 8\r\nSTRU F\r\nMODE S\r\nPASV\r\nNLST {d}\r\n"
        f"MKD {d}/new{n}\r\nRMD {d}/old\r\nPWD\r\nCDUP\r\n",
    ])

def ftp_bad(rnd, phase):
    mode = _next_error_mode()
    if mode == 0:  # auth cluster
        u = rnd.choice(USERS_BAD)
        return f"USER {u}\r\nPASS wrongpass{rnd.randint(1,99)}\r\nLIST\r\nRETR /etc/shadow\r\n"
    if mode == 1:  # sequence cluster (skip auth, go straight to commands)
        return f"LIST /etc\r\nRETR /etc/passwd\r\nSTOR /tmp/pwned\r\nDELE /etc/hosts\r\n"
    # parameter cluster (valid auth, malformed args)
    u = rnd.choice(USERS_OK); p = rnd.choice(PASS_OK)
    return f"USER {u}\r\nPASS {p}\r\nPORT 999,999,999,999,999,999\r\nRETR ../../../etc/passwd\r\n"

def ftp_rare(rnd, phase, ctx_states):
    u = rnd.choice(USERS_OK); p = rnd.choice(PASS_OK)
    if phase == 2 and ctx_states:
        st = ctx_states[0]
        return f"USER {u}\r\nPASS {p}\r\nSTAT /proc/{st}\r\nSITE HELP\r\nFEAT\r\n"
    return rnd.choice([
        f"USER {u}\r\nPASS {p}\r\nSITE HELP\r\nHELP SITE\r\nSITE CHMOD 600 {rnd.choice(FILES)}\r\n",
        "FEAT\r\nOPTS UTF8 ON\r\nOPTS MLST type*;size*;modify*;\r\nHELP MLST\r\n",
        f"USER {u}\r\nPASS {p}\r\nSIZE {rnd.choice(FILES)}\r\nMDTM {rnd.choice(FILES)}\r\nMLSD {rnd.choice(DIRS)}\r\n",
        "ALLO 0\r\nNOOP\r\nNOOP\r\nNOOP\r\nTYPE L 7\r\nSTRU X\r\nMODE C\r\nABOR\r\nQUIT\r\n",
    ])

def ftp_mut(rnd):
    return rnd.choice([
        f"MKD d{rnd.randint(1,999999)}\r\n", "SITE HELP\r\n", "FEAT\r\n",
        f"REST {rnd.randint(0,2**24)}\r\n", "EPSV\r\n", "NOOP\r\n",
        f"CWD {rnd.choice(DIRS)}\r\n", f"SIZE {rnd.choice(FILES)}\r\n",
        f"MDTM {rnd.choice(FILES)}\r\n", f"SITE CHMOD {rnd.randint(100,777)} {rnd.choice(FILES)}\r\n",
    ])

BANKS = {
    "FTP": dict(
        tpl=["USER","PASS","LIST","SYST","FEAT","PWD","TYPE","PASV","EPSV","HELP",
             "NOOP","STAT","MKD","RMD","CWD","MODE","STRU","REST","SIZE","MDTM",
             "SITE","ALLO","ABOR","MLSD","LPRT","LPSV","QUIT"],
        seed="USER mockuser\r\nPASS mockpass\r\nSYST\r\nFEAT\r\nPASV\r\nLIST\r\n",
        deep=ftp_deep, rare=ftp_rare, bad=ftp_bad, mut=ftp_mut),
    "SMTP": dict(
        tpl=["EHLO","HELO","MAIL","RCPT","DATA","NOOP","RSET","HELP","VRFY",
             "EXPN","AUTH","STARTTLS","ETRN","TURN","QUIT"],
        seed="EHLO mock.local\r\nNOOP\r\nRSET\r\nHELP\r\nVRFY user\r\n",
        deep=lambda rnd, i, ph, ctx: rnd.choice([
            "EHLO mock.local\r\nMAIL FROM:<sender@mock.local>\r\nRCPT TO:<rcpt@mock.local>\r\nDATA\r\nSubject: test\r\nFrom: sender@mock.local\r\nTo: rcpt@mock.local\r\n\r\nbody here\r\n.\r\n",
            f"HELO h{rnd.randint(1,999)}.local\r\nMAIL FROM:<x{rnd.randint(1,9999)}@mock.local> SIZE={rnd.randint(100,99999)}\r\nRCPT TO:<y@mock.local>\r\nDATA\r\nX-Header: val\r\n\r\ncontent {rnd.randint(1,99999)}\r\n.\r\nRSET\r\n",
        ]) if ph >= 1 else "EHLO mock.local\r\nNOOP\r\nHELP\r\n",
        rare=lambda rnd, ph, ctx: rnd.choice([
            "EHLO mock.local\r\nVRFY postmaster\r\nEXPN staff\r\nHELP MAIL\r\nHELP RCPT\r\n",
            "EHLO mock.local\r\nAUTH PLAIN dGVzdA==\r\nAUTH LOGIN\r\nSTARTTLS\r\nRSET\r\n",
            f"EHLO mock.local\r\nETRN {rnd.choice(['mock.local','remote.example.com','queue'])}\r\nTURN\r\n",
        ]),
        bad=lambda rnd, ph: rnd.choice([
            f"MAIL FROM:<bomb{rnd.randint(1,999)}@nowhere>\r\nRCPT TO:<{rnd.choice(USERS_BAD)}@invalid>\r\nDATA\r\nx\r\n.",
            "EHLO mock.local\r\nVRFY ../../etc/passwd\r\nEXPN root\r\nAUTH CRAM-MD5\r\n",
            f"HELO x\r\nMAIL FROM:<>\r\nRCPT TO:<{'A'*{rnd.randint(100,999)}}@overflow>\r\n",
        ]),
        mut=lambda rnd: rnd.choice(["NOOP\r\n","RSET\r\n",f"VRFY user{rnd.randint(1,99999)}\r\n","EXPN staff\r\n","HELP\r\n",f"ETRN {rnd.choice(['a','b','c'])}\r\n"])),
    "DAAP": dict(
        tpl=["GET /server-info","GET /databases","GET /logout","GET /update",
             "GET /content-codes","GET /databases/1/items","GET /databases/1/containers",
             "GET /databases/1/groups","GET /databases/1/playlists","GET /login"],
        seed="GET /server-info HTTP/1.1\r\nHost: localhost\r\n\r\nGET /content-codes HTTP/1.1\r\nHost: localhost\r\n\r\n",
        deep=lambda rnd, i, ph, ctx: rnd.choice([
            f"GET /databases HTTP/1.1\r\nHost: localhost\r\n\r\n"
            f"GET /databases/1/items?meta=all&index={rnd.randint(0,9999)}&type=music HTTP/1.1\r\nHost: localhost\r\n\r\n"
            f"GET /databases/1/containers/{rnd.randint(1,10)}/items?type=music&output=json HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"GET /login HTTP/1.1\r\nHost: localhost\r\n\r\n"
            f"GET /update?revision={rnd.randint(1,99999)} HTTP/1.1\r\nHost: localhost\r\n\r\n"
            f"GET /databases/1/playlists?meta=dmap.itemname HTTP/1.1\r\nHost: localhost\r\n\r\n"
            f"GET /logout HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ]) if ph >= 1 else "GET /server-info HTTP/1.1\r\nHost: localhost\r\n\r\n",
        rare=lambda rnd, ph, ctx: rnd.choice([
            f"GET /databases/{rnd.randint(1,99)}/groups?meta=dm.container.artist HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            f"GET /databases/1/browse/{rnd.choice(['genre','artist','album','composer'])} HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ]),
        bad=lambda rnd, ph: f"GET /../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\nGET /databases/{rnd.randint(90,99)}/nope HTTP/1.1\r\nHost: localhost\r\n\r\n",
        mut=lambda rnd: f"GET /databases/1/items?query={rnd.randint(1,999999)}&index={rnd.randint(0,9999)} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    "HTTP": dict(
        tpl=["GET","HEAD","POST","PUT","DELETE","OPTIONS","TRACE","PATCH"],
        seed="GET / HTTP/1.1\r\nHost: localhost\r\n\r\nHEAD /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n",
        deep=lambda rnd, i, ph, ctx: rnd.choice([
            f"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            f"GET /index{rnd.randint(1,99)}.html HTTP/1.1\r\nHost: localhost\r\nRange: bytes={rnd.randint(0,99999)}-\r\n\r\n"
            f"HEAD / HTTP/1.1\r\nHost: localhost\r\nIf-Modified-Since: Thu, 01 Jan 2026 00:00:00 GMT\r\n\r\n",
            f"POST /form{rnd.randint(1,9)} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {rnd.randint(10,500)}\r\n\r\n"
            f"a={rnd.randint(1,999999)}&b=x&c={'d'*rnd.randint(10,200)}&submit=true\r\n"
            f"GET /?q={rnd.randint(1,99999)}&page={rnd.randint(1,99)} HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ]) if ph >= 1 else "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        rare=lambda rnd, ph, ctx: rnd.choice([
            f"OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\nTRACE / HTTP/1.1\r\nHost: localhost\r\nMax-Forwards: 5\r\n\r\n",
            f"PUT /upload{rnd.randint(1,99)}.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
            f"DELETE /nonexistent{rnd.randint(1,999)} HTTP/1.1\r\nHost: localhost\r\n\r\n"
            f"PATCH /data{rnd.randint(1,9)} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{{\"op\":\"replace\"}}",
            f"GET /server-status?auto HTTP/1.1\r\nHost: localhost\r\n\r\nGET /status HTTP/1.0\r\n\r\n",
        ]),
        bad=lambda rnd, ph: rnd.choice([
            f"GET /../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"BREW / HTT/1.1\r\nHost: localhost\r\n\r\n",
            f"GET /%zz{rnd.randint(1,9999)} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"GET /{'A'*rnd.randint(100,500)} HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ]),
        mut=lambda rnd: f"GET /x{rnd.randint(1,999999)}?v={rnd.randint(1,99999)} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    "RTSP": dict(
        tpl=["OPTIONS","DESCRIBE","SETUP","PLAY","PAUSE","TEARDOWN",
             "GET_PARAMETER","SET_PARAMETER"],
        seed="OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\nDESCRIBE rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: 2\r\n\r\n",
        deep=lambda rnd, i, ph, ctx: rnd.choice([
            f"DESCRIBE rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {i}\r\nAccept: application/sdp\r\n\r\n"
            f"SETUP rtsp://127.0.0.1/media/streamid={rnd.randint(0,5)} RTSP/1.0\r\nCSeq: {i+1}\r\n"
            f"Transport: RTP/AVP;unicast;client_port={rnd.randint(40000,60000)}-{rnd.randint(60001,65000)}\r\n\r\n"
            f"PLAY rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {i+2}\r\nSession: {rnd.randint(1000,9999)}\r\nRange: npt=0-\r\nScale: {rnd.choice(['1.0','2.0','0.5'])}\r\n\r\n"
            f"PAUSE rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {i+3}\r\nSession: {rnd.randint(1000,9999)}\r\n\r\n"
            f"TEARDOWN rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {i+4}\r\nSession: {rnd.randint(1000,9999)}\r\n\r\n",
        ]) if ph >= 1 else f"OPTIONS * RTSP/1.0\r\nCSeq: {i}\r\n\r\n",
        rare=lambda rnd, ph, ctx: rnd.choice([
            f"GET_PARAMETER rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {rnd.randint(1,999)}\r\nSession: {rnd.randint(1,9999)}\r\n\r\n"
            f"SET_PARAMETER rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {rnd.randint(1,999)}\r\n"
            f"Content-Type: text/parameters\r\nContent-Length: 20\r\n\r\nbarparam: value\r\n",
            f"DESCRIBE rtsp://127.0.0.1:{rnd.randint(40000,60000)}/media RTSP/1.0\r\nCSeq: {rnd.randint(1,999)}\r\n\r\n",
        ]),
        bad=lambda rnd, ph: f"DESCRIBE rtsp://127.0.0.1/missing{rnd.randint(1,999)} RTSP/9.9\r\nCSeq: {rnd.randint(1,999)}\r\n\r\n",
        mut=lambda rnd: f"OPTIONS * RTSP/1.0\r\nCSeq: {rnd.randint(1,99999)}\r\n\r\n"),
    "SIP": dict(
        tpl=["REGISTER","INVITE","ACK","BYE","CANCEL","OPTIONS",
             "SUBSCRIBE","NOTIFY","MESSAGE","INFO","REFER","UPDATE"],
        seed="OPTIONS sip:test@127.0.0.1 SIP/2.0\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n",
        deep=lambda rnd, i, ph, ctx: (
            f"REGISTER sip:127.0.0.1 SIP/2.0\r\nCSeq: {i} REGISTER\r\n"
            f"Via: SIP/2.0/TCP 127.0.0.1:5060\r\nTo: <sip:user{rnd.randint(1,99)}@127.0.0.1>\r\n"
            f"Contact: <sip:user{rnd.randint(1,99)}@127.0.0.1:{rnd.randint(50000,60000)}>\r\n"
            f"Expires: {rnd.choice([60,3600,86400])}\r\nCall-ID: {rnd.randint(1,999999)}@127.0.0.1\r\n\r\n"
            f"MESSAGE sip:user{rnd.randint(1,99)}@127.0.0.1 SIP/2.0\r\nCSeq: {i+1} MESSAGE\r\n"
            f"Via: SIP/2.0/TCP 127.0.0.1:5060\r\nContent-Type: text/plain\r\nContent-Length: {rnd.randint(5,200)}\r\n\r\n"
            f"msg body {rnd.randint(1,99999)}\r\n"
            f"BYE sip:user{rnd.randint(1,99)}@127.0.0.1 SIP/2.0\r\nCSeq: {i+2} BYE\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n"
        ) if ph >= 1 else f"OPTIONS sip:test@127.0.0.1 SIP/2.0\r\nCSeq: {i} OPTIONS\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n",
        rare=lambda rnd, ph, ctx: rnd.choice([
            f"SUBSCRIBE sip:127.0.0.1 SIP/2.0\r\nCSeq: {rnd.randint(1,999)} SUBSCRIBE\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\nEvent: presence\r\nExpires: {rnd.choice([300,3600])}\r\n\r\n",
            f"REFER sip:user{rnd.randint(1,99)}@127.0.0.1 SIP/2.0\r\nCSeq: {rnd.randint(1,999)} REFER\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\nRefer-To: <sip:target{rnd.randint(1,99)}@elsewhere>\r\n\r\n",
            f"INFO sip:call{rnd.randint(1,999)}@127.0.0.1 SIP/2.0\r\nCSeq: {rnd.randint(1,999)} INFO\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\nContent-Type: application/dtmf-relay\r\n\r\nSignal={rnd.randint(0,9)}\r\n",
        ]),
        bad=lambda rnd, ph: rnd.choice([
            f"INVITE sip:nobody@invalid{rnd.randint(1,999)} SIP/2.0\r\nCSeq: {rnd.randint(1,999)} INVITE\r\n\r\n",
            f"REGISTER sip:127.0.0.1 SIP/2.0\r\nCSeq: {rnd.randint(1,999)} REGISTER\r\nExpires: -1\r\nContact: <sip:{'A'*rnd.randint(50,200)}@invalid>\r\n\r\n",
        ]),
        mut=lambda rnd: f"OPTIONS sip:t{rnd.randint(1,999999)}@127.0.0.1 SIP/2.0\r\nCSeq: {rnd.randint(1,9999)} OPTIONS\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n"),
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

def reply_for(prompt):
    proto = detect_proto(prompt)
    bank = BANKS[proto]
    if "message templates" in prompt:
        reqs["templates"] += 1
        return "\n".join(f'{c}: ["{c} <<VALUE>>\\r\\n"]' for c in bank["tpl"])
    if "ONLY valid JSON" in prompt or "suggested_request" in prompt:
        reqs["plateau"] += 1
        i = reqs["plateau"]
        rnd = random.Random(20261023 * 10000 + i)
        ph = _phase(i)
        ctx = _context_states(prompt)
        roll = rnd.random() * 100.0
        kind = _MIX_ORDER[-1]
        for _edge, _k in _MIX_CUM:
            if roll < _edge:
                kind = _k
                break
        if kind == "mut":
            ins = bank["mut"](rnd)
            return json.dumps({
                "analysis": f"mock-v4: mutate seed ({proto}) phase={ph}",
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
            candidate = bank["rare"](rnd, ph, ctx)
        else:
            candidate = bank["deep"](rnd, i, ph, ctx)
        return json.dumps({
            "analysis": f"mock-v4: {proto} candidate phase={ph} ctx={len(ctx)}",
            "suggested_request": candidate if candidate.endswith("\n") else candidate + "\r\n"})
    reqs["seed"] += 1
    return bank["seed"]

class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(n) or b"{}")
        prompt = "".join(m.get("content", "") for m in req.get("messages", [])
                         if m.get("role") == "user")
        content = reply_for(prompt)
        out = json.dumps({
            "id": "mockv4-%d" % sum(reqs.values()),
            "object": "chat.completion",
            "model": req.get("model", "mock-v4"),
            "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": content},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": max(1, len(prompt) // 4),
                      "completion_tokens": max(1, len(content) // 4),
                      "total_tokens": max(2, (len(prompt) + len(content)) // 4)},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
        print(f"[mock-v4] #{sum(reqs.values())} proto={proto_counts} class={reqs} "
              f"prompt_head={prompt[:40]!r}", flush=True)

    def log_message(self, *a):
        pass

proto_counts = {}

class Srv(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    port = int(os.environ.get("MOCK_PORT", "8099"))
    with Srv(("0.0.0.0", port), H) as s:
        print(f"[mock-v4] listening on 0.0.0.0:{port} mix={MIX}", flush=True)
        s.serve_forever()
