#!/usr/bin/env python3
"""Enriched protocol-aware mock OpenAI gateway (v3) for hour-level smoke runs.

Approximates real-LLM candidate quality along the axes the ablation audit
identified as load-bearing:

- four candidate classes, drawn deterministically by plateau index so every
  arm of a controlled comparison sees the SAME candidate stream:
    * deep valid sessions  (~40%) -> code-bearing (G_code / durable path)
    * rare-command probes  (~25%) -> novel response states (G_state path)
    * bad-credential/error sessions (~15%) -> U rejects (realistic FN mix)
    * seed mutations       (~20%) -> actions[] channel
- parameterized argument pools (paths, files, creds, numbers, headers) for
  cross-candidate diversity without run-to-run randomness
- richer grammar-template and seed-session replies
Reply contract identical to llm_mock_v2 (chat completions on :8099).
"""
import base64, json, http.server, socketserver, random, os

reqs = {"templates": 0, "plateau": 0, "seed": 0}

# Candidate-class mix (percent weights, sum 100): the "valuable share p"
# scan variable.  deep = code-bearing valuable candidates; rare = state-
# novelty probes (provisional tier); bad = hard-U-fail junk; mut = seed
# mutations.  Default reproduces the original v3 behaviour.
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
proto_counts = {}

DIRS = ["tmp", "pub", "upload", "a", "b/c", "incoming", "share"]
FILES = ["file.txt", "test.bin", "big.dat", "index.html", "notes.md", "f%d.bin"]
USERS = ["mockuser", "ftp", "anonymous", "user%d", "admin"]
OKPASS = ["mockpass", "mockpass", "mockpass", "ftp", "anonymous"]
BADPASS = ["wrongpass", "x", "hunter2", "1"]

def ftp_creds(rnd, bad=False):
    plain = [x for x in USERS if "%d" not in x]
    numbered = [x for x in USERS if "%d" in x]
    u = rnd.choice(numbered) % rnd.randint(1, 9) if numbered and rnd.random() < 0.4 else rnd.choice(plain)
    p = rnd.choice(BADPASS) if bad else rnd.choice(OKPASS)
    return u, p

def ftp_deep(rnd, i):
    u, p = ftp_creds(rnd)
    d = rnd.choice(DIRS)
    f = rnd.choice([x for x in FILES if "%d" not in x])
    seqs = [
        f"USER {u}\r\nPASS {p}\r\nTYPE I\r\nPASV\r\nLIST",
        f"USER {u}\r\nPASS {p}\r\nEPSV\r\nNLST {d}",
        f"USER {u}\r\nPASS {p}\r\nCWD {d}\r\nPASV\r\nRETR {f}",
        f"USER {u}\r\nPASS {p}\r\nMODE S\r\nSTRU F\r\nREST {rnd.randint(1,999)}\r\nPASV\r\nLIST {d}",
        f"USER {u}\r\nPASS {p}\r\nPASV\r\nSTOR {f}\r\nPASV\r\nLIST",
    ]
    return rnd.choice(seqs)

def ftp_rare(rnd):
    rnd2 = random.Random(rnd.randint(0, 1 << 30))
    u, p = "mockuser", "mockpass" if rnd2.random() < 0.8 else ftp_creds(rnd2)[1]
    return rnd.choice([
        f"USER {u}\r\nPASS {p}\r\nSITE HELP\r\nSITE CHMOD 644 {rnd.choice(FILES)}",
        "FEAT\r\nOPTS UTF8 ON\r\nHELP SITE\r\nSTAT /",
        f"USER {u}\r\nPASS {p}\r\nSIZE {rnd.choice(FILES)}\r\nMDTM {rnd.choice(FILES)}",
        "ALLO 1024\r\nSMNT /dev/null\r\nACCT none\r\nMODE B\r\nSTRU R",
        "LPRT 4,4,127,0,0,1,2,100,200\r\nLPSV\r\nABOR\r\nNOOP",
        f"USER {u}\r\nPASS {p}\r\nSTAT {rnd.choice(DIRS)}\r\nLIST -la {rnd.choice(DIRS)}",
    ])

def ftp_bad(rnd):
    u, _ = ftp_creds(rnd)
    return rnd.choice([
        f"USER {u}\r\nPASS {rnd.choice(BADPASS)}\r\nLIST\r\nRETR secret",
        f"USER {u}\r\nPASS {rnd.choice(BADPASS)}\r\nDELE /etc/passwd\r\nRMD /",
        f"USER nonexistent{rnd.randint(1,99)}\r\nPASS x\r\nCWD /root\r\nLIST",
    ])

def ftp_mut(rnd):
    return rnd.choice([
        f"MKD d{rnd.randint(1,999)}\r\n", "SITE HELP\r\n", "FEAT\r\n",
        f"REST {rnd.randint(0,4096)}\r\n", "EPSV\r\n", "NOOP\r\n",
        f"CWD {rnd.choice(DIRS)}\r\n", f"SIZE {rnd.choice(FILES)}\r\n",
    ])

BANKS = {
    "FTP": dict(
        tpl=["USER", "PASS", "LIST", "SYST", "FEAT", "PWD", "TYPE", "PASV",
             "EPSV", "HELP", "NOOP", "STAT", "MKD", "RMD", "CWD", "MODE",
             "STRU", "REST", "SIZE", "MDTM", "SITE", "ALLO", "ABOR", "QUIT"],
        seed="USER mockuser\r\nPASS mockpass\r\nSYST\r\nFEAT\r\nPASV\r\nLIST\r\n",
        deep=ftp_deep, rare=ftp_rare, bad=ftp_bad, mut=ftp_mut),
    "SMTP": dict(
        tpl=["EHLO", "HELO", "MAIL", "RCPT", "DATA", "NOOP", "RSET", "HELP",
             "VRFY", "EXPN", "AUTH", "STARTTLS", "QUIT"],
        seed="EHLO mock.local\r\nNOOP\r\nRSET\r\nHELP\r\nVRFY user\r\n",
        deep=lambda rnd, i: rnd.choice([
            "EHLO mock.local\r\nMAIL FROM:<a@mock.local>\r\nRCPT TO:<b@mock.local>\r\nDATA\r\nsubject: t\r\n.\r\n",
            f"HELO h{rnd.randint(1,9)}.local\r\nMAIL FROM:<x{rnd.randint(1,99)}@mock.local> SIZE={rnd.randint(100,9000)}\r\nRCPT TO:<y@mock.local>\r\nDATA\r\nhello\r\n.\r\n",
        ]),
        rare=lambda rnd: rnd.choice([
            "EHLO mock.local\r\nVRFY postmaster\r\nEXPN staff\r\nHELP MAIL\r\nNOOP",
            "EHLO mock.local\r\nAUTH PLAIN dGVzdA==\r\nSTARTTLS\r\nRSET",
        ]),
        bad=lambda rnd: rnd.choice([
            f"EHLO mock.local\r\nMAIL FROM:<bad{rnd.randint(1,99)}@nowhere>\r\nRCPT TO:<nobody@invalid>\r\nDATA\r\nx\r\n.",
            "EHLO mock.local\r\nVRFY ../../etc/passwd\r\nEXPN root",
        ]),
        mut=lambda rnd: rnd.choice(["NOOP\r\n", "RSET\r\n", f"VRFY user{rnd.randint(1,99)}\r\n", "EXPN staff\r\n", "HELP\r\n"])),
    "RTSP": dict(
        tpl=["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN",
             "GET_PARAMETER", "SET_PARAMETER"],
        seed="OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\nDESCRIBE rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: 2\r\n\r\n",
        deep=lambda rnd, i: (
            f"DESCRIBE rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {i}\r\n\r\n"
            f"SETUP rtsp://127.0.0.1/media/streamid={rnd.randint(0,3)} RTSP/1.0\r\nCSeq: {i+1}\r\nTransport: RTP/AVP;unicast;client_port={rnd.randint(40000,60000)}-{rnd.randint(60001,65000)}\r\n\r\n"
            f"PLAY rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {i+2}\r\nSession: {rnd.randint(1000,9999)}\r\nRange: npt=0-\r\n\r\n"),
        rare=lambda rnd: f"GET_PARAMETER rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: {rnd.randint(1,999)}\r\nSession: {rnd.randint(1,9999)}\r\n\r\nOPTIONS * RTSP/1.0\r\nCSeq: {rnd.randint(1,999)}\r\n\r\n",
        bad=lambda rnd: f"DESCRIBE rtsp://127.0.0.1/missing{rnd.randint(1,99)} RTSP/9.9\r\nCSeq: {rnd.randint(1,999)}\r\n\r\n",
        mut=lambda rnd: f"OPTIONS * RTSP/1.0\r\nCSeq: {rnd.randint(1,9999)}\r\n\r\n"),
    "SIP": dict(
        tpl=["REGISTER", "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS",
             "SUBSCRIBE", "NOTIFY", "MESSAGE", "INFO"],
        seed="OPTIONS sip:test@127.0.0.1 SIP/2.0\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n",
        deep=lambda rnd, i: (
            f"REGISTER sip:127.0.0.1 SIP/2.0\r\nCSeq: {i} REGISTER\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\nContact: <sip:user{rnd.randint(1,99)}@127.0.0.1>\r\nExpires: {rnd.choice([60, 3600, 86400])}\r\n\r\n"
            f"OPTIONS sip:user{rnd.randint(1,99)}@127.0.0.1 SIP/2.0\r\nCSeq: {i+1} OPTIONS\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n"),
        rare=lambda rnd: rnd.choice([
            f"SUBSCRIBE sip:127.0.0.1 SIP/2.0\r\nCSeq: {rnd.randint(1,999)} SUBSCRIBE\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\nEvent: presence\r\n\r\n",
            f"MESSAGE sip:user{rnd.randint(1,9)}@127.0.0.1 SIP/2.0\r\nCSeq: {rnd.randint(1,999)} MESSAGE\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\nContent-Type: text/plain\r\n\r\nhi",
        ]),
        bad=lambda rnd: f"INVITE sip:nobody@invalid{rnd.randint(1,99)} SIP/2.0\r\nCSeq: {rnd.randint(1,999)} INVITE\r\n\r\n",
        mut=lambda rnd: f"OPTIONS sip:t{rnd.randint(1,999)}@127.0.0.1 SIP/2.0\r\nCSeq: {rnd.randint(1,999)} OPTIONS\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n"),
    "DAAP": dict(
        tpl=["GET /server-info", "GET /databases", "GET /logout", "GET /update",
             "GET /content-codes", "GET /databases/1/items", "GET /databases/1/containers"],
        seed="GET /server-info HTTP/1.1\r\nHost: localhost\r\n\r\nGET /content-codes HTTP/1.1\r\nHost: localhost\r\n\r\n",
        deep=lambda rnd, i: (
            f"GET /databases HTTP/1.1\r\nHost: localhost\r\n\r\n"
            f"GET /databases/1/items?meta=all&index={rnd.randint(0,99)} HTTP/1.1\r\nHost: localhost\r\n\r\n"
            f"GET /databases/1/containers/{rnd.randint(1,3)}/items?type=music HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        rare=lambda rnd: rnd.choice([
            f"GET /update?revision={rnd.randint(1,99)} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"GET /databases/1/groups?meta=dm.container.artist HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        ]),
        bad=lambda rnd: f"GET /../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\nGET /databases/{rnd.randint(90,99)}/nope HTTP/1.1\r\nHost: localhost\r\n\r\n",
        mut=lambda rnd: f"GET /databases/1/items?query={rnd.randint(1,999)} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    "HTTP": dict(
        tpl=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"],
        seed="GET / HTTP/1.1\r\nHost: localhost\r\n\r\nHEAD /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n",
        deep=lambda rnd, i: rnd.choice([
            f"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\r\nGET /index{rnd.randint(1,9)}.html HTTP/1.1\r\nHost: localhost\r\n\r\nHEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"GET /dir{rnd.randint(1,9)}/ HTTP/1.1\r\nHost: localhost\r\nRange: bytes={rnd.randint(0,999)}-\r\n\r\nGET /?q={rnd.randint(1,999)} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"POST /form{rnd.randint(1,9)} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {rnd.randint(5,40)}\r\n\r\na={rnd.randint(1,999)}&b=x",
        ]),
        rare=lambda rnd: rnd.choice([
            f"OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\nTRACE / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"PUT /upload{rnd.randint(1,9)}.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\nDELETE /nonexistent{rnd.randint(1,99)} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"GET /status HTTP/1.0\r\n\r\nGET /server-status?auto HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ]),
        bad=lambda rnd: rnd.choice([
            f"GET /../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
            f"BREW / HTT/1.1\r\nHost: localhost\r\n\r\n",
            f"GET /%zz{rnd.randint(1,99)} HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ]),
        mut=lambda rnd: f"GET /x{rnd.randint(1,999)} HTTP/1.1\r\nHost: localhost\r\n\r\n"),
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
    proto_counts[proto] = proto_counts.get(proto, 0) + 1
    if "message templates" in prompt:
        reqs["templates"] += 1
        return "\n".join(f'{c}: ["{c} <<VALUE>>\\r\\n"]' for c in bank["tpl"])
    if "ONLY valid JSON" in prompt or "suggested_request" in prompt:
        reqs["plateau"] += 1
        i = reqs["plateau"]
        rnd = random.Random(20261021 * 1000 + i)   # deterministic per candidate
        roll = rnd.random() * 100.0
        kind = _MIX_ORDER[-1]
        for _edge, _k in _MIX_CUM:
            if roll < _edge:
                kind = _k
                break
        if kind == "mut":  # seed mutation via actions[]
            ins = bank["mut"](rnd)
            return json.dumps({
                "analysis": f"mock-v3: mutate seed ({proto})",
                "actions": [
                    {"type": "propose_mutations", "seed_id": 0,
                     "ops": [{"op": "insert", "pos": 999999,
                              "data": base64.b64encode(ins.encode()).decode()}]},
                    {"type": "set_target_state", "state_id": 0},
                    {"type": "prioritize_seeds", "seed_ids": [0]},
                ]})
        if kind == "bad":
            candidate = bank["bad"](rnd)      # realistic U-reject stream
        elif kind == "rare":
            candidate = bank["rare"](rnd)     # state-novelty probes
        else:
            candidate = bank["deep"](rnd, i)  # code-bearing sessions
        return json.dumps({
            "analysis": f"mock-v3: {proto} candidate",
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
            "id": "mockv3-%d" % sum(reqs.values()),
            "object": "chat.completion",
            "model": req.get("model", "mock-v3"),
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
        print(f"[mock-v3] #{sum(reqs.values())} proto={proto_counts} class={reqs} "
              f"prompt_head={prompt[:40]!r}", flush=True)

    def log_message(self, *a):
        pass

class Srv(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    with Srv(("0.0.0.0", 8099), H) as s:
        print("[mock-v3] listening on 0.0.0.0:8099", flush=True)
        s.serve_forever()
