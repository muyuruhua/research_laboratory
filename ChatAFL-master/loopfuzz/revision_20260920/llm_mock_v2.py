#!/usr/bin/env python3
"""Protocol-aware mock OpenAI-compatible gateway for LoopFuzz v3.3b full-matrix
verification (9 targets: FTP/SMTP/RTSP/SIP/HTTP/DAAP).

Dispatch:
  1. protocol from prompt keywords ("analyzing the %s protocol" / seed text)
  2. reply class from prompt shape:
     - "message templates" -> per-protocol template lines (grammar phase)
     - "ONLY valid JSON"/"suggested_request" -> plateau reply
       (even # -> actions[] mutate seed; odd # -> suggested_request)
     - else -> per-protocol seed session (enrichment phase)
"""
import base64, json, http.server, socketserver

reqs = {"templates": 0, "plateau": 0, "seed": 0}
proto_counts = {}

BANKS = {
    "FTP": dict(
        cmds=["NOOP", "PWD", "SYST", "TYPE I", "PASV", "FEAT", "HELP",
              "MODE S", "STRU F", "REST 0", "STAT", "LIST", "MKD m%d",
              "SITE HELP", "ABOR"],
        tpl=["USER", "PASS", "LIST", "SYST", "FEAT", "PWD", "TYPE", "PASV",
             "HELP", "NOOP", "STAT", "MKD", "CWD", "MODE", "STRU", "ABOR",
             "QUIT"],
        seed="USER mockuser\r\nPASS mockpass\r\nSYST\r\nNOOP\r\n"),
    "SMTP": dict(
        cmds=["NOOP", "RSET", "HELP", "VRFY user%d", "EXPN list",
              "EHLO mock.local", "HELO mock.local"],
        tpl=["EHLO", "HELO", "MAIL", "RCPT", "DATA", "NOOP", "RSET", "HELP",
             "VRFY", "EXPN", "QUIT"],
        seed="EHLO mock.local\r\nNOOP\r\nRSET\r\nHELP\r\n"),
    "RTSP": dict(
        cmds=["OPTIONS * RTSP/1.0\r\nCSeq: %d\r\n",
              "DESCRIBE rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: %d\r\n",
              "GET_PARAMETER rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: %d\r\n"],
        tpl=["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN",
             "GET_PARAMETER", "SET_PARAMETER"],
        seed="OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"
             "DESCRIBE rtsp://127.0.0.1/media RTSP/1.0\r\nCSeq: 2\r\n\r\n"),
    "SIP": dict(
        cmds=["OPTIONS sip:test@127.0.0.1 SIP/2.0\r\nCSeq: %d OPTIONS\r\n",
              "REGISTER sip:127.0.0.1 SIP/2.0\r\nCSeq: %d REGISTER\r\n"],
        tpl=["REGISTER", "INVITE", "ACK", "BYE", "CANCEL", "OPTIONS",
             "SUBSCRIBE", "NOTIFY"],
        seed="OPTIONS sip:test@127.0.0.1 SIP/2.0\r\nCSeq: 1 OPTIONS\r\n"
             "Via: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n"),
    "DAAP": dict(
        cmds=["GET /server-info HTTP/1.1\r\nHost: localhost\r\n",
              "GET /databases HTTP/1.1\r\nHost: localhost\r\n"],
        tpl=["GET /server-info", "GET /databases", "GET /logout",
             "GET /update", "GET /content-codes"],
        seed="GET /server-info HTTP/1.1\r\nHost: localhost\r\n\r\n"
             "GET /content-codes HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    "HTTP": dict(
        cmds=["GET /index%d.html HTTP/1.1\r\nHost: localhost\r\n",
              "HEAD / HTTP/1.1\r\nHost: localhost\r\n",
              "OPTIONS * HTTP/1.1\r\nHost: localhost\r\n"],
        tpl=["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"],
        seed="GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
             "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
}

PROTO_ORDER = ["FTP", "SMTP", "RTSP", "SIP", "DAAP", "HTTP"]

def detect_proto(prompt):
    up = prompt.upper()
    for p in PROTO_ORDER:
        if f" {p} " in up or f"{p} PROTOCOL" in up or f"/{p}" in up:
            return p
    # fall back on seed-content cues
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
        cmd = bank["cmds"][(i - 1) % len(bank["cmds"])]
        if "%d" in cmd:
            cmd = cmd % i
        ins = bank["cmds"][(i - 1) % len(bank["cmds"])]
        if "%d" in ins:
            ins = ins % i
        ins_b64 = base64.b64encode(ins.encode()).decode()
        if i % 2 == 0:
            return json.dumps({
                "analysis": f"mock: mutate the clean initial seed ({proto})",
                "actions": [
                    {"type": "propose_mutations", "seed_id": 0,
                     "ops": [{"op": "insert", "pos": 999999,
                              "data": ins_b64}]},
                    {"type": "set_target_state", "state_id": 0},
                    {"type": "prioritize_seeds", "seed_ids": [0]},
                ]})
        return json.dumps({
            "analysis": f"mock: propose a {proto} request",
            "suggested_request": cmd if cmd.endswith("\n") else cmd + "\r\n"})
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
            "id": "mock-%d" % sum(reqs.values()),
            "object": "chat.completion",
            "model": req.get("model", "mock"),
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
        print(f"[mock] #{sum(reqs.values())} proto={detect_proto(prompt)} "
              f"class_counts={reqs} protos={proto_counts} "
              f"prompt_head={prompt[:50]!r}", flush=True)

    def log_message(self, *a):
        pass

class Srv(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    with Srv(("0.0.0.0", 8099), H) as s:
        print("[mock-v2] listening on 0.0.0.0:8099", flush=True)
        s.serve_forever()
