#!/usr/bin/env python3
"""Mock OpenAI-compatible gateway for LoopFuzz mechanism verification.

Dispatches on the user prompt:
  - "message templates"  -> FTP template lines (grammar phase)
  - "ONLY valid JSON"    -> plateau reply with suggested_request + actions[]
  - anything else        -> plain seed text (enrichment phase)

v2 (2026-10-06): suggested_request and propose_mutations both use
POST-AUTH-safe FTP commands (2xx on bftpd after login), and the mutation
op is insert-at-end with BASE64 data (the fuzzer base64-decodes the data
field — v1 sent plaintext, which executed as garbage bytes and failed U).
"""
import base64, json, http.server, socketserver

reqs = {"templates": 0, "plateau": 0, "seed": 0}
CMDS = ["NOOP", "PWD", "SYST", "TYPE I", "TYPE A", "PASV", "FEAT", "HELP",
        "ABOR", "MODE S", "STRU F", "REST 0", "SITE HELP", "STAT", "LIST",
        "MKD m%d", "MDTM x", "SIZE x"]
TPL_CMDS = ["USER", "PASS", "LIST", "SYST", "FEAT", "PWD", "TYPE", "PASV",
            "HELP", "NOOP", "STAT", "MKD", "CWD", "MODE", "STRU", "ABOR", "QUIT"]

def reply_for(prompt):
    if "message templates" in prompt:
        reqs["templates"] += 1
        return "\n".join(f'{c}: ["{c} <<VALUE>>\\r\\n"]' for c in TPL_CMDS)
    if "ONLY valid JSON" in prompt or "suggested_request" in prompt:
        reqs["plateau"] += 1
        i = reqs["plateau"]
        cmd = CMDS[(i - 1) % len(CMDS)]
        if "%d" in cmd:
            cmd = cmd % i
        ins = CMDS[(i - 1) % len(CMDS)].split()[0] + "\r\n"
        # v3: ALTERNATE reply shapes.  The fuzzer's parser takes
        # suggested_request when present and NEVER processes actions[] in
        # that reply — returning both (v1/v2 behaviour) means the clean
        # seed-0 mutation path is never exercised.  Even replies:
        # actions-only (mutate the clean initial seed); odd: suggested-only.
        if i % 2 == 0:
            return json.dumps({
                "analysis": "mock: mutate the clean initial seed",
                "actions": [
                    {"type": "propose_mutations", "seed_id": 0,
                     "ops": [{"op": "insert", "pos": 999999,
                              "data": base64.b64encode(ins.encode()).decode()}]},
                    {"type": "set_target_state", "state_id": 0},
                    {"type": "prioritize_seeds", "seed_ids": [0]},
                ]})
        return json.dumps({
            "analysis": "mock: propose a post-auth-safe command",
            "suggested_request": cmd + "\r\n"})
    reqs["seed"] += 1
    return "USER mockuser\r\nPASS mockpass\r\nSYST\r\n"

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
        print(f"[mock] #{sum(reqs.values())} class_counts={reqs} "
              f"prompt_head={prompt[:60]!r}", flush=True)

    def log_message(self, *a):
        pass

class Srv(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    with Srv(("0.0.0.0", 8099), H) as s:
        print("[mock] listening on 0.0.0.0:8099", flush=True)
        s.serve_forever()
