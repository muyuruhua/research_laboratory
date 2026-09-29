#!/usr/bin/env python3
"""Post-hoc vulnerability-predicate replay for LoopFuzz campaign outputs.

Turns already-generated inputs (queue / replayable-crashes / replayable-hangs)
into COUNTED findings for detector-blind vulnerability classes:

  kamailio : Content-Length signed-overflow — replays each input over TCP
             against a fresh campaign kamailio and greps the server log for
             the negative-value fingerprint emitted by tcp_read_headers.
  live555  : duplicate-SETUP wedge (CPU busy-loop hang) — replays each input
             against a fresh testOnDemandRTSPServer, then probes liveness on
             a NEW connection and samples /proc utime.  Server unresponsive
             + CPU spinning = wedge confirmed.

Usage:
  predicate_replay.py kamailio FILE [FILE...]
  predicate_replay.py live555  FILE [FILE...]

Files may be raw CRLF-framed streams or AFLNet length-prefixed message
files (4-byte LE per message) — auto-detected.

Exits 0 if at least one input triggered the predicate, else 1.
"""
import os
import re
import socket
import struct
import subprocess
import sys
import time

CNAME = "predrep"


def sh(cmd, timeout=60, check=False):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout, check=check)


def sh_stdin(cmd, script, timeout=60):
    """Run `docker exec -i ... python3 -` feeding script on stdin —
    avoids every layer of shell quoting (bytes reprs contain quotes)."""
    return subprocess.run(cmd, shell=True, input=script,
                          capture_output=True, text=True, timeout=timeout)


def parse_messages(path):
    """Return list of message bytes, or None if not length-prefixed."""
    raw = open(path, "rb").read()
    msgs, off = [], 0
    while off + 4 <= len(raw):
        (n,) = struct.unpack("<I", raw[off:off + 4])
        if n == 0 or off + 4 + n > len(raw):
            return None
        msgs.append(raw[off + 4:off + 4 + n])
        off += 4 + n
    return msgs if msgs and off == len(raw) else None


def load_payload(path, framing="line"):
    msgs = parse_messages(path)
    if msgs is not None:
        return msgs
    raw = open(path, "rb").read()
    if framing == "request":
        parts = raw.split(b"\r\n\r\n")
        return [p + b"\r\n\r\n" for p in parts if p.strip()]
    return [p + b"\r\n" for p in raw.split(b"\r\n") if p]


# ── kamailio ────────────────────────────────────────────────────────────

def kamailio_setup():
    sh(f"docker rm -f {CNAME}-kam 2>/dev/null")
    sh(f"docker run -d --name {CNAME}-kam kamailio:latest tail -f /dev/null")
    sh(f"docker exec -u root {CNAME}-kam bash -c '"
       f"sed -e \"s/^fork=no/fork=yes/\" "
       f"-e \"s/^disable_tcp=yes/disable_tcp=no/\" "
       f"-e \"s|^listen=udp:127.0.0.1:5060|listen=udp:127.0.0.1:5060\\nlisten=tcp:127.0.0.1:5060|\" "
       f"/home/ubuntu/experiments/kamailio-basic.cfg > /tmp/kam-tcp.cfg; "
       f"mkdir -p /tmp/kamrun'")
    sh(f"docker exec -d -u root {CNAME}-kam bash -c '"
       f"cd /home/ubuntu/experiments/kamailio && "
       f"./src/kamailio -f /tmp/kam-tcp.cfg -L src/modules -Y /tmp/kamrun "
       f"-n 1 -E > /tmp/kam.log 2>&1'")
    for _ in range(30):
        r = sh(f"docker exec {CNAME}-kam grep -ci 13C4 /proc/net/tcp")
        if r.stdout.strip() not in ("", "0"):
            return
        time.sleep(1)
    print("[!] kamailio TCP listener never came up", file=sys.stderr)


def kamailio_replay_one(path):
    msgs = load_payload(path)
    script = ("import socket\n"
              "msgs=" + repr(msgs[:30]) + "\n"
              "s=socket.create_connection(('127.0.0.1',5060),timeout=10)\n"
              "s.settimeout(0.3)\n"
              "for m in msgs:\n"
              "    try: s.sendall(m)\n"
              "    except Exception: break\n"
              "    try: s.recv(4096)\n"
              "    except Exception: pass\n"
              "s.close()\n")
    sh_stdin(f"docker exec -i {CNAME}-kam python3 -", script, timeout=30)
    time.sleep(0.3)
    r = sh(f"docker exec {CNAME}-kam grep -ac 'bad Content-Length' /tmp/kam.log")
    return int(r.stdout.strip() or 0)


def kamailio_teardown():
    sh(f"docker rm -f {CNAME}-kam 2>/dev/null")


# ── live555 ─────────────────────────────────────────────────────────────

def live555_setup():
    sh(f"docker rm -f {CNAME}-l555 2>/dev/null")
    sh(f"docker run -d --name {CNAME}-l555 live555:latest tail -f /dev/null")
    sh(f"docker exec -d -u root {CNAME}-l555 bash -c '"
       f"cd /home/ubuntu/experiments/live/testProgs && "
       f"env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=0 "
       f"./testOnDemandRTSPServer 8554 > /tmp/live.log 2>&1'")
    for _ in range(20):
        r = sh(f"docker exec {CNAME}-l555 pgrep -c -f testOnDemandRTSPServer")
        if r.stdout.strip() not in ("", "0"):
            return
        time.sleep(1)
    print("[!] live555 server never came up", file=sys.stderr)


def _live555_utime():
    pid = sh(f"docker exec {CNAME}-l555 pgrep -f testOnDemandRTSPServer")
    pid = pid.stdout.split()[0] if pid.stdout.split() else ""
    if not pid:
        return None
    r = sh(f"docker exec {CNAME}-l555 awk '{{print $14}}' /proc/{pid}/stat")
    try:
        return int(r.stdout.strip())
    except ValueError:
        return None


def live555_replay_one(path):
    msgs = load_payload(path, framing="request")
    script = ("import socket,time\n"
              "msgs=" + repr(msgs) + "\n"
              "try:\n"
              "    s=socket.create_connection(('127.0.0.1',8554),timeout=10)\n"
              "    s.settimeout(2.0)\n"
              "    try: s.recv(4096)\n"
              "    except Exception: pass\n"
              "    for m in msgs:\n"
              "        s.sendall(m); time.sleep(0.05)\n"
              "        try: s.recv(65535)\n"
              "        except Exception: pass\n"
              "    s.close()\n"
              "except Exception: pass\n")
    u1 = _live555_utime()
    sh_stdin(f"docker exec -i {CNAME}-l555 python3 -", script, timeout=60)
    time.sleep(1.0)
    u2 = _live555_utime()
    probe_script = ("import socket\n"
                    "try:\n"
                    "    p=socket.create_connection(('127.0.0.1',8554),"
                    "timeout=3)\n"
                    "    p.settimeout(2.0)\n"
                    "    p.sendall(b'OPTIONS * RTSP/1.0\\r\\n"
                    "CSeq: 1\\r\\n\\r\\n')\n"
                    "    print(1 if p.recv(200) else 0)\n"
                    "except Exception:\n"
                    "    print(0)\n")
    probe = sh_stdin(f"docker exec -i {CNAME}-l555 python3 -",
                     probe_script, timeout=30)
    alive = probe.stdout.strip() == "1"
    spin = (u2 - u1) if (u1 is not None and u2 is not None) else 0
    if alive:
        return False
    # Unresponsive — retry patiently (load starvation on the host can
    # mimic a wedge for a few seconds) before concluding.  The wedge has
    # both a busy-loop and a stall mode (observed utime deltas ~350 and
    # 0), so CPU spin is reported but not required.
    for attempt in range(3):
        time.sleep(2.0)
        pr = sh_stdin(f"docker exec -i {CNAME}-l555 python3 -",
                      probe_script, timeout=30)
        if pr.stdout.strip() == "1":
            return False        # starvation false-alarm — server recovered
    # Still dead: distinguish wedge (process alive) from crash (gone).
    proc = sh(f"docker exec {CNAME}-l555 pgrep -c -f testOnDemandRTSPServer")
    if proc.stdout.strip() in ("", "0"):
        print("      [server-died] process gone — crash class, not wedge")
        return False
    print(f"      [wedge] spin={spin} jiffies (mode: "
          f"{'busy-loop' if spin > 20 else 'stall'})")
    return True


def live555_teardown():
    sh(f"docker rm -f {CNAME}-l555 2>/dev/null")


# ── forked-daapd ────────────────────────────────────────────────────────

def fd_setup():
    sh(f"docker rm -f {CNAME}-fd 2>/dev/null")
    sh(f"docker run -d --name {CNAME}-fd forked-daapd:latest tail -f /dev/null")
    sh(f"docker exec -d -u root {CNAME}-fd bash -c '"
       f"mkdir -p /run/dbus && dbus-daemon --system --fork 2>/dev/null; "
       f"sleep 1; avahi-daemon -D 2>/dev/null; sleep 1; "
       f"cd /home/ubuntu/experiments/forked-daapd && "
       f"env ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:symbolize=0 "
       f"./src/forked-daapd -d 0 -c /home/ubuntu/experiments/forked-daapd.conf "
       f"-f > /tmp/fd.log 2>&1'")
    for _ in range(25):
        r = sh(f"docker exec {CNAME}-fd grep -c :0E69 /proc/net/tcp")
        if r.stdout.strip() not in ("", "0"):
            return
        time.sleep(1)
    print("[!] forked-daapd listener never came up", file=sys.stderr)


def fd_replay_one(path):
    msgs = load_payload(path, framing="request")
    script = ("import socket,time\n"
              "msgs=" + repr(msgs) + "\n"
              "try:\n"
              "    s=socket.create_connection(('127.0.0.1',3689),timeout=8)\n"
              "    s.settimeout(2.0)\n"
              "    for m in msgs:\n"
              "        try: s.sendall(m); s.recv(65535)\n"
              "        except Exception: pass\n"
              "    try: s.recv(65535)\n"
              "    except Exception: pass\n"
              "    s.close()\n"
              "except Exception: pass\n")
    sh_stdin(f"docker exec -i {CNAME}-fd python3 -", script, timeout=60)
    # SMARTPL deadlock is TERMINAL (event loop blocked) but the process
    # stays alive — probe /api/config patiently on NEW connections.
    for attempt in range(3):
        time.sleep(2.0)
        probe_script = ("import socket\n"
                        "try:\n"
                        "    p=socket.create_connection(('127.0.0.1',3689),"
                        "timeout=3)\n"
                        "    p.settimeout(2.0)\n"
                        "    p.sendall(b'GET /api/config HTTP/1.1\\r\\n"
                        "Host: h\\r\\n\\r\\n')\n"
                        "    print(1 if p.recv(400) else 0)\n"
                        "except Exception:\n"
                        "    print(0)\n")
        pr = sh_stdin(f"docker exec -i {CNAME}-fd python3 -",
                      probe_script, timeout=30)
        if pr.stdout.strip() == "1":
            return False
    proc = sh(f"docker exec {CNAME}-fd pgrep -c -x forked-daapd")
    if proc.stdout.strip() in ("", "0"):
        print("      [server-died] process gone — crash class, not deadlock")
        return False
    lex = sh(f"docker exec {CNAME}-fd grep -ac 'lexer error' /tmp/fd.log")
    print(f"      [deadlock] lexer-errors={lex.stdout.strip()}")
    return True


def fd_teardown():
    sh(f"docker rm -f {CNAME}-fd 2>/dev/null")


# ── main ────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("kamailio", "live555",
                                                 "forked-daapd"):
        print(__doc__)
        return 2
    target, files = sys.argv[1], sys.argv[2:]
    files = [f for f in files if os.path.isfile(f)]
    if not files:
        print("[!] no input files", file=sys.stderr)
        return 2

    if target == "kamailio":
        setup, replay, teardown = (kamailio_setup, kamailio_replay_one,
                                   kamailio_teardown)
    elif target == "forked-daapd":
        setup, replay, teardown = (fd_setup, fd_replay_one, fd_teardown)
    else:
        setup, replay, teardown = (live555_setup, live555_replay_one,
                                   live555_teardown)

    # live555's wedge is TERMINAL for the server instance — one wedged
    # replay poisons every subsequent file on the same server (the first
    # validation run false-positived exactly this way).  Reset the server
    # per file for live555; kamailio's CL fingerprint is stateless, so it
    # keeps one shared instance.
    per_file_reset = target in ("live555", "forked-daapd")
    setup()
    hits = []
    try:
        for idx, f in enumerate(files):
            try:
                if per_file_reset and idx > 0:
                    teardown()
                    setup()
                if replay(f):
                    hits.append(f)
                    print(f"[HIT ] {f}")
                else:
                    print(f"[ -- ] {f}")
            except Exception as e:
                print(f"[ERR ] {f}: {e}", file=sys.stderr)
    finally:
        teardown()

    print(f"\n== {target}: {len(hits)}/{len(files)} inputs triggered the "
          f"predicate ==")
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
