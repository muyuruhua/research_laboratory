import socket, struct, subprocess, threading, json, os, time, sys
CASES = {
 "single":            (b"220 welcome\r\n", ["220"]),
 "multiline-feat-421body": (b"214-Features:\r\n MFMT\r\n421 fake inside\r\n214 End.\r\n421 real close\r\n", ["214","421"]),
 "digits-body":       (b"500-X\r\n123 digits body\r\n500 end\r\n", ["500"]),
 "incomplete-ml":     (b"220 hi\r\n214-Features:\r\n MFMT\r\n", ["220"]),
 "consecutive":       (b"331 user ok\r\n230 logged in\r\n257 path\r\n", ["331","230","257"]),
 "binary-short":      (b"\x00\x01\x02\r\nab\r\n\r\n12\r\n220 ok\r\n", ["220"]),
 "no-final-crlf":     (b"220 no crlf", ["220"]),
 "banner-feat-421":   (b"220-a\r\n220-b\r\n220 c\r\n530 login\r\n214-Features:\r\n MFMT\r\n REST\r\n214 End.\r\n421 Unable to set up\r\n", ["220","530","214","421"]),
}
results=[]
for idx,(name,(payload,expect)) in enumerate(CASES.items()):
    port=(50000+(os.getpid()%4000)*3)+idx*2
    def srv(p=payload,port=port):
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(("127.0.0.1",port)); s.listen(1); s.settimeout(10)
        c,_=s.accept()
        try:
            c.sendall(p)
            for _ in range(3):
                hdr=c.recv(4)
                if len(hdr)<4: break
                (l,)=struct.unpack("<I",hdr);
                if l: c.recv(l)
        except Exception: pass
        time.sleep(0.4)
        try: c.close()
        except: pass
        s.close()
    t=threading.Thread(target=srv,daemon=True); t.start(); time.sleep(0.6)
    frames=b"".join(struct.pack("<I",len(p))+p for p in [b"USER x\r\n",b"PASS y\r\n",b"SYST\r\n"])
    open("/tmp/f.bin","wb").write(frames)
    env=dict(os.environ); env["LOOPFUZZ_REPLAY_LEDGER"]="/tmp/l.jsonl"
    r=subprocess.run(["./aflnet-replay","/tmp/f.bin","FTP",str(port),str(port+1),"150","150"],
                     env=env,capture_output=True,timeout=15)
    out=r.stderr.decode(errors="replace")
    import re
    m=re.search(r"Responses from server:0((?:-\d+)*)-", out)
    got=[c for c in (m.group(1).strip("-").split("-") if m else []) if c]
    ok = got==expect
    results.append(ok)
    print(f"{name:24s} expect={expect} got={got} -> {'PASS' if ok else 'FAIL'}")
overall = all(results)
print("ALL", "PASS" if overall else "FAIL")
sys.exit(0 if overall else 1)
