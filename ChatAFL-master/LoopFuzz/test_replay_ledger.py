import socket, struct, subprocess, threading, json, os, sys, time
def server(port, mode):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.1",port)); s.listen(1)
    c,_=s.accept()
    try:
        if mode=="normal":
            for expect in (b"USER x\r\n", b"PASS y\r\n", b"QUIT\r\n"):
                got=b""
                while len(got)<len(expect):
                    chunk=c.recv(len(expect)-len(got))
                    if not chunk: break
                    got+=chunk
                if got!=expect: break
                c.sendall(b"200 OK\r\n")
        elif mode=="close-early":
            got=b""
            while not got.endswith(b"\r\n"):
                chunk=c.recv(1)
                if not chunk: break
                got+=chunk
            c.sendall(b"200 OK\r\n"); c.close()
    except Exception: pass
    try: c.close()
    except: pass
    s.close()
# framed input: 3 frames
frames=b"".join(struct.pack("<I",len(p))+p for p in [b"USER x\r\n",b"PASS y\r\n",b"QUIT\r\n"])
open("/tmp/frames.bin","wb").write(frames)
failed = False
for i,(mode,expect) in enumerate([("normal","eof"),("close-early","NOT-eof")]):
    port=59600+i
    t=threading.Thread(target=server,args=(port,mode),daemon=True); t.start()
    time.sleep(0.3)
    env=dict(os.environ); env["LOOPFUZZ_REPLAY_LEDGER"]=f"/tmp/ledger_{mode}.jsonl"
    result = subprocess.run(["./aflnet-replay","/tmp/frames.bin","FTP",str(port),"59610","200","200"],
                   env=env,capture_output=True,timeout=20)
    rows=[json.loads(l) for l in open(f"/tmp/ledger_{mode}.jsonl")]
    end=[r for r in rows if r["event"]=="session_end"][0]
    fr=[r for r in rows if r["event"]=="frame"]
    ok = (end["stop_reason"] == "eof") if expect=="eof" else (end["stop_reason"] != "eof")
    # normal: 3 frames all send_complete
    if mode=="normal":
        ok = ok and result.returncode==0 and len(fr)==3 and all(r["sent_bytes"]==r["len"] for r in fr) and end["frames_total"]==3
    else:
        # An early FIN stops replay before attempting any trailing frame.
        ok = ok and result.returncode==2 and end["stop_reason"]=="peer-closed-before-input-end"
        ok = ok and len(fr)==1 and end["frames_total"]==1 and end["peer_closed"]
        ok = ok and fr[0]["send_attempt"] and fr[0]["sent_bytes"]==fr[0]["len"]
    print(f"{mode}: stop={end['stop_reason']} frames_ledgered={len(fr)} -> {'PASS' if ok else 'FAIL'}")
    failed = failed or not ok
raise SystemExit(1 if failed else 0)
