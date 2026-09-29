import tarfile, sys
try:
    with tarfile.open(sys.argv[1], "r:gz") as tf:
        for m in tf.getnames():
            if m.endswith("fuzzer_stats"):
                c = tf.extractfile(m).read().decode()
                s = {}
                for line in c.split("\n"):
                    p = line.split(":", 1)
                    if len(p) == 2:
                        s[p[0].strip()] = p[1].strip()
                if "start_time" in s and "last_update" in s:
                    print(int((int(s["last_update"]) - int(s["start_time"])) / 60))
                else:
                    print(-1)
                break
        else:
            print(-1)
except:
    print(-2)
