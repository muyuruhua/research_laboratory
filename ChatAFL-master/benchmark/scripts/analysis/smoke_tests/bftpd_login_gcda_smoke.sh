#!/bin/bash
# Smoke test: bftpd 登录成功会话的 gcda 采集（2026-10-31 根因修复的验收测试）。
#
# 缺陷：coverage_v4 以前以 root 建立 jail 内镜像目录（默认 0755）；bftpd
# DO_CHROOT=yes 登录后 chroot + setuid(ubuntu) 且 gcov.patch 在 chroot 内
# unsetenv(GCOV_PREFIX)，降权会话子进程无法在镜像目录创建 .gcda →
# 登录成功会话的覆盖被静默丢弃（20261027/20261031 批 93-95% 回放
# session_coverage_missing，且与登录成功完全相关）。
#
# 修复：jail 内镜像目录 chmod 0777；coverage-only chroot wrapper 对
# regular / anonymous / FILE_AUTH 全部成功 chroot 统一清除 GCOV_PREFIX。
#
# 本测试在真实镜像内走 coverage_v4 完整 replay 管线（含 reset 契约），
# 断言：
#   1) 登录成功输入的 checkpoint：imported_gcda 非空 且
#      session_coverage_missing=false；
#   2) 全部 checkpoint 无 session_coverage_missing；
#   3) terminal.json 的 covered_branch_ids 非空。
# 用法：IMAGE=bftpd:salvage4 ./bftpd_login_gcda_smoke.sh
set -u
IMAGE=${IMAGE:-bftpd:salvage4}
HERE=$(cd "$(dirname "$0")" && pwd)
ANALYSIS=$(cd "$HERE/.." && pwd)
REPO=$(cd "$ANALYSIS/../../.." && pwd)
WORK=${WORK:-$(mktemp -d /tmp/bftpd-gcda-smoke.XXXXXX)}
mkdir -p "$WORK"
echo "Evidence directory: $WORK"

mkdir -p "$WORK/corpus/replayable-queue"
# replayable-queue 格式 = 重复的 [u32 LE 长度][消息字节]（与 fuzzer 写出一致）
python3 - "$WORK/corpus/replayable-queue" << 'PYEOF'
import struct, sys, pathlib
out = pathlib.Path(sys.argv[1])
def pack(msgs, name):
    with (out / name).open("wb") as f:
        for m in msgs:
            f.write(struct.pack("<I", len(m)))
            f.write(m.encode())
# 登录成功会话（触发 chroot + setuid + unsetenv(GCOV_PREFIX) 路径）。
# 正常退出对照。LIST及提前断开输入也必须保留gcda。
pack(["USER ubuntu\r\n", "PASS ubuntu\r\n", "SYST\r\n", "TYPE I\r\n",
      "PWD\r\n", "QUIT\r\n"], "id:000001,smoke-login.raw")
# 未登录会话（对照组，历史上 gcda 正常）
pack(["USER nosuchuser\r\n", "QUIT\r\n"], "id:000002,smoke-nologin.raw")
pack(["USER ubuntu\r\n", "PASS ubuntu\r\n", "LIST\r\n"], "id:000003,smoke-list.raw")
pack(["USER ubuntu\r\n", "PASS ubuntu\r\n", "SYST\r\n"] * 4, "id:000004,smoke-peer-close.raw")
pack(["USER ftp\r\n", "PASS anonymous@example.test\r\n", "PWD\r\n", "QUIT\r\n"],
     "id:000005,smoke-anonymous.raw")
pack(["USER anonymous\r\n", "PASS anonymous@example.test\r\n", "LIST\r\n"],
     "id:000006,smoke-anonymous-alias.raw")
PYEOF
cat > "$WORK/corpus/queue-checkpoints.jsonl" << 'EOF'
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000001,smoke-login.raw","queue_id":1,"kind":"discovery","discovery_time_ms":1790000000000,"monotonic_ms":1000,"discovery_execution_id":1}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000002,smoke-nologin.raw","queue_id":2,"kind":"discovery","discovery_time_ms":1790000001000,"monotonic_ms":2000,"discovery_execution_id":2}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000003,smoke-list.raw","queue_id":3,"kind":"discovery","discovery_time_ms":1790000002000,"monotonic_ms":3000,"discovery_execution_id":3}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000004,smoke-peer-close.raw","queue_id":4,"kind":"discovery","discovery_time_ms":1790000003000,"monotonic_ms":4000,"discovery_execution_id":4}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000005,smoke-anonymous.raw","queue_id":5,"kind":"discovery","discovery_time_ms":1790000004000,"monotonic_ms":5000,"discovery_execution_id":5}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000006,smoke-anonymous-alias.raw","queue_id":6,"kind":"discovery","discovery_time_ms":1790000005000,"monotonic_ms":6000,"discovery_execution_id":6}
EOF
mkdir -p "$WORK/file-auth-corpus/replayable-queue"
python3 - "$WORK/file-auth-corpus" << 'PYEOF'
import json, pathlib, struct, sys
out = pathlib.Path(sys.argv[1])
name = "id:000001,smoke-file-auth.raw"
with (out / "replayable-queue" / name).open("wb") as target:
    for message in [b"USER virtual\r\n", b"PASS secret\r\n", b"PWD\r\n", b"QUIT\r\n"]:
        target.write(struct.pack("<I", len(message)) + message)
record = dict(schema_version=1, campaign_id="gcda-file-auth-smoke-1", filename=name,
              queue_id=1, kind="discovery", discovery_time_ms=1790000000000,
              monotonic_ms=1000, discovery_execution_id=1)
(out / "queue-checkpoints.jsonl").write_text(json.dumps(record) + "\n")
PYEOF
cp "$ANALYSIS/reset_commands/bftpd.sh" "$WORK/reset.sh"
chmod +x "$WORK/reset.sh"

docker run --rm \
  -v "$ANALYSIS/coverage_v4.py":/opt/coverage_v4.py:ro \
  -v "$ANALYSIS/install_bftpd_coverage_exit.py":/opt/install_bftpd_coverage_exit.py:ro \
  -v "$WORK":/smoke \
  -w /home/ubuntu/experiments/bftpd-gcov \
  -e WORKDIR=/home/ubuntu/experiments \
  -e COVERAGE_V4_MODULE=/opt/coverage_v4.py \
  -e COVERAGE_V4_RESET_COMMAND_JSON='["/smoke/reset.sh"]' \
  "$IMAGE" bash -c '
    set -e
    python3 /opt/install_bftpd_coverage_exit.py /home/ubuntu/experiments/bftpd-gcov
    mkdir -p /smoke/source
    cp *.c *.h *.gcno bftpd coverage-exit-policy.json /smoke/source/
    python3 /opt/coverage_v4.py replay --target bftpd --folder /smoke/corpus \
      --port 21 --step 1 --output /smoke/out/cov.csv --mode 1 --require-coordinates
    python3 /opt/coverage_v4.py audit /smoke/out/cov.csv
    python3 - << "PYEOF"
from pathlib import Path
config = Path("/home/ubuntu/experiments/basic.conf").read_text()
config = config.replace("#FILE_AUTH=\"/etc/ftpdpassword\"", "FILE_AUTH=\"/smoke/auth.txt\"")
assert "FILE_AUTH=\"/smoke/auth.txt\"" in config
Path("/smoke/file-auth.conf").write_text(config)
Path("/smoke/auth.txt").write_text("virtual secret users /home/ubuntu/ftpshare\n")
PYEOF
    COVERAGE_V4_TARGET_CONFIG=/smoke/file-auth.conf python3 /opt/coverage_v4.py replay \
      --target bftpd --folder /smoke/file-auth-corpus --port 21 --step 1 \
      --output /smoke/file-auth-out/cov.csv --mode 1 --require-coordinates
    python3 /opt/coverage_v4.py audit /smoke/file-auth-out/cov.csv
    chown -R '"$(id -u):$(id -g)"' /smoke/out /smoke/source /smoke/file-auth-out 2>/dev/null || true
  ' > "$WORK/replay.log" 2>&1 || { echo "FAIL: replay pipeline errored"; tail -20 "$WORK/replay.log"; docker run --rm -v "$WORK":/smoke "$IMAGE" bash -c 'chown -R '"$(id -u):$(id -g)"' /smoke 2>/dev/null || true'; exit 1; }

python3 - "$WORK" << 'EOF'
import json, sys, pathlib
work = pathlib.Path(sys.argv[1])
cps = [json.loads(l) for l in (work/"out/cov.csv.v4/checkpoints.jsonl").open()]
by_file = {c["path"].split("/")[-1]: c for c in cps if c.get("kind") == "discovery"}
login = next((c for k, c in by_file.items() if "smoke-login" in k), None)
nologin = next((c for k, c in by_file.items() if "smoke-nologin" in k), None)
assert login is not None, "login input was not replayed"
r = login["replay"]
assert r.get("imported_gcda"), \
    "LOGIN SESSION STILL LOSES GCDA: imported_gcda empty (fix not effective)"
assert r.get("session_coverage_missing") is False, \
    "LOGIN SESSION STILL flagged session_coverage_missing"
terminal = json.load((work/"out/cov.csv.v4/terminal.json").open())
assert terminal.get("covered_branch_ids"), "terminal union is empty"
assert terminal.get("coverage_complete") is True, terminal
assert all(c["replay"].get("coverage_complete") for c in cps), cps
for marker in ("smoke-anonymous.raw", "smoke-anonymous-alias.raw"):
    checkpoint = next(c for name, c in by_file.items() if marker in name)
    assert checkpoint["replay"].get("imported_gcda"), checkpoint
    assert not checkpoint["replay"].get("session_coverage_missing"), checkpoint
for index in (1, 3, 4, 5, 6):
    replay_log = (work / "out/cov.csv.v4" / ("replay-%06d.log" % index)).read_text()
    assert "230 User logged in." in replay_log, replay_log
file_auth = json.loads((work/"file-auth-out/cov.csv.v4/checkpoints.jsonl").read_text().splitlines()[0])
assert file_auth["replay"].get("coverage_complete") is True, file_auth
assert file_auth["replay"].get("imported_gcda"), file_auth
file_auth_log = (work/"file-auth-out/cov.csv.v4/replay-000001.log").read_text()
assert "230 User logged in." in file_auth_log, file_auth_log
file_auth_terminal = json.loads((work/"file-auth-out/cov.csv.v4/terminal.json").read_text())
assert file_auth_terminal.get("coverage_complete") is True, file_auth_terminal
assert any(c["replay"].get("sigpipe_normal_exit_observed") for c in cps), \
    "fixture did not exercise the SIGPIPE normal-exit path"
missing = sum(1 for c in cps if (c.get("replay") or {}).get("session_coverage_missing"))
print(f"SMOKE PASS: login imported {len(r['imported_gcda'])} gcda; "
      f"{missing}/{len(cps)} checkpoints missing coverage; "
      f"union branches={len(terminal['covered_branch_ids'])}; "
      f"nologin_missing={(nologin or {}).get('replay', {}).get('session_coverage_missing')}")
EOF
