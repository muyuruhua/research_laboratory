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
REPLAY_BIN=${REPLAY_BIN:-/opt/aflnet-replay}
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
pack(["USER ubuntu\r\n", "PASS ubuntu\r\n", "TYPE I\r\n",
      "RETR smoke-compressed.txt.gz\r\n", "QUIT\r\n"],
     "id:000007,smoke-compressed-retr.raw")
pack(["USER ubuntu\r\n", "SYST\nQUITgarbage\r\n", "NOOP\r\n"],
     "id:000008,smoke-protocol-end.raw")
pack(["USER ubuntu\r\n", "PASS ubuntu\r\n", "PASV\r\n",
      "PORT 127,0,0,1,14,178\r\n", "NOOP\r\n", "QUIT\r\n"],
     "id:000009,smoke-pasv-port.raw")
pack(["USER ubuntu\r\n", "PASS ubuntu\r\n",
      "STOR smoke-compressed.txt.gz\r\n", "NOOP\r\n", "QUIT\r\n"],
     "id:000010,smoke-stor-error.raw")
PYEOF
cat > "$WORK/corpus/queue-checkpoints.jsonl" << 'EOF'
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000001,smoke-login.raw","queue_id":1,"kind":"discovery","discovery_time_ms":1790000000000,"monotonic_ms":1000,"discovery_execution_id":1}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000002,smoke-nologin.raw","queue_id":2,"kind":"discovery","discovery_time_ms":1790000001000,"monotonic_ms":2000,"discovery_execution_id":2}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000003,smoke-list.raw","queue_id":3,"kind":"discovery","discovery_time_ms":1790000002000,"monotonic_ms":3000,"discovery_execution_id":3}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000004,smoke-peer-close.raw","queue_id":4,"kind":"discovery","discovery_time_ms":1790000003000,"monotonic_ms":4000,"discovery_execution_id":4}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000005,smoke-anonymous.raw","queue_id":5,"kind":"discovery","discovery_time_ms":1790000004000,"monotonic_ms":5000,"discovery_execution_id":5}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000006,smoke-anonymous-alias.raw","queue_id":6,"kind":"discovery","discovery_time_ms":1790000005000,"monotonic_ms":6000,"discovery_execution_id":6}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000007,smoke-compressed-retr.raw","queue_id":7,"kind":"discovery","discovery_time_ms":1790000006000,"monotonic_ms":7000,"discovery_execution_id":7}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000008,smoke-protocol-end.raw","queue_id":8,"kind":"discovery","discovery_time_ms":1790000007000,"monotonic_ms":8000,"discovery_execution_id":8}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000009,smoke-pasv-port.raw","queue_id":9,"kind":"discovery","discovery_time_ms":1790000008000,"monotonic_ms":9000,"discovery_execution_id":9}
{"schema_version":1,"campaign_id":"gcda-smoke-1","filename":"id:000010,smoke-stor-error.raw","queue_id":10,"kind":"discovery","discovery_time_ms":1790000009000,"monotonic_ms":10000,"discovery_execution_id":10}
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
cp "$ANALYSIS/reset_commands/bftpd.sh" "$WORK/reset-base.sh"
cat > "$WORK/reset.sh" << 'EOF'
#!/bin/bash
set -e
/smoke/reset-base.sh
python3 - << 'PYEOF'
import gzip
with gzip.open("/home/ubuntu/ftpshare/smoke-compressed.txt.gz", "wb") as target:
    target.write(b"coverage replay compressed transfer fixture\\n")
PYEOF
EOF
chmod +x "$WORK/reset.sh"

docker run --rm \
  -v "$ANALYSIS/coverage_v4.py":/opt/coverage_v4.py:ro \
  -v "$ANALYSIS/install_bftpd_coverage_exit.py":/opt/install_bftpd_coverage_exit.py:ro \
  -v "$WORK":/smoke \
  -v "$REPLAY_BIN":/opt/aflnet-replay:ro \
  -e COVERAGE_V4_LOOPFUZZ_REPLAYER=/opt/aflnet-replay \
  -w /home/ubuntu/experiments/bftpd-gcov \
  -e WORKDIR=/home/ubuntu/experiments \
  -e COVERAGE_V4_MODULE=/opt/coverage_v4.py \
  -e COVERAGE_V4_RESET_COMMAND_JSON='["/smoke/reset.sh"]' \
  "$IMAGE" bash -c '
    set -e
    python3 /opt/install_bftpd_coverage_exit.py /home/ubuntu/experiments/bftpd-gcov
    mkdir -p /smoke/source
    cp *.c *.h *.gcno bftpd coverage-exit-policy.json /smoke/source/
    python3 - << "PYEOF"
from pathlib import Path
config = Path("/home/ubuntu/experiments/basic.conf").read_text()
assert "GZ_DOWNLOAD=\"no\"" in config
config = config.replace("GZ_DOWNLOAD=\"no\"", "GZ_DOWNLOAD=\"yes\"")
Path("/smoke/smoke.conf").write_text(config)
PYEOF
    COVERAGE_V4_TARGET_CONFIG=/smoke/smoke.conf python3 /opt/coverage_v4.py replay --target bftpd --folder /smoke/corpus \
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
policy = json.loads((work/"source/coverage-exit-policy.json").read_text())
assert policy.get("data_channel_policy") == "COVERAGE_REPLAY_DATA_CHANNEL_CONTROL_FD_V1", policy
assert policy.get("data_channel_fd_ownership") == \
    "COVERAGE_REPLAY_DATA_CHANNEL_DUP_FD_OWNERSHIP_V1", policy
binary = (work / "source/bftpd").read_bytes()
assert b"COVERAGE_REPLAY_DATA_CHANNEL_CONTROL_FD_V1" in binary
assert b"COVERAGE_REPLAY_DATA_CHANNEL_DUP_FD_OWNERSHIP_V1" in binary
assert b"COVERAGE_REPLAY_PASSIVE_TO_ACTIVE_FD_OWNERSHIP_V1" in binary
assert b"COVERAGE_REPLAY_DATA_SOCKET_LIFECYCLE_V1" in binary
list_checkpoint = next(c for name, c in by_file.items() if "smoke-list.raw" in name)
list_log = (work / "out/cov.csv.v4" / ("replay-%06d.log" %
            list_checkpoint["queue_id"])).read_text()
assert "150 BINARY data connection established." in list_log, list_log
assert "226 Directory list has been submitted." in list_log, list_log
compressed = next(c for name, c in by_file.items() if "smoke-compressed-retr.raw" in name)
compressed_log = (work / "out/cov.csv.v4" / ("replay-%06d.log" %
                 compressed["queue_id"])).read_text()
assert "150 BINARY data connection established." in compressed_log, compressed_log
assert "226 File transmission successful." in compressed_log, compressed_log
assert "221 See you later..." in compressed_log, compressed_log
protocol_end = next(c for name, c in by_file.items() if "smoke-protocol-end.raw" in name)
assert protocol_end["replay"]["bftpd_protocol_end_expected"] is True, protocol_end
assert protocol_end["replay"]["sent_prefix_has_bftpd_quit"] is True, protocol_end
assert protocol_end["replay"]["last_attempted_frame_is_quit"] is False, protocol_end
assert protocol_end["replay"]["frames_unattempted"] > 0, protocol_end
pasv_port = next(c for name, c in by_file.items() if "smoke-pasv-port.raw" in name)
pasv_port_log = (work / "out/cov.csv.v4" / ("replay-%06d.log" %
                 pasv_port["queue_id"])).read_text()
assert "200 PORT 127.0.0.1:3762 OK" in pasv_port_log, pasv_port_log
assert "221 See you later..." in pasv_port_log, pasv_port_log
assert pasv_port["replay"]["send_completeness"] == "complete", pasv_port
stor_error = next(c for name, c in by_file.items() if "smoke-stor-error.raw" in name)
stor_error_log = (work / "out/cov.csv.v4" / ("replay-%06d.log" %
                  stor_error["queue_id"])).read_text()
assert "553 Error: Remote file is write protected." in stor_error_log, stor_error_log
assert "221 See you later..." in stor_error_log, stor_error_log
assert stor_error["replay"]["send_completeness"] == "complete", stor_error
missing = sum(1 for c in cps if (c.get("replay") or {}).get("session_coverage_missing"))
print(f"SMOKE PASS: login imported {len(r['imported_gcda'])} gcda; "
      f"{missing}/{len(cps)} checkpoints missing coverage; "
      f"union branches={len(terminal['covered_branch_ids'])}; "
      f"LIST=226; compressed_RETR=226+QUIT=221; "
      f"nologin_missing={(nologin or {}).get('replay', {}).get('session_coverage_missing')}")
EOF
