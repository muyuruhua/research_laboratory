#!/usr/bin/env python3
"""
ChatAFL-Opt 漏洞复现工具集
============================
提供 seed 格式重构 + Docker 容器内重放 + 安全属性验证。

种子格式：
  AFLNet 格式 (replayable-crashes/):
    [u32 LE 长度][请求数据] [u32 LE 长度][请求数据] ...
    工具: aflnet-replay  — 逐请求发送，每个请求前后有 recv/send/recv 周期

  AFL 格式 (queue/):
    原始 FTP 命令拼接，\r\n 分隔
    工具: afl-replay  — 整个文件一次性 net_send

Violation 报告的 REQUEST DATA:
    原始 FTP 命令拼接（= AFL 格式），可直接用于 afl-replay。
    需解析拆分后才能构建 AFLNet 格式。

漏洞验证判据 (来自 FindVulnerability.txt):
    "漏洞不是 bug，而是安全属性被破坏"
    — 程序有没有做了安全上不该做的事？
"""

import os
import re
import struct
import sys
import tarfile
import tempfile
import subprocess
import argparse
import textwrap
from pathlib import Path
from typing import Optional, Tuple, List, Dict
from dataclasses import dataclass, field


# ── 常量 ──────────────────────────────────────────────────

PROTOCOL_PORT = {"FTP": 21, "SMTP": 25, "RTSP": 554, "SIP": 5060,
                 "MQTT": 1883, "HTTP": 80, "DAAP": 3689}

ORACLE_CATEGORY_NAMES = {
    0x0001: "AUTH_BYPASS (Authentication 认证绕过)",
    0x0002: "AUTHZ_BYPASS (Authorization 授权绕过)",
    0x0004: "STATE_VIOLATION (State Consistency 状态一致性违规)",
    0x0008: "INFO_LEAK (Confidentiality 机密性/信息泄露)",
    0x0010: "PATH_TRAVERSAL (Integrity 完整性/路径遍历)",
    0x0020: "INJECTION (Integrity 完整性/注入)",
    0x0040: "DOS (Availability 可用性/拒绝服务)",
    0x0080: "RESOURCE_EXHAUST (Availability 可用性/资源耗尽)",
    0x0100: "ISOLATION (Isolation 隔离性逃逸)",
    0x0200: "REPLAY (State Consistency 状态一致性/双花)",
    0x0400: "SMUGGLING (Integrity 完整性/请求走私)",
}

SEVERITY_NAMES = {
    1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"
}


# ── 数据结构 ──────────────────────────────────────────────

@dataclass
class ViolationInfo:
    """从 violation 报告中解析出的结构化信息。"""
    report_path: str = ""
    max_severity: int = 0
    categories_hit: int = 0
    violations: List[Dict] = field(default_factory=list)
    raw_request_data: bytes = b""
    request_len: int = 0
    raw_response_data: bytes = b""
    response_len: int = 0


@dataclass
class ReplayResult:
    """一次重放的结果。"""
    seed_path: str
    seed_type: str          # "crash" | "violation"
    seed_format: str        # "aflnet" | "afl"
    replay_rc: int
    server_exit_code: Optional[int]
    server_signal: Optional[int]
    asan_output: str
    server_responses: str
    reproduced: bool
    note: str


# ── Seed 重构：Violation → 可重放种子 ─────────────────────

def parse_violation_report(report_bytes: bytes, report_path: str = "") -> ViolationInfo:
    """解析 Protocol Oracle 生成的 violation 报告。

    报告格式 (由 protocol-oracle.c oracle_save_violation 生成):
        === PROTOCOL ORACLE VIOLATION REPORT ===
        Time: <unix_ts>
        Violations: <count>
        Max Severity: <1-5>
        Categories: 0x<hex>
        --- Violation N ---
        Severity: N
        Category: 0x<hex>
        Description: <text>
        Request Index: N
        Pattern Hash: 0x<hex>
        === REQUEST DATA (<len> bytes) ===
        <raw bytes>
        === RESPONSE DATA (<len> bytes) ===
        <raw bytes>
    """
    info = ViolationInfo(report_path=report_path)

    text = report_bytes.decode("latin-1")

    # Parse header fields
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("Max Severity:"):
            info.max_severity = int(line.split(":")[1].strip())
        elif line.startswith("Categories:"):
            info.categories_hit = int(line.split(":")[1].strip(), 16)

    # Parse individual violations
    viol_sections = re.split(r"--- Violation \d+ ---\n", text)
    for section in viol_sections[1:]:  # skip header
        v = {}
        for line in section.strip().split("\n"):
            line = line.strip()
            if ":" in line and not line.startswith("="):
                key, _, val = line.partition(":")
                v[key.strip()] = val.strip()
        if v:
            info.violations.append(v)

    # Extract raw request data
    req_match = re.search(
        rb"=== REQUEST DATA \((\d+) bytes\) ===\n", report_bytes)
    if req_match:
        info.request_len = int(req_match.group(1))
        start = req_match.end()
        info.raw_request_data = report_bytes[start:start + info.request_len]

    # Extract raw response data
    resp_match = re.search(
        rb"=== RESPONSE DATA \((\d+) bytes\) ===\n", report_bytes)
    if resp_match:
        info.response_len = int(resp_match.group(1))
        start = resp_match.end()
        info.raw_response_data = report_bytes[start:start + info.response_len]

    return info


def split_ftp_requests(raw: bytes) -> List[bytes]:
    """将原始 FTP 请求数据拆分为独立的请求列表。

    FTP 协议以 \r\n 分隔命令。但 fuzzer 变异可能破坏分隔符。
    策略:
      1. 以 \r\n 作为主要分隔符
      2. 跨 \r\n 分割后，检查是否有只含 \r 的残留（被破坏的 CRLF）
      3. 每个请求保留其 \r\n 终止符
    """
    requests = []
    # 以 CRLF 分割
    parts = raw.split(b"\r\n")
    for part in parts:
        if not part:
            continue
        # 检查是否有孤立的 \r（被 mutation 破坏的 CRLF）
        # e.g. b'PWD\r\x02RNFR test' -> 第二个 \r 后跟的不是 \n
        sub = part.split(b"\r")
        for j, s in enumerate(sub):
            if j < len(sub) - 1:
                # 非最后一个片段：\r 后跟的不是 \n
                # 前一片段 + \r\n 作为一个请求；后一片段开始新请求
                requests.append(s + b"\r\n")
            else:
                # 最后一个片段
                if s:
                    requests.append(s + b"\r\n")
    return requests


def build_aflnet_seed(requests: List[bytes]) -> bytes:
    """构建 aflnet-replay 兼容种子: [u32 LE 长度][数据]..."""
    seed = b""
    for req in requests:
        seed += struct.pack("<I", len(req)) + req
    return seed


def build_afl_seed(raw: bytes) -> bytes:
    """构建 afl-replay 兼容种子: 原始字节直接拼接。"""
    return raw


# FTP 认证前缀（violation 报告的 REQUEST DATA 通常只包含触发违规的
# 请求子集，丢失了建立认证状态的 USER/PASS 前缀。从零开始重放时
# 必须补上，否则服务器返回 503 Bad sequence。）
FTP_AUTH_PREAMBLE = [
    b"USER ubuntu\r\n",
    b"PASS ubuntu\r\n",
]


def _raw_starts_with_user(raw: bytes) -> bool:
    """检查原始请求数据是否以 USER 命令开头。"""
    return (raw.startswith(b"USER ") or
            raw.startswith(b"USER\r") or
            raw.startswith(b"USER\n"))


def reconstruct_seeds_from_violation(
        report_bytes: bytes,
        prepend_auth: bool = True,
        auth_requests: List[bytes] = None
) -> Dict:
    """从 violation 报告重建可重放种子。

    Args:
        report_bytes: violation 报告原始字节
        prepend_auth: 是否在种子前补上 USER/PASS 认证前缀
        auth_requests: 自定义认证请求列表 (默认: ubuntu/ubuntu)

    Returns:
        {
            "aflnet": bytes,          # aflnet-replay 格式
            "afl": bytes,             # afl-replay 格式
            "raw": bytes,             # 原始 REQUEST DATA
            "requests": List[bytes],  # 解析后的请求列表（含 auth 前缀）
            "auth_prepended": bool,   # 是否补了 auth
        }
    """
    info = parse_violation_report(report_bytes)

    if not info.raw_request_data:
        raise ValueError("Violation report contains no REQUEST DATA")

    raw = info.raw_request_data
    requests = split_ftp_requests(raw)

    if auth_requests is None:
        auth_requests = list(FTP_AUTH_PREAMBLE)

    auth_prepended = False
    if prepend_auth and not _raw_starts_with_user(raw):
        requests = auth_requests + requests
        raw = b"".join(auth_requests) + raw
        auth_prepended = True

    return {
        "aflnet": build_aflnet_seed(requests),
        "afl": build_afl_seed(raw),
        "raw": raw,
        "requests": requests,
        "auth_prepended": auth_prepended,
        "info": info,
    }


# ── Docker 容器重放 ──────────────────────────────────────

DOCKER_IMAGE = "bftpd:latest"
CONTAINER_WORKDIR = "/home/ubuntu/experiments/bftpd"
CONTAINER_REPLAYER_DIR = "/home/ubuntu/chatafl-opt"


def _run_docker(seed_bytes: bytes, command: str,
                timeout: int = 30, asan_opts: str = "") -> Tuple[int, str, str]:
    """在 Docker 容器内执行命令，返回 (exit_code, stdout, stderr)."""
    with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as f:
        f.write(seed_bytes)
        seed_path = f.name

    full_cmd = f"""
cd {CONTAINER_WORKDIR}
export ASAN_OPTIONS="{asan_opts or 'abort_on_error=1:symbolize=1:detect_leaks=0'}"
{command}
"""

    try:
        result = subprocess.run(
            ["docker", "run", "--rm",
             "-v", f"{seed_path}:/tmp/seed_input",
             "-e", f"ASAN_OPTIONS={asan_opts or 'abort_on_error=1:symbolize=1:detect_leaks=0'}",
             DOCKER_IMAGE, "/bin/bash", "-c", full_cmd],
            capture_output=True, timeout=timeout,
        )
        rc = result.returncode
        stdout = result.stdout.decode("utf-8", errors="replace") if isinstance(result.stdout, bytes) else (result.stdout or "")
        stderr = result.stderr.decode("utf-8", errors="replace") if isinstance(result.stderr, bytes) else (result.stderr or "")
    except subprocess.TimeoutExpired:
        rc = -1
        stdout = ""
        stderr = "TIMEOUT"
    finally:
        try:
            os.unlink(seed_path)
        except OSError:
            pass

    return rc, stdout, stderr


def replay_crash(seed_bytes: bytes, protocol: str = "FTP",
                 port: int = 21, max_retries: int = 64) -> ReplayResult:
    """重放 crash 种子，检测服务器是否因 ASAN 崩溃而异常退出。

    方法: 循环重放（模拟 fuzzer fork-server 状态累积），
          检测服务器进程是否因信号终止。
    """
    cmd = f"""
./bftpd -D -c /home/ubuntu/experiments/basic.conf &
SRV_PID=$!
sleep 1

CRASHED=0
CRASH_SIG=0
for rep in $(seq 1 {max_retries}); do
    {CONTAINER_REPLAYER_DIR}/aflnet-replay /tmp/seed_input {protocol} {port} 0 >/dev/null 2>&1
    if ! kill -0 $SRV_PID 2>/dev/null; then
        wait $SRV_PID 2>/dev/null
        EC=$?
        if [ $EC -ge 128 ]; then
            CRASH_SIG=$((EC - 128))
        fi
        CRASHED=1
        break
    fi
done

if [ $CRASHED -eq 0 ]; then
    kill $SRV_PID 2>/dev/null
    wait $SRV_PID 2>/dev/null
fi

echo "CRASHED=$CRASHED"
echo "CRASH_SIG=$CRASH_SIG"

# Dump ASAN logs
for f in /tmp/asan.*; do
    [ -f "$f" ] && cat "$f" 2>/dev/null
done
"""

    rc, stdout, stderr = _run_docker(
        seed_bytes, cmd, timeout=120,
        asan_opts="abort_on_error=1:symbolize=1:detect_leaks=0:log_path=/tmp/asan")

    crashed = "CRASHED=1" in stdout
    sig_match = re.search(r"CRASH_SIG=(\d+)", stdout)
    crash_sig = int(sig_match.group(1)) if sig_match else None

    # Extract ASAN report
    asan_lines = []
    for line in stdout.split("\n"):
        if any(kw in line for kw in ["ERROR:", "AddressSanitizer",
                                       "heap-buffer", "stack-buffer",
                                       "use-after-free", "double-free"]):
            asan_lines.append(line)

    # Extract responses
    responses = stdout

    return ReplayResult(
        seed_path="/tmp/seed_input",
        seed_type="crash",
        seed_format="aflnet",
        replay_rc=rc,
        server_exit_code=crash_sig + 128 if crash_sig else None,
        server_signal=crash_sig,
        asan_output="\n".join(asan_lines),
        server_responses=responses[-2000:] if len(responses) > 2000 else responses,
        reproduced=crashed,
        note="Server crashed with signal" if crashed else
             f"Server survived {max_retries} replays"
    )


def replay_violation(seed_bytes: bytes, violation_info: ViolationInfo,
                     protocol: str = "FTP", port: int = 21,
                     auth_prepended: bool = False) -> ReplayResult:
    """重放 violation 种子并验证安全属性是否仍被违反。

    与 crash 重放的核心区别（来自 FindVulnerability.txt）:
      最重要的不是"程序有没有崩？"，而是"程序有没有做了安全上不该做的事？"
      → 判定标准：服务器响应码揭示安全属性是否被破坏
    """
    cmd = f"""
./bftpd -D -c /home/ubuntu/experiments/basic.conf &
SRV_PID=$!
sleep 1

echo "=== REPLAY_START ==="
{CONTAINER_REPLAYER_DIR}/aflnet-replay /tmp/seed_input {protocol} {port} 0 2>&1
REPLAY_EC=$?
echo "REPLAY_EXIT_CODE=$REPLAY_EC"
echo "=== REPLAY_END ==="

sleep 1
if kill -0 $SRV_PID 2>/dev/null; then
    echo "SERVER_ALIVE=1"
    kill $SRV_PID 2>/dev/null
    wait $SRV_PID 2>/dev/null || true
else
    wait $SRV_PID 2>/dev/null
    EC=$?
    echo "SERVER_ALIVE=0"
    echo "SERVER_EXIT=$EC"
fi
"""

    rc, stdout, stderr = _run_docker(seed_bytes, cmd, timeout=30)

    # ── 安全属性验证 ──
    response_codes = re.findall(r"^\d{3}(?=[ -])", stdout, re.MULTILINE)
    response_lines = re.findall(
        r"^(\d{3})[ -](.*)$", stdout, re.MULTILINE)

    prop_violated = False
    verification_notes = []
    categories = violation_info.categories_hit

    if categories & 0x0001:  # AUTH_BYPASS
        # 检查未认证数据命令是否返回 2xx（成功）= 认证绕过
        # 若 auth 已补上 → 观察补认证前的命令响应；若未补 → 看全局
        if not auth_prepended:
            data_2xx = [c for c in response_codes
                        if c.startswith("2") or c == "150"]
            if data_2xx:
                prop_violated = True
                verification_notes.append(
                    f"AUTH_BYPASS CONFIRMED: unauthenticated commands returned {data_2xx}")

    if categories & 0x0004:  # STATE_VIOLATION
        for v in violation_info.violations:
            desc = v.get("Description", "")
            if "RNTO without prior RNFR" in desc:
                # 严谨判定：检查服务器是否明确拒绝 "RNFR before RNTO"
                server_explicitly_rejected = (
                    "RNFR before RNTO expected" in stdout or
                    "RNFR before RNTO" in stdout
                )
                # 同时排除 HELP 命令列出的 214-RNTO（那只是命令列表，不是成功响应）
                rnto_accepted = False
                for code, msg in response_lines:
                    # 250 = 文件操作成功，且消息含 rename/RNTO
                    if code == "250" and any(
                            kw in msg.upper()
                            for kw in ["RENAME", "RNTO", "FILE RENAMED"]):
                        rnto_accepted = True
                        break
                    # 350 = 请求文件操作待确认（RFC 959: RNTO 的中间响应）
                    if code == "350" and "RNTO" in msg.upper():
                        rnto_accepted = True
                        break

                if server_explicitly_rejected and not rnto_accepted:
                    verification_notes.append(
                        "STATE_VIOLATION NOT reproduced: server correctly "
                        "rejected RNTO with 'RNFR before RNTO expected'")
                elif rnto_accepted:
                    prop_violated = True
                    verification_notes.append(
                        "STATE_VIOLATION CONFIRMED: RNTO accepted without RNFR")
                else:
                    verification_notes.append(
                        "STATE_VIOLATION indeterminate: no explicit rejection "
                        "or acceptance detected; manual triage needed")

    if categories & 0x0010:  # PATH_TRAVERSAL
        for code, msg in response_lines:
            if code.startswith("2") and ("../" in msg or "traversal" in msg.lower()):
                prop_violated = True
                verification_notes.append("PATH_TRAVERSAL CONFIRMED: traversal accepted")

    if categories & 0x0008:  # INFO_LEAK
        leak_kw = ["/etc/passwd", "/etc/shadow", "root:", "password", "shadow"]
        for kw in leak_kw:
            if kw in stdout.lower():
                prop_violated = True
                verification_notes.append(f"INFO_LEAK CONFIRMED: '{kw}' in response")

    if categories & 0x0040:  # DOS
        if "SERVER_ALIVE=0" in stdout:
            prop_violated = True
            verification_notes.append("DoS CONFIRMED: server terminated abnormally")

    if not verification_notes:
        verification_notes.append(
            "Manual triage needed: compare response codes with RFC 959 expected behavior")

    return ReplayResult(
        seed_path="/tmp/seed_input",
        seed_type="violation",
        seed_format="aflnet",
        replay_rc=rc,
        server_exit_code=None,
        server_signal=None,
        asan_output="",
        server_responses=stdout[-3000:] if len(stdout) > 3000 else stdout,
        reproduced=prop_violated,
        note="; ".join(verification_notes),
    )


# ── 批量处理入口 ──────────────────────────────────────────

def process_results_dir(results_dir: str, protocol: str = "FTP",
                        port: int = 21, image: str = "bftpd:latest"):
    """处理一个 results-* 目录下的所有 tar.gz 结果。"""
    global DOCKER_IMAGE
    DOCKER_IMAGE = image

    results_path = Path(results_dir)
    if not results_path.is_dir():
        print(f"ERROR: {results_dir} is not a directory")
        sys.exit(1)

    tar_files = sorted(results_path.glob("out-*.tar.gz"))
    if not tar_files:
        print(f"ERROR: No out-*.tar.gz found in {results_dir}")
        sys.exit(1)

    print(f"Found {len(tar_files)} archive(s) in {results_dir}")
    print()

    total_crashes = 0
    total_violations = 0
    crashes_reproduced = 0
    violations_reproduced = 0

    for tar_path in tar_files:
        run_name = tar_path.stem.replace(".tar", "")
        print(f"{'='*70}")
        print(f"  {run_name}")
        print(f"{'='*70}")

        with tarfile.open(tar_path, "r:gz") as tf:
            members = tf.getmembers()

            # ── 处理 crashes ──
            crash_members = [
                m for m in members
                if "/replayable-crashes/" in m.name
                and m.isfile()
                and not m.name.endswith("README.txt")
            ]

            for cm in crash_members:
                total_crashes += 1
                basename = os.path.basename(cm.name)
                print(f"\n  [CRASH] {basename}")

                seed_bytes = tf.extractfile(cm).read()
                result = replay_crash(seed_bytes, protocol, port)

                if result.reproduced:
                    crashes_reproduced += 1
                    print(f"    REPRODUCED: signal={result.server_signal}")
                else:
                    print(f"    NOT reproduced: {result.note}")
                if result.asan_output:
                    print(f"    ASAN: {result.asan_output[:200]}")

            # ── 处理 violations ──
            viol_members = [
                m for m in members
                if "/replayable-violations/" in m.name
                and m.isfile()
            ]

            for vm in viol_members:
                total_violations += 1
                basename = os.path.basename(vm.name)
                print(f"\n  [VIOLATION] {basename}")

                report_bytes = tf.extractfile(vm).read()
                info = parse_violation_report(report_bytes, vm.name)

                # 显示 violation 摘要
                cat_names = []
                for mask, name in ORACLE_CATEGORY_NAMES.items():
                    if info.categories_hit & mask:
                        cat_names.append(name)
                print(f"    Severity: {info.max_severity} ({SEVERITY_NAMES.get(info.max_severity, '?')})")
                print(f"    Categories: {', '.join(cat_names)}")
                for v in info.violations:
                    print(f"    → {v.get('Description', '?')}")

                # 重构种子并重放
                try:
                    seeds = reconstruct_seeds_from_violation(report_bytes)
                    auth_note = " (auth prepended)" if seeds["auth_prepended"] else ""
                    print(f"    Reconstructed: {len(seeds['requests'])} requests{auth_note}")

                    result = replay_violation(
                        seeds["aflnet"], info, protocol, port,
                        auth_prepended=seeds["auth_prepended"])

                    if result.reproduced:
                        violations_reproduced += 1
                        print(f"    VIOLATION REPRODUCED: {result.note}")
                    else:
                        print(f"    Not reproduced: {result.note}")
                    codes = re.findall(r'^\d{3}(?=[ -])', result.server_responses, re.MULTILINE)
                    print(f"    Response codes: {codes}")

                except ValueError as e:
                    print(f"    SKIP: {e}")

    # ── 汇总 ──
    print(f"\n{'='*70}")
    print(f"  SUMMARY")
    print(f"{'='*70}")
    print(f"  Total crashes:    {total_crashes}  (reproduced: {crashes_reproduced})")
    print(f"  Total violations: {total_violations}  (reproduced: {violations_reproduced})")
    print()


# ── CLI ───────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ChatAFL-Opt 漏洞复现工具 — crash 重放 + 逻辑漏洞安全属性验证",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          # 处理所有结果
          python3 replay_tools.py benchmark/results-bftpd_May-08_16-15-27

          # 只处理单个 tar.gz
          python3 replay_tools.py --single benchmark/results-bftpd_May-08_16-15-27/out-bftpd-chatafl_opt_1.tar.gz

          # 指定其他 Docker 镜像
          python3 replay_tools.py --image proftpd:latest results-proftpd_May-08_12-34-22
        """))
    parser.add_argument("results_dir",
                        help="results-* 目录路径，或 --single 时指向单个 tar.gz")
    parser.add_argument("--single", action="store_true",
                        help="处理单个 tar.gz 而非整个目录")
    parser.add_argument("--protocol", default="FTP",
                        help="协议类型 (默认: FTP)")
    parser.add_argument("--port", type=int, default=21,
                        help="服务端口 (默认: 21)")
    parser.add_argument("--image", default="bftpd:latest",
                        help="Docker 镜像名 (默认: bftpd:latest)")
    parser.add_argument("--extract-only", action="store_true",
                        help="仅提取并重建种子文件，不重放")
    parser.add_argument("--output-dir", default="/tmp/violation_seeds",
                        help="--extract-only 时的输出目录 (默认: /tmp/violation_seeds)")

    args = parser.parse_args()

    if args.extract_only:
        # 仅提取模式：从 tar.gz 中提取所有 violation → 重建种子
        os.makedirs(args.output_dir, exist_ok=True)
        tar_files = [Path(args.results_dir)] if args.single else \
            sorted(Path(args.results_dir).glob("out-*.tar.gz"))

        for tar_path in tar_files:
            if not tar_path.exists():
                print(f"ERROR: {tar_path} not found")
                continue
            with tarfile.open(tar_path, "r:gz") as tf:
                for m in tf.getmembers():
                    if "/replayable-violations/" in m.name and m.isfile():
                        report = tf.extractfile(m).read()
                        try:
                            seeds = reconstruct_seeds_from_violation(report)
                            basename = os.path.basename(m.name).replace(
                                ":", "_").replace(",", "_")
                            auth_tag = "_withAuth" if seeds["auth_prepended"] else ""
                            for fmt in ["aflnet", "afl"]:
                                out_path = os.path.join(
                                    args.output_dir, f"{basename}{auth_tag}.{fmt}_seed")
                                with open(out_path, "wb") as f:
                                    f.write(seeds[fmt])
                            print(f"  {out_path} ({len(seeds[fmt])} bytes, "
                                  f"{len(seeds['requests'])} requests"
                                  f"{', auth prepended' if seeds['auth_prepended'] else ''})")
                        except ValueError as e:
                            print(f"  SKIP {m.name}: {e}")

    elif args.single:
        # 单文件模式
        tar_path = Path(args.results_dir)
        if not tar_path.exists():
            print(f"ERROR: {tar_path} not found")
            sys.exit(1)
        # 临时创建包装目录
        tmp_dir = tempfile.mkdtemp(prefix="single_replay_")
        import shutil
        shutil.copy(tar_path, tmp_dir)
        process_results_dir(tmp_dir, args.protocol, args.port, args.image)
        shutil.rmtree(tmp_dir)
    else:
        process_results_dir(args.results_dir, args.protocol, args.port, args.image)


if __name__ == "__main__":
    main()
