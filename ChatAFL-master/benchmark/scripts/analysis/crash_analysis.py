#!/usr/bin/env python3
"""
crash_analysis.py — 缺陷/漏洞/异常分析脚本
=================================================

分析 ProFuzzBench 风格的 results-* 结果目录，从 tar.gz 存档中提取
crash、hang、fuzzer_stats 等信息，并按信号类型、复现置信度、
跨 fuzzer/run 去重等维度进行分类。

─── 分类标准与设计理由 ───

本脚本 **仅能基于信号类型和输入去重做静态分类**，无法获取 ASAN 栈回溯、
崩溃 PC 地址等精确去重信息。因此分类结果是 **上界估计** (保守不漏报)，
需人工 triage 确认最终结论。

  ● 确认漏洞(Confirmed Bug):
      触发安全相关信号 (SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT)
      且同一 fuzzer 内 ≥2 run 出现相同信号, 或 ≥2 fuzzer 均触发。
      理由: 多次独立触发极大降低了环境噪声/误报的可能性。
      注意: SIGABRT 在 ASAN 模式下通常代表 heap-overflow、UAF、double-free
            等内存安全漏洞, 与 SIGSEGV 同等严重, 不应降级。

  ● 疑似漏洞(Likely Bug):
      触发安全相关信号, 但仅在单个 run 的单个 fuzzer 中出现。
      理由: fuzzing 的非确定性 (ASLR、线程调度、网络时序) 导致真实漏洞
            可能仅偶发触发。单次出现不能排除, 但置信度低于多次复现。
      要求: 人工 replay 确认。

  ● Hang(超时挂起):
      进程在规定时间内未响应。
      理由: 对协议服务器而言, hang 可构成 DoS 漏洞 (无限循环、死锁),
            但也可能是 fuzzer 的网络超时误判。不能一律忽略。
      ≥3 run 复现 → 升级为 HIGH (可能是真实 DoS)。

  ● 噪声(Noise):
      低风险信号 (SIGPIPE/SIGTERM/SIGALRM/SIGHUP)。
      理由: 在网络 fuzzing 场景下, 这些信号通常来自连接断开/进程清理,
            不代表程序缺陷。

─── 去重与复现策略 ───

  层级 1: 输入内容 SHA-256 hash — 精确去重完全相同的输入。
      用途: 统计唯一触发输入数量 (唯一漏洞数的上界)。

  层级 2: 信号级复现度 — 统计同一 fuzzer 的多少 run 触发过同类安全信号。
      用途: 评估该目标是否稳定暴露某类安全问题。
      理由: 不同 run 往往通过不同变异路径触发同一 root cause,
        不能要求输入字节完全相同。

  ⚠ 已知局限: 无法获取 ASAN 栈 hash, 因此无法确认不同输入是否属于同一
    root cause。去重后的 hash 数量是唯一漏洞数的 **上界**;
    信号级复现度则是漏洞存在性的 **置信度证据**。

─── forced_kills 审计 ───

  LoopFuzz 的 Fix-14c 会将 SIGKILL 升级的进程终止分类为 FAULT_NONE。
  若某 run 的 forced_kills 偏高, 理论上可能掩盖 ASAN 处理器死锁时的真实
  崩溃。本脚本审计该计数器并标注风险。

用法:
  python3 crash_analysis.py <results-dir> [--verbose]
  python3 crash_analysis.py /path/to/results-kamailio_Mar-16_23-10-02_ten -v

输出:
  1. 终端摘要报告
  2. <results-dir>/crash_analysis_report.csv   — 逐条 crash/hang 记录
  3. <results-dir>/crash_analysis_summary.csv   — 按 fuzzer 汇总统计
  4. <results-dir>/crash_analysis_per_run.csv   — 逐 run 统计
"""

import argparse
import csv
import io
import json
import os
import re
import sys
import tarfile
import hashlib
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

# ────────────────────────────────── 常量 ──────────────────────────────────

# POSIX 信号编号 → 名称
SIGNAL_MAP = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
    5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
    9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2",
    13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM",
}

# 安全相关信号 — 均可能指示内存安全漏洞, 不分级
# SIGSEGV: 非法内存访问 (空指针、越界)
# SIGBUS:  总线错误 (未对齐访问)
# SIGFPE:  算术异常 (除零)
# SIGILL:  非法指令 (控制流劫持)
# SIGABRT: 程序主动中止 — 在 ASAN 模式下代表检测到的
#          heap-buffer-overflow / use-after-free / double-free /
#          stack-buffer-overflow 等, 严重性与 SIGSEGV 等同
SECURITY_SIGNALS = {11, 7, 8, 4, 6}  # SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT

# 低风险/噪声信号 — 网络 fuzzing 场景常见, 通常非安全问题
NOISE_SIGNALS = {13, 15, 14, 1}  # SIGPIPE, SIGTERM, SIGALRM, SIGHUP

# AFL crash 文件名正则: id:NNNNNN,sig:NN,src:NNNNNN,...
CRASH_FILENAME_RE = re.compile(
    r"id[:_](\d+)"
    r"(?:,sig[:_](\d+))?"
    r"(?:,src[:_](\d+))?"
    r"(?:,time[:_](\d+))?"
    r"(?:,op[:_]([^,]+))?"
    r"(?:,rep[:_](\d+))?"
)

# fuzzer_stats 字段提取
STATS_INT_FIELDS = [
    "start_time", "last_update", "cycles_done", "execs_done",
    "paths_total", "paths_found", "paths_favored",
    "unique_crashes", "unique_hangs",
]
STATS_FLOAT_FIELDS = ["execs_per_sec", "stability", "bitmap_cvg"]
STATS_OPT_FIELDS = ["forced_kills", "plateau_calls", "plateau_threshold",
                     "edges_growth_rate", "llm_dedup_hits",
                     "hypothesis_count", "hypothesis_parse_success",
                     "hypothesis_parse_failure", "hypothesis_avg_fitness"]

# forced_kills 阈值
FORCED_KILLS_WARN_THRESHOLD = 50

# 复现性阈值
SIGNAL_REPRO_THRESHOLD = 0.5    # 同一 fuzzer 中 ≥50% run 触发同类安全信号 → 高置信
HANG_REPRO_THRESHOLD = 0.5      # 同一 fuzzer 中 ≥50% run 出现 hang → 高置信 DoS

LOOPFUZZ_FUZZER = "loopfuzz"
LOOPFUZZ_LABEL = "LoopFuzz"
LEGACY_LOOPFUZZ_FUZZERS = {"chat" + "afl_opt", "chat" + "afl-opt"}
KNOWN_FUZZERS = (
    LOOPFUZZ_FUZZER,
    "chatafl",
    "aflnet",
    "aflnwe",
    "stateafl",
    "nsfuzz",
    "snpsfuzzer",
    "mbfuzzer",
    *LEGACY_LOOPFUZZ_FUZZERS,
)


def normalize_fuzzer_name(name: str) -> str:
    """Map historical LoopFuzz aliases to the current fuzzer key."""
    return LOOPFUZZ_FUZZER if name in LEGACY_LOOPFUZZ_FUZZERS else name

# ────────────────────────────────── 数据结构 ──────────────────────────────

@dataclass
class CrashEntry:
    """单个 crash/hang 文件的元信息."""
    subject: str
    fuzzer: str
    run: int
    category: str           # "crash" | "hang"
    filename: str
    signal: Optional[int]
    signal_name: str
    src_id: Optional[int]
    discovery_time: Optional[int]   # AFL 时间戳(秒, 相对)
    mutation_op: str
    file_size: int
    content_hash: str       # SHA-256 前 16 字符 (去重用)
    signal_run_ratio: float # 同一 fuzzer 中, 触发同类信号的 run 占比
    classification: str     # "confirmed_bug" | "likely_bug" | "hang" | "noise" | "unknown"
    severity: str           # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    reason: str             # 分类理由


@dataclass
class FuzzerRunStats:
    """单次 fuzzer run 的汇总统计."""
    subject: str
    fuzzer: str
    run: int
    runtime_sec: int = 0
    execs_done: int = 0
    execs_per_sec: float = 0.0
    paths_total: int = 0
    unique_crashes: int = 0
    unique_hangs: int = 0
    stability: float = 0.0
    bitmap_cvg: float = 0.0
    forced_kills: int = 0
    # 分析后填充
    confirmed_bug_count: int = 0
    likely_bug_count: int = 0
    noise_count: int = 0
    hang_count: int = 0


@dataclass
class FuzzerSummary:
    """按 fuzzer 聚合的汇总."""
    fuzzer: str
    total_runs: int = 0
    total_crashes: int = 0
    total_hangs: int = 0
    total_confirmed_hash: int = 0  # confirmed_bug + CRITICAL (hash级复现)
    total_confirmed_signal: int = 0  # confirmed_bug + HIGH (信号级稳定复现)
    total_confirmed: int = 0      # confirmed_bug
    total_likely: int = 0         # likely_bug
    total_noise: int = 0          # noise signals
    total_hang_high: int = 0      # hang with HIGH severity
    deduped_crash_hashes: int = 0
    deduped_confirmed_hash_hashes: int = 0
    deduped_confirmed_signal_hashes: int = 0
    deduped_confirmed_hashes: int = 0
    mean_unique_crashes: float = 0.0
    mean_unique_hangs: float = 0.0
    total_forced_kills: int = 0
    forced_kills_warning: bool = False


# ────────────────────────────────── 解析函数 ────────────────────────────

def parse_subject_fuzzer_run(tarname: str) -> Tuple[str, str, int]:
    """从 tar.gz 文件名提取 subject, fuzzer, run."""
    # out-kamailio-loopfuzz_3.tar.gz → ("kamailio", "loopfuzz", 3)
    base = os.path.basename(tarname).replace(".tar.gz", "").replace(".tar", "")
    # 去掉 "out-" 前缀
    if base.startswith("out-"):
        base = base[4:]

    # 从末尾提取 run 编号: ..._N
    m = re.match(r"^(.+?)_(\d+)$", base)
    if not m:
        return base, "unknown", 0
    prefix, run = m.group(1), int(m.group(2))

    # prefix = "forked-daapd-loopfuzz" → subject="forked-daapd", fuzzer="loopfuzz"
    # 规则: 优先匹配已知 fuzzer 后缀, 避免 subject 本身含 "-" 时被切坏。
    for fuzzer in sorted(KNOWN_FUZZERS, key=len, reverse=True):
        suffix = f"-{fuzzer}"
        if prefix.endswith(suffix):
            return prefix[:-len(suffix)], normalize_fuzzer_name(fuzzer), run

    parts = prefix.rsplit("-", 1)
    if len(parts) == 2:
        return parts[0], normalize_fuzzer_name(parts[1]), run
    return prefix, "unknown", run


def parse_fuzzer_stats(content: str) -> dict:
    """解析 fuzzer_stats 文件内容为 dict."""
    stats = {}
    for line in content.strip().split("\n"):
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip().rstrip("%")
        if key in STATS_INT_FIELDS:
            try:
                stats[key] = int(val)
            except ValueError:
                stats[key] = 0
        elif key in STATS_FLOAT_FIELDS:
            try:
                stats[key] = float(val)
            except ValueError:
                stats[key] = 0.0
        elif key in STATS_OPT_FIELDS:
            try:
                stats[key] = float(val) if "." in val else int(val)
            except ValueError:
                stats[key] = 0
    return stats


def parse_crash_filename(filename: str) -> dict:
    """从 AFL crash/hang 文件名中提取元数据."""
    info = {"signal": None, "src_id": None, "time": None, "op": "", "rep": None}
    m = CRASH_FILENAME_RE.search(filename)
    if m:
        if m.group(2):
            info["signal"] = int(m.group(2))
        if m.group(3):
            info["src_id"] = int(m.group(3))
        if m.group(4):
            info["time"] = int(m.group(4))
        if m.group(5):
            info["op"] = m.group(5)
        if m.group(6):
            info["rep"] = int(m.group(6))
    return info


def classify_crash(signal: Optional[int], category: str,
                   cross_run_count: int, cross_fuzzer_count: int,
                   forced_kills: int, fuzzer: str,
                   signal_run_ratio: float = 0.0,
                   signal_fuzzer_count: int = 0,
                   total_runs_for_fuzzer: int = 0) -> Tuple[str, str, str]:
    """
    分类单个 crash/hang。

    返回: (classification, severity, reason)

    分类逻辑 (修正版):

        1. hang:
             - 同一 fuzzer 中 ≥50% run 出现 hang → hang, HIGH (可能是真实 DoS)
             - 否则                            → hang, LOW  (可能是网络超时误判)

    2. 安全相关信号 (SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT):
       注意: SIGABRT 在 ASAN 模式下与 SIGSEGV 同等严重, 不降级。
             - 同一输入(hash)跨 ≥2 run 或 ≥2 fuzzer 复现
                 → confirmed_bug, CRITICAL
             - 同类信号在同一 fuzzer 的 ≥50% run 中出现, 或 ≥2 fuzzer 均触发该信号
                 → confirmed_bug, HIGH
             - 其余安全信号
                 → likely_bug, MEDIUM (需人工 replay)

    3. 低风险信号 (SIGPIPE/SIGTERM/SIGALRM/SIGHUP):
       → noise, LOW (网络 fuzzing 常见, 非安全问题)

    4. 无信号 / 其他信号:
       → unknown, INFO

    LoopFuzz 标注:
    - forced_kills > 阈值时, 在 reason 中标注掩盖风险 (不改变分类本身,
      因为掩盖的是 FAULT_NONE, 不是改变已检测到的 crash 的分类)
    """
    # forced_kills 可疑标注 (仅影响 reason 文本, 不影响分类结果)
    loopfuzz_warning = ""
    if normalize_fuzzer_name(fuzzer) == LOOPFUZZ_FUZZER and forced_kills > FORCED_KILLS_WARN_THRESHOLD:
        loopfuzz_warning = (f" [⚠ 该run forced_kills={forced_kills}, "
                            f"可能有额外崩溃被SIGKILL→FAULT_NONE掩盖而未记录到crash目录]")

    # ── 1. Hang ──
    if category == "hang":
        if signal_run_ratio >= HANG_REPRO_THRESHOLD:
            return ("hang", "HIGH",
                    f"进程挂起: 在同一fuzzer的{signal_run_ratio:.0%} run中出现, "
                    f"可能是真实DoS漏洞(死锁/无限循环){loopfuzz_warning}")
        return ("hang", "LOW",
                f"进程挂起: 仅在同一fuzzer的{signal_run_ratio:.0%} run中出现, "
                f"可能是网络超时误判, 需人工确认{loopfuzz_warning}")

    # ── 2. 无信号 ──
    if signal is None:
        return ("unknown", "INFO",
                f"crash文件名中无sig字段, 无法判定信号类型{loopfuzz_warning}")

    sig_name = SIGNAL_MAP.get(signal, f"SIG{signal}")

    # ── 3. 安全相关信号 (SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT) ──
    if signal in SECURITY_SIGNALS:
        if cross_run_count >= 2 or cross_fuzzer_count >= 2:
            return ("confirmed_bug", "CRITICAL",
                    f"{sig_name}: 相同输入在{cross_run_count}个run/{cross_fuzzer_count}个fuzzer"
                    f"中复现, 极高置信度安全漏洞{loopfuzz_warning}")
        if signal_run_ratio >= SIGNAL_REPRO_THRESHOLD or signal_fuzzer_count >= 2:
            basis = []
            if total_runs_for_fuzzer:
                basis.append(f"同一fuzzer {signal_run_ratio:.0%} run触发")
            if signal_fuzzer_count >= 2:
                basis.append(f"{signal_fuzzer_count}个fuzzer均出现该信号")
            return ("confirmed_bug", "HIGH",
                    f"{sig_name}: 信号级稳定复现({' / '.join(basis)}), "
                    f"高置信度存在安全问题, 但输入未hash级重合{loopfuzz_warning}")
        return ("likely_bug", "MEDIUM",
                f"{sig_name}: 安全相关信号但仅偶发出现(同一fuzzer复现度{signal_run_ratio:.0%}), "
                f"需人工replay确认{loopfuzz_warning}")

    # ── 4. 低风险/噪声信号 ──
    if signal in NOISE_SIGNALS:
        return ("noise", "LOW",
                f"{sig_name}: 低风险信号, 网络fuzzing场景常见, "
                f"通常为连接断开/进程清理{loopfuzz_warning}")

    # ── 5. 其他信号 ──
    return ("unknown", "INFO",
            f"{sig_name}: 非典型信号, 需人工判断含义{loopfuzz_warning}")


def content_hash(data: bytes) -> str:
    """计算文件内容的 SHA-256 前 16 字符."""
    return hashlib.sha256(data).hexdigest()[:16]


# ────────────────────────────────── 核心分析 ────────────────────────────

class CrashAnalyzer:
    """主分析器: 从 results 目录提取并分类所有 crash/hang."""

    def __init__(self, results_dir: str, verbose: bool = False):
        self.results_dir = Path(results_dir)
        self.verbose = verbose
        self.entries: List[CrashEntry] = []
        self.run_stats: List[FuzzerRunStats] = []
        self.fuzzer_summaries: Dict[str, FuzzerSummary] = {}
        # 用于跨 run/fuzzer 去重: content_hash → set of (fuzzer, run)
        self.hash_to_occurrences: Dict[str, Set[Tuple[str, int]]] = defaultdict(set)

    def log(self, msg: str):
        if self.verbose:
            print(f"  [DBG] {msg}", file=sys.stderr)

    def find_tar_archives(self) -> List[Path]:
        """发现所有 .tar.gz 存档."""
        tars = sorted(self.results_dir.glob("out-*.tar.gz"))
        if not tars:
            tars = sorted(self.results_dir.glob("out-*.tar"))
        return tars

    def extract_from_tar(self, tar_path: Path):
        """从单个 tar.gz 中提取 fuzzer_stats + crash/hang 文件."""
        subject, fuzzer, run = parse_subject_fuzzer_run(tar_path.name)
        self.log(f"处理: {tar_path.name} → subject={subject}, fuzzer={fuzzer}, run={run}")

        try:
            tf = tarfile.open(tar_path, "r:gz")
        except tarfile.ReadError:
            try:
                tf = tarfile.open(tar_path, "r:")
            except Exception as e:
                print(f"  [WARN] 无法打开 {tar_path.name}: {e}", file=sys.stderr)
                return

        stats_content = None
        crash_members = []
        hang_members = []

        with tf:
            for member in tf.getmembers():
                name = member.name
                # fuzzer_stats (可能在顶层或子目录)
                if name.endswith("fuzzer_stats") and member.isfile():
                    try:
                        f = tf.extractfile(member)
                        if f:
                            stats_content = f.read().decode("utf-8", errors="replace")
                    except Exception:
                        pass

                # replayable-crashes/ 优先, crashes/ 其次
                elif ("/replayable-crashes/" in name or "/crashes/" in name) and member.isfile():
                    basename = os.path.basename(name)
                    if basename.startswith("id") or basename.startswith("README") is False:
                        if not basename.startswith("README"):
                            crash_members.append(member)

                # replayable-hangs/ 或 hangs/
                elif ("/replayable-hangs/" in name or "/hangs/" in name) and member.isfile():
                    basename = os.path.basename(name)
                    if not basename.startswith("README"):
                        hang_members.append(member)

            # 1. 解析 fuzzer_stats
            stats = {}
            if stats_content:
                stats = parse_fuzzer_stats(stats_content)

            forced_kills = int(stats.get("forced_kills", 0))
            run_stat = FuzzerRunStats(
                subject=subject, fuzzer=fuzzer, run=run,
                runtime_sec=stats.get("last_update", 0) - stats.get("start_time", 0),
                execs_done=stats.get("execs_done", 0),
                execs_per_sec=stats.get("execs_per_sec", 0.0),
                paths_total=stats.get("paths_total", 0),
                unique_crashes=stats.get("unique_crashes", 0),
                unique_hangs=stats.get("unique_hangs", 0),
                stability=stats.get("stability", 0.0),
                bitmap_cvg=stats.get("bitmap_cvg", 0.0),
                forced_kills=forced_kills,
            )

            # 2. 提取 crash 文件
            for member in crash_members:
                self._process_crash_hang(tf, member, subject, fuzzer, run,
                                         "crash", forced_kills)

            # 3. 提取 hang 文件
            for member in hang_members:
                self._process_crash_hang(tf, member, subject, fuzzer, run,
                                         "hang", forced_kills)

            # 交叉验证: fuzzer_stats 报告的数量 vs 实际提取的数量
            reported_crashes = run_stat.unique_crashes
            actual_crashes = len([e for e in self.entries
                                  if e.fuzzer == fuzzer and e.run == run and e.category == "crash"])
            if reported_crashes != actual_crashes and reported_crashes > 0:
                self.log(f"  ⚠ {fuzzer}/run{run}: fuzzer_stats报告 {reported_crashes} crashes, "
                         f"实际提取 {actual_crashes} 个 (差异可能来自 replayable 去重)")

            self.run_stats.append(run_stat)

    def _process_crash_hang(self, tf: tarfile.TarFile, member: tarfile.TarInfo,
                            subject: str, fuzzer: str, run: int,
                            category: str, forced_kills: int):
        """处理单个 crash/hang 文件."""
        filename = os.path.basename(member.name)
        info = parse_crash_filename(filename)

        # 读取文件内容计算 hash
        file_data = b""
        try:
            f = tf.extractfile(member)
            if f:
                file_data = f.read()
        except Exception:
            pass

        chash = content_hash(file_data) if file_data else "no_content"
        file_size = len(file_data) if file_data else member.size

        # 记录 hash → (fuzzer, run) 映射
        self.hash_to_occurrences[chash].add((fuzzer, run))

        sig = info["signal"]
        sig_name = SIGNAL_MAP.get(sig, f"SIG{sig}") if sig else "N/A"

        entry = CrashEntry(
            subject=subject, fuzzer=fuzzer, run=run,
            category=category, filename=filename,
            signal=sig, signal_name=sig_name,
            src_id=info["src_id"],
            discovery_time=info["time"],
            mutation_op=info["op"],
            file_size=file_size,
            content_hash=chash,
            signal_run_ratio=0.0,
            classification="pending",
            severity="pending",
            reason="pending",
        )
        self.entries.append(entry)

    def classify_all(self):
        """对所有 crash/hang 进行分类.

          复现性计算策略:
             1. 精确: 同一 content_hash 出现在多少 run/fuzzer 中。
                 用于 CRITICAL 级确认。
             2. 信号级: 同一信号在同一 fuzzer 的多少 run 中出现过 (不同输入)。
                 用于 HIGH 级确认。
                 理由: 不同输入可能指向同一 root cause; 在缺少 ASAN 栈时,
                 信号级稳定复现是更合理的高层证据。

        设计决策记录:
          - 旧版使用 (signal, file_size) 做 fallback 升级, 已删除。
            理由: 不同 root cause 碰巧产生相同大小的输入很常见
            (例如所有 SIP 消息都约 700-800 bytes), 导致虚假升级。
          - 不合并 SIGABRT "降级"为 defect。
            理由: ASAN 通过 abort() 报告 heap-overflow/UAF/double-free,
            这些都是内存安全漏洞, 不应比 SIGSEGV 低一等。
        """
        # 构建 forced_kills 索引: (fuzzer, run) → forced_kills
        fk_by_run: Dict[Tuple[str, int], int] = {}
        for rs in self.run_stats:
            fk_by_run[(rs.fuzzer, rs.run)] = rs.forced_kills

        total_runs_by_fuzzer: Dict[str, int] = defaultdict(int)
        for rs in self.run_stats:
            total_runs_by_fuzzer[rs.fuzzer] += 1

        signal_runs_by_fuzzer: Dict[Tuple[str, Optional[int]], Set[int]] = defaultdict(set)
        signal_fuzzers: Dict[Optional[int], Set[str]] = defaultdict(set)
        hang_runs_by_fuzzer: Dict[str, Set[int]] = defaultdict(set)

        for entry in self.entries:
            if entry.category == "hang":
                hang_runs_by_fuzzer[entry.fuzzer].add(entry.run)
            elif entry.signal in SECURITY_SIGNALS:
                signal_runs_by_fuzzer[(entry.fuzzer, entry.signal)].add(entry.run)
                signal_fuzzers[entry.signal].add(entry.fuzzer)

        for entry in self.entries:
            # 精确: 同一 content_hash 出现在哪些 (fuzzer, run)
            occurrences = self.hash_to_occurrences.get(entry.content_hash, set())
            cross_run_count = len({r for (f, r) in occurrences if f == entry.fuzzer})
            cross_fuzzer_count = len({f for (f, r) in occurrences})

            if entry.category == "hang":
                run_hits = len(hang_runs_by_fuzzer.get(entry.fuzzer, set()))
                total_runs = total_runs_by_fuzzer.get(entry.fuzzer, 0)
                signal_run_ratio = run_hits / total_runs if total_runs else 0.0
                signal_fuzzer_count = 0
            else:
                run_hits = len(signal_runs_by_fuzzer.get((entry.fuzzer, entry.signal), set()))
                total_runs = total_runs_by_fuzzer.get(entry.fuzzer, 0)
                signal_run_ratio = run_hits / total_runs if total_runs else 0.0
                signal_fuzzer_count = len(signal_fuzzers.get(entry.signal, set()))

            # 使用该 entry 所在 run 的 forced_kills (比取全局 max 更精确)
            fk = fk_by_run.get((entry.fuzzer, entry.run), 0)

            cls, sev, reason = classify_crash(
                entry.signal, entry.category,
                cross_run_count, cross_fuzzer_count,
                fk, entry.fuzzer,
                signal_run_ratio=signal_run_ratio,
                signal_fuzzer_count=signal_fuzzer_count,
                total_runs_for_fuzzer=total_runs,
            )
            entry.signal_run_ratio = signal_run_ratio
            entry.classification = cls
            entry.severity = sev
            entry.reason = reason

    def compute_summaries(self):
        """计算按 fuzzer 的汇总统计."""
        # 按 fuzzer 分组
        fuzzers = sorted(set(e.fuzzer for e in self.entries))
        if not fuzzers:
            fuzzers = sorted(set(rs.fuzzer for rs in self.run_stats))

        for fz in fuzzers:
            fz_entries = [e for e in self.entries if e.fuzzer == fz]
            fz_crashes = [e for e in fz_entries if e.category == "crash"]
            fz_hangs = [e for e in fz_entries if e.category == "hang"]
            fz_stats = [rs for rs in self.run_stats if rs.fuzzer == fz]

            n_runs = len(fz_stats)
            total_fk = sum(rs.forced_kills for rs in fz_stats)

            # 去重: 同一 fuzzer 内, 不同 run 的相同 hash 只算一次
            unique_crash_hashes = set(e.content_hash for e in fz_crashes)
            unique_confirmed_hash_hashes = set(
                e.content_hash for e in fz_crashes
                if e.classification == "confirmed_bug" and e.severity == "CRITICAL"
            )
            unique_confirmed_signal_hashes = set(
                e.content_hash for e in fz_crashes
                if e.classification == "confirmed_bug" and e.severity == "HIGH"
            )
            unique_confirmed_hashes = set(e.content_hash for e in fz_crashes
                                          if e.classification == "confirmed_bug")

            summary = FuzzerSummary(
                fuzzer=fz,
                total_runs=n_runs,
                total_crashes=len(fz_crashes),
                total_hangs=len(fz_hangs),
                total_confirmed_hash=len([
                    e for e in fz_crashes
                    if e.classification == "confirmed_bug" and e.severity == "CRITICAL"
                ]),
                total_confirmed_signal=len([
                    e for e in fz_crashes
                    if e.classification == "confirmed_bug" and e.severity == "HIGH"
                ]),
                total_confirmed=len([e for e in fz_crashes if e.classification == "confirmed_bug"]),
                total_likely=len([e for e in fz_crashes if e.classification == "likely_bug"]),
                total_noise=len([e for e in fz_crashes if e.classification == "noise"]),
                total_hang_high=len([e for e in fz_hangs if e.severity == "HIGH"]),
                deduped_crash_hashes=len(unique_crash_hashes),
                deduped_confirmed_hash_hashes=len(unique_confirmed_hash_hashes),
                deduped_confirmed_signal_hashes=len(unique_confirmed_signal_hashes),
                deduped_confirmed_hashes=len(unique_confirmed_hashes),
                mean_unique_crashes=(sum(rs.unique_crashes for rs in fz_stats) / max(n_runs, 1)),
                mean_unique_hangs=(sum(rs.unique_hangs for rs in fz_stats) / max(n_runs, 1)),
                total_forced_kills=total_fk,
                forced_kills_warning=(total_fk > FORCED_KILLS_WARN_THRESHOLD * n_runs),
            )
            self.fuzzer_summaries[fz] = summary

        # 更新 run_stats 的分类计数
        for rs in self.run_stats:
            rs_entries = [e for e in self.entries if e.fuzzer == rs.fuzzer and e.run == rs.run]
            rs.confirmed_bug_count = len([e for e in rs_entries if e.classification == "confirmed_bug"])
            rs.likely_bug_count = len([e for e in rs_entries if e.classification == "likely_bug"])
            rs.noise_count = len([e for e in rs_entries if e.classification == "noise"])
            rs.hang_count = len([e for e in rs_entries if e.classification == "hang"])

    def cross_fuzzer_analysis(self) -> List[dict]:
        """跨 fuzzer 对比: 哪些 crash hash 被多个 fuzzer 发现."""
        cross_results = []
        for chash, occurrences in sorted(self.hash_to_occurrences.items()):
            fuzzers_involved = sorted(set(f for f, r in occurrences))
            if len(fuzzers_involved) < 2:
                continue
            # 找到该 hash 的任一 entry 来获取信号信息
            representative = None
            for e in self.entries:
                if e.content_hash == chash:
                    representative = e
                    break
            if representative:
                cross_results.append({
                    "content_hash": chash,
                    "signal": representative.signal_name,
                    "classification": representative.classification,
                    "severity": representative.severity,
                    "fuzzers": ", ".join(fuzzers_involved),
                    "total_occurrences": len(occurrences),
                    "file_size": representative.file_size,
                })
        return cross_results

    def forced_kills_audit(self) -> List[dict]:
        """审计 LoopFuzz 的 forced_kills, 评估是否影响漏洞发现."""
        audit = []
        for rs in self.run_stats:
            if rs.forced_kills > 0:
                risk = "LOW"
                note = "正常范围"
                if rs.forced_kills > FORCED_KILLS_WARN_THRESHOLD:
                    risk = "HIGH"
                    note = f"forced_kills={rs.forced_kills} 超过阈值{FORCED_KILLS_WARN_THRESHOLD}, " \
                           f"Fix-14c的SIGKILL→FAULT_NONE映射可能掩盖了真实崩溃"
                elif rs.forced_kills > 20:
                    risk = "MEDIUM"
                    note = f"forced_kills={rs.forced_kills}, 接近警戒线, 建议关注"
                audit.append({
                    "fuzzer": rs.fuzzer,
                    "run": rs.run,
                    "forced_kills": rs.forced_kills,
                    "unique_crashes": rs.unique_crashes,
                    "risk": risk,
                    "note": note,
                })
        return audit

    def run(self):
        """完整分析流程."""
        print(f"\n{'='*72}")
        print(f"  缺陷/漏洞/异常分析")
        print(f"  目标目录: {self.results_dir}")
        print(f"{'='*72}\n")

        # 1. 发现 tar 存档
        tars = self.find_tar_archives()
        if not tars:
            print("  [ERROR] 未找到 out-*.tar.gz 文件!", file=sys.stderr)
            sys.exit(1)
        print(f"  发现 {len(tars)} 个 tar.gz 存档\n")

        # 2. 逐个提取
        for i, tar in enumerate(tars, 1):
            subject, fuzzer, run = parse_subject_fuzzer_run(tar.name)
            print(f"  [{i:3d}/{len(tars)}] {tar.name}")
            self.extract_from_tar(tar)
        print()

        # 3. 分类
        print("  ── 分类分析 ──")
        self.classify_all()
        self.compute_summaries()

        # 4. 输出结果
        self._print_summary()
        self._print_signal_distribution()
        self._print_cross_fuzzer()
        self._print_forced_kills_audit()
        self._print_verdict()

        # 5. 写 CSV
        self._write_detail_csv()
        self._write_summary_csv()

        print(f"\n{'='*72}")
        print(f"  分析完成")
        print(f"{'='*72}\n")

    # ────────────────── 输出函数 ──────────────────

    def _print_summary(self):
        """打印按 fuzzer 的汇总表格."""
        print(f"\n  ┌{'─'*78}┐")
        print(f"  │{'按 Fuzzer 汇总':^78}│")
        print(f"  ├{'─'*11}┬{'─'*4}┬{'─'*7}┬{'─'*7}┬{'─'*6}┬{'─'*6}┬{'─'*5}┬{'─'*6}┬{'─'*6}┬{'─'*5}┤")
        print(f"  │{'Fuzzer':^11}│{'Run':^4}│{'Crash':^7}│{'HashCf':^7}│{'SigCf':^6}│{'Likely':^6}│{'Noise':^5}│{'Hang':^6}│{'HangHi':^6}│{'Dedup':^5}│")
        print(f"  ├{'─'*11}┼{'─'*4}┼{'─'*7}┼{'─'*7}┼{'─'*6}┼{'─'*6}┼{'─'*5}┼{'─'*6}┼{'─'*6}┼{'─'*5}┤")

        for fz, s in sorted(self.fuzzer_summaries.items()):
            v_mark = " ⚠" if s.forced_kills_warning else ""
            print(f"  │{fz:^11}│{s.total_runs:^4}│{s.total_crashes:^7}│"
                  f"{s.total_confirmed_hash:^7}│{s.total_confirmed_signal:^6}│{s.total_likely:^6}│{s.total_noise:^5}│"
                  f"{s.total_hangs:^6}│{s.total_hang_high:^6}│{s.deduped_crash_hashes:^5}│{v_mark}")

        print(f"  └{'─'*11}┴{'─'*4}┴{'─'*7}┴{'─'*7}┴{'─'*6}┴{'─'*6}┴{'─'*5}┴{'─'*6}┴{'─'*6}┴{'─'*5}┘")

        # 去重后的统计
        all_confirmed_hashes = set()
        all_likely_hashes = set()
        for e in self.entries:
            if e.classification == "confirmed_bug":
                all_confirmed_hashes.add(e.content_hash)
            elif e.classification == "likely_bug":
                all_likely_hashes.add(e.content_hash)

        print(f"\n  去重后唯一 crash hash (⚠ 上界估计, 无栈hash无法合并同root cause):")
        all_hash_confirmed = set(e.content_hash for e in self.entries
                     if e.classification == "confirmed_bug" and e.severity == "CRITICAL")
        all_signal_confirmed = set(e.content_hash for e in self.entries
                       if e.classification == "confirmed_bug" and e.severity == "HIGH")
        print(f"    Hash-confirmed:       {len(all_hash_confirmed)} 个 (相同输入跨run/fuzzer复现)")
        print(f"    Signal-confirmed:     {len(all_signal_confirmed)} 个 (同类安全信号稳定复现)")
        print(f"    确认漏洞(Confirmed):   {len(all_confirmed_hashes)} 个 (两类确认合计)")
        print(f"    疑似漏洞(Likely):      {len(all_likely_hashes)} 个 (偶发安全信号, 需replay确认)")
        print(f"    安全相关crash总计:     {len(all_confirmed_hashes | all_likely_hashes)} 个唯一hash")

    def _print_signal_distribution(self):
        """打印信号分布."""
        crashes = [e for e in self.entries if e.category == "crash"]
        if not crashes:
            print("\n  无 crash 记录")
            return

        sig_counter = Counter(e.signal_name for e in crashes)
        print(f"\n  ── 信号分布 (共 {len(crashes)} crashes) ──")
        for sig, count in sig_counter.most_common():
            pct = count / len(crashes) * 100
            bar = "█" * int(pct / 2)
            print(f"    {sig:>10}: {count:5d} ({pct:5.1f}%) {bar}")

    def _print_cross_fuzzer(self):
        """打印跨 fuzzer 发现的相同 crash."""
        cross = self.cross_fuzzer_analysis()
        if not cross:
            print("\n  ── 跨 Fuzzer 交叉验证 ──")
            print("    无跨 fuzzer 相同 crash (各 fuzzer 发现的 crash 输入内容不重叠)")
            return

        print(f"\n  ── 跨 Fuzzer 交叉验证 ({len(cross)} 个共同发现) ──")
        for c in cross:
            icon = "🔴" if c["severity"] == "CRITICAL" else "🟡" if c["severity"] == "HIGH" else "⚪"
            print(f"    {icon} [{c['severity']}] {c['signal']} | hash={c['content_hash']} | "
                  f"fuzzers: {c['fuzzers']} | 总出现: {c['total_occurrences']}x")

    def _print_forced_kills_audit(self):
        """打印 forced_kills 审计."""
        audit = self.forced_kills_audit()
        if not audit:
            return

        has_issue = any(a["risk"] != "LOW" for a in audit)
        if not has_issue and not self.verbose:
            return

        print(f"\n  ── Forced Kills 审计 (Fix-14c SIGKILL→FAULT_NONE) ──")
        for a in audit:
            if a["risk"] == "LOW" and not self.verbose:
                continue
            icon = "🔴" if a["risk"] == "HIGH" else "🟡" if a["risk"] == "MEDIUM" else "🟢"
            print(f"    {icon} {a['fuzzer']}/run{a['run']}: "
                  f"forced_kills={a['forced_kills']}, "
                  f"unique_crashes={a['unique_crashes']} — {a['note']}")

    def _print_verdict(self):
        """打印最终判定."""
        all_confirmed = [e for e in self.entries if e.classification == "confirmed_bug"]
        all_likely = [e for e in self.entries if e.classification == "likely_bug"]
        hang_high = [e for e in self.entries if e.classification == "hang" and e.severity == "HIGH"]
        any_fk_warning = any(s.forced_kills_warning for s in self.fuzzer_summaries.values())

        print(f"\n  {'='*60}")
        print(f"  ██ 最终判定")
        print(f"  {'='*60}")

        critical_confirmed = [e for e in all_confirmed if e.severity == "CRITICAL"]
        high_confirmed = [e for e in all_confirmed if e.severity == "HIGH"]

        # ── 确认漏洞 ──
        if all_confirmed:
            confirmed_hashes = set(e.content_hash for e in all_confirmed)
            print(f"  🔴 确认漏洞: {len(confirmed_hashes)} 个唯一hash")
            if critical_confirmed:
                print(f"     · CRITICAL: {len(set(e.content_hash for e in critical_confirmed))} 个 (相同输入跨run/fuzzer复现)")
            if high_confirmed:
                print(f"     · HIGH:     {len(set(e.content_hash for e in high_confirmed))} 个 (信号级稳定复现)")
            by_sig = defaultdict(list)
            for e in all_confirmed:
                by_sig[e.signal_name].append(e)
            for sig, entries in sorted(by_sig.items()):
                unique = set(e.content_hash for e in entries)
                fuzzers = sorted(set(e.fuzzer for e in entries))
                print(f"     → {sig}: {len(unique)} 唯一hash, "
                      f"发现者: {', '.join(fuzzers)}")
        else:
            print(f"  🟢 无确认漏洞 (无安全信号的跨run复现)")

        # ── 疑似漏洞 ──
        if all_likely:
            likely_hashes = set(e.content_hash for e in all_likely)
            print(f"  🟡 疑似漏洞: {len(likely_hashes)} 个唯一hash (偶发安全信号, 需replay确认)")
            by_sig = defaultdict(list)
            for e in all_likely:
                by_sig[e.signal_name].append(e)
            for sig, entries in sorted(by_sig.items()):
                unique = set(e.content_hash for e in entries)
                print(f"     → {sig}: {len(unique)} 唯一hash")
        else:
            print(f"  🟢 无疑似漏洞")

        # ── DoS Hang ──
        if hang_high:
            print(f"  🟠 高置信度Hang: {len(hang_high)} 个 (同一fuzzer ≥{HANG_REPRO_THRESHOLD:.0%} run出现, 可能是DoS)")

        # ── forced_kills 警告 ──
        if any_fk_warning:
            print(f"  ⚠  {LOOPFUZZ_LABEL} forced_kills偏高: Fix-14c可能掩盖了部分崩溃")
            print(f"     注意: 掩盖的是未被记录的crash, 已记录crash的分类不受影响")

        # ── 已知局限声明 ──
        print(f"\n  ── ⚠ 已知局限 ──")
        print(f"    1. 去重基于输入内容hash, 不同输入触发同一root cause会被计为多个")
        print(f"    2. 无ASAN栈回溯, 无法判断具体漏洞类型(UAF/overflow/etc.)")
        print(f"    3. '确认'表示hash级或信号级稳定复现, 不等于人工验证; '疑似'不等于误报")

        # ── 跨 fuzzer 对比 ──
        fz_list = sorted(self.fuzzer_summaries.keys())
        if len(fz_list) >= 2:
            print(f"\n  ── Fuzzer 漏洞发现能力对比 ──")
            for fz in fz_list:
                s = self.fuzzer_summaries[fz]
                print(f"    {fz:>11}: hcfm={s.deduped_confirmed_hash_hashes}, "
                      f"scfm={s.deduped_confirmed_signal_hashes}, "
                      f"likely={s.total_likely}, dedup={s.deduped_crash_hashes}, "
                      f"avg/run={s.mean_unique_crashes:.1f}")

            # 比较 chatafl vs loopfuzz
            if "chatafl" in self.fuzzer_summaries and LOOPFUZZ_FUZZER in self.fuzzer_summaries:
                c = self.fuzzer_summaries["chatafl"]
                o = self.fuzzer_summaries[LOOPFUZZ_FUZZER]
                print(f"\n  ── ChatAFL vs {LOOPFUZZ_LABEL} 漏洞发现差异 ──")
                diff_c = c.mean_unique_crashes - o.mean_unique_crashes
                if abs(diff_c) < 0.5:
                    print(f"    ✅ 两者平均 crash 数量接近 (差异 {diff_c:+.1f}), 优化未显著影响")
                elif diff_c > 0:
                    print(f"    ⚠  ChatAFL 平均多 {diff_c:.1f} crashes/run, "
                          f"{LOOPFUZZ_LABEL} 可能因优化遗漏部分缺陷")
                else:
                    print(f"    ✅ {LOOPFUZZ_LABEL} 平均多 {-diff_c:.1f} crashes/run, "
                          f"优化对漏洞发现有正向帮助")

                # 检查只被一方发现的 crash
                c_hashes = set(e.content_hash for e in self.entries
                               if e.fuzzer == "chatafl" and e.category == "crash")
                o_hashes = set(e.content_hash for e in self.entries
                               if e.fuzzer == LOOPFUZZ_FUZZER and e.category == "crash")
                only_c = c_hashes - o_hashes
                only_o = o_hashes - c_hashes
                both = c_hashes & o_hashes
                if only_c:
                    sigs = Counter()
                    for e in self.entries:
                        if e.content_hash in only_c and e.fuzzer == "chatafl":
                            sigs[e.signal_name] += 1
                    print(f"    仅 ChatAFL 发现: {len(only_c)} 个 hash "
                          f"(信号分布: {dict(sigs.most_common())})")
                if only_o:
                    sigs = Counter()
                    for e in self.entries:
                        if e.content_hash in only_o and e.fuzzer == LOOPFUZZ_FUZZER:
                            sigs[e.signal_name] += 1
                    print(f"    仅 {LOOPFUZZ_LABEL} 发现: {len(only_o)} 个 hash "
                          f"(信号分布: {dict(sigs.most_common())})")
                if both:
                    print(f"    双方共同发现: {len(both)} 个 hash")

    def _write_detail_csv(self):
        """写入逐条 crash/hang 明细 CSV."""
        outpath = self.results_dir / "crash_analysis_report.csv"
        fields = [
            "subject", "fuzzer", "run", "category", "filename",
            "signal", "signal_name", "src_id", "discovery_time",
            "mutation_op", "file_size", "content_hash", "signal_run_ratio",
            "classification", "severity", "reason",
        ]
        with open(outpath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for e in sorted(self.entries,
                            key=lambda x: (x.severity != "CRITICAL",
                                           x.severity != "HIGH",
                                           x.fuzzer, x.run)):
                row = {k: getattr(e, k) for k in fields}
                writer.writerow(row)
        print(f"\n  📄 明细报告: {outpath}")

    def _write_summary_csv(self):
        """写入按 fuzzer 汇总 CSV."""
        outpath = self.results_dir / "crash_analysis_summary.csv"
        fields = [
            "fuzzer", "total_runs", "total_crashes", "total_hangs",
            "total_confirmed_hash", "total_confirmed_signal",
            "total_confirmed", "total_likely", "total_noise", "total_hang_high",
            "deduped_crash_hashes", "deduped_confirmed_hash_hashes",
            "deduped_confirmed_signal_hashes", "deduped_confirmed_hashes",
            "mean_unique_crashes", "mean_unique_hangs",
            "total_forced_kills", "forced_kills_warning",
        ]
        with open(outpath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for fz in sorted(self.fuzzer_summaries):
                s = self.fuzzer_summaries[fz]
                row = {k: getattr(s, k) for k in fields}
                row["mean_unique_crashes"] = f"{s.mean_unique_crashes:.1f}"
                row["mean_unique_hangs"] = f"{s.mean_unique_hangs:.1f}"
                writer.writerow(row)
        print(f"  📄 汇总报告: {outpath}")

        # 同时写一个 per-run 的 CSV
        run_outpath = self.results_dir / "crash_analysis_per_run.csv"
        run_fields = [
            "subject", "fuzzer", "run", "runtime_sec",
            "execs_done", "execs_per_sec", "paths_total",
            "unique_crashes", "unique_hangs", "stability", "bitmap_cvg",
            "forced_kills", "confirmed_bug_count", "likely_bug_count",
            "noise_count", "hang_count",
        ]
        with open(run_outpath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=run_fields)
            writer.writeheader()
            for rs in sorted(self.run_stats, key=lambda x: (x.fuzzer, x.run)):
                row = {k: getattr(rs, k) for k in run_fields}
                writer.writerow(row)
        print(f"  📄 逐Run报告: {run_outpath}")


# ────────────────────────────────── CLI 入口 ──────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="缺陷/漏洞/异常分析脚本 — 分析 ProFuzzBench 风格的 results 目录",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
分类标准 (SIGABRT 与 SIGSEGV 同级, 均为安全信号):
    确认漏洞(Confirmed): 相同输入跨run/fuzzer复现     → CRITICAL
    确认漏洞(Confirmed): 同类安全信号在≥50% run出现  → HIGH
    疑似漏洞(Likely):    偶发安全信号                 → MEDIUM (需replay)
    Hang:                同一fuzzer ≥50% run出现hang → HIGH (可能DoS)
  噪声(Noise):         SIGPIPE/SIGTERM 等            → LOW
  
已知局限:
  · 去重基于输入hash, 非栈hash — 计数是唯一漏洞数的上界
  · 无ASAN栈回溯, 无法判断具体漏洞类型
  · 需人工 replay 最终确认

示例:
  python3 crash_analysis.py /path/to/results-kamailio_Mar-16_23-10-02_ten
  python3 crash_analysis.py /path/to/results-kamailio_Mar-16_23-10-02_ten --verbose
        """
    )
    parser.add_argument("results_dir", help="results-* 结果目录路径")
    parser.add_argument("--output", "-o", help="输出 CSV 前缀 (默认写入 results_dir 下)")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出")

    args = parser.parse_args()

    if not os.path.isdir(args.results_dir):
        print(f"错误: {args.results_dir} 不是有效目录", file=sys.stderr)
        sys.exit(1)

    analyzer = CrashAnalyzer(args.results_dir, verbose=args.verbose)
    analyzer.run()


if __name__ == "__main__":
    main()
