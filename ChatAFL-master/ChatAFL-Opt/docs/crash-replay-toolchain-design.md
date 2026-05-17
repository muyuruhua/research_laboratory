# ChatAFL-Opt Crash-Replay 工具链分析与改进设计

## 一、现有机制系统分析

### 1.1 Crash 检测与保存流程

```
run_target() 返回 fault 类型
    │
    ▼
save_if_interesting() 处理 FAULT_CRASH
    │
    ├── 判断 unique_crashes < KEEP_UNIQUE_CRASH (5000)
    ├── 用 simplify_trace + has_new_bits(virgin_crash) 去重
    ├── 生成文件名: replayable-crashes/id:%06llu,sig:%02u,%s
    └── save_kl_messages_to_file(kl_messages, fn, 1, messages_sent)
          │
          └── 迭代 kl_messages 链表
                └── [4字节长度][消息体]... 写入文件
```

**关键观察：**
- Crash 文件格式为 `[u32 size][data]...` 串联（`replay_enabled=1` 模式）
- 该格式与 `aflnet-replay` 读取格式一致
- 使用 `virgin_crash` bitmap 做覆盖率去重 → 一个 crash 触发信号 + 一份独特覆盖率 = 一个 crash 文件
- `KEEP_UNIQUE_CRASH = 5000`，达到阈值后不再保存新的 crash 输入

### 1.2 现有 Replay 工具

| 工具 | 功能 | 局限 |
|------|------|------|
| `afl-replay` | 读取原始格式文件，发送到 TCP/UDP 目标，收集响应并提取状态码 | 只打印 stderr，无机器可读输出；无 crash 检测逻辑 |
| `aflnet-replay` | 同上，但支持多报文序列（length-prefixed 格式） | 无 crash 判定；无重试；单次执行即结束 |
| `replay-crash-forkserver.sh` | 用 Docker + afl-showmap 复现 crash，64 次顺序重放 | 仅限 AM=0 的 ASAN 内存在问题；非通用；依赖 `clean` 脚本 |

### 1.3 Oracle 违规保存

```c
oracle_save_violation()
    └── 保存到 replayable-violations/id:%06llu,sev:%d,cat:%04x
        └── 文本格式：版本报告 + 请求/响应数据的前 4096 字节
```

**特点：** 不可用于自动重放；纯文本；请求数据截断。

### 1.4 持久化模式 Crash 保存

```c
// mqtt_persistent 子进程死亡时
save_kl_messages_to_file(kl_messages, fn_persist_crash, 1, messages_sent)
    └── replayable-crashes/persistent_crash_%llu_count%u
```

---

## 二、现有流程的不足

### 2.1 结构性缺陷

| 问题 | 描述 | 影响 |
|------|------|------|
| **无统一 Replay 入口** | `afl-replay` / `aflnet-replay` / shell 脚本三者松散耦合，参数接口不统一 | 无法形成自动化工具链 |
| **无 Crashing 判定逻辑** | Replay 工具仅发送报文、收集响应，不做 server 进程存活检查 | 无法判断 crash 是否真的复现 |
| **无结果分类与报告** | Oracle 违规是纯文本日志，crash 是二进制报文文件，缺乏统一的结构化报告格式 | 无法进行批量数据分析 |
| **无指标量化** | 不记录复现成功率、触发所需轮次、执行耗时等指标 | 无法衡量 crash 的稳定性与可复现性 |
| **缺乏批量处理能力** | 每次只能处理一个 crash 文件，无批处理模式 | 面对 `replayable-crashes/` 中数千个文件时不可用 |
| **Oracle 违规格式不可重放** | `oracle_save_violation()` 保存的是截断后的明文而非完整二进制 msg 序列 | 违规发现无法自动转化为可重放的测试用例 |
| **信号处理粗糙** | `aflnet-replay` 不检测 SIGSEGV/SIGABRT 等信号 | 即使 server 崩溃也退出码为 0 |

### 2.2 数据流断裂

```
Fuzzing 阶段                                Replay 阶段
┌─────────────────────┐         ┌────────────────────────┐
│ replayable-crashes/ │ ──────→ │ aflnet-replay          │
│   id:000001,sig:06  │         │   → 打印 stderr        │
│   id:000002,sig:11  │         │   → 不检查退出码       │
│   ...               │         │   → 不生成报告         │
└─────────────────────┘         └────────────────────────┘
         ↓                                    ↓
   crash 文件 = 二进制报文              人工逐个查看 stderr 输出

         ↓                                    ↓
  replayable-violations/          oracle_save_violation()
    id:000001,sev:3,cat:0002          → 纯文本截断报告
                                       → 无法自动化处理
```

### 2.3 工具链视角的缺失

- **无 Crash 回放回归测试**：无法在版本更新后自动验证旧 crash 是否修补
- **无多服务器差异测试**：不支持同一 crash 对多 target 统一执行
- **无容器化编排**：`replay-crash-forkserver.sh` 硬编码了 Docker 路径和目标环境
- **无统计信息输出**：不生成 JSON/CSV 等可被下游分析工具消费的数据

### 2.4 协议漏洞模式总结（从 协议漏洞汇总.xlsx 提取）

对 xlsx 中 6 个协议（FTP/SIP/MQTT/SMTP/RTSP/HTTP）共 85+ CVE 的分析揭示了不同协议的攻击面特征，这些特征直接指导 replay 工具链的设计优先级：

| 协议 | 收集 CVE 数 | 高频漏洞类型 | 对 Replay 工具链的设计启示 |
|------|------------|-------------|--------------------------|
| FTP | 15 | 缓冲区溢出 (4)、拒绝服务 (2)、路径穿越 (2)、命令注入 (1) | 需要多报文序列重放（PORT/PASV 命令依赖上下文）；路径穿越需检测文件系统状态 |
| MQTT | 13 | 拒绝服务 (3)、认证/授权绕过 (3)、内存破坏 (4) | 持久化模式 crash 检测很重要（mosquitto 常以 daemon 运行）；CONNECT 报文必须优先发送 |
| HTTP | 10 | 拒绝服务 (1)、请求走私 (2)、路径遍历 (2)、缓冲区溢出 (1) | 响应码序列比较（200 vs 404 vs 500）可作为 oracle 指标；HTTP/2 支持需考虑 |
| RTSP | 10 | Use-After-Free (4)、缓冲区溢出 (2)、拒绝服务 (1)、整数下溢 (1) | LIVE555 系列对畸形 SETUP/PLAY 请求敏感；需检测媒体会话状态变化 |
| SMTP | 12 | 缓冲区溢出 (3)、拒绝服务 (2)、认证绕过 (1)、命令注入 (1) | STARTTLS 协商后的状态转变需要多轮重放；邮件队列状态检测可作为 oracle |
| SIP | 8 | 认证绕过 (3)、拒绝服务 (1)、缓冲区溢出 (1)、SQL 注入 (1) | SIP 是有状态协议（INVITE/ACK/BYE 事务）；Call-ID/CSeq 合法性校验可作 oracle |

**关键发现：**
1. **多报文序列重放是硬需求** — 多数协议（FTP/MQTT/SMTP/SIP）需要多步交互才能触发漏洞，单报文重放的覆盖面不足 30%
2. **SIGABRT 与 SIGSEGV 同等重要** — MQTT 和 RTSP 中大量的 UAF/堆溢出通过 ASAN 触发 SIGABRT，与 `crash_analysis.py` 的分类策略一致
3. **协议状态追踪** — FTP (PORT/PASV)、SIP (INVITE/ACK/BYE) 的状态机缺陷需要 oracle 层面的响应码序列比较才能检测
4. **持久化模式（MQTT 等）** — MQTT broker 通常作为后台服务运行，退出信号捕获与传统 forkserver 模式不同，需独立处理

---

## 三、改进设计思路

### 3.1 设计原则

1. **向下兼容**：保留现有 `replayable-crashes/`, `replayable-violations/` 目录结构，新增工具可直接读取
2. **管道式架构**：`解析 → 重放 → 判定 → 报告` 各阶段解耦，支持独立使用和组合使用
3. **多模式支持**：单用例重排、批量回归、稳健性评估、多目标差异化分析
4. **可观测性**：结构化日志 + 机器可读报告（JSON）+ 人类可读摘要

### 3.2 整体架构

```
┌──────────────────────────────────────────────────────────────────────┐
│                        crash-replay-toolchain                         │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  parse_crash_bin        ← 读取 replayable-crashes/ 中的二进制报文数据 │
│      │                                                               │
│      ▼                                                               │
│  prepare_server_env     ← 启动/检查目标服务器                         │
│      │                                                               │
│      ▼                                                               │
│  run_replay_once        ← 发送报文序列并检测目标存活                  │
│      │                                                               │
│      ▼                                                               │
│  detect_crash_repro     ← 多轮重放 + 轮次级检测 + 信号分类           │
│      │                                                               │
│      ▼                                                               │
│  collect_response_info  ← 提取状态码序列、比较期望 vs 实际响应       │
│      │                                                               │
│      ▼                                                               │
│  generate_report        ← 结构化报告 (JSON/YAML/Text)                │
│      │                                                               │
│      ▼                                                               │
│  batch_orchestrator     ← 批量处理 + 汇总统计                        │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

### 3.3 状态管理

```
[INIT] => [CONNECT] => [SEND_PACKET_1] => [RECV_RESP_1] => ... => [SEND_PACKET_N]
    |                                                           |
    v                                                           v
[CRASH_DETECTED]                                         [DONE_WITH_RESPONSE]
    |                                                           |
    +-- CRASH_TYPE_CRASH   (server 进程死亡，kill -0 失败)       |
    +-- CRASH_TYPE_HANG    (响应超时)                             |
    +-- CRASH_TYPE_SIGNAL  (子进程收到信号)                       |
```

### 3.4 集成到 Benchmark 分析管线

`crash_analysis.py`（位于 `benchmark/scripts/analysis/crash_analysis.py`，1040 行）
已提供一套完整的实验后分析框架，能对 ProFuzzBench 风格的 results-* 结果目录做以下
分类：

- **确认漏洞**：相同输入跨 run/fuzzer 复现或同类安全信号在 >=50% run 出现
- **疑似漏洞**：偶发安全信号（单次出现，需人工 replay 确认）
- **Hang**：进程在规定时间内未响应，>=3 run 复现升级为 HIGH
- **噪声**：SIGPIPE/SIGTERM/SIGALRM/SIGHUP

**Replay 工具链与 `crash_analysis.py` 的集成方式：**

```
+--------------------- Fuzzing 实验（数十 run）---------------------+
|  results-kamailio_Mar-16/                                         |
|   +-- run_0001/.../replayable-crashes/                            |
|   +-- run_0002/.../replayable-crashes/                            |
|   +-- ...                                                         |
+----------------------------+-------------------------------------+
                             v
+---------------- crash_analysis.py（静态分析）--------------------+
|  -> 按信号/输入 hash 去重                                         |
|  -> 标注 Confirmed / Likely / Noise                              |
|  -> 输出 crash_analysis_report.csv                               |
|  -> 标记出 "疑似漏洞" 列表（需要 replay 确认）                     |
+----------------------------+-------------------------------------+
                             v
+--------------------- Replay 工具链（本设计）----------------------+
|  -> 读取 crash_analysis_report.csv 中 classification="likely"   |
|     的条目进行定向重放确认                                        |
|  -> 同时对 confirmed 条目抽样验证                                  |
|  -> 输出 replay_verification.json                                 |
+----------------------------+-------------------------------------+
                             v
+--------------------- 更新 crash_analysis_report.csv -------------+
|  -> 追加 replay 列：reproducible / stability_score / signal        |
|  -> 疑似升级为 Confirmed 或标记 Not Reproducible                   |
+-------------------------------------------------------------------+
```

**具体数据流：**

```bash
# Step 1: 静态分析（已有）
python3 benchmark/scripts/analysis/crash_analysis.py results-kamailio_Mar-16 -v

# Step 2: 从 crash_analysis_report.csv 提取需要 replay 的条目
#   -> classification == "likely" 且 signal_name 不是 SIGPIPE/SIGTERM

# Step 3: 定向 replay
python3 tools/replay-core/replay_crash.py \
    results-xxx/run_0001/replayable-crashes/id:000001,sig:06,... \
    kamailio 127.0.0.1 5060 \
    --max-rounds 20 --report-json replay_output.json

# Step 4: 合并结果至分析报告
python3 tools/analyze/crash_stats.py \
    --merge-with analysis/crash_analysis_report.csv \
    --replay-results replay_output.json \
    --output analysis/enriched_report.csv
```

这个集成方式保证了：
1. **不重复造轮子**：crash_analysis.py 已有的去重/分类逻辑直接复用
2. **关键环节互补**：静态分析做广覆盖，replay 做精准确认
3. **渐进式落地**：可以只对部分疑似漏洞做 replay，不影响已有分析流程

---

## 四、实现计划

```
[INIT] → [CONNECT] → [SEND_PACKET_1] → [RECV_RESP_1] → ... → [SEND_PACKET_N]
    │                                                           │
    ▼                                                           ▼
[CRASH_DETECTED]                                         [DONE_WITH_RESPONSE]
    │                                                           │
    ├── CRASH_TYPE_CRASH   (server 进程死亡，kill -0 失败)       │
    ├── CRASH_TYPE_HANG    (响应超时)                             │
    └── CRASH_TYPE_SIGNAL  (子进程收到信号)                       │
```

---

## 四、实现计划

### 4.1 模块清单

| 模块 | 文件 | 语言 | 职责 |
|------|------|------|------|
| M1 | `tools/replay-core/replay_crash.py` | Python 3 | 核心库：解析报文文件、重放逻辑、存活检测、信号分类 |
| M2 | `tools/replay-core/checker/check_oracle.py` | Python 3 | Oracle 违规分析：将 replayable-violations 转化为可重放用例并验证 |
| M3 | `tools/batch-replay.sh` | Bash | 批处理：遍历 `replayable-crashes/`，调用 M1 执行所有用例 |
| M4 | `tools/regression/regression_test.py` | Python 3 | 回归测试：跨版本比对 crash 复现状态 |
| M5 | `tools/analyze/crash_stats.py` | Python 3 | 统计分析：汇总报告、分类统计、趋势分析 |
| M6 | `tools/crash-report-viewer.py` | Python 3 | Web UI 可视化浏览 crash 复现结果 |
| M7 | `tools/sync/convert_to_replayable.py` | Python 3 | 格式转换器：将 `oracle_save_violation` 的文本格式转换为二进制可重放格式 |

### 4.2 M1: replay_crash.py — 核心重放引擎

**功能描述：**
- 解析 `replayable-crashes/` 目录中的二进制报文文件
- 建立 TCP/UDP 连接至目标服务器
- 按序发送报文，检测目标进程存活状态
- 多轮重放以判断 crash 的稳定性
- 输出结构化结果

**接口设计：**

```python
# 单用例重放
def replay_single(
    crash_file: str,       # replayable-crashes/id:000001,sig:06,...
    protocol: str,         # FTP / RTSP / MQTT / HTTP / ...
    host: str,             # 127.0.0.1
    port: int,             # 21
    max_rounds: int = 10,  # 最大重试轮次
    resp_timeout: float = 1.0,
    poll_timeout: float = 0.001,
) -> ReplayResult:
    ...

# 批处理
def replay_batch(
    crashes_dir: str,      # replayable-crashes/
    protocol: str,
    host: str,
    port: int,
    max_rounds: int = 10,
    workers: int = 1,      # 并行度
) -> BatchReport:
    ...

# 返回数据结构
@dataclass
class ReplayResult:
    crash_file: str
    total_rounds: int
    crash_rounds: list[int]        # crash 发生的轮次编号
    reproducible: bool              # 是否至少复现一次
    stability_score: float         # crash 轮次 / 总轮次
    first_crash_round: int | None
    exit_signals: list[int]        # 退出信号列表
    response_codes: list[list[int]] # 每轮的响应状态码序列
    server_responses: list[bytes]  # 每轮的原始响应数据
    total_time_ms: float
    error: str | None
```

**关键实现细节：**

```python
def _detect_server_alive(pid: int = None, port: int = None) -> bool:
    """检测目标服务器是否存活。优先使用 PID，否则用端口探测。"""
    if pid:
        return os.path.exists(f"/proc/{pid}")  # Linux
    if port:
        # 用 connect + shutdown 快速检测端口存活
        ...

def _classify_signal(exit_code: int) -> str:
    """将退出码映射为信号名。"""
    signals = {6: "SIGABRT", 11: "SIGSEGV", 4: "SIGILL", 8: "SIGFPE",
               15: "SIGTERM", 9: "SIGKILL", 2: "SIGINT", 3: "SIGQUIT"}
    return signals.get(exit_code - 128, f"SIGUNKNOWN({exit_code})")
```

### 4.3 M2: Oracle 违规可重放化

**问题分析：**
`oracle_save_violation()` 仅保存了请求/响应的前 4096 字节文本格式，损失了完整的报文序列信息。修复应在源头进行 — 在 `protocol-oracle.c` 中扩展 `oracle_save_violation`：

```c
// 增强建议：在保存文本报告的同时，也保存标准二进制格式
void oracle_save_violation(...) {
    // ... 现有文本逻辑 ...

    // ← 新增：保存二进制重放格式
    u8 *replay_fn = alloc_printf("%s/replayable-violations/%s.replay",
                                 dir_path, basename);
    // 使用 save_kl_messages_to_file() 相同的格式保存
    save_violation_as_replay(replay_fn, request_data, request_len);
}
```

**Python 侧适配：**
```python
def convert_violation_to_replay(violation_file: str) -> bytes:
    """将 oracle 违规文本报告转换为可重放二进制格式。"""
    # 解析文本报告中 === REQUEST DATA === 之后的原始字节
    # 重建为 [len][payload]... 格式
```

### 4.4 M3: batch-replay.sh — 批量编排器

**设计要点：**
- 遍历 `replayable-crashes/` 目录，排除 `README.txt`
- 根据文件名解析 `protocol` 和 `port`（可通过参数指定）
- 依次调用 `replay_crash.py` 执行
- 汇总结果至 `replay-summary.json`
- 生成 HTML 摘要报告

```bash
usage: batch-replay.sh [options] <crashes-dir> <protocol> <host> <port>
  -w N      并行工作线程数 (default: 1)
  -r N      每个用例最大重放轮次 (default: 10)
  -o DIR    输出目录 (default: ./replay-results-<timestamp>)
  -s SCRIPT 服务器启动脚本 (可选)
  --oracle  同时测试 oracle 违规
```

### 4.5 M4: 回归测试模块

**目的：**
在目标服务器版本更新后，自动回归验证已知 crash 是否已修复。

```python
def regression_suite(
    crash_dir: str,
    protocol: str,
    host: str,
    port: int,
    baseline_report: str,  # 上次结果的 JSON
) -> RegressionReport:
    """
    输出：
    - fixed:   以前能复现、现在不能 → 已修复
    - still:   仍然能复现 → 未修复
    - new:     新发现 → 可能新增
    - regress: 以前不能重现、现在能 → 回归
    """
```

### 4.6 M5: 统计分析模块

**聚合指标：**

| 指标 | 计算方式 | 含义 |
|------|----------|------|
| 复现率 | reproducible_count / total_count × 100% | 批量复现成功率 |
| 稳定性分数 | mean(rounds_until_crash) / max_rounds | crash 触发的一致程度 |
| 信号分布 | SIGSEGV / SIGABRT / SIGILL 各自占比 | 各类 crash 类型占比 |
| 状态码差异 | 每轮响应码序列对比 | 协议实现差异 |
| 复现时间 CDF | 累积分布图 | 重放效率评估 |

### 4.7 M6: Crash 报告可视化

- 轻量级独立 HTML 页面（无服务器依赖）
- 显示：批量摘要统计、每条用例结果、信号分类、响应码序列
- 设计思路参考：AFL 的 web UI 风格

### 4.8 M7: 格式转换桥

```bash
convert_to_replayable.py \
    --input  replayable-violations/id:000001,sev:3,cat:0002 \
    --output replayable-violations/id:000001,sev:3,cat:0002.replay \
    --protocol FTP
```

---

## 五、使用方式

### 5.1 单用例重放

```bash
# 最基本的用法
python3 tools/replay-core/replay_crash.py \
    output/replayable-crashes/id:000001,sig:06,src:000001+op:arith8 \
    FTP 127.0.0.1 21

# 带详细输出和 JSON 报告
python3 tools/replay-core/replay_crash.py \
    output/replayable-crashes/id:000001,sig:06,src:000001+op:arith8 \
    FTP 127.0.0.1 21 \
    --max-rounds 20 \
    --report-json result.json \
    --verbose

# 输出示例:
# Crash File:     id:000001,sig:06,src:000001+op:arith8
# Protocol:       FTP → 127.0.0.1:21
# Max Rounds:     10
# ─────────────────────────────────────
# Round  1: ✅ 回应正常 (220 ProFTPD 1.3.5)
# Round  2: ✅ 回应正常
# Round  3: ❌ CRASH (SIGABRT, 信号 6)
# Round  4: ❌ CRASH (SIGABRT, 信号 6)
# Round  5: ❌ CRASH (SIGSEGV, 信号 11)
# ...
# ─────────────────────────────────────
# 结果:   可复现 (6/10 轮次触发 crash)
# 稳定性: 0.60
# 首次:   第 3 轮
# 信号:   SIGABRT x5, SIGSEGV x1
# 耗时:   4.23 秒
```

### 5.2 批量回归

```bash
# 自动重放 replayable-crashes/ 中所有 crash 文件
bash tools/batch-replay.sh \
    -w 4 \
    -r 10 \
    -o ./replay-results-20250329 \
    output/replayable-crashes \
    FTP 127.0.0.1 21 \
    --server-start "./start_server.sh"

# 输出目录结构
replay-results-20250329/
├── summary.json           # 完整汇总
├── summary.md             # Markdown 摘要
├── summary.html           # HTML 可视化报告
├── per-case/              # 每个用例的详细结果
│   ├── id:000001.json
│   ├── id:000002.json
│   └── ...
└── logs/                  # 执行日志
    └── batch.log
```

### 5.3 Oracle 违规验证

```bash
# 将 oracle 违规转换为可重放格式后验证
tools/sync/convert_to_replayable.py \
    --input-dir output/replayable-violations/ \
    --output-dir output/replayable-violations-replayable/ \
    --protocol MQTT

python3 tools/replay-core/replay_crash.py \
    output/replayable-violations-replayable/id:000001,sev:3,cat:0002.replay \
    MQTT 127.0.0.1 1883
```

### 5.4 版本回归测试

```bash
python3 tools/regression/regression_test.py \
    --crashes output/replayable-crashes/ \
    --protocol FTP \
    --baseline replay-baseline-v1.json \
    --host 127.0.0.1 --port 21 \
    --output regression-result.md
```

### 5.5 统计分析

```bash
# 批量分析已生成的 replay 结果
python3 tools/analyze/crash_stats.py \
    --input replay-results-20250329/summary.json \
    --output-dir ./analysis/ \
    --plot                     # 生成分布图

# 输出
analysis/
├── summary.md
├── stability_distribution.png
├── signal_pie_chart.png
├── rounds_to_crash_ecdf.png
└── per_signal_stats.csv
```

### 5.6 在 Docker 容器中使用

```bash
# 同 replay-crash-forkserver.sh 的设计思路，但通用化
docker run --rm \
    -v $(pwd)/output/replayable-crashes:/crashes:ro \
    -v $(pwd)/replay-results:/results \
    --network host \
    crash-replay-tool \
    bash /tools/batch-replay.sh \
        -w 4 -r 10 \
        /crashes \
        FTP 127.0.0.1 21
```

---

## 六、前后端接口契约

### 6.1 输入文件格式

**Crash 文件**（`replayable-crashes/id:*`）：

```
[4B: u32 size_1][size_1 bytes: packet_1][4B: u32 size_2][size_2 bytes: packet_2]...
```

此格式已由 `save_kl_messages_to_file` + `replay_enabled=1` 生成，`aflnet-replay` 可直接读取。改进工具应继续使用此格式。

**可重放的 Oracle 文件**（`.replay`）：

建议采用完全相同的 `[len][payload]...` 格式，使 replay 工具无需区分文件来源。

### 6.2 输出格式

**JSON 报告结构：**

```json
{
  "tool_version": "1.0.0",
  "timestamp": "2025-03-29T14:30:00Z",
  "crash_file": "id:000001,sig:06,src:000001+op:arith8",
  "protocol": "FTP",
  "target": "127.0.0.1:21",
  "max_rounds": 10,
  "results": {
    "reproducible": true,
    "stability_score": 0.6,
    "first_crash_round": 3,
    "crash_rounds": [3, 4, 5, 7, 8, 9],
    "exit_signals": [6, 6, 11, 6, 6, 6],
    "signals_summary": {
      "SIGABRT": 5,
      "SIGSEGV": 1
    },
    "response_code_sequences": [
      [],
      [220],
      [220, 331],
      null,
      null,
      ...
    ],
    "total_time_ms": 4230
  }
}
```

---

## 七、Oracle 违规保存的源头修复建议

在 `protocol-oracle.c` 的 `oracle_save_violation` 中（第 1301 行），当前仅保存文本截断报告。建议**同时保存二进制重放格式**：

```c
/* ← 新增：同时保存二进制重放格式 */
{
    char replay_fn[1024];
    snprintf(replay_fn, sizeof(replay_fn), "%s/%s.replay", dir_path, basename);
    FILE *rfp = fopen(replay_fn, "wb");
    if (rfp) {
        /* 用与 save_kl_messages_to_file 相同的格式 */
        /* 先写请求数据: [4B总长度][请求报文]... */
        /* 再写响应数据: [4B总长度][响应报文]... */
        save_binary_replay(rfp, request_data, request_len,
                           response_data, response_len);
        fclose(rfp);
    }
}
```

这样可以使得 `oracle_save_violation` 的输出也可被 `replay_crash.py` 直接读取。

---

## 八、实施路线图

| 阶段 | 里程碑 | 产出 | 前置依赖 | 与现有组件的接口 |
|------|--------|------|----------|-----------------|
| Phase 1 | M1 核心重放引擎 | replay_crash.py | 无 | 输入: replayable-crashes/ 格式；输出: JSON |
| Phase 2 | M3 批量编排器 | batch-replay.sh + JSON 输出 | Phase 1 | 遍历 replayable-crashes/, 调用 M1 |
| Phase 3 | M2 Oracle 违规桥接 | convert_to_replayable.py + protocol-oracle.c 补丁 | Phase 1 | 读取 replayable-violations/, 输出 .replay 格式 |
| Phase 4 | M5 统计分析与 crash_analysis.py 集成 | crash_stats.py | Phase 1, 2 | 读取 crash_analysis_report.csv, 追加 replay 验证结果 |
| Phase 5 | M4 回归测试 | regression_test.py | Phase 1 | 读取 baseline JSON + crash_analysis_report.csv |
| Phase 6 | M6 HTML 可视化 | crash-report-viewer.py | Phase 1, 2 | 读取 batch replay 输出的 JSON |
| Phase 7 | 集成测试与文档 | 完整工具链端到端验证 + Docker 编排 | 全部 | 覆盖 FTP/MQTT/RTSP 三个典型协议 |

### 核心原则

1. **Phase 1 必须最先完成** — 它是整个工具链的基石
2. **每个阶段产出必须可独立使用** — 不需要等待下游阶段
3. **格式兼容性优先** — 现有 replayable-crashes/ 目录中的文件无需任何转换即可被新工具使用
4. **输出结构化数据** — JSON 作为中间层，确保各模块可通过文件系统松耦合
5. **复用已有基础设施** — crash_analysis.py, Docker 编排脚本、已有 replay 工具都作为输入/辅助，而非被替代

### 8.1 从现有脚本的迁移路径

当前有两种已有重放方式：

**方式 A: replay-crash-forkserver.sh（硬编码 Docker 方案）**
```bash
# 当前用法
cd /home/ckt/ChatAFL-Opt
sudo ../eval/lightftp-10.clean
./replay-crash-forkserver.sh lightftp 21 \\
    lightftp-replayable-crashes/id:000001,sig:06,src:000001+op:arith8
```

**方式 B: crash_analysis.py 的分类 + 手动 replay**

**迁移方案：**
1. batch-replay.sh 继承方式 A 的 Docker 参数体系，但改为通用化设计
2. crash_stats.py 直接读取 crash_analysis_report.csv 作为输入，追加 replay 结果列
3. 保留 replay-crash-forkserver.sh 作为备选，不删除已有功能

### 8.2 与 Docker 编排的集成

n-gram 论文的 evaluation 使用 Docker 容器管理目标服务器：

```
eval/
+-- dockerfiles/
|   +-- Dockerfile.lightftp
|   +-- Dockerfile.live555
|   +-- Dockerfile.mosquitto
+-- lightftp-10.clean   <- 清理/重启脚本
+-- lightftp-10.patch
+-- ...
```

replay-crash-forkserver.sh 使用 sudo ../eval/lightftp-10.clean 来重置环境。
新的 batch-replay.sh 应设计为：

```bash
# 新用法（兼容旧参数风格）
bash tools/batch-replay.sh \\
    --docker-clean ../eval/lightftp-10.clean \\
    --docker-build ../eval/lightftp-10.patch \\
    --server-start "sudo docker start lightftp" \\
    --server-stop  "sudo docker stop lightftp" \\
    -w 4 -r 10 \\
    output/replayable-crashes/ \\
    FTP 127.0.0.1 21
```

---

*文档版本: v1.1 | 基于 ChatAFL-Opt commit 当前状态 + 协议漏洞汇总.xlsx 数据分析*
