# LoopFuzz 零安全漏洞发现优化方案（v2，证据驱动修订）

日期：2026-08-25
依据：benchmark `results-*_Aug-24_19-10-06`（9 subject × 3 run）、`papers/漏洞发现经验.docx`、`LoopFuzz/OPTIMIZATION_CHANGELOG.md` 全部历史实验记录。

---

## 0. 与 v1 方案的关系

v1（本目录 `LOOPFUZZ_VULN_OPTIMIZATION_PROPOSAL.md`）提出 RAE/CAR/DSE/TAS 四项，其中 RAE（竞态延迟注入）与 CAR（崩溃归因）已在 `LoopFuzz/afl-fuzz.c` 未提交改动中实现（默认门控关闭）。**v2 并不推翻 v1，而是基于 Aug-24 批次与 changelog 中已有的三组硬证据，指出 v1 遗漏的两个更根本的框架缺口**，并按《漏洞发现经验》的核心公式重新排定优先级：

> Vulnerability discovery = exploration + oracle
> coverage 只回答"执行到了哪里"，不回答"执行结果是否安全"。

LoopFuzz 的 exploration（b_abs / edges / 状态边）已被多批次证明健康；零漏洞的根因全部位于**观察侧（oracle 的证据输入通道）**，而不是探索侧。因此 v2 的原则是：**只修观察与证据保存通道，不碰调度、变异、覆盖反馈——零回归由结构保证，而非靠统计运气。**

---

## 1. 根因分析（全部有实验证据）

### 证据 A：oracle 对响应流的捕获存在系统性盲区（逻辑漏洞为零的第一根因）

changelog 2026-08-21 pure-ftpd R2 正对照的三方交叉证实：

- fuzzer 每条消息 send 后仅 `net_recv(poll_wait_msecs=1ms)`（`afl-fuzz.c:462` 默认值，benchmark 不传 `-W`）；
- pure-ftpd PASS 处理实测 ~20ms，`230 / 257 / 350 / 250` 等关键响应**系统性落在 1ms 窗口外**——live 捕获流全部止于 `331 User fuzzing OK`；
- oracle 规则本身正确（离线喂入完整响应流可触发 R2 MEDIUM），live 激活也正常（91,680 checks / 0 误报）。

**结论：R1–R10 共 10 条攻击型 oracle 规则被"喂不上证据"。** 这直接解释 Aug-22 9×3 批次 1.79M 次 oracle 检查仅 1 个（后被审计为 FP 的）violation，以及 Aug-24 批次的持续为零。逻辑漏洞零发现不是规则不够多，而是**观察通道不完整**。这是《漏洞发现经验》第 4 节"只有 exploration 没有 oracle"的具体形态——我们连已有的 oracle 都没有喂饱。

### 证据 B：崩溃类已知漏洞是低频竞态彩票，且 P1 通道被伪影淹没

- live555 stack-UAR：A/B 阶段 A 臂曾撞出 2 个带 `.asan.log` 铁证的内存错误（UAR 重放率 48%），证明崩溃通道**工作正常但命中是彩票**；Aug-24 批次 0 命中。
- bftpd Aug-24：117 个 P1 teardown SIGABRT（race:1），A2 自动重放 20×全部 non-replayable，0 个内存错误边车——纯 sock=2 伪影族，但占据了分诊报告 123 行中的绝大多数，稀释真信号。
- kamailio / lighttpd1 各 1–2 个同类 non-replayable teardown-fatal。

**结论：崩溃侧缺的不是触发机制而是（a）把已知竞态模式的触发次数放大，（b）把伪影在保存时就降级隔离。**

### 证据 C：hang 候选只保存裸种子，证据链为空

`afl-fuzz.c:9230` 一带：FAULT_TMOUT 保存路径只写裸种子文件到 `replayable-hangs/`，随后（若 `exec_tmout < hang_tmout`）用 `run_target()` 直连复跑验证。问题有三层：

1. **无证据边车**：不像 teardown/crash 通道有 A1 的 `.asan.log`/`.stderr.log`，hang 既无服务器侧 stderr、也无响应尾流、也无协议状态快照——分诊时只能盲猜"是不是资源耗尽型逻辑漏洞"（《漏洞发现经验》主线三明确把 resource-exhaustion 列为重要逻辑漏洞类别）。
2. **复跑验证路径失真**：`run_target()` 走 forkserver 直连，不复刻网络消息序列的时序与服务器端会话状态；网络型 hang（如 exim Aug-24 P2、forked-daapd P2×2）在直连复跑中极易"不复现"而被 `return keeping` 丢弃——这本身可能就是把真 hang 误杀为 false hang 的框架缺陷（changelog 曾记录 forked-daapd 140 false hangs 的清理，方向是收紧 hang_tmout，但误杀风险未消除）。
3. **`hang_tmout = MIN(EXEC_TIMEOUT, exec_tmout*2+100)`**（`afl-fuzz.c:10994`）在 benchmark 同参（`-t 8000+`、EXEC_TIMEOUT 钳制）下使复跑验证窗口未必比触发窗口宽多少，慢命令型 hang（数据传输、深层状态）被系统性排除。

---

## 2. v2 优化设计

### E1（最高优先级）：响应捕获补全——"结束前排水"（Teardown Response Drain）

**设计**：在一次执行的协议消息序列发送完毕、进入 `oracle_check`（`afl-fuzz.c:11177` 调用点）之前，追加**一次**有界排水接收：

```c
/* E1: teardown response drain — 给慢响应一次进入 oracle 证据流的机会 */
if (oracle_drain_enabled && protocol_name && collect_primary) {
  net_recv(target_fd, timeout, oracle_drain_ms, &response_buf, &response_buf_size);
  oracle_drain_execs++;   /* 写入 fuzzer_stats，供 A/B 监控成本 */
}
```

- 默认 `CHATAFL_ORACLE_DRAIN_MS=0`（关闭）；建议启用值 10–25ms（覆盖 pure-ftpd ~20ms 的 PASS 延迟）。
- **每执行最多一次**，成本上界 = drain_ms × exec/s。以 bftpd ~20 exec/s 计，25ms drain 理论吞吐损失 ≤ 1/（1+20×0.025）≈ 33%——若超 A/B 门，可只对**末条命令是 oracle 敏感命令**（PASS/鉴权/状态变更/RETR 类，复用 RAE 已实现的 `is_race_sensitive_message` 同款协议命令表）的执行排水，将成本再压到零头。
- 排水只 append 到 `response_buf`，不触碰 trace_bits、调度、变异——**覆盖路径零改动**。
- 备选（零代码改动）：benchmark 运行参数加 `-W 25` 放宽每消息轮询窗口，作为 E1 的运行参数对照组。

**验证硬门**（沿用既有门制）：2 subject × 2 run × 290min A/B，均值 b_abs 降幅 ≤2%、edges ≤5%、hangs +≤2；B 臂要求 pure-ftpd R2 在 live 批次中出现 ≥1 次保存 violation（正对照关闭"喂不上证据"缺口）。

**为什么这是第一优先级**：这是唯一被三方实验证据定位、且修复后能让**已验证正确的 10 条 oracle 规则立即开始产出**的改动。符合《漏洞发现经验》"oracle 设计是 fuzzing 下半场"的判断。

### E2：Hang 证据链保存与网络感知复跑（Hang Evidence & Network-Aware Re-verification）

**E2a 证据边车**（保存路径附加，零执行路径改动）：FAULT_TMOUT 保存候选时，仿照 A1 惯例写：

- `<seed>.stderr.log` ← `/tmp/afl_stderr_capture`（服务器侧最后输出）；
- `<seed>.request.replay` ← `save_kl_messages_to_file(replay_enabled=1)` 长度前缀格式（与 A2 重放 sweep 直接兼容，修复 hang 通道目前无 `.request.replay` 边车的问题）；
- `<seed>.hang.meta`：协议状态摘要（当前 state id、已发送命令序列的命令名列表）、`response_buf` 尾部 4KB、触发时 `exec_tmout/hang_tmout`、`getrusage` 快照（区分 CPU 自旋型与 IO 等待型资源耗尽）。

**E2b 网络感知复跑**：保存前的"genuine hang"复跑，在门控 `CHATAFL_HANG_NET_REVERIFY=1` 时改走 `save_if_unique` 外的完整网络路径（重放 `.request.replay` 消息序列 + 宽窗口计时），而非 `run_target()` 直连。判定规则保守化：**网络复跑仍超时 → 确认 hang；网络复跑正常但直连复跑超时 → 降级为 `suspect-hangs/`（不丢弃、不计入 unique_hangs 主统计）**——修复"网络型真 hang 被直连复跑误杀"的框架缺陷。

**E2c 自适应超时分级**（v1 第五节落地）：数据传输/深层状态命令（RETR/STOR/PAUSE 类，复用 E1 的命令表）复跑窗口 ×2–3，避免慢命令被系统性判 hang 或反向误杀。

**性能保证**：E2a 仅在 hang 保存时触发（稀有事件）；E2b 默认关闭；E2c 只影响复跑窗口不影响主执行超时。fuzzer_stats 新增 `hang_evidence_saved / hang_net_reverify / hang_downgraded` 计数。

### E3：崩溃伪影保存时降级 + 竞态放大（对 v1 RAE/CAR 的收口）

**E3a 伪影保存时隔离**（CAR 落地的最后一环）：`teardown_persist_candidate()` 保存时即调 `classify_crash()`：`CRASH_CONFIRMED_ASAN` / 有 `.asan.log`·`.stderr.log` 非空边车 → `teardown-crashes/`（P1）；SIGABRT 无任何内存错误边车且 `sock>=2`（bftpd 伪影指纹）→ `teardown-artifacts/` 新目录（分诊直接归 P3，不再产生 117 行噪声）。纯文件路径分流，零行为变化。

**E3b 竞态放大走批后通道而非引擎内扰动**：维持既有否决决定——引擎内 usleep 延迟注入（已实现的 RAE）默认关闭、仅作研究对照。竞态类已知漏洞的放大依赖已验证的 A2 自动重放 sweep（`run_crash_replay.sh`，竞态类 ≥10% 复现率即 confirmed），并把 A2 并入 `run_vuln_triage.sh` 批后流水线自动执行，替代人工触发。可选增强（门控 `CHATAFL_RACE_RESWEEP=N`）：对 race-tagged 种子在批后以 N=50 次重放（而非 20）提高低频竞态的确认概率——成本仅在批后，不占 fuzzing 预算。

**E3c 状态敏感命令的重复执行预算**（可选，最激进的探索侧改动，默认关闭）：plateau 期间对含竞态敏感序列（PAUSE→PLAY、重复 SETUP）的 queue 种子，附加 k 次（默认 3）原样重执行，仅收集崩溃信号、不收集覆盖反馈（不污染 has_new_bits 统计）。对应《漏洞发现经验》主线四"状态序列测试"。**此项有真实的吞吐成本，必须单独过 A/B 硬门，且排在 E1/E2 之后。**

---

## 3. 实施与验证计划

| 阶段 | 内容 | 门 |
|------|------|----|
| P0 | E1 drain + E2a hang 边车（纯观察侧） | make 零新警告；pure-ftpd R2 live 正对照；2×2×290min A/B 覆盖门 |
| P1 | E2b/E2c 网络感知复跑；E3a 伪影分流 | 仿真 hang 批次分诊 A/B；hang 计数与 Aug-24 对齐（+0 误杀证据） |
| P2 | A2 并入批后流水线 + E3b N=50；9×3 有效性批次 | 目标：≥1 个已知竞态漏洞命中或 R2 类逻辑 violation 落盘；覆盖门全绿 |
| P3 | （独立评审后）E3c 重复执行预算 | 单独 A/B 硬门 |

## 4. 指标预期与风险

- b_abs / edges / 状态边：全部改动观察侧或批后，目标 ±2%/±5% 门内（结构性保证：不触碰 virgin_bits 反馈环、调度打分、变异主体、forkserver）。
- 真实漏洞：E1 直接解除 oracle 证据饥饿（R1–R10 恢复产出能力）；E2 修复 hang 误杀并补齐资源耗尽型逻辑漏洞的证据链；E3 恢复 P1 信噪比并放大竞态彩票次数。
- 主要风险：E1 drain 的吞吐税（有 A/B 门 + 命令敏感门控兜底）；E2b 复跑路径复杂度（默认关闭 + 降级不丢弃）；E3c 吞吐成本（默认关闭、最后实施）。

## 5. 环境开关汇总（新增）

| 变量 | 默认 | 作用 |
|------|------|------|
| CHATAFL_ORACLE_DRAIN_MS | 0 | E1：执行结束前响应排水窗口（ms） |
| CHATAFL_ORACLE_DRAIN_SENSITIVE_ONLY | 1 | E1：仅末条命令为 oracle 敏感命令时排水 |
| CHATAFL_HANG_EVIDENCE | 1 | E2a：hang 证据边车 |
| CHATAFL_HANG_NET_REVERIFY | 0 | E2b：网络感知 hang 复跑 |
| CHATAFL_RACE_RESWEEP | 50 | E3b：批后 race-tagged 种子重放次数 |

---

## 6. 实现状态（2026-08-25 更新）

### 已实现并验证（P0 范围）

**E1 响应排水**（`LoopFuzz/afl-fuzz.c`）：
- 挂钩点为单 fd 发送路径的 `HANDLE_RESPONSES` 最终排水（原 1ms `poll_wait_msecs`），drain 启用时替换为 `oracle_drain_ms`，每执行最多一次、以 `messages_sent>0` 为前提；多出的字节日归于最后一条消息的 `response_bytes` 段——恰是慢 2xx/5xx 语义上所属的位置。
- 门控 `CHATAFL_ORACLE_DRAIN_MS`（默认 0=legacy 行为；>1000 硬钳制）+ `CHATAFL_ORACLE_DRAIN_SENSITIVE_ONLY`（默认 1，按协议命令表过滤：FTP PASS/ACCT/CWD/DELE/MKD/RMD/RNFR/RNTO/STOR/RETR/APPE/SITE；RTSP DESCRIBE/SETUP/PLAY/PAUSE/TEARDOWN/SET_PARAMETER/GET_PARAMETER；SMTP AUTH/MAIL/RCPT/DATA/STARTTLS/VRFY；SIP REGISTER/INVITE/SUBSCRIBE/NOTIFY/BYE/CANCEL/REFER/PUBLISH；HTTP|DAAP GET/POST/PUT/DELETE/PATCH；MQTT 按包类型 CONNECT/PUBLISH/SUBSCRIBE/UNSUBSCRIBE）。USER 被有意排除（其 3xx 响应即时到达，排水只亏吞吐）。
- fuzzer_stats 新增 `oracle_drain_ms / oracle_drain_sensitive_only / oracle_drain_execs / oracle_drain_bytes`——`oracle_drain_bytes≈0` 可直接复现"1ms 窗口饿死 oracle"的既有结论。
- benchmark 透传：`profuzzbench_exec_common_dev.sh` ATTACK_FLAGS 块新增三个变量。

**E1 端到端冒烟证据**（`.e1smoke/`，20ms PASS 延迟的插桩冒烟服务器，45s×2 臂）：
- legacy 臂：`oracle_drain_execs=0`（正确反映关闭），2331 execs，violation 27 次。
- drain 臂：`oracle_drain_execs=976`、`oracle_drain_bytes=34160`（≈35B/exec = `230 Login successful\r\n`+`250 renamed\r\n`，legacy 全部丢失——violation 落盘的 `.response.bin` 十六进制直接对比证实：legacy 流止于 `250 renamed` 缺 `230`，drain 臂完整）。violation 1824 次带完整证据触发。
- 已知代价（须 A/B 量化）：本冒烟负载 45s 内 execs 2331→992（该负载每条执行都以敏感命令结尾，属最坏情形；真实目标变异大量非敏感结尾执行，税额按比例下降）。

**E2a hang 证据边车**（`LoopFuzz/afl-fuzz.c` FAULT_TMOUT 保存分支）：
- 写 `<seed>.hang.meta`：时间戳、协议、exec/hang tmout、total_execs、children rusage（utime/stime/maxrss——区分 CPU 自旋与 IO 等待型资源耗尽）、命令序列（前 64 条 × 12 可见字符）、响应长度 + 尾部 4KB hex。gate `CHATAFL_HANG_EVIDENCE=0` 关闭（默认开）；`hang_evidence_saved` 入 fuzzer_stats。`.request.replay`/`.asan.log`/`.stderr.log` 由既有通用保存块覆盖（hang 同样受益），E2a 仅补齐 hang 特有诊断。
- 验证状态：编译零警告 + oracle_selftest 43/43（33 attack 夹具）不受牵连；保存路径惯例与已验证的 A1/O6 同构。live FAULT_TMOUT 触发未在合成冒烟中复现（本构建 teardown 200ms SIGKILL 先于 itimer 的 Fix-14c 反假 hang 语义 + SO_SNDTIMEO=1ms 使合成停顿难以进入 FAULT_TMOUT 分类；多组时序窗口尝试未命中），留待 benchmark 批次在真实易 hang 目标（exim/forked-daapd，Aug-24 批分别产出 16/3 个 P2 hang）上验证——该路径一旦触发即写 hang.meta。

**顺带修复**：未提交的 RAE/CAR 代码存在 `classify_crash` 先用后定义的编译错误（`make` 直接失败），已补前置声明——此前该树无法构建。

### 待实现（P1+）

E2b 网络感知复跑、E2c 自适应超时分级、E3a 伪影保存时分流、E3b A2 并入批后流水线、E3c 重复执行预算——见第 2/3 节，均默认关闭、单独过 A/B 门。

### 探索侧 P0 实现（2026-08-25 追加，同日探索侧审计结论）

探索侧审计发现两个 P0 缺陷并有实现：

**P0-1 DSE 存根修复**：v1 的 plateau DSE 只打日志从不注入（代码注释自认"简化版：仅日志记录"），已知竞态触发序列（PAUSE→PLAY 连击、TEARDOWN 后复用会话、深 FTP 文件生命周期、ABOR 数据通道竞态、SMTP RSET 重用、SIP BYE 后 re-INVITE、HTTP 资源生命周期）没有定向供给。修复：`attack-catalog.c` 新增 8 个 deep-state 模式（RTSP×3 / FTP×2 / SMTP×1 / SIP×1 / HTTP×1，DAAP 映射 HTTP），经与 CVE 种子完全相同的 in_dir/read_testcases 准入通道写入 `attack_deep_*.raw`（`deep_state_enrich_seeds()`，gate `CHATAFL_DEEP_STATE_EXPLORE` 默认开、cap `CHATAFL_DEEP_STATE_SEED_MAX`=6）。plateau 存根改为真实遥测（checkpoint 计数 + 模板注册数入日志）。fuzzer_stats 新增 `deep_state_seeds_written`。

**P0-2 havoc payload guard**：证据（2026-08-21 pure-ftpd）——130 个含 RNTO 的队列条目中仅原始种子保留 `../..`，字节变异系统性摧毁攻击种子的触发 payload。修复：fuzz_one havoc 阶段对 `attack_*` 队列条目（含 deep），按协议锚点表（FTP `../..`/`abcdefgh`、RTSP `000022B8` 会话 token/`../`、MQTT `$SYS/`/`$share/`）在执行前从 pristine `in_buf` 恢复被变异破坏的锚点区间；**长度变化的迭代（insert/delete/clone）跳过恢复**，结构变异威力不减；非攻击条目完全不受影响。gate `CHATAFL_PAYLOAD_GUARD`（默认开）；fuzzer_stats 新增 `payload_guard_restores`。

**冒烟证据**（.e1smoke/，插桩冒烟服务器）：P0-1——`attack_seeds_written=2 + deep_state_seeds_written=2`，in_dir 出现 `attack_deep_ftp_abor/file_lifecycle` 文件且内容完整（xxd 验证全部消息渲染）；P0-2——单锚点种子 75s 双臂：ON `payload_guard_restores=7`（7 次被破坏的攻击执行被修复为有效），OFF=0（门控行为正确）。M2/M3 状态窗口语义确认：guard 按执行缓冲（状态窗口内）工作，锚点进入窗口即生效。

**指标影响论证**：两项均为"只加不改"——P0-1 走已被 A/B 硬门（2×2×290min，9×3 批）证明不扰动 b_abs/edges 的种子注入通道，且 cap≤6；P0-2 仅作用于 attack_/deep_ 条目的 havoc 执行前字节恢复，覆盖反馈、调度、forkserver 零触碰，非攻击条目字节级等价。benchmark 透传已补三个新变量。

**剩余 P1**（未实现，需独立 A/B）：竞态序列放大重执行（E3c）、消息级结构变异算子、LLM 降级缓存与 oom 修复。

### 绑定层加固（2026-08-25 晚，Aug-25 批次三 FP 修复）

Aug-25_14-34-13 批次（E1 首批 live，violation 首次落盘 3 例）逐一审计：**3/3 为绑定层误报**（含源码级证伪的 bftpd RNTO——stock bftpd 6.1 对无 RNFR 的 RNTO 只可能回 503/451）。三个根因：① 消息缺 CRLF 结尾被服务器与下一条合并（bftpd）；② AUTH 后同消息续行的 SASL 吞行歧义 + 裸 LF 幻影槽（exim）；③ 变异合并两请求进一条消息，内嵌方法的 CSeq 错绑 SETUP 的 201 块（live555）。修复（protocol-oracle-precise.c，纯观察侧）：**CRLF 分帧完整性硬门**（缺结尾/裸 LF/AUTH 续行 → 序数检查跳过）+ **RTSP 首行绑定护栏**（内嵌方法不绑）。验证：三 FP 离线复现归零；selftest 47 检查/37 夹具全绿（+4 永久回归夹具 BH1-BH4）；make 零警告；新遥测 oracle_framing_defect_skips/oracle_embedded_method_skips 入 fuzzer_stats。**结论修正：Aug-25 批次确认漏洞数 0**——E1 证据通道有效，绑定层曾是唯一精度瓶颈，现已修复；下批 violation 可直接进人工分诊。

### 漏报面回收（2026-08-26）

零误报姿态的代价审计后三处回收：① 分帧硬门→逐槽信任限（缺陷点之前槽位照常判定，BH5 夹具实证 FN 恢复）；② payload guard 10% 概率放行锚点变异；③ oracle_untrusted_slots 遥测使屏蔽面可量化。验证：48 检查/38 夹具全绿、三 FP 复现保持归零、make 零警告。遗留：pure-ftpd 排水仲裁、E2b hang 网络复跑、E3c 竞态放大。

### 验证命令（就绪）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && \
export KEY="sk-..." SKIPCOUNT=100 && \
export CHATAFL_ORACLE_DRAIN_MS=25 CHATAFL_HANG_EVIDENCE=1 \
       CHATAFL_ATTACK_ORACLE=1 CHATAFL_ATTACK_SEEDS=1 CHATAFL_ATTACK_PROMPT=1 && \
sudo -E ./run_dev.sh 2 120 exim,live555,kamailio,lighttpd1,pure-ftpd,forked-daapd,lightftp,bftpd,proftpd loopfuzz
# 批后：./benchmark/run_vuln_triage.sh results-<subject>_<ts> && ./benchmark/run_crash_replay.sh results-<subject>_<ts>
# 判据：容器 banner "response-evidence drain ENABLED"；fuzzer_stats oracle_drain_execs>0 且
# pure-ftpd oracle_drain_bytes 明显>0；R2 类 violation 在 live 批次落盘；覆盖指标对照 Aug-24/Aug-19 基线过门。
```
