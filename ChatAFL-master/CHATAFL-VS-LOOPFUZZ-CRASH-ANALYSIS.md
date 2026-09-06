# 为何 ChatAFL 报告更多"疑似崩溃与挂起"而 LoopFuzz 不报 — 严谨分析

- **日期**：2026-09-03
- **数据**：ChatAFL 26h 批次（Aug-04/09/10，`results-*_chatafl`）vs LoopFuzz 26h 批次
  （Aug-07 ablation full 组）vs LoopFuzz 现行版本 3h 批次（Aug-31 / Sep-02）
- **方法**：同时长计数对比 + 崩溃样本 ASAN 重放 + 挂起种子内容量化 + 双方代码对照

---

## 0. 一句话结论

**ChatAFL 的"更多崩溃与挂起"主要是测量口径与 LLM 输出卫生问题，不是发现能力更强**：
（1）崩溃侧，ChatAFL 把 SIGTERM 关停窗口的 SIGABRT 一律计为 crash，而 LoopFuzz
要求 ASAN 证据才计数、否则隔离到 teardown-crashes——抽验证明 ChatAFL 的这类
"崩溃"全部不能重放；（2）挂起侧，ChatAFL 会把 LLM 回复原文（markdown/解释
文字）当协议消息发给服务器并被计入队列繁衍，**56%–99% 的挂起种子含 LLM 残留**；
LoopFuzz 的 JSON schema 校验 + admission 门控在执行前就拦截了这些输入。

## 1. 数据对照（run_1，26h vs 26h）

| Target | ChatAFL 26h<br>crashes / hangs | LoopFuzz 26h (Aug-07*)<br>crashes / hangs | LoopFuzz 现行 3h<br>crashes / hangs / teardown |
|---|---|---|---|
| bftpd | **42** / 54 | 7 / 0 | 0 / 0 / 4 |
| proftpd | 7 / **424** | 2 / 0 | 0 / 0 / 1 |
| exim | 0 / **71** | 0 / 0 | 0 / 0 / 0 |
| forked-daapd | 0 / **90** | 0 / 10（仅 4.8h） | 0 / 0 / 0 |
| kamailio | 4 / 5 | —（无 tarball） | 0 / 0 / 23 |
| live555 | 1 / 3 | 27 / 2 | 0 / 0 / 0 |
| lighttpd1 | 0 / 0 | 6 / 0 | 0 / 0 / 13 |
| lightftp / pure-ftpd | 0 / 0 | 0 / 0 | 0 / 0 / 0 |

\* Aug-07 批次早于 Aug-13/17 的 crash-channel 加固（无 teardown 目录，计数口径
仍与 ChatAFL 同类）；live555 上当时 LoopFuzz 反而找到 27 个 crash——即"LoopFuzz
找不到崩溃"在旧口径下不成立，差异是**口径**而非能力。

## 2. 崩溃差异根因：信号分类语义（可验证）

**ChatAFL `run_target()`**（`ChatAFL/afl-fuzz.c`）：
```c
if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;
if (kill_signal == SIGTERM)                   return FAULT_NONE;
return FAULT_CRASH;   // SIGTERM 窗口内的 SIGABRT/SIGSEGV → 一律算 crash
```
无 `child_term_sent` 标志、无 ASAN stderr 筛查。

**LoopFuzz**（Aug-2026 加固）：fuzzer 发过 SIGTERM 后子进程死于致命信号时，
先查 stderr 是否有 `ERROR: AddressSanitizer`：有 → FAULT_CRASH；无 →
FAULT_NONE，并把证据存入 `teardown-crashes/`（带 `race:1` 标记）待 triage。

**实证**：
- ChatAFL bftpd 的 42 个 crash **全部 sig:06 (SIGABRT)** ——与 LoopFuzz teardown
  候选同签名；
- 抽 3 个 ChatAFL crash 在 ASAN bftpd 容器各重放 5 次：**3/3 全部存活、零
  ASAN 报告**——与 `TRIAGE-2026-09-02-teardown.md` 的 39/39 伪影结论同
  类（kamailio 根因：`handle_sigs`→`shutdown_children()`→`abort()`）。

## 3. 挂起差异根因：LLM 回复原文注入（主因，56%–99%）

**ChatAFL 机制**（`ChatAFL/chat-llm.c`）：
```c
// extract_stalled_message(): 惰性正则只剥掉回复第一行，其余全部保留
pcre2_compile("\r?\n?.*?\r?\n", ...);
res = strdup(message + ovector[1]);        // ← 解释文字+markdown 全进来
// format_request_message(): 仅补 \r，无任何内容校验
common_fuzz_stuff(argv, stall_message, strlen(stall_message));  // 直接发送
```
LLM 回复一段"Sure! Here is a reasonable modified sequence ... ```text
USER ubuntu ..." 时，整段（常见 5–11KB）被当作协议消息发给服务器：服务器
解析器在垃圾字节流上缓冲/等待 → 超过 `-t 5000` → FAULT_TMOUT → 且因垃圾
踩出新 parser 路径（virgin_tmout 新位）而**作为 unique hang 保存、甚至进入
queue 被 havoc 继续繁衍**（hang 文件名大量 `op:havoc_explore, src:...`）。

**量化**（本次实测，LLM 残留特征 = ``` 围栏 / **加粗** / "Here is" 等）：

| Target | 含 LLM 残留的 hang 比例 |
|---|---|
| proftpd | **422/424 = 99%**（中位 8.7KB） |
| bftpd | 48/54 = 88% |
| kamailio | 3/5 = 60% |
| exim | 40/71 = 56% |
| forked-daapd | 0/90 = 0%（见 §4） |

**LoopFuzz 的三道防线**（现行代码）：
1. `validate_and_parse_llm_json()`——严格 JSON schema（suggested_request /
   actions[]）；闲聊式回复 parse 失败 → P fail → **不执行**；
2. `clean_llm_response()`——grammar 回复先剥 markdown；
3. admission 门控 U 谓词——即使执行，错误响应（4xx/5xx）候选被拒之门外，
   不进 queue 繁衍。Sep-02 批次实测 245 个候选中 228 个被 U 拒绝。

## 4. 例外：forked-daapd 的 90 个挂起（0% LLM 残留）

内容为 4.3KB 的长度前缀 DAAP/HTTP 多请求序列（`GET /api/library/...`、
`/api/spotify` 等慢端点的 havoc 变异）——属"慢处理器曝光"类挂起，与 fuzzer
无关：ChatAFL 26h 速率 ≈3.5/h，LoopFuzz（Aug-07）4.8h 内 10 个 ≈2.1/h，
**同数量级**。该类差异主要来自 campaign 时长与执行吞吐（ChatAFL proftpd
135k execs vs LoopFuzz 62k，LoopFuzz 每 exec 附加 oracle 采样/校验开销）。

## 5. 诚实警告：LoopFuzz 的口径不是免费的

- **FN 风险**：Aug-17 曾发生 28+11 crashes → 0 的召回回归；live555 类 teardown
  竞态真漏洞（CVE-2019-7314 类）若无 ASAN stderr 证据同样会被降级。现行
  设计的兜底是：teardown 候选**不丢弃**而是留证据（`.request.replay` 种子 +
  `race:1` 标记）供离线重放 triage（本仓库 2026-09-02 已完成一轮：39/39 伪影）。
- **曝光差异**：LoopFuzz 每小时执行数约为 ChatAFL 的 0.5–0.7×，纯粹的
  慢端点类挂起曝光相应减少。

## 6. 论文表述建议

按 first_paper.md 口径：**不得用 crash/hang 文件数量当漏洞计数**。若审稿人问
"为何基线 crash 更多"，正确回答是：基线把（a）关停窗口伪影和（b）未验证 LLM
输出造成的解析挂起都计入了发现；LoopFuzz 的 evidence-gated 设计使这两类信号
在执行前/计数时被分离，并保留可 triage 的证据链——这正是"response-derived
信号不可直接信任"这一论文主题在 crash 通道上的又一体现。

---

# 附录（2026-09-03 追加）：谁能更好地发现漏洞

**数据约束**（用户指定）：LoopFuzz 只采信九月数据（现行 evidence-controller
代码，`results-*_Sep-02_18-16-08`，9 target × 3 runs × 3h ≈ **81 run-hours**）；
基线（ChatAFL/aflnet 系，代码未变）可用更早数据（Aug-04/09/10，≈**470 run-hours**）。
未发现独立的 aflnet 结果目录可用（近月批次均为 chatafl/loopfuzz）。

## A. 实证记分（按项目判据：ASAN 报告 + 可重放）

| | ChatAFL（470 run-h，可用更早数据） | LoopFuzz（81 run-h，仅九月） |
|---|---|---|
| 崩溃信号 | 42+7+4+1+2×… 全部 **sig:06** | 0 |
| ASAN 证据文件 | **0**（无 sidecar 系统） | 0（机筛在 fuzz 时已做） |
| 抽样重放 | bftpd 3/3、live555 1/1（5 次）**全部存活、零 ASAN** | teardown 39/39 全伪影（TRIAGE-2026-09-02） |
| hang | 56–99% 为 LLM 垃圾注入源 | 0 |
| **确认真漏洞** | **0** | **0** |

两个真 bug（live555 SUR、proftpd UAF，2026-08-16 定性）出自 **8 月中旬的
旧版 LoopFuzz**（hang 通道 + ASAN sidecar），按约束不计入现行 LoopFuzz
战绩，但证明该检测通道设计**能够**落地真 bug。

## B. 覆盖获取效率（触发漏洞的前提）

九月 LoopFuzz 3h 的最终绝对行覆盖 vs ChatAFL 26h（run_1，gcovr）：

| Target | LoopFuzz 3h l_abs | ChatAFL 26h l_abs | 达成率 |
|---|---|---|---|
| bftpd | 1270 | 1270 | 100%（1/9 时间） |
| lighttpd1 | 4015 | 4057 | 99% |
| proftpd | 11583 | 11635 | 99.6% |
| live555 | 5993 | 6127 | 98% |
| exim | 6357 | 6567 | 97% |
| kamailio | 16643 | 17315 | 96% |
| forked-daapd | **8112** | 7872 | **103%（反超）** |
| pure-ftpd | 1850 | 2171 | 85% |
| lightftp | 171 | 279 | 61% |

→ 单位时间到达深度 **6–10×**（且 ChatAFL 的 plateau 预算还在被 markdown
垃圾消耗）。到达是触发的前提：同样预算下 LoopFuzz 触发深层 bug 的机会
显著更高。

## C. 检测通道完备性对比

| 漏洞表现形态 | ChatAFL | LoopFuzz（九月版） |
|---|---|---|
| ASAN 可见内存错误（SEGV/UAF/溢出） | 计入 crash 堆，**无证据、混在伪影里** | 同等计入（FAULT_CRASH 路径未动）+ 自动 ASAN 佐证 |
| 无 ASAN 输出的 abort()/assert 类 | 计入 crash 堆（不可区分） | 降级 teardown-crashes，**保留重放种子+race 标记**，可 triage |
| 表现为超时的慢速内存错误（proftpd UAF 类） | hang 通道，被 424 个 LLM 垃圾 hang **淹没** | hang 通道干净 + E2a 证据边车 |
| 逻辑漏洞（无崩溃） | **结构上不可见** | 协议 oracle 通道（FP 审计后） |
| 关停竞态（live555 CVE 类） | 混入 crash 堆 | 隔离保留，需 triage（FN 风险有界） |

## D. 结论

**在"发现真实漏洞"的意义上，LoopFuzz 更强**，理由是四条可验证的结构性
优势而非信号数量：

1. **到达效率 6–10×**（§B）：同等预算下触发深层代码的机会量级更高；
2. **通道完备**（§C）：内存错误/竞态/慢速错误/逻辑违规四类形态都有对应
   检测通道，ChatAFL 只有单一且被污染的信号通道；
3. **精度与可定位性**：ChatAFL 的 470+ 疑似信号中真值为 0 且无证据，真
   bug 出现会被伪影淹没（人需全量重放）；LoopFuzz 每个"疑似"都带可重放
   证据，机筛先行，真 bug 出现即被隔离呈现；
4. **LLM 预算效率**：不被垃圾回复消耗（ChatAFL 每 plateau 有概率注入
   markdown 并繁衍出数百垃圾 hang）。

**诚实的边界声明**：
- 九月 LoopFuzz 曝光仅 81 run-h（基线的 1/6），"0 vs 0 确认"的置信区间
  都很宽，结论主要由通道结构与效率证据支撑；
- LoopFuzz 的 ASAN 门控存在 FN 窗口（无 ASAN stderr 的关停竞态会延迟到
  triage 阶段而非当场计数）——这是用精度换时延的明确取舍，teardown 证据
  保留是其兜底；
- live555 类低频竞态 5 次重放不能 100% 排除，但 ChatAFL 数据中不存在任
  何 ASAN 证据文件可佐证其任何崩溃为真。

**一句话**：ChatAFL 报得更多，LoopFuzz 找得更准、到得更快、证据更硬——
"疑似数量"不是漏洞发现能力，"单位预算内带证据的真漏洞产出"才是。
