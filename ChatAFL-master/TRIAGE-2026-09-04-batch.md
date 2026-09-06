# Sep-04_18-30-09 批次分析（9 target × 3 runs × 3h，arm D）

- **日期**：2026-09-05
- **判定标准（用户指定）**：必须是**能复现出异常结果**或**违反安全业务属性**的才算漏洞。

## 1. 优化方案生效验证 — 27/27 全部生效

- 27/27 容器 `arm=loopfuzz-gated-fixed`，run-config 完整（start/end、LLM 配置、fuzzer_commit）。
- state-selection episode 机制：全批 2,821 个 episode，jsonl 行数与 fuzzer_stats `cal_episodes` 逐一相符。
- admission 门控正常（g_code/g_state 分列、disposition 记录齐全）；provisional 通道本批仍未触发（与前两批一致）。
- bug-events.jsonl 已覆盖 teardown 事件（上一轮补丁生效）。

## 2. 崩溃与挂起：零

- `unique_crashes=0`、`unique_hangs=0`（27/27）。
- teardown 候选 45 个（kamailio 42、bftpd 3），全部 sig:06+race:1、无 ASAN 证据——与 9/2 批 39/39 已判定的关停伪影同签名同根因，**不构成漏洞**。
- oracle 内存安全违规：0。

## 3. Oracle 逻辑违规：bftpd 报出 7+2 条 — **判定为 oracle 误报（附复现证明）**

这是 oracle 通道启用以来第一次报出候选（此前数批全为 0），必须按用户标准严判：

- **报告内容**：`FTP: RNTO without prior RNFR accepted by server`（severity=3,
  evidence=STRONG），两个 run 各自独立报出，pattern hash 一致。
- **表面看像真发现**：双 run 独立复现、evidence=STRONG、状态一致性违规。

### 复现实验（按用户标准执行）

将 v1 违规种子在干净 bftpd 6.1 容器逐消息重放并记录**每条消息的实际响应**：

```
17 RNFR test   -> 350 File exists, ready for destination name
18 RNTO test2  -> 250 OK
```

**会话里根本不存在"无前置 RNFR 的 RNTO"**：RNFR 就在紧邻的上一条消息且
得到 350。被违反的"安全业务属性"在真实服务器行为中**没有发生**——复现
不出异常结果，按用户标准**不构成漏洞**。

### 误报根因（oracle 对齐缺陷）

bftpd 对超长命令行（本会话 msg01 是 643B 的 LLM `<think>` 残留）做截断
处理，把一条消息当多条命令回多个 500——**响应槽数（22）≠ 请求消息数
（20）**。oracle 的 request→response 槽位对齐被整体推移 2 位，RNTO 位置
读到了错位的响应码，导致 `rnfr_pending/prior_rnfr_ready` 双双判否。
oracle 自带的 `text_command_line_is_clean`/`ftp_response_has_rnto_reject`
两个防误报护栏都未能拦住这种"截断多响应"形态。

### 处置

1. 这 9 条违规**全部作废**，不计入任何发现；
2. oracle 缺陷登记为**工具 bug**（slot 对齐需按"响应码总数 vs 消息数"
   或行截断特征做失配检测，失配即弃权该会话）；
3. 修复前，oracle 通道的 bftpd 输出不可作为论文 RQ 证据。

## 4. 结论

- **优化方案：全部生效**（27/27 arm 正确、episodes 记账一致、事件日志完备）。
- **本批零漏洞**：无崩溃、无挂起、无内存安全违规；oracle 的 9 条候选经
  复现检验全部为误报（对齐缺陷），已按"能复现异常/违反业务属性"的标准否决。
- **顺带产出**：发现并定位了 oracle 的一个真实工具缺陷（bftpd 行截断导致
  槽位漂移），修复建议已给出——这本身是 oracle 通道自我纠错能力的体现。

---

# 附录：Sep-05_21-13-51 批次（截至 6/9 target 完成，18 runs）

## 优化生效验证

| 项 | 结果 |
|---|---|
| arm 正确 + episode 记账 | 17/18（1 个 SIGKILL 竞态差异，见下） |
| **oracle 弃权机制（首次全批生效）** | FTP/SMTP 系 target 全部触发：bftpd 17,476 / proftpd 4,688 / pure-ftpd 2,179 / exim 1,056 / lightftp 448；lighttpd1=0（HTTP，不适用，符合设计） |
| **影子层（oracle-abstained/）** | 11/18 run 达 64 上限、6/18 部分落盘、1/18 零（纯 HTTP target），FN 抽样通道畅通 |
| hang 0 字节修复 | 3 个 proftpd hang 种子全部 820-900B 非零（可重放）|
| 判决零误报 | oracle_total_violations = 0（18/18）——修复前同种子报 7-19 条 |

## 信号严判（按"能复现异常/违反业务属性才算漏洞"标准）

**proftpd 3 个 hang（重放验证，全部否决）**：3×3 次重放全部 270-430ms 完成
（远低于 5000ms 阈值）、零 ASAN、无挂起行为复现。hang.meta 显示原始执行
children CPU 43.2s——CPU 密集型慢执行（havoc 变异引起的服务器内部
计算），非死锁。**不构成漏洞**。

**bftpd 16 个 teardown（分类+抽验，全部否决）**：14×sig:06（关停 SIGABRT，
同 Sep-02/04 根因）+ 2×sig:09（SIGKILL——fuzzer 自身超时强杀痕迹，
非服务器自发信号）。4 个抽样重放全部存活、零 ASAN。**不构成漏洞**。

**弃权存档 FN 抽样（exim SMTP，3 个样本）**：逐消息重放建立真实绑定，
全部为垃圾变异消息收 554 拒绝序列——弃权通道 FN=0（弃掉的正是不可判
定的噪声会话）。

## 零崩溃 / 零 oracle 判决 / 零漏洞

本批（6 target × 3h）无任何通过严判标准的漏洞发现。

## 工程发现（不影响判定，如实记录）

bftpd run_3 的 episode 记账差异（jsonl=62 vs stats=61）诊断为 docker
SIGKILL（exit 137）终止时 JSONL 已追加最终 episode 但周期性 stats 快照
未及更新——非确定性终止下的记账竞态，暴露 run-config start 事件位于
enrichment 之后的放置缺陷（enrichment 阶段崩溃会丢失 run-config）。
