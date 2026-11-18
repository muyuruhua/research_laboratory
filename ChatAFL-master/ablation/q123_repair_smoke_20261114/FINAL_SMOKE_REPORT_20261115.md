# 九目标 threshold-1 mock 冒烟最终报告（2026-11-16 更正版，取代 11-15 版）

本版按 codex 复审五条意见全面更正；11-15 版中的错误判断（pure-ftpd 根因、
方向性数字四处、真实网关前置条件）在本版撤销或修正。更正依据与工件：
`Key_Experiment/ablation_20261113/codex_reaudit_fixes_20261116/verification.md`。

审计标准：audition.md + audit_smoke.py（本版新增 v4 深层工件审计）。
统一源码指纹：`5f818ed7…`（fuzzer）；回放模块版本
`20261116-proptpd-natural-exit-framecomplete-pureftpd-421-tail-v1`。
配置：threshold=1、warmup=8、energy=32、reward_window=16、15 分钟墙钟、
SKIPCOUNT=40、mock llm_mock_v5.py 容器内隔离；九目标各 8 核心臂 × 3 重复。

## 一、记分牌（全部经 v4 深层工件审计：逐输入哈希/快照重建/转录帧核对）

| 目标 | 结果 | 深层审计 |
|---|---|---|
| proptpd | 8/8 PASS | 105/105×臂；48 条豁免输入帧完整=0 缺失 |
| exim | 8/8 PASS | 通过 |
| live555 | 8/8 PASS | 通过 |
| kamailio | 8/8 PASS | 通过 |
| forked-daapd | 8/8 PASS | 通过 |
| bftpd | 8/8 PASS（--arms core） | 通过 |
| lightftp | 8/8 PASS（salvage1 重跑后） | 通过 |
| lighttpd1 | 8/8 PASS | 通过 |
| pure-ftpd | **7/8**；nollm1 未解决（见二） | 7 臂通过；nollm1 96/99 |

审计文件：`audit_<target>_final_fp5f818ed7_20261115.txt`（bftpd/lightftp/
lighttpd1 为 11-16 批次），深层扫描副本存于 `audit_DEEP_fp5f818ed7_20261116/`。
**删除底层证据（checkpoint/snapshot/日志）的归档现在 FAIL**（原有 102/102 假
阳性缺口已闭合，回归测试 test_audit_smoke.V4DeepArtifactAuditTests）。

## 二、pure-ftpd nollm1：根因更正与最终归因（撤回 11-15 版「非管线缺陷/潜在 DoS」）

**11-15 版判断有误**。事实链（codex 复审 + 本方独立复核）：
1. FTP 回复提取器（aflnet.c，多行回复遇无数字行即 break）导致回放客户端
   摘要截断；5/7 条异常的日志原文实际以 `421` 结尾（4× secure-anonymous-FTP、
   1× Line-too-long），按 v2 策略本应豁免——**确有解析缺陷**。
2. 修复（coverage_v4）：`pureftpd_final_reply_code` 接受「原文=摘要+完整
   尾部回复」时取尾部码；其他分歧仍拒。独立重放验证（修正 harness，
   `replay_verify_fp5f818ed7_20261116/pureftpd_nollm1_run*`）：
   run1 complete（6 豁免）、run3 complete（3 豁免）——解析缺陷修复被证实。
3. 剩余异常归因（不再宣称 DoS，留人工分诊）：run2 重放后剩 1 条——
   服务器在错误回复（垃圾字节 CWD→550）后无 421 关闭即退 251；
   另一历史形态为横幅后零响应退 252。两者按策略保持异常。
4. 结论：nollm1 三重复仍非全完整，**未解决**；其 580 分支值为不完整下界，
   不参与比较。

## 三、proptpd 停机伪影：v2 → v3（codex 两缺口闭合）

- v2 缺口：client=0 不能证明全帧发送；豁免会话 gcov 落盘未证明。
- v3 修复（按 codex 建议路径）：回放收割在客户端完成后**先等 ≤5s 的
  `-X` 自然退出**（自然退出即正常 gcov atexit 落盘），仅滞留才发 TERM；
  豁免条件增加 frames==packets（转录帧完整），无帧账本不豁免。
- **独立重放验证（24/24 全部 complete、0 异常、0 豁免）**：
  `replay_verify_proftpd_fp5f818ed7_20261116/`——自然退出优先从机制上
  消除了 SEGV 场景，v2 的 48 条豁免在新 harness 下不复存在；分支数与
  战役内回放同量级（pvstop1 4155、wrapgate1 4445、native1 4412）。
- 存量 v2 归档未回溯升级；其豁免输入的帧完整性由深层审计逐条验证通过。

## 四、机制触发表（PASS≠机制验证；threshold-1/15min 的固有限度）

| 目标 | calibrated1 选择/applied | 准入事件 | 说明 |
|---|---|---|---|
| kamailio | 56 次 / **48 applied** | 6 | Q3 机制触发 |
| bftpd | 38 / **30 applied** | 42 | Q3 机制触发 |
| lightftp | 47 / **39 applied** | 58 | Q3 机制触发 |
| live555 | 11 / 3 applied | 10 | 部分触发 |
| proftpd | 9–21 / 0–1 applied | 12–14 | 基本未越过 warmup |
| exim | 4–5 / 0 | 2 | 未触发 |
| forked-daapd | 6 / 0 | 6 | 未触发 |
| lighttpd1 | 8 / 0 | 0 | 未触发 |
| pure-ftpd | 7 个 LLM 臂 21 次运行全部仅回放 184 初始种子、0 新增分支、机制计数 0 | | 仅验证归档回放 |

含义：8/9 目标的冒烟 PASS 证明**测量与归档管线闭合**；门控/salvage/校准
机制在多数目标的 15 分钟窗口内未触发或未越过 warmup=8。按 audition.md §1，
这些目标上的机制级比较属未触发/未解决；机制验证由真实网关（512 阈值、
更长时长）承担。Q1/Q2 配对臂（q1a1–q1d1、ordmatch1）本批未包含，
Q1 配额回流与 Q2 同预算对照**不能**由本批回答。

## 五、方向性信号（更正 11-15 版四处错误；仅冒烟级，不作 Q1–Q3 结论）

均值±样本标准差（分支；调用=目标执行次数）：
- proptpd：wrapgate1 4416±45 最高；门控臂均值 4172–4416，nollm1 4142±8；
  门控臂调用均值 ~5680–6027 vs nollm1 8474（**少 ~30%**，proptpd 专属）。
- kamailio：calibrated1 5884±28 最高；pvstop1/wrapgate1/calibrated1 调用
  比 nollm1 分别少 **6.9%、7.5%、9.4%**（11-15 版误写 ~30%）。
- forked-daapd：calibrated1 2148.67 **并非居首**——低于 nollm1 2154.67、
  salvage1 2151.33、cal_ewma1 2150.67、cal_run_rate1 2150（11-15 版错误）。
- kamailio 调用最少为 cal_ewma1 5147，非 salvage1 5199（11-15 版错误）；
  salvage1 5199 为次少、覆盖均值最低（5620±93）——**仅描述性排序，
  无显著性检验，不得写「显著垫底」**。
- live555/exim/pure-ftpd：臂间均值差 <1.7%/0.7%/0（门控臂间无方向）。
- **注意**：固定时长内调用数偏少可来自 LLM 等待/初始化开销，不能直接
  解释为门控节省了无效资源；节省主张需 Q1 专属臂的配额回流账本。

## 六、宿主异常记录（不影响结论，已绕过）

11-16 04:00–06:00 宿主出现名字级路径解析异常（`out-proptpd-loopfuzz`
 等：readdir 可见、路径 lookup ENOENT；find/dirfd 可通行；跨沙箱/容器
 视图互相覆盖）。以容器内 `tar --transform` 改名 + 全容器侧落盘绕过；
 该现象使 proftpd 重放验证多耗 ~2 小时。建议后续对 /home 做 fsck 检查。

## 七、真实网关前置条件判定（更正 11-15 版）

11-15 版「前置条件已满足」**不成立**。当前状态：
- 已满足：九目标管线级冒烟（71/72 臂-目标）、深层工件审计、proptpd/pure-ftpd
  回放缺陷修复与独立验证、kamailio 关闭中止修复（24/24 干净）、源码指纹统一。
- 未满足（放行前需完成或确认）：
  1. pure-ftpd nollm1 未解决（按 audition.md §1 如实标注即可放行或
     先完成剩余异常的人工分诊——由你决定）；
  2. 机制验证：多数目标 15 分钟窗口内校准/门控未触发——真实网关批次
     本身承担该验证（建议时长 ≥120 分钟/臂）；
  3. KEY、臂集（建议 8 核心臂 + q1a1–q1d1 + ordmatch1）、每臂重复数。

## 附：当日修复清单（全部有验证工件与测试）

1. audit_smoke v4 深层工件审计（+剔除→FAIL 回归测试；会话型 gcda 豁免；
   lightftp 路径映射）。
2. coverage_v4 proptpd v3：自然退出优先 + 帧完整豁免（24/24 独立重放
   验证零异常零豁免；51/51 单测）。
3. coverage_v4 pure-ftpd 尾部 421 前缀扩展解析（nollm1 run1/run3 由
   incomplete 转 complete 验证）。
4. （11-15 已录）kamailio helper stop_soon 修复；proptpd v2 策略（被 v3 取代）。
