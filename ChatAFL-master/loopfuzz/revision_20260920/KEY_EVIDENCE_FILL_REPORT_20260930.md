# 缺失实验数据补充报告（2026-09-30，Key_Experiment 证据填充轮）

## 数据来源与验证方法

- 来源：`/home/ckt/Documents/000_2026_test_dev/Key_Experiment`（642 个归档，与 10:40 数据更新轮相同快照；本轮无新增归档）。
- 新增扫描：逐归档解析 `run-config.jsonl`（含 start/end 两个事件，end 为生效配置）与 `fuzzer_stats`（plateau/provisional/promotion 计数器）；版本锚点取自 benchmark `subjects/*/Dockerfile`；endpoint/种子/字典/重置取自每 run 记录的 `orig_cmdline`。
- 关键结论：B–E 与两个 γ 敏感性组的 end 配置在 model/endpoint/temperature/top_p/max_output_tokens/call_cap/token_cap/γ/ε/provisional 参数上完全一致（C 内 2 个 commit、D 内 4 个、E 内 2 个，仅 fuzzer_commit 不同）。

## 已填充

| 位置 | 内容 | 证据 |
|---|---|---|
| tab:targets（原 9×3 全空） | 9 个 target 的版本锚点、localhost endpoint、种子/字典/重置脚本 | Dockerfile 版本 pin（bftpd 6.1、LightFTP 139af7c、ProFTPD 61e621e743346、Pure-FTPd 10122d9f、Exim d6a5a05b84、Live555 live.2023.05.10、Kamailio a2209018fb03d、forked-daapd 2ca10d9、lighttpd1 9f38b63cae3e2）+ 每 run orig_cmdline |
| tab:llm（原 9 行中 6 行空） | model=codex-auto-review@cctq.ai、temperature 0.5/1.2、top_p 1.0、max_output 4096、call_cap 64/token_cap 0、plateau 阈值 512 | 全部 466 个 LLM-arm 归档 end-config 一致；penalties/超时重试/模型端种子/prompt 模板版本无记录，保留空白；B 臂归档无内嵌配置记录（已在表注说明） |
| tab:mechanisms（原 2 行空） | state-only provisional rate：C disabled、D 0.0%(0/2,227)、E 0.0%(0/746)；conversion/expiration：无 provisional 准入 | 642 归档 provisional-events.jsonl 全缺、provisional 计数器全 0 |
| tab:repair（原第 1 行空） | E repair-off：0（无事件文件） | 642 归档无 repair-events.jsonl |
| RQ3 正文 | 删除已失实的"两个敏感性条件均无 Forked-daapd"（现 E99 n=9、E100 n=10）；改为 per-run γ 验证（66/81 γ=0.99、79/91 γ=1.0，其余为 γ=0.995 fixed 标签）与 4 个未满 10 组的明示 | end-config 逐 run 校验 + archive_arm_results_20260930.csv |
| 采样构成段（新增证据句） | 有效配置异质性：C 目录 17/90、E 目录 12/91、E99 15/81、E100 12/91 的 end-arm 为 gated-fixed；C 的 17 个行为证据（全部 durable、零 reject）支持 direct；commit 分布 D 78/12/9/5、C 83/7、E 71/20、E99/E100 单 commit | 逐归档 end-config + disposition 行为交叉验证 |
| RQ5 正文 | LLM 配置陈述由"reported"升级为"逐 run 记录"并指向 tab:llm | 同上 |

## 仍无法从 Key_Experiment 补充的（数据确实不存在，保留空白/说明）

- E99 四组未满 10：Lighttpd1 6、Live555 7、Kamailio 9、Forked-daapd 9（无归档；Forked-daapd run10 可从 docker 容器 073fc581… 重打包、Lighttpd1 7–10 可从 git 索引恢复，均在 Key_Experiment 之外）。
- tab:mechanisms 其余 7 行：promotion latency、productivity@64、queue size、shadow-validation、per-episode code gain、fixed-energy BS/ECE/AUPRC、joined code-gain/token —— 需要事件级 descendant/provisional 日志或验证时间戳，归档中不存在（代理口径 BS/ECE/AP 已在 tab:logged_calibration）。
- tab:repair 其余行：无 repair-on 臂。
- CVE Kaplan–Meier / arm-level recall：无受控 CVE 战役数据（论文 §Vulnerability 已如实声明协议要求）。
- B 臂配置内嵌记录：ChatAFL 归档无 run-config.jsonl。

## 构建验证

- latexmk 全量重编译通过：22 页、0 Overfull、0 未定义引用、0 重复标签。
- tab:targets（第 9 页）、tab:llm（第 10 页）、tab:mechanisms（第 15 页）文本层核对无错位。
- 修改前备份：`before_key_evidence_fill_20260930/main.revised.tex`。

## 补充轮：Table 8 三格 + Table 14 等能量子集两行（2026-09-30 晚）

- Table 8（tab:llm）3 格填入，均为源码派生（表注已声明 source-derived、跨 arm 相同）：
  - 超时/重试：120s 请求 / 30s 连接 / 60s 低速中止；按调用类 2–5 次重试、间隔 2s；致命提供方错误立即中止（chat-llm.c:172-178, chat-llm.h 重试常量）；
  - 模型端种子：无，请求体不含 seed 参数（chat-llm.c:142）；
  - prompt 模板版本：无版本标识；candidate-events.jsonl 逐请求记录 prompt_id/prompt_hash；模板身份由 fuzzer_commit 承载。
- Table 14（tab:mechanisms）两行按 equal-energy subset 口径填入（6 格）：
  - 子集定义：mutations 恰为 265（三 arm 共享的最高频非零能量），n = C 3,986 / D 6,604 / E 1,474；
  - 每 episode 平均 code edges：0.009 / 0.003 / 0.016；proxy-reward 基率 0.004 / 0.001 / 0.005；
  - BS 0.240 / 0.192 / 0.315，10-bin ECE 0.428 / 0.373 / 0.516，AP 0.012 / 0.005 / 0.038；
  - 发现：固定能量下 pre-update 预测严重过度自信（posterior 在混合能量下更新），排序能力仍高于基率（E 的 AP/基率 ≈ 8×）。
- 正文声明：RQ3 新增一段定义子集、给出数字与边界（探索性、未按 target 聚类、不替代 tab:logged_calibration 的全样本诊断）；tab:logged_calibration 段尾的交叉引用句同步改为"等能量子集行继承 proxy-reward 的限制"。
- 脚本与数据：equal_energy_analysis_20260930.py、equal_energy_results_20260930.txt、episodes_cde_20260930.json（285 个 C/D/E 归档的 episode 最小字段）。
- 剩余空白：tab:mechanisms 5 行（15 格，需改 LoopFuzz 实现）+ tab:repair 6 行（11 格，repair 未实现、论文策略降级）。
- 构建：23 页、0 Overfull、0 未定义引用。备份：before_equal_energy_20260930/。
