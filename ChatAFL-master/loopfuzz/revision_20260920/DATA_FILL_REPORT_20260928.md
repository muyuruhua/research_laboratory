# 实验数据回填与最终核查（2026-09-28）

本次入口是 `main.revised.tex`，预览为同目录的 `main.revised.pdf`。本报告补充 2026-09-20 的历史修订报告；旧报告中的 181 个归档、旧终点值、17 页预览和以 `../main.tex` 为入口的说明不适用于本次回填。

## 数据来源与口径

读取 `../../Key_Experiment/benchmark` 和 `../../Key_Experiment/ablation` 的 517 个现存归档对应的 summary、覆盖轨迹、最终保存的统计和事件日志，形成 60 个 arm–target 汇总。

| Arm | 来源 | 可观测归档行数 |
|---|---|---:|
| A | benchmark / AFLNet | 94 |
| B | benchmark / ChatAFL | 101 |
| C | ablation/direct | 90 |
| D | benchmark / LoopFuzz，按用户指定作为 gated_fixed | 108 |
| E | ablation/calibrated | 76 |
| E，gamma=0.99 | ablation/cal_gamma099 | 24 |
| E，gamma=1.0 | ablation/cal_gamma100 | 24 |

- 不足 10 次的组保留名义数量 `N=10`，实际可观测数量单列 `n`；缺少的观测保持空缺，不复制已有值，不补零，也不把 3 或 6 个观测冒充 10 个独立测量。
- 均值和样本标准差由可观测值计算；标准差分母为实际 `n−1`。超过 10 次的归档行全部保留，没有按结果好坏选择运行；额外归档的统计独立性未作假定。
- D 只使用 benchmark LoopFuzz 一次；不把 gated_fixed 与其重复计数。
- final branches 取 summary 的 `b_abs`；IPSM 取 `edges`。AUC 使用原归档 `cov_over_time.csv` 的时间戳和 `b_abs`，排序、重复时间取最大覆盖值，再对已观测时间段作梯形积分，单位 branch-hours。不外推到统一 24 小时。
- 原始退出状态保留；退出码 137 不能独立证明 OOM。正文表格已标明运行时间单位为分钟。

## 已回填与修正

- 主表的 45 个目标–arm 单元格中填入 44 个，bftpd 的 E 组无归档，保持空白。
- 同步 benchmark 终点表、各臂 AUC 表、正文 RQ1 数值及三目标动机图。新图为 `native_endpoints_filled.{pdf,png,svg}`，旧图及旧绘图脚本保留。
- 机制表记录候选、trial、reject/durable 标签，以及按 P→U→R 顺序统计的第一个 false 日志字段。这些字段和 disposition 都不被解释成已验证的实际队列状态。
- 填入 trial 的 `latency_ms`：先在每个具有 trial 的运行内取平均，再跨运行报告均值±样本标准差。C/D/E 有 trial 的运行数分别为 67/84/55；没有 trial 的运行没有被当作零延迟。promotion latency 仍为空。
- D 模型调用次数范围修正为 52–248；C/D/E 的 episode `mutations` 字段合并范围修正为 0–18,816。
- 修复引用转义、状态标签下划线、表格列宽及超页问题。修订稿头部的编辑器入口指向自身。

| Arm | Candidates | Trials | Reject | Durable | Episodes |
|---|---:|---:|---:|---:|---:|
| C | 1,326 | 1,326 | 0 | 1,326 | 56,164 |
| D | 1,992 | 1,991 | 1,968 | 23 | 75,631 |
| E | 726 | 725 | 716 | 9 | 28,866 |

事件 ID 在各归档内检查：无重复候选或 trial ID，无 orphan trial；D/E 各有 1 个候选缺少 trial。没有 provisional 标签不等于 provisional 转换率为零。

## 与 first_paper.md 的一致性和证据边界

保留 JNCA 定位、三个贡献、独立 G_code/G_state、reject/provisional/durable 两级队列、固定预算 episode、discounted Beta–Thompson、五臂 D−C/E−D 对照、repair 降级、LLM 策略与资源上限公平性、六类核心事件、RQ1–RQ5、历史漏洞最小补丁配对及信息控制、intention-to-run 和统计方案。

文本和结果解释按这些要求组织；现有数据不能补足要求中尚未实施或未经验证的实验。特别是 descendant lineage、实际 queue membership、可靠性校准指标、shadow validation、独立 repair 效果、historical CVE vulnerable/patch-paired 结果与部分 build/resource 配置保持空白。核心臂扩展至 20 次是要求文档中的后续方案，未写成已完成事实。当前回填不能被解释成已满足全部实证验收条件或已证明因果收益。

## 可核查文件与复算

- `filled_run_evidence.json`：517 条数值来源记录，包括归档相对路径；不包含 prompt 或候选请求正文。
- `filled_experiment_data.json`、`archive_arm_results.csv`：60 组汇总。
- `filled_mechanism_data.json`：P/U/R 日志失败数与 trial 延迟统计。
- `verify_filled_data.py`：将 per-run 数值、现存 summary、JSON/CSV、主表、归档表、终点表、费用表及编译日志交叉核对。
- `filled_validation.json`：最终机器可读核查结果。
- `plot_filled_endpoints.py`：基于本次 JSON 的版本化绘图入口。
- `build_revised.sh`：固定构建入口，显式把输出写到修订目录，避免父目录的同名辅助文件混用。

在本目录运行：

```bash
python3 plot_filled_endpoints.py
bash build_revised.sh
python3 verify_filled_data.py
```

最终数值核查为 PASS；PDF 为 18 页。LaTeX/BibTeX 无错误、未定义引用、Overfull 或 oversized float；保留 5 条 Underfull 段落排版提示。已渲染检查第 4 页动机图、第 14 页归档表和第 16 页机制表，未见裁切或列重叠。原归档及 fuzzer 源码未因本次回填而修改。
