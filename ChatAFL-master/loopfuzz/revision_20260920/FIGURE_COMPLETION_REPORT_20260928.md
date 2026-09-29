# 图形完成与核查记录（2026-09-28）

已更新 `main.revised.tex` 和 `main.revised.pdf`，正式插图使用矢量 PDF，另附可编辑 SVG。最终论文为 26 页，包含 9 幅图。新生成的六幅图位于 `figures_20260928/`；PNG 仅存放在 `figure_checks_20260928/` 作为排版检查预览，未嵌入论文。

## 图形与 first_paper.md 的要求对应

| 论文图 | 内容 | 输出 / 证据状态 |
|---|---|---|
| Figure 1 | 三个目标的 code-branch / IPSM state-edge 对比 | 保留已核验的 `native_endpoints_filled.pdf`，矢量 |
| Figure 2 | evidence-gated controller architecture | 保留原生 TikZ，矢量 |
| Figure 3 | episode → pre-update prediction → reward → posterior update | 保留原生 TikZ，矢量；这是方法示意图 |
| Figure 4 | 按目标分组的日志奖励可靠性诊断 | `logged_reward_reliability.pdf/.svg`；附各 bin 的计数和按 run 重采样的区间 |
| Figure 5 | 五个 arm 的覆盖率轨迹 | `coverage_trajectories.pdf/.svg`；44 个已有 target–arm 组合 |
| Figure 6 | 三个目标的状态后验及调度权重演化 | `posterior_cases.pdf/.svg`；确定性选例规则与源路径随图发布 |
| Figure 7 | candidate disposition 与首个失败 P/U/R 标志 | `candidate_dispositions.pdf/.svg`；以候选和 trial 分别为分母 |
| Figure 8 | token 成本与终点覆盖 | `token_cost_coverage.pdf/.svg`；375 个 B–E 观测 |
| Figure 9 | call 成本与终点覆盖 | `call_cost_coverage.pdf/.svg`；同一组 375 个观测 |
| 历史 CVE Kaplan–Meier | 缺少验证后的 trigger-time / vulnerable–patched oracle 记录 | 移除空白图框，正文说明不可估计，结果表仍留空 |
| CPU-hours / CVE recall 成本前沿 | 缺少完整 CPU 用量、验证后的 CVE 结果及匹配预算条件 | 不绘制虚构前沿，不用 wall time 冒充 CPU-hours |

现有数据支持描述性图形，尚不足以完成计划中的统一 build、固定 episode energy、独立 source-branch reward、provisional 生命周期及历史漏洞因果验证。图注与正文保留这些边界，未将图形补齐表述为完成了全部确认性实验。

## 数据来源与统计口径

- 来源为 `Key_Experiment/benchmark` 和 `Key_Experiment/ablation`。沿用经核验的 517-run ledger，其中主图涉及 A/B/C/D/E 的 469 份归档；两个 gamma sensitivity 组仍保留在原实验表中。
- D 使用 benchmark LoopFuzz，视为用户指定的 gated_fixed 等价来源，只计一次。
- 名义重复数 N=10；均值、分位数与 bootstrap 使用实际可见观测。缺失 run 不补零、不复制、不扩大样本量。E–bftpd 不绘制伪曲线；Forked-daapd E 的实际 n=6。
- 覆盖率读取每份归档的 `cov_over_time.csv`，以原始 `fuzzer_stats.start_time` 为时间零点，5 分钟网格上只在首末实测点之间线性插值。图显示 0–24 小时，中位数与四分位区间；超出支持范围为缺失。每个时间点的 n 保存在 `coverage_trajectory_values.csv`，区间不是置信区间。
- 全部轨迹的梯形 AUC 与既有 ledger 一致。轨迹结束时间范围为 21.928333–25.587222 小时。121 条原始序列存在下降，未施加累计最大值，也未修饰为单调曲线。
- 一份 D / Lighttpd1 归档 `benchmark/results-lighttpd1_Sep-17_02-35-46/out-lighttpd1-loopfuzz_11.tar.gz` 的序列末值为 2115，汇总表为 2139。曲线保留序列值，端点表及成本图保留汇总值；正文明确披露，未擅自覆盖任一来源。
- E 的 28,866 条 episode 通过概率有限性与范围、Beta 均值、二元奖励、episode ID 唯一性、时间顺序、单 episode discounted update 核查。5,753 条零执行记录从可靠性诊断中排除，保留 76 个 run 的 23,113 条记录。三个跨 episode 的 posterior 不连续点被记录，未伪造缺失历史。
- 可靠性使用 `posterior_mean_before`，不使用 post-update probability 或 sampled_theta；10 个固定等宽 bin；2,000 次目标内按整个 run 重采样，固定 seed=20260928（各目标采用固定偏移）。空 bin 无估计，不足两个贡献 run 的 bin 不报告 bootstrap 区间。指标按目标统计，不把不同程序混为一个独立样本池。
- Brier / ECE / AUPRC 附在独立的日志奖励诊断表。AUPRC 使用 non-interpolated average precision，同分概率在同一阈值处理；Brier 对照为同一 run 已纳入历史奖励的 Beta(1,1) 平滑 prequential base rate。没有正奖励时 AP 不定义。区间未解决归档之间可能存在的依赖。
- 日志 reward 表示 native coverage-save event，可能含 hit-count novelty，不等同于独立回放的 source-level branch reward。正执行 episode 不保证固定 energy 或正常完成；终止时写出的记录按已记录数据保留。原机制表中要求完整独立 reward 的 Brier/ECE/AUPRC 单元格仍留空。
- 状态演化图每个目标选择终点 branch count 排序后的 lower-median E run，以路径打破平局；再选择正执行 episode 最多的两个状态。显示所选状态的全部日志历史，包括零执行记录；frontier=0 时不计算比值。曲线横坐标是 episode 结束时刻，连线只辅助阅读。
- 队列图统计 C/D/E 的 1326/1992/726 个候选与 1326/1991/725 个 trial。D/E 各有一个未匹配候选。durable/reject 是日志标签，不声称已验证真实队列成员资格；provisional、converted、expired 没有可用生命周期证据，不作为零率绘制。
- 成本图使用保存的 prompt+completion token / model-call 计数，保留所有 375 个 B–E 终点。A 缺少同口径计数，不填成零。不同 target 分面，不拟合 Pareto frontier，不把 saved counters 当作完整账单或 cost-matched 效果。

## 可复现文件

- `prepare_vector_figure_data_20260928.py`：直接只读遍历 tar，不解包任意路径；只保存绘图需要的数值字段。原始实验文件不变。
- `vector_figure_evidence_20260928.json.gz`：持久化数值证据，不依赖 `/tmp` 缓存。含来源相对路径、归档大小/mtime、coverage/episode member 内容哈希及 ledger 哈希，不含候选请求或提示词正文。
- `figure_evidence_cache_20260928/`：逐归档检查点，源文件属性或 ledger 变化时失效。
- `plot_vector_figures_20260928.py`：绘图、统计与独立日志奖励表生成。
- `verify_vector_figures_20260928.py`：源数值一致性、时间支持、分位数、Brier、计数守恒、矢量内容、引用和编译日志检查。
- `figures_20260928/` 内 CSV/JSON：逐点曲线与分母、校准 bin/指标、候选分布、每 run 成本、案例选择、分析和核查记录。
- 修改前论文备份为 `main.before_vector_figures_20260928.tex/.pdf`。

在本目录执行：

```sh
python3 prepare_vector_figure_data_20260928.py
python3 plot_vector_figures_20260928.py
bash build_revised.sh
python3 verify_vector_figures_20260928.py
python3 verify_filled_data.py
pdftotext -layout main.revised.pdf main.revised.txt
```

Python 3.13.11，NumPy 1.26.4，Matplotlib 3.10.8；使用本地 LaTeX 类文件、latexmk 和 Poppler，无联网、无新增依赖。

## 最终核查

- `figure_validation.json`：PASS；六份 PDF/SVG 为矢量，整篇论文 PDF 的嵌入栅格图像数为 0，PDF 字体嵌入。
- `filled_validation.json`：PASS；原有 517 份归档、60 个组、44 个主表已填单元及缺失格均保持一致。
- 编译无错误、未定义引用、Overfull 或超高浮动体；原有少量 Underfull 段落提示不影响图形。
- 已检查独立图与整页渲染，修正标题遮挡、图注对应、图号顺序及候选图的版面布局。正式稿没有空白图框。
- 图所在页：Figure 1 → p.4, Figure 2 → p.6, Figure 3 → p.6, Figure 4 → p.15, Figure 5 → p.17, Figure 6 → p.18, Figure 7 → p.18, Figure 8 → p.20, Figure 9 → p.21。
