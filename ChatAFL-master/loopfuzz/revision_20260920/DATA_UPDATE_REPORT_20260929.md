# 实验数据同步与一致性审计报告

数据提取快照：2026-09-29。最终验证时间：2026-09-30T00:11:55.400604+08:00。版本文件名保留快照日期。

已更新 main.revised.tex、main.revised.pdf 和对应表格、七幅实验矢量图及正文。原始 Key_Experiment 文件未改动。执行时使用 research-writing-skill、scientific-toolkit-skill，并按 first_paper.md 区分控制器设计、归档观测和仍待执行的确认性实验。

## 数据来源与运行口径

| 实验臂 | 来源 | 可用归档 |
|---|---|---:|
| A | benchmark / AFLNet | 94 |
| B | benchmark / ChatAFL | 91 |
| C | ablation/direct | 90 |
| D | benchmark / LoopFuzz | 104 |
| E | ablation/calibrated | 86 |
| E, gamma=0.99 | ablation/cal_gamma099 | 108 |
| E, gamma=1.0 | ablation/cal_gamma100 | 55 |
| 总计 | 61 个已观测目标—实验臂组合 | 628 |

名义设计数保持 N=10，实际观测数 n 逐组显示。均值、样本标准差、区间只使用可用观测；没有补造运行或用零填补缺失。超过十次的归档保留，但不额外假定各次启动相互独立。ablation/gated_fixed 根据用户确认视为 benchmark LoopFuzz 的重复来源，未重复计入 D。

主实验 A–E 共 465 个归档，45 个目标—实验臂组合均有数据。B–E 成本图使用 371 个具有保存计数器的归档，覆盖全部 36 个组合。E/bftpd 已有十次观测。D 的 104 条 summary 均标为 completed；这只是原始状态标签。全部 628 个轨迹终点与各自 summary 的 b_abs 一致。

## 逐图更新映射

| 图号 / LaTeX 标签 | 新的矢量文件，位于 figures_updated_20260929 | 数据与处理 |
|---|---|---|
| 图 1 / fig:mismatch | native_endpoints.pdf / .svg | 三个动机目标、A/D、代码分支与 IPSM 边，均值 ± 样本 SD；已纠正此前遗漏的旧图引用。 |
| 图 4 / fig:reliability | logged_reward_reliability.pdf / .svg | E 的逐 episode 更新前概率与日志奖励；只纳入 mutations>0。 |
| 图 5 / fig:trajectories | coverage_trajectories.pdf / .svg | 465 条轨迹，五分钟网格，中位数/IQR；只在实际观测时间内插值。 |
| 图 6 / fig:posterior_cases | posterior_cases.pdf / .svg | 三个目标的确定性选例，逐状态后验与记录的调度倍率。 |
| 图 7 / fig:dispositions | candidate_dispositions.pdf / .svg | C/D/E candidate、trial、处置及首次失败谓词；未匹配记录明确列出。 |
| 图 8 / fig:cost | token_cost_coverage.pdf / .svg | 371 次运行的保存 token 总数与终点代码分支。 |
| 图 9 / fig:callcost | call_cost_coverage.pdf / .svg | 同一批 371 次运行的模型调用数与终点代码分支。 |

图 2、3 是机制示意图，保留原设计。所有七幅更新图均有 PDF 和 SVG；SVG 无 image 元素，PDF 无嵌入位图。CSV/JSON 边表保留图中数值、源路径和抽样规则。

## 逐表及正文更新

| 位置 | 同步内容 |
|---|---|
| 表 9 / observed_inventory | 各目标 A/B/D 数量、D 状态/退出码和运行时范围。 |
| 表 10 / observed_endpoints | A/D 代码分支与 IPSM 边的全部均值、样本 SD。 |
| 表 11 / observed_log_counts | D 的候选、试验、处置、episode 计数。 |
| 表 12 / logged_calibration | 九目标 Brier、参考 Brier、ECE、AP，及按整次运行重抽样的 95% 区间。 |
| 表 13 / mainresults | 45 个 A–E 单元的终点、AUC、样本 SD、实际 n。 |
| 表 14 / mechanisms | C/D/E 机制计数、处置率、首次失败字段及运行内平均延迟的跨运行统计；缺证据指标留空。 |
| 表 15 / observed_costs | D 按目标的模型调用及 token 最小—最大值。 |
| 附录表 A.1 / archive_arms | 61 行完整观测，含两组 gamma 敏感性结果、样本数及状态。 |
| 表 17、18 / cve、cveresults | 与漏洞目录重新核对，无新增案例或证据变化；保留原批次分母和日志/报告来源区别。 |

摘要、归档清单、RQ1–RQ4、相关图注和数据可用性说明同步更新。删除两组 gamma 数据“small”的过时描述、主实验仍缺目标组合的表述，以及 D 包含中断记录的旧描述。保存调用数范围为 52–248 次；不能将配置中的 64 解释为已经强制执行的全调用上限。修复重复的“Appendix Appendix A”引用。

| 实验臂 | Candidates | Trials | Reject | Durable | Episodes |
|---|---:|---:|---:|---:|---:|
| C | 1,326 | 1,326 | 0 | 1,326 | 56,164 |
| D | 2,227 | 2,226 | 2,203 | 23 | 77,593 |
| E | 735 | 734 | 725 | 9 | 31,826 |

D、E 各有一个 candidate 缺少 trial 匹配，未将其归为 reject。E 校准诊断从 31,826 个记录中排除 6,070 个零 mutation 记录，纳入 25,756 个记录、86 次运行；保留并报告三处跨 episode 后验不连续。主轨迹中有 127/465 条存在分支计数下降，未施加累计最大值修补。

## 完成的核验

- 重新扫描归档与 summary 清单；43 个 summary 文件 SHA-256 与快照一致，628 个归档的存在性、大小和修改时间一致。归档完整 SHA-256 已在提取时保存，本轮最终验证没有重复读取全部压缩包计算哈希。
- 从逐运行台账复算所有组的均值、样本 SD、极值、AUC 和计数；实际解析并比较主表 45 个单元、附录 61 行及各观测表、机制表、成本表。
- 逐点复算全部覆盖轨迹网格、成本散点、动机图端点、后验选例和处置数据。
- 从逐 episode 记录独立重算 Brier、参考 Brier、ECE、AP、十个分箱和每目标 2,000 次整运行 bootstrap 区间；验证表格显示数值与舍入口径。
- 漏洞目录清单与全部 14 个文件哈希通过检查，四个案例的文中批次及证据来源与原文件一致。未重新执行漏洞目标或声称独立确认 CVE/补丁。
- 修复生成脚本中的 LaTeX 行末、下划线及附录状态标签问题。连续生成的四个 TeX 文件字节一致，旧的一次性 patch_main 入口已转为安全的统一表格生成入口；修复前脚本保存在 before_final_consistency_20260929。
- 通过 regenerate_data_update_20260929.py --reuse-figures 实际运行完整构建与验证流程。最终 PDF 为 21 页，25 条参考文献正常解析，无 LaTeX 错误、未定义引用、overfull hbox 或 oversized float。仍有五条普通 underfull hbox 提示，不代表缺页或缺图。

机器结果见 data_update_validation_20260929.json、vulnerability_validation_20260929.json 和 data_update_layout_20260929.json。

## 版面检查

与本轮数据更新前 before_data_update_20260929/main.revised.pdf 直接比较，页数均为 21。全宽大空白条带等效页数由 0.420 降至 0.392，半栏等效页数由 0.678 降至 0.642，分别下降 6.7% 和 5.4%。这是排版代理指标，不是内容质量评分。最后一页参考文献结束后的自然留白保留。未将更早排版修改的约 80% 改善归功于本轮数据更新。

## 仍缺少的证据

两个 gamma 组均无 Forked-daapd 归档；已有但 n<10 的组如下。名义 N=10 不改变这些实际观测数。

| 实验臂与目标 | 实际 n | 距名义 10 次 |
|---|---:|---:|
| E / forked-daapd | 6 | 4 |
| E-gamma099 / kamailio | 5 | 5 |
| E-gamma099 / lightftp | 8 | 2 |
| E-gamma099 / live555 | 3 | 7 |
| E-gamma100 / kamailio | 3 | 7 |
| E-gamma100 / lightftp | 4 | 6 |
| E-gamma100 / lighttpd1 | 6 | 4 |
| E-gamma100 / live555 | 2 | 8 |

此外仍缺少统一构建与资源清单、匹配观察时限的受控比较、provisional/repair 完整生命周期、后代收益关联、固定能量独立代码奖励、拒绝候选 shadow-validation，以及完整 A–E 漏洞重发现对照数据。这些空白未用端点、日志标签或回放批次替代。论文的设计规范与可用证据可以按 first_paper.md 对齐，但不能声称其中要求的全部确认性实验已经完成。

## 复现命令

在本报告所在目录执行：

~~~bash
# 重生成当前证据快照的七幅矢量图、表格和 PDF，并校验
python3 regenerate_data_update_20260929.py

# 保留已生成矢量文件，重生成表格、编译，并逐点验证图中数值
python3 regenerate_data_update_20260929.py --reuse-figures

# 单独执行源数据—论文一致性验证
python3 verify_data_update_20260929.py
python3 verify_vulnerability_evidence_20260929.py
~~~

原始归档的提取程序为 update_experiment_data_20260929.py；随后 prepare_vector_figure_data_20260929.py 生成绘图证据。二者在本次更新中已运行。若数据再次变化，应重新审计并同步正文，不能把这个固定快照的重生成入口当作无人审核的未来论文更新程序。入口会在源清单、summary 哈希或归档大小/时间变化时停止，避免混用新旧数据。

验证环境：Python 3.13.11，NumPy 1.26.4，Matplotlib 3.10.8；系统 latexmk/BibTeX/pdfLaTeX 与 Poppler 工具。
