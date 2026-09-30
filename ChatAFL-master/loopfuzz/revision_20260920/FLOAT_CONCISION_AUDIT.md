# 图表文字精简核验

状态：PASS。范围：9 幅图、20 张表（含附录）。

- 图注/表注：1173 → 217 词，减少 81.5%。
- 表格单元格：2328 → 2096 词，减少 10.0%；数值单元格不变。
- 105 处显式文字单元格精简；日志字段表改为三列，七类事件及公共字段完整保留。
- 598 个数值或缺失值单元格逐项保持；公式、算法、引用、图形引用与尺寸不变。
- 原始证据核对：628 个归档的清单/大小/时间戳、43 个汇总文件哈希、14 个漏洞文件哈希全部通过；既有归档哈希保留。
- 独立数值、结构和构建校验：299,219 项。图中 2,000 次整运行 bootstrap 已重新计算。
- 摘要 181 词、关键词 5 个，摘要和正文缩写作用域校验通过。
- PDF：21 页，25 条参考文献，无未定义引用、越界盒子或位图嵌入。

## 与 first_paper.md 的一致性

- 保留独立的 code/IPSM 证据、provisional/durable 层次及观测前预测。
- 保留同策略/资源上限要求，实际调用量、样本数、单位和误差定义不变。
- 设计要求与已验证实现、日志标签与队列成员资格分别表述。
- 漏洞 L/R 证据类别、批次分母、未合并批次及未完成的受控 A–E 结果保持明确。
- 数据缺口维持空白；本轮未执行新实验，不将计划写成已证实结论。

## 版面检查

- 检查全部页面，并放大核对日志字段表、漏洞清单与回放结果表。
- 正文无新增整页或半页空白；末页仅为参考文献的自然余量。精简后末页留白增加，未通过缩小字号或强制拉伸填满。

## 实际数据路径

原记录路径已不存在，实验资料位于工作区根目录 Key_Experiment。校验时显式传入 --source-root，所有既有内容校验仍启用；未改写原始实验文件。

## 每项对照

| 图表标签 | 图/表注原词数 | 精简后 |
|---|---:|---:|
| fig:mismatch | 65 | 8 |
| fig:architecture | 25 | 7 |
| fig:posterior | 16 | 9 |
| fig:reliability | 114 | 9 |
| fig:trajectories | 112 | 7 |
| fig:posterior_cases | 96 | 10 |
| fig:dispositions | 77 | 10 |
| fig:cost | 97 | 10 |
| fig:callcost | 48 | 11 |
| tab:boundary | 8 | 5 |
| tab:novelty | 11 | 5 |
| tab:predicates | 8 | 5 |
| tab:implementation | 25 | 5 |
| tab:events | 28 | 5 |
| tab:arms | 18 | 5 |
| tab:targets | 13 | 5 |
| tab:llm | 19 | 6 |
| tab:mainresults | 54 | 8 |
| tab:mechanisms | 44 | 8 |
| tab:repair | 13 | 7 |
| tab:cve | 40 | 9 |
| tab:cveresults | 38 | 9 |
| tab:threats | 7 | 7 |
| tab:observed_inventory | 34 | 8 |
| tab:observed_endpoints | 28 | 8 |
| tab:observed_log_counts | 20 | 10 |
| tab:observed_costs | 23 | 7 |
| tab:logged_calibration | 59 | 7 |
| tab:archive_arms | 33 | 7 |

计数口径：移除 TeX 命令名、将引用替换为 REF 后按空白分词；保留数值和数学记号。

详细逐项检查见 float_concision_validation.json。原稿及相关生成脚本保存在 before_float_concision/。

## 2026-09-30：当前全部图表再次精简

已对当前 20 张表、9 幅图执行新一轮逐项精简并编译验证。详见 [本轮核查记录](float_concision_20260930/AUDIT.md) 与 [逐项结果](float_concision_20260930/validation.json)。历史记录保留。
