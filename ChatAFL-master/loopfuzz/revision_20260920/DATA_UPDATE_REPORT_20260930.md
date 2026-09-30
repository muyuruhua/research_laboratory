# 实验数据更新报告（2026-09-30）

## 数据来源与纳入规则

- 原始来源：`/home/ckt/Documents/000_2026_test_dev/Key_Experiment`。
- 纳入 `benchmark`、`ablation/direct`、`ablation/calibrated`、`ablation/cal_gamma099` 和 `ablation/cal_gamma100` 中有对应 `run_summary.csv` 台账的归档。
- `ablation/gated_fixed` 与 benchmark 的 LoopFuzz D 条件重复，本次仍排除，避免重复计数。
- nominal $N=10$ 保留为设计目标；实际样本数 $n$ 逐组记录。缺失组合保留空白，不以零填充，也不补造运行。

## 更新结果

- 选入 642 条归档，形成 63 个 target--arm 聚合组；核心 A--E 图表使用 470 条记录。
- A/B/C/D/E 分别为 94/91/90/104/91 条；$\gamma=0.99$ 和 $\gamma=1.0$ 敏感性组分别为 81/91 条。
- E 臂可靠性诊断包含 32,946 个已记录 episode；排除 6,562 个零 mutation episode 后，保留 26,384 个 episode，覆盖 91 次运行。
- 成本图更新为 376 个 B--E 观测。附录当前归档表为 63 行。
- 同步更新摘要、结果段落、主结果表、机制表、附录表、成本表、覆盖轨迹、后验状态图、可靠性图和候选处置图。
- 可靠性图改为 0.90	extwidth，消除了新数据分页后产生的两个 13.4pt vbox 溢出；最终 PDF 无 Overfull、未定义引用或重复目标警告。

## 验证结果

`data_update_validation_20260930.json`：PASS。

- 所有当前 summary 哈希、642 个归档的大小/mtime 与运行台账一致。
- 所有经验表、轨迹 CSV、成本 CSV、端点图和 episode 诊断重新计算一致。
- 7 幅实验图均为 PDF/SVG 矢量文件；最终论文无位图对象。
- 最终 PDF 为 22 页，50 条参考文献解析有效。
- `verify_reference_links_data_20260930.py` 检测到 103 个有效内部链接、50 个可跳转文献目标和 29 个图表目标。

## 证据边界

本次是对已有归档的重建和稿件同步，没有执行新实验或漏洞回放。没有可核验的运行仍保持空白；归档终点不构成匹配时长的因果比较，漏洞案例也未因本次数据更新而增加新的重复试验。
