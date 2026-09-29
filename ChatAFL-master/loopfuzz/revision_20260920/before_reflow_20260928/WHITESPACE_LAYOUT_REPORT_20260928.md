# 论文排版与大片空白专项审计（2026-09-28）

对象：`main.revised.tex` 及其重新编译的 `main.revised.pdf`。本轮依照 research-writing-skill、scientific-toolkit-skill 和 PDF 检查规范，针对页面空白、浮动体拥塞、图表分页和附录分页进行了二次优化。当前 PDF 为 **21 页**；对比本轮修订前的 24 页，减少为 21 页。

## 已确认的大片空白来源

- 结果章节中连续的 `figure*`/`table*` 浮动体在双栏模式下积压，导致正文先结束、浮动体再单独成页；第 13 页右栏和第 17–18 页图下出现大段空白。
- 成本图原尺寸过高，两幅图各自占据独立页面，造成图题和后续正文之间的大面积空白。
- 60 行完整台账以普通 `longtable` 排版时，最后一页只剩少数续行，附录续页利用率很低。
- 正文和附录之间的栏切换、浮动体清空以及双栏栏高恢复不协调，曾使后续章节首页出现不必要的空栏。
- 这不是实验数据缺失造成的“空图”：空白区域主要是 TeX 浮动体放置和分页约束产生的版式空白。真正缺失的数据仍以空单元格保留。

以下页码指本轮备份的 24 页 PDF；测量不含页边距和页脚：

| 原页面 | 主要空白 | 连续空白高度 |
|---|---|---:|
| 第 11 页 | reliability 图下方 | 169pt，约 60mm |
| 第 13 页 | 右栏提前结束 | 439pt，约 155mm |
| 第 17 页 | token-cost 图下方 | 257pt，约 91mm |
| 第 18 页 | call-cost 图下方 | 271pt，约 96mm |
| 第 23 页 | 台账续表后 | 394pt，约 139mm |

## 已实施的优化

- 将成本图改为更紧凑的 3×3 矢量图布局，使 token-cost 和 call-cost 两幅图在同一页展示；图例、坐标轴、样本数和标题仍保留。
- 将完整台账改为横向附录中的左右双分栏表，同一页容纳全部 60 行；不使用 `resizebox`，保留约 9pt 表格字号、列标题、状态码说明和所有实际观测 n。
- 调整双栏浮动比例、图表间距和浮动页顶部对齐；移除结果节末尾强制 `\twocolumn` 分页及其栏高补丁，使后续正文可填充图表下方空间；仅保留横向附录所需的栏切换。
- 保留 9 幅图和所有正文表格，不通过删除图表、缩小到不可读字号或填入虚构数据来消除空白。
- 图形生成脚本另存为 `plot_compact_figures_20260928.py`，输出目录为 `figures_compact_20260928/`；旧版图形目录和原稿均保留。

## 量化结果

留白测量采用 72 dpi 检查栅格，仅用于版式测量：正文区域中连续至少 28pt、且每行少于 3 个深色像素的区域被计为空白带；页边距和页脚排除。该指标不是语义质量分数。

| 指标 | 优化前 | 优化后 | 变化 |
|---|---:|---:|---:|
| 页数 | 24 | 21 | −3 页 |
| 整页宽度空白等效页数 | 2.40 | 0.61 | 减少 74.4% |
| 双栏分别计算的空白等效页数 | 3.30 | 0.96 | 减少 71.0% |

优化后第 19 页双栏声明平衡结束，下方仍留约 189pt（约 67mm）自然空白，随后为必须独立旋转的横向附录。历史漏洞模板中的空单元格是未验证数据，必须保留。连续排版也意味着部分结果图出现在后续小节文字之间，图表编号与引用顺序保持一致；本轮优先解决大片版式留白，不声称每幅图均与首次引用同页。仍有 6 条 Underfull 段落松排提示，无越界。

## 完整性验证

- `verify_filled_data.py`：517 个档案、60 个 target–arm 分组通过；主结果表 44 个有数据单元格、1 个缺失单元格。
- `verify_vector_figures_20260928.py`：469 个主实验档案、375 个成本观测、23,113 个 E 正执行 episode 通过；PDF/SVG 无嵌入栅格图像。
- `verify_layout_references_20260928.py`：附录 60 行的实际 n、均值、SD、状态计数逐项一致；25 条文献全部解析；22 个 DOI 唯一；无未定义引用、BibTeX 警告、越界盒或超大浮动体。
- 论文仍严格保留 N=10 的名义目标、实际观测 n、缺失留空，以及 D 等同 benchmark LoopFuzz 且只计一次的规则。任何 CVE、CPU-hours 或 provisional lifecycle 的未验证结果没有被填充。

## 当前文件

- 正文：[main.revised.tex](main.revised.tex)
- PDF：[main.revised.pdf](main.revised.pdf)
- 紧凑矢量图：[figures_compact_20260928/](figures_compact_20260928/)
- 横向附录源码：[archive_arm_results.compact_20260928.tex](archive_arm_results.compact_20260928.tex)
- 空白测量：[whitespace_checks_20260928/whitespace_metrics.json](whitespace_checks_20260928/whitespace_metrics.json)
- 完整验证：[layout_reference_validation_20260928.json](layout_reference_validation_20260928.json)

原版本已备份于 `before_whitespace_20260928/`。构建工具为 TeX Live 2019 / pdfTeX 1.40.20、BibTeX 0.99d、latexmk 4.67。参考文献身份限制（T-Scheduler 尚未核实）与实验缺失证据说明沿用前一轮审计，没有因本轮排版而改变。

重建命令：

```bash
bash build_revised.sh
python3 verify_filled_data.py
python3 verify_vector_figures_20260928.py
python3 verify_layout_references_20260928.py
python3 audit_whitespace_20260928.py
```
