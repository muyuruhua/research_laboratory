# 排版与参考文献修订审计（2026-09-28）

审计对象为 `main.revised.tex` 及重新编译的 `main.revised.pdf`。本次使用 research-writing-skill、scientific-toolkit-skill，并按引用管理、科学可视化和 PDF 检查规范核对。原稿、原 PDF 和原验证脚本保存在 `before_layout_20260928/`；原始实验档案和旧版图形保留。

最终 PDF 为 **24 页**，修订前为 **26 页**。包含 **9 幅图、正文 19 张表及附录表 A.1、25 条实际引用文献**。参考文献从第 24 页开始。优化以可读性、图文位置和证据完整性为准，没有通过删掉数据或虚构缺失项压缩篇幅。

## 发现的问题与处理

| 修订前的问题 | 证据与影响 | 已实施的修正 |
|---|---|---|
| 浮动体屏障造成空疏页 | 原第 11 页仅约 88 个提取单词；连续大表阻塞正文流动 | 撤去结果清单后的局部强制屏障，调整顶端浮动比例和间距；结果章节结束后集中排完图表，避免进入后续章节；恢复后续页的完整栏高 |
| 图表页垂直居中、图文距离较远 | 大尺寸多面板图及多张宽表积压 | 浮动页从顶部排布；缩减图中冗余空间；显式划分结果图表与历史漏洞章节的边界 |
| 完整实验台账字号过小 | 原 60 行台账采用 scriptsize 加整体缩放，PDF 提取字号约 6pt | 移至单栏附录，用不缩放的 9pt longtable，重复表头、续页提示；每行实际 n 只显示一次；采用明示状态代码 |
| 图内标签过小 | 原 reliability 计数标签约 5pt，部分说明文字不足 7pt | 提高标签字号；扩大计数条空间、统一子图标题位置；重新导出 PDF/SVG |
| 主结果表各目标之间拥挤 | 每个目标单元格含均值/SD、AUC、n 三行 | 在目标行之间增加留白；机制表改进列宽及左列断行，保证缺失值仍为空 |
| 正文与数学字体不统一 | lmodern 覆盖了 elsarticle 的 Times 正文字体，而数学仍采用 Times 系列 | 正文与数学使用模板的 Times 系列；等宽文字单独使用矢量 LMMono，避免位图字体回退 |
| 表题或编号不够准确 | 库存表题曾写 A/B/D，实际列为 A/D；附录表号不应沿用正文计数 | 更正表题，附录编号为 A.1，正文交叉引用随编译更新 |
| 文献缺口和题录错误 | 原有 12 条已渲染文献，但数篇关键相关工作仅写名称；统计方法缺正文引证；StateAFL 期号、Böhme 变音符号有误 | 文献扩展至 25 条并全部插入实际正文或比较表；修正题录和作者字符；核对正文引用、BibTeX、BBL 与 PDF |
| 单次编译容易漏更新参考文献 | 原编辑器指令指向 pdflatex，不能单独完成 BibTeX 全流程 | 明示 latexmk，保留从父目录运行的 build_revised.sh，以使用正确的 elsarticle 类和路径 |

## 引用的补全范围及准确性边界

原稿的参考文献**不是完全消失**：备份 PDF 的第 25–26 页已有 12 条。本次补入 13 条，其中 3 篇是此前缺失且现已核实的相关工作，1 篇是已核实的 Thompson sampling 种子调度研究，9 篇用于正文实际采用或预先规定的统计方法。

| 用途 | 正式来源 |
|---|---|
| 状态选择的 bandit 先行工作 | Borcherding 等，The Bandit's States，EuroS&PW 2023，345–350，DOI: 10.1109/EuroSPW59978.2023.00043 |
| 可核实的 Thompson sampling 种子调度研究 | Zhang 等，A novel seed scheduling scheme using Thompson sampling for coverage-guided greybox fuzzing，Journal of Systems and Software 236 (2026), 112794，DOI: 10.1016/j.jss.2026.112794 |
| SSGFuzz | Jian 等，State Significance-Guided Fuzzing for Stateful Protocol Program，Theoretical Aspects of Software Engineering，361–379，DOI: 10.1007/978-3-031-98208-8_21 |
| reached/triggered 的基准参照 | Hazimeh 等，Magma: A Ground-Truth Fuzzing Benchmark，POMACS 4(3), 2020，DOI: 10.1145/3428334 |
| Thompson sampling、Brier、ECE | Thompson 1933；Brier 1950；Guo 等 2017（PMLR 70） |
| Precision–Recall 诊断、bootstrap | Davis 与 Goadrich 2006；Efron 1979 |
| Mann–Whitney U、Cliff's delta、BH、Kaplan–Meier | Mann 与 Whitney 1947；Cliff 1993；Benjamini 与 Hochberg 1995；Kaplan 与 Meier 1958 |

**T-Scheduler 名称仍未核实。** 原提纲只给出工具名，未给作者、论文题名或链接。经过出版社和公开索引查询，无法可靠认定它对应哪篇正式论文。正文已改为引用确实存在的 Zhang 等（2026）Thompson sampling 种子调度论文，保留“此类调度是已有工作”的论证；不将这篇论文认定为 T-Scheduler，也不附会其 Beta 参数实现。若要恢复该工具名，仍需能确认身份的原始出处。这是文献身份边界，不是编译漏引。

**SSGFuzz 年份存在来源差异。** Springer 官方 BibTeX 导出和推荐引用写 2026；页面与 Crossref 的首次上线时间为 2025-07-09。本版依出版社推荐引用写 2026，原始导出保存在 `reference_audit_20260928/ssgfuzz_export.bib`。正文没有作年份优先权断言。

ChatAFL 的 1–17 页已从 NDSS 官方 PDF 核实；StateAFL 期号由 8 更正为 7；NSFuzz 采用可验证的 1–26 页范围。Efron 1979 的已取得元数据未提供页码，因此省略该字段。22 个 DOI 唯一；另 3 条使用正式 USENIX/PMLR 来源，不编造 DOI。完整逐条来源、保存文件及哈希见 `reference_audit_20260928/citation_provenance.json`。

## 检查结果与仍需保留的边界

- `verify_filled_data.py`：517 个档案、60 个 target–arm 分组通过核验；主结果表仍为 44 个有数据单元格、1 个缺失单元格。
- `verify_vector_figures_20260928.py`：469 个主实验档案、375 个成本观测和 23,113 个正执行数 E episode 的图形核验通过。
- `verify_layout_references_20260928.py`：附录 60 行的实际 n、均值、SD、状态计数逐项一致；10 个图形数值/审计文件与此前版本逐字节一致；25 个引用键全部进入 BBL；PDF 确实包含 9 个图题和 20 个表题。
- PDF/SVG 无嵌入栅格图像；最终 PDF 无 Type 3 字体；正文 Times 与等宽 LMMono 均为矢量字体。
- 最终 LaTeX/BibTeX：0 编译错误、0 未定义引用、0 越界盒、0 超大浮动体、0 BibTeX 警告。仍有 6 条 Underfull 段落松排提示，属于少数双栏文本的词间距问题；没有通过屏蔽警告掩盖它们。
- 已检查整篇页面缩略图，并放大复核主要结果表、reliability 图、章节边界、附录续页与文献页。独立图页、结果节末及附录续页仍存在自然留白；不会为填满页面而缩小字号或填补无数据区域。

本次排版和引文修改不改变 N=10 的名义目标、实际观测 n、缺失留空、D 等同 benchmark LoopFuzz 且只计一次的规则。CVE/CPU-hours/provisional lifecycle 等证据缺口仍保留；新增方法引用不表示对应实验已经完成。归档数据中 Lighttpd1 某 D run 的轨迹终值 2115 与摘要终值 2139 的既有冲突也保留说明。作者贡献、利益冲突、资金和数据发布声明仍需作者确认，排版修复不代表论文已具备全部投稿证据。

## 文件与重建

- 正文：`main.revised.tex`
- 阅读版本：`main.revised.pdf`
- 本版独立文献库：`references.verified_20260928.bib`
- 矢量图与数值导出：`figures_layout_20260928/`
- 附录源码：`archive_arm_results.layout_20260928.tex`
- 结果审计：`layout_reference_validation_20260928.json`
- 图形生成：`plot_layout_figures_20260928.py`

在当前修订目录运行：

```bash
bash build_revised.sh
python3 verify_filled_data.py
python3 verify_vector_figures_20260928.py
python3 verify_layout_references_20260928.py
```

需要重新生成图形时先运行 `python3 plot_layout_figures_20260928.py`，随后编译。原始 `.bib` 与旧版图形没有被覆盖。本报告记录的是本次修订后的状态；更早的 DATA_FILL_REPORT、FIGURE_COMPLETION_REPORT、REVISION_REPORT 为历史阶段记录。
