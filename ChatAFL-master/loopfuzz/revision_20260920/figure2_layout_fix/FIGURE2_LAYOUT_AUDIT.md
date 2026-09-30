# Figure 2 布局修复核验

状态：PASS。修改 Figure 2 的布局、节点和箭头标签，并在对应方法段落补充一处可点击引用。

## 原因

- 原主流程框间净距仅 1.75 mm，箭头缺少可辨识的线段；拒绝、过期路径共享部分路线，使方向不清。
## 修改

- 主流程净距增至约 9.79 mm；箭头采用明确的 Latex 箭头头部和 0.85 pt 深色线条。
- 通过与失败分别用实线、虚线表达；拒绝与过期分离布线，晋升路径独立向上。
- 临时队列标为 bounded validation；只有 validated code gain 才指向 durable queue。
- 保持原图注、编号与正文逻辑；未增加图注篇幅。

## 研究要求

- 先完成 P 与 U/R 检查；独立区分代码收益与状态新颖性。
- 代码收益支持 durable 准入；状态新颖性仅支持 provisional 准入；缺少两种收益则拒绝。
- provisional 必须通过有限验证获得代码证据才能晋升；预算耗尽后过期。该流程不把回放等同于受控再发现，也不新增实验结论。

## 验证

- 在最终论文第 5 页直接检测到 10 个矢量箭头头部；144 dpi 实际 PDF 渲染中 10 个均有可见深色像素。
- 7 个模块和 9 个箭头标签无包围框重叠；主文字 9 pt、条件标签 8.5 pt；已查看独立图的实际渲染。
- 论文仍为 22 页，无溢出和未定义引用；50 条文献及 29 个图表跳转目标保持有效。
- 图外仅增加一处 Figure 2 可点击引用，其他源文本逐字符一致；参考文献 bbl 逐字节一致，图仍为纯矢量。
- 既有纯浮动图表页提示保留在 validation.json 中，不是本图溢出。

## 文件

- 最终稿：../main.revised.tex 和 ../main.revised.pdf。
- 独立矢量预览：[PDF](figure2_after.pdf)、[SVG](figure2_after.svg)。
- 核验记录：[validation.json](validation.json)；原稿备份：before/。
- 复核：在修订目录执行 python3 figure2_layout_fix/verify_figure2_layout.py。
