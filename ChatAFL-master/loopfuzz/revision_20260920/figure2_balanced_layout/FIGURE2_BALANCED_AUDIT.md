# Figure 2 均衡布局核验

状态：PASS。本轮只修改 Figure 2 的 TikZ 图形块，图外正文逐字符保持一致。

## 问题与修复

- 原布局在右侧堆叠临时队列与长期队列，左侧 LLM proposal 下方缺少对应模块，造成视觉重心右移。
- 改为两行四列。上排为 LLM proposal、Structural check、Bounded trial、Separate gains；下排为 Reject / expire、Provisional queue、Descendant validation、Durable queue。
- Reject / expire 与 LLM proposal 按列对齐，八个模块等高等宽，四列等距；不使用装饰性或虚构模块填补空白。
- Descendant validation 是原文已有的有限后代验证步骤，本轮将其独立绘制，以明确临时队列的晋升与过期分支。
- 三条失败分支在显式合流点汇合后进入 Reject；预算耗尽回路独立从下方返回。保留精简图注。

## 与 first_paper.md 的对应

- 对照第 181–239 行的两级队列准入要求，以及第 1098–1099 行的 controller architecture 要求。
- 结构检查 P 和有界试验 U/R 在前；之后分别判别代码收益与状态新颖性。
- 代码收益支持 durable 准入；state-only 候选仅进入 provisional。未通过检查或两种收益均无则拒绝。
- provisional 候选经有预算的后代验证，取得合格代码证据后晋升；预算耗尽则过期。
- 图中没有新增实验结论，也没有把状态新颖性直接当作代码收益。该核验限于 Figure 2，不代表对全文研究完成度的重新认证。

## 检查结果

- 17 个模块/标签包围框无重叠；8 个模块同尺寸，两排各自水平对齐，4 列等距且上下同轴。
- 独立矢量画布由 483.946 × 196.354 pt 减至 458.434 × 168.008 pt：高度减少 14.4%，面积减少 18.9%。这是画布尺寸变化，不是语义空白面积估计。
- 最终论文第 5 页与独立预览均检测到 9 个矢量箭头头部；最终 PDF 的 144 dpi 渲染中，9 个箭头均检测到可见深色像素。
- 正文框内字号 9 pt，条件标签 8.5 pt；保持矢量路径和文本，PDF 中无位图对象。
- 论文保持 22 页；未出现 Overfull、未定义引用或重复目标警告。
- 50 条文献均有可点击引用，29 个图表目标有效；Figure 2 的目标位于第 5 页。
- 图外源文本、参考文献 bbl、图注及 first_paper.md 均与本轮修改前保持一致；没有变更实验数据或正文论断。
- 仍有既有第 12、15 页纯浮动体页面提示；具体提示记录于 validation.json，未将其误报为零警告。

## 文件与复核

- 最终稿：../main.revised.tex 和 ../main.revised.pdf。
- 独立矢量预览：[PDF](figure2_after.pdf)、[SVG](figure2_after.svg)。
- 数值核验：[validation.json](validation.json)；修改前备份：before/。
- 在修订目录执行 python3 figure2_balanced_layout/verify_figure2_balanced.py 可重新核验。
