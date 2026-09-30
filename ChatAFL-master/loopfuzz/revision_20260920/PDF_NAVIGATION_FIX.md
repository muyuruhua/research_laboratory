# PDF 引用点击修复

## 复现与修复

在用户当前的 VS Code / LaTeX Workshop PDF 预览实例中，单击正文文献编号后未出现定位跳转。
此前对 PDF 命名目标和链接字典的结构检查通过，但该检查不足以证明当前预览器能够响应鼠标点击。

本次仅在工作区设置中，为这份论文指定已安装的 PDF Preview 预览器（pdf.preview），并关闭、重新打开了当前 PDF。其他工作区设置逐项保持不变。

论文源文件和 PDF 文件均未再次改写；其 SHA-256 与前次链接修改后的文件一致。研究内容、数据、公式、文献条目及 first_paper.md 的研究边界保持原状。

## 实际点击验证

使用本机安装的 PDF Preview 1.2.2 全套预览资源，在独立浏览器窗口中打开同一 PDF；发送真实鼠标按下/释放事件，确认点击区域为链接元素，并检查跳转后的页码及滚动位置。

| 引用 | 来源页 | 实际目标 | 结果 |
| --- | --- | --- | --- |
| 文献 [1] | 1 | 第 20 页对应文献条目 | PASS |
| Figure 4 | 10 | 第 12 页图形起始位置 | PASS |
| Table 12 | 11 | 第 11 页表格位置；同页滚动位置发生改变 | PASS |

详细点击结果、来源页、目标页、前后滚动位置及 PDF 哈希见 pdf_viewer_click_validation.json。

## 设置范围与恢复

- 仅对 **/research_laboratory/ChatAFL-master/loopfuzz/revision_20260920/main.revised.pdf 生效。
- 其他 PDF 的默认预览器未改变。
- 修改文件：工作区 .vscode/settings.json。
- 原设置备份：.vscode/settings.before_pdf_navigation.json。
- 如需恢复，只删除本次增加的文件专用 workbench.editorAssociations 条目即可。

此修复针对已复现的预览器交互问题；未修改扩展安装文件，也未把问题归因于未经验证的特定插件版本缺陷。
