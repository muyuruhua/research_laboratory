# 本轮引用核验状态

## 可编译引用

新稿保留并使用原 `references.bib` 中12个与当前论证直接相关的条目。此处只确认条目存在、key可解析及本轮引用位置与论证相关，不声称已重新逐篇核验全部原有文献元数据。

## 四项明确缺口

| 要求文件中的名称 | 本轮采用方式 | 尚缺证据 |
|---|---|---|
| The Bandit's States | Related Work和novelty表列出，正文脚注明确待核验 | 完整标题、作者、年份、venue、DOI或正式页面 |
| T-Scheduler | 同上；不将Thompson scheduling当本研究原创 | 同上 |
| SSGFuzz | 同上；不将state significance当本研究原创 | 同上 |
| Magma | Historical rediscovery论证中讨论reached/triggered方法 | 正式论文元数据及主张对应位置 |

`references_calibration.bib`目前仅包含说明注释，没有伪造条目，也没有生成悬空的citation key。待核验脚注在PDF中可见，属于投稿前需补全的明确问题。

## 查询记录

- 使用paper-lookup的Crossref路线，只查询公开论文标题，不发送稿件或实验内容。
- 查询endpoint：`https://api.crossref.org/works?query.title=The%20Bandit%E2%80%99s%20States&rows=3`。
- 沙箱请求失败：`curl (6) Could not resolve host`。
- 其后的提权查询未获得返回数据，工具最终报告`aborted by user`；没有成功JSON响应，也没有有效元数据可引用。
- 本地检索找到 `C_two_papers/two/references.bib` 的Magma条目，但其作者/venue组合未经核验，未复制。另一个本地Magma artifact README确认了项目标题与homepage链接，不能替代正式论文元数据。

原有参考文献完整性审计文件属于旧稿；不要把它当作本轮四项缺口已经核验的证据。
