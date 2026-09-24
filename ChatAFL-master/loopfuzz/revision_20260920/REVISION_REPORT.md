# 全文修订交付说明

本轮依据 `C_two_papers/first_paper.md`，直接重写 `loopfuzz/main.tex`；保留原稿的英文论文语言、作者信息与 Elsevier 模板，目标期刊改为 **Journal of Network and Computer Applications**。用户指定的两项技能用于控制学术表述与数据处理：既有数据、设计要求、当前实现和待完成实验分别陈述，不虚构结果。

## 交付文件

- `../main.tex`：修订后的主稿；章节、公式、算法、实验设计与结论均已重写。
- `main.revised.pdf`：本轮编译预览。上一级原有 `main.pdf` 未覆盖，不是本轮预览。
- `main.before.tex`、`main.before.pdf`：修改前备份。
- `first_paper.snapshot.md`：本轮要求快照。
- `observed_tables.tex`：全部已提供运行的清单、原始终点和事件记录表。
- `observed_costs.tex`：已记录调用量与 token 范围。
- `native_endpoints.pdf/.svg/.png`：三个动机目标的真实终点对照，均值±样本标准差。
- `audit_experiments.py`、`experiment_audit.json`、`experiment_audit_notes.md`：可复算的数据审计与来源校验。
- `plot_native_endpoints.py`：绘图脚本。
- `implementation_audit.md`：实现与设计契约的逐项差异及源码位置。
- `../references_calibration.bib`、`CITATION_STATUS.md`：四项直接相关文献的明确待核验记录；补充bib暂只含说明，不伪造条目。原 `references.bib` 保留。

## 对 first_paper.md 的逐项落实

| 原要求 | 主稿中的落实 | 证据状态 |
|---|---|---|
| 开篇、第一节：新研究定位和 JNCA | 新标题、期刊字段、摘要、Introduction、Conclusion；主线为响应状态代理的生产率和长期队列资源分配。 | 已完成文本修改；不声称首次发现状态代理失真。 |
| 第二节：仅三项贡献 | evidence-gated admission、online productivity calibration、controlled empirical framework。 | 第三项明确是部分证据与评估框架，未冒充完整因果验证。 |
| 第三节：符号和信号分离 | U 仅表示响应可接受性；效用使用 theta；G_code 与 G_state 独立定义；区分 IPSM state edges、code edges、source branches、bitmap slots/save events。 | 已完成全文术语和公式重构。 |
| 第四节：两级队列 | 三种 disposition、严格条件、初始64次后代/30秒/64 live entries、晋升/过期/删失与 lineage。 | 设计明确；当前实现不能严格保证之处另表披露。 |
| 第五节：在线校准 | 固定预算 episode、独立 code reward、Beta(1,1)、discounted update、gamma=.995及三点敏感性、epsilon=.1、Thompson加权选择。 | 初始协议值不是已完成参数冻结；D/E保留共同基础调度项。 |
| 第六节：三类动机目标 | Forked-daapd、Lighttpd1、LightFTP 假设表、真实终点图和新的RQ1解释。 | 本批Forked结果不支持旧稿分支下降；三种机制不强行宣布全部复现。 |
| 第七节：五臂矩阵 | A AFLNet；B Controlled ChatAFL；C direct；D gated-fixed；E gated-calibrated。 | D−C、E−D作为明确对照；B保留原调度谱系。缺失臂留空。 |
| 第八节：repair降级 | C/D/E主实验关闭repair；单独诊断表及完整事件要求。 | 无独立效果结论，不再作为第四贡献。 |
| 第九节：LLM公平性和replay | equal-policy/equal-cap、实际usage、cost-matched敏感性、配置表、快照候选配对。 | 不声称自适应campaign实际调用/输出完全相同；replay不等价在线campaign。 |
| 第十节：事件日志 | 六类核心流加可选repair流，完整join字段、pre-update prediction、schema和验收标准。 | 现有文件存在≠日志完整≠设计实现；99.32%只是观测join比例。 |
| 第十一节：指标 | 固定后代horizon、排除admission本身gain、删失上下界、C/D污染对照、shadow validation、Brier/ECE/AUPRC。 | 修正不完整负例被剔除造成的生产率偏差。缺少机制结果不填0。 |
| 第十二节：历史漏洞 | 专节Historical Vulnerability Rediscovery；base+minimal patch、信息控制、reached/triggered、oracle、六到十二pair计划、隔离和KM。 | 不编造CVE、patch、oracle或成功次数；所有结果格留空。 |
| 第十三节：RQ1–5 | 状态/代码一致性、admission、calibration、historical rediscovery、成本与边界。 | 协议先于结果；不倒签preregistration。 |
| 第十四节：样本与统计 | 5臂×10×24h，核心补至20；intention-to-run、host block、随机种子、CI/MWU/Cliff/BH、hierarchical bootstrap。 | 所需规模为计划；本批181归档全部保留，不选择仅完成run。 |
| 第十五节：图表 | 八类图位置：真实动机终点图、controller、posterior、五臂轨迹、reliability、disposition、KM、cost；十二类要求表均已覆盖。 | 有真实数据的表/图已填；未完成实验图空白，不绘模拟线。 |
| 第十六节：逐节重写 | Abstract至Conclusion整体替换旧集成系统叙述；保留必要声明。 | 不沿用旧胜出目标数、旧显著性、crash数量或外部不可比排名。 |
| 第十七节及后续：冻结、pilot、停止规则 | 备份、日志验收、四目标pilot、CVE pilot、参数/数据冻结、降级与停止规则、最低证据条件。 | 本次仅修改论文和分析交付物；未启动长实验、修fuzzer、建新算法或声称达到投稿条件。 |

## 要求冲突的处理

1. 以明确指定的JNCA为准，不因文档中零散TOSEM/Computers & Security文字自动改投。
2. 保持D/E准入完全一致；校准通过状态选择改变候选/后续探索机会，不增加E独有的准入阈值。
3. 严格相同LLM output限定于同snapshot候选诊断；自适应主实验匹配策略和预算上限。
4. “六类事件”按六核心+可选repair解释，不遗漏bug_event。
5. 十周、10–14天等相互冲突的管理时限不写成已完成事实；论文只列可检验协议和完成条件。

## 需要保留的关键事实边界

- 91个AFLNet和90个LoopFuzz归档不等于完整A–E实验；LoopFuzz观测时长410–1522分钟，不能把最后一行当共同24h终点。
- 1,610个candidate、1,599个trial、17个durable标签不证明严格准入已成功；当前源码存在native save先于完整gate的路径。
- 未提供provisional/repair生命周期证据；转换率、过期率、repair效果留空。
- 当前source的bitmap/事件计数不能直接当source-level code branches；源码与归档二进制一致性亦未独立证明。
- 全部运行最后保存的调用/token计数不是独立billing；64不是全API硬上限。
- 校准、历史CVE配对和因果对照未完成，不能作为已证明收益。作者声明、经费和公开artifact地址仍需作者核实。
- The Bandit's States、T-Scheduler、SSGFuzz、Magma的正式书目信息未取得有效外部核验，正文脚注明确待补；没有猜作者、年份或DOI。

## 复算与编译

从 `research_laboratory/ChatAFL-master` 运行：

```bash
python3 loopfuzz/revision_20260920/audit_experiments.py
python3 loopfuzz/revision_20260920/plot_native_endpoints.py
```

从 `loopfuzz` 目录生成本轮预览（保留根目录旧PDF）：

```bash
latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=revision_20260920 -jobname=main.revised main.tex
```

移交或上传Overleaf时必须同时保留主稿引用的 `revision_20260920/observed_tables.tex`、`observed_costs.tex`、`native_endpoints.pdf`、两份 `.bib` 和 Elsevier 模板文件；不能只复制main.tex。

## 最终验证

- 最终修订预览为 **17页**，由上述latexmk命令成功生成；LaTeX/BibTeX日志无错误、未定义引用或Overfull越界。少量Underfull段落提示不影响编译。
- 已检查实测终点图及页面布局；待完成结果图保留空框，待填表格使用空单元格。文末浮动表已限制在参考文献之前。
- 已复核报告列出的交付文件及主稿使用的相对路径，文件均存在。原始实验归档和fuzzer源码未修改。
- 分析环境为Python 3.13.11、Matplotlib 3.10.8；排版环境为pdfTeX 1.40.20（TeX Live 2019）、latexmk 4.67。
- 原稿备份SHA-256为 `f88b18e96ec7f8205862d49767f6f9df559eb68223ed27dd7b1a9897056eabb9`，要求快照为 `ca3d8b7ce23bcf2462fc9c85e40352b671eafa8986e0053edbc1e21deab4063b`；交付前校验一致。
- 本轮全文修订已完成，但不代表实验完成或达到投稿条件。仍需补齐对照实验、机制与历史漏洞证据，并核验上述四项文献及作者声明。
