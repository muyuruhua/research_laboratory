# 三篇文献替换及两篇新增全文核查（2026-09-30）

## 本轮结果

按用户明确指令，保留并核查本地 NSFuzz、WingMuzz 完整原文；移除 SSGFuzz、Zhang 等（2026）和 Brier（1950）三个书目条目，以三篇软工顶会/顶刊论文替代。正文、比较表及参考文献同步修改，实际引用仍为 51 篇。

**本报告中的 PASS 仅指结构、编译和链接检查通过，不表示全部 51 篇出版社正式版全文逐句核查通过。** 新增三篇均已取得公开作者全文，具体版本及限制分别列明。其余文献沿用前轮判断，未伪称本轮重新阅读全文。

## 替换关系与论断调整

| 移除条目 | 替代条目 | 正式出版信息 | 本文的引用用途 |
|---|---|---|---|
| SSGFuzz | Learning-Guided Fuzzing for Testing Stateful SDN Controllers | TOSEM 35(2), 2026, 1–45; DOI 10.1145/3733717 | SeqFuzzSDN 从事件轨迹学习扩展有限状态机并规划控制消息序列；不冒称其采用 state-significance 调度。 |
| Zhang 等（2026） | Boosting Fuzzer Efficiency: An Information Theoretic Perspective | ESEC/FSE 2020, 678–689; DOI 10.1145/3368089.3409748 | Entropic 按信息量估计分配种子能量；不将它称为 Thompson sampling。真正的 T-Scheduler 保留。 |
| Brier（1950） | An Empirical Comparison of Model Validation Techniques for Defect Prediction Models | IEEE TSE 43(1), 2017, 1–18; DOI 10.1109/TSE.2016.2584050 | 引用软工缺陷预测中使用 Brier 分数的先例及平方误差定义，不归属该指标的原创权。 |

选择依据是软工主流顶会/顶刊且有可核验的相关原文，不按年份机械凑数。三篇分别为 2026、2020 和 2017 年，不能统一表述为近年论文。

## 两篇保留文献

- NSFuzz：用户提供的 TOSEM 正式 PDF，26 页。第 9–12 页第 4.2–4.5 节支持基于程序状态变量的识别、注释及跟踪。相关工作现已明确区分 StateAFL 的内存快照与 NSFuzz 的变量跟踪。
- WingMuzz：用户提供的 ASE 2025 正式 PDF，13 页。第 3–5 页第 III 节及 Figure 1 支持两维分别调度开源协议实现（wingmates）和种子。正文已点明两维含义，没有把它写成响应状态调度。

## 新增全文的版本边界

- **seqfuzzsdn2026**：arXiv:2411.08626v2, 5 May 2025; same title and authors, arXiv metadata links DOI 10.1145/3733717; publisher metadata is TOSEM 35(2), 2026, 1--45. Author manuscript has 46 PDF pages and placeholder publication footer; final-typeset-version equivalence is not claimed. 原文位置：PDF [10, 11, 12, 14, 15, 16, 17]，Sections 3.3 (Learning) and 3.4 (Planning)。
- **entropic2020**：Full author-hosted FSE 2020 paper; not independently compared page-by-page against publisher layout. 原文位置：PDF [5, 6, 7]，Section 4, Algorithm 1。
- **validation2017**：Full 21-page author manuscript hosted by the coauthor research group; published article is TSE 43(1), 2017, 1--18. Evidence page numbers refer to author PDF; publisher-layout equivalence is not claimed. 原文位置：PDF [9]，Section 5.6.2, Equation (4)。

出版元数据由 Crossref 的出版社登记记录核对；本地保存 JSON、PDF 和 SHA-256。SeqFuzzSDN 的 arXiv 记录与正式 DOI 对应，但其 2025 年作者稿与 2026 年出版社版未做逐页同一性比对。TSE 作者稿共 21 页，而正式版书目页码为 1–18；不得把作者稿页码写成正式出版页码。

新增三份作者稿也存放在工作区 papers 目录，文件名明确标注 author manuscript；用户原有两份文件未改写。

## first_paper.md 的约束

- 保留 response-derived state 只是代理、独立 code productivity 才是校准目标的主线。
- 保留 execute-before-promote 及 provisional/durable 准入分层；不把 Beta/Thompson 本身当作创新。
- 要求文件举例点名 SSGFuzz；本轮根据用户后续明确指令移除该引文。该操作只改变可引用证据，不意味着否认 state-significance 研究存在，也不建立排他性首创声明。The Bandit’s States、T-Scheduler 和其他既有状态研究保留。
- Brier 分数名称和计算公式完整保留。新引用支持指标在软工中的使用，不代替其历史发明归属。
- 实验结果章节逐字一致；全部 equation 块一致；主要实验输入和要求文件哈希均一致。

## 当前引用句与证据

### C004:nsfuzz — main.revised.tex:137

\section{Related Work and Novelty Boundary}
Stateful greybox fuzzing studies how to expose, infer, and schedule protocol state~\cite{aflnet,stateafl,nsfuzz,sgf_usenix22}.

- 依据：PDF [9, 10, 11, 12]，Sections 4.2--4.5。
- 支持范围：The supplied publisher PDF supports state-variable extraction, optional annotations and instrumented state tracing; current text makes no unverified quantitative claim.
- 来源记录：[nsfuzz](sources/nsfuzz/retrieval.json)

### C027:entropic2020 — main.revised.tex:145

Entropic allocates seed energy using estimated information gain~\cite{entropic2020}.

- 依据：PDF [5, 6, 7]，Section 4, Algorithm 1。
- 支持范围：Entropy-based power scheduling allocates seed energy according to local information estimates. It is not described as Thompson sampling.
- 来源记录：[entropic2020](sources/entropic2020/retrieval.json)

### C028:seqfuzzsdn2026 — main.revised.tex:145

SeqFuzzSDN infers extended finite-state machines and plans control-message sequences for software-defined networking controllers~\cite{seqfuzzsdn2026}.

- 依据：PDF [10, 11, 12, 14, 15, 16, 17]，Sections 3.3 (Learning) and 3.4 (Planning)。
- 支持范围：Learns extended finite-state machines from traces and plans control-message sequences with coverage, accuracy and diversity objectives. Does not establish response-state utility calibration or the absence of prior state-significance work.
- 来源记录：[seqfuzzsdn2026](sources/seqfuzzsdn2026/retrieval.json)

### C031:wingmuzz2025 — main.revised.tex:145

WingMuzz schedules open-source protocol implementations and their seeds to guide blackbox testing~\cite{wingmuzz2025}.

- 依据：PDF [3, 4, 5]，Section III, Figure 1, Sections III.A--III.C。
- 支持范围：The two dimensions are wingmate scheduling and seed scheduling, not protocol-state scheduling; the manuscript now names both explicitly.
- 来源记录：[wingmuzz2025](sources/wingmuzz2025/retrieval.json)

### C040:entropic2020 — main.revised.tex:162

T-Scheduler~\cite{tscheduler2024}; Entropic~\cite{entropic2020} & Posterior- or entropy-based seed scheduling. & Established allocation methods; response-proxy calibration here. \\

- 依据：PDF [5, 6, 7]，Section 4, Algorithm 1。
- 支持范围：Entropy-based power scheduling allocates seed energy according to local information estimates. It is not described as Thompson sampling.
- 来源记录：[entropic2020](sources/entropic2020/retrieval.json)

### C041:seqfuzzsdn2026 — main.revised.tex:163

SeqFuzzSDN~\cite{seqfuzzsdn2026} & Learned state models; message-sequence planning. & Response-proxy productivity; candidate admission. \\

- 依据：PDF [10, 11, 12, 14, 15, 16, 17]，Sections 3.3 (Learning) and 3.4 (Planning)。
- 支持范围：Learns extended finite-state machines from traces and plans control-message sequences with coverage, accuracy and diversity objectives. Does not establish response-state utility calibration or the absence of prior state-significance work.
- 来源记录：[seqfuzzsdn2026](sources/seqfuzzsdn2026/retrieval.json)

### C045:validation2017 — main.revised.tex:546

We assess probabilistic accuracy with the binary Brier score (BS), also used in software defect prediction~\cite{validation2017}:
\begin{equation}
\mathrm{BS}=\frac{1}{n}\sum_{t=1}^{n}(p_t-r_t)^2.

- 依据：PDF [9]，Section 5.6.2, Equation (4)。
- 支持范围：Defines binary Brier score as mean squared probability error in defect prediction. Cited as software-engineering use of an established metric, not as the origin of the Brier score or evidence that defect prediction and fuzzing episodes have identical distributions.
- 来源记录：[validation2017](sources/validation2017/retrieval.json)

另检查比较表中未重复带引文的 NSFuzz 行（main.revised.tex:159），其“内部状态反馈”与第 4.2–4.5 节相容。

## 编译与保留限制

- PDF 23 页；51 个不同文献目的地；59 个文献链接；110 个内部链接；无悬空目的地。
- 摘要 183 词，关键词 5 个。无未定义引用、Overfull 或致命 LaTeX 错误。
- 仍有 7 条非致命 Underfull 提示；四条既有 BibTeX 缺少页码提示保留，未捏造出版页码。
- FuzzGPT、HGFuzzer 仍保留前轮的早期版本差异限制；Cliff 和 Mann–Whitney 的浏览器全文来源限制也未因本轮替换自动解决。
- 三篇被移除的文献不再出现在当前主稿引用与书目中；历史审计原样保留，不改写过去“未取得全文”的事实。

可机读记录：[validation.json](validation.json)、[全部 59 次引文使用](sentence_evidence_matrix.current.json)、[主稿差异](main.revised.tex.diff)、[书目差异](references.expanded.bib.diff)。
