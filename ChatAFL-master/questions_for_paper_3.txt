以下是领域专家针对【/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/loopfuzz/main_compare.tex】内容给出的最严谨专业的修改建议，必须严谨结合修改建议进行修改，摘要内容保持精简，不要出现啰嗦的废话，要求修改后main_compare.tex编译成main_compare.pdf后不超过22页，若内容已改正了或者没有问题的话直接跳过：


一、论文中逻辑链相关的问题

1：核心贡献 P/U/R/G 无法被因果验证——最严重的逻辑断裂

位置： Section 4.2, Table 2, Abstract（"corrected improvements on eight targets"）, Section 5.3

问题：论文将 A(x)=P(x)∧U(x)∧R(x)∧G(x)作为核心设计主张，但实验中明确承认"archive lacks a LoopFuzz-no-admission arm"（5.3）且"candidate-level admission logs are absent"（Table 11）。这导致核心逻辑链断裂：观察到的 coverage/IPSM 提升，无法归因于 admission gate，还是 LLM plateau budget 增加（4096 vs 2048 token），还是 temperature schedule 差异，还是 IPSM scheduling 变化。论文自己在 Abstract 和 Section 5.3 都承认这一点，但仍在 Abstract 中写"corrected improvements"——这两句话之间存在直接矛盾。

修改建议：考虑增加 LoopFuzz-no-admission 变体作为 ablation baseline：保持相同 LLM endpoint，相同 plateau 预算（64 calls），相同 IPSM scheduling，相同 token budget（4096），仅跳过 P/U/R/G 检查直接入队。此实验代价最小但逻辑修复效果最强。若无法补实验，则 Abstract 和 Section 1 必须将"demonstrates"/"improves"降级为"correlates with"，同时在 Conclusion Section 9 明确标注此为结论的主要限制。

 

2：Figure 2 中"三个循环"与实际实现看似有脱节，表格11数据不完整

位置： Figure 2, Section 4（全节），Table 11, Table 13

问题：Figure 2 展示了 Grammar Hypothesis Loop，Fuzz Execution Loop，LLM Intervention Loop 三个并列的完整闭环，图中每个模块看起来都是"完整实现"。但 Table 11 明确列出大量"Missing"字段，Table 13 中 Hyp. pass 在多数 target 为 0.0±0.0%，说明 Grammar Hypothesis Loop 在实际运行中几乎未激活（或激活后无效）。Figure 2 制造了一个系统远比实际更完整的错误印象。审稿人一旦对照 Table 11/13，会直接质疑论文的诚信。

建议：在 Figure 2 中，对已实现但未完整 logged 的模块（如 Tier-2 repair、Hypothesis validation）添加注释标注"implemented, partially logged"；对 candidate-level P/U/R/G decision 模块标注"implemented, not archived"。或者，在 Section 4 开头添加一段"Implementation Scope"说明，明确哪些组件在当前 evaluation 中是 instrumented 的，哪些是 design-level 的。保留 Figure 2，把数据补全。如果你已经做完了，这个问题确认下细节，是不是前后都对应上了。

 

3：论文标题和自我定位中"closed-loop control"是类比而非工程实现，不恰当

位置： 论文标题, Section 1 Introduction, Section 4 开头, Section 9 Conclusion

问题：Closed-loop control在控制理论中有严格含义：需要定义 state space，control objective，feedback law，convergence property。当前系统是：LLM 生成候选 → heuristic admission gate → IPSM schedule 更新，这是"feedback-driven heuristic orchestration"，而不是 formal closed-loop controller。论文在 Section 2.4 自己说"The name LoopFuzz emphasizes closed-loop admission and local repair, not formal verification"，但标题仍使用"Integrated Closed-Loop Control"，让 Systems/Security 双向审稿人都感到定位模糊。

修改建议：将标题中"Integrated Closed-Loop Control"修改为"Feedback-Driven Orchestration"或"Runtime-Evidence-Guided"，以准确反映实现。或在 Section 1 增加一段明确说明：此处"closed-loop"指运行时 evidence 对 LLM proposals 的 feedback cycle，而非 control-theoretic 意义上的 stability-guaranteed closed-loop。修改标题代价最小，但效果最直接，你自己琢磨一下

 

二、实验设计问题

4：Baseline 计算资源不对等——最明显的公平性问题

位置： Table 6（Controlled ChatAFL-lineage baseline scope），Section 5.1

问题：LoopFuzz 使用 max_tokens=4096，ChatAFL baseline 使用 max_tokens=2048；LoopFuzz 的 plateau 调用温度为 1.2，ChatAFL 为 1.5；LoopFuzz 每次 campaign 多出 hypothesis/repair 专用调用（额外 3 calls/plateau event）。Table 6 第三行Calls/max tokens一栏已清晰呈现这个差异，但正文没有针对这个不对等进行任何控制或敏感性分析。在 Table 13 中，部分 target（如 LightFTP, Pure-FTPd）的 prompt token 极差超过 10 倍（66k–1349k），更说明 token budget 差异在不同 run 之间已经产生极大的不确定性。

修改建议：
增加一组 ChatAFL+4096 token 的对照实验，或在 Table 6 之后明确报告每 run 的平均 LLM token 消耗（已在 Table 13 有部分数据），并在统计分析中说明：token 消耗与 endpoint 之间的 Spearman 相关系数（Table 14 已有 ρ_tok 数据，但未在正文中被正式纳入结论）。Table 14 中 ρ_tok b/e 列已经显示几乎没有单调关系，这应当在正文中被主动引用以消除审稿人疑虑，而不是让其悬在附表中被忽视。

 

5：Controlled ChatAFL 不是真正的 ChatAFL——baseline 溯源问题

位置： Table 6, Section 5.1 第四段, Section 8 Reproducibility

问题：论文使用controlled ChatAFL替换原始 ChatAFL（gpt-3.5-turbo）是合理的工程决定，但 Table 6 显示两者在 model，temperature，max_tokens，control logic 上均不同。Section 8 承认"primary comparison is against the controlled lineage baseline, not the original ChatAFL artifact results"——这意味着论文无法声称"LoopFuzz improves over ChatAFL"，只能声称"improves over controlled-ChatAFL"。但 Abstract 和 Section 6 的措辞多次直接使用"ChatAFL"作为 baseline，未加限定词。

修改建议：在 Abstract，Section 1，Section 6 每处提及"ChatAFL baseline"时，加上限定词"controlled ChatAFL-lineage baseline"，并在第一次出现时插入脚注说明差异。Table 6 已经做得很好，需要将其中的差异在正文结论部分明确呼应一次。

 

6：n=10 runs 统计功效不足，但 Abstract 措辞过强

位置： Section 5.2 最后两段, Table 16, Table 17, Abstract

问题：Section 5.2 明确说明the corrected tests have limited power for medium effects，Table 17 列出 8 个 power-sensitive rows（包括 bftpd ChatAFL b_abs、ProFTPD ChatAFL b_abs、Kamailio ChatAFL edges 等）。但 Abstract 写道corrected improvements in IPSM edges on eight targets versus AFLNet and six versus ChatAFL，这 8/6 数字直接来自 BH-corrected 结果，但在功效不足的情况下，BH correction 的"不显著"不等于"无效果"，"显著"也可能是假阳性。这个问题的本质是：n=10 的 BH-corrected result 被当作强结论呈现在 Abstract 中。

修改建议：Abstract 中修改措辞：将corrected improvements...on eight targets改为statistically supported improvements (BH-adjusted, n=10) on eight targets, with additional positive trends on remaining targets requiring larger samples for confirmation。同时在 Section 5.2 中增加事后功效分析（post-hoc power calculation）：给定 n=10，对观察到的 Cliff's δ≥0.57 的效应量，报告 achieved power（通常需要报告 β ≤ 0.2）。

 

7：Forked-daapd 失败案例的分析不够深入，却与论文主张直接矛盾

位置： Section 6.7, Table 15, Table 19, Table 25

问题：Forked-daapd 是论文自己承认的primary branch-coverage negative case：LoopFuzz final b_abs = 2171.9±226.0，低于 AFLNet 的 2326.3±77.3，branch CV = 0.104（AFLNet = 0.033）。Table 25 对该 target 的 audit 显示所有关键量（candidate admissions, productive-edge ratio, state-progressive but branch-unproductive ratio）均为"Not recoverable"。这个 target 直接反驳了论文的核心主张（admission control + IPSM scheduling improves coverage），但 Section 6.7 的解释停留在"plausible explanation"层面，且 Table 26 的 ablation 数据显示所有 perturbations 都降低 b_abs（-91.8 to -145.0），这实际上说明无论哪个组件，Forked-daapd 上的 LoopFuzz 都比 baseline 差，这个结论比论文呈现的更严重。

修改建议： 6.7 中建议明确说明：在 Forked-daapd 上，LoopFuzz 的所有 ablation 变体均差于基础控制器，而基础控制器本身已差于 AFLNet 和 ChatAFL。这意味着 DAAP/DACP 的 response 信号本身就不适合 AFLNet-lineage IPSM abstraction，应当在 Section 7（Discussion）中将此作为"协议类型边界条件"明确列出，而不是仅作为"design-boundary case"一笔带过。可以在 Section 4（设计部分）增加一小节"Scope Limitations"，明确指出 response-ambiguous protocols 不在当前 admission controller 的有效范围内。

 

三、形式化与算法设计问题

8：A(x)=P∧U∧R∧G 中各谓词的独立性假设未验证

位置： Section 4.2（公式），Table 2

问题：论文将 admission 定义为四谓词的合取，但未讨论谓词之间的相关性。在实践中，通过 P（parseability）的候选几乎必然能获得某种服务器响应（U 的输入），而通过 U（non-rejection response）的候选往往也意味着状态进展（R 的充分条件）。如果 U∧R 高度相关，则 G（coverage gain）才是真正的筛选谓词，P 和 R 实为冗余。这对 Table 2 的"controlled specification"影响不大，但对论文声称"四个独立谓词共同构成 admission boundary"的技术贡献有直接影响。

建议：在 Section 4.2 增加一段分析各谓词的理论独立性：给出至少一个反例说明 P 通过但 U 失败、U 通过但 R 失败、R 通过但 G 失败的场景（论文在 FTP 示例中已有 P 通过 / U 失败的案例，但后两种未展示）。Section 4.2.3 已有 "a candidate may reach the intended state, yet fail G" 的文字描述，将其补充为正式的三个反例段落即可，无需额外实验。

 

9：β(s) scheduling 中常数（4.0/2.0/1.0/0.5/0.7）无理论依据

位置： Section 4.4，ρ(s) 和 β_frontier(s) 的定义

问题：论文对所有调度常数（frontier bonus 4.0，degree ≤1 bonus 4.0，rejection penalty 0.5，low-productivity penalty 0.7）均声明"reported control policy, not a claim of optimality"，同时 τ 阈值（512/600/700）也无来源说明（仅说"aligned with ChatAFL plateau floor"）。对于 Computers & Security 期刊，这种缺乏 sensitivity analysis 的启发式参数设置会被要求解释，否则系统看起来是"tuned to the benchmark"。

修改建议：增加附录级别的 sensitivity analysis：对最敏感的两个参数（frontier bonus 4.0 和 rejection penalty 0.5），各取 ±50% 变化（即 3.0/6.0 和 0.3/0.8），在 2–3 个代表性 target 上报告 endpoint 变化。若变化小，则强化"policy is robust"的结论；若变化大，则必须在正文中标注为超参数。这是期刊审稿中最常见的"小修"要求，提前做掉。

 

10：Algorithm 1 中 plateau 触发逻辑与 Section 4.4 文字描述不一致

位置： Algorithm 1（第 9–21 行），Section 4.4

问题：算法 1 第 11 行条件为"accumulated counterexamples AND low fitness open the repair gate"，但 Section 4.4 文字说"repair is reached only through the plateau path when validation-count, low-fitness, and accumulated-counterexample gates hold"——多了一个 validation-count 条件。Algorithm 1 中第 6–8 行的 sampled validation 与第 11 行的 repair gate 之间的 data flow 未在算法中显式表达（validation count 变量未出现在算法中）。这是一个直接的形式描述与算法的不一致。

修改建议：在 算法1 中增加一个显式变量 val_count，在第 7 行更新它，并在第 11 行的条件中加入 val_count ≥ threshold。同时在算法下方的说明段中明确 threshold 的取值（如果有固定值）或标注为 configurable parameter。

 

四、指标与统计问题

11：IPSM edges 作为"主要度量指标"的有效性在 Table 28 中已被自我证伪

位置： RQ2，Table 28，Section 7.1

问题：表格 28 的最后一行显示 Forked-daapd 的 ∆edges = +1.6（positive）但 ∆b_abs = -143.4（strongly negative），proxy ∆b/∆e = -89.6。这直接证明 IPSM edges 在该 target 上是"noisy/misleading metric"。同时 Lighttpd1 的 proxy = +60.4（169.0 branches 对应仅 2.8 edges），说明在 HTTP 协议上 edges 严重低估了 branch 进展。然而 RQ2 的标题仍是"Response-Derived State Exploration"，并在 Section 6.2 中将 IPSM edge improvement 作为正面结果呈现，却没有在 RQ2 的结论处直接引用 Table 28 的 proxy 数据来限定结论。

建议：在 Section 6.2 结尾增加一段："Table 28 shows that the IPSM-edge-to-branch proxy varies by over two orders of magnitude across targets (from -89.6 for Forked-daapd to +60.4 for Lighttpd1), confirming that IPSM edges are a useful exploration diagnostic only when response codes co-vary with branch-productive progress." 这段话将 Table 28 的信息主动融入 RQ2 结论，消除审稿人"作者回避负面数据"的印象。

 

12：图3和图4的 y 轴 zoom 策略造成视觉误导

位置： Figure 3（branch coverage 轨迹），Figure 4（IPSM edge 轨迹）

问题：两图均采用"post-initial y-zoomed"策略，即 y 轴从接近终点值的某处开始，使得较小的绝对差异在视觉上看起来非常显著。以 Figure 3 的 LightFTP 为例，y 轴范围约为 71.0–71.8，实际差异不足 1 branch；Figure 4 的 Lighttpd1 y 轴从约 8 开始，终点为 33，而 AFLNet 终点仅 15，视觉上 LoopFuzz 呈压倒性优势，但绝对值上是 32.5 vs 14.9 edges。这种展示方式对 LightFTP（已在正文中标注为 saturated）尤其有问题，因为即使标注了，图还是被放在 Figure 3 中展示。

建议：对 LightFTP 的 Figure 3 子图，在图中显著位置标注"[saturated — excluded from coverage-breadth claims]"，或将其移至附录并在正文中仅保留文字说明。对其余子图，在 Figure caption 中统一增加一句："Note: y-axes are zoomed to show trajectory differences; absolute scales are given in Table 15."

 

13：Table 13 中 Hypothesis pass rate = 0.0±0.0% 的解释被弱化

位置： Table 13, Section 5.4 "Interpreting low hypothesis-pass rates"

问题：Section 5.4 花费一整段解释"0.0% Hyp. pass does not imply no candidate was admitted"——这个解释在技术上正确，但逻辑上等于承认了：Grammar Hypothesis Loop 的 Tier-1 sampling + Tier-2 repair 机制，在 LightFTP, Exim, Live555, Kamailio, Forked-daapd, Lighttpd1 这 6 个 target 上几乎从未成功验证任何 grammar hypothesis。这意味着 Section 4.1 描述的"hypothesis layer"在这 6 个 target 的 campaign 中实际上处于"无效激活"状态。然而论文主张这是系统的四大组件之一。

建议：在4.1 结尾增加一句话，明确 hypothesis layer 的激活条件："The hypothesis layer is lazily initialized and only produces non-trivial updates when the protocol's response structure is sufficiently structured to yield parseable grammar regions; targets with irregular or sparse response content may consistently show low sampled validation pass rates (see Table 13), in which case the controller falls back to plateau scheduling and admission-based filtering." 此修改将设计意图与实验现象统一，而不是让审稿人自己发现矛盾。

 

五、Logging 与可复现性问题

14：Table 9（launch-ledger gaps）暴露了 survivorship bias 风险，但正文未充分处理

位置： Table 9, Section 5.1 "Run filtering and missing-data handling"

问题：表格9 明确写道：Launched runs: Not recoverable，Artifact/recovery failure: Not recoverable。这意味着实验中可能存在未完成的 run 被过滤掉，而过滤标准（"at least 1400 archived minutes"）本身可能对某些 target-fuzzer 组合有偏。例如，若 LoopFuzz 的部分 run 因 LLM endpoint 故障而提前终止（<1400 min），这些 run 会被过滤，而 AFLNet 因为没有 LLM dependency 极少提前终止。这种系统性丢失恰好对 LoopFuzz 有利。

修改建议：
在 Section 5.1 中增加一段：明确报告已知的 run 失败原因（即使只能说"LLM endpoint timeout as only known failure mode"），并增加敏感性分析：若每个 LoopFuzz cell 随机移除 1–2 个 run，main conclusions 是否仍然成立（可以用 bootstrap resampling 在现有 10 runs 上模拟）。这不需要新实验，只需对 Table 16 的统计结果做 leave-one-out 稳健性报告。

 

15：Table 7 的 reproducibility gaps 与 Data Availability 声明不一致

位置： Table 7, Section 9 Data Availability

问题：表格7 列出多项No状态：provider seed not requested、prompt payloads in memory only、no per-call latency rows、no action replay mode。但 Data Availability 部分承诺提供"prompt templates, raw selected and auxiliary summary tables, representative logs"。问题在于：没有 per-call prompt payloads 和 action ledger，即便提供了 prompt templates，也无法 replay 任何具体 campaign decision，与安全期刊要求的 artifact reproducibility 预期存在差距。

建议：在 Data Availability 中明确标注哪些内容支持"audit"（可以核查），哪些支持"reproduction"（可以重跑），哪些不可重建（bit-for-bit 不可能）。使用 Table 7 的结构在 Data Availability 中给出一个简短的"reproducibility scope statement"，消除审稿人对 artifact 的过度期望，同时不削弱合理的 auditability 主张。

 

六、表格与图形一致性问题

16：Table 1 的 taxonomy 对 LoopFuzz 描述夸大创新点

位置： Table 1（Section 2 开头）

问题：Table 1 中 ChatAFL 的"State signal"列为"Interaction history"（无 runtime admission），LoopFuzz 列为"IPSM frontier + validation"——这在视觉上暗示 LoopFuzz 有更高级的 state signal。但实际上 LoopFuzz 的 IPSM 与 AFLNet 的完全一样（论文 Section 2.2 明确说"In the AFLNet lineage, this machine is an approximate response-derived graph"），LoopFuzz 的贡献是 admission gate 和 scheduling bonus，而不是 state signal 本身。Table 1 的填写方式将"使用了 IPSM"错误地呈现为"拥有更好的 state signal"。

建议：将 Table 1 中 LoopFuzz 的 State signal 列改为"AFLNet-style IPSM (same as AFLNet) + frontier scheduling"，明确区分 state model（与 AFLNet 相同）和 scheduling policy（LoopFuzz 的贡献）。这使 taxonomy 更准确，同时实际上更清晰地展示了 LoopFuzz 在相同 state abstraction 下改进了利用效率。

 

17：Table 20 (NSFuzz branch diagnostics) 和 Table 21 (auxiliary state diagnostics) 同时出现在 Section 6，但在 RQ3 中被引用时未加足够警示

位置： Table 20, Table 21, Section 6.3 末段

问题：Section 6.6 专门分析 LightFTP 的 NSFuzz vs AFLNet-lineage 数字差异（414.3 vs 71.0 branches），指出这是"cross-artifact metric divergence"。但 Table 20 和 Table 21 仍然并列放置在主文中，与 Table 15（primary results）视觉权重相同。读者在快速阅读时容易将 NSFuzz 的 414.3 branches 与 AFLNet 的 71.0 直接比较，得出 NSFuzz 远优于 AFLNet 的错误印象。

建议：在 Table 20 和 Table 21 的 caption 中分别加上一句加粗警示："NSFuzz artifact counts use a different instrumentation pipeline and are NOT directly comparable to AFLNet-lineage b_abs values; see Section 6.6 for explanation." 同时在这两个表的标题中将"diagnostics"改为"cross-artifact diagnostics (incomparable metric surfaces)"，使其在快速扫表时即可识别。

 

18：Table 26（ablation deltas）的基准列是"local full controller"而非主实验 LoopFuzz，但 caption 未清晰说明

位置： Table 26, Section 6.8

本质：表格 26 的"Full"列数值（如 ProFTPD = 5395.9/284.2）与 Table 15 的 LoopFuzz 数值（ProFTPD = 5358.8±136.1）不完全一致，因为 Table 26 来自 separate ablation archive，使用不同的 run set。Section 5.3 中提到"its full-controller column need not match every primary-table endpoint exactly"，但 Table 26 的 caption 没有对这个不一致给出任何注释，读者很容易混淆两组数据。

修改建议：
在 Table 26 的 caption 中明确加上："Full column values come from the separate ablation archive (Section 5.3) and may differ from primary Table 15 LoopFuzz values due to different run sets." 并在 Section 6.8 的正文中，在第一次引用 Table 26 时增加一句脚注级别的提醒。

 

七、安全性与 Bug Triage 问题

19：Table 24 的 crash/vulnerability triage 呈现方式可能引发误解

位置： Table 24, Section 6.5

问题：表格24 列出了"CVE/CWE boundary"列，其中 bftpd 写"CVE-2025-11947-related; refs only"，Pure-FTPd 写"CVE-2024-48208 not reproduced; refs only"——这些 CVE 编号的出现会让审稿人误以为 LoopFuzz 发现了这些 CVE，但实际上 Section 6.5 说明"CVE identifiers in the source worksheets are treated conservatively as known-bug or same-class references, not as newly assigned CVEs for the current seeds." 这个重要限制只出现在正文中，没有在 Table 24 中直接体现。

建议：
在 Table 24 的 CVE/CWE boundary 列的列头下方，加括号注明"(known-bug class refs only; no new CVE assignment)"。或者将所有 CVE 条目改写为"same class as CVE-XXXX (not reproduced/not claimed)"，使读者在看表时即可获得准确信息。

 

八、结论支撑强度问题

20：Section 9 Conclusion 的三个"lesson"超出实验证据支撑

位置： Section 9 Conclusion，全三段

问题：Lesson 1 声称LLM output is most useful when it remains a bounded proposal until live execution evidence supports it，但由于没有 no-admission baseline，这个 lesson 没有实验支撑，只是设计动机的重申。Lesson 2 声称"IPSM edges are useful when response structure co-varies with meaningful protocol progress"——这个 lesson 在 Forked-daapd 上已被证伪，却仍以正面陈述的方式出现。Lesson 3 关于 methodology 的呼吁是合理的。三个 lesson 中有两个超出当前实验的归因能力。

建议：
将 Lesson 1 改写为条件性陈述：Our results are consistent with the hypothesis that...，并在后面加上A direct causal test requires a LoopFuzz-no-admission arm, which we identify as the primary limitation of the current evaluation. 将 Lesson 2 改写为："IPSM edges are informative when...but can mislead when response signals are sparse or protocol state and branch coverage diverge, as observed in Forked-daapd (Table 28)." 这两处改动使 Conclusion 与 Section 8 Threats to Validity 的声明保持一致，消除自相矛盾。

 

九、补充：Figure 1 专项问题

21：Figure 1 标注"illustrative, non-archived"但被 Introduction 作为核心动机

位置： Figure 1 caption, Section 2.4, Section 1 Introduction

问题：Figure 1 的 caption 明确写"Illustrative, non-archived FTP semantic-drift pattern"，但 Section 2.4 将其作为核心动机 example（"semantic drift"），Section 1 Introduction 也引用了相同的 FTP 语境。一个既非 archived 也非 measured 的 illustrative example 作为系统设计的主要动机，在严格审稿标准下会被质疑：论文是否真正测量过 semantic drift 的发生频率？若未测量，动机的说服力下降。

建议：在 Section 2.4 结尾增加一句话："While we cannot quantify semantic-drift prevalence from the current archive (see Table 11, U-fail count: missing), Table 24 shows that the benchmark produces replayable artifacts including protocol-oracle violations, confirming that semantically premature requests do occur in practice and motivate the admission boundary." 这将 Figure 1 的 illustrative 性质与实际 triage 证据连接，使动机更有根基，让审稿人看着更放心。