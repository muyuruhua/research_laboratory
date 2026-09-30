# 全文—正文论断逐句审查（2026-09-30）

## 结论与未完成边界

**未达到“原 50 篇正式发表版本全部完成全文核验”。不得将本报告或编译检查的 PASS 改写为所有引用都已完全核实。**

- 原稿 50 篇、49 处引文组、57 次文献使用已逐一列入证据矩阵；没有抽样省略条目。
- 43 篇完成基于可访问全文的对应引用句核查：41 篇有本地原始 PDF，另 2 篇通过浏览器阅读全文。
- FuzzGPT、HGFuzzer 另取得早期预印本：窄范围陈述可对照，但正式版版本差异仍未完成核验。
- 5 篇未取得完整原文：NSFuzz、SSGFuzz、WingMuzz、Zhang 等（2026）及 Brier（1950）。出版记录或摘要验证不能代替全文验证。
- 为满足 first_paper.md 明确要求，另补入并审查真正的 T-Scheduler（Luo 等，AsiaCCS 2024），没有把它与 Zhang 等（2026）混同。当前正文引用 51 篇、59 次。

## 本轮实质修正

1. 分开 Gramatron/CarpetFuzz，以及 ChatAFL/LLMIF/Fuzz4All 的机制归属，消除一组引文笼统支撑多项机制的歧义。
2. 增补 T-Scheduler；删除未以 Zhang 全文证实的 Beta 机制归属，并收窄与 SSGFuzz 的排他性比较。
3. HGFuzzer 只保留作者稿和正式题名共同支持的高层定位，删除更具体且尚未完成最终版核验的 predicate-guided synthesis。
4. 明确 Guo 的 ECE 在本文中是对二元 episode reward 概率的适配，不直接等同原文的预测类别置信度校准。
5. 统一为现有实现实际计算的非插值 AP；去除 AP 与任意 AUPRC 面积等同的表述。数值没有重算。
6. Efron 引文限定为 bootstrap 原理；整 run 抽样、百分位区间和层级设计明确为本文的分析选择。
7. Mann–Whitney 限定独立 run 对比并处理并列值，不把秩检验直接解释为中位数差；Cliff δ 明确优势概率之差及方向。
8. BH 改为 nominal q，指出原始保证所需独立性并未由共享比较组/相关终点自动满足；KM 补充非信息性删失条件。
9. Thompson 原始论文与本文折扣、frontier 权重和比例采样适配明确区分；不宣称后者由经典文献保证。
10. 根据 Efron 原始扫描论文补齐页码 1–26。

## 审查方法

检查每个引文所在完整句子或表格行，并查看相邻机制/统计解释是否将本文设计或实测结论归属于外部文献。取得完整论文后，定位与引文对应的原始方法、定义、结果和限制；报告页码/章节及支持范围。本报告不声称逐字转录所有原文，也不重新验证这些论文的实验结果。

页码默认包含 PDF 封面；Cliff 条目使用期刊印刷页码。arXiv/作者稿并不被称为出版社最终排版版本。除已知题名/作者差异单列的两篇外，其余作者稿的结论仅限当前实际引用的论断。

## 来源与版本限制

- Mann–Whitney：浏览器成功读取完整 12 页 PDF（封面 + 11 页论文）；本地下载超时，未伪造本地 SHA-256。
- Cliff：浏览器读取原论文 494–509 页的全文镜像转录。镜像可能存在 OCR 差异；它不是出版社 PDF，本地请求只返回访问外壳，不作为全文副本。
- Efron：27 页扫描 PDF，只有封面可自动提取文字。正文原 pp. 1–3 经渲染图像直接审阅，不能将封面文字量冒充 OCR 全文。
- FuzzGPT：预印本题名为 Large Language Models are Edge-Case Fuzzers: Testing Deep Learning Libraries via FuzzGPT，正式题名已变化；六位作者相符。
- HGFuzzer：2025 预印本为三作者；2026 正式条目为四作者。相关机制不可假定逐字未变。

## first_paper.md 对应检查

| 要求 | 当前处理 |
|---|---|
| response-derived state 不等于独立代码进度 | 保留双反馈分离；StateAFL 的既有发现被明确承认。 |
| LLM 只提出候选，execute-before-promote，provisional/durable | 方法与创新边界保持一致；未以他人生成方法代替本文准入证据。 |
| 不将 Beta/Thompson 本身当创新 | 补入 T-Scheduler，保留 The Bandit’s States 和 SSGFuzz；强调组合与独立证据。 |
| Magma / 漏洞证据分层 | reached / triggered / detected 区分不变；回放不等于受控再发现。 |
| 公平性与五 arm 因果对照 | 保持 matched policy/cap 与实际使用量的区别；未将未完成实验写成完成。 |
| 缺失数据与证据限制 | 实验数值及输入文件不变；本轮仅修正引证与统计措辞，不填造实验。 |
| 摘要和关键词限制 | 摘要 183 词，关键词 5 个。 |

这只能确认本轮改动与上述主线约束相容；不能因为引证修订就宣称整篇已满足所有实验完成要求。SSGFuzz 等未取得全文的创新比较仍有待解决的证据缺口。

## 逐篇覆盖清单

| # | key / 题名 | 正文行号 | 来源状态 | 页码 / 章节 | 结论 |
|---:|---|---|---|---|---|
| 1 | sgf_usenix22: Stateful Greybox Fuzzing | 137 | 本地全文 | 2, 3, 5; Introduction; state identification | supported |
| 2 | aflnet: AFLNet: A Greybox Fuzzer for Network Protocols | 83, 137 | 本地全文 | 3, 4; II, State Machine Learner / Sequence Mutator | supported |
| 3 | chatafl: Large Language Model Guided Protocol Fuzzing | 87, 143 | 本地全文 | 2, 5, 8, 9; IV, LLM-guided protocol fuzzing | supported |
| 4 | stateafl: StateAFL: Greybox fuzzing for stateful network servers | 85, 137 | 本地全文 | 3, 5, 6; Introduction; related work; approach | supported |
| 5 | nsfuzz: NSFuzz: Towards Efficient and State-Aware Network Service Fuzzing | 137 | 全文未取得 | —; — | fulltext_unresolved |
| 6 | fuzz4all_universal_fuzzing_large_2024: Fuzz4All: Universal Fuzzing with Large Language Models | 143 | 本地全文 | 2, 3, 4; Autoprompting and fuzzing loop | attribution_split |
| 7 | gramatron_effective_grammar_aware_2021: Gramatron: effective grammar-aware fuzzing | 141 | 本地全文 | 2, 3, 4; Sections 2--3, grammar automata | attribution_split |
| 8 | sok_prudent_evaluation_practices_2024: SoK: Prudent Evaluation Practices for Fuzzing | 149 | 本地全文 | 2, 3, 4; Recommendations 4--5; evaluation review | supported |
| 9 | profuzzbench_benchmark_stateful_protocol_2021: ProFuzzBench: A Benchmark for Stateful Protocol Fuzzing | 149 | 本地全文 | 2, 3, 4; Benchmark workflow and reproducibility | supported |
| 10 | llmif_augmented_large_language_2024: LLMIF: Augmented Large Language Model for Fuzzing IoT Devices | 143 | 本地全文 | 2, 4; Specification extraction and algorithm overview | attribution_split |
| 11 | reliability_benchmarking_2022: On the Reliability of Coverage-Based Fuzzer Benchmarking | 149 | 本地全文 | 2, 3, 4; Research questions and proxy reliability | supported |
| 12 | carpetfuzz_documentation_2023: CarpetFuzz: Automatic Program Option Constraint Extraction from Documentation for Fuzzing | 141 | 本地全文 | 3, 4; Challenges and option constraints | attribution_split |
| 13 | bandits_states2023: The Bandit's States: Modeling State Selection for Stateful Network Fuzzing as Multi-armed Bandit Problem | 145, 161 | 本地全文 | 2, 3, 4; Sections 3--4, state-selection bandit formulation | novelty_boundary_clarified |
| 14 | ssgfuzz2026: State Significance-Guided Fuzzing for Stateful Protocol Program | 145, 163 | 全文未取得 | —; — | fulltext_unresolved |
| 15 | magma2020: Magma: A Ground-Truth Fuzzing Benchmark | 147, 164 | 本地全文 | 2, 8, 10; Sections 4 and 4.3, ground-truth metrics | supported |
| 16 | thompson1933: On the likelihood that one unknown probability exceeds another in view of the evidence of two samples | 321 | 本地全文 | 1, 2, 8; Sections 1--3 | adaptation_clarified |
| 17 | brier1950: Verification of forecasts expressed in terms of probability | 546 | 全文未取得 | —; — | fulltext_unresolved |
| 18 | guo2017calibration: On Calibration of Modern Neural Networks | 550 | 本地全文 | 2, 3; 2, Definitions; Eqs. (1)--(3) | adaptation_clarified |
| 19 | benjamini1995: Controlling the False Discovery Rate: A Practical and Powerful Approach to Multiple Testing | 557 | 本地全文 | 2, 6, 12; Theorem 1 and Appendix A | guarantee_qualified |
| 20 | kaplan1958: Nonparametric Estimation from Incomplete Observations | 559 | 本地全文 | 2, 3; Original pp. 457--458; Section 1.1 | assumption_added |
| 21 | mann1947: On a Test of Whether One of Two Random Variables is Stochastically Larger than the Other | 557 | 浏览器全文（无本地 PDF） | 2, 3; Original pp. 50--51; Section 1 | inference_scope_clarified |
| 22 | cliff1993: Dominance statistics: Ordinal analyses to answer ordinal questions | 557 | 浏览器全文（无本地 PDF） | 494, 495, 496; Original article pp. 494--496, independent-group dominance | effect_definition_clarified |
| 23 | efron1979: Bootstrap Methods: Another Look at the Jackknife | 557 | 本地全文 | 2, 3, 4; Original pp. 1--3, Section 2 and Eqs. (2.1)--(2.5) | resampling_scope_clarified |
| 24 | davis2006pr: The relationship between Precision-Recall and ROC curves | 550 | 本地全文 | 1, 2, 4; ROC/PR relation and interpolation | metric_distinction_fixed |
| 25 | zhang2026thompson: A novel seed scheduling scheme using Thompson sampling for coverage-guided greybox fuzzing | 145, 162 | 全文未取得 | —; — | fulltext_unresolved |
| 26 | aflnet5years2025: AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing | 137 | 本地全文 | 3, 5, 6; III, design and interesting sequences | supported |
| 27 | nyxnet2022: Nyx-net: network fuzzing with incremental snapshots | 139 | 本地全文 | 2, 6; Design, incremental snapshots | supported |
| 28 | snapfuzz2022: SnapFuzz: high-throughput fuzzing of network applications | 139 | 本地全文 | 4, 5, 6; 3.2--3.5, network protocol / file system / rewriting | supported |
| 29 | fuzztructionnet2024: No Peer, no Cry: Network Application Fuzzing via Fault Injection | 139 | 本地全文 | 4, 5, 6; 3.1--3.5, fault injection into protocol peer | supported |
| 30 | fox2024: FOX: Coverage-guided Fuzzing as Online Stochastic Control | 145 | 本地全文 | 3, 4; Section 2, online stochastic control formulation | supported |
| 31 | prophetfuzz2024: ProphetFuzz: Fully Automated Prediction and Fuzzing of High-Risk Option Combinations with Only Documentation via Large Language Model | 143 | 本地全文 | 2, 4; Documentation constraints and few-shot option prediction | supported |
| 32 | whitefox2024: WhiteFox: White-Box Compiler Fuzzing Empowered by Large Language Models | 143 | 本地全文 | 3, 4; Motivating example; source-derived requirements | supported |
| 33 | fuzzgpt2024: Large Language Models are Edge-Case Generators: Crafting Unusual Programs for Fuzzing Deep Learning Libraries | 143 | 早期版本；待最终版 | 2, 3, 5; Historical bug programs; in-context learning/fine-tuning | version_limited |
| 34 | formatfuzzer: FormatFuzzer: Effective Fuzzing of Binary File Formats | 141 | 本地全文 | 2, 4; Binary templates and format-aware fuzzing | supported |
| 35 | fuzzbench2021: FuzzBench: an open fuzzer benchmarking platform and service | 149 | 本地全文 | 2, 3, 4; Section 2, benchmark methodology | supported |
| 36 | benchmarkproperties: Fuzzing: On Benchmarking Outcome as a Function of Benchmark Properties | 841 | 本地全文 | 6, 7, 8, 9; Controlled covariates and holistic benchmarking | supported |
| 37 | stateinspector2022: The Closer You Look, The More You Learn: A Grey-box Approach to Protocol State Machine Learning | 137 | 本地全文 | 3, 4, 5; 3--4, limitations and greybox architecture | supported |
| 38 | wingmuzz2025: WingMuzz: Blackbox Testing of IoT Protocols via Two-dimensional Fuzzing Schedule | 145 | 全文未取得 | —; — | fulltext_unresolved |
| 39 | hybridllm2026: Large Language Model Assisted Hybrid Fuzzing | 143 | 本地全文 | 2, 3, 4; Section III, LLM-assisted concolic execution | supported |
| 40 | hgfuzzer2026: HGFuzzer: Directed Greybox Fuzzing via Large Language Model | 143 | 早期版本；待最终版 | 2, 4; Path conditions, harness generation, target-specific mutators | version_limited |
| 41 | greenbenchmark2023: Green Fuzzer Benchmarking | 501 | 本地全文 | 4, 7, 9; Benchmark construction; resource/accuracy trade-off | supported |
| 42 | protocolguard2026: ProtocolGuard: Detecting Protocol Non-compliance Bugs via LLM-guided Static Analysis and Dynamic Verification | 147 | 本地全文 | 2, 3, 4; Specification rules and dynamic verification | supported |
| 43 | bsfuzzer2026: BSFuzzer: Context-Aware Semantic Fuzzing for BLE Logic Flaw Detection | 147 | 本地全文 | 2, 3, 4; Semantic extraction and state-machine violations | supported |
| 44 | mercuriuzz2026: Identifying Logical Vulnerabilities in QUIC Implementations | 147 | 本地全文 | 2, 3, 4; Section IV; QUIC logical vulnerabilities | supported |
| 45 | distfuzz2025: Blackbox Fuzzing of Distributed Systems with Multi-Dimensional Inputs and Symmetry-Based Feedback Pruning | 139 | 本地全文 | 2, 3, 4; Table I and architecture | supported |
| 46 | blueman2025: BLuEMan: A Stateful Simulation-based Fuzzing Framework for Open-Source RTOS Bluetooth Low Energy Protocol Stacks | 139 | 本地全文 | 3, 4; Design overview; simulated BLE boards | supported |
| 47 | fishfuzz2023: FISHFUZZ: Catch Deeper Bugs by Throwing Larger Nets | 145 | 本地全文 | 2, 3; Overview of multi-distance and dynamic prioritization | supported |
| 48 | miner2023: MINER: A Hybrid Data-Driven Approach for REST API Fuzzing | 141 | 本地全文 | 2, 3, 4; Overview; REST API sequence generation | supported |
| 49 | mutationassessment2023: Systematic Assessment of Fuzzers using Mutation Analysis | 841 | 本地全文 | 2, 3, 4; Mutation analysis and fault detection | supported |
| 50 | fuzztruction2023: Fuzztruction: Using Fault Injection-based Fuzzing to Leverage Implicit Domain Knowledge | 141 | 本地全文 | 3, 4; Sections 2--3, generator fault injection | supported |
| 51 | tscheduler2024: Make out like a (Multi-Armed) Bandit: Improving the Odds of Fuzzer Seed Scheduling with T-Scheduler | 145, 162 | 本地全文 | 1, 4, 5; Section 3.2; Algorithm 1 | required_prior_work_added |

## 逐句证据矩阵

以下每项对应一次实际文献使用，保留修改前后原句；多文献同句分别给出证据，避免用其中一篇替代整组。完整可机读记录见 sentence_evidence_matrix.json。

### C001:aflnet — main.revised.tex:83

- 状态：supported；本地全文
- 原句：AFLNet uses responses to construct an inferred protocol state machine (IPSM), making protocol-visible feedback available without a target-specific internal-state extractor~\cite{aflnet}.
- 当前句：AFLNet uses responses to construct an inferred protocol state machine (IPSM), making protocol-visible feedback available without a target-specific internal-state extractor~\cite{aflnet}.
- 原文位置：[3, 4] / II, State Machine Learner / Sequence Mutator（PDF page including cover）
- 核查说明：Response status codes form observed state transitions; independent code-coverage instrumentation remains required. Does not establish complete semantic states.
- 来源记录：[retrieval.json](sources/aflnet/retrieval.json)

### C002:stateafl — main.revised.tex:85

- 状态：supported；本地全文
- 原句：StateAFL already identifies limitations of response-derived state abstractions and uses memory observations to infer server states~\cite{stateafl}.
- 当前句：StateAFL already identifies limitations of response-derived state abstractions and uses memory observations to infer server states~\cite{stateafl}.
- 原文位置：[3, 5, 6] / Introduction; related work; approach（PDF page including cover）
- 核查说明：Long-lived memory snapshots and locality-sensitive hashing infer states; explicitly describes poor information in response codes. Confirms prior recognition of proxy limitations.
- 来源记录：[retrieval.json](sources/stateafl/retrieval.json)

### C003:chatafl — main.revised.tex:87

- 状态：supported；本地全文
- 原句：ChatAFL demonstrates that LLMs can derive protocol structures and propose interaction sequences~\cite{chatafl}.
- 当前句：ChatAFL demonstrates that LLMs can derive protocol structures and propose interaction sequences~\cite{chatafl}.
- 原文位置：[2, 5, 8, 9] / IV, LLM-guided protocol fuzzing（PDF page including cover）
- 核查说明：Grammar extraction, initial-seed message enrichment, and plateau-triggered message generation support both occurrences. Does not validate LoopFuzz admission effects.
- 来源记录：[retrieval.json](sources/chatafl/retrieval.json)

### C004:aflnet — main.revised.tex:137

- 状态：supported；本地全文
- 原句：\section{Related Work and Novelty Boundary}
Stateful greybox fuzzing studies how to expose, infer, and schedule protocol state~\cite{aflnet,stateafl,nsfuzz,sgf_usenix22}.
- 当前句：\section{Related Work and Novelty Boundary}
Stateful greybox fuzzing studies how to expose, infer, and schedule protocol state~\cite{aflnet,stateafl,nsfuzz,sgf_usenix22}.
- 原文位置：[3, 4] / II, State Machine Learner / Sequence Mutator（PDF page including cover）
- 核查说明：Response status codes form observed state transitions; independent code-coverage instrumentation remains required. Does not establish complete semantic states.
- 来源记录：[retrieval.json](sources/aflnet/retrieval.json)

### C004:stateafl — main.revised.tex:137

- 状态：supported；本地全文
- 原句：\section{Related Work and Novelty Boundary}
Stateful greybox fuzzing studies how to expose, infer, and schedule protocol state~\cite{aflnet,stateafl,nsfuzz,sgf_usenix22}.
- 当前句：\section{Related Work and Novelty Boundary}
Stateful greybox fuzzing studies how to expose, infer, and schedule protocol state~\cite{aflnet,stateafl,nsfuzz,sgf_usenix22}.
- 原文位置：[3, 5, 6] / Introduction; related work; approach（PDF page including cover）
- 核查说明：Long-lived memory snapshots and locality-sensitive hashing infer states; explicitly describes poor information in response codes. Confirms prior recognition of proxy limitations.
- 来源记录：[retrieval.json](sources/stateafl/retrieval.json)

### C004:nsfuzz — main.revised.tex:137

- 状态：fulltext_unresolved；全文未取得
- 原句：\section{Related Work and Novelty Boundary}
Stateful greybox fuzzing studies how to expose, infer, and schedule protocol state~\cite{aflnet,stateafl,nsfuzz,sgf_usenix22}.
- 当前句：\section{Related Work and Novelty Boundary}
Stateful greybox fuzzing studies how to expose, infer, and schedule protocol state~\cite{aflnet,stateafl,nsfuzz,sgf_usenix22}.
- 原文位置：[] / None（PDF page including cover）
- 核查说明：出版记录已核实，但完整原文仍未取得；不得将题名/摘要/项目说明当作全文审查通过。保留窄范围已知表述，待原文补证。
- 来源记录：[retrieval.json](sources/nsfuzz/retrieval.json)

### C004:sgf_usenix22 — main.revised.tex:137

- 状态：supported；本地全文
- 原句：\section{Related Work and Novelty Boundary}
Stateful greybox fuzzing studies how to expose, infer, and schedule protocol state~\cite{aflnet,stateafl,nsfuzz,sgf_usenix22}.
- 当前句：\section{Related Work and Novelty Boundary}
Stateful greybox fuzzing studies how to expose, infer, and schedule protocol state~\cite{aflnet,stateafl,nsfuzz,sgf_usenix22}.
- 原文位置：[2, 3, 5] / Introduction; state identification（PDF page including cover）
- 核查说明：Tracks sequences of assigned named constants in state variables, usually enums. Grouped stateful-fuzzing sentence is supported.
- 来源记录：[retrieval.json](sources/sgf_usenix22/retrieval.json)

### C005:aflnet5years2025 — main.revised.tex:137

- 状态：supported；本地全文
- 原句：The subsequent AFLNet study revisits coverage-guided protocol fuzzing~\cite{aflnet5years2025}, while greybox protocol-state learning investigates how internal observations inform inferred models~\cite{stateinspector2022}.
- 当前句：The subsequent AFLNet study revisits coverage-guided protocol fuzzing~\cite{aflnet5years2025}, while greybox protocol-state learning investigates how internal observations inform inferred models~\cite{stateinspector2022}.
- 原文位置：[3, 5, 6] / III, design and interesting sequences（PDF page including cover）
- 核查说明：Extended AFLNet combines code and state feedback; the manuscript makes only a bounded background claim.
- 来源记录：[retrieval.json](sources/aflnet5years2025/retrieval.json)

### C006:stateinspector2022 — main.revised.tex:137

- 状态：supported；本地全文
- 原句：The subsequent AFLNet study revisits coverage-guided protocol fuzzing~\cite{aflnet5years2025}, while greybox protocol-state learning investigates how internal observations inform inferred models~\cite{stateinspector2022}.
- 当前句：The subsequent AFLNet study revisits coverage-guided protocol fuzzing~\cite{aflnet5years2025}, while greybox protocol-state learning investigates how internal observations inform inferred models~\cite{stateinspector2022}.
- 原文位置：[3, 4, 5] / 3--4, limitations and greybox architecture（PDF page including cover）
- 核查说明：Internal memory/execution observations supplement state-model learning. Requires specific learning assumptions; no generalization to LoopFuzz inferred.
- 来源记录：[retrieval.json](sources/stateinspector2022/retrieval.json)

### C007:nyxnet2022 — main.revised.tex:139

- 状态：supported；本地全文
- 原句：Nyx-Net uses incremental snapshots for network fuzzing~\cite{nyxnet2022}; SnapFuzz targets high-throughput execution of network applications~\cite{snapfuzz2022}; fault-injection-based network fuzzing provides another approach to exercising protocol interactions~\cite{fuzztructionnet2024}.
- 当前句：Nyx-Net uses incremental snapshots for network fuzzing~\cite{nyxnet2022}; SnapFuzz targets high-throughput execution of network applications~\cite{snapfuzz2022}; fault-injection-based network fuzzing provides another approach to exercising protocol interactions~\cite{fuzztructionnet2024}.
- 原文位置：[2, 6] / Design, incremental snapshots（PDF page including cover）
- 核查说明：Incremental snapshots skip shared message prefixes; snapshot design is not evidence of LoopFuzz portability.
- 来源记录：[retrieval.json](sources/nyxnet2022/retrieval.json)

### C008:snapfuzz2022 — main.revised.tex:139

- 状态：supported；本地全文
- 原句：Nyx-Net uses incremental snapshots for network fuzzing~\cite{nyxnet2022}; SnapFuzz targets high-throughput execution of network applications~\cite{snapfuzz2022}; fault-injection-based network fuzzing provides another approach to exercising protocol interactions~\cite{fuzztructionnet2024}.
- 当前句：Nyx-Net uses incremental snapshots for network fuzzing~\cite{nyxnet2022}; SnapFuzz targets high-throughput execution of network applications~\cite{snapfuzz2022}; fault-injection-based network fuzzing provides another approach to exercising protocol interactions~\cite{fuzztructionnet2024}.
- 原文位置：[4, 5, 6] / 3.2--3.5, network protocol / file system / rewriting（PDF page including cover）
- 核查说明：Execution synchronization, in-memory file system and snapshots support high-throughput network fuzzing claim.
- 来源记录：[retrieval.json](sources/snapfuzz2022/retrieval.json)

### C009:fuzztructionnet2024 — main.revised.tex:139

- 状态：supported；本地全文
- 原句：Nyx-Net uses incremental snapshots for network fuzzing~\cite{nyxnet2022}; SnapFuzz targets high-throughput execution of network applications~\cite{snapfuzz2022}; fault-injection-based network fuzzing provides another approach to exercising protocol interactions~\cite{fuzztructionnet2024}.
- 当前句：Nyx-Net uses incremental snapshots for network fuzzing~\cite{nyxnet2022}; SnapFuzz targets high-throughput execution of network applications~\cite{snapfuzz2022}; fault-injection-based network fuzzing provides another approach to exercising protocol interactions~\cite{fuzztructionnet2024}.
- 原文位置：[4, 5, 6] / 3.1--3.5, fault injection into protocol peer（PDF page including cover）
- 核查说明：Mutates peer program operations while retaining session/integrity handling; manuscript claim stays at mechanism level.
- 来源记录：[retrieval.json](sources/fuzztructionnet2024/retrieval.json)

### C010:blueman2025 — main.revised.tex:139

- 状态：supported；本地全文
- 原句：BLuEMan simulates interactions between actual Bluetooth Low Energy (BLE) stacks~\cite{blueman2025}.
- 当前句：BLuEMan simulates interactions between actual Bluetooth Low Energy (BLE) stacks~\cite{blueman2025}.
- 原文位置：[3, 4] / Design overview; simulated BLE boards（PDF page including cover）
- 核查说明：真实 BLE 协议栈在物理层仿真环境中交互；保留 simulations 的限定，不将其写成物理硬件实测。
- 来源记录：[retrieval.json](sources/blueman2025/retrieval.json)

### C011:distfuzz2025 — main.revised.tex:139

- 状态：supported；本地全文
- 原句：DistFuzz combines events, faults, and timing with message-sequence feedback and symmetry-based pruning for distributed systems~\cite{distfuzz2025}.
- 当前句：DistFuzz combines events, faults, and timing with message-sequence feedback and symmetry-based pruning for distributed systems~\cite{distfuzz2025}.
- 原文位置：[2, 3, 4] / Table I and architecture（PDF page including cover）
- 核查说明：常规事件、故障事件和时间间隔；消息序列反馈与对称性剪枝。原句各机制均有全文支持。
- 来源记录：[retrieval.json](sources/distfuzz2025/retrieval.json)

### C012:gramatron_effective_grammar_aware_2021 — main.revised.tex:141

- 状态：attribution_split；本地全文
- 原句：Gramatron and CarpetFuzz exploit grammars and documented constraints~\cite{gramatron_effective_grammar_aware_2021,carpetfuzz_documentation_2023}.
- 当前句：Gramatron generates inputs through grammar automata~\cite{gramatron_effective_grammar_aware_2021}; CarpetFuzz extracts option constraints from documentation~\cite{carpetfuzz_documentation_2023}.
- 原文位置：[2, 3, 4] / Sections 2--3, grammar automata（PDF page including cover）
- 核查说明：将 CFG 转为自动机进行生成和变异；已拆开与 CarpetFuzz 的合并引证，避免两篇都支持同一组机制的歧义。
- 来源记录：[retrieval.json](sources/gramatron_effective_grammar_aware_2021/retrieval.json)

### C013:carpetfuzz_documentation_2023 — main.revised.tex:141

- 状态：attribution_split；本地全文
- 原句：Gramatron and CarpetFuzz exploit grammars and documented constraints~\cite{gramatron_effective_grammar_aware_2021,carpetfuzz_documentation_2023}.
- 当前句：Gramatron generates inputs through grammar automata~\cite{gramatron_effective_grammar_aware_2021}; CarpetFuzz extracts option constraints from documentation~\cite{carpetfuzz_documentation_2023}.
- 原文位置：[3, 4] / Challenges and option constraints（PDF page including cover）
- 核查说明：从自然语言文档抽取选项冲突/依赖关系；已单独陈述，未将其误归为通用语法自动机。
- 来源记录：[retrieval.json](sources/carpetfuzz_documentation_2023/retrieval.json)

### C014:formatfuzzer — main.revised.tex:141

- 状态：supported；本地全文
- 原句：FormatFuzzer derives parsers, mutators, and generators from binary-format specifications~\cite{formatfuzzer}; Fuzztruction instead injects faults into a generating program to retain implicit format knowledge~\cite{fuzztruction2023}.
- 当前句：FormatFuzzer derives parsers, mutators, and generators from binary-format specifications~\cite{formatfuzzer}; Fuzztruction instead injects faults into a generating program to retain implicit format knowledge~\cite{fuzztruction2023}.
- 原文位置：[2, 4] / Binary templates and format-aware fuzzing（PDF page including cover）
- 核查说明：输入为二进制格式模板，可构建生成器、解析器和变异器；不据此主张无须人工模板精化。
- 来源记录：[retrieval.json](sources/formatfuzzer/retrieval.json)

### C015:fuzztruction2023 — main.revised.tex:141

- 状态：supported；本地全文
- 原句：FormatFuzzer derives parsers, mutators, and generators from binary-format specifications~\cite{formatfuzzer}; Fuzztruction instead injects faults into a generating program to retain implicit format knowledge~\cite{fuzztruction2023}.
- 当前句：FormatFuzzer derives parsers, mutators, and generators from binary-format specifications~\cite{formatfuzzer}; Fuzztruction instead injects faults into a generating program to retain implicit format knowledge~\cite{fuzztruction2023}.
- 原文位置：[3, 4] / Sections 2--3, generator fault injection（PDF page including cover）
- 核查说明：在输入生成程序中注入故障，利用隐含格式约束生成测试输入；原句为机制描述。
- 来源记录：[retrieval.json](sources/fuzztruction2023/retrieval.json)

### C016:miner2023 — main.revised.tex:141

- 状态：supported；本地全文
- 原句：MINER uses valid sequence templates and learned request parameters to guide later requests~\cite{miner2023}.
- 当前句：MINER uses valid sequence templates and learned request parameters to guide later requests~\cite{miner2023}.
- 原文位置：[2, 3, 4] / Overview; REST API sequence generation（PDF page including cover）
- 核查说明：保留有效请求序列作为模板并偏向较长序列；学习关键请求参数。原句未将其等同长期队列代码收益验证。
- 来源记录：[retrieval.json](sources/miner2023/retrieval.json)

### C017:chatafl — main.revised.tex:143

- 状态：supported；本地全文
- 原句：LLM-assisted fuzzing extends generation to protocol interactions, device inputs, and programs~\cite{chatafl,llmif_augmented_large_language_2024,fuzz4all_universal_fuzzing_large_2024}.
- 当前句：ChatAFL uses LLMs for protocol-message generation~\cite{chatafl}; LLMIF derives device-testing inputs from protocol specifications~\cite{llmif_augmented_large_language_2024}; Fuzz4All generates and mutates program inputs across languages~\cite{fuzz4all_universal_fuzzing_large_2024}.
- 原文位置：[2, 5, 8, 9] / IV, LLM-guided protocol fuzzing（PDF page including cover）
- 核查说明：Grammar extraction, initial-seed message enrichment, and plateau-triggered message generation support both occurrences. Does not validate LoopFuzz admission effects.
- 来源记录：[retrieval.json](sources/chatafl/retrieval.json)

### C018:llmif_augmented_large_language_2024 — main.revised.tex:143

- 状态：attribution_split；本地全文
- 原句：LLM-assisted fuzzing extends generation to protocol interactions, device inputs, and programs~\cite{chatafl,llmif_augmented_large_language_2024,fuzz4all_universal_fuzzing_large_2024}.
- 当前句：ChatAFL uses LLMs for protocol-message generation~\cite{chatafl}; LLMIF derives device-testing inputs from protocol specifications~\cite{llmif_augmented_large_language_2024}; Fuzz4All generates and mutates program inputs across languages~\cite{fuzz4all_universal_fuzzing_large_2024}.
- 原文位置：[2, 4] / Specification extraction and algorithm overview（PDF page including cover）
- 核查说明：抽取消息格式、字段值、头部结构及依赖来生成设备测试输入；已与 ChatAFL/Fuzz4All 分开逐项引证。
- 来源记录：[retrieval.json](sources/llmif_augmented_large_language_2024/retrieval.json)

### C019:fuzz4all_universal_fuzzing_large_2024 — main.revised.tex:143

- 状态：attribution_split；本地全文
- 原句：LLM-assisted fuzzing extends generation to protocol interactions, device inputs, and programs~\cite{chatafl,llmif_augmented_large_language_2024,fuzz4all_universal_fuzzing_large_2024}.
- 当前句：ChatAFL uses LLMs for protocol-message generation~\cite{chatafl}; LLMIF derives device-testing inputs from protocol specifications~\cite{llmif_augmented_large_language_2024}; Fuzz4All generates and mutates program inputs across languages~\cite{fuzz4all_universal_fuzzing_large_2024}.
- 原文位置：[2, 3, 4] / Autoprompting and fuzzing loop（PDF page including cover）
- 核查说明：跨多种程序输入语言，以自动提示、生成和变异开展测试；不声称已验证所有协议类型。
- 来源记录：[retrieval.json](sources/fuzz4all_universal_fuzzing_large_2024/retrieval.json)

### C020:fuzzgpt2024 — main.revised.tex:143

- 状态：version_limited；早期版本；待最终版
- 原句：FuzzGPT studies unusual programs for deep-learning libraries~\cite{fuzzgpt2024}, and WhiteFox uses compiler source information to guide optimization-triggering tests~\cite{whitefox2024}.
- 当前句：FuzzGPT studies unusual programs for deep-learning libraries~\cite{fuzzgpt2024}, and WhiteFox uses compiler source information to guide optimization-triggering tests~\cite{whitefox2024}.
- 原文位置：[2, 3, 5] / Historical bug programs; in-context learning/fine-tuning（PDF page including cover）
- 核查说明：可用 2023 作者稿题名不同但六位作者及 FuzzGPT 方法对应；支持当前 unusual programs 的窄表述。正式 ICSE 2024 版尚未逐页比对。
- 来源记录：[retrieval.json](sources/fuzzgpt2024/retrieval.json)

### C021:whitefox2024 — main.revised.tex:143

- 状态：supported；本地全文
- 原句：FuzzGPT studies unusual programs for deep-learning libraries~\cite{fuzzgpt2024}, and WhiteFox uses compiler source information to guide optimization-triggering tests~\cite{whitefox2024}.
- 当前句：FuzzGPT studies unusual programs for deep-learning libraries~\cite{fuzzgpt2024}, and WhiteFox uses compiler source information to guide optimization-triggering tests~\cite{whitefox2024}.
- 原文位置：[3, 4] / Motivating example; source-derived requirements（PDF page including cover）
- 核查说明：利用优化器源代码总结触发条件并生成相应测试；原句获得支持，不推出 LoopFuzz 性能。
- 来源记录：[retrieval.json](sources/whitefox2024/retrieval.json)

### C022:prophetfuzz2024 — main.revised.tex:143

- 状态：supported；本地全文
- 原句：ProphetFuzz predicts high-risk option combinations from documentation~\cite{prophetfuzz2024}.
- 当前句：ProphetFuzz predicts high-risk option combinations from documentation~\cite{prophetfuzz2024}.
- 原文位置：[2, 4] / Documentation constraints and few-shot option prediction（PDF page including cover）
- 核查说明：依据文档及示例预测高风险选项组合；当前表述没有声称纯零样本或未经验证即可认定漏洞。
- 来源记录：[retrieval.json](sources/prophetfuzz2024/retrieval.json)

### C023:hybridllm2026 — main.revised.tex:143

- 状态：supported；本地全文
- 原句：Recent studies also address LLM-assisted hybrid fuzzing~\cite{hybridllm2026} and predicate-guided synthesis for directed testing~\cite{hgfuzzer2026}.
- 当前句：Recent studies also address LLM-assisted hybrid fuzzing~\cite{hybridllm2026} and LLM-assisted directed greybox fuzzing~\cite{hgfuzzer2026}.
- 原文位置：[2, 3, 4] / Section III, LLM-assisted concolic execution（PDF page including cover）
- 核查说明：HyLLfuzz 在灰盒覆盖平台期使用 LLM 辅助 concolic 执行；当前 hybrid fuzzing 概述得到支持，来源为作者稿。
- 来源记录：[retrieval.json](sources/hybridllm2026/retrieval.json)

### C024:hgfuzzer2026 — main.revised.tex:143

- 状态：version_limited；早期版本；待最终版
- 原句：Recent studies also address LLM-assisted hybrid fuzzing~\cite{hybridllm2026} and predicate-guided synthesis for directed testing~\cite{hgfuzzer2026}.
- 当前句：Recent studies also address LLM-assisted hybrid fuzzing~\cite{hybridllm2026} and LLM-assisted directed greybox fuzzing~\cite{hgfuzzer2026}.
- 原文位置：[2, 4] / Path conditions, harness generation, target-specific mutators（PDF page including cover）
- 核查说明：取得 2025 三作者预印本，正式 2026 条目为四作者。已删除更具体的 predicate-guided synthesis，保留 LLM-assisted directed greybox fuzzing；正式版机制仍待比对。
- 来源记录：[retrieval.json](sources/hgfuzzer2026/retrieval.json)

### C025:bandits_states2023 — main.revised.tex:145

- 状态：novelty_boundary_clarified；本地全文
- 原句：The Bandit's States models protocol-state selection as a bandit problem~\cite{bandits_states2023}; Thompson-sampling seed scheduling~\cite{zhang2026thompson} and state-significance-guided protocol fuzzing~\cite{ssgfuzz2026} further delimit the contribution.
- 当前句：The Bandit's States models protocol-state selection as a bandit problem~\cite{bandits_states2023}.
- 原文位置：[2, 3, 4] / Sections 3--4, state-selection bandit formulation（PDF page including cover）
- 核查说明：已有协议状态 bandit 建模，讨论非平稳奖励，初步结果弱于 AFLNet。本文不得将 bandit 或代码反馈本身称为创新；表格已改为组合边界。
- 来源记录：[retrieval.json](sources/bandits_states2023/retrieval.json)

### C026:tscheduler2024 — main.revised.tex:145

- 状态：required_prior_work_added；本地全文
- 原句：（本轮新增必需文献）
- 当前句：T-Scheduler combines Beta--Bernoulli estimation with Thompson sampling for seed scheduling~\cite{tscheduler2024}; Zhang et al.
- 原文位置：[1, 4, 5] / Section 3.2; Algorithm 1（PDF page including cover）
- 核查说明：要求文件所指为 Luo 等 AsiaCCS 2024，非 Zhang 2026。Beta 参数更新、Thompson 抽样及覆盖特征稀有度修正在算法中明确；已补入正文及边界表，正式元数据由 Crossref 核对。
- 来源记录：[retrieval.json](sources/tscheduler2024/retrieval.json)

### C027:zhang2026thompson — main.revised.tex:145

- 状态：fulltext_unresolved；全文未取得
- 原句：The Bandit's States models protocol-state selection as a bandit problem~\cite{bandits_states2023}; Thompson-sampling seed scheduling~\cite{zhang2026thompson} and state-significance-guided protocol fuzzing~\cite{ssgfuzz2026} further delimit the contribution.
- 当前句：T-Scheduler combines Beta--Bernoulli estimation with Thompson sampling for seed scheduling~\cite{tscheduler2024}; Zhang et al. also study Thompson-sampling seed scheduling~\cite{zhang2026thompson}.
- 原文位置：[] / None（PDF page including cover）
- 核查说明：出版记录已核实，但完整原文仍未取得；不得将题名/摘要/项目说明当作全文审查通过。保留窄范围已知表述，待原文补证。
- 来源记录：[retrieval.json](sources/zhang2026thompson/retrieval.json)

### C028:ssgfuzz2026 — main.revised.tex:145

- 状态：fulltext_unresolved；全文未取得
- 原句：The Bandit's States models protocol-state selection as a bandit problem~\cite{bandits_states2023}; Thompson-sampling seed scheduling~\cite{zhang2026thompson} and state-significance-guided protocol fuzzing~\cite{ssgfuzz2026} further delimit the contribution.
- 当前句：SSGFuzz studies state-significance-guided protocol fuzzing~\cite{ssgfuzz2026}.
- 原文位置：[] / None（PDF page including cover）
- 核查说明：出版记录已核实，但完整原文仍未取得；不得将题名/摘要/项目说明当作全文审查通过。保留窄范围已知表述，待原文补证。
- 来源记录：[retrieval.json](sources/ssgfuzz2026/retrieval.json)

### C029:fox2024 — main.revised.tex:145

- 状态：supported；本地全文
- 原句：FOX formulates coverage-guided fuzzing as online stochastic control~\cite{fox2024}, while FISHFUZZ dynamically prioritizes targets and seeds using distance information~\cite{fishfuzz2023}.
- 当前句：FOX formulates coverage-guided fuzzing as online stochastic control~\cite{fox2024}, while FISHFUZZ dynamically prioritizes targets and seeds using distance information~\cite{fishfuzz2023}.
- 原文位置：[3, 4] / Section 2, online stochastic control formulation（PDF page including cover）
- 核查说明：将覆盖引导变异模糊测试建模为在线优化/随机控制，目标为期望代码覆盖收益；原句准确。
- 来源记录：[retrieval.json](sources/fox2024/retrieval.json)

### C030:fishfuzz2023 — main.revised.tex:145

- 状态：supported；本地全文
- 原句：FOX formulates coverage-guided fuzzing as online stochastic control~\cite{fox2024}, while FISHFUZZ dynamically prioritizes targets and seeds using distance information~\cite{fishfuzz2023}.
- 当前句：FOX formulates coverage-guided fuzzing as online stochastic control~\cite{fox2024}, while FISHFUZZ dynamically prioritizes targets and seeds using distance information~\cite{fishfuzz2023}.
- 原文位置：[2, 3] / Overview of multi-distance and dynamic prioritization（PDF page including cover）
- 核查说明：多距离指标、动态目标排序和队列裁剪共同引导探索/利用；原句的距离优先化表述可保留。
- 来源记录：[retrieval.json](sources/fishfuzz2023/retrieval.json)

### C031:wingmuzz2025 — main.revised.tex:145

- 状态：fulltext_unresolved；全文未取得
- 原句：WingMuzz studies two-dimensional scheduling for blackbox protocol testing~\cite{wingmuzz2025}.
- 当前句：WingMuzz studies two-dimensional scheduling for blackbox protocol testing~\cite{wingmuzz2025}.
- 原文位置：[] / None（PDF page including cover）
- 核查说明：出版记录已核实，但完整原文仍未取得；不得将题名/摘要/项目说明当作全文审查通过。保留窄范围已知表述，待原文补证。
- 来源记录：[retrieval.json](sources/wingmuzz2025/retrieval.json)

### C032:protocolguard2026 — main.revised.tex:147

- 状态：supported；本地全文
- 原句：ProtocolGuard combines specification-derived checks with dynamic verification of non-compliance~\cite{protocolguard2026}; BSFuzzer uses context-aware semantic testing for BLE logic flaws~\cite{bsfuzzer2026}; MerCuriuzz targets logical vulnerabilities in QUIC implementations~\cite{mercuriuzz2026}.
- 当前句：ProtocolGuard combines specification-derived checks with dynamic verification of non-compliance~\cite{protocolguard2026}; BSFuzzer uses context-aware semantic testing for BLE logic flaws~\cite{bsfuzzer2026}; MerCuriuzz targets logical vulnerabilities in QUIC implementations~\cite{mercuriuzz2026}.
- 原文位置：[2, 3, 4] / Specification rules and dynamic verification（PDF page including cover）
- 核查说明：规范性要求形成规则，结合代码分析定位不一致，再进行动态验证；当前表述支持语义正确性与覆盖奖励的区分。
- 来源记录：[retrieval.json](sources/protocolguard2026/retrieval.json)

### C033:bsfuzzer2026 — main.revised.tex:147

- 状态：supported；本地全文
- 原句：ProtocolGuard combines specification-derived checks with dynamic verification of non-compliance~\cite{protocolguard2026}; BSFuzzer uses context-aware semantic testing for BLE logic flaws~\cite{bsfuzzer2026}; MerCuriuzz targets logical vulnerabilities in QUIC implementations~\cite{mercuriuzz2026}.
- 当前句：ProtocolGuard combines specification-derived checks with dynamic verification of non-compliance~\cite{protocolguard2026}; BSFuzzer uses context-aware semantic testing for BLE logic flaws~\cite{bsfuzzer2026}; MerCuriuzz targets logical vulnerabilities in QUIC implementations~\cite{mercuriuzz2026}.
- 原文位置：[2, 3, 4] / Semantic extraction and state-machine violations（PDF page including cover）
- 核查说明：从 BLE 规范提取语义约束、状态信息，并合成上下文感知测试检测逻辑缺陷；原句范围准确。
- 来源记录：[retrieval.json](sources/bsfuzzer2026/retrieval.json)

### C034:mercuriuzz2026 — main.revised.tex:147

- 状态：supported；本地全文
- 原句：ProtocolGuard combines specification-derived checks with dynamic verification of non-compliance~\cite{protocolguard2026}; BSFuzzer uses context-aware semantic testing for BLE logic flaws~\cite{bsfuzzer2026}; MerCuriuzz targets logical vulnerabilities in QUIC implementations~\cite{mercuriuzz2026}.
- 当前句：ProtocolGuard combines specification-derived checks with dynamic verification of non-compliance~\cite{protocolguard2026}; BSFuzzer uses context-aware semantic testing for BLE logic flaws~\cite{bsfuzzer2026}; MerCuriuzz targets logical vulnerabilities in QUIC implementations~\cite{mercuriuzz2026}.
- 原文位置：[2, 3, 4] / Section IV; QUIC logical vulnerabilities（PDF page including cover）
- 核查说明：目标为 QUIC 实现逻辑漏洞，区分响应违例、资源异常与通用内存崩溃；不能将覆盖增长视为漏洞证明。
- 来源记录：[retrieval.json](sources/mercuriuzz2026/retrieval.json)

### C035:magma2020 — main.revised.tex:147

- 状态：supported；本地全文
- 原句：Magma's ground-truth bug conditions motivate distinguishing bug-related reachability from triggering~\cite{magma2020}; our historical vulnerability protocol additionally requires patch validation and controlled information exposure.
- 当前句：Magma's ground-truth bug conditions motivate distinguishing bug-related reachability from triggering~\cite{magma2020}; our historical vulnerability protocol additionally requires patch validation and controlled information exposure.
- 原文位置：[2, 8, 10] / Sections 4 and 4.3, ground-truth metrics（PDF page including cover）
- 核查说明：原文区分 reached、triggered 与 detected；故障位置被覆盖不等于触发。补丁配对和提示信息控制属于本文协议，未归为 Magma 原有规则。
- 来源记录：[retrieval.json](sources/magma2020/retrieval.json)

### C036:profuzzbench_benchmark_stateful_protocol_2021 — main.revised.tex:149

- 状态：supported；本地全文
- 原句：ProFuzzBench and FuzzBench provide structured evaluation settings for protocol and general-purpose fuzzers~\cite{profuzzbench_benchmark_stateful_protocol_2021,fuzzbench2021}.
- 当前句：ProFuzzBench and FuzzBench provide structured evaluation settings for protocol and general-purpose fuzzers~\cite{profuzzbench_benchmark_stateful_protocol_2021,fuzzbench2021}.
- 原文位置：[2, 3, 4] / Benchmark workflow and reproducibility（PDF page including cover）
- 核查说明：协议目标、构建/运行/分析流程及确定性挑战支持协议 fuzzer 评测平台的陈述。
- 来源记录：[retrieval.json](sources/profuzzbench_benchmark_stateful_protocol_2021/retrieval.json)

### C036:fuzzbench2021 — main.revised.tex:149

- 状态：supported；本地全文
- 原句：ProFuzzBench and FuzzBench provide structured evaluation settings for protocol and general-purpose fuzzers~\cite{profuzzbench_benchmark_stateful_protocol_2021,fuzzbench2021}.
- 当前句：ProFuzzBench and FuzzBench provide structured evaluation settings for protocol and general-purpose fuzzers~\cite{profuzzbench_benchmark_stateful_protocol_2021,fuzzbench2021}.
- 原文位置：[2, 3, 4] / Section 2, benchmark methodology（PDF page including cover）
- 核查说明：提供可重复实验、重复 trial 和统计报告。正文未把默认配置当作所有实验的唯一规范。
- 来源记录：[retrieval.json](sources/fuzzbench2021/retrieval.json)

### C037:reliability_benchmarking_2022 — main.revised.tex:149

- 状态：supported；本地全文
- 原句：Reliability analyses and prudent evaluation practices require care when interpreting coverage, repeated trials, and resource controls~\cite{reliability_benchmarking_2022,sok_prudent_evaluation_practices_2024}.
- 当前句：Reliability analyses and prudent evaluation practices require care when interpreting coverage, repeated trials, and resource controls~\cite{reliability_benchmarking_2022,sok_prudent_evaluation_practices_2024}.
- 原文位置：[2, 3, 4] / Research questions and proxy reliability（PDF page including cover）
- 核查说明：区别相关性与排名一致性；覆盖与漏洞数高度相关并不保证比较排序一致。当前谨慎解释覆盖的表述获得支持。
- 来源记录：[retrieval.json](sources/reliability_benchmarking_2022/retrieval.json)

### C037:sok_prudent_evaluation_practices_2024 — main.revised.tex:149

- 状态：supported；本地全文
- 原句：Reliability analyses and prudent evaluation practices require care when interpreting coverage, repeated trials, and resource controls~\cite{reliability_benchmarking_2022,sok_prudent_evaluation_practices_2024}.
- 当前句：Reliability analyses and prudent evaluation practices require care when interpreting coverage, repeated trials, and resource controls~\cite{reliability_benchmarking_2022,sok_prudent_evaluation_practices_2024}.
- 原文位置：[2, 3, 4] / Recommendations 4--5; evaluation review（PDF page including cover）
- 核查说明：不以覆盖/栈哈希单独充当漏洞结果，强调统计评估、重复和实验可重复性；不能替代本文尚未完成实验。
- 来源记录：[retrieval.json](sources/sok_prudent_evaluation_practices_2024/retrieval.json)

### C038:bandits_states2023 — main.revised.tex:161

- 状态：novelty_boundary_clarified；本地全文
- 原句：The Bandit's States~\cite{bandits_states2023} & Bandit-based protocol-state selection. & Prior bandit formulation; independent reward and queue evidence here. \\
- 当前句：The Bandit's States~\cite{bandits_states2023} & Bandit-based protocol-state selection. & Established selection framework; coupled proxy calibration and admission here. \\
- 原文位置：[2, 3, 4] / Sections 3--4, state-selection bandit formulation（PDF page including cover）
- 核查说明：已有协议状态 bandit 建模，讨论非平稳奖励，初步结果弱于 AFLNet。本文不得将 bandit 或代码反馈本身称为创新；表格已改为组合边界。
- 来源记录：[retrieval.json](sources/bandits_states2023/retrieval.json)

### C039:tscheduler2024 — main.revised.tex:162

- 状态：required_prior_work_added；本地全文
- 原句：（本轮新增必需文献）
- 当前句：T-Scheduler~\cite{tscheduler2024}; Zhang et al.~\cite{zhang2026thompson} & Thompson-sampling seed scheduling. & Established sampling principle; response-state episodes here. \\
- 原文位置：[1, 4, 5] / Section 3.2; Algorithm 1（PDF page including cover）
- 核查说明：要求文件所指为 Luo 等 AsiaCCS 2024，非 Zhang 2026。Beta 参数更新、Thompson 抽样及覆盖特征稀有度修正在算法中明确；已补入正文及边界表，正式元数据由 Crossref 核对。
- 来源记录：[retrieval.json](sources/tscheduler2024/retrieval.json)

### C040:zhang2026thompson — main.revised.tex:162

- 状态：fulltext_unresolved；全文未取得
- 原句：Zhang et al.~\cite{zhang2026thompson} & Thompson-sampling seed scheduling. & Reused Beta estimation and Thompson sampling. \\
- 当前句：T-Scheduler~\cite{tscheduler2024}; Zhang et al.~\cite{zhang2026thompson} & Thompson-sampling seed scheduling. & Established sampling principle; response-state episodes here. \\
- 原文位置：[] / None（PDF page including cover）
- 核查说明：出版记录已核实，但完整原文仍未取得；不得将题名/摘要/项目说明当作全文审查通过。保留窄范围已知表述，待原文补证。
- 来源记录：[retrieval.json](sources/zhang2026thompson/retrieval.json)

### C041:ssgfuzz2026 — main.revised.tex:163

- 状态：fulltext_unresolved；全文未取得
- 原句：SSGFuzz~\cite{ssgfuzz2026} & State-significance-guided fuzzing. & Code-productivity calibration, distinct from state importance. \\
- 当前句：SSGFuzz~\cite{ssgfuzz2026} & State-significance-guided fuzzing. & Our focus: response-proxy productivity and queue admission. \\
- 原文位置：[] / None（PDF page including cover）
- 核查说明：出版记录已核实，但完整原文仍未取得；不得将题名/摘要/项目说明当作全文审查通过。保留窄范围已知表述，待原文补证。
- 来源记录：[retrieval.json](sources/ssgfuzz2026/retrieval.json)

### C042:magma2020 — main.revised.tex:164

- 状态：supported；本地全文
- 原句：Magma~\cite{magma2020}; evaluation methodology & Ground-truth bug conditions; repeated evaluation. & Information-controlled network rediscovery; minimal security-patch pairs. \\
- 当前句：Magma~\cite{magma2020}; evaluation methodology & Ground-truth bug conditions; repeated evaluation. & Information-controlled network rediscovery; minimal security-patch pairs. \\
- 原文位置：[2, 8, 10] / Sections 4 and 4.3, ground-truth metrics（PDF page including cover）
- 核查说明：原文区分 reached、triggered 与 detected；故障位置被覆盖不等于触发。补丁配对和提示信息控制属于本文协议，未归为 Magma 原有规则。
- 来源记录：[retrieval.json](sources/magma2020/retrieval.json)

### C043:thompson1933 — main.revised.tex:321

- 状态：adaptation_clarified；本地全文
- 原句：Keeping this factor and any warm-up policy fixed prevents calibration from simultaneously changing the baseline scheduler. Using the Thompson-sampling principle~\cite{thompson1933}, draw
- 当前句：Keeping this factor and any warm-up policy fixed prevents calibration from simultaneously changing the baseline scheduler. Adapting posterior-guided randomization~\cite{thompson1933} to the discounted, frontier-weighted controller, draw
- 原文位置：[1, 2, 8] / Sections 1--3（PDF page including cover）
- 核查说明：原文以证据形成概率并据此随机分配；不证明本文的折扣、frontier 加权或比例采样形式。已明确这些是本文的适配。
- 来源记录：[retrieval.json](sources/thompson1933/retrieval.json)

### C044:greenbenchmark2023 — main.revised.tex:501

- 状态：supported；本地全文
- 原句：Resource-efficient benchmarking also makes the cost of obtaining reliable comparisons an explicit concern~\cite{greenbenchmark2023}.
- 当前句：Resource-efficient benchmarking also makes the cost of obtaining reliable comparisons an explicit concern~\cite{greenbenchmark2023}.
- 原文位置：[4, 7, 9] / Benchmark construction; resource/accuracy trade-off（PDF page including cover）
- 核查说明：以较短任务和随机化初始条件研究降低评测成本；正文只据此说明成本需要报告，没有把其流程当成本研究已执行。
- 来源记录：[retrieval.json](sources/greenbenchmark2023/retrieval.json)

### C045:brier1950 — main.revised.tex:546

- 状态：fulltext_unresolved；全文未取得
- 原句：The Brier score (BS)~\cite{brier1950} is
\begin{equation}
\mathrm{BS}=\frac{1}{n}\sum_{t=1}^{n}(p_t-r_t)^2.
- 当前句：The binary Brier score (BS)~\cite{brier1950} is
\begin{equation}
\mathrm{BS}=\frac{1}{n}\sum_{t=1}^{n}(p_t-r_t)^2.
- 原文位置：[] / None（PDF page including cover）
- 核查说明：出版记录已核实，但完整原文仍未取得；不得将题名/摘要/项目说明当作全文审查通过。保留窄范围已知表述，待原文补证。
- 来源记录：[retrieval.json](sources/brier1950/retrieval.json)

### C046:guo2017calibration — main.revised.tex:550

- 状态：adaptation_clarified；本地全文
- 原句：\end{equation}
Expected calibration error (ECE)~\cite{guo2017calibration} uses ten fixed equal-width probability bins and reports counts, mean predictions, and observed frequencies.
- 当前句：\end{equation}
We adapt the binned expected calibration error (ECE) of Guo et al.~\cite{guo2017calibration} to binary episode productivity: within ten fixed equal-width bins, we compare the mean predicted reward probability with the observed reward frequency and weight each absolute gap by its episode count.
- 原文位置：[2, 3] / 2, Definitions; Eqs. (1)--(3)（PDF page including cover）
- 核查说明：Original ECE compares predicted-label confidence with classification accuracy. Manuscript now explicitly adapts binning to binary reward probabilities versus observed reward frequencies; ten bins is a manuscript choice.
- 来源记录：[retrieval.json](sources/guo2017calibration/retrieval.json)

### C047:davis2006pr — main.revised.tex:550

- 状态：metric_distinction_fixed；本地全文
- 原句：Reliability plots and the area under the precision--recall curve (AUPRC)~\cite{davis2006pr} accompany the BS; with no positive episodes AUPRC is undefined.
- 当前句：Reliability plots and precision--recall analysis~\cite{davis2006pr} accompany the BS.
- 原文位置：[1, 2, 4] / ROC/PR relation and interpolation（PDF page including cover）
- 核查说明：原文强调 PR 分析及非线性插值；不证明任意 AUPRC 与非插值 AP 恒等。已统一报告实际实现的 AP，并写明与梯形积分不同。
- 来源记录：[retrieval.json](sources/davis2006pr/retrieval.json)

### C048:efron1979 — main.revised.tex:557

- 状态：resampling_scope_clarified；本地全文
- 原句：Per target, report mean, median, dispersion, bootstrap 95\% confidence intervals (CIs)~\cite{efron1979}, two-sided Mann--Whitney U tests~\cite{mann1947}, and Cliff's $\delta$~\cite{cliff1993}.
- 当前句：Bootstrap resampling~\cite{efron1979} operates on whole runs; the percentile 95\% confidence intervals (CIs) and resampling hierarchy are analysis choices specified here.
- 原文位置：[2, 3, 4] / Original pp. 1--3, Section 2 and Eqs. (2.1)--(2.5)（PDF page including cover）
- 核查说明：原文从独立样本的经验分布有放回重抽样以近似抽样分布。95% 百分位区间、整 run 和分层设计为本文选择，不能宣称原文保证当前依赖数据的覆盖率。扫描正文通过页面图像审阅。
- 来源记录：[retrieval.json](sources/efron1979/retrieval.json)

### C049:mann1947 — main.revised.tex:557

- 状态：inference_scope_clarified；浏览器全文（无本地 PDF）
- 原句：Per target, report mean, median, dispersion, bootstrap 95\% confidence intervals (CIs)~\cite{efron1979}, two-sided Mann--Whitney U tests~\cite{mann1947}, and Cliff's $\delta$~\cite{cliff1993}.
- 当前句：For independent run-level contrasts, report two-sided Mann--Whitney U tests~\cite{mann1947} with ties accounted for, and Cliff's $\delta$~\cite{cliff1993}, oriented as $\Pr(X_{\rm treatment}>X_{\rm comparator})-\Pr(X_{\rm treatment}<X_{\rm comparator})$.
- 原文位置：[2, 3] / Original pp. 50--51; Section 1（PDF page including cover）
- 核查说明：原文对两个独立连续分布的随机样本定义 U 统计量，非一般中位数差检验。协议现在明确 run 层独立性及并列值处理；全文通过浏览工具读取，未声称本地下载成功。
- 来源记录：[retrieval.json](sources/mann1947/retrieval.json)

### C050:cliff1993 — main.revised.tex:557

- 状态：effect_definition_clarified；浏览器全文（无本地 PDF）
- 原句：Per target, report mean, median, dispersion, bootstrap 95\% confidence intervals (CIs)~\cite{efron1979}, two-sided Mann--Whitney U tests~\cite{mann1947}, and Cliff's $\delta$~\cite{cliff1993}.
- 当前句：For independent run-level contrasts, report two-sided Mann--Whitney U tests~\cite{mann1947} with ties accounted for, and Cliff's $\delta$~\cite{cliff1993}, oriented as $\Pr(X_{\rm treatment}>X_{\rm comparator})-\Pr(X_{\rm treatment}<X_{\rm comparator})$.
- 原文位置：[494, 495, 496] / Original article pp. 494--496, independent-group dominance（printed journal pages）
- 核查说明：原文将组间优势定义为两方向概率之差，并讨论并列值及分布假设。正文明确 δ 的方向；所审为全文镜像转录，出版社 PDF 仍未取得。
- 来源记录：[retrieval.json](sources/cliff1993/retrieval.json)

### C051:benjamini1995 — main.revised.tex:557

- 状态：guarantee_qualified；本地全文
- 原句：The Benjamini--Hochberg procedure~\cite{benjamini1995} controls this family at $q=0.05$.
- 当前句：Apply the Benjamini--Hochberg procedure~\cite{benjamini1995} at nominal $q=0.05$.
- 原文位置：[2, 6, 12] / Theorem 1 and Appendix A（PDF page including cover）
- 核查说明：原始 FDR 保证针对独立检验统计量。本文共享比较组/相关覆盖终点未证明该条件；改为 nominal q 并删除无条件控制承诺。
- 来源记录：[retrieval.json](sources/benjamini1995/retrieval.json)

### C052:kaplan1958 — main.revised.tex:559

- 状态：assumption_added；本地全文
- 原句：Historical time-to-trigger uses Kaplan--Meier estimates~\cite{kaplan1958}, right censoring, and CVE-specific deadline recall.
- 当前句：Historical time-to-trigger uses Kaplan--Meier estimates~\cite{kaplan1958} under non-informative right censoring, alongside CVE-specific deadline recall.
- 原文位置：[2, 3] / Original pp. 457--458; Section 1.1（PDF page including cover）
- 核查说明：观察时限须独立于生存/触发时间的标准设定已核对；正文补入非信息性右删失限定并保留故障中断警告。
- 来源记录：[retrieval.json](sources/kaplan1958/retrieval.json)

### C053:benchmarkproperties — main.revised.tex:841

- 状态：supported；本地全文
- 原句：Benchmark properties can change the relative ranking of fuzzers: initial seed coverage and execution speed are empirically consequential covariates~\cite{benchmarkproperties}.
- 当前句：Benchmark properties can change the relative ranking of fuzzers: initial seed coverage and execution speed are empirically consequential covariates~\cite{benchmarkproperties}.
- 原文位置：[6, 7, 8, 9] / Controlled covariates and holistic benchmarking（PDF page including cover）
- 核查说明：初始种子覆盖和执行速度会影响相对表现与排名；正文不将其推广为任何不受控 endpoint 都能给因果解释。
- 来源记录：[retrieval.json](sources/benchmarkproperties/retrieval.json)

### C054:mutationassessment2023 — main.revised.tex:841

- 状态：supported；本地全文
- 原句：Mutation-based assessment offers a complementary fault-oriented perspective~\cite{mutationassessment2023}; here, code coverage and IPSM growth are kept separate from independently verified vulnerability outcomes.
- 当前句：Mutation-based assessment offers a complementary fault-oriented perspective~\cite{mutationassessment2023}; here, code coverage and IPSM growth are kept separate from independently verified vulnerability outcomes.
- 原文位置：[2, 3, 4] / Mutation analysis and fault detection（PDF page including cover）
- 核查说明：评估检测注入故障的能力，补充覆盖度指标；本文未声称自己已完成 mutation-based 实验。
- 来源记录：[retrieval.json](sources/mutationassessment2023/retrieval.json)

## 编译与文件完整性

- 编译通过，23 页；51 个引文目标、59 个文献链接；无悬空链接。
- 无未定义引用、Overfull 越界和致命 LaTeX 错误。仍有 7 条非致命 Underfull 提示，不能据此声称完成了新的全篇视觉排版检查。
- 4 条 BibTeX 缺页码提示保留：DistFuzz、ProtocolGuard、BSFuzzer、MerCuriuzz。未将 PDF 文件页数擅自当会议出版页码。
- 结果章节仅调整 AP 名称；实验表输入和 first_paper.md 的 SHA-256 与开始时完全相同。
- 逐项验证见 [validation.json](validation.json)；文稿差异见 [main.revised.tex.diff](main.revised.tex.diff)。

## 后续关闭条件

须取得并核查五篇缺失全文，并比对 FuzzGPT、HGFuzzer 的正式版。对来源镜像的严格出版版本复核，还需补存 Mann–Whitney 和 Cliff 的可信最终版 PDF。完成这些条件前，不能声称“50 篇正式版全文逐句审查全部通过”。
