# 参考文献真实性逐条核验（2026-09-30）

## 结论

当前 main.revised.tex 实际加载 references.expanded.bib，共 50 条，全部在正文引用并进入 PDF。50 条均找到相应外部出版记录，未发现凭空杜撰或 DOI 指向完全无关论文的条目。文献存在性与全部书目字段准确性、正文引用准确性分别判断。

- 42 条 DOI：本轮实时 Crossref DOI 查询均返回对应记录，题名、作者完整姓名、出版信息结合原始缓存逐项复核。
- 8 条无 DOI：7 条 USENIX、1 条 PMLR，实时官方页面中的 BibTeX 题名、作者、年份、页码和会议逐项核对通过；不以 HTTP 200 单独认定真实性。
- 无重复 DOI、重复规范化题名或未引用条目。

## 确切修正

ProtocolGuard 的 Crossref 作者记录将 Xiaofeng Liu 重复列在第 7 位和第 10 位；当前 BibTeX 原样继承了这一错误。NDSS 官方作者页仅列 9 人且 Xiaofeng Liu 只出现一次。本轮已删除末尾重复作者，重新编译 PDF；正文和实验数据未改变。

[NDSS 官方作者页](https://www.ndss-symposium.org/ndss-paper/protocolguard-detecting-protocol-non-compliance-bugs-via-llm-guided-static-analysis-and-dynamic-verification/)；抓取证据见 official/protocolguard2026.html。

## 需要保留的说明

- Magma、Nyx-net、The Closer You Look, The More You Learn：Crossref 将主标题与副标题分字段存储；合并后与 BibTeX 完整题名一致。
- FormatFuzzer：Crossref 题名含 scp 展示标签；去除标签后对应。以上四项是初始匹配脚本的表示差异，不是虚假文献。
- SSGFuzz：首次上线为 2025-07-09，正式出版年为 2026。当前按出版社推荐引用使用 2026，不应据此声称该工作到 2026 年才首次出现。
- HGFuzzer：记录显示 2026-08-22 在线发表，尚未获得卷期页码；当前保留在线发表状态。
- Fuzz4All：完整姓名 Jia Le Tian 可对应，Crossref 的 given=Jia、family=Le Tian 与当前 BibTeX 姓名解析不同。本轮未擅自更改姓氏拆分；姓名格式仍需依据作者/出版社推荐引用确认。
- pages 字段为空的条目共七条：StateAFL 已使用文章号 191，HGFuzzer 保留在线发表状态；其余五条为 Efron (1979)、DistFuzz、ProtocolGuard、BSFuzzer、QUIC 逻辑漏洞论文。已取得的元数据未给出可用页码，不能据此断言论文原文没有页码。Project Euclid 本轮返回短页面，未将其用作补页码证据。
- first_paper.md 点名的 T-Scheduler 身份仍未确认；当前 Zhang 等的 Thompson-sampling 种子调度论文确实存在，但没有足够证据证明二者是同一个工作。该要求仍不能宣称已完全满足。

## 逐条清单

所有 DOI 条目均有实时查询记录；其中四个题名表示差异已用 subtitle 字段或标签规范化解释。编号按下表顺序，不冒充 PDF 中的引用编号。

| 序号 | 引用 key | 完整题名 | 年份 | 一手来源 |
|---:|---|---|---:|---|
| 1 | sgf_usenix22 | Stateful Greybox Fuzzing | 2022 | [官方页面](https://www.usenix.org/conference/usenixsecurity22/presentation/ba) |
| 2 | aflnet | AFLNet: A Greybox Fuzzer for Network Protocols | 2020 | [10.1109/ICST46399.2020.00062](https://doi.org/10.1109/ICST46399.2020.00062) |
| 3 | chatafl | Large Language Model Guided Protocol Fuzzing | 2024 | [10.14722/ndss.2024.24556](https://doi.org/10.14722/ndss.2024.24556) |
| 4 | stateafl | StateAFL: Greybox fuzzing for stateful network servers | 2022 | [10.1007/s10664-022-10233-3](https://doi.org/10.1007/s10664-022-10233-3) |
| 5 | nsfuzz | NSFuzz: Towards Efficient and State-Aware Network Service Fuzzing | 2023 | [10.1145/3580598](https://doi.org/10.1145/3580598) |
| 6 | fuzz4all_universal_fuzzing_large_2024 | Fuzz4All: Universal Fuzzing with Large Language Models | 2024 | [10.1145/3597503.3639121](https://doi.org/10.1145/3597503.3639121) |
| 7 | gramatron_effective_grammar_aware_2021 | Gramatron: effective grammar-aware fuzzing | 2021 | [10.1145/3460319.3464814](https://doi.org/10.1145/3460319.3464814) |
| 8 | sok_prudent_evaluation_practices_2024 | SoK: Prudent Evaluation Practices for Fuzzing | 2024 | [10.1109/sp54263.2024.00137](https://doi.org/10.1109/sp54263.2024.00137) |
| 9 | profuzzbench_benchmark_stateful_protocol_2021 | ProFuzzBench: A Benchmark for Stateful Protocol Fuzzing | 2021 | [10.1145/3460319.3469077](https://doi.org/10.1145/3460319.3469077) |
| 10 | llmif_augmented_large_language_2024 | LLMIF: Augmented Large Language Model for Fuzzing IoT Devices | 2024 | [10.1109/sp54263.2024.00211](https://doi.org/10.1109/sp54263.2024.00211) |
| 11 | reliability_benchmarking_2022 | On the Reliability of Coverage-Based Fuzzer Benchmarking | 2022 | [10.1145/3510003.3510230](https://doi.org/10.1145/3510003.3510230) |
| 12 | carpetfuzz_documentation_2023 | CarpetFuzz: Automatic Program Option Constraint Extraction from Documentation for Fuzzing | 2023 | [官方页面](https://www.usenix.org/conference/usenixsecurity23/presentation/wang-dawei) |
| 13 | bandits_states2023 | The Bandit's States: Modeling State Selection for Stateful Network Fuzzing as Multi-armed Bandit Problem | 2023 | [10.1109/EuroSPW59978.2023.00043](https://doi.org/10.1109/EuroSPW59978.2023.00043) |
| 14 | ssgfuzz2026 | State Significance-Guided Fuzzing for Stateful Protocol Program | 2026 | [10.1007/978-3-031-98208-8_21](https://doi.org/10.1007/978-3-031-98208-8_21) |
| 15 | magma2020 | Magma: A Ground-Truth Fuzzing Benchmark | 2020 | [10.1145/3428334](https://doi.org/10.1145/3428334) |
| 16 | thompson1933 | On the likelihood that one unknown probability exceeds another in view of the evidence of two samples | 1933 | [10.1093/biomet/25.3-4.285](https://doi.org/10.1093/biomet/25.3-4.285) |
| 17 | brier1950 | Verification of forecasts expressed in terms of probability | 1950 | [10.1175/1520-0493(1950)078<0001:VOFEIT>2.0.CO;2](https://doi.org/10.1175/1520-0493%281950%29078%3C0001%3AVOFEIT%3E2.0.CO%3B2) |
| 18 | guo2017calibration | On Calibration of Modern Neural Networks | 2017 | [官方页面](https://proceedings.mlr.press/v70/guo17a.html) |
| 19 | benjamini1995 | Controlling the False Discovery Rate: A Practical and Powerful Approach to Multiple Testing | 1995 | [10.1111/j.2517-6161.1995.tb02031.x](https://doi.org/10.1111/j.2517-6161.1995.tb02031.x) |
| 20 | kaplan1958 | Nonparametric Estimation from Incomplete Observations | 1958 | [10.1080/01621459.1958.10501452](https://doi.org/10.1080/01621459.1958.10501452) |
| 21 | mann1947 | On a Test of Whether One of Two Random Variables is Stochastically Larger than the Other | 1947 | [10.1214/aoms/1177730491](https://doi.org/10.1214/aoms/1177730491) |
| 22 | cliff1993 | Dominance statistics: Ordinal analyses to answer ordinal questions | 1993 | [10.1037/0033-2909.114.3.494](https://doi.org/10.1037/0033-2909.114.3.494) |
| 23 | efron1979 | Bootstrap Methods: Another Look at the Jackknife | 1979 | [10.1214/aos/1176344552](https://doi.org/10.1214/aos/1176344552) |
| 24 | davis2006pr | The relationship between Precision-Recall and ROC curves | 2006 | [10.1145/1143844.1143874](https://doi.org/10.1145/1143844.1143874) |
| 25 | zhang2026thompson | A novel seed scheduling scheme using Thompson sampling for coverage-guided greybox fuzzing | 2026 | [10.1016/j.jss.2026.112794](https://doi.org/10.1016/j.jss.2026.112794) |
| 26 | aflnet5years2025 | AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing | 2025 | [10.1109/tse.2025.3535925](https://doi.org/10.1109/tse.2025.3535925) |
| 27 | nyxnet2022 | Nyx-net: network fuzzing with incremental snapshots | 2022 | [10.1145/3492321.3519591](https://doi.org/10.1145/3492321.3519591) |
| 28 | snapfuzz2022 | SnapFuzz: high-throughput fuzzing of network applications | 2022 | [10.1145/3533767.3534376](https://doi.org/10.1145/3533767.3534376) |
| 29 | fuzztructionnet2024 | No Peer, no Cry: Network Application Fuzzing via Fault Injection | 2024 | [10.1145/3658644.3690274](https://doi.org/10.1145/3658644.3690274) |
| 30 | fox2024 | FOX: Coverage-guided Fuzzing as Online Stochastic Control | 2024 | [10.1145/3658644.3670362](https://doi.org/10.1145/3658644.3670362) |
| 31 | prophetfuzz2024 | ProphetFuzz: Fully Automated Prediction and Fuzzing of High-Risk Option Combinations with Only Documentation via Large Language Model | 2024 | [10.1145/3658644.3690231](https://doi.org/10.1145/3658644.3690231) |
| 32 | whitefox2024 | WhiteFox: White-Box Compiler Fuzzing Empowered by Large Language Models | 2024 | [10.1145/3689736](https://doi.org/10.1145/3689736) |
| 33 | fuzzgpt2024 | Large Language Models are Edge-Case Generators: Crafting Unusual Programs for Fuzzing Deep Learning Libraries | 2024 | [10.1145/3597503.3623343](https://doi.org/10.1145/3597503.3623343) |
| 34 | formatfuzzer | FormatFuzzer: Effective Fuzzing of Binary File Formats | 2024 | [10.1145/3628157](https://doi.org/10.1145/3628157) |
| 35 | fuzzbench2021 | FuzzBench: an open fuzzer benchmarking platform and service | 2021 | [10.1145/3468264.3473932](https://doi.org/10.1145/3468264.3473932) |
| 36 | benchmarkproperties | Fuzzing: On Benchmarking Outcome as a Function of Benchmark Properties | 2026 | [10.1145/3732936](https://doi.org/10.1145/3732936) |
| 37 | stateinspector2022 | The Closer You Look, The More You Learn: A Grey-box Approach to Protocol State Machine Learning | 2022 | [10.1145/3548606.3559365](https://doi.org/10.1145/3548606.3559365) |
| 38 | wingmuzz2025 | WingMuzz: Blackbox Testing of IoT Protocols via Two-dimensional Fuzzing Schedule | 2025 | [10.1109/ase63991.2025.00212](https://doi.org/10.1109/ase63991.2025.00212) |
| 39 | hybridllm2026 | Large Language Model Assisted Hybrid Fuzzing | 2026 | [10.1109/tse.2026.3694408](https://doi.org/10.1109/tse.2026.3694408) |
| 40 | hgfuzzer2026 | HGFuzzer: Directed Greybox Fuzzing via Large Language Model | 2026 | [10.1145/3841476](https://doi.org/10.1145/3841476) |
| 41 | greenbenchmark2023 | Green Fuzzer Benchmarking | 2023 | [10.1145/3597926.3598144](https://doi.org/10.1145/3597926.3598144) |
| 42 | protocolguard2026 | ProtocolGuard: Detecting Protocol Non-compliance Bugs via LLM-guided Static Analysis and Dynamic Verification | 2026 | [10.14722/ndss.2026.240521](https://doi.org/10.14722/ndss.2026.240521) |
| 43 | bsfuzzer2026 | BSFuzzer: Context-Aware Semantic Fuzzing for BLE Logic Flaw Detection | 2026 | [10.14722/ndss.2026.240094](https://doi.org/10.14722/ndss.2026.240094) |
| 44 | mercuriuzz2026 | Identifying Logical Vulnerabilities in QUIC Implementations | 2026 | [10.14722/ndss.2026.231777](https://doi.org/10.14722/ndss.2026.231777) |
| 45 | distfuzz2025 | Blackbox Fuzzing of Distributed Systems with Multi-Dimensional Inputs and Symmetry-Based Feedback Pruning | 2025 | [10.14722/ndss.2025.241912](https://doi.org/10.14722/ndss.2025.241912) |
| 46 | blueman2025 | BLuEMan: A Stateful Simulation-based Fuzzing Framework for Open-Source RTOS Bluetooth Low Energy Protocol Stacks | 2025 | [官方页面](https://www.usenix.org/conference/usenixsecurity25/presentation/kao) |
| 47 | fishfuzz2023 | FISHFUZZ: Catch Deeper Bugs by Throwing Larger Nets | 2023 | [官方页面](https://www.usenix.org/conference/usenixsecurity23/presentation/zheng) |
| 48 | miner2023 | MINER: A Hybrid Data-Driven Approach for REST API Fuzzing | 2023 | [官方页面](https://www.usenix.org/conference/usenixsecurity23/presentation/lyu) |
| 49 | mutationassessment2023 | Systematic Assessment of Fuzzers using Mutation Analysis | 2023 | [官方页面](https://www.usenix.org/conference/usenixsecurity23/presentation/gorz) |
| 50 | fuzztruction2023 | Fuzztruction: Using Fault Injection-based Fuzzing to Leverage Implicit Domain Knowledge | 2023 | [官方页面](https://www.usenix.org/conference/usenixsecurity23/presentation/bars) |

## 当前文件核验

- 重新编译成功：23 页，50 条参考文献；105 个内部链接、57 个文献链接覆盖 50 个独立文献目标，没有悬空目标。
- 有四条 BibTeX 缺页码警告及非致命 Underfull 提示；无未定义引用、Overfull 越界或致命错误。
- 本轮主稿 main.revised.tex 与开始时逐字节一致；参考文献仅有 ProtocolGuard 作者去重一项变更。
- 旧版两个验证脚本因比较更早正文快照而失败，未将它们标记为通过；本轮使用其中只读 PDF 检查逻辑，针对当前条目集合独立验证。
- 当前结果见 [current_validation.json](current_validation.json)，可运行 python3 reference_reality_audit_20260930/finalize_audit.py 复核。

## 证据文件

- [42 条实时 Crossref 查询比较](live_crossref_comparison.json)。
- [原始缓存字段比较](cached_metadata_comparison.json)：保留未经人工解释覆盖的初始差异，ProtocolGuard 以官方作者表优先。
- [八篇官方 BibTeX 逐字段比较](official_metadata_comparison.json)。
- [官方页面抓取时间与 SHA-256](live_official_manifest.json)。
- PDF 的实际命名目标和链接注释分别见 pdf_destinations.txt、pdf_annotations.txt。
- references.before_protocolguard_fix.bib 是按唯一单行修正反向重建的修改前副本；原 Crossref/官方缓存均保留。

## 核验范围

本轮确认出版记录存在，检查主要书目字段并修正已确证错误；没有逐篇精读全部 50 篇全文核验每一句正文论断，也没有进行完整撤稿状态审查或会议期刊等级评级。不能把“文献真实”写成“所有引用完全正确”或“50 篇都是近年顶会顶刊”。
