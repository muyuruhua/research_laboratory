# 文献扩充与正文对应核验

状态：PASS。按 first_paper.md 的证据校准主线补充实际引用；检索核验截止 2026-09-29。

## 结果

- 正文实际引用 **50 篇**，由 25 篇增加至 50 篇；新增 25 篇均有明确论述位置。
- 2022–2026 年文献 **36 篇（72%）**；新增文献中 24/25 篇发表于 2022–2026 年。
- 新增来源：USENIX Security 5 篇，NDSS 4 篇，ACM CCS 4 篇，ACM TOSEM 3 篇，IEEE TSE 2 篇，ISSTA 2 篇，ICSE、EuroSys、ESEC/FSE、ASE、OOPSLA 各 1 篇。
- 50 篇总数含必要的经典统计、概率校准和直接先行工作；不将全部条目宣称为近年顶会论文。
- 未使用 nocite 增加条目；无重复 DOI、重复题名或未引用的条目。

## 正文修改

- 相关工作按状态表征、执行条件、结构化生成、LLM 生成、调度、语义 oracle、评测方法组织。
- 实验控制补充资源成本文献；有效性讨论补充基准属性与变异分析文献。
- 明确已提出的方法与尚未完成的受控评测；未将他人实验数值或性能结论归属于本文。
- 保持响应状态代理与代码进度、provisional 与 durable、漏洞回放与受控再发现之间的区别。
- Beta–Bernoulli、Thompson sampling、已有状态建模与调度思想均保留先行工作归属。
- 修复一处原有断裂的 Table 引用；Figure 4 保持原矢量文件，仅将展示宽度调整为正文宽度的 97%，消除页高溢出。

## 出版信息核验

- 20 篇新增文献核对出版方提交至 Crossref 的题名、作者、DOI、年份、卷期及页码；5 篇采用 USENIX 官方摘要与 BibTeX。
- 方法细节引用限定于已查阅摘要支持的内容；其余引用仅说明已核实题名明确的研究范围，不引入性能数值或额外机制。
- WhiteFox 正确 DOI 为 10.1145/3689736；排除误匹配的 Rustlantis。ELFuzz 的误匹配页面实际为 GradEscape，未收入。
- FormatFuzzer 按正式期次记为 2024 年；HGFuzzer 明示 2026 年 8 月在线发表，未补造卷期页码。

## PDF 与内容保护

- 已重新编译：22 页；101 个内部链接目标有效，57 个文献链接覆盖全部 50 条独立文献目标。
- 9 幅图、20 张表的 29 个目的地完整；无未定义引用、重复目标或溢出框。
- 摘要保持原文，按本轮词元规则计 183 词；关键词仍为 5 个。不同连字符分词方式可有 1 词差异。
- 192 个既有受保护文件逐字节一致；所有实验表格、公式、算法与图表说明保持一致。
- 独立漏洞节副本在前一轮已仅变更引用包装，本轮没有修改；9 幅图仍是矢量图，PDF 中位图数为 0。
- XML 版面测量仅过滤 Poppler 从数学字体提取出的 3 个非法 XML 控制字符，不修改 PDF 或公式。
- 非致命排版提示（未屏蔽）：LaTeX Warning: Text page 12 contains only floats.; LaTeX Warning: Text page 12 contains only floats.; LaTeX Warning: Text page 15 contains only floats.。提示对应浮动图表页，不是未定义引用或溢出错误。

## 新增文献与论述对应

| 文献 | 年份 / 出处 | 支持的论述 | 正文行 | 核验来源 |
|---|---|---|---|---|
| AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing | 2025 / IEEE Transactions on Software Engineering | 覆盖引导协议模糊测试及 AFLNet 后续研究 | 136 | [来源](https://api.crossref.org/works?query.title=AFLNet+Five+Years+Later+On+Coverage-Guided+Protocol+Fuzzing&rows=3&filter=until-pub-date%3A2026-09-29) |
| Nyx-net: network fuzzing with incremental snapshots | 2022 / Proceedings of the Seventeenth European Conference on Computer Systems | 增量快照与网络模糊测试的执行条件 | 139 | [来源](https://api.crossref.org/works?query.title=Nyx-Net+Network+Fuzzing+with+Incremental+Snapshots&rows=3&filter=until-pub-date%3A2026-09-29) |
| SnapFuzz: high-throughput fuzzing of network applications | 2022 / Proceedings of the 31st ACM SIGSOFT International Symposium on Software Testing and Analysis | 网络应用测试的执行吞吐量 | 139 | [来源](https://api.crossref.org/works?query.title=SnapFuzz+High-Efficiency+and+Fidelity+Fuzzing+of+Network+Applications&rows=3&filter=until-pub-date%3A2026-09-29) |
| No Peer, no Cry: Network Application Fuzzing via Fault Injection | 2024 / Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security | 通过故障注入构造网络协议交互 | 139 | [来源](https://api.crossref.org/works?query.title=No+Peer+no+Cry+Network+Application+Fuzzing+via+Fault+Injection&rows=3&filter=until-pub-date%3A2026-09-29) |
| FOX: Coverage-guided Fuzzing as Online Stochastic Control | 2024 / Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security | 把覆盖引导模糊测试建模为在线随机控制 | 145 | [来源](https://api.crossref.org/works?query.title=FOX+Coverage-guided+Fuzzing+as+Online+Stochastic+Control&rows=3&filter=until-pub-date%3A2026-09-29) |
| ProphetFuzz: Fully Automated Prediction and Fuzzing of High-Risk Option Combinations with Only Documentation via Large Language Model | 2024 / Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security | 基于文档预测高风险选项组合 | 143 | [来源](https://api.crossref.org/works?query.title=ProphetFuzz+Fully+Automated+Prediction+and+Fuzzing+of+High-Risk+Option+Combinations+with+Only+Documentation+via+Large+Language+Model&rows=3&filter=until-pub-date%3A2026-09-29) |
| WhiteFox: White-Box Compiler Fuzzing Empowered by Large Language Models | 2024 / Proceedings of the ACM on Programming Languages | 利用编译器源码信息引导优化触发测试 | 143 | [来源](https://api.crossref.org/works?query.title=WhiteFox+White-Box+Compiler+Fuzzing+Empowered+by+Large+Language+Models&rows=3) |
| Large Language Models are Edge-Case Generators: Crafting Unusual Programs for Fuzzing Deep Learning Libraries | 2024 / Proceedings of the IEEE/ACM 46th International Conference on Software Engineering | 生成深度学习库的异常边界程序 | 143 | [来源](https://api.crossref.org/works?query.title=Large+Language+Models+are+Edge-Case+Generators+Crafting+Unusual+Programs+for+Fuzzing+Deep+Learning+Libraries&rows=3&filter=until-pub-date%3A2026-09-29) |
| FormatFuzzer: Effective Fuzzing of Binary File Formats | 2024 / ACM Transactions on Software Engineering and Methodology | 由二进制格式规范构造解析器、变异器和生成器 | 141 | [来源](https://api.crossref.org/works?query.title=FormatFuzzer+Effective+Fuzzing+of+Binary+File+Formats&rows=3&filter=until-pub-date%3A2026-09-29) |
| FuzzBench: an open fuzzer benchmarking platform and service | 2021 / Proceedings of the 29th ACM Joint Meeting on European Software Engineering Conference and Symposium on the Foundations of Software Engineering | 通用模糊测试器的结构化评测 | 149 | [来源](https://api.crossref.org/works?query.title=FuzzBench+an+open+fuzzer+benchmarking+platform+and+service&rows=3&filter=until-pub-date%3A2026-09-29) |
| Fuzzing: On Benchmarking Outcome as a Function of Benchmark Properties | 2026 / ACM Transactions on Software Engineering and Methodology | 初始语料和执行速度对模糊测试排名的影响 | 816 | [来源](https://api.crossref.org/works?query.title=Fuzzing+On+Benchmarking+Outcome+as+a+Function+of+Benchmark+Properties&rows=3&filter=until-pub-date%3A2026-09-29) |
| The Closer You Look, The More You Learn: A Grey-box Approach to Protocol State Machine Learning | 2022 / Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security | 内部观察与灰盒协议状态机学习 | 136 | [来源](https://api.crossref.org/works?query.title=The+Closer+You+Look+The+More+You+Learn+A+Grey-box+Approach+to+Protocol+State+Machine+Learning&rows=3&filter=until-pub-date%3A2026-09-29) |
| WingMuzz: Blackbox Testing of IoT Protocols via Two-dimensional Fuzzing Schedule | 2025 / 2025 40th IEEE/ACM International Conference on Automated Software Engineering (ASE) | 黑盒协议测试中的二维调度 | 145 | [来源](https://api.crossref.org/works/10.1109%2FASE63991.2025.00212) |
| Large Language Model Assisted Hybrid Fuzzing | 2026 / IEEE Transactions on Software Engineering | LLM 辅助混合模糊测试的研究范围 | 143 | [来源](https://api.crossref.org/works/10.1109%2FTSE.2026.3694408) |
| HGFuzzer: Directed Greybox Fuzzing via Large Language Model | 2026 / ACM Transactions on Software Engineering and Methodology | 定向测试中的谓词引导执行合成 | 143 | [来源](https://api.crossref.org/works/10.1145%2F3841476) |
| Green Fuzzer Benchmarking | 2023 / Proceedings of the 32nd ACM SIGSOFT International Symposium on Software Testing and Analysis | 可靠评测的资源成本 | 478 | [来源](https://api.crossref.org/works/10.1145%2F3597926.3598144) |
| ProtocolGuard: Detecting Protocol Non-compliance Bugs via LLM-guided Static Analysis and Dynamic Verification | 2026 / Proceedings 2026 Network and Distributed System Security Symposium | 规范一致性检查与动态验证 | 147 | [来源](https://api.crossref.org/works?query.title=ProtocolGuard+Detecting+Protocol+Non-compliance+Bugs+via+LLM-guided+Static+Analysis+and+Dynamic+Verification&rows=3&filter=until-pub-date%3A2026-09-29) |
| BSFuzzer: Context-Aware Semantic Fuzzing for BLE Logic Flaw Detection | 2026 / Proceedings 2026 Network and Distributed System Security Symposium | BLE 语义测试与逻辑缺陷 | 147 | [来源](https://api.crossref.org/works?query.title=BSFuzzer+Context-Aware+Semantic+Fuzzing+for+BLE+Logic+Flaw+Detection&rows=3&filter=until-pub-date%3A2026-09-29) |
| Identifying Logical Vulnerabilities in QUIC Implementations | 2026 / Proceedings 2026 Network and Distributed System Security Symposium | QUIC 实现的逻辑漏洞 | 147 | [来源](https://api.crossref.org/works?query.title=Identifying+Logical+Vulnerabilities+in+QUIC+Implementations&rows=3&filter=until-pub-date%3A2026-09-29) |
| Blackbox Fuzzing of Distributed Systems with Multi-Dimensional Inputs and Symmetry-Based Feedback Pruning | 2025 / Proceedings 2025 Network and Distributed System Security Symposium | 事件、故障、时间与消息序列反馈 | 139 | [来源](https://api.crossref.org/works?query.title=Blackbox+Fuzzing+of+Distributed+Systems+with+Multi-Dimensional+Inputs+and+Symmetry-Based+Feedback+Pruning&rows=3&filter=until-pub-date%3A2026-09-29) |
| BLuEMan: A Stateful Simulation-based Fuzzing Framework for Open-Source RTOS Bluetooth Low Energy Protocol Stacks | 2025 / USENIX Security | BLE 协议栈的模拟执行条件 | 139 | [来源](https://www.usenix.org/conference/usenixsecurity25/presentation/kao) |
| FISHFUZZ: Catch Deeper Bugs by Throwing Larger Nets | 2023 / USENIX Security | 距离信息驱动的目标与种子优先级 | 145 | [来源](https://www.usenix.org/conference/usenixsecurity23/presentation/zheng) |
| MINER: A Hybrid Data-Driven Approach for REST API Fuzzing | 2023 / USENIX Security | 有效请求序列模板与参数学习 | 141 | [来源](https://www.usenix.org/conference/usenixsecurity23/presentation/lyu) |
| Systematic Assessment of Fuzzers using Mutation Analysis | 2023 / USENIX Security | 基于变异分析的故障导向评测 | 816 | [来源](https://www.usenix.org/conference/usenixsecurity23/presentation/gorz) |
| Fuzztruction: Using Fault Injection-based Fuzzing to Leverage Implicit Domain Knowledge | 2023 / USENIX Security | 在生成程序中注入故障以保留格式约束 | 141 | [来源](https://www.usenix.org/conference/usenixsecurity23/presentation/bars) |

## 复核

在论文修订目录执行：

    bash build_revised.sh
    python3 reference_expansion/verify_reference_expansion.py

- 完整机器核验见 [validation.json](validation.json)，逐条来源及原句映射见 [manifest.json](manifest.json)。
- 原稿备份见 before_reference_expansion；本轮源文本差异见 [manuscript.diff](manuscript.diff)。
- 本轮未执行新实验。既有实验缺口仍然存在；文献扩充不构成补做实验，也不将回顾性证据升级为因果验证。
