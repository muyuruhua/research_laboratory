# Citation Audit for `main.tex`

说明：
- 下列四类列表基于**精修前正文实际引用的 61 篇文献**逐条分类。
- 分类标准不是“是否和本文沾边”，而是看其对本文主线——**stateful protocol fuzzing / LLM-assisted protocol fuzzing / runtime validation / state-aware scheduling**——的支撑强度。
- 在此基础上，我已完成两轮 citation hardening：
  - **从正文移除**：`ityfuzz_contract_2023`, `grayc_analysers_2023`
  - **向正文补入**：`efficient_errors_2022`, `windranger_blocks_2022`, `when_analysis_2025`
  - **进一步压缩邻近支撑**：从正文移除 `muffin_fuzzing_2022`
- 因而**进一步精修后正文实际引用数为 61**，且主线更硬、更集中。

## 一、核心相关（Core Related）
这些文献直接构成本文的问题定义、比较基线或最接近的方法谱系。

- `aflnet` — AFLNet: A greybox fuzzer for network protocols。本文最直接的 stateful protocol fuzzing 基线之一。
- `stateafl` — StateAFL: Greybox fuzzing for stateful network servers。本文问题设定与状态反馈主线的核心前作。
- `sgf_usenix22` — Stateful greybox fuzzing。本文状态导向调度与 plateau 讨论的理论核心。
- `chatafl` — Large language model guided protocol fuzzing。本文最直接的 open-loop LLM 基线。
- `profuzzbench_benchmark_stateful_protocol_2021` — ProFuzzBench: a benchmark for stateful protocol fuzzing。本文实验设计与 target 选择的重要比较背景。
- `snapfuzz_high_throughput_fuzzing_2022` — SnapFuzz: high-throughput fuzzing of network applications。直接属于网络应用 fuzzing 主线。
- `bleem_packet_sequence_2023` — Bleem: Packet Sequence Oriented Fuzzing for Protocol Implementations。直接支撑“序列”而非单消息视角。
- `formatted_stateful_greybox_fuzzing_2024` — Formatted Stateful Greybox Fuzzing of TLS Server。直接属于格式+状态结合的协议 fuzzing。
- `logos_log_guided_fuzzing_2024` — Logos: Log Guided Fuzzing for Protocol Implementations。直接属于协议实现 fuzzing 主线。
- `msgfuzzer_message_sequence_guided_2024` — MSGFuzzer: Message Sequence Guided Industrial Robot Protocol Fuzzing。直接支撑 message-sequence guidance。
- `resolverfuzz_query_response_2024` — ResolverFuzz: Automated Discovery of DNS Resolver Vulnerabilities with Query-Response Fuzzing。直接支撑 query-response / network protocol fuzzing。
- `mbfuzzer_mqtt_2025` — MBFuzzer: A Multi-Party Protocol Fuzzer for MQTT Brokers。直接支撑 MQTT broker fuzzing 与本文目标域。
- `corecrisis_context_aware_2025` — CoreCrisis: Threat-Guided and Context-Aware Iterative Learning and Fuzzing of 5G Core Networks。直接支撑 context-aware network fuzzing。
- `llmif_augmented_large_language_2024` — LLMIF: Augmented Large Language Model for Fuzzing IoT Devices。属于最接近的 LLM-assisted fuzzing 文献。
- `matter_llm_specification_2024` — LLM Assisted Fuzzing of Matter IoT Devices from Specification。直接支撑 specification-driven LLM fuzzing。
- `carpetfuzz_documentation_2023` — CarpetFuzz: Automatic Program Option Constraint Extraction from Documentation for Fuzzing。直接支撑文档/规范提取约束。
- `prompt_fuzzing_fuzz_driver_2024` — Prompt Fuzzing for Fuzz Driver Generation。直接支撑 LLM 参与 fuzzing 输入或 driver 构造。
- `gramatron_effective_grammar_aware_2021` — Gramatron: effective grammar-aware fuzzing。直接支撑 grammar-aware 线索。
- `griffin_grammar_free_dbms_2022` — Griffin: Grammar-Free DBMS Fuzzing。直接支撑“结构恢复/约束恢复”而非纯随机变异。
- `snipuzz_black_box_fuzzing_2021` — Snipuzz: Black-box Fuzzing of IoT Firmware via Message Snippet Inference。直接支撑消息片段推断与协议结构恢复。
- `dtls_fuzzer_dtls_protocol_2022` — DTLS-Fuzzer: A DTLS Protocol State Fuzzer。直接属于协议状态 fuzzing。
- `edhoc_fuzzer_edhoc_protocol_2023` — EDHOC-Fuzzer: An EDHOC Protocol State Fuzzer。直接属于协议状态 fuzzing。
- `tron_fuzzing_linux_network_2025` — Tron: Fuzzing Linux Network Stack via Protocol-System Call Payload Synthesis。直接支撑 network/protocol payload synthesis。

## 二、直接支撑（Direct Support）
这些文献不是最贴脸的对照对象，但对背景、方法机制、实验纪律或经典基线有直接支撑作用。

- `afl_whitepaper` — afl-fuzz whitepaper。经典 coverage-guided fuzzing 背景。
- `libfuzzer` — libFuzzer documentation。经典 coverage-guided fuzzing 背景。
- `peach` — Peach。经典协议/模型驱动 fuzzing 框架。
- `sulley` — Sulley。经典协议 fuzzing 框架。
- `boofuzz` — boofuzz。经典网络协议 fuzzing 框架。
- `directed_greybox_fuzzing_2017` — Directed Greybox Fuzzing。直接支撑“定向/目标导向” fuzzing 方法学。
- `seed_selection_successful_fuzzing_2021` — Seed selection for successful fuzzing。直接支撑 seed scheduling 与效率问题。
- `one_fuzzing_strategy_rule_2022` — One fuzzing strategy to rule them all。直接支撑 fuzzing strategy 设计空间。
- `regression_greybox_fuzzing_2021` — Regression Greybox Fuzzing。直接支撑 greybox fuzzing 方法学。
- `sok_prudent_evaluation_practices_2024` — SoK: Prudent Evaluation Practices for Fuzzing。直接支撑实验纪律与结果解读。
- `fuzzusb_hybrid_stateful_fuzzing_2022` — FuzzUSB。支撑 stateful fuzzing 在通信设备环境中的扩展。
- `diane_identifying_fuzzing_triggers_2021` — Diane。支撑交互式/设备类 fuzzing 中的触发条件问题。
- `differential_fuzzing_data_distribution_2024` — Differential Fuzzing for DDS Programs with Dynamic Configuration。支撑动态配置与通信中间件场景。
- `no_grammar_no_problem_2023` — No Grammar, No Problem。支撑“先验结构不足时如何恢复/绕过语法描述”。
- `docter_documentation_guided_fuzzing_2022` — DocTer。支撑 documentation-guided fuzzing 的方法逻辑。
- `large_language_models_are_2023` — Large Language Models Are Zero-Shot Fuzzers。支撑 LLM 作为结构化输入生成器的通用论点。
- `large_language_models_are_2024` — Large Language Models are Edge-Case Generators。支撑 LLM 生成边界样例的通用论点。
- `fuzz4all_universal_fuzzing_large_2024` — Fuzz4All。支撑通用 LLM-assisted fuzzing 视角。
- `rfc_ftp` — RFC 959。支撑 FTP motivation 与协议事实。
- `rfc_smtp` — RFC 5321。支撑 SMTP motivation 与协议事实。
- `rfc_sip` — RFC 3261。支撑 stateful network protocol 示例背景。
- `housefuzz_service_aware_grey_2025` — HouseFuzz。支撑 service-aware greybox fuzzing。
- `reliability_benchmarking_2022` — On the Reliability of Coverage-Based Fuzzer Benchmarking。直接支撑统计和 benchmark 方法学。
- `many_stack_2022` — So Many Fuzzers, So Little Time。直接支撑网络栈 fuzzing 评估经验。

## 三、邻近支撑（Neighboring Support）
这些文献与本文不是同一问题，但能支撑“长序列依赖”“结构恢复”“模型辅助输入生成”这类邻近论点。

- `rulf_rust_library_fuzzing_2021` — RULF。不是网络协议 fuzzing，但支撑 API dependency graph / sequence exploration。
- `llm_based_fuzzing_method_2025` — LLM-based Fuzzing Method Using UI-based Input Value Generation for IoT Devices。虽然不属于协议 fuzzing 主线，但比 smart-contract fuzzing 更接近本文的交互式 IoT / LLM-assisted fuzzing 语境。
- `fuzzing_deep_learning_libraries_2022` — relational API inference for DL libraries。属于结构恢复的邻近证据。
- `free_source_2022` — Free Lunch for Testing。属于开源资产驱动 fuzzing 的邻近证据。
- `utopia_automatic_generation_fuzz_2023` — UTopia。属于自动 fuzz driver 生成的邻近证据。
- `dualfuzz_detecting_vulnerability_wi_2025` — DualFuzz。不是本文主域，但仍属通信/协议相关 fuzzing。
- `android_smarttvs_vulnerability_discovery_2021` — Android SmartTVs Vulnerability Discovery via Log-Guided Fuzzing。不是协议主线，但支撑 log-guided/communication-heavy 场景。
- `saturn_host_gadget_synergistic_2024` — Saturn。不是协议主线，但支撑交互式设备栈 fuzzing。
- `devfuzz_automatic_device_model_2023` — DevFuzz。不是协议主线，但支撑 model-guided fuzzing 逻辑。
- `dnafuzz_descriptor_aware_fuzzing_2025` — DNAFuzz。不是协议主线，但支撑通信设备/驱动结构约束问题。
- `magneto_step_wise_approach_2024` — Magneto。不是协议 fuzzing，但支撑 LLM-empowered directed fuzzing 的邻近论点。

## 四、建议删除（Suggested for Deletion）
这些文献不是“错误”，但放在本文现有叙事里会稀释主线，因此已建议从正文中移除。

- `ityfuzz_contract_2023` — ItyFuzz: Snapshot-Based Fuzzer for Smart Contract。与 stateful protocol fuzzing/LLM-assisted protocol fuzzing 的距离过远。
- `grayc_analysers_2023` — GrayC: Greybox Fuzzing of Compilers and Analysers for C。与本文协议交互、状态机、LLM辅助主线关联过弱。
- `muffin_fuzzing_2022` — Muffin: Testing Deep Learning Libraries via Neural Architecture Fuzzing。可作为邻近支撑，但对本文的 protocol/state/interaction 主线贡献偏弱，因此在进一步压缩后从正文移除。
- `smartian_analyses_2021` — SMARTIAN: Enhancing Smart Contract Fuzzing with Static and Dynamic Data-Flow Analyses。对“序列依赖”确有启发，但与 protocol/state/interaction 主线距离仍偏远，因此在极致压缩版本中从正文移除。

## 精修动作摘要
- 已从 `main.tex` 中移除对 `ityfuzz_contract_2023` 与 `grayc_analysers_2023` 的正文引用。
- 已补入更贴近 fuzzing methodology 的 `efficient_errors_2022`, `windranger_blocks_2022`, `when_analysis_2025`。
- 已进一步从 `main.tex` 中移除 `muffin_fuzzing_2022`，收紧 LLM 邻近文献簇的跨域跨度。
- 已执行一次“1 出 1 进”替换：移除 `smartian_analyses_2021`，补入 `llm_based_fuzzing_method_2025`。
- 已在 `references.bib` 中删除若干重复/低质量别名条目，并修正 `windranger_blocks_2022` 的标题格式。
