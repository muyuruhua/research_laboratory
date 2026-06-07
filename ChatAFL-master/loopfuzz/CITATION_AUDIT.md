# LoopFuzz Citation Audit

Audit date: 2026-06-04

Scope:
- `main.tex`
- `references.bib`
- generated `main.bbl`

## Mechanical Result

- `main.tex` contains 103 citation occurrences and 56 unique citation keys.
- `references.bib` contains exactly 56 entries.
- Every cited key has a BibTeX entry.
- Every BibTeX entry is cited by the manuscript.
- Entry types are restricted to academic-paper types: 54 `@inproceedings` and 2 `@article`.
- The generated bibliography contains 56 `\bibitem` entries, satisfying the requirement that the reference count remain greater than 50.
- No `@misc`, `@techreport`, RFC, software homepage, whitepaper, or tool-only reference remains in the active bibliography.

## Edits Made

- Removed non-paper and uncited entries from the active BibTeX file:
  - `rfc_ftp`
  - `rfc_smtp`
  - `rfc_sip`
  - `afl_whitepaper`
  - `peach`
  - `sulley`
  - `boofuzz`
  - `libfuzzer`
- Added a proper academic citation for NSFuzz:
  - `nsfuzz`: ACM Transactions on Software Engineering and Methodology, 32(6), 160:1--160:26, 2023, DOI `10.1145/3580598`.
- Updated the related-work paragraph so NSFuzz is not forced into an AFLNet-style IPSM claim. The text now says these systems expose or infer state structure from responses, memory, or program variables.
- Updated the baseline paragraph so the auxiliary NSFuzz and MBFuzzer comparisons are explicitly cited.
- Added verified DOI metadata for two core references:
  - AFLNet: DOI `10.1109/ICST46399.2020.00062`
  - StateAFL: DOI `10.1007/s10664-022-10233-3`

## Relevance Verdict

No active citation is currently judged irrelevant to its citation context.

The references are grouped as follows:

- Core stateful protocol fuzzing and network-service fuzzing:
  `aflnet`, `stateafl`, `nsfuzz`, `sgf_usenix22`, `profuzzbench_benchmark_stateful_protocol_2021`, `snapfuzz_high_throughput_fuzzing_2022`, `formatted_stateful_greybox_fuzzing_2024`, `resolverfuzz_query_response_2024`, `mbfuzzer_mqtt_2025`, `bleem_packet_sequence_2023`, `logos_log_guided_fuzzing_2024`, `msgfuzzer_message_sequence_guided_2024`, `fuzzusb_hybrid_stateful_fuzzing_2022`, `dtls_fuzzer_dtls_protocol_2022`, `edhoc_fuzzer_edhoc_protocol_2023`, `tron_fuzzing_linux_network_2025`.
- LLM-assisted fuzzing, documentation-guided fuzzing, and LLM-based synthesis:
  `chatafl`, `fuzz4all_universal_fuzzing_large_2024`, `llmif_augmented_large_language_2024`, `matter_llm_specification_2024`, `carpetfuzz_documentation_2023`, `prompt_fuzzing_fuzz_driver_2024`, `large_language_models_are_2023`, `large_language_models_are_2024`, `docter_documentation_guided_fuzzing_2022`, `magneto_step_wise_approach_2024`.
- Structure-aware fuzzing, grammar or token guidance, and semantic validation:
  `snipuzz_black_box_fuzzing_2021`, `token_level_fuzzing_2021`, `gramatron_effective_grammar_aware_2021`, `griffin_grammar_free_dbms_2022`, `no_grammar_no_problem_2023`, `likely_invariants_feedback_2021`, `mundofuzz_grammar_inference_2022`, `one_engine_to_fuzz_em_all_2021`, `apicraft_fuzz_driver_2021`.
- Search scheduling, directed fuzzing, strategy selection, and benchmarking rigor:
  `directed_greybox_fuzzing_2017`, `windranger_blocks_2022`, `when_analysis_2025`, `seed_selection_successful_fuzzing_2021`, `one_fuzzing_strategy_rule_2022`, `regression_greybox_fuzzing_2021`, `efficient_errors_2022`, `sok_prudent_evaluation_practices_2024`, `reliability_benchmarking_2022`, `many_stack_2022`.
- Adjacent state-aware, interaction-heavy, or context-guided fuzzing:
  `pgfuzz_policy_guided_fuzzing_2021`, `android_smarttvs_vulnerability_discovery_2021`, `fuzzware_mmio_2022`, `statefuzz_linux_driver_2022`, `differential_fuzzing_data_distribution_2024`, `fuzzing_hardware_like_software_2022`, `coverage_guided_fuzzing_embedded_2023`, `rulf_rust_library_fuzzing_2021`, `smartian_analyses_2021`, `diane_identifying_fuzzing_triggers_2021`, `corecrisis_context_aware_2025`.

The last group is intentionally framed in the paper as adjacent evidence for the importance of state feedback, interaction context, and data-flow or learned guidance. These papers should not be used to claim direct superiority in stateful protocol fuzzing. The manuscript currently follows that boundary.

## External Spot Checks

The most submission-critical references were spot-checked against external scholarly or publisher pages:

- NSFuzz:
  - DOI and TOSEM metadata: https://doi.org/10.1145/3580598
  - NDSS/FUZZING registered-report page: https://www.ndss-symposium.org/ndss-paper/auto-draft-272/
- AFLNet:
  - ICST page / DOI: https://doi.org/10.1109/ICST46399.2020.00062
- StateAFL:
  - Springer article page / DOI: https://doi.org/10.1007/s10664-022-10233-3
- ChatAFL:
  - NDSS 2024 paper DOI: https://doi.org/10.14722/ndss.2024.24556
- MBFuzzer:
  - USENIX Security 2025 page and BibTeX: https://www.usenix.org/conference/usenixsecurity25/presentation/song-xiangpu

## Remaining Risks

- BibTeX still reports four missing-page warnings:
  - `no_grammar_no_problem_2023`
  - `pgfuzz_policy_guided_fuzzing_2021`
  - `when_analysis_2025`
  - `chatafl`
- These warnings do not indicate fake or unresolved references. They indicate missing page metadata in the BibTeX entries.
- Do not fabricate page ranges to silence these warnings. Fill them only if verified publisher or proceedings metadata are available.
- A complete publisher-by-publisher verification of all 56 entries would require a separate DOI/proceedings audit. The present audit verifies the active bibliography mechanically, removes non-paper material, fixes the missing NSFuzz citation, and externally spot-checks the most critical baseline and positioning papers.
