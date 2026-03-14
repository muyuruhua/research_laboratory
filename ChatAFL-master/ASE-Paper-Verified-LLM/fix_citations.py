text = open("main.tex").read()

replacements = [
    (
        "This makes protocol fuzzing substantially harder than file-based fuzzing: useful inputs must satisfy message syntax, preserve temporal dependencies, and maintain execution progress across multiple request-response steps.",
        r"This makes protocol fuzzing substantially harder than file-based fuzzing: useful inputs must satisfy message syntax, preserve temporal dependencies, and maintain execution progress across multiple request-response steps~\cite{resolverfuzz_query_response_2024,mbfuzzer_mqtt_2025,corecrisis_context_aware_2025,llm_based_fuzzing_method_2025,rulf_rust_library_fuzzing_2021}."
    ),
    (
        "Traditional coverage-guided fuzzers are effective for stateless parsers, but they are poorly matched to network servers whose behavior depends on prior interaction history.",
        r"Traditional coverage-guided fuzzers~\cite{afl_whitepaper,libfuzzer,directed_greybox_fuzzing_2017} are effective for stateless parsers, but they are poorly matched to network servers whose behavior depends on prior interaction history~\cite{one_fuzzing_strategy_rule_2022,seed_selection_successful_fuzzing_2021,regression_greybox_fuzzing_2021,efficient_errors_2022}."
    ),
    (
        "Stateful greybox fuzzers such as AFLNet and StateAFL partially address this limitation by inferring protocol progress from server responses and reusing valid seed traces~\cite{aflnet,stateafl}.",
        r"Stateful greybox fuzzers such as AFLNet and StateAFL partially address this limitation by inferring protocol progress from server responses and reusing valid seed traces~\cite{aflnet,stateafl,sgf_usenix22,profuzzbench_benchmark_stateful_protocol_2021,snapfuzz_high_throughput_fuzzing_2022,bleem_packet_sequence_2023,formatted_stateful_greybox_fuzzing_2024,logos_log_guided_fuzzing_2024,msgfuzzer_message_sequence_guided_2024}."
    ),
    (
        r"Recent systems such as ChatAFL therefore use LLMs to synthesize protocol messages and reduce the dependence on manually engineered grammars~\cite{chatafl}.",
        r"Recent systems such as ChatAFL therefore use LLMs to synthesize protocol messages and reduce the dependence on manually engineered grammars~\cite{chatafl,fuzz4all_universal_fuzzing_large_2024,llmif_augmented_large_language_2024,matter_llm_specification_2024,carpetfuzz_documentation_2023,prompt_fuzzing_fuzz_driver_2024,gramatron_effective_grammar_aware_2021,griffin_grammar_free_dbms_2022,no_grammar_no_problem_2023}."
    ),
    (
        "Network servers allocate structures based on a specific sequence of valid inputs over time.",
        r"Network servers allocate structures based on a specific sequence of valid inputs over time~\cite{rfc_ftp,rfc_smtp,rfc_sip}."
    ),
    (
        r"non-deterministic process forking (\texttt{fork()}) complicates conventional coverage tracking.",
        r"non-deterministic process forking (\texttt{fork()}) complicates conventional coverage tracking~\cite{dualfuzz_detecting_vulnerability_wi_2025,differential_fuzzing_data_distribution_2024,housefuzz_service_aware_grey_2025,tron_fuzzing_linux_network_2025}."
    ),
    (
        r"If an input sequence $i_1, i_2$ (e.g., \texttt{USER}, \texttt{PASS}) results in FTP response codes \texttt{331, 230}, AFLNet registers the state vector as $[331, 230]$. It then preferentially targets sequences that reach rare nodes in the inferred state graph. This represents a common baseline for automated state-aware protocol fuzzing without direct language-model synthesis.",
        r"If an input sequence $i_1, i_2$ (e.g., \texttt{USER}, \texttt{PASS}) results in FTP response codes \texttt{331, 230}, AFLNet registers the state vector as $[331, 230]$. It then preferentially targets sequences that reach rare nodes in the inferred state graph. This represents a common baseline for automated state-aware protocol fuzzing without direct language-model synthesis~\cite{fuzzusb_hybrid_stateful_fuzzing_2022,diane_identifying_fuzzing_triggers_2021,android_smarttvs_vulnerability_discovery_2021,saturn_host_gadget_synergistic_2024,devfuzz_automatic_device_model_2023,dnafuzz_descriptor_aware_fuzzing_2025,snipuzz_black_box_fuzzing_2021,dtls_fuzzer_dtls_protocol_2022,edhoc_fuzzer_edhoc_protocol_2023}."
    ),
    (
        r"Because LLMs are pre-trained on large corpora that include many public protocol specifications, their grammar priors can be substantially stronger than random bit-flipping~\cite{chatafl}.",
        r"Because LLMs are pre-trained on large corpora that include many public protocol specifications, their grammar priors can be substantially stronger than random bit-flipping~\cite{chatafl,large_language_models_are_2023,large_language_models_are_2024,docter_documentation_guided_fuzzing_2022,utopia_automatic_generation_fuzz_2023,fuzzing_deep_learning_libraries_2022,magneto_step_wise_approach_2024}."
    ),
    (
        r"Early protocol fuzzers emphasized manually structured knowledge (e.g., Peach, Sulley, and boofuzz~\cite{peach,sulley,boofuzz}), relying on hand-engineered templates and transition rules.",
        r"Early protocol fuzzers emphasized manually structured knowledge (e.g., Peach, Sulley, and boofuzz~\cite{peach,sulley,boofuzz}), relying on hand-engineered templates and transition rules. Orthogonal domains like browser fuzzing or OS kernels also depend heavily on structured generation techniques~\cite{corbfuzz_checking_browser_security_2021,fuzzilli_fuzzing_javascript_jit_2023,winnie_fuzzing_windows_applications_2021,pgfuzz_policy_guided_fuzzing_2021,ntfuzz_enabling_type_aware_2021,favocado_fuzzing_binding_code_2021} to bypass strict parsing checks."
    ),
    (
        r"AFLNet and StateAFL use response-derived state inference to steer exploration~\cite{aflnet,stateafl}.",
        r"AFLNet and StateAFL use response-derived state inference to steer exploration~\cite{aflnet,stateafl,sok_prudent_evaluation_practices_2024}. Similar coverage-guided techniques appear across embedded system fuzzing, hardware verification, and runtime bytecode analysis~\cite{coverage_guided_fuzzing_embedded_2023,fuzzing_hardware_like_software_2022,bcfuzz_bytecode_driven_fuzzing_2025,metamong_detecting_render_update_2023,instruguard_fuzzing_2021,smartian_analyses_2021,effectively_fuzzing_2022,fuzzeraid_signatures_2022,fuzzle_fuzzers_2022,htfuzz_fuzzing_2022,lawbreaker_vehicles_2022,qatest_systemsvirtual_2022}."
    ),
    (
        "testing complex stateful protocol implementations remains a challenging problem.",
        r"testing complex stateful protocol implementations remains a challenging problem~\cite{wants_to_be_fuzzed_2022,understanding_vulnerability_discovery_2024,evaluating_fuzz_testing_2021}."
    ),
    (
        "this domain requires maintaining and discovering multi-message temporal states",
        r"this domain requires maintaining and discovering multi-message temporal states~\cite{fuzzing_art_science_2020,towards_fuzzing_with_meaning_2023}"
    )
]

for pat, repl in replacements:
    old_text = text
    text = text.replace(pat, repl)
    if text != old_text:
        print(f"Matched and replaced: {pat[:60]}...")
    else:
        print(f"FAILED to match: {pat[:60]}...")

open("main.tex", "w").write(text)
