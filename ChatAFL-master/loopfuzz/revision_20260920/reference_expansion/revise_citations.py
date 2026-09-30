from pathlib import Path
import re,json
B=Path(__file__).resolve().parent;P=B.parent/'main.revised.tex';s=P.read_text()
a=s.index(r'\section{Related Work and Novelty Boundary}');b=s.index(r'\begin{table*}',a)
related=r'''\section{Related Work and Novelty Boundary}
Stateful greybox fuzzing studies how to expose, infer, and schedule protocol state~\cite{aflnet,stateafl,nsfuzz,sgf_usenix22}. AFLNet supplies a response-derived IPSM, whereas StateAFL and NSFuzz use different internal observations. The subsequent AFLNet study revisits coverage-guided protocol fuzzing~\cite{aflnet5years2025}, while greybox protocol-state learning investigates how internal observations inform inferred models~\cite{stateinspector2022}. LoopFuzz retains the response-visible interface and studies its instrumental reliability under an independent code-progress criterion. It does not claim to originate state inference or to first identify misleading responses.

Execution control and feedback interpretation address complementary problems. Nyx-Net uses incremental snapshots for network fuzzing~\cite{nyxnet2022}; SnapFuzz targets high-throughput execution of network applications~\cite{snapfuzz2022}; fault-injection-based network fuzzing provides another approach to exercising protocol interactions~\cite{fuzztructionnet2024}. BLuEMan simulates interactions between actual Bluetooth Low Energy (BLE) stacks~\cite{blueman2025}. DistFuzz combines events, faults, and timing with message-sequence feedback and symmetry-based pruning for distributed systems~\cite{distfuzz2025}. These studies motivate treating execution conditions and observable feedback as separate design choices. Their protocol domains and execution mechanisms are not evidence that LoopFuzz generalizes beyond its evaluated servers.

Structured generation reduces the difficulty of producing admissible inputs. Gramatron and CarpetFuzz exploit grammars and documented constraints~\cite{gramatron_effective_grammar_aware_2021,carpetfuzz_documentation_2023}. FormatFuzzer derives parsers, mutators, and generators from binary-format specifications~\cite{formatfuzzer}; Fuzztruction instead injects faults into a generating program to retain implicit format knowledge~\cite{fuzztruction2023}. MINER uses valid sequence templates and learned request parameters to guide later requests~\cite{miner2023}. These approaches concern how candidates are constructed. Our admission rule asks a subsequent question: whether a candidate has enough independently observed code value to acquire durable queue resources.

LLM-assisted fuzzing extends generation to protocol interactions, device inputs, and programs~\cite{chatafl,llmif_augmented_large_language_2024,fuzz4all_universal_fuzzing_large_2024}. FuzzGPT studies unusual programs for deep-learning libraries~\cite{fuzzgpt2024}, and WhiteFox uses compiler source information to guide optimization-triggering tests~\cite{whitefox2024}. ProphetFuzz predicts high-risk option combinations from documentation~\cite{prophetfuzz2024}. Recent studies also address LLM-assisted hybrid fuzzing~\cite{hybridllm2026} and predicate-guided synthesis for directed testing~\cite{hgfuzzer2026}. These varied generation objectives reinforce the distinction between a model's proposal and evidence obtained by executing it. LoopFuzz's controlled ChatAFL comparison preserves its scheduling lineage; the proposed intervention concerns admission and subsequent response-state investment.

Adaptive resource allocation is established in fuzzing. The Bandit's States models protocol-state selection as a bandit problem~\cite{bandits_states2023}; Thompson-sampling seed scheduling~\cite{zhang2026thompson} and state-significance-guided protocol fuzzing~\cite{ssgfuzz2026} further delimit the contribution. FOX formulates coverage-guided fuzzing as online stochastic control~\cite{fox2024}, while FISHFUZZ dynamically prioritizes targets and seeds using distance information~\cite{fishfuzz2023}. WingMuzz studies two-dimensional scheduling for blackbox protocol testing~\cite{wingmuzz2025}. Thus neither adaptive selection nor a productivity score is novel by itself. The distinction here is the combination of a response-derived proxy, an independent code-progress target, provisional and durable LLM-candidate admission, and traceable episode-level evidence.

Protocol correctness also requires an oracle beyond apparent acceptance. ProtocolGuard combines specification-derived checks with dynamic verification of non-compliance~\cite{protocolguard2026}; BSFuzzer uses context-aware semantic testing for BLE logic flaws~\cite{bsfuzzer2026}; MerCuriuzz targets logical vulnerabilities in QUIC implementations~\cite{mercuriuzz2026}. These studies examine semantic violations, whereas our calibration reward measures code productivity. A response-state transition or positive code reward therefore does not certify security impact. Magma's ground-truth bug conditions motivate distinguishing bug-related reachability from triggering~\cite{magma2020}; our historical vulnerability protocol additionally requires patch validation and controlled information exposure.

Evaluation methodology is a further boundary. ProFuzzBench and FuzzBench provide structured evaluation settings for protocol and general-purpose fuzzers~\cite{profuzzbench_benchmark_stateful_protocol_2021,fuzzbench2021}. Reliability analyses and prudent evaluation practices require care when interpreting coverage, repeated trials, and resource controls~\cite{reliability_benchmarking_2022,sok_prudent_evaluation_practices_2024}. Our protocol adopts these concerns while keeping available retrospective observations distinct from the unfinished confirmatory comparisons. A larger bibliography does not supply the missing candidate-level, episode-level, or controlled rediscovery evidence.

'''
# The manuscript discusses evidence, not the editorial process.
related=related.replace('A larger bibliography does not supply the missing candidate-level, episode-level, or controlled rediscovery evidence.','Candidate-level, episode-level, and controlled rediscovery measurements remain necessary to establish the proposed mechanisms.')
s=s[:a]+related+s[b:]
old='Allocated resources do not establish equal consumption; initialization, model waiting, validation, mutation, and termination all contribute to experimental cost.'
new=old+r' Resource-efficient benchmarking also makes the cost of obtaining reliable comparisons an explicit concern~\cite{greenbenchmark2023}. The proposed analysis therefore distinguishes allocated CPU-hours, measured consumption, and actual search exposure.'
assert s.count(old)==1;s=s.replace(old,new)
old='Admission, calibration, and rediscovery each require independent supporting evidence.'
new=old+r'''

Benchmark properties can change the relative ranking of fuzzers: initial seed coverage and execution speed are empirically consequential covariates~\cite{benchmarkproperties}. Consequently, a favorable endpoint under unequal experimental conditions cannot isolate the admission or scheduling effect. Mutation-based assessment offers a complementary fault-oriented perspective~\cite{mutationassessment2023}; here, code coverage and IPSM growth are kept separate from independently verified vulnerability outcomes.'''
assert s.count(old)==1;s=s.replace(old,new)
# Repair a pre-existing broken reference without changing its sentence meaning.
s=s.replace('Table~\nef{tab:llm}',r'\namedref{Table}{tab:llm}')
P.write_text(s)
keys=set(k.strip() for group in re.findall(r'\\cite\w*\*?(?:\[[^]]*\])*\{([^}]+)\}',s) for k in group.split(','))
bibkeys=set(re.findall(r'@\w+\s*\{([^,]+),',(B.parent/'references.expanded.bib').read_text()))
assert keys==bibkeys,(keys-bibkeys,bibkeys-keys)
assert len(keys)>=50 and r'\nocite' not in s
manifest=json.loads((B/'manifest.json').read_text())
for entry in manifest['sources']:
 hits=[]
 for n,p in enumerate(s.split('\n\n'),1):
  if any(entry['key'] in [k.strip() for k in group.split(',')] for group in re.findall(r'\\cite\w*\*?(?:\[[^]]*\])*\{([^}]+)\}',p)):
   line=s[:s.index(p)].count('\n')+1;hits.append({'line':line,'paragraph':p})
 entry['cited_in']=hits
manifest['unique_actual_citations']=len(keys)
manifest['related_work_words']=len(re.findall(r"[A-Za-z]+(?:[-'][A-Za-z]+)*",re.sub(r'\\cite\{[^}]+\}','',related)))
(B/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'actual_distinct_citations':len(keys),'uncited_entries':len(bibkeys-keys),'related_work_words':manifest['related_work_words'],'cited_source_mapping':len(manifest['sources'])},ensure_ascii=False))
