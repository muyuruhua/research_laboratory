from pathlib import Path
import json,re,sys
a=Path(__file__).resolve().parent
cues={
'aflnet':r'response codes|inferred protocol|state machine',
'stateafl':r'response codes|long-lived|memory snapshot',
'nsfuzz':r'state variables|synchronization|instrumentation',
'sgf_usenix22':r'enum|state variables',
'chatafl':r'grammar extraction|seed enrichment|predicting|coverage plateau',
'aflnet5years2025':r'protocol state|response codes|coverage-guided',
'stateinspector2022':r'memory|snapshot|learning',
'nyxnet2022':r'incremental snapshot',
'snapfuzz2022':r'snapshot|asynchronous|file system',
'fuzztructionnet2024':r'fault injection|generator|protocol participant',
'blueman2025':r'simulat|physical|stack',
'distfuzz2025':r'message sequence|symmetry|time',
'gramatron_effective_grammar_aware_2021':r'automaton|grammar representation',
'carpetfuzz_documentation_2023':r'dependenc|constraint|natural language',
'formatfuzzer':r'binary templates|parser|mutator',
'fuzztruction2023':r'fault injection|generator|generating',
'miner2023':r'template|longer|attention',
'llmif_augmented_large_language_2024':r'feedback|device|field',
'fuzz4all_universal_fuzzing_large_2024':r'autoprompt|mutation|input generation',
'fuzzgpt2024':r'edge.case|unusual|prim',
'whitefox2024':r'optimization|analysis LLM',
'prophetfuzz2024':r'high-risk|option combination',
'hybridllm2026':r'hybrid|concolic|plateau|saturat',
'hgfuzzer2026':r'harness|predicate|constraint',
'bandits_states2023':r'bandit|reward|AFLNet',
'fox2024':r'stochastic|control|scheduler',
'fishfuzz2023':r'distance|dynamic',
'protocolguard2026':r'finite state|verification|specification',
'bsfuzzer2026':r'semantic|state machine|verification',
'mercuriuzz2026':r'logical vulnerabilit|oracle|black.box',
'magma2020':r'reached|triggered|canar',
'profuzzbench_benchmark_stateful_protocol_2021':r'coverage|repeat|target',
'fuzzbench2021':r'reproducib|benchmark|statistic',
'reliability_benchmarking_2022':r'bug|coverage|correlat',
'sok_prudent_evaluation_practices_2024':r'repeat|statistic|coverage',
'greenbenchmark2023':r'resource|early|confidence',
'benchmarkproperties':r'execution speed|seed coverage|ranking',
'mutationassessment2023':r'mutation analysis|killed|fault',
'davis2006pr':r'interpolat|area|skew',
'benjamini1995':r'independent|theorem|dependen',
'kaplan1958':r'independen|censor|limit',
'efron1979':r'empirical distribution|sample|bootstrap',
'thompson1933':r'probability|distribution|proportion',
'brier1950':r'score|categories|verification',
'cliff1993':r'dominance|probability|independen',
'mann1947':r'continu|independen|stochastic',
'guo2017calibration':r'Expected Calibration Error|ECE =',
'ssgfuzz2026':r'significance|coverage|state',
'zhang2026thompson':r'Beta|Thompson|seed',
'wingmuzz2025':r'two.dimensional|sequence|packet',
 'tscheduler2024':r'Beta|Bernoulli|Thompson|schedule'
}
for k in sys.argv[1:]:
 p=a/'sources'/k/'paper.txt'
 if not p.exists():print('MISSING',k);continue
 pages=p.read_text().split('\f');out=[]
 for idx,page in enumerate(pages):
  if idx==0:continue
  lines=page.splitlines();matches=[j for j,l in enumerate(lines) if re.search(cues.get(k,k),l,re.I)]
  if not matches:continue
  if re.search(r'^\s*(?:\d+\s+)?REFERENCES\s*$',page,re.M|re.I):break
  # Use one substantive window per page, never just the paper title.
  j=next((j for j in matches if j>3),None)
  if j is None:continue
  text='\n'.join(lines[max(0,j-3):j+8]);out.append({'pdf_page':idx+1,'excerpt':text})
  if len(out)==3:break
 (a/'sources'/k/'evidence_windows.json').write_text(json.dumps(out,indent=2,ensure_ascii=False)+'\n')
 print('\nSOURCE',k,'PAGES',len(pages)-1)
 for x in out:print('PDF PAGE',x['pdf_page'],'\n',x['excerpt'])
