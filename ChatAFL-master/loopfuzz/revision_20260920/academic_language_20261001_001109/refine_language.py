from pathlib import Path
import json,re,difflib,collections
rev=Path('/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/loopfuzz/revision_20260920')
audit=rev/'academic_language_20261001_001109'
p=rev/'main.revised.tex'
old=p.read_text();new=old;changes=[]
def replace(before,after):
 global new
 assert before!=after
 assert new.count(before)==1,(before,new.count(before))
 new=new.replace(before,after,1)
 changes.append({'before':before,'after':after})
def paragraph(start,after):
 lines=[l for l in new.splitlines() if l.startswith(start)]
 assert len(lines)==1,(start,len(lines))
 replace(lines[0],after)
replace('This deployment advantage comes with an abstraction boundary:','This limited need for target-specific knowledge comes with an abstraction boundary:')
paragraph('The scope is textual or semi-textual',r'The scope is textual or semi-textual request-response protocols for which request structure, responses, and code coverage are observable. Response-derived state inference requires no target-specific access to internal state, but the complete controller remains greybox because productivity requires code feedback. It is not a pure black-box system. Encrypted or opaque binary protocols require additional assumptions about request construction, response interpretation, and code observability before evaluation.')
replace('WingMuzz schedules open-source protocol implementations and their seeds to guide blackbox testing','WingMuzz schedules open-source protocol programs and their seeds to guide blackbox testing')
replace('MerCuriuzz targets logical vulnerabilities in QUIC implementations','MerCuriuzz targets logical vulnerabilities in QUIC systems')
replace('What runtime, throughput, and LLM costs arise,','What execution-time, throughput, and LLM costs arise,')
replace('Timeout, retry, seed, and template descriptions are source-derived; they do not independently verify the settings of every executed build.','Timeout, retry, seed, and prompt-template settings describe the prescribed procedure; their actual use is not independently verified for every run.')
replace('fatal provider errors abort retries','nonrecoverable service failures end further attempts')
replace('none; no seed parameter is sent','none specified in model requests')
replace('no version identifier; per-request prompt hashes logged; template identity tracks the fuzzer commit','no independent corpus/template version; prompts identifiable; template tied to fuzzer version')
paragraph('The dataset contains 94 AFLNet',r'The dataset contains 94 AFLNet (A), 91 ChatAFL (B), 104 benchmark LoopFuzz (D), 90 direct-admission (C), and 91 calibrated (E) observations. The sensitivity conditions contain 81 observations at $\gamma=0.99$ and 91 at $\gamma=1.0$. Final configuration records assign a fixed-policy label to 17 of the 90 nominal C observations and 12 of the 91 nominal E observations; the $\gamma=0.99$ and $\gamma=1.0$ groups contain 15 and 12 such records. Within nominal C, the reported dispositions (all durable, none rejected) corroborate direct admission. E and the sensitivity groups cannot be distinguished behaviorally from the presence of posterior observations alone, because these observations occur in every LoopFuzz condition. Program versions also vary within nominal arms: D includes four versions (78/12/9/5 runs), C two (83/7), and E two (71/20); each sensitivity condition uses a single version. The analysis retains the original nominal group assignments and treats their uncertain correspondence to effective conditions as a validity limitation. All available observations are retained without assuming independence. The nominal target is ten trials per condition; actual sample sizes $n$ remain explicit. Means and sample SDs use observed values only, with no imputation for unavailable trials.')
replace('Reported runtime measures active fuzzing rather than total CPU consumption or the entire experimental period.','The reported duration measures active fuzzing rather than total CPU consumption or the entire experimental period.')
replace('therefore describe recorded counters, not verified queue behavior.','therefore describe reported totals, not independently verified queue behavior.')
replace('first-failure flags do not independently explain queue retention.','first-failure classifications do not independently explain queue retention.')
replace('Some coverage observations represent distinct instrumentation locations or coverage-based retention events rather than independent source-level code branches.','Some coverage observations identify monitored execution locations or coverage-based retention decisions rather than independent source-level code branches.')
replace('they condition the logged proxy reward on one energy','they condition the observed proxy reward on one energy')
replace('over 0--24 hours from fuzzer startup','over 0--24 hours from the start of each run')
replace('without applying a cumulative maximum or otherwise correcting the replay output','without enforcing monotonicity or otherwise altering the recorded measurements')
replace('provider charges','service charges')
paragraph('The recorded end-of-run configurations identify',r'The final configuration records specify a model name, grammar/plateau temperatures of 0.5/1.2, top-$p$ of 1.0, an output limit of 4096 tokens, a call cap of 64, and a token-limit setting of 0. These values are present for every C/D/E and $\gamma$-sensitivity observation and are summarized in \namedref{Table}{tab:llm}; equivalent configuration evidence is unavailable for B. A model name does not uniquely identify the inference version. Uncertainty in effective conditions and resource measurement limits interpretation, so these values do not establish the shared confirmatory settings required of B--E.')
replace('Candidate token fields do not necessarily cover all call classes or retries; summing them is not total campaign cost.','Candidate-associated token counts may exclude other request types or repeated attempts; their sum therefore need not equal total campaign cost.')
replace('Reported vulnerable build; 65,535-byte buffer.','Reported vulnerable version; 65,535-byte buffer.')
replace('Reported vulnerable build; TCP required.','Reported vulnerable version; TCP required.')
paragraph('For ProFTPD, the reported defect',r"""For ProFTPD, the reported defect is an out-of-bounds read during FTP command processing, supported by an ASan heap-buffer-overflow observation. The 60,006-byte reproducer caused a one-byte read beyond a 65,568-byte region. The oracle uses a 65,535-byte command buffer; the report states that the default 512-byte configuration does not expose the same error to ASan. The result is therefore conditional on this setting. The full replay in \namedref{Table}{tab:cveresults} compares the campaign's base version with the same version incorporating only the minimal upstream security correction. In this pair, 172 of 233 campaign crash inputs satisfy the FTP command-processing memory-error criterion in the vulnerable version, whereas none of 242 activate ASan in the patched version. This supplies differential replay evidence with verified version identity for the pair, while the earlier three-trial patch comparison remains separate. Earlier reported replays yielded 1/1 seed, 1/1 fuzzer-crash, and 3/3 batch-crash reproductions; the separate patch comparison yielded 0/3 using the same input and buffer.""")
paragraph('For Kamailio, a negative parsed',r'For Kamailio, a negative parsed Content-Length supports the reported integer-overflow condition. The trigger requires TCP and is not assessed by the UDP-only benchmark condition. The complete-input comparison in \namedref{Table}{tab:cveresults} evaluates every retained input with an oversized Content-Length against two versions that differ only by the upstream security check. Among these inputs, 102 of 253 produce a negative-length outcome in the vulnerable version and none do in the patched version; the security check is observed in 193 of 253 patched-version trials. Earlier reported batches remain separate: 1/1 seed and 3/4, 19/20, 19/20, and 50/51 selected inputs. The earlier comparison using a local security check is also separate. These inputs were generated during fuzzing, so the analysis measures predicate yield among retained inputs rather than independent rediscovery. An earlier unsupported 20/20 versus 0/20 claim is excluded from quantitative results.')
paragraph('For SMARTPL, the 148-byte',r'For SMARTPL, the 148-byte input reportedly causes lexical-analysis errors and service unresponsiveness while the process remains active. Reported repeats comprise 5/5 advisory trials, 3/3 trials with a 48-message seed, and a later 1/1 replay. None of the five recorded campaign hangs reproduces this condition; a CVE and verified patched counterpart remain unavailable. Removal of the affected parsing component in version 28.4 is reported, but has not been validated by a patched-version replay.')
paragraph('Three complete-input replays extend',r'''Complete-input replays (September 30 observations) provide three additional comparisons. For ProFTPD, every crash-associated input from the two 24-hour LoopFuzz campaigns (233 inputs during active fuzzing: 121 and 112 per run; 9 during termination) was replayed once against a verified version pair with a common base version and only the minimal upstream security correction. In the vulnerable version, 172 of the 233 inputs from active fuzzing satisfy the ASan heap-buffer-overflow criterion in FTP command processing. All 172 share the same diagnostic signature, with no alternative signature observed. The patched version shows no ASan activation for any of the 242 inputs. The 61 non-reproducing inputs and the 9 termination-phase inputs may depend on campaign states not reconstructed by isolated replay. Diagnostics from the original campaigns are insufficient to confirm these outcomes, so their classification relies on the controlled version-pair replay.

For LIVE555, all 88 campaign crash inputs were replayed against the tested version without sanitizer-based memory checks: 82 terminate the server and 6 do not. This establishes reproduction only under those experimental conditions; without a patched counterpart or memory-error diagnosis, it does not attribute the crashes to the use-after-free.

For Kamailio, all 253 retained inputs with Content-Length $\geq 2^{31}$ were evaluated against the verified vulnerable/patched pair. Of these, 102 produce a negative-length outcome in the vulnerable version and none in the patched version. The two runs contributed 77 and 176 inputs, with yields of 36/77 and 66/176. Overflow values include $-2147483648$, $-1$, and $-954437177$; 151/253 inputs do not produce the outcome, and the roles of interaction order and request interpretation remain unresolved. These three comparisons characterize individual-input replay; they provide no arm-level recall, time-to-trigger, or cost denominators.''')
replace('Artifact replay; campaign recall unmeasured.','Input replay; campaign recall unmeasured.')
replace('No sanitizer or verified patched build.','No sanitizer or verified patched version.')
replace('while retaining anonymous oracle IDs in separate benchmark metadata.','while maintaining a separate, anonymized correspondence between cases and their evaluation criteria.')
replace('Richer parsing or internal-state instrumentation addresses different aspects at the cost of adapter complexity and deployment effort.','Richer response interpretation or direct observation of internal state addresses different aspects but requires additional target-specific knowledge and measurement access.')
replace(r'\subsection{Cost, nonstationarity, and provider variability}',r'\subsection{Cost, nonstationarity, and model variability}')
replace('boundary cases; adapter assumptions.','boundary cases; observability assumptions.')
replace('under incomplete operational validation.','under incompletely verified experimental conditions.')
def nums(s):
 s=re.sub(r'\\texttt\{o-(?:pftp|kam)-01\}','',s)
 return collections.Counter(re.findall(r'(?<![A-Za-z0-9])[-+]?\d+(?:,\d{3})*(?:\.\d+)?(?![A-Za-z0-9])',s))
assert nums(old)==nums(new),{'removed':list((nums(old)-nums(new)).items()),'added':list((nums(new)-nums(old)).items())}
def citations(s):return re.findall(r'\\cite\w*\*?(?:\[[^\]]*\])*\{[^}]+\}',s)
assert citations(old)==citations(new)
for name in ['align','equation','tikzpicture','algorithm']:
 pat=re.compile(r'\\begin\{'+name+r'\*?\}.*?\\end\{'+name+r'\*?\}',re.S)
 assert pat.findall(old)==pat.findall(new),name
p.write_text(new)
assert p.read_text()==new
(audit/'phase2_changes.json').write_text(json.dumps(changes,ensure_ascii=False,indent=2)+'\n')
original=(audit/'before'/'main.revised.tex').read_text()
(audit/'changes.diff').write_text(''.join(difflib.unified_diff(original.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='before/main.revised.tex',tofile='main.revised.tex')))
print(json.dumps({'phase2_changes':len(changes),'all_numerical_values_preserved':True,'only_numeric_identifier_removal':['o-pftp-01','o-kam-01'],'citations_preserved':True,'equations_diagrams_algorithm_preserved':True,'bytes_before':len(old.encode()),'bytes_after':len(new.encode())},ensure_ascii=False,indent=2))
print('ALGORITHM_CONTEXT')
ls=new.splitlines()
for i in range(352,380):print(f'{i+1}: {ls[i]}')
print('REMAINING_ENGINEERING_MARKERS')
pat=re.compile(r'\b(?:Docker\w*|directories|directory|folder|archives?|commits?|hashes?|logging|logged|sidecars?|teardown|startup|builds?|scripts?|files?|artifact[s]?|pipeline|repository|debug|harness|telemetry|adapter[s]?|deployment|runtime)\b|/home/|Key_Experiment|make\\_ftp\\_cmd|o-pftp-01|o-kam-01',re.I)
for i,l in enumerate(ls,1):
 if l.startswith('%'):continue
 # Do not interpret nonprinting LaTeX dependency paths or reference keys as prose.
 l=re.sub(r'\\(?:input|includegraphics|bibliography|label|ref|figref)(?:\[[^\]]*\])?\{[^}]*\}','',l)
 l=re.sub(r'\\namedref\{([^}]*)\}\{[^}]*\}',r'\1',l)
 if pat.search(l):print(i,l)
