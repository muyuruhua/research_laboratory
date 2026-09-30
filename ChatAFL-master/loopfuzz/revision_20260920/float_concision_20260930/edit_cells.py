from pathlib import Path
import re
R=Path(__file__).resolve().parent.parent
p=R/'main.revised.tex';s=p.read_text()
def block(label):
 global s
 for m in re.finditer(r'\\begin\{(table\*?)\}.*?\\end\{\1\}',s,re.S):
  if r'\label{'+label+'}' in m[0]:return m
 raise ValueError(label)
def rows(label,content):
 global s
 m=block(label);b=m[0];a=b.index(r'\midrule')+len(r'\midrule');z=b.index(r'\bottomrule')
 s=s[:m.start()]+b[:a]+'\n'+content.strip()+'\n'+b[z:]+s[m.end():]
def replacements(label,pairs):
 global s
 m=block(label);b=m[0]
 for old,new in pairs:
  assert b.count(old)==1,(label,old);b=b.replace(old,new)
 s=s[:m.start()]+b+s[m.end():]
def prose(old,new):
 global s
 assert s.count(old)==1,old[:100];s=s.replace(old,new)
rows('tab:boundary',r'''
Forked-daapd & Overestimation: IPSM-only growth. & IPSM growth; low code reward. & Code regression not reproduced. \\
Lighttpd1 & Underestimation: weak state signal. & Code gain with little IPSM growth. & Both endpoints increase; mechanism unverified. \\
LightFTP & Saturation: IPSM growth after code plateau. & Aligned code/IPSM saturation trajectories. & Near-equal code endpoints; matched-version trajectories needed. \\
''')
replacements('tab:novelty',[
('Calibrate the response proxy; no semantic-state recovery.','Proxy calibration, not semantic-state recovery.'),
('Protocol-informed message/sequence generation.','Protocol-guided message/sequence generation.'),
('Established selection framework; coupled proxy calibration and admission here.','Couple proxy calibration with admission.'),
('Established allocation methods; response-proxy calibration here.','Calibrate response proxies.'),
('Magma~\\cite{magma2020}; evaluation methodology','Magma~\\cite{magma2020}; evaluation studies'),
('Ground-truth bug conditions; repeated evaluation.','Ground-truth bug oracles; repeated trials.')])
replacements('tab:predicates',[('Predicate & Positive evidence & Example failure & Required evidence','Predicate & Pass condition & Failure & Measurements')])
rows('tab:predicates',r'''
$P$ & Valid required structure. & Missing fields; invalid lengths/delimiters. & Candidate; criteria; reason; hypothesis version. \\
$U$ & Accepted response. & Rejection; timeout/reset/drop; unparseable reply. & Response; acceptance rule; failure/exception. \\
$R$ & Target/frontier reached or sink escaped. & Sink retained; destination missed. & Source/target; observed state sequence. \\
$\gcode$ & New code coverage or code-supported favored entry. & IPSM-only novelty. & Pre/post coverage; novelty; favored reason. \\
$\gstate$ & New IPSM node, state edge, or path. & Known IPSM structure. & Pre/post IPSM; new state transitions. \\
''')
rows('tab:implementation',r'''
Gate before promotion & Retention may precede $U/R$. & Queue protection unverified. \\
Independent state-only evidence & State assessment follows retention. & Zero provisional counts may be structural. \\
Complete $P/R$ verification & $P$: recognition; $R$: transition. & Validity and reachability unverified. \\
New-code reward & Execution-frequency novelty may contribute. & Distinguish branches, frequency, and retention. \\
Fixed-energy episodes & Variable energy; zero executions. & Unequal opportunities. \\
Strict provisional budget & Post-round budget checks. & 64-mutation/30-second limits may be exceeded. \\
Verified run conditions & Initial and effective settings may differ. & Verify conditions throughout each run. \\
Total call/token caps & 64-call cap: plateau only; tokens unverified. & Total-budget fairness unverified. \\
Repair off in C/D/E & Repair status incompletely verified. & Arm labels do not prove adherence. \\
''')
rows('tab:events',r'''
Experimental conditions & Arm; software/model versions; environment; sampling seed. & Call/token caps; resources; period; termination. \\
Candidate generation & Candidate/prompt; lineage; request/response; action; source/target. & Input/output tokens; generation time. \\
Admission trial & Candidate/trial; $P/U/R$; responses; reachability. & Code/IPSM changes; priority; latency; decision. \\
Provisional validation & Candidate; budget; first productive descendant. & Executions; code gain; conversion/expiration; latency; censoring. \\
State-selection episode & State/seed; pre-update posterior; sample; selection scores. & Mutations; code/IPSM gain; reward; updated posterior; duration/completion. \\
Security outcome & Anonymous oracle; reproducer; diagnostics; root cause. & Reached/triggered; first trigger; version-pair outcomes. \\
Repair (optional) & Lineage; counterexample; hypotheses; changed component. & Validation; post-repair predicates/gain; tokens; latency. \\
''')
prose('CVE identities remain isolated benchmark metadata. Missing observations are not assigned zero values.',r'CVE identities remain isolated benchmark metadata. Missing observations are not assigned zero values. Conditions distinguish target/fuzzer and model/service versions, sampling parameters, random seeds, and CPU/memory limits. Admission measurements retain reasons, state sequences, and separate pre/post code and IPSM counts. Episodes retain pre/post $\alpha,\beta$, the pre-update mean, Thompson sample, and frontier/selection scores.')
replacements('tab:arms',[
('B--A: controlled LLM-lineage change.','B--A: LLM-lineage comparison.'),
('Parseable candidates directly durable','Parseable to durable'),
('Evidence gate + provisional queue','Evidence gate; provisional queue'),
('D--C: admission effect.','D--C: admission effect.'),
('E--D: calibration effect.','E--D: calibration effect.')])
replacements('tab:targets',[
('Pinned source revision','Source revision'),('Seeds / dictionary / reset','Seed protocol / dictionary / reset'),
('in-ftp; ftp.dict; ftpclean script','FTP; yes; cleanup'),
('in-smtp; smtp.dict; clean script','SMTP; yes; cleanup'),
('in-rtsp; rtsp.dict; no reset script recorded','RTSP; yes; unrecorded'),
('in-sip; no dictionary; run\\_pjsip reset','SIP; no; PJSIP routine'),
('in-daap; no dictionary; no reset script recorded','DAAP; no; unrecorded'),
('in-http; http.dict; no reset script recorded','HTTP; yes; unrecorded')])
m=block('tab:targets');b=m[0];assert b.count('in-ftp; ftp.dict; clean script')==3;s=s[:m.start()]+b.replace('in-ftp; ftp.dict; clean script','FTP; yes; cleanup')+s[m.end():]
prose('Source revisions are pinned in the benchmark Dockerfiles, and each archive records its own invocation; image rebuild provenance beyond those pins is not embedded in the per-run evidence, and conditions reported for other studies are not attributed to these trials.','Source revisions are fixed by the benchmark configuration; endpoints and initialization procedures follow the recorded trial conditions. Build identity beyond those revisions remains unverified. In the table, yes/no denotes dictionary use, and unrecorded means that no reset procedure was recorded; it does not establish that state restoration occurred.')
replacements('tab:llm',[
('Model, version, and inference service','Model / version / service'),
('codex-auto-review via cctq.ai chat-completions endpoint','codex-auto-review; cctq.ai'),
('Identical resolved version; name alone insufficient.','Same resolved version; name insufficient.'),
('Temperature by call class','Temperature by call class'),
('Match each call class across arms.','Match each call class.'),
('Top-$p$ / presence and frequency penalties','Top-$p$ / presence/frequency penalties'),
('Explicit values or documented defaults.','Explicit values or defaults.'),
('Maximum output tokens per attempt','Output tokens per attempt'),
('Shared limit; include truncated/failed responses.','Same cap; include truncation/failures.'),
('Maximum attempted calls / total tokens','Attempted-call / total-token caps'),
('Count all call classes and retries.','Count all classes and retries.'),
('Timeout and repeated-request policy','Timeout / retry policy'),
('Identical policy; account for waiting and failures.','Same policy; include waits/failures.'),
('Model-side seed / support status','Model seed / support'),
('Record support; no determinism guarantee.','Document support; determinism unassured.'),
('Prompt corpus / template version','Prompt corpus / template'),
('Shared information policy; traceable prompts/responses.','Same information policy; traceable exchanges.'),
('Shared intervention and state-growth criteria.','Same intervention/state-growth criteria.')])
prose('Unverified shared settings remain unspecified in \\namedref{Table}{tab:llm}.','Unverified shared settings remain unspecified in \\namedref{Table}{tab:llm}. Listed values are supported by final configuration observations for C/D/E and the sensitivity groups; equivalent B observations are unavailable.')
replacements('tab:mechanisms',[
('Distinct candidates within each experimental record.','Within-run distinct candidates.'),
('Distinct trials within each experimental record.','Within-run distinct trials.'),
('First false $P$, then $U$, then $R$; denominator: trials.','Trial denominator; first false $P$, $U$, or $R$.'),
('Provisional admissions; include pending/censored cases.','Provisional admissions; retain pending/censored cases.'),
('Mean $\\pm$ SD of within-run trial means; contributing runs only.','Within-run trial means; contributing runs only.'),
('Verified queue-promotion timestamps required.','Verified promotion timestamps.'),
('Descendant code gain; exclude admission gain.','Descendant code gain only.'),
('Queue state and C--D counterfactual.','Queue state; C--D counterfactual.'),
('Random rejected-candidate sample.','Random rejected-candidate sample.'),
('Fixed-energy code-branch reward; proxy diagnostics: \\namedref{Table}{tab:logged_calibration}.','Fixed-energy code reward; proxies: \\namedref{Table}{tab:logged_calibration}.'),
('Joined code gain and complete usage.','Linked code gain and usage.')])
replacements('tab:repair',[
('0 (no event files)','0 recorded'),
('Before/after validation success','Pre/post validation success'),
('Post-repair descendant code gain','Post-repair descendant gain'),
('Independent effect / interval','Effect / uncertainty interval')])
rows('tab:cve',r'''
\mbox{CVE-2023-51713}\newline ProFTPD / FTP & Reported vulnerable build; 65,535-byte buffer. & 60,006-byte input; ASan heap-buffer-overflow (L). & Security patch: three rejections, no ASan (L). \\
\addlinespace[3pt]
\mbox{CVE-2026-38998}\newline LIVE555 / RTSP & Campaign: 2023.05.10; report: 2026.02.26 (R). & 728-byte public PoC; use-after-free (L). & Local patch: 1/1 triggers (R); upstream comparison unavailable. \\
\addlinespace[3pt]
\mbox{CVE-2026-39863}\newline Kamailio / SIP over TCP & Reported vulnerable build; TCP required. & 278-byte input; parsed Content-Length $-10$ (L). & Patched: 0/253 negative-value outcomes; guard observed (L). \\
\addlinespace[3pt]
SMARTPL availability case\newline forked-daapd / HTTP & Reported version 27.2. & 148-byte input; unresponsive service, live process (R). & No patched replay/CVE; removal reported in 28.4. \\
''')
# Retain detailed conditions and batch denominators in their case-specific prose.
prose('The oracle uses a 65,535-byte command buffer;', 'The 60,006-byte reproducer caused a one-byte read beyond a 65,568-byte region. The oracle uses a 65,535-byte command buffer;')
prose('while the earlier three-trial fix batch remains a separate observation.','while the earlier three-trial fix batch remains separate. Earlier reported replays yielded 1/1 seed, 1/1 fuzzer-crash, and 3/3 batch-crash reproductions; the separate fix batch yielded 0/3 using the same input and buffer.')
prose('The report attributes fuzzer-generated inputs to the same memory-lifetime failure, records 8/9 replay hits, and describes an unsuccessful local patch.','The report attributes fuzzer-generated inputs to the same memory-lifetime failure. It gives 1/1 public-PoC reproduction, 3/3 repeats for each of three fuzzer inputs, a later 8/9 aggregate, and 1/1 persistence after a local patch.')
prose('The earlier reported batches and the prior local-guard observation remain separate records.','Earlier reported batches remain separate: 1/1 seed and 3/4, 19/20, 19/20, and 50/51 selected inputs. The prior local-guard observation is also separate.')
prose('The SMARTPL case reports reproducible unavailability from a known input, while none of the five recorded campaign hangs satisfies that condition; neither a CVE identity nor a verified patched counterpart is established.','\n\nFor SMARTPL, the 148-byte input reportedly causes lexer errors and a failed health probe while the process remains alive. Reported repeats comprise 5/5 advisory trials, 3/3 trials with a 48-message seed, and a later 1/1 replay. None of the five recorded campaign hangs reproduces this condition; a CVE and verified patched counterpart remain unavailable. Parser removal in version 28.4 is reported, not a verified patched replay.')
prose('\\namedref{Table}{tab:cveresults} preserves each reported batch separately.','\\namedref{Table}{tab:cveresults} summarizes the replay outcomes; earlier reported batches remain separate in the case descriptions.')
prose('Two full-artifact replays extend these batches.','Three complete-input replays extend these batches (September 30 observations).')
prose('(233 in-campaign and 9 teardown inputs)','(233 in-campaign inputs: 121 and 112 per run; 9 teardown inputs)')
prose('Third, all 253 Kamailio queue entries carrying an oversized Content-Length were replayed on the \\texttt{o-kam-01} pair: 102 produce the negative-value overflow artifact on the vulnerable build and none on the patched build.',r'Third, all 253 Kamailio queue entries with Content-Length $\geq 2^{31}$ were replayed on the \texttt{o-kam-01} pair: 102 produce the negative-value artifact on the vulnerable build and none on the patched build. The two runs contributed 77 and 176 entries, with yields of 36/77 and 66/176. Overflow values include $-2147483648$, $-1$, and $-954437177$; 151/253 entries do not produce the artifact, with ordering and parse-path explanations unresolved.')
replacements('tab:cveresults',[('Case & Vulnerable-side batches (R) & Patched or diagnostic control & Interpretation / missing evidence','Case & Replay outcome & Control outcome & Evidence limit')])
rows('tab:cveresults',r'''
\mbox{CVE-2023-51713} & 172/233 ASan triggers (L). & Patched: 0/242 ASan activations (L). & Artifact replay; campaign recall unmeasured. \\
\addlinespace[3pt]
\mbox{CVE-2026-38998} & 82/88 server terminations (L). & Local patch: 1/1 triggers (R). & No sanitizer or verified patched build. \\
\addlinespace[3pt]
\mbox{CVE-2026-39863} & 102/253 negative-value outcomes (L). & Patched: 0/253; guard: 193/253 (L). & Selected queue entries; campaign recall unmeasured. \\
\addlinespace[3pt]
SMARTPL availability case & Advisory: 5/5; seed: 3/3; later: 1/1 (R). & Campaign hangs: 0/5 matching outcomes (R). & Known-input replay; no patch or CVE. \\
''')
rows('tab:threats',r'''
Internal & Admission-only C--D; scheduling-only E--D; repair off; matched initial states. & Missing observations; uncertain decision order. \\
Construct & Separate code branches, IPSM state edges, bitmap counts, and oracle outcomes. & Proxies incompletely measure intended criteria. \\
Statistical & Repeated runs; test families; effect sizes; clustered/hierarchical CIs; censoring. & Unequal durations; no confirmatory effects. \\
Selection & Intention-to-run accounting; prespecified infrastructure repetitions. & Unobserved planned runs; independence uncertain. \\
Reproducibility & Match versions, settings, seeds, prompts, and measurements. & Unresolved model versions; incomplete provenance. \\
External & Multiple targets/protocols; boundary cases; adapter assumptions. & Encrypted/opaque binary protocols untested. \\
Security & Minimal patch pairs; independent triggers; information isolation. & Controlled A--E/patch-pair evidence incomplete; pretraining leakage unresolved. \\
''')
p.write_text(s)
print('Compressed narrative cells in 13 tables; retained case details in nearby prose.')
