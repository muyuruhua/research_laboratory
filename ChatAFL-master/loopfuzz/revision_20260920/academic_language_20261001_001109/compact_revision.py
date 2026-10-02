from pathlib import Path
import re,json,collections,difflib,subprocess
rev=Path('/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/loopfuzz/revision_20260920')
audit=rev/'academic_language_20261001_001109'
p=rev/'main.revised.tex';old=p.read_text();new=old;changes=[]
def replace(a,b):
 global new
 assert new.count(a)==1,(a,new.count(a))
 new=new.replace(a,b,1);changes.append({'before':a,'after':b})
def para(prefix,b):
 rows=[r for r in new.splitlines() if r.startswith(prefix)]
 assert len(rows)==1,(prefix,len(rows))
 replace(rows[0],b)
replace('This limited need for target-specific knowledge comes with an abstraction boundary:','Limited target-specific knowledge introduces an abstraction boundary:')
para('The scope is textual or semi-textual',r'The scope covers textual or semi-textual request-response protocols with observable structure, responses, and code coverage. Response-derived inference requires no internal-state access, but code-based productivity makes the controller greybox rather than purely black-box. Encrypted or opaque binary protocols require additional assumptions about request construction, response interpretation, and code observability.')
replace('Each candidate is associated with its source state, intended target/frontier, and the information supplied to and returned by the model.','Each candidate is linked to its source state, intended target/frontier, prompt, and model response.')
replace('Protocol-specific exceptions must be prespecified, with each decision supported by the observed response and its interpretation.','Protocol-specific exceptions are prespecified; responses and justifications accompany each decision.')
replace('Coverage and IPSM observations obtained before each trial establish which gains are new.','Pre-trial coverage and IPSM observations identify new gains.')
replace('Each newly discovered code element is attributed once to the responsible execution and candidate ancestry, avoiding repeated credit across ancestors.','Each code discovery receives credit once, linked to its execution and candidate ancestry.')
replace('Trial execution, ordinary mutation, and provisional validation are distinguished when attributing rewards, preventing duplicate posterior updates.','Trial execution, ordinary mutation, and provisional validation remain distinct in reward attribution, preventing duplicate updates.')
replace('Observations are linked to their originating trials and ordered in time under a consistent measurement definition. CVE identities remain separate from information available during testing.','Each observation identifies its trial, measurement definition, order, and time. CVE identities remain inaccessible during testing.')
replace(r'Associate $x$ with its proposal context and ancestry\;',r'Associate candidate with proposal context and ancestry\;')
replace(r'Reject $x$ for structural invalidity; terminate validation\;',r'Reject $x$ for invalid structure; stop\;')
replace(r'Evaluate $U,R,\gcode,\gstate$ with supporting evidence\;',r'Assess $U,R,\gcode,\gstate$ and supporting evidence\;')
replace(r'Identify the first productive descendant; promote; end validation\;',r'Identify first productive descendant; promote; stop\;')
replace(r'Classify unresolved provisional status as expiration or campaign censoring\;',r'Classify provisional status: expired or censored\;')
para('The dataset contains 94 AFLNet',r'The dataset contains 94 AFLNet (A), 91 ChatAFL (B), 104 benchmark LoopFuzz (D), 90 direct-admission (C), and 91 calibrated (E) observations. The sensitivity conditions contain 81 observations at $\gamma=0.99$ and 91 at $\gamma=1.0$. Final configuration records assign fixed-policy labels to 17 of the 90 nominal C observations and 12 of the 91 nominal E observations; the $\gamma=0.99$ and $\gamma=1.0$ groups contain 15 and 12 such records. Within C, all-durable, no-rejection outcomes corroborate direct admission. Posterior observations occur in every LoopFuzz condition and therefore do not distinguish E or the sensitivity groups. Nominal arms also contain multiple program versions: D four (78/12/9/5 runs), C two (83/7), and E two (71/20); each sensitivity group uses one version. Original group assignments are retained, but correspondence to effective conditions remains uncertain. All observations are included without assuming independence. The nominal target is ten trials per condition; means and sample SDs use observed values only, with actual $n$ and no imputation.')
replace('This supplies differential replay evidence with verified version identity for the pair, while the earlier three-trial patch comparison remains separate.','This establishes differential replay for the verified pair; the earlier three-trial patch comparison remains separate.')
replace('Complete-input replays (September 30 observations) provide three additional comparisons.','Complete-input replays (September 30 observations) extend the evidence.')
replace('All 172 share the same diagnostic signature, with no alternative signature observed.','All 172 share one diagnostic signature; no alternative appears.')
replace('Diagnostics from the original campaigns are insufficient to confirm these outcomes, so their classification relies on the controlled version-pair replay.','Original campaign diagnostics are insufficient; outcome classification therefore relies on the controlled version-pair replay.')
para('For LIVE555, all 88 campaign',r'For LIVE555, all 88 campaign crash inputs were replayed against the tested version without sanitizer checks: 82 terminate the server and 6 do not. Without a patched comparison or memory-error diagnosis, these results establish reproduction in that version only, not attribution to the use-after-free.')
para('For Kamailio, all 253 retained',r'For Kamailio, all 253 retained inputs with Content-Length $\geq 2^{31}$ were evaluated against the verified vulnerable/patched pair: 102 produce a negative-length outcome in the vulnerable version and none in the patched version. The two runs contributed 77 and 176 inputs, with yields of 36/77 and 66/176. Overflow values include $-2147483648$, $-1$, and $-954437177$; 151/253 inputs do not produce the outcome. The roles of interaction order and request interpretation remain unresolved. These comparisons characterize input replay, without arm-level recall, time-to-trigger, or cost denominators.')
replace('Removal of the affected parsing component in version 28.4 is reported, but has not been validated by a patched-version replay.','Removal of the affected parsing component in version 28.4 remains unverified by patched-version replay.')
replace('while maintaining a separate, anonymized correspondence between cases and their evaluation criteria.','while retaining anonymized case-to-oracle correspondence separately.')
replace('Richer response interpretation or direct observation of internal state addresses different aspects but requires additional target-specific knowledge and measurement access.','Richer response interpretation or internal-state observation addresses different aspects but requires target-specific knowledge and measurement access.')
def nums(s):
 s=re.sub(r'\\texttt\{o-(?:pftp|kam)-01\}','',s)
 return collections.Counter(re.findall(r'(?<![A-Za-z0-9])[-+]?\d+(?:,\d{3})*(?:\.\d+)?(?![A-Za-z0-9])',s))
assert nums(old)==nums(new),{'removed':list((nums(old)-nums(new)).items()),'added':list((nums(new)-nums(old)).items())}
p.write_text(new)
(audit/'phase4_changes.json').write_text(json.dumps(changes,indent=2)+'\n')
before=(audit/'before/main.revised.tex').read_text()
(audit/'changes.diff').write_text(''.join(difflib.unified_diff(before.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='before/main.revised.tex',tofile='main.revised.tex')))
print('COMPACTED',json.dumps({'words_removed':len(old.split())-len(new.split()),'changes':len(changes),'numerical_values_preserved':True}),flush=True)
with (audit/'build.output.log').open('w') as out:
 proc=subprocess.run(['latexmk','-pdf','-interaction=nonstopmode','-halt-on-error','-outdir=revision_20260920','revision_20260920/main.revised.tex'],cwd=rev.parent,stdout=out,stderr=subprocess.STDOUT,timeout=240)
if proc.returncode:
 print((audit/'build.output.log').read_text(errors='replace')[-14000:]);raise SystemExit(proc.returncode)
log=(rev/'main.revised.log').read_text(errors='replace')
print('ISSUES',[l for l in log.splitlines() if re.search(r'undefined|^!|Overfull',l,re.I)])
print(subprocess.run(['pdfinfo',str(rev/'main.revised.pdf')],capture_output=True,text=True,check=True).stdout)
for l in (rev/'main.revised.aux').read_text().splitlines():
 if any(s in l for s in ['newlabel{tab:targets}','newlabel{tab:llm}','newlabel{tab:cve}','newlabel{alg:admission}']):print(l)
