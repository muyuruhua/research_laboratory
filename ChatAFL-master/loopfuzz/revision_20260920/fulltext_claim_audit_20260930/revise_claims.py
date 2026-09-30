from pathlib import Path
import json,shutil
a=Path(__file__).resolve().parent;r=a.parent
for k,stem in [('benjamini1995','candidate0'),('kaplan1958','round4_0'),('tscheduler2024','candidate0')]:
 p=a/'sources'/k;d=json.loads((p/(stem+'.json')).read_text());shutil.copy2(p/(stem+'.pdf'),p/'paper.pdf');shutil.copy2(p/(stem+'.txt'),p/'paper.txt')
 out=json.loads((p/'retrieval.json').read_text()) if (p/'retrieval.json').exists() else {'key':k}
 out.update(status='fulltext_downloaded',source=d['url'],pages=len((p/'paper.txt').read_text().rstrip('\n\f ').split('\f')),sha256=d['sha256'],identity_check='Title, authors and publication verified against original first page')
 if k=='tscheduler2024':out.update(supplemental=True,version_note='arXiv:2312.04749v1, author manuscript; official publication metadata cross-checked with Crossref')
 (p/'retrieval.json').write_text(json.dumps(out,indent=2)+'\n')
bib=r/'references.expanded.bib';s=bib.read_text()
if '@inproceedings{tscheduler2024,' not in s:
 s+='\n'+r'''@inproceedings{tscheduler2024,
  author = {Simon Luo and Adrian Herrera and Paul Quirk and Michael Chase and Damith C. Ranasinghe and Salil S. Kanhere},
  title = {Make out like a (Multi-Armed) Bandit: Improving the Odds of Fuzzer Seed Scheduling with {T-Scheduler}},
  booktitle = {Proceedings of the 19th ACM Asia Conference on Computer and Communications Security},
  year = {2024},
  pages = {1463--1479},
  doi = {10.1145/3634737.3637639}
}
''';bib.write_text(s)
p=r/'main.revised.tex';s=p.read_text()
pairs=[
(r"Gramatron and CarpetFuzz exploit grammars and documented constraints~\cite{gramatron_effective_grammar_aware_2021,carpetfuzz_documentation_2023}.",r"Gramatron generates inputs through grammar automata~\cite{gramatron_effective_grammar_aware_2021}; CarpetFuzz extracts option constraints from documentation~\cite{carpetfuzz_documentation_2023}."),
(r"LLM-assisted fuzzing extends generation to protocol interactions, device inputs, and programs~\cite{chatafl,llmif_augmented_large_language_2024,fuzz4all_universal_fuzzing_large_2024}.",r"ChatAFL uses LLMs for protocol-message generation~\cite{chatafl}; LLMIF derives device-testing inputs from protocol specifications~\cite{llmif_augmented_large_language_2024}; Fuzz4All generates and mutates program inputs across languages~\cite{fuzz4all_universal_fuzzing_large_2024}."),
(r"and predicate-guided synthesis for directed testing~\cite{hgfuzzer2026}",r"and LLM-assisted directed greybox fuzzing~\cite{hgfuzzer2026}"),
(r"The Bandit's States models protocol-state selection as a bandit problem~\cite{bandits_states2023}; Thompson-sampling seed scheduling~\cite{zhang2026thompson} and state-significance-guided protocol fuzzing~\cite{ssgfuzz2026} further delimit the contribution.",r"The Bandit's States models protocol-state selection as a bandit problem~\cite{bandits_states2023}. T-Scheduler combines Beta--Bernoulli estimation with Thompson sampling for seed scheduling~\cite{tscheduler2024}; Zhang et al. also study Thompson-sampling seed scheduling~\cite{zhang2026thompson}. SSGFuzz studies state-significance-guided protocol fuzzing~\cite{ssgfuzz2026}. These works delimit the contribution."),
(r"The Bandit's States~\cite{bandits_states2023} & Bandit-based protocol-state selection. & Prior bandit formulation; independent reward and queue evidence here.",r"The Bandit's States~\cite{bandits_states2023} & Bandit-based protocol-state selection. & Established selection framework; coupled proxy calibration and admission here."),
(r"Zhang et al.~\cite{zhang2026thompson} & Thompson-sampling seed scheduling. & Reused Beta estimation and Thompson sampling.",r"T-Scheduler~\cite{tscheduler2024}; Zhang et al.~\cite{zhang2026thompson} & Thompson-sampling seed scheduling. & Established sampling principle; response-state episodes here."),
(r"SSGFuzz~\cite{ssgfuzz2026} & State-significance-guided fuzzing. & Code-productivity calibration, distinct from state importance.",r"SSGFuzz~\cite{ssgfuzz2026} & State-significance-guided fuzzing. & Our focus: response-proxy productivity and queue admission."),
(r"The Benjamini--Hochberg procedure~\cite{benjamini1995} controls this family at $q=0.05$.",r"Apply the Benjamini--Hochberg procedure~\cite{benjamini1995} at nominal $q=0.05$. Its original guarantee assumes independent test statistics; shared comparator runs and correlated coverage outcomes do not establish that condition here. Report adjusted values without claiming unconditional false-discovery-rate control."),
(r"Historical time-to-trigger uses Kaplan--Meier estimates~\cite{kaplan1958}, right censoring, and CVE-specific deadline recall.",r"Historical time-to-trigger uses Kaplan--Meier estimates~\cite{kaplan1958} under non-informative right censoring, alongside CVE-specific deadline recall.")]
for old,new in pairs:
 assert s.count(old)==1,(old[:80],s.count(old));s=s.replace(old,new)
p.write_text(s)
print('Updated manuscript claim boundaries and added verified T-Scheduler bibliography entry.')
