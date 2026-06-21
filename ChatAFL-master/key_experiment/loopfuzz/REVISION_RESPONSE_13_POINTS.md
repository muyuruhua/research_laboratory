# LoopFuzz 13-Point Revision Response

Date: 2026-06-08

Scope:
- Manuscript checked: `main.tex`
- Design source checked: `../work_and_data_flow.txt`
- Concern list checked: `../questions_for_paper.txt`
- Template checked: `../elsarticle`
- Journal guide checked: Computers & Security Guide for Authors

## Results

1. Work-and-data-flow alignment: revised the manuscript to keep the four design requirements visible as academic content: hypothesis generation, runtime admission, CEGR, and state-aware scheduling. The abstract now explicitly mentions RFC fragments, seed traces, and observed responses.

2. Title, abstract, keywords: title is exactly `LoopFuzz: Closed-Loop Runtime Admission Control for LLM-Guided Stateful Protocol Fuzzing`. The abstract is one paragraph and 158 words. Keywords are 5.

3. Continuity and terminology: unified the manuscript around `closed-loop runtime admission control`. Removed misleading `Runtime verification` and `Runtime Verifier` wording except where the paper clarifies that the method is not formal verification.

4. Motivation: strengthened the FTP `RETR` example. It now states the missing data-channel precondition, the `425` negative response, the rejection decision, and the CEGR repair path.

5. Core idea and novelty boundary: the paper now presents the core idea as a runtime admission boundary between LLM proposals and queue admission. It explicitly avoids claiming formal verification or universal dominance.

6. Figure terminology: added text mapping the framework terms to method components, including Grammar Hypothesis Loop, Fuzz Execution Loop, LLM Intervention Loop, Tier-1 sampling, Tier-2 CEGR, schema validation, runtime admission, prompt reuse filtering, query isolation, and bounded action dispatch.

7. Academic writing style: replaced several engineering/documentation phrases with academic framing. Long claims were split or bounded, especially in motivation, design, ablation, and threats.

8. Logic, figures, and tables: the primary results table is framed as end-of-campaign evidence, the auxiliary NSFuzz and MQTT tables are explicitly qualified, and the ablation table is framed as policy perturbation rather than per-module causal proof. The source wording now states the deterministic archive-selection rule and separates the nine-target primary comparison from the MQTT auxiliary comparison.

9. References: compiled bibliography contains 56 cited entries. The cited entries are academic papers/proceedings: 54 `@inproceedings` and 2 `@article`. Every BibTeX entry is cited, and no `@misc`, `@techreport`, RFC, software homepage, whitepaper, or tool-only reference remains in the active bibliography. BibTeX author formatting for the core AFLNet, SGF, ChatAFL, and B{\"o}hme entries is normalized.

10. Engineering-document risk: removed or softened `shipped controller`, `code-driven`, `current draft`, and similar implementation-report wording where it weakened the academic argument.

11. Elsevier template and length: `main.tex` uses `elsarticle`, `frontmatter`, `preprint`, `authoryear`, `\journal{Computers \& Security}`, and `elsarticle-harv`. Final PDF compiles to 25 pages, satisfying the requested length target.

12. System-level framing: discussion and conclusion now keep the claim at the campaign-control level. IPSM-edge count is framed as a diagnostic, not as a standalone proof of superiority.

13. `questions_for_paper.txt`: addressed the major listed risks: ablation self-undermining, incomplete targets, MWU tests, small code-edge gains, no CVE claim, BibTeX author formatting, Table 2/Table 3 mismatch, missing external baselines, Mosquitto fairness, semantic-drift quantification, hyperparameter limits, and misleading `Veri` naming.

## Verification

- `pdflatex`, `bibtex`, `pdflatex`, `pdflatex` completed successfully.
- Final log has no unresolved citation, unresolved label, fatal error, or rerun warning.
- Abstract word count: 158.
- Keyword count: 5.
- Cited bibliography entries: 56.
- PDF pages: 25.
- Remaining LaTeX warnings are nine non-fatal overfull boxes in long technical phrases and wide tables.
- BibTeX reports no unresolved citation, no missing entry, and no missing-page warning.

## Still Requiring Author Input

- Confirm the final CRediT contribution statement for the two-author metadata now shown in `main.tex`.
- Competing-interest, funding, data/code availability, CRediT, and generative-AI declarations.
- Optional completion of missing bibliography page ranges from authoritative sources.
- Final editorial decision on Computers & Security fit, because the guide flags papers where AI/ML is the significant component as potentially out of scope.
