# LoopFuzz 13-Point Revision Response

Date: 2026-06-04

Scope:
- Manuscript checked: `main.tex`
- Design source checked: `../work_and_data_flow.txt`
- Concern list checked: `../questions_for_paper.txt`
- Template checked: `../elsarticle`
- Journal guide checked: Computers & Security Guide for Authors

## Results

1. Work-and-data-flow alignment: revised the manuscript to keep the four design requirements visible as academic content: hypothesis generation, runtime admission, CEGR, and state-aware scheduling. The abstract now explicitly mentions RFC fragments, seed traces, and observed responses.

2. Title, abstract, keywords: title is exactly `LoopFuzz: Closed-Loop Runtime Admission Control for LLM-Guided Stateful Protocol Fuzzing`. The abstract is one paragraph and 157 words. Keywords are 5.

3. Continuity and terminology: unified the manuscript around `closed-loop runtime admission control`. Removed misleading `Runtime verification` and `Runtime Verifier` wording except where the paper clarifies that the method is not formal verification.

4. Motivation: strengthened the FTP `RETR` example. It now states the missing data-channel precondition, the `425` negative response, the rejection decision, and the CEGR repair path.

5. Core idea and novelty boundary: the paper now presents the core idea as a runtime admission boundary between LLM proposals and queue admission. It explicitly avoids claiming formal verification or universal dominance.

6. Figure terminology: added text mapping the Figure 1 terms to method components, including Tier-1 Sampling, Tier-2 Refinement, JSON Validation, Action Dispatch, Dedup, and fork-based query isolation.

7. Academic writing style: replaced several engineering/documentation phrases with academic framing. Long claims were split or bounded, especially in motivation, design, ablation, and threats.

8. Logic, figures, and tables: Table 2 is framed as primary end-of-campaign evidence, trajectory figures are treated as dynamics only, and Table 3 is framed as policy perturbation rather than per-module causal proof. The source wording now says a declared per-target result archive, not a single global root.

9. References: compiled bibliography contains 56 cited entries. The cited entries are academic papers/proceedings: 54 `@inproceedings` and 2 `@article`. Every BibTeX entry is cited, and no `@misc`, `@techreport`, RFC, software homepage, whitepaper, or tool-only reference remains in the active bibliography. Remaining risk: 4 entries still lack verified page ranges in BibTeX.

10. Engineering-document risk: removed or softened `shipped controller`, `code-driven`, `current draft`, and similar implementation-report wording where it weakened the academic argument.

11. Elsevier template and length: `main.tex` uses `elsarticle`, `frontmatter`, `review`, `12pt`, `authoryear`, line numbers, `\journal{Computers \& Security}`, and `elsarticle-harv`. Final PDF compiles to 48 pages, above the requested 11-page threshold.

12. System-level framing: discussion and conclusion now keep the claim at the campaign-control level. IPSM-edge count is framed as a diagnostic, not as a standalone proof of superiority.

13. `questions_for_paper.txt`: addressed the major listed risks: ablation self-undermining, incomplete targets, MWU tests, small code-edge gains, no CVE claim, BibTeX author formatting, Table 2/Table 3 mismatch, missing external baselines, Mosquitto fairness, semantic-drift quantification, hyperparameter limits, and misleading `Veri` naming.

## Verification

- `pdflatex`, `bibtex`, `pdflatex`, `pdflatex` completed successfully.
- Final log has no unresolved citation, unresolved label, fatal error, or rerun warning.
- Abstract word count: 157.
- Keyword count: 5.
- Cited bibliography entries: 56.
- PDF pages: 48.
- Remaining LaTeX warnings are non-fatal overfull boxes.
- Remaining BibTeX warnings are missing page ranges in 4 entries.

## Still Requiring Author Input

- Confirm the final CRediT contribution statement for the two-author metadata now shown in `main.tex`.
- Competing-interest, funding, data/code availability, CRediT, and generative-AI declarations.
- Optional completion of missing bibliography page ranges from authoritative sources.
- Final editorial decision on Computers & Security fit, because the guide flags papers where AI/ML is the significant component as potentially out of scope.
