# ASE Final Submission Checklist

A final pre-submission checklist focused on ASE-style expectations and common rejection triggers for systems + software engineering/security papers.

---

## A. Claim discipline

- [ ] Every main claim is supported by a figure, table, or explicit methodological argument.
- [ ] No paragraph claims universal superiority, broad generality, or causal proof beyond the evaluated targets.
- [ ] Positive findings are phrased as evidence on the evaluated targets, not as unconditional truths.
- [ ] Mixed results are acknowledged directly rather than hidden behind aggregate language.
- [ ] Proxy metrics (coverage, inferred states) are not described as direct evidence of vulnerability yield or semantic correctness.

### Common reject reason
- Overclaiming from limited targets, limited trials, or proxy metrics.

---

## B. Problem–method alignment

- [ ] The problem statement matches the actual contribution: runtime-mediated LLM assistance, not “LLM solves protocol fuzzing.”
- [ ] The method section stays aligned with the implementation in `work_and_data_flow.txt`.
- [ ] The four core mechanisms are explicit and consistently named:
  - [ ] Hypothesis generation
  - [ ] Verifier / runtime validation
  - [ ] Counterexample-guided refinement
  - [ ] State-aware scheduling
- [ ] Figure 1 terminology is defined in prose and reused consistently throughout the paper.

### Common reject reason
- The system diagram promises a cleaner or stronger design than the implementation actually realizes.

---

## C. Writing style and tone

- [ ] No paragraph reads like README prose, source-code commentary, or marketing copy.
- [ ] Implementation details are included only when they support reproducibility or explain an observed effect.
- [ ] Internal field names, file names, JSON keys, and magic constants are abstracted unless they are analytically necessary.
- [ ] The abstract, results, discussion, and conclusion all use the same evidence-first tone.
- [ ] There is no visible “AI voice”: no inflated metaphors, no generic filler, no unsupported rhetorical flourish.

### Common reject reason
- The paper sounds generated, padded, or insufficiently grounded in technical evidence.

---

## D. Experimental design

- [ ] All compared systems use the same hardware, time budget, target versions, and trial counts.
- [ ] Any deviations from the original baseline implementations are disclosed and justified.
- [ ] The unit of analysis is clearly stated (e.g., five terminal 24-hour runs).
- [ ] Statistical tests, significance thresholds, and what is actually tested are stated explicitly.
- [ ] Time-series plots are described as interpretive support, not as substitutes for statistical testing.
- [ ] Pending targets are clearly labeled as pending everywhere they appear.

### Common reject reason
- Unfair baselines, unclear measurement pipeline, or hand-wavy statistical practice.

---

## E. Results section quality

- [ ] Each RQ begins with the actual observation before offering interpretation.
- [ ] Each RQ distinguishes between strong evidence, modest evidence, and pending evidence.
- [ ] Explanations are phrased as interpretations consistent with the data, not as proven causal facts.
- [ ] Any target-specific exceptions are explicitly discussed.
- [ ] The text never depends on cherry-picked single runs when the design is based on repeated trials.

### Common reject reason
- Results are narrated as a victory lap rather than analyzed as evidence with uncertainty.

---

## F. Discussion quality

- [ ] Discussion extends the results instead of repeating them.
- [ ] The paper states where the method is likely to work best.
- [ ] The paper states where the method is likely to transfer poorly.
- [ ] Limitations are concrete and technical, not ceremonial.
- [ ] Practical trade-offs (especially API cost and delay) are discussed in terms of deployment relevance.

### Common reject reason
- Discussion is generic, defensive, or detached from the observed evidence.

---

## G. Threats to validity

- [ ] Internal validity addresses randomness, nondeterminism, and campaign history dependence.
- [ ] External validity addresses the target class and what is not covered.
- [ ] Construct validity explicitly acknowledges proxy metrics.
- [ ] Reproducibility validity discusses the proprietary LLM dependency.
- [ ] Conclusion validity does not pretend five repeated trials eliminate all variance.

### Common reject reason
- Threats are boilerplate and do not engage the actual weaknesses of the study.

---

## H. Citations and related work

- [ ] Every citation is relevant to the sentence it supports.
- [ ] No citation is included only to inflate the count.
- [ ] Related work is organized by problem line, not as a flat list.
- [ ] The closest prior system (ChatAFL) is compared directly and precisely.
- [ ] The paper explains not only what prior work did, but what control gap remains.
- [ ] Total effective references remain above the required threshold.

### Common reject reason
- Citation dumping or weak positioning relative to the nearest prior work.

---

## I. Tables and figures

- [ ] Every table caption is self-contained.
- [ ] Every figure is interpretable without relying on the main text for basic semantics.
- [ ] Axes, units, and significance markers are unambiguous.
- [ ] Placeholder rows or cells are removed before submission unless absolutely necessary for a draft.
- [ ] Table/figure discussion in the text matches what is actually shown.

### Common reject reason
- Visuals are aesthetically fine but analytically underexplained or slightly misleading.

---

## J. Reproducibility and artifact readiness

- [ ] The paper states what is open, what is proprietary, and what can be reproduced exactly.
- [ ] All scripts/configurations needed for the reported completed runs are tracked and organized.
- [ ] Model version, temperatures, and any protocol-specific implementation changes are documented.
- [ ] The paper does not promise artifact reproducibility beyond what the infrastructure actually allows.

### Common reject reason
- Reproducibility claims are stronger than the artifact and dependencies support.

---

## K. Final LaTeX and formatting pass

- [ ] The paper compiles cleanly with `pdflatex + bibtex`.
- [ ] No undefined references, citation warnings, or layout overflows remain.
- [ ] IEEE style is respected consistently in captions, sectioning, and references.
- [ ] Math notation is defined before use and reused consistently.
- [ ] Terminology is stable across abstract, introduction, method, results, discussion, and conclusion.

---

## L. Last-minute kill list

Before submission, explicitly search for and remove:

- [ ] “obviously”, “clearly”, “significantly better” without statistical support
- [ ] “novel” unless needed and justified
- [ ] “solve”, “prove”, “guarantee”, “always”, “universal” unless literally true
- [ ] leftover `TBA`, placeholder text, or draft-only notes
- [ ] residual code-comment style prose or implementation variable dumping

---

## M. Submission-day sanity check

- [ ] Abstract can stand alone and does not overclaim.
- [ ] Introduction states the real paper, not a grander paper.
- [ ] Method matches implementation.
- [ ] Results match tables and figures.
- [ ] Discussion respects limitations.
- [ ] Conclusion says only what the evidence can bear.

If all six lines above are true, the paper is in strong submission shape.
