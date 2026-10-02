# 逐句修改明细

以下为按执行顺序保存的 68 条替换记录。同一句可能经历学术表达和精简两次修改；最终文本以主稿和 main.changes.diff 为准。

## 1. changes.phase1

原文：
% Reproducible build (including BibTeX): bash build_revised.sh

替换为：
（移出主稿，原文保留在备份和审查记录中）

理由：Remove build-command commentary from manuscript source; retain original in backup.

## 2. changes.phase1

原文：
% Revision 2026-09-20: C_two_papers/first_paper.md.

替换为：
（移出主稿，原文保留在备份和审查记录中）

理由：Move editorial file-path provenance entirely to the audit.

## 3. changes.phase1

原文：
after the measured code surface has saturated

替换为：
after measured code coverage has saturated

理由：Replace an imprecise implementation metaphor with the measured quantity.

## 4. changes.phase1

原文：
message structure and live session conditions

替换为：
message structure and session state during execution

理由：Describe the experimental state rather than operational availability.

## 5. changes.phase1

原文：
Source-level code branches are the main evaluation surface.

替换为：
Source-level code branches are the primary coverage measure.

理由：Use an explicit measurement term.

## 6. changes.phase1

原文：
the proposed live provisional capacity is 64

替换为：
at most 64 provisional candidates may be retained simultaneously

理由：State the capacity as a mathematical resource constraint.

## 7. changes.phase1

原文：
unselected states do not automatically age in wall-clock time

替换为：
unselected states retain their accumulated evidence regardless of elapsed time

理由：Describe the absence of time-based discounting precisely.

## 8. changes.phase1

原文：
the inherited base weight shared by C, D, and E

替换为：
the common base weight of C, D, and E

理由：Remove code-lineage wording while preserving the shared-weight definition.

## 9. changes.phase1

原文：
Counterexample-guided repair is an optional feature without quantitative evaluation in this study.

替换为：
Counterexample-guided repair is an optional procedure without quantitative evaluation in this study.

理由：Describe a research procedure rather than a software feature.

## 10. changes.phase1

原文：
Repair remains an optional, unquantified feature.

替换为：
Repair remains an optional, unquantified procedure.

理由：Use consistent methodological terminology.

## 11. changes.phase2

原文：
Measure IPSM state-edge/code-branch alignment, episode productivity, calibration, and boundary cases.

替换为：
Outcomes include IPSM state-edge/code-branch alignment, episode productivity, calibration, and boundary cases.

理由：Replace a task instruction with the research-question scope.

## 12. changes.phase2

原文：
Compare D with C.

替换为：
The intended contrast is D--C.

理由：State the causal contrast without an instruction to perform it.

## 13. changes.phase2

原文：
Compare E with D.

替换为：
The intended contrast is E--D.

理由：State the causal contrast without implying completion.

## 14. changes.phase2

原文：
Compare the BS to a prequential base-rate predictor because rare rewards can make uninformative near-zero predictions look accurate.

替换为：
A prequential base-rate predictor provides a BS reference because rare rewards can favor uninformative near-zero predictions.

理由：State the statistical rationale instead of an analysis instruction.

## 15. changes.phase2

原文：
Per target, report mean, median and dispersion.

替换为：
The confirmatory analysis specifies target-specific means, medians, and dispersion.

理由：Preserve prospective status and remove author-facing instructions.

## 16. changes.phase2

原文：
For independent run-level contrasts, report two-sided Mann--Whitney U tests

替换为：
Planned independent run-level contrasts use two-sided Mann--Whitney U tests

理由：Distinguish intended statistical procedures from completed tests.

## 17. changes.phase2

原文：
Apply the Benjamini--Hochberg procedure

替换为：
The design specifies the Benjamini--Hochberg procedure

理由：Remove command-style prose without claiming prior registration.

## 18. changes.phase2

原文：
Report adjusted values without claiming unconditional false-discovery-rate control.

替换为：
Adjusted values would not imply unconditional false-discovery-rate control.

理由：Keep the inferential limitation in declarative form.

## 19. changes.phase2

原文：
Primary coverage outcomes are code-branch AUC over 24 hours and final code-branch count.

替换为：
The confirmatory outcomes are code-branch AUC over 24 hours and final code-branch count.

理由：Explicitly identify intended outcomes instead of implying a completed matched analysis.

## 20. changes.phase2

原文：
Cross-target summaries use equal-weight target effects

替换为：
Confirmatory cross-target summaries would use equal-weight target effects

理由：Preserve prospective status of the uncompleted inferential analysis.

## 21. changes.phase2

原文：
Trial order is randomized within machine blocks and balanced across machines and time periods.

替换为：
The confirmatory design randomizes trial order within machine blocks and balances trials across machines and periods.

理由：Do not imply verified execution of the prescribed trial-order policy.

## 22. changes.phase2

原文：
Each arm initially receives 10 independent 24-hour runs per target; C/D/E receive 10 more, reaching 20 each.

替换为：
The design allocates 10 independent 24-hour runs per target to each arm, plus 10 for C/D/E, reaching 20 each.

理由：Keep intended sample sizes distinct from observed sample sizes.

## 23. changes.phase2

原文：
These initial settings are checked in the pilot and prespecified before formal runs.

替换为：
The design requires pilot assessment and parameter specification before formal runs.

理由：State a methodological requirement without claiming completed pilot validation.

## 24. changes.phase2

原文：
All attempts, retries, failures, and successful replies enter the declared call/token accounting.

替换为：
Call/token totals include all attempts, retries, failures, and successful replies.

理由：Express the cost definition as a measurement rule.

## 25. changes.phase2

原文：
Verify conditions throughout each run.

替换为：
Within-run adherence requires verification.

理由：Replace an operational instruction with an evidential criterion.

## 26. changes.phase2

原文：
call cap 64; token cap 0 (unset)

替换为：
call cap 64; token-limit setting 0

理由：Preserve the recorded value without treating an implementation flag as an effective resource ceiling.

## 27. changes.phase2

原文：
Match each call class.

替换为：
Equal temperature within each call class.

理由：Use an experimental-control condition.

## 28. changes.phase2

原文：
Count all classes and retries.

替换为：
All request classes and retries included.

理由：State the scope of the required cost measurement.

## 29. changes.phase2

原文：
Document support; determinism unassured.

替换为：
Seed-support status; determinism unassured.

理由：Describe the required information without an author-facing instruction.

## 30. changes.phase2

原文：
Final configuration records assign fixed-policy labels to

替换为：
Settings reported at trial completion identify fixed-policy labels for

理由：Describe measurement timing and reported classification instead of configuration-file operations.

## 31. changes.phase2

原文：
RQ1: Current alignment observations

替换为：
RQ1: State--code alignment

理由：Use a research-focused heading.

## 32. changes.phase2

原文：
This direction does not reproduce the older motivating claim of code regression.

替换为：
This direction does not support the motivating hypothesis of code regression.

理由：Remove revision-history wording while retaining contradictory evidence.

## 33. changes.phase2

原文：
unknown dependence between launches

替换为：
unknown dependence between trials

理由：Use the experimental unit rather than a process-launch term.

## 34. changes.phase2

原文：
These diagnostics therefore do not fill independent code-branch calibration outcomes

替换为：
These diagnostics do not establish calibration against independent code-branch outcomes

理由：State the scientific evidence gap rather than data-completion status.

## 35. changes.phase2

原文：
this fixed low energy selects a heavily imbalanced slice

替换为：
this fixed low energy yields a subset with unequal sample sizes

理由：Replace informal data-processing jargon with the sampling limitation.

## 36. changes.phase2

原文：
reports the recoverable endpoints and AUCs

替换为：
reports the observed endpoints and AUCs

理由：Remove data-recovery workflow wording.

## 37. changes.phase2

原文：
End-of-run configuration records verify

替换为：
Settings reported at trial completion specify

理由：Preserve the distinction between reported parameters and verified runtime behavior.

## 38. changes.phase2

原文：
the remaining records carry the fixed-policy configuration at

替换为：
the remaining observations report a fixed policy at

理由：Use experimental-condition language without changing group membership.

## 39. changes.phase2

原文：
with a deterministic record ordering resolving ties

替换为：
with ties resolved by a fixed ordering of observations

理由：Describe the selection rule without data-processing jargon or an invented preregistration claim.

## 40. changes.phase2

原文：
The final configuration records specify a model name

替换为：
Settings reported at trial completion specify a model name

理由：Describe the provenance and timing of reported settings.

## 41. changes.phase2

原文：
unresponsive service, live process (R).

替换为：
unresponsive service; process active (R).

理由：Use a concise description of the observed availability failure.

## 42. changes.phase2

原文：
Controlled rediscovery still to be measured

替换为：
Evidence limits for controlled rediscovery

理由：Replace a to-do heading with the scope of the scientific limitation.

## 43. changes.phase3

原文：
message structure and session state during execution

替换为：
message structure and session state

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 44. changes.phase3

原文：
The available records permit descriptive assessment of these signals, but do not establish that every run satisfied the complete decision criteria.

替换为：
The observations describe these signals without establishing full adherence to the decision criteria in every run.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 45. changes.phase3

原文：
A formal decision rule alone does not demonstrate experimental adherence.

替换为：
A decision rule alone does not establish experimental adherence.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 46. changes.phase3

原文：
The information policy excludes CVE identifiers, security advisories, exploit inputs, and patch contents. It specifies the documentation and observed responses available to the model.

替换为：
The information policy specifies permitted documentation and observed responses, excluding CVE identifiers, security advisories, exploit inputs, and patch contents.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 47. changes.phase3

原文：
Outputs that propose requests pass through admission. Outputs that only guide scheduling require structural, state-consistency, and seed-consistency checks and cannot insert durable inputs.

替换为：
Request proposals undergo admission; scheduling proposals require structural, state-consistency, and seed-consistency checks and cannot insert durable inputs.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 48. changes.phase3

原文：
If coverage measurement observes code edges instead, that reward definition must be prespecified and reported separately.

替换为：
A code-edge reward requires a prespecified, separately reported definition.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 49. changes.phase3

原文：
at most 64 provisional candidates may be retained simultaneously

替换为：
the proposed provisional capacity is 64

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 50. changes.phase3

原文：
Exhaustion expires the entry from active scheduling while preserving the observations supporting that decision.

替换为：
Budget exhaustion removes the entry from active scheduling while preserving its supporting evidence.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 51. changes.phase3

原文：
The record identifies the first productive descendant and the candidate whose status changes. Each code discovery receives credit once, linked to its execution and candidate ancestry.

替换为：
The observations identify the first productive descendant and the candidate promoted. Each code discovery is attributed once to its execution and candidate ancestry.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 52. changes.phase3

原文：
unselected states retain their accumulated evidence regardless of elapsed time

替换为：
elapsed time alone does not discount unselected states

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 53. changes.phase3

原文：
Post-update predictions would leak the outcome into their own evaluation.

替换为：
Post-update predictions would leak the outcome.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 54. changes.phase3

原文：
Thompson samples are recorded separately and are not substituted for predicted Bernoulli probabilities in reliability calculations.

替换为：
Thompson samples remain separate from the Bernoulli probabilities used for reliability assessment.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 55. changes.phase3

原文：
Experimental fidelity therefore depends on both effective experimental conditions and the sequence of admission decisions.

替换为：
Experimental fidelity requires verified conditions and admission order.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 56. changes.phase3

原文：
The measurement framework distinguishes experimental conditions

替换为：
Measurements distinguish experimental conditions

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 57. changes.phase3

原文：
The evaluation analyzes recorded outcomes from the benchmark and ablation studies.

替换为：
The analysis covers benchmark and ablation outcomes.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 58. changes.phase3

原文：
Result tables contain observed quantities; unmeasured effects are described as evidence limitations and are not assigned zero values.

替换为：
Tables report observed quantities; unmeasured effects remain limitations rather than zero-valued results.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 59. changes.phase3

原文：
These measurements alone do not verify that every run followed the intended scheduling policy.

替换为：
These measurements do not establish policy adherence in every run.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 60. changes.phase3

原文：
The contribution is the controller specification and a documented assessment of the evidence needed to validate its intended benefits; no quantitative repair effect is claimed.

替换为：
The contribution comprises a controller specification and an assessment of its validation requirements; no quantitative repair effect is claimed.

理由：Concise academic expression; preserve the scientific condition and evidence limitation.

## 61. changes.phase4

原文：
All three cases require common experimental versions, matched observation periods, and linked state/execution measurements before supporting a mechanism claim.

替换为：
Mechanism claims require matched versions and observation periods, with linked state/execution measurements, for all three cases.

理由：Condense wording while retaining sample definitions, uncertainty, and the unverified-efficacy boundary.

## 62. changes.phase4

原文：
\namedref{Figure}{fig:reliability} instead examines a narrower estimand: agreement between pre-update probabilities and the binary reward associated with coverage-based retention, separately by target.

替换为：
\namedref{Figure}{fig:reliability} examines target-specific agreement between pre-update probabilities and binary rewards for coverage-based retention.

理由：Condense wording while retaining sample definitions, uncertainty, and the unverified-efficacy boundary.

## 63. changes.phase4

原文：
Percentile 95\% CIs use 2,000 bootstrap resamples of whole runs within each target; they do not resolve unknown dependence between trials.

替换为：
Percentile 95\% CIs use 2,000 bootstrap resamples of runs within each target; dependence between trials remains unresolved.

理由：Condense wording while retaining sample definitions, uncertainty, and the unverified-efficacy boundary.

## 64. changes.phase4

原文：
Empty bins have no estimate, and bins represented by fewer than two runs have no CI.

替换为：
Empty bins are unestimated; CIs require at least two runs per bin.

理由：Condense wording while retaining sample definitions, uncertainty, and the unverified-efficacy boundary.

## 65. changes.phase4

原文：
The observed reward reflects coverage-based retention, which may include execution-frequency novelty; positive mutation counts do not establish complete fixed-energy episodes.

替换为：
Rewards measure coverage-based retention, potentially including execution-frequency novelty; nonzero mutation counts do not establish complete fixed-energy episodes.

理由：Condense wording while retaining sample definitions, uncertainty, and the unverified-efficacy boundary.

## 66. changes.phase4

原文：
These diagnostics do not establish calibration against independent code-branch outcomes; the equal-energy subset rows in \namedref{Table}{tab:mechanisms} condition the same proxy reward on one fixed energy and inherit these limits.

替换为：
These diagnostics do not establish independent code-branch calibration. The equal-energy subset in \namedref{Table}{tab:mechanisms} conditions the same proxy reward on one energy and retains these limits.

理由：Condense wording while retaining sample definitions, uncertainty, and the unverified-efficacy boundary.

## 67. changes.phase4

原文：
LoopFuzz is presented as an integrated controller design with a retrospective analysis of its evidence boundaries. The proposed admission rule separates code progress from IPSM novelty and gives state-only proposals a bounded provisional budget. Productivity calibration is an exploratory scheduling mechanism; it does not recover semantic protocol states.

替换为：
We present a LoopFuzz controller design with retrospective boundary analysis. Admission separates code progress from IPSM novelty and bounds provisional validation for state-only proposals. Productivity calibration remains exploratory and does not recover semantic protocol states.

理由：Condense wording while retaining sample definitions, uncertainty, and the unverified-efficacy boundary.

## 68. changes.phase4

原文：
The contribution comprises a controller specification and an assessment of its validation requirements; no quantitative repair effect is claimed.

替换为：
The contribution is a controller specification and validation assessment; repair remains unquantified.

理由：Condense wording while retaining sample definitions, uncertainty, and the unverified-efficacy boundary.
