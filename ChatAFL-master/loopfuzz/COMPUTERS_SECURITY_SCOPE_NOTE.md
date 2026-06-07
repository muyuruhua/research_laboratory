# Computers & Security Scope Positioning Note

Use this wording in the cover letter or submission comments if the system asks
why the manuscript fits Computers & Security.

## Short Positioning

This manuscript is submitted as a software and systems security testing paper,
not as a general AI or machine-learning paper. The central contribution is a
runtime admission-control policy for stateful protocol fuzzing. The large
language model is treated as a bounded hypothesis generator whose outputs must
pass execution-grounded checks before they can affect the fuzzing queue.

## Cover-Letter Paragraph

LoopFuzz addresses stateful protocol fuzzing, a security-testing problem in
which syntactically plausible messages often fail because they violate live
session-state preconditions. The paper does not propose a new language model or
claim generic AI capability. Instead, it studies how model-generated protocol
hypotheses should be controlled by runtime evidence. The proposed admission
boundary validates candidate interventions through parseability,
response-grounded acceptability, state reachability, and downstream gain, and
then uses counterexamples for local refinement. The contribution therefore lies
in secure software testing methodology, protocol-state exploration, and
empirical fuzzing evaluation, which are aligned with the security-engineering
scope of Computers & Security.

## Terms to Emphasize

- stateful protocol fuzzing
- security testing
- runtime admission control
- execution-grounded validation
- inferred protocol state machine
- empirical fuzzing evaluation

## Terms to Avoid as the Primary Framing

- generic AI system
- new large language model
- prompt engineering paper
- AI benchmark
- machine-learning model improvement
