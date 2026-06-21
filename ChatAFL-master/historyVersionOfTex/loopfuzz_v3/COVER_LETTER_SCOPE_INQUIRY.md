Dear Editors,

We are writing to ask whether the enclosed manuscript, entitled
"LoopFuzz: Closed-Loop Runtime Admission Control for LLM-Guided Stateful
Protocol Fuzzing", fits the current editorial scope of Computers & Security.

The manuscript is a software and systems security testing paper. It addresses
stateful protocol fuzzing, where syntactically plausible messages can still
violate live session-state preconditions and waste fuzzing budget. The central
contribution is a runtime admission-control boundary for LLM-guided fuzzing.
The large language model is not treated as the scientific object of the paper.
We do not propose a new model, new model-training method, AI benchmark, or
generic prompt-engineering technique. Instead, the model is used only as a
bounded hypothesis generator. Its outputs must pass execution-grounded checks
for parseability, response-grounded acceptability, state reachability, and
downstream campaign gain before they can affect the fuzzing queue.

The paper's empirical evidence is therefore organized around security-testing
outcomes. It evaluates branch coverage, state-transition coverage, repeated-run
variance, statistical comparisons against AFLNet and ChatAFL, auxiliary
comparisons with NSFuzz and MBFuzzer, and policy ablations. The claims are
bounded to stateful protocol fuzzing and runtime campaign control. They do not
claim general AI capability or model-level improvement.

We understand that Computers & Security has tightened its policy for manuscripts
where artificial intelligence or machine learning is the significant component.
For that reason, we have framed the manuscript around secure software testing,
stateful protocol analysis, runtime admission control, and empirical fuzzing
evaluation. We would appreciate your guidance on whether this framing is within
the journal's scope before formal submission.

Sincerely,

Ketang Chen and Xiaolei Ren
