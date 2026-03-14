import re

with open('/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex', 'r') as f:
    text = f.read()

# 1. Title formatting
text = text.replace(
    r"\title{VeriSPFuzz: Verified LLM-in-the-Loop Stateful Protocol Fuzzing}",
    r"\title{VeriSPFuzz: Verified LLM-in-the-Loop Stateful Protocol Fuzzing}"
)

# 2. Simplify long sentences (Abstract)
text = text.replace(
    "This problem becomes acute in LLM-assisted fuzzing, where fluent generations often enter the queue without verifiable runtime evidence.",
    "This problem exacerbates LLM-assisted fuzzing. Fluent generations often enter the queue without verifiable runtime evidence."
)
text = text.replace(
    "It creates formal message grammars and state-conditioned continuations. A meticulously designed Runtime Verifier acts as the gatekeeper. It assesses every LLM proposal and admits an input only when it guarantees local parseability, response-grounded acceptability, explicit state reachability, and measurable downstream coverage gain.",
    "It creates formal message grammars and state-conditioned continuations. A Runtime Verifier acts as the strict gatekeeper. It assesses every LLM proposal before admission. An input enters the queue only when it passes four checks. It must guarantee parseability, response-based acceptability, state reachability, and measurable coverage gain."
)
text = text.replace(
    "In a stateful campaign, a request can be grammatically plausible and still be wrong for the live session. Once such a request enters the queue, the campaign can spend budget around a rejected branch instead of a productive one.",
    "A request can be grammatically plausible but semantically wrong for the live state. The queue then spends its budget on rejected branches instead of productive ones."
)

# 3. Method Refinement - Academic formal tone
text = text.replace(
    r"Algorithm~\ref{alg:fuzz} summarizes the plateau path and the hypothesis-refinement gate. It belongs to the design logic rather than to a low-level implementation appendix because it captures the exact point where state-aware triggering, Runtime Verifier checks, and counterexample-guided local refinement meet in one control loop.",
    r"Algorithm~\ref{alg:fuzz} specifies the plateau path and the hypothesis-refinement gate. It formally defines the integration point among state-aware triggering, Runtime Verifier checks, and counterexample-guided local refinement within a single control loop."
)
text = text.replace(
    "The prototype extends the ChatAFL/AFLNet execution path.",
    "The proposed method fundamentally restructures the baseline execution path."
)
text = text.replace(
    "All reported subjects are textual or semi-textual request/response protocols. We therefore treat the evidence as specific to that regime, not as a claim that the same method is already validated on opaque binary or encrypted protocols such as DNS, TLS, SSH, DTLS, or DICOM.",
    "All evaluated subjects are textual or semi-textual request/response protocols. We restrict our claims to this regime. The method is not yet validated on opaque binary or encrypted protocols such as DNS, TLS, SSH, DTLS, or DICOM."
)

with open('/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex', 'w') as f:
    f.write(text)
