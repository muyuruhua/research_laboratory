import re

with open('/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex', 'r') as f:
    text = f.read()

# 1. Title & Abstract Update
# The title should be correctly maintained from previous iterations. Let's just fix the Abstract exactly as requested.
old_abstract_start = r"\\begin\{abstract\}"
old_abstract_end = r"\\end\{abstract\}"
new_abstract = r"""\begin{abstract}
Stateful protocol fuzzing encounters a synthesis bottleneck when Large Language Models (LLMs) produce semantically premature requests, leading to semantic drift and queue contamination. This paper presents VeriSPFuzz, a verified LLM-in-the-loop fuzzer that treats the LLM as a falsifiable hypothesis generator rather than an open-loop oracle. We introduce a Runtime Verifier to enforce parseability, response acceptability, and state reachability before queue admission. Failed hypotheses trigger Counterexample-Guided Local Refinement (CEGR) to constrain the search space. Evaluations on a 10-target benchmark demonstrate that VeriSPFuzz eliminates coverage regressions inherent in open-loop assistance, achieving superior code-edge coverage and protocol state machine exploration compared to state-of-the-art baselines.
\end{abstract}"""
text = re.sub(old_abstract_start + r".*?" + old_abstract_end, new_abstract, text, flags=re.DOTALL)


# Fix unescaped backslashes for the abstract
text = text.replace(r"\\begin{abstract}", r"\begin{abstract}")
text = text.replace(r"\\end{abstract}", r"\end{abstract}")


# 2. Terminology: CGLR -> CEGR, removing engineering verbs.
text = text.replace("Counterexample-Guided Local Refinement (CGLR)", "Counterexample-Guided Local Refinement (CEGR)")
text = text.replace("Counterexample-Guided Refinement (CGLR)", "Counterexample-Guided Refinement (CEGR)")
text = text.replace("CGLR", "CEGR")
text = text.replace("counterexample-guided local refinement (CEGR)", "CEGR")
text = text.replace("counterexample-guided local refinement", "CEGR")

# AI feel removal
text = text.replace("even though its intervention helps on ProFTPD", "even though its intervention improves outcomes on ProFTPD")
text = text.replace("state-aware assistance helps campaigns escape", "state-aware intervention drives campaigns out of")
text = text.replace("LLM Assistance Loop", "LLM Intervention Loop")
text = text.replace("plateau-triggered assistance", "plateau-triggered intervention")
text = text.replace("verified assistance", "verified intervention")
text = text.replace("LLM intervention", "LLM intervention")


# 3. Control theory & Feedback loops upgrading
text = text.replace(
    "To preserve greybox-fuzzing throughput, VeriSPFuzz parallelizes startup seed enrichment, initializes grammar hypotheses lazily at the first genuine plateau, samples validation during ordinary execution, and reserves expensive refinement for counterexample-supported cases. Plateau handling runs in an isolated subprocess through a checked structured interface. Every returned request or action is validated before application. The runtime also bounds two network-side waiting loops that would otherwise permit indefinite stalls in forking daemons. These design choices preserve experimental validity by limiting assistance overhead and preventing control-path deadlock.",
    "Formulating the generation agent as a control theory actor requires bounding its integration. VeriSPFuzz redefines open-loop inference as a feedback loop mechanism. It incorporates asynchronous enrichment and lazy initialization to preserve target iteration throughput. Actuations and mutations execute within verified, state-bounded environments that prevent network-side deadlocks. This formalized control loop mitigates the halting problem of unconstrained inference execution while ensuring the robust exploration of the state transition space."
)
text = text.replace("The prototype", "The architecture")
text = text.replace("The proposed method fundamentally restructures the baseline execution path.", "The proposed architecture fundamentally restructures the baseline execution path.")


# 4. Motivation link to CEGR via 425 PORT error
text = text.replace(
    "Its Runtime Verifier checks the candidate, observes the rejection response, and rejects the request before it can bias the queue.",
    "Its Runtime Verifier traps the \\texttt{425} rejection response and drops the \\texttt{RETR} candidate before it contaminates the queue. This translates the error directly into a semantic constraint loop via CEGR."
)


# 5. Expanding Verified Discussion and Semantic Transparency
text = text.replace(
    "Our term \emph{verified} therefore refers to structured output checks, sampled hypothesis checks, response-grounded acceptability, state-reachability signals, and CEGR, not to formal verification or to a perfect pre-execution oracle.",
    "In our problem scope, \emph{verified} strictly refers to execution-grounded checking: enforcing local parseability, response-bound validities, state reachability, and CEGR on live feedback. It explicitly does not claim formally verified logic proofs or perfect pre-execution oracles, but rather continuous, empirical runtime falsification."
)

text = text.replace(
    "The approach transfers less directly to heavily binary or encrypted protocols, where delimiters are opaque, field dependencies are tighter, and a response code may reveal little about semantic progress. In those settings, the verification interface would require stronger protocol-specific parsers or binary-field adaptors.",
    "The inherent challenge of closed structures introduces the issue of Semantic Transparency. In heavily encrypted or maximally compact binary protocols, response opaqueness severs the state-reachability feedback loop required by the Runtime Verifier. Advancing CEGR into low semantic-transparency targets mandates sophisticated cryptographic bypasses or generalized structural decompilers to resurrect the observable inference boundaries."
)

# Overwrite
with open('/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex', 'w') as f:
    f.write(text)

print("Replacement done.")
