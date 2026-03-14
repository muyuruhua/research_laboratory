import re

with open('/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex', 'r') as f:
    text = f.read()

# 2. Abstract & Keywords
old_abstract_start = r"\begin{abstract}"
old_abstract_end = r"\end{abstract}"
new_abstract = r"""\begin{abstract}
Stateful protocol fuzzing often struggles with semantic drift, where LLMs generate syntactically valid but semantically premature requests. We present VeriSPFuzz, a runtime-verified framework that treats LLMs as falsifiable hypothesis generators. Unlike open-loop systems, VeriSPFuzz introduces a Runtime Verifier to enforce parseability, response-grounded acceptability, state reachability, and coverage gain before queue admission. By integrating counterexample-guided local refinement (CGLR), VeriSPFuzz transforms execution failures into targeted grammar repairs, effectively curbing hallucinations. Evaluated on diverse protocols, VeriSPFuzz outperforms state-of-the-art baselines in both code-edge coverage and protocol state exploration while maintaining minimal computational overhead.
\end{abstract}"""
text = re.sub(old_abstract_start + r".*?" + old_abstract_end, new_abstract, text, flags=re.DOTALL)

old_keywords_start = r"\begin{IEEEkeywords}"
old_keywords_end = r"\end{IEEEkeywords}"
new_keywords = r"""\begin{IEEEkeywords}
Stateful Protocol Fuzzing, Large Language Models, Runtime Verification, Counterexample-Guided Refinement, Software Security
\end{IEEEkeywords}"""
text = re.sub(old_keywords_start + r".*?" + old_keywords_end, new_keywords, text, flags=re.DOTALL)

# 1. & 7. Academic phrasing & Short sentences
text = text.replace(
    "To prevent wasteful queries, VeriSPFuzz continuously tracks the IPSM frontier and dynamic growth rate. It invokes the model only when ordinary mutation genuinely stalls.",
    "To optimize the computational budget distribution over the search space, VeriSPFuzz monitors the IPSM frontier and growth rate. It invokes the model only when mutation stalls."
)
text = text.replace(
    "Failed hypotheses immediately become counterexamples.",
    "Failed hypotheses form an informing counterexample set."
)
text = text.replace(
    "These counterexamples trigger the target-aware local refinement of exact field constraints.",
    "These counterexamples trigger target-aware CGLR for exact field constraints."
)
text = text.replace("counterexample-guided local refinement", "CGLR")
# Re-fix first mention in abstract if it was replaced globally
text = text.replace("CGLR (CGLR)", "counterexample-guided local refinement (CGLR)") 
text = text.replace("Counterexample-Guided Local Refinement", "CGLR")
text = text.replace("CGLR (CGLR)", "Counterexample-Guided Local Refinement (CGLR)") 

# 3. & 4. & 12. Motivation & Semantic Chasm & Systemic thinking
text = text.replace(
    "The next useful step is not another filename mutation. It is a state repair.",
    "This exposes a profound semantic chasm. The generative agent performs blind reasoning because runtime state variables remain invisible to it. The next useful step is identical to a state repair."
)
text = text.replace(
    "This yields a closed explore-validate-refine loop.",
    "This establishes a formalized verification boundary between an unreliable generative agent and a strict deterministic system. It yields a closed explore-validate-refine loop. VeriSPFuzz transforms hallucinated generations into actionable counterexamples viable for refining grammar hypotheses."
)

# 10. Engineering phrases -> Academic
text = text.replace(
    "VeriSPFuzz then tests local parseability against the current message hypotheses by reusing parsed message regions already available during ordinary execution.",
    "VeriSPFuzz enforces structural action schema consistency against the current message hypotheses. It achieves this by reusing parsed message regions."
)
text = text.replace(
    "The goal is fast rejection of structurally invalid interventions",
    "The goal is the fast rejection of structurally invalid interventions"
)

# Consistent IPSM usage
text = text.replace("inferred state graph", "IPSM")
text = text.replace("inferred protocol state graph", "IPSM")
text = text.replace("state graph", "IPSM")
text = text.replace("protocol machine", "IPSM")

text = text.replace(
    r"\text{UpdateGraph}(G, Q_{path})",
    r"\text{UpdateIPSM}(G, Q_{path})"
)
text = text.replace(
    r"Initialize protocol IPSM",
    r"Initialize IPSM"
)

# Overwrite
with open('/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex', 'w') as f:
    f.write(text)

print("Replacement done.")
