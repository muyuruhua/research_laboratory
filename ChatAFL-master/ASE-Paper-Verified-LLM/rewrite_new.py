import re

with open("main.tex", "r") as f:
    text = f.read()

# Replace Abstract
abstract_pattern = re.compile(r"\\begin\{abstract\}.*?\\end\{abstract\}", re.DOTALL)
new_abstract = r"""\begin{abstract}
Stateful protocol fuzzing is challenging due to strict message syntax and deep execution states. Large language models (LLMs) can generate plausible messages but often introduce semantic drift. Syntactically correct outputs may still violate the server's runtime state and pollute the fuzzing queue. To address this, we propose LoopFuzz, an adaptive closed-loop framework. LoopFuzz validates all LLM outputs against runtime evidence before accepting them. It continuously checks grammar hypotheses against actual network traffic and refines them using counterexamples. Furthermore, it features a state-aware stagnation handler that queries the LLM only when ordinary mutation stalls. We evaluate LoopFuzz against state-of-the-art baselines across multiple real-world protocol servers in 24-hour campaigns. Our broader benchmark suite spans 10 implementations. In this revision, results on completed targets (ProFTPD, Exim, Forked-daapd, and Mosquitto) demonstrate that LoopFuzz consistently mitigates semantic drift. It achieves competitive or superior code coverage and substantially improves state-transition discovery on bottlenecks where context preservation is critical. By treating the LLM as an unverified generator and enforcing rigorous runtime validation, LoopFuzz provides a scalable, defensible approach to LLM-in-the-loop fuzzing.
\end{abstract}"""
text = abstract_pattern.sub(new_abstract, text)

# Replace Keywords
kw_pattern = re.compile(r"\\begin\{IEEEkeywords\}.*?\\end\{IEEEkeywords\}", re.DOTALL)
new_kw = r"""\begin{IEEEkeywords}
Stateful Fuzzing, Large Language Models, Protocol Testing, Closed-Loop Control, Software Security
\end{IEEEkeywords}"""
text = kw_pattern.sub(new_kw, text)

# Unify terminology
text = text.replace("the verified variant proposed in this paper", "LoopFuzz")
text = text.replace("the proposed design", "LoopFuzz")
text = text.replace("our implementation", "LoopFuzz")
text = text.replace("The implementation", "LoopFuzz")
text = text.replace("the implementation", "LoopFuzz")
text = text.replace("Verified LLM-in-the-Loop SGF (Ours)", "LoopFuzz (Ours)")

with open("main.tex", "w") as f:
    f.write(text)

print("Done string replacement")