import sys

with open('/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex', 'r') as f:
    lines = f.readlines()

new_lines = []
in_abstract = False
for line in lines:
    if r"\begin{abstract}" in line:
        in_abstract = True
        new_lines.append(r"\begin{abstract}" + "\n")
        new_lines.append("Stateful protocol fuzzing encounters a synthesis bottleneck when Large Language Models (LLMs) produce semantically premature requests, leading to semantic drift and queue contamination. This paper presents VeriSPFuzz, a verified LLM-in-the-loop fuzzer that treats the LLM as a falsifiable hypothesis generator rather than an open-loop oracle. We introduce a Runtime Verifier to enforce parseability, response acceptability, and state reachability before queue admission. Failed hypotheses trigger Counterexample-Guided Local Refinement (CEGR) to constrain the search space. Evaluations on a 10-target benchmark demonstrate that VeriSPFuzz eliminates coverage regressions inherent in open-loop assistance, achieving superior code-edge coverage and protocol state machine exploration compared to state-of-the-art baselines.\n")
        continue
    if r"\end{abstract}" in line:
        in_abstract = False
        new_lines.append(r"\end{abstract}" + "\n")
        continue

    if not in_abstract:
        # CGLR -> CEGR globally
        line = line.replace("Counterexample-Guided Local Refinement (CGLR)", "Counterexample-Guided Local Refinement (CEGR)")
        line = line.replace("CGLR", "CEGR")
        line = line.replace("counterexample-guided local refinement", "CEGR")
        line = line.replace("Counterexample-Guided Local Refinement", "CEGR")
        
        # Fixing AI/Engineering phrasing
        line = line.replace("even though its intervention helps on ProFTPD", "even though its intervention improves outcomes on ProFTPD")
        line = line.replace("state-aware assistance helps campaigns escape", "state-aware intervention drives campaigns out of")
        line = line.replace("LLM Assistance Loop", "LLM Intervention Loop")
        line = line.replace("plateau-triggered assistance", "plateau-triggered intervention")
        line = line.replace("verified assistance", "verified intervention")

        # Rewrite control loop para
        if "To preserve greybox-fuzzing throughput" in line and "preventing control-path deadlock" in line:
            line = "Formulating the generation agent as a control theory actor requires bounding its integration. VeriSPFuzz redefines open-loop inference as a feedback loop mechanism. It incorporates asynchronous enrichment and lazy initialization to preserve target iteration throughput. Actuations and mutations execute within verified, state-bounded environments that prevent network-side deadlocks. This formalized control loop mitigates the halting problem of unconstrained inference execution while ensuring the robust exploration of the state transition space.\n"

        line = line.replace("The prototype", "The architecture")
        line = line.replace("The proposed method fundamentally restructures the baseline execution path", "The proposed architecture fundamentally restructures the baseline execution path")
        line = line.replace("Its Runtime Verifier checks the candidate, observes the rejection response, and rejects the request before it can bias the queue.", r"Its Runtime Verifier traps the \texttt{425} rejection response and drops the \texttt{RETR} candidate before it contaminates the queue. This translates the error directly into a semantic constraint loop via CEGR.")
        
        # Verified & Encryption rewrites
        if "Our term \\emph{verified} therefore refers" in line:
            line = line.replace("Our term \emph{verified} therefore refers to structured output checks, sampled hypothesis checks, response-grounded acceptability, state-reachability signals, and CEGR, not to formal verification or to a perfect pre-execution oracle.", "In our problem scope, \emph{verified} strictly refers to execution-grounded checking: enforcing local parseability, response-bound validities, state reachability, and CEGR on live feedback. It explicitly does not claim formally verified logic proofs or perfect pre-execution oracles, but rather continuous, empirical runtime falsification.")
        
        if "The approach transfers less directly to heavily binary or encrypted protocols" in line:
            line = line.replace("The approach transfers less directly to heavily binary or encrypted protocols, where delimiters are opaque, field dependencies are tighter, and a response code may reveal little about semantic progress. In those settings, the verification interface would require stronger protocol-specific parsers or binary-field adaptors.", "The inherent challenge of closed structures introduces the issue of Semantic Transparency. In heavily encrypted or maximally compact binary protocols, response opaqueness severs the state-reachability feedback loop required by the Runtime Verifier. Advancing CEGR into low semantic-transparency targets mandates sophisticated cryptographic bypasses or generalized structural decompilers to resurrect the observable inference boundaries.")

        new_lines.append(line)

with open('/Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex', 'w') as f:
    f.writelines(new_lines)
