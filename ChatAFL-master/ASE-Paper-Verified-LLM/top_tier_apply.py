import re

with open("main.tex", "r") as f:
    text = f.read()

# 1. 摘要修改：
new_abstract = r"""\begin{abstract}
Stateful protocol fuzzing encounters a synthesis bottleneck when Large Language Models (LLMs) produce semantically premature requests, leading to semantic drift and queue contamination. This paper presents VeriSPFuzz, a verified LLM-in-the-loop fuzzer that treats the LLM as a falsifiable hypothesis generator. We introduce a Runtime Verifier to enforce parseability, response acceptability, and state reachability before queue admission. Failed hypotheses trigger Counterexample-Guided Local Refinement (CEGR) to constrain the LLM's search space. Evaluations on a 10-target benchmark demonstrate that VeriSPFuzz eliminates coverage regressions inherent in open-loop assistance, achieving superior code-edge coverage and protocol state exploration compared to state-of-the-art baselines like ChatAFL.
\end{abstract}"""
text = re.sub(r"\\begin\{abstract\}.*?\\end\{abstract\}", new_abstract, text, flags=re.DOTALL)

# 2. 术语清洗：
text = text.replace("inferred protocol state machine", "IPSM")
text = text.replace("inferred protocol state graph", "IPSM")
text = text.replace("inferred state graph", "IPSM")
text = text.replace("state graph G", "IPSM $\mathcal{M}$")
text = text.replace("protocol state graph $G", "IPSM $\mathcal{M}$")
text = text.replace("state graph", "IPSM")
text = text.replace("UpdateGraph(G", "UpdateIPSM(\mathcal{M}")
text = text.replace("UpdateFrontierScores(G", "UpdateFrontierScores(\mathcal{M}")
text = text.replace("BuildStatePrompt(G", "BuildStatePrompt(\mathcal{M}")
text = text.replace("UpdateGraph", "UpdateIPSM")

# remove AI phrasing
text = re.sub(r"In this paper, we explore.*?\.", "", text)
text = re.sub(r"This paper studies.*?\.", "", text)
text = text.replace("This paper presents VeriSPFuzz", "We present VeriSPFuzz")

ftp_example = r"""\subsection{A Motivating Example: Semantic Drift}
Consider an FTP fuzzing campaign against ProFTPD. The fuzzer executes \texttt{USER} and \texttt{PASS}. It then queries the LLM for the next request. The model returns:
\begin{lstlisting}[basicstyle=\ttfamily\footnotesize,breaklines=true,columns=fullflexible,frame=single]
RETR example_file.txt
\end{lstlisting}

The request is syntactically fluent but semantically premature. The client lacks an active data channel via \texttt{PASV} or \texttt{PORT}. The server rejects it with \texttt{425 Use PORT or PASV first}.

An open-loop LLM fuzzer admits this \texttt{RETR} request based on surface fluency. This admission instantiates \emph{semantic drift}. The fuzzer wastes execution budget mutating a rejected execution branch. VeriSPFuzz blocks this drift. The Runtime Verifier traps the \texttt{425} rejection and drops the \texttt{RETR} candidate. This rejection instantiates Counterexample-Guided Local Refinement (CEGR). The trace becomes a counterexample. The LLM repairs the state precondition instead of regenerating from scratch. This yields a closed explore-validate-refine loop."""
text = re.sub(r"\\subsection\{A Motivating Example:.*?loop\.", ftp_example, text, flags=re.DOTALL)

# 4. 图表与算法一致性: Algorithm 1 重写
new_alg = r"""\begin{algorithm}[htbp]
\caption{Runtime-Validated Plateau Recovery in VeriSPFuzz}
\label{alg:fuzz}
\SetAlgoLined
\small
\KwIn{Target $T$, LLM function $\mathcal{L}$, Corpus $C$, Target edge growth $\dot{E}$}
\KwOut{Coverage bitmap $\mathcal{B}_{global}$, IPSM $\mathcal{M}$}
Initialize global bitmap $\mathcal{B}_{global} \leftarrow \emptyset$\;
Initialize IPSM $\mathcal{M} \leftarrow \emptyset$\;
\While{Campaign Time $<$ 24 hours}{
    $s \leftarrow \text{SelectSeed}(C)$\;
    $trace_{exec}, Q_{path} \leftarrow \text{MutateAndExecute}(T, s)$\;
    $\text{UpdateIPSM}(\mathcal{M}, Q_{path})$\;
    $\text{UpdateFrontierScores}(\mathcal{M})$\;
    \If{$\text{ShouldSampleValidate}()$}{
        $\text{ValidateHypothesesOnParsedRegions}(Q_{path})$\;
    }
    \If{$\text{PlateauDetected}(\tau(\dot{E}))$}{
        \If{$\text{HypCtxMissing}()$}{
            $\text{InitHypLazily}(C, Q_{path})$\;
        }
        \If{$\text{RefineGateOpen}()$}{
            $\text{CEGR\_RefineLowFitnessHyp}()$\;
        }
        $c_{state} \leftarrow \text{BuildStatePrompt}(\mathcal{M}, C, Q_{path})$\;
        \If{$\neg \text{PromptSeen\_Dedup}(c_{state})$}{
            $r \leftarrow \text{ForkQueryLLM}(\mathcal{L}, c_{state})$\;
            \If{$A(r) \equiv P(r) \land U(r) \land R(r) \land G(r)$}{
                $\text{ActionDispatch}(r, C)$\;
            }
        }
    }
}
\end{algorithm}"""
text = re.sub(r"\\begin\{algorithm\}.*?\\end\{algorithm\}", new_alg, text, flags=re.DOTALL)

# 5. 工程词汇替换
text = text.replace("parallel startup enrichment", "Asynchronous Startup Enrichment")
text = text.replace("asynchronous enrichment", "Asynchronous Startup Enrichment")

# 6. S-V-O 句子拆分优化 (Section IV snippets)
text = text.replace("VeriSPFuzz preserves the AFLNet/ChatAFL execution path, but it changes the control boundary between LLM generation and queue admission. A model output affects the campaign only after runtime evidence supports it.",
"VeriSPFuzz preserves the stateful greybox fuzzing execution path. It sets a strict control boundary between LLM generation and queue admission. A model output alters the campaign exclusively upon runtime evidence.")

text = text.replace("Failed hypotheses trigger Counterexample-Guided Local Refinement (CEGR) to constrain the search space.",
"Failed hypotheses trigger Counterexample-Guided Local Refinement (CEGR). CEGR strictly constrains the LLM's search space.")

# Finally write it back
with open("main.tex", "w") as f:
    f.write(text)
