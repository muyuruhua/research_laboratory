#!/bin/bash

# Fix Abstract
sed -i '' '/\\begin{abstract}/,/\\end{abstract}/c\
\\begin{abstract}\
Stateful protocol fuzzing often struggles with semantic drift, where LLMs generate syntactically valid but semantically premature requests. We present VeriSPFuzz, a runtime-verified framework that treats LLMs as falsifiable hypothesis generators. Unlike open-loop systems, VeriSPFuzz introduces a Runtime Verifier to enforce parseability, response-grounded acceptability, state reachability, and coverage gain before queue admission. By integrating counterexample-guided local refinement (CGLR), VeriSPFuzz transforms execution failures into targeted grammar repairs, effectively curbing hallucinations. Evaluated on diverse protocols, VeriSPFuzz outperforms state-of-the-art baselines in both code-edge coverage and protocol state exploration while maintaining minimal computational overhead.\
\\end{abstract}' /Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex

# Fix Keywords
sed -i '' '/\\begin{IEEEkeywords}/,/\\end{IEEEkeywords}/c\
\\begin{IEEEkeywords}\
Stateful Protocol Fuzzing, Large Language Models, Runtime Verification, Counterexample-Guided Refinement, Software Security\
\\end{IEEEkeywords}' /Users/ketangchen/Documents/000_20260114dev/research_laboratory/ChatAFL-master/ASE-Paper-Verified-LLM/main.tex
