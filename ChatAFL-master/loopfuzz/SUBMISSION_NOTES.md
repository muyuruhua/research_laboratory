# Computers & Security Submission Notes

Source material used:
- Original manuscript: `../ASE-Paper-Verified-LLM/main.tex`
- Original bibliography: `../ASE-Paper-Verified-LLM/references.bib`
- Original figures: `../ASE-Paper-Verified-LLM/figures/`
- Elsevier template bundle: current `loopfuzz/` directory
- Journal guide checked: https://www.sciencedirect.com/journal/computers-and-security/publish/guide-for-authors

Implemented in `main.tex`:
- Converted from `IEEEtran` to `elsarticle`.
- Set journal name to `Computers & Security`.
- Enabled `preprint,review,12pt,authoryear` for double-spaced review format.
- Enabled line numbers via `lineno`.
- Converted title, author block, abstract, highlights, and keywords to `frontmatter`.
- Converted references from `IEEEtran` to `elsarticle-harv`.
- Preserved all original manuscript sections, formulas, tables, figures, algorithms, results, limitations, and bibliography content.
- Generated local `elsarticle.cls` from the bundled `elsarticle.ins`/`elsarticle.dtx` so the project uses the provided Elsevier template rather than the older system class.

Files to submit or inspect:
- `main.tex`
- `references.bib`
- `main.bbl`
- `elsarticle.cls`
- `elsarticle-harv.bst`
- `motivation.pdf`
- `fig1.pdf`
- `state_coverage.pdf`
- `edge_coverage.pdf`
- `highlights.txt`
- `AUTHOR_DECLARATIONS_TO_CONFIRM.md`

Do not submit the whole `loopfuzz/` working directory as a LaTeX source archive.
Elsevier Editorial Manager does not process LaTeX source packages with
subfolders. The figure files have therefore been copied to the same folder as
`main.tex`, and the `\includegraphics` paths in `main.tex` use flat filenames.
The older `figures/` folder is retained only as local working material.

Author-provided information still required:
- Author and corresponding-author metadata have been configured according to the
  user-provided values.
- Confirm the declarations in `AUTHOR_DECLARATIONS_TO_CONFIRM.md` before
  copying them into the Elsevier submission system.
- Check whether a graphical abstract is required or optional for the chosen article type.

Journal-fit risk:
- The current Computers & Security guide states that papers where AI/ML is the significant component are considered out of scope. Because this manuscript studies LLM-guided protocol fuzzing, the submission should frame the contribution around security testing, stateful protocol fuzzing, runtime admission control, and empirical security evaluation rather than generic AI/ML novelty. Use `COMPUTERS_SECURITY_SCOPE_NOTE.md` as the cover-letter positioning note.

Compilation:
- Verified with `pdflatex`, `bibtex`, and repeated `pdflatex`.
- Final build produced `main.pdf`.
- After flattening figure paths, `pdflatex -interaction=nonstopmode main.tex`
  still compiles successfully and produces a 48-page PDF.
- Latest recheck on 2026-06-04 16:18 CST: no unresolved citation, unresolved
  label, fatal error, or rerun warning remains in `main.log`/`main.blg`.
- BibTeX reports 4 non-fatal missing-page warnings for entries whose verified
  page metadata are still unavailable in the checked sources:
  `no_grammar_no_problem_2023`, `pgfuzz_policy_guided_fuzzing_2021`,
  `when_analysis_2025`, and `chatafl`.
- Remaining LaTeX warnings are non-fatal overfull boxes in long technical paragraphs and code-style terms; no unresolved citation or cross-reference warnings remained in the final run.
