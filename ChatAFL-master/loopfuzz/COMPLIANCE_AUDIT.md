# LoopFuzz Elsevier / Computers & Security Compliance Audit

Audit date: 2026-06-04
Latest recheck: 2026-06-04 16:18 CST

Checked sources:
- Local Elsevier bundle: `../elsarticle`
- Manuscript package: `./`
- Journal guide: https://www.sciencedirect.com/journal/computers-and-security/publish/guide-for-authors

## Overall Result

`main.tex` is compliant with the local `elsarticle` bundle and compiles
successfully. The local `elsarticle` bundle is the correct Elsevier LaTeX
template family for a Computers & Security submission: Computers & Security is
an Elsevier/ScienceDirect journal, its Guide for Authors requires editable
source files such as LaTeX, and Elsevier's LaTeX instructions identify the
`elsarticle` package as the article-class template for Elsevier manuscripts.

The manuscript is LaTeX-template compliant and mechanically ready as a flat
Elsevier source package. Submission declarations that require factual author
confirmation are collected in `AUTHOR_DECLARATIONS_TO_CONFIRM.md`. Author and
corresponding-author metadata have been set according to the user-provided
values. Also, do not upload the entire `loopfuzz/` working directory as a source archive, because it contains
subdirectories such as `doc/` and `figures/`. Elsevier Editorial Manager cannot
process LaTeX submissions containing subfolders. Use a flat source-file set or
flat archive instead.

## Passed Checks

- `elsarticle.dtx`, `elsarticle.ins`, and `elsarticle-harv.bst` in `loopfuzz`
  match the corresponding files in `../elsarticle` by SHA-256.
- `main.tex` uses `\documentclass[preprint,review,12pt,authoryear]{elsarticle}`.
- `main.tex` sets `\journal{Computers \& Security}`.
- `frontmatter` is present and contains title, author block, affiliation,
  abstract, highlights, and keywords.
- Review formatting is enabled through the `review` class option.
- Line numbering is enabled through `lineno` and `\linenumbers`.
- Bibliography style is `elsarticle-harv`.
- The manuscript compiles with `pdflatex`, `bibtex`, and repeated `pdflatex`.
- Final LaTeX log contains no unresolved citation, unresolved label, fatal
  error, or rerun warning.
- Abstract word count is 157, within the requested 200-word limit.
- Abstract word count is also within the Computers & Security 250-word limit.
- Keyword count is 5, which satisfies the Computers & Security 5-to-10 keyword
  requirement.
- Separate `highlights.txt` is present.
- `highlights.txt` contains 5 items; each item is at most 85 characters.
- Included figures are present at the same folder level as `main.tex`, which is
  required for an Editorial Manager-safe LaTeX source package:
  - `motivation.pdf`
  - `fig1.pdf`
  - `state_coverage.pdf`
  - `edge_coverage.pdf`
- The compiled manuscript is 48 pages.
- Approximate main-text word count is 6278 words, under the Computers &
  Security 10k-word main-text limit.
- The compiled bibliography contains 56 cited entries.
- A prose sanity pass was performed after the latest edit. The manuscript keeps
  one central claim, closed-loop runtime admission control, and no ordinary
  prose paragraph now exceeds 170 words in the local scan.

## Flat Source Set for Editorial Manager

For a strict source-file upload, use only top-level files and avoid subfolders.
The flat source set should include:

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

`doc/`, `figures/`, generated `.aux`, `.log`, `.blg`, `.spl`, and template
example files are not part of the minimal source set.

## Author Metadata

- Author names have been set to `Ketang Chen` and `Xiaolei Ren`.
- Affiliation has been set to `Macau University of Science and Technology`,
  `Macau`, `China`.
- Corresponding author marker has been assigned to Xiaolei Ren.
- Author emails have been set to `3250006913@student.must.edu.mo` and
  `xlren@must.edu.mo`.
- Corresponding author email has been set to `xlren@must.edu.mo`.
- The corresponding-author note in `main.tex` now names Xiaolei Ren explicitly.

## Declarations Prepared for Author Confirmation

- `AUTHOR_DECLARATIONS_TO_CONFIRM.md` contains submission-ready wording for
  competing interest, funding, data availability, code availability, CRediT, and
  generative-AI declarations.
- `main.tex` contains a generative-AI declaration before the bibliography.
- These statements are not asserted as final facts until the author confirms
  they are true.

## Warnings / Risks

- BibTeX reports 4 remaining missing-page warnings. These do not block
  compilation. The unresolved entries are `no_grammar_no_problem_2023`,
  `pgfuzz_policy_guided_fuzzing_2021`, `when_analysis_2025`, and `chatafl`;
  complete them only when verified page metadata are available.
- The final LaTeX run reports only non-fatal overfull boxes in long technical
  phrases and code-style terms.
- The journal guide states that papers where AI/ML is the significant component
  may be considered out of scope. Because this manuscript studies LLM-guided
  protocol fuzzing, the manuscript should be framed as security testing,
  stateful protocol fuzzing, and runtime admission control rather than generic
  AI/ML novelty.
- Directly zipping the entire `loopfuzz/` directory is not compliant with
  Elsevier Editorial Manager's LaTeX source handling because the working
  directory contains subfolders. Submit the flat source set instead.
