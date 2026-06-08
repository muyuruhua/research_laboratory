# LoopFuzz Elsevier / Computers & Security Compliance Audit

Audit date: 2026-06-04
Latest recheck: 2026-06-08 00:04 CST

Checked sources:
- Local Elsevier bundle: `../elsarticle`
- Manuscript package: `./`
- Journal guide: https://www.sciencedirect.com/journal/computers-and-security/publish/guide-for-authors

## Overall Result

`main.tex` is compliant with the local `elsarticle` bundle and compiles
successfully. The local `elsarticle` bundle is the correct Elsevier LaTeX
template family for a Computers & Security submission: Computers & Security is
an Elsevier/ScienceDirect journal, its Guide for Authors accepts editable
source files such as LaTeX, and Elsevier's LaTeX instructions identify the
`elsarticle` package as the article-class template for Elsevier manuscripts.

The manuscript is LaTeX-template compliant and mechanically ready as a flat
Elsevier source package. Submission declarations that require factual author
confirmation are collected in `AUTHOR_DECLARATIONS_TO_CONFIRM.md`. Author and
corresponding-author metadata have been set according to the user-provided
values. Do not upload the entire `loopfuzz/` working directory as a source
archive, because it contains generated files, template examples, and local
working artifacts. Use a flat source-file set or flat archive instead.

## Passed Checks

- `elsarticle.dtx`, `elsarticle.ins`, and `elsarticle-harv.bst` in `loopfuzz`
  match the corresponding files in `../elsarticle` by SHA-256. The local
  `elsarticle.cls` was generated from the bundled `elsarticle.dtx` and
  `elsarticle.ins`; the upstream `../elsarticle` folder does not ship a
  pre-generated `elsarticle.cls`.
- `main.tex` uses `\documentclass[preprint,authoryear]{elsarticle}`.
- `main.tex` sets `\journal{Computers \& Security}`.
- `frontmatter` is present and contains title, author block, affiliation,
  abstract, and keywords.
- Affiliation uses Elsevier's structured `\affiliation` fields and now includes
  organization, address line, city, and country.
- Bibliography style is `elsarticle-harv`.
- The manuscript compiles with `pdflatex`, `bibtex`, and repeated `pdflatex`.
- Final LaTeX log contains no unresolved citation, unresolved label, fatal
  error, or rerun warning.
- Abstract word count is 158, within the requested 200-word limit and the
  Computers & Security 250-word limit.
- Keyword count is 5, which satisfies the Computers & Security 5-to-10 keyword
  requirement.
- Separate `highlights.txt` is present.
- `highlights.txt` contains 5 items; each item is at most 85 characters.
- The current `main.tex` uses TikZ figures and does not require external
  graphics files for compilation.
- Booktabs tables no longer use vertical rules.
- The compiled manuscript is 25 pages.
- Approximate main-text word count remains under the Computers &
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
- `highlights.txt`

`doc/`, `figures/`, generated `.aux`, `.log`, `.blg`, `.spl`, old result PDFs,
and template example files are not part of the minimal source set.

## Author Metadata

- Author names have been set to `Ketang Chen` and `Xiaolei Ren`.
- Affiliation has been set to `Macau University of Science and Technology`,
  `Avenida Wai Long, Taipa`, `Macau`, `China`.
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

- BibTeX reports no remaining missing-page warnings after adding verified page
  ranges for `no_grammar_no_problem_2023`,
  `pgfuzz_policy_guided_fuzzing_2021`, `when_analysis_2025`, and `chatafl`.
- The final LaTeX run reports nine non-fatal overfull boxes in long technical
  phrases and wide tables.
- The Computers & Security guide states that, since 2024, papers where AI/ML is
  a significant component are generally paused/out of scope. Because this
  manuscript studies LLM-guided protocol fuzzing, this is the highest desk-check
  risk. The cover letter and manuscript should frame the contribution as
  security testing, stateful protocol fuzzing, and runtime admission control
  rather than generic AI/ML novelty. A scope-inquiry draft has been added as
  `COVER_LETTER_SCOPE_INQUIRY.md` for pre-submission use.
- Directly zipping the entire `loopfuzz/` directory is not compliant with
  clean LaTeX source-submission practice because the working directory contains
  generated files and local artifacts. Submit the flat source set instead.
