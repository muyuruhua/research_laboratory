# LoopFuzz Elsevier / Computers & Security Compliance Audit

Latest repair: 2026-06-09 CST

## Overall Result

`main.tex` is mechanically compatible with the local Elsevier `elsarticle` bundle and satisfies the checked Computers & Security / Elsevier manuscript-format requirements that can be verified locally. The manuscript still has one non-mechanical blocker: factual author declarations and the final data/code availability wording must be confirmed by the authors before final submission.

## Passed / Repaired Checks

- Local `elsarticle.dtx` and bibliography styles match the corresponding files in `../elsarticle`.
- Compilation uses local `./elsarticle.cls` rather than a system copy.
- The class reported by LaTeX is `elsarticle 2024/04/04, 3.4`.
- The document class is `\documentclass[final,5p,times,number]{elsarticle}`, which is an Elsevier double-column journal-layout mode compatible with the local template family.
- `main.tex` sets `\journal{Computers \& Security}`.
- Title, authors, emails, corresponding-author note, affiliation, abstract, and keywords are in `frontmatter`.
- Abstract length is 179 words.
- Keyword count is 5.
- Main text from Introduction through Conclusion is estimated at 9,949 words with `detex`, within the 10,000-word main-text limit stated in the Computers & Security guide.
- Current PDF build is 20 pages, below the user's 30-page constraint.
- Bibliography uses numbered Elsevier style: `elsarticle-num-names`.
- Figure paths are flat-source friendly: `primary_branch_coverage_curve.pdf` and `primary_edge_exploration_curve.pdf`.
- Top-level copies of those figure PDFs exist beside `main.tex`.
- `highlights.txt` has 5 highlights, each 68--77 characters, within Elsevier's 3--5 highlight and 85-character limits.
- `main.tex` now contains sections for CRediT, competing interest, funding, data availability, and generative-AI disclosure.
- The primary, NSFuzz, and ablation table values were recomputed from the declared experiment directories and match the manuscript aggregates under the stated selection rule.

## Remaining Author-Confirmation Items

The following statements cannot be finalized by an editor or coding agent without author confirmation:

- Exact CRediT role split for Ketang Chen and Xiaolei Ren.
- Whether there are competing financial interests or personal relationships.
- Whether the work had funding, and if so funder names/grant numbers.
- Whether data/code will be public, available on request, or unavailable for a stated reason. Computers & Security / Elsevier expects deposited research data with citation when possible, or a clear reason when deposit is not applicable.

The manuscript currently uses conservative confirmation-required wording for these sections. Replace it with final factual declarations before submission.

## Source Package Guidance

Do not submit the whole `loopfuzz/` directory. It contains old generated files, example templates, local audit notes, and older zip archives. Submit a flat source package containing only current manuscript sources and included figures.

## Journal-Fit Risk

Computers & Security is an Elsevier journal and accepts LaTeX source submissions through the Elsevier workflow, for which `elsarticle` is the correct template family. The largest non-format risk is journal scope: the guide's AI/ML policy can affect papers where AI/ML is the significant component. The cover letter should emphasize security testing, stateful protocol fuzzing, runtime admission control, and empirical fuzzing evaluation rather than generic AI/ML novelty.

## Latest Verification Commands

- `cmp -s loopfuzz/elsarticle.dtx elsarticle/elsarticle.dtx`
- `cmp -s loopfuzz/elsarticle-num-names.bst elsarticle/elsarticle-num-names.bst`
- `latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex`
- abstract / keyword / highlights local counter script
- `awk 'BEGIN{p=0} /\\section\\{Introduction\\}/{p=1} /\\section\\*\\{CRediT/{p=0} p{print}' main.tex | detex | wc -w`
