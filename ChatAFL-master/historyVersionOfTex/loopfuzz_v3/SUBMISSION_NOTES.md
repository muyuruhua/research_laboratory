# Computers & Security Submission Notes

Latest repair: 2026-06-09 CST

Checked sources:
- Manuscript: `main.tex`
- Bibliography: `references.bib`
- Elsevier template bundle: `../elsarticle`
- Journal guide: https://www.sciencedirect.com/journal/computers-and-security/publish/guide-for-authors
- Elsevier LaTeX instructions: https://www.elsevier.com/researcher/author/policies-and-guidelines/latex-instructions

## Current Manuscript State

- Uses local Elsevier `elsarticle.cls` generated from the bundled 2024 `elsarticle.dtx`/`elsarticle.ins`.
- Current class option is `final,5p,times,number`, with numbered citations and `elsarticle-num-names`.
- `\journal{Computers \& Security}` is set.
- `frontmatter` contains title, authors, emails, affiliation, abstract, and keywords.
- Abstract is 179 words; keyword count is 5.
- `detex` estimate for the main text from Introduction through Conclusion is 9,949 words.
- Current PDF build is 20 pages.
- `highlights.txt` contains 5 highlights, each under 85 characters.
- Required author declarations have source sections in `main.tex`, but factual wording still requires author confirmation.
- The manuscript uses the Elsevier `elsarticle` family, which is the correct LaTeX source format for Elsevier submission. Computers & Security permits double-column LaTeX files.
- The current Computers & Security guide requires 5--10 keywords, an abstract of no more than 250 words, 3--5 highlights with at most 85 characters each, and a main text not exceeding 10,000 words.

## Flat Source Set for Editorial Manager

Use a flat source set. Do not upload the whole working directory.

Recommended source files:
- `main.tex`
- `references.bib`
- `main.bbl`
- `elsarticle.cls`
- `elsarticle-num-names.bst`
- `primary_branch_coverage_curve.pdf`
- `primary_edge_exploration_curve.pdf`
- `highlights.txt`

Optional/admin files, not part of the LaTeX source manuscript:
- `AUTHOR_DECLARATIONS_TO_CONFIRM.md`
- `COMPUTERS_SECURITY_SCOPE_NOTE.md`
- `COVER_LETTER_SCOPE_INQUIRY.md`
- `COMPLIANCE_AUDIT.md`

Do not submit `doc/`, `figures/`, generated `.aux/.log/.blg/.spl`, old PDFs, old zip archives, or template example files.

## Author Confirmation Required

Before submission, confirm and replace placeholder declaration wording for:
- CRediT authorship contribution statement
- Declaration of competing interest
- Funding
- Data availability
- Code availability, if required by the submission form

`AUTHOR_DECLARATIONS_TO_CONFIRM.md` contains draft wording and alternatives. Do not submit factual declarations until all authors confirm they are true.

Computers & Security uses Elsevier's research-data workflow. Under the guide's data option, deposit the data in a recognized repository and cite it in the manuscript when possible; otherwise, state the reason data cannot be shared or why repository deposit is not applicable. The current manuscript has no public repository URL or DOI, so the data-availability wording must be finalized before upload.

## Scope Risk

Computers & Security has a current scope risk for manuscripts where AI/ML is the significant component. This paper should be framed as a security-testing and stateful protocol fuzzing paper whose LLM component is a bounded proposal source controlled by runtime admission. Use `COMPUTERS_SECURITY_SCOPE_NOTE.md` or `COVER_LETTER_SCOPE_INQUIRY.md` for cover-letter positioning.

## Verification

After the 2026-06-09 repair:
- `main.tex` builds successfully with `latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex`.
- `main.pdf` is 20 pages.
- The main text from Introduction through Conclusion is 9,949 words by local `detex` estimate.
- The abstract is 179 words.
- The five highlights are 68--77 characters each.
- Figure paths were made flat-source friendly.
- New top-level copies of the two included figure PDFs were created.
- The primary, NSFuzz, and ablation numbers in Tables 2--5 were rechecked against:
  - `experiment_data/ten_groups_data_ten`
  - `experiment_data/NSFUZZER(ten)`
  - `experiment_data/ten_groups_ablation_ten`
  - `experiment_data/MBFUZZER(ten)` for the MQTT/Mosquitto archive exclusion note
- Rebuild and final zip verification should be run before upload.
