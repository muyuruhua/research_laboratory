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
- Uses `preprint,authoryear` to match the local Elsevier Harvard template while
  keeping the manuscript near the requested 25-page length.
- Converted title, author block, abstract, and keywords to `frontmatter`.
- Converted references from `IEEEtran` to `elsarticle-harv`.
- Preserved all original manuscript sections, formulas, tables, figures, algorithms, results, limitations, and bibliography content.
- Generated local `elsarticle.cls` from the bundled `elsarticle.ins`/`elsarticle.dtx` so the project uses the provided Elsevier template rather than the older system class.
- Moved highlights to the separate `highlights.txt` file.
- Removed result figures that duplicated the terminal aggregate tables.
- Removed vertical rules from booktabs tables.

Files to submit or inspect:
- `main.tex`
- `references.bib`
- `main.bbl`
- `elsarticle.cls`
- `elsarticle-harv.bst`
- `highlights.txt`
- `AUTHOR_DECLARATIONS_TO_CONFIRM.md`
- `COVER_LETTER_SCOPE_INQUIRY.md`

Do not submit the whole `loopfuzz/` working directory as a LaTeX source archive.
The working directory contains generated files, template examples, old result
PDFs, and local audit notes. Use a flat source-file set or a flat archive.

Author-provided information still required:
- Author and corresponding-author metadata have been configured according to the
  user-provided values.
- Confirm the declarations in `AUTHOR_DECLARATIONS_TO_CONFIRM.md` before
  copying them into the Elsevier submission system.
- Check whether a graphical abstract is required or optional for the chosen article type.

Journal-fit risk:
- The current Computers & Security guide states that papers where AI/ML is the
  significant component are generally paused/out of scope. Because this
  manuscript studies LLM-guided protocol fuzzing, this is the highest
  non-format submission risk. The submission should frame the contribution
  around security testing, stateful protocol fuzzing, runtime admission control,
  and empirical security evaluation rather than generic AI/ML novelty. Use
  `COMPUTERS_SECURITY_SCOPE_NOTE.md` as the cover-letter positioning note. Use
  `COVER_LETTER_SCOPE_INQUIRY.md` to ask the editorial office for a scope
  decision before formal submission if needed.

Compilation:
- Verified with `pdflatex`, `bibtex`, and repeated `pdflatex`.
- Final build produced `main.pdf`.
- Latest recheck on 2026-06-08 00:04 CST: no unresolved citation, unresolved
  label, fatal error, or rerun warning remains in `main.log`/`main.blg`.
- The current compiled manuscript is 25 pages.
- BibTeX no longer reports missing-page warnings for the four previously
  incomplete entries.
- Remaining LaTeX warnings, if any, are non-fatal overfull boxes in long
  technical paragraphs and code-style terms; no unresolved citation or
  cross-reference warnings remained in the final run.
