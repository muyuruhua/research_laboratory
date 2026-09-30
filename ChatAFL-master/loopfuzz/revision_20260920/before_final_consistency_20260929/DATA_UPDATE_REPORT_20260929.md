# Experimental-data update report (2026-09-29)

The manuscript revision uses the current `Key_Experiment` archive as its numeric source. `ablation/gated_fixed` is excluded because it duplicates benchmark LoopFuzz and would double count arm D. No missing runs were fabricated. The nominal design count remains `N=10`; every table and figure reports the observed `n`, and unavailable target–arm combinations remain blank.

## Selected archive ledger

| Arm | Meaning | Observed archives |
|---|---|---:|
| A | benchmark AFLNet | 94 |
| B | benchmark ChatAFL | 91 |
| C | ablation/direct | 90 |
| D | benchmark LoopFuzz | 104 |
| E | ablation/calibrated | 86 |
| E, gamma=0.99 | sensitivity | 108 |
| E, gamma=1.0 | sensitivity | 55 |
| **Total** |  | **628** |

The core A–E figures therefore contain 465 archives. Cost plots contain 371 B–E observations with saved counters. E/bftpd now has ten archives and is included in the endpoint table and figures when the relevant counter is available. All 628 coverage endpoints match their supplied `run_summary.csv` terminal `b_abs` values.

## Updated mechanism totals

| Arm | Candidates | Trials | Reject | Durable | Episodes |
|---|---:|---:|---:|---:|---:|
| C | 1,326 | 1,326 | 0 | 1,326 | 56,164 |
| D | 2,227 | 2,226 | 2,203 | 23 | 77,593 |
| E | 735 | 734 | 725 | 9 | 31,826 |

The E reliability figure uses 25,756 positive-mutation episodes after excluding 6,070 zero-mutation records. This is a logged-reward diagnostic; it is not a fixed-energy source-branch calibration result.

## Outputs

- `filled_run_evidence_20260929.json` and `filled_experiment_data_20260929.json`: auditable run ledger and aggregates.
- `archive_arm_results_20260929.csv`: machine-readable per-arm summary.
- `observed_tables.updated_20260929.tex`, `observed_costs.updated_20260929.tex`, and `archive_arm_results.updated_20260929.tex`: updated LaTeX tables.
- `vector_figure_evidence_20260929.json.gz`: numeric evidence for the core figures.
- `figures_updated_20260929/`: six vector PDF/SVG figures plus numeric CSV/JSON sidecars.
- `data_update_manifest_20260929.json`: source summary and archive SHA-256 manifest.

## Verification

`bash build_revised.sh` completes successfully. The resulting `main.revised.pdf` has 21 pages, no LaTeX errors, no undefined citations/references, and no `Overfull \\hbox` or float-size warnings. `pdfimages -list` reports no embedded raster images; all six updated plots have SVG files with zero `<image>` elements. The whitespace audit reports a 83.0% reduction in whole-width blank-band equivalents relative to the pre-whitespace snapshot and a 79.9% reduction for half-column bands.

The archive remains descriptive: heterogeneous run counts and horizons, incomplete build/resource provenance, and absent matched counterfactuals do not support causal admission, calibration, cost-efficiency, or arm-level vulnerability-recall claims.
