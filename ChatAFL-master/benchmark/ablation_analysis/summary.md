# Historical Ablation Analysis Summary

## Dataset completeness

- Targets discovered: exim, forked-daapd, kamailio, live555, mosquitto, pure-ftpd.
- Variants discovered per target: `full_opt`, `wo_adaptive_100`, `wo_adaptive_512`, `wo_all`, `wo_frontier`, `wo_refinement`, `wo_state_prompt`.
- Fully complete targets with 5 runs for all 7 variants: exim, live555, mosquitto, pure-ftpd.
- Partially complete target: kamailio (`full_opt`=4, `wo_adaptive_100`=3, `wo_adaptive_512`=4, `wo_all`=3, `wo_frontier`=3, `wo_refinement`=5, `wo_state_prompt`=5).
- Missing target archive: forked-daapd (all 7 ablation directories contain no tarballs).

## Extraction basis

All metrics were extracted directly from each archived `out-*.tar.gz`:

- `cov_over_time.csv` → final source coverage (`l_abs`, `b_abs`)
- `plot_data` → final IPSM graph size (`n_nodes`, `n_edges`) and some LLM counters
- `fuzzer_stats` → final `paths_total`, crash/hang counts, `llm_total_calls`, token counts, plateau statistics

## Median results by target and variant

### exim

| Variant | Runs | l_abs | b_abs | IPSM edges | LLM calls |
|---|---:|---:|---:|---:|---:|
| full_opt | 5 | 6501 | 3903 | 106 | 58 |
| wo_adaptive_100 | 5 | 6558 | 3923 | 119 | 57 |
| wo_adaptive_512 | 5 | 6506 | 3898 | 107 | 12 |
| wo_all | 5 | 6562 | 3919 | 118 | 13 |
| wo_frontier | 5 | 6517 | 3897 | 115 | 57 |
| wo_refinement | 5 | 6498 | 3886 | 111 | 59 |
| wo_state_prompt | 5 | 6518 | 3899 | 120 | 53 |

### kamailio

Coverage was available, but `plot_data` / `fuzzer_stats` were not consistently usable across archived runs.

| Variant | Runs | l_abs | b_abs |
|---|---:|---:|---:|
| full_opt | 4 | 10023 | 4646 |
| wo_adaptive_100 | 3 | 10016 | 4641 |
| wo_adaptive_512 | 4 | 10052 | 4682 |
| wo_all | 3 | 10087 | 4723 |
| wo_frontier | 3 | 10019 | 4644 |
| wo_refinement | 5 | 10079 | 4717 |
| wo_state_prompt | 5 | 10015 | 4641 |

### live555

| Variant | Runs | l_abs | b_abs | IPSM edges | LLM calls |
|---|---:|---:|---:|---:|---:|
| full_opt | 5 | 5826 | 2896 | 154 | 335 |
| wo_adaptive_100 | 5 | 5837 | 2897 | 151 | 284 |
| wo_adaptive_512 | 5 | 5850 | 2907 | 151 | 332 |
| wo_all | 5 | 5856 | 2910 | 155 | 353 |
| wo_frontier | 5 | 5848 | 2898 | 152 | 250 |
| wo_refinement | 5 | 5872 | 2922 | 151 | 359 |
| wo_state_prompt | 5 | 5834 | 2894 | 154 | 323 |

### mosquitto

| Variant | Runs | l_abs | b_abs | IPSM edges | LLM calls |
|---|---:|---:|---:|---:|---:|
| full_opt | 5 | 3245 | 2029 | 36 | 118 |
| wo_adaptive_100 | 5 | 3250 | 2020 | 35 | 119 |
| wo_adaptive_512 | 5 | 3255 | 2031 | 40 | 114 |
| wo_all | 5 | 3223 | 2022 | 41 | 89 |
| wo_frontier | 5 | 3306 | 2080 | 35 | 114 |
| wo_refinement | 5 | 3339 | 2116 | 37 | 117 |
| wo_state_prompt | 5 | 3125 | 1988 | 30 | 81 |

### pure-ftpd

| Variant | Runs | l_abs | b_abs | IPSM edges | LLM calls |
|---|---:|---:|---:|---:|---:|
| full_opt | 5 | 2138 | 1225 | 296 | 40 |
| wo_adaptive_100 | 5 | 2228 | 1301 | 297 | 39 |
| wo_adaptive_512 | 5 | 2225 | 1291 | 297 | 32 |
| wo_all | 5 | 2184 | 1253 | 298 | 16 |
| wo_frontier | 5 | 2150 | 1217 | 303 | 27 |
| wo_refinement | 5 | 2182 | 1251 | 284 | 41 |
| wo_state_prompt | 5 | 2243 | 1304 | 300 | 26 |

## Cross-target patterns

### Five-target source-coverage view

Wins/losses are counted against `full_opt` using target-level medians.

| Variant | l_abs wins/losses | b_abs wins/losses | Interpretation |
|---|---:|---:|---|
| wo_adaptive_100 | 4 / 1 | 3 / 2 | Removing current adaptive thresholding usually does not hurt and often helps. |
| wo_adaptive_512 | 5 / 0 | 4 / 1 | Fixed 512 is the most coverage-stable alternative to `full_opt`. |
| wo_all | 4 / 1 | 4 / 1 | The exposed control bundle is not justified as a net-positive package. |
| wo_frontier | 4 / 1 | 2 / 3 | Frontier mostly helps line coverage weakly, but branch coverage support is poor. |
| wo_refinement | 4 / 1 | 4 / 1 | Historical data do not support a claim that refinement is consistently beneficial. |
| wo_state_prompt | 3 / 2 | 1 / 4 | State-prompt bundle is the least stable and often hurts branch coverage. |

### Four-target complete-data view (`exim`, `live555`, `mosquitto`, `pure-ftpd`)

- `wo_adaptive_512` beats `full_opt` on `l_abs` for all 4 complete targets and reduces `llm_total_calls` on all 4.
- `wo_all` beats `full_opt` on `IPSM edges` for all 4 complete targets and on `paths_total` for all 4.
- `wo_frontier` reduces `llm_total_calls` on all 4 complete targets, while only splitting 2/2 on branch coverage and IPSM-edge wins.
- `wo_refinement` improves source coverage on 3 of 4 complete targets, but increases LLM calls on 3 of 4.
- `wo_state_prompt` reduces LLM cost on all 4 complete targets, but hurts both source coverage and IPSM edges badly on mosquitto.

## Main conclusions

1. `full_opt` is not the dominant configuration in the historical archive.
2. The current adaptive mechanism is not empirically supported in its present form; fixed-512 is a stronger baseline than `full_opt` on the available data.
3. The current frontier scoring bundle is not cleanly justified: it reliably increases LLM cost and only inconsistently improves coverage/state exploration.
4. The current refinement mechanism cannot be presented as consistently beneficial; the larger archive overturns any provisional claim based on the smaller table snapshot.
5. The state-prompt switch is strongly target-dependent and should not be described as a universally helpful module.
6. Since `wo_all` often matches or exceeds `full_opt`, the paper should avoid claiming that the exposed controls, as a package, jointly explain LoopFuzz's gains.

## Recommended redesign direction

- Treat the current seven-way table as a diagnostic sanity check, not as causal evidence of component benefit.
- Rebuild the ablation study around orthogonal factors instead of bundled switches.
- Separate always-on engineering safeguards from search-policy mechanisms.
- Introduce independent switches for at least:
  - adaptive thresholding,
  - frontier out-degree bonus,
  - error/productivity penalty,
  - state-context injection,
  - action-list injection,
  - refinement / Tier-2 update,
  - dedup / bounded execution if those are claimed as part of the practical system contribution.
- Use a fixed stronger baseline (`full_opt` is not sufficient as the sole “best” anchor given the archive).
- Report completeness explicitly and either exclude forked-daapd / incomplete kamailio from strong claims or rerun them.
