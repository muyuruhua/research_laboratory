# Results/Discussion Fill Template

Use this file after the remaining `5x24h` campaigns, ablation runs, and API-cost measurements finish. Replace every bracketed placeholder with final numbers or target-specific statements. The paragraphs are written to match the current tone of `main.tex`: evidence-first, reviewer-resistant, and conservative about causal claims.

---

## 1. Quick fill checklist

Before updating the paper, collect the following:

- Final `24h` terminal means and sample SDs for all five targets:
  - Code edge coverage: `AFLNet`, `ChatAFL`, `ChatAFL-Opt`
  - State transitions: `AFLNet`, `ChatAFL`, `ChatAFL-Opt`
- Statistical test results:
  - Mann-Whitney U `p` values for each target and metric pair of interest
- Time-series observations:
  - When the optimized curve separates from baselines
  - Whether the gain appears early, late, or mainly in terminal values
- Ablation results:
  - Coverage drop and state-transition drop after removing each mechanism
- API overhead:
  - Invocation count
  - Prompt tokens
  - Completion tokens
  - Estimated cost
  - Relative wall-clock delay or slowdown

---

## 2. Table wording updates

### Table II / 24-hour main results caption

Use if all five targets are complete:

> Mean $\pm$ sample SD of end-of-campaign results over five 24-hour trials for code-edge coverage and inferred protocol state transitions. Bold marks the highest mean per target per metric. `*` denotes statistical significance versus both baselines under a two-sided Mann-Whitney U test at $p < 0.05$.

### Table IV / ablation caption

> Ablation results over five 24-hour trials. Each row reports the mean drop relative to the full ChatAFL-Opt configuration, isolating the marginal contribution of one disabled control mechanism at a time.

### Table V / API cost caption

> Per-target LLM invocation footprint and estimated cost over a 24-hour campaign. Reported values summarize the practical overhead of runtime-mediated LLM assistance rather than optimization targets in themselves.

---

## 3. RQ1 template: System-level campaign effects

> RQ1 asks whether the complete system improves long-horizon campaign behavior relative to direct LLM assistance. Across all five completed targets, the results show `[OVERALL_PATTERN]`. ChatAFL-Opt finishes above ChatAFL on `[N_OUT_OF_5]` targets for edge coverage and on `[N_OUT_OF_5]` targets for inferred state transitions. Relative to AFLNet, ChatAFL-Opt finishes higher on `[N_OUT_OF_5]` targets for edge coverage and `[N_OUT_OF_5]` targets for inferred transitions.
>
> The strongest edge-coverage gains appear on `[TARGET_A]` and `[TARGET_B]`, where ChatAFL-Opt improves over ChatAFL by `[DELTA_A]%` and `[DELTA_B]%`, respectively, and over AFLNet by `[DELTA_A2]%` and `[DELTA_B2]%`. On `[TARGET_C]`, the larger effect appears in inferred state-transition growth rather than terminal edge coverage, suggesting that the main benefit on that target is sustained protocol progress rather than immediate marginal coverage.
>
> We therefore interpret RQ1 conservatively. The data do not imply that every control mechanism helps every target equally. They do indicate that replacing direct LLM admission with runtime-mediated admission changes campaign outcomes in the intended direction across the completed benchmark set.

---

## 4. RQ2 template: State-space velocity and escape from plateaus

> Fig. X shows the state-discovery trajectories. The main pattern is that ChatAFL-Opt separates from the baselines at `[EARLY/LATE/MIXED]` stages of the campaign. On `[TARGET_A, TARGET_B]`, the separation becomes visible after approximately `[HOUR_RANGE]`, when the baseline trajectories begin to flatten. On `[TARGET_C]`, the gain is smaller but remains positive through the terminal state count.
>
> This pattern is consistent with the intended role of adaptive plateau triggering and state-aware prompting. The mechanism is not expected to dominate from the start of the run, when replayable valid traces are still plentiful. Instead, it is expected to matter after ordinary mutation loses momentum. The time-series behavior matches that expectation on `[N_OUT_OF_5]` of the completed targets.
>
> We avoid a stronger claim because inferred state counts remain proxy measures. The evidence supports the statement that the optimized policy is associated with later and more sustained IPSM expansion; it does not, by itself, prove deeper semantic reachability on every target.

---

## 5. RQ3 template: Sustained edge coverage

> Fig. Y and Table II show that ChatAFL-Opt maintains stronger late-stage edge-coverage growth on `[N_OUT_OF_5]` of the completed targets. Statistically significant gains versus both baselines appear on `[TARGET_LIST_SIGNIFICANT]`. On `[TARGET_LIST_MODEST]`, the advantage is positive but smaller, so we treat those results as supportive rather than decisive.
>
> The most direct reading is not that the model simply generates more candidate traffic. Rather, the optimized system appears to admit fewer low-value or context-misaligned suggestions into the shared corpus. This interpretation is consistent with the late-campaign shape of the curves: the gain becomes most visible once easy replay-and-mutate opportunities have already been exhausted.
>
> Numerically, the average terminal edge-coverage improvement of ChatAFL-Opt over ChatAFL is `[AVG_OPT_VS_CHAT_COV]%`, and the corresponding improvement over AFLNet is `[AVG_OPT_VS_AFLNET_COV]%`. These aggregate numbers should still be read alongside the per-target variance, because the practical effect size depends on protocol structure.

---

## 6. RQ4 template: Ablation study

> Table IV isolates the contribution of the four main controls. Removing frontier weighting reduces edge coverage by `[DROP_FRONTIER_COV]%` on average and state transitions by `[DROP_FRONTIER_STATE]%`. Removing adaptive plateau triggering reduces edge coverage by `[DROP_ADAPTIVE_COV]%` and state transitions by `[DROP_ADAPTIVE_STATE]%`. Removing hypothesis refinement reduces edge coverage by `[DROP_REFINEMENT_COV]%` and state transitions by `[DROP_REFINEMENT_STATE]%`. Removing state-context prompting reduces edge coverage by `[DROP_CONTEXT_COV]%` and state transitions by `[DROP_CONTEXT_STATE]%`.
>
> Two conclusions are possible depending on the final numbers:
>
> **If one mechanism dominates:**
>
> > The ablation results suggest that `[DOMINANT_MECHANISM]` accounts for the largest share of the observed gain. The remaining controls are still beneficial, but their marginal effect is smaller.
>
> **If the gains are distributed:**
>
> > The ablation results do not point to a single dominant mechanism. Instead, they suggest that the full benefit arises from the interaction of scheduling, validation, refinement, and state-context construction.
>
> In either case, the ablation should be framed as attribution rather than proof of strict causal independence, because the mechanisms interact within one campaign loop.

---

## 7. RQ5 template: API cost and practical overhead

> Table V reports the practical overhead of runtime-mediated LLM assistance. Across the five targets, ChatAFL-Opt makes `[AVG_CALLS]` API calls per 24-hour run on average, consumes `[AVG_PROMPT_TOKENS]` prompt tokens and `[AVG_COMPLETION_TOKENS]` completion tokens, and incurs an estimated mean cost of `[AVG_COST]` USD per campaign. The relative wall-clock delay is `[AVG_DELAY]%`.
>
> These numbers matter because the method should be judged as a campaign policy rather than as a pure effectiveness result. If the final cost is modest relative to the observed coverage and state-space gains, then the approach is practically attractive. If the cost is high on certain targets, then the benefit should be interpreted more selectively.
>
> A reviewer-resistant way to phrase the result is:
>
> > The cost data show that runtime-mediated LLM assistance is not free, but the invocation budget remains bounded and concentrated around plateau events rather than ordinary executions.

---

## 8. Discussion template

### Deep-state reachability

> The completed data are consistent with the claim that the optimized system better preserves the interaction context required to cross deep protocol bottlenecks. This interpretation is strongest on `[TARGET_LIST_STRONGEST]`, where the optimized configuration maintains state growth after the baselines flatten. We still phrase this claim carefully because state transitions and edge coverage remain proxy measures rather than direct observations of latent server state.

### Overhead and prompt budget

> The final token and delay measurements show that the cost-control mechanisms `[WERE / WERE NOT]` sufficient to keep model interaction within a practical budget. In particular, lazy hypothesis initialization and sampled validation `[LIMITED / DID NOT FULLY LIMIT]` prompt growth on `[TARGET_LIST]`. The practical conclusion is therefore `[PRACTICAL_CONCLUSION]`.

### Broader implications and limitations

> The final evidence suggests that runtime-mediated LLM assistance is most useful for protocols that are structured enough for prompt-based generation to propose plausible continuations, yet constrained enough that unconstrained generation would otherwise drift into low-value behavior. The approach remains less directly applicable to `[OPAQUE_TARGET_TYPES]`, where response signals are weak and additional format-aware front ends would likely be necessary.

---

## 9. Optional updated abstract sentence after all five targets finish

Replace the current final abstract sentence with one of these depending on the final outcome.

### If all five targets are positive

> Across five 24-hour benchmarks, the completed results show that ChatAFL-Opt consistently improves state exploration over direct LLM assistance and yields statistically significant edge-coverage gains on `[TARGET_LIST]`.

### If the outcome is mixed but favorable

> Across five 24-hour benchmarks, the completed results show that ChatAFL-Opt consistently improves over direct LLM assistance on `[MAIN_METRIC]`, with statistically significant edge-coverage gains on `[TARGET_LIST]` and the largest remaining effect on `[TARGET]` appearing in inferred state-transition growth.

---

## 10. Optional updated conclusion sentence after all data arrive

> With all five targets and the ablation suite complete, the evidence supports the view that LLM assistance is most effective in stateful protocol fuzzing when it is introduced as a runtime-mediated control policy rather than as an open-loop source of candidate messages.
