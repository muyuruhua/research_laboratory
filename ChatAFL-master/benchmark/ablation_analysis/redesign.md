# Recommended Redesign of the Ablation Study

## Goal

The redesigned study should answer two narrower and defensible questions:

1. Which search-policy mechanisms improve coverage or state exploration relative to a strong baseline?
2. What cost is paid in LLM calls/tokens and operational overhead for each mechanism?

It should **not** try to treat the current bundled switches as a clean additive decomposition of LoopFuzz.

## Principle 1: separate engineering safeguards from search-policy heuristics

Do not mix the following two categories in the same causal claim.

### Always-on engineering controls

These should remain enabled in the main system unless the paper explicitly studies robustness / operational safety:

- fork-isolated LLM invocation
- bounded execution and kill escalation
- startup parallel enrichment
- prompt dedup ring

These are practical system-hardening features, not directly comparable to policy heuristics like adaptive thresholds or frontier scoring.

### Search-policy mechanisms

These are the proper ablation targets:

- adaptive plateau thresholding
- frontier out-degree bonus
- error/productivity penalty
- Tier-2 refinement
- state-context injection
- action-list injection

## Principle 2: stop ablating bundled switches

The current archive shows that bundled switches are too entangled to interpret.

### Current problems

- `wo_frontier` disables more than one idea at once.
- `wo_state_prompt` removes both `state_ctx` and the structured `actions[]` path.
- `wo_all` mixes multiple policy changes, so it is useful only as a stress test, not as evidence of additive contribution.

### Required new switches

The implementation should eventually expose at least these independent toggles:

- `CHATAFL_NO_ADAPTIVE`
- `CHATAFL_FIXED_THRESHOLD=<value>`
- `CHATAFL_NO_FRONTIER_BONUS`
- `CHATAFL_NO_ERROR_PENALTY`
- `CHATAFL_NO_REFINEMENT`
- `CHATAFL_NO_STATE_CTX`
- `CHATAFL_NO_ACTIONS`

Optional but useful if the paper wants operational-cost claims:

- `CHATAFL_NO_DEDUP`
- `CHATAFL_NO_BOUNDED_EXEC`
- `CHATAFL_NO_PARALLEL_ENRICHMENT`

## Principle 3: change the baseline

Historical data show that `full_opt` is not a trustworthy “best configuration” anchor.

### Recommended baseline ladder

Use three baselines instead of one:

1. **Safety baseline**: engineering controls on, all search-policy heuristics off.
2. **Static-policy baseline**: same as above, plus fixed thresholding with a single fixed value.
3. **Candidate full policy**: add one policy mechanism at a time, then combine only the mechanisms that show positive value.

### Why fixed 512 is the right first anchor

Across the historical archive, `wo_adaptive_512` is the strongest currently available alternative:

- it improves line coverage on all 5 targets with coverage data,
- it improves branch coverage on 4 of 5,
- it reduces LLM calls on all 4 complete-data targets.

So the next study should treat **fixed-512** as the initial comparison point, not current `full_opt`.

## Proposed experiment matrix

## Stage A: recover credible single-factor effects

Run all experiments with engineering safeguards fixed and enabled.

### A1. Threshold policy

- Baseline: fixed 512
- Compare: fixed 100, fixed 200, fixed 300, adaptive
- Outputs:
  - final line coverage
  - final branch coverage
  - final IPSM edges / nodes
  - `paths_total`
  - `llm_total_calls`
  - prompt/completion tokens

Question answered: whether adaptive thresholding actually beats strong static thresholds.

### A2. Frontier decomposition

Start from the best threshold policy from A1.

- baseline: no frontier bonus, no error penalty
- + out-degree frontier bonus only
- + error/productivity penalty only
- + both together

Question answered: whether the current frontier bundle is helping because of graph novelty, because of error suppression, or neither.

### A3. Prompt-structure decomposition

Start from the best configuration from A2.

- baseline: original prompt path
- + `state_ctx` only
- + `actions[]` only
- + both together

Question answered: whether state context and action constraints contribute independently or only as a coupled prompt design.

### A4. Refinement policy

Start from the best configuration from A3.

- no Tier-2 refinement
- periodic Tier-2 refinement on

Question answered: whether refinement adds value after thresholding/frontier/prompt design are fixed.

## Stage B: interaction checks only where justified

Do **not** run a full factorial across every switch.

Instead, only test pairwise interactions that are plausible and supported by Stage A:

- best threshold policy × best frontier policy
- best threshold policy × best prompt policy
- best prompt policy × refinement

This keeps the study interpretable and avoids a combinatorial table full of noisy negative results.

## Target selection rules

### Strong-claim set

Use only targets with complete, balanced run counts for every compared condition:

- exim
- live555
- mosquitto
- pure-ftpd

### Weak-evidence / appendix only

- kamailio: include only after rerunning missing variants to 5 seeds each
- forked-daapd: exclude entirely until the missing ablation archives are regenerated

## Reporting rules

### Per-target first, aggregate second

Do not lead with a single averaged table.

For each factor, report:

- per-target median across seeds
- win/loss count against baseline
- aggregate median delta only as a supporting summary

### Separate effect from cost

Each ablation row should report both benefit and cost:

- effectiveness: `l_abs`, `b_abs`, `IPSM edges`, `paths_total`
- cost: `llm_total_calls`, prompt tokens, completion tokens
- stability: crash/hang count, forced kills if available

### Predefine interpretation rules

Use language like this:

- **Supported**: improves coverage on most targets without systematic cost inflation.
- **Mixed**: improves some targets but hurts others or causes large cost growth.
- **Not supported**: does not outperform the baseline on the majority of targets.

This prevents over-claiming from small, target-specific gains.

## What the paper can safely claim after redesign

If the redesigned experiments reproduce the historical pattern, the likely safe claims are:

- LoopFuzz's practical gains come primarily from a robust operational pipeline plus a subset of policy heuristics, not from every currently exposed control.
- Fixed thresholding may outperform the current adaptive strategy.
- Frontier and prompt-structure mechanisms are target-dependent and should be presented as conditional heuristics, not universally positive modules.
- Refinement is beneficial only if it clears a direct comparison against the stronger fixed-threshold baseline.

## Immediate next steps

1. Regenerate missing `forked-daapd` and incomplete `kamailio` ablation archives.
2. Add orthogonal switches for frontier bonus / error penalty / state context / actions.
3. Rerun Stage A on the 4 complete targets first.
4. Only if a factor wins in Stage A, keep it in the candidate full configuration.
5. Rewrite the paper so the ablation section tests narrower hypotheses instead of defending the current bundled design.
