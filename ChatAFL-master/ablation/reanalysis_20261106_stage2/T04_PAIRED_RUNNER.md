# T04 Q2 paired-run harness

`t04_paired_runner.py` validates the T04 manifest, checks checkpoint bytes, launches an adapter for each eligible root × path, preserves unserved/ineligible rows, and validates invocation/censor/branch receipts. Paths are `pv`, `same_root_ordinary`, and `ordinary_corpus`. The runner fixes the per-path charged budget at 64 and carries one root ID, block ID, seed, checkpoint digest, operator-manifest digest, and M2 window through all three paths.

## Important implementation boundary

The current LoopFuzz binary does not expose a verified mechanism to snapshot and restore its queue, RNG, counters, target protocol state, and coverage state as one checkpoint. This harness therefore does not itself claim to run the experiment. A native adapter must restore all five components and return a matching receipt. Until that adapter exists and is validated against real restored state, T04 remains **not experimentally executable**; the test adapter is only a contract fixture.

## Campaign manifest

Minimal shape:

```json
{
  "schema_version": 1,
  "per_path_budget": 64,
  "charged_execution_kinds": ["mutation", "calibration", "hang-retry"],
  "operator_manifest_sha256": "<64 lowercase hex characters>",
  "m2_window": 4,
  "roots": [{
    "root_id": "root-001",
    "state": "eligible",
    "eligible": true,
    "block_id": "block-01",
    "pair_seed": 20261107,
    "checkpoint_stage": "post_trial_pre_validation",
    "checkpoint_path": "/absolute/path/to/immutable-checkpoint",
    "checkpoint_sha256": "<sha256 of file or deterministic tree digest>",
    "checkpoint_complete": true,
    "checkpoint_components": ["queue", "fuzzer_rng", "counters", "target_state", "coverage_baseline"],
    "baseline_source_branch_ids": ["source-branch-id-1"]
  }]
}
```

Roots with `state: "unserved"` are retained as censored in all three path rows and require `eligible: true` plus `unserved_reason`; roots with `state: "ineligible"` are retained as not eligible and require `eligible: false` plus `ineligible_reason`. They are not silently dropped from the output denominator. For eligible roots, checkpoint content is hashed before execution; the declared component list is not proof that those components are actually restorable, so the adapter must acknowledge restored components and independent checkpoint-digest comparison is still needed.

## Adapter protocol

The runner executes:

```text
<adapter command> --request REQUEST.json --result RECEIPT.json
```

Each request includes the common root/checkpoint identity, `pair_seed`, the fixed operator digest, M2 window, allowed charged execution kinds, and `max_charged_invocations=64`. A result receipt must include the same identities, `restored_checkpoint_sha256`, all five `restored_components`, status (`completed`, `censored`, or `technical_failure`), every actual target invocation with its `execution_kind` and `charged` flag, and unique `source_branch_events` with first-seen charged-call index. The runner derives beyond-trial branches as source branch identities absent from the post-trial checkpoint baseline; baseline branch IDs are not counted as gains.

`completed` requires exactly 64 charged invocations. A censored root/path is preserved with its observed charged count and reason; a valid censor does not count as a completed pair. Over-budget receipts, wrong root/seed/checkpoint/operator identity, malformed component acknowledgements, wrong charge flags, duplicate calls/branches, or invalid first-seen indices fail validation. A nonzero adapter exit or malformed receipt is preserved as a failed row and must be treated as a technical failure, not as zero gain.

## Invocation

```bash
python3 t04_paired_runner.py \
  --campaign campaign.json \
  --output t04-output \
  --adapter '/path/to/native_t04_adapter' \
  --workers 1
```

Use `--workers 1` for initial adapter validation. Increase only after the adapter guarantees isolated target/container state per path. The result rows are in `t04-output/t04_results.json`, with the raw request and adapter receipt retained separately.

## Self-test

```bash
cd ablation/reanalysis_20261106_stage2
python3 -m unittest -v test_t04_paired_runner.py
```

These tests validate harness invariants and use a synthetic adapter; they do not satisfy the native restore prerequisite, the 20-paired-root dose line, or the source-branch evidence audit.
