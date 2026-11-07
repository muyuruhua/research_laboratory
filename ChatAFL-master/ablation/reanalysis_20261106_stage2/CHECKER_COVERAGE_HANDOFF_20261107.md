# Checker/Coverage Handoff

This handoff records the read-only audit changes for Stage-2. No production
fuzzer source or archive was changed.

## Added

- `ledger_check_T02B_v2.py`: run-level output with one record per archive;
  duplicate/extra invocation IDs, start/end field mismatches, unknown execution
  kinds, attempt reuse, campaign-budget overruns, and Q1 flow arithmetic are
  checked. Missing provisional root identity is reported as `INCONCLUSIVE`,
  rather than passing a vacuous root-cap check.
- `coverage_audit_T02C.py`: verifies terminal replay completeness and reports
  branch identities. It does not label a zero-counter gcovr baseline as a seed
  branch set. New coverage-v4 terminals may instead provide the explicit
  `seed_covered_branch_ids` union from initial-queue replays; the audit also
  joins every `executed_input_witnesses` row to replay-plan/checkpoint hashes.
  Archives without either proof remain `INCONCLUSIVE`.
- `tests/test_ledger_check_T02B_v2.py`: nine fixture tests covering pairing,
  duplicate IDs, unknown kinds, budget overrun, missing root identity, Q1 flow
  arithmetic, and coverage baseline handling.
- `ledger_check_T07_v2.json` and `coverage_audit_T02C_T07.json`: run-level
  audit results for all 45 T07 archives.  The flow checker accepts the
  production `consumed` event (`destination=ordinary-mutation`) only when its
  `flow_id`, source candidate, receiver invocation, amount, and remaining
  quota match a previously saved reservation.  It also cross-links every
  receiver invocation to the corresponding `invocation_end` record and checks
  its mutation kind, flow ID, and source candidate.

## Verification

```bash
python3 -m unittest discover -s \
  ablation/reanalysis_20261106_stage2/tests -v
```

Result: 9 tests passed.

```bash
python3 ablation/reanalysis_20261106_stage2/ledger_check_T02B_v2.py \
  ablation/reanalysis_20261106_stage2/T07_233140_matrix/evidence/index.json \
  --output ablation/reanalysis_20261106_stage2/ledger_check_T07_v2.json
python3 ablation/reanalysis_20261106_stage2/coverage_audit_T02C.py \
  ablation/reanalysis_20261106_stage2/T07_233140_matrix/evidence/index.json \
  --output ablation/reanalysis_20261106_stage2/coverage_audit_T02C_T07.json
```

The rerun of the 45 archives is not a blanket PASS.  The ledger contains 39
PASS, 3 `INCONCLUSIVE` runs without provisional root identity, and 3 `FAIL`
`q1c8` runs whose historical reflow events have no reservation `flow_id`.
Those old events cannot establish candidate-to-receiver binding and are not
silently upgraded.  Coverage is `INCONCLUSIVE` for all 45 runs: terminal
replay is complete, but the archives have no explicit seed branch identity and
no ever-seen input witness proof.  New smoke archives must be generated after
the production Q1 flow fix before claiming ledger PASS.
