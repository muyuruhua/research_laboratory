# T04 implementation handoff

Implemented the manifest-driven T04 contract harness in:

- `t04_paired_runner.py`
- `test_t04_paired_runner.py`
- `T04_PAIRED_RUNNER.md`

Validation run from this directory:

```text
python3 -m unittest -v test_t04_paired_runner.py
Ran 8 tests in 0.073s
OK
```

The harness validates a 64 charged-call budget per path for `pv`,
`same_root_ordinary`, and `ordinary_corpus`; immutable checkpoint tree digest;
root/checkpoint/block/seed/operator identity; invocation charge kinds; censor
retention; and beyond-trial source branch identity against the post-trial
baseline. It keeps unserved and ineligible roots in the output denominator.

It intentionally does not claim that T04 is experimentally complete: the
current LoopFuzz executable has no verified native adapter for restoring queue,
RNG, counters, target protocol state, and coverage as one checkpoint. A native
adapter remains a prerequisite; the fake adapter used by the tests is only a
contract fixture.

## 2026-11-07 audit update

The contract runner now re-hashes each eligible checkpoint immediately before
launching its adapter worker. If the tree changed after manifest validation,
the path is recorded as a technical failure rather than executing against a
different snapshot. Receipt validation also requires every target invocation to
carry the requested path and requires `charged` to be a JSON boolean, avoiding
cross-path receipts and numeric values that compare equal to `true` in Python.

`python3 -m unittest -v test_t04_paired_runner.py` passes all 9 tests. These
checks strengthen fail-closed accounting only; they do not provide the missing
native restore implementation. T04 remains experimentally blocked until an
adapter can restore and independently attest queue, fuzzer RNG, counters,
target protocol state, and coverage baseline from an immutable checkpoint.
