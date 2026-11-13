# Reproducible mechanism metrics and minimum smoke matrix

Run one campaign at a time; outputs refuse overwrite:

```bash
python3 benchmark/scripts/analysis/loopfuzz_metrics.py /new/out-or-archive.tar.gz \
  --output-dir /new/analysis-run1 \
  --coverage-csv /new/cov.csv --coverage-source-root /matching/gcov/source \
  --resource-jsonl /new/resource-samples.jsonl
```

Coverage and resource arguments are optional. Without them the corresponding
measure is unavailable; no value is imputed from a proxy. Input/member SHA256s,
campaign/build/config identities and independently checked coverage scope are
recorded in metrics.json. No original archive is extracted or changed.

## The three questions

1. Candidate quality: use productivity-events.jsonl from the common
   `fuzz_one-full-session` 64-invocation kernel. Productivity@64 among completed
   roots is productive complete roots / all complete roots. Every invocation,
   including calibration/retry, consumes the same budget. Report starts,
   complete64, censored, unclosed, exposure and source class beside this rate.
   For all started roots report lower bound known productive / starts and upper
   bound (known productive + unresolved negative roots) / starts. These bounds
   expose censoring rather than treating it as failure. Ordinary roots are
   `ordinary_no_tracked_llm`, not proven LLM-free. Samples are unpaired; stratify
   by recorded starting virgin bitmap hash and never assert equal coverage
   starts from equal runtime alone. Provisional conversions are separately
   reported and do not substitute for this endpoint.
2. Code and state coverage: source code coverage is the independently audited
   branch-identity union from coverage-v4. Observed response-state coverage is
   the directed edge-identity union in ipsm.dot. Keep these separate; neither
   is inferred by summing episode novelty counts. Compare source branches only
   under identical pinned scope, source/gcno/tool/build and exit policy. An
   incomplete replay is a labelled lower bound and fails scientific acceptance.
3. Calibration: report config enabled, total selections, reason counts,
   weighted-eligible selections with positive weight and completed episode
   scores. Enabling the flag or updating posteriors does not establish active
   weighted selection. Changed-choice counts require explicit evidence;
   activation does not establish coverage benefit. Compare matched D/E runs.

## Costs

Fuzzer execs / fuzz clock is a fuzzer-counter throughput, not audited network
requests or every physical process launch. Provisional closure charged work
excludes work after conversion and exposure still open. Candidate64 exposure is
reported separately. HTTP latency sum, explicit interval union, measured fuzzer
blocked time and cgroup CPU are different quantities. The tool reports the first
three only if their distinct fields are recorded; it never calls summed HTTP
latency CPU time. Cgroup delta is (last usage_usec - first usage_usec)/1e6, over
the sampled interval and all container descendants; counter reset is an error.
No fixed-execution or CPU-budget benefit is inferred from a fixed-time campaign.

## Minimum smoke matrix for the current implementation

All arms use one target build, seed corpus, elapsed fuzzing time >3600s, isolated
containers, isolated mock gateway ports and the user-specified llm_mock_v5.py.
Capture target reset events, all ledgers, resource samples, queue discovery
coordinates, exit cause, build hashes and complete coverage replay. A smoke run
checks execution/observability, not a statistical effectiveness claim.

| Question | Minimum controls | Acceptance evidence |
|---|---|---|
| Gating and usable validation | direct, gate, U-off, salvage, salvage+probe-gate, random-shadow | configured flags match; actual admissions; full-session service; complete64 or explicit censor; ordinary comparison samples; branch replay complete |
| Calibration | gate fixed (D), calibrated Thompson (E), EWMA, past-run-rate; same gate/candidate policy | positive weighted selection after warmup; enabled estimator observed in log; posterior update; no endless no-M2 spin |
| Trigger | response-state plateau, code plateau, fixed interval | complete decision ledger including suppression; actual attempts and per-rule exposure; costs separated |
| LLM package | grammar-only, enrichment-only, plateau-only; no-LLM as applicable | request type and globally unique ID; disabled components make no requests; costs/candidates by class |
| Measurement | all above | reset validators pass; no unflushed replay; source scope hashes equal within comparisons; CPU samples cover stated interval; completion reason recorded |

The root runner resolves exact existing arm names and flags; these rows are
mechanism requirements, not a claim that every listed control has already run.
An untriggered arm, a zero-attempt component, or an estimator staying in warmup
is an inconclusive smoke for that mechanism and must be reported as such. Mock
campaigns establish implementation behavior only; real gateway effectiveness,
longer horizons, multiple random repetitions and multiple targets remain
separate experiments.
