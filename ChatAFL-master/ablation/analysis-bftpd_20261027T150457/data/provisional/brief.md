# Provisional / salvage / lineage audit, bftpd 20261027T150457

Inputs: exactly nine complete files matching `results-bftpd_ablation_{wrapdirect8,wrapgate8,salvage8}_20261027T150457/out-bftpd-loopfuzz_[123].tar.gz`. All `.incomplete.*` copies excluded. Every input archive has a run-config start and end. No input files changed. Rerun: `python3 audit.py --root /path/to/ChatAFL-master --output /path/to/derived`.

Archive facts: 0 malformed JSON records, 0 duplicate candidate keys (campaign_id,candidate_id), 0 duplicate admission-trial keys, 0 duplicate invocation start/end IDs, 0 unmatched invocation start/end pairs; all nine campaign IDs differ. For maximal safety use (archive,campaign_id,candidate_id), not candidate_id alone. Configuration records fuzzer commit c73afe54a and hash b58ab7e66fce31b17fbb5bb575c260cb9604e8c40b0218b3c49bf00297af60eb. All nine record calibration=false; cal_episodes stats are not evidence that adaptive Calibration is enabled.

## Per run

`D/P/R` are actual trial dispositions durable / provisional / reject. `Desc target` are invocations labelled mutation or calibration with candidate_id>0 (candidate trial and shadow excluded). `LLM gain` counts lineage new-edge SAVE events; code-gain counts all native hnb==2 SAVE events, not unique source branches. Shadow columns are candidate validations / positive candidates / positive shadow invocations; shadow positives are not retained coverage.

| Arm | Run | Trials | D/P/R | Prov admit/convert/expire/censor | Desc target | LLM gain | Native code-gain events | Shadow candidate/positive/positive invocation |
|---|---:|---:|---|---|---:|---:|---:|---|
| wrapdirect8 | 1 | 52 | 52/0/0 | 0/0/0/0 | 307 | 0 | 51 | 0/0/0 |
| wrapdirect8 | 2 | 42 | 42/0/0 | 0/0/0/0 | 8 | 1 | 52 | 0/0/0 |
| wrapdirect8 | 3 | 47 | 47/0/0 | 0/0/0/0 | 379 | 0 | 46 | 0/0/0 |
| wrapgate8 | 1 | 50 | 0/2/48 | 2/0/2/0 | 0 | 0 | 48 | 7/1/10 |
| wrapgate8 | 2 | 53 | 0/1/52 | 1/0/1/0 | 0 | 0 | 45 | 11/1/1 |
| wrapgate8 | 3 | 48 | 0/1/47 | 1/0/1/0 | 0 | 0 | 47 | 5/0/0 |
| salvage8 | 1 | 43 | 0/3/40 | 3/0/3/0 | 0 | 0 | 55 | 4/0/0 |
| salvage8 | 2 | 54 | 0/1/53 | 1/0/1/0 | 0 | 0 | 50 | 6/1/15 |
| salvage8 | 3 | 55 | 0/1/54 | 1/0/1/0 | 0 | 0 | 50 | 11/1/1 |

## Decisive lifecycle evidence

All nine provisional entries terminate with reason `no-executable-M2`, descendant_execs=0, descendant_code_gain=0, budget_left=64. None converts, none is censored, none exhausts its validation budget, none expires by TTL. Entries are therefore never serviced by actual provisional descendant validation. Zero conversions must not be presented as a measured 0/9 productivity rate for 64-call validation.

- wrapgate run1 candidates13,42 (queue390,560), run2 candidate17 (queue395), run3 candidate24 (queue473): all admitted for state novelty, no actual validation.
- salvage run1 candidates9,10,41 (queue356,368,560), run2 candidate3 (queue295): four salvage admissions, no actual validation.
- salvage run3 candidate53 (queue570): ordinary state-novelty provisional admission, no actual validation.
- Salvage attempts total151, successful queue admissions4. `salvage_succeeded` means successful queueing only and supplies no code-value evidence.

Local source explanation only, pending historical binary/source match: `entry_can_fuzz_full_session()` requires q->regions and region_count and every region to have nonzero state_count and a non-NULL state_sequence. `provisional_select_service()` expires an entry as no-executable-M2 when that guard fails. The archive proves zero service; the events do not identify exactly which region annotation was missing or why. Do not overstate the exact root cause without matching the archived binary.

## Candidate vs descendant code value

The sole tracked LLM-lineage native new-edge save is wrapdirect run2 candidate5, queue355, invocation6589, execution_kind=candidate. It joins the same candidate's original admission trial6589 (`native_promoted=true`, g_code_pass=true, u_pass=false). It is immediate candidate value, not a descendant gain and not provisional validation. All 694 direct post-admission invocations yield zero recorded descendant new-edge saves.

Direct post-admission calls: mutations630 + calibration64 =694, target-invocation elapsed206592ms; trial calls141 add28159ms. wrapgate spends368 shadow calls78906ms +151 trials31339ms; salvage spends336 shadow calls67028ms +152 trials30155ms. These durations exclude other work outside invocation start/end and are not CPU time or total wall-clock resource savings. Candidate streams differ across arms.

The no-tracked-candidate ancestry mutation calls total44531 (direct),47701 (gate),49482 (salvage); corresponding native code-gain SAVE totals across all ancestry149,140,155. Because only direct has one LLM lineage save, native gains without tracked candidate ancestry are148,140,155. `candidate_id=0` does not imply an LLM-free campaign: it can include initially enriched seeds. No paired counterfactual establishes that one arm's extra ordinary mutations were caused specifically by the saved direct descendant calls.

## Shadow potential and limit

Positive rejected candidates: wrapgate run1 candidate7 (g_code true) 10/16; wrapgate run2 candidate1 (g_state true, g_code false)1/16; salvage run2 candidate1 (g_code true)15/16; salvage run3 candidate3 (g_state true,g_code false)1/16.

Aggregate shadow-positive candidates: gate2/23, salvage2/21. The denominator is a selected subset of rejected candidates with G_code or G_state evidence; not all rejected candidates and not a general gate false-negative rate. Local source increments `shadow_new_edges` once for each shadow invocation with last_trial_hnb==2 and does not update virgin_bits, so repeated discoveries of the same unseen edge may count repeatedly. Hence11 and16 are positive invocation counts, not distinct new edges. Shadow probes do not insert a queue entry or retain coverage; they show missed potential and cannot substitute for actual provisional conversion or superiority to ordinary mutation under equal budgets.

## Answers supported by these mechanism logs

Q1: limited operational support for avoiding continued spending on unproductive tracked candidate descendants (direct694 calls, zero descendant gains); not sufficient evidence of net system resource benefit, and the unserviced provisional route confounds interpretation. Shadow-positive rejected candidates show a cost of hard rejection.

Q2: not tested successfully: all provisional validation entries are terminated before executing validation. No evidence of discovered code value due to provisional validation, and no equal-budget ordinary mutation control. This is not evidence that such value is absent.

Q3: cannot answer from these arms because calibration=false everywhere and no EWMA/run-rate online scheduler comparator exists in this batch.
