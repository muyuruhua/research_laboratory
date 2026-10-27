# bftpd 20261027T150457 execution resource / LLM audit

Read only the nine exact `out-bftpd-loopfuzz_[1-3].tar.gz` archives. Excluded `.incomplete.*` duplicate files. Script `analyze.py` and full sanitized machine results `workload.json`, `aggregate.json` are reproducible. No raw prompts, keys, candidate input bytes or response text are included.

## Per-run accounting

| Arm | Rep | ledger admitted calls | AFL counted executions | candidates | LLM ok/transport/api | observed tokens | candidate / tracked descendant mutation / tracked descendant calibration / shadow |
|---|---:|---:|---:|---:|---|---:|---|
| wrapdirect8 | 1 | 20896 | 20896 | 52 | 217/6/0 | 243828 | 52 / 291 / 16 / 0 |
| wrapdirect8 | 2 | 19922 | 19921 | 42 | 215/11/0 | 235171 | 42 / 0 / 8 / 0 |
| wrapdirect8 | 3 | 19860 | 19859 | 47 | 217/7/0 | 244137 | 47 / 339 / 40 / 0 |
| wrapgate8 | 1 | 22734 | 22733 | 50 | 218/4/0 | 228225 | 50 / 0 / 0 / 112 |
| wrapgate8 | 2 | 20386 | 20385 | 53 | 220/11/0 | 248486 | 53 / 0 / 0 / 176 |
| wrapgate8 | 3 | 19899 | 19898 | 48 | 217/6/0 | 234131 | 48 / 0 / 0 / 80 |
| salvage8 | 1 | 20569 | 20568 | 43 | 214/4/0 | 226063 | 43 / 0 / 0 / 64 |
| salvage8 | 2 | 22405 | 22404 | 54 | 221/9/1 | 248367 | 54 / 0 / 0 / 96 |
| salvage8 | 3 | 22580 | 22579 | 55 | 221/6/1 | 257777 | 55 / 0 / 0 / 176 |

## Interpretation

- **Q1 only weak/mechanistic support**: direct retained 141/141 candidates (139 forced, 2 native hnb>0), all 141 gate decisions would have rejected. Gate actual disposition 147 rejects + 4 provisional / 151 candidates; salvage 147 rejects + 5 provisional / 152. Direct consumed 630 descendant mutations plus 64 descendant calibration calls, total 206.592 target invocation seconds across 3 runs. The 630 mutations belonged to only two candidate roots: run 1 candidate 24 (291 calls) and run 3 candidate 22 (339 calls), both U=false, no trial code gain, and zero lineage gains during campaign. Gate/salvage have no descendant mutation or descendant calibration. Gate pays 368 shadow calls / 78.906 seconds, salvage 336 / 67.028 seconds. Candidate trial costs are 28.159 / 31.339 / 30.155 seconds respectively. This demonstrates resource routing changed beyond fewer inputs, but cannot establish identical-candidate avoided cost or net coverage improvement. The observed direct descendant tax is only 694/60678 = 1.144% of admitted calls (206.592/17100 = 1.208% aggregate campaign wall time), so do not overstate resource savings.

- Direct generated 1 lineage_gain, **run 2 candidate 5 on immediate trial**, with U=false and G_code=true. It received zero descendant mutation calls. This is an observed code-positive U rejection risk and is not delayed provisional value. No lineage_gain occurred in gate or salvage. No direct descendant positive code result observed in these runs.

- No tracked candidate ancestry (cid=0) mutation calls: direct 44531, gate 47701, salvage 49482. These are not guaranteed pure ordinary-mutation baselines because initial LLM seed enrichment has no candidate_id. Initial seeds hash is identical across all nine campaigns, but campaign RNG is not fixed. Higher cid=0 mutations does not alone prove resource reallocation caused extra discoveries.

- **Q2 not tested operationally**: all nine provisional roots (4 gate, 5 salvage) received zero budget service and expired `no-executable-M2`; 0 converts. Four salvage-specific admits (3 run1, 1 run2) came from 151 salvage attempts total. No-executable expiry is structural inability to execute validation, not empirical demonstration of zero biological/code potential. Shadow gains must remain separate from actual promoted/provisional lineage gains.

- **Q3 cannot be answered**: calibration=false in all run_config records. All 332 scheduler selections are warmup-eligible and all episode sampled_theta=-1. Posterior_updated=true in 323 completed episodes is passive update logging: afl-fuzz.c:5219 updates eligible episodes regardless calibration flag, whereas :5014 applies posterior to selection only under calibration_enabled. :5074 activates weighted FAVOR only after 5 complete state sweeps. Neither calibrated selector nor EWMA/run-rate arm was exercised.

## Measurement limits / invariants

- Total ledger 189251 invocation_start and 189251 matching invocation_end, unique invocation ids, no orphan tracked candidate ids. Two invocation_refused records (gate runs 1 and 3); do not count as execution. Eight runs have one final shutdown invocation with execution_id_before=after, so AFL counted executions sum is 189243. Direct run1 has no shutdown delta0. The wrapper logs executed=true even when run_target_impl returns early on stop_soon before total_execs++; interpret ledger as admitted invocation calls, and exclude 8 interrupted calls when reporting completed AFL work. This is not evidence that fuzzer_stats missed eight ordinary executions.

- run_config start/end spans ~5700000ms (=95 min) including initial setup/LLM grammar+enrichment. First target invocation arrives 7.57–9.51min after campaign start. fuzzer_stats start_time is assigned after grammar/enrichment (afl-fuzz.c:21050), yielding 85.42–87.37min start-to-last_update, and it is second-resolution. Do not use its start as if campaign initial LLM cost was free.

- LLM rows total 2026 = 1960 ok + 64 transport-error + 2 api-error; successful requested/served models all codex-auto-review. Per-arm observed prompt+completion tokens direct723136, gate710842, salvage732207; unsuccessful usage not reported in ledger could still cost provider resources. Count rows / sum per-row tokens, not seq or cumulative fields. Sequence collisions occur after fork boundaries: seq files get overwritten, final cum_calls undercounts rows, cum_tokens nonmonotonic. For example direct run1 rows223 vs unique seq198, and repeated seq198 at distinct timestamps. Sidecar `.req/.resp` is not one-to-one provenance.

- api-error rows are salvage runs2/3 and lack HTTP status in the ledger. Their archived seq responses now contain a later successful chat.completion, so cannot recover exact HTTP or classify as 401 from these archives. The 1960 successful calls exclude a campaign-wide invalid-key outage; do not claim the 2 errors prove 401 persists.

- LLM summed request latency cannot be subtracted from wall time because initial enrichment uses concurrent requests. Interval unions per-run provide elapsed LLM-active wall intervals, but not CPU time or guaranteed idle time. Initial startup latency sums can exceed startup wall duration by 3x. Target invocation durations likewise exclude external reset time and are wall duration, not CPU seconds.

- Same fuzzer sha256, target sha256, image digest, seeds sha256 in all nine configs. All reset records succeeded. None of these checks repair missing offline replay coverage; root coverage audit must govern whether coverage can be ranked.
