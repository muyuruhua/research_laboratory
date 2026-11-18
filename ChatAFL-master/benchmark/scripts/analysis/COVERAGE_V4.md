# Source Coverage V4

`coverage_v4.py` replaces summary-text extraction for LightFTP, Lighttpd1,
Forked-daapd, BFTPD and Kamailio, Exim, ProFTPD, Pure-FTPd and Live555. The
nine subject `cov_script.sh` entry points
keep the existing five positional arguments. They require the shared module and
complete discovery coordinates by default. Other subject scripts are unchanged.

## Installation

Install or mount this one module inside each new experiment container and set:

```bash
export COVERAGE_V4_MODULE=/opt/loopfuzz-coverage/coverage_v4.py
export COVERAGE_V4_RESET_COMMAND_JSON='["/opt/experiment/reset-and-validate"]'
```

The subject wrapper must also replace the image's old `${WORKDIR}/cov_script`.
An existing image does not gain the new code merely because the host repository
changed. `COVERAGE_V4_MODULE` defaults to `${WORKDIR}/coverage_v4/coverage_v4.py`;
the wrapper also resolves the in-repository module for local development. This
change does not edit Dockerfiles or run scripts. Failed coverage collection must
be checked by the experiment runner; the historic run scripts do not all propagate
the coverage command's failure status.

The reset command is a JSON argv array, run once before each input with a 30s
limit. It receives `COVERAGE_V4_INPUT` and must verify the target-specific files,
database and service state, not merely return success. Its stdout/stderr and exit
status are recorded. This module authenticates command completion, not the
semantic correctness of a supplied reset script. A failing reset stops replay.
`--allow-unverified-reset` is diagnostic only and is never added by the wrappers.
The root experiment runner owns validated reset scripts and isolated containers.

Validated per-target reset scripts are delivered in `reset_commands/` (see
`reset_commands/README.md` for the state cleared per target and the in-container
validation evidence). The execution layer injects them as the default
`COVERAGE_V4_RESET_COMMAND_JSON` for lightftp, bftpd, forked-daapd, lighttpd1
and kamailio; operator-supplied commands always take precedence.

## Chroot targets and world-writable gcda mirrors (2026-10-31 fix)

bftpd (`DO_CHROOT=yes`) logs in, chroots into `/home/ubuntu/ftpshare`, drops to
the FTP user's uid, and the subject's `gcov.patch` unsets `GCOV_PREFIX` inside
the chroot — so the demoted session child writes its `.gcda` at the
compiled-in object paths **as resolved inside the jail**, i.e. exactly the
mirror tree this module stages under the chroot prefix. The collector usually
runs as root while the child runs as the FTP user: a root-owned 0755 mirror
silently loses **every logged-in session's** coverage (93–95% of checkpoints
in the 20261027/20261031 batches, perfectly correlated with successful login).
`run_one_replay` therefore `chmod 0777`s every staged mirror directory before
the replay; the reset contract wipes and re-stages the jail per input, so this
is safe in the measurement containers. Verification:
`smoke_tests/bftpd_login_gcda_smoke.sh` (fails on the pre-fix module, passes
after). Missing session data is an incomplete measurement, not a zero-coverage
observation. The SIGPIPE issue described below needs the coverage-build fix as
well as writable mirror directories.

## BFTPD peer-close SIGPIPE and strict completeness (2026-11-01)

The coverage subject substitutes fd 2 for a data connection. A LIST or a peer
closing its control socket can produce SIGPIPE before libgcov writes gcda. This
is a measurement failure; a successful replay client does not establish that the
server flushed coverage. In the audited October batch, empty imports coincided
with server exit -13, so the previous branch union was a lower bound.

`install_bftpd_coverage_exit.py` patches and rebuilds only `bftpd-gcov`. The
coverage-only policy `COVERAGE_REPLAY_SIGPIPE_NORMAL_EXIT_V2` handles SIGPIPE by
writing an optional trace through a descriptor opened before chroot, ignoring
subsequent SIGPIPE, and setting a `sig_atomic_t` flag. The command loop then exits
normally and libgcov dumps through atexit. Neither `exit` nor `__gcov_dump` runs
inside this handler. The fuzz target and crash signal handlers are unchanged.
The policy is armed only when coverage replay sets `COVERAGE_V4_EXIT_TRACE`.

The BFTPD Dockerfile applies `coverage-exit.patch` after `gcov.patch`; the dev
executor also installs this policy into existing images before experiments.
Strict replay checks the marker in source and binary. The source hashes, gcno
hashes, binary SHA and exit policy enter the pinned scope identity. These outputs
must not be pooled with older scopes or used to backfill historical results.

Every checkpoint records `coverage_complete`, `incomplete_reasons` and
`sigpipe_normal_exit_observed`. Terminal completeness also requires no missing
replayable inputs and verified reset-command completion. Missing gcda, signaled
server exits or replay anomalies preserve a labelled partial union and return
failure after writing terminal evidence. `--allow-incomplete` is diagnostic only:
it never changes the incomplete label. Earlier pipeline failures write
`incomplete.json` where an artifact directory has already been created.

Run `smoke_tests/bftpd_login_gcda_smoke.sh` for normal QUIT, invalid login, LIST
and early peer-close fixtures. It keeps its evidence directory, a matching source
copy, per-input snapshots, policy hashes and an independent artifact audit. This
small integration test is a measurement check, not evidence of fuzzing benefit.

## Inputs and Coordinates

`queue-checkpoints.jsonl` in the fuzzer output directory must provide exactly one
record per replay corpus basename, and exactly one basename per queue ID. When a
provisional subtree expires, the fuzzer unlinks its files and appends a
`"kind":"removal"` checkpoint for every removed basename; the loader applies
removals in order and a removal without a prior discovery is a corrupt ledger.
The initial corpus scan does not emit discovery records for pre-pivot input
names — `pivot_inputs` logs the definitive `initial-queue-name` checkpoint under
the final queue basename:

```json
{"schema_version":1,"campaign_id":"immutable-campaign-id","filename":"id:000001,src:000000","queue_id":1,"discovery_time_ms":1790000000000,"monotonic_ms":123450,"discovery_execution_id":100}
```

`discovery_execution_id` is the fuzzer's `total_execs` counter, not a count of
network requests or independently audited physical invocations. Seeds can have
execution ID zero. Mixed campaign identities, duplicate names/IDs, partial joins
and decreasing execution/monotonic coordinates stop collection. Corpus order is
explicit discovery order, never glob order or silently clamped file mtimes. Input
SHA256 and original mtimes are preserved in `replay-plan.json`.

For explicitly labelled historical diagnostics only,
`COVERAGE_V4_REQUIRE_COORDINATES=0` permits a wholly absent ledger. That mode uses
original mtime order, leaves execution coordinates empty, and marks them invalid
for a fixed-execution analysis. A partially populated ledger is always rejected.
No missing coordinate is interpolated from episode work or assigned from `idx`.

## Scope and Accumulation

The same root and object search path are used for baseline, every checkpoint and
the endpoint. Scope includes every non-excluded source line/branch returned by
gcovr beneath that root. The source-relative file list, source hashes, full branch
and line universe, gcno hashes, JSON format and tool versions are pinned before
replay. Any source content, branch universe or instrumented-object change fails.

| Target | Replay Working Directory | Source Root | Object Search |
| --- | --- | --- | --- |
| LightFTP | `LightFTP-gcov/Source/Release` | `Source` | `Source/Release` |
| Lighttpd1 | `lighttpd1-gcov` | `lighttpd1-gcov/src` | `lighttpd1-gcov` |
| Forked-daapd | `${WORKDIR}` | `forked-daapd-gcov` | same root |
| BFTPD | `bftpd-gcov` | `bftpd-gcov` | same root |
| Kamailio | `${WORKDIR}` | `kamailio-gcov` | same root |

Kamailio's declared full-tree scope includes instrumented modules. A core-only
scope cannot be mixed with this denominator. It requires a separately declared,
tested policy and new scope identity. The TCP replay profile is rejected rather
than silently replayed through the UDP configuration.

Branch identity is `(relative source file, line_number, branchno)`. JSON from
gcovr 4.2 lacks explicit branch numbers and uses the stable branch-array ordinal
within a pinned gcno/tool scope. Counts are not branch identities. Per-replay
branch sets are unioned; `max(b_abs)` or sum of per-run counts cannot substitute.
Every input is collected even when `step` suppresses intermediate CSV rows.
BFTPD's chroot gcda are imported one input at a time and unioned at the branch-ID
level, so overwriting gcda cannot erase earlier observed IDs. Missing chroot data
fails collection. The supplied BFTPD reset validator must provision writable
chroot paths and the intended `AUTO_CHDIR` configuration.

gcovr's structured deletion API clears preexisting gcda, then a separate baseline
must verify zero covered lines/branches. No original archive is opened or changed.
Existing coverage outputs or artifact directories are never overwritten.

## Optional sampled checkpoints for accumulated gcda (schema v5)

By default the command remains v4: it runs gcovr and saves a full JSON snapshot
after every replayed input, while `--step` only controls CSV rows. An explicit
`--sampled-checkpoints` option enables the separate
`loopfuzz-coverage-v5-sampled-checkpoints` schema and `.v5` artifact directory.
It is accepted only for targets whose counters accumulate in the fixed gcda
tree: LightFTP, Lighttpd1, Forked-daapd, Kamailio, Exim, ProFTPD and Live555.
BFTPD and Pure-FTPd keep per-input snapshots because their collection paths
import or reset per-session counters.

Sampled mode still verifies every input hash before replay, executes the
target-specific reset and replay, verifies gcno identity, and writes a
`replay-ledger.jsonl` record for every input with reset/replay results. It runs
gcovr and saves a compressed snapshot at each `--step` boundary, at the end of
the initial-seed prefix when present, and at the final input. The last checkpoint
is always present. `checkpoints.jsonl` and `cov_over_time.csv` contain only
those sampled points; each checkpoint links back to its replay input index. The
auditor checks policy-derived indices, all per-input records, each snapshot
hash, fixed branch identities, cumulative branch/line unions, CSV rows, and the
terminal endpoint. This mode relies on the listed target's gcda actually
accumulating across its replay processes; it must not be used if a reset command
or target startup clears gcda.

The existing subject wrappers and `run_ablation.sh` defaults stay on v4. To
opt in manually in a prepared target environment, invoke the module with the
same five positional values the wrapper normally passes, plus the explicit
flag:

```bash
python3 "$COVERAGE_V4_MODULE" replay \
  --target exim --folder "$CORPUS" --port 25 --step 16 \
  --output "$OUTPUT/cov_over_time.csv" --mode 1 \
  --require-coordinates --sampled-checkpoints
```

## Smoke-only replay cap

The 15-minute integrity smoke can bound replay work without changing the
formal fixed-dose path. Set both `COVERAGE_V4_SMOKE=1` and
`COVERAGE_V4_MAX_REPLAY_INPUTS=N`; the subject wrapper passes
`--smoke --max-replay-inputs N`. A capped run records `replay_truncated=true`,
the full `planned_n_replayed` count, and `acceptance=incomplete` in
`terminal.json`. Its branch union is a diagnostic lower bound and cannot pass
the fixed-dose coverage gate. A cap without the smoke marker is rejected, and
formal runs leave the variable unset so all corpus inputs are replayed.

The sampled output is audited with the same command and automatically resolved
from the `.v5` suffix:

```bash
python3 "$COVERAGE_V4_MODULE" audit "$OUTPUT/cov_over_time.csv"
```

The Q1 smoke archive auditor also accepts `.v5` only for those seven targets and
independently reconstructs its sampled union. It requires exactly one of `.v4`
or `.v5` in an archive; it never interprets a legacy v4 artifact as sampled
coverage. Sampled results must not be pooled with v4 results without reporting
their distinct schema and checkpoint policy.

## Outputs and Independent Audit

The main CSV retains `Time,l_per,l_abs,b_per,b_abs,idx` and adds exact discovery
coordinates and hashes. `${output}.v4/` contains the immutable replay plan, scope,
zero baseline, compressed JSON snapshot for every replay, reset/replay command
logs, checkpoint JSONL and terminal branch/line-ID union.

There is no synthetic campaign-end row and no second gcovr command with a wider
root. The final endpoint is an actual checkpoint. Source file save time bounds
when that retained input was available; it does not establish when a branch was
first discovered in the original run. Replayed source coverage and online AFL
bitmap feedback remain different measurements. Stable source paths on a tiny
fixture do not establish stability of a protocol target; representative target
repeat replay remains an integration acceptance requirement.

Nonmonotonic raw coverage is recorded separately from the cumulative union.
BFTPD's per-input reset is expected. Other raw decreases preserve evidence and
return a failure status requiring investigation. `audit` independently reads
compressed snapshots, verifies their content hashes, reconstructs the branch-ID
union and checks every CSV row and terminal aggregate. A source checkout with
matching contents is required; `--source-root` relocates it without weakening
source hashes.

```bash
python3 coverage_v4.py audit /new-output/cov_over_time.csv \
  --source-root /matching-source-checkout
```

The audit does not reconstruct missing branch identities or legitimate execution
coordinates from old aggregate CSV files, and this patch does not retroactively
validate the historical paper's coverage values.

## Regression Verification

From the workspace root:

```bash
python3 diagnostics/vscode_20261021/run_analysis.py \
  research_laboratory/ChatAFL-master/benchmark/scripts/analysis/test_coverage_v4.py
```

Tests cover schema-0.1 and modern branch identities, disjoint branch union,
unexpected raw decreases, scope/source changes, duplicate identity/join rejection,
mtime versus discovery order, missing execution coordinates, aggregate mismatch,
output preservation and all nine shell wrappers. Real local GCC/gcov/gcovr tests
compile a harmless branch program, exercise two disjoint gcda runs and repeat one
path, then exercise complete output generation and an independent corruption
check. They launch no protocol target, socket, container, API call or long run.

Current verified native tools: GCC/gcov 9.4.0 and gcovr 7.2. gcovr 4.2 JSON is
covered by fixtures and by in-container integration on all nine subject images.
Other target replay commands, reset validation, source instrumentation and
environment identities must pass the parent experiment runner's checks before
these outputs are accepted for scientific comparisons.

## Subject Calibration and In-Container Verification (2026-10-21)

Every subject's collection profile is calibrated against its image with real
gcov data present, and every subject passed a full mock-LLM campaign smoke
(fuzz -> ledger -> per-input verified reset replay -> fixed discovery
coordinates -> terminal branch-ID union -> archive collection):

- gcov roots: exim build-dir; forked-daapd/kamailio `<target>-gcov/src`;
  live555 `testProgs` with the whole tree as a source search root; proftpd and
  pure-ftpd use per-gcno-directory collection with dir-prefixed names (their
  builds record bare source names).
- Zero-gcda baselines: images that never executed the instrumented binary
  have no gcda after the delete pass; the filesystem proof of zero gcda
  admits an empty baseline (`zero_baseline_mode`) whose branch/line universe
  is adopted from the first replayed checkpoint and binding thereafter.
- Graceful server shutdown signals are per target (fftp/lighttpd/live555/
  forked-daapd: SIGUSR1; exim/proftpd/pure-ftpd/kamailio: SIGTERM); proftpd
  and exim coverage comes from per-session children.
- Crash inputs: signal exits and missing flushes preserve available evidence,
  mark the endpoint incomplete, and fail strict scientific acceptance. They
  cannot silently count as zero new branch coverage.
- Ledger supersets: imported seeds without a structured replay form are
  disclosed via `unreplayable-ledger-entries.json` and
  `n_unreplayable_ledger_entries` instead of failing the join.
- Reset commands for all nine subjects and the fuzzer-side `-c` audit are
  documented with validation evidence in `reset_commands/README.md`.
