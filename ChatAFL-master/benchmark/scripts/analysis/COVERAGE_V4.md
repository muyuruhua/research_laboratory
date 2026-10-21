# Source Coverage V4

`coverage_v4.py` replaces summary-text extraction for LightFTP, Lighttpd1,
Forked-daapd, BFTPD and Kamailio. The five subject `cov_script.sh` entry points
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
output preservation and all five shell wrappers. Real local GCC/gcov/gcovr tests
compile a harmless branch program, exercise two disjoint gcda runs and repeat one
path, then exercise complete output generation and an independent corruption
check. They launch no protocol target, socket, container, API call or long run.

Current verified native tools: GCC/gcov 9.4.0 and gcovr 7.2. gcovr 4.2 JSON is
covered by fixtures; its actual container integration has not been run here.
Other target replay commands, reset validation, source instrumentation and
environment identities must pass the parent experiment runner's checks before
these outputs are accepted for scientific comparisons.
