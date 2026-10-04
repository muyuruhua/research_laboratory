# StateAFL baseline freeze (ProtoPair benchmark)

Frozen snapshot of the StateAFL baseline arm. Cite this file (and the commit
that contains it) as the exact baseline configuration in the paper.

## Provenance

- Upstream: https://github.com/stateafl/stateafl @ `d923e22` ("Update link to arXiv")
- Local tree: `ChatAFL-master/stateafl`, HEAD `3ecae22` (upstream + the port
  patch below). Subject-level copies under
  `benchmark/subjects/<proto>/<target>/stateafl/` are byte-identical for the
  two patched files.
- Patch series vs upstream: `stateafl-fixes.patch` (single commit, all
  changes marked `[stateafl-fix 2026-10-02]`; ASLR-check demotion to warning
  is the only pre-existing local change). Category: integration/stability
  bug fixes only — no change on code paths where upstream did not already
  crash or abort. See the patch message for the per-fix rationale.

## Per-target configuration (dispatch: `stateafl_target_config`)

| Target    | Options                                                | Corpus           | State inference |
|-----------|--------------------------------------------------------|------------------|-----------------|
| proftpd   | `-m none -P FTP -D 10000 -q 3 -s 3 -E -K -t 5000+`     | `in-ftp-replay`  | native          |
| live555   | `-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t 5000+` | `in-rtsp-replay` | native          |
| kamailio  | `-m none -P SIP -l 5061 -D 50000 -q 3 -s 3 -E -K -t 5000+` | `in-sip-replay` | native        |
| forked-daapd | `-P HTTP -D 200000 -m none -K -t 20000+`            | `in-daap-single` | disabled (`STATEAFL_DISABLE_TRACER=1`, run.sh) |

### Disclosed deviations (forked-daapd only)

1. Tracer disabled + no `-E/-q/-s`: StateAFL's state signal requires
   RECV->SEND transitions observed in pass-instrumented code; forked-daapd
   does all socket I/O inside libevent, which the pass does not instrument
   (verified 2026-10-04: libevent was rebuilt with StateAFL's afl-clang-fast
   and the objects carry the hooks, but `evbuffer_write_iovec` sends via
   `writev(2)` (buffer.c:2458), which afl-llvm-pass.so.cc does not
   instrument — the send side stays invisible, zero dumps/states either
   way). Enabling the hooks additionally causes intermittent SIGABRT/SIGSEGV
   on this multi-threaded target (upstream ships the hook mutex disabled).
   Restoring native inference would require extending the LLVM pass
   (writev) and making the hook layer thread-safe — re-engineering, not a
   bug fix, and therefore out of scope for a baseline.
2. `-t 20000+` (4x): per-exec startup (sqlite + avahi) exceeds 5 s under
   multi-container load; at 5 s every seed times out at dry run.
3. Corpus `in-daap-single` (each session flattened to one length-prefixed
   message): the native multi-message replay corpus produces wildly varying
   region counts under havoc, which trips an AFLNet-lineage M2/M3 list
   use-after-free and aborts the fuzzer within minutes.
4. Restart-on-crash loop in `run.sh` (`-i-` resume + orphan cleanup): the
   M2/M3 defect above still fires occasionally; the loop keeps the arm at
   duty cycle instead of ending the trial. **Record restart counts per
   trial** (e.g. a `stateafl_restarts` JSONL field); `ipsm_edges` for this
   arm/target is *undefined*, never 0 (paper rule: no zero-filling).

## Image digests (sha256 prefix)

    proftpd-stateafl        2d102d466ec9
    live555-stateafl        f589243ffdc3
    kamailio-stateafl       1814ff99eafb
    forked-daapd-stateafl   ba683b8ff6b9
    o-exim-01-stateafl:vuln  694ef4f3e79b
    o-kam-01-stateafl:vuln   242361dbd2dd
    o-mosq-01-stateafl:vuln  4ff7eb605ea7
    o-pftp-01-stateafl:vuln  baf7c175898c
    o-pure-01-stateafl:vuln  db482aaff30a

Rebuild: `cd <subject dir> && docker build -f Dockerfile-stateafl -t <target>-stateafl --build-arg MAKE_OPT=-j6 .`
CVE oracles: `cve-benchmark/bin/build_stateafl_vuln.sh <ORACLE_ID>` (stages
`ChatAFL-master/stateafl` at build time — always rebuild after patching).

## Validation (2026-10-03/04)

- kamailio: 3x90 s standalone runs, no crashes, 2832 queue cycles; smoke
  campaign collects a complete archive; IPSM built (states + transitions).
- End-to-end smoke (1 container x 3 min per target): all four targets
  `[recover] complete`; queue growth 28 / 310 / 48 / 12 entries.
- Pilot watch-item: O-MOSQ-01 (mosquitto) is multi-threaded — check the
  stateafl arm there for the forked-daapd-style flakiness during the pilot
  phase; the kill switch and restart loop are available per-target.

## Known unrelated issues (affect other arms equally, not fixed here)

- kamailio gcovr stops at missing `src/atomic_x86.h` (cov_html degenerates
  to index.html) — also present in the loopfuzz arm.
- `aflnet-replay` segfaults when cov_script's glob matches nothing
  (consequence of an aborted campaign, not an independent defect).
