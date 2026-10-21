# Verified per-input reset commands (coverage_v4)

Per-target reset scripts fulfilling the `COVERAGE_V4_RESET_COMMAND_JSON`
contract (COVERAGE_V4.md): run once before every replay input, 30 s limit,
receiving `COVERAGE_V4_INPUT`; exit 0 only when the target-specific files,
database and service state are actually cleared. Any failure stops replay.

## Deployment

`profuzzbench_exec_common_dev.sh` injects the default
`COVERAGE_V4_RESET_COMMAND_JSON=["bash","/tmp/coverage-v4-src/reset_commands/<target>.sh"]`
for these five targets when the operator has not supplied one; the analysis
mount provides the scripts in-container. An operator-provided value always
wins; targets without a validated script keep failing fast.

## Per-target state cleared

| target | process killed | persistent state removed | configuration verified |
| --- | --- | --- | --- |
| lightftp | `fftp` | `~/ftpshare/*`, `~/fftplog` | ftpshare empty + writable |
| bftpd | `bftpd` | `/home/ubuntu/ftpshare/*` (chroot jail; pipeline re-stages gcov objects after reset) | `AUTO_CHDIR="/"`, `DO_CHROOT="yes"`, jail writable |
| forked-daapd | `forked-daapd` | `db/songs3.db`, `db/cache.db` (+wal/shm), `forked-daapd.log`; MP3 media dir untouched | db dir writable, conf present |
| lighttpd1 | `lighttpd` | none (docroot `/tmp`, no upload/log state in replay config) | `server.document-root = "/tmp"` |
| kamailio | `kamailio` | `kamailio-gcov/runtime_dir/` (sockets, pids) | cfg + gcov tree present |

Notes: the bftpd image ends its Dockerfile with `USER root`, so that script
accepts root or ubuntu and uses absolute paths. All other subjects run as
`ubuntu`. Scripts are safe to run from any cwd (absolute paths only).

## Runtime (fuzzer-side) vs replay resets — do not mix them

The fuzzer's `-c` cleanup script runs before the forkserver and before every
target invocation, and phase-2 requires exit 0. Two constraints apply there:

1. It must be idempotent on a fresh container (the historic lightftp
   `ftpclean` exits 1 when `~/fftplog` does not exist, which aborts the
   campaign at start).
2. It must NEVER kill processes by target name: the AFL forkserver is itself
   a copy of the target binary (e.g. `fftp`), so `pkill -x fftp` would kill
   the forkserver mid-campaign.

`*-runtime.sh` scripts are the fuzzer-side cleaners (file state only,
forkserver-safe, exit-clean on fresh state). The five `<target>.sh` scripts
above are coverage-replay resets: they may kill leftover server processes
because the replay pipeline starts a fresh server per input and no forkserver
exists in that context. `lightftp-runtime.sh` is wired into the subject
`run.sh` via the shared analysis mount; the other subjects' existing `-c`
scripts (bftpd `clean`, kamailio `run_pjsip`) are already exit-clean, and
forked-daapd/lighttpd1 run without `-c`.

## Validation evidence (2026-10-21, in-container)

For each target, on the local image, three tests were executed via
`docker run --rm -v <analysis>:/tmp/coverage-v4-src:ro`:

1. dirty state + planted leftover server process → reset must kill the
   process, remove the state, exit 0;
2. immediate clean re-run → exit 0 (idempotence);
3. negative control (undeletable file / drifted config / missing config)
   → reset must exit non-zero.

Results — all 5 targets × 3 tests PASS:

| target | image (sha256 id) | T1 kill+wipe | T2 idempotent | T3 negative |
| --- | --- | --- | --- | --- |
| lightftp | cf45182ed629 | PASS | PASS | PASS |
| bftpd | c74adae74d06 | PASS | PASS | PASS |
| forked-daapd | 2fc7b0f5106c | PASS | PASS | PASS |
| lighttpd1 | 1abcf102caa7 | PASS | PASS | PASS |
| kamailio | e98d280fe6c9 | PASS | PASS | PASS |
| exim | fc5d4df85fa8 | PASS | PASS | PASS |
| proftpd | 0672ceb58fb9 | PASS | PASS | PASS |
| pure-ftpd | 1fe402056dbd | PASS | PASS | PASS |
| live555 | 876d852975a9 | PASS | PASS | PASS |

The four 2026-10-21 additions (exim kills the pidfile daemon plus any
name-match leftover; proftpd re-provisions gcov-dir ownership/permissions
after clearing the jail; pure-ftpd wipes the /home/fuzzing chroot the
pipeline re-stages; live555 terminates leftover `testOnDemandRTS*` servers).
proftpd/pure-ftpd images end as USER root, so those scripts accept root or
ubuntu and use absolute paths.

These validate the reset commands themselves. The end-to-end replay
(with real corpora and gcov collection) is exercised by the small-scale
campaigns; any reset failure there stops the pipeline by design.

## Fuzzer-side `-c` cleanup audit across all nine subjects (2026-10-21)

Phase-2 requires the fuzzer `-c` cleanup to exit 0 on every invocation;
a nonzero cleanup aborts the campaign. Fresh-state behavior verified
in-container for every subject that passes `-c`:

| subject | `-c` script | fresh-state exit | action |
| --- | --- | --- | --- |
| lightftp | ftpclean (`rm ~/fftplog`) | 1 — BROKEN | replaced by `lightftp-runtime.sh` (campaign-smoked) |
| exim | clean (`pkill -F /var/lock/exim.pid`) | 1 — BROKEN (also on every stale pidfile) | replaced by `exim-runtime.sh` (4/4 in-container tests incl. forkserver-pid guard) |
| bftpd | clean (`rm -rf ftpshare/*`) | 0 | none needed |
| kamailio | run_pjsip | 0 | none needed |
| proftpd | clean (`find ... -delete \|\| true`) | 0 | none needed |
| pure-ftpd | clean (`rm -rf /home/fuzzing/*`) | 0 | none needed |
| forked-daapd, lighttpd1, live555 | (no `-c`) | n/a | no fuzzer-side reset by design |

`exim-runtime.sh` additionally honors `PHASE2_ALLOWED_FORKSERVER_PID`
(exported by the fuzzer before every reset) so the pidfile can never cause
the idle forkserver itself to be killed.
