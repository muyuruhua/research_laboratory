#!/usr/bin/env python3
"""vuln_triage.py — post-batch vulnerability triage across fuzzer output dirs.

Scans every out-* run directory under a results-* batch for the four
artifact channels LoopFuzz can emit, grades each artifact, and merges any
crash_analysis.py output that already exists:

  teardown-crashes/       P1 (fatal signal + replay sidecar) / P3 (artifact)
  replayable-hangs/       P2 (needs replay confirmation)
  replayable-violations/  graded by oracle severity (MEDIUM+ → P2)
  crash_analysis.csv      merged verbatim as reference rows

Output: <results-dir>/vuln_triage_report.csv with one row per artifact
plus a summary row per run.  Exit code is always 0 (reporting tool).

Usage:
  python3 vuln_triage.py <results-dir> [--verbose]
"""

import argparse
import csv
import glob
import os
import re
import shutil
import sys
import tarfile

# Signals that indicate memory-safety faults rather than shutdown artifacts.
FATAL_SIGNALS = {11, 7, 8, 4, 6}
# Signals we treat as teardown/shutdown artifacts (not vulnerabilities).
ARTIFACT_SIGNALS = {13, 15}  # SIGPIPE, SIGTERM

FATAL_NAMES = {4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 11: "SIGSEGV"}
ARTIFACT_NAMES = {13: "SIGPIPE", 15: "SIGTERM"}

TEARDOWN_RE = re.compile(r"sig:(\d+)")
RACE_RE = re.compile(r"race:1")
# Oracle severity range is 0-5 (HEURISTIC..CRITICAL); the filename encodes
# whatever oracle_add_violation graded the finding with.
SEV_RE = re.compile(r"sev:([0-5])")


def has_memory_evidence(path):
    """True when the fuzzer snapshotted memory-error evidence at save time.

    A1 writes TWO sidecars when stderr_has_asan_error() fires: .asan.log
    (copied from /tmp/asan.*, ASAN builds only) and .stderr.log (the raw
    stderr capture).  For non-ASAN evidence — glibc "malloc(): ", "free(): ",
    stack-protector, asserts — /tmp/asan.* does not exist, so cp silently
    produces NO .asan.log and the only trace is .stderr.log.  Checking
    .asan.log alone (the pre-fix behavior) missed exactly those cases;
    either sidecar marks the candidate as memory-error-evidenced.  A
    zero-byte .asan.log can appear when cp matched nothing, so also
    require it to be non-empty; .stderr.log is never written empty by A1
    (the grep that gates it found a match in that very file)."""
    for suffix in (".asan.log", ".stderr.log"):
        side = path + suffix
        if os.path.isfile(side) and os.path.getsize(side) > 0:
            return True
    return False


def classify_teardown_file(fname, has_replay):
    """Grade one teardown-crashes entry → (priority, kind, signal, race_tagged)."""
    m = TEARDOWN_RE.search(fname)
    sig = int(m.group(1)) if m else -1
    race = bool(RACE_RE.search(fname))
    if sig in FATAL_SIGNALS:
        # Replay sidecar present → directly replayable candidate.
        pri = "P1" if has_replay else "P1-no-replay"
        return pri, "teardown-fatal", FATAL_NAMES.get(sig, "sig%d" % sig), race
    if sig in ARTIFACT_SIGNALS:
        return "P3", "teardown-artifact", ARTIFACT_NAMES.get(sig, "sig%d" % sig), race
    return "P3", "teardown-unknown", "sig%d" % sig if sig >= 0 else "nosig", race


def classify_violation_file(fname):
    """Grade one replayable-violations entry → (priority, severity)."""
    m = SEV_RE.search(fname)
    sev = int(m.group(1)) if m else -1
    # 2 = MEDIUM, 3 = STRONG in oracle_result_t severity encoding.
    if sev >= 3:
        return "P1", sev
    if sev == 2:
        return "P2", sev
    return "P3", sev


def triage_run(run_dir):
    """Collect artifact rows + counters for one out-* run directory."""
    rows = []
    c = {"p1": 0, "p2": 0, "p3": 0, "teardown_race": 0}

    td_dir = os.path.join(run_dir, "teardown-crashes")
    if os.path.isdir(td_dir):
        for f in sorted(os.listdir(td_dir)):
            path = os.path.join(td_dir, f)
            if not os.path.isfile(path):
                continue
            if f.endswith(".request.replay"):
                continue  # sidecar of the artifact, not an artifact itself
            if f.endswith(".asan.log") or f.endswith(".stderr.log"):
                continue  # diagnostic sidecars captured at save time
            has_replay = os.path.exists(path + ".request.replay")
            # A1 (2026-08-23): fuzzer now snapshots memory-error stderr at
            # save time; presence upgrades "fatal, needs replay" to "fatal
            # with memory-error evidence" (either sidecar counts — see
            # has_memory_evidence for the non-ASAN .stderr.log-only case).
            has_asan = has_memory_evidence(path)
            pri, kind, signame, race = classify_teardown_file(f, has_replay)
            if pri.startswith("P1") and has_asan:
                kind = "teardown-fatal+asan"
            if race:
                c["teardown_race"] += 1
            c["p" + (pri[-1].lower() if pri[-1] in "123" else "3")] += 1
            rows.append({
                "run": os.path.basename(run_dir),
                "priority": pri, "kind": kind, "signal": signame,
                "race_tagged": "1" if race else "",
                "file": os.path.relpath(path, run_dir),
                "detail": "asan_log=1" if has_asan else "",
            })

    # Older/emergency channel: crashes the fuzzer itself deemed replayable.
    # Same grading as teardown-crashes (replay sidecar is the seed itself).
    rc_dir = os.path.join(run_dir, "replayable-crashes")
    if os.path.isdir(rc_dir):
        for f in sorted(os.listdir(rc_dir)):
            path = os.path.join(rc_dir, f)
            if not os.path.isfile(path):
                continue
            if f == "README.txt":
                continue  # AFL boilerplate, not an artifact
            if f.endswith(".asan.log") or f.endswith(".stderr.log"):
                continue  # diagnostic sidecars captured at save time
            has_asan = has_memory_evidence(path)
            pri, kind, signame, race = classify_teardown_file(f, True)
            if pri.startswith("P1") and has_asan:
                kind = "replayable-fatal+asan"
            else:
                kind = "replayable-" + kind
            if race:
                c["teardown_race"] += 1
            c["p" + (pri[-1].lower() if pri[-1] in "123" else "3")] += 1
            rows.append({
                "run": os.path.basename(run_dir),
                "priority": pri, "kind": kind, "signal": signame,
                "race_tagged": "1" if race else "",
                "file": os.path.relpath(path, run_dir),
                "detail": "asan_log=1" if has_asan else "",
            })

    hang_dir = os.path.join(run_dir, "replayable-hangs")
    if os.path.isdir(hang_dir):
        for f in sorted(os.listdir(hang_dir)):
            path = os.path.join(hang_dir, f)
            if not os.path.isfile(path):
                continue
            if f.endswith(".asan.log") or f.endswith(".stderr.log"):
                continue  # diagnostic sidecars captured at save time
            c["p2"] += 1
            rows.append({
                "run": os.path.basename(run_dir),
                "priority": "P2", "kind": "hang", "signal": "",
                "race_tagged": "", "file": os.path.relpath(path, run_dir),
                "detail": "",
            })

    viol_dir = os.path.join(run_dir, "replayable-violations")
    if os.path.isdir(viol_dir):
        for f in sorted(os.listdir(viol_dir)):
            path = os.path.join(viol_dir, f)
            if not os.path.isfile(path):
                continue
            if f.endswith(".asan.log") or f.endswith(".stderr.log"):
                continue  # diagnostic sidecars captured at save time
            if f.endswith(".request.bin") or f.endswith(".response.bin") or \
               f.endswith(".request.replay"):
                continue  # payload sidecars of the id:* marker entry
            pri, sev = classify_violation_file(f)
            c["p" + (pri[-1].lower() if pri[-1] in "123" else "3")] += 1
            rows.append({
                "run": os.path.basename(run_dir),
                "priority": pri, "kind": "violation", "signal": "",
                "race_tagged": "", "file": os.path.relpath(path, run_dir),
                "detail": "oracle_sev=%d" % sev,
            })

    return rows, c


def merge_crash_analysis(run_dir, rows, counters):
    """Append crash_analysis.py CSV rows (if present) as reference rows."""
    csv_path = os.path.join(run_dir, "crash_analysis.csv")
    if not os.path.isfile(csv_path):
        return
    try:
        with open(csv_path, newline="") as fh:
            for rec in csv.DictReader(fh):
                cls = (rec.get("classification") or rec.get("class") or "").strip()
                if cls == "confirmed_bug":
                    pri = "P1"
                elif cls == "likely_bug":
                    pri = "P2"
                elif cls in ("hang", "noise"):
                    pri = "P3"
                else:
                    pri = "P3"
                counters[pri[1].lower()] += 1
                rows.append({
                    "run": os.path.basename(run_dir),
                    "priority": pri, "kind": "crash_analysis:" + (cls or "unknown"),
                    "signal": rec.get("signal", ""),
                    "race_tagged": "",
                    "file": rec.get("file", ""),
                    "detail": rec.get("detail", ""),
                })
    except (OSError, csv.Error) as exc:
        print("[WARN] failed to read %s: %s" % (csv_path, exc), file=sys.stderr)


def _tar_root_member(archive_path):
    """Top-level member name of the archive (its entries share one root),
    or None if the archive is unreadable/empty/has no single common root."""
    try:
        with tarfile.open(archive_path) as tf:
            names = tf.getnames()
    except (tarfile.TarError, OSError) as exc:
        print("[WARN] failed to list %s: %s" % (archive_path, exc),
              file=sys.stderr)
        return None
    if not names:
        return None
    return names[0].split("/", 1)[0]


def materialize_run_archives(results):
    """Extract out-*.tar.gz archives (once) so the artifact dirs inside can
    be scanned.  Returns list of run dirs.

    Each tarball in a batch carries the SAME interior root (out-<subject>/)
    even though the tarballs themselves are named out-<subject>_N.tar.gz.
    Extracting all of them into <results> would collide on that root, so
    each archive is extracted under its own tarball basename
    (out-<subject>_N/)."""
    run_dirs = []
    for d in sorted(glob.glob(os.path.join(results, "out-*.tar.gz"))):
        root_member = _tar_root_member(d)
        if not root_member or root_member in (".", ".."):
            continue
        base = os.path.basename(d)[: -len(".tar.gz")]
        dest = os.path.join(results, base)
        real_dest = os.path.abspath(dest)
        if not (real_dest == results or
                real_dest.startswith(results + os.sep)):
            print("[WARN] skipping archive with unsafe root member: %s" % d,
                  file=sys.stderr)
            continue
        if os.path.isdir(dest):
            run_dirs.append(dest)
            continue
        try:
            with tarfile.open(d) as tf:
                # Flatten the shared interior root into dest/ by extracting
                # to a temp name inside results, then renaming the root.
                tmp = dest + ".extracting"
                if os.path.exists(tmp):
                    shutil.rmtree(tmp)
                tf.extractall(tmp, filter="data")
                inner = os.path.join(tmp, root_member)
                if os.path.isdir(inner):
                    os.rename(inner, dest)
                    shutil.rmtree(tmp, ignore_errors=True)
                else:
                    os.rename(tmp, dest)  # no shared root: keep whole tree
            run_dirs.append(dest)
            print("[INFO] extracted %s" % os.path.basename(d))
        except (tarfile.TarError, OSError) as exc:
            print("[WARN] failed to extract %s: %s" % (d, exc),
                  file=sys.stderr)
    for d in sorted(glob.glob(os.path.join(results, "out-*"))):
        if os.path.isdir(d) and d not in run_dirs:
            run_dirs.append(d)
    return sorted(set(run_dirs) - {results})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results_dir")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    results = os.path.abspath(args.results_dir)
    if not os.path.isdir(results):
        print("Error: not a directory: %s" % results, file=sys.stderr)
        return 1

    run_dirs = materialize_run_archives(results)
    if not run_dirs:
        print("[WARN] no out-* run directories under %s" % results, file=sys.stderr)

    all_rows = []
    totals = {"p1": 0, "p2": 0, "p3": 0, "teardown_race": 0}
    per_run_summary = []
    # A2: batch-level replay report is merged once, attributed by its own
    # run column (rows may reference runs outside run_dirs, e.g. a fresh
    # report against an older extraction); unmatched runs are still kept
    # as reference rows below.
    replay_by_run = {}
    csv_path = os.path.join(results, "crash_replay_report.csv")
    if os.path.isfile(csv_path):
        pri_of = {"confirmed": "P1", "low-rate": "P2", "non-replayable": "P3",
                  "error": "P3", "sampled": "P3"}
        try:
            with open(csv_path, newline="") as fh:
                for rec in csv.DictReader(fh):
                    verdict = (rec.get("verdict") or "").strip()
                    if not verdict:
                        continue
                    pri = pri_of.get(verdict, "P3")
                    replay_by_run.setdefault(rec.get("run", ""), []).append({
                        "priority": pri, "kind": "replay:" + verdict,
                        "signal": "", "race_tagged": "",
                        "file": rec.get("file", ""),
                        "detail": "crashes=%s/replays=%s rate=%s" %
                                  (rec.get("crashes", ""), rec.get("replays", ""),
                                   rec.get("rate", "")),
                    })
        except (OSError, csv.Error) as exc:
            print("[WARN] failed to read %s: %s" % (csv_path, exc),
                  file=sys.stderr)

    for rd in run_dirs:
        rd_name = os.path.basename(rd)
        rows, c = triage_run(rd)
        merge_crash_analysis(rd, rows, c)
        if rd_name in replay_by_run:
            for rr in replay_by_run.pop(rd_name):
                c["p" + rr["priority"][1].lower()] += 1
                rows.append(dict(rr, run=rd_name))
        all_rows.extend(rows)
        for k in totals:
            totals[k] += c[k]
        per_run_summary.append(
            "%s: P1=%d P2=%d P3=%d race=%d" %
            (rd_name, c["p1"], c["p2"], c["p3"], c["teardown_race"]))
        if args.verbose:
            for r in rows:
                print("  %-6s %-13s %-28s %s" %
                      (r["priority"], r["kind"], r["signal"], r["file"]))

    # Any replay rows whose run never matched an out-* dir still belong in
    # the report — append them as unmatched reference rows.
    for rd_name, rrs in sorted(replay_by_run.items()):
        for rr in rrs:
            totals["p" + rr["priority"][1].lower()] += 1
            all_rows.append(dict(rr, run=rd_name))
        per_run_summary.append(
            "%s (replay-only): %d rows" % (rd_name, len(rrs)))

    out_path = os.path.join(results, "vuln_triage_report.csv")
    with open(out_path, "w", newline="") as fh:
        w = csv.DictWriter(
            fh, fieldnames=["run", "priority", "kind", "signal",
                            "race_tagged", "file", "detail"])
        w.writeheader()
        w.writerows(all_rows)
        w.writerow({"run": "SUMMARY", "priority": "",
                    "kind": "total_runs=%d" % len(run_dirs),
                    "signal": "",
                    "race_tagged": str(totals["teardown_race"]),
                    "file": "",
                    "detail": "P1=%d P2=%d P3=%d" %
                              (totals["p1"], totals["p2"], totals["p3"])})

    for line in per_run_summary:
        print("[INFO] " + line)
    print("[INFO] report written: %s  (P1=%d P2=%d P3=%d teardown_race=%d)" %
          (out_path, totals["p1"], totals["p2"], totals["p3"],
           totals["teardown_race"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
