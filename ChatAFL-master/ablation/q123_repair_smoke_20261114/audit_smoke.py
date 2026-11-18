#!/usr/bin/env python3
"""Audit archived LoopFuzz runs against explicit smoke or arm-default controls."""

from __future__ import annotations

import argparse
import csv
import gzip
import glob
import hashlib
import io
import json
import math
import os
import re
import shlex
import statistics
import multiprocessing
import struct
import tarfile
from collections import Counter
from pathlib import Path


SAMPLED_COVERAGE_SCHEMA = "loopfuzz-coverage-v5-sampled-checkpoints"
SAMPLED_COVERAGE_TARGETS = frozenset({
    "lightftp", "lighttpd1", "forked-daapd", "kamailio", "exim", "proftpd", "live555"})
# arm-default matches LoopFuzz/afl-fuzz.c without the launcher's smoke
# overrides. Choose expectations explicitly; never infer them from evidence.
AUDIT_CONTROL_PROFILES = {
    "smoke": {
        "scheduler_warmup_max_selections": 8,
        "episode_energy_cap": 32,
        "cal_reward_window_invocations": 16,
    },
    "arm-default": {
        "scheduler_warmup_max_selections": 64,
        "episode_energy_cap": 512,
        "cal_reward_window_invocations": 0,
    },
}
SCOPE_IDENTITY_FIELDS = (
    "schema_version", "sources", "gcno", "branch_ids", "line_ids",
    "gcovr_format", "gcovr_version", "gcov_version", "branch_identity",
    "source_resolution", "replay_policy", "checkpoint_policy",
    "replay_harness_version",
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _snapshot_ids(report: dict) -> tuple[set[tuple], set[tuple], set[tuple], set[tuple]]:
    branches: set[tuple] = set()
    covered_branches: set[tuple] = set()
    lines: set[tuple] = set()
    covered_lines: set[tuple] = set()
    for source in report.get("files", []):
        filename = source.get("file")
        if not isinstance(filename, str) or not filename:
            raise ValueError("snapshot has an invalid source filename")
        for item in source.get("lines", []):
            if item.get("gcovr/excl_line", False):
                continue
            number = item.get("line_number")
            if isinstance(number, bool) or not isinstance(number, int) or number < 0:
                raise ValueError("snapshot has an invalid line number")
            line_id = (filename, number)
            if line_id in lines:
                raise ValueError("snapshot has a duplicate source line")
            lines.add(line_id)
            if item.get("count", 0) > 0:
                covered_lines.add(line_id)
            for ordinal, branch in enumerate(item.get("branches", [])):
                if branch.get("gcovr/excluded", False):
                    continue
                branchno = branch.get("branchno", ordinal)
                if isinstance(branchno, bool) or not isinstance(branchno, int) or branchno < 0:
                    raise ValueError("snapshot has an invalid branch number")
                branch_id = (filename, number, branchno)
                if branch_id in branches:
                    raise ValueError("snapshot has a duplicate branch identity")
                branches.add(branch_id)
                if branch.get("count", 0) > 0:
                    covered_branches.add(branch_id)
    return branches, covered_branches, lines, covered_lines


def _v4_snapshot_payload(raw: bytes):
    """Parse one decompressed gcovr snapshot and return its id sets (worker)."""
    report = json.loads(raw)
    return _snapshot_ids(report)


def _v4_snapshot_worker(item):
    index, raw = item
    return index, hashlib.sha256(raw).hexdigest(), gzip.decompress(raw)


def ledger_lengths(framed: bytes) -> list[int]:
    lengths, offset = [], 0
    while offset + 4 <= len(framed):
        (length,) = struct.unpack_from("<I", framed, offset)
        lengths.append(length)
        offset += 4 + length
    return lengths


def _v4_parse_worker(args):
    index, compressed, expected_sha, full, name_map = args
    raw = gzip.decompress(compressed)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError(f"v4 snapshot hash mismatch at input {index}")
    report = json.loads(raw)
    raw_files = {entry.get("file") for entry in report.get("files", [])}
    all_branches, covered_branches, all_lines, covered_lines = _snapshot_ids(report)
    if name_map is not None:
        # gcovr reports source paths relative to its invocation directory
        # (e.g. lightftp emits "Release/cfgparse.c" while the sealed scope
        # names it "cfgparse.c"); apply the run-wide raw->scope mapping the
        # replay itself used via filesystem-relative resolution.
        remap = lambda item: (name_map.get(item[0], item[0]), item[1], item[2])
        all_branches = {remap(item) for item in all_branches}
        covered_branches = {remap(item) for item in covered_branches}
        all_lines = {(name_map.get(f, f), n) for f, n in all_lines}
        covered_lines = {(name_map.get(f, f), n) for f, n in covered_lines}
    scope_key = (
        len(all_branches), len(all_lines),
        hashlib.sha256(_canonical([list(item) for item in sorted(all_branches)])).hexdigest(),
        hashlib.sha256(_canonical([list(item) for item in sorted(all_lines)])).hexdigest())
    if full:
        return index, scope_key, covered_branches, covered_lines, all_branches, all_lines, raw_files
    return index, scope_key, covered_branches, covered_lines, None, None, raw_files


def audit_v4_coverage_archive(tf, prefix: str, target: str) -> dict:
    """Independently rebuild v4 coverage from per-input evidence inside the archive.

    The v4 terminal/scope summaries alone are not trusted: every checkpoint is
    re-verified against its hashed replay/reset logs and decompressed snapshot,
    the cumulative unions are recomputed from the snapshots, the Pure-FTPd and
    ProFTPD exit-policy audit files are recomputed from the ledger, and each
    replay transcript must account for every frame of its archived input
    (the replay client can return 0 after a partial send, so transcript frame
    counts — not client exit codes — close that gap).
    """
    directory = "cov_over_time.csv.v4"
    # Single sequential pass over the tarball: random-access extractfile on a
    # .tar.gz re-decompresses the stream per call, so collect every needed
    # member once (compressed bytes only; snapshots are decompressed in the
    # parallel workers).
    wanted_meta = {"terminal.json", "scope.json", "replay-plan.json", "checkpoints.jsonl"}
    ledger_re = re.compile(r"^frame-ledger-\d{6}\.jsonl$")
    collected: dict[str, bytes] = {}
    queue_files: dict[str, bytes] = {}
    queue_prefix = prefix + "replayable-queue/"
    v4_prefix = prefix + directory + "/"
    for info in tf.getmembers():
        if not info.isfile():
            continue
        name = info.name[2:] if info.name.startswith("./") else info.name
        if name.startswith(v4_prefix):
            tail = name[len(v4_prefix):]
            if (tail in wanted_meta or tail.startswith("replay-") or
                    tail.startswith("reset-") or tail.startswith("snapshot-") or
                    tail in ("pureftpd-exit-policy-audit.json", "proftpd-exit-policy-audit.json")):
                collected[tail] = tf.extractfile(info).read()
            elif "frame-ledger" in tail and tail.endswith(".jsonl"):
                collected[tail] = tf.extractfile(info).read()
        elif name.startswith(queue_prefix):
            queue_files[name[len(queue_prefix):]] = tf.extractfile(info).read()

    def artifact(tail: str) -> bytes:
        if tail not in collected:
            raise ValueError(f"v4 archive is missing underlying evidence: {tail}")
        return collected[tail]

    scope = json.loads(artifact("scope.json"))
    terminal = json.loads(artifact("terminal.json"))
    if (scope.get("schema_version") != "loopfuzz-coverage-v4" or
            terminal.get("schema_version") != "loopfuzz-coverage-v4"):
        raise ValueError("v4 directory contains a different coverage schema")
    scope_hash = scope.get("scope_sha256")
    scope_identity = {field: scope[field] for field in SCOPE_IDENTITY_FIELDS if field in scope}
    if (not scope_hash or
            hashlib.sha256(_canonical(scope_identity)).hexdigest() != scope_hash or
            terminal.get("scope_sha256") != scope_hash):
        raise ValueError("v4 scope hash mismatch")
    plan = json.loads(artifact("replay-plan.json"))
    events = read_jsonl(artifact("checkpoints.jsonl"))
    if not isinstance(plan, list) or not plan:
        raise ValueError("v4 replay plan is missing or empty")
    if len(plan) != len(events) or terminal.get("n_replayed") != len(plan):
        raise ValueError("v4 plan, checkpoint, and terminal input counts disagree")

    expected_branch_ids = {tuple(item) for item in scope.get("branch_ids", [])}
    expected_line_ids = {tuple(item) for item in scope.get("line_ids", [])}
    policy = scope.get("replay_policy") or {}

    expected_key = (
        len(expected_branch_ids), len(expected_line_ids),
        hashlib.sha256(_canonical([list(item) for item in sorted(expected_branch_ids)])).hexdigest(),
        hashlib.sha256(_canonical([list(item) for item in sorted(expected_line_ids)])).hexdigest())

    tasks = []
    ledger_rows = []
    frame_gaps = []
    exempted_frame_gaps = []
    legacy_unknown = []
    reset_all_ok = True
    snapshots_raw: dict[int, bytes] = {}
    snapshot_shas: dict[int, str] = {}
    n = len(plan)
    for index, (record, event) in enumerate(zip(plan, events), 1):
        if (event.get("idx") != index or
                event.get("filename") != record.get("filename") or
                event.get("input_sha256") != record.get("input_sha256")):
            raise ValueError(f"v4 checkpoint identity disagrees at input {index}")
        replay = event.get("replay") or {}
        reset = event.get("reset") or {}
        replay_bytes = artifact(f"replay-{index:06d}.log")
        reset_bytes = artifact(f"reset-{index:06d}.log")
        if (replay.get("replay_log_file") != f"replay-{index:06d}.log" or
                replay.get("replay_log_sha256") != hashlib.sha256(replay_bytes).hexdigest()):
            raise ValueError(f"v4 replay log hash mismatch at input {index}")
        if (reset.get("log_file") != f"reset-{index:06d}.log" or
                reset.get("log_sha256") != hashlib.sha256(reset_bytes).hexdigest()):
            raise ValueError(f"v4 reset log hash mismatch at input {index}")
        if reset.get("command_succeeded") is not True:
            reset_all_ok = False
        if event.get("snapshot_file") != f"snapshot-{index:06d}.json.gz":
            raise ValueError(f"v4 snapshot naming disagrees at input {index}")

        filename = record.get("filename")
        if filename not in queue_files:
            raise ValueError(f"v4 archive is missing the framed input at input {index}")
        framed = queue_files[filename]
        frames, offset = 0, 0
        while offset + 4 <= len(framed):
            (length,) = struct.unpack_from("<I", framed, offset)
            if length > len(framed) - offset - 4:
                raise ValueError(f"v4 framed input is corrupt at input {index}")
            frames += 1
            offset += 4 + length
        policy_requires_ledger = (target == "proftpd" and
                                   (policy.get("name") or "").endswith("-v4"))
        ledger_tail = replay.get("frame_ledger_file")
        if isinstance(ledger_tail, str) and (ledger_tail != Path(ledger_tail).name or
                                             ledger_tail.startswith(".") or ".." in ledger_tail):
            raise ValueError(f"unsafe frame ledger name at input {index}")
        ledger_bytes = collected.get(ledger_tail) if isinstance(ledger_tail, str) else None
        if ledger_bytes is not None:
            # New replayer: validate the ledger against the framed input and
            # the replay row; banner counts are never send evidence.
            rows = [json.loads(line) for line in ledger_bytes.decode().splitlines() if line.strip()]
            if (not rows or rows[0].get("event") != "session_begin" or
                    rows[0].get("schema") != "loopfuzz-replay-frame-ledger-v1" or
                    rows[-1].get("event") != "session_end"):
                raise ValueError(f"v4 frame ledger is malformed at input {index}")
            led = [row for row in rows if row.get("event") == "frame"]
            if [row.get("frame") for row in led] != list(range(1, len(led) + 1)):
                raise ValueError(f"v4 frame ledger sequence breaks at input {index}")
            led_lens = [row.get("len") for row in led]
            if led_lens != ledger_lengths(framed)[:len(led_lens)] or len(led_lens) > frames:
                raise ValueError(f"v4 frame ledger lengths disagree at input {index}")
            if rows[-1].get("frames_total") != len(led):
                raise ValueError(f"v4 frame ledger count disagrees at input {index}")
            if (replay.get("frame_ledger_file") != ledger_tail or
                    replay.get("frame_ledger_sha256") != hashlib.sha256(ledger_bytes).hexdigest() or
                    replay.get("frames_total") != len(led)):
                raise ValueError(f"v4 replay row disagrees with its frame ledger at input {index}")
            # Same per-frame consistency rules as the replay-side reader
            # (GLM53 round-4): a full send needs read_complete, pre_recv_ok,
            # send_attempt, sent_bytes==len, zero errno and post_recv_ok;
            # contradictory rows invalidate completeness here too.
            sent = 0
            consistent = True
            for row in led:
                sb, ln = row.get("sent_bytes"), row.get("len")
                if not isinstance(sb, int) or not isinstance(ln, int) or (
                        sb not in (-2, -1) and (sb < 0 or sb > ln)):
                    raise ValueError(f"v4 frame ledger byte counts out of range at input {index}")
                if row.get("read_complete") is not True:
                    consistent = False
                if row.get("send_attempt") is True:
                    if row.get("pre_recv_ok") is not True or row.get("send_errno") not in (0, None):
                        consistent = False
                    if sb == ln and row.get("post_recv_ok") is True:
                        sent += 1
                elif sb not in (-2, None):
                    consistent = False
            expected_completeness = "complete" if (consistent and sent == frames and
                                                   len(led) == frames and
                                                   rows[-1].get("stop_reason") == "eof") else "incomplete"
            if replay.get("send_completeness") != expected_completeness:
                raise ValueError(f"v4 replay row send_completeness disagrees at input {index}")
            if replay.get("frames_sent_complete") != sent:
                raise ValueError(f"v4 replay row send count disagrees at input {index}")
            # Independent recompute of attempted / unattempted / stop reason.
            # frames_total is the LEDGER-RECORDED frame count (a prefix may
            # record fewer than the input's frames); unattempted counts every
            # input frame never attempted, in-ledger or beyond the prefix.
            attempted_led = sum(1 for row in led if row.get("send_attempt") is True)
            unattempted_expected = frames - attempted_led
            if replay.get("frames_attempted") != attempted_led:
                raise ValueError(f"v4 replay row frames_attempted disagrees at input {index}")
            if replay.get("frames_unattempted") != unattempted_expected:
                raise ValueError(f"v4 replay row frames_unattempted disagrees at input {index}")
            if replay.get("send_stop_reason") != rows[-1].get("stop_reason"):
                raise ValueError(f"v4 replay row send_stop_reason disagrees at input {index}")
            if expected_completeness != "complete":
                frame_gaps.append(index)
                if replay.get("coverage_complete") is True:
                    raise ValueError(f"v4 input claims complete coverage with incomplete frame sending at input {index}")
                if target == "proftpd" and replay.get("proftpd_shutdown_exit_expected") is True:
                    exempted_frame_gaps.append(index)
        elif policy_requires_ledger:
            raise ValueError(f"v4 replay policy requires a frame ledger at input {index}")
        else:
            # Legacy replayer (no ledger): banner counts prove loop entry
            # only; send facts stay unknown and are never inferred.
            legacy_unknown.append(index)
            packets = replay_bytes.count(b"Size of the current packet")
            if packets != frames:
                frame_gaps.append(index)
                if target == "proftpd" and replay.get("proftpd_shutdown_exit_expected") is True:
                    exempted_frame_gaps.append(index)
        ledger_rows.append((event, replay))
        snapshots_raw[index] = artifact(f"snapshot-{index:06d}.json.gz")
        snapshot_shas[index] = event.get("snapshot_sha256")

    # Pass 2 (parallel): parse snapshots and extract id sets.  The first
    # snapshot also yields the raw->scope filename mapping used by the rest.
    pool_size = min(16, os.cpu_count() or 4)
    with multiprocessing.Pool(pool_size) as pool:
        _, _, _, _, first_all_branches, _, first_raw_files = pool.apply(
            _v4_parse_worker, [(1, snapshots_raw[1], snapshot_shas[1], True, None)])
        if first_all_branches is not None and set(first_all_branches) == expected_branch_ids:
            name_map = None
        else:
            scope_by_name = {}
            for item in expected_branch_ids:
                scope_by_name.setdefault(item[0], set()).add(item)
            from collections import Counter as _Counter
            scope_names = {name for name, _, _ in expected_branch_ids}
            basename_counts = _Counter(name.rsplit("/", 1)[-1] for name in scope_names)
            name_map = {}
            for raw_name in first_raw_files:
                if raw_name in scope_names:
                    name_map[raw_name] = raw_name
                    continue
                base = raw_name.rsplit("/", 1)[-1]
                candidates = [name for name in scope_names if name.rsplit("/", 1)[-1] == base]
                if len(candidates) == 1 and basename_counts[base] == 1:
                    name_map[raw_name] = candidates[0]
                # unresolved names fail the scope comparison below (fail-closed)
        tasks = [(index, snapshots_raw[index], snapshot_shas[index],
                  index in (1, n) or index % 32 == 0,
                  name_map)
                 for index in range(1, n + 1) if index in snapshots_raw]
        parsed = pool.map(_v4_parse_worker, tasks, chunksize=4)

    branches_union: set[tuple] = set()
    lines_union: set[tuple] = set()
    seed_branches: set[tuple] = set()
    seed_lines: set[tuple] = set()
    seed_indices: list[int] = []
    previous_snapshot: set[tuple] = set()
    incomplete_rows: list[dict] = []
    witnesses: list[dict] = []
    first_raw_files = None
    for (index, scope_key, covered_branches, covered_lines,
         full_branches, full_lines, raw_files), (event, replay) in zip(parsed, ledger_rows):
        if first_raw_files is None:
            first_raw_files = raw_files
        elif raw_files != first_raw_files:
            raise ValueError(f"v4 snapshot source set changed at input {index}")
        if scope_key != expected_key:
            raise ValueError(f"v4 snapshot scope mismatch at input {index}")
        if full_branches is not None and (set(full_branches) != expected_branch_ids or
                                          set(full_lines) != expected_line_ids):
            raise ValueError(f"v4 snapshot scope id sets disagree at input {index}")
        if target in V4_ACCUMULATING_GCDA_TARGETS and previous_snapshot - covered_branches:
            raise ValueError(f"v4 accumulated coverage decreased at input {index}")
        newly = covered_branches - branches_union
        branches_union.update(covered_branches)
        lines_union.update(covered_lines)
        record = plan[index - 1]
        if (event.get("snapshot_covered_branches") != len(covered_branches) or
                event.get("cumulative_covered_branches") != len(branches_union) or
                event.get("snapshot_covered_lines") != len(covered_lines) or
                event.get("cumulative_covered_lines") != len(lines_union) or
                event.get("newly_covered_branch_ids") != [list(item) for item in sorted(newly)]):
            raise ValueError(f"v4 checkpoint aggregate mismatch at input {index}")
        previous_snapshot = covered_branches
        witnesses.append(dict(idx=index, filename=record.get("filename"),
                              input_sha256=record.get("input_sha256"),
                              snapshot_sha256=event.get("snapshot_sha256")))
        if replay.get("incomplete_reasons"):
            incomplete_rows.append(dict(filename=record.get("filename"),
                                        reasons=replay["incomplete_reasons"]))
        if event.get("is_seed_input"):
            seed_indices.append(index)
            seed_branches.update(covered_branches)
            seed_lines.update(covered_lines)

    if (terminal.get("covered_branch_ids") != [list(item) for item in sorted(branches_union)] or
            terminal.get("covered_line_ids") != [list(item) for item in sorted(lines_union)] or
            terminal.get("seed_covered_branch_ids") != [list(item) for item in sorted(seed_branches)] or
            terminal.get("seed_covered_line_ids") != [list(item) for item in sorted(seed_lines)] or
            terminal.get("seed_replay_indices") != sorted(seed_indices) or
            terminal.get("n_seed_replayed") != len(seed_indices) or
            terminal.get("executed_input_witnesses") != witnesses):
        raise ValueError("v4 terminal endpoint disagrees with rebuilt evidence")
    if terminal.get("incomplete_replays") != incomplete_rows:
        raise ValueError("v4 terminal incomplete list disagrees with per-input evidence")
    if terminal.get("all_reset_commands_succeeded") is not reset_all_ok:
        raise ValueError("v4 terminal reset summary disagrees with per-input evidence")
    replay_truncated = terminal.get("replay_truncated", False)
    planned_n_replayed = terminal.get("planned_n_replayed", terminal.get("n_replayed"))
    if (not isinstance(replay_truncated, bool) or
            isinstance(planned_n_replayed, bool) or
            not isinstance(planned_n_replayed, int) or
            planned_n_replayed < len(plan) or
            replay_truncated != (planned_n_replayed > len(plan))):
        raise ValueError("v4 terminal replay plan count disagrees with truncation metadata")
    complete = (not incomplete_rows and reset_all_ok and
                not terminal.get("n_unreplayable_ledger_entries", 0) and
                not replay_truncated and not frame_gaps)
    if terminal.get("coverage_complete") is not complete or terminal.get("acceptance") != ("complete" if complete else "incomplete"):
        raise ValueError("v4 terminal completeness disagrees with per-input evidence")
    if exempted_frame_gaps:
        raise ValueError("v4 ProFTPD shutdown exemptions lack transcript frame completeness at inputs " +
                         ",".join(map(str, exempted_frame_gaps[:5])))

    # Recompute the per-input exit-policy audit files from the ledger.
    if target == "pure-ftpd" and policy.get("name") == "pure-ftpd-gcov-die-421-exit-251-252-v2":
        expected_policy_audit = _pureftpd_policy_audit_report(policy, events)
        _verify_policy_audit_file(artifact, terminal, directory,
                                  "pureftpd-exit-policy-audit.json",
                                  "pureftpd_exit_policy_audit_file",
                                  "pureftpd_exit_policy_audit_sha256",
                                  expected_policy_audit)
    if target == "proftpd" and policy.get("name") in ("proftpd-ready-client-graceful-exit-v2",
                                                       "proftpd-ready-client-graceful-exit-v3",
                                                       "proftpd-ready-client-graceful-exit-v4"):
        expected_policy_audit = _proftpd_policy_audit_report(policy, events)
        _verify_policy_audit_file(artifact, terminal, directory,
                                  "proftpd-exit-policy-audit.json",
                                  "proftpd_exit_policy_audit_file",
                                  "proftpd_exit_policy_audit_sha256",
                                  expected_policy_audit)

    # ProFTPD policy identity uses an exact version set: an unknown version
    # (e.g. a future "...-v999") must fail closed, and a v4-policy archive
    # requires per-input frame ledgers - their absence is a failure, not a
    # legacy-unknown downgrade.
    has_ledgers = any(key.endswith(".jsonl") and "frame-ledger" in key for key in collected)
    if target == "proftpd" and policy and policy.get("name") not in (
            "proftpd-ready-client-graceful-exit-v2",
            "proftpd-ready-client-graceful-exit-v3",
            "proftpd-ready-client-graceful-exit-v4"):
        raise ValueError("proptpd archive carries an unrecognized replay policy: "
                         + repr(policy.get("name")))
    if target == "proftpd" and (policy.get("name") or "").endswith("-v4") and not has_ledgers:
        raise ValueError("proptpd v4 policy requires per-input frame ledgers; none found")

    # The archived cov_over_time.csv is the campaign-period sampled table
    # (SKIPCOUNT cadence), not the replay ledger; per-input evidence lives in
    # checkpoints.jsonl and the hashed snapshot/replay/reset files above.
    return {"ok": True, "inputs": len(plan), "branches": len(branches_union),
            "lines": len(lines_union), "scope_sha256": scope_hash,
            "frame_gap_inputs": frame_gaps}


def _verify_policy_audit_file(artifact, terminal, directory, file_name, file_field, sha_field, expected):
    audit_bytes = artifact(file_name)
    if (terminal.get(file_field) != file_name or
            terminal.get(sha_field) != hashlib.sha256(audit_bytes).hexdigest()):
        raise ValueError(f"{file_name} identity disagrees with terminal record")
    if json.loads(audit_bytes) != expected:
        raise ValueError(f"{file_name} disagrees with recomputed per-input evidence")


def _pureftpd_policy_audit_report(policy, events):
    inputs = []
    for index, event in enumerate(events, 1):
        replay = event.get("replay", {})
        reset = event.get("reset", {})
        inputs.append(dict(
            idx=index, filename=event.get("filename"),
            server_exit_code=replay.get("server_exit_code"),
            client_exit_code=replay.get("client_exit_code"),
            server_ready=replay.get("server_ready"),
            client_timed_out=replay.get("client_timed_out"),
            harness_shutdown_requested=replay.get("harness_shutdown_requested"),
            final_ftp_reply_code=replay.get("final_ftp_reply_code"),
            imported_gcda_count=len(replay.get("imported_gcda", [])),
            reset_command_succeeded=reset.get("command_succeeded") is True,
            expected_session_exit=replay.get("pureftpd_session_exit_expected") is True,
            anomaly_kind=replay.get("anomaly_kind"),
            incomplete_reasons=replay.get("incomplete_reasons", []),
            policy_evidence=replay.get("pureftpd_session_exit_evidence", {})))
    accepted = sum(row["expected_session_exit"] for row in inputs)
    return dict(schema_version="pureftpd-session-exit-audit-v1",
                policy_name=policy.get("name"),
                policy_verified=policy.get("verified") is True,
                verified_scope=policy.get("verified_scope"),
                source_sha256=policy.get("source_sha256"),
                binary_sha256=policy.get("binary_sha256"),
                source_binary_build_association=policy.get("source_binary_build_association", "not-verified"),
                n_inputs=len(inputs), n_expected_session_exits=accepted,
                n_other_inputs=len(inputs) - accepted, inputs=inputs)


def _proftpd_policy_audit_report(policy, events):
    inputs = []
    for index, event in enumerate(events, 1):
        replay = event.get("replay", {})
        reset = event.get("reset", {})
        inputs.append(dict(
            idx=index, filename=event.get("filename"),
            server_exit_code=replay.get("server_exit_code"),
            client_exit_code=replay.get("client_exit_code"),
            server_ready=replay.get("server_ready"),
            client_timed_out=replay.get("client_timed_out"),
            harness_shutdown_requested=replay.get("harness_shutdown_requested"),
            harness_shutdown_signal=replay.get("harness_shutdown_signal"),
            reset_command_succeeded=reset.get("command_succeeded") is True,
            expected_shutdown_exit=replay.get("proftpd_shutdown_exit_expected") is True,
            anomaly_kind=replay.get("anomaly_kind"),
            incomplete_reasons=replay.get("incomplete_reasons", []),
            policy_evidence=replay.get("proftpd_shutdown_exit_evidence", {})))
    accepted = sum(row["expected_shutdown_exit"] for row in inputs)
    return dict(schema_version="proftpd-shutdown-exit-audit-v1",
                policy_name=policy.get("name"),
                policy_verified=policy.get("verified") is True,
                verified_scope=policy.get("verified_scope"),
                n_inputs=len(inputs), n_expected_shutdown_exits=accepted,
                n_other_inputs=len(inputs) - accepted, inputs=inputs)


def _exim_server_rejection_evidence(index, replay_log_bytes, ledger_rows, frames,
                                    input_lengths, consistent, sent, attempted, replay):
    """Classify an incomplete Exim replay as a server-initiated session drop.

    Exim ends the SMTP call with "500 Too many syntax or protocol errors" (or
    a 421 close) once an input exhausts smtp_max_synprot_errors; the remaining
    frames can never be delivered on that connection.  Such an input stays
    send-incomplete and never counts toward coverage_complete — this only
    decides whether the batch audit accepts the archive.  Acceptance requires
    the frame ledger to show an orderly close with every attempted frame fully
    delivered and answered, and the hash-pinned replay transcript to carry the
    server's own terminal rejection line after at least one prior error
    response.  Anything else returns None and remains a strict failure.
    """
    tail = ledger_rows[-1]
    if (tail.get("stop_reason") != "peer-closed-before-input-end" or
            tail.get("peer_closed") is not True):
        return None
    if (not consistent or not frames or sent != attempted or sent != len(frames) or
            len(frames) >= len(input_lengths)):
        return None
    if replay.get("client_exit_code") != 2 or replay.get("client_timed_out"):
        return None
    text = replay_log_bytes.decode("utf-8", errors="replace")
    marker = "Responses in details:"
    if marker not in text:
        return None
    # The client's transcript section is followed by captured server stderr
    # that can share the dashed separator line; responses end at the first
    # line beginning with that separator.
    section = text.split(marker, 1)[1]
    response_lines = []
    for line in section.splitlines():
        if line.startswith("----------"):
            break
        if line.strip():
            response_lines.append(line.strip())
    if not response_lines:
        return None
    final = response_lines[-1]
    if not (final.startswith("500 Too many syntax or protocol errors") or
            final.startswith("421 ")):
        return None
    prior_errors = sum(1 for line in response_lines[:-1]
                       if len(line) > 3 and line[:3].isdigit() and line[0] in "45")
    if prior_errors < 1:
        return None
    return {"stop_reason": tail.get("stop_reason"),
            "final_response": final[:120],
            "prior_error_responses": prior_errors,
            "frames_delivered": sent,
            "frames_unattempted": len(input_lengths) - attempted}


def _audit_sampled_input_evidence(member, target, index, planned, record, replay_input):
    """Authenticate raw artifacts and independently require every framed send.

    Exit zero and packet banners cannot establish delivery: the replay client
    can stop early and still return zero.  Use the same per-frame conditions
    as the v4 reader, including matching the entire archived input.

    Returns (frame_count, send_complete, rejection_evidence).  An incomplete
    send is only tolerable with per-target server-rejection evidence; without
    it this raises exactly as before.
    """
    directory = "cov_over_time.csv.v5/"
    replay, reset = record["replay"], record["reset"]

    def artifact(name):
        try:
            raw = member(directory + name)
        except (KeyError, FileNotFoundError, ValueError) as exc:
            raise ValueError(f"sampled input {index} is missing underlying evidence: {name}") from exc
        if not isinstance(raw, bytes):
            raise ValueError(f"sampled input {index} has invalid underlying evidence: {name}")
        return raw

    replay_log_bytes = None
    for name, metadata, file_key, hash_key in (
            (f"replay-{index:06d}.log", replay, "replay_log_file", "replay_log_sha256"),
            (f"reset-{index:06d}.log", reset, "log_file", "log_sha256")):
        raw = artifact(name)
        if metadata.get(file_key) != name or metadata.get(hash_key) != hashlib.sha256(raw).hexdigest():
            raise ValueError(f"sampled input {index} log hash/name mismatch: {name}")
        if file_key == "replay_log_file":
            replay_log_bytes = raw
    reset_ok = (isinstance(reset.get("command"), list) and bool(reset["command"]) and
                type(reset.get("exit_code")) is int and reset["exit_code"] == 0)
    # The producer authenticates reset in record.reset on every target. Some
    # targets additionally copy the result into replay; require agreement
    # when present, while the authoritative exit code/log remain mandatory.
    if (reset.get("command_succeeded") is not reset_ok or
            ("reset_command_succeeded" in replay and replay["reset_command_succeeded"] is not reset_ok)):
        raise ValueError(f"sampled input {index} reset result disagrees with command exit")

    ledger_name = replay.get("frame_ledger_file")
    if ledger_name != f"replay-{index:06d}-frame-ledger.jsonl":
        raise ValueError(f"sampled input {index} requires its own named frame ledger")
    raw = artifact(ledger_name)
    if replay.get("frame_ledger_sha256") != hashlib.sha256(raw).hexdigest():
        raise ValueError(f"sampled input {index} frame ledger hash mismatch")
    rows = read_jsonl(raw)
    if (len(rows) < 3 or any(not isinstance(row, dict) for row in rows) or
            rows[0].get("event") != "session_begin" or
            rows[0].get("schema") != "loopfuzz-replay-frame-ledger-v1" or
            rows[-1].get("event") != "session_end" or
            any(row.get("event") != "frame" for row in rows[1:-1])):
        raise ValueError(f"sampled input {index} frame ledger is malformed")
    if (rows[0].get("input_file") != planned["filename"] or
            type(rows[0].get("input_size")) is not int or
            rows[0]["input_size"] != len(replay_input) or
            rows[0].get("protocol") != PROTOCOL_BY_TARGET[target]):
        raise ValueError(f"sampled input {index} frame ledger input identity disagrees")
    lengths, offset = [], 0
    while offset + 4 <= len(replay_input):
        (length,) = struct.unpack_from("<I", replay_input, offset)
        if length > len(replay_input) - offset - 4:
            raise ValueError(f"sampled input {index} framed input is corrupt")
        lengths.append(length)
        offset += 4 + length
    if offset != len(replay_input):
        raise ValueError(f"sampled input {index} framed input has trailing bytes")
    frames = rows[1:-1]
    if (any(type(row.get("frame")) is not int or row["frame"] != number
            for number, row in enumerate(frames, 1)) or
            any(type(row.get("len")) is not int or row["len"] < 0 for row in frames) or
            [row["len"] for row in frames] != lengths[:len(frames)] or
            len(frames) > len(lengths) or
            type(rows[-1].get("frames_total")) is not int or
            rows[-1]["frames_total"] != len(frames)):
        raise ValueError(f"sampled input {index} frame ledger sequence/lengths disagree")
    sent, attempted, consistent = 0, 0, True
    for row in frames:
        sent_bytes, length = row.get("sent_bytes"), row["len"]
        if type(sent_bytes) is not int or (sent_bytes not in (-2, -1) and not 0 <= sent_bytes <= length):
            raise ValueError(f"sampled input {index} frame ledger byte count is invalid")
        if row.get("read_complete") is not True:
            consistent = False
        if row.get("send_attempt") is True:
            attempted += 1
            if row.get("pre_recv_ok") is not True or row.get("send_errno") not in (0, None):
                consistent = False
            if sent_bytes == length and row.get("post_recv_ok") is True:
                sent += 1
        elif sent_bytes != -2:
            consistent = False
    complete = bool(consistent and frames and len(frames) == len(lengths) and
                    sent == len(lengths) and attempted == len(lengths) and
                    rows[-1].get("stop_reason") == "eof")
    recomputed = {"frames_total": len(frames), "frames_attempted": attempted,
                  "frames_sent_complete": sent, "frames_unattempted": len(lengths) - attempted,
                  "send_stop_reason": rows[-1].get("stop_reason"),
                  "send_completeness": "complete" if complete else "incomplete"}
    if any(replay.get(key) != value or
           (type(value) is int and type(replay.get(key)) is not int)
           for key, value in recomputed.items()):
        raise ValueError(f"sampled input {index} replay send summary disagrees with frame ledger")
    if complete:
        return len(frames), True, None
    rejection = None
    if target == "exim":
        rejection = _exim_server_rejection_evidence(
            index, replay_log_bytes, rows, frames, lengths, consistent,
            sent, attempted, replay)
    if rejection is None:
        raise ValueError(f"sampled input {index} frame send is incomplete")
    return len(frames), False, rejection


def audit_sampled_coverage_archive(member, target: str, archive_names=None) -> dict:
    """Rebuild sampled v5 coverage from archived per-input and snapshot evidence."""
    if target not in SAMPLED_COVERAGE_TARGETS:
        raise ValueError(f"sampled coverage is not permitted for {target}")
    schema = json.loads(member("cov_over_time.csv.v5/scope.json"))
    terminal = json.loads(member("cov_over_time.csv.v5/terminal.json"))
    if schema.get("schema_version") != SAMPLED_COVERAGE_SCHEMA or terminal.get("schema_version") != SAMPLED_COVERAGE_SCHEMA:
        raise ValueError("v5 directory contains a different coverage schema")
    scope_hash = schema.get("scope_sha256")
    scope_identity = {field: schema[field] for field in SCOPE_IDENTITY_FIELDS if field in schema}
    if not scope_hash or hashlib.sha256(_canonical(scope_identity)).hexdigest() != scope_hash or terminal.get("scope_sha256") != scope_hash:
        raise ValueError("sampled scope hash mismatch")
    policy = schema.get("checkpoint_policy", {})
    step = policy.get("step")
    if (policy.get("kind") != "step-plus-terminal-and-seed-boundary" or
            isinstance(step, bool) or not isinstance(step, int) or step < 1 or
            policy.get("final_checkpoint_required") is not True or
            policy.get("seed_boundary_required") is not True or
            policy.get("every_input_has_replay_ledger") is not True):
        raise ValueError("unsupported sampled checkpoint policy")
    plan = json.loads(member("cov_over_time.csv.v5/replay-plan.json"))
    ledger = read_jsonl(member("cov_over_time.csv.v5/replay-ledger.jsonl"))
    events = read_jsonl(member("cov_over_time.csv.v5/checkpoints.jsonl"))
    if not plan or len(plan) != len(ledger):
        raise ValueError("sampled replay plan and per-input ledger lengths disagree")
    planned_names = [row.get("filename") for row in plan]
    if (any(not isinstance(name, str) or not name or Path(name).name != name
            for name in planned_names) or len(set(planned_names)) != len(planned_names)):
        raise ValueError("sampled replay plan has missing, unsafe, or duplicate input filenames")
    if archive_names is not None:
        queue_prefix = "out-%s-loopfuzz/replayable-queue/" % target
        archived_names = sorted(
            name[len(queue_prefix):] for name in archive_names
            if name.startswith(queue_prefix) and not name.endswith("/")
        )
        if terminal.get("replay_truncated") is True:
            planned_count = terminal.get("planned_n_replayed")
            if (isinstance(planned_count, bool) or not isinstance(planned_count, int) or
                    len(archived_names) != planned_count or
                    planned_names != archived_names[:len(planned_names)]):
                raise ValueError("truncated replay plan is not a prefix of the archived full queue")
        elif sorted(planned_names) != archived_names:
            raise ValueError("archived replayable-queue file set disagrees with replay plan")
    seed_indices = [i for i, row in enumerate(plan, 1) if row.get("kind") == "initial-queue-name"]
    if seed_indices and seed_indices != list(range(1, len(seed_indices) + 1)):
        raise ValueError("sampled seed inputs are not a replay-plan prefix")
    expected = {i for i in range(1, len(plan) + 1) if i % step == 0 or i == len(plan)}
    if seed_indices:
        expected.add(seed_indices[-1])

    incomplete = []
    server_rejected = []
    verified_frames = 0
    witnesses = []
    for index, (planned, record) in enumerate(zip(plan, ledger), 1):
        replay_input = member("replayable-queue/" + planned["filename"])
        input_hash = hashlib.sha256(replay_input).hexdigest()
        if not replay_input:
            raise ValueError("archived replay input is empty: " + planned["filename"])
        if input_hash != planned.get("input_sha256"):
            raise ValueError("archived replay input hash disagrees with replay plan: " + planned["filename"])
        if (record.get("schema_version") != SAMPLED_COVERAGE_SCHEMA or record.get("idx") != index or
                record.get("filename") != planned.get("filename") or
                record.get("input_sha256") != planned.get("input_sha256") or
                record.get("input_hash_verified_before_replay") is not True or
                record.get("instrumented_objects_unchanged") is not True or
                not isinstance(record.get("reset"), dict) or
                not isinstance(record.get("replay"), dict) or
                record.get("checkpoint") is not (index in expected)):
            raise ValueError(f"invalid sampled per-input ledger entry {index}")
        if index in expected:
            if (not record.get("snapshot_file") or not record.get("snapshot_sha256") or
                    record.get("coverage_event_idx") is None):
                raise ValueError(f"sampled input {index} lacks its snapshot witness")
        elif any(key in record for key in ("snapshot_file", "snapshot_sha256", "coverage_event_idx")):
            raise ValueError(f"unsampled input {index} contains snapshot evidence")
        replay = record["replay"]
        input_frames, send_complete, rejection = _audit_sampled_input_evidence(
            member, target, index, planned, record, replay_input)
        verified_frames += input_frames
        reasons = []
        if replay.get("session_coverage_missing"):
            reasons.append("session-gcda-not-flushed")
        if replay.get("server_crashed"):
            reasons.append("server-signal-exit")
        if replay.get("replay_anomaly"):
            reasons.append(replay.get("anomaly_kind") or "replay-anomaly")
        if replay.get("client_timed_out"):
            reasons.append("client-timeout")
        if replay.get("server_ready") is False:
            reasons.append("server-not-ready")
        if replay.get("helper_ready") is False:
            reasons.append("helper-not-ready")
        if not send_complete:
            reasons.append("frame-ledger-incomplete")
        if rejection is not None and reasons != ["client-exit-2", "frame-ledger-incomplete"]:
            # A server-side rejection cannot coexist with any other anomaly;
            # confounded incompleteness stays a strict failure.
            raise ValueError(
                f"sampled input {index} server rejection is confounded: {reasons}")
        if reasons:
            incomplete.append({"filename": record["filename"], "reasons": reasons})
        if rejection is not None:
            server_rejected.append({
                "idx": index, "filename": record["filename"],
                "input_sha256": record["input_sha256"],
                "stop_reason": rejection["stop_reason"],
                "final_response": rejection["final_response"],
                "prior_error_responses": rejection["prior_error_responses"],
                "frames_delivered": rejection["frames_delivered"],
                "frames_unattempted": rejection["frames_unattempted"]})
        witnesses.append({"idx": index, "filename": record["filename"],
                          "input_sha256": record["input_sha256"],
                          "checkpoint": record["checkpoint"],
                          "snapshot_sha256": record.get("snapshot_sha256")})
    if [row["idx"] for row in ledger if row["checkpoint"]] != sorted(expected):
        raise ValueError("per-input ledger omits a required checkpoint")
    if len(events) != len(expected):
        raise ValueError("sampled checkpoint event count disagrees with policy")

    branches_union: set[tuple] = set()
    lines_union: set[tuple] = set()
    seed_branches: set[tuple] = set()
    seed_lines: set[tuple] = set()
    previous_snapshot: set[tuple] = set()
    expected_branch_ids = {tuple(item) for item in schema.get("branch_ids", [])}
    expected_line_ids = {tuple(item) for item in schema.get("line_ids", [])}
    if not expected_branch_ids or not expected_line_ids:
        raise ValueError("sampled scope has an empty source universe")
    for event_index, (event, replay_index) in enumerate(zip(events, sorted(expected)), 1):
        record = ledger[replay_index - 1]
        if (event.get("schema_version") != SAMPLED_COVERAGE_SCHEMA or
                event.get("idx") != event_index or event.get("replay_input_idx") != replay_index or
                event.get("scope_sha256") != scope_hash or
                event.get("snapshot_file") != record.get("snapshot_file") or
                event.get("snapshot_sha256") != record.get("snapshot_sha256") or
                event.get("replay") != record.get("replay") or event.get("reset") != record.get("reset")):
            raise ValueError(f"sampled checkpoint {event_index} disagrees with its replay ledger entry")
        raw_snapshot = gzip.decompress(member("cov_over_time.csv.v5/" + event["snapshot_file"]))
        if hashlib.sha256(raw_snapshot).hexdigest() != event.get("snapshot_sha256"):
            raise ValueError(f"sampled snapshot hash mismatch at replay input {replay_index}")
        report = json.loads(raw_snapshot)
        all_branches, covered_branches, all_lines, covered_lines = _snapshot_ids(report)
        if all_branches != expected_branch_ids or all_lines != expected_line_ids:
            raise ValueError(f"sampled snapshot scope mismatch at replay input {replay_index}")
        newly = covered_branches - branches_union
        if previous_snapshot - covered_branches:
            raise ValueError(f"accumulated gcda coverage decreased at replay input {replay_index}")
        branches_union.update(covered_branches)
        lines_union.update(covered_lines)
        if seed_indices and replay_index <= len(seed_indices):
            seed_branches.update(covered_branches)
            seed_lines.update(covered_lines)
        if (event.get("snapshot_covered_branches") != len(covered_branches) or
                event.get("cumulative_covered_branches") != len(branches_union) or
                event.get("snapshot_covered_lines") != len(covered_lines) or
                event.get("cumulative_covered_lines") != len(lines_union) or
                event.get("newly_covered_branch_ids") != [list(item) for item in sorted(newly)]):
            raise ValueError(f"sampled checkpoint aggregate mismatch at replay input {replay_index}")
        previous_snapshot = covered_branches

    if (terminal.get("coverage_capture_mode") != "sampled-step-plus-terminal" or
            terminal.get("sampled_checkpoint_input_indices") != sorted(expected) or
            terminal.get("n_replayed") != len(plan) or
            terminal.get("n_coverage_checkpoints") != len(events) or
            terminal.get("n_seed_replayed") != len(seed_indices) or
            terminal.get("seed_replay_indices") != seed_indices or
            terminal.get("executed_input_witnesses") != witnesses or
            terminal.get("covered_branch_ids") != [list(item) for item in sorted(branches_union)] or
            terminal.get("covered_line_ids") != [list(item) for item in sorted(lines_union)] or
            terminal.get("seed_covered_branch_ids") != [list(item) for item in sorted(seed_branches)] or
            terminal.get("seed_covered_line_ids") != [list(item) for item in sorted(seed_lines)]):
        raise ValueError("sampled terminal endpoint disagrees with reconstructed evidence")
    all_resets = all(row["reset"].get("command_succeeded") is True for row in ledger)
    replay_truncated = terminal.get("replay_truncated", False)
    planned_n_replayed = terminal.get("planned_n_replayed", terminal.get("n_replayed"))
    if (not isinstance(replay_truncated, bool) or
            isinstance(planned_n_replayed, bool) or
            not isinstance(planned_n_replayed, int) or
            planned_n_replayed < len(plan) or
            replay_truncated != (planned_n_replayed > len(plan))):
        raise ValueError("sampled terminal replay plan count disagrees with truncation metadata")
    replay_evidence_complete = (not incomplete and all_resets and
                                not terminal.get("n_unreplayable_ledger_entries", 0))
    complete = replay_evidence_complete and not replay_truncated
    smoke_cap_valid = (
        replay_truncated and terminal.get("smoke_mode") is True and
        isinstance(terminal.get("replay_input_limit"), int) and
        not isinstance(terminal.get("replay_input_limit"), bool) and
        terminal.get("replay_input_limit") == len(plan) and
        planned_n_replayed > len(plan) and
        terminal.get("incomplete_reasons") == ["smoke-replay-input-cap"]
    )
    if (terminal.get("coverage_complete") is not complete or
            terminal.get("acceptance") != ("complete" if complete else "incomplete") or
            terminal.get("all_reset_commands_succeeded") is not all_resets or
            terminal.get("incomplete_replays") != incomplete):
        raise ValueError("sampled terminal completeness disagrees with per-input evidence")
    if terminal.get("unexpected_snapshot_decrease") is not False:
        raise ValueError("sampled terminal records a raw snapshot decrease")
    # Server-rejected incompleteness is reported, never relabeled complete
    # (coverage_complete stays False above); it only stops being a batch-level
    # strict failure when every incomplete input carries rejection evidence.
    server_rejected_names = {row["filename"] for row in server_rejected}
    unexplained_incomplete = [row for row in incomplete
                              if row["filename"] not in server_rejected_names]
    hard_incomplete = bool(unexplained_incomplete) or not all_resets or bool(
        terminal.get("n_unreplayable_ledger_entries", 0))
    if hard_incomplete or (replay_truncated and not smoke_cap_valid):
        raise ValueError("sampled coverage is incomplete")

    with io.StringIO(member("cov_over_time.csv").decode("utf-8"), newline="") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != len(events):
        raise ValueError("sampled coverage CSV row count disagrees with snapshots")
    for row, event in zip(rows, events):
        if (int(row["idx"]) != event["idx"] or int(row["b_abs"]) != event["cumulative_covered_branches"] or
                int(row["l_abs"]) != event["cumulative_covered_lines"] or
                abs(float(row["b_per"]) - 100 * event["cumulative_covered_branches"] / len(expected_branch_ids)) > 1e-8 or
                abs(float(row["l_per"]) - 100 * event["cumulative_covered_lines"] / len(expected_line_ids)) > 1e-8 or
                row.get("scope_sha256") != scope_hash or
                row.get("snapshot_sha256") != event.get("snapshot_sha256")):
            raise ValueError("sampled coverage CSV disagrees with checkpoint ledger")
    return {"ok": True, "coverage_complete": complete,
            "replay_truncated": replay_truncated,
            "planned_inputs": planned_n_replayed,
            "inputs": len(plan), "checkpoints": len(events),
            "complete_inputs": len(plan) - len(incomplete),
            "server_rejected_inputs": server_rejected,
            "verified_log_pairs": len(plan), "verified_frame_ledgers": len(plan),
            "verified_frames": verified_frames,
            "branches": len(branches_union), "lines": len(lines_union), "scope_sha256": scope_hash}


def parse_kv(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def parse_stats(raw: bytes) -> dict[str, int | float | str]:
    result: dict[str, int | float | str] = {}
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        try:
            result[key.strip()] = int(value)
        except ValueError:
            try:
                result[key.strip()] = float(value)
            except ValueError:
                result[key.strip()] = value
    return result


def read_jsonl(raw: bytes) -> list[dict]:
    return [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]


def sample_sd(values: list[float]) -> float | None:
    return statistics.stdev(values) if len(values) >= 2 else None


def format_sample_sd(values: list[float], digits: int = 2) -> str:
    value = sample_sd(values)
    return f"{value:.{digits}f}" if value is not None else "n/a (n<2)"


def add_check(checks: list[tuple[str, bool, str]], name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, bool(ok), detail))


V4_ACCUMULATING_GCDA_TARGETS = frozenset({
    "lightftp", "lighttpd1", "forked-daapd", "kamailio", "exim", "proftpd", "live555"})

SHARED_COMPARISON_FIELDS = (
    "target", "target_sha256", "fuzzer", "fuzzer_commit", "fuzzer_sha256",
    "loopfuzz_source_sha256",
    "seeds_sha256", "image_digest",
    "protocol_name",
    "scope_sha256", "coverage_schema_version", "replay_harness_version",
    "campaign_call_budget", "threshold_requested", "threshold_resolved",
    "scheduler_warmup_max_selections",
    "episode_energy_cap", "cal_reward_window_invocations", "mock_gateway",
)
CONDITIONAL_SHARED_FIELDS = ("campaign_stop_mode", "campaign_duration_sec", "campaign_resource_basis")

LIVE_GATEWAY_FIELDS = (
    "model", "endpoint", "top_p", "max_output_tokens", "llm_total_call_cap",
    "token_cap", "token_cap_enforced",
)


def audit_live_gateway(
    member, names: list[str], prefix: str, cfg: dict, end_cfg: dict,
    *, profile: str = "smoke", arm_label: str | None = None,
) -> dict:
    """Reconcile actual client attempts with raw exchanges; never infer billed zero.

    This validates archived evidence, not provider billing or a hard token bound.
    Transport failures can have no response; their usage is explicitly unknown.
    Successful replies require model/content/usage corroborated by the raw JSON.
    """
    if profile not in AUDIT_CONTROL_PROFILES:
        raise ValueError("unknown audit profile: " + profile)
    errors, exchanges = [], []
    known_prompt = known_completion = successes = unknown_usage = outbound = 0
    def integer(value):
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0
    for field in LIVE_GATEWAY_FIELDS:
        if field not in cfg or field not in end_cfg or cfg[field] != end_cfg[field]:
            errors.append("missing/mismatched live configuration: " + field)
    if not isinstance(cfg.get("model"), str) or not cfg.get("model"):
        errors.append("missing configured model")
    if not integer(cfg.get("max_output_tokens")) or not 0 < cfg["max_output_tokens"] <= 32768:
        errors.append("invalid effective max_output_tokens")
    top_p = cfg.get("top_p")
    if isinstance(top_p, bool) or not isinstance(top_p, (int, float)) or not 0 < top_p <= 1:
        errors.append("invalid effective top_p")
    if not isinstance(cfg.get("endpoint"), str) or not cfg.get("endpoint", "").startswith("https://"):
        errors.append("live endpoint must explicitly use HTTPS")
    call_cap = cfg.get("llm_total_call_cap")
    bounded_calls = integer(call_cap) and call_cap > 0
    # The runtime records -1 when no LLM call cap was configured. This is
    # allowed only by explicit arm-default audit; positive caps still bind.
    uncapped_calls = type(call_cap) is int and call_cap == -1
    if profile == "smoke" and not bounded_calls:
        errors.append("live smoke requires a positive effective total-call cap")
    elif profile == "arm-default" and not (bounded_calls or uncapped_calls):
        errors.append("invalid effective total-call cap (expected positive or -1)")
    token_cap, token_effective = cfg.get("token_cap"), cfg.get("token_cap_enforced")
    if (not integer(token_cap) or not isinstance(token_effective, int)
            or isinstance(token_effective, bool)
            or (token_cap > 0 and token_effective != token_cap)
            or (token_cap == 0 and token_effective >= 0)):
        errors.append("declared/effective token threshold mismatch")
    if cfg.get("mock_gateway") is not None or end_cfg.get("mock_gateway") is not None:
        errors.append("live archive carries mock gateway configuration")
    no_llm_arm = isinstance(arm_label, str) and re.fullmatch(r"nollm[1-9][0-9]*", arm_label) is not None
    confirmed_no_llm = no_llm_arm and cfg.get("no_llm") is True and end_cfg.get("no_llm") is True
    ledger_present = any(name.removeprefix("./") == prefix + "llm-calls.jsonl" for name in names)
    try:
        # A disabled client never opens the ledger. Its absence is permitted
        # only for this explicitly identified control, with zero runtime
        # counters checked below; malformed present evidence still fails.
        rows = [] if confirmed_no_llm and not ledger_present else read_jsonl(member("llm-calls.jsonl"))
    except Exception as exc:
        rows = []
        errors.append("missing/invalid live call ledger: " + str(exc))
    if no_llm_arm or cfg.get("no_llm") is True or end_cfg.get("no_llm") is True:
        # This exception belongs to the independently identified control arm,
        # never to a live-LLM arm with missing request evidence. Require both
        # configuration phases plus all independent counters to corroborate it.
        if not no_llm_arm or cfg.get("no_llm") is not True or end_cfg.get("no_llm") is not True:
            errors.append("no-LLM control requires an explicit nollm arm and matching boolean configuration")
        if rows:
            errors.append("no-LLM control carries call-ledger records")
        if any(name.removeprefix("./").startswith(prefix + "llm-archive/")
               and name.endswith((".req", ".resp")) for name in names):
            errors.append("no-LLM control carries raw exchange sidecars")
        try:
            stats = parse_stats(member("fuzzer_stats"))
            for field in ("llm_total_calls", "llm_prompt_tokens", "llm_completion_tok"):
                if type(stats.get(field)) is not int or stats[field] != 0:
                    errors.append("no-LLM control requires zero recorded " + field)
            if type(stats.get("no_llm_mode")) is not int or stats["no_llm_mode"] != 1:
                errors.append("no-LLM control lacks its effective runtime mode")
        except Exception as exc:
            errors.append("missing/invalid no-LLM runtime counters: " + str(exc))
        return {"eligible": not errors, "errors": errors,
                "evidence_mode": "no-llm-control", "outbound_attempts": 0,
                "successful_requests": 0, "unknown_usage_attempts": 0,
                "known_prompt_tokens": 0, "known_completion_tokens": 0,
                "reported_total_tokens": 0,
                "llm_call_cap_enforced": call_cap if bounded_calls else None,
                "token_cap_semantics": "no-LLM control; recorded zero usage is not independent provider billing",
                "exchanges": []}
    identities, expected_sidecars = set(), set()
    for index, row in enumerate(rows):
        label = f"row {index + 1}"
        if not isinstance(row, dict):
            errors.append(label + ": invalid ledger record")
            continue
        request_id = row.get("request_id")
        identity = (row.get("pid"), row.get("seq"))
        if (not all(integer(v) and v > 0 for v in identity)
                or request_id != f"{identity[0]}-{identity[1]}" or request_id in identities):
            errors.append(label + ": duplicate/invalid request identity")
            continue
        identities.add(request_id)
        status = row.get("status")
        if status not in {"ok", "api-error", "transport-error", "invalid-response", "empty-content",
                          "cap-refused", "deadline-before-dispatch"}:
            errors.append(label + ": unknown call status")
        if row.get("endpoint") != cfg.get("endpoint") or row.get("model_requested") != cfg.get("model"):
            errors.append(label + ": configured endpoint/model mismatch")
        if row.get("archived") is not True:
            errors.append(label + ": raw exchange not archived")
        if not integer(row.get("prompt_tokens")) or not integer(row.get("completion_tokens")):
            errors.append(label + ": invalid ledger token values")
        req_name, resp_name = "llm-archive/" + request_id + ".req", "llm-archive/" + request_id + ".resp"
        expected_sidecars.add(req_name)
        exchange = {"request_id": request_id, "status": status, "usage": "unknown"}
        try:
            raw_request = member(req_name)
            request = json.loads(raw_request)
            exchange["request_sha256"] = hashlib.sha256(raw_request).hexdigest()
            if (not isinstance(request, dict) or request.get("model") != cfg.get("model")
                    or request.get("max_tokens") != cfg.get("max_output_tokens")
                    or request.get("top_p") != cfg.get("top_p")
                    or not isinstance(request.get("messages"), list) or not request["messages"]):
                errors.append(label + ": request JSON/config mismatch")
        except Exception as exc:
            errors.append(label + ": missing/invalid request sidecar: " + str(exc))
        if status == "deadline-before-dispatch":
            # A reservation may persist while fsync crosses the elapsed-time
            # endpoint. This is auditable non-dispatch, never provider usage.
            duration, start_ms, time_ms = (cfg.get("campaign_duration_sec"),
                                           cfg.get("start_time_ms"), row.get("time_ms"))
            if (cfg.get("campaign_stop_mode") != "wallclock"
                    or end_cfg.get("campaign_stop_mode") != "wallclock"
                    or not integer(duration) or duration <= 0
                    or end_cfg.get("campaign_duration_sec") != duration
                    or not integer(start_ms) or not integer(time_ms)
                    or time_ms < start_ms + duration * 1000):
                errors.append(label + ": deadline non-dispatch lacks an elapsed-time endpoint")
            if (not integer(row.get("reservation_id")) or row["reservation_id"] <= 0
                    or row.get("outbound_attempted") is not False
                    or row.get("prompt_tokens") != 0 or row.get("completion_tokens") != 0
                    or row.get("usage_reported") is not False
                    or row.get("model_served") != "" or row.get("retry") is not False
                    or row.get("latency_ms") != 0):
                errors.append(label + ": invalid reserved-but-not-dispatched evidence")
            expected_sidecars.add(resp_name)
            try:
                raw_response = member(resp_name)
                exchange["response_sha256"] = hashlib.sha256(raw_response).hexdigest()
                if raw_response != b"":
                    errors.append(label + ": non-dispatched request has a nonempty response")
            except Exception as exc:
                errors.append(label + ": missing non-dispatch response sidecar: " + str(exc))
            exchange["usage"] = "not-sent"
            exchange["outbound_attempted"] = False
            exchanges.append(exchange)
            continue
        if status == "cap-refused":
            exchange["usage"] = "not-sent"
            if row.get("prompt_tokens") != 0 or row.get("completion_tokens") != 0:
                errors.append(label + ": refused request reports tokens")
            exchanges.append(exchange)
            continue
        outbound += 1
        try:
            raw_response = member(resp_name)
        except Exception as exc:
            raw_response = None
            if status != "transport-error":
                errors.append(label + ": missing response sidecar: " + str(exc))
        response = None
        if raw_response is not None:
            expected_sidecars.add(resp_name)
            exchange["response_sha256"] = hashlib.sha256(raw_response).hexdigest()
            try:
                response = json.loads(raw_response)
                if not isinstance(response, dict):
                    raise ValueError("response is not an object")
                if status == "invalid-response":
                    errors.append(label + ": invalid-response status contradicts JSON object sidecar")
            except Exception:
                if status not in {"transport-error", "invalid-response"}:
                    errors.append(label + ": invalid response JSON")
                response = None
        usage = response.get("usage") if response else None
        usage_known = (isinstance(usage, dict) and integer(usage.get("prompt_tokens"))
                       and integer(usage.get("completion_tokens")))
        if usage_known:
            pt, ct = usage["prompt_tokens"], usage["completion_tokens"]
            if (pt, ct) != (row.get("prompt_tokens"), row.get("completion_tokens")):
                errors.append(label + ": raw/ledger usage mismatch")
            if "total_tokens" in usage and (not integer(usage["total_tokens"]) or usage["total_tokens"] != pt + ct):
                errors.append(label + ": inconsistent response total_tokens")
            known_prompt += pt
            known_completion += ct
            exchange["usage"] = {"prompt_tokens": pt, "completion_tokens": ct}
        else:
            unknown_usage += 1
            if row.get("prompt_tokens") != 0 or row.get("completion_tokens") != 0:
                errors.append(label + ": uncorroborated ledger token values")
        served = response.get("model") if response else None
        if response and (served or row.get("model_served")) and served != row.get("model_served"):
            errors.append(label + ": raw/ledger served model mismatch")
        exchange["model_served"] = served
        if status == "ok":
            choices = response.get("choices") if response else None
            first = choices[0] if isinstance(choices, list) and choices else None
            message = first.get("message") if isinstance(first, dict) else None
            content = message.get("content") if isinstance(message, dict) else None
            if (not response or response.get("error") or not isinstance(content, str) or not content.strip()
                    or not isinstance(served, str) or not served.strip()):
                errors.append(label + ": success lacks genuine content/served model")
            else:
                successes += 1
            if not usage_known:
                errors.append(label + ": successful response has unknown usage")
        if status == "api-error" and response and not response.get("error"):
            errors.append(label + ": API failure lacks error object")
        exchanges.append(exchange)
    if outbound == 0 or successes == 0:
        errors.append("live integration requires at least one actual successful request")
    if bounded_calls and outbound > call_cap:
        errors.append("observed outbound attempts exceed effective call cap")
    sidecars = set()
    for name in names:
        normalized = name[2:] if name.startswith("./") else name
        if normalized.startswith(prefix + "llm-archive/") and normalized.endswith((".req", ".resp")):
            sidecars.add(normalized[len(prefix):])
    if sidecars != expected_sidecars:
        errors.append("orphan/missing raw exchange sidecars")
    return {"eligible": not errors, "errors": errors, "outbound_attempts": outbound,
            "successful_requests": successes, "unknown_usage_attempts": unknown_usage,
            "known_prompt_tokens": known_prompt, "known_completion_tokens": known_completion,
            "reported_total_tokens": None if unknown_usage else known_prompt + known_completion,
            "llm_call_cap_enforced": call_cap if bounded_calls else None,
            "token_cap_semantics": "post-response threshold; no hard total-token bound claimed",
            "exchanges": exchanges}


def shared_identity_from_sample(
    cfg: dict, terminal: dict, coverage_scope: dict, mock: dict, gateway: str = "mock",
) -> dict:
    """Build the repeat identity used to compare dose, protocol, mock, and replay."""
    identity = {
        "target": cfg.get("target"),
        "target_sha256": cfg.get("target_sha256"),
        "fuzzer": cfg.get("fuzzer"),
        "fuzzer_commit": cfg.get("fuzzer_commit"),
        "fuzzer_sha256": cfg.get("fuzzer_sha256"),
        "loopfuzz_source_sha256": cfg.get("loopfuzz_source_sha256"),
        "seeds_sha256": cfg.get("seeds_sha256"),
        "image_digest": cfg.get("image_digest"),
        "protocol_name": cfg.get("protocol_name"),
        "scope_sha256": terminal.get("scope_sha256"),
        "coverage_schema_version": terminal.get("schema_version"),
        "replay_harness_version": coverage_scope.get("replay_harness_version"),
        "campaign_call_budget": cfg.get("campaign_call_budget"),
        "threshold_requested": cfg.get("threshold_requested"),
        "threshold_resolved": cfg.get("threshold_resolved"),
        "scheduler_warmup_max_selections": cfg.get("scheduler_warmup_max_selections"),
        "episode_energy_cap": cfg.get("episode_energy_cap"),
        "cal_reward_window_invocations": cfg.get("cal_reward_window_invocations"),
        # Compare the complete effective mock configuration recorded by
        # the gateway. Its per-run request counts are outcome metrics and
        # intentionally stay outside this identity signature.
        "mock_gateway": mock.get("effective_config"),
    }
    for field in CONDITIONAL_SHARED_FIELDS:
        if field in cfg:
            identity[field] = cfg[field]
    if gateway == "live":
        identity.pop("mock_gateway")
        identity["live_gateway"] = {field: cfg.get(field) for field in LIVE_GATEWAY_FIELDS}
    return identity

CORE_ARM_BASES = frozenset({
    "pvstop", "salvage", "nollm", "wrapgate", "native",
    "calibrated", "cal_ewma", "cal_run_rate",
})
Q1_ARM_BASES = frozenset({"q1a", "q1b", "q1c", "q1d"})
Q2_ARM_BASES = frozenset({"ordmatch"})
ALL_ARM_BASES = CORE_ARM_BASES | Q1_ARM_BASES | Q2_ARM_BASES

# The 8 core arms are the common cross-target smoke set. BFTPD retains the
# completed 13-arm default batch; Q1/Q2 controls can be selected explicitly
# for other targets when those comparisons are part of the planned batch.
PROTOCOL_BY_TARGET = {
    "lightftp": "FTP",
    "bftpd": "FTP",
    "proftpd": "FTP",
    "pure-ftpd": "FTP",
    "exim": "SMTP",
    "live555": "RTSP",
    "kamailio": "SIP",
    "forked-daapd": "HTTP",
    "lighttpd1": "HTTP",
}
DEFAULT_ARM_BASES_BY_TARGET = {
    target: CORE_ARM_BASES for target in PROTOCOL_BY_TARGET
}
DEFAULT_ARM_BASES_BY_TARGET["bftpd"] = ALL_ARM_BASES
# Backwards-compatible import name for existing BFTPD batch consumers.
EXPECTED_BATCH_ARM_LABELS = frozenset(f"{base}1" for base in ALL_ARM_BASES)
EXPECTED_CAMPAIGN_TERMINATION = "campaign-call-budget"
DEFAULT_CAMPAIGN_RUNTIME_MS = 900_000


def parse_arm_bases(raw: str, threshold: int) -> frozenset[str]:
    """Expand --arms groups and normalize arm names to the requested threshold."""
    groups = {
        "core": CORE_ARM_BASES,
        "q1": Q1_ARM_BASES,
        "q2": Q2_ARM_BASES,
        "all": ALL_ARM_BASES,
    }
    requested: set[str] = set()
    for item in raw.split(","):
        name = item.strip()
        if not name:
            continue
        if name in groups:
            requested.update(groups[name])
            continue
        base = name
        if name[-1:].isdigit():
            digits = name[len(name.rstrip("0123456789")):]
            base = name[:-len(digits)]
            if int(digits) != threshold:
                raise ValueError(f"arm {name!r} uses threshold {digits}, expected {threshold}")
        if base not in ALL_ARM_BASES:
            raise ValueError(f"unknown arm {name!r}; use a core/Q1/Q2 arm or group")
        requested.add(base)
    if not requested:
        raise ValueError("at least one expected arm is required")
    return frozenset(requested)


def expected_arm_labels(
    target: str = "bftpd", threshold: int = 1, arms: str | None = None,
) -> frozenset[str]:
    bases = (
        parse_arm_bases(arms, threshold)
        if arms is not None
        else DEFAULT_ARM_BASES_BY_TARGET[target]
    )
    return frozenset(f"{base}{threshold}" for base in bases)


def audit_campaign_termination(
    start_cfg: dict, end_cfg: dict,
    max_runtime_ms: int = DEFAULT_CAMPAIGN_RUNTIME_MS,
) -> tuple[bool, str]:
    """Check the configured fixed-dose or fixed-wallclock stopping rule."""
    start_ms = start_cfg.get("start_time_ms")
    end_ms = end_cfg.get("end_time_ms")
    valid_times = (
        isinstance(start_ms, (int, float)) and not isinstance(start_ms, bool)
        and isinstance(end_ms, (int, float)) and not isinstance(end_ms, bool)
        and math.isfinite(start_ms) and math.isfinite(end_ms)
    )
    elapsed_ms = end_ms - start_ms if valid_times else None
    reason = end_cfg.get("termination_reason")
    stop_mode = start_cfg.get("campaign_stop_mode", "call-budget")
    if stop_mode == "wallclock":
        duration = start_cfg.get("campaign_duration_sec")
        duration_ms = duration * 1000 if isinstance(duration, int) and duration > 0 else None
        tolerance_ms = 360_000
        lower_tolerance_ms = 0 if start_cfg.get("campaign_call_budget") == 0 else tolerance_ms
        ok = (
            duration_ms is not None
            and reason in ("wallclock-duration", "signal-or-timeout")
            and valid_times
            and duration_ms - lower_tolerance_ms <= elapsed_ms <= duration_ms + tolerance_ms
        )
        return ok, (
            f"mode=wallclock reason={reason!r} elapsed_ms={elapsed_ms!r} "
            f"duration_ms={duration_ms!r} tolerance_ms=-{lower_tolerance_ms}/+{tolerance_ms}"
        )
    if stop_mode != "call-budget":
        return False, f"unknown campaign stop mode: {stop_mode!r}"
    ok = (
        reason == EXPECTED_CAMPAIGN_TERMINATION
        and valid_times
        and 0 <= elapsed_ms < max_runtime_ms
    )
    return ok, f"reason={reason!r} expected={EXPECTED_CAMPAIGN_TERMINATION!r} elapsed_ms={elapsed_ms!r} limit_ms={max_runtime_ms}"


def audit_campaign_integrity_termination(
    start_cfg: dict, end_cfg: dict,
    max_runtime_ms: int = DEFAULT_CAMPAIGN_RUNTIME_MS,
) -> tuple[bool, str]:
    """Accept either a timely call-cap end or the configured runtime censor."""
    fixed_call, fixed_detail = audit_campaign_termination(start_cfg, end_cfg, max_runtime_ms)
    if fixed_call:
        return True, f"fixed-call campaign; {fixed_detail}"
    if start_cfg.get("campaign_stop_mode") == "wallclock" and start_cfg.get("campaign_call_budget") == 0:
        return False, f"uncapped elapsed-time campaign did not reach its endpoint; {fixed_detail}"

    start_ms = start_cfg.get("start_time_ms")
    end_ms = end_cfg.get("end_time_ms")
    valid_times = (
        isinstance(start_ms, (int, float)) and not isinstance(start_ms, bool)
        and isinstance(end_ms, (int, float)) and not isinstance(end_ms, bool)
        and math.isfinite(start_ms) and math.isfinite(end_ms)
    )
    elapsed_ms = end_ms - start_ms if valid_times else None
    reason = end_cfg.get("termination_reason")
    # Allow a small lower tolerance for signal delivery and a short upper
    # tolerance for teardown; unrelated early signals remain an integrity failure.
    censored = (
        reason == "signal-or-timeout" and valid_times
        and max_runtime_ms * 0.95 <= elapsed_ms <= max_runtime_ms * 1.03
    )
    return censored, (
        f"reason={reason!r} elapsed_ms={elapsed_ms!r}; accepted censor is "
        f"signal-or-timeout near the configured {max_runtime_ms} ms limit"
    )


def audit_repeat_mapping(manifest_rows: list[dict], summary_rows: list[dict]) -> tuple[bool, str]:
    """Require three distinct runs and exact manifest/status-summary identity mapping."""
    archives = [row.get("archive_name", "") for row in manifest_rows]
    run_ids = [str(row.get("run", "")) for row in manifest_rows]
    container_ids = [row.get("container_id", "") for row in manifest_rows]
    sources = [row.get("source", "") for row in summary_rows]
    summary_runs = [str(row.get("run", "")) for row in summary_rows]
    nonempty_unique = lambda values: all(values) and len(set(values)) == len(values)
    checks = {
        "three_manifest_rows": len(manifest_rows) == 3,
        "three_summary_rows": len(summary_rows) == 3,
        "unique_archive_names": nonempty_unique(archives),
        "unique_manifest_run_ids": nonempty_unique(run_ids),
        "unique_manifest_container_ids": nonempty_unique(container_ids),
        "unique_summary_sources": nonempty_unique(sources),
        "unique_summary_run_ids": nonempty_unique(summary_runs),
        "archive_source_set_matches": set(archives) == set(sources),
        "manifest_summary_run_mapping_matches": {
            row.get("archive_name"): str(row.get("run", "")) for row in manifest_rows
        } == {
            row.get("source"): str(row.get("run", "")) for row in summary_rows
        },
    }
    ok = all(checks.values())
    detail = ", ".join(f"{name}={value}" for name, value in checks.items())
    return ok, detail


def audit_status_mapping(manifest_rows: list[dict], statuses_dir: Path) -> tuple[bool, str]:
    """Require exactly one status record per manifest archive/container identity."""
    status_paths = sorted(statuses_dir.glob("*.status"))
    status_rows = [parse_kv(path) for path in status_paths]
    manifest_archives = [row.get("archive_name", "") for row in manifest_rows]
    manifest_containers = {
        row.get("archive_name"): row.get("container_id") for row in manifest_rows
    }
    status_archives = [row.get("archive_name", "") for row in status_rows]
    status_containers = [row.get("container_id", "") for row in status_rows]
    status_mapping = {
        row.get("archive_name"): row.get("container_id") for row in status_rows
    }
    checks = {
        "three_status_files": len(status_paths) == 3,
        "unique_status_archive_names": all(status_archives) and len(set(status_archives)) == len(status_archives),
        "unique_status_container_ids": all(status_containers) and len(set(status_containers)) == len(status_containers),
        "status_archive_set_matches_manifest": set(status_archives) == set(manifest_archives),
        "status_container_mapping_matches_manifest": status_mapping == manifest_containers,
    }
    ok = all(checks.values())
    return ok, ", ".join(f"{name}={value}" for name, value in checks.items())


def find_unique_archive_member(
    names: list[str], prefix: str, suffix: str, *, optional: bool = False,
) -> str | None:
    """Find exactly one archive path for a requested member suffix."""
    matches = [name for name in names if name.endswith(prefix + suffix)]
    if not matches and optional:
        return None
    if len(matches) != 1:
        raise ValueError(f"expected one archive member ending in {prefix + suffix!r}; found {len(matches)}")
    return matches[0]


def coverage_archive_schema(names: list[str], prefix: str) -> tuple[str, str]:
    """Select exactly one coverage artifact schema; never infer v5 from v4 data."""
    candidates = (
        ("loopfuzz-coverage-v4", "cov_over_time.csv.v4"),
        (SAMPLED_COVERAGE_SCHEMA, "cov_over_time.csv.v5"),
    )
    found = [(schema, directory) for schema, directory in candidates
             if any(name.startswith(prefix + directory + "/") for name in names)]
    if len(found) != 1:
        raise ValueError(f"expected exactly one v4 or sampled v5 coverage artifact tree; found {found}")
    return found[0]


def audit_invocation_pairs(executions: list[dict]) -> tuple[bool, str]:
    """Check unique invocation IDs and matching per-call attempt/execution coordinates."""
    starts = [row for row in executions if row.get("event") == "invocation_start"]
    ends = [row for row in executions if row.get("event") == "invocation_end"]
    start_ids = [row.get("invocation_id") for row in starts]
    end_ids = [row.get("invocation_id") for row in ends]
    attempt_ids = [row.get("attempt_id") for row in starts]
    execution_before_ids = [row.get("execution_id_before") for row in starts]
    valid_id_sets = (
        bool(starts) and all(value is not None for value in start_ids + end_ids)
        and len(set(start_ids)) == len(start_ids)
        and len(set(end_ids)) == len(end_ids)
        and set(start_ids) == set(end_ids)
        and all(value is not None for value in attempt_ids)
        and len(set(attempt_ids)) == len(attempt_ids)
        and all(value is not None for value in execution_before_ids)
        and len(set(execution_before_ids)) == len(execution_before_ids)
    )
    details = []
    if valid_id_sets:
        ends_by_id = {row["invocation_id"]: row for row in ends}
        for start in starts:
            end = ends_by_id[start["invocation_id"]]
            before = start.get("execution_id_before")
            end_before = end.get("execution_id_before")
            start_after = start.get("execution_id_after")
            end_after = end.get("execution_id_after")
            coordinates_valid = (
                isinstance(before, int) and not isinstance(before, bool) and before >= 0
                and end_before == before
                and start_after == before
                and isinstance(end_after, int) and not isinstance(end_after, bool)
                and end_after >= before
            )
            pair_valid = (
                start.get("attempt_id") is not None
                and start.get("attempt_id") == end.get("attempt_id")
                and start.get("campaign_id") is not None
                and start.get("campaign_id") == end.get("campaign_id")
                and start.get("executed") is True and end.get("executed") is True
                and coordinates_valid
            )
            if not pair_valid:
                details.append({
                    "invocation_id": start.get("invocation_id"),
                    "start_attempt": start.get("attempt_id"),
                    "end_attempt": end.get("attempt_id"),
                    "start_execution_before": before,
                    "start_execution_after": start_after,
                    "end_execution_before": end_before,
                    "end_execution_after": end_after,
                })
    ok = valid_id_sets and not details
    return ok, f"starts={len(starts)} ends={len(ends)} unique_ids={valid_id_sets} invalid_pairs={details[:5]}"


def audit_mock_protocol(mock: dict, cfg: dict, expected_protocol: str) -> tuple[bool, str]:
    """Require a target-pinned mock and reject cross-protocol attribution.

    Older mock archives inferred the label from prompt text, which could
    confuse DAAP with HTTP and did not prove which response bank was used.
    Such archives remain auditable as legacy evidence, but are ineligible for
    the strict protocol check until rerun with ``MOCK_PROTOCOL`` pinned.
    """
    by_proto = mock.get("by_proto", {})
    campaign_requests = mock.get("campaign_requests")
    campaign_count_valid = (
        isinstance(campaign_requests, int) and not isinstance(campaign_requests, bool)
        and campaign_requests >= 0
    )
    no_llm = cfg.get("no_llm") is True
    preflight_requests = mock.get("startup_preflight_requests")
    if not isinstance(preflight_requests, int) or isinstance(preflight_requests, bool):
        # Preserve compatibility with stats that expose class counts but not
        # the convenience field.
        classes = mock.get("requests_by_class", {})
        preflight_requests = classes.get("startup_preflight") if isinstance(classes, dict) else None
    if not isinstance(preflight_requests, int) or isinstance(preflight_requests, bool):
        total_requests = mock.get("requests")
        preflight_requests = (
            total_requests - campaign_requests
            if campaign_count_valid and isinstance(total_requests, int)
            and not isinstance(total_requests, bool)
            else None
        )
    preflight_count_valid = (
        isinstance(preflight_requests, int) and not isinstance(preflight_requests, bool)
        and preflight_requests >= 0
    )
    effective_config = mock.get("effective_config", {})
    pinned_protocol = (
        effective_config.get("protocol")
        if isinstance(effective_config, dict) else None
    )
    pin_ok = pinned_protocol == expected_protocol
    campaign_ok = campaign_count_valid and preflight_count_valid and (
        campaign_requests == 0 and preflight_requests == 0
        if no_llm else campaign_requests > 0
    )
    valid_counts = isinstance(by_proto, dict) and all(
        isinstance(count, int) and not isinstance(count, bool) and count > 0
        for count in by_proto.values()
    )
    totals_match = (
        valid_counts and preflight_count_valid
        and sum(by_proto.values()) == campaign_requests + preflight_requests
    ) if campaign_count_valid else False
    if no_llm:
        attribution_ok = valid_counts and not by_proto and campaign_requests == 0 and preflight_requests == 0
    else:
        # With a target pin, preflight and campaign prompts both use the same
        # response bank. This makes the recorded aggregate directly checkable.
        attribution_ok = totals_match and (
            (campaign_requests + preflight_requests == 0 and not by_proto)
            or by_proto == {expected_protocol: campaign_requests + preflight_requests}
        )
    try:
        port_ok = (
            int(mock.get("port", 0))
            == int(cfg.get("mock_gateway", {}).get("port", -1))
        )
    except (TypeError, ValueError, AttributeError):
        port_ok = False
    ok = pin_ok and attribution_ok and campaign_ok and port_ok
    return ok, (
        f"expected_protocol={expected_protocol} pinned_protocol={pinned_protocol} pin_ok={pin_ok} "
        f"by_proto={by_proto} "
        f"port={mock.get('port')} campaign={campaign_requests} preflight={preflight_requests} "
        f"campaign_count_valid={campaign_count_valid} no_llm={no_llm} attribution_ok={attribution_ok}"
    )


def audit_fuzzer_protocol(cfg: dict, expected_protocol: str) -> tuple[bool, str]:
    """Cross-check the parser-selected protocol against the archived argv.

    ``protocol_name`` comes from the live ``-P`` parser state. The recorded
    command line independently proves which option was supplied, so a pinned
    mock gateway alone cannot establish the fuzzer's protocol attribution.
    """
    parsed_protocol = cfg.get("protocol_name")
    command = cfg.get("orig_cmdline")
    parse_error = ""
    tokens: list[str] = []
    if isinstance(command, str) and command:
        try:
            tokens = shlex.split(command)
        except ValueError as exc:
            parse_error = str(exc)
    else:
        parse_error = "missing orig_cmdline"

    protocol_args: list[str] = []
    malformed = False
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-P":
            if index + 1 >= len(tokens) or tokens[index + 1].startswith("-"):
                malformed = True
            else:
                protocol_args.append(tokens[index + 1])
                index += 1
        elif token.startswith("-P") and len(token) > 2:
            protocol_args.append(token[2:])
        index += 1

    argv_protocol = protocol_args[0] if len(protocol_args) == 1 else None
    ok = (not parse_error and not malformed and len(protocol_args) == 1
          and parsed_protocol == expected_protocol
          and argv_protocol == expected_protocol)
    detail = (
        f"expected={expected_protocol} protocol_name={parsed_protocol!r} "
        f"argv_protocols={protocol_args!r}"
        + (f" parse_error={parse_error}" if parse_error else "")
        + (" malformed=-P" if malformed else "")
    )
    return bool(ok), detail


def audit_mock_request_accounting(mock: dict) -> tuple[bool, str]:
    """Check request/status accounting without treating truncation as a status.

    ``truncated`` is a subset of HTTP 200 responses. ``reply_classes`` counts
    successfully generated campaign replies, excluding preflight and HTTP
    errors, so it is intentionally not added to request totals.
    """
    requests = mock.get("requests")
    campaign = mock.get("campaign_requests")
    preflight = mock.get("startup_preflight_requests")
    classes = mock.get("requests_by_class", {})
    counts = [requests, campaign, preflight]
    valid = all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in counts
    )
    valid = valid and isinstance(classes, dict) and all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in classes.values()
    )
    statuses = [mock.get(key) for key in ("http_200", "http_429", "http_500")]
    truncated = mock.get("truncated")
    valid = valid and all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in statuses + [truncated]
    )
    class_values_valid = isinstance(classes, dict) and all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in classes.values()
    )
    status_values_valid = all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in statuses
    )
    class_sum = sum(classes.values()) if class_values_valid else -1
    status_sum = sum(statuses) if status_values_valid else -1
    consistent = (
        valid
        and requests == campaign + preflight
        and class_sum == requests
        and status_sum == requests
        and truncated <= mock.get("http_200", -1)
    )
    reply_classes = mock.get("reply_classes", {})
    reply_sum = (
        sum(reply_classes.values())
        if isinstance(reply_classes, dict)
        and all(isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for value in reply_classes.values())
        else None
    )
    return bool(consistent), (
        f"requests={requests} campaign={campaign} preflight={preflight} "
        f"request_classes={class_sum} http_statuses={status_sum} "
        f"truncated_subset_of_http_200={truncated} reply_classes={reply_sum}"
    )


def audit_complete_batch(
    result_dirs: list[Path], target: str = "bftpd", threshold: int = 1,
    expected_labels: frozenset[str] | None = None,
) -> tuple[bool, str]:
    """Require the configured target's complete, duplicate-free arm set."""
    expected_labels = expected_labels or expected_arm_labels(target, threshold)
    result_prefix = f"results-{target}_ablation_"
    labels = []
    unknown = []
    for result_dir in result_dirs:
        if not result_dir.name.startswith(result_prefix):
            unknown.append(result_dir.name)
            continue
        name = result_dir.name.removeprefix(result_prefix)
        match = next((
            arm for arm in sorted(expected_labels, key=len, reverse=True)
            if name == arm or name.startswith(arm + "_")
        ), None)
        if match is None:
            unknown.append(name)
        else:
            labels.append(match)
    counts = Counter(labels)
    missing = sorted(expected_labels - set(labels))
    duplicates = sorted(label for label, count in counts.items() if count != 1)
    ok = len(result_dirs) == len(expected_labels) and not unknown and not missing and not duplicates
    return ok, f"dirs={len(result_dirs)} arms={len(set(labels))} missing={missing} duplicate={duplicates} unknown={unknown}"


def shared_identity_difference(identities: list[dict], gateway: str = "mock") -> tuple[bool, str]:
    """Require every compared run to share target, dose, mock, and replay identity."""
    if not identities:
        return False, "no run identities were available"
    fields = tuple(field for field in SHARED_COMPARISON_FIELDS if field != "mock_gateway") + ("live_gateway",) if gateway == "live" else SHARED_COMPARISON_FIELDS
    fields += tuple(
        field for field in CONDITIONAL_SHARED_FIELDS
        if any(field in identity for identity in identities)
    )
    missing = [
        (idx, field) for idx, identity in enumerate(identities)
        for field in fields
        if field not in identity or identity[field] is None or identity[field] == ""
    ]
    if missing:
        return False, f"missing shared identity fields: {missing[:12]}"
    canonical = set()
    shared_rows = []
    for identity in identities:
        shared = {field: identity[field] for field in fields}
        # The mock listener port is an isolation detail and may differ between
        # concurrently executed batches. Each repeat independently validates
        # that its recorded port matches the effective gateway config; compare
        # the response semantics here while preserving all other config fields.
        gateway = shared.get("mock_gateway")
        if isinstance(gateway, dict):
            gateway = dict(gateway)
            gateway.pop("port", None)
            shared["mock_gateway"] = gateway
        shared_rows.append(shared)
        canonical.add(json.dumps(shared, sort_keys=True, separators=(",", ":")))
    differing_fields = [
        field for field in fields
        if len({json.dumps(row[field], sort_keys=True, separators=(",", ":"))
                for row in shared_rows}) > 1
    ]
    return len(canonical) == 1, (
        f"unique shared identities={len(canonical)} across runs={len(identities)} "
        f"differing_fields={differing_fields}"
    )


def audit_uncapped_q1_flow(cfg: dict, stats: dict, flow_rows: list[dict],
                           execution_rows: list[dict] | None) -> tuple[bool, str]:
    """Reconcile uncapped Q1 transfers; this does not establish matched-dose claims."""
    policy = cfg.get("q1_policy")
    fields = ("amount", "requested_amount", "uncredited_amount", "remaining",
              "saved_total", "idle_total", "idle_uncredited_total", "reflow_pool_left",
              "reflow_consumed", "charged_invocations", "effective_cap", "flow_id",
              "candidate_id", "receiver_invocation_id", "time_ms")
    saved = consumed = previous_calls = previous_time = 0
    reservations = {}
    receiver_ids = set()
    campaign = cfg.get("campaign_id")
    starts = {row.get("invocation_id"): row for row in execution_rows or []
              if row.get("event") == "invocation_start" and row.get("executed") is True}
    if not flow_rows or flow_rows[-1].get("kind") != "campaign-final":
        return False, "uncapped Q1 requires a terminal campaign-final flow row"
    for index, row in enumerate(flow_rows):
        if any(type(row.get(key)) is not int or row[key] < 0 for key in fields):
            return False, f"uncapped Q1 malformed flow fields at row {index}"
        if not campaign or row.get("campaign_id") != campaign:
            return False, f"uncapped Q1 flow campaign identity mismatch at row {index}"
        if (row["effective_cap"] != 0 or row["charged_invocations"] < previous_calls
                or row["charged_invocations"] > stats["campaign_charged_calls"]
                or row["time_ms"] < previous_time):
            return False, f"uncapped Q1 flow cap/call/time inconsistency at row {index}"
        previous_calls, previous_time = row["charged_invocations"], row["time_ms"]
        kind, amount, flow_id = row.get("kind"), row["amount"], row["flow_id"]
        if kind == "campaign-final":
            if (index != len(flow_rows) - 1 or row.get("destination") != "none"
                    or any(row[key] != 0 for key in ("amount", "requested_amount",
                        "remaining", "flow_id", "candidate_id"))
                    or row["receiver_invocation_id"] != stats["campaign_charged_calls"]):
                return False, f"uncapped Q1 invalid final row at {index}"
        elif policy != "reflow":
            return False, "uncapped direct-service cannot transfer quota"
        elif kind == "consumed":
            receiver_id = row["receiver_invocation_id"]
            reservation = reservations.get(flow_id)
            if (row.get("destination") != "ordinary-mutation" or amount != 1
                    or row["requested_amount"] != 1 or not reservation
                    or reservation["candidate"] != row["candidate_id"]
                    or reservation["left"] <= 0 or receiver_id <= 0
                    or receiver_id in receiver_ids or receiver_id > row["charged_invocations"]):
                return False, f"uncapped Q1 invalid consumption at row {index}"
            if execution_rows is None:
                return False, "uncapped Q1 consumption requires the execution ledger"
            execution = starts.get(receiver_id, {})
            if (execution.get("campaign_id") != campaign
                    or execution.get("execution_kind") != "mutation"
                    or execution.get("q1_flow_id") != flow_id
                    or execution.get("q1_flow_source_candidate") != row["candidate_id"]):
                return False, f"uncapped Q1 receiver does not match executed invocation at row {index}"
            reservation["left"] -= 1
            if row["remaining"] != reservation["left"]:
                return False, f"uncapped Q1 reservation remainder mismatch at row {index}"
            receiver_ids.add(receiver_id)
            consumed += 1
        else:
            if (kind not in ("validation-closed-unused", "validation-converted-unused",
                             "ordinary-window-closed-unused", "candidate-unallocated")
                    or row.get("destination") != "ordinary-pool"
                    or amount != row["requested_amount"]
                    or row["receiver_invocation_id"] != 0 or row["candidate_id"] <= 0
                    or (amount and (flow_id <= 0 or flow_id in reservations))
                    or (not amount and flow_id != 0) or row["remaining"] != amount):
                return False, f"uncapped Q1 invalid release at row {index}"
            if amount:
                reservations[flow_id] = {"candidate": row["candidate_id"], "left": amount}
            saved += amount
        if (row["uncredited_amount"] != 0 or row["idle_total"] != 0
                or row["idle_uncredited_total"] != 0 or row["saved_total"] != saved
                or row["reflow_consumed"] != consumed
                or row["reflow_pool_left"] != saved - consumed):
            return False, f"uncapped Q1 running quota conservation failed at row {index}"
    expected = {"q1_saved_quota": saved, "q1_idle_quota": 0,
                "q1_idle_quota_uncredited": 0, "q1_reflow_consumed": consumed,
                "q1_reflow_pool_left": saved - consumed}
    if any(type(stats.get(key)) is not int or stats[key] != value for key, value in expected.items()):
        return False, "uncapped Q1 final quota counters do not match flow ledger"
    if flow_rows[-1]["charged_invocations"] != stats["campaign_charged_calls"]:
        return False, "uncapped Q1 final charged counter mismatch"
    if execution_rows is not None:
        linked = {row.get("invocation_id") for row in starts.values() if row.get("q1_flow_id", 0)}
        if linked != receiver_ids:
            return False, "uncapped Q1 execution/consumption receiver sets disagree"
    return True, "uncapped Q1 per-event flow conservation verified; matched-dose inference unavailable"


def campaign_inference_scope(cfg: dict) -> dict:
    """Describe the experimental resource control, without claiming an effect."""
    uncapped = cfg.get("campaign_stop_mode") == "wallclock" and cfg.get("campaign_call_budget") == 0
    return {
        "resource_basis": "elapsed-time" if cfg.get("campaign_stop_mode") == "wallclock" else "target-invocations",
        "matched_call_budget_available": not uncapped and cfg.get("campaign_call_budget", 0) > 0,
        "fixed_call_allocation_eligible": not uncapped and cfg.get("campaign_call_budget", 0) > 0,
        "inference_limits": (["No matched total-call budget; Q1 allocation comparison is not established by this audit."]
                             if uncapped and cfg.get("q1_policy", "none") != "none" else []),
    }


def audit_campaign_dose(
    cfg: dict,
    stats: dict,
    executed_count: int | None = None,
    flow_rows: list[dict] | None = None,
    *,
    require_cap: bool = True,
    execution_rows: list[dict] | None = None,
) -> tuple[bool, str]:
    """Check policy-specific dose, conservation, and optionally cap completion."""
    budget = stats.get("campaign_call_budget")
    charged = stats.get("campaign_charged_calls")
    exhausted = stats.get("campaign_budget_exhausted")
    policy = cfg.get("q1_policy")
    common_counters = (budget, charged, exhausted)
    if not all(isinstance(value, int) for value in common_counters):
        return False, f"missing/non-integer campaign counters: {common_counters!r}"
    if budget < 0:
        return False, f"invalid campaign budget: {budget}"

    # A zero budget is an explicit disabled cap, never a matched invocation
    # dose. Q1a/c/d can retain independently audited transfers in elapsed-time
    # campaigns. Q1b needs a finite cap to give quota parking operational force.
    if budget == 0:
        if policy != "none":
            if policy == "no-reflow":
                return False, "uncapped Q1b is invalid: quota parking requires a finite campaign budget"
            if (policy not in ("direct-service", "reflow") or require_cap
                    or cfg.get("campaign_stop_mode") != "wallclock"
                    or type(cfg.get("campaign_duration_sec")) is not int
                    or cfg["campaign_duration_sec"] <= 0
                    or cfg.get("campaign_resource_basis", "elapsed-time") != "elapsed-time"
                    or cfg.get("campaign_call_budget") != 0 or exhausted != 0
                    or charged < 0 or (executed_count is not None and executed_count != charged)):
                return False, "uncapped Q1 requires a consistent elapsed-time campaign, with no fixed-dose completion claim"
            return audit_uncapped_q1_flow(cfg, stats, flow_rows or [], execution_rows)
        if cfg.get("campaign_call_budget", 0) != 0:
            return False, f"run-config campaign budget disagrees with stats: {cfg.get('campaign_call_budget')} != 0"
        if exhausted != 0:
            return False, f"uncapped campaign must report exhausted=0, got {exhausted}"
        q1_values = [stats.get(key, 0) for key in (
            "q1_saved_quota", "q1_idle_quota", "q1_reflow_consumed",
            "q1_reflow_pool_left", "q1_idle_quota_uncredited",
        )]
        if any(not isinstance(value, int) or value != 0 for value in q1_values):
            return False, f"uncapped non-Q1 run has nonzero/invalid Q1 counters: {q1_values}"
        execution_ok = executed_count is None or executed_count == charged
        if not execution_ok:
            return False, f"uncapped execution ledger mismatch: executed={executed_count} charged={charged}"
        # Schema-v5 always emits one campaign-final row so even an uncapped
        # run has a terminal ledger record. That zero-valued summary is not a
        # quota transfer. Reject actual flow events, duplicate/malformed
        # terminal rows, or a terminal row that contradicts the counters.
        if flow_rows:
            finals = [row for row in flow_rows if row.get("kind") == "campaign-final"]
            nonterminal = [row for row in flow_rows if row.get("kind") != "campaign-final"]
            if nonterminal or len(finals) != 1:
                return False, (
                    "uncapped non-Q1 run has unexpected quota-flow events: "
                    f"nonterminal={len(nonterminal)} campaign_final={len(finals)}"
                )
            final = finals[0]
            zero_fields = (
                "amount", "requested_amount", "uncredited_amount", "remaining",
                "saved_total", "idle_total", "idle_uncredited_total",
                "reflow_pool_left", "reflow_consumed", "effective_cap",
            )
            invalid = {
                key: final.get(key) for key in zero_fields
                if not isinstance(final.get(key), int) or final.get(key) != 0
            }
            if final.get("charged_invocations") != charged:
                invalid["charged_invocations"] = final.get("charged_invocations")
            if final.get("destination", "none") != "none":
                invalid["destination"] = final.get("destination")
            if invalid:
                return False, f"uncapped campaign-final row disagrees with zero Q1 counters: {invalid}"
        return True, (
            f"policy=none uncapped charged={charged} execution_count={executed_count}; "
            "budget_disabled=True; quota_counters_zero=True; execution_ledger_consistent=True"
        )

    quota_keys = (
        "q1_saved_quota", "q1_idle_quota", "q1_reflow_consumed",
        "q1_reflow_pool_left", "q1_idle_quota_uncredited",
    )
    if policy in ("no-reflow", "reflow", "direct-service"):
        missing = [key for key in quota_keys if not isinstance(stats.get(key), int)]
        if missing:
            return False, f"missing/non-integer Q1 quota counters: {missing}"
        saved, idle, reflow_used, reflow_left, uncredited = (
            stats[key] for key in quota_keys
        )
    elif policy == "none":
        # Core arms do not implement Q1 quota accounting. Older campaign
        # archives may omit these Q1-only fields; validate them when present.
        invalid = [key for key in quota_keys
                   if key in stats and not isinstance(stats[key], int)]
        if invalid:
            return False, f"non-integer optional quota counters: {invalid}"
        saved, idle, reflow_used, reflow_left, uncredited = (
            stats.get(key, 0) for key in quota_keys
        )
    else:
        return False, f"unrecognized Q1 policy: {policy!r}"

    if policy == "no-reflow":
        expected_charged = max(budget - idle, 0)
        quota_ok = (
            saved == idle and reflow_used == 0 and reflow_left == 0
            and charged <= expected_charged and charged + idle <= budget
        )
    elif policy == "reflow":
        expected_charged = budget
        quota_ok = idle == 0 and uncredited == 0 and saved == reflow_used + reflow_left
    elif policy in ("direct-service", "none"):
        expected_charged = budget
        quota_ok = saved == 0 and idle == 0 and reflow_used == 0 and reflow_left == 0 and uncredited == 0

    flow_rows = flow_rows or []
    final_rows = [row for row in flow_rows if row.get("kind") == "campaign-final"]
    final = final_rows[-1] if final_rows else {}
    release_rows = [row for row in flow_rows if row.get("kind") not in ("consumed", "campaign-final")]
    flow_saved = sum(row.get("amount", 0) for row in release_rows if isinstance(row.get("amount", 0), int))
    flow_uncredited = sum(row.get("uncredited_amount", 0) for row in release_rows if isinstance(row.get("uncredited_amount", 0), int))
    if policy == "none" and not flow_rows:
        # Core arms in older archives have no Q1 flow ledger at all. Their
        # campaign dose is still checked above; absence of an inapplicable Q1
        # ledger is valid only when all observed/implicit Q1 counters are zero.
        ledger_ok = all(value == 0 for value in
                        (saved, idle, reflow_used, reflow_left, uncredited))
    else:
        ledger_ok = (
            len(final_rows) == 1
            and final.get("charged_invocations") == charged
            and final.get("saved_total") == saved
            and final.get("idle_total") == idle
            and final.get("reflow_consumed") == reflow_used
            and final.get("reflow_pool_left") == reflow_left
            and final.get("effective_cap") == expected_charged
            and flow_saved == saved
            and flow_uncredited == uncredited
        )
    execution_ok = executed_count is None or executed_count == charged
    cap_state_ok = (
        charged == expected_charged and exhausted == 1
        if require_cap
        else charged <= expected_charged and exhausted in (0, 1)
        and (exhausted == 0 or charged == expected_charged)
    )
    ok = cap_state_ok and quota_ok and ledger_ok and execution_ok
    return ok, (
        f"policy={policy} charged={charged} expected={expected_charged} exhausted={exhausted}; "
        f"require_cap={require_cap}; "
        f"quota_consistent={quota_ok}; execution_count={executed_count}; ledger_consistent={ledger_ok}; "
        f"flow_saved={flow_saved} saved={saved}; flow_uncredited={flow_uncredited} uncredited={uncredited}; "
        f"final_rows={len(final_rows)}"
    )


def audit_wallclock_budget_censor(cfg: dict, end_cfg: dict, stats: dict) -> tuple[bool, str]:
    """Reconcile the wallclock run's cap-censor flag and exhaustion time."""
    if cfg.get("campaign_stop_mode", "call-budget") != "wallclock":
        return True, "not a wallclock campaign"
    exhausted = stats.get("campaign_budget_exhausted")
    censored = end_cfg.get("campaign_budget_censored")
    exhausted_ms = end_cfg.get("campaign_budget_exhausted_time_ms")
    start_ms = cfg.get("start_time_ms")
    end_ms = end_cfg.get("end_time_ms")
    if exhausted not in (0, 1) or censored is not (exhausted == 1):
        return False, f"budget censor mismatch: stats_exhausted={exhausted!r} end_censored={censored!r}"
    if not all(isinstance(value, int) for value in (exhausted_ms, start_ms, end_ms)):
        return False, "missing/integer-invalid wallclock budget timestamps"
    if exhausted and not (start_ms <= exhausted_ms <= end_ms):
        return False, f"budget exhausted outside campaign: start={start_ms} exhausted={exhausted_ms} end={end_ms}"
    if not exhausted and exhausted_ms != 0:
        return False, f"unexhausted campaign has exhaustion timestamp {exhausted_ms}"
    idle_ms = end_ms - exhausted_ms if exhausted else 0
    return True, f"budget_censored={bool(censored)} exhausted_time_ms={exhausted_ms} post_budget_idle_ms={idle_ms}"


def audit_wallclock_budget_role(cfg: dict, stats: dict) -> tuple[bool, str]:
    """Separate an intentional Q1b parked-quota stop from a binding run cap."""
    if cfg.get("campaign_stop_mode", "call-budget") != "wallclock":
        return True, "not a fixed-wallclock campaign"
    exhausted = stats.get("campaign_budget_exhausted")
    if stats.get("campaign_call_budget") == 0:
        if cfg.get("q1_policy") == "no-reflow":
            return False, "uncapped Q1b cannot enforce quota parking"
        return exhausted == 0, "total call cap disabled; elapsed-time endpoint only, no matched-dose comparison"
    if exhausted == 0:
        return True, "common call cap remained nonbinding"
    if exhausted != 1:
        return False, f"invalid campaign_budget_exhausted={exhausted!r}"

    budget = stats.get("campaign_call_budget")
    charged = stats.get("campaign_charged_calls")
    policy = cfg.get("q1_policy", "none")
    if policy == "no-reflow":
        idle = stats.get("q1_idle_quota")
        if not all(isinstance(value, int) for value in (budget, charged, idle)):
            return False, "Q1b parked-quota stop is missing integer budget counters"
        expected_cap = max(budget - idle, 0)
        if idle > 0 and idle <= budget and charged == expected_cap and charged + idle == budget:
            return True, f"planned Q1b quota parking: charged={charged} parked={idle} nominal={budget}"
        return False, (
            "Q1b exhausted without conserved parked quota: "
            f"charged={charged} parked={idle} nominal={budget} expected_cap={expected_cap}"
        )

    return False, (
        "shared call cap bound before the wallclock deadline; fixed-time run is censored "
        f"(policy={policy!r}, charged={charged!r}, budget={budget!r})"
    )


def audit_q1_mechanism_evidence(cfg: dict, stats: dict) -> tuple[bool, str]:
    """Reject Q1 runs whose configured allocation mechanism never activated."""
    policy = cfg.get("q1_policy", "none")
    if policy == "none":
        return True, "not a Q1 arm"
    if policy == "direct-service":
        count = stats.get("provisional_admitted")
        ok = isinstance(count, int) and count > 0
        return ok, f"direct_service_provisional_admissions={count!r}"
    if policy == "no-reflow":
        idle = stats.get("q1_idle_quota")
        ok = isinstance(idle, int) and idle > 0
        return ok, f"parked_quota={idle!r}"
    if policy == "reflow":
        consumed = stats.get("q1_reflow_consumed")
        if not isinstance(consumed, int) or consumed <= 0:
            return False, f"reflow_consumed={consumed!r}"
        if cfg.get("code_retain"):
            retained = stats.get("code_retain_admitted")
            return (isinstance(retained, int) and retained > 0), (
                f"reflow_consumed={consumed} code_retain_admitted={retained!r}"
            )
        return True, f"reflow_consumed={consumed}"
    return False, f"unknown Q1 policy: {policy!r}"


def audit_resets(resets: list[dict], executions: list[dict], termination_reason: str) -> dict:
    """Separate failed resets for executed calls from cancellation of refused calls.

    A run_target request can be refused at the wall-clock/call limit. Its
    attempt may have a cancelled reset record even though no target call was
    executed. Treat that as a censored request only when the event log proves
    the same attempt was refused for the configured resource limit.
    """
    executed_starts = [
        row for row in executions
        if row.get("event") == "invocation_start" and row.get("executed") is True
    ]
    executed_attempt_counts = Counter(
        row.get("attempt_id") for row in executed_starts
        if row.get("attempt_id") is not None
    )
    executed_attempts = set(executed_attempt_counts)
    missing_execution_attempt_ids = sum(row.get("attempt_id") is None for row in executed_starts)
    invocation_starts = {
        row.get("invocation_id"): row for row in executed_starts
        if row.get("invocation_id") is not None
    }
    missing_invocation_ids = sum(row.get("invocation_id") is None for row in executed_starts)
    end_rows_by_invocation: dict[object, list[dict]] = {}
    for row in executions:
        if row.get("event") == "invocation_end" and row.get("invocation_id") is not None:
            end_rows_by_invocation.setdefault(row["invocation_id"], []).append(row)
    unmatched_end_counts = {
        invocation_id: len(end_rows_by_invocation.get(invocation_id, []))
        for invocation_id in invocation_starts
        if len(end_rows_by_invocation.get(invocation_id, [])) != 1
    }
    refused_attempts = {
        row.get("attempt_id"): row for row in executions
        if row.get("event") == "invocation_refused" and row.get("executed") is False
        and row.get("attempt_id") is not None
    }
    succeeded = sum(row.get("success") is True for row in resets)
    invocation_resets_by_attempt: dict[object, list[dict]] = {}
    bootstrap_resets_by_execution: dict[object, list[dict]] = {}
    for row in resets:
        attempt_id = row.get("attempt_id")
        if row.get("stage") == "invocation":
            if attempt_id is not None:
                invocation_resets_by_attempt.setdefault(attempt_id, []).append(row)
        elif row.get("stage") == "pre-forkserver":
            execution_id = row.get("execution_id")
            if execution_id is not None:
                bootstrap_resets_by_execution.setdefault(execution_id, []).append(row)

    expected_terminal_cancellations = []
    unexplained_failures = []
    executed_call_failures = []
    for row in resets:
        if row.get("success") is True:
            continue
        attempt_id = row.get("attempt_id")
        if attempt_id in executed_attempts:
            # Count it after linking the reset to the call; the first call's
            # reset is the pre-forkserver bootstrap and uses a different ID.
            continue
        refusal = refused_attempts.get(attempt_id)
        if (
            refusal is not None
            and refusal.get("fault") == "resource-limit-not-executed"
            and row.get("cancelled") is True
            and row.get("system_status") == 15
            and row.get("stage") == "invocation"
            and termination_reason in ("signal-or-timeout", "wallclock-duration")
        ):
            expected_terminal_cancellations.append(row)
        else:
            unexplained_failures.append(row)

    # The first target call uses the successful pre-forkserver reset. Later
    # calls reset immediately before invocation_start, with the same attempt_id.
    # Reset records have their own attempt sequence, so the bootstrap reset is
    # intentionally associated by the first call's execution_id_before.
    ordered_starts = sorted(
        (row for row in executed_starts if row.get("invocation_id") is not None),
        key=lambda row: row["invocation_id"],
    )
    matched_reset_rows: dict[object, list[dict]] = {}
    missing_invocation_resets = []
    duplicate_invocation_reset_counts = {}
    reset_identity_mismatches = []
    if ordered_starts:
        first = ordered_starts[0]
        first_exec_id = first.get("execution_id_before")
        bootstrap = bootstrap_resets_by_execution.get(first_exec_id, [])
        if len(bootstrap) == 1:
            matched_reset_rows[first.get("invocation_id")] = bootstrap
        elif not bootstrap:
            missing_invocation_resets.append(first.get("attempt_id"))
        else:
            duplicate_invocation_reset_counts[first.get("attempt_id")] = len(bootstrap)

        for start in ordered_starts[1:]:
            attempt_id = start.get("attempt_id")
            candidates = invocation_resets_by_attempt.get(attempt_id, [])
            if len(candidates) == 1:
                reset = candidates[0]
                if reset.get("execution_id") == start.get("execution_id_before"):
                    matched_reset_rows[start.get("invocation_id")] = candidates
                else:
                    reset_identity_mismatches.append({
                        "attempt_id": attempt_id,
                        "expected_execution_id": start.get("execution_id_before"),
                        "reset_execution_id": reset.get("execution_id"),
                    })
                    missing_invocation_resets.append(attempt_id)
            elif not candidates:
                missing_invocation_resets.append(attempt_id)
            else:
                duplicate_invocation_reset_counts[attempt_id] = len(candidates)

    # Every failed reset associated with an executed call makes that repeat
    # ineligible, including the bootstrap reset assigned to its first call.
    for rows in matched_reset_rows.values():
        if any(row.get("success") is not True for row in rows):
            executed_call_failures.extend(row for row in rows if row.get("success") is not True)

    duplicate_executed_attempt_ids = {
        attempt_id: count for attempt_id, count in executed_attempt_counts.items()
        if count != 1
    }
    duplicate_reset_records = sum(
        len(rows) - 1 for rows in invocation_resets_by_attempt.values() if len(rows) > 1
    )
    wrong_stage_reset_records_for_executed_attempts = sum(
        row.get("stage") != "invocation"
        for row in resets
        if row.get("attempt_id") in executed_attempts
    )
    exact_successful_reset_attempts = sum(
        len(matched_reset_rows.get(invocation_id, [])) == 1
        and matched_reset_rows[invocation_id][0].get("success") is True
        for invocation_id in invocation_starts
    )
    all_executed_invocations_reset = (
        bool(executed_starts)
        and missing_execution_attempt_ids == 0
        and missing_invocation_ids == 0
        and not duplicate_executed_attempt_ids
        and not unmatched_end_counts
        and not missing_invocation_resets
        and not duplicate_invocation_reset_counts
        and wrong_stage_reset_records_for_executed_attempts == 0
        and not executed_call_failures
        and exact_successful_reset_attempts == len(invocation_starts)
    )
    return {
        "executed_invocation_count": len(executed_starts),
        "executed_unique_attempt_id_count": len(executed_attempts),
        "executed_starts_missing_attempt_id": missing_execution_attempt_ids,
        "executed_starts_missing_invocation_id": missing_invocation_ids,
        "duplicate_executed_attempt_ids": duplicate_executed_attempt_ids,
        "executed_invocations_missing_or_duplicate_end": unmatched_end_counts,
        "successful_reset_count": succeeded,
        "executed_invocation_reset_failures": len(executed_call_failures),
        "executed_invocations_with_exactly_one_successful_pre_reset": exact_successful_reset_attempts,
        "executed_invocations_missing_invocation_reset": len(missing_invocation_resets),
        "missing_invocation_reset_attempt_ids": sorted(missing_invocation_resets, key=str),
        "reset_execution_id_mismatches": reset_identity_mismatches,
        "duplicate_invocation_reset_records": duplicate_reset_records,
        "duplicate_invocation_reset_counts_by_attempt": duplicate_invocation_reset_counts,
        "wrong_stage_reset_records_for_executed_attempts": wrong_stage_reset_records_for_executed_attempts,
        "terminal_refused_attempt_cancellations": len(expected_terminal_cancellations),
        "unexplained_reset_failures": len(unexplained_failures),
        "all_executed_invocations_reset": all_executed_invocations_reset,
        "all_reset_failures_explained_by_refused_terminal_attempts": not unexplained_failures,
        "eligible": (
            bool(executed_starts)
            and all_executed_invocations_reset
            and not duplicate_invocation_reset_counts
            and not executed_call_failures
            and not unexplained_failures
        ),
    }


def expected_config(label: str) -> dict[str, object]:
    # Arm labels use the numeric threshold as their trailing suffix (for
    # example q1a512). Strip only that number so the treatment semantics are
    # identical across thresholds.
    suffix = label.rstrip("0123456789")
    semantics: dict[str, dict[str, object]] = {
        "pvstop": {"salvage_enabled": True, "pv_early_stop_k": 32, "no_llm": False, "admission_mode": "gate"},
        "salvage": {"salvage_enabled": True, "pv_early_stop_k": 0, "no_llm": False, "admission_mode": "gate"},
        "nollm": {"no_llm": True, "admission_mode": "gate"},
        "wrapgate": {"salvage_enabled": False, "no_llm": False, "admission_mode": "gate", "calibration": False},
        "native": {"admission_mode": "native", "provisional_enabled": False, "shadow_enabled": False},
        "calibrated": {"calibration": True, "state_select_override": "calibrated"},
        "cal_ewma": {"calibration": True, "state_select_override": "ewma"},
        "cal_run_rate": {"calibration": True, "state_select_override": "run_rate"},
        "q1a": {"q1_policy": "direct-service"},
        "q1b": {"q1_policy": "no-reflow"},
        "q1c": {"q1_policy": "reflow"},
        "q1d": {"q1_policy": "reflow", "code_retain": True},
        "ordmatch": {"ordinary_budget": True, "salvage_enabled": True},
    }
    return semantics.get(suffix, {})


def audit_shared_controls(cfg: dict, threshold: int, profile: str = "smoke") -> tuple[bool, str]:
    expected = {"threshold_resolved": threshold, **AUDIT_CONTROL_PROFILES[profile]}
    actual = {field: cfg.get(field) for field in expected}
    ok = all(type(actual[field]) is int and actual[field] == value
             for field, value in expected.items())
    return ok, f"profile={profile} expected={expected} actual={actual}"


def audit_result_dir(
    result_dir: Path, target: str = "bftpd", threshold: int = 1,
    protocol: str | None = None,
    max_runtime_ms: int = DEFAULT_CAMPAIGN_RUNTIME_MS,
    gateway: str = "mock",
    profile: str = "smoke",
) -> tuple[list[tuple[str, bool, str]], list[dict]]:
    if gateway not in {"mock", "live"}:
        raise ValueError("gateway must explicitly be mock or live")
    if profile not in AUDIT_CONTROL_PROFILES:
        raise ValueError("unknown audit profile: " + profile)
    checks: list[tuple[str, bool, str]] = []
    metrics: list[dict] = []
    result_prefix = f"results-{target}_ablation_"
    label = result_dir.name.removeprefix(result_prefix).rsplit("_", 1)[0]
    expected_protocol = protocol or PROTOCOL_BY_TARGET[target]
    manifests = result_dir / ".result_manifest.tsv"
    statuses = result_dir / ".sample_status"
    summary_path = result_dir / "run_summary.csv"
    add_check(checks, "manifest exists", manifests.is_file())
    add_check(checks, "run_summary exists", summary_path.is_file())
    if not manifests.is_file() or not summary_path.is_file():
        return checks, metrics

    with manifests.open(newline="") as stream:
        manifest_rows = list(csv.DictReader(stream, delimiter="\t"))
    with summary_path.open(newline="") as stream:
        summary_rows = list(csv.DictReader(stream))
    add_check(checks, "three manifest samples", len(manifest_rows) == 3, f"n={len(manifest_rows)}")
    add_check(checks, "three run_summary rows", len(summary_rows) == 3, f"n={len(summary_rows)}")
    mapping_ok, mapping_detail = audit_repeat_mapping(manifest_rows, summary_rows)
    add_check(checks, "three unique archive/run/container/summary identities map one-to-one",
              mapping_ok, mapping_detail)
    status_mapping_ok, status_mapping_detail = audit_status_mapping(manifest_rows, statuses)
    add_check(checks, "three unique status identities map one-to-one",
              status_mapping_ok, status_mapping_detail)
    summaries = {row.get("source", ""): row for row in summary_rows}
    scopes: set[str] = set()
    identities: set[tuple] = set()
    shared_identities: list[dict] = []
    expected = expected_config(label)

    for item in manifest_rows:
        archive_name = item.get("archive_name", "")
        archive = result_dir / archive_name
        sample_name = archive_name
        sample_checks: list[tuple[str, bool, str]] = []
        status_path = statuses / f"{sample_name}.status"
        status = parse_kv(status_path) if status_path.is_file() else {}
        add_check(sample_checks, f"{sample_name}: status file", status_path.is_file())
        add_check(sample_checks, f"{sample_name}: status identity matches manifest",
                  status.get("archive_name") == archive_name
                  and status.get("container_id") == item.get("container_id"),
                  f"status_archive={status.get('archive_name')} manifest_archive={archive_name} status_container={status.get('container_id')} manifest_container={item.get('container_id')}")
        add_check(sample_checks, f"{sample_name}: completed exit 0", status.get("status") == "completed" and status.get("exit_code") == "0" and status.get("oom_killed") == "false", str(status))
        add_check(sample_checks, f"{sample_name}: archive readable", archive.is_file())
        if not archive.is_file():
            checks.extend(sample_checks)
            continue

        try:
            with tarfile.open(archive, "r:gz") as tf:
                names = tf.getnames()
                prefix = f"out-{target}-loopfuzz/"

                def member(suffix: str) -> bytes:
                    path = find_unique_archive_member(names, prefix, suffix)
                    extracted = tf.extractfile(path)
                    if extracted is None:
                        raise ValueError(f"archive member is not readable: {path}")
                    return extracted.read()

                configs = read_jsonl(member("run-config.jsonl"))
                resets = read_jsonl(member("reset-events.jsonl"))
                executions = read_jsonl(member("execution-events.jsonl"))
                flow_path = find_unique_archive_member(names, prefix, "q1-budget-flow.jsonl", optional=True)
                if flow_path:
                    flow_member = tf.extractfile(flow_path)
                    if flow_member is None:
                        raise ValueError(f"archive member is not readable: {flow_path}")
                    flow_rows = read_jsonl(flow_member.read())
                else:
                    # Let the policy-specific final-ledger check report missing telemetry.
                    flow_rows = []
                coverage_schema, coverage_directory = coverage_archive_schema(names, prefix)
                if coverage_schema == SAMPLED_COVERAGE_SCHEMA:
                    sampled_audit = audit_sampled_coverage_archive(member, target, names)
                    v4_audit = None
                    terminal = json.loads(member(coverage_directory + "/terminal.json"))
                    coverage_scope = json.loads(member(coverage_directory + "/scope.json"))
                else:
                    sampled_audit = None
                    v4_audit = audit_v4_coverage_archive(tf, prefix, target)
                    terminal = json.loads(member(coverage_directory + "/terminal.json"))
                    coverage_scope = json.loads(member(coverage_directory + "/scope.json"))
                stats = parse_stats(member("fuzzer_stats"))
                live_audit = audit_live_gateway(
                    member, names, prefix, configs[0], configs[-1], profile=profile,
                    arm_label=label,
                ) if gateway == "live" and configs else None
        except Exception as exc:
            add_check(sample_checks, f"{sample_name}: archive parse", False, str(exc))
            checks.extend(sample_checks)
            continue

        add_check(sample_checks, f"{sample_name}: config has start/end", len(configs) == 2 and configs[0].get("event") == "run_config" and configs[1].get("event") == "run_config" and configs[0].get("phase") == "start" and configs[1].get("phase") == "end", f"rows={len(configs)} phases={[r.get('phase') for r in configs]}")
        cfg = configs[0] if configs else {}
        end_cfg = configs[-1] if configs else {}
        campaign_ids = {row.get("campaign_id") for row in configs}
        add_check(sample_checks, f"{sample_name}: campaign/config identity", len(campaign_ids) == 1 and None not in campaign_ids and cfg.get("config_hash") == end_cfg.get("config_hash"))
        phase_identity_fields = (
            "target", "target_sha256", "fuzzer", "fuzzer_commit", "fuzzer_sha256",
            "loopfuzz_source_sha256",
            "seeds_sha256", "image_digest", "protocol_name", "orig_cmdline",
            "campaign_call_budget",
            "threshold_requested", "threshold_resolved",
            "scheduler_warmup_max_selections", "episode_energy_cap",
            "cal_reward_window_invocations", "mock_gateway",
        )
        if gateway == "live":
            phase_identity_fields = tuple(field for field in phase_identity_fields if field != "mock_gateway") + LIVE_GATEWAY_FIELDS
        phase_identity_fields += tuple(field for field in CONDITIONAL_SHARED_FIELDS
                                       if field in cfg or field in end_cfg)
        phase_identity_ok = all(
            field in cfg and field in end_cfg
            and cfg[field] is not None and cfg[field] != ""
            and cfg[field] == end_cfg[field]
            for field in phase_identity_fields
        )
        phase_identity_diff = {
            field: (cfg.get(field), end_cfg.get(field))
            for field in phase_identity_fields if cfg.get(field) != end_cfg.get(field)
        }
        add_check(sample_checks, f"{sample_name}: start/end pinned identity", phase_identity_ok,
                  json.dumps(phase_identity_diff, sort_keys=True) if phase_identity_diff else "all pinned fields match")
        campaign_end_ok, campaign_end_detail = audit_campaign_integrity_termination(
            cfg, end_cfg, max_runtime_ms,
        )
        add_check(sample_checks, f"{sample_name}: campaign ended at call cap or configured timeout",
                  campaign_end_ok, campaign_end_detail)
        add_check(sample_checks, f"{sample_name}: target and threshold match request",
                  cfg.get("target") == target
                  and cfg.get("threshold_requested") == threshold
                  and cfg.get("threshold_resolved") == threshold,
                  f"target={cfg.get('target')} expected_target={target} requested={cfg.get('threshold_requested')} resolved={cfg.get('threshold_resolved')} expected_threshold={threshold}")
        fuzzer_protocol_ok, fuzzer_protocol_detail = audit_fuzzer_protocol(
            cfg, expected_protocol,
        )
        add_check(sample_checks, f"{sample_name}: fuzzer protocol matches target and -P argv",
                  fuzzer_protocol_ok, fuzzer_protocol_detail)
        source_sha = cfg.get("loopfuzz_source_sha256")
        source_sha_ok = isinstance(source_sha, str) and re.fullmatch(r"[0-9a-f]{64}", source_sha) is not None
        add_check(sample_checks, f"{sample_name}: LoopFuzz build source fingerprint recorded",
                  source_sha_ok, f"loopfuzz_source_sha256={source_sha!r}")
        if gateway == "mock":
            add_check(sample_checks, f"{sample_name}: mock config embedded", isinstance(cfg.get("mock_gateway"), dict) and int(cfg.get("mock_gateway", {}).get("port", 0)) > 0)
        else:
            add_check(sample_checks, f"{sample_name}: live exchanges/model/usage/config audited", bool(live_audit) and live_audit["eligible"], json.dumps(live_audit, sort_keys=True))
        for key, value in expected.items():
            add_check(sample_checks, f"{sample_name}: expected {key}", cfg.get(key) == value, f"expected={value!r} actual={cfg.get(key)!r}")

        starts = Counter(row.get("invocation_id") for row in executions if row.get("event") == "invocation_start")
        ends = Counter(row.get("invocation_id") for row in executions if row.get("event") == "invocation_end")
        invocation_pair_ok, invocation_pair_detail = audit_invocation_pairs(executions)
        add_check(sample_checks, f"{sample_name}: unique invocation start/end coordinates",
                  invocation_pair_ok, invocation_pair_detail)
        reset_audit = audit_resets(resets, executions, end_cfg.get("termination_reason", ""))
        add_check(sample_checks, f"{sample_name}: executed calls reset; terminal refusals accounted",
                  reset_audit["eligible"], json.dumps(reset_audit, sort_keys=True))
        add_check(sample_checks, f"{sample_name}: invocation pairs", starts == ends and bool(starts), f"starts={sum(starts.values())} ends={sum(ends.values())}")
        if profile == "arm-default":
            add_check(sample_checks, f"{sample_name}: replay has no smoke truncation",
                      terminal.get("replay_truncated", False) is False)
        if coverage_schema == SAMPLED_COVERAGE_SCHEMA:
            bounded_smoke = (terminal.get("replay_truncated") is True
                             and terminal.get("smoke_mode") is True
                             and terminal.get("replay_input_limit") == terminal.get("n_replayed")
                             and terminal.get("planned_n_replayed", 0) > terminal.get("n_replayed", 0))
            rejection_rows = ((sampled_audit or {}).get("server_rejected_inputs") or [])
            rejection_names = {row.get("filename") for row in rejection_rows}
            unexplained_replays = [row for row in terminal.get("incomplete_replays", [])
                                   if row.get("filename") not in rejection_names]
            anomaly_kinds = set((terminal.get("replay_anomalies", {}).get("kinds") or {}))
            explained_rejection = (
                bool(rejection_rows) and not unexplained_replays and
                terminal.get("acceptance") == "incomplete" and
                terminal.get("coverage_complete") is False and
                anomaly_kinds <= {"client-exit-2"} and
                terminal.get("replay_anomalies", {}).get("total") == len(rejection_rows))
            coverage_status_ok = (
                terminal.get("acceptance") == "incomplete" and
                terminal.get("coverage_complete") is False and
                bounded_smoke
                if bounded_smoke else
                (terminal.get("acceptance") == "complete" and
                 terminal.get("coverage_complete") is True) or
                explained_rejection
            )
            add_check(sample_checks, f"{sample_name}: sampled coverage-v5 replay evidence audited",
                      terminal.get("schema_version") == SAMPLED_COVERAGE_SCHEMA
                      and coverage_status_ok
                      and terminal.get("all_reset_commands_succeeded") is True
                      and terminal.get("fixed_execution_coordinates_valid") is True
                      and terminal.get("n_unreplayable_ledger_entries") == 0
                      and (not terminal.get("incomplete_replays") or explained_rejection)
                      and (terminal.get("replay_anomalies", {}).get("total") == 0
                           or explained_rejection)
                      and terminal.get("unexpected_snapshot_decrease") is False
                      and sampled_audit is not None and sampled_audit.get("ok") is True,
                      f"acceptance={terminal.get('acceptance')} replayed={terminal.get('n_replayed')}/"
                      f"{terminal.get('planned_n_replayed', terminal.get('n_replayed'))} "
                      f"checkpoints={terminal.get('n_coverage_checkpoints')} "
                      f"server_rejected={len(rejection_rows)} "
                      f"branches={len(terminal.get('covered_branch_ids', []))}")
        else:
            add_check(sample_checks, f"{sample_name}: coverage-v4 complete",
                      terminal.get("schema_version") == "loopfuzz-coverage-v4"
                      and terminal.get("acceptance") == "complete"
                      and terminal.get("coverage_complete") is True
                      and terminal.get("all_reset_commands_succeeded") is True
                      and terminal.get("fixed_execution_coordinates_valid") is True
                      and terminal.get("n_unreplayable_ledger_entries") == 0
                      and terminal.get("incomplete_replays") == []
                      and terminal.get("replay_anomalies", {}).get("total") == 0
                      and terminal.get("unexpected_snapshot_decrease") is False,
                      f"acceptance={terminal.get('acceptance')} branches={len(terminal.get('covered_branch_ids', []))}")
            if v4_audit is not None:
                add_check(sample_checks, f"{sample_name}: v4 deep artifact audit",
                          v4_audit.get("ok") is True,
                          f"inputs={v4_audit.get('inputs')} branches={v4_audit.get('branches')} "
                          f"frame_gap_inputs={len(v4_audit.get('frame_gap_inputs') or [])}")
        add_check(sample_checks, f"{sample_name}: replay scope/version identity",
                  coverage_scope.get("schema_version") == terminal.get("schema_version") == coverage_schema
                  and coverage_scope.get("scope_sha256") == terminal.get("scope_sha256")
                  and bool(coverage_scope.get("replay_harness_version")),
                  f"scope={coverage_scope.get('scope_sha256')} replay={coverage_scope.get('replay_harness_version')}")
        scopes.add(terminal.get("scope_sha256", ""))
        identities.add((
            cfg.get("target_sha256"), cfg.get("fuzzer_sha256"), cfg.get("seeds_sha256"),
            cfg.get("loopfuzz_source_sha256"),
            cfg.get("image_digest"), terminal.get("scope_sha256"),
            cfg.get("campaign_call_budget"), cfg.get("threshold_resolved"),
            cfg.get("scheduler_warmup_max_selections"), cfg.get("episode_energy_cap"),
            cfg.get("cal_reward_window_invocations"),
        ))

        charged = stats.get("campaign_charged_calls")
        budget_exhausted = stats.get("campaign_budget_exhausted")
        config_budget = cfg.get("campaign_call_budget")
        stats_budget = stats.get("campaign_call_budget")
        budget_consistent = (
            isinstance(config_budget, int) and config_budget >= 0
            and isinstance(stats_budget, int) and stats_budget == config_budget
        )
        add_check(sample_checks, f"{sample_name}: campaign-call budget matches run configuration",
                  budget_consistent,
                  f"config={config_budget} stats={stats_budget}")
        actual_calls = sum(row.get("event") == "invocation_start" and row.get("executed") is True for row in executions)
        dose_accounted_ok, dose_account_detail = audit_campaign_dose(
            cfg, stats, actual_calls, flow_rows, require_cap=False, execution_rows=executions,
        )
        add_check(sample_checks, f"{sample_name}: charged calls and policy ledgers are consistent",
                  dose_accounted_ok, dose_account_detail)
        censor_ok, censor_detail = audit_wallclock_budget_censor(cfg, end_cfg, stats)
        add_check(sample_checks, f"{sample_name}: wallclock budget-censor ledger",
                  censor_ok, censor_detail)
        budget_role_ok, budget_role_detail = audit_wallclock_budget_role(cfg, stats)
        add_check(sample_checks, f"{sample_name}: wallclock budget role",
                  budget_role_ok, budget_role_detail)
        q1_mechanism_ok, q1_mechanism_detail = audit_q1_mechanism_evidence(cfg, stats)
        add_check(sample_checks, f"{sample_name}: Q1 allocation mechanism activated",
                  q1_mechanism_ok, q1_mechanism_detail)
        fixed_call_ok, fixed_call_detail = audit_campaign_termination(
            cfg, end_cfg, max_runtime_ms,
        )
        fixed_wallclock = cfg.get("campaign_stop_mode", "call-budget") == "wallclock"
        fixed_dose_ok, fixed_dose_detail = audit_campaign_dose(
            cfg, stats, actual_calls, flow_rows, require_cap=not fixed_wallclock,
            execution_rows=executions,
        )
        controls_ok, controls_detail = audit_shared_controls(cfg, threshold, profile)
        add_check(sample_checks, f"{sample_name}: shared {profile} controls",
                  controls_ok, controls_detail)

        mock_stem = archive_name.removesuffix(".tar.gz")
        mock_path = result_dir / f"{mock_stem}.mock-stats.json"
        mock = json.loads(mock_path.read_text()) if mock_path.is_file() else {}
        has_mock = bool(mock)
        if gateway == "mock":
            add_check(sample_checks, f"{sample_name}: mock stats file", has_mock, str(mock_path))
        else:
            add_check(sample_checks, f"{sample_name}: live archive has no mock stats", not has_mock, str(mock_path))
        if has_mock and gateway == "mock":
            add_check(sample_checks, f"{sample_name}: embedded and observed mock configuration agree",
                      cfg.get("mock_gateway") == end_cfg.get("mock_gateway")
                      and cfg.get("mock_gateway") == mock.get("effective_config"),
                      f"start={cfg.get('mock_gateway')} end={end_cfg.get('mock_gateway')} observed={mock.get('effective_config')}")
            accounting_ok, accounting_detail = audit_mock_request_accounting(mock)
            add_check(sample_checks, f"{sample_name}: mock request totals", accounting_ok, accounting_detail)
            protocol_ok, protocol_detail = audit_mock_protocol(mock, cfg, expected_protocol)
            add_check(sample_checks, f"{sample_name}: mock protocol/port", protocol_ok, protocol_detail)

        summary = summaries.get(archive_name, {})
        add_check(sample_checks, f"{sample_name}: run_summary completed", summary.get("status") == "completed" and summary.get("exit_code") == "0")
        branches = len(terminal.get("covered_branch_ids", []))
        try:
            add_check(sample_checks, f"{sample_name}: branch count agrees", int(summary.get("b_abs", -1)) == branches, f"summary={summary.get('b_abs')} replay={branches}")
        except (TypeError, ValueError):
            add_check(sample_checks, f"{sample_name}: branch count agrees", False)

        shared_identities.append(shared_identity_from_sample(
            cfg, terminal, coverage_scope, mock, gateway,
        ))

        add_check(sample_checks, f"{sample_name}: execution ledger matches charged calls",
                  actual_calls == charged, f"executed={actual_calls} charged={charged}")
        endpoint_eligible = fixed_call_ok and fixed_dose_ok and budget_role_ok
        elapsed_ms = end_cfg.get("end_time_ms", 0) - cfg.get("start_time_ms", 0)
        metrics.append({
            "run": item.get("run"), "archive": archive_name,
            "branches": branches, "lines": int(summary.get("l_abs", 0) or 0),
            "target_invocations": actual_calls, "charged_calls": charged,
            "campaign_call_budget": config_budget,
            "budget_exhausted": budget_exhausted,
            "budget_stop_disposition": budget_role_detail,
            "elapsed_seconds": elapsed_ms / 1000 if isinstance(elapsed_ms, (int, float)) else None,
            "budget_exhausted_time_ms": end_cfg.get("campaign_budget_exhausted_time_ms"),
            "parked_quota": stats.get("q1_idle_quota", 0),
            "reflow_calls": stats.get("q1_reflow_consumed", 0),
            "branch_per_1000_calls": 1000.0 * branches / actual_calls if actual_calls else math.nan,
            "fixed_dose_eligible": endpoint_eligible and not fixed_wallclock and config_budget > 0,
            **campaign_inference_scope(cfg),
            "fixed_call_allocation_eligible": endpoint_eligible and q1_mechanism_ok
                                             and isinstance(config_budget, int) and config_budget > 0,
            "q1_mechanism_activated": q1_mechanism_ok,
            "policy_endpoint_eligible": endpoint_eligible,
            "endpoint_detail": {"termination": fixed_call_detail, "dose": fixed_dose_detail,
                                "budget_role": budget_role_detail},
            "mock_requests": mock.get("requests"), "mock_campaign_requests": mock.get("campaign_requests"),
            "prompt_tokens": mock.get("prompt_tokens"), "completion_tokens": mock.get("completion_tokens"),
            "branch_scope": terminal.get("scope_sha256"), "_shared_identity": shared_identities[-1],
        })
        if gateway == "live":
            for key in ("mock_requests", "mock_campaign_requests", "prompt_tokens", "completion_tokens"):
                metrics[-1].pop(key)
            metrics[-1]["live_gateway"] = live_audit
        checks.extend(sample_checks)

    add_check(checks, "comparison scope shared", len(scopes) == 1 and "" not in scopes, f"scopes={len(scopes)}")
    add_check(checks, "target/fuzzer/seed/image/scope identity shared", len(identities) == 1 and None not in next(iter(identities), (None,)), f"identities={len(identities)}")
    shared_ok, shared_detail = shared_identity_difference(shared_identities, gateway)
    add_check(checks, "repeat-level dose/mock/replay identity shared", shared_ok, shared_detail)
    return checks, metrics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result_dirs", nargs="+", help="one or more ablation/results-* result directories")
    parser.add_argument("--target", choices=sorted(PROTOCOL_BY_TARGET), default="bftpd",
                        help="target represented by these result directories (default: bftpd)")
    parser.add_argument("--threshold", type=int, default=1,
                        help="expected requested/resolved threshold (default: 1)")
    parser.add_argument("--timeout-min", type=int, default=15,
                        help="configured campaign runtime limit in minutes (default: 15)")
    parser.add_argument("--protocol", choices=sorted(set(PROTOCOL_BY_TARGET.values())),
                        help="expected mock protocol; defaults from --target")
    parser.add_argument("--gateway", choices=("mock", "live"), default="mock",
                        help="evidence source; live requires actual client ledgers and raw exchanges (default: mock)")
    parser.add_argument("--profile", choices=tuple(AUDIT_CONTROL_PROFILES), default="smoke",
                        help="smoke: controls 8/32/16 and positive live call cap; "
                             "arm-default: controls 64/512/0, optional live call cap, "
                             "and no replay truncation (default: smoke)")
    parser.add_argument(
        "--arms",
        help="expected arms as a comma-separated list; groups: core, q1, q2, all. "
             "Defaults to all 13 for bftpd and the 8 core arms for other targets.",
    )
    args = parser.parse_args()
    if args.threshold <= 0:
        parser.error("--threshold must be a positive integer")
    if args.timeout_min <= 0:
        parser.error("--timeout-min must be a positive integer")
    max_runtime_ms = args.timeout_min * 60_000
    try:
        expected_labels = expected_arm_labels(args.target, args.threshold, args.arms)
    except ValueError as exc:
        parser.error(str(exc))
    protocol = args.protocol or PROTOCOL_BY_TARGET[args.target]
    if protocol != PROTOCOL_BY_TARGET[args.target]:
        parser.error(
            f"--protocol {protocol!r} conflicts with target {args.target!r}; "
            f"expected {PROTOCOL_BY_TARGET[args.target]!r}"
        )
    overall_ok = True
    if len(args.result_dirs) > 1:
        complete_ok, complete_detail = audit_complete_batch(
            [Path(raw_dir) for raw_dir in args.result_dirs], args.target,
            args.threshold, expected_labels,
        )
        print(f"[complete {args.target} threshold-{args.threshold} arm set] {'PASS' if complete_ok else 'FAIL'} — {complete_detail}")
        overall_ok = overall_ok and complete_ok
    batch_shared_identities: list[dict] = []
    for raw_dir in args.result_dirs:
        result_dir = Path(raw_dir)
        checks, metrics = audit_result_dir(
            result_dir, args.target, args.threshold, protocol, max_runtime_ms,
            gateway=args.gateway, profile=args.profile,
        )
        passed = sum(ok for _, ok, _ in checks)
        print(f"\n[{result_dir.name}] {'PASS' if passed == len(checks) else 'FAIL'} ({passed}/{len(checks)} checks)")
        fixed_runs = [row for row in metrics if row.get("fixed_dose_eligible")]
        endpoint_runs = [row for row in metrics if row.get("policy_endpoint_eligible")]
        configured_budgets = {row.get("_shared_identity", {}).get("campaign_call_budget") for row in metrics}
        stop_modes = {row.get("_shared_identity", {}).get("campaign_stop_mode") for row in metrics}
        if stop_modes == {"wallclock"}:
            dispositions: dict[str, int] = {}
            for row in metrics:
                label = row.get("budget_stop_disposition", "missing").split(":", 1)[0]
                dispositions[label] = dispositions.get(label, 0) + 1
            detail = ", ".join(f"{key}={value}" for key, value in sorted(dispositions.items()))
            print(f"  fixed-wallclock comparison: {'ELIGIBLE' if len(endpoint_runs) == 3 else 'INELIGIBLE'} ({len(endpoint_runs)}/3 reached the elapsed-time endpoint with a valid budget role; {detail})")
            if configured_budgets == {0}:
                print("  matched-dose/Q1 call-allocation comparison: NOT APPLICABLE (total call cap disabled; mechanism events do not establish a matched-budget effect)")
        elif configured_budgets == {0}:
            print(f"  fixed-dose comparison: NOT APPLICABLE (uncapped campaign; profile={args.profile})")
        else:
            budget = next(iter(configured_budgets)) if len(configured_budgets) == 1 else "mixed-budget"
            print(f"  fixed-dose comparison: {'ELIGIBLE' if len(fixed_runs) == 3 else 'INELIGIBLE'} ({len(fixed_runs)}/3 repeats reached their policy-defined endpoint in time; configured gross budget={budget} invocations)")
        for name, ok, detail in checks:
            print(f"  {'PASS' if ok else 'FAIL'} {name}" + (f" — {detail}" if detail else ""))
        if metrics:
            branches = [row["branches"] for row in metrics]
            calls = [row["target_invocations"] for row in metrics]
            yields = [row["branch_per_1000_calls"] for row in metrics]
            print("  repeats:")
            for row in metrics:
                print("    " + json.dumps({key: value for key, value in row.items() if not key.startswith("_")}, sort_keys=True))
                if row.get("_shared_identity"):
                    batch_shared_identities.append(row["_shared_identity"])
            print(f"  branch mean={statistics.mean(branches):.2f} sample_sd={format_sample_sd(branches)}; calls mean={statistics.mean(calls):.2f}; branches/1000 calls mean={statistics.mean(yields):.3f} sample_sd={format_sample_sd(yields, 3)}")
        overall_ok = overall_ok and passed == len(checks)
    if len(args.result_dirs) > 1:
        shared_ok, shared_detail = shared_identity_difference(batch_shared_identities, args.gateway)
        print(f"\n[batch-wide shared dose/mock/replay identity] {'PASS' if shared_ok else 'FAIL'} — {shared_detail}")
        overall_ok = overall_ok and shared_ok
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
