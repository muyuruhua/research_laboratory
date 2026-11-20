#!/usr/bin/env python3
"""Safe fixtures and real local gcov regression; no protocol target or socket."""

import copy
import argparse
import csv
import errno
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import coverage_v4 as cov


class CoverageFixtureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="loopfuzz-cov-v4-")
        self.root = Path(self.directory.name)
        self.replayer = self.root / "aflnet-replay"
        self.replayer.write_text(
            "#!/bin/sh\n"
            "# LOOPFUZZ_REPLAY_LEDGER\n"
            "if [ \"$1\" = --capabilities ]; then echo 'peer-reset-after-input-end-v1 terminal-quit-reply-v6'; exit 0; fi\n"
            "echo 'Usage: aflnet-replay packet_file protocol port local_port [first_resp_timeout(us) [follow-up_resp_timeout(ms)]]' >&2\n"
            "exit 1\n")
        self.replayer.chmod(0o755)
        replayer_env = mock.patch.dict(os.environ, {
            cov.LOOPFUZZ_REPLAYER_ENV: str(self.replayer)})
        replayer_env.start()
        self.addCleanup(replayer_env.stop)
        (self.root / "main.c").write_text("int main(void) { return 0; }\n")
        (self.root / "commands.c").write_text("int dataconn(void) { return 0; }\n")
        self.report = {"gcovr/format_version": "0.1", "files": [{"file": "main.c", "lines": [
            {"line_number": 1, "count": 0, "branches": [
                {"count": 0, "fallthrough": True, "throw": False},
                {"count": 0, "fallthrough": False, "throw": False}]}]}]}
        self.baseline = cov.parse_snapshot(self.report, self.root)
        self.manifest = cov.scope_manifest(self.baseline, {"main.gcno": "fixture"}, "4.2", "gcc fixture")

    def tearDown(self):
        self.directory.cleanup()

    def test_replay_input_cap_requires_smoke_mode(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(cov.CoverageError, "smoke-only"):
                cov.resolve_replay_limit(argparse.Namespace(max_replay_inputs=2, smoke=False))

    def test_replay_input_cap_is_explicit_and_positive(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            smoke, limit = cov.resolve_replay_limit(
                argparse.Namespace(max_replay_inputs=2, smoke=True))
            self.assertTrue(smoke)
            self.assertEqual(limit, 2)
            with self.assertRaisesRegex(cov.CoverageError, "positive integer"):
                cov.resolve_replay_limit(argparse.Namespace(max_replay_inputs=0, smoke=True))

    def test_replay_input_cap_can_be_set_by_smoke_environment(self):
        with mock.patch.dict(os.environ, {
                "COVERAGE_V4_SMOKE": "1",
                "COVERAGE_V4_MAX_REPLAY_INPUTS": "3"}, clear=True):
            smoke, limit = cov.resolve_replay_limit(
                argparse.Namespace(max_replay_inputs=None, smoke=False))
            self.assertTrue(smoke)
            self.assertEqual(limit, 3)

    def snapshot(self, branch):
        report = copy.deepcopy(self.report)
        line = report["files"][0]["lines"][0]
        line["count"] = 1
        line["branches"][branch]["count"] = 1
        return cov.parse_snapshot(report, self.root)

    def coordinates(self, index):
        return dict(schema_version=1, filename="id:%06d" % index, campaign_id="fixture", queue_id=index,
                    discovery_time_ms=1000 + index, monotonic_ms=2000 + index,
                    discovery_execution_id=index * 10, coordinate_source="queue-checkpoints.jsonl")


    def test_scope_hash_excludes_provenance_paths_but_pins_measurement_identity(self):
        manifest = copy.deepcopy(self.manifest)
        original = manifest["scope_sha256"]
        manifest.update(source_root="/relocated/src", object_root="/relocated/obj",
                        source_search_roots=["/relocated/src"], target="fixture",
                        zero_baseline_mode="filesystem-verified-no-gcda")
        self.assertEqual(cov.scope_identity_hash(manifest), original)
        manifest["gcno"]["main.gcno"] = "changed-instrumentation"
        self.assertNotEqual(cov.scope_identity_hash(manifest), original)


    def test_replay_exit_classification_tolerates_pureftpd_252(self):
        # Exit 252 is only expected when the replay policy later confirms all
        # required transcript, reset, and coverage evidence.
        f = cov.classify_replay_exit(252, 0)
        self.assertTrue(f["replay_anomaly"])
        self.assertEqual(f["anomaly_kind"], "server-exit-252")
        self.assertFalse(f["server_crashed"])
        self.assertFalse(f["client_anomalous_exit"])

    def test_pureftpd_final_reply_requires_matching_complete_transcript(self):
        log = self.root / "pure-replay.log"
        log.write_text(
            "Responses from server:0-220-421-\n"
            "++++++++++++++++++++++++++++++++\n"
            "Responses in details:\n"
            "220---------- welcome ----------\r\n"
            "220 You will be disconnected\r\n"
            "421 Unable to set up secure anonymous FTP\r\n"
            "--------------------------------\n")
        self.assertEqual(cov.pureftpd_final_reply_code(log), 421)

        log.write_text(log.read_text().replace("Responses from server:0-220-421-",
                                              "Responses from server:0-220-530-"))
        self.assertIsNone(cov.pureftpd_final_reply_code(log))

        log.write_text("Responses from server:0-421-\nResponses in details:\n")
        self.assertIsNone(cov.pureftpd_final_reply_code(log))

    def test_bftpd_final_reply_uses_terminal_detail_when_summary_omits_replies(self):
        log = self.root / "bftpd-replay.log"
        log.write_text(
            "Responses from server:0-220-331-500-200-\n"
            "++++++++++++++++++++++++++++++++\nResponses in details:\n"
            "220 bftpd ready.\r\n"
            "331 Password please.\r\n"
            "500 Unknown command.\r\n"
            "200 OK\r\n"
            "221 See you later...\r\n"
            "--------------------------------\n")
        # BFTPD's summary omits replies present in the detail transcript. The
        # terminal control-close reply remains auditable from the full detail.
        self.assertEqual(cov.bftpd_final_reply_code(log), 221)
        self.assertIsNone(cov.pureftpd_final_reply_code(log))

        # Ordinary terminal replies also need to be reconstructed for the
        # archived per-input classification. They do not receive the special
        # protocol-close exception reserved for a verified 221.
        for code, message in ((500, "Unknown command."),
                              (503, "Bad command sequence.")):
            log.write_bytes(
                (f"Responses from server:0-220-{code}-\n"
                 "++++++++++++++++++++++++++++++++\nResponses in details:\n"
                 f"220 bftpd ready.\r\n{code} {message}\r\n\n"
                 "--------------------------------\n").encode("ascii"))
            self.assertEqual(cov.bftpd_final_reply_code(log), code)
            self.assertEqual(cov.bftpd_final_reply_code(
                log, allow_terminal_fallback=False), code)

        # A final non-221 reply hidden in an unterminated multiline body must
        # not use the narrowly scoped 221 fallback.
        log.write_bytes(
            b"Responses from server:0-220-\n"
            b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
            b"220 bftpd ready.\r\n"
            b"211-Features begin.\r\n"
            b"500 Unknown command.\r\n\n"
            b"--------------------------------\n")
        self.assertIsNone(cov.bftpd_final_reply_code(log))

        # A bare LF does not frame an ordinary terminal reply either.
        log.write_bytes(
            b"Responses from server:0-220-500-\n"
            b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
            b"220 bftpd ready.\r\n"
            b"500 Unknown command.\n\n"
            b"--------------------------------\n")
        self.assertIsNone(cov.bftpd_final_reply_code(log))

        # Summary codes may be omitted, but their order must match the full
        # detail sequence.
        log.write_text(log.read_text().replace(
            "Responses from server:0-220-331-500-200-",
            "Responses from server:0-331-220-500-200-"))
        self.assertIsNone(cov.bftpd_final_reply_code(log))

        # An explicit summary reply after 221 contradicts protocol close.
        log.write_text(log.read_text().replace(
            "Responses from server:0-331-220-500-200-",
            "Responses from server:0-220-331-221-500-"))
        self.assertIsNone(cov.bftpd_final_reply_code(log))

        # A 221-shaped line inside a multiline body is not a terminal reply;
        # the actual final code is the matching 211 terminator.
        log.write_text(
            "Responses from server:0-220-211-\n"
            "++++++++++++++++++++++++++++++++\nResponses in details:\n"
            "220 bftpd ready.\r\n"
            "211-Features:\r\n"
            "221 See you later...\r\n"
            "211 End\r\n"
            "--------------------------------\n")
        self.assertEqual(cov.bftpd_final_reply_code(log), 211)

        # Without the terminating separator the log may be truncated after a
        # plausible 221, so it cannot establish that 221 was the final reply.
        log.write_text(
            "Responses from server:0-221-\n"
            "++++++++++++++++++++++++++++++++\nResponses in details:\n"
            "221 See you later...\r\n")
        self.assertIsNone(cov.bftpd_final_reply_code(log))

        # A bare-LF final line is not an FTP reply boundary.
        log.write_bytes(
            b"Responses from server:0-221-\n"
            b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
            b"221 See you later...\n\n"
            b"--------------------------------\n")
        self.assertIsNone(cov.bftpd_final_reply_code(log))

        # Bare LF inside a multiline body is allowed. A 221-looking body line
        # does not close the active 213 response, while the final CRLF-framed
        # 221 is still recognized as the actual terminal reply.
        log.write_bytes(
            b"Responses from server:0-220-213-221-\n"
            b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
            b"220 bftpd ready.\r\n"
            b"213-Status follows.\r\n"
            b"file listing line\n221 body text\r\n"
            b"213 End of Status.\r\n"
            b"221 See you later...\r\n\n"
            b"--------------------------------\n")
        self.assertEqual(cov.bftpd_final_reply_code(log), 221)

        # A malformed earlier multiline reply can leave the RFC 959 parser
        # inside a body. The final, independently CRLF-delimited 221 remains
        # valid, while a summary that places another reply after it is not.
        log.write_bytes(
            b"Responses from server:0-220-\n"
            b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
            b"220 bftpd ready.\r\n"
            b"211-Features begin.\r\n"
            b"500 this malformed body never closes.\r\n"
            b"221 See you later...\r\n\n"
            b"--------------------------------\n")
        self.assertEqual(cov.bftpd_final_reply_code(log), 221)
        log.write_bytes(log.read_bytes().replace(
            b"Responses from server:0-220-", b"Responses from server:0-220-221-500-"))
        self.assertIsNone(cov.bftpd_final_reply_code(log))

    def test_pureftpd_exit_policy_requires_all_observed_evidence(self):
        for server_code in (251, 252):
            flags = cov.classify_replay_exit(server_code, 0)
            accepted = cov.apply_pureftpd_session_exit_policy(
                flags, server_code, 0, True, False, False, 421,
                ["src/ftpd.gcda"], True)
            self.assertTrue(accepted["pureftpd_session_exit_expected"])
            self.assertFalse(accepted["replay_anomaly"])
            self.assertEqual(accepted["anomaly_kind"], "")

            failures = (
                (False, False, False, 421, ["src/ftpd.gcda"], True),
                (True, True, False, 421, ["src/ftpd.gcda"], True),
                (True, False, True, 421, ["src/ftpd.gcda"], True),
                (True, False, False, 530, ["src/ftpd.gcda"], True),
                (True, False, False, 421, [], True),
                (True, False, False, 421, ["src/ftpd.gcda"], False),
            )
            for ready, timed_out, shutdown, reply, gcda, reset in failures:
                result = cov.apply_pureftpd_session_exit_policy(
                    cov.classify_replay_exit(server_code, 0), server_code, 0,
                    ready, timed_out, shutdown, reply, gcda, reset)
                self.assertFalse(result["pureftpd_session_exit_expected"])
                self.assertTrue(result["replay_anomaly"])
                self.assertEqual(result["anomaly_kind"],
                                 "server-exit-%s" % server_code)

        # A transcript-confirmed 421 does not excuse a different process exit.
        result = cov.apply_pureftpd_session_exit_policy(
            cov.classify_replay_exit(0, 0), 0, 0, True, False, False, 421,
            ["src/ftpd.gcda"], True)
        self.assertFalse(result["pureftpd_session_exit_expected"])

    def test_replay_exit_classification_normal_and_crash(self):
        self.assertFalse(cov.classify_replay_exit(0, 0)["replay_anomaly"])
        self.assertFalse(cov.classify_replay_exit(124, 0)["replay_anomaly"])
        crash = cov.classify_replay_exit(-11, 1)
        self.assertTrue(crash["server_crashed"])
        self.assertFalse(crash["replay_anomaly"])  # crash finding, not anomaly
        self.assertEqual(crash["anomaly_kind"], "server-crash-finding")
        self.assertIn("server-signal-exit", cov.replay_incompleteness(
            dict(server_crashed=True, session_coverage_missing=True)))
        self.assertEqual(cov.replay_incompleteness(dict(
            server_crashed=False, session_coverage_missing=False)), [])

    def test_unpatched_bftpd_is_not_accepted(self):
        with self.assertRaisesRegex(cov.CoverageError, "SIGPIPE normal-exit"):
            cov.bftpd_exit_policy(self.root)
        self.assertFalse(cov.bftpd_exit_policy(self.root, True)["verified"])

    def test_replay_exit_classification_lone_client_failure(self):
        f = cov.classify_replay_exit(0, 1)
        self.assertTrue(f["replay_anomaly"])
        self.assertEqual(f["anomaly_kind"], "client-exit-1")
        # client failure on a crashed server is part of the crash finding
        f2 = cov.classify_replay_exit(-15, 1)
        self.assertFalse(f2["replay_anomaly"])

    def test_replay_policy_version_tracks_harness_revision(self):
        self.assertEqual(cov.replay_policy_version(
            "20261119-verified-peer-close-and-final-send-v5"), 5)
        self.assertEqual(cov.replay_policy_version(
            "20261119-ftp-quit-proftpd-bftpd-audit-v9"), 9)
        self.assertEqual(cov.replay_policy_version(
            "20261120-final-221-multiline-aware-replay-v10"), 10)
        self.assertEqual(cov.replay_policy_version(
            "20261120-verified-overlong-policy-close-v11"), 11)
        self.assertEqual(cov.replay_policy_version(cov.REPLAY_HARNESS_VERSION), 12)
        with self.assertRaisesRegex(cov.CoverageError, "unknown replay harness version"):
            cov.replay_policy_version("unknown")

    def test_disjoint_bftpd_snapshots_are_unioned_not_maxed(self):
        union = cov.CoverageUnion(self.baseline, self.manifest)
        first = union.add(self.snapshot(0), self.coordinates(1), "a", expected_counter_reset=True)
        second = union.add(self.snapshot(1), self.coordinates(2), "b", expected_counter_reset=True)
        self.assertEqual(first["cumulative_covered_branches"], 1)
        self.assertEqual(second["snapshot_covered_branches"], 1)
        self.assertEqual(second["cumulative_covered_branches"], 2)
        self.assertEqual(len(second["dropped_snapshot_branch_ids"]), 1)
        self.assertFalse(second["unexpected_nonmonotonic_snapshot"])

    def test_seed_union_is_explicit_and_separate_from_replay_union(self):
        union = cov.CoverageUnion(self.baseline, self.manifest)
        event = union.add(self.snapshot(0), self.coordinates(1), "a",
                          expected_counter_reset=True, is_seed_input=True)
        union.add(self.snapshot(1), self.coordinates(2), "b",
                  expected_counter_reset=True, is_seed_input=False)
        self.assertTrue(event["is_seed_input"])
        self.assertEqual(union.seed_covered, self.snapshot(0).covered_branches)
        self.assertEqual(union.covered, self.snapshot(0).covered_branches |
                         self.snapshot(1).covered_branches)
        self.assertEqual(union.seed_events, [1])

    def test_unexpected_snapshot_decrease_is_detected(self):
        union = cov.CoverageUnion(self.baseline, self.manifest)
        union.add(self.snapshot(0), self.coordinates(1), "a")
        event = union.add(self.snapshot(1), self.coordinates(2), "b")
        self.assertTrue(event["unexpected_nonmonotonic_snapshot"])
        self.assertEqual(len(union.covered), 2)

    def test_changed_branch_universe_fails_even_with_same_count(self):
        changed = copy.deepcopy(self.report)
        changed["files"][0]["lines"][0]["line_number"] = 2
        union = cov.CoverageUnion(self.baseline, self.manifest)
        with self.assertRaisesRegex(cov.CoverageError, "scope changed"):
            union.add(cov.parse_snapshot(changed, self.root), self.coordinates(1), "a")

    def test_source_content_change_fails(self):
        (self.root / "main.c").write_text("int main(void) { return 1; }\n")
        union = cov.CoverageUnion(self.baseline, self.manifest)
        with self.assertRaisesRegex(cov.CoverageError, "files"):
            union.add(self.snapshot(0), self.coordinates(1), "a")

    def test_source_escape_fails(self):
        report = copy.deepcopy(self.report)
        report["files"][0]["file"] = "../unrelated.c"
        # A source outside every known root (escape or plain missing) must
        # never be silently admitted into the measured universe.
        with self.assertRaisesRegex(cov.CoverageError, "cannot be fingerprinted"):
            cov.parse_snapshot(report, self.root)

    def test_modern_explicit_branch_numbers(self):
        report = copy.deepcopy(self.report)
        report["gcovr/format_version"] = "0.6"
        for branchno, entry in enumerate(report["files"][0]["lines"][0]["branches"]):
            entry["branchno"] = branchno
        self.assertEqual(cov.parse_snapshot(report, self.root).branches, self.baseline.branches)

    def test_duplicate_branch_identity_fails(self):
        report = copy.deepcopy(self.report)
        for branch in report["files"][0]["lines"][0]["branches"]:
            branch["branchno"] = 0
        with self.assertRaisesRegex(cov.CoverageError, "duplicate branch"):
            cov.parse_snapshot(report, self.root)

    def test_nonzero_baseline_fails(self):
        with self.assertRaisesRegex(cov.CoverageError, "not reset"):
            cov.CoverageUnion(self.snapshot(0), self.manifest)

    def make_corpus(self):
        corpus = self.root / "campaign/replayable-queue"
        corpus.mkdir(parents=True)
        for index in (1, 2):
            (corpus / ("id:%06d" % index)).write_text(str(index))
        return corpus.parent

    def test_discovery_order_overrides_mtime_and_ids_are_exact(self):
        folder = self.make_corpus()
        os.utime(folder / "replayable-queue/id:000001", ns=(9000000000, 9000000000))
        os.utime(folder / "replayable-queue/id:000002", ns=(1000000000, 1000000000))
        coordinates = {r["filename"]: r for r in (self.coordinates(1), self.coordinates(2))}
        plan, unreplayable = cov.plan_corpus(folder, 1, coordinates, True)
        self.assertEqual([r["discovery_execution_id"] for r in plan], [10, 20])
        self.assertEqual(unreplayable, [])
        self.assertGreater(plan[0]["original_mtime_ns"], plan[1]["original_mtime_ns"])

    def test_missing_coordinates_never_invent_execution_id(self):
        folder = self.make_corpus()
        plan, _ = cov.plan_corpus(folder, 1, {})
        self.assertTrue(all("discovery_execution_id" not in row for row in plan))
        with self.assertRaisesRegex(cov.CoverageError, "no unique discovery"):
            cov.plan_corpus(folder, 1, {}, True)

    def test_uncommitted_admission_replay_artifacts_fail_strict_plan(self):
        for publish_raw in (False, True):
            with self.subTest(publish_raw=publish_raw):
                folder = self.root / ("campaign-raw-%s" % publish_raw)
                replay_dir = folder / "replayable-queue"
                replay_dir.mkdir(parents=True)
                (replay_dir / "id:000001,prov").write_bytes(b"\x08\x00\x00\x00USER a\r\n")
                if publish_raw:
                    queue_dir = folder / "queue"
                    queue_dir.mkdir()
                    (queue_dir / "id:000001,prov").write_bytes(b"USER a\r\n")
                with self.assertRaisesRegex(cov.CoverageError, "no unique discovery"):
                    cov.plan_corpus(folder, 1, {}, True)

    def test_zero_byte_replay_input_is_rejected(self):
        folder = self.make_corpus()
        (folder / "replayable-queue/id:000002").write_bytes(b"")
        with self.assertRaisesRegex(cov.CoverageError, "empty replay input"):
            cov.plan_corpus(folder, 1, {})

    def test_partial_join_and_duplicate_ledger_are_rejected(self):
        folder = self.make_corpus()
        with self.assertRaisesRegex(cov.CoverageError, "partially joined"):
            cov.plan_corpus(folder, 1, {"id:000001": self.coordinates(1)})
        ledger = folder / "queue-checkpoints.jsonl"
        ledger.write_text((json.dumps(self.coordinates(1)) + "\n") * 2)
        with self.assertRaisesRegex(cov.CoverageError, "not unique"):
            cov.load_coordinates(ledger)

    def test_removal_records_close_expired_provisional_joins(self):
        folder = self.make_corpus()
        expired = self.coordinates(3)
        removal = dict(schema_version=1, kind="removal", filename=expired["filename"],
                       campaign_id=expired["campaign_id"], queue_id=3,
                       discovery_time_ms=1999, monotonic_ms=2999, discovery_execution_id=99)
        ledger = folder / "queue-checkpoints.jsonl"
        entries = [self.coordinates(1), self.coordinates(2), expired, removal]
        ledger.write_text("".join(json.dumps(entry) + "\n" for entry in entries))
        coordinates = cov.load_coordinates(ledger)
        self.assertEqual(set(coordinates), {"id:000001", "id:000002"})
        plan, dropped = cov.plan_corpus(folder, 1, coordinates, True)
        self.assertEqual(len(plan), 2)
        self.assertEqual(dropped, [])
        # Ledger names without a corpus file (imported seed never given a
        # structured replay form) are permitted but must be reported.
        extra = dict(self.coordinates(9), filename="id:000009")
        ledger.write_text("".join(json.dumps(entry) + "\n"
                                  for entry in entries[:2] + [extra]))
        coordinates = cov.load_coordinates(ledger)
        plan, dropped = cov.plan_corpus(folder, 1, coordinates, True)
        self.assertEqual(len(plan), 2)
        self.assertEqual(dropped, ["id:000009"])
        # A removal without a prior discovery is a corrupt ledger, not a no-op.
        orphan = dict(removal, filename="id:000009", queue_id=9)
        ledger.write_text(json.dumps(self.coordinates(1)) + "\n" +
                          json.dumps(orphan) + "\n")
        with self.assertRaisesRegex(cov.CoverageError, "removal without"):
            cov.load_coordinates(ledger)

    def test_zero_gcda_baseline_bootstraps_from_first_checkpoint(self):
        # Images that never ran the instrumented binary have no gcda, so
        # gcovr 4.x reports an empty branch universe at baseline.
        empty_report = copy.deepcopy(self.report)
        empty_report["files"][0]["lines"][0]["branches"] = []
        baseline = cov.parse_snapshot(empty_report, self.root, allow_empty=True)
        self.assertEqual(baseline.branches, set())
        manifest = cov.scope_manifest(baseline, {"main.gcno": "fixture"}, "4.2", "gcc fixture")
        manifest["zero_baseline_mode"] = "filesystem-verified-no-gcda"
        union = cov.CoverageUnion(baseline, manifest)
        event = union.add(self.snapshot(0), self.coordinates(1), "a")
        self.assertEqual(event["cumulative_covered_branches"], 1)
        # The adopted universe is now binding: an unknown branch fails.
        drifted = self.snapshot(0)
        drifted.branches.add(("main.c", 99, 0))
        with self.assertRaisesRegex(cov.CoverageError, "scope changed"):
            union.add(drifted, self.coordinates(2), "b")
        # allow_empty=False (the default) keeps rejecting empty universes.
        with self.assertRaisesRegex(cov.CoverageError, "empty source/branch"):
            cov.parse_snapshot(empty_report, self.root)

    def test_nonmonotonic_execution_and_time_rejected(self):
        union = cov.CoverageUnion(self.baseline, self.manifest)
        union.add(self.snapshot(0), self.coordinates(2), "a")
        with self.assertRaisesRegex(cov.CoverageError, "nonmonotonic"):
            union.add(self.snapshot(1), self.coordinates(1), "b")

    def test_aggregate_csv_mismatch_is_rejected(self):
        union = cov.CoverageUnion(self.baseline, self.manifest)
        event = union.add(self.snapshot(0), self.coordinates(1), "a")
        row = union.csv_row(event)
        path = self.root / "coverage.csv"
        with path.open("w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=cov.CSV_FIELDS)
            writer.writeheader()
            writer.writerow(row)
        self.assertEqual(cov.audit_csv(path, self.manifest)["terminal_branches"], 1)
        row["b_per"] = 100
        with path.open("w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=cov.CSV_FIELDS)
            writer.writeheader()
            writer.writerow(row)
        with self.assertRaisesRegex(cov.CoverageError, "percentage disagrees"):
            cov.audit_csv(path, self.manifest)

    def test_target_roots_and_kamailio_scope_are_fixed(self):
        expected = {"lightftp": (self.root.parent, self.root),
                    "lighttpd1": (self.root / "src", self.root),
                    "forked-daapd": (self.root / "forked-daapd-gcov" / "src",) * 2,
                    "kamailio": (self.root / "kamailio-gcov" / "src",) * 2,
                    "bftpd": (self.root, self.root),
                    "exim": (self.root / "src" / "build-Linux-x86_64",) * 2,
                    "proftpd": (self.root, self.root),
                    "pure-ftpd": (self.root, self.root),
                    "live555": (self.root.parent, self.root.parent)}
        for target, roots in expected.items():
            self.assertEqual(cov.profile_paths(target, self.root), roots)
        with mock.patch.dict(os.environ, {"KAMAILIO_TCP": "1"}):
            with self.assertRaisesRegex(cov.CoverageError, "UDP substitution"):
                cov.replay_commands("kamailio", "input", 5060, 1, self.root, self.root)
        # New subjects: replay argv shapes must stay pinned.
        exim_client, exim_server = cov.replay_commands("exim", "input", 25, 1,
                                                       self.root, self.root)
        self.assertEqual(exim_client[:4], [str(self.replayer), "input", "SMTP", "25"])
        self.assertEqual(exim_client[4:], ["0", "100", "10000"])
        self.assertIn("-bd", exim_server)
        daap_client, daap_server = cov.replay_commands(
            "forked-daapd", "input", 3689, 1, self.root, self.root)
        self.assertEqual(daap_client[:3], [str(self.replayer), "input", "HTTP"])
        self.assertIn("./forked-daapd-gcov/src/forked-daapd", daap_server)
        (self.root / "src" / "src").mkdir(parents=True, exist_ok=True)
        self.assertEqual(cov.source_search_roots("exim", self.root,
                                                 self.root / "src" / "build-Linux-x86_64"),
                         [self.root / "src" / "src"])
        self.assertEqual(cov.source_search_roots("bftpd", self.root, self.root), [])
        proftpd_client, proftpd_server = cov.replay_commands("proftpd", "input", 21, 1,
                                                             self.root, self.root)
        self.assertEqual(proftpd_client[2], "FTP")
        self.assertIn("./proftpd", proftpd_server)
        _, pure_server = cov.replay_commands("pure-ftpd", "input", 21, 1,
                                             self.root, self.root)
        self.assertIn("src/pure-ftpd", pure_server)
        live_client, live_server = cov.replay_commands("live555", "input", 8554, 1,
                                                       self.root / "testProgs",
                                                       self.root)
        self.assertEqual(live_client[2], "RTSP")
        self.assertEqual(live_client[4:], ["0", "100", "10000"])
        self.assertIn("./testOnDemandRTSPServer", live_server)

    def test_unsupervised_replay_client_receives_frame_ledger_environment(self):
        record_path = self.root / "input.raw"
        record_path.write_bytes(struct.pack("<I", 1) + b"x")
        log_path = self.root / "replay.log"
        processes = [mock.Mock(returncode=0), mock.Mock(returncode=0)]
        for process in processes:
            process.wait.return_value = 0
        cov.loopfuzz_replayer()
        with mock.patch.object(cov.subprocess, "Popen", side_effect=processes) as popen, \
             mock.patch.object(cov, "stop_process"):
            cov.run_one_replay("lightftp", {"path": record_path, "filename": "input.raw"},
                               2200, 1, self.root, self.root, log_path, self.root)
        client_env = popen.call_args_list[0].kwargs["env"]
        self.assertEqual(client_env["LOOPFUZZ_REPLAY_LEDGER"],
                         str(self.root / "replay-frame-ledger.jsonl"))

    def test_strict_replay_rejects_a_legacy_replayer(self):
        legacy = self.root / "legacy-aflnet-replay"
        legacy.write_text(
            "#!/bin/sh\n"
            "# LOOPFUZZ_REPLAY_LEDGER\n"
            "echo 'Usage: aflnet-replay packet protocol port timeout' >&2\n"
            "exit 1\n")
        legacy.chmod(0o755)
        with mock.patch.dict(os.environ, {cov.LOOPFUZZ_REPLAYER_ENV: str(legacy)}):
            with self.assertRaisesRegex(cov.CoverageError, "lacks the LoopFuzz"):
                cov.replay_commands("live555", "input", 8554, 1,
                                    self.root / "testProgs", self.root)

    def test_strict_replay_rejects_replayer_without_frame_ledger(self):
        no_ledger = self.root / "no-ledger-aflnet-replay"
        no_ledger.write_text(
            "#!/bin/sh\n"
            "echo 'Usage: aflnet-replay packet_file protocol port local_port "
            "[first_resp_timeout(us) [follow-up_resp_timeout(ms)]]' >&2\n"
            "exit 1\n")
        no_ledger.chmod(0o755)
        with mock.patch.dict(os.environ, {cov.LOOPFUZZ_REPLAYER_ENV: str(no_ledger)}):
            with self.assertRaisesRegex(cov.CoverageError, "frame-ledger capability"):
                cov.replay_commands("live555", "input", 8554, 1,
                                    self.root / "testProgs", self.root)

    def test_strict_replay_rejects_replayer_without_final_reset_capability(self):
        stale = self.root / "stale-aflnet-replay"
        stale.write_text(
            "#!/bin/sh\n"
            "# LOOPFUZZ_REPLAY_LEDGER\n"
            "echo 'Usage: aflnet-replay packet_file protocol port local_port "
            "[first_resp_timeout(us) [follow-up_resp_timeout(ms)]]' >&2\n"
            "exit 1\n")
        stale.chmod(0o755)
        with mock.patch.dict(os.environ, {cov.LOOPFUZZ_REPLAYER_ENV: str(stale)}):
            with self.assertRaisesRegex(cov.CoverageError, "terminal-QUIT handling"):
                cov.loopfuzz_replayer()

    def test_strict_replay_rejects_old_terminal_quit_capability(self):
        stale = self.root / "old-terminal-quit-aflnet-replay"
        stale.write_text(
            "#!/bin/sh\n"
            "# LOOPFUZZ_REPLAY_LEDGER\n"
            "if [ \"$1\" = --capabilities ]; then "
            "echo 'peer-reset-after-input-end-v1 terminal-quit-reply-v5'; exit 0; fi\n"
            "echo 'Usage: aflnet-replay packet_file protocol port local_port "
            "[first_resp_timeout(us) [follow-up_resp_timeout(ms)]]' >&2\n"
            "exit 1\n")
        stale.chmod(0o755)
        with mock.patch.dict(os.environ, {cov.LOOPFUZZ_REPLAYER_ENV: str(stale)}):
            with self.assertRaisesRegex(cov.CoverageError, "terminal-QUIT handling"):
                cov.loopfuzz_replayer()

    def test_proftpd_v4_replay_requires_a_complete_frame_ledger(self):
        incomplete = dict(harness_policy="proftpd-ready-client-graceful-exit-v4",
                          send_completeness="unknown")
        self.assertIn("frame-ledger-incomplete", cov.replay_incompleteness(incomplete))
        complete = dict(incomplete, send_completeness="complete")
        self.assertNotIn("frame-ledger-incomplete", cov.replay_incompleteness(complete))

    def test_expected_pureftpd_421_exit_cannot_exempt_partial_frame_sending(self):
        for completeness in ("incomplete", "unknown"):
            with self.subTest(completeness=completeness):
                replay = dict(pureftpd_session_exit_expected=True,
                              replay_anomaly=False, server_crashed=False,
                              send_completeness=completeness)
                self.assertIn("frame-ledger-incomplete", cov.replay_incompleteness(replay))

    def test_long_smtp_timeout_uses_saved_session_dose(self):
        path = self.root / "session.raw"
        path.write_bytes((struct.pack("<I", 6) + b"NOOP\r\n") * 80)
        command = ["aflnet-replay", str(path), "SMTP", "25", "0", "100", "10000"]
        self.assertEqual(cov.structured_message_count(path), 80)
        self.assertEqual(cov.client_timeout_seconds(command, path, 1), 21)
        path.write_bytes(struct.pack("<I", 100) + b"short")
        with self.assertRaisesRegex(cov.CoverageError, "truncated replay frame"):
            cov.structured_message_count(path)

    def test_readiness_observes_real_socket_without_connecting(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
            self.assertFalse(cov.bound_port(port, "tcp"))
            listener.listen(1)
            self.assertTrue(cov.wait_bound_port(None, port, "tcp", timeout=0.1))
            listener.setblocking(False)
            with self.assertRaises(BlockingIOError):
                listener.accept()  # readiness must not generate a connection

    def test_proftpd_harness_shutdown_sigterm_is_not_a_crash(self):
        # ProFTPD used to sit behind a three-second timeout. A valid client
        # could finish after that timeout sent SIGTERM, which was then
        # misclassified as a crash. The supervised path waits for TCP readiness
        # and sends SIGTERM only after its client has completed.
        server = mock.Mock(pid=101, returncode=-signal.SIGTERM)
        server.poll.return_value = None
        server.wait.return_value = -signal.SIGTERM
        client = mock.Mock(pid=202, returncode=0)
        client.wait.return_value = 0
        client_command = ["aflnet-replay", "input", "FTP", "2121", "1"]
        server_command = ["timeout", "-k", "1s", "-s", "SIGTERM", "3s",
                          "./proftpd", "-n", "-c", "basic.conf", "-X"]
        with mock.patch.object(cov.subprocess, "Popen", side_effect=[server, client]) as popen, \
             mock.patch.object(cov, "wait_bound_port", return_value=True) as readiness, \
             mock.patch.object(cov, "client_timeout_seconds", return_value=10), \
             mock.patch.object(cov.os, "killpg"):
            result = cov.run_supervised_session(
                "proftpd", client_command, server_command, {"path": "input"}, 1,
                2121, self.root, {}, mock.Mock())
        readiness.assert_called_once_with(server, 2121, "tcp")
        self.assertEqual(popen.call_args_list[0].args[0], server_command[6:])
        self.assertTrue(result["harness_shutdown_requested"])
        self.assertEqual(result["server_exit_code"], -signal.SIGTERM)
        self.assertFalse(result["server_crashed"])
        self.assertFalse(result["replay_anomaly"])
        self.assertTrue(cov.proftpd_replay_policy()["verified"])

    def test_bftpd_supervised_session_strips_only_four_token_timeout_wrapper(self):
        server = mock.Mock(pid=101, returncode=0)
        server.poll.return_value = 0
        server.wait.return_value = 0
        client = mock.Mock(pid=202, returncode=2)
        client.wait.return_value = 2
        client_command = ["aflnet-replay", "input", "FTP", "2121", "0", "100", "10000"]
        server_command = ["timeout", "-k", "1s", "3s", "./bftpd", "-D", "-c", "basic.conf"]
        with mock.patch.object(cov.subprocess, "Popen", side_effect=[server, client]) as popen, \
             mock.patch.object(cov, "wait_bound_port", return_value=True), \
             mock.patch.object(cov, "client_timeout_seconds", return_value=10):
            result = cov.run_supervised_session(
                "bftpd", client_command, server_command, {"path": "input"}, 1,
                2121, self.root, {}, mock.Mock())
        self.assertEqual(popen.call_args_list[0].args[0], server_command[4:])
        self.assertEqual(result["server_exit_code"], 0)
        self.assertEqual(result["client_exit_code"], 2)

    def test_bftpd_protocol_close_requires_last_attempted_frame_to_be_quit(self):
        # An audited 221 after a terminal QUIT explains why a later input
        # suffix was never attempted. It does not excuse bytes after QUIT,
        # another terminal reply, or a close on a non-QUIT command.
        framed = (struct.pack("<I", 6) + b"QUIT\r\n" +
                  struct.pack("<I", 6) + b"NOOP\r\n")
        ledger_path = self.root / "frame-ledger.jsonl"
        ledger_path.write_text("\n".join([
            json.dumps({"event": "session_begin", "schema": "loopfuzz-replay-frame-ledger-v1"}),
            json.dumps({"event": "frame", "frame": 1, "len": 6,
                        "read_complete": True, "pre_recv_ok": True,
                        "send_attempt": True, "send_errno": 0,
                        "sent_bytes": 6, "post_recv_ok": True}),
            json.dumps({"event": "session_end", "frames_total": 1,
                        "stop_reason": "peer-closed-before-input-end", "peer_closed": True}),
        ]) + "\n")
        ledger = cov.read_frame_ledger(ledger_path, framed)
        self.assertEqual(ledger["frames_unattempted"], 1)
        self.assertTrue(ledger["last_attempted_frame_is_quit"])
        replay = dict(server_exit_code=0, client_exit_code=2,
                      server_ready=True, client_timed_out=False,
                      harness_shutdown_requested=False,
                      imported_gcda=["main.gcda"], session_coverage_missing=False)
        reset = dict(command_succeeded=True, exit_code=0)
        self.assertTrue(cov.bftpd_protocol_end_expected(replay, ledger, 221, reset))
        replay["bftpd_protocol_end_expected"] = True
        replay["send_completeness"] = "incomplete"
        self.assertEqual(cov.replay_incompleteness(replay), [])
        # Ordinary final error replies are parseable, but only a protocol
        # closing 221 after QUIT may excuse the unattempted suffix.
        for final_reply in (226, 421, 500, 503, None):
            self.assertFalse(cov.bftpd_protocol_end_expected(replay, ledger, final_reply, reset))

        # A visible 221 cannot excuse a close on a non-QUIT frame.
        no_quit = (struct.pack("<I", 6) + b"NOOP\r\n" +
                   struct.pack("<I", 6) + b"QUIT\r\n")
        no_quit_ledger = cov.read_frame_ledger(ledger_path, no_quit)
        self.assertFalse(no_quit_ledger["last_attempted_frame_is_quit"])
        self.assertFalse(cov.bftpd_protocol_end_expected(
            replay, no_quit_ledger, 221, reset))

        # A complete-input close is recorded as EOF by this client and exits
        # successfully; a synthetic "closed before frame" reason cannot
        # override its contradictory incomplete-client status.
        complete_ledger = dict(ledger, frames_unattempted=0, frames_total=2,
                               stop_reason="eof")
        self.assertFalse(cov.bftpd_protocol_end_expected(
            replay, complete_ledger, 221, reset))
        normal_replay = dict(replay, client_exit_code=0)
        self.assertFalse(cov.bftpd_protocol_end_expected(
            normal_replay, complete_ledger, 221, reset))
        self.assertFalse(cov.classify_replay_exit(0, 0)["replay_anomaly"])

        # BFTPD's command loop is LF-delimited; a prior bare-LF line in the
        # same fuzz frame does not stop a final CRLF-terminated QUIT from being
        # executed. Bytes after QUIT or a QUIT embedded in another line do.
        self.assertTrue(cov.ftp_frame_ends_with_quit(b"SYST\nQUIT\r\n"))
        self.assertFalse(cov.ftp_frame_ends_with_quit(b"SYSTQUIT\r\n"))
        self.assertFalse(cov.ftp_frame_ends_with_quit(b"SYST\nQUIT\r\nNOOP\r\n"))

        def framed_payloads(payloads):
            return b"".join(struct.pack("<I", len(payload)) + payload
                            for payload in payloads)

        def complete_send_ledger(payloads):
            rows = [dict(event="session_begin", schema="loopfuzz-replay-frame-ledger-v1")]
            for number, payload in enumerate(payloads, 1):
                rows.append(dict(event="frame", frame=number, len=len(payload),
                                 read_complete=True, pre_recv_ok=True,
                                 send_attempt=True, send_errno=0,
                                 sent_bytes=len(payload), post_recv_ok=True))
            rows.append(dict(event="session_end", frames_total=len(payloads),
                             stop_reason="eof", peer_closed=False))
            return rows

        # Frame boundaries disappear on the TCP stream. A QUIT-looking frame
        # suffix is not a command if the previous frame ended mid-line.
        cross_frame_bad = [b"NOOP", b"QUIT\r\n"]
        cross_frame_good = [b"SYST\n", b"QUIT\r\n"]
        for payloads, expected_quit in ((cross_frame_bad, False),
                                        (cross_frame_good, True)):
            framed = framed_payloads(payloads)
            ledger_path.write_text("\n".join(
                json.dumps(row) for row in complete_send_ledger(payloads)) + "\n")
            actual = cov.read_frame_ledger(ledger_path, framed)
            self.assertEqual(actual["last_attempted_frame_is_quit"], expected_quit)

    def test_bftpd_protocol_close_requires_quit_evidence_and_not_timeout(self):
        ledger = dict(prefix_sent_complete=True, peer_closed=True,
                      frames_unattempted=1, frames_attempted=1, frames_total=1,
                      last_attempted_frame_is_quit=True,
                      stop_reason="peer-closed-before-input-end")
        replay = dict(server_exit_code=0, client_exit_code=2,
                      server_ready=True, client_timed_out=False,
                      harness_shutdown_requested=False,
                      imported_gcda=["main.gcda"], session_coverage_missing=False)
        reset = dict(command_succeeded=True, exit_code=0)
        self.assertTrue(cov.bftpd_protocol_end_expected(replay, ledger, 221, reset))
        replay["client_timed_out"] = True
        self.assertFalse(cov.bftpd_protocol_end_expected(replay, ledger, 221, reset))
        replay["client_timed_out"] = False
        ledger["peer_closed"] = False
        self.assertFalse(cov.bftpd_protocol_end_expected(replay, ledger, 221, reset))

    def test_bftpd_protocol_close_after_quit_requires_peer_closed_ledger(self):
        replay = dict(server_exit_code=0, client_exit_code=2,
                      server_ready=True, client_timed_out=False,
                      harness_shutdown_requested=False,
                      imported_gcda=["main.gcda"], session_coverage_missing=False)
        reset = dict(command_succeeded=True, exit_code=0)
        ledger = dict(prefix_sent_complete=True, peer_closed=False,
                      frames_unattempted=1, frames_attempted=1, frames_total=1,
                      sent_prefix_has_bftpd_quit=True,
                      last_attempted_frame_is_quit=True,
                      last_attempted_post_recv_ok=True,
                      stop_reason="protocol-close-after-quit")
        self.assertFalse(cov.bftpd_protocol_end_expected(
            replay, ledger, 221, reset, policy_version=4))
        ledger["peer_closed"] = True
        self.assertTrue(cov.bftpd_protocol_end_expected(
            replay, ledger, 221, reset, policy_version=4))

    def test_bftpd_v2_quit_matches_its_real_command_parser(self):
        for stream in (b"QUIT\xffyyPASS ubuntu\r\n",
                       b"SYST\nQUIT\x10XMK\r\n",
                       b"SYST\nQUIT\r\x7f\r\n",
                       b"SYST\nQUIT\x08\n"):
            with self.subTest(stream=stream):
                self.assertTrue(cov.bftpd_stream_has_quit(stream))
        for stream in (b"SYSTQUIT\r\n", b"QUI\x00T\r\n",
                       b"SYST\nNOOP\r\n", b"X" * 253 + b"QUIT\r\n"):
            with self.subTest(stream=stream):
                self.assertFalse(cov.bftpd_stream_has_quit(stream))
        replay = dict(server_exit_code=0, client_exit_code=2,
                      server_ready=True, client_timed_out=False,
                      harness_shutdown_requested=False, imported_gcda=["main.gcda"],
                      session_coverage_missing=False)
        ledger = dict(prefix_sent_complete=True, peer_closed=True,
                      frames_unattempted=3, frames_attempted=2,
                      sent_prefix_has_bftpd_quit=True,
                      last_attempted_frame_is_quit=False,
                      stop_reason="peer-closed-before-input-end")
        reset = dict(command_succeeded=True, exit_code=0)
        self.assertTrue(cov.bftpd_protocol_end_expected(
            replay, ledger, 221, reset, policy_version=2))
        self.assertFalse(cov.bftpd_protocol_end_expected(replay, ledger, 221, reset))
        for bad_reply in (200, 421, None):
            self.assertFalse(cov.bftpd_protocol_end_expected(
                replay, ledger, bad_reply, reset, policy_version=2))
        ledger["stop_reason"] = "client-recv-post-send-failed"
        self.assertFalse(cov.bftpd_protocol_end_expected(
            replay, ledger, 221, reset, policy_version=2))
        ledger.update(peer_closed=False, prior_post_recv_ok=True,
                      last_attempted_post_recv_ok=False,
                      last_attempted_post_recv_errno=errno.ECONNRESET)
        self.assertTrue(cov.bftpd_protocol_end_expected(
            replay, ledger, 221, reset, policy_version=3))
        self.assertFalse(cov.bftpd_protocol_end_expected(
            replay, ledger, 250, reset, policy_version=3))
        for changed in (dict(last_attempted_post_recv_errno=errno.ETIMEDOUT),
                        dict(prior_post_recv_ok=False),
                        dict(last_attempted_post_recv_ok=True)):
            self.assertFalse(cov.bftpd_protocol_end_expected(
                replay, dict(ledger, **changed), 221, reset, policy_version=3))

    def test_all_nine_replay_commands_use_local_port_zero(self):
        for target, protocol in cov.TARGET_PROTOCOLS.items():
            with self.subTest(target=target):
                command, _ = cov.replay_commands(target, "input", 2121, 1,
                                                 self.root, self.root)
                self.assertEqual(command,
                                 [str(self.replayer), "input", protocol, "2121",
                                  "0", "100", "10000"])

    def test_cross_target_frame_audit_recomputes_sent_bytes(self):
        filename = "id:000001.raw"
        input_path = self.root / filename
        payload = b"NOOP\r\n"
        input_path.write_bytes(struct.pack("<I", len(payload)) + payload)
        input_hash = cov.digest_file(input_path)
        replay_log = self.root / "replay-000001.log"
        reset_log = self.root / "reset-000001.log"
        ledger_path = self.root / "replay-000001-frame-ledger.jsonl"
        replay_log.write_text("replay complete\n")
        reset_log.write_text("reset complete\n")
        planned = dict(filename=filename, path=str(input_path), input_sha256=input_hash)
        for target, protocol in cov.TARGET_PROTOCOLS.items():
            if target == "bftpd":
                continue
            with self.subTest(target=target):
                rows = [dict(event="session_begin", schema="loopfuzz-replay-frame-ledger-v1",
                             input_file=filename, input_size=input_path.stat().st_size,
                             protocol=protocol),
                        dict(event="frame", frame=1, len=len(payload),
                             read_complete=True, pre_recv_ok=True, send_attempt=True,
                             sent_bytes=len(payload), send_errno=0, post_recv_ok=True),
                        dict(event="session_end", frames_total=1, stop_reason="eof",
                             peer_closed=False)]
                ledger_path.write_text("\n".join(map(json.dumps, rows)) + "\n")
                replay = dict(client_command=[str(self.replayer), str(input_path),
                                              protocol, "2121", "0", "100", "10000"],
                              replay_log_file=replay_log.name,
                              replay_log_sha256=cov.digest_file(replay_log),
                              frame_ledger_file=ledger_path.name,
                              frame_ledger_sha256=cov.digest_file(ledger_path),
                              frames_total=1, frames_unattempted=0,
                              frames_attempted=1, frames_sent_complete=1,
                              send_stop_reason="eof", send_completeness="complete",
                              incomplete_reasons=[], coverage_complete=True)
                gcno = None
                if target in cov.ACCUMULATING_GCDA_TARGETS:
                    replay.update(session_gcda_touched=["main.gcda"],
                                  session_coverage_missing=False)
                    gcno = {"main.gcno": "fixture"}
                reset = dict(log_file=reset_log.name,
                             log_sha256=cov.digest_file(reset_log))
                event = dict(filename=filename, input_sha256=input_hash,
                             replay=replay, reset=reset)
                cov.verify_target_frame_replay(event, planned, self.root, 1, target,
                                               gcno=gcno)
                if gcno is not None:
                    replay["session_gcda_touched"] = []
                    with self.assertRaisesRegex(cov.CoverageError, "gcda freshness"):
                        cov.verify_target_frame_replay(event, planned, self.root, 1, target,
                                                       gcno=gcno)
                    replay["session_gcda_touched"] = ["main.gcda"]
                replay["client_command"][4] = "100"
                with self.assertRaisesRegex(cov.CoverageError, "client ABI"):
                    cov.verify_target_frame_replay(event, planned, self.root, 1, target)
                replay["client_command"][4] = "0"
                replay["frames_sent_complete"] = 0
                with self.assertRaisesRegex(cov.CoverageError, "frame ledger classification"):
                    cov.verify_target_frame_replay(event, planned, self.root, 1, target)

    def test_protocol_end_requires_request_reply_and_coverage_evidence(self):
        ftp_log = self.root / "ftp-end.log"
        ftp_log.write_bytes(
            b"Responses from server:0-220-221-\nResponses in details:\n"
            b"220 ready\r\n221 bye\r\n\n--------------------------------\n")
        http_log = self.root / "http-end.log"
        http_log.write_bytes(
            b"Responses from server:0-200-\nResponses in details:\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n"
            b"BODY\n--------------------------------\n")
        valid_http = http_log.read_bytes()
        reset = dict(command_succeeded=True, exit_code=0)
        replay = dict(server_exit_code=0, client_exit_code=2, server_ready=True,
                      client_timed_out=False, helper_ready=None,
                      session_coverage_missing=False,
                      imported_gcda=["main.gcda"], session_gcda_touched=["main.gcda"])
        ledger = dict(prefix_sent_complete=True, frames_unattempted=1,
                      peer_closed=True, stop_reason="peer-closed-before-input-end",
                      last_attempted_frame_is_quit=True,
                      last_attempted_frame_is_http_close=True)
        for target, log in (("lightftp", ftp_log), ("pure-ftpd", ftp_log),
                            ("forked-daapd", http_log), ("lighttpd1", http_log)):
            with self.subTest(target=target):
                self.assertTrue(cov.protocol_end_expected(target, replay, reset, ledger, log))
                self.assertFalse(cov.protocol_end_expected(
                    target, replay, reset, dict(ledger, frames_unattempted=0), log))
                self.assertFalse(cov.protocol_end_expected(
                    target, replay, reset, dict(ledger, frames_unattempted=None), log))
                self.assertFalse(cov.protocol_end_expected(
                    target, replay, dict(reset, exit_code=1), ledger, log))
                self.assertFalse(cov.protocol_end_expected(
                    target, dict(replay, session_coverage_missing=True), reset, ledger, log))
        self.assertFalse(cov.protocol_end_expected(
            "lightftp", replay, reset,
            dict(ledger, last_attempted_frame_is_quit=False), ftp_log))
        self.assertFalse(cov.protocol_end_expected(
            "pure-ftpd", dict(replay, imported_gcda=[]), reset, ledger, ftp_log))
        self.assertFalse(cov.protocol_end_expected(
            "lighttpd1", dict(replay, session_gcda_touched=[]), reset, ledger, http_log))
        self.assertFalse(cov.protocol_end_expected(
            "forked-daapd", replay, reset,
            dict(ledger, last_attempted_frame_is_http_close=False), http_log))
        http_log.write_bytes(valid_http.replace(b"Content-Length: 4",
                                                b"Content-Length: 5"))
        self.assertFalse(cov.http_close_response_complete(http_log))
        http_log.write_bytes(valid_http.replace(
            b"Content-Length: 4", b"Content-Length: " + b"9" * 100))
        self.assertFalse(cov.http_close_response_complete(http_log))
        http_log.write_bytes(valid_http.replace(b"Connection: close",
                                                b"Connection: keep-alive"))
        self.assertFalse(cov.http_close_response_complete(http_log))
        self.assertFalse(cov.http_close_request(
            b"GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n"))

    def test_v5_protocol_close_requires_terminal_reply_and_fresh_coverage(self):
        http_log = self.root / "http-v5.log"
        http_log.write_bytes(
            b"Responses from server:0-200-405-\nResponses in details:\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
            b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n"
            b"Content-Length: 4\r\n\r\nBODY\n--------------------------------")
        smtp_log = self.root / "smtp-v5.log"
        smtp_log.write_bytes(b"Responses from server:0-220-421-\nResponses in details:\n"
                             b"220 ready\r\n421 Too many errors\r\n\n--------------------------------")
        ftp_log = self.root / "ftp-v5.log"
        ftp_log.write_bytes(b"Responses from server:0-220-221-\nResponses in details:\n"
                            b"220 ready\r\n221 closing\r\n\n--------------------------------")
        replay = dict(server_exit_code=0, client_exit_code=2, server_ready=True,
                      client_timed_out=False, session_coverage_missing=False,
                      session_gcda_touched=["main.gcda"], imported_gcda=["main.gcda"])
        reset = dict(command_succeeded=True, exit_code=0)
        ledger = dict(prefix_sent_complete=True, frames_unattempted=2,
                      peer_closed=True, stop_reason="peer-closed-before-input-end")
        for target, log in (("lighttpd1", http_log), ("forked-daapd", http_log),
                            ("lightftp", ftp_log), ("pure-ftpd", ftp_log),
                            ("exim", smtp_log)):
            with self.subTest(target=target):
                self.assertTrue(cov.protocol_end_expected(
                    target, replay, reset, ledger, log, policy_version=5))
                self.assertFalse(cov.protocol_end_expected(
                    target, replay, reset, dict(ledger, frames_unattempted=0),
                    log, policy_version=5))
                self.assertFalse(cov.protocol_end_expected(
                    target, dict(replay, session_coverage_missing=True), reset,
                    ledger, log, policy_version=5))
        self.assertTrue(cov.http_final_close_response_complete(http_log))
        http_log.write_bytes(http_log.read_bytes().replace(b"Content-Length: 4", b"Content-Length: 5"))
        self.assertFalse(cov.http_final_close_response_complete(http_log))
        self.assertFalse(cov.protocol_end_expected(
            "lighttpd1", replay, reset, ledger, http_log, policy_version=5))
        self.assertEqual(cov.smtp_final_close_reply(smtp_log), 421)
        reset_ledger = dict(
            ledger, peer_closed=False, stop_reason="client-recv-post-send-failed",
            prior_post_recv_ok=True, last_attempted_post_recv_ok=False,
            last_attempted_post_recv_errno=errno.ECONNRESET)
        self.assertTrue(cov.protocol_end_expected(
            "exim", replay, reset, reset_ledger, smtp_log, policy_version=5))
        self.assertFalse(cov.protocol_end_expected(
            "exim", replay, reset,
            dict(reset_ledger, last_attempted_post_recv_ok=True),
            smtp_log, policy_version=5))
        smtp_log.write_bytes(smtp_log.read_bytes().replace(
            b"421 Too many errors", b"503 Too many syntax or protocol errors"))
        self.assertTrue(cov.protocol_end_expected(
            "exim", replay, reset, ledger, smtp_log, policy_version=5))
        smtp_log.write_bytes(smtp_log.read_bytes().replace(
            b"503 Too many syntax or protocol errors", b"500 syntax error"))
        self.assertFalse(cov.protocol_end_expected(
            "exim", replay, reset, ledger, smtp_log, policy_version=5))
        self.assertFalse(cov.protocol_end_expected(
            "exim", replay, reset,
            dict(ledger, peer_closed=False, stop_reason="client-recv-post-send-failed",
                 prior_post_recv_ok=True, last_attempted_post_recv_errno=errno.ETIMEDOUT),
            smtp_log, policy_version=5))

    def test_v5_final_reset_is_full_send_only_without_a_suffix(self):
        ledger_path = self.root / "reset-ledger.jsonl"
        rows = [dict(event="session_begin", schema="loopfuzz-replay-frame-ledger-v1"),
                dict(event="frame", frame=1, len=4, read_complete=True,
                     pre_recv_ok=True, send_attempt=True, sent_bytes=4,
                     send_errno=0, post_recv_ok=False,
                     post_recv_errno=errno.ECONNRESET),
                dict(event="session_end", frames_total=1,
                     stop_reason="peer-reset-after-input-end", peer_closed=False)]
        ledger_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        framed = struct.pack("<I", 4) + b"NOOP"
        self.assertTrue(cov.read_frame_ledger(ledger_path, framed)["send_complete"])
        self.assertFalse(cov.read_frame_ledger(
            ledger_path, framed + struct.pack("<I", 4) + b"QUIT")["send_complete"])
        rows[1]["post_recv_errno"] = errno.ETIMEDOUT
        ledger_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        self.assertFalse(cov.read_frame_ledger(ledger_path, framed)["send_complete"])
        rows[1]["post_recv_errno"] = errno.ECONNRESET
        rows[1]["post_recv_ok"] = True
        ledger_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        self.assertFalse(cov.read_frame_ledger(ledger_path, framed)["send_complete"])

    def test_v5_http_close_rejects_ambiguous_or_truncated_response(self):
        log = self.root / "http-invalid-v5.log"
        prefix = b"Responses from server:0-200-\nResponses in details:\n"
        footer = b"\n--------------------------------"
        valid = (b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
                 b"Content-Length: 2\r\n\r\nOK")
        log.write_bytes(prefix + valid + footer)
        self.assertTrue(cov.http_final_close_response_complete(log))
        invalid = (
            valid.replace(b"HTTP/1.1 200 OK", b"not a status line"),
            valid.replace(b"Content-Length: 2\r\n", b""),
            valid.replace(b"Content-Length: 2\r\n",
                          b"Content-Length: 2\r\nContent-Length: 2\r\n"),
            valid.replace(b"Content-Length: 2\r\n",
                          b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n"),
            valid.replace(b"Content-Length: 2", b"Content-Length: 3"),
            valid.replace(b"Connection: close", b"Connection: keep-alive"),
            valid + b"HTTP/1.1 200 OK\r\nConnection: close\r\n",
        )
        for response in invalid:
            with self.subTest(response=response):
                log.write_bytes(prefix + response + footer)
                self.assertFalse(cov.http_final_close_response_complete(log))

    def test_http_close_requires_summary_detail_status_sequence_match(self):
        log = self.root / "http-status-sequence.log"
        footer = b"\n--------------------------------"
        first = (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        closing = (b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n"
                   b"Content-Length: 3\r\n\r\nBAD")
        reordered_first = (b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 3\r\n"
                           b"\r\nBAD")
        final_close = (b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
                       b"Content-Length: 2\r\n\r\nOK")

        cases = (
            (b"0-200-405-", first + closing, True),
            (b"0-200-", first + closing, False),
            (b"0-200-405-", final_close, False),
            (b"0-200-405-", reordered_first + final_close, False),
        )
        for sequence, details, expected in cases:
            with self.subTest(sequence=sequence, expected=expected):
                log.write_bytes(b"Responses from server:" + sequence +
                                b"\nResponses in details:\n" + details + footer)
                self.assertEqual(cov.http_final_close_response_complete(log), expected)

    def test_http_close_accepts_complete_unknown_minor_version(self):
        log = self.root / "http-unknown-minor.log"
        prefix = b"Responses from server:0-400-\nResponses in details:\n"
        response = (b"HTTP/1.5 400 Bad Request\r\nConnection: close\r\n"
                    b"Content-Length: 4\r\n\r\nbody")
        footer = b"\n--------------------------------"
        log.write_bytes(prefix + response + footer)
        self.assertTrue(cov.http_final_close_response_complete(log))
        log.write_bytes(prefix + response[:-1] + footer)
        self.assertFalse(cov.http_final_close_response_complete(log))

    def test_v5_http_head_response_has_no_body_despite_content_length(self):
        log = self.root / "http-head-v5.log"
        prefix = b"Responses from server:0-200-400-\nResponses in details:\n"
        footer = b"\n--------------------------------"
        head_reply = (b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
        close_reply = (b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n"
                       b"Content-Length: 2\r\n\r\nOK")
        frames = [b"HEAD /x HTTP/1.1\r\nHost: localhost\r\n\r\n",
                  b"GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n"]
        log.write_bytes(prefix + head_reply + close_reply + footer)
        self.assertFalse(cov.http_final_close_response_complete(log))
        self.assertTrue(cov.http_final_close_response_complete(log, frames))
        replay = dict(server_exit_code=0, client_exit_code=2, server_ready=True,
                      client_timed_out=False, session_coverage_missing=False,
                      session_gcda_touched=["main.gcda"])
        reset = dict(command_succeeded=True, exit_code=0)
        ledger = dict(prefix_sent_complete=True, frames_unattempted=1,
                      peer_closed=True, stop_reason="peer-closed-before-input-end",
                      sent_payloads=frames)
        self.assertTrue(cov.protocol_end_expected(
            "lighttpd1", replay, reset, ledger, log, policy_version=5))
        self.assertFalse(cov.http_final_close_response_complete(
            log, [frames[0].replace(b"HEAD ", b"XGET "), frames[1]]))
        self.assertFalse(cov.protocol_end_expected(
            "lighttpd1", replay, reset,
            dict(ledger, sent_payloads=[frames[0].replace(b"HEAD ", b"XGET "),
                                        frames[1]]), log, policy_version=5))
        log.write_bytes(prefix + head_reply + close_reply[:-2] + footer)
        self.assertFalse(cov.http_final_close_response_complete(log, frames))

    def test_v6_exim_quit_close_and_lightftp_buffer_boundary(self):
        smtp_log = self.root / "smtp-quit-v6.log"
        smtp_log.write_bytes(
            b"Responses from server:0-220-221-\nResponses in details:\n"
            b"220 ready\r\n221 closing connection\r\n\n--------------------------------")
        replay = dict(server_exit_code=0, client_exit_code=2, server_ready=True,
                      client_timed_out=False, session_coverage_missing=False,
                      session_gcda_touched=["smtp_in.gcda"])
        reset = dict(command_succeeded=True, exit_code=0)
        quit_ledger = dict(prefix_sent_complete=True, frames_unattempted=2,
                           peer_closed=True, stop_reason="protocol-close-after-quit",
                           last_attempted_frame_is_quit=True,
                           last_attempted_post_recv_ok=True)
        self.assertTrue(cov.protocol_end_expected(
            "exim", replay, reset, quit_ledger, smtp_log, policy_version=6))
        self.assertFalse(cov.protocol_end_expected(
            "exim", replay, reset, dict(quit_ledger, last_attempted_frame_is_quit=False),
            smtp_log, policy_version=6))
        self.assertFalse(cov.protocol_end_expected(
            "exim", replay, reset, dict(quit_ledger, stop_reason="client-recv-post-send-failed"),
            smtp_log, policy_version=6))
        self.assertFalse(cov.protocol_end_expected(
            "exim", replay, reset, dict(quit_ledger, peer_closed=False),
            smtp_log, policy_version=6))

        source_root, object_root = self.root / "Source", self.root / "Release"
        source_root.mkdir()
        object_root.mkdir()
        source = source_root / "ftpserv.c"
        source.write_bytes(b'#include "ftpserv.h"\n'
                           b"char *cmd, *params, rcvbuf[PATH_MAX]; "
                           b"int recvcmd(PFTPCONTEXT context, char *buffer, size_t buffer_size) "
                           b"--buffer_size; while (buffer_size > 0) if ( p >= 2 ) "
                           b"(buffer[p-2] == '\\r') && (buffer[p-1] == '\\n') "
                           b"if ( !recvcmd(&ctx, rcvbuf, sizeof(rcvbuf)) ) break; "
                           b"WorkerThreadCleanup(&ctx); close(ctx.ControlSocket);")
        (source_root / "ftpserv.h").write_bytes(b"#include <limits.h>\n")
        binary = object_root / "fftp"
        binary.write_text("fixture executable\n")
        binary.chmod(0o755)
        policy = cov.lightftp_replay_policy(source_root, object_root)
        self.assertFalse(policy["verified"])
        self.assertFalse(policy["exception_enabled"])
        self.assertEqual(policy["source_binary_build_association"], "not-established")
        self.assertTrue(cov.verify_lightftp_replay_policy(policy, source_root, object_root))
        self.assertTrue(cov.replay_policy_verified_for_completeness(
            "lightftp", policy, source_root, object_root))
        enabled_policy = dict(policy, verified=True, exception_enabled=True,
                              source_binary_build_association="verified")
        self.assertFalse(cov.verify_lightftp_replay_policy(
            enabled_policy, source_root, object_root))
        ledger = dict(prefix_sent_complete=True, frames_unattempted=4,
                      peer_closed=False,
                      stop_reason="client-recv-post-send-failed",
                      prior_post_recv_ok=True,
                      last_attempted_post_recv_ok=False,
                      last_attempted_post_recv_errno=errno.ECONNRESET,
                      sent_payloads=[b"NOOP\r\n", b"X" * 3000,
                                     b"Y" * (policy["max_bytes_without_crlf"] - 3000)])
        lightftp_replay = dict(replay, session_gcda_touched=["ftpserv.gcda"])
        ftp_log = self.root / "no-ftp-reply.log"
        ftp_log.write_bytes(b"Responses from server:0-230-\nResponses in details:\n"
                            b"230 User logged in, proceed.\r\n\n--------------------------------")
        self.assertFalse(cov.protocol_end_expected(
            "lightftp", lightftp_replay, reset, ledger, ftp_log,
            policy_version=6, replay_policy=policy))
        self.assertEqual(policy["command_buffer_size"], policy["path_max"])
        quit_log = self.root / "quit-reply.log"
        quit_log.write_bytes(
            b"Responses from server:0-220-221-\nResponses in details:\n"
            b"220 FTP server ready.\r\n221 Goodbye.\r\n\n--------------------------------")
        quit_ledger = dict(prefix_sent_complete=True, frames_unattempted=1,
                           peer_closed=True, stop_reason="protocol-close-after-quit",
                           last_attempted_frame_is_quit=True,
                           last_attempted_post_recv_ok=True)
        self.assertTrue(cov.protocol_end_expected(
            "lightftp", lightftp_replay, reset, quit_ledger, quit_log,
            policy_version=6, replay_policy=policy))
        original_source = source.read_bytes()
        source.write_bytes(b"changed")
        self.assertFalse(cov.verify_lightftp_replay_policy(policy, source_root, object_root))
        self.assertFalse(cov.replay_policy_verified_for_completeness(
            "lightftp", policy, source_root, object_root))
        source.write_bytes(original_source)
        binary.write_text("changed executable\n")
        self.assertFalse(cov.verify_lightftp_replay_policy(policy, source_root, object_root))
        self.assertFalse(cov.replay_policy_verified_for_completeness(
            "lightftp", policy, source_root, object_root))

    def test_overlong_close_trigger_frame_boundaries(self):
        payloads_ok = [b"USER x\r\n", b"PASS x\r\n", b"A" * 5000, b"NOOP\r\n"]
        self.assertEqual(cov.overlong_close_trigger_frame(payloads_ok, 2048, b"\n"), 3)
        self.assertEqual(cov.overlong_close_trigger_frame(payloads_ok, 4095, b"\r\n"), 3)
        # First frame starts a fresh command after the banner.
        self.assertEqual(cov.overlong_close_trigger_frame(
            [b"A" * 5000, b"NOOP\r\n"], 4095, b"\r\n"), 1)
        # Below the derived minimum: the server is still within its budget.
        self.assertIsNone(cov.overlong_close_trigger_frame(
            payloads_ok[:2] + [b"A" * 2047], 2048, b"\n"))
        # A newline inside the window lets the server resynchronize.
        self.assertIsNone(cov.overlong_close_trigger_frame(
            payloads_ok[:2] + [b"A" * 1500 + b"\n" + b"A" * 1500], 2048, b"\n"))
        # The overlong frame must start at a command boundary: a partial
        # command before it means the server is mid-command, not at frame start.
        self.assertIsNone(cov.overlong_close_trigger_frame(
            [b"USE", b"A" * 3000], 2048, b"\n"))
        # Telnet IAC escapes compress the stream: the raw window must grow by
        # three bytes per 0xFF so the processed window still exceeds the
        # minimum without a newline.
        self.assertEqual(cov.overlong_close_trigger_frame(
            payloads_ok[:2] + [b"A" * 2049 + b"\xff" + b"A" * 20], 2048, b"\n",
            telnet_iac=True), 3)
        self.assertIsNone(cov.overlong_close_trigger_frame(
            payloads_ok[:2] + [b"\xff" * 800 + b"A" * 1800], 2048, b"\n",
            telnet_iac=True))
        # Without the telnet bound the same payload would falsely trigger.
        self.assertEqual(cov.overlong_close_trigger_frame(
            payloads_ok[:2] + [b"\xff" * 800 + b"A" * 1800], 2048, b"\n"), 3)

    def _overlong_replay_and_reset(self, **overrides):
        replay = dict(server_exit_code=0, client_exit_code=2, server_ready=True,
                      client_timed_out=False, session_coverage_missing=False,
                      session_gcda_touched=["src/main.gcda"],
                      harness_shutdown_requested=False)
        reset = dict(command_succeeded=True, exit_code=0)
        replay.update(overrides)
        return replay, reset

    def test_proftpd_overlong_close_expected_gate_matrix(self):
        policy = dict(overlong_close=dict(
            verified=True, exception_enabled=True, give_up_bytes=16408))
        ledger = dict(
            prefix_sent_complete=True, frames_unattempted=4,
            prior_post_recv_ok=True, stop_reason="client-recv-post-send-failed",
            last_attempted_post_recv_errno=errno.ECONNRESET,
            sent_payloads=[b"USER ubuntu\r\n", b"PASS ubuntu\r\n",
                           b"A" * 18940, b"ACCT\r\n", b"NOOP\r\n"])
        replay, reset = self._overlong_replay_and_reset()
        self.assertTrue(cov.proftpd_overlong_close_expected(replay, reset, ledger, policy))
        self.assertFalse(cov.proftpd_overlong_close_expected(
            replay, reset, ledger,
            dict(policy, overlong_close=dict(policy["overlong_close"], verified=False))))
        self.assertFalse(cov.proftpd_overlong_close_expected(
            replay, reset, ledger,
            dict(policy, overlong_close=dict(policy["overlong_close"],
                                             exception_enabled=False))))
        # Pre-send variant: the reset surfaced in the next unattempted frame's
        # pre-recv, and the never-sent big frame is absent from sent_payloads.
        pre_send = dict(
            ledger, stop_reason="client-recv-pre-send-failed",
            last_attempted_post_recv_errno=0,
            next_unattempted_pre_recv_errno=errno.ECONNRESET,
            sent_payloads=[b"USER ubuntu\r\n", b"PASS ubuntu\r\n", b"A" * 27286,
                           b"SYST\r\n", b"CDUPF\r\n"])
        self.assertTrue(cov.proftpd_overlong_close_expected(replay, reset, pre_send, policy))
        self.assertFalse(cov.proftpd_overlong_close_expected(
            replay, reset,
            dict(pre_send, next_unattempted_pre_recv_errno=0), policy))
        for field, value in (("harness_shutdown_requested", True),
                             ("server_exit_code", 124),
                             ("client_exit_code", 0),
                             ("client_timed_out", True),
                             ("session_gcda_touched", [])):
            broken_replay, broken_reset = self._overlong_replay_and_reset(**{field: value})
            self.assertFalse(cov.proftpd_overlong_close_expected(
                broken_replay, broken_reset, ledger, policy), field)
        self.assertFalse(cov.proftpd_overlong_close_expected(
            replay, dict(reset, exit_code=1), ledger, policy))
        for field, value in (("stop_reason", "send-short-or-error"),
                             ("last_attempted_post_recv_errno", errno.EPIPE),
                             ("prior_post_recv_ok", False),
                             ("prefix_sent_complete", False),
                             ("frames_unattempted", 0)):
            self.assertFalse(cov.proftpd_overlong_close_expected(
                replay, reset, dict(ledger, **{field: value}), policy), field)
        # An input whose largest no-newline frame stays inside the budget
        # never reaches the E2BIG give-up and must not be accepted.
        self.assertFalse(cov.proftpd_overlong_close_expected(
            replay, reset,
            dict(ledger, sent_payloads=[b"USER x\r\n", b"A" * 16000]), policy))

    def test_lightftp_oversized_command_close_expected_shapes(self):
        enabled = dict(verified=True, exception_enabled=True,
                       max_bytes_without_crlf=4095)
        disabled = dict(enabled, exception_enabled=False)
        midstream = dict(
            prefix_sent_complete=True, frames_unattempted=7,
            prior_post_recv_ok=True, stop_reason="client-recv-post-send-failed",
            last_attempted_post_recv_errno=errno.ECONNRESET,
            sent_payloads=[b"USER anonymous\r\n", b"PASS x\r\n", b"LIST\r\n",
                           b"Q" * 17521])
        tail = dict(
            midstream, sent_payloads=[b"NOOP\r\n", b"X" * 3000,
                                      b"Y" * (4095 - 3000)])
        replay, reset = self._overlong_replay_and_reset(
            session_gcda_touched=["ftpserv.gcda"])
        self.assertTrue(cov.lightftp_oversized_command_close_expected(
            replay, reset, midstream, enabled))
        self.assertTrue(cov.lightftp_oversized_command_close_expected(
            replay, reset, tail, enabled))
        self.assertFalse(cov.lightftp_oversized_command_close_expected(
            replay, reset, midstream, disabled))
        # A CRLF inside the first 4095 bytes does not rescue the session:
        # recvcmd tests only the accumulated tail, so the buffer still fills
        # and the close happens (tail shape covers it here).
        self.assertTrue(cov.lightftp_oversized_command_close_expected(
            replay, reset,
            dict(midstream, sent_payloads=[b"USER x\r\n",
                                           b"A" * 4000 + b"\r\n" + b"A" * 14000]),
            enabled))

    def test_protocol_end_expected_proftpd_overlong_is_v11_gated(self):
        policy = dict(overlong_close=dict(
            verified=True, exception_enabled=True, give_up_bytes=16408))
        ledger = dict(
            prefix_sent_complete=True, frames_unattempted=4,
            prior_post_recv_ok=True, stop_reason="client-recv-post-send-failed",
            last_attempted_post_recv_ok=False, peer_closed=False,
            last_attempted_post_recv_errno=errno.ECONNRESET,
            sent_payloads=[b"USER ubuntu\r\n", b"PASS ubuntu\r\n",
                           b"A" * 18940, b"ACCT\r\n"])
        replay, reset = self._overlong_replay_and_reset()
        log = self.root / "proftpd-overlong.log"
        log.write_bytes(b"Responses from server:0-220-331-230-\n"
                        b"Responses in details:\n220 ready\r\n331 pass\r\n230 ok\r\n"
                        b"\n--------------------------------")
        self.assertFalse(cov.protocol_end_expected(
            "proftpd", replay, reset, ledger, log, policy_version=10,
            replay_policy=policy))
        self.assertTrue(cov.protocol_end_expected(
            "proftpd", replay, reset, ledger, log, policy_version=11,
            replay_policy=policy))
        # The reset can land between frames (v11b id:000259): the stop is the
        # next frame's pre-recv and the errno evidence moves to the
        # never-sent row; v10's outer gate must keep rejecting it.
        pre_send = dict(
            ledger, stop_reason="client-recv-pre-send-failed",
            last_attempted_post_recv_ok=True, last_attempted_post_recv_errno=0,
            next_unattempted_pre_recv_errno=errno.ECONNRESET,
            sent_payloads=[b"USER ubuntu\r\n", b"PASS ubuntu\r\n",
                           b"A" * 22311, b"ACCT\r\n", b"REIN\r\n"])
        self.assertFalse(cov.protocol_end_expected(
            "proftpd", replay, reset, pre_send, log, policy_version=10,
            replay_policy=policy))
        self.assertTrue(cov.protocol_end_expected(
            "proftpd", replay, reset, pre_send, log, policy_version=11,
            replay_policy=policy))
        for field, value in (("next_unattempted_pre_recv_errno", errno.EPIPE),
                             ("last_attempted_post_recv_ok", False),
                             ("prior_post_recv_ok", False)):
            self.assertFalse(cov.protocol_end_expected(
                "proftpd", replay, reset, dict(pre_send, **{field: value}), log,
                policy_version=11, replay_policy=policy), field)
        accepted = cov.replay_incompleteness(
            dict(replay, replay_anomaly=False, anomaly_kind="",
                 send_completeness="incomplete", protocol_end_expected=True))
        self.assertEqual(accepted, [])

    def test_read_frame_ledger_exposes_pre_send_reset_errno(self):
        rows = [
            dict(event="session_begin", schema="loopfuzz-replay-frame-ledger-v1",
                 input_file="x", input_size=0, protocol="FTP"),
            dict(event="frame", frame=1, len=6, read_complete=True,
                 pre_recv_ok=True, send_attempt=True, sent_bytes=6,
                 send_errno=0, post_recv_ok=True, pre_recv_errno=0,
                 post_recv_errno=0, peer_closed=False),
            dict(event="frame", frame=2, len=6, read_complete=True,
                 pre_recv_ok=False, send_attempt=False, sent_bytes=-2,
                 send_errno=0, post_recv_ok=False, pre_recv_errno=errno.ECONNRESET,
                 post_recv_errno=0, peer_closed=False),
            dict(event="session_end", frames_total=2,
                 stop_reason="client-recv-pre-send-failed", peer_closed=False),
        ]
        ledger_path = self.root / "pre-send-ledger.jsonl"
        framed = (struct.pack("<I", 6) + b"NOOP\r\n") * 2
        ledger_path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        ledger = cov.read_frame_ledger(ledger_path, framed)
        self.assertEqual(ledger["next_unattempted_pre_recv_errno"], errno.ECONNRESET)
        self.assertEqual(ledger["frames_attempted"], 1)
        self.assertEqual(ledger["frames_unattempted"], 1)

    def test_proftpd_overlong_source_policy_derives_boundary(self):
        source_root = self.root / "proftpd-gcov"
        (source_root / "src").mkdir(parents=True)
        main_c = source_root / "src" / "main.c"
        main_c.write_bytes(
            b"#define PR_DEFAULT_CMD_BUFSZ\t(PR_TUNABLE_PATH_MAX + 7)\n"
            b"int pr_cmd_read(void) { if (errno == E2BIG) {\n"
            b"too_large_count++;\n"
            b"pr_timer_usleep(250 * 1000);\n"
            b"if (too_large_count > 3) { return -1; } } }\n")
        (source_root / "src" / "netio.c").write_bytes(
            b"if (saw_newline == FALSE) { errno = E2BIG; return -1; }\n")
        binary = source_root / "proftpd"
        binary.write_text("fixture\n")
        binary.chmod(0o755)
        conf = self.root / "basic.conf"
        conf.write_bytes(b"ServerName test\nPort 21\n")
        policy = cov.proftpd_overlong_source_policy(source_root, source_root, conf)
        self.assertTrue(policy["verified"])
        self.assertFalse(policy["exception_enabled"])
        self.assertEqual(policy["command_buffer_size_source"], "source-default")
        self.assertEqual(policy["command_buffer_size_effective"], 4096 + 7)
        self.assertEqual(policy["give_up_bytes"], 4 * (4096 + 7 - 1))
        self.assertEqual(policy["probe_min_close_delay_ms"], 1000)
        # The fuzzing run.sh injects CommandBufferSize 65535; the boundary
        # must follow the effective value, never the source default.
        conf.write_bytes(b"ServerName test\nPort 21\nCommandBufferSize\t65535\n")
        policy = cov.proftpd_overlong_source_policy(source_root, source_root, conf)
        self.assertTrue(policy["verified"])
        self.assertEqual(policy["command_buffer_size_source"], "conf-directive")
        self.assertEqual(policy["command_buffer_size_effective"], 65535)
        self.assertEqual(policy["give_up_bytes"], 4 * (65535 - 1))
        self.assertEqual(policy["command_buffer_size_default"], 4096 + 7)

    def test_lightftp_v5_policy_requires_probe_and_artifacts(self):
        source_root, object_root = self.root / "Source", self.root / "Release"
        source_root.mkdir()
        object_root.mkdir()
        (source_root / "ftpserv.c").write_bytes(
            b'#include "ftpserv.h"\nchar rcvbuf[PATH_MAX]; '
            b"int recvcmd(PFTPCONTEXT context, char *buffer, size_t buffer_size) "
            b"--buffer_size; while (buffer_size > 0) if ( p >= 2 ) "
            b"(buffer[p-2] == '\\r') && (buffer[p-1] == '\\n') "
            b"if ( !recvcmd(&ctx, rcvbuf, sizeof(rcvbuf)) ) break; "
            b"close(ctx.ControlSocket);")
        (source_root / "ftpserv.h").write_bytes(b"#include <limits.h>\n")
        binary = object_root / "fftp"
        binary.write_text("fixture\n")
        binary.chmod(0o755)
        probe = dict(verified=False, minimum_bytes=4095,
                     probe_ledger_file="probe-frame-ledger.jsonl",
                     probe_log_file="probe.log")
        build = dict(verified=False)
        policy = cov.lightftp_replay_policy(source_root, object_root,
                                            overlong_probe=probe, build_record=build)
        self.assertFalse(policy["verified"])
        self.assertEqual(policy["name"], "lightftp-gcov-path-max-stream-close-v4")
        probe_dir = self.root / "overlong-close-probe"
        probe_dir.mkdir()
        (probe_dir / "probe-input").write_bytes(b"fixture input")
        (probe_dir / "probe-frame-ledger.jsonl").write_text("{}\n")
        (probe_dir / "probe.log").write_text("fixture log\n")
        (probe_dir / "lightftp-rebuild.log").write_text("fixture rebuild log\n")
        probe.update(verified=True,
                     probe_input_sha256=cov.digest_file(probe_dir / "probe-input"),
                     probe_ledger_sha256=cov.digest_file(probe_dir / "probe-frame-ledger.jsonl"),
                     probe_log_sha256=cov.digest_file(probe_dir / "probe.log"))
        # Probe alone is not enough: the exception also needs the
        # reproducible-build record bound to the running binary.
        policy = cov.lightftp_replay_policy(source_root, object_root,
                                            overlong_probe=probe, build_record=build)
        self.assertFalse(policy["verified"])
        self.assertEqual(policy["name"], "lightftp-gcov-path-max-stream-close-v4")
        build.update(verified=True,
                     rebuild_log_file="lightftp-rebuild.log",
                     binary_sha256=cov.digest_file(binary),
                     disassembly_identical=True,
                     objects_unexpected_difference=[],
                     rebuild_log_sha256=cov.digest_file(probe_dir / "lightftp-rebuild.log"))
        policy = cov.lightftp_replay_policy(source_root, object_root,
                                            overlong_probe=probe, build_record=build)
        self.assertTrue(policy["verified"])
        self.assertTrue(policy["exception_enabled"])
        self.assertEqual(policy["name"], "lightftp-gcov-path-max-stream-close-v5")
        self.assertTrue(cov.verify_lightftp_replay_policy(
            policy, source_root, object_root, artifact_root=self.root))
        self.assertFalse(cov.verify_lightftp_replay_policy(
            policy, source_root, object_root))  # no artifact root -> fail closed
        tampered = dict(build, binary_sha256="0" * 64)
        broken = cov.lightftp_replay_policy(source_root, object_root,
                                            overlong_probe=probe, build_record=tampered)
        # The builder itself refuses a build record whose binary hash does
        # not match the executable beside the source.
        self.assertFalse(broken["verified"])
        self.assertEqual(broken["name"], "lightftp-gcov-path-max-stream-close-v4")
        # A tampered archived log hash passes the builder (it cannot see the
        # artifact) but the audit rejects it against the archived bytes.
        tampered_log = dict(build, rebuild_log_sha256="0" * 64)
        stale = cov.lightftp_replay_policy(source_root, object_root,
                                           overlong_probe=probe, build_record=tampered_log)
        self.assertTrue(stale["verified"])
        self.assertFalse(cov.verify_lightftp_replay_policy(
            stale, source_root, object_root, artifact_root=self.root))

    def test_proftpd_replay_policy_v6_carries_overlong_exception(self):
        base = cov.proftpd_replay_policy()
        self.assertEqual(base["name"], "proftpd-ready-client-graceful-exit-v5")
        self.assertNotIn("overlong_close", base)
        v6 = cov.proftpd_replay_policy(overlong_close=dict(
            verified=True, exception_enabled=True, give_up_bytes=16408))
        self.assertEqual(v6["name"], "proftpd-ready-client-graceful-exit-v6")
        self.assertTrue(v6["overlong_close"]["exception_enabled"])
        self.assertIn("verified-overlong-behavior-probe", v6["acceptance_requires"])

    def test_smtp_final_close_reply_tolerates_trailing_noise(self):
        head = (b"Responses from server:0-220-221-\n"
                b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
                b"220 ready\r\n221 bye\r\n")
        footer = b"\n--------------------------------"
        noise = b"87643 daemon forked for daemon-del-pidfile: 87655\n" \
                b"87643 >>>>>>>>>> Exim pid=87643 terminating with rc=0 >>>>>>>>\n"
        log = self.root / "smtp-noise.log"
        log.write_bytes(head + footer + b"\n" + noise)
        # Noise after the section footer never affected the strict parser;
        # the strict gap was the truncated-details case below.
        self.assertEqual(cov.smtp_final_close_reply(log), 221)
        self.assertEqual(cov.smtp_final_close_reply(log, trailing_noise_ok=True), 221)
        # Any SMTP reply after the 221 invalidates the close (and the state
        # sequence, being derived from the complete buffer, shows it too).
        later = self.root / "smtp-later-reply.log"
        later.write_bytes(head.replace(
            b"Responses from server:0-220-221-", b"Responses from server:0-220-221-250-"
        ).replace(b"221 bye", b"221 bye\r\n250 late") + footer + b"\n")
        self.assertIsNone(cov.smtp_final_close_reply(later, trailing_noise_ok=True))
        # A truncated details print still closes when the atomic state
        # sequence line ends in 221 (observed 2026-11-20 on exim).
        truncated = self.root / "smtp-truncated.log"
        truncated.write_bytes(
            b"Responses from server:0-220-250-221-\n"
            b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
            b"220 ready\r\n250 OK\r\n250 Acc" + footer + b"\n" + noise)
        self.assertEqual(cov.smtp_final_close_reply(truncated, trailing_noise_ok=True), 221)
        # A non-close final code never qualifies, even with the fallback.
        truncated_250 = self.root / "smtp-truncated-250.log"
        truncated_250.write_bytes(
            b"Responses from server:0-220-250-\n"
            b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
            b"220 ready\r\n250 OK\r\n250 Acc" + footer + b"\n")
        self.assertIsNone(cov.smtp_final_close_reply(truncated_250, trailing_noise_ok=True))

    def test_lighttpd1_announced_close_accepted_at_v12(self):
        body = b"<html>not found</html>"
        # Real shape (2026-11-20): several responses share the connection,
        # the LAST one carries Connection: close and a matching body length,
        # while the HTTP state line records only the final status code —
        # which is why the v5..v11 summary-vs-details equality rejected
        # every multi-response close.
        head = (b"Responses from server:0-404-\n"
                b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
                b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n"
                b"Content-Length: %d\r\n\r\n" % len(body) + body)
        log = self.root / "lighttpd1-close.log"
        log.write_bytes(head + b"\n--------------------------------")
        self.assertTrue(cov.http_response_announced_close_complete(log))
        ledger = dict(prefix_sent_complete=True, frames_unattempted=3,
                      prior_post_recv_ok=True, peer_closed=True,
                      stop_reason="peer-closed-before-input-end")
        replay = dict(server_exit_code=0, client_exit_code=2, server_ready=True,
                      client_timed_out=False, session_coverage_missing=False,
                      session_gcda_touched=["src/lighttpd.gcda"])
        reset = dict(command_succeeded=True, exit_code=0)
        self.assertTrue(cov.protocol_end_expected(
            "lighttpd1", replay, reset, ledger, log, policy_version=12))
        self.assertFalse(cov.protocol_end_expected(
            "lighttpd1", replay, reset, ledger, log, policy_version=11))
        # Truncated body, missing close header, or a later partial response
        # must never qualify.
        short = self.root / "lighttpd1-short.log"
        short.write_bytes(head[:len(head) - 5] + b"\n--------------------------------")
        self.assertFalse(cov.http_response_announced_close_complete(short))
        noclose = self.root / "lighttpd1-noclose.log"
        noclose.write_bytes(head.replace(b"Connection: close\r\n", b"") +
                            b"\n--------------------------------")
        self.assertFalse(cov.http_response_announced_close_complete(noclose))
        trailing = self.root / "lighttpd1-trailing.log"
        trailing.write_bytes(head + b"HTTP/1.1 200 OK\r\nBro" +
                             b"\n--------------------------------")
        self.assertFalse(cov.http_response_announced_close_complete(trailing))

    def test_exim_error_limit_close_accepted_at_v12(self):
        # globals.c: smtp_max_synprot_errors = 3; smtp_in.c:2734 drops the
        # session once the counter exceeds it. The counter resets on some
        # valid commands, so the trailing visible run can be shorter than
        # the limit while the session total exceeds it (observed shapes:
        # ...-503-500-500-250-501-501 close, ...-503-500-500-503-503 close).
        body = (b"Responses from server:0-220-250-503-500-500-250-501-501-\n"
                b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
                b"220 ready\r\n250 OK\r\n503 bad\r\n500 bad\r\n500 bad\r\n"
                b"250 OK\r\n501 bad\r\n501 bad\r\n")
        log = self.root / "exim-error-close.log"
        log.write_bytes(body + b"\n--------------------------------")
        ledger = dict(prefix_sent_complete=True, frames_unattempted=6,
                      prior_post_recv_ok=True, peer_closed=True,
                      stop_reason="peer-closed-before-input-end")
        replay = dict(server_exit_code=0, client_exit_code=2, server_ready=True,
                      client_timed_out=False, session_coverage_missing=False,
                      session_gcda_touched=["smtp_in.gcda"])
        reset = dict(command_succeeded=True, exit_code=0)
        self.assertTrue(cov.protocol_end_expected(
            "exim", replay, reset, ledger, log, policy_version=12))
        self.assertFalse(cov.protocol_end_expected(
            "exim", replay, reset, ledger, log, policy_version=11))
        # A close whose final reply is a success code never qualifies, and
        # neither does a lone trailing error without the error pile-up.
        healthy = self.root / "exim-healthy-close.log"
        healthy.write_bytes(body.replace(b"-501-501-", b"-501-250-") +
                            b"\n--------------------------------")
        ledger_healthy = dict(ledger, stop_reason="peer-closed-before-input-end")
        self.assertFalse(cov.exim_error_limit_close_expected(
            replay, reset, ledger_healthy, healthy))
        sparse = self.root / "exim-sparse-error.log"
        sparse.write_bytes(
            b"Responses from server:0-220-250-501-\n"
            b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
            b"220 ready\r\n250 OK\r\n501 bad\r\n"
            b"\n--------------------------------")
        self.assertFalse(cov.exim_error_limit_close_expected(
            replay, reset, ledger, sparse))
        # Missing process evidence fails closed.
        self.assertFalse(cov.exim_error_limit_close_expected(
            dict(replay, server_exit_code=124), reset, ledger, log))
        self.assertFalse(cov.exim_error_limit_close_expected(
            replay, dict(reset, exit_code=1), ledger, log))

    def test_pureftpd_die_family_exit_accepted_at_v12(self):
        # _EXIT(-priority - 1): 249=LOG_INFO .. 252=LOG_ERR. A deterministic
        # unknown-command session (2026-11-20 id:000258) closed FIN with a
        # complete 500 reply and exited 249.
        head = (b"Responses from server:0-220-331-215-530-500-\n"
                b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
                b"220 welcome\r\n331 password\r\n215 UNIX\r\n"
                b"530 not logged in\r\n500 HTTP command: [post]\r\n")
        log = self.root / "pureftpd-die-close.log"
        log.write_bytes(head + b"\n--------------------------------")
        ledger = dict(prefix_sent_complete=True, frames_unattempted=23,
                      prior_post_recv_ok=True, peer_closed=True,
                      stop_reason="peer-closed-before-input-end")
        replay = dict(server_exit_code=249, client_exit_code=2,
                      server_ready=True, client_timed_out=False,
                      session_coverage_missing=False,
                      imported_gcda=["src/ftpd.gcda"])
        reset = dict(command_succeeded=True, exit_code=0)
        self.assertTrue(cov.protocol_end_expected(
            "pure-ftpd", replay, reset, ledger, log, policy_version=12))
        self.assertFalse(cov.protocol_end_expected(
            "pure-ftpd", replay, reset, ledger, log, policy_version=11))
        # A success-family final reply with a die exit, or a die exit
        # without coverage evidence, never qualifies.
        healthy = self.root / "pureftpd-die-230.log"
        healthy.write_bytes(head.replace(b"-331-215-530-500", b"-331-230")
                            .replace(b"530 not logged in\r\n", b"")
                            .replace(b"500 HTTP command: [post]", b"230 ok")
                            + b"\n--------------------------------")
        self.assertFalse(cov.protocol_end_expected(
            "pure-ftpd", replay, reset, ledger, healthy, policy_version=12))
        self.assertFalse(cov.protocol_end_expected(
            "pure-ftpd", dict(replay, imported_gcda=[]), reset, ledger,
            log, policy_version=12))

    def test_lightftp_lenient_quit_extraction_at_v12(self):
        # ftpserv.c skips non-alpha bytes before matching the command name,
        # so a newline-less garbage frame glued before a bare QUIT still
        # executes as QUIT (observed 2026-11-20: 205 bytes of 0xF2 + QUIT
        # closed the session with 221 after the strict stream check
        # rejected it).
        self.assertTrue(cov.lightftp_command_line_extracts_quit(
            [b"\xf2" * 205 + b"%", b"QUIT\r\n"]))
        self.assertTrue(cov.lightftp_command_line_extracts_quit(
            [b"NOOP\r\n", b"QUIT\r\n"]))
        self.assertFalse(cov.lightftp_command_line_extracts_quit([b"QUITX\r\n"]))
        self.assertFalse(cov.lightftp_command_line_extracts_quit([b"LIST\r\n"]))
        head = (b"Responses from server:0-220-331-230-221-\n"
                b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
                b"220 ready\r\n331 pass\r\n230 ok\r\n221 \r\n")
        log = self.root / "lightftp-lenient-quit.log"
        log.write_bytes(head + b"\n--------------------------------")
        ledger = dict(prefix_sent_complete=True, frames_unattempted=1,
                      prior_post_recv_ok=True, peer_closed=True,
                      stop_reason="protocol-close-after-quit",
                      last_attempted_post_recv_ok=True,
                      last_attempted_frame_is_quit=False,
                      sent_payloads=[b"\xf2" * 205 + b"%", b"QUIT\r\n"])
        replay = dict(server_exit_code=0, client_exit_code=2,
                      server_ready=True, client_timed_out=False,
                      session_coverage_missing=False,
                      session_gcda_touched=["ftpserv.gcda"])
        reset = dict(command_succeeded=True, exit_code=0)
        self.assertTrue(cov.protocol_end_expected(
            "lightftp", replay, reset, ledger, log, policy_version=12))
        self.assertFalse(cov.protocol_end_expected(
            "lightftp", replay, reset, ledger, log, policy_version=11))
        # The lenient path is lightftp-only: the same glued-QUIT ledger must
        # not open the gate for another FTP target's strict quit check.
        self.assertFalse(cov.protocol_end_expected(
            "exim", replay, reset, ledger, log, policy_version=12))

    def test_lightftp_quit_accepts_only_known_interleaved_thread_exit(self):
        log = self.root / "lightftp-thread-exit.log"
        summary = (b"Responses from server:0-220-331-230-215-257-200-150-451-"
                   b"19-11-2026 18:53:11 S-id=1 : <- Thread exit. "
                   b"Thread counter g_threads=0\nResponses in details:\n")
        details = (b"220 ready\r\n331 password required\r\n"
                   b"230 logged in\r\n215 UNIX Type: L8\r\n"
                   b"257 current directory\r\n200 command okay\r\n"
                   b"150 opening data connection\r\n451 local error\r\n"
                   b"500 syntax error\r\n257 directory created\r\n"
                   b"550 permission denied\r\n200 chmod okay\r\n221 \r\n")
        footer = b"\n--------------------------------"
        log.write_bytes(summary + details + footer)

        self.assertEqual(cov.lightftp_final_reply_code(log), 221)
        replay = dict(server_exit_code=0, client_exit_code=2, server_ready=True,
                      client_timed_out=False, session_coverage_missing=False,
                      session_gcda_touched=["ftpserv.gcda"])
        reset = dict(command_succeeded=True, exit_code=0)
        ledger = dict(prefix_sent_complete=True, frames_unattempted=1,
                      peer_closed=True, stop_reason="protocol-close-after-quit",
                      last_attempted_frame_is_quit=True,
                      last_attempted_post_recv_ok=True)
        self.assertTrue(cov.protocol_end_expected(
            "lightftp", replay, reset, ledger, log, policy_version=6))

        log.write_bytes(summary.replace(b"Thread counter g_threads=0",
                                        b"Thread counter g_threads=1") + details + footer)
        self.assertIsNone(cov.lightftp_final_reply_code(log))
        self.assertFalse(cov.protocol_end_expected(
            "lightftp", replay, reset, ledger, log, policy_version=6))

        body_221 = (b"211-Features\r\n221 not a closing reply\r\n"
                    b"211 End\r\n")
        log.write_bytes(
            b"Responses from server:0-211-"
            b"19-11-2026 18:53:11 S-id=1 : <- Thread exit. "
            b"Thread counter g_threads=0\nResponses in details:\n" +
            body_221 + footer)
        self.assertIsNone(cov.lightftp_final_reply_code(log))

        nonfinal_221 = (b"220 ready\r\n221 premature close\r\n"
                        b"200 later reply\r\n")
        log.write_bytes(
            b"Responses from server:0-220-221-200-"
            b"19-11-2026 18:53:11 S-id=1 : <- Thread exit. "
            b"Thread counter g_threads=0\nResponses in details:\n" +
            nonfinal_221 + footer)
        self.assertIsNone(cov.lightftp_final_reply_code(log))

    def test_bftpd_audit_rejects_missing_or_misaligned_replay_plan(self):
        with self.assertRaisesRegex(cov.CoverageError, "requires replay-plan.json"):
            cov.verify_bftpd_replay_events([{}], [], self.root)
        with self.assertRaisesRegex(cov.CoverageError, "lacks an input path"):
            cov.verify_bftpd_replay_events([{}], [{}], self.root)

    def test_bftpd_audit_reclassifies_legacy_cache_from_hashed_evidence(self):
        filename = "id:000001.raw"
        input_path = self.root / filename
        framed = struct.pack("<I", 6) + b"NOOP\r\n" + struct.pack("<I", 6) + b"QUIT\r\n"
        input_path.write_bytes(framed)
        input_hash = cov.digest_file(input_path)
        replay_log = self.root / "replay-000001.log"
        replay_log.write_bytes(
            b"Responses from server:0-220-\n"
            b"++++++++++++++++++++++++++++++++\nResponses in details:\n"
            b"220 bftpd ready.\r\n221 See you later...\r\n\n"
            b"--------------------------------\n")
        ledger_path = self.root / "replay-000001-frame-ledger.jsonl"
        ledger_path.write_text("\n".join([
            json.dumps({"event": "session_begin", "schema": "loopfuzz-replay-frame-ledger-v1",
                        "input_file": filename, "input_size": len(framed), "protocol": "FTP"}),
            json.dumps({"event": "frame", "frame": 1, "len": 6,
                        "read_complete": True, "pre_recv_ok": True,
                        "send_attempt": True, "send_errno": 0,
                        "sent_bytes": 6, "post_recv_ok": True}),
            json.dumps({"event": "session_end", "frames_total": 1,
                        "stop_reason": "peer-closed-before-input-end", "peer_closed": True}),
        ]) + "\n")
        reset_log = self.root / "reset-000001.log"
        reset_log.write_text("reset ok\n")
        replay = dict(
            server_exit_code=0, client_exit_code=2, server_ready=True,
            client_timed_out=False, harness_shutdown_requested=False,
            imported_gcda=["main.gcda"], session_coverage_missing=False,
            replay_log_file=replay_log.name, replay_log_sha256=cov.digest_file(replay_log),
            frame_ledger_file=ledger_path.name, frame_ledger_sha256=cov.digest_file(ledger_path),
            final_ftp_reply_code=221, bftpd_protocol_end_expected=True,
            frames_total=1, frames_unattempted=1, frames_attempted=1,
            frames_sent_complete=1, send_stop_reason="peer-closed-before-input-end",
            send_completeness="incomplete", server_crashed=False,
            client_aborted_on_crash=False, server_anomalous_exit=False,
            client_anomalous_exit=True, replay_anomaly=False, anomaly_kind="",
            incomplete_reasons=[], coverage_complete=True,
            client_command=["aflnet-replay", str(input_path)])
        reset = dict(command=["reset"], command_succeeded=True, exit_code=0,
                     log_file=reset_log.name, log_sha256=cov.digest_file(reset_log))
        event = dict(filename=filename, path=str(input_path), input_sha256=input_hash,
                     replay=replay, reset=reset)
        plan = [dict(filename=filename, path=str(input_path), input_sha256=input_hash)]

        audited = cov.verify_bftpd_replay_events([event], plan, self.root)
        self.assertTrue(audited["legacy_reclassification"])
        self.assertEqual(audited["n_reclassified_inputs"], 1)
        self.assertEqual(audited["n_incomplete_inputs"], 1)
        derived = audited["events"][0]["replay"]
        self.assertFalse(derived["bftpd_protocol_end_expected"])
        self.assertFalse(derived["last_attempted_frame_is_quit"])
        self.assertIn("frame-ledger-incomplete", derived["incomplete_reasons"])
        self.assertTrue(event["replay"]["coverage_complete"])  # source archive stays untouched

        # Once the new field is present, a contradictory cached classification
        # is a hard audit error instead of being silently reclassified.
        current_event = copy.deepcopy(event)
        current_event["replay"]["last_attempted_frame_is_quit"] = False
        with self.assertRaisesRegex(cov.CoverageError, "replay classification mismatch"):
            cov.verify_bftpd_replay_events([current_event], plan, self.root)

    def test_bftpd_legacy_reply_cache_requires_exact_terminal_221_transform(self):
        def add_replay(index, detail, cached_reply):
            path = self.root / ("replay-%06d.log" % index)
            path.write_bytes(
                b"Responses from server:0-220-\n"
                b"++++++++++++++++++++++++++++++++\nResponses in details:\n" +
                detail + b"\n--------------------------------\n")
            return {"replay": {
                "replay_log_file": path.name,
                "replay_log_sha256": cov.digest_file(path),
                "final_ftp_reply_code": cached_reply,
            }}

        events = [
            add_replay(1, b"220 bftpd ready.\r\n221 See you later...\r\n", 221),
            add_replay(2, b"220 bftpd ready.\r\n500 Unknown command.\r\n", None),
            # An incomplete/unparseable transcript also maps to null.
            add_replay(3, b"220 bftpd ready.\r\n500 Unknown command.\n", None),
        ]
        self.assertTrue(cov.bftpd_legacy_221_only_reply_classification(
            events, self.root))

        # The compatibility is run-wide and exact: a cached ordinary reply,
        # a missing cached 221, or a cached 221 without parser evidence blocks it.
        for index, cached_reply in ((2, 500), (1, None), (3, 221)):
            changed = copy.deepcopy(events)
            changed[index - 1]["replay"]["final_ftp_reply_code"] = cached_reply
            self.assertFalse(cov.bftpd_legacy_221_only_reply_classification(
                changed, self.root))

    def test_pureftpd_replay_uses_supervised_listener_lifecycle(self):
        server = mock.Mock(pid=101, returncode=-signal.SIGTERM)
        server.poll.return_value = None
        server.wait.return_value = -signal.SIGTERM
        client = mock.Mock(pid=202, returncode=0)
        client.wait.return_value = 0
        client_command = ["aflnet-replay", "input", "FTP", "21", "1"]
        server_command = ["timeout", "-k", "1s", "-s", "SIGTERM", "3s",
                          "src/pure-ftpd", "-A"]
        with mock.patch.object(cov.subprocess, "Popen", side_effect=[server, client]) as popen, \
             mock.patch.object(cov, "wait_bound_port", return_value=True) as readiness, \
             mock.patch.object(cov, "client_timeout_seconds", return_value=10), \
             mock.patch.object(cov.os, "killpg"):
            result = cov.run_supervised_session(
                "pure-ftpd", client_command, server_command, {"path": "input"}, 1,
                21, self.root, {}, mock.Mock())
        readiness.assert_called_once_with(server, 21, "tcp")
        self.assertEqual(popen.call_args_list[0].args[0], ["src/pure-ftpd", "-A"])
        self.assertTrue(result["harness_shutdown_requested"])
        self.assertEqual(result["harness_shutdown_signal"], "SIGTERM")
        self.assertFalse(result["server_crashed"])
        self.assertFalse(result["replay_anomaly"])
        source_dir = self.root / "policy-fixture" / "src"
        source_dir.mkdir(parents=True)
        (source_dir / "ftpd.c").write_bytes(
            b"void _EXIT(const int status)\n{\n    delete_atomic_file();\n"
            b"#ifdef FTPWHO\n    ftpwho_exit();\n#endif\n    exit(status);\n}\n"
            b"addreply(230, MSG_CURRENT_DIR_IS, wd);\n    }\n"
            b"    unsetenv(\"GCOV_PREFIX\");\n\n#ifndef NON_ROOT_FTP\n"
            b"sigaddset(&set, SIGCHLD);\n    sigprocmask(SIG_BLOCK, &set, NULL);\n"
            b"    nb_children++;\n    child = 0;\n")
        binary = source_dir / "pure-ftpd"
        binary.write_bytes(b"fixture executable bytes")
        binary.chmod(0o755)
        policy = cov.pureftpd_replay_policy(source_dir.parent)
        self.assertTrue(policy["verified"])
        self.assertEqual(policy["source_binary_build_association"], "not-verified")

    def test_pureftpd_policy_rejects_missing_patch_or_executable(self):
        source_dir = self.root / "policy-fixture" / "src"
        source_dir.mkdir(parents=True)
        (source_dir / "ftpd.c").write_text("void _EXIT(const int status) { _exit(status); }\n")
        binary = source_dir / "pure-ftpd"
        binary.write_bytes(b"fixture executable bytes")
        binary.chmod(0o755)
        with self.assertRaisesRegex(cov.CoverageError, "single-process"):
            cov.pureftpd_replay_policy(source_dir.parent)
        self.assertFalse(cov.pureftpd_replay_policy(
            source_dir.parent, allow_incomplete=True)["verified"])

    def test_pureftpd_artifact_audit_recomputes_policy_from_hashed_logs(self):
        artifact_dir = self.root / "pureftpd-artifacts"
        artifact_dir.mkdir()
        replay_path = artifact_dir / "replay-000001.log"
        replay_path.write_text(
            "Responses from server:0-220-421-\n"
            "++++++++++++++++++++++++++++++++\nResponses in details:\n"
            "220---------- welcome ----------\r\n"
            "220 You will be disconnected\r\n"
            "421 Unable to set up secure anonymous FTP\r\n"
            "--------------------------------\n")
        reset_path = artifact_dir / "reset-000001.log"
        reset_path.write_text("reset passed\n")
        reset = dict(command=["bash", "reset.sh"], command_succeeded=True,
                     exit_code=0, log_file=reset_path.name,
                     log_sha256=cov.digest_file(reset_path))
        flags = cov.apply_pureftpd_session_exit_policy(
            cov.classify_replay_exit(252, 0), 252, 0, True, False, False,
            421, ["src/ftpd.gcda"], True)
        replay = dict(flags, server_exit_code=252, client_exit_code=0,
                      server_ready=True, client_timed_out=False,
                      harness_shutdown_requested=False,
                      final_ftp_reply_code=421, imported_gcda=["src/ftpd.gcda"],
                      session_coverage_missing=False,
                      replay_log_file=replay_path.name,
                      replay_log_sha256=cov.digest_file(replay_path))
        replay["incomplete_reasons"] = cov.replay_incompleteness(replay)
        replay["coverage_complete"] = not replay["incomplete_reasons"]
        self.assertEqual(cov.verify_pureftpd_replay_evidence(
            replay, reset, artifact_dir, 1, {"src/ftpd.gcno": "fixture"}), [])

        forged = dict(replay, pureftpd_session_exit_expected=False)
        errors = cov.verify_pureftpd_replay_evidence(
            forged, reset, artifact_dir, 1, {"src/ftpd.gcno": "fixture"})
        self.assertIn("replay-classification-mismatch:pureftpd_session_exit_expected", errors)

        replay_path.write_text(replay_path.read_text().replace(
            "421 Unable", "530 Unable"))
        errors = cov.verify_pureftpd_replay_evidence(
            replay, reset, artifact_dir, 1, {"src/ftpd.gcno": "fixture"})
        self.assertIn("replay-log-hash-mismatch", errors)
        self.assertIn("final-ftp-reply-disagrees-with-transcript", errors)

    def test_proftpd_shutdown_policy_requires_all_observed_evidence(self):
        supervised = dict(server_ready=True, client_timed_out=False,
                          harness_shutdown_requested=True,
                          harness_shutdown_signal="SIGTERM")
        flags = cov.classify_replay_exit(-signal.SIGSEGV, 0)
        self.assertEqual(flags["anomaly_kind"], "server-crash-finding")
        accepted = cov.apply_proftpd_shutdown_exit_policy(
            flags, -signal.SIGSEGV, 0, supervised, True,
            frames_expected=4, packets_sent=4,
            ledger_send_complete=True, session_gcda_touched=["src/main.gcda"])
        self.assertTrue(accepted["proftpd_shutdown_exit_expected"])
        self.assertFalse(accepted["server_crashed"])
        self.assertFalse(accepted["replay_anomaly"])
        self.assertEqual(accepted["anomaly_kind"], "")

        failures = (
            (-signal.SIGSEGV, 0, dict(supervised, harness_shutdown_requested=False), True),
            (-signal.SIGSEGV, 1, supervised, True),
            (-signal.SIGSEGV, 0, dict(supervised, client_timed_out=True), True),
            (-signal.SIGSEGV, 0, dict(supervised, server_ready=False), True),
            (-signal.SIGSEGV, 0, dict(supervised, harness_shutdown_signal="SIGUSR1"), True),
            (-signal.SIGSEGV, 0, supervised, False),
            (-signal.SIGTERM, 0, dict(supervised, harness_shutdown_requested=False), True),
            (-signal.SIGKILL, 0, supervised, True),
        )
        for server_code, client_code, sup, reset in failures:
            result = cov.apply_proftpd_shutdown_exit_policy(
                cov.classify_replay_exit(server_code, client_code),
                server_code, client_code, sup, reset,
                frames_expected=4, packets_sent=4,
                ledger_send_complete=True, session_gcda_touched=["src/main.gcda"])
            self.assertFalse(result["proftpd_shutdown_exit_expected"], (server_code, sup))
            self.assertTrue(result["server_crashed"])
            self.assertEqual(result["anomaly_kind"], "server-crash-finding")

        # A clean exit is not a policy candidate and must stay non-expected.
        result = cov.apply_proftpd_shutdown_exit_policy(
            cov.classify_replay_exit(0, 0), 0, 0, dict(supervised), True)
        self.assertFalse(result["proftpd_shutdown_exit_expected"])

    def test_proftpd_artifact_audit_recomputes_policy_from_hashed_logs(self):
        import struct as _struct
        artifact_dir = self.root / "proftpd-artifacts"
        artifact_dir.mkdir()
        replay_path = artifact_dir / "replay-000001.log"
        replay_path.write_text(
            "Size of the current packet 1 is  15\n"
            "Size of the current packet 2 is  6\n"
            "proftpd session transcript fixture\n")
        reset_path = artifact_dir / "reset-000001.log"
        reset_path.write_text("reset passed\n")
        reset = dict(command=["bash", "reset.sh"], command_succeeded=True,
                     exit_code=0, log_file=reset_path.name,
                     log_sha256=cov.digest_file(reset_path))
        supervised = dict(server_ready=True, client_timed_out=False,
                          harness_shutdown_requested=True,
                          harness_shutdown_signal="SIGTERM",
                          helper_ready=None)
        flags = cov.apply_proftpd_shutdown_exit_policy(
            cov.classify_replay_exit(-signal.SIGSEGV, 0), -signal.SIGSEGV, 0,
            supervised, True, frames_expected=2, packets_sent=2,
            ledger_send_complete=True, session_gcda_touched=["src/main.gcda"])
        framed = self.root / "framed-input.raw"
        framed.write_bytes(_struct.pack("<I", 2) + b"AB" + _struct.pack("<I", 0) + b"")
        ledger_path = artifact_dir / "frame-ledger-000001.jsonl"
        ledger_path.write_text(
            "{\"event\":\"session_begin\",\"schema\":\"loopfuzz-replay-frame-ledger-v1\","
            "\"input_file\":\"framed-input.raw\",\"input_size\":10,\"protocol\":\"FTP\"}\n"
            "{\"event\":\"frame\",\"frame\":1,\"len\":2,\"read_complete\":true,"
            "\"pre_recv_ok\":true,\"send_attempt\":true,\"sent_bytes\":2,"
            "\"send_errno\":0,\"post_recv_ok\":true}\n"
            "{\"event\":\"frame\",\"frame\":2,\"len\":0,\"read_complete\":true,"
            "\"pre_recv_ok\":true,\"send_attempt\":true,\"sent_bytes\":0,"
            "\"send_errno\":0,\"post_recv_ok\":true}\n"
            "{\"event\":\"session_end\",\"frames_total\":2,\"stop_reason\":\"eof\"}\n")
        replay = dict(flags, client_command=["aflnet-replay", str(framed), "FTP", "21", "1"],
                      frame_ledger_file=ledger_path.name,
                      frame_ledger_sha256=cov.digest_file(ledger_path),
                      server_exit_code=-signal.SIGSEGV, client_exit_code=0,
                      server_ready=True, client_timed_out=False,
                      harness_shutdown_requested=True,
                      harness_shutdown_signal="SIGTERM", helper_ready=None,
                      session_coverage_missing=False,
                      replay_log_file=replay_path.name,
                      replay_log_sha256=cov.digest_file(replay_path))
        replay["incomplete_reasons"] = cov.replay_incompleteness(replay)
        replay["coverage_complete"] = not replay["incomplete_reasons"]
        self.assertEqual(cov.verify_proftpd_replay_evidence(
            replay, reset, artifact_dir, 1, require_frames=True), [])

        ledger_path.write_text(
            "{\"event\":\"session_begin\",\"schema\":\"loopfuzz-replay-frame-ledger-v1\","
            "\"input_file\":\"framed-input.raw\",\"input_size\":10,\"protocol\":\"FTP\"}\n"
            "{\"event\":\"frame\",\"frame\":1,\"len\":2,\"read_complete\":true,"
            "\"pre_recv_ok\":true,\"send_attempt\":true,\"sent_bytes\":2,"
            "\"send_errno\":0,\"post_recv_ok\":true}\n"
            "{\"event\":\"session_end\",\"frames_total\":1,"
            "\"stop_reason\":\"peer-closed-before-frame\",\"peer_closed\":true}\n")
        incomplete_flags = cov.apply_proftpd_shutdown_exit_policy(
            cov.classify_replay_exit(0, 2), 0, 2,
            dict(server_ready=True, client_timed_out=False,
                 harness_shutdown_requested=False, harness_shutdown_signal=None),
            True, frames_expected=2, packets_sent=2,
            ledger_send_complete=False, session_gcda_touched=["src/main.gcda"])
        incomplete = dict(incomplete_flags,
                          client_command=replay["client_command"],
                          frame_ledger_file=ledger_path.name,
                          frame_ledger_sha256=cov.digest_file(ledger_path),
                          server_exit_code=0, client_exit_code=2,
                          server_ready=True, client_timed_out=False,
                          harness_shutdown_requested=False,
                          harness_shutdown_signal=None, helper_ready=None,
                          session_coverage_missing=False,
                          session_gcda_touched=["src/main.gcda"],
                          replay_log_file=replay_path.name,
                          replay_log_sha256=cov.digest_file(replay_path),
                          send_completeness="incomplete",
                          protocol_end_expected=False)
        incomplete["incomplete_reasons"] = cov.replay_incompleteness(incomplete)
        incomplete["coverage_complete"] = False
        self.assertIn("frame-ledger-incomplete", incomplete["incomplete_reasons"])
        self.assertEqual(cov.verify_proftpd_replay_evidence(
            incomplete, reset, artifact_dir, 1, require_frames=True), [])

        forged_incomplete = dict(incomplete, send_completeness="complete",
                                 incomplete_reasons=[])
        errors = cov.verify_proftpd_replay_evidence(
            forged_incomplete, reset, artifact_dir, 1, require_frames=True)
        self.assertIn("incomplete-reasons-mismatch", errors)

        ledger_path.write_text(
            "{\"event\":\"session_begin\",\"schema\":\"loopfuzz-replay-frame-ledger-v1\","
            "\"input_file\":\"framed-input.raw\",\"input_size\":10,\"protocol\":\"FTP\"}\n"
            "{\"event\":\"frame\",\"frame\":1,\"len\":2,\"read_complete\":true,"
            "\"pre_recv_ok\":true,\"send_attempt\":true,\"sent_bytes\":2,"
            "\"send_errno\":0,\"post_recv_ok\":true}\n"
            "{\"event\":\"frame\",\"frame\":2,\"len\":0,\"read_complete\":true,"
            "\"pre_recv_ok\":true,\"send_attempt\":true,\"sent_bytes\":0,"
            "\"send_errno\":0,\"post_recv_ok\":true}\n"
            "{\"event\":\"session_end\",\"frames_total\":2,\"stop_reason\":\"eof\"}\n")

        forged = dict(replay, proftpd_shutdown_exit_expected=False)
        errors = cov.verify_proftpd_replay_evidence(
            forged, reset, artifact_dir, 1, require_frames=True)
        self.assertIn("replay-classification-mismatch:proftpd_shutdown_exit_expected", errors)

        tampered = dict(replay, harness_shutdown_requested=False,
                        server_crashed=True, replay_anomaly=True,
                        anomaly_kind="server-crash-finding")
        errors = cov.verify_proftpd_replay_evidence(
            tampered, reset, artifact_dir, 1, require_frames=True)
        self.assertIn("replay-classification-mismatch:proftpd_shutdown_exit_expected", errors)

        replay_path.write_text("tampered transcript\n")
        errors = cov.verify_proftpd_replay_evidence(
            replay, reset, artifact_dir, 1, require_frames=True)
        self.assertIn("replay-log-hash-mismatch", errors)

    def test_pureftpd_final_reply_uses_multiline_state_machine(self):
        log = self.root / "ftp-reply-sm.log"
        # Summary and details both from the state-machine extractor: the FEAT
        # body (including digit-prefixed lines and a decoy "421 fake") emits
        # nothing; the trailing 421 is the final reply.
        log.write_text(
            "Size of the current packet 1 is  15\n"
            "Responses from server:0-220-530-214-421-\n"
            "++++++++++++++++++++++++++++++++\nResponses in details:\n"
            "220 Service ready\n"
            "530 Login incorrect\n"
            "214-Features:\n"
            " MFMT\n"
            "123 digit body line\n"
            "421 fake inside body\n"
            "214 End.\n"
            "421 Unable to set up secure anonymous FTP\n"
            "--------------------------------\n")
        self.assertEqual(cov.pureftpd_final_reply_code(log), 421)

        # Disagreement between summary and state-machine transcript stays None.
        log.write_text(log.read_text().replace("0-220-530-214-421-", "0-220-530-214-"))
        self.assertIsNone(cov.pureftpd_final_reply_code(log))

        # Unterminated multi-line body emits nothing for it.
        self.assertEqual(cov.ftp_reply_codes("220 hi\r\n214-Features:\r\n MFMT\r\n"), [220])

    def test_frame_ledger_rejects_contradictory_rows_and_trailing_bytes(self):
        import struct as _s2
        import tempfile as _tf
        # Counterexample 1 (GLM53 verification 2.2): a forged frame row that
        # claims sent_bytes==len with a failed pre-recv and nonzero errno
        # under stop_reason=eof must NOT be judged complete.
        framed = _s2.pack("<I", 3) + b"ABC"
        with _tf.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "l.jsonl"
            ledger.write_text(
                "{\"event\":\"session_begin\",\"schema\":\"loopfuzz-replay-frame-ledger-v1\",\"input_size\":7,\"protocol\":\"FTP\"}\n"
                "{\"event\":\"frame\",\"frame\":1,\"len\":3,\"read_complete\":false,\"pre_recv_ok\":false,"
                "\"send_attempt\":true,\"sent_bytes\":3,\"send_errno\":5,\"post_recv_ok\":false}\n"
                "{\"event\":\"session_end\",\"frames_total\":1,\"stop_reason\":\"eof\"}\n")
            result = cov.read_frame_ledger(ledger, framed)
            self.assertFalse(result["send_complete"])
            self.assertEqual(result["frames_sent_complete"], 0)
            # Counterexample 2: a valid frame plus one trailing byte must not
            # parse as a clean framed input.
            with self.assertRaises(cov.CoverageError):
                cov.read_frame_ledger(ledger, framed + b"X")
            bad = Path(tmp) / "bad.raw"
            bad.write_bytes(framed + b"X")
            with self.assertRaises(cov.CoverageError):
                cov.framed_input_frames(bad)

    def test_frame_ledger_accepts_minus2_not_attempted_marker(self):
        import struct as _s3
        import tempfile as _tf
        framed = _s3.pack("<I", 3) + b"ABC" + _s3.pack("<I", 0)
        with _tf.TemporaryDirectory() as tmp:
            ledger = Path(tmp) / "l2.jsonl"
            ledger.write_text(
                "{\"event\":\"session_begin\",\"schema\":\"loopfuzz-replay-frame-ledger-v1\",\"input_size\":8,\"protocol\":\"FTP\"}\n"
                "{\"event\":\"frame\",\"frame\":1,\"len\":3,\"read_complete\":true,\"pre_recv_ok\":true,"
                "\"send_attempt\":true,\"sent_bytes\":3,\"send_errno\":0,\"post_recv_ok\":true}\n"
                "{\"event\":\"frame\",\"frame\":2,\"len\":0,\"read_complete\":true,\"pre_recv_ok\":false,"
                "\"send_attempt\":false,\"sent_bytes\":-2,\"send_errno\":0,\"post_recv_ok\":false}\n"
                "{\"event\":\"session_end\",\"frames_total\":2,\"stop_reason\":\"client-recv-pre-send-failed\"}\n")
            result = cov.read_frame_ledger(ledger, framed)
            # Valid ledger, legal -2 marker: parses, counts attempted=1, and is
            # NOT complete (frame 2 never attempted).
            self.assertEqual(result["frames_total"], 2)
            self.assertEqual(result["frames_attempted"], 1)
            self.assertFalse(result["send_complete"])

    def test_proptpd_shutdown_policy_v3_requires_frame_completeness(self):
        supervised = dict(server_ready=True, client_timed_out=False,
                          harness_shutdown_requested=True,
                          harness_shutdown_signal="SIGTERM")
        base = cov.classify_replay_exit(-signal.SIGSEGV, 0)
        accepted = cov.apply_proftpd_shutdown_exit_policy(
            base, -signal.SIGSEGV, 0, supervised, True,
            frames_expected=4, packets_sent=4,
            ledger_send_complete=True, session_gcda_touched=["src/main.gcda"])
        self.assertTrue(accepted["proftpd_shutdown_exit_expected"])
        self.assertEqual(accepted["anomaly_kind"], "")

        # A partial send (client exited 0 after break) must stay a finding.
        partial = cov.apply_proftpd_shutdown_exit_policy(
            base, -signal.SIGSEGV, 0, supervised, True,
            frames_expected=4, packets_sent=2,
            ledger_send_complete=False, session_gcda_touched=["src/main.gcda"])
        self.assertFalse(partial["proftpd_shutdown_exit_expected"])
        self.assertTrue(partial["server_crashed"])

        # Missing frame accounting cannot certify the exemption either.
        unknown = cov.apply_proftpd_shutdown_exit_policy(
            base, -signal.SIGSEGV, 0, supervised, True,
            frames_expected=None, packets_sent=None,
            ledger_send_complete=None, session_gcda_touched=None)
        # Banner-parity without ledger or flushed-session evidence is not
        # enough for the v4 exemption.
        no_evidence = cov.apply_proftpd_shutdown_exit_policy(
            base, -signal.SIGSEGV, 0, supervised, True,
            frames_expected=4, packets_sent=4,
            ledger_send_complete=None, session_gcda_touched=[])
        self.assertFalse(no_evidence["proftpd_shutdown_exit_expected"])
        self.assertFalse(unknown["proftpd_shutdown_exit_expected"])

    def test_framed_input_frames_parses_length_prefixes(self):
        import struct as _struct
        framed = self.root / "input.raw"
        framed.write_bytes(_struct.pack("<I", 3) + b"AB")
        with self.assertRaises(cov.CoverageError):
            cov.framed_input_frames(framed)
        framed.write_bytes(_struct.pack("<I", 2) + b"AB" + _struct.pack("<I", 0) + b"")
        self.assertEqual(cov.framed_input_frames(framed), 2)

    def test_pureftpd_run_one_replay_dispatches_through_supervisor(self):
        cwd = self.root / "pure-ftpd-gcov"
        cwd.mkdir()
        log = self.root / "pure-replay.log"
        record = {"path": "input.raw", "filename": "seed.raw"}
        supervised = {"server_exit_code": -signal.SIGTERM, "client_exit_code": 0,
                      "server_crashed": False, "replay_anomaly": False,
                      "anomaly_kind": "", "harness_shutdown_requested": True,
                      "client_timed_out": False, "server_ready": True,
                      "harness_policy": "ready-client-graceful-exit-v1"}

        def avoid_system_chroot_stage(path, *args, **kwargs):
            if str(path).startswith("/home/fuzzing/"):
                return None
            return original_mkdir(path, *args, **kwargs)

        original_mkdir = Path.mkdir
        with mock.patch.object(cov, "run_reset", return_value={"command_succeeded": True}), \
             mock.patch.object(cov, "instrument_identity", return_value={"gcno": "fixture"}), \
             mock.patch.object(cov, "run_supervised_session", return_value=supervised) as run_session, \
             mock.patch.object(cov.Path, "mkdir", avoid_system_chroot_stage):
            result = cov.run_one_replay("pure-ftpd", record, 21, 1, cwd,
                                        self.root, log, self.root)
        run_session.assert_called_once()
        self.assertEqual(run_session.call_args.args[0], "pure-ftpd")
        self.assertTrue(result["server_ready"])
        self.assertTrue(result["harness_shutdown_requested"])
        # Dispatch alone cannot certify coverage: this fixture intentionally
        # has no session gcda, which must remain an incomplete measurement.
        self.assertTrue(result["session_coverage_missing"])
        self.assertIn("session-gcda-not-flushed", result["incomplete_reasons"])
        self.assertFalse(result["coverage_complete"])

    def test_live555_replay_waits_for_listener_before_client(self):
        # Live555's initial corpus seeds can be replayed before its RTSP
        # listener binds if the client and server are started concurrently.
        # Exercise the production dispatch and require the readiness-aware
        # supervisor for the RTSP target.
        cwd = self.root / "live-gcov" / "testProgs"
        cwd.mkdir(parents=True)
        log = self.root / "replay.log"
        record = {"path": "input.raw", "filename": "seed.raw"}
        supervised = {"server_exit_code": -signal.SIGTERM, "client_exit_code": 0,
                      "server_crashed": False, "replay_anomaly": False,
                      "anomaly_kind": "", "harness_shutdown_requested": True,
                      "client_timed_out": False, "server_ready": True,
                      "harness_policy": "ready-client-graceful-exit-v1"}
        with mock.patch.object(cov, "run_reset", return_value={"command_succeeded": True}), \
             mock.patch.object(cov, "instrument_identity", return_value={"gcno": "fixture"}), \
             mock.patch.object(cov, "run_supervised_session", return_value=supervised) as run_session:
            result = cov.run_one_replay("live555", record, 8554, 1, cwd, self.root,
                                        log, self.root)
        self.assertEqual(run_session.call_args.args[0], "live555")
        self.assertTrue(result["server_ready"])
        self.assertTrue(result["harness_shutdown_requested"])
        self.assertFalse(result["coverage_complete"])
        self.assertIn("frame-ledger-incomplete", result["incomplete_reasons"])

    def test_lightftp_and_lighttpd_wait_for_listener_before_client(self):
        record = {"path": "input.raw", "filename": "seed.raw"}
        cov.loopfuzz_replayer()
        supervised = {"server_exit_code": 0, "client_exit_code": 0,
                      "server_crashed": False, "replay_anomaly": False,
                      "anomaly_kind": "", "harness_shutdown_requested": True,
                      "client_timed_out": False, "server_ready": True,
                      "harness_policy": "ready-client-graceful-exit-v1"}
        for target, directory in (("lightftp", self.root / "LightFTP-gcov" / "Source"),
                                  ("lighttpd1", self.root / "lighttpd1-gcov")):
            with self.subTest(target=target):
                directory.mkdir(parents=True, exist_ok=True)
                log = self.root / (target + "-replay.log")
                with mock.patch.object(cov, "instrument_identity", return_value={"gcno": "fixture"}), \
                     mock.patch.object(cov, "run_supervised_session", return_value=supervised) as run_session, \
                     mock.patch.object(cov.subprocess, "Popen") as popen:
                    result = cov.run_one_replay(target, record, 2121, 1, directory,
                                                self.root, log, directory)
                run_session.assert_called_once()
                self.assertEqual(run_session.call_args.args[0], target)
                popen.assert_not_called()
                self.assertTrue(result["server_ready"])
                self.assertTrue(result["session_coverage_missing"])
                self.assertEqual(result["session_gcda_touched"], [])
                self.assertIn("frame-ledger-incomplete", result["incomplete_reasons"])

    def test_forked_daapd_supervised_replay_does_not_start_a_second_server(self):
        # forked-daapd's supervised run owns server startup and shutdown. The
        # legacy post-supervision launch started a second daemon after replay,
        # which could retain target state and contaminate the next input.
        cwd = self.root / "forked-daapd-gcov" / "src"
        cwd.mkdir(parents=True)
        log = self.root / "daap-replay.log"
        record = {"path": "input.raw", "filename": "seed.raw"}
        supervised = {"server_exit_code": 0, "client_exit_code": 0,
                      "server_crashed": False, "replay_anomaly": False,
                      "anomaly_kind": "", "harness_shutdown_requested": True,
                      "client_timed_out": False, "server_ready": True,
                      "harness_policy": "forked-daapd-ready-client-sigusr1-exit0-v1"}
        cov.loopfuzz_replayer()
        with mock.patch.object(cov, "run_reset", return_value={"command_succeeded": True}), \
             mock.patch.object(cov, "instrument_identity", return_value={"gcno": "fixture"}), \
             mock.patch.object(cov, "run_supervised_session", return_value=supervised) as run_session, \
             mock.patch.object(cov.subprocess, "Popen") as popen:
            result = cov.run_one_replay("forked-daapd", record, 3689, 1, cwd,
                                        self.root, log, self.root)
        run_session.assert_called_once()
        self.assertEqual(run_session.call_args.args[0], "forked-daapd")
        self.assertEqual(run_session.call_args.args[1][2:], ["HTTP", "3689", "0", "100", "10000"])
        popen.assert_not_called()
        self.assertTrue(result["server_ready"])
        self.assertFalse(result["coverage_complete"])
        self.assertIn("frame-ledger-incomplete", result["incomplete_reasons"])

    def test_timeout_and_readiness_remain_incomplete(self):
        self.assertIn("client-timeout", cov.replay_incompleteness({"client_timed_out": True}))
        self.assertIn("server-not-ready", cov.replay_incompleteness({"server_ready": False}))
        self.assertIn("helper-not-ready", cov.replay_incompleteness({"helper_ready": False}))

    def test_supervised_session_waits_for_server_and_flushes_on_shutdown(self):
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        server = self.root / "delayed_server.py"
        marker = self.root / "normal-exit"
        server.write_text("import socket,signal,time,sys\n"
                          "def done(*args):\n"
                          " open(sys.argv[2],'w').write('flushed')\n"
                          " raise SystemExit(0)\n"
                          "signal.signal(signal.SIGTERM,done)\n"
                          "time.sleep(0.15)\n"
                          "s=socket.socket();s.bind(('127.0.0.1',int(sys.argv[1])));s.listen(1)\n"
                          "c,a=s.accept();c.sendall(b'valid-response');c.close()\n"
                          "while True:time.sleep(0.1)\n")
        client = self.root / "client.py"
        client.write_text("import socket,sys\n"
                          "s=socket.create_connection(('127.0.0.1',int(sys.argv[1])))\n"
                          "assert s.recv(32)==b'valid-response'\n")
        prefix = ["timeout", "-k", "1s", "-s", "SIGTERM", "3s"]
        # A stalled client must yield an explicit incomplete record and
        # release both processes, so the next input can still be replayed.
        with (self.root / "timeout.log").open("wb") as log, \
                mock.patch.object(cov, "client_timeout_seconds", return_value=0.05):
            stalled = cov.run_supervised_session("exim",
                [sys.executable, "-c", "import time; time.sleep(60)"],
                prefix + [sys.executable, str(server), str(port), str(marker)],
                {"path": str(client)}, 0, port, self.root, os.environ.copy(), log)
        self.assertTrue(stalled["client_timed_out"])
        self.assertIn("client-timeout", cov.replay_incompleteness(stalled))
        self.assertEqual(marker.read_text(), "flushed")
        marker.unlink()
        with (self.root / "session.log").open("wb") as log:
            result = cov.run_supervised_session("exim", [sys.executable, str(client), str(port)],
                prefix + [sys.executable, str(server), str(port), str(marker)],
                {"path": str(client)}, 0, port, self.root, os.environ.copy(), log)
        self.assertTrue(result["server_ready"])
        self.assertEqual(result["client_exit_code"], 0)
        self.assertEqual(result["server_exit_code"], 0)
        self.assertFalse(result["server_crashed"])
        self.assertFalse(result["client_timed_out"])
        self.assertEqual(marker.read_text(), "flushed")

    def test_supervised_live555_sigusr1_flushes_on_normal_exit(self):
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        server = self.root / "live555_gcda_server.py"
        marker = self.root / "live555-normal-exit"
        server.write_text("import socket,signal,time,sys\n"
                          "def done(*args):\n"
                          " open(sys.argv[2],'w').write('gcda-flushed')\n"
                          " raise SystemExit(0)\n"
                          "signal.signal(signal.SIGUSR1,done)\n"
                          "time.sleep(0.15)\n"
                          "s=socket.socket();s.bind(('127.0.0.1',int(sys.argv[1])));s.listen(1)\n"
                          "c,a=s.accept();c.sendall(b'RTSP-response');c.close()\n"
                          "while True:time.sleep(0.1)\n")
        client = self.root / "live555_client.py"
        client.write_text("import socket,sys\n"
                          "s=socket.create_connection(('127.0.0.1',int(sys.argv[1])))\n"
                          "assert s.recv(32)==b'RTSP-response'\n")
        prefix = ["timeout", "-k", "1s", "-s", "SIGUSR1", "3s"]
        with (self.root / "live555-session.log").open("wb") as log:
            result = cov.run_supervised_session(
                "live555", [sys.executable, str(client), str(port)],
                prefix + [sys.executable, str(server), str(port), str(marker)],
                {"path": str(client)}, 0, port, self.root, os.environ.copy(), log)
        self.assertTrue(result["server_ready"])
        self.assertEqual(result["client_exit_code"], 0)
        self.assertEqual(result["server_exit_code"], 0)
        self.assertEqual(result["harness_shutdown_signal"], "SIGUSR1")
        self.assertEqual(result["harness_policy"], "live555-ready-client-sigusr1-exit0-v2")
        self.assertFalse(result["server_crashed"])
        self.assertFalse(result["replay_anomaly"])
        self.assertEqual(marker.read_text(), "gcda-flushed")

    def test_supervised_lightftp_waits_and_flushes_on_sigusr1(self):
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        server = self.root / "lightftp_gcda_server.py"
        marker = self.root / "lightftp-normal-exit"
        server.write_text("import socket,signal,time,sys\n"
                          "def done(*args):\n"
                          " open(sys.argv[2],'w').write('gcda-flushed')\n"
                          " raise SystemExit(0)\n"
                          "signal.signal(signal.SIGUSR1,done)\n"
                          "time.sleep(0.15)\n"
                          "s=socket.socket();s.bind(('127.0.0.1',int(sys.argv[1])));s.listen(1)\n"
                          "c,a=s.accept();c.sendall(b'220 ready\\r\\n');c.close()\n"
                          "while True:time.sleep(0.1)\n")
        client = self.root / "lightftp_client.py"
        client.write_text("import socket,sys\n"
                          "s=socket.create_connection(('127.0.0.1',int(sys.argv[1])))\n"
                          "assert s.recv(32)==b'220 ready\\r\\n'\n")
        prefix = ["timeout", "-k", "1s", "-s", "SIGUSR1", "3s"]
        with (self.root / "lightftp-session.log").open("wb") as log:
            result = cov.run_supervised_session(
                "lightftp", [sys.executable, str(client), str(port)],
                prefix + [sys.executable, str(server), str(port), str(marker)],
                {"path": str(client)}, 0, port, self.root, os.environ.copy(), log)
        self.assertTrue(result["server_ready"])
        self.assertEqual(result["client_exit_code"], 0)
        self.assertEqual(result["server_exit_code"], 0)
        self.assertEqual(result["harness_shutdown_signal"], "SIGUSR1")
        self.assertEqual(marker.read_text(), "gcda-flushed")

    def test_supervised_forked_daapd_waits_for_listener_and_flushes_on_sigusr1(self):
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        server = self.root / "daap_gcda_server.py"
        marker = self.root / "daap-normal-exit"
        server.write_text("import socket,signal,time,sys\n"
                          "def done(*args):\n"
                          " open(sys.argv[2],'w').write('gcda-flushed')\n"
                          " raise SystemExit(0)\n"
                          "signal.signal(signal.SIGUSR1,done)\n"
                          "time.sleep(0.15)\n"
                          "s=socket.socket();s.bind(('127.0.0.1',int(sys.argv[1])));s.listen(1)\n"
                          "c,a=s.accept();c.sendall(b'HTTP-response');c.close()\n"
                          "while True:time.sleep(0.1)\n")
        client = self.root / "daap_client.py"
        client.write_text("import socket,sys\n"
                          "s=socket.create_connection(('127.0.0.1',int(sys.argv[1])))\n"
                          "assert s.recv(32)==b'HTTP-response'\n")
        prefix = ["timeout", "-k", "1s", "-s", "SIGUSR1", "10s"]
        with (self.root / "daap-session.log").open("wb") as log:
            result = cov.run_supervised_session(
                "forked-daapd", [sys.executable, str(client), str(port)],
                prefix + [sys.executable, str(server), str(port), str(marker)],
                {"path": str(client)}, 0, port, self.root, os.environ.copy(), log)
        self.assertTrue(result["server_ready"])
        self.assertEqual(result["client_exit_code"], 0)
        self.assertEqual(result["server_exit_code"], 0)
        self.assertEqual(result["harness_shutdown_signal"], "SIGUSR1")
        self.assertEqual(result["harness_policy"], "forked-daapd-ready-client-sigusr1-exit0-v1")
        self.assertFalse(result["server_crashed"])
        self.assertFalse(result["replay_anomaly"])
        self.assertEqual(marker.read_text(), "gcda-flushed")
        self.assertTrue(cov.forked_daapd_replay_policy()["verified"])

    def test_target_config_override_is_forwarded_as_argv(self):
        config = self.root / "prepared config.conf"
        config.write_text("prepared\n")
        with mock.patch.dict(os.environ, {"COVERAGE_V4_TARGET_CONFIG": str(config)}):
            lightftp = cov.replay_commands("lightftp", "input", 2200, 1,
                                           self.root, self.root)[1]
            lighttpd = cov.replay_commands("lighttpd1", "input", 8080, 1,
                                           self.root, self.root)[1]
            daap = cov.replay_commands("forked-daapd", "input", 3689, 1,
                                       self.root, self.root)[1]
        self.assertIn(str(config), lightftp)
        self.assertIn(str(config), lighttpd)
        self.assertIn(str(config), daap)

    def test_existing_output_is_not_overwritten(self):
        output = self.root / "existing.csv"
        output.write_text("original\n")
        result = cov.main(["replay", "--target", "lightftp", "--folder", str(self.root),
                           "--port", "2200", "--step", "5", "--output", str(output), "--mode", "1"])
        self.assertEqual(result, 2)
        self.assertEqual(output.read_text(), "original\n")

    def test_sampled_checkpoints_are_explicit_and_target_scoped(self):
        args = cov.main(["replay", "--target", "bftpd", "--folder", str(self.root),
                         "--port", "2200", "--step", "2", "--output",
                         str(self.root / "sampled.csv"), "--mode", "1",
                         "--sampled-checkpoints"])
        self.assertEqual(args, 2)  # excluded target rejected before touching paths
        seen = []
        with mock.patch.object(cov, "run_replay", side_effect=lambda parsed: seen.append(parsed) or 0):
            result = cov.main(["replay", "--target", "lightftp", "--folder", str(self.root),
                               "--port", "2200", "--step", "2", "--output",
                               str(self.root / "sampled.csv"), "--mode", "1"])
        self.assertEqual(result, 0)
        self.assertFalse(seen[0].sampled_checkpoints)

    def test_five_wrappers_forward_paths_and_require_exact_coordinates(self):
        benchmark = Path(__file__).resolve().parents[2]
        targets = {"FTP/LightFTP": "lightftp", "HTTP/Lighttpd1": "lighttpd1",
                   "DAAP/forked-daapd": "forked-daapd", "FTP/BFTPD": "bftpd",
                   "SIP/Kamailio": "kamailio", "SMTP/Exim": "exim",
                   "FTP/ProFTPD": "proftpd", "FTP/PureFTPD": "pure-ftpd",
                   "RTSP/Live555": "live555"}
        fake = self.root / "fake coverage module.py"
        fake.write_text("import json, sys\nprint(json.dumps(sys.argv[1:]))\n")
        env = dict(os.environ, COVERAGE_V4_MODULE=str(fake), COVERAGE_V4_REQUIRE_COORDINATES="1")
        sampled_env = dict(env, COVERAGE_V4_SAMPLED_CHECKPOINTS="1")
        sampled_targets = set(cov.ACCUMULATING_GCDA_TARGETS)
        for relative, target in targets.items():
            wrapper = benchmark / "subjects" / relative / "cov_script.sh"
            self.assertTrue(os.access(wrapper, os.X_OK))
            subprocess.run(["bash", "-n", str(wrapper)], check=True)
            output = subprocess.check_output(["bash", str(wrapper), "/corpus with space", "2200",
                                              "5", "/output with space.csv", "1"], env=env, text=True)
            arguments = json.loads(output)
            self.assertEqual(arguments, ["replay", "--target", target, "--folder", "/corpus with space",
                                         "--port", "2200", "--step", "5", "--output",
                                         "/output with space.csv", "--mode", "1", "--require-coordinates"])
            sampled_output = subprocess.check_output(
                ["bash", str(wrapper), "/corpus with space", "2200", "5",
                 "/output with space.csv", "1"], env=sampled_env, text=True)
            sampled_arguments = json.loads(sampled_output)
            expected = arguments + (["--sampled-checkpoints"] if target in sampled_targets else [])
            self.assertEqual(sampled_arguments, expected)


@unittest.skipUnless(shutil.which("gcc") and shutil.which("gcov") and shutil.which("gcovr"),
                     "requires local gcc/gcov/gcovr")
class RealGcovTests(unittest.TestCase):
    def test_full_pipeline_and_independent_artifact_audit(self):
        with tempfile.TemporaryDirectory(prefix="loopfuzz-cov-e2e-") as temporary:
            root = Path(temporary)
            (root / "probe.c").write_text("#include <stdio.h>\nint main(int argc, char **argv) {\n"
                                         "  if (argc > 1) { puts(\"right\"); }\n"
                                         "  else { puts(\"left\"); }\n  return 0;\n}\n")
            subprocess.run(["gcc", "--coverage", "-O0", "-o", "probe", "probe.c"], cwd=root, check=True)
            corpus = root / "campaign/replayable-queue"
            corpus.mkdir(parents=True)
            ledger = []
            for index in (1, 2, 3):
                filename = "id:%06d" % index
                (corpus / filename).write_text(str(index))
                ledger.append(dict(schema_version=1, filename=filename, queue_id=index,
                                   campaign_id="real-fixture", discovery_time_ms=index * 1000,
                                   monotonic_ms=index * 1000, discovery_execution_id=index * 10))
            (corpus.parent / "queue-checkpoints.jsonl").write_text(
                "".join(json.dumps(record) + "\n" for record in ledger))
            output = root / "coverage.csv"
            args = argparse.Namespace(folder=corpus.parent, output=output, target="bftpd", port=0,
                                      mode=1, step=5, require_coordinates=True, gcovr="gcovr",
                                      allow_unverified_reset=False)

            def local_replay(target, record, port, mode, cwd, workdir, replay_log, object_root,
                             reset=None, replay_policy=None):
                cov.collect_report(root, root, delete=True)
                arguments = [] if record["queue_id"] == 1 else ["right"]
                subprocess.run([str(root / "probe"), *arguments], cwd=root, check=True,
                               stdout=subprocess.DEVNULL)
                Path(replay_log).write_text("local fixture, no socket or protocol target\n")
                return dict(server_exit_code=0, client_exit_code=0)

            original = Path.cwd()
            try:
                os.chdir(root)
                with mock.patch.object(cov, "run_one_replay", side_effect=local_replay), \
                     mock.patch.object(cov, "bftpd_exit_policy", return_value={"verified": True, "name": "unit-fixture"}), \
                        mock.patch.object(cov, "REPLAY_HARNESS_VERSION", "unit-fixture"), \
                        mock.patch.dict(os.environ, {"COVERAGE_V4_RESET_COMMAND_JSON": '["/usr/bin/true"]'}):
                    self.assertEqual(cov.run_replay(args), 0)
            finally:
                os.chdir(original)
            audit = cov.audit_artifacts(output)
            self.assertEqual(audit["rows"], 1)
            # This end-to-end fixture mocks a generic unit policy, not the
            # production BFTPD protocol-end policy that triggers this audit.
            self.assertNotIn("bftpd_replay_audit", audit)
            directory = Path(str(output) + ".v4")
            terminal = json.loads((directory / "terminal.json").read_text())
            self.assertEqual(terminal["n_replayed"], 3)
            self.assertTrue(terminal["fixed_execution_coordinates_valid"])
            self.assertFalse(Path(str(output) + ".final").exists())
            self.assertEqual(len(list(directory.glob("snapshot-*.json.gz"))), 3)
            events = [json.loads(row) for row in (directory / "checkpoints.jsonl").read_text().splitlines()]
            self.assertGreater(events[1]["cumulative_covered_branches"], events[0]["cumulative_covered_branches"])
            self.assertEqual(events[1]["cumulative_covered_branches"], events[2]["cumulative_covered_branches"])
            # A valid partial branch union cannot authenticate an unflushed
            # replay; preserve evidence but fail strict acceptance.
            incomplete_args = argparse.Namespace(**vars(args))
            incomplete_args.output = root / "incomplete.csv"
            def incomplete_replay(*arguments, **keywords):
                result = local_replay(*arguments, **keywords)
                result.update(session_coverage_missing=True, server_crashed=True)
                return result
            try:
                os.chdir(root)
                with mock.patch.object(cov, "run_one_replay", side_effect=incomplete_replay), \
                     mock.patch.object(cov, "bftpd_exit_policy", return_value={"verified": True, "name": "unit-fixture"}), \
                     mock.patch.object(cov, "REPLAY_HARNESS_VERSION", "unit-fixture"), \
                     mock.patch.dict(os.environ, {"COVERAGE_V4_RESET_COMMAND_JSON": '["/usr/bin/true"]'}):
                    with self.assertRaisesRegex(cov.CoverageError, "coverage is incomplete"):
                        cov.run_replay(incomplete_args)
            finally:
                os.chdir(original)
            incomplete_directory = Path(str(incomplete_args.output) + ".v4")
            partial = json.loads((incomplete_directory / "terminal.json").read_text())
            self.assertFalse(partial["coverage_complete"])
            self.assertEqual(len(partial["incomplete_replays"]), 3)
            cov.audit_artifacts(incomplete_args.output)
            partial["coverage_complete"] = True
            cov.write_json(incomplete_directory / "terminal.json", partial)
            with self.assertRaisesRegex(cov.CoverageError, "completeness"):
                cov.audit_artifacts(incomplete_args.output)
            # Percentages can be self-consistent while counts disagree with identities.
            terminal["covered_branch_ids"].pop()
            cov.write_json(directory / "terminal.json", terminal)
            with self.assertRaisesRegex(cov.CoverageError, "terminal aggregate"):
                cov.audit_artifacts(output)

    def test_two_real_disjoint_gcda_runs_union_and_replay_stability(self):
        with tempfile.TemporaryDirectory(prefix="loopfuzz-real-gcov-") as temporary:
            root = Path(temporary)
            source = root / "probe.c"
            source.write_text("#include <stdio.h>\nint main(int argc, char **argv) {\n"
                              "  if (argc > 1) { puts(\"right\"); }\n"
                              "  else { puts(\"left\"); }\n  return 0;\n}\n")
            subprocess.run(["gcc", "--coverage", "-O0", "-o", "probe", "probe.c"], cwd=root, check=True)
            notes = cov.instrument_identity(root)
            baseline_report, _, _ = cov.collect_report(root, root)
            baseline = cov.parse_snapshot(baseline_report, root)
            manifest = cov.scope_manifest(baseline, notes, "local-real-test", "local-real-test")
            union = cov.CoverageUnion(baseline, manifest)
            covered = []
            for index, arguments in enumerate(([], ["right"], ["right"]), 1):
                cov.collect_report(root, root, delete=True)
                subprocess.run([str(root / "probe"), *arguments], cwd=root, check=True,
                               stdout=subprocess.DEVNULL)
                report, _, _ = cov.collect_report(root, root)
                snapshot = cov.parse_snapshot(report, root)
                covered.append(snapshot.covered_branches)
                union.add(snapshot, dict(discovery_time_ms=index * 1000,
                                        discovery_execution_id=index,
                                        monotonic_ms=index * 1000,
                                        coordinate_source="real-gcov-fixture"),
                          cov.digest_bytes(cov.canonical(report).encode()), expected_counter_reset=True)
            self.assertGreater(len(covered[0] | covered[1]), max(len(covered[0]), len(covered[1])))
            self.assertEqual(covered[1], covered[2])
            self.assertEqual(union.covered, covered[0] | covered[1])
            self.assertEqual(cov.instrument_identity(root), notes)

    def test_sampled_gcda_checkpoints_keep_every_input_auditable(self):
        with tempfile.TemporaryDirectory(prefix="loopfuzz-cov-sampled-") as temporary:
            root = Path(temporary)
            (root / "probe.c").write_text(
                "#include <stdio.h>\nint main(int argc, char **argv) {\n"
                "  if (argc > 1) { puts(\"right\"); }\n"
                "  else { puts(\"left\"); }\n  return 0;\n}\n")
            subprocess.run(["gcc", "--coverage", "-O0", "-o", "probe", "probe.c"], cwd=root, check=True)
            campaign = root / "campaign"
            corpus = campaign / "replayable-queue"
            corpus.mkdir(parents=True)
            ledger = []
            for index in (1, 2, 3):
                filename = "id:%06d" % index
                (corpus / filename).write_text(str(index))
                ledger.append(dict(schema_version=1, filename=filename, queue_id=index,
                                   campaign_id="sampled-fixture", discovery_time_ms=index * 1000,
                                   monotonic_ms=index * 1000, discovery_execution_id=index * 10))
            (campaign / "queue-checkpoints.jsonl").write_text(
                "".join(json.dumps(record) + "\n" for record in ledger))
            output = root / "sampled.csv"
            args = argparse.Namespace(folder=campaign, output=output, target="forked-daapd", port=0,
                                      mode=1, step=2, require_coordinates=True, gcovr="gcovr",
                                      allow_unverified_reset=False, sampled_checkpoints=True)

            def local_replay(target, record, port, mode, cwd, workdir, replay_log, object_root,
                             reset=None, replay_policy=None):
                arguments = [] if record["queue_id"] == 1 else ["right"]
                subprocess.run([str(root / "probe"), *arguments], cwd=root, check=True,
                               stdout=subprocess.DEVNULL)
                Path(replay_log).write_text("local fixture, no socket or protocol target\n")
                return dict(server_exit_code=0, client_exit_code=0)

            original = Path.cwd()
            try:
                os.chdir(root)
                with mock.patch.object(cov, "profile_paths", return_value=(root, root)), \
                     mock.patch.object(cov, "source_search_roots", return_value=[]), \
                     mock.patch.object(cov, "run_one_replay", side_effect=local_replay), \
                     mock.patch.object(cov, "REPLAY_HARNESS_VERSION", "unit-fixture"), \
                     mock.patch.dict(os.environ, {"COVERAGE_V4_RESET_COMMAND_JSON": '["/usr/bin/true"]'}):
                    self.assertEqual(cov.run_replay(args), 0)
            finally:
                os.chdir(original)
            directory = Path(str(output) + ".v5")
            self.assertTrue(directory.is_dir())
            self.assertFalse(Path(str(output) + ".v4").exists())
            self.assertEqual(cov.audit_artifacts(output)["rows"], 2)
            records = [json.loads(row) for row in (directory / "replay-ledger.jsonl").read_text().splitlines()]
            events = [json.loads(row) for row in (directory / "checkpoints.jsonl").read_text().splitlines()]
            self.assertEqual(len(records), 3)
            self.assertEqual([r["checkpoint"] for r in records], [False, True, True])
            self.assertEqual([e["replay_input_idx"] for e in events], [2, 3])
            # The first saved checkpoint includes the branch from input 1,
            # proving skipped inputs still contributed through accumulated gcda.
            self.assertGreater(events[0]["cumulative_covered_branches"], 0)
            self.assertTrue(json.loads((directory / "terminal.json").read_text())["coverage_complete"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
