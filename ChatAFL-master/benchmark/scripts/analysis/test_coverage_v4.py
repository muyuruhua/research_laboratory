#!/usr/bin/env python3
"""Safe fixtures and real local gcov regression; no protocol target or socket."""

import copy
import argparse
import csv
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
            "echo 'Usage: aflnet-replay packet_file protocol port local_port [first_resp_timeout(us) [follow-up_resp_timeout(ms)]]' >&2\n"
            "exit 1\n")
        self.replayer.chmod(0o755)
        replayer_env = mock.patch.dict(os.environ, {
            cov.LOOPFUZZ_REPLAYER_ENV: str(self.replayer)})
        replayer_env.start()
        self.addCleanup(replayer_env.stop)
        (self.root / "main.c").write_text("int main(void) { return 0; }\n")
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
                             reset=None):
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
                        mock.patch.dict(os.environ, {"COVERAGE_V4_RESET_COMMAND_JSON": '["/usr/bin/true"]'}):
                    self.assertEqual(cov.run_replay(args), 0)
            finally:
                os.chdir(original)
            self.assertEqual(cov.audit_artifacts(output)["rows"], 1)
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
            args = argparse.Namespace(folder=campaign, output=output, target="lightftp", port=0,
                                      mode=1, step=2, require_coordinates=True, gcovr="gcovr",
                                      allow_unverified_reset=False, sampled_checkpoints=True)

            def local_replay(target, record, port, mode, cwd, workdir, replay_log, object_root,
                             reset=None):
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
