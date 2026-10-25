#!/usr/bin/env python3
"""Safe fixtures and real local gcov regression; no protocol target or socket."""

import copy
import argparse
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import coverage_v4 as cov


class CoverageFixtureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="loopfuzz-cov-v4-")
        self.root = Path(self.directory.name)
        (self.root / "main.c").write_text("int main(void) { return 0; }\n")
        self.report = {"gcovr/format_version": "0.1", "files": [{"file": "main.c", "lines": [
            {"line_number": 1, "count": 0, "branches": [
                {"count": 0, "fallthrough": True, "throw": False},
                {"count": 0, "fallthrough": False, "throw": False}]}]}]}
        self.baseline = cov.parse_snapshot(self.report, self.root)
        self.manifest = cov.scope_manifest(self.baseline, {"main.gcno": "fixture"}, "4.2", "gcc fixture")

    def tearDown(self):
        self.directory.cleanup()

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


    def test_replay_exit_classification_tolerates_pureftpd_252(self):
        # pure-ftpd session supervisors exit 252 after a normal logout;
        # this must be a recorded per-input anomaly, not a campaign abort.
        f = cov.classify_replay_exit(252, 0)
        self.assertTrue(f["replay_anomaly"])
        self.assertEqual(f["anomaly_kind"], "server-exit-252")
        self.assertFalse(f["server_crashed"])
        self.assertFalse(f["client_anomalous_exit"])

    def test_replay_exit_classification_normal_and_crash(self):
        self.assertFalse(cov.classify_replay_exit(0, 0)["replay_anomaly"])
        self.assertFalse(cov.classify_replay_exit(124, 0)["replay_anomaly"])
        crash = cov.classify_replay_exit(-11, 1)
        self.assertTrue(crash["server_crashed"])
        self.assertFalse(crash["replay_anomaly"])  # crash finding, not anomaly
        self.assertEqual(crash["anomaly_kind"], "server-crash-finding")

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
                    "live555": (self.root, self.root)}
        for target, roots in expected.items():
            self.assertEqual(cov.profile_paths(target, self.root), roots)
        with mock.patch.dict(os.environ, {"KAMAILIO_TCP": "1"}):
            with self.assertRaisesRegex(cov.CoverageError, "UDP substitution"):
                cov.replay_commands("kamailio", "input", 5060, 1, self.root, self.root)
        # New subjects: replay argv shapes must stay pinned.
        exim_client, exim_server = cov.replay_commands("exim", "input", 25, 1,
                                                       self.root, self.root)
        self.assertEqual(exim_client[:3], ["aflnet-replay", "input", "SMTP"])
        self.assertIn("-bd", exim_server)
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
        self.assertIn("./testOnDemandRTSPServer", live_server)

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

            def local_replay(target, record, port, mode, cwd, workdir, replay_log, object_root):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
