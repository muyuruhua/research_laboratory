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
        with self.assertRaisesRegex(cov.CoverageError, "escapes"):
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
        plan = cov.plan_corpus(folder, 1, coordinates, True)
        self.assertEqual([r["discovery_execution_id"] for r in plan], [10, 20])
        self.assertGreater(plan[0]["original_mtime_ns"], plan[1]["original_mtime_ns"])

    def test_missing_coordinates_never_invent_execution_id(self):
        folder = self.make_corpus()
        plan = cov.plan_corpus(folder, 1, {})
        self.assertTrue(all("discovery_execution_id" not in row for row in plan))
        with self.assertRaisesRegex(cov.CoverageError, "no unique discovery"):
            cov.plan_corpus(folder, 1, {}, True)

    def test_partial_join_and_duplicate_ledger_are_rejected(self):
        folder = self.make_corpus()
        with self.assertRaisesRegex(cov.CoverageError, "one-to-one"):
            cov.plan_corpus(folder, 1, {"id:000001": self.coordinates(1)})
        ledger = folder / "queue-checkpoints.jsonl"
        ledger.write_text((json.dumps(self.coordinates(1)) + "\n") * 2)
        with self.assertRaisesRegex(cov.CoverageError, "not unique"):
            cov.load_coordinates(ledger)

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
                    "forked-daapd": (self.root / "forked-daapd-gcov",) * 2,
                    "kamailio": (self.root / "kamailio-gcov",) * 2,
                    "bftpd": (self.root, self.root)}
        for target, roots in expected.items():
            self.assertEqual(cov.profile_paths(target, self.root), roots)
        with mock.patch.dict(os.environ, {"KAMAILIO_TCP": "1"}):
            with self.assertRaisesRegex(cov.CoverageError, "UDP substitution"):
                cov.replay_commands("kamailio", "input", 5060, 1, self.root, self.root)

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
                   "SIP/Kamailio": "kamailio"}
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
