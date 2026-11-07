import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import ledger_check_T02B_v2 as checker  # noqa: E402
import coverage_audit_T02C as coverage  # noqa: E402


def make_archive(events, budget=10, policy="none", flow=None,
                 campaign_id=None, stats=None, config_end=None):
    tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    tmp.close()
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "out-bftpd-loopfuzz"
        root.mkdir()
        (root / "execution-events.jsonl").write_text(
            "".join(json.dumps(e) + "\n" for e in events)
        )
        config = {
            "event": "run_config", "phase": "start",
            "campaign_call_budget": budget, "q1_policy": policy,
        }
        if campaign_id is not None:
            config["campaign_id"] = campaign_id
        config_rows = [config]
        if config_end is not None:
            config_rows.append({"event": "run_config", "phase": "end",
                                **config_end})
        (root / "run-config.jsonl").write_text(
            "".join(json.dumps(x) + "\n" for x in config_rows))
        if stats is not None:
            (root / "fuzzer_stats").write_text(
                "".join(f"{k:<30} : {v}\n" for k, v in stats.items()))
        if flow is not None:
            (root / "q1-budget-flow.jsonl").write_text(
                "".join(json.dumps(e) + "\n" for e in flow)
            )
        with tarfile.open(tmp.name, "w:gz") as tf:
            tf.add(root, arcname="out-bftpd-loopfuzz")
    return Path(tmp.name)


def pair(i=1, kind="mutation", root=None):
    common = {
        "schema_version": 4, "campaign_id": "c1", "invocation_id": i,
        "attempt_id": i, "execution_kind": kind,
        "provisional_root_queue_id": root,
    }
    return [{"event": "invocation_start", **common},
            {"event": "invocation_end", **common}]


class LedgerCheckerTests(unittest.TestCase):
    def test_valid_budget_and_pairing(self):
        p = make_archive(pair())
        try:
            r = checker.check_archive(p)
            self.assertEqual(r["status"], "PASS")
        finally:
            p.unlink()

    def test_duplicate_invocation_id_is_failure(self):
        events = pair(1) + pair(1)
        p = make_archive(events, budget=2)
        try:
            r = checker.check_archive(p)
            self.assertEqual(r["status"], "FAIL")
            self.assertIn("duplicate-start-invocation-id", r["failures"])
        finally:
            p.unlink()

    def test_unmatched_end_is_failure(self):
        events = pair(1) + [{"event": "invocation_end", "invocation_id": 99,
                             "attempt_id": 99, "campaign_id": "c1",
                             "execution_kind": "mutation"}]
        p = make_archive(events, budget=2)
        try:
            r = checker.check_archive(p)
            self.assertEqual(r["status"], "FAIL")
            self.assertIn("unmatched-or-extra-end-id", r["failures"])
        finally:
            p.unlink()

    def test_unknown_execution_kind_is_failure(self):
        p = make_archive(pair(kind="not-a-kind"))
        try:
            r = checker.check_archive(p)
            self.assertEqual(r["status"], "FAIL")
            self.assertTrue(any(x.startswith("unknown-execution-kind") for x in r["failures"]))
        finally:
            p.unlink()

    def test_budget_overrun_is_failure(self):
        p = make_archive(pair(1) + pair(2), budget=1)
        try:
            r = checker.check_archive(p)
            self.assertEqual(r["status"], "FAIL")
            self.assertIn("starts-over-campaign-budget", r["failures"])
        finally:
            p.unlink()

    def test_q1_missing_root_is_explicitly_inconclusive(self):
        p = make_archive(pair(), budget=1, policy="reflow")
        try:
            r = checker.check_archive(p)
            self.assertEqual(r["status"], "INCONCLUSIVE")
            self.assertIn("missing-provisional-root-identity", r["inconclusive"])
        finally:
            p.unlink()

    def test_q1_flow_arithmetic_is_checked(self):
        good = [{"event": "q1_budget_flow", "kind": "saved",
                 "campaign_id": "c1",
                 "candidate_id": 1, "destination": "ordinary-pool", "flow_id": 7,
                 "receiver_invocation_id": 0, "amount": 64, "remaining": 64,
                 "saved_total": 64, "idle_total": 0, "reflow_consumed": 0,
                 "reflow_pool_left": 64},
                {"event": "q1_budget_flow", "kind": "consumed",
                 "campaign_id": "c1",
                 "candidate_id": 1, "destination": "ordinary-mutation", "flow_id": 7,
                 "receiver_invocation_id": 2, "amount": 1, "remaining": 63,
                 "saved_total": 64, "idle_total": 0, "reflow_consumed": 1,
                 "reflow_pool_left": 63}]
        bad = [dict(good[0], saved_total=65)]
        events = pair(2)
        for event in events:
            event.update({"q1_flow_id": 7, "q1_flow_source_candidate": 1})
        for flow, expected in ((good, "PASS"), (bad, "FAIL")):
            p = make_archive(events, flow=flow)
            try:
                r = checker.check_archive(p)
                self.assertEqual(r["q1_flow_status"], expected)
            finally:
                p.unlink()

    def test_q1_flow_rejects_unbound_consumption(self):
        flow = [{"event": "q1_budget_flow", "kind": "saved",
                 "campaign_id": "c1",
                 "candidate_id": 1, "destination": "ordinary-pool", "flow_id": 7,
                 "receiver_invocation_id": 0, "amount": 2, "remaining": 2,
                 "saved_total": 2, "idle_total": 0, "reflow_consumed": 0,
                 "reflow_pool_left": 2},
                {"event": "q1_budget_flow", "kind": "consumed",
                 "campaign_id": "c1",
                 "candidate_id": 999, "destination": "ordinary-mutation", "flow_id": 8,
                 "receiver_invocation_id": 2, "amount": 1, "remaining": 1,
                 "saved_total": 2, "idle_total": 0, "reflow_consumed": 1,
                 "reflow_pool_left": 1}]
        p = make_archive(pair(2), flow=flow)
        try:
            r = checker.check_archive(p)
            self.assertEqual(r["q1_flow_status"], "FAIL")
            self.assertIn("q1-consumed-unknown-flow-id:1", r["failures"])
        finally:
            p.unlink()

    def test_q1_flow_requires_campaign_binding(self):
        flow = [{"event": "q1_budget_flow", "kind": "saved",
                 "campaign_id": "wrong", "candidate_id": 1,
                 "destination": "ordinary-pool", "flow_id": 7,
                 "receiver_invocation_id": 0, "amount": 2,
                 "remaining": 2, "saved_total": 2, "idle_total": 0,
                 "reflow_consumed": 0, "reflow_pool_left": 2}]
        events = pair(1)
        for row in events:
            row["campaign_id"] = "right"
        p = make_archive(events, policy="reflow", flow=flow,
                         campaign_id="right")
        try:
            r = checker.check_archive(p)
            self.assertEqual(r["q1_flow_status"], "FAIL")
            self.assertIn("q1-flow-campaign-mismatch:0", r["failures"])
        finally:
            p.unlink()

    def test_stats_bind_charged_and_q1_conservation(self):
        events = pair(1)
        for row in events:
            row["campaign_id"] = "c1"
        p = make_archive(
            events, budget=4, policy="reflow", campaign_id="c1",
            stats={"campaign_charged_calls": 2,
                   "campaign_budget_exhausted": 1,
                   "q1_saved_quota": 2, "q1_idle_quota": 0,
                   "q1_reflow_consumed": 2, "q1_reflow_pool_left": 0},
            config_end={"campaign_id": "c1",
                        "termination_reason": "campaign-call-budget"})
        try:
            r = checker.check_archive(p)
            self.assertEqual(r["status"], "FAIL")
            self.assertIn("charged-start-count-mismatch", r["failures"])
            self.assertIn("q1-effective-budget-not-closed", r["failures"])
        finally:
            p.unlink()

    def test_coverage_audit_does_not_invent_seed_delta(self):
        p = make_archive(pair())
        try:
            # Add the two coverage JSON files to a replacement archive.
            with tempfile.TemporaryDirectory() as d:
                root = Path(d) / "out-bftpd-loopfuzz"
                root.mkdir()
                for name in ("execution-events.jsonl", "run-config.jsonl"):
                    (root / name).write_bytes(b"")
                covdir = root / "cov_over_time.csv.v4"
                covdir.mkdir()
                (covdir / "terminal.json").write_text(json.dumps({
                    "acceptance": "complete", "coverage_complete": True,
                    "covered_branch_ids": [["x.c", 1, 0]],
                    "n_unreplayable_ledger_entries": 0,
                    "replay_anomalies": [], "n_replayed": 1,
                }))
                (covdir / "baseline.json").write_text(json.dumps({"files": []}))
                q = Path(d) / "coverage.tar.gz"
                with tarfile.open(q, "w:gz") as tf:
                    tf.add(root, arcname="out-bftpd-loopfuzz")
                r = coverage.audit_archive(q)
                self.assertEqual(r["status"], "INCONCLUSIVE")
                self.assertIsNone(r["terminal_minus_baseline_branch_ids"])
                self.assertFalse(r["seed_subtraction_proven"])
        finally:
            p.unlink()

    def test_coverage_audit_accepts_seed_and_input_witness(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "out-bftpd-loopfuzz"
            covdir = root / "cov_over_time.csv.v4"
            covdir.mkdir(parents=True)
            (root / "execution-events.jsonl").write_text("")
            (root / "run-config.jsonl").write_text("")
            plan = [{"filename": "id:000001", "input_sha256": "input-hash"}]
            checkpoint = {"idx": 1, "filename": "id:000001",
                          "input_sha256": "input-hash", "snapshot_sha256": "snap-hash"}
            (covdir / "replay-plan.json").write_text(json.dumps(plan))
            (covdir / "checkpoints.jsonl").write_text(json.dumps(checkpoint) + "\n")
            (covdir / "terminal.json").write_text(json.dumps({
                "acceptance": "complete", "coverage_complete": True,
                "covered_branch_ids": [["x.c", 1, 0]],
                "seed_covered_branch_ids": [["seed.c", 2, 0]],
                "n_seed_replayed": 1, "n_unreplayable_ledger_entries": 0,
                "replay_anomalies": [], "n_replayed": 1,
                "executed_input_witnesses": [checkpoint],
            }))
            (covdir / "baseline.json").write_text(json.dumps({"files": []}))
            q = Path(d) / "coverage.tar.gz"
            with tarfile.open(q, "w:gz") as tf:
                tf.add(root, arcname="out-bftpd-loopfuzz")
            result = coverage.audit_archive(q)
            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["seed_subtraction_proven"])
            self.assertTrue(result["executed_input_union_proven"])


if __name__ == "__main__":
    unittest.main()
