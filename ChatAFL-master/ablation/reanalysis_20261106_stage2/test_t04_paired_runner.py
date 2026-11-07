#!/usr/bin/env python3
"""Contract tests for the manifest and per-root accounting in T04."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

import t04_paired_runner as t04


OPERATOR_DIGEST = hashlib.sha256(b"fixed-operator-manifest-v1").hexdigest()
CHECKPOINT_COMPONENTS = sorted(t04.REQUIRED_CHECKPOINT_COMPONENTS)


def make_checkpoint(base: Path) -> tuple[Path, str]:
    path = base / "checkpoint"
    path.mkdir()
    (path / "queue.json").write_text('{"root":"r1"}\n', encoding="utf-8")
    (path / "rng.bin").write_bytes(b"rng-state")
    return path, t04.checkpoint_tree_sha256(path)


def make_root(root_id: str, state: str, checkpoint: Path | None, digest: str | None) -> dict:
    row = {
        "root_id": root_id,
        "state": state,
        "eligible": state != "ineligible",
        "block_id": "block-01",
        "pair_seed": 20261107,
        "checkpoint_stage": "post_trial_pre_validation",
        "baseline_source_branch_ids": ["src:seed:1", "src:trial:7"],
    }
    if state == "eligible":
        row.update({
            "checkpoint_path": str(checkpoint),
            "checkpoint_sha256": digest,
            "checkpoint_complete": True,
            "checkpoint_components": CHECKPOINT_COMPONENTS,
        })
    elif state == "unserved":
        row["unserved_reason"] = "ttl_before_service"
    else:
        row.update({"eligible": False, "ineligible_reason": "failed_root_eligibility_predicate"})
    return row


def make_campaign(root: dict) -> dict:
    return {
        "schema_version": 1,
        "per_path_budget": 64,
        "charged_execution_kinds": ["mutation", "calibration", "hang-retry"],
        "operator_manifest_sha256": OPERATOR_DIGEST,
        "m2_window": 4,
        "roots": [root],
    }


def make_request(root: dict, path: str = "pv") -> dict:
    return t04.make_request(make_campaign(root), root, path)


def make_receipt(request: dict, *, n_mutations: int = 64, status: str = "completed") -> dict:
    checkpoint = request["checkpoint_sha256"]
    events = [
        {"invocation_id": f"{request['path']}-i{i}", "root_id": request["root_id"], "path": request["path"], "execution_kind": "mutation", "charged": True}
        for i in range(1, n_mutations + 1)
    ]
    branch_events = [
        {"source_branch_id": "src:trial:7", "first_seen_charged_call": 1},
        {"source_branch_id": "src:new:9", "first_seen_charged_call": min(n_mutations, 12)},
    ] if n_mutations else []
    return {
        "schema_version": 1,
        "root_id": request["root_id"],
        "path": request["path"],
        "restored_checkpoint_sha256": checkpoint,
        "restored_components": CHECKPOINT_COMPONENTS,
        "block_id": request["block_id"],
        "pair_seed": request["pair_seed"],
        "operator_manifest_sha256": request["operator_manifest_sha256"],
        "m2_window": request["m2_window"],
        "status": status,
        "censor_reason": "run_ttl" if status == "censored" else None,
        "target_invocations": events,
        "source_branch_events": branch_events,
    }


class T04ContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.checkpoint, self.digest = make_checkpoint(self.base)
        self.root = make_root("root-001", "eligible", self.checkpoint, self.digest)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_campaign_rejects_incomplete_or_mutated_checkpoint(self) -> None:
        campaign = make_campaign(self.root)
        loaded = self.base / "campaign.json"
        loaded.write_text(json.dumps(campaign), encoding="utf-8")
        self.assertEqual(t04.load_campaign(loaded)["roots"][0]["root_id"], "root-001")

        bad = json.loads(json.dumps(campaign))
        bad["roots"][0]["checkpoint_components"].remove("target_state")
        loaded.write_text(json.dumps(bad), encoding="utf-8")
        with self.assertRaises(t04.ContractError):
            t04.load_campaign(loaded)

        (self.checkpoint / "queue.json").write_text("changed\n", encoding="utf-8")
        loaded.write_text(json.dumps(campaign), encoding="utf-8")
        with self.assertRaisesRegex(t04.ContractError, "digest mismatch"):
            t04.load_campaign(loaded)

    def test_worker_rechecks_checkpoint_after_manifest_load(self) -> None:
        campaign = make_campaign(self.root)
        loaded = self.base / "campaign.json"
        loaded.write_text(json.dumps(campaign), encoding="utf-8")
        validated = t04.load_campaign(loaded)
        (self.checkpoint / "queue.json").write_text("changed-after-load\n", encoding="utf-8")
        adapter_path = self._write_fake_adapter()
        row = t04._run_one(
            [sys.executable, str(adapter_path)], self.base / "run-recheck",
            validated, self.root, "pv"
        )
        self.assertEqual(row["validation"], "FAIL")
        self.assertEqual(row["status"], "technical_failure")
        self.assertIn("checkpoint changed", row["reason"])

    def test_three_path_requests_are_same_root_seed_checkpoint_budget_and_operator(self) -> None:
        campaign = make_campaign(self.root)
        requests = [t04.make_request(campaign, self.root, p) for p in t04.PATHS]
        self.assertEqual([r["path"] for r in requests], list(t04.PATHS))
        for key in ("root_id", "checkpoint_sha256", "pair_seed", "block_id", "operator_manifest_sha256", "m2_window", "max_charged_invocations"):
            self.assertEqual({r[key] for r in requests}, {requests[0][key]})
        self.assertEqual(requests[0]["max_charged_invocations"], 64)

    def test_receipt_counts_exact_budget_and_excludes_checkpoint_baseline(self) -> None:
        request = make_request(self.root)
        outcome = t04.validate_receipt(request, make_receipt(request))
        self.assertEqual(outcome["charged_invocations"], 64)
        self.assertEqual(outcome["beyond_trial_source_branches"], 1)
        self.assertEqual(outcome["first_beyond_trial_gain_call"], 12)
        self.assertEqual(outcome["status"], "completed")

    def test_receipt_rejects_pair_identity_and_charge_mismatches(self) -> None:
        request = make_request(self.root)
        bad_pair = make_receipt(request)
        bad_pair["pair_seed"] += 1
        with self.assertRaisesRegex(t04.ContractError, "pair_seed mismatch"):
            t04.validate_receipt(request, bad_pair)

        bad_charge = make_receipt(request)
        bad_charge["target_invocations"][0]["charged"] = False
        with self.assertRaisesRegex(t04.ContractError, "charged flag"):
            t04.validate_receipt(request, bad_charge)

        bad_path = make_receipt(request)
        bad_path["target_invocations"][0]["path"] = "pv" if request["path"] != "pv" else "ordinary_corpus"
        with self.assertRaisesRegex(t04.ContractError, "path mismatch"):
            t04.validate_receipt(request, bad_path)

    def test_budget_overrun_fails_and_censor_is_retained_not_completed(self) -> None:
        request = make_request(self.root)
        over = make_receipt(request, n_mutations=65)
        with self.assertRaisesRegex(t04.ContractError, "exceed budget"):
            t04.validate_receipt(request, over)

        partial = make_receipt(request, n_mutations=17, status="censored")
        outcome = t04.validate_receipt(request, partial)
        self.assertEqual(outcome["status"], "censored")
        self.assertEqual(outcome["charged_invocations"], 17)

    def test_runner_keeps_unserved_and_ineligible_roots_in_all_three_rows(self) -> None:
        campaign = make_campaign(self.root)
        campaign["roots"] += [
            make_root("root-unserved", "unserved", None, None),
            make_root("root-ineligible", "ineligible", None, None),
        ]
        campaign_path = self.base / "campaign.json"
        campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
        loaded = t04.load_campaign(campaign_path)
        adapter_path = self._write_fake_adapter()
        result = t04.run_campaign(loaded, self.base / "run", [sys.executable, str(adapter_path)], workers=3)
        self.assertEqual(result["n_roots"], 3)
        self.assertEqual(result["n_eligible"], 1)
        self.assertEqual(result["n_unserved"], 1)
        self.assertEqual(result["n_ineligible"], 1)
        self.assertEqual(len(result["rows"]), 9)
        self.assertEqual(sum(r["status"] == "censored" for r in result["rows"]), 3)
        self.assertEqual(sum(r["status"] == "not_eligible" for r in result["rows"]), 3)
        self.assertTrue(result["all_eligible_roots_complete"])
        self.assertEqual(sum(r["validation"] == "PASS" for r in result["rows"]), 3)

    def test_runner_marks_any_censored_path_as_incomplete_pair(self) -> None:
        campaign = make_campaign(self.root)
        campaign_path = self.base / "campaign-censor.json"
        campaign_path.write_text(json.dumps(campaign), encoding="utf-8")
        loaded = t04.load_campaign(campaign_path)
        adapter_path = self._write_fake_adapter(censor_path="same_root_ordinary")
        result = t04.run_campaign(loaded, self.base / "run-censor", [sys.executable, str(adapter_path)], workers=1)
        self.assertTrue(result["all_executed_rows_pass"])
        self.assertFalse(result["all_eligible_roots_complete"])
        self.assertTrue(result["pair_checks"][0]["paired_receipts_valid"])
        self.assertFalse(result["pair_checks"][0]["paired_complete"])

    def _write_fake_adapter(self, censor_path: str | None = None) -> Path:
        adapter_path = self.base / "fake_adapter.py"
        source = '''#!/usr/bin/env python3
import argparse, json
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument("--request", required=True)
p.add_argument("--result", required=True)
a = p.parse_args()
r = json.loads(Path(a.request).read_text())
n = 19 if r["path"] == CENSOR_PATH else 64
status = "censored" if n < 64 else "completed"
receipt = {
  "schema_version": 1,
  "root_id": r["root_id"],
  "path": r["path"],
  "restored_checkpoint_sha256": r["checkpoint_sha256"],
  "restored_components": r["checkpoint_components"],
  "block_id": r["block_id"],
  "pair_seed": r["pair_seed"],
  "operator_manifest_sha256": r["operator_manifest_sha256"],
  "m2_window": r["m2_window"],
  "status": status,
  "censor_reason": "test-censor" if status == "censored" else None,
  "target_invocations": [
    {"invocation_id": f"{r['path']}-{i}", "root_id": r["root_id"], "path": r["path"], "execution_kind": "mutation", "charged": True}
    for i in range(1, n + 1)
  ],
  "source_branch_events": [
    {"source_branch_id": "src:trial:7", "first_seen_charged_call": 1},
    {"source_branch_id": "src:new:9", "first_seen_charged_call": 12}
  ] if n >= 12 else []
}
Path(a.result).write_text(json.dumps(receipt))
'''.replace("CENSOR_PATH", repr(censor_path))
        adapter_path.write_text(source, encoding="utf-8")
        adapter_path.chmod(0o755)
        return adapter_path

    def test_censored_paired_root_is_not_reported_as_complete(self) -> None:
        campaign = make_campaign(self.root)
        # Check that receipt-level valid censoring remains a valid outcome but
        # does not satisfy the 64-call completion contract.
        for path_name in t04.PATHS:
            request = t04.make_request(campaign, self.root, path_name)
            outcome = t04.validate_receipt(request, make_receipt(request, n_mutations=31, status="censored"))
            self.assertEqual(outcome["status"], "censored")
            self.assertNotEqual(outcome["charged_invocations"], 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
