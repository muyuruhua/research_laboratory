#!/usr/bin/env python3
"""Manifest-driven T04 paired-run harness.

This module enforces the *data and accounting contract* for the three Q2
branches (provisional validation, same-root ordinary, ordinary-corpus
opportunity cost).  The adapter is responsible for restoring the fuzzer and
target from the supplied checkpoint, executing calls, and returning the
receipt schema documented in ``T04_PAIRED_RUNNER.md``.  The harness refuses
to call a checkpoint complete based on a filename or a self-reported digest:
it hashes the checkpoint tree and requires the adapter to acknowledge the
same digest and all required restored components.

It deliberately does not claim that a checkpoint can be restored by the
current LoopFuzz executable.  A native restore adapter is a prerequisite for
using this runner for an experiment; the included fake adapter is test-only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


PATHS = ("pv", "same_root_ordinary", "ordinary_corpus")
REQUIRED_CHECKPOINT_COMPONENTS = frozenset(
    {"queue", "fuzzer_rng", "counters", "target_state", "coverage_baseline"}
)
VALID_ROOT_STATES = {"eligible", "unserved", "ineligible"}


class ContractError(ValueError):
    """Input or adapter output violates the predeclared paired-run contract."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def checkpoint_tree_sha256(path: Path) -> str:
    """Hash a file or a directory tree, including relative file names."""
    if path.is_symlink():
        raise ContractError(f"checkpoint path is a symlink: {path}")
    if path.is_file():
        return sha256_file(path)
    if not path.is_dir():
        raise ContractError(f"checkpoint path does not exist or is not regular: {path}")
    h = hashlib.sha256()
    files = sorted(p for p in path.rglob("*") if p.is_file())
    if not files:
        raise ContractError(f"checkpoint directory is empty: {path}")
    for file_path in files:
        if file_path.is_symlink():
            raise ContractError(f"checkpoint contains symlink: {file_path}")
        rel = file_path.relative_to(path).as_posix().encode("utf-8")
        h.update(len(rel).to_bytes(8, "big"))
        h.update(rel)
        size = file_path.stat().st_size
        h.update(size.to_bytes(8, "big"))
        with file_path.open("rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
    return h.hexdigest()


def _required(obj: dict[str, Any], key: str, typ: type, where: str) -> Any:
    value = obj.get(key)
    if not isinstance(value, typ):
        raise ContractError(f"{where}.{key} must be {typ.__name__}")
    return value


def load_campaign(path: Path) -> dict[str, Any]:
    try:
        campaign = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read campaign manifest {path}: {exc}") from exc
    if not isinstance(campaign, dict) or campaign.get("schema_version") != 1:
        raise ContractError("campaign manifest schema_version must be 1")
    budget = _required(campaign, "per_path_budget", int, "campaign")
    if budget != 64:
        raise ContractError("T04 contract requires per_path_budget=64")
    charged_kinds = campaign.get("charged_execution_kinds")
    if (not isinstance(charged_kinds, list) or not charged_kinds or
            any(not isinstance(k, str) or not k for k in charged_kinds) or
            len(set(charged_kinds)) != len(charged_kinds)):
        raise ContractError("campaign.charged_execution_kinds must be a nonempty unique string list")
    _required(campaign, "operator_manifest_sha256", str, "campaign")
    if not re.fullmatch(r"[0-9a-f]{64}", campaign["operator_manifest_sha256"]):
        raise ContractError("campaign.operator_manifest_sha256 must be a lowercase SHA-256")
    _required(campaign, "m2_window", int, "campaign")
    if campaign["m2_window"] <= 0:
        raise ContractError("campaign.m2_window must be positive")
    roots = campaign.get("roots")
    if not isinstance(roots, list) or not roots:
        raise ContractError("campaign.roots must be a nonempty list")
    seen: set[str] = set()
    for ix, root in enumerate(roots):
        where = f"campaign.roots[{ix}]"
        if not isinstance(root, dict):
            raise ContractError(f"{where} must be an object")
        root_id = _required(root, "root_id", str, where)
        if not root_id or root_id in seen:
            raise ContractError(f"{where}.root_id must be unique and nonempty")
        seen.add(root_id)
        state = _required(root, "state", str, where)
        if state not in VALID_ROOT_STATES:
            raise ContractError(f"{where}.state must be one of {sorted(VALID_ROOT_STATES)}")
        if root.get("checkpoint_stage") != "post_trial_pre_validation":
            raise ContractError(f"{where}.checkpoint_stage must be post_trial_pre_validation")
        _required(root, "block_id", str, where)
        _required(root, "pair_seed", int, where)
        if root["pair_seed"] < 0:
            raise ContractError(f"{where}.pair_seed must be nonnegative")
        baseline = root.get("baseline_source_branch_ids")
        if not isinstance(baseline, list) or any(not isinstance(x, str) or not x for x in baseline):
            raise ContractError(f"{where}.baseline_source_branch_ids must be a string list")
        if len(set(baseline)) != len(baseline):
            raise ContractError(f"{where}.baseline_source_branch_ids contains duplicates")
        if state == "eligible":
            if root.get("eligible") is not True:
                raise ContractError(f"{where}: eligible state requires eligible=true")
            _required(root, "checkpoint_path", str, where)
            _required(root, "checkpoint_sha256", str, where)
            if not re.fullmatch(r"[0-9a-f]{64}", root["checkpoint_sha256"]):
                raise ContractError(f"{where}.checkpoint_sha256 must be a lowercase SHA-256")
            if root.get("checkpoint_complete") is not True:
                raise ContractError(f"{where}.checkpoint_complete must be true")
            components = root.get("checkpoint_components")
            if not isinstance(components, list) or not REQUIRED_CHECKPOINT_COMPONENTS.issubset(set(components)):
                raise ContractError(f"{where}.checkpoint_components lacks required components")
            actual = checkpoint_tree_sha256(Path(root["checkpoint_path"]))
            if actual != root["checkpoint_sha256"]:
                raise ContractError(f"{where}: checkpoint digest mismatch ({actual})")
        elif state == "unserved":
            if root.get("eligible") is not True:
                raise ContractError(f"{where}: unserved state means eligible root awaiting service; eligible must be true")
            if not isinstance(root.get("unserved_reason"), str) or not root["unserved_reason"]:
                raise ContractError(f"{where}.unserved_reason is required")
        else:
            if root.get("eligible") is not False:
                raise ContractError(f"{where}: ineligible state requires eligible=false")
            if not isinstance(root.get("ineligible_reason"), str) or not root["ineligible_reason"]:
                raise ContractError(f"{where}.ineligible_reason is required")
    return campaign


def make_request(campaign: dict[str, Any], root: dict[str, Any], path_name: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "root_id": root["root_id"],
        "path": path_name,
        "checkpoint_path": root.get("checkpoint_path"),
        "checkpoint_sha256": root.get("checkpoint_sha256"),
        "checkpoint_stage": root["checkpoint_stage"],
        "checkpoint_components": sorted(REQUIRED_CHECKPOINT_COMPONENTS),
        "pair_seed": root["pair_seed"],
        "block_id": root["block_id"],
        "operator_manifest_sha256": campaign["operator_manifest_sha256"],
        "m2_window": campaign["m2_window"],
        "max_charged_invocations": campaign["per_path_budget"],
        "charged_execution_kinds": campaign["charged_execution_kinds"],
        "baseline_source_branch_ids": root["baseline_source_branch_ids"],
        "all_paths": list(PATHS),
    }


def validate_receipt(request: dict[str, Any], receipt: Any) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(receipt, dict):
        raise ContractError("adapter receipt must be a JSON object")
    for key in ("root_id", "path", "checkpoint_sha256", "block_id", "pair_seed",
                "operator_manifest_sha256", "m2_window"):
        expected = request.get(key)
        actual = receipt.get("restored_checkpoint_sha256") if key == "checkpoint_sha256" else receipt.get(key)
        if actual != expected:
            errors.append(f"{key} mismatch: expected {expected!r}, got {actual!r}")
    if receipt.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    restored = receipt.get("restored_components")
    if not isinstance(restored, list) or not REQUIRED_CHECKPOINT_COMPONENTS.issubset(set(restored)):
        errors.append("restored_components does not acknowledge all required components")
    events = receipt.get("target_invocations")
    if not isinstance(events, list):
        errors.append("target_invocations must be a list")
        events = []
    ids: set[str] = set()
    charged_count = 0
    charged_kinds = set(request["charged_execution_kinds"])
    for ix, event in enumerate(events):
        if not isinstance(event, dict):
            errors.append(f"target_invocations[{ix}] must be an object")
            continue
        inv_id = event.get("invocation_id")
        if not isinstance(inv_id, str) or not inv_id or inv_id in ids:
            errors.append(f"target_invocations[{ix}].invocation_id must be unique and nonempty")
        else:
            ids.add(inv_id)
        if event.get("root_id") != request["root_id"]:
            errors.append(f"target_invocations[{ix}] root_id mismatch")
        if event.get("path") != request["path"]:
            errors.append(f"target_invocations[{ix}] path mismatch")
        kind = event.get("execution_kind")
        if not isinstance(kind, str) or not kind:
            errors.append(f"target_invocations[{ix}].execution_kind is required")
            continue
        charged = kind in charged_kinds
        # ``1 == True`` in Python; require an actual JSON boolean so that a
        # numeric counter cannot be smuggled into the charge accounting bit.
        if type(event.get("charged")) is not bool or event.get("charged") is not charged:
            errors.append(f"target_invocations[{ix}] charged flag disagrees with frozen kind contract")
        charged_count += int(charged)
    budget = request["max_charged_invocations"]
    if charged_count > budget:
        errors.append(f"charged invocations {charged_count} exceed budget {budget}")

    status = receipt.get("status")
    if status not in {"completed", "censored", "technical_failure"}:
        errors.append("status must be completed, censored, or technical_failure")
    reason = receipt.get("censor_reason")
    if status == "completed" and charged_count != budget:
        errors.append(f"completed receipt must consume exactly {budget} charged calls; got {charged_count}")
    if status == "censored" and (charged_count >= budget or not isinstance(reason, str) or not reason):
        errors.append("censored receipt requires fewer than budget calls and a nonempty censor_reason")
    if status == "technical_failure" and (not isinstance(reason, str) or not reason):
        errors.append("technical_failure receipt requires a nonempty censor_reason")

    branch_events = receipt.get("source_branch_events")
    if not isinstance(branch_events, list):
        errors.append("source_branch_events must be a list")
        branch_events = []
    branch_ids: set[str] = set()
    baseline = set(request["baseline_source_branch_ids"])
    new_branches: list[dict[str, Any]] = []
    for ix, event in enumerate(branch_events):
        if not isinstance(event, dict):
            errors.append(f"source_branch_events[{ix}] must be an object")
            continue
        branch_id = event.get("source_branch_id")
        call_index = event.get("first_seen_charged_call")
        if not isinstance(branch_id, str) or not branch_id:
            errors.append(f"source_branch_events[{ix}].source_branch_id is required")
            continue
        if branch_id in branch_ids:
            errors.append(f"duplicate source_branch_id in events: {branch_id}")
            continue
        branch_ids.add(branch_id)
        if not isinstance(call_index, int) or call_index < 1 or call_index > charged_count:
            errors.append(f"source_branch_events[{ix}].first_seen_charged_call outside observed charged calls")
            continue
        if branch_id not in baseline:
            new_branches.append({"source_branch_id": branch_id, "first_seen_charged_call": call_index})
    if errors:
        raise ContractError("; ".join(errors))
    return {
        "status": status,
        "censor_reason": reason,
        "charged_invocations": charged_count,
        "budget": budget,
        "beyond_trial_source_branches": len(new_branches),
        "new_source_branch_events": new_branches,
        "first_beyond_trial_gain_call": min((e["first_seen_charged_call"] for e in new_branches), default=None),
        "receipt": receipt,
    }


def _slug(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return (safe[:48] or "root") + "-" + hashlib.sha256(value.encode()).hexdigest()[:10]


def _run_one(adapter: list[str], output_dir: Path, campaign: dict[str, Any], root: dict[str, Any], path_name: str) -> dict[str, Any]:
    request = make_request(campaign, root, path_name)
    request_path = output_dir / "requests" / f"{_slug(root['root_id'])}--{path_name}.json"
    receipt_path = output_dir / "receipts" / f"{_slug(root['root_id'])}--{path_name}.json"
    request_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    # The manifest is loaded before the worker pool starts. Rehash immediately
    # before launch so a checkpoint modified after manifest validation cannot be
    # silently used for one branch while its siblings use the old bytes.
    try:
        current_digest = checkpoint_tree_sha256(Path(root["checkpoint_path"]))
    except (OSError, ContractError) as exc:
        return {
            "root_id": root["root_id"], "path": path_name,
            "pair_seed": root["pair_seed"], "block_id": root["block_id"],
            "adapter_exit_code": None, "validation": "FAIL",
            "status": "technical_failure",
            "reason": f"checkpoint rehash before launch failed: {exc}",
        }
    if current_digest != root["checkpoint_sha256"]:
        return {
            "root_id": root["root_id"], "path": path_name,
            "pair_seed": root["pair_seed"], "block_id": root["block_id"],
            "adapter_exit_code": None, "validation": "FAIL",
            "status": "technical_failure",
            "reason": "checkpoint changed after manifest validation",
            "expected_checkpoint_sha256": root["checkpoint_sha256"],
            "actual_checkpoint_sha256": current_digest,
        }
    request_path.write_bytes(canonical_json_bytes(request) + b"\n")
    cmd = adapter + ["--request", str(request_path), "--result", str(receipt_path)]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    row: dict[str, Any] = {"root_id": root["root_id"], "path": path_name, "pair_seed": root["pair_seed"], "block_id": root["block_id"], "adapter_exit_code": proc.returncode}
    if proc.returncode != 0:
        row.update({"validation": "FAIL", "status": "technical_failure", "reason": f"adapter_exit={proc.returncode}", "stderr_tail": proc.stderr[-2000:]})
        return row
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        validated = validate_receipt(request, receipt)
        row.update({"validation": "PASS", **{k: v for k, v in validated.items() if k != "receipt"}, "receipt_path": str(receipt_path)})
    except (OSError, json.JSONDecodeError, ContractError) as exc:
        row.update({"validation": "FAIL", "status": "invalid_receipt", "reason": str(exc), "receipt_path": str(receipt_path)})
    return row


def run_campaign(campaign: dict[str, Any], output_dir: Path, adapter: list[str], workers: int = 1) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    jobs = []
    for root in campaign["roots"]:
        if root["state"] != "eligible":
            retained_status = "censored" if root["state"] == "unserved" else "not_eligible"
            reason = root.get("unserved_reason") or root.get("ineligible_reason")
            for path_name in PATHS:
                rows.append({"root_id": root["root_id"], "path": path_name, "pair_seed": root["pair_seed"], "block_id": root["block_id"], "validation": "NOT_RUN", "status": retained_status, "reason": reason, "charged_invocations": None, "budget": campaign["per_path_budget"], "beyond_trial_source_branches": None})
        else:
            for path_name in PATHS:
                jobs.append((root, path_name))
    if jobs:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            future_map = {pool.submit(_run_one, adapter, output_dir, campaign, root, path_name): (root, path_name) for root, path_name in jobs}
            for future in as_completed(future_map):
                rows.append(future.result())
    rows.sort(key=lambda r: (r["root_id"], PATHS.index(r["path"])))
    by_root: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_root.setdefault(row["root_id"], []).append(row)
    pair_checks = []
    for root_id, root_rows in sorted(by_root.items()):
        present = [r["path"] for r in root_rows]
        pair_ok = present == list(PATHS)
        valid_receipts = pair_ok and all(r["validation"] == "PASS" for r in root_rows)
        if valid_receipts:
            # The root/seed/block/checkpoint identity must be common across all
            # branches; each receipt has already been checked against the same
            # request, and these fields remain explicit in the output.
            valid_receipts = len({r["pair_seed"] for r in root_rows}) == 1 and len({r["block_id"] for r in root_rows}) == 1
        completed = valid_receipts and all(r["status"] == "completed" and r["charged_invocations"] == campaign["per_path_budget"] for r in root_rows)
        pair_checks.append({"root_id": root_id, "paths": present, "paired_receipts_valid": valid_receipts, "paired_complete": completed})
    result = {
        "schema_version": 1,
        "per_path_budget": campaign["per_path_budget"],
        "paths": list(PATHS),
        "operator_manifest_sha256": campaign["operator_manifest_sha256"],
        "m2_window": campaign["m2_window"],
        "n_roots": len(campaign["roots"]),
        "n_eligible": sum(r["state"] == "eligible" for r in campaign["roots"]),
        "n_unserved": sum(r["state"] == "unserved" for r in campaign["roots"]),
        "n_ineligible": sum(r["state"] == "ineligible" for r in campaign["roots"]),
        "rows": rows,
        "pair_checks": pair_checks,
        "all_executed_rows_pass": all(r["validation"] == "PASS" for r in rows if r["validation"] != "NOT_RUN"),
        "all_eligible_roots_complete": all(x["paired_complete"] for x in pair_checks if any(r["root_id"] == x["root_id"] and r["validation"] != "NOT_RUN" for r in rows)),
    }
    result_path = output_dir / "t04_results.json"
    result_path.write_bytes(canonical_json_bytes(result) + b"\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True, help="T04 campaign JSON manifest")
    parser.add_argument("--output", type=Path, required=True, help="new or existing output directory")
    parser.add_argument("--adapter", required=True, help="adapter executable/command; receives --request FILE --result FILE")
    parser.add_argument("--workers", type=int, default=1, help="maximum concurrent path jobs (default: 1)")
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be >= 1")
    try:
        campaign = load_campaign(args.campaign)
        adapter = shlex.split(args.adapter)
        if not adapter:
            raise ContractError("--adapter command is empty")
        result = run_campaign(campaign, args.output, adapter, args.workers)
    except ContractError as exc:
        print(f"T04 contract error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({k: result[k] for k in ("n_roots", "n_eligible", "n_unserved", "n_ineligible", "all_executed_rows_pass", "all_eligible_roots_complete")}, sort_keys=True))
    return 0 if result["all_executed_rows_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
