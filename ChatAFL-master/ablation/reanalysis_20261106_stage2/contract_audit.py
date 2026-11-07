#!/usr/bin/env python3
"""Fail-closed, run-level audit for a completed ablation batch.

The launcher writes a summary for diagnostics, but a summary is not an
acceptance record.  This module joins each archive with its status sidecar,
then runs the immutable ledger and coverage auditors on that exact archive.
The output is intentionally one row per archive; arm names are never used as
keys, so three replicates cannot overwrite one another.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import tarfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from coverage_audit_T02C import audit_archive  # noqa: E402
from ledger_check_T02B_v2 import check_archive  # noqa: E402

try:
    from t05_config_whitelist import audit as audit_t05
except ImportError:  # pragma: no cover - T05 is optional for Q1/Q2-only batches.
    audit_t05 = None


ARM_RE = re.compile(r"^results-(?P<target>.+?)_ablation_(?P<arm>.+)_(?P<stamp>\d{8}T\d{6})$")
REQUIRED_MEMBERS = ("fuzzer_stats", "cov_over_time.csv", "run-config.jsonl")


def read_kv(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.is_file():
        return result
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in raw:
            key, value = raw.split("=", 1)
            result[key] = value
    return result


def archive_members(path: Path) -> set[str]:
    with tarfile.open(path, "r:gz") as tf:
        return set(tf.getnames())


def _member_suffix_present(members: set[str], suffix: str) -> bool:
    return any(name == suffix or name.endswith("/" + suffix) for name in members)


def archive_complete(path: Path) -> tuple[bool, list[str]]:
    try:
        members = archive_members(path)
    except (OSError, tarfile.TarError) as exc:
        return False, [f"archive-open:{exc}"]
    missing = [suffix for suffix in REQUIRED_MEMBERS
               if not _member_suffix_present(members, suffix)]
    # The v4 terminal is the evidence gate.  cov_over_time.csv alone is only a
    # plotting artifact and cannot establish replay completeness.
    if not any(name.endswith("/cov_over_time.csv.v4/terminal.json")
               or name == "cov_over_time.csv.v4/terminal.json" for name in members):
        missing.append("cov_over_time.csv.v4/terminal.json")
    return not missing, missing


def _run_config_rows(path: Path) -> list[dict[str, Any]]:
    with tarfile.open(path, "r:gz") as tf:
        candidates = [name for name in tf.getnames()
                      if name == "run-config.jsonl" or name.endswith("/run-config.jsonl")]
        if len(candidates) != 1:
            raise ValueError(f"expected one run-config.jsonl, found {len(candidates)}")
        stream = tf.extractfile(candidates[0])
        if stream is None:
            raise ValueError("run-config.jsonl is unreadable")
        rows: list[dict[str, Any]] = []
        for line in io.TextIOWrapper(stream):
            if line.strip():
                value = json.loads(line)
                if isinstance(value, dict):
                    rows.append(value)
        return rows


def duration_ms(path: Path) -> int | None:
    """Return the recorded fuzzing interval, excluding coverage collection."""
    try:
        rows = _run_config_rows(path)
    except (OSError, tarfile.TarError, ValueError, json.JSONDecodeError):
        return None
    starts = [r for r in rows if r.get("event") == "run_config" and r.get("phase") == "start"]
    ends = [r for r in rows if r.get("event") == "run_config" and r.get("phase") == "end"]
    if len(starts) != 1 or len(ends) != 1:
        return None
    start, end = starts[0].get("start_time_ms"), ends[0].get("end_time_ms")
    if not isinstance(start, int) or not isinstance(end, int) or end < start:
        return None
    return end - start


def campaign_id(path: Path) -> str | None:
    try:
        rows = _run_config_rows(path)
    except (OSError, tarfile.TarError, ValueError, json.JSONDecodeError):
        return None
    starts = [r for r in rows if r.get("event") == "run_config" and r.get("phase") == "start"]
    value = starts[0].get("campaign_id") if len(starts) == 1 else None
    return value if isinstance(value, str) and value else None


def manifest_rows(results_dir: Path) -> list[dict[str, Any]]:
    manifest = results_dir / ".result_manifest.tsv"
    if not manifest.is_file():
        raise ValueError(f"missing .result_manifest.tsv: {results_dir}")
    rows: list[dict[str, Any]] = []
    with manifest.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            archive_name = row.get("archive_name", "")
            if not archive_name:
                raise ValueError(f"manifest row has no archive_name: {results_dir}")
            archive = results_dir / archive_name
            run_index = row.get("run", "")
            arm_match = ARM_RE.match(results_dir.name)
            arm = arm_match.group("arm") if arm_match else results_dir.name
            rows.append({
                "arm": arm,
                "run_index": int(run_index) if run_index.isdigit() else run_index,
                "archive": archive,
                "container_id": row.get("container_id") or None,
                "status_file": results_dir / ".sample_status" / f"{archive_name}.status",
            })
    return rows


def audit_one(row: dict[str, Any], min_duration_sec: int) -> dict[str, Any]:
    archive = Path(row["archive"])
    status = read_kv(Path(row["status_file"]))
    complete, missing = archive_complete(archive) if archive.is_file() else (False, ["archive-missing"])
    duration = duration_ms(archive) if archive.is_file() else None
    ledger = check_archive(archive) if archive.is_file() else {
        "status": "FAIL", "failures": ["archive-missing"], "inconclusive": []
    }
    coverage = audit_archive(archive) if archive.is_file() else {
        "status": "FAIL", "failures": ["archive-missing"], "inconclusive": []
    }
    failures: list[str] = []
    if status.get("status") != "completed":
        failures.append(f"status:{status.get('status', 'missing')}")
    if status.get("exit_code") != "0":
        failures.append(f"exit-code:{status.get('exit_code', 'missing')}")
    if status.get("oom_killed") != "false":
        failures.append(f"oom-killed:{status.get('oom_killed', 'missing')}")
    if not complete:
        failures.extend("archive:" + item for item in missing)
    if duration is None:
        failures.append("duration:missing-or-invalid")
    elif duration < min_duration_sec * 1000:
        failures.append(f"duration:{duration / 1000:.3f}s<{min_duration_sec}s")
    if ledger.get("status") != "PASS":
        failures.append("ledger:" + str(ledger.get("status")))
    if coverage.get("status") != "PASS":
        failures.append("coverage:" + str(coverage.get("status")))
    return {
        "run_id": f"{row['arm']}#run{row['run_index']}@{archive.name}",
        "arm": row["arm"],
        "run_index": row["run_index"],
        "archive": str(archive.resolve()),
        "container_id": row.get("container_id"),
        "campaign_id": ledger.get("campaign_id") or campaign_id(archive) if archive.is_file() else None,
        "status_file": str(Path(row["status_file"]).resolve()),
        "duration_ms": duration,
        "archive_complete": complete,
        "status_sidecar": status,
        "ledger": ledger,
        "coverage": coverage,
        "status": "PASS" if not failures else "FAIL",
        "failures": sorted(set(failures)),
    }


def run_audit(results_dirs: list[Path], min_duration_sec: int, run_t05: bool) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for results_dir in results_dirs:
        rows.extend(manifest_rows(results_dir))
    audited = [audit_one(row, min_duration_sec) for row in rows]
    index = {
        "schema_version": 1,
        "runs": [
            {"run_id": item["run_id"], "arm": item["arm"],
             "archive": item["archive"], "container_id": item.get("container_id"),
             "campaign_id": item.get("campaign_id")}
            for item in audited
        ],
    }
    t05_result: dict[str, Any] | None = None
    if run_t05:
        if audit_t05 is None:
            t05_result = {"status": "FAIL", "errors": ["t05-import-failed"]}
        else:
            try:
                # T05 consumes the same one-row-per-archive index that is
                # written below; no arm-level aggregation is substituted.
                import tempfile
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
                    json.dump(index, handle)
                    index_path = Path(handle.name)
                try:
                    t05_result = audit_t05(index_path)
                finally:
                    index_path.unlink(missing_ok=True)
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                t05_result = {"status": "FAIL", "errors": [f"t05-error:{exc}"]}
    status = "PASS" if audited and all(item["status"] == "PASS" for item in audited) else "FAIL"
    if run_t05 and (not t05_result or t05_result.get("status") != "PASS"):
        status = "FAIL"
    return {
        "schema_version": 1,
        "status": status,
        "min_duration_sec": min_duration_sec,
        "results_dirs": [str(p.resolve()) for p in results_dirs],
        "runs": audited,
        "t05": t05_result,
        "index": index,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results_dirs", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--min-duration-sec", type=int, default=0)
    parser.add_argument("--t05", action="store_true")
    args = parser.parse_args()
    if args.min_duration_sec < 0:
        parser.error("--min-duration-sec must be nonnegative")
    try:
        result = run_audit(args.results_dirs, args.min_duration_sec, args.t05)
    except (OSError, ValueError, csv.Error) as exc:
        result = {"schema_version": 1, "status": "FAIL", "error": str(exc), "runs": []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"contract-audit {result['status']}: {len(result.get('runs', []))} runs -> {args.output}")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
