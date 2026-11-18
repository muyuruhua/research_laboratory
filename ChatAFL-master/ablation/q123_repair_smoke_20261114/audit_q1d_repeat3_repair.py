#!/usr/bin/env python3
"""Validate one replacement attempt without representing it as a new batch."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import audit_smoke


ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = "out-proftpd-loopfuzz_3.tar.gz"


def link(source, destination):
    if not destination.exists():
        os.link(source, destination)


def audit(output):
    manifest = json.loads((output / "manifest.json").read_text())
    completion = json.loads((output / "completion.json").read_text())
    assert manifest["repeat"] == 3 and manifest["arm"] == "q1d1"
    stamp = output.name.removeprefix("q1d_repeat3_repair_")
    view = output / ("results-proftpd_ablation_q1d1_" + stamp)
    view.mkdir(exist_ok=True)
    link(output / ARCHIVE, view / ARCHIVE)
    mock_name = ARCHIVE.removesuffix(".tar.gz") + ".mock-stats.json"
    link(output / mock_name, view / mock_name)
    with (view / ".result_manifest.tsv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, delimiter="\t", fieldnames=(
            "run", "container_id", "container_name", "image", "fuzzer", "outdir", "archive_name"))
        writer.writeheader()
        writer.writerow(dict(run=3, container_id=manifest["container_id"],
                             container_name=manifest["container_name"], image="proftpd",
                             fuzzer="loopfuzz", outdir="out-proftpd-loopfuzz", archive_name=ARCHIVE))
    statuses = view / ".sample_status"
    statuses.mkdir(exist_ok=True)
    state = completion["state"]
    values = dict(archive_name=ARCHIVE, container_id=manifest["container_id"],
                  status="completed" if state["ExitCode"] == 0 else "failed",
                  reason="completed" if state["ExitCode"] == 0 else "nonzero-exit",
                  exit_code=state["ExitCode"], oom_killed=str(state["OOMKilled"]).lower(),
                  finished_at=state["FinishedAt"])
    (statuses / (ARCHIVE + ".status")).write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    subprocess.run([sys.executable, str(ROOT / "benchmark/scripts/analysis/run_summary.py"),
                    str(view), "--include-invalid", "--timeout-min", "10",
                    "--output", str(view / "run_summary.csv")], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    checks, metrics = audit_smoke.audit_result_dir(
        view, target="proftpd", threshold=1, protocol="FTP",
        max_runtime_ms=manifest["fuzz_timeout_seconds"] * 1000)
    # The directory auditor also requires a complete three-repeat batch.
    # This report deliberately evaluates only its existing per-archive checks;
    # it does not bypass or report success for those inapplicable batch checks.
    checks = [row for row in checks if row[0].startswith(ARCHIVE + ":")]
    checks.append(("deadline respected", not completion["deadline_reached"] and
                   completion["elapsed_seconds"] <= manifest["total_timeout_seconds"],
                   str(completion["elapsed_seconds"])))
    original = ROOT / manifest["original_archive"]
    checks.append(("original failure archive unchanged",
                   hashlib.sha256(original.read_bytes()).hexdigest() == manifest["original_archive_sha256"],
                   str(original)))
    with tarfile.open(view / ARCHIVE) as tf:
        terminal = json.load(tf.extractfile("out-proftpd-loopfuzz/cov_over_time.csv.v5/terminal.json"))
        configs = audit_smoke.read_jsonl(tf.extractfile("out-proftpd-loopfuzz/run-config.jsonl").read())
    cfg = configs[0]
    checks.append(("replacement campaign identity", cfg["campaign_id"] == manifest["campaign_id"],
                   cfg["campaign_id"]))
    checks.append(("original third-repeat RNG preserved",
                   cfg["rng_seed"] % 2**64 == int(manifest["rng_seed"], 0), str(cfg["rng_seed"])))
    baseline = ROOT / "ablation/results-proftpd_ablation_q1d1_20261117T020935"
    with tarfile.open(baseline / "out-proftpd-loopfuzz_1.tar.gz") as tf:
        baseline_cfg = audit_smoke.read_jsonl(tf.extractfile("out-proftpd-loopfuzz/run-config.jsonl").read())[0]
        baseline_terminal = json.load(tf.extractfile("out-proftpd-loopfuzz/cov_over_time.csv.v5/terminal.json"))
        baseline_scope = json.load(tf.extractfile("out-proftpd-loopfuzz/cov_over_time.csv.v5/scope.json"))
    baseline_mock = json.loads((baseline / "out-proftpd-loopfuzz_1.mock-stats.json").read_text())
    baseline_identity = audit_smoke.shared_identity_from_sample(
        baseline_cfg, baseline_terminal, baseline_scope, baseline_mock)
    controls_ok, controls_detail = audit_smoke.shared_identity_difference(
        [baseline_identity, metrics[0]["_shared_identity"]])
    checks.append(("experimental controls match earlier Q1d repeat; runtime change disclosed separately",
                   controls_ok, controls_detail))
    metric = {key: value for key, value in metrics[0].items() if not key.startswith("_")}
    metric["campaign_endpoint_reached"] = metric.pop("fixed_dose_eligible")
    passed = bool(checks) and all(row[1] for row in checks)
    report = dict(schema="q1d-replacement-audit-v1", smoke_integrity_passed=passed,
                  classification=manifest["classification"], repeat=3,
                  checks=[dict(name=name, ok=ok, detail=detail) for name, ok, detail in checks],
                  passed_checks=sum(row[1] for row in checks), total_checks=len(checks),
                  elapsed_seconds=completion["elapsed_seconds"],
                  replayed_inputs=terminal["n_replayed"], planned_inputs=terminal["planned_n_replayed"],
                  coverage_complete=terminal["coverage_complete"],
                  fixed_dose_effect_eligible=False, result_merged_with_original=False,
                  runtime_limit_changed=True, fuzz_timeout_seconds=manifest["fuzz_timeout_seconds"],
                  metric=metric, archive_sha256=hashlib.sha256((view / ARCHIVE).read_bytes()).hexdigest())
    (output / "validation.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    raise SystemExit(audit(parser.parse_args().output.resolve()))
