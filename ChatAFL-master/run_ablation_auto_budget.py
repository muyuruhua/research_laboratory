#!/usr/bin/env python3
"""Calibrate one target's shared call cap, then launch fresh timed campaigns.

No gateway or Docker commands run with --dry-run. Real calibration costs are
additional to the requested formal duration and remain in separate archives.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parent
TARGETS = ("lightftp", "bftpd", "proftpd", "pure-ftpd", "exim", "live555",
           "kamailio", "forked-daapd", "lighttpd1")
ARMS = ("pvstop512", "salvage512", "nollm512", "wrapgate512", "native512",
        "calibrated512", "cal_ewma512", "cal_run_rate512", "ordmatch512",
        "q1a512", "q1b512", "q1c512", "q1d512")
RATE_ARMS = tuple(arm for arm in ARMS if arm != "q1b512")
PILOT_CAP = 100_000_000  # Temporary guard; never used as the formal budget.
AUDITOR = ROOT / "ablation/q123_repair_smoke_20261114/audit_smoke.py"
CALCULATOR = ROOT / "scripts/calibrate_ablation_budget.py"


def positive_minutes(value):
    number = int(value)
    if not 1 <= number <= 10080:
        raise argparse.ArgumentTypeError("minutes must be in [1, 10080]")
    return number


def selected_arms(value):
    arms = tuple(part.strip() for part in value.split(","))
    if not arms or len(set(arms)) != len(arms) or any(a not in ARMS for a in arms):
        raise argparse.ArgumentTypeError("use distinct supported threshold-512 arms")
    return arms


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def context_hash(target, minutes, environment):
    # Keep credentials and endpoint strings out of reports. Hash effective
    # shared settings and source bytes so later single-arm launches cannot
    # silently reuse a budget calibrated under another configuration.
    settings = {key: value for key, value in environment.items()
                if key.startswith("CHATAFL_") or key in ("SKIPCOUNT", "LLM_MODEL")
                or key.startswith("ABLATION_")}
    for key in ("ABLATION_BATCH_ID", "ABLATION_DRY_RUN", "ABLATION_CALL_BUDGET_OVERRIDE",
                "ABLATION_STOP_MODE", "ABLATION_RUN_CONTRACT_AUDIT", "ABLATION_PILOT_MINUTES"):
        settings.pop(key, None)
    digest = hashlib.sha256(json.dumps([target, minutes, settings], sort_keys=True).encode())
    files = [ROOT / "run_ablation.sh", Path(__file__), CALCULATOR, AUDITOR]
    files += sorted((ROOT / "LoopFuzz").glob("*.c"))
    files += sorted((ROOT / "LoopFuzz").glob("*.h"))
    for path in files:
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def phase_manifest(target, arms, repeats, batch_id, pilot_minutes, minutes):
    runs = []
    for arm in arms:
        stamp = f"ablation_{arm}_{batch_id}"
        directory = ROOT / "ablation" / f"results-{target}_{stamp}"
        for repeat in range(1, repeats + 1):
            runs.append({"arm": arm, "repeat": repeat, "target": target,
                         "expected_timestamp": stamp,
                         "archive": str(directory / f"out-{target}-loopfuzz_{repeat}.tar.gz")})
    return {"schema_version": 1, "batch_id": batch_id, "target": target,
            "pilot_duration_seconds": pilot_minutes * 60,
            "formal_duration_seconds": minutes * 60,
            "temporary_call_cap": PILOT_CAP, "expected_arms": list(arms), "runs": runs}


def launch_phase(manifest, minutes, budget, environment, log_path):
    directories = sorted({str(Path(row["archive"]).parent) for row in manifest["runs"]})
    if any(Path(directory).exists() for directory in directories):
        raise ValueError("phase result directory already exists; refusing to reuse campaign state")
    launch_env = dict(environment, Q1_COMMON_CALL_BUDGET=str(budget),
                      ABLATION_CALL_BUDGET_OVERRIDE=str(budget),
                      ABLATION_STOP_MODE="wallclock", ABLATION_DRY_RUN="0",
                      ABLATION_BATCH_ID=manifest["batch_id"], CHATAFL_MOCK_LLM="0",
                      CHATAFL_NO_LLM="0", ABLATION_RUN_CONTRACT_AUDIT="0")
    command = ["bash", str(ROOT / "run_ablation.sh"), manifest["target"], "3",
               str(minutes), "-g", ",".join(manifest["expected_arms"])]
    # Child receives KEY via the inherited environment; never serialize it.
    with log_path.open("w") as log:
        process = subprocess.Popen(command, cwd=ROOT, env=launch_env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            for line in process.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                log.write(line)
                log.flush()
            return_code = process.wait()
        except BaseException:
            process.terminate()
            raise
    if return_code:
        raise RuntimeError(f"phase launcher failed (exit {return_code}); formal continuation forbidden")


def audit_phase(manifest, minutes, report_path):
    directories = sorted({str(Path(row["archive"]).parent) for row in manifest["runs"]})
    command = [sys.executable, str(AUDITOR), *directories, "--target", manifest["target"],
               "--threshold", "512", "--timeout-min", str(minutes), "--gateway", "live",
               "--profile", "arm-default", "--arms", ",".join(manifest["expected_arms"])]
    with report_path.open("w") as report:
        result = subprocess.run(command, cwd=ROOT, stdout=report, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"phase audit failed; see {report_path}; no successful comparison claimed. "
                           "For insufficient pilot events, increase --pilot-minutes and use a new calibration.")


def read_frozen_budget(path, target, minutes, fingerprint):
    report = json.loads(path.read_text())
    if not isinstance(report, dict):
        raise ValueError("frozen budget must be a JSON object")
    budget = report.get("q1_common_call_budget")
    if (type(budget) is not int or not 1 <= budget <= PILOT_CAP
            or report.get("target") != target
            or report.get("formal_duration_seconds") != minutes * 60
            or report.get("launch_context_sha256") != fingerprint
            or report.get("pilot_live_audit_passed") is not True):
        raise ValueError("frozen budget target, duration, source/settings or live audit does not match")
    return budget


def calibrate_budget(args, environment, fingerprint, identity, output):
    pilot = phase_manifest(args.target, RATE_ARMS, 3, "pilot-" + identity,
                           args.pilot_minutes, args.minutes)
    pilot_path = output / "pilot-manifest.json"
    write_json(pilot_path, pilot)
    print("[AUTO-BUDGET] separate real-gateway calibration; formal clock has not started", flush=True)
    launch_phase(pilot, args.pilot_minutes, PILOT_CAP, environment, output / "pilot-launch.log")
    audit_phase(pilot, args.pilot_minutes, output / "pilot-audit.log")
    if context_hash(args.target, args.minutes, environment) != fingerprint:
        raise RuntimeError("source/settings changed during calibration; refusing formal launch")
    frozen_path = output / "frozen-budget.json"
    subprocess.run([sys.executable, str(CALCULATOR), "--manifest", str(pilot_path),
                    "--output", str(frozen_path)], cwd=ROOT, check=True)
    report = json.loads(frozen_path.read_text())
    if not isinstance(report, dict):
        raise ValueError("budget calculator output must be a JSON object")
    report.update(launch_context_sha256=fingerprint, pilot_live_audit_passed=True)
    write_json(frozen_path, report)
    budget = read_frozen_budget(frozen_path, args.target, args.minutes, fingerprint)
    return budget, frozen_path.resolve()


def cached_budget(args, environment, fingerprint, identity, output):
    """Serialize first calibration, then release the lock before formal work.

    An existing invalid entry is an error: silently recalibrating would assign
    a different cap to later arms of the same comparison.
    """
    directory = ROOT / "ablation" / "budget-cache"
    directory.mkdir(parents=True, exist_ok=True)
    cache_path = directory / f"{args.target}-{args.minutes}-{fingerprint}.json"
    with cache_path.with_suffix(".lock").open("a+") as lock:
        print(f"[AUTO-BUDGET] waiting for shared calibration lock: {cache_path.name}", flush=True)
        fcntl.flock(lock, fcntl.LOCK_EX)
        if cache_path.exists() or cache_path.is_symlink():
            try:
                entry = json.loads(cache_path.read_text())
                if (not isinstance(entry, dict) or entry.get("schema_version") != 1
                        or entry.get("target") != args.target
                        or entry.get("formal_minutes") != args.minutes
                        or entry.get("launch_context_sha256") != fingerprint
                        or not isinstance(entry.get("frozen_budget_file"), str)
                        or not Path(entry["frozen_budget_file"]).is_absolute()):
                    raise ValueError("cache identity or frozen budget path is invalid")
                frozen_path = Path(entry["frozen_budget_file"])
                if hashlib.sha256(frozen_path.read_bytes()).hexdigest() != entry.get("frozen_budget_sha256"):
                    raise ValueError("frozen budget file changed after cache publication")
                budget = read_frozen_budget(frozen_path, args.target, args.minutes, fingerprint)
                if type(entry.get("q1_common_call_budget")) is not int or budget != entry["q1_common_call_budget"]:
                    raise ValueError("frozen budget differs from the published common cap")
            except (OSError, ValueError) as error:
                raise ValueError(f"invalid shared budget cache {cache_path}; refusing automatic "
                                 f"recalibration: {error}") from error
            print(f"[AUTO-BUDGET] reusing shared budget cache: {cache_path}", flush=True)
            return budget, frozen_path
        budget, frozen_path = calibrate_budget(args, environment, fingerprint, identity, output)
        write_json(cache_path, {"schema_version": 1, "target": args.target,
                   "formal_minutes": args.minutes, "launch_context_sha256": fingerprint,
                   "frozen_budget_file": str(frozen_path), "q1_common_call_budget": budget,
                   "frozen_budget_sha256": hashlib.sha256(frozen_path.read_bytes()).hexdigest()})
        return budget, frozen_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=TARGETS)
    parser.add_argument("runs", type=int, help="must be 3 for the current repeat auditor")
    parser.add_argument("minutes", type=positive_minutes, help="formal time per repeat; 1440 = 24 hours")
    parser.add_argument("-g", "--groups", type=selected_arms, default=ARMS)
    parser.add_argument("--pilot-minutes", type=positive_minutes, default=30,
                        help="separate live calibration duration per repeat (default: 30 minutes)")
    budget_source = parser.add_mutually_exclusive_group()
    budget_source.add_argument("--budget-file", type=Path, help="reuse this target/duration's audited frozen budget")
    budget_source.add_argument("--reuse-or-calibrate", action="store_true",
                               help="reuse this configuration's cached budget, or calibrate and freeze it once")
    parser.add_argument("--dry-run", action="store_true", help="print plan only; no gateway, Docker or freeze")
    args = parser.parse_args(argv)
    if args.runs != 3:
        parser.error("current repeat audit requires exactly 3 runs")
    environment = dict(os.environ)
    environment.pop("Q1_COMMON_CALL_BUDGET", None)
    environment.pop("ABLATION_CALL_BUDGET_OVERRIDE", None)
    if environment.get("CHATAFL_MOCK_LLM", "0") != "0":
        parser.error("automatic formal budgeting requires the real gateway; mock is forbidden")
    if environment.get("CHATAFL_NO_LLM", "0") != "0":
        parser.error("unset global CHATAFL_NO_LLM; nollm512 controls its own channel")
    if args.dry_run:
        print(json.dumps({"offline_plan_only": True, "target": args.target,
                          "formal_minutes_per_repeat": args.minutes, "repeats": args.runs,
                          "formal_arms": args.groups, "reuse_budget_file": str(args.budget_file) if args.budget_file else None,
                          "reuse_or_calibrate": args.reuse_or_calibrate,
                          "shared_cache_directory": str(ROOT / "ablation/budget-cache") if args.reuse_or_calibrate else None,
                          "shared_cache_plan": ("reuse matching audited budget; if absent, lock, calibrate, audit and freeze; "
                                                "invalid cache fails without recalibration") if args.reuse_or_calibrate else None,
                          "pilot_minutes_per_repeat": args.pilot_minutes,
                          "pilot_arms": RATE_ARMS, "temporary_pilot_guard": PILOT_CAP,
                          "budget_rule": "ceil(formal_seconds * max_arm(mean_rate + t95_df2 * sample_sd / sqrt(3)))",
                          "creates_formal_budget": False}, indent=2))
        return 0
    if not environment.get("KEY"):
        parser.error("export KEY before starting the real gateway experiment")
    fingerprint = context_hash(args.target, args.minutes, environment)
    identity = uuid.uuid4().hex
    output = ROOT / "ablation" / f"auto-budget-{args.target}-{identity}"
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / "request.json", {"target": args.target, "formal_minutes": args.minutes,
               "formal_arms": args.groups, "repeats": args.runs, "pilot_minutes": args.pilot_minutes,
               "launch_context_sha256": fingerprint, "status": "started"})
    print(f"[AUTO-BUDGET] records: {output}", flush=True)
    try:
        if args.budget_file:
            budget = read_frozen_budget(args.budget_file.resolve(), args.target, args.minutes, fingerprint)
            frozen_path = args.budget_file.resolve()
        elif args.reuse_or_calibrate:
            budget, frozen_path = cached_budget(args, environment, fingerprint, identity, output)
        else:
            budget, frozen_path = calibrate_budget(args, environment, fingerprint, identity, output)
        if context_hash(args.target, args.minutes, environment) != fingerprint:
            raise RuntimeError("source/settings changed before formal launch; refusing stale shared budget")
        print(f"[AUTO-BUDGET] frozen common target-call budget={budget}; file={frozen_path}", flush=True)
        formal = phase_manifest(args.target, args.groups, args.runs, "formal-" + identity,
                                args.pilot_minutes, args.minutes)
        formal.update(q1_common_call_budget=budget, frozen_budget_file=str(frozen_path))
        write_json(output / "formal-manifest.json", formal)
        print(f"[AUTO-BUDGET] starting fresh formal campaigns: {args.minutes} minutes per repeat", flush=True)
        launch_phase(formal, args.minutes, budget, environment, output / "formal-launch.log")
        audit_phase(formal, args.minutes, output / "formal-audit.log")
        if context_hash(args.target, args.minutes, environment) != fingerprint:
            raise RuntimeError("source/settings changed during formal campaigns; result requires review")
        write_json(output / "completion.json", {"status": "completed-and-audited", "budget": budget,
                   "formal_minutes": args.minutes, "mechanism_sufficiency_assessed": False,
                   "contribution_supported": "requires result analysis"})
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        write_json(output / "completion.json", {"status": "failed", "reason": str(error),
                   "container_cleanup": "launcher failure/interruption may leave containers; inspect recorded identities"})
        print(f"[AUTO-BUDGET] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
