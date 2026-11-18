#!/usr/bin/env python3
"""Freeze a common target-call guard from explicit, uncensored live pilots.

This is an offline rate calculation, not approval of mechanism sufficiency.
The manifest supplies exact archive paths; no latest-directory discovery is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import statistics
import sys
import tarfile
import tempfile

AUDIT_DIR = Path(__file__).resolve().parents[1] / "ablation/q123_repair_smoke_20261114"
sys.path.insert(0, str(AUDIT_DIR))
from audit_smoke import (  # noqa: E402
    ALL_ARM_BASES,
    LIVE_GATEWAY_FIELDS,
    PROTOCOL_BY_TARGET,
    audit_campaign_dose,
    audit_invocation_pairs,
    audit_live_gateway,
    audit_wallclock_budget_censor,
    expected_config,
    parse_stats,
)

T95_DF2 = 2.919985580353724
PINNED_FIELDS = (
    "target", "target_sha256", "fuzzer_sha256", "loopfuzz_source_sha256",
    "seeds_sha256", "image_digest", "config_hash", "campaign_id", "rng_seed",
    "afl_rng_seed", "campaign_call_budget", "campaign_stop_mode",
    "campaign_duration_sec", "protocol_name", "threshold_resolved",
    "scheduler_warmup_max_selections", "episode_energy_cap",
    "cal_reward_window_invocations", "no_llm", *LIVE_GATEWAY_FIELDS,
)
COMMON_FIELDS = (
    "target_sha256", "fuzzer_sha256", "loopfuzz_source_sha256", "seeds_sha256",
    "image_digest", "protocol_name", "threshold_resolved",
    "scheduler_warmup_max_selections", "episode_energy_cap",
    "cal_reward_window_invocations", *LIVE_GATEWAY_FIELDS,
)


class CalibrationError(ValueError):
    """An evidence check failed. Messages contain no gateway payloads."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CalibrationError(message)


def positive_integer(value: object) -> bool:
    return type(value) is int and value > 0


def json_rows(raw: bytes) -> list[dict]:
    try:
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    except (ValueError, UnicodeError) as exc:
        raise CalibrationError("invalid JSON evidence") from exc
    require(all(isinstance(row, dict) for row in rows), "JSONL evidence must contain objects")
    return rows


def upper_rate(rates: list[float]) -> dict:
    require(len(rates) == 3 and all(math.isfinite(r) and r > 0 for r in rates),
            "three positive finite pilot rates are required")
    mean = statistics.mean(rates)
    sd = statistics.stdev(rates)
    return {"rates": rates, "mean_rate": mean, "sample_sd": sd,
            "t95_upper_rate": mean + T95_DF2 * sd / math.sqrt(3)}


def _read_run(run: dict, manifest: dict) -> tuple[dict, dict]:
    target, arm, repeat = run["target"], run["arm"], run["repeat"]
    path = Path(run["archive"])
    stamp = run.get("expected_timestamp")
    require(stamp == f"ablation_{arm}_{manifest['batch_id']}", "unexpected pilot batch timestamp")
    require(path.is_absolute() and path.parent.name == f"results-{target}_{stamp}",
            "archive path does not match its exact pilot batch directory")
    require(path.name == f"out-{target}-loopfuzz_{repeat}.tar.gz", "archive repeat/target filename mismatch")
    require(path.is_file() and not path.is_symlink(), "missing or symbolic pilot archive")
    prefix = f"out-{target}-loopfuzz/"
    try:
        with tarfile.open(path, "r:gz") as tf:
            members = tf.getmembers()
            names = [m.name.removeprefix("./") for m in members]
            require(len(names) == len(set(names)), "duplicate archive member identity")
            by_name = dict(zip(names, members))

            def member(suffix: str) -> bytes:
                found = by_name.get(prefix + suffix)
                require(found is not None and found.isfile(), "missing or nonregular required archive member")
                stream = tf.extractfile(found)
                require(stream is not None, "unreadable required archive member")
                return stream.read()

            configs = json_rows(member("run-config.jsonl"))
            require(len(configs) == 2 and [r.get("phase") for r in configs] == ["start", "end"]
                    and all(r.get("event") == "run_config" for r in configs), "pilot lacks exactly one start/end configuration")
            cfg, end = configs
            require(all(field in cfg and field in end and cfg[field] == end[field]
                        for field in PINNED_FIELDS), "pilot start/end pinned identity mismatch")
            require(all(cfg.get(field) not in (None, "", "unknown", "unrecorded")
                        for field in ("campaign_id", "config_hash", "target_sha256", "fuzzer_sha256",
                                      "loopfuzz_source_sha256", "seeds_sha256", "image_digest")),
                    "pilot provenance identity is missing")
            require(type(cfg.get("rng_seed")) is int and type(cfg.get("afl_rng_seed")) is int,
                    "pilot RNG identities are missing or invalid")
            require(cfg.get("target") == target and cfg.get("protocol_name") == PROTOCOL_BY_TARGET[target],
                    "pilot target/protocol identity mismatch")
            require(cfg.get("campaign_stop_mode") == "wallclock"
                    and cfg.get("campaign_duration_sec") == manifest["pilot_duration_seconds"],
                    "pilot is not configured for the requested wallclock interval")
            start_ms, end_ms = cfg.get("start_time_ms"), end.get("end_time_ms")
            require(type(start_ms) is int and type(end_ms) is int, "invalid pilot elapsed timestamps")
            elapsed = (end_ms - start_ms) / 1000
            duration = manifest["pilot_duration_seconds"]
            require(duration <= elapsed <= duration + 360, "pilot did not reach its full configured interval")
            require(end.get("termination_reason") in ("wallclock-duration", "signal-or-timeout"),
                    "pilot has an invalid termination reason")
            require(cfg.get("q1_policy") != "no-reflow", "parked Q1b pilots cannot calibrate active call rate")
            base = arm.rstrip("0123456789")
            semantics = expected_config(arm)
            require(semantics and all(cfg.get(k) == v for k, v in semantics.items()), "pilot arm semantics mismatch")
            threshold = int(arm[len(base):])
            require(cfg.get("threshold_resolved") == threshold, "pilot threshold does not match arm")
            require(cfg.get("campaign_call_budget") == manifest["temporary_call_cap"], "temporary pilot cap mismatch")
            require(cfg.get("mock_gateway") is None and end.get("mock_gateway") is None,
                    "mock evidence cannot calibrate a live campaign")
            require(isinstance(cfg.get("endpoint"), str) and cfg["endpoint"].startswith("https://"),
                    "pilot live endpoint must use HTTPS")
            require(cfg.get("no_llm") is (base == "nollm"), "pilot LLM mode does not match arm")
            require(isinstance(cfg.get("model"), str) and bool(cfg["model"])
                    and positive_integer(cfg.get("max_output_tokens")), "missing effective live model configuration")
            if base == "nollm":
                rows = json_rows(member("llm-calls.jsonl")) if prefix + "llm-calls.jsonl" in names else []
                require(not rows
                        and not any(n.startswith(prefix + "llm-archive/") and n.endswith((".req", ".resp")) for n in names),
                        "no-LLM pilot unexpectedly carries requests")
            else:
                live = audit_live_gateway(member, names, prefix, cfg, end, profile="arm-default")
                require(live.get("eligible") is True, "live request/response evidence failed validation")
            stats = parse_stats(member("fuzzer_stats"))
            if base == "nollm":
                require(stats.get("no_llm_mode") == 1 and all(stats.get(key) == 0 for key in
                        ("llm_total_calls", "llm_prompt_tokens", "llm_completion_tok")),
                        "no-LLM pilot lacks corroborating zero request/token counters")
            charged = stats.get("campaign_charged_calls")
            require(positive_integer(charged), "pilot has no positive charged-call rate")
            require(stats.get("campaign_call_budget") == manifest["temporary_call_cap"]
                    and stats.get("campaign_budget_exhausted") == 0
                    and charged < manifest["temporary_call_cap"], "temporary pilot cap was reached or disagrees with configuration")
            require(end.get("campaign_budget_censored") is False
                    and end.get("campaign_budget_exhausted_time_ms") == 0,
                    "pilot was censored by its temporary cap")
            censor_ok, _ = audit_wallclock_budget_censor(cfg, end, stats)
            require(censor_ok, "pilot cap-censor ledger mismatch")
            executions = json_rows(member("execution-events.jsonl"))
            pairs_ok, _ = audit_invocation_pairs(executions)
            require(pairs_ok and all(r.get("campaign_id") == cfg["campaign_id"] for r in executions),
                    "pilot invocation identities are incomplete or mismatched")
            starts = sum(r.get("event") == "invocation_start" and r.get("executed") is True for r in executions)
            require(starts == charged, "pilot charged calls disagree with invocation ledger")
            flow = json_rows(member("q1-budget-flow.jsonl"))
            require(len([r for r in flow if r.get("kind") == "campaign-final"]) == 1
                    and all(r.get("campaign_id") == cfg["campaign_id"] for r in flow),
                    "pilot lacks a unique matching terminal quota record")
            dose_ok, _ = audit_campaign_dose(cfg, stats, starts, flow, require_cap=False)
            require(dose_ok, "pilot charged calls or terminal quota counters are inconsistent")
    except (tarfile.TarError, OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, CalibrationError):
            raise
        raise CalibrationError("pilot archive is unreadable or malformed") from exc
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return ({"arm": arm, "repeat": repeat, "target": target,
             "archive": str(path), "archive_sha256": digest,
             "campaign_id": cfg["campaign_id"], "charged_calls": charged,
             "elapsed_seconds": elapsed, "rate": charged / elapsed,
             "rng_seed": cfg["rng_seed"], "afl_rng_seed": cfg["afl_rng_seed"]}, cfg)


def calibrate(manifest: dict) -> dict:
    require(isinstance(manifest, dict) and manifest.get("schema_version") == 1, "unsupported pilot manifest schema")
    target, batch = manifest.get("target"), manifest.get("batch_id")
    require(target in PROTOCOL_BY_TARGET, "unsupported pilot target")
    require(isinstance(batch, str) and re.fullmatch(r"[A-Za-z0-9_-]+", batch) is not None, "invalid pilot batch ID")
    for field in ("pilot_duration_seconds", "formal_duration_seconds", "temporary_call_cap"):
        require(positive_integer(manifest.get(field)), "positive integer pilot/formal durations and temporary cap are required")
    arms = manifest.get("expected_arms")
    require(isinstance(arms, list) and arms and all(isinstance(a, str) for a in arms)
            and len(set(arms)) == len(arms), "expected nonpark arms are missing or duplicated")
    require(all(re.fullmatch(r"[a-z0-9_]+[1-9][0-9]*", a) and a.rstrip("0123456789") in ALL_ARM_BASES - {"q1b"}
                for a in arms), "unsupported or parked pilot arm")
    runs = manifest.get("runs")
    require(isinstance(runs, list) and len(runs) == len(arms) * 3, "every expected arm requires exactly three repeats")
    expected = {(arm, repeat) for arm in arms for repeat in (1, 2, 3)}
    observed, paths = set(), set()
    for run in runs:
        require(isinstance(run, dict) and run.get("target") == target
                and type(run.get("repeat")) is int and isinstance(run.get("arm"), str)
                and isinstance(run.get("archive"), str), "invalid pilot run identity")
        coordinate = (run["arm"], run["repeat"])
        path = str(Path(run["archive"]).resolve())
        require(coordinate in expected and coordinate not in observed and path not in paths,
                "duplicate or unexpected pilot run/archive coordinate")
        observed.add(coordinate)
        paths.add(path)
    require(observed == expected, "pilot repeat matrix is incomplete")
    results, configs = [], []
    for run in sorted(runs, key=lambda r: (r["arm"], r["repeat"])):
        result, cfg = _read_run(run, manifest)
        results.append(result)
        configs.append(cfg)
    require(len({r["campaign_id"] for r in results}) == len(results)
            and len({r["archive_sha256"] for r in results}) == len(results), "pilot archive/campaign identities are reused")
    require(all(all(c.get(k) == configs[0].get(k) for k in COMMON_FIELDS) for c in configs),
            "pilot build, corpus, gateway or shared controls differ across repeats/arms")
    by_arm = {}
    for arm in arms:
        selected = [r for r in results if r["arm"] == arm]
        require(len({r["rng_seed"] for r in selected}) == 3
                and len({r["afl_rng_seed"] for r in selected}) == 3, "pilot repeats reuse RNG seed identities")
        by_arm[arm] = upper_rate([r["rate"] for r in selected])
    budget = math.ceil(manifest["formal_duration_seconds"] * max(a["t95_upper_rate"] for a in by_arm.values()))
    require(0 < budget <= 100_000_000, "calibrated budget exceeds launcher's supported 100000000-call limit")
    return {"schema_version": 1, "batch_id": batch, "target": target,
            "q1_common_call_budget": budget,
            "pilot_duration_seconds": manifest["pilot_duration_seconds"],
            "formal_duration_seconds": manifest["formal_duration_seconds"],
            "temporary_call_cap": manifest["temporary_call_cap"],
            "formula": "ceil(formal_duration_seconds * max_arm(mean(rate) + t_0.95_df2 * sample_sd(rate) / sqrt(3)))",
            "t_one_sided_95_df2": T95_DF2, "arms": by_arm, "runs": results,
            "calibration_scope": "budget-rate calibration only; not mechanism sufficiency or contribution approval",
            "mechanism_sufficiency_assessed": False,
            "formal_cap_policy": "unexpected formal cap hit remains censored; this rate estimate cannot guarantee an unbound formal cap"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = json.loads(args.manifest.read_text())
        result = calibrate(manifest)
        payload = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(prefix=".calibrated-budget-", dir=args.output.parent)
            try:
                with os.fdopen(fd, "w") as stream:
                    stream.write(payload)
                os.replace(name, args.output)
            finally:
                if os.path.exists(name):
                    os.unlink(name)
        print(payload, end="")
        return 0
    except (CalibrationError, OSError, ValueError, TypeError, KeyError) as exc:
        # Never print JSON payloads, keys, gateway URLs or provider responses.
        message = str(exc) if isinstance(exc, CalibrationError) else "manifest/output is unreadable or malformed"
        print("calibration failed: " + message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
