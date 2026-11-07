#!/usr/bin/env python3
"""Audit Q3 arm configs in archived run-config.jsonl files.

The comparison intentionally treats campaign identity, seeds, timestamps, PID,
and derived config hash as per-run provenance. Every other field is compared
exactly; scorer-specific fields are the only allowed Q3 differences.
"""
import argparse
import io
import json
import tarfile
from pathlib import Path

ARMS = ("wrapgate8", "cal_run_rate8", "calibrated8", "cal_ewma8", "cal_shrink")
RUN_FIELDS = {"campaign_id", "rng_seed", "afl_rng_seed", "pid", "start_time_ms",
              "end_time_ms", "monotonic_ms", "config_hash"}
SCORER_FIELDS = {"arm", "cal_estimator", "calibration", "state_select_override",
                 "cal_shrink_kappa", "cal_ewma_alpha"}
EXPECTED = {
    "wrapgate8": ("thompson", "none", False),
    "cal_run_rate8": ("run_rate", "run_rate", True),
    "calibrated8": ("thompson", "calibrated", True),
    "cal_ewma8": ("ewma", "ewma", True),
    "cal_shrink": ("shrink", "shrink", True),
}
EXPECTED_SCORER_PARAMS = {
    "wrapgate8": {"cal_ewma_alpha": 0.05, "cal_shrink_kappa": 8.0},
    "cal_run_rate8": {"cal_ewma_alpha": 0.05, "cal_shrink_kappa": 8.0},
    "calibrated8": {"cal_ewma_alpha": 0.05, "cal_shrink_kappa": 8.0},
    "cal_ewma8": {"cal_ewma_alpha": 0.05, "cal_shrink_kappa": 8.0},
    "cal_shrink": {"cal_ewma_alpha": 0.05, "cal_shrink_kappa": 8.0},
}
EXPECTED_RUNS_PER_ARM = 3


def read_config(archive):
    with tarfile.open(archive, "r:gz") as tf:
        matches = [m for m in tf.getmembers()
                   if m.name.endswith("/run-config.jsonl") or m.name == "run-config.jsonl"]
        if len(matches) != 1:
            raise ValueError(f"{archive}: expected one run-config.jsonl, found {len(matches)}")
        stream = tf.extractfile(matches[0])
        if stream is None:
            raise ValueError(f"{archive}: unreadable run-config.jsonl")
        records = [json.loads(line) for line in io.TextIOWrapper(stream) if line.strip()]
    starts = [r for r in records if r.get("event") == "run_config" and r.get("phase") == "start"]
    if len(starts) != 1:
        raise ValueError(f"{archive}: expected one start config, found {len(starts)}")
    return starts[0]


def audit(index_path):
    index = json.loads(Path(index_path).read_text())
    grouped = {arm: [] for arm in ARMS}
    for item in index.get("runs", []):
        if item.get("arm") not in grouped:
            continue
        path = Path(item["archive"])
        if not path.is_file():
            raise ValueError(f"missing archive: {path}")
        cfg = read_config(path)
        grouped[item["arm"]].append((item, cfg))
    counts = {a: len(v) for a, v in grouped.items()}
    if any(v == 0 for v in counts.values()):
        raise ValueError(f"required Q3 arm absent: {counts}")

    errors = []
    all_archives = [str(item["archive"]) for rows in grouped.values() for item, _ in rows]
    if len(all_archives) != len(set(all_archives)):
        errors.append("duplicate archive path across Q3 runs")
    for arm, rows in grouped.items():
        if len(rows) != EXPECTED_RUNS_PER_ARM:
            errors.append(f"{arm}: expected exactly {EXPECTED_RUNS_PER_ARM} runs, got {len(rows)}")
    campaigns = []
    containers = []
    rng_seeds = []
    afl_rng_seeds = []
    for arm, rows in grouped.items():
        for item, cfg in rows:
            campaign = cfg.get("campaign_id")
            if not isinstance(campaign, str) or not campaign:
                errors.append(f"{arm}: missing campaign_id in run-config")
            else:
                campaigns.append(campaign)
            if not isinstance(item.get("campaign_id"), str) or item["campaign_id"] != campaign:
                    errors.append(f"{arm}: index campaign_id does not match run-config")
            container = item.get("container_id")
            if not isinstance(container, str) or not container:
                errors.append(f"{arm}: missing or invalid container_id in index")
            else:
                containers.append(container)
            if cfg.get("arm") != arm:
                errors.append(f"{arm}: run-config arm does not match index arm")
            rng_seed = cfg.get("rng_seed")
            afl_rng_seed = cfg.get("afl_rng_seed")
            if isinstance(rng_seed, bool) or not isinstance(rng_seed, int):
                errors.append(f"{arm}: rng_seed must be an integer")
            else:
                rng_seeds.append(rng_seed)
            if isinstance(afl_rng_seed, bool) or not isinstance(afl_rng_seed, int):
                errors.append(f"{arm}: afl_rng_seed must be an integer")
            else:
                afl_rng_seeds.append(afl_rng_seed)
    if len(campaigns) != len(set(campaigns)):
        errors.append("campaign_id is not unique per run")
    if len(containers) != len(set(containers)):
        errors.append("container_id is not unique per run")
    if len(rng_seeds) == sum(counts.values()) and len(rng_seeds) != len(set(rng_seeds)):
        errors.append("rng_seed is not unique per run")
    if len(afl_rng_seeds) == sum(counts.values()) and len(afl_rng_seeds) != len(set(afl_rng_seeds)):
        errors.append("afl_rng_seed is not unique per run")
    # Confirm each arm is internally stable on every non-run-specific field.
    for arm, rows in grouped.items():
        ref = {k: v for k, v in rows[0][1].items() if k not in RUN_FIELDS}
        for item, cfg in rows[1:]:
            cur = {k: v for k, v in cfg.items() if k not in RUN_FIELDS}
            if cur != ref:
                keys = sorted(k for k in set(cur) | set(ref) if cur.get(k) != ref.get(k))
                errors.append(f"{arm} within-arm drift {item.get('archive')}: {keys}")
        estimator, override, calibration = EXPECTED[arm]
        expected = {"arm": arm, "cal_estimator": estimator,
                    "state_select_override": override, "calibration": calibration}
        for item, cfg in rows:
            for key, value in expected.items():
                if cfg.get(key) != value:
                    errors.append(f"{arm} {key}: expected {value!r}, got {cfg.get(key)!r} ({item.get('archive')})")
            for key, value in EXPECTED_SCORER_PARAMS[arm].items():
                actual = cfg.get(key)
                if not isinstance(actual, (int, float)) or abs(float(actual) - value) > 1e-9:
                    errors.append(f"{arm} {key}: expected {value!r}, got {actual!r} ({item.get('archive')})")

    # Each calibrated scorer must be identical outside the explicit scorer
    # allowlist. The uncalibrated gate base may additionally differ only by
    # activation of calibration itself and the associated scorer declaration.
    base = {k: v for k, v in grouped["cal_run_rate8"][0][1].items()
            if k not in RUN_FIELDS | SCORER_FIELDS}
    for arm in ARMS:
        for item, cfg in grouped[arm]:
            invariant = {k: v for k, v in cfg.items()
                         if k not in RUN_FIELDS | SCORER_FIELDS}
            if invariant != base:
                keys = sorted(k for k in set(invariant) | set(base)
                              if invariant.get(k) != base.get(k))
                errors.append(f"{arm} Q3 invariant mismatch: {keys} ({item.get('archive')})")
    # Required invariant settings guard against incomplete run-config schemas.
    # These names match the fields emitted by LoopFuzz/run-config.jsonl.
    # Do not silently substitute the older seed_sha256/binary_sha256 aliases:
    # that would turn a complete current run-config into a false failure.
    required = (
        "target", "fuzzer", "arm", "run_id", "campaign_id", "config_hash",
        "rng_seed", "afl_rng_seed",
        "seeds_sha256", "fuzzer_sha256", "target_sha256", "image_digest",
        "campaign_call_budget", "call_cap", "episode_energy_cap",
        "episode_energy_semantics", "code_reward_semantics",
        "scheduler_warmup_max_selections", "scheduler_warmup_policy",
        "admission_mode", "provisional_enabled", "provisional_budget",
        "provisional_ttl_ms", "plaintext_wrap_enabled", "no_adaptive",
        "no_frontier", "no_llm", "shadow_enabled", "trial_mode_admission",
        "q1_policy", "threshold_mode", "threshold_requested", "threshold_resolved",
        "cal_estimator", "calibration", "cal_ewma_alpha", "cal_shrink_kappa",
    )
    for arm, rows in grouped.items():
        cfg = rows[0][1]
        missing = [k for k in required if k not in cfg]
        if missing:
            errors.append(f"{arm} config missing required fields: {missing}")

    result = {"schema": "q3-config-whitelist-v1", "status": "PASS" if not errors else "FAIL",
              "counts": counts, "run_specific_excluded_fields": sorted(RUN_FIELDS),
              "scorer_allowlist": sorted(SCORER_FIELDS), "errors": errors,
              "configs": {a: grouped[a][0][1] for a in ARMS}}
    return result


def selftest():
    # The whitelist must reject any non-scorer change.
    baseline = {"candidate_eligibility": "same", "cal_estimator": "run_rate"}
    changed = {"candidate_eligibility": "different", "cal_estimator": "ewma"}
    invariants = lambda x: {k: v for k, v in x.items() if k not in SCORER_FIELDS}
    assert invariants(baseline) != invariants(changed)
    print("t05_config_whitelist selftest: PASS")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("index", type=Path, nargs="?")
    ap.add_argument("--output", type=Path)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        selftest()
        if args.index is None:
            return 0
    if args.index is None:
        ap.error("the following arguments are required: index (unless --selftest is used)")
    if args.output is None:
        ap.error("the following arguments are required: --output when auditing an index")
    result = audit(args.index)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"T05 {result['status']}: {result['counts']} -> {args.output}")
    for error in result["errors"]:
        print("FAIL:", error)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
