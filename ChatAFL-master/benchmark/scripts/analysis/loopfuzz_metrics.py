#!/usr/bin/env python3
"""Recompute campaign mechanism metrics without inventing missing evidence.

Read an output directory or one tar.gz; never extract/modify it. The three
questions are candidate productivity under the common 64-invocation kernel,
code-branch versus observed response-state coverage, and actual calibration
activation. Missing ledgers remain null with a reason. No pooled p-values or
cross-build coverage comparisons are produced.
"""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import re
import tarfile

SCHEMA = "loopfuzz-metrics-v1"
NAMES = {"run-config.jsonl", "fuzzer_stats", "productivity-events.jsonl",
         "provisional-events.jsonl", "candidate-events.jsonl",
         "admission-events.jsonl", "execution-events.jsonl",
         "scheduler-selections.jsonl", "state-episodes.jsonl",
         "llm-calls.jsonl", "trigger-events.jsonl", "resource-samples.jsonl",
         "resource-usage.jsonl", "resource-usage.json", "ipsm.dot"}

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for data in iter(lambda: source.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()

def read_input(path):
    path = Path(path).resolve()
    data, hashes, members = {}, {}, {}
    def put(name, content, member):
        if name in data:
            raise ValueError("multiple ambiguous members for " + name)
        data[name] = content.decode("utf-8")
        hashes[name] = hashlib.sha256(content).hexdigest()
        members[name] = member
    if path.is_dir():
        for name in NAMES:
            candidate = path / name
            if candidate.is_file():
                put(name, candidate.read_bytes(), str(candidate))
    else:
        with tarfile.open(path) as archive:
            for member in archive:
                name = Path(member.name).name
                if member.isfile() and name in NAMES:
                    put(name, archive.extractfile(member).read(), member.name)
    return data, dict(input=str(path), archive_sha256=sha(path) if path.is_file() else None,
                      member_sha256=hashes, member_paths=members)

def rows(data, name):
    return [json.loads(line) for line in data.get(name, "").splitlines() if line.strip()]

def ratio(a, b):
    return a / b if b else None

def event_kind(row):
    return row.get("kind") or row.get("event")

def productivity(events):
    if not events:
        return dict(available=False, reason="productivity-events.jsonl absent/empty; conversion rate is not a substitute", groups=[]), []
    roots = {}
    for event in events:
        key = event.get("root_queue_id")
        if key is None:
            raise ValueError("productivity event has no root_queue_id")
        kind = event_kind(event)
        if kind == "start":
            if key in roots:
                raise ValueError("duplicate productivity root start")
            if event.get("horizon") != 64 or event.get("kernel") != "fuzz_one-full-session":
                raise ValueError("unsupported productivity horizon/kernel")
            roots[key] = dict(event, status="unclosed", positive=False, charged_invocations=0)
        elif key not in roots:
            raise ValueError("productivity event precedes root start")
        else:
            root = roots[key]
            charged = event.get("charged_invocations", root["charged_invocations"])
            if charged < root["charged_invocations"] or charged > 64:
                raise ValueError("productivity budget counter decreased/exceeded 64")
            root["charged_invocations"] = charged
            if kind == "first_gain" or event.get("first_gain_invocation_id", 0) or event.get("first_gain_invocation", 0):
                root["positive"] = True
                for name, value in event.items():
                    if name.startswith("first_gain"):
                        root[name] = value
            if kind in ("complete", "censor"):
                if root["status"] != "unclosed":
                    raise ValueError("duplicate productivity root closure")
                if kind == "complete" and charged != 64:
                    raise ValueError("complete productivity trial did not consume 64 invocations")
                root.update(status=kind, closure_reason=event.get("reason"))
    groups = []
    for source in sorted({root.get("source_class", "missing-source-class") for root in roots.values()}):
        selected = [root for root in roots.values() if root.get("source_class", "missing-source-class") == source]
        complete = [root for root in selected if root["status"] == "complete"]
        known_positive = sum(root["positive"] for root in selected)
        uncertain = sum(not root["positive"] and root["status"] != "complete" for root in selected)
        charged = sum(root["charged_invocations"] for root in selected)
        groups.append(dict(source_class=source, starts=len(selected), complete64=len(complete),
            censored=sum(root["status"] == "censor" for root in selected),
            unclosed=sum(root["status"] == "unclosed" for root in selected),
            productive_complete64=sum(root["positive"] for root in complete),
            productivity_at64_complete_only=ratio(sum(root["positive"] for root in complete), len(complete)),
            productivity_at64_all_started_lower=ratio(known_positive, len(selected)),
            productivity_at64_all_started_upper=ratio(known_positive + uncertain, len(selected)),
            charged_invocations=charged, known_productive_roots_per_1000_invocations=1000 * known_positive / charged if charged else None,
            paired=False, coverage_start_hashes=sorted({str(root.get("start_virgin_hash")) for root in selected}),
            interpretation="ordinary roots may have untracked LLM ancestry; independent samples, not same-start paired trials"))
    return dict(available=True, horizon=64, kernel="fuzz_one-full-session", groups=groups), list(roots.values())

def provisional(events, total_execs):
    admits = [row for row in events if event_kind(row) == "admit"]
    closures = [row for row in events if event_kind(row) in ("expire", "convert", "censor")]
    charged = sum(row.get("descendant_execs", 0) for row in closures)
    return dict(admitted=len(admits), conversions=sum(event_kind(row) == "convert" for row in closures),
        closure_reasons=dict(Counter(row.get("reason", "unspecified") for row in closures)),
        charged_before_conversion_or_close=charged, charged_share_of_fuzzer_execs=ratio(charged, total_execs),
        interpretation="partial descriptive closure costs; excludes converted descendants after conversion and unclosed exposure")

def calibration(config, selections, episodes):
    weighted = [row for row in selections if row.get("reason") == "weighted-eligible" and row.get("weight_total", 0) > 0]
    enabled = config.get("calibration")
    scores = [row for row in episodes if row.get("completed") and row.get("final_selection_score", 0) > 0 and row.get("sampled_theta", -1) >= 0]
    explicit = [row for row in selections if row.get("calibration_applied") is True]
    return dict(config_enabled=enabled, selection_rows=len(selections),
        reasons=dict(Counter(row.get("reason", "missing") for row in selections)),
        weighted_selections=len(weighted), weighted_fraction=ratio(len(weighted), len(selections)),
        explicit_calibration_applied_selections=len(explicit) if any("calibration_applied" in row for row in selections) else None,
        activated_weighted_path=(bool(enabled) and bool(weighted)) if selections and enabled is not None else None,
        completed_episodes_with_sampled_score=len(scores),
        posterior_changed_choices=sum(bool(row.get("calibration_changed_selection")) for row in selections) if any("calibration_changed_selection" in row for row in selections) else None,
        interpretation="configuration plus weighted-path observation establishes activation only; outcome benefit requires matched D/E runs")

def interval_union(intervals):
    if not intervals:
        return None
    total, start, end = 0, *sorted(intervals)[0]
    for left, right in sorted(intervals)[1:]:
        if left > end:
            total += end - start
            start, end = left, right
        else:
            end = max(end, right)
    return (total + end - start) / 1000

def costs(calls, stats, resource):
    seqs = Counter(row.get("seq") for row in calls)
    ids = [row.get("request_id") for row in calls]
    intervals = []
    for row in calls:
        start, end = row.get("start_time_ms"), row.get("end_time_ms")
        if start is not None and end is not None:
            if end < start:
                raise ValueError("request end time precedes start")
            intervals.append((start, end))
    cpu_values = [row.get("cpu_usage_usec", row.get("usage_usec")) for row in resource]
    cpu_values = [value for value in cpu_values if value is not None]
    cpu_delta = None
    if len(cpu_values) >= 2:
        if any(after < before for before, after in zip(cpu_values, cpu_values[1:])):
            raise ValueError("cgroup CPU counter reset; do not merge containers")
        cpu_delta = (cpu_values[-1] - cpu_values[0]) / 1000000
    return dict(llm_ledger_rows=len(calls), statuses=dict(Counter(row.get("status") for row in calls)),
        tokens=sum((row.get("prompt_tokens") or 0) + (row.get("completion_tokens") or 0) for row in calls) if calls else None,
        summed_request_latency_s=sum((row.get("latency_ms") or 0) for row in calls) / 1000 if calls else None,
        explicit_request_interval_union_s=interval_union(intervals) if len(intervals) == len(calls) else None,
        explicit_request_interval_rows=len(intervals),
        unique_request_ids_valid=bool(calls) and all(ids) and len(set(ids)) == len(ids),
        seq_duplicate_extra_rows=sum(max(0, value - 1) for value in seqs.values()),
        request_types=dict(Counter(row.get("request_type", row.get("channel", "unrecorded")) for row in calls)),
        container_cpu_delta_s=cpu_delta, cpu_sample_rows=len(resource),
        total_llm_wait_wall_s=None,
        interpretation="summed HTTP latency and request-interval union are not CPU time or measured fuzzer-blocked time; cgroup CPU includes container descendants within sampled interval")

def observed_edges(data):
    dot = data.get("ipsm.dot")
    if dot is None:
        return dict(available=False, edge_ids=None, reason="ipsm.dot absent; episode novelty sums are not an edge-identity union")
    edges = sorted(set(re.findall(r'"?([0-9]+)"?\s*->\s*"?([0-9]+)"?', dot)))
    return dict(available=True, edge_ids=edges, count=len(edges),
        measurement="observed response-derived IPSM directed edges; neither code branches nor semantic internal states")

def trigger_summary(events, ledger_present=None):
    if ledger_present is None:
        ledger_present = bool(events)
    return dict(ledger_present=ledger_present, rows=len(events),
        kinds=dict(Counter(row.get("rule", row.get("trigger_rule", row.get("policy", "unrecorded")))
                           for row in events)))

def code_branches(csv_path, source_root=None):
    if csv_path is None:
        return dict(available=False, reason="no independent coverage-v4 artifacts supplied")
    import coverage_v4
    directory = Path(str(csv_path) + ".v4")
    if not (directory / "terminal.json").is_file():
        failure = directory / "incomplete.json"
        return dict(available=True, scientific_acceptance=False, coverage_complete=False,
                    reason="terminal coverage artifact missing",
                    failure=json.loads(failure.read_text()) if failure.is_file() else None)
    terminal = json.loads((directory / "terminal.json").read_text())
    scope = json.loads((directory / "scope.json").read_text())
    result = dict(available=True, scope_sha256=scope["scope_sha256"],
                  cumulative_branch_count=len(terminal["covered_branch_ids"]),
                  coverage_complete=terminal.get("coverage_complete"),
                  replay_policy=scope.get("replay_policy"),
                  measurement="cumulative retained-corpus replay source-branch identity union",
                  scope_must_match_before_comparison=True)
    checkpoints = [json.loads(line) for line in (directory / "checkpoints.jsonl").read_text().splitlines() if line.strip()]
    result["campaign_ids"] = sorted({row["campaign_id"] for row in checkpoints if row.get("campaign_id")})
    try:
        result["artifact_audit"] = coverage_v4.audit_artifacts(csv_path, source_root)
        result["artifact_audit_passed"] = True
    except (OSError, ValueError, KeyError) as error:
        result["artifact_audit_passed"] = False
        result["artifact_audit_error"] = str(error)
    result["scientific_acceptance"] = result["artifact_audit_passed"] and result["coverage_complete"] is True
    return result

def analyze(path, coverage_csv=None, coverage_source_root=None, resource_path=None):
    data, provenance = read_input(path)
    configs = rows(data, "run-config.jsonl")
    starts = [row for row in configs if row.get("phase") == "start"]
    if len(starts) != 1:
        raise ValueError("one campaign start config is required")
    config = starts[0]
    campaigns = {row.get("campaign_id") for name in NAMES if name.endswith(".jsonl")
                 for row in rows(data, name) if row.get("campaign_id")}
    if len(campaigns) > 1:
        raise ValueError("mixed campaign identities")
    stats = {key.strip(): value.strip() for line in data.get("fuzzer_stats", "").splitlines()
             if ":" in line for key, value in [line.split(":", 1)]}
    execs = int(stats["execs_done"]) if "execs_done" in stats else None
    duration = int(stats["last_update"]) - int(stats["start_time"]) if {"last_update", "start_time"} <= stats.keys() else None
    if duration is not None and duration < 0:
        raise ValueError("fuzzer stats end precedes start")
    product, product_rows = productivity(rows(data, "productivity-events.jsonl"))
    resource = rows(data, "resource-samples.jsonl") or rows(data, "resource-usage.jsonl")
    if resource_path:
        resource = [json.loads(line) for line in Path(resource_path).read_text().splitlines() if line.strip()]
        provenance["external_resource_sha256"] = sha(Path(resource_path))
    result = dict(schema_version=SCHEMA, provenance=provenance,
        identity={key:config.get(key) for key in ("campaign_id", "arm", "target", "fuzzer_sha256", "target_sha256", "seeds_sha256", "image_digest", "rng_seed", "config_hash")},
        budget=dict(fuzzer_total_execs=execs, fuzz_clock_s=duration,
                    fuzzer_execs_per_fuzz_clock_s=ratio(execs, duration) if execs is not None else None,
                    physical_target_invocations=None),
        candidate64=product, provisional=provisional(rows(data, "provisional-events.jsonl"), execs),
        calibration=calibration(config, rows(data, "scheduler-selections.jsonl"), rows(data, "state-episodes.jsonl")),
        code_branches=code_branches(coverage_csv, coverage_source_root),
        observed_response_state_edges=observed_edges(data),
        costs=costs(rows(data, "llm-calls.jsonl"), stats, resource),
        trigger=trigger_summary(rows(data, "trigger-events.jsonl"),
                                "trigger-events.jsonl" in data))
    branch = result["code_branches"]
    if branch.get("campaign_ids") != [config.get("campaign_id")] and coverage_csv is not None:
        branch["scientific_acceptance"] = False
        branch["campaign_join_error"] = "coverage artifacts do not uniquely match input campaign"
    return result, product_rows

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--coverage-csv", type=Path)
    parser.add_argument("--coverage-source-root", type=Path)
    parser.add_argument("--resource-jsonl", type=Path)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise SystemExit("refusing to overwrite analysis directory")
    result, samples = analyze(args.input, args.coverage_csv, args.coverage_source_root, args.resource_jsonl)
    args.output_dir.mkdir(parents=True)
    (args.output_dir / "metrics.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if samples:
        keys = sorted({key for row in samples for key in row})
        with (args.output_dir / "candidate64_samples.csv").open("w", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=keys)
            writer.writeheader()
            writer.writerows(samples)
    print(json.dumps(dict(output=str(args.output_dir), campaign_id=result["identity"]["campaign_id"])))

if __name__ == "__main__":
    main()
