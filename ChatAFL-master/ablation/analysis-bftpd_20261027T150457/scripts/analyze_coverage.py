#!/usr/bin/env python3
"""Read canonical 150457 archives without extracting or modifying raw inputs.

All AUCs describe saved-corpus replay unions, not online first discovery.
An incomplete session-coverage export invalidates scientific use of those AUCs.
"""
import argparse
import collections
import csv
import hashlib
import io
import json
import pathlib
import statistics
import tarfile

BATCH = "20261027T150457"
ARMS = ("wrapdirect8", "wrapgate8", "salvage8")


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def curve(events, coordinate):
    points = {0.0: 0}
    for event in events:
        x = coordinate(event)
        points[x] = max(points.get(x, 0), event["cumulative_covered_branches"])
    return sorted(points.items())


def integral(points, horizon):
    area, previous_x, previous_y = 0.0, 0.0, 0
    for x, y in points:
        if x > horizon:
            break
        area += previous_y * (x - previous_x)
        previous_x, previous_y = x, y
    area += previous_y * (horizon - previous_x)
    return dict(horizon=horizon, area=area, mean_branches=area / horizon,
                terminal_at_horizon=previous_y)


def summary(values):
    return dict(n=len(values), values=values, mean=statistics.mean(values),
                sample_sd=statistics.stdev(values) if len(values) > 1 else None,
                minimum=min(values), maximum=max(values))


def analyze(path, root, arm, run):
    with tarfile.open(path, "r:gz") as t:
        names = t.getnames()
        def get(suffix):
            matches = [n for n in names if n.endswith("/" + suffix)]
            if len(matches) != 1:
                raise ValueError((path, suffix, matches))
            return t.extractfile(matches[0]).read()

        terminal = json.loads(get("terminal.json"))
        scope = json.loads(get("scope.json"))
        events = [json.loads(line) for line in get("cov_over_time.csv.v4/checkpoints.jsonl").splitlines()]
        initial_input_manifest = [{k:e[k] for k in ("queue_id", "filename", "input_sha256")}
            for e in events if e["kind"] == "initial-queue-name"]
        initial_input_manifest.sort(key=lambda e: e["queue_id"])
        initial_hash_list = [e["input_sha256"] for e in initial_input_manifest]
        initial_hash_list_sha256 = hashlib.sha256(
            json.dumps(initial_hash_list,separators=(",", ":")).encode()).hexdigest()
        initial_hash_multiset_sha256 = hashlib.sha256(
            json.dumps(sorted(initial_hash_list),separators=(",", ":")).encode()).hexdigest()
        configs = [json.loads(line) for line in get("run-config.jsonl").splitlines()]
        start, end = configs[0], configs[-1]
        stats = dict(line.split(":", 1) for line in get("fuzzer_stats").decode().splitlines() if ":" in line)
        stats = {k.strip(): v.strip() for k, v in stats.items()}
        csv_rows = list(csv.DictReader(io.StringIO(get("cov_over_time.csv").decode())))
        # Each checkpoint has a preserved replay log. Read in physical tar order.
        log_class = collections.Counter()
        log_examples = {}
        evidence_logs = {}
        event_by_log = {"replay-%06d.log" % e["idx"]: e for e in events}
        for member in t.getmembers():
            key = member.name.rsplit("/", 1)[-1]
            if key not in event_by_log:
                continue
            body = t.extractfile(member).read()
            authenticated = b"230 User logged in." in body
            missing = event_by_log[key]["replay"]["session_coverage_missing"]
            label = ("authenticated" if authenticated else "no_successful_login") + ("_missing_gcda" if missing else "_has_gcda")
            log_class[label] += 1
            log_examples.setdefault(label, member.name)
            if arm == "wrapdirect8" and run == 1 and key in ("replay-000001.log", "replay-000185.log"):
                evidence_logs[key] = dict(member=member.name, text=body.decode("utf-8", errors="replace"),
                    checkpoint_replay=event_by_log[key]["replay"],
                    cumulative_covered_branches=event_by_log[key]["cumulative_covered_branches"],
                    kind=event_by_log[key]["kind"], queue_id=event_by_log[key]["queue_id"])

    covered = set(map(tuple, terminal["covered_branch_ids"]))
    reconstructed = set()
    for e in events:
        reconstructed.update(map(tuple, e["newly_covered_branch_ids"]))
    assert covered == reconstructed
    assert terminal["n_replayed"] == len(events)
    assert terminal["csv_audit"]["terminal_branches"] == len(covered)
    assert int(csv_rows[-1]["b_abs"]) == len(covered)
    assert scope["scope_sha256"] == terminal["scope_sha256"]
    missing = sum(e["replay"]["session_coverage_missing"] for e in events)
    missing_normal = sum(e["replay"]["session_coverage_missing"] and e["replay"]["server_exit_code"] == 0 for e in events)
    branch_gains = [e for e in events if e["newly_covered_branch_ids"]]
    runtime_s = (end["end_time_ms"] - start["start_time_ms"]) / 1000
    record = dict(
        arm=arm, run=run, archive=str(path.relative_to(root)), archive_sha256=sha256(path),
        campaign_id=start["campaign_id"], start_time_ms=start["start_time_ms"],
        end_time_ms=end["end_time_ms"], campaign_duration_s=runtime_s,
        fuzzer_stats_start_time_s=int(stats["start_time"]),
        fuzzer_stats_last_update_s=int(stats["last_update"]),
        execs_done=int(stats["execs_done"]), paths_total=int(stats["paths_total"]),
        terminal_branches=len(covered), terminal_lines=len(terminal["covered_line_ids"]),
        branch_scope=len(scope["branch_ids"]), line_scope=len(scope["line_ids"]),
        scope_sha256=scope["scope_sha256"], terminal_coverage_fraction=len(covered)/len(scope["branch_ids"]),
        n_replayed=len(events), n_csv_checkpoints=len(csv_rows),
        fixed_execution_coordinates_valid=terminal["fixed_execution_coordinates_valid"],
        all_reset_commands_succeeded=terminal["all_reset_commands_succeeded"],
        replay_anomalies=terminal["replay_anomalies"],
        unreplayable_ledger_entries=terminal["n_unreplayable_ledger_entries"],
        unexpected_snapshot_decrease=terminal["unexpected_snapshot_decrease"],
        session_coverage_missing=missing, session_coverage_missing_fraction=missing/len(events),
        normal_server_exit_but_session_coverage_missing=missing_normal,
        replay_server_exit_counts=dict(collections.Counter(str(e["replay"]["server_exit_code"]) for e in events)),
        replay_log_login_gcda_cross_tab=dict(log_class), replay_log_examples=log_examples,
        evidence_logs=evidence_logs,
        initial_queue_checkpoint_count=sum(e["kind"] == "initial-queue-name" for e in events),
        initial_input_manifest=initial_input_manifest,
        initial_ordered_input_hash_list_sha256=initial_hash_list_sha256,
        initial_input_hash_multiset_sha256=initial_hash_multiset_sha256,
        first_100_checkpoint_missing_gcda=sum(e["replay"]["session_coverage_missing"] for e in events[:100]),
        first_184_checkpoint_missing_gcda=sum(e["replay"]["session_coverage_missing"] for e in events[:184]),
        first_184_checkpoint_kinds=dict(collections.Counter(e["kind"] for e in events[:184])),
        first_184_max_cumulative_covered_branches=max(e["cumulative_covered_branches"] for e in events[:184]),
        code_gain_checkpoint_count=len(branch_gains),
        code_gain_candidate_id_counts=dict(collections.Counter(str(e["candidate_id"]) for e in branch_gains)),
        code_gain_checkpoints=[{k:e[k] for k in ("idx","filename","queue_id","candidate_id","discovery_execution_id","discovery_time_ms","cumulative_covered_branches","newly_covered_branch_ids")} for e in branch_gains],
        measurement=terminal["measurement"], temporal_limit=terminal["temporal_limit"],
        branches=sorted(covered), lines=terminal["covered_line_ids"],
    )
    wall = curve(events, lambda e: (e["discovery_time_ms"]-start["start_time_ms"])/1000)
    executions = curve(events, lambda e: float(e["discovery_execution_id"]))
    return record, wall, executions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    records, curves = [], {}
    for arm in ARMS:
        folder = root / "ablation" / ("results-bftpd_ablation_%s_%s" % (arm,BATCH))
        canonical = sorted(folder.glob("out-bftpd-loopfuzz_*.tar.gz"))
        assert len(canonical) == 3, (folder,canonical)
        for path in canonical:
            run = int(path.name.split("_")[-1].split(".")[0])
            record, wall, executions = analyze(path, root, arm, run)
            records.append(record)
            curves[arm,run] = (wall,executions)
    assert len({r["scope_sha256"] for r in records}) == 1
    wall_horizon = min(r["campaign_duration_s"] for r in records)
    execution_horizon = min(r["execs_done"] for r in records)
    curve_rows = []
    for r in records:
        wall, executions = curves[r["arm"],r["run"]]
        r["diagnostic_wall_auc"] = integral(wall, wall_horizon)
        r["diagnostic_execution_auc"] = integral(executions, execution_horizon)
        for axis,points in (("campaign_wall_seconds",wall),("fuzzer_total_execs",executions)):
            curve_rows.extend(dict(arm=r["arm"],run=r["run"],axis=axis,coordinate=x,branches=y) for x,y in points)
    arm_summary = {}
    for arm in ARMS:
        rs = [r for r in records if r["arm"] == arm]
        arm_union = set.union(*(set(map(tuple,r["branches"])) for r in rs))
        arm_summary[arm] = dict(
            terminal_branches=summary([r["terminal_branches"] for r in rs]),
            terminal_lines=summary([r["terminal_lines"] for r in rs]),
            diagnostic_wall_auc_mean_branches=summary([r["diagnostic_wall_auc"]["mean_branches"] for r in rs]),
            diagnostic_execution_auc_mean_branches=summary([r["diagnostic_execution_auc"]["mean_branches"] for r in rs]),
            session_coverage_missing=sum(r["session_coverage_missing"] for r in rs),
            n_replayed=sum(r["n_replayed"] for r in rs),
            branch_union=sorted(arm_union), branch_union_count=len(arm_union))
    all_union = set.union(*(set(map(tuple,r["branches"])) for r in records))
    all_inter = set.intersection(*(set(map(tuple,r["branches"])) for r in records))
    result = dict(
        batch=BATCH, target="bftpd", roots=str(root), runs=records, arms=arm_summary,
        terminal_branch_union_count=len(all_union), terminal_branch_intersection_count=len(all_inter),
        unique_initial_ordered_input_hash_lists=len({r["initial_ordered_input_hash_list_sha256"] for r in records}),
        unique_initial_input_hash_multisets=len({r["initial_input_hash_multiset_sha256"] for r in records}),
        nonuniversal_branch_ids=sorted(all_union-all_inter),
        interpretation="Saved-corpus replay branch unions are lower bounds. Session gcda missing for most replayed inputs, including successful authenticated sessions, prevents scientific coverage efficacy inference. AUCs are diagnostics only.",
        auc_method="Dense checkpoints.jsonl cumulative branch union; right-continuous step integral; zero before first checkpoint; campaign wall origin run_config.start_time_ms includes initialization; execution origin total_execs zero; hold last observed union to common horizon.",
        statistics_limit="n=3 independent runs per arm. Terminal eight198/one197 cannot establish superiority or noninferiority; incomplete gcda export is a measurement validity issue before statistical power.",
    )
    (args.output/"coverage.json").write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
    with (args.output/"coverage_curves.csv").open("w",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=("arm","run","axis","coordinate","branches"))
        writer.writeheader();writer.writerows(curve_rows)
    print(json.dumps({"output":str(args.output),"wall_horizon_s":wall_horizon,"execution_horizon":execution_horizon,"terminal":{a:s["terminal_branches"] for a,s in arm_summary.items()},"missing_gcda":sum(r["session_coverage_missing"] for r in records),"n_replayed":sum(r["n_replayed"] for r in records)},indent=2))


if __name__ == "__main__":
    main()
