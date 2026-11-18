#!/usr/bin/env python3
"""Resource-admitted parallel Q1 quick-validation runner.

Each target/arm is one launcher task (three repeats within that task), so the
four Q1 arms can run concurrently across targets under one global reservation.
The plan manifest is write-once. Progress and audit outcomes are recorded in a
separate append-only JSONL event log. Existing containers are never stopped.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


# q123_repair_smoke_*/ -> ablation/ -> ChatAFL-master/
BASE = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
TARGET_PORTS = {
    "proftpd": 18131,
    "pure-ftpd": 18132,
    "bftpd": 18105,
    "exim": 18125,
    "live555": 18120,
    "lightftp": 18104,
    "kamailio": 18126,
    "forked-daapd": 18123,
    "lighttpd1": 18122,
}
DEFAULT_TARGETS = ("exim", "live555", "lightftp", "kamailio", "forked-daapd", "lighttpd1")
ARMS = ("q1a1", "q1b1", "q1c1", "q1d1")
ARM_START = re.compile(r"\[ABLATION:(q1[a-d]1)\] 启动 → ablation/(results-[^/ ]+)/")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def available_memory_mb(meminfo: str) -> int:
    match = re.search(r"^MemAvailable:\s+(\d+)\s+kB$", meminfo, re.MULTILINE)
    if not match:
        raise RuntimeError("MemAvailable is unavailable; refusing resource admission")
    return int(match.group(1)) // 1024


def admission(avail_mb: int, running_fuzzers: int, active_tasks: int,
              repeats: int, arms: int, estimate_mb: int, reserve_mb: int,
              broker_mb: int = 1024) -> tuple[bool, int, int]:
    per_task = repeats * arms
    # Count visible fuzzers at their full reservation and reserve slots for
    # containers from admitted launchers that Docker has not listed yet.
    pending_slots = max(0, active_tasks * per_task - running_fuzzers)
    reserved_existing_mb = (running_fuzzers + pending_slots) * estimate_mb + active_tasks * broker_mb
    required_mb = per_task * estimate_mb + broker_mb
    free_after_reserves = avail_mb - reserve_mb - reserved_existing_mb
    return free_after_reserves >= required_mb, free_after_reserves, required_mb


def docker_fuzzers() -> list[str]:
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"],
        check=True, capture_output=True, text=True,
    )
    return [line.strip() for line in result.stdout.splitlines()
            if line.strip().endswith("-loopfuzz-run") or "-loopfuzz-run" in line.strip()]


def target_running(target: str, names: list[str]) -> list[str]:
    prefix = f"{target}-loopfuzz-run"
    return [name for name in names if name.startswith(prefix)]


def append_event(path: Path, event: dict) -> None:
    row = {"time_utc": dt.datetime.now(dt.timezone.utc).isoformat(), **event}
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def write_immutable(path: Path, payload: dict) -> str:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    digest = hashlib.sha256(encoded).hexdigest()
    sidecar = path.with_suffix(path.suffix + ".sha256")
    sidecar.write_text(f"{digest}  {path.name}\n", encoding="ascii")
    sidecar.chmod(0o444)
    return digest


def parse_pinned_dirs(log_path: Path, target: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for match in ARM_START.finditer(log_path.read_text(encoding="utf-8", errors="replace")):
        arm, dirname = match.groups()
        if not dirname.startswith(f"results-{target}_ablation_{arm}_"):
            continue
        if arm in result:
            raise RuntimeError(f"launcher printed duplicate start line for {target}/{arm}")
        result[arm] = BASE / "ablation" / dirname
    return result


def audit_target(target: str, run_id: str, dirs: dict[str, Path], audit_path: Path) -> tuple[int, str]:
    if set(dirs) != set(ARMS):
        missing = sorted(set(ARMS) - set(dirs))
        raise RuntimeError(f"missing pinned arms: {missing}")
    all_ids: set[str] = set()
    checks: list[str] = []
    for arm in ARMS:
        result_dir = dirs[arm]
        archives = sorted(result_dir.glob("out-*.tar.gz"))
        if len(archives) != 3 or not (result_dir / "run_summary.csv").is_file():
            raise RuntimeError(f"{target}/{arm}: expected 3 archives and run_summary.csv; found {len(archives)}")
        for archive in archives:
            check = subprocess.run(
                [sys.executable, str(OUT / "verify_q1_identity.py"), str(archive), target, arm],
                capture_output=True, text=True,
            )
            cid = check.stdout.strip()
            if check.returncode != 0 or not cid or cid in {"BADCFG", "NOCID"}:
                raise RuntimeError(f"repeat identity failed for {archive.name}: {check.stderr.strip() or cid}")
            if cid in all_ids:
                raise RuntimeError(f"duplicate campaign_id across {target} Q1 arms: {cid}")
            all_ids.add(cid)
            checks.append(f"IDENTITY {arm} {archive.name} {cid}")

    command = [
        sys.executable, str(OUT / "audit_smoke.py"), "--target", target,
        "--arms", "q1", "--timeout-min", "15",
        *(str(dirs[arm]) for arm in ARMS),
    ]
    result = subprocess.run(command, cwd=OUT, capture_output=True, text=True)
    with audit_path.open("w", encoding="utf-8") as stream:
        stream.write(f"batch={run_id}\ntarget={target}\nclassification=15-minute integrity smoke; not a fixed-dose comparison\n")
        stream.write("\n".join(checks) + "\n\n")
        stream.write("COMMAND " + " ".join(command) + "\n\n")
        stream.write(result.stdout)
        stream.write(result.stderr)
    return result.returncode, result.stdout + result.stderr


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", default=",".join(DEFAULT_TARGETS),
                        help="comma-separated targets (default: remaining six after BFTPD)")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--timeout-min", type=int, default=15)
    parser.add_argument("--call-budget-cap", type=int, default=5000,
                        help="configured cap only; wall-time-censored runs are not fixed-dose results")
    parser.add_argument("--parallel-arms", type=int, default=4)
    parser.add_argument("--estimate-mb-per-container", type=int, default=2048,
                        help="fuzzer-container reservation used by global admission (default: 2 GiB)")
    parser.add_argument("--broker-mb-per-task", type=int, default=1024,
                        help="broker/launcher reservation per target/arm task (default: 1 GiB)")
    parser.add_argument("--reserve-gb", type=int, default=8)
    parser.add_argument("--max-active-tasks", "--max-targets", dest="max_active_tasks", type=int, default=4)
    parser.add_argument("--poll-seconds", type=int, default=10)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main() -> int:
    args = make_parser().parse_args()
    targets = tuple(dict.fromkeys(part.strip() for part in args.targets.split(",") if part.strip()))
    unknown = sorted(set(targets) - TARGET_PORTS.keys())
    if unknown:
        raise SystemExit(f"unknown targets: {unknown}")
    if not targets or args.runs < 1 or args.timeout_min < 1 or args.parallel_arms != 4:
        raise SystemExit("targets/runs/timeout must be positive and --parallel-arms must be 4")
    if min(args.estimate_mb_per_container, args.broker_mb_per_task, args.reserve_gb,
           args.max_active_tasks, args.poll_seconds) < 1:
        raise SystemExit("resource and polling values must be positive")

    run_id = dt.datetime.now(dt.timezone.utc).strftime("q1p-%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
    plan_path = OUT / f"q1_parallel_manifest_{run_id}.json"
    events_path = OUT / f"q1_parallel_events_{run_id}.jsonl"
    plan = {
        "schema": "q1-parallel-manifest-v1",
        "run_id": run_id,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "base": str(BASE),
        "targets": [{"target": target, "mock_port": TARGET_PORTS[target]} for target in targets],
        "arms": list(ARMS),
        "coordinates": [
            {"coord": f"{target}|{arm}|{repeat}", "target": target,
             "arm": arm, "repeat": repeat, "status": "pending"}
            for target in targets for arm in ARMS for repeat in range(1, args.runs + 1)
        ],
        "runs_per_arm": args.runs,
        "timeout_min": args.timeout_min,
        "call_budget_cap": args.call_budget_cap,
        "result_class": "time-limited integrity smoke; not a fixed-dose Q1 comparison",
        "launcher": "run_ablation.sh",
        "launcher_sha256": sha256(BASE / "run_ablation.sh"),
        "auditor_sha256": sha256(OUT / "audit_smoke.py"),
        "resource_admission": {
            "global_parallel_arm_tasks": args.max_active_tasks,
            "requested_q1_arms": args.parallel_arms,
            "estimated_mb_per_container": args.estimate_mb_per_container,
            "broker_mb_per_task": args.broker_mb_per_task,
            "reserved_host_headroom_mb": args.reserve_gb * 1024,
            "fuzz_containers_per_task": args.runs,
            "max_active_tasks": args.max_active_tasks,
            "basis": "3 repeats x 2 GiB fuzzer cap + 1 GiB broker and 8 GiB host reserve",
        },
        "environment": {
            "ABLATION_THRESHOLD_OVERRIDE": "1",
            "ABLATION_WARMUP_MAX_OVERRIDE": "8",
            "ABLATION_EPISODE_ENERGY_OVERRIDE": "32",
            "ABLATION_CAL_REWARD_WINDOW_OVERRIDE": "16",
            "ABLATION_CALL_BUDGET_OVERRIDE": str(args.call_budget_cap),
            "ABLATION_MEM_PER_FUZZER": "2",
            "ABLATION_DOCKER_MEM_CAP": "2g",
            "ABLATION_KILL_GRACE_SEC": "30",
            "ABLATION_PARALLEL": "1",
            "ABLATION_SHUFFLE": "1",
            "CHATAFL_MOCK_LLM": "1",
            "MOCK_LATENCY": "1",
            "MOCK_ERROR_RATE": "1.5",
            "MOCK_SEED": "20261102",
            # A 15-minute integrity smoke still records the full terminal and
            # invocation ledgers, but samples coverage checkpoints sparsely so
            # post-run replay does not turn the smoke into an hours-long job.
            "SKIPCOUNT": "500",
            "COVERAGE_V4_SAMPLED_CHECKPOINTS": "1",
            "COVERAGE_V4_SMOKE": "1",
            "COVERAGE_V4_MAX_REPLAY_INPUTS": "32",
            "CHATAFL_NO_LLM": "0",
        },
    }
    if args.dry_run:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    digest = write_immutable(plan_path, plan)
    events_path.touch(mode=0o644, exist_ok=False)
    append_event(events_path, {"event": "plan_created", "plan": plan_path.name, "sha256": digest})
    print(f"plan={plan_path}\nplan_sha256={digest}\nevents={events_path}", flush=True)

    env = os.environ.copy()
    env.update({key: str(value) for key, value in plan["environment"].items()})
    env["ABLATION_MEM_EST_MB"] = str(args.estimate_mb_per_container)
    env["KEY"] = "loopfuzz-mock-key"

    pending = [(target, arm) for target in targets for arm in ARMS]
    active: dict[str, dict] = {}
    target_dirs: dict[str, dict[str, Path]] = {target: {} for target in targets}
    target_launchers: dict[str, int] = {target: 0 for target in targets}
    target_blocked = set(targets)
    outcomes: dict[str, str] = {}
    waiting_logged: set[str] = set()
    while pending or active:
        names = docker_fuzzers()
        # Hold a target with pre-existing containers until idle. Once this
        # coordinator launches its first arm, the remaining arms share it.
        for target in list(target_blocked):
            already = target_running(target, names)
            if already:
                if target not in waiting_logged:
                    waiting_logged.add(target)
                    append_event(events_path, {"event": "target_waiting", "target": target,
                                               "reason": "existing target containers left untouched", "containers": already})
                    print(f"WAIT {target}: existing containers retained ({len(already)})", flush=True)
            else:
                target_blocked.remove(target)

        for target, arm in list(pending):
            task_key = f"{target}/{arm}"
            if target in target_blocked or len(active) >= args.max_active_tasks:
                continue
            avail_mb = available_memory_mb(Path("/proc/meminfo").read_text())
            names = docker_fuzzers()
            admitted, free_mb, needed_mb = admission(
                avail_mb, len(names), len(active), args.runs, 1,
                args.estimate_mb_per_container, args.reserve_gb * 1024,
                args.broker_mb_per_task,
            )
            if not admitted:
                continue
            pending.remove((target, arm))
            launch_log = OUT / f"q1_parallel_launch_{run_id}_{target}_{arm}.log"
            launch_cmd = ["bash", str(BASE / "run_ablation.sh"), target,
                          str(args.runs), str(args.timeout_min), "--groups", arm]
            log_stream = launch_log.open("w", encoding="utf-8")
            process = subprocess.Popen(
                launch_cmd, cwd=BASE, env={**env, "MOCK_PORT": str(TARGET_PORTS[target])},
                stdout=log_stream, stderr=subprocess.STDOUT, start_new_session=True,
            )
            active[task_key] = {"target": target, "arm": arm, "process": process,
                                "log_stream": log_stream, "launch_log": launch_log, "pid": process.pid}
            target_launchers[target] += 1
            append_event(events_path, {
                "event": "arm_admitted", "target": target, "arm": arm, "pid": process.pid,
                "command": launch_cmd, "available_mb": avail_mb,
                "free_after_reservations_mb": free_mb, "required_mb": needed_mb,
                "active_tasks": sorted(active), "log": launch_log.name,
            })
            print(f"START {task_key} pid={process.pid} free_after_reservations={free_mb}MB required={needed_mb}MB", flush=True)

        for task_key, job in list(active.items()):
            target, arm = job["target"], job["arm"]
            process = job["process"]
            rc = process.poll()
            if rc is None:
                continue
            job["log_stream"].close()
            launch_log = job["launch_log"]
            append_event(events_path, {"event": "arm_launcher_exit", "target": target, "arm": arm,
                                       "pid": job["pid"], "return_code": rc, "log": launch_log.name})
            status = "arm-launch-pass" if rc == 0 else f"arm-launch-fail:{rc}"
            try:
                dirs = parse_pinned_dirs(launch_log, target)
                if set(dirs) != {arm}:
                    raise RuntimeError(f"expected only pinned arm {arm}, got {sorted(dirs)}")
                target_dirs[target][arm] = dirs[arm]
                append_event(events_path, {"event": "result_pinned", "target": target,
                                           "arm": arm, "dir": str(dirs[arm])})
            except Exception as error:
                status = "arm-pin-error"
                append_event(events_path, {"event": "arm_pin_error", "target": target, "arm": arm,
                                           "error": str(error)})
            append_event(events_path, {"event": "arm_completed", "target": target, "arm": arm,
                                       "launcher_return_code": rc, "status": status})
            print(f"DONE {task_key} launcher_rc={rc} status={status}", flush=True)
            del active[task_key]

            if target_launchers[target] == len(ARMS) and not any(job["target"] == target for job in active.values()):
                audit_path = OUT / f"audit_{target}_q1_parallel_{run_id}.txt"
                try:
                    audit_rc, _ = audit_target(target, run_id, target_dirs[target], audit_path)
                    target_status = "audit-pass" if audit_rc == 0 else "audit-fail"
                except Exception as error:
                    target_status = "audit-error"
                    audit_path.write_text(f"batch={run_id}\ntarget={target}\nAUDIT ERROR: {error}\n", encoding="utf-8")
                    append_event(events_path, {"event": "target_audit_error", "target": target,
                                               "error": str(error), "audit": audit_path.name})
                outcomes[target] = target_status
                append_event(events_path, {"event": "target_audited", "target": target,
                                           "audit": audit_path.name, "status": target_status})
                print(f"AUDIT {target} status={target_status} file={audit_path.name}", flush=True)

        if pending or active:
            time.sleep(args.poll_seconds)

    append_event(events_path, {"event": "batch_complete", "outcomes": outcomes})
    print("outcomes=" + json.dumps(outcomes, sort_keys=True), flush=True)
    return 0 if outcomes and all(value == "audit-pass" for value in outcomes.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
