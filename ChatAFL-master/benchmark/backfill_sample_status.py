#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Iterable

REQUIRED_FILES = ("fuzzer_stats", "cov_over_time.csv")
WORKDIR = "/home/ubuntu/experiments"


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True)


def tarball_is_complete(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size == 0:
        return False
    try:
        with tarfile.open(path, "r:gz") as tf:
            names = [member.name for member in tf.getmembers()]
    except (tarfile.TarError, OSError):
        return False
    return all(any(name.endswith(req) for name in names) for req in REQUIRED_FILES)


def parse_manifest(manifest: Path) -> list[dict[str, str]]:
    with manifest.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


def inspect_container(container_id: str) -> dict[str, str] | None:
    fmt = "status={{.State.Status}}\nrunning={{.State.Running}}\nexit_code={{.State.ExitCode}}\noom={{.State.OOMKilled}}\nname={{.Name}}"
    proc = run(["docker", "inspect", "--format", fmt, container_id])
    if proc.returncode != 0:
        return None
    result: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def get_fuzzer_stat(container_id: str, outdir: str, key: str) -> str:
    cmd = (
        f"grep '^{key}[[:space:]]*:' '{WORKDIR}/{outdir}/fuzzer_stats' 2>/dev/null "
        "| head -n1 | awk -F: '{print $2}' | tr -d ' '"
    )
    proc = run(["docker", "exec", container_id, "/bin/bash", "-lc", cmd])
    return proc.stdout.strip() if proc.returncode == 0 else ""


def get_thread_snapshot(container_id: str) -> str:
    pid_proc = run(["docker", "exec", container_id, "/bin/bash", "-lc", "pgrep -xo afl-fuzz"])
    pid = pid_proc.stdout.strip()
    if not pid:
        return ""
    proc = run([
        "docker",
        "exec",
        container_id,
        "/bin/bash",
        "-lc",
        f"ps -L -p {pid} -o pid,tid,stat,pcpu,psr,comm,wchan:32",
    ])
    return proc.stdout


def collect_forensics(results_dir: Path, archive_name: str, container_id: str, outdir: str) -> str:
    forensics_dir = results_dir / ".forensics" / archive_name.removesuffix(".tar.gz")
    forensics_dir.mkdir(parents=True, exist_ok=True)

    def capture(name: str, cmd: list[str]) -> None:
        proc = run(cmd)
        (forensics_dir / name).write_text(proc.stdout + proc.stderr, encoding="utf-8", errors="replace")

    capture("docker_inspect.json", ["docker", "inspect", container_id])
    capture("docker_logs.tail.txt", ["docker", "logs", "--tail", "200", container_id])
    capture("fuzzer_stats.txt", ["docker", "exec", container_id, "/bin/bash", "-lc", f"cat '{WORKDIR}/{outdir}/fuzzer_stats' 2>/dev/null"])
    capture("plot_data.tail.txt", ["docker", "exec", container_id, "/bin/bash", "-lc", f"test -f '{WORKDIR}/{outdir}/plot_data' && tail -n 200 '{WORKDIR}/{outdir}/plot_data'"])
    capture("ps.txt", ["docker", "exec", container_id, "/bin/bash", "-lc", "ps -eo pid,ppid,stat,etime,pcpu,comm,args"])
    capture("ps_threads.txt", ["docker", "exec", container_id, "/bin/bash", "-lc", "pid=$(pgrep -xo afl-fuzz 2>/dev/null || true); test -n \"$pid\" && ps -L -p $pid -o pid,tid,stat,pcpu,psr,comm,wchan:32"])
    capture("proc_status.txt", ["docker", "exec", container_id, "/bin/bash", "-lc", "pid=$(pgrep -xo afl-fuzz 2>/dev/null || true); test -n \"$pid\" && cat /proc/$pid/status"])
    capture("proc_wchan.txt", ["docker", "exec", container_id, "/bin/bash", "-lc", "pid=$(pgrep -xo afl-fuzz 2>/dev/null || true); test -n \"$pid\" && cat /proc/$pid/wchan"])
    capture("task_wchan.txt", ["docker", "exec", container_id, "/bin/bash", "-lc", "pid=$(pgrep -xo afl-fuzz 2>/dev/null || true); if test -n \"$pid\"; then for task in /proc/$pid/task/*; do tid=$(basename \"$task\"); printf '=== TID=%s\\n' \"$tid\"; cat \"$task/wchan\" 2>/dev/null || true; done; fi"])
    capture("gdb_thread_bt.txt", ["docker", "exec", "-u", "0", container_id, "/bin/bash", "-lc", "pid=$(pgrep -xo afl-fuzz 2>/dev/null || true); if command -v gdb >/dev/null 2>&1 && test -n \"$pid\"; then gdb -q -batch -ex 'set pagination off' -ex 'thread apply all bt' -p $pid; fi"])
    return str(forensics_dir)


def write_status(results_dir: Path, archive_name: str, data: dict[str, str]) -> None:
    status_dir = results_dir / ".sample_status"
    status_dir.mkdir(parents=True, exist_ok=True)
    lines = [f"archive_name={archive_name}"] + [f"{key}={value}" for key, value in data.items()]
    (status_dir / f"{archive_name}.status").write_text("\n".join(lines) + "\n", encoding="utf-8")


def classify_row(results_dir: Path, row: dict[str, str], stall_threshold_sec: int, overwrite: bool) -> str:
    archive_name = row["archive_name"]
    container_id = row["container_id"]
    outdir = row["outdir"]
    archive_path = results_dir / archive_name
    status_path = results_dir / ".sample_status" / f"{archive_name}.status"

    if status_path.exists() and not overwrite:
        return "skipped-existing"

    archive_complete = tarball_is_complete(archive_path)
    inspect = inspect_container(container_id)
    now = int(time.time())
    detected_at = dt.datetime.now(dt.timezone.utc).isoformat()
    data: dict[str, str] = {
        "container_id": container_id,
        "archive_complete": "1" if archive_complete else "0",
        "detected_at": detected_at,
        "diagnostics_dir": "",
        "stale_seconds": "0",
    }

    if inspect is None:
        if archive_complete:
            data.update({"status": "completed", "reason": "archive_complete_container_missing"})
        elif archive_path.exists():
            data.update({"status": "failed", "reason": "archive_incomplete_container_missing"})
        else:
            data.update({"status": "failed", "reason": "archive_missing_container_missing"})
        write_status(results_dir, archive_name, data)
        return data["status"]

    data.update({
        "docker_status": inspect.get("status", "unknown"),
        "docker_running": inspect.get("running", "false"),
        "docker_exit_code": inspect.get("exit_code", ""),
        "docker_oom": inspect.get("oom", ""),
        "container_name": inspect.get("name", ""),
    })

    if inspect.get("running") == "true":
        last_update = get_fuzzer_stat(container_id, outdir, "last_update")
        execs_done = get_fuzzer_stat(container_id, outdir, "execs_done")
        thread_snapshot = get_thread_snapshot(container_id)
        data.update({"last_update": last_update, "execs_done": execs_done})
        stale_seconds = None
        if last_update.isdigit():
            stale_seconds = max(0, now - int(last_update))
            data["stale_seconds"] = str(stale_seconds)
        if stale_seconds is not None and stale_seconds >= stall_threshold_sec:
            reason = "stale_fuzzer_stats"
            if thread_snapshot.count("futex_wait_queue_me") >= 2:
                reason = "stale_fuzzer_stats_futex_wait_queue_me"
            diag_dir = collect_forensics(results_dir, archive_name, container_id, outdir)
            data.update({"status": "stalled", "reason": reason, "diagnostics_dir": diag_dir})
        else:
            data.update({"status": "running", "reason": "container_running"})
        write_status(results_dir, archive_name, data)
        return data["status"]

    if archive_complete:
        data.update({"status": "completed", "reason": "container_exited_archive_complete"})
    else:
        exit_code = inspect.get("exit_code", "unknown")
        data.update({"status": "failed", "reason": f"container_exited_{exit_code}_archive_incomplete"})
    write_status(results_dir, archive_name, data)
    return data["status"]


def iter_results_dirs(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir() and path.name.startswith("results-"):
            yield path
        elif path.is_dir():
            for child in sorted(path.glob("results-*")):
                if child.is_dir():
                    yield child


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill .sample_status metadata for historical results directories.")
    parser.add_argument("paths", nargs="+", help="Results directories or parent directories containing results-*")
    parser.add_argument("--stall-threshold-sec", type=int, default=300)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    results_dirs = list(iter_results_dirs(Path(path).resolve() for path in args.paths))
    if not results_dirs:
        raise SystemExit("No results-* directories found")

    summary: dict[str, int] = {}
    for results_dir in results_dirs:
        manifest = results_dir / ".result_manifest.tsv"
        if not manifest.is_file():
            print(f"[backfill] skip {results_dir}: no manifest")
            continue
        rows = parse_manifest(manifest)
        print(f"[backfill] processing {results_dir} ({len(rows)} rows)")
        for row in rows:
            status = classify_row(results_dir, row, args.stall_threshold_sec, args.overwrite)
            summary[status] = summary.get(status, 0) + 1

    print("[backfill] summary:")
    for key in sorted(summary):
        print(f"  {key}: {summary[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
