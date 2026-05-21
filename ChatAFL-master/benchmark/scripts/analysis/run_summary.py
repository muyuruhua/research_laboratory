#!/usr/bin/env python3
"""Summarize per-run fuzzing results into a CSV.

The script scans a results directory for either packed archives:
  out-<subject>-<fuzzer>_<run>.tar.gz
or extracted run directories:
  out-<subject>-<fuzzer>-<run>/

For each run it extracts:
  - tarball / directory name
  - subject, fuzzer, run index
  - runtime in minutes from fuzzer_stats (start_time -> last_update)
  - final l_abs / b_abs from cov_over_time.csv
  - final nodes / edges from plot_data

Usage:
  python3 run_summary.py <results-dir> [--output summary.csv]
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


NAME_RE = re.compile(r"^out-(?P<subject>.+)-(?P<fuzzer>[A-Za-z0-9_]+)_(?P<run>\d+)\.tar\.gz$")


@dataclass
class RunMetrics:
    source: str
    subject: str
    fuzzer: str
    run: int
    runtime_min: int | None = None
    elapsed_min: int | None = None
    l_abs: int | None = None
    b_abs: int | None = None
    nodes: int | None = None
    edges: int | None = None
    start_time: int | None = None
    last_update: int | None = None
    status: str = "unknown"
    invalid_reason: str = ""
    exit_code: int | None = None
    diagnostics_dir: str = ""


INVALID_STATUSES = {"stalled", "invalid", "failed"}
FATAL_EXIT_CODES = {
    137: "oom_killed",       # SIGKILL (128+9) — default, refined by classify_status
    139: "sigsegv",          # SIGSEGV (128+11)
    134: "sigabrt",          # SIGABRT (128+6)
    143: "sigterm",          # SIGTERM (128+15)
    124: "timeout",          # timeout command's own exit code
}


def classify_status(
    exit_code: int | None,
    runtime_min: int | None,
    reason: str,
    status: str,
    timeout_min: int | None = None,
) -> str:
    """Classify final status.

    exit_code=137 is ambiguous:
      - Real cgroup OOM: fuzzer killed by kernel, runtime << timeout
      - Timeout shutdown race: ``timeout -k 2s`` sends SIGKILL when afl-fuzz
        is slow to exit after SIGTERM at the timeout mark. Runtime ~ timeout.
    """
    if exit_code == 137:
        if timeout_min is not None and runtime_min is not None:
            if runtime_min >= timeout_min - 7:
                return "timeout_kill"
            return "oom_killed"
        if runtime_min is not None and runtime_min >= 50:
            return "exit_137_near_limit"
        return "oom_killed"

    if exit_code is not None and exit_code in FATAL_EXIT_CODES:
        return FATAL_EXIT_CODES[exit_code]
    if status in INVALID_STATUSES:
        return status
    if reason and reason not in ("", "completed"):
        return reason
    return "completed"


def parse_run_name(name: str) -> Optional[tuple[str, str, int]]:
    match = NAME_RE.match(name)
    if not match:
        return None
    return match.group("subject"), match.group("fuzzer"), int(match.group("run"))


def safe_int(value: str | None) -> Optional[int]:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return int(float(value))
    except ValueError:
        return None


def read_text_from_tar(tf: tarfile.TarFile, suffix: str) -> str:
    for member in tf.getmembers():
        if member.name.endswith(suffix):
            extracted = tf.extractfile(member)
            if extracted is not None:
                return extracted.read().decode("utf-8", errors="replace")
    return ""


def read_text_from_dir(root: Path, suffix: str) -> str:
    for path in root.rglob("*"):
        if path.is_file() and path.name == suffix or str(path).endswith(suffix):
            return path.read_text(encoding="utf-8", errors="replace")
    return ""


def read_status_metadata(results_dir: Path) -> dict[str, dict[str, str]]:
    status_dir = results_dir / ".sample_status"
    metadata: dict[str, dict[str, str]] = {}

    if not status_dir.is_dir():
        return metadata

    for path in sorted(status_dir.glob("*.status")):
        values: dict[str, str] = {}
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
        except OSError:
            continue

        archive_name = values.get("archive_name") or path.name[:-7]
        metadata[archive_name] = values

    return metadata


def parse_cov_text(text: str) -> tuple[Optional[int], Optional[int]]:
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) <= 1:
        return None, None
    last = lines[-1].split(",")
    if len(last) < 5:
        return None, None
    return safe_int(last[2]), safe_int(last[4])


def parse_plot_text(text: str) -> tuple[Optional[int], Optional[int]]:
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) <= 1:
        return None, None
    last = lines[-1].split(",")
    if len(last) < 13:
        return None, None
    return safe_int(last[11]), safe_int(last[12])


def parse_fuzzer_stats(text: str) -> tuple[Optional[int], Optional[int], Optional[int]]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()

    start = safe_int(data.get("start_time"))
    last = safe_int(data.get("last_update"))
    runtime_min = None
    if start is not None and last is not None and last >= start:
        runtime_min = (last - start) // 60
    return runtime_min, start, last


def iter_sources(results_dir: Path) -> Iterable[Path]:
    for path in sorted(results_dir.iterdir()):
        if path.name.startswith("out-") and (path.name.endswith(".tar.gz") or path.is_dir()):
            yield path


def read_metrics(path: Path, status_map: dict[str, dict[str, str]], timeout_min: int | None = None) -> Optional[RunMetrics]:
    parsed = parse_run_name(path.name)
    if not parsed:
        return None
    subject, fuzzer, run = parsed
    metrics = RunMetrics(source=path.name, subject=subject, fuzzer=fuzzer, run=run)

    if path.is_file() and path.suffixes[-2:] == [".tar", ".gz"]:
        with tarfile.open(path, "r:gz") as tf:
            cov_text = read_text_from_tar(tf, "cov_over_time.csv")
            plot_text = read_text_from_tar(tf, "plot_data")
            stats_text = read_text_from_tar(tf, "fuzzer_stats")
    else:
        cov_text = read_text_from_dir(path, "cov_over_time.csv")
        plot_text = read_text_from_dir(path, "plot_data")
        stats_text = read_text_from_dir(path, "fuzzer_stats")

    metrics.l_abs, metrics.b_abs = parse_cov_text(cov_text)
    metrics.nodes, metrics.edges = parse_plot_text(plot_text)
    metrics.runtime_min, metrics.start_time, metrics.last_update = parse_fuzzer_stats(stats_text)
    status_meta = status_map.get(path.name, {})
    raw_exit = status_meta.get("exit_code", "")
    try:
        metrics.exit_code = int(raw_exit) if raw_exit else None
    except (ValueError, TypeError):
        metrics.exit_code = None
    raw_status = status_meta.get("status", "completed" if status_meta else "unknown")
    raw_reason = status_meta.get("reason", "")
    metrics.status = classify_status(metrics.exit_code, metrics.runtime_min, raw_reason, raw_status, timeout_min)
    metrics.invalid_reason = raw_reason
    metrics.diagnostics_dir = status_meta.get("diagnostics_dir", "")
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a per-run CSV summary from a results directory.")
    parser.add_argument("results_dir", help="Directory containing out-*.tar.gz files or extracted out-* folders")
    parser.add_argument("--output", "-o", help="Write CSV to this path instead of stdout")
    parser.add_argument("--include-invalid", action="store_true", help="Include stalled/invalid runs in the generated CSV")
    parser.add_argument("--timeout-min", type=int, default=None,
                        help="Expected campaign timeout in minutes. Used to distinguish "
                             "real OOM (exit 137 early) from timeout shutdown race "
                             "(exit 137 near timeout from 'timeout -k 2s').")
    args = parser.parse_args()

    timeout_min = args.timeout_min
    results_dir = Path(args.results_dir).resolve()
    if not results_dir.is_dir():
        raise SystemExit(f"results directory not found: {results_dir}")

    status_map = read_status_metadata(results_dir)

    rows = []
    for source in iter_sources(results_dir):
        metrics = read_metrics(source, status_map, timeout_min)
        if metrics is not None:
            if not args.include_invalid and metrics.status in INVALID_STATUSES:
                continue
            rows.append(metrics)

    rows.sort(key=lambda r: (r.subject, r.fuzzer, r.run, r.source))

    fieldnames = [
        "subject",
        "fuzzer",
        "run",
        "source",
        "runtime_min",
        "elapsed_min",
        "l_abs",
        "b_abs",
        "nodes",
        "edges",
        "start_time",
        "last_update",
        "status",
        "invalid_reason",
        "exit_code",
        "diagnostics_dir",
    ]

    output_stream = open(args.output, "w", newline="", encoding="utf-8") if args.output else None
    try:
        writer = csv.DictWriter(output_stream or os.sys.stdout, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "subject": row.subject,
                "fuzzer": row.fuzzer,
                "run": row.run,
                "source": row.source,
                "runtime_min": row.runtime_min if row.runtime_min is not None else "",
                "elapsed_min": row.runtime_min if row.runtime_min is not None else "",
                "l_abs": row.l_abs if row.l_abs is not None else "",
                "b_abs": row.b_abs if row.b_abs is not None else "",
                "nodes": row.nodes if row.nodes is not None else "",
                "edges": row.edges if row.edges is not None else "",
                "start_time": row.start_time if row.start_time is not None else "",
                "last_update": row.last_update if row.last_update is not None else "",
                "status": row.status,
                "invalid_reason": row.invalid_reason,
                "exit_code": row.exit_code if row.exit_code is not None else "",
                "diagnostics_dir": row.diagnostics_dir,
            })
    finally:
        if output_stream is not None:
            output_stream.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())