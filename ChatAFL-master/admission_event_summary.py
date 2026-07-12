#!/usr/bin/env python3
"""Summarize LoopFuzz admission-events.jsonl files.

Accepts result directories, extracted fuzzer output directories, JSONL files,
or tar.gz archives. The script uses only the JSONL ledger emitted by LoopFuzz,
so it does not replay targets or require the benchmark containers.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tarfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Tuple


def iter_jsonl_from_path(path: Path) -> Iterator[Tuple[str, str]]:
    if path.is_file() and path.name.endswith(".tar.gz"):
        try:
            with tarfile.open(path, "r:gz") as tf:
                for member in tf.getmembers():
                    if member.name.endswith("admission-events.jsonl"):
                        fh = tf.extractfile(member)
                        if fh is None:
                            continue
                        for raw in fh:
                            yield f"{path}:{member.name}", raw.decode("utf-8", "replace")
        except tarfile.TarError as exc:
            print(f"[warn] cannot read tarball {path}: {exc}", file=sys.stderr)
        return

    if path.is_file() and path.name == "admission-events.jsonl":
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                yield str(path), line
        return

    if path.is_dir():
        for jsonl in path.rglob("admission-events.jsonl"):
            with jsonl.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    yield str(jsonl), line
        for tarball in path.rglob("*.tar.gz"):
            yield from iter_jsonl_from_path(tarball)


def infer_target(source: str, event: Dict[str, object]) -> str:
    request_path = str(event.get("request_path", ""))
    lower = source.lower()
    if "forked-daapd" in lower or request_path.startswith(("/ctrl-int", "/databases", "/login", "/update")):
        return "forked-daapd"
    for token in (
        "lightftp",
        "bftpd",
        "proftpd",
        "pure-ftpd",
        "exim",
        "live555",
        "kamailio",
        "lighttpd1",
        "mosquitto",
    ):
        if token in lower:
            return token
    return "unknown"


def summarize(paths: Iterable[Path]) -> List[Dict[str, object]]:
    groups: Dict[Tuple[str, str, str], Dict[str, object]] = {}
    edge_sets: Dict[Tuple[str, str, str], set] = defaultdict(set)
    daap_paths: Dict[Tuple[str, str, str], Counter] = defaultdict(Counter)

    for path in paths:
        for source, line in iter_jsonl_from_path(path):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"[warn] malformed JSONL in {source}", file=sys.stderr)
                continue

            target = infer_target(source, event)
            no_admission = "1" if event.get("no_admission") else "0"
            event_source = str(event.get("source", "unknown"))
            key = (target, no_admission, event_source)
            row = groups.setdefault(
                key,
                {
                    "target": target,
                    "no_admission": no_admission,
                    "source": event_source,
                    "events": 0,
                    "p_pass": 0,
                    "u_pass": 0,
                    "r_pass": 0,
                    "g_pass": 0,
                    "native_promoted": 0,
                    "forced_promoted": 0,
                    "productive_edge_events": 0,
                    "state_progress_no_gain": 0,
                    "avg_latency_ms": 0.0,
                },
            )

            row["events"] += 1
            for field in ("p_pass", "u_pass", "r_pass", "g_pass", "native_promoted", "forced_promoted"):
                if event.get(field):
                    row[field] += 1

            row["avg_latency_ms"] += float(event.get("latency_ms") or 0.0)

            edge_delta = int(event.get("ipsm_edges_delta") or 0)
            if event.get("g_pass") and edge_delta > 0:
                row["productive_edge_events"] += 1
                edge_seq = str(event.get("edge_sequence", ""))
                if edge_seq:
                    edge_sets[key].add(edge_seq)

            if event.get("r_pass") and not event.get("g_pass"):
                row["state_progress_no_gain"] += 1

            if target == "forked-daapd":
                req_path = str(event.get("request_path", ""))
                if req_path:
                    daap_paths[key][req_path] += 1

    rows: List[Dict[str, object]] = []
    for key, row in groups.items():
        events = int(row["events"])
        if events:
            row["avg_latency_ms"] = round(float(row["avg_latency_ms"]) / events, 3)
        row["unique_productive_edge_sequences"] = len(edge_sets[key])
        row["top_daap_paths"] = ";".join(
            f"{path}:{count}" for path, count in daap_paths[key].most_common(8)
        )
        rows.append(row)

    rows.sort(key=lambda r: (str(r["target"]), str(r["no_admission"]), str(r["source"])))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="Result dirs, output dirs, JSONL files, or tar.gz archives")
    parser.add_argument("-o", "--output", type=Path, help="Write CSV summary to this path")
    args = parser.parse_args()

    fieldnames = [
        "target",
        "no_admission",
        "source",
        "events",
        "p_pass",
        "u_pass",
        "r_pass",
        "g_pass",
        "native_promoted",
        "forced_promoted",
        "productive_edge_events",
        "unique_productive_edge_sequences",
        "state_progress_no_gain",
        "avg_latency_ms",
        "top_daap_paths",
    ]

    out_fh = args.output.open("w", newline="", encoding="utf-8") if args.output else sys.stdout
    try:
        writer = csv.DictWriter(out_fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in summarize(args.paths):
            writer.writerow({name: row.get(name, "") for name in fieldnames})
    finally:
        if args.output:
            out_fh.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
