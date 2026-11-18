#!/usr/bin/env python3
"""Replay the latest 8x3 ProFTPD archives with the repaired coverage harness.

The campaign only reads the archived replayable corpus and queue ledger. It
does not invoke AFL or modify the source archives.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path, PurePosixPath


PROJECT = Path(__file__).resolve().parents[2]
ANALYSIS = PROJECT / "benchmark/scripts/analysis"
ARCHIVE_ROOT = PROJECT / "ablation"
OUTPUT = Path(os.environ.get("PROFTPD_REPLAY_OUTPUT", str(PROJECT / "ablation/q123_repair_smoke_20261114/proftpd_archive_replay_20261114")))
# Use the shared strict harness so this replay gets the LoopFuzz replayer ABI
# and frame-send ledger checks; retain an override for targeted diagnostics.
DEFAULT_COVERAGE_OVERRIDE = ANALYSIS / "coverage_v4.py"
COVERAGE_OVERRIDE = os.environ.get("PROFTPD_COVERAGE_SCRIPT", str(DEFAULT_COVERAGE_OVERRIDE))
REPLAYER_BINARY = os.environ.get("PROFTPD_REPLAYER_BINARY")
REPLAYER_CONTAINER_PATH = "/tmp/loopfuzz-replayer/aflnet-replay"
IMAGE = "proftpd:latest"
STEP = 16
DEFAULT_ARMS = {
    "pvstop1": "results-proftpd_ablation_pvstop1_20261114T170440",
    "salvage1": "results-proftpd_ablation_salvage1_20261114T173227",
    "nollm1": "results-proftpd_ablation_nollm1_20261114T175914",
    "wrapgate1": "results-proftpd_ablation_wrapgate1_20261114T181716",
    "native1": "results-proftpd_ablation_native1_20261114T183610",
    "calibrated1": "results-proftpd_ablation_calibrated1_20261114T185813",
    "cal_ewma1": "results-proftpd_ablation_cal_ewma1_20261114T191944",
    "cal_run_rate1": "results-proftpd_ablation_cal_run_rate1_20261114T194211",
}


def selected_arms() -> dict[str, str]:
    requested = os.environ.get("PROFTPD_ARMS")
    arm_names = list(DEFAULT_ARMS)
    if requested:
        arm_names = [name for name in (part.strip() for part in requested.split(",")) if name]
        unknown = sorted(set(arm_names) - set(DEFAULT_ARMS))
        if unknown:
            raise RuntimeError("unknown ProFTPD arms: " + ",".join(unknown))
    window_start = os.environ.get("PROFTPD_ARCHIVE_WINDOW_START")
    if not window_start:
        return {arm: DEFAULT_ARMS[arm] for arm in arm_names}
    selected = {}
    for arm in arm_names:
        candidates = []
        for result_dir in ARCHIVE_ROOT.glob(f"results-proftpd_ablation_{arm}_*"):
            timestamp = result_dir.name.rsplit("_", 1)[-1]
            if timestamp < window_start or len(list(result_dir.glob("out-proftpd-loopfuzz_*.tar.gz"))) != 3:
                continue
            if not (result_dir / "run_summary.csv").is_file():
                continue
            candidates.append(result_dir)
        if not candidates:
            raise RuntimeError(f"no complete three-repeat archive directory for {arm} after {window_start}")
        selected[arm] = max(candidates, key=lambda path: path.name).name
    return selected


ARMS = selected_arms()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_extract_corpus(archive: Path, destination: Path) -> list[dict]:
    root_name = "out-proftpd-loopfuzz/"
    queue_prefix = root_name + "replayable-queue/"
    destination.mkdir(parents=True)
    queue = destination / root_name / "replayable-queue"
    queue.mkdir(parents=True)
    records: list[dict] = []
    ledger_written = False
    with tarfile.open(archive, "r:gz") as source:
        names = source.getnames()
        if names.count(root_name + "queue-checkpoints.jsonl") != 1:
            raise RuntimeError(f"archive lacks one queue ledger: {archive}")
        for member in source.getmembers():
            if member.name == root_name + "queue-checkpoints.jsonl":
                if not member.isfile():
                    raise RuntimeError("queue ledger is not a regular file")
                extracted = source.extractfile(member)
                if extracted is None:
                    raise RuntimeError("cannot read queue ledger")
                target = destination / root_name / "queue-checkpoints.jsonl"
                target.write_bytes(extracted.read())
                ledger_written = True
            elif member.name.startswith(queue_prefix) and member.isfile():
                relative = member.name[len(queue_prefix):]
                if not relative or PurePosixPath(relative).name != relative or member.issym() or member.islnk():
                    raise RuntimeError(f"unsafe replay corpus member: {member.name}")
                extracted = source.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"cannot read corpus member: {member.name}")
                contents = extracted.read()
                target = queue / relative
                target.write_bytes(contents)
                records.append({"filename": relative, "size": len(contents),
                                "sha256": hashlib.sha256(contents).hexdigest()})
    if not ledger_written or not records:
        raise RuntimeError(f"empty archive corpus: {archive}")
    records.sort(key=lambda row: row["filename"])
    return records


def main() -> int:
    if OUTPUT.exists():
        raise SystemExit(f"refusing to overwrite existing replay output: {OUTPUT}")
    if REPLAYER_BINARY:
        binary = Path(REPLAYER_BINARY).resolve()
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise SystemExit(f"configured replayer is missing or not executable: {binary}")
    for path in (OUTPUT / "inputs", OUTPUT / "results", OUTPUT / "logs"):
        path.mkdir(parents=True, exist_ok=True)
    image_id = subprocess.check_output(
        ["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"], text=True
    ).strip()
    jobs = []
    for arm, dirname in ARMS.items():
        result_dir = ARCHIVE_ROOT / dirname
        archives = sorted(result_dir.glob("out-proftpd-loopfuzz_*.tar.gz"))
        if len(archives) != 3:
            raise RuntimeError(f"{arm} archive count is {len(archives)}, expected 3")
        for repeat, archive in enumerate(archives, 1):
            key = f"{arm}_run{repeat}"
            input_dir = OUTPUT / "inputs" / key
            result_path = OUTPUT / "results" / key
            result_path.mkdir(parents=True)
            corpus = safe_extract_corpus(archive, input_dir)
            log_path = OUTPUT / "logs" / f"{key}.docker.log"
            out_csv = "/result/cov_over_time.csv"
            command = [
                "docker", "run", "--rm", "--name", "proftpd_cov_" + key,
                "--cpus=0.75", "--memory=1g", "--memory-swap=1536m",
                "-v", f"{input_dir}:/corpus:ro",
                "-v", f"{result_path}:/result",
                "-v", f"{ANALYSIS}:/tmp/coverage-v4-src:ro",
                *( ["-v", f"{COVERAGE_OVERRIDE}:/tmp/coverage-v4-src/coverage_v4.py:ro"] if COVERAGE_OVERRIDE else [] ),
                *( ["-v", f"{Path(REPLAYER_BINARY).resolve()}:{REPLAYER_CONTAINER_PATH}:ro"] if REPLAYER_BINARY else [] ),
                "-e", "WORKDIR=/home/ubuntu/experiments",
                "-e", 'COVERAGE_V4_RESET_COMMAND_JSON=["bash","/tmp/coverage-v4-src/reset_commands/proftpd.sh"]',
                *( ["-e", f"COVERAGE_V4_LOOPFUZZ_REPLAYER={REPLAYER_CONTAINER_PATH}"] if REPLAYER_BINARY else [] ),
                IMAGE, "/bin/bash", "-lc",
                "cd /home/ubuntu/experiments/proftpd-gcov && "
                "python3 /tmp/coverage-v4-src/coverage_v4.py replay "
                "--target proftpd --folder /corpus/out-proftpd-loopfuzz "
                f"--port 21 --step {STEP} --sampled-checkpoints "
                f"--output {out_csv} --mode 1 --require-coordinates && "
                f"python3 /tmp/coverage-v4-src/coverage_v4.py audit {out_csv}"
            ]
            jobs.append({
                "key": key, "arm": arm, "repeat": repeat,
                "source_result_dir": str(result_dir), "archive": str(archive),
                "archive_sha256": sha256(archive), "input_dir": str(input_dir),
                "corpus_count": len(corpus), "corpus_sha256": hashlib.sha256(
                    "\n".join(row["sha256"] for row in corpus).encode()
                ).hexdigest(),
                "input_manifest": corpus, "result_dir": str(result_path),
                "log": str(log_path), "command": command,
            })

    manifest = {
        "schema": "proftpd-archive-replay-batch-v1",
        "target": "proftpd", "image": IMAGE, "image_id": image_id,
        "coverage_harness": str(ANALYSIS / "coverage_v4.py"),
        "replay_harness_version": "20261116b-frame-ledger-strict-proptpd-v4-pureftpd-sm-v1",
        "loopfuzz_replayer": ({"host_path": str(Path(REPLAYER_BINARY).resolve()),
                               "sha256": sha256(Path(REPLAYER_BINARY).resolve())}
                              if REPLAYER_BINARY else None),
        "checkpoint_step": STEP,
        "checkpoint_policy": "sample every 16 inputs, plus terminal and seed boundary; replay ledger covers every corpus input",
        "archive_window_start": os.environ.get("PROFTPD_ARCHIVE_WINDOW_START"),
        "max_parallel_jobs": max(1, int(os.environ.get("PROFTPD_REPLAY_PARALLEL", "4"))),
        "jobs": [],
    }
    (OUTPUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    def replay_job(job: dict) -> dict:
        log_stream = open(job["log"], "wb")
        started = time.monotonic()
        try:
            code = subprocess.run(job["command"], stdout=log_stream,
                                  stderr=subprocess.STDOUT, check=False).returncode
        except OSError as error:
            code = 127
            log_stream.write((str(error) + "\n").encode())
        finally:
            log_stream.close()
        elapsed = round(time.monotonic() - started, 1)
        result = {key: value for key, value in job.items() if key != "command"}
        result.update(exit_code=code, elapsed_seconds=elapsed,
                      output_csv=str(Path(job["result_dir"]) / "cov_over_time.csv"),
                      sampled_artifacts=str(Path(job["result_dir"]) / "cov_over_time.csv.v5"))
        return result

    parallel = manifest["max_parallel_jobs"]
    print(f"START batch jobs={len(jobs)} max_parallel={parallel}", flush=True)
    with ThreadPoolExecutor(max_workers=parallel) as executor:
        futures = {executor.submit(replay_job, job): job for job in jobs}
        for future in as_completed(futures):
            job_result = future.result()
            manifest["jobs"].append(job_result)
            manifest["jobs"].sort(key=lambda row: row["key"])
            (OUTPUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
            print(f"DONE {job_result['key']} exit={job_result['exit_code']} elapsed={job_result['elapsed_seconds']}s", flush=True)

    manifest["jobs"].sort(key=lambda row: row["key"])
    manifest["completed"] = all(row["exit_code"] == 0 for row in manifest["jobs"])
    manifest["completed_count"] = sum(row["exit_code"] == 0 for row in manifest["jobs"])
    (OUTPUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"BATCH completed={manifest['completed_count']}/{len(jobs)} output={OUTPUT}", flush=True)
    return 0 if manifest["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
