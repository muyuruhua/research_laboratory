#!/usr/bin/env python3
"""Rerun only ProFTPD Q1d repeat 3 with time reserved for finalization."""

import datetime as dt
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NOTES = Path(__file__).resolve().parent
SOURCE = "ff14905a3e9b6f41a2187e2f39d2d5b5a493d68a4532116f04cfb2ea696abbfa"
FUZZ_SECONDS = 600
TOTAL_SECONDS = 900


def docker(*args, **kwargs):
    return subprocess.check_output(["docker", *args], text=True, **kwargs).strip()


def main():
    original = json.loads(docker("inspect", SOURCE))[0]
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = NOTES / ("q1d_repeat3_repair_" + stamp)
    output.mkdir()
    env = dict(item.split("=", 1) for item in original["Config"]["Env"])
    campaign = "lf-" + hashlib.sha256((SOURCE + stamp).encode()).hexdigest()[:32]
    env["CHATAFL_CAMPAIGN_ID"] = campaign
    env["AFL_NO_UI"] = "1"
    # Keep the failed repeat's RNG and every experimental control.  The
    # shorter runtime is explicit and does not create a matched-dose result.
    assert env["CHATAFL_MOCK_LLM"] == "1"
    assert env["CHATAFL_Q1_REFLOW"] == "1"
    assert env["CHATAFL_CODE_RETAIN"] == "1"
    assert env["COVERAGE_V4_SMOKE"] == "1"
    assert env["COVERAGE_V4_MAX_REPLAY_INPUTS"] == "32"
    cmd = list(original["Config"]["Cmd"])
    cmd[-1], changed = re.subn(r" 900 500;", f" {FUZZ_SECONDS} 500;", cmd[-1])
    assert changed == 1, "original fuzz invocation changed; review before launching"
    name = "proftpd-q1d-repeat3-repair-" + stamp.lower()
    create = ["create", "--name", name, "--cpus=1", "--memory=2g",
              "--memory-swap=2g", "--cap-add=SYS_PTRACE",
              "--security-opt=seccomp=unconfined"]
    for key, value in env.items():
        create.extend(["--env", key + "=" + value])
    for mount in original["Mounts"]:
        assert mount["Type"] == "bind" and not mount["RW"]
        create.extend(["--volume", mount["Source"] + ":" + mount["Destination"] + ":ro"])
    container = docker(*create, original["Image"], *cmd)
    manifest = {
        "schema": "q1d-repeat-repair-v1", "target": "proftpd", "arm": "q1d1",
        "repeat": 3, "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_container": SOURCE, "container_id": container, "container_name": name,
        "campaign_id": campaign, "rng_seed": env["CHATAFL_RNG_SEED"],
        "image_id": original["Image"], "fuzz_timeout_seconds": FUZZ_SECONDS,
        "total_timeout_seconds": TOTAL_SECONDS, "cpus": 1, "memory_bytes": 2 * 1024**3,
        "classification": "time-limited integrity smoke; independent replacement attempt",
        "original_archive": "ablation/results-proftpd_ablation_q1d1_20261117T020935/out-proftpd-loopfuzz_3.tar.gz",
        "original_archive_sha256": hashlib.sha256((ROOT / "ablation/results-proftpd_ablation_q1d1_20261117T020935/out-proftpd-loopfuzz_3.tar.gz").read_bytes()).hexdigest(),
        "runtime_changed_from_seconds": 900,
        "result_merged_with_original": False,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"event": "created", "output": str(output), "container_id": container}), flush=True)
    started = time.monotonic()
    docker("start", container)
    deadline_reached = False
    while True:
        state = json.loads(docker("inspect", container, "--format", "{{json .State}}"))
        elapsed = time.monotonic() - started
        (output / "progress.json").write_text(json.dumps({"elapsed_seconds": round(elapsed, 1),
                                                          "state": state}, indent=2) + "\n")
        if not state["Running"]:
            break
        if elapsed >= TOTAL_SECONDS - 15:
            deadline_reached = True
            docker("stop", "--time", "10", container)
            state = json.loads(docker("inspect", container, "--format", "{{json .State}}"))
            break
        time.sleep(5)
    with (output / "container.log").open("w") as stream:
        subprocess.run(["docker", "logs", container], stdout=stream, stderr=subprocess.STDOUT, check=False)
    copied = {}
    for source, filename in [
        ("/home/ubuntu/experiments/out-proftpd-loopfuzz.tar.gz", "out-proftpd-loopfuzz_3.tar.gz"),
        ("/tmp/loopfuzz_mock_stats.json", "out-proftpd-loopfuzz_3.mock-stats.json"),
    ]:
        result = subprocess.run(["docker", "cp", container + ":" + source, str(output / filename)],
                                capture_output=True, text=True)
        copied[filename] = {"ok": result.returncode == 0,
                            "error": result.stderr.strip() if result.returncode else None}
    final = {"state": state, "deadline_reached": deadline_reached,
             "elapsed_seconds": round(time.monotonic() - started, 1), "artifacts": copied}
    (output / "completion.json").write_text(json.dumps(final, indent=2) + "\n")
    print(json.dumps({"event": "finished", "output": str(output), **final}), flush=True)
    return 0 if state["ExitCode"] == 0 and not deadline_reached and all(row["ok"] for row in copied.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
