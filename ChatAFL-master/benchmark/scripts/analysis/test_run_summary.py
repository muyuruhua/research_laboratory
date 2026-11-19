#!/usr/bin/env python3
"""CLI regression tests for run_summary record retention."""

from __future__ import annotations

import csv
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("run_summary.py")


def write_archive(results: Path, run: int, status: str, reason: str) -> str:
    archive_name = f"out-bftpd-loopfuzz_{run}.tar.gz"
    archive_path = results / archive_name
    members = {
        "run/fuzzer_stats": "start_time : 1000\nlast_update : 1600\n",
        "run/cov_over_time.csv": "time,elapsed,l_abs,l_pct,b_abs,b_pct\n0,0,10,50,4,40\n",
        "run/plot_data": "header\n" + ",".join(["0"] * 11 + ["7", "9"]) + "\n",
    }
    with tarfile.open(archive_path, "w:gz") as tf:
        for name, value in members.items():
            payload = value.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))

    status_dir = results / ".sample_status"
    status_dir.mkdir(exist_ok=True)
    (status_dir / f"{archive_name}.status").write_text(
        f"archive_name={archive_name}\nstatus={status}\nreason={reason}\nexit_code=0\n",
        encoding="utf-8",
    )
    return archive_name


class RunSummaryRecordRetentionTest(unittest.TestCase):
    def test_default_keeps_all_attempts_and_valid_only_keeps_completed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            results = Path(temp)
            write_archive(results, 1, "failed", "coverage_incomplete")
            write_archive(results, 2, "oom_killed", "oom_killed")
            write_archive(results, 3, "completed", "completed")

            all_output = results / "all.csv"
            subprocess.run(
                [sys.executable, str(SCRIPT), str(results), "--output", str(all_output)],
                check=True,
            )
            with all_output.open(newline="", encoding="utf-8") as stream:
                all_rows = list(csv.DictReader(stream))

            self.assertEqual([row["run"] for row in all_rows], ["1", "2", "3"])
            self.assertEqual(all_rows[0]["status"], "failed")
            self.assertEqual(all_rows[0]["invalid_reason"], "coverage_incomplete")
            self.assertEqual(all_rows[0]["l_abs"], "10")
            self.assertEqual(all_rows[0]["b_abs"], "4")
            self.assertEqual(all_rows[1]["status"], "oom_killed")

            legacy_output = results / "legacy-include-invalid.csv"
            subprocess.run(
                [sys.executable, str(SCRIPT), str(results), "--include-invalid",
                 "--output", str(legacy_output)],
                check=True,
            )
            with legacy_output.open(newline="", encoding="utf-8") as stream:
                legacy_rows = list(csv.DictReader(stream))
            self.assertEqual(len(legacy_rows), 3)

            valid_output = results / "valid.csv"
            subprocess.run(
                [sys.executable, str(SCRIPT), str(results), "--valid-only",
                 "--output", str(valid_output)],
                check=True,
            )
            with valid_output.open(newline="", encoding="utf-8") as stream:
                valid_rows = list(csv.DictReader(stream))

            self.assertEqual([row["run"] for row in valid_rows], ["3"])
            self.assertEqual(valid_rows[0]["status"], "completed")


if __name__ == "__main__":
    unittest.main()
