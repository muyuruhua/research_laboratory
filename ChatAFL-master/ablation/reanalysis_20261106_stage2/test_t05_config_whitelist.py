#!/usr/bin/env python3
"""Archive-level contract tests for the Q3 configuration whitelist."""

from __future__ import annotations

import json
import sys
import tarfile
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from t05_config_whitelist import ARMS, EXPECTED, audit


def _config(arm: str, run: int, *, changed_budget: int | None = None) -> dict:
    estimator, override, calibration = EXPECTED[arm]
    cfg = {
        "event": "run_config", "phase": "start", "target": "bftpd",
        "fuzzer": "loopfuzz", "arm": arm, "run_id": "out-bftpd-loopfuzz",
        "campaign_id": f"campaign-{arm}-{run}", "config_hash": f"hash-{arm}-{run}",
        "rng_seed": 1000 + run * 10 + ARMS.index(arm),
        "afl_rng_seed": 2000 + run * 10 + ARMS.index(arm),
        "seeds_sha256": "seed-hash", "fuzzer_sha256": "fuzzer-hash",
        "target_sha256": "target-hash", "image_digest": "image-digest",
        "campaign_call_budget": changed_budget or 17000, "call_cap": 64,
        "episode_energy_cap": 64, "episode_energy_semantics": "mutation-only",
        "code_reward_semantics": "new-edge-only", "scheduler_warmup_max_selections": 8,
        "scheduler_warmup_policy": "fixed-test", "admission_mode": "gate",
        "provisional_enabled": True, "provisional_budget": 64,
        "provisional_ttl_ms": 600000, "plaintext_wrap_enabled": True,
        "no_adaptive": True, "no_frontier": False, "no_llm": False,
        "shadow_enabled": True, "trial_mode_admission": False, "q1_policy": "none",
        "threshold_mode": "fixed", "threshold_requested": 1,
        "threshold_resolved": 1, "cal_estimator": estimator,
        "calibration": calibration, "state_select_override": override,
        "cal_ewma_alpha": 0.05, "cal_shrink_kappa": 8.0,
        "pid": 3000 + run, "start_time_ms": 100000 + run,
        "end_time_ms": 0, "monotonic_ms": 500000 + run,
    }
    return cfg


class T05WhitelistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.index = {"runs": []}
        self.configs: dict[tuple[str, int], dict] = {}
        for run in range(3):
            for arm in ARMS:
                cfg = _config(arm, run)
                archive = self.root / f"{arm}-{run}.tar.gz"
                payload = (json.dumps(cfg, sort_keys=True) + "\n").encode()
                with tarfile.open(archive, "w:gz") as tf:
                    info = tarfile.TarInfo("out-bftpd-loopfuzz/run-config.jsonl")
                    info.size = len(payload)
                    tf.addfile(info, BytesIO(payload))
                self.configs[(arm, run)] = cfg
                self.index["runs"].append({
                    "arm": arm, "archive": str(archive),
                    "campaign_id": cfg["campaign_id"],
                    "container_id": f"container-{arm}-{run}",
                })
        self.index_path = self.root / "index.json"
        self._write_index()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_index(self) -> None:
        self.index_path.write_text(json.dumps(self.index), encoding="utf-8")

    def test_scorer_only_changes_pass_for_all_three_repeats(self) -> None:
        result = audit(self.index_path)
        self.assertEqual(result["status"], "PASS", result["errors"])
        self.assertEqual(result["counts"], {arm: 3 for arm in ARMS})

    def test_non_scorer_change_in_any_repeat_fails(self) -> None:
        item = next(x for x in self.index["runs"] if x["arm"] == "cal_ewma8" and "-2.tar.gz" in x["archive"])
        cfg = self.configs[("cal_ewma8", 2)]
        cfg["campaign_call_budget"] = 16000
        archive = Path(item["archive"])
        payload = (json.dumps(cfg, sort_keys=True) + "\n").encode()
        with tarfile.open(archive, "w:gz") as tf:
            info = tarfile.TarInfo("out-bftpd-loopfuzz/run-config.jsonl")
            info.size = len(payload)
            tf.addfile(info, BytesIO(payload))
        result = audit(self.index_path)
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any("within-arm drift" in error for error in result["errors"]))
        self.assertTrue(any("Q3 invariant mismatch" in error for error in result["errors"]))

    def test_missing_run_identity_fails_closed(self) -> None:
        self.index["runs"][0].pop("container_id")
        self._write_index()
        result = audit(self.index_path)
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any("container_id" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
