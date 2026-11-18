import unittest

import audit_q2_pairs as audit


def make_repeat(role, repeat=1, *, budget=5000, root_cap=64, dose=64, count=10,
                config_marker="same", campaign_complete=True, lifecycle=True):
    is_salvage = role == "salvage"
    q2 = {
        "salvage_admitted_roots": count if is_salvage else 0,
        "admitted_roots": count,
        "ordinary_match_admitted_roots": 0 if is_salvage else count,
    }
    report = {
        "telemetry_consistency_status": "consistent",
        "required_but_missing_telemetry_files": [],
        "Q2_provisional_productivity_and_salvage": q2,
    }
    cfg = {
        "target": "bftpd",
        "campaign_call_budget": budget,
        "provisional_budget": root_cap,
        "provisional_budget_scope": "per-root",
        "salvage_enabled": True,
        "ordinary_budget": not is_salvage,
        "ordinary_rate": "1.0000" if not is_salvage else None,
        "shared": config_marker,
    }
    return {
        "path": f"{role}-{repeat}",
        "repeat_index": repeat,
        "repeat_index_matches_expected": True,
        "errors": {},
        "report": report,
        "config": cfg,
        "stats": {
            "campaign_call_budget": budget,
            "campaign_charged_calls": budget if campaign_complete else budget - 1,
            "campaign_budget_exhausted": 1 if campaign_complete else 0,
        },
        "end_config": {"phase": "end", "termination_reason": "campaign-call-budget" if campaign_complete else "wall-clock-limit"},
        "local_lifecycle_ok": lifecycle,
        "cohort_classification_errors": [],
        "campaign_complete": campaign_complete,
        "linked_positive_doses": {
            "provisional": [dose] * count if is_salvage else [],
            "ordinary-match": [dose] * count if not is_salvage else [],
        },
    }


class LinkedDoseTests(unittest.TestCase):
    def test_q2_outcome_uses_linked_beyond_baseline_slots_per_descendant_call(self):
        data = {
            "provisional-events.jsonl": [
                {"kind": "admit", "candidate_id": 1, "queue_entry": 7, "ordinary_match": False},
                {"kind": "convert", "candidate_id": 1, "queue_entry": 7, "descendant_execs": 5},
                {"kind": "admit", "candidate_id": 2, "queue_entry": 8, "ordinary_match": False},
                {"kind": "expire", "candidate_id": 2, "queue_entry": 8, "descendant_execs": 5},
            ],
            "productivity-events.jsonl": [
                {"candidate_id": 1, "root_queue_id": 7, "cohort": "provisional", "outcome": "convert",
                 "descendant_invocations": 5, "baseline_valid": True, "conversion_class": 2,
                 "beyond_baseline_slots": 3},
                {"candidate_id": 2, "root_queue_id": 8, "cohort": "provisional", "outcome": "expire",
                 "descendant_invocations": 5, "baseline_valid": True, "conversion_class": 0,
                 "beyond_baseline_slots": 0},
            ],
        }
        outcomes, complete = audit._linked_positive_q2_outcomes(data, True)
        self.assertTrue(complete)
        summary = audit._q2_outcome_summary(outcomes["provisional"])
        self.assertEqual(summary["descendant_calls"], 10)
        self.assertEqual(summary["beyond_baseline_bitmap_slots"], 3)
        self.assertEqual(summary["beyond_baseline_bitmap_slots_per_1000_descendant_calls"], 300.0)

    def test_q2_outcome_missing_baseline_gain_fields_fails_closed(self):
        data = {
            "provisional-events.jsonl": [
                {"kind": "admit", "candidate_id": 1, "queue_entry": 7, "ordinary_match": False},
                {"kind": "convert", "candidate_id": 1, "queue_entry": 7, "descendant_execs": 5},
            ],
            "productivity-events.jsonl": [{
                "candidate_id": 1, "root_queue_id": 7, "cohort": "provisional", "outcome": "convert",
                "descendant_invocations": 5, "baseline_valid": True,
            }],
        }
        outcomes, complete = audit._linked_positive_q2_outcomes(data, True)
        self.assertFalse(complete)
        self.assertEqual(outcomes["provisional"], [])

    def test_q2_outcome_rejects_conversion_class_slot_disagreement(self):
        data = {
            "provisional-events.jsonl": [
                {"kind": "admit", "candidate_id": 1, "queue_entry": 7, "ordinary_match": False},
                {"kind": "convert", "candidate_id": 1, "queue_entry": 7, "descendant_execs": 5},
            ],
            "productivity-events.jsonl": [{
                "candidate_id": 1, "root_queue_id": 7, "cohort": "provisional", "outcome": "convert",
                "descendant_invocations": 5, "baseline_valid": True, "conversion_class": 0,
                "beyond_baseline_slots": 1,
            }],
        }
        outcomes, complete = audit._linked_positive_q2_outcomes(data, True)
        self.assertFalse(complete)
        self.assertEqual(outcomes["provisional"], [])

    def test_only_uniquely_linked_positive_matching_roots_count(self):
        data = {
            "provisional-events.jsonl": [
                {"kind": "admit", "candidate_id": 1, "queue_entry": 7, "ordinary_match": False},
                {"kind": "convert", "candidate_id": 1, "queue_entry": 7, "descendant_execs": 4},
                {"kind": "admit", "candidate_id": 2, "queue_entry": 8, "ordinary_match": True},
                {"kind": "ordinary-close", "candidate_id": 2, "queue_entry": 8, "descendant_execs": 0},
            ],
            "productivity-events.jsonl": [
                {"candidate_id": 1, "root_queue_id": 7, "cohort": "provisional", "outcome": "convert", "descendant_invocations": 4},
                {"candidate_id": 2, "root_queue_id": 8, "cohort": "ordinary_match", "outcome": "ordinary-close", "descendant_invocations": 0},
                # A duplicated row makes this identity non-unique and must exclude it.
                {"candidate_id": 1, "root_queue_id": 7, "cohort": "provisional", "outcome": "convert", "descendant_invocations": 4},
            ],
        }
        self.assertEqual(
            audit._linked_positive_doses(data, True),
            {"provisional": [], "ordinary-match": []},
        )

    def test_underscore_spelling_is_accepted_and_zero_dose_excluded(self):
        data = {
            "provisional-events.jsonl": [
                {"kind": "admit", "candidate_id": 3, "queue_entry": 9, "ordinary_match": True},
                {"kind": "ordinary-close", "candidate_id": 3, "queue_entry": 9, "descendant_execs": 5},
                {"kind": "admit", "candidate_id": 4, "queue_entry": 10, "ordinary_match": True},
                {"kind": "ordinary-close", "candidate_id": 4, "queue_entry": 10, "descendant_execs": 0},
            ],
            "productivity-events.jsonl": [
                {"candidate_id": 3, "root_queue_id": 9, "cohort": "ordinary_match", "outcome": "ordinary-close", "descendant_invocations": 5},
                {"candidate_id": 4, "root_queue_id": 10, "cohort": "ordinary-match", "outcome": "ordinary-close", "descendant_invocations": 0},
            ],
        }
        self.assertEqual(
            audit._linked_positive_doses(data, True),
            {"provisional": [], "ordinary-match": [5]},
        )

    def test_cohort_alias_and_admission_flag_must_agree(self):
        data = {
            "provisional-events.jsonl": [
                {"kind": "admit", "candidate_id": 5, "queue_entry": 11, "ordinary_match": True},
                {"kind": "ordinary-close", "candidate_id": 5, "queue_entry": 11, "descendant_execs": 5},
            ],
            "productivity-events.jsonl": [{
                "candidate_id": 5, "root_queue_id": 11, "cohort": "ordinary_match",
                "outcome": "ordinary-close", "descendant_invocations": 5,
            }],
        }
        self.assertEqual(audit._cohort_classification_errors(data), [])
        data["provisional-events.jsonl"][0]["ordinary_match"] = False
        self.assertEqual(audit._cohort_classification_errors(data), ["candidate_id=5,root_queue_id=11"])


class PairGateTests(unittest.TestCase):
    def test_pair_ready_with_matching_caps_and_dose(self):
        result = audit._pair_repeat(
            1, make_repeat("salvage"), make_repeat("ordinary"),
        )
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["median_descendant_dose_ratio_salvage_over_ordinary_match"], 1.0)

    def test_configuration_or_root_cap_mismatch_unresolves_pair(self):
        result = audit._pair_repeat(
            1,
            make_repeat("salvage", config_marker="changed"),
            make_repeat("ordinary", root_cap=32),
        )
        self.assertEqual(result["status"], "unresolved")
        self.assertFalse(result["gates"]["shared_configuration_matches"])
        self.assertFalse(result["gates"]["per_root_provisional_cap_matches"])

    def test_each_arm_needs_ten_linked_positive_roots(self):
        result = audit._pair_repeat(
            1, make_repeat("salvage", count=9), make_repeat("ordinary"),
        )
        self.assertFalse(result["gates"]["at_least_10_positive_linked_roots_in_each_arm"])
        self.assertEqual(result["status"], "unresolved")

    def test_linked_root_dose_cannot_exceed_configured_cap(self):
        result = audit._pair_repeat(
            1, make_repeat("salvage", dose=65), make_repeat("ordinary"),
        )
        self.assertFalse(result["gates"]["linked_root_doses_within_provisional_cap"])
        self.assertEqual(result["status"], "unresolved")

    def test_median_dose_ratio_is_checked_inclusive_of_boundary(self):
        result = audit._pair_repeat(
            1, make_repeat("salvage", dose=80), make_repeat("ordinary", dose=100),
        )
        self.assertEqual(result["median_descendant_dose_ratio_salvage_over_ordinary_match"], 0.8)
        self.assertTrue(result["gates"]["median_descendant_dose_ratio_0.80_to_1.25"])
        outside = audit._pair_repeat(
            1, make_repeat("salvage", dose=79), make_repeat("ordinary", dose=100),
        )
        self.assertFalse(outside["gates"]["median_descendant_dose_ratio_0.80_to_1.25"])

    def test_campaign_must_reach_configured_cap(self):
        result = audit._pair_repeat(
            1,
            make_repeat("salvage", campaign_complete=False),
            make_repeat("ordinary"),
        )
        self.assertFalse(result["gates"]["campaign_cap_reached_in_both_arms"])
        self.assertEqual(result["status"], "unresolved")

    def test_all_six_repeats_must_share_configuration_and_caps(self):
        runs = [
            make_repeat("salvage", repeat=1),
            make_repeat("salvage", repeat=2),
            make_repeat("salvage", repeat=3),
            make_repeat("ordinary", repeat=1),
            make_repeat("ordinary", repeat=2),
            make_repeat("ordinary", repeat=3),
        ]
        self.assertTrue(all(audit._all_repeat_gates(runs).values()))
        runs[-1]["config"]["provisional_budget"] = 32
        self.assertFalse(audit._all_repeat_gates(runs)["all_six_runs_share_per_root_provisional_cap"])


if __name__ == "__main__":
    unittest.main()
