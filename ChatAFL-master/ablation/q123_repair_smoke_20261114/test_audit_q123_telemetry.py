#!/usr/bin/env python3
"""Focused regression tests for Q1–Q3 telemetry counting semantics."""

import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_q123_telemetry as audit  # noqa: E402
import audit_smoke  # noqa: E402


class Q123TelemetryTests(unittest.TestCase):
    def test_reset_audit_separates_executed_failures_from_refused_terminal_cancellation(self):
        executions = [
            {"event": "invocation_start", "attempt_id": 2, "invocation_id": 1,
             "execution_id_before": 0, "executed": True},
            {"event": "invocation_end", "attempt_id": 2, "invocation_id": 1,
             "execution_id_after": 1, "executed": True},
            {"event": "invocation_start", "attempt_id": 3, "invocation_id": 2,
             "execution_id_before": 1, "executed": True},
            {"event": "invocation_end", "attempt_id": 3, "invocation_id": 2,
             "execution_id_after": 2, "executed": True},
            {"event": "invocation_refused", "attempt_id": 4, "executed": False,
             "fault": "resource-limit-not-executed"},
        ]
        resets = [
            {"attempt_id": 1, "stage": "pre-forkserver", "execution_id": 0,
             "success": True, "cancelled": False},
            {"attempt_id": 3, "stage": "invocation", "execution_id": 1,
             "success": True, "cancelled": False},
            {"attempt_id": 4, "stage": "invocation", "execution_id": 2,
             "success": False, "cancelled": True, "system_status": 15},
        ]
        result = audit_smoke.audit_resets(resets, executions, "signal-or-timeout")
        self.assertTrue(result["eligible"])
        self.assertEqual(result["terminal_refused_attempt_cancellations"], 1)
        self.assertEqual(result["executed_invocation_reset_failures"], 0)

        resets[1]["success"] = False
        result = audit_smoke.audit_resets(resets, executions, "signal-or-timeout")
        self.assertFalse(result["eligible"])
        self.assertEqual(result["executed_invocation_reset_failures"], 1)

    def test_reset_audit_rejects_missing_pre_reset_for_executed_invocation(self):
        result = audit_smoke.audit_resets(
            [],
            [
                {"event": "invocation_start", "attempt_id": 11, "invocation_id": 1,
                 "execution_id_before": 0, "executed": True},
                {"event": "invocation_end", "attempt_id": 11, "invocation_id": 1,
                 "execution_id_after": 1, "executed": True},
            ],
            "campaign-budget-exhausted",
        )
        self.assertFalse(result["eligible"])
        self.assertFalse(result["all_executed_invocations_reset"])
        self.assertEqual(result["executed_invocations_missing_invocation_reset"], 1)
        self.assertEqual(result["missing_invocation_reset_attempt_ids"], [11])
        self.assertEqual(result["executed_invocations_with_exactly_one_successful_pre_reset"], 0)

    def test_reset_audit_rejects_duplicate_successful_resets_for_invocation(self):
        executions = [
            {"event": "invocation_start", "attempt_id": 12, "invocation_id": 1,
             "execution_id_before": 0, "executed": True},
            {"event": "invocation_end", "attempt_id": 12, "invocation_id": 1,
             "execution_id_after": 1, "executed": True},
        ]
        reset = {"attempt_id": 1, "stage": "pre-forkserver", "execution_id": 0,
                 "success": True, "cancelled": False}
        result = audit_smoke.audit_resets([reset.copy(), reset.copy()], executions, "campaign-budget-exhausted")
        self.assertFalse(result["eligible"])
        self.assertFalse(result["all_executed_invocations_reset"])
        self.assertEqual(result["duplicate_invocation_reset_counts_by_attempt"], {12: 2})
        self.assertEqual(result["executed_invocations_with_exactly_one_successful_pre_reset"], 0)

    def test_reset_audit_rejects_missing_or_duplicate_executed_attempt_ids(self):
        executions = [
            {"event": "invocation_start", "attempt_id": None, "invocation_id": 1,
             "execution_id_before": 0, "executed": True},
            {"event": "invocation_end", "attempt_id": None, "invocation_id": 1,
             "execution_id_after": 1, "executed": True},
            {"event": "invocation_start", "attempt_id": 13, "invocation_id": 2,
             "execution_id_before": 1, "executed": True},
            {"event": "invocation_end", "attempt_id": 13, "invocation_id": 2,
             "execution_id_after": 2, "executed": True},
            {"event": "invocation_start", "attempt_id": 13, "invocation_id": 3,
             "execution_id_before": 2, "executed": True},
            {"event": "invocation_end", "attempt_id": 13, "invocation_id": 3,
             "execution_id_after": 3, "executed": True},
        ]
        resets = [
            {"attempt_id": 1, "stage": "pre-forkserver", "execution_id": 0, "success": True},
            {"attempt_id": 13, "stage": "invocation", "execution_id": 1, "success": True},
        ]
        result = audit_smoke.audit_resets(resets, executions, "campaign-budget-exhausted")
        self.assertFalse(result["eligible"])
        self.assertEqual(result["executed_starts_missing_attempt_id"], 1)
        self.assertEqual(result["duplicate_executed_attempt_ids"], {13: 2})

    def test_reset_audit_rejects_failed_reset_even_when_attempt_is_present(self):
        executions = [
            {"event": "invocation_start", "attempt_id": 14, "invocation_id": 1,
             "execution_id_before": 0, "executed": True},
            {"event": "invocation_end", "attempt_id": 14, "invocation_id": 1,
             "execution_id_after": 1, "executed": True},
            {"event": "invocation_start", "attempt_id": 15, "invocation_id": 2,
             "execution_id_before": 1, "executed": True},
            {"event": "invocation_end", "attempt_id": 15, "invocation_id": 2,
             "execution_id_after": 2, "executed": True},
        ]
        resets = [
            {"attempt_id": 1, "stage": "pre-forkserver", "execution_id": 0, "success": True},
            {"attempt_id": 15, "stage": "invocation", "execution_id": 1,
             "success": False, "system_status": 1},
        ]
        result = audit_smoke.audit_resets(resets, executions, "campaign-budget-exhausted")
        self.assertFalse(result["eligible"])
        self.assertEqual(result["executed_invocation_reset_failures"], 1)
        self.assertEqual(result["executed_invocations_missing_invocation_reset"], 0)
        self.assertEqual(result["executed_invocations_with_exactly_one_successful_pre_reset"], 1)

    def test_q1_reports_effective_cap_and_flow_ledger(self):
        data = {
            "run-config.jsonl": [{"phase": "start", "campaign_id": "c1", "q1_policy": "no-reflow", "campaign_call_budget": 20}],
            "execution-events.jsonl": [
                {"event": "invocation_start", "executed": True, "execution_kind": "mutation", "q1_flow_id": 0},
                {"event": "invocation_start", "executed": True, "execution_kind": "mutation", "q1_flow_id": 4},
            ],
            "q1-budget-flow.jsonl": [{
                "event": "q1_budget_flow", "kind": "validation-converted-unused", "destination": "idle", "flow_id": 0,
                "amount": 64, "saved_total": 64, "idle_total": 64, "reflow_consumed": 0,
                "reflow_pool_left": 0, "charged_invocations": 3, "effective_cap": 0,
            }],
            "fuzzer_stats": [{"campaign_call_budget": 20, "campaign_charged_calls": 3,
                              "q1_idle_quota": 5, "q1_saved_quota": 5,
                              "q1_reflow_consumed": 0, "q1_reflow_pool_left": 0}],
        }
        report = audit._report(data, {}, "synthetic-repeat")
        q1 = report["Q1_flow_and_accounting"]
        self.assertEqual(q1["effective_cap_from_stats"], 15)
        self.assertEqual(q1["invocation_event_counts"]["q1_flow_tagged_start"], 1)
        self.assertEqual(q1["flow_event_counts"], {"validation-converted-unused": 1})
        self.assertFalse(report["telemetry_consistency"]["q1_flow_final_idle_matches_stats"])
        self.assertFalse(report["telemetry_consistency"]["q1_executed_starts_match_campaign_charged_calls"])
        self.assertTrue(report["telemetry_consistency"]["q1_flow_kind_destination_pairs_valid"])
        self.assertEqual(report["telemetry_consistency_status"], "inconsistent")

    def test_q1_flow_pairs_follow_emitted_kinds_and_policy_destinations(self):
        config = {"phase": "end", "q1_policy": "no-reflow"}
        rows = [
            {"kind": kind, "destination": "idle"}
            for kind in (
                "validation-closed-unused", "ordinary-window-closed-unused",
                "validation-converted-unused", "candidate-unallocated",
            )
        ] + [
            {"kind": "consumed", "destination": "ordinary-mutation"},
            {"kind": "campaign-final", "destination": "none"},
        ]
        report = audit._report({"run-config.jsonl": [config], "q1-budget-flow.jsonl": rows}, {}, "q1-pairs-valid")
        self.assertTrue(report["telemetry_consistency"]["q1_flow_kind_destination_pairs_valid"])
        self.assertEqual(report["Q1_flow_and_accounting"]["invalid_flow_kind_destination_pairs"], [])

        rows[0]["destination"] = "ordinary-pool"
        report = audit._report({"run-config.jsonl": [config], "q1-budget-flow.jsonl": rows}, {}, "q1-pairs-invalid")
        self.assertFalse(report["telemetry_consistency"]["q1_flow_kind_destination_pairs_valid"])
        self.assertEqual(
            report["Q1_flow_and_accounting"]["invalid_flow_kind_destination_pairs"][0]["reason"],
            "release_destination_conflicts_with_q1_policy",
        )

    def test_q1_requires_terminal_ledger_and_checks_policy_cap(self):
        config = {"phase": "end", "campaign_id": "q1-final", "execution_log": True,
                  "q1_policy": "no-reflow", "campaign_call_budget": 20,
                  "no_llm": True, "admission_mode": "native", "provisional_enabled": False}
        release = {"event": "q1_budget_flow", "campaign_id": "q1-final", "kind": "validation-closed-unused", "destination": "idle",
                   "amount": 5, "requested_amount": 8, "uncredited_amount": 3,
                   "saved_total": 5, "idle_total": 5, "idle_uncredited_total": 3,
                   "reflow_consumed": 0, "reflow_pool_left": 0,
                   "charged_invocations": 15, "effective_cap": 15}
        final = {"event": "q1_budget_flow", "campaign_id": "q1-final", "kind": "campaign-final", "destination": "none",
                 "amount": 0, "requested_amount": 0, "uncredited_amount": 0,
                 "saved_total": 5, "idle_total": 5, "idle_uncredited_total": 3,
                 "reflow_consumed": 0, "reflow_pool_left": 0,
                 "charged_invocations": 15, "effective_cap": 15}
        stats = {"campaign_call_budget": 20, "campaign_charged_calls": 15,
                 "campaign_budget_exhausted": 0, "q1_saved_quota": 5,
                 "q1_idle_quota": 5, "q1_idle_quota_uncredited": 3,
                 "q1_reflow_consumed": 0, "q1_reflow_pool_left": 0,
                 "no_llm_mode": 1}
        data = {"run-config.jsonl": [config], "q1-budget-flow.jsonl": [release, final],
                "execution-events.jsonl": [
                    {"campaign_id": "q1-final", "event": "invocation_start", "executed": True}
                    for _ in range(15)
                ], "fuzzer_stats": [stats]}
        report = audit._report(data, {}, "q1-final")
        consistency = report["telemetry_consistency"]
        self.assertTrue(consistency["q1_campaign_final_row_unique_and_last"])
        self.assertTrue(consistency["q1_final_effective_cap_matches_policy"])
        self.assertTrue(consistency["q1_quota_invariants_hold"])
        self.assertTrue(consistency["q1_release_flow_sum_matches_stats"])
        self.assertTrue(consistency["q1_flow_rows_schema_complete"])
        self.assertTrue(consistency["q1_consumed_flow_sum_matches_stats"])
        self.assertEqual(report["telemetry_consistency_status"], "consistent")

        data["q1-budget-flow.jsonl"] = [release]
        config["phase"] = "start"
        report = audit._report(data, {}, "q1-final-still-running")
        self.assertIsNone(report["telemetry_consistency"]["q1_campaign_final_row_unique_and_last"])
        self.assertEqual(report["telemetry_consistency_status"], "incomplete")

        config["phase"] = "end"
        report = audit._report(data, {}, "q1-final-missing")
        self.assertFalse(report["telemetry_consistency"]["q1_campaign_final_row_unique_and_last"])
        self.assertEqual(report["telemetry_consistency_status"], "inconsistent")

    def test_q1_reflow_consumption_and_required_row_fields_reconcile(self):
        config = {"phase": "end", "campaign_id": "q1-reflow", "execution_log": True,
                  "q1_policy": "reflow", "campaign_call_budget": 10,
                  "no_llm": True, "admission_mode": "native", "provisional_enabled": False}

        def flow(kind, amount, requested, *, saved=3, idle=0, uncredited=0,
                 consumed=2, pool=1, charged=2, cap=10):
            return {
                "event": "q1_budget_flow", "campaign_id": "q1-reflow", "kind": kind,
                "destination": "ordinary-mutation" if kind == "consumed" else "none" if kind == "campaign-final" else "ordinary-pool",
                "amount": amount, "requested_amount": requested,
                "uncredited_amount": requested - amount,
                "saved_total": saved, "idle_total": idle,
                "idle_uncredited_total": uncredited,
                "reflow_consumed": consumed, "reflow_pool_left": pool,
                "charged_invocations": charged, "effective_cap": cap,
            }

        stats = {"campaign_call_budget": 10, "campaign_charged_calls": 2,
                 "campaign_budget_exhausted": 0, "q1_saved_quota": 3,
                 "q1_idle_quota": 0, "q1_idle_quota_uncredited": 0,
                 "q1_reflow_consumed": 2, "q1_reflow_pool_left": 1,
                 "no_llm_mode": 1}
        data = {
            "run-config.jsonl": [config],
            "q1-budget-flow.jsonl": [
                flow("candidate-unallocated", 3, 3),
                flow("consumed", 2, 2),
                flow("campaign-final", 0, 0),
            ],
            "execution-events.jsonl": [
                {"campaign_id": "q1-reflow", "event": "invocation_start", "executed": True}
                for _ in range(2)
            ],
            "fuzzer_stats": [stats],
        }
        report = audit._report(data, {}, "q1-reflow-valid")
        consistency = report["telemetry_consistency"]
        self.assertTrue(consistency["q1_consumed_flow_sum_matches_stats"])
        self.assertTrue(consistency["q1_flow_campaign_ids_match_start_config"])
        self.assertEqual(report["telemetry_consistency_status"], "consistent")

        data["q1-budget-flow.jsonl"][-1]["effective_cap"] = 9
        report = audit._report(data, {}, "q1-reflow-cap-mismatch")
        self.assertFalse(report["telemetry_consistency"]["q1_final_effective_cap_matches_policy"])
        self.assertEqual(report["telemetry_consistency_status"], "inconsistent")
        data["q1-budget-flow.jsonl"][-1]["effective_cap"] = 10

        stats["q1_reflow_pool_left"] = 0
        report = audit._report(data, {}, "q1-reflow-conservation-mismatch")
        self.assertFalse(report["telemetry_consistency"]["q1_quota_invariants_hold"])
        self.assertEqual(report["telemetry_consistency_status"], "inconsistent")
        stats["q1_reflow_pool_left"] = 1

        data["q1-budget-flow.jsonl"][-1]["charged_invocations"] = 1
        report = audit._report(data, {}, "q1-reflow-terminal-counter-mismatch")
        self.assertFalse(report["telemetry_consistency"]["q1_final_charged_matches_stats"])
        self.assertEqual(report["telemetry_consistency_status"], "inconsistent")
        data["q1-budget-flow.jsonl"][-1]["charged_invocations"] = 2

        data["q1-budget-flow.jsonl"].append(flow("campaign-final", 0, 0))
        report = audit._report(data, {}, "q1-reflow-duplicate-terminal-row")
        self.assertFalse(report["telemetry_consistency"]["q1_campaign_final_row_unique_and_last"])
        self.assertEqual(report["telemetry_consistency_status"], "inconsistent")
        data["q1-budget-flow.jsonl"].pop()

        data["q1-budget-flow.jsonl"][1]["amount"] = 1
        data["q1-budget-flow.jsonl"][1]["requested_amount"] = 1
        report = audit._report(data, {}, "q1-reflow-consumption-mismatch")
        self.assertFalse(report["telemetry_consistency"]["q1_consumed_flow_sum_matches_stats"])
        self.assertEqual(report["telemetry_consistency_status"], "inconsistent")

        del data["q1-budget-flow.jsonl"][0]["requested_amount"]
        report = audit._report(data, {}, "q1-reflow-missing-field")
        self.assertFalse(report["telemetry_consistency"]["q1_flow_rows_schema_complete"])
        self.assertEqual(report["telemetry_consistency_status"], "inconsistent")

    def test_q2_counts_salvage_and_ordinary_close_separately(self):
        data = {
            "run-config.jsonl": [{"phase": "start", "campaign_id": "c2"}],
            "provisional-events.jsonl": [
                {"kind": "admit", "reason": "salvage", "candidate_id": 1, "queue_entry": 101,
                 "baseline_source": "saved-session-probe"},
                {"kind": "admit", "reason": "state-novelty-only evidence (ordinary-match cohort)",
                 "ordinary_match": True, "candidate_id": 2, "queue_entry": 102,
                 "baseline_source": "original-candidate-trial"},
                {"kind": "admit", "reason": "regular", "candidate_id": 3, "queue_entry": 103,
                 "baseline_source": "original-candidate-trial"},
                {"kind": "convert", "candidate_id": 1, "queue_entry": 101, "descendant_execs": 8,
                 "conversion_class": 2, "conversion_class_name": "contains-beyond-trial-slots"},
                {"kind": "ordinary-close", "candidate_id": 2, "queue_entry": 102, "descendant_execs": 64},
                {"kind": "censor", "candidate_id": 3, "queue_entry": 103, "descendant_execs": 2},
            ],
            "productivity-events.jsonl": [{
                "cohort": "provisional", "outcome": "convert", "candidate_id": 1, "root_queue_id": 101,
                "descendant_invocations": 8, "converted": True, "beyond_baseline_slots": 1,
                "conversion_class": 2, "baseline_valid": True, "censored": False,
            }, {
                "cohort": "ordinary-match", "outcome": "ordinary-close", "candidate_id": 2, "root_queue_id": 102,
                "descendant_invocations": 64, "converted": False, "baseline_valid": True,
                "conversion_class": 0, "censored": False,
            }, {
                "cohort": "provisional", "outcome": "censor", "candidate_id": 3, "root_queue_id": 103,
                "descendant_invocations": 2, "converted": False, "baseline_valid": False,
                "conversion_class": 0, "censored": True,
            }],
            "fuzzer_stats": [{"provisional_admitted": 3, "salvage_succeeded": 1,
                              "ordinary_match_closed": 1, "prov_conv_beyond_trial": 1}],
        }
        report = audit._report(data, {}, "synthetic-repeat")
        q2 = report["Q2_provisional_productivity_and_salvage"]
        self.assertEqual(q2["salvage_admitted_roots"], 1)
        self.assertEqual(q2["terminal_root_events"]["ordinary_close"], 1)
        self.assertEqual(q2["terminal_root_events"]["censor"], 1)
        self.assertEqual(q2["conversion_class_2_events"], 1)
        self.assertEqual(q2["valid_beyond_baseline_slots_sum"], 1)
        self.assertEqual(q2["provisional_terminal_descendant_invocations"], 74)
        self.assertEqual(q2["served_roots_with_descendant_execution"], 3)
        self.assertEqual(q2["served_root_descendant_invocation_distribution"]["sum"], 74)
        self.assertTrue(report["telemetry_consistency"]["q2_ordinary_close_events_match_stats"])
        self.assertTrue(report["telemetry_consistency"]["q2_productivity_roots_match_terminal_events"])
        self.assertTrue(report["telemetry_consistency"]["q2_root_lifecycle_matches_by_id"])
        self.assertTrue(report["telemetry_consistency"]["q2_salvage_roots_match_success_counter"])
        self.assertEqual(q2["root_identity_audit"]["root_mismatches"], [])

    def test_q2_salvage_counter_is_unresolved_when_ordinary_match_route_is_hidden(self):
        data = {
            "run-config.jsonl": [{"phase": "end", "campaign_id": "ordmatch", "provisional_enabled": True}],
            "provisional-events.jsonl": [
                {"kind": "admit", "candidate_id": 10, "queue_entry": 20,
                 "reason": "state-novelty-only evidence (ordinary-match cohort)", "ordinary_match": True},
                {"kind": "ordinary-close", "candidate_id": 10, "queue_entry": 20,
                 "descendant_execs": 5},
            ],
            "productivity-events.jsonl": [{
                "candidate_id": 10, "root_queue_id": 20, "cohort": "ordinary-match",
                "outcome": "ordinary-close", "descendant_invocations": 5,
            }],
            "fuzzer_stats": [{"salvage_succeeded": 1, "provisional_admitted": 1,
                              "ordinary_match_closed": 1}],
        }
        report = audit._report(data, {}, "legacy-ordmatch-repeat")
        self.assertIsNone(report["telemetry_consistency"]["q2_salvage_roots_match_success_counter"])
        self.assertTrue(report["telemetry_consistency"]["q2_root_lifecycle_matches_by_id"])
        self.assertEqual(report["telemetry_applicability"]["q2-salvage-route-counter"]["state"], "unresolved")
        self.assertEqual(report["Q2_provisional_productivity_and_salvage"]["salvage_admitted_roots"], None)

        data["provisional-events.jsonl"][0]["baseline_source"] = "saved-session-probe"
        report = audit._report(data, {}, "routed-ordmatch-repeat")
        self.assertTrue(report["telemetry_consistency"]["q2_salvage_roots_match_success_counter"])
        self.assertEqual(report["Q2_provisional_productivity_and_salvage"]["salvage_admitted_roots"], 1)

    def test_q2_root_audit_rejects_id_outcome_and_descendant_dose_mismatches(self):
        report = audit._report({
            "provisional-events.jsonl": [
                {"kind": "admit", "candidate_id": 7, "queue_entry": 70},
                {"kind": "convert", "candidate_id": 7, "queue_entry": 70, "descendant_execs": 4},
                {"kind": "admit", "candidate_id": 8, "queue_entry": 80},
                {"kind": "convert", "candidate_id": 8, "queue_entry": 80, "descendant_execs": 4},
            ],
            "productivity-events.jsonl": [{
                "candidate_id": 7, "root_queue_id": 71, "cohort": "provisional",
                "outcome": "expire", "descendant_invocations": 3,
            }, {
                "candidate_id": 8, "root_queue_id": 80, "cohort": "provisional",
                "outcome": "expire", "descendant_invocations": 3,
            }],
        }, {}, "q2-root-mismatch")
        consistency = report["telemetry_consistency"]
        self.assertFalse(consistency["q2_root_lifecycle_matches_by_id"])
        mismatches = report["Q2_provisional_productivity_and_salvage"]["root_identity_audit"]["root_mismatches"]
        self.assertEqual(len(mismatches), 3)
        self.assertTrue(any("terminal_kind" in row for row in mismatches))
        self.assertTrue(any("productivity_rows" in row for row in mismatches))

    def test_q2_answerability_requires_ten_linked_positive_dose_roots_per_cohort(self):
        def sample(provisional_count, ordinary_count):
            admits = []
            terminals = []
            productivity = []
            root_id = 0
            for cohort, count in (("provisional", provisional_count), ("ordinary-match", ordinary_count)):
                for _ in range(count):
                    root_id += 1
                    candidate_id = root_id + 100
                    ordinary = cohort == "ordinary-match"
                    admits.append({
                        "kind": "admit", "candidate_id": candidate_id, "queue_entry": root_id,
                        "ordinary_match": ordinary,
                        "baseline_source": "original-candidate-trial",
                    })
                    terminals.append({
                        "kind": "expire", "candidate_id": candidate_id, "queue_entry": root_id,
                        "descendant_execs": 2,
                    })
                    productivity.append({
                        "cohort": "ordinary_match" if ordinary else cohort,
                        "outcome": "expire", "candidate_id": candidate_id,
                        "root_queue_id": root_id, "descendant_invocations": 2,
                    })
            return {
                "run-config.jsonl": [{
                    "phase": "end", "campaign_id": "q2-dose-floor",
                    "provisional_enabled": True, "admission_mode": "gate",
                }],
                "provisional-events.jsonl": admits + terminals,
                "productivity-events.jsonl": productivity,
            }

        under_floor = audit._report(sample(9, 10), {}, "q2-under-floor")[
            "Q2_provisional_productivity_and_salvage"
        ]
        self.assertEqual(under_floor["answerability_prerequisites"]["status"], "unresolved")
        self.assertEqual(
            under_floor["answerability_prerequisites"]["per_repeat_counts_and_dose"][
                "uniquely_linked_positive_dose_roots_by_cohort"
            ],
            {"provisional": 9, "ordinary-match": 10},
        )

        at_floor = audit._report(sample(10, 10), {}, "q2-at-floor")[
            "Q2_provisional_productivity_and_salvage"
        ]
        self.assertEqual(at_floor["answerability_prerequisites"]["status"], "unresolved")
        self.assertEqual(at_floor["answerability_prerequisites"]["single_archive_status"], "ready")
        self.assertEqual(
            at_floor["answerability_prerequisites"]["paired_arm_prerequisites"]["status"],
            "not_evaluated_by_single_archive_audit",
        )
        self.assertEqual(
            at_floor["answerability_prerequisites"]["per_repeat_counts_and_dose"][
                "uniquely_linked_positive_dose_roots_by_cohort"
            ],
            {"provisional": 10, "ordinary-match": 10},
        )

        broken_link = sample(10, 10)
        broken_link["provisional-events.jsonl"][-1]["descendant_execs"] = 3
        broken_link_report = audit._report(broken_link, {}, "q2-broken-link")[
            "Q2_provisional_productivity_and_salvage"
        ]
        self.assertEqual(broken_link_report["answerability_prerequisites"]["status"], "unresolved")
        self.assertEqual(
            broken_link_report["answerability_prerequisites"]["per_repeat_counts_and_dose"][
                "uniquely_linked_positive_dose_roots_by_cohort"
            ]["ordinary-match"],
            9,
        )

    def test_q3_intersections_require_weighted_applied_changed_and_fixed_windows(self):
        data = {
            "run-config.jsonl": [{"phase": "start", "campaign_id": "c3", "calibration": True,
                                  "cal_reward_window_invocations": 16}],
            "scheduler-selections.jsonl": [
                {"reason": "weighted-eligible", "weight_total": 8, "calibration_applied": True, "calibration_changed_selection": True},
                {"reason": "weighted-eligible", "weight_total": 8, "calibration_applied": True, "calibration_changed_selection": False},
                {"reason": "weighted-eligible", "weight_total": 0, "calibration_applied": True, "calibration_changed_selection": True},
                {"reason": "warmup-eligible", "weight_total": 0, "calibration_applied": True, "calibration_changed_selection": True},
            ],
            "state-episodes.jsonl": [
                {"selected_state": 1, "train_eligible": True, "completed": True, "posterior_updated": True, "reward": 1,
                 "training_observations": 2, "training_rewarded_observations": 1,
                 "cal_reward_window_invocations": 16},
                {"selected_state": 2, "train_eligible": True, "completed": False, "posterior_updated": True, "reward": -1,
                 "training_observations": 1, "training_rewarded_observations": 0,
                 "cal_reward_window_invocations": 16},
                {"selected_state": 1, "train_eligible": True, "completed": True, "posterior_updated": False, "reward": -1,
                 "training_observations": 0, "training_rewarded_observations": 0,
                 "cal_reward_window_invocations": 16},
            ],
            "calibration-windows.jsonl": [
                {"selected_state": 1, "training_invocations": 16, "reward": 1},
                {"selected_state": 1, "training_invocations": 16, "reward": 0},
                {"selected_state": 2, "training_invocations": 8, "reward": 0},
            ],
            "fuzzer_stats": [{"cal_training_windows": 3, "cal_episodes_jsonl": 3}],
        }
        q3 = audit._report(data, {}, "synthetic-repeat")["Q3_scheduler_and_reward_training"]
        self.assertEqual(q3["weighted_eligible_rows"], 3)
        self.assertEqual(q3["weighted_rows_with_positive_weight_total"], 2)
        self.assertEqual(q3["weighted_applied_changed_intersection"], 1)
        self.assertEqual(q3["episode_flag_counts"]["eligible_completed_updated_intersection"], 1)
        self.assertEqual(q3["fixed_width_rows"], 2)
        consistency = audit._report(data, {}, "synthetic-repeat")["telemetry_consistency"]
        self.assertTrue(consistency["q3_window_count_matches_episode_training_observations"])
        self.assertTrue(consistency["q3_positive_window_rewards_match_episode_rewarded_observations"])
        self.assertTrue(consistency["q3_state_level_window_posterior_link_matches"])
        self.assertTrue(consistency["q3_eligible_completed_episodes_updated_posterior"])
        self.assertTrue(consistency["q3_posterior_updates_have_training_evidence"])
        self.assertTrue(consistency["q3_posterior_updates_match_training_evidence"])

    def test_q3_posterior_update_expectations_follow_training_evidence_by_reward_mode(self):
        def base(width, window_count=0):
            return {
                "run-config.jsonl": [{
                    "phase": "end", "campaign_id": "posterior-evidence",
                    "no_llm": True, "execution_log": True, "q1_policy": "none",
                    "admission_mode": "native", "provisional_enabled": False,
                    "calibration": True, "cal_reward_window_invocations": width,
                }],
                "scheduler-selections.jsonl": [{
                    "reason": "warmup-eligible", "calibration_applied": False,
                    "calibration_changed_selection": False,
                }],
                "fuzzer_stats": [{
                    "no_llm_mode": 1, "campaign_charged_calls": 0,
                    "admission_accounting": 0, "cal_episodes_jsonl": 1,
                    "cal_training_windows": window_count,
                    "cal_reward_window_invocations": width,
                }],
            }

        bernoulli_base = {
            **base(0),
        }
        zero_call = {
            "selected_state": 1, "train_eligible": True, "completed": True,
            "posterior_updated": False, "training_invocations": 0,
            "cal_reward_window_invocations": 0,
        }
        report = audit._report({
            **bernoulli_base,
            "state-episodes.jsonl": [zero_call],
        }, {}, "bernoulli-zero-call")
        self.assertTrue(report["telemetry_consistency"]["q3_eligible_completed_episodes_updated_posterior"])
        self.assertTrue(report["telemetry_consistency"]["q3_posterior_updates_match_training_evidence"])
        self.assertEqual(report["telemetry_consistency_status"], "consistent")

        trained_without_update = {
            **bernoulli_base,
            "state-episodes.jsonl": [{
                **zero_call, "training_invocations": 1,
            }],
        }
        report = audit._report(trained_without_update, {}, "bernoulli-missing-update")
        self.assertFalse(report["telemetry_consistency"]["q3_posterior_updates_match_training_evidence"])
        self.assertEqual(report["telemetry_consistency_status"], "inconsistent")

        fixed_base = {
            **base(512),
        }
        fixed_zero_call = {
            "selected_state": 1, "train_eligible": True, "completed": True,
            "posterior_updated": False, "training_invocations": 0,
            "training_observations": 0, "cal_reward_window_invocations": 512,
        }
        report = audit._report({
            **fixed_base,
            "state-episodes.jsonl": [fixed_zero_call],
        }, {}, "fixed-window-zero-call")
        self.assertTrue(report["telemetry_consistency"]["q3_eligible_completed_episodes_updated_posterior"])
        self.assertTrue(report["telemetry_consistency"]["q3_posterior_updates_match_training_evidence"])
        self.assertEqual(report["telemetry_consistency_status"], "consistent")

        completed_window = {
            **base(512, window_count=1),
            "state-episodes.jsonl": [{
                **fixed_zero_call, "completed": False, "posterior_updated": True,
                "training_invocations": 512, "training_observations": 1,
            }],
            "calibration-windows.jsonl": [{
                "selected_state": 1, "training_invocations": 512, "reward": 0,
            }],
        }
        report = audit._report(completed_window, {}, "fixed-window-interrupted-after-window")
        self.assertTrue(report["telemetry_consistency"]["q3_posterior_updates_match_training_evidence"])
        self.assertEqual(report["telemetry_consistency_status"], "consistent")

        fixed_missing_update = {
            **base(512, window_count=1),
            "state-episodes.jsonl": [{
                **fixed_zero_call, "training_invocations": 512,
                "training_observations": 1,
            }],
            "calibration-windows.jsonl": [{
                "selected_state": 1, "training_invocations": 512, "reward": 0,
            }],
        }
        report = audit._report(fixed_missing_update, {}, "fixed-window-missing-update")
        self.assertFalse(report["telemetry_consistency"]["q3_posterior_updates_match_training_evidence"])
        self.assertEqual(report["telemetry_consistency_status"], "inconsistent")

        missing_evidence = {
            **bernoulli_base,
            "state-episodes.jsonl": [{
                "selected_state": 1, "train_eligible": True, "completed": True,
                "posterior_updated": False,
            }],
        }
        report = audit._report(missing_evidence, {}, "bernoulli-missing-evidence-field")
        self.assertFalse(report["telemetry_consistency"]["q3_episode_posterior_evidence_fields_complete"])
        self.assertEqual(report["telemetry_consistency_status"], "incomplete")

    def test_missing_calibration_fields_remain_unresolved(self):
        report = audit._report({
            "run-config.jsonl": [{"phase": "start", "campaign_id": "c4"}],
            "scheduler-selections.jsonl": [{"reason": "weighted-eligible", "weight_total": 1}],
        }, {}, "synthetic-repeat")
        q3 = report["Q3_scheduler_and_reward_training"]
        self.assertIsNone(q3["weighted_applied_changed_intersection"])
        self.assertEqual(q3["calibration_applied_rows_all"], 0)
        self.assertEqual(q3["selection_rows_missing_calibration_applied_field"], 1)
        self.assertEqual(q3["weighted_positive_rows_missing_either_calibration_field"], 1)

    def test_q3_intersection_uses_observed_positive_weighted_pairs_only(self):
        report = audit._report({
            "scheduler-selections.jsonl": [
                {"reason": "weighted-eligible", "weight_total": 2,
                 "calibration_applied": True, "calibration_changed_selection": True},
                {"reason": "weighted-eligible", "weight_total": 1, "calibration_applied": True},
                {"reason": "weighted-eligible", "weight_total": 1},
                {"reason": "weighted-eligible", "weight_total": 0, "calibration_applied": True},
            ],
        }, {}, "synthetic-repeat")["Q3_scheduler_and_reward_training"]
        self.assertEqual(report["weighted_positive_rows_with_applicable_calibration_fields"], 1)
        self.assertEqual(report["weighted_positive_rows_missing_calibration_applied_field"], 1)
        self.assertEqual(report["weighted_positive_rows_missing_calibration_changed_selection_field"], 1)
        self.assertEqual(report["weighted_positive_rows_missing_either_calibration_field"], 2)
        self.assertEqual(report["weighted_applied_changed_intersection"], 1)

    def test_q3_answerability_requires_trigger_and_positive_posterior_update(self):
        fixed = {
            "run-config.jsonl": [{
                "phase": "end", "campaign_id": "q3-answerable", "calibration": True,
                "cal_reward_window_invocations": 4,
            }],
            "scheduler-selections.jsonl": [{
                "reason": "weighted-eligible", "weight_total": 4,
                "calibration_applied": True, "calibration_changed_selection": True,
            }],
            "state-episodes.jsonl": [{
                "selected_state": 1, "calibration_revision": "fixed-invocation-window-v1",
                "train_eligible": True, "completed": True, "posterior_updated": True,
                "reward": 1, "training_invocations": 4, "training_observations": 1,
                "training_rewarded_observations": 1, "alpha_before": 1.0, "alpha_after": 2.0,
                "cal_reward_window_invocations": 4,
            }],
            "calibration-windows.jsonl": [{
                "selected_state": 1, "training_invocations": 4, "reward": 1,
            }],
        }
        q3 = audit._report(fixed, {}, "q3-answerable") ["Q3_scheduler_and_reward_training"]
        self.assertEqual(q3["answerability_prerequisites"]["status"], "ready")
        self.assertTrue(q3["answerability_prerequisites"]["mechanism_triggered"])

        no_selection_change = {
            **fixed,
            "scheduler-selections.jsonl": [{
                **fixed["scheduler-selections.jsonl"][0],
                "calibration_changed_selection": False,
            }],
        }
        q3 = audit._report(no_selection_change, {}, "q3-no-selection-effect") ["Q3_scheduler_and_reward_training"]
        self.assertEqual(q3["answerability_prerequisites"]["status"], "unresolved")
        self.assertFalse(q3["answerability_prerequisites"]["mechanism_triggered"])

        no_positive_update = {
            **fixed,
            "state-episodes.jsonl": [{
                **fixed["state-episodes.jsonl"][0],
                "training_rewarded_observations": 0, "alpha_after": 1.0,
            }],
            "calibration-windows.jsonl": [{
                **fixed["calibration-windows.jsonl"][0], "reward": 0,
            }],
        }
        q3 = audit._report(no_positive_update, {}, "q3-no-positive-update") ["Q3_scheduler_and_reward_training"]
        self.assertEqual(q3["answerability_prerequisites"]["status"], "unresolved")

        episode_width_mismatch = {
            **fixed,
            "state-episodes.jsonl": [{
                **fixed["state-episodes.jsonl"][0], "cal_reward_window_invocations": 8,
            }],
        }
        q3 = audit._report(episode_width_mismatch, {}, "q3-episode-width-mismatch")[
            "Q3_scheduler_and_reward_training"
        ]
        self.assertEqual(q3["answerability_prerequisites"]["status"], "unresolved")
        self.assertFalse(q3["answerability_prerequisites"]["prerequisites"][
            "fixed_reward_window_matches_configured_width"
        ])

        window_width_mismatch = {
            **fixed,
            "calibration-windows.jsonl": [{
                **fixed["calibration-windows.jsonl"][0], "training_invocations": 8,
            }],
        }
        q3 = audit._report(window_width_mismatch, {}, "q3-window-width-mismatch")[
            "Q3_scheduler_and_reward_training"
        ]
        self.assertEqual(q3["answerability_prerequisites"]["status"], "unresolved")
        self.assertFalse(q3["answerability_prerequisites"]["prerequisites"][
            "fixed_reward_window_matches_configured_width"
        ])

        bernoulli = {
            "run-config.jsonl": [{
                "phase": "end", "campaign_id": "q3-bernoulli", "calibration": True,
                "cal_reward_window_invocations": 0,
            }],
            "scheduler-selections.jsonl": fixed["scheduler-selections.jsonl"],
            "state-episodes.jsonl": [{
                "selected_state": 1, "calibration_revision": "episode-bernoulli-v1",
                "train_eligible": True, "completed": True, "posterior_updated": True,
                "reward": 1, "training_invocations": 3, "alpha_before": 1.0, "alpha_after": 2.0,
            }],
        }
        q3 = audit._report(bernoulli, {}, "q3-bernoulli-positive") ["Q3_scheduler_and_reward_training"]
        self.assertEqual(q3["answerability_prerequisites"]["status"], "ready")

    def test_q3_weighted_off_calibration_changed_field_is_not_applicable(self):
        report = audit._report({
            "scheduler-selections.jsonl": [{
                "reason": "weighted-eligible", "weight_total": 4,
                "calibration_applied": False,
            }],
        }, {}, "weighted-calibration-off")["Q3_scheduler_and_reward_training"]
        self.assertEqual(report["weighted_positive_rows_with_applicable_calibration_fields"], 1)
        self.assertEqual(report["weighted_positive_rows_missing_either_calibration_field"], 0)
        self.assertEqual(report["weighted_positive_applied_rows"], 0)
        self.assertEqual(report["weighted_positive_not_applicable_rows"], 1)
        self.assertEqual(report["weighted_positive_applied_rows_missing_changed_selection_field"], 0)
        self.assertIsNone(report["weighted_positive_changed_selection_rate_applied_rows_with_field"])
        self.assertTrue(report["positive_weighted_scheduler_calibration_fields_complete"])
        self.assertEqual(report["calibration_applied_rows_all"], 0)
        self.assertEqual(report["calibration_not_applicable_rows_all"], 1)
        self.assertEqual(report["calibration_applied_rows_missing_changed_selection_field"], 0)

    def test_q3_weighted_on_calibration_requires_changed_selection_field(self):
        report = audit._report({
            "scheduler-selections.jsonl": [{
                "reason": "weighted-eligible", "weight_total": 4,
                "calibration_applied": True,
            }],
        }, {}, "weighted-calibration-on-missing-change-field")["Q3_scheduler_and_reward_training"]
        self.assertEqual(report["weighted_positive_rows_with_applicable_calibration_fields"], 0)
        self.assertEqual(report["weighted_positive_rows_missing_either_calibration_field"], 1)
        self.assertEqual(report["weighted_positive_applied_rows"], 1)
        self.assertEqual(report["weighted_positive_not_applicable_rows"], 0)
        self.assertEqual(report["weighted_positive_applied_rows_with_changed_selection_field"], 0)
        self.assertEqual(report["weighted_positive_applied_rows_missing_changed_selection_field"], 1)
        self.assertIsNone(report["weighted_positive_changed_selection_rate_applied_rows_with_field"])
        self.assertFalse(report["positive_weighted_scheduler_calibration_fields_complete"])

    def test_q3_weighted_changed_selection_rate_uses_only_applied_rows_with_field(self):
        report = audit._report({
            "scheduler-selections.jsonl": [
                {"reason": "weighted-eligible", "weight_total": 4,
                 "calibration_applied": True, "calibration_changed_selection": True},
                {"reason": "weighted-eligible", "weight_total": 4,
                 "calibration_applied": True, "calibration_changed_selection": False},
                {"reason": "weighted-eligible", "weight_total": 4,
                 "calibration_applied": False},
                {"reason": "warmup-eligible", "calibration_applied": False},
                {"reason": "warmup-eligible", "calibration_applied": True,
                 "calibration_changed_selection": True},
            ],
        }, {}, "weighted-applied-change-rate")["Q3_scheduler_and_reward_training"]
        self.assertEqual(report["weighted_positive_applied_rows"], 2)
        self.assertEqual(report["weighted_positive_not_applicable_rows"], 1)
        self.assertEqual(report["weighted_positive_applied_rows_with_changed_selection_field"], 2)
        self.assertEqual(report["weighted_positive_changed_selection_true_rows"], 1)
        self.assertEqual(report["weighted_positive_changed_selection_rate_applied_rows_with_field"], 0.5)
        self.assertEqual(report["calibration_applied_rows_with_changed_selection_field"], 3)
        self.assertEqual(report["calibration_applied_rows_missing_changed_selection_field"], 0)
        self.assertEqual(report["calibration_changed_selection_rate_applied_rows_with_field"], 2 / 3)

    def test_successful_jsonl_reads_do_not_create_parse_errors(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "run-config.jsonl").write_text('{"campaign_id":"c5"}\n')
            _, directory_errors, _ = audit._read_dir(root)
            self.assertEqual(directory_errors, {})

            archive_path = root / "repeat.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(root / "run-config.jsonl", arcname="out/run-config.jsonl")
            _, archive_errors, _ = audit._read_tar(archive_path)
            self.assertEqual(archive_errors, {})

    def test_report_only_exit_status_does_not_claim_consistency(self):
        report = audit._report({
            "run-config.jsonl": [{"phase": "start", "campaign_id": "c6"}],
        }, {}, "incomplete-repeat")
        self.assertEqual(report["report_generation_status"], "generated")
        self.assertEqual(report["telemetry_consistency_status"], "incomplete")
        self.assertIn("inspect telemetry_consistency_status", report["default_exit_code_semantics"])

    def test_disabled_or_zero_trigger_streams_do_not_make_a_run_incomplete(self):
        data = {
            "run-config.jsonl": [{
                "phase": "end", "campaign_id": "c7", "no_llm": True,
                "execution_log": True, "q1_policy": "none", "admission_mode": "gate",
                "provisional_enabled": True, "calibration": False,
                "cal_reward_window_invocations": 0,
            }],
            "execution-events.jsonl": [{"event": "invocation_start", "executed": True}],
            "fuzzer_stats": [{
                "campaign_charged_calls": 1, "admission_accounting": 1,
                "admission_candidate_total": 0, "llm_total_calls": 0,
                "provisional_admitted": 0, "cal_episodes_jsonl": 0,
                "cal_training_windows": 0, "cal_reward_window_invocations": 0,
                "q1_saved_quota": 0, "q1_idle_quota": 0, "q1_reflow_consumed": 0,
            }],
        }
        report = audit._report(data, {}, "zero-dose-run")
        self.assertEqual(report["telemetry_consistency_status"], "consistent")
        self.assertEqual(report["telemetry_applicability"]["candidate-events.jsonl"]["state"], "disabled")
        self.assertEqual(report["telemetry_applicability"]["q1-budget-flow.jsonl"]["state"], "not_applicable")
        self.assertEqual(report["telemetry_applicability"]["provisional-events.jsonl"]["state"], "enabled_no_trigger")
        self.assertEqual(report["telemetry_applicability"]["calibration-windows.jsonl"]["state"], "not_applicable")

    def test_non_q1_budgeted_arm_does_not_require_q1_quota_ledger(self):
        data = {
            "run-config.jsonl": [
                {"phase": "start", "campaign_id": "core-campaign",
                 "q1_policy": "none", "campaign_call_budget": 5000,
                 "no_llm": True, "execution_log": True, "admission_mode": "gate",
                 "provisional_enabled": True, "calibration": False,
                 "cal_reward_window_invocations": 0},
                {"phase": "end", "campaign_id": "core-campaign",
                 "q1_policy": "none", "campaign_call_budget": 5000,
                 "no_llm": True, "execution_log": True, "admission_mode": "gate",
                 "provisional_enabled": True, "calibration": False,
                 "cal_reward_window_invocations": 0},
            ],
            "execution-events.jsonl": [{"event": "invocation_start", "executed": True}],
            "fuzzer_stats": [{
                "campaign_call_budget": 5000,
                "campaign_charged_calls": 1,
                "campaign_budget_exhausted": 0,
                "admission_accounting": 1, "admission_candidate_total": 0,
                "llm_total_calls": 0, "provisional_admitted": 0,
                "cal_episodes_jsonl": 0, "cal_training_windows": 0,
                "cal_reward_window_invocations": 0,
            }],
        }
        report = audit._report(data, {}, "core-budgeted-run")
        self.assertNotEqual(report["telemetry_consistency_status"], "inconsistent")
        self.assertFalse(any(value is False for key, value in report["telemetry_consistency"].items()
                             if key.startswith("q1_") and key != "q1_stats_budget_matches_config"))
        self.assertEqual(report["telemetry_applicability"]["q1-terminal-boundary"]["state"], "not_applicable")
        self.assertEqual(report["telemetry_applicability"]["q1-counter-fields"]["state"], "not_applicable")
        self.assertIsNone(report["telemetry_consistency"]["q1_campaign_final_row_unique_and_last"])

    def test_enabled_stream_missing_after_independent_trigger_fails_completeness(self):
        data = {
            "run-config.jsonl": [{
                "phase": "end", "campaign_id": "c8", "no_llm": True,
                "execution_log": True, "q1_policy": "reflow", "admission_mode": "gate",
                "provisional_enabled": True, "calibration": True,
                "cal_reward_window_invocations": 16,
            }],
            "fuzzer_stats": [{
                "campaign_charged_calls": 8, "admission_accounting": 1,
                "admission_candidate_total": 0, "provisional_admitted": 0,
                "cal_episodes_jsonl": 0, "cal_training_windows": 2,
                "cal_reward_window_invocations": 16, "q1_saved_quota": 1,
                "q1_idle_quota": 1, "q1_reflow_consumed": 0,
            }],
        }
        report = audit._report(data, {}, "missing-enabled-streams")
        self.assertEqual(report["telemetry_consistency_status"], "incomplete")
        self.assertEqual(set(report["required_but_missing_telemetry_files"]), {
            "execution-events.jsonl", "q1-budget-flow.jsonl", "calibration-windows.jsonl",
        })

    def test_scheduler_changed_selection_is_required_only_when_calibration_applied(self):
        report = audit._report({
            "run-config.jsonl": [{"phase": "end", "campaign_id": "c9", "calibration": False}],
            "scheduler-selections.jsonl": [
                {"reason": "warmup-eligible", "calibration_applied": False},
            ],
        }, {}, "fixed-scheduler")
        self.assertTrue(report["Q3_scheduler_and_reward_training"]["scheduler_calibration_fields_complete"])

    def test_collection_name_and_repeat_index_are_parsed_for_uniqueness_checks(self):
        sample = Path("/tmp/results-bftpd_ablation_cal_ewma1_20261114T025147/out-bftpd-loopfuzz_2.tar.gz")
        directory, identity = audit._collection_identity(sample)
        self.assertEqual(directory.name, "results-bftpd_ablation_cal_ewma1_20261114T025147")
        self.assertEqual(identity["target"], "bftpd")
        self.assertEqual(identity["arm_alias"], "cal_ewma")
        self.assertEqual(identity["threshold"], 1)
        self.assertEqual(audit._repeat_index(sample), 2)


if __name__ == "__main__":
    unittest.main()
