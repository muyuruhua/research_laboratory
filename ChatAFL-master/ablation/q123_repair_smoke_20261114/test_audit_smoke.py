#!/usr/bin/env python3
"""Policy-specific campaign-dose and batch-identity checks for Q1 smoke."""

import unittest
import sys
import tempfile
import gzip
import hashlib
import json
import csv
import io
import os
import subprocess
import runpy
import struct
import tarfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import audit_smoke
from audit_smoke import (
    CORE_ARM_BASES,
    EXPECTED_BATCH_ARM_LABELS,
    PROTOCOL_BY_TARGET,
    SHARED_COMPARISON_FIELDS,
    audit_campaign_dose,
    campaign_inference_scope,
    audit_campaign_integrity_termination,
    audit_campaign_termination,
    audit_q1_mechanism_evidence,
    audit_wallclock_budget_censor,
    audit_complete_batch,
    audit_fuzzer_protocol,
    audit_invocation_pairs,
    audit_mock_protocol,
    audit_mock_request_accounting,
    audit_repeat_mapping,
    audit_status_mapping,
    audit_sampled_coverage_archive,
    audit_wallclock_budget_role,
    coverage_archive_schema,
    find_unique_archive_member,
    expected_arm_labels,
    expected_config,
    parse_arm_bases,
    format_sample_sd,
    shared_identity_difference,
    shared_identity_from_sample,
)


def stats(**overrides):
    values = {
        "campaign_call_budget": 5000,
        "campaign_charged_calls": 5000,
        "campaign_budget_exhausted": 1,
        "q1_saved_quota": 0,
        "q1_idle_quota": 0,
        "q1_reflow_consumed": 0,
        "q1_reflow_pool_left": 0,
        "q1_idle_quota_uncredited": 0,
    }
    values.update(overrides)
    return values


def flow(*, charged=5000, saved=0, idle=0, reflow_used=0, reflow_left=0,
         uncredited=0, effective_cap=5000, amount=None):
    release_amount = saved if amount is None else amount
    rows = []
    if release_amount or uncredited:
        rows.append({"kind": "validation-closed-unused", "amount": release_amount,
                     "uncredited_amount": uncredited})
    rows.append({"kind": "campaign-final", "charged_invocations": charged,
                 "saved_total": saved, "idle_total": idle,
                 "reflow_consumed": reflow_used, "reflow_pool_left": reflow_left,
                 "effective_cap": effective_cap})
    return rows


class CampaignDoseAuditTests(unittest.TestCase):
    def test_no_reflow_uses_reduced_effective_cap(self):
        ok, _ = audit_campaign_dose(
            {"q1_policy": "no-reflow"},
            stats(campaign_charged_calls=3912, q1_saved_quota=1088, q1_idle_quota=1088),
            3912, flow(charged=3912, saved=1088, idle=1088, effective_cap=3912),
        )
        self.assertTrue(ok)

    def test_no_reflow_rejects_full_budget_when_quota_is_parked(self):
        ok, _ = audit_campaign_dose(
            {"q1_policy": "no-reflow"},
            stats(q1_saved_quota=1088, q1_idle_quota=1088),
            5000, flow(saved=1088, idle=1088, effective_cap=3912),
        )
        self.assertFalse(ok)


    def test_no_reflow_rejects_retroactive_cap_overrun(self):
        ok, _ = audit_campaign_dose(
            {"q1_policy": "no-reflow"},
            stats(campaign_charged_calls=3892, q1_saved_quota=1152,
                  q1_idle_quota=1152, q1_idle_quota_uncredited=0),
            3892, flow(charged=3892, saved=1152, idle=1152, effective_cap=3848),
        )
        self.assertFalse(ok)

    def test_late_release_records_credited_and_uncredited_quota(self):
        ok, _ = audit_campaign_dose(
            {"q1_policy": "no-reflow"},
            stats(campaign_call_budget=100, campaign_charged_calls=80,
                  q1_saved_quota=20, q1_idle_quota=20,
                  q1_idle_quota_uncredited=44),
            80, flow(charged=80, saved=20, idle=20, uncredited=44,
                     effective_cap=80, amount=20),
        )
        self.assertTrue(ok)

    def test_reflow_must_account_for_saved_quota(self):
        ok, _ = audit_campaign_dose(
            {"q1_policy": "reflow"},
            stats(q1_saved_quota=1792, q1_reflow_consumed=1596, q1_reflow_pool_left=196),
            5000, flow(saved=1792, reflow_used=1596, reflow_left=196),
        )
        self.assertTrue(ok)

    def test_direct_service_keeps_full_budget_without_quota_flow(self):
        ok, _ = audit_campaign_dose(
            {"q1_policy": "direct-service"}, stats(), 5000, flow())
        self.assertTrue(ok)

    def test_non_q1_arms_use_fixed_campaign_budget(self):
        non_q1_stats = stats()
        non_q1_stats.pop("q1_idle_quota_uncredited")
        ok, _ = audit_campaign_dose(
            {"q1_policy": "none"}, non_q1_stats, 5000, [])
        self.assertTrue(ok)

    def test_uncapped_wall_clock_smoke_accepts_consistent_non_q1_calls(self):
        uncapped_stats = stats(
            campaign_call_budget=0,
            campaign_charged_calls=582,
            campaign_budget_exhausted=0,
        )
        ok, detail = audit_campaign_dose(
            {"q1_policy": "none", "campaign_call_budget": 0},
            uncapped_stats,
            582,
            [],
            require_cap=False,
        )
        self.assertTrue(ok, detail)
        self.assertIn("uncapped", detail)

    def test_uncapped_smoke_accepts_zero_campaign_final_ledger_row(self):
        uncapped_stats = stats(
            campaign_call_budget=0,
            campaign_charged_calls=582,
            campaign_budget_exhausted=0,
        )
        final = {
            "kind": "campaign-final", "destination": "none",
            "amount": 0, "requested_amount": 0, "uncredited_amount": 0,
            "remaining": 0, "saved_total": 0, "idle_total": 0,
            "idle_uncredited_total": 0, "reflow_pool_left": 0,
            "reflow_consumed": 0, "effective_cap": 0,
            "charged_invocations": 582,
        }
        ok, detail = audit_campaign_dose(
            {"q1_policy": "none", "campaign_call_budget": 0},
            uncapped_stats, 582, [final], require_cap=False,
        )
        self.assertTrue(ok, detail)
        self.assertIn("uncapped", detail)

    def test_uncapped_smoke_rejects_nonzero_or_duplicate_flow_rows(self):
        uncapped_stats = stats(
            campaign_call_budget=0,
            campaign_charged_calls=582,
            campaign_budget_exhausted=0,
        )
        final = {
            "kind": "campaign-final", "destination": "none",
            "amount": 0, "requested_amount": 0, "uncredited_amount": 0,
            "remaining": 0, "saved_total": 0, "idle_total": 0,
            "idle_uncredited_total": 0, "reflow_pool_left": 0,
            "reflow_consumed": 0, "effective_cap": 0,
            "charged_invocations": 582,
        }
        actual_flow = {"kind": "validation-closed-unused", "amount": 1}
        nonzero_final = dict(final, saved_total=1)
        for rows in ([final, actual_flow], [final, dict(final)], [nonzero_final]):
            with self.subTest(rows=rows):
                ok, _ = audit_campaign_dose(
                    {"q1_policy": "none", "campaign_call_budget": 0},
                    uncapped_stats, 582, rows, require_cap=False,
                )
                self.assertFalse(ok)

    def test_uncapped_smoke_rejects_config_and_execution_mismatch(self):
        uncapped_stats = stats(
            campaign_call_budget=0,
            campaign_charged_calls=582,
            campaign_budget_exhausted=0,
        )
        config_mismatch, _ = audit_campaign_dose(
            {"q1_policy": "none", "campaign_call_budget": 5000},
            uncapped_stats, 582, [], require_cap=False,
        )
        execution_mismatch, _ = audit_campaign_dose(
            {"q1_policy": "none", "campaign_call_budget": 0},
            uncapped_stats, 581, [], require_cap=False,
        )
        self.assertFalse(config_mismatch)
        self.assertFalse(execution_mismatch)

    def test_non_q1_arm_rejects_nonzero_quota_without_q1_flow_ledger(self):
        non_q1_stats = stats(q1_saved_quota=1)
        ok, _ = audit_campaign_dose(
            {"q1_policy": "none"}, non_q1_stats, 5000, [])
        self.assertFalse(ok)

    def test_q1_no_reflow_still_requires_complete_idle_ledger(self):
        q1_stats = stats(q1_saved_quota=100, q1_idle_quota=100)
        q1_stats.pop("q1_idle_quota_uncredited")
        ok, _ = audit_campaign_dose(
            {"q1_policy": "no-reflow"}, q1_stats, 4900,
            flow(charged=4900, saved=100, idle=100, effective_cap=4900),
        )
        self.assertFalse(ok)

    def test_censored_campaign_accepts_consistent_partial_dose_but_not_as_fixed_dose(self):
        partial_stats = stats(campaign_charged_calls=1200, campaign_budget_exhausted=0)
        partial_flow = flow(charged=1200)
        ok, _ = audit_campaign_dose(
            {"q1_policy": "none"}, partial_stats, 1200, partial_flow,
            require_cap=False,
        )
        self.assertTrue(ok)
        fixed_ok, _ = audit_campaign_dose(
            {"q1_policy": "none"}, partial_stats, 1200, partial_flow,
        )
        self.assertFalse(fixed_ok)

    def test_censored_campaign_rejects_inconsistent_call_ledger(self):
        ok, _ = audit_campaign_dose(
            {"q1_policy": "none"},
            stats(campaign_charged_calls=1200, campaign_budget_exhausted=0),
            1199, flow(charged=1200), require_cap=False,
        )
        self.assertFalse(ok)


class UncappedQ1AuditTests(unittest.TestCase):
    def setUp(self):
        self.cfg = {"q1_policy": "reflow", "campaign_call_budget": 0,
                    "campaign_stop_mode": "wallclock", "campaign_duration_sec": 86400,
                    "campaign_resource_basis": "elapsed-time", "campaign_id": "campaign"}
        self.stats = stats(campaign_call_budget=0, campaign_charged_calls=3,
                           campaign_budget_exhausted=0, q1_saved_quota=2,
                           q1_reflow_consumed=1, q1_reflow_pool_left=1)
        base = {"campaign_id": "campaign", "amount": 0, "requested_amount": 0,
                "uncredited_amount": 0, "remaining": 0, "saved_total": 0,
                "idle_total": 0, "idle_uncredited_total": 0, "reflow_pool_left": 0,
                "reflow_consumed": 0, "effective_cap": 0, "flow_id": 0,
                "candidate_id": 0, "receiver_invocation_id": 0,
                "charged_invocations": 0, "time_ms": 0}
        self.rows = [
            dict(base, kind="candidate-unallocated", destination="ordinary-pool",
                 amount=2, requested_amount=2, remaining=2, saved_total=2,
                 reflow_pool_left=2, flow_id=1, candidate_id=7,
                 charged_invocations=1, time_ms=10),
            dict(base, kind="consumed", destination="ordinary-mutation", amount=1,
                 requested_amount=1, remaining=1, saved_total=2, reflow_pool_left=1,
                 reflow_consumed=1, flow_id=1, candidate_id=7, receiver_invocation_id=2,
                 charged_invocations=2, time_ms=20),
            dict(base, kind="campaign-final", destination="none", saved_total=2,
                 reflow_pool_left=1, reflow_consumed=1, receiver_invocation_id=3,
                 charged_invocations=3, time_ms=30),
        ]
        self.executions = [
            {"event": "invocation_start", "executed": True, "campaign_id": "campaign",
             "invocation_id": 2, "execution_kind": "mutation", "q1_flow_id": 1,
             "q1_flow_source_candidate": 7},
        ]

    def audit(self, **changes):
        args = dict(cfg=self.cfg, stats=self.stats, executed_count=3,
                    flow_rows=self.rows, require_cap=False, execution_rows=self.executions)
        args.update(changes)
        return audit_campaign_dose(**args)

    def test_q1c_and_q1d_accept_executed_conserved_reflow(self):
        for retain in (False, True):
            ok, detail = self.audit(cfg=dict(self.cfg, code_retain=retain))
            self.assertTrue(ok, detail)
            self.assertIn("matched-dose inference unavailable", detail)

    def test_q1a_accepts_zero_quota_terminal_summary(self):
        final = dict(self.rows[-1], saved_total=0, reflow_pool_left=0, reflow_consumed=0)
        zero_stats = dict(self.stats, q1_saved_quota=0, q1_reflow_consumed=0, q1_reflow_pool_left=0)
        ok, detail = self.audit(cfg=dict(self.cfg, q1_policy="direct-service"),
                                stats=zero_stats, flow_rows=[final], execution_rows=[])
        self.assertTrue(ok, detail)

    def test_q1b_is_rejected_even_if_ledger_is_present(self):
        ok, detail = self.audit(cfg=dict(self.cfg, q1_policy="no-reflow"))
        self.assertFalse(ok)
        self.assertIn("quota parking requires", detail)
        self.assertFalse(audit_wallclock_budget_role(
            dict(self.cfg, q1_policy="no-reflow"), self.stats)[0])

    def test_q1_rejects_fixed_dose_completion_or_wrong_resource_basis(self):
        for changes in ({"require_cap": True},
                        {"cfg": dict(self.cfg, campaign_resource_basis="target-invocations")},
                        {"cfg": dict(self.cfg, campaign_stop_mode="call-budget")},
                        {"cfg": dict(self.cfg, campaign_duration_sec=0)}):
            with self.subTest(changes=changes):
                self.assertFalse(self.audit(**changes)[0])

    def test_flow_conservation_and_receiver_evidence_are_required(self):
        mutations = ((0, {"campaign_id": "other"}), (0, {"amount": 3}),
                     (0, {"effective_cap": 5000}), (1, {"remaining": 0}),
                     (1, {"receiver_invocation_id": 3}), (1, {"candidate_id": 8}),
                     (1, {"reflow_consumed": 2}), (2, {"saved_total": 1}),
                     (2, {"charged_invocations": 2}), (0, {"kind": "unknown"}))
        for index, fields in mutations:
            rows = [dict(row) for row in self.rows]
            rows[index].update(fields)
            with self.subTest(index=index, fields=fields):
                self.assertFalse(self.audit(flow_rows=rows)[0])
        self.assertFalse(self.audit(execution_rows=None)[0])
        self.assertFalse(self.audit(execution_rows=[])[0])
        self.assertFalse(self.audit(flow_rows=self.rows + [self.rows[-1]])[0])
        self.assertFalse(self.audit(stats=dict(self.stats, q1_reflow_consumed=0))[0])

    def test_single_mechanism_event_cannot_enable_matched_call_claim(self):
        for retain in (False, True):
            cfg = dict(self.cfg, code_retain=retain)
            runtime = dict(self.stats, code_retain_admitted=1)
            self.assertTrue(audit_q1_mechanism_evidence(cfg, runtime)[0])
            scope = campaign_inference_scope(cfg)
            self.assertEqual(scope["resource_basis"], "elapsed-time")
            self.assertFalse(scope["fixed_call_allocation_eligible"])
            self.assertFalse(scope["matched_call_budget_available"])
            self.assertTrue(scope["inference_limits"])

    def test_actual_time_endpoint_cannot_end_early_even_for_short_runs(self):
        cfg = dict(self.cfg, start_time_ms=1000, campaign_duration_sec=60)
        for elapsed in (0, 57_000, 59_999):
            end = {"end_time_ms": 1000 + elapsed, "termination_reason": "signal-or-timeout"}
            self.assertFalse(audit_campaign_termination(cfg, end, 60_000)[0])
            self.assertFalse(audit_campaign_integrity_termination(cfg, end, 60_000)[0])
        end = {"end_time_ms": 61_000, "termination_reason": "wallclock-duration"}
        self.assertTrue(audit_campaign_termination(cfg, end, 60_000)[0])


class WallclockBudgetRoleTests(unittest.TestCase):
    def test_uncapped_is_explicitly_an_elapsed_time_endpoint(self):
        ok, detail = audit_wallclock_budget_role(
            {"campaign_stop_mode": "wallclock", "q1_policy": "reflow"},
            {"campaign_call_budget": 0, "campaign_budget_exhausted": 0})
        self.assertTrue(ok, detail)
        self.assertIn("cap disabled", detail)
    def test_nonbinding_common_cap_preserves_fixed_time_comparison(self):
        ok, detail = audit_wallclock_budget_role(
            {"campaign_stop_mode": "wallclock", "q1_policy": "reflow"},
            {"campaign_budget_exhausted": 0, "campaign_call_budget": 1000,
             "campaign_charged_calls": 700},
        )
        self.assertTrue(ok, detail)
        self.assertIn("nonbinding", detail)

    def test_q1b_exact_parked_quota_is_a_planned_stop(self):
        ok, detail = audit_wallclock_budget_role(
            {"campaign_stop_mode": "wallclock", "q1_policy": "no-reflow"},
            {"campaign_budget_exhausted": 1, "campaign_call_budget": 1000,
             "campaign_charged_calls": 760, "q1_idle_quota": 240},
        )
        self.assertTrue(ok, detail)
        self.assertIn("planned Q1b quota parking", detail)

    def test_q1b_nonconserved_parking_is_rejected(self):
        ok, _ = audit_wallclock_budget_role(
            {"campaign_stop_mode": "wallclock", "q1_policy": "no-reflow"},
            {"campaign_budget_exhausted": 1, "campaign_call_budget": 1000,
             "campaign_charged_calls": 760, "q1_idle_quota": 200},
        )
        self.assertFalse(ok)

    def test_other_arm_touching_safety_cap_is_censored(self):
        ok, detail = audit_wallclock_budget_role(
            {"campaign_stop_mode": "wallclock", "q1_policy": "reflow"},
            {"campaign_budget_exhausted": 1, "campaign_call_budget": 1000,
             "campaign_charged_calls": 1000, "q1_idle_quota": 0},
        )
        self.assertFalse(ok)
        self.assertIn("fixed-time run is censored", detail)


class FuzzerProtocolAuditTests(unittest.TestCase):
    def test_forked_daapd_http_parser_and_single_http_pin_pass(self):
        cfg = {
            "protocol_name": "HTTP",
            "orig_cmdline": "afl-fuzz -P HTTP -D 200000 -i seeds -o out",
        }
        self.assertTrue(audit_fuzzer_protocol(cfg, "HTTP")[0])

    def test_daap_label_or_wrong_wire_protocol_fails_http_expectation(self):
        wrong_values = (
            {"protocol_name": "DAAP", "orig_cmdline": "afl-fuzz -P DAAP"},
            {"protocol_name": "DAAP", "orig_cmdline": "afl-fuzz -P HTTP"},
            {"protocol_name": "HTTP", "orig_cmdline": "afl-fuzz -P DAAP"},
        )
        for cfg in wrong_values:
            with self.subTest(cfg=cfg):
                self.assertFalse(audit_fuzzer_protocol(cfg, "HTTP")[0])

    def test_missing_protocol_name_or_original_command_line_fails(self):
        incomplete = (
            {"orig_cmdline": "afl-fuzz -P HTTP"},
            {"protocol_name": "HTTP"},
            {},
        )
        for cfg in incomplete:
            with self.subTest(cfg=cfg):
                self.assertFalse(audit_fuzzer_protocol(cfg, "HTTP")[0])

    def test_repeated_protocol_option_fails_even_when_values_agree(self):
        cfg = {
            "protocol_name": "HTTP",
            "orig_cmdline": "afl-fuzz -P HTTP -P HTTP",
        }
        self.assertFalse(audit_fuzzer_protocol(cfg, "HTTP")[0])


class SharedIdentityAuditTests(unittest.TestCase):
    def identity(self):
        return {
            "target": "bftpd",
            "target_sha256": "target-hash",
            "fuzzer": "loopfuzz",
            "fuzzer_commit": "commit-id",
            "fuzzer_sha256": "fuzzer-hash",
            "loopfuzz_source_sha256": "a" * 64,
            "protocol_name": "FTP",
            "seeds_sha256": "seeds-hash",
            "image_digest": "sha256:image",
            "scope_sha256": "scope-hash",
            "coverage_schema_version": "loopfuzz-coverage-v4",
            "replay_harness_version": "replay-v1",
            "campaign_call_budget": 5000,
            "threshold_requested": 1,
            "threshold_resolved": 1,
            "scheduler_warmup_max_selections": 8,
            "episode_energy_cap": 32,
            "cal_reward_window_invocations": 16,
            "mock_gateway": {"port": 8099, "latency": 0, "seed": 20261102},
        }

    def test_equal_shared_identity_passes(self):
        ok, _ = shared_identity_difference([self.identity(), self.identity()])
        self.assertTrue(ok)

    def test_wallclock_window_and_stop_mode_are_shared_identity_fields(self):
        first = self.identity()
        second = self.identity()
        first.update(campaign_stop_mode="wallclock", campaign_duration_sec=86_400)
        second.update(campaign_stop_mode="call-budget", campaign_duration_sec=86_400)
        ok, detail = shared_identity_difference([first, second])
        self.assertFalse(ok)
        self.assertIn("campaign_stop_mode", detail)

    def test_sample_identity_preserves_wire_protocol_from_run_config(self):
        cfg = {
            "target": "forked-daapd",
            "target_sha256": "target-hash",
            "fuzzer": "loopfuzz",
            "fuzzer_commit": "commit-id",
            "fuzzer_sha256": "fuzzer-hash",
            "loopfuzz_source_sha256": "source-hash",
            "seeds_sha256": "seeds-hash",
            "image_digest": "sha256:image",
            "protocol_name": "HTTP",
            "campaign_call_budget": 5000,
            "threshold_requested": 1,
            "threshold_resolved": 1,
            "scheduler_warmup_max_selections": 8,
            "episode_energy_cap": 32,
            "cal_reward_window_invocations": 16,
        }
        terminal = {"scope_sha256": "scope-hash", "schema_version": "loopfuzz-coverage-v4"}
        scope = {"replay_harness_version": "replay-v1"}
        mock = {"effective_config": {"protocol": "HTTP", "port": 18123}}
        identity = shared_identity_from_sample(cfg, terminal, scope, mock)
        self.assertEqual(identity["protocol_name"], "HTTP")
        self.assertTrue(shared_identity_difference([identity, identity])[0])
        wrong_protocol = dict(identity, protocol_name="DAAP")
        ok, detail = shared_identity_difference([identity, wrong_protocol])
        self.assertFalse(ok)
        self.assertIn("protocol_name", detail)

    def test_source_fingerprint_is_part_of_shared_identity(self):
        changed = self.identity()
        changed["loopfuzz_source_sha256"] = "b" * 64
        ok, detail = shared_identity_difference([self.identity(), changed])
        self.assertFalse(ok)
        self.assertIn("loopfuzz_source_sha256", detail)

    def test_mock_or_replay_mismatch_fails(self):
        baseline = self.identity()
        changed = self.identity()
        changed["mock_gateway"] = {"port": 8099, "latency": 1, "seed": 20261102}
        ok, _ = shared_identity_difference([baseline, changed])
        self.assertFalse(ok)


        changed = self.identity()
        changed["replay_harness_version"] = "replay-v2"
        ok, _ = shared_identity_difference([baseline, changed])
        self.assertFalse(ok)

    def test_isolated_mock_ports_do_not_change_shared_semantics(self):
        first = self.identity()
        second = self.identity()
        first["mock_gateway"]["port"] = 18173
        second["mock_gateway"]["port"] = 18174
        ok, _ = shared_identity_difference([first, second])
        self.assertTrue(ok)

    def test_mock_protocol_change_still_fails_shared_identity(self):
        first = self.identity()
        second = self.identity()
        first["mock_gateway"]["protocol"] = "SMTP"
        second["mock_gateway"]["protocol"] = "FTP"
        ok, _ = shared_identity_difference([first, second])
        self.assertFalse(ok)

    def test_arm_control_mismatch_fails(self):
        for field, value in (
            ("target", "proftpd"),
            ("protocol_name", "SMTP"),
            ("fuzzer", "other-fuzzer"),
            ("seeds_sha256", "different-seeds"),
            ("image_digest", "sha256:other-image"),
            ("scope_sha256", "other-scope"),
            ("campaign_call_budget", 4999),
            ("threshold_requested", 512),
            ("scheduler_warmup_max_selections", 9),
            ("episode_energy_cap", 33),
            ("cal_reward_window_invocations", 17),
        ):
            with self.subTest(field=field):
                baseline = self.identity()
                changed = self.identity()
                changed[field] = value
                ok, _ = shared_identity_difference([baseline, changed])
                self.assertFalse(ok)

    def test_gateway_request_count_differences_do_not_change_identity(self):
        first = self.identity()
        second = self.identity()
        first["mock_requests"] = 17
        second["mock_requests"] = 0
        first["mock_gateway_requests"] = 17
        second["mock_gateway_requests"] = 0
        ok, _ = shared_identity_difference([first, second])
        self.assertTrue(ok)

    def test_nested_effective_mock_configuration_is_compared_completely(self):
        baseline = self.identity()
        changed = self.identity()
        changed["mock_gateway"] = {
            "port": 8099,
            "latency": 0,
            "seed": 20261102,
            "mix": {"mut": 20, "bad": 16},
        }
        baseline["mock_gateway"] = {
            "port": 8099,
            "latency": 0,
            "seed": 20261102,
            "mix": {"mut": 20, "bad": 15},
        }
        ok, _ = shared_identity_difference([baseline, changed])
        self.assertFalse(ok)

    def test_missing_mock_configuration_fails_closed(self):
        identity = self.identity()
        identity["mock_gateway"] = None
        ok, _ = shared_identity_difference([identity])
        self.assertFalse(ok)

    def test_missing_identity_field_fails_closed(self):
        identity = self.identity()
        identity.pop("seeds_sha256")
        ok, _ = shared_identity_difference([identity])
        self.assertFalse(ok)

    def test_contract_field_list_is_complete(self):
        self.assertIn("fuzzer", SHARED_COMPARISON_FIELDS)
        self.assertIn("threshold_requested", SHARED_COMPARISON_FIELDS)
        self.assertIn("mock_gateway", SHARED_COMPARISON_FIELDS)
        self.assertIn("replay_harness_version", SHARED_COMPARISON_FIELDS)


class StrictSmokeQualificationTests(unittest.TestCase):
    def test_fixed_call_termination_requires_reason_and_runtime_below_900_seconds(self):
        start = {"start_time_ms": 1_000_000}
        end = {"end_time_ms": 1_899_999, "termination_reason": "campaign-call-budget"}
        self.assertTrue(audit_campaign_termination(start, end)[0])

        end["end_time_ms"] = 1_900_000
        self.assertFalse(audit_campaign_termination(start, end)[0])
        end["end_time_ms"] = 1_899_999
        end["termination_reason"] = "signal-or-timeout"
        self.assertFalse(audit_campaign_termination(start, end)[0])
        self.assertFalse(audit_campaign_termination(start, {"termination_reason": "campaign-call-budget"})[0])

    def test_wallclock_termination_accepts_24h_end_and_keeps_budget_censor(self):
        start = {
            "start_time_ms": 1_000_000,
            "campaign_stop_mode": "wallclock",
            "campaign_duration_sec": 86_400,
        }
        end = {
            "end_time_ms": 87_400_000,
            "termination_reason": "wallclock-duration",
        }
        self.assertTrue(audit_campaign_termination(start, end)[0])
        end["end_time_ms"] = 87_300_000
        self.assertTrue(audit_campaign_termination(start, end)[0])
        end["end_time_ms"] = 87_760_001
        self.assertFalse(audit_campaign_termination(start, end)[0])
        end["end_time_ms"] = 87_400_000
        end["termination_reason"] = "campaign-call-budget"
        self.assertFalse(audit_campaign_termination(start, end)[0])

    def test_wallclock_dose_audit_does_not_require_the_budget_to_bind(self):
        ok, _ = audit_campaign_dose(
            {"q1_policy": "reflow"},
            stats(campaign_charged_calls=80, campaign_budget_exhausted=0,
                  q1_saved_quota=20, q1_reflow_consumed=8,
                  q1_reflow_pool_left=12),
            80, flow(charged=80, saved=20, reflow_used=8, reflow_left=12),
            require_cap=False,
        )
        self.assertTrue(ok)

    def test_wallclock_budget_censor_requires_a_reconciled_timestamp(self):
        cfg = {"campaign_stop_mode": "wallclock", "start_time_ms": 1000}
        end = {
            "end_time_ms": 9000,
            "campaign_budget_censored": True,
            "campaign_budget_exhausted_time_ms": 5000,
        }
        self.assertTrue(audit_wallclock_budget_censor(cfg, end, {"campaign_budget_exhausted": 1})[0])
        end["campaign_budget_exhausted_time_ms"] = 10000
        self.assertFalse(audit_wallclock_budget_censor(cfg, end, {"campaign_budget_exhausted": 1})[0])
        self.assertFalse(audit_wallclock_budget_censor(cfg, end, {"campaign_budget_exhausted": 0})[0])

    def test_q1_mechanism_audit_requires_policy_specific_events(self):
        self.assertTrue(audit_q1_mechanism_evidence(
            {"q1_policy": "no-reflow"}, {"q1_idle_quota": 64},
        )[0])
        self.assertFalse(audit_q1_mechanism_evidence(
            {"q1_policy": "no-reflow"}, {"q1_idle_quota": 0},
        )[0])
        self.assertTrue(audit_q1_mechanism_evidence(
            {"q1_policy": "reflow"}, {"q1_reflow_consumed": 12},
        )[0])
        self.assertFalse(audit_q1_mechanism_evidence(
            {"q1_policy": "reflow", "code_retain": True},
            {"q1_reflow_consumed": 12, "code_retain_admitted": 0},
        )[0])

    def test_integrity_accepts_configured_timeout_but_fixed_dose_does_not(self):
        start = {"start_time_ms": 1_000_000}
        end = {"end_time_ms": 1_900_000, "termination_reason": "signal-or-timeout"}
        self.assertTrue(audit_campaign_integrity_termination(start, end)[0])
        self.assertFalse(audit_campaign_termination(start, end)[0])
        early = {"end_time_ms": 1_800_000, "termination_reason": "signal-or-timeout"}
        self.assertFalse(audit_campaign_integrity_termination(start, early)[0])

    def test_extended_timeout_changes_runtime_window_without_changing_default(self):
        start = {"start_time_ms": 1_000_000}
        at_240_minutes = {
            "end_time_ms": 15_399_999,
            "termination_reason": "campaign-call-budget",
        }
        self.assertFalse(audit_campaign_termination(start, at_240_minutes)[0])
        self.assertTrue(audit_campaign_termination(start, at_240_minutes, 14_400_000)[0])

        timeout = {
            "end_time_ms": 15_400_000,
            "termination_reason": "signal-or-timeout",
        }
        self.assertFalse(audit_campaign_integrity_termination(start, timeout)[0])
        self.assertTrue(audit_campaign_integrity_termination(start, timeout, 14_400_000)[0])
        early = {
            "end_time_ms": 14_000_000,
            "termination_reason": "signal-or-timeout",
        }
        self.assertFalse(audit_campaign_integrity_termination(start, early, 14_400_000)[0])

    def manifest_rows(self):
        return [
            {"archive_name": f"run_{run}.tar.gz", "run": str(run), "container_id": f"container-{run}"}
            for run in range(1, 4)
        ]

    def summary_rows(self):
        return [
            {"source": f"run_{run}.tar.gz", "run": str(run)}
            for run in range(1, 4)
        ]

    def test_three_repeat_manifest_and_summary_mapping_is_one_to_one(self):
        self.assertTrue(audit_repeat_mapping(self.manifest_rows(), self.summary_rows())[0])

        manifests = self.manifest_rows()
        manifests[2]["archive_name"] = manifests[0]["archive_name"]
        self.assertFalse(audit_repeat_mapping(manifests, self.summary_rows())[0])

        manifests = self.manifest_rows()
        summaries = self.summary_rows()
        summaries[2]["run"] = "2"
        self.assertFalse(audit_repeat_mapping(manifests, summaries)[0])

        manifests = self.manifest_rows()
        manifests[2]["container_id"] = manifests[0]["container_id"]
        self.assertFalse(audit_repeat_mapping(manifests, self.summary_rows())[0])

    def test_status_files_are_unique_and_match_manifest(self):
        manifests = self.manifest_rows()
        with tempfile.TemporaryDirectory() as temporary:
            statuses = Path(temporary)
            for row in manifests:
                (statuses / f"{row['archive_name']}.status").write_text(
                    f"archive_name={row['archive_name']}\ncontainer_id={row['container_id']}\n"
                )
            self.assertTrue(audit_status_mapping(manifests, statuses)[0])
            (statuses / "extra.tar.gz.status").write_text(
                "archive_name=extra.tar.gz\ncontainer_id=container-extra\n"
            )
            self.assertFalse(audit_status_mapping(manifests, statuses)[0])

    def test_archive_member_lookup_rejects_missing_or_duplicate_paths(self):
        names = ["out-bftpd-loopfuzz/run-config.jsonl"]
        self.assertEqual(find_unique_archive_member(names, "out-bftpd-loopfuzz/", "run-config.jsonl"), names[0])
        self.assertIsNone(find_unique_archive_member(names, "out-bftpd-loopfuzz/", "optional.jsonl", optional=True))
        with self.assertRaises(ValueError):
            find_unique_archive_member(names, "out-bftpd-loopfuzz/", "missing.jsonl")
        with self.assertRaises(ValueError):
            find_unique_archive_member(
                names + ["duplicate/out-bftpd-loopfuzz/run-config.jsonl"],
                "out-bftpd-loopfuzz/", "run-config.jsonl",
            )

    def test_coverage_schema_selection_keeps_v4_separate_from_sampled_v5(self):
        prefix = "out-exim-loopfuzz/"
        self.assertEqual(coverage_archive_schema(
            [prefix + "cov_over_time.csv.v4/terminal.json"], prefix),
            ("loopfuzz-coverage-v4", "cov_over_time.csv.v4"))
        self.assertEqual(coverage_archive_schema(
            [prefix + "cov_over_time.csv.v5/terminal.json"], prefix),
            ("loopfuzz-coverage-v5-sampled-checkpoints", "cov_over_time.csv.v5"))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            coverage_archive_schema([
                prefix + "cov_over_time.csv.v4/terminal.json",
                prefix + "cov_over_time.csv.v5/terminal.json"], prefix)

    def sampled_coverage_fixture(self):
        scope = {
            "schema_version": "loopfuzz-coverage-v5-sampled-checkpoints",
            "sources": {"main.c": "source-hash"},
            "branch_ids": [["main.c", 1, 0]],
            "line_ids": [["main.c", 1]],
            "replay_harness_version": "test-harness-v1",
            "source_root": "/provenance/path/that-is-not-measurement-identity",
            "scope_sha256": "",
            "checkpoint_policy": {
                "kind": "step-plus-terminal-and-seed-boundary", "step": 2,
                "final_checkpoint_required": True, "seed_boundary_required": True,
                "every_input_has_replay_ledger": True,
            },
        }
        scope_identity = {field: scope[field] for field in audit_smoke.SCOPE_IDENTITY_FIELDS
                          if field in scope}
        scope["scope_sha256"] = hashlib.sha256(json.dumps(
            scope_identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        report = {"files": [{"file": "main.c", "lines": [{"line_number": 1, "count": 1,
                   "branches": [{"count": 1}]}]}]}
        raw_snapshot = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        snapshot_hash = hashlib.sha256(raw_snapshot).hexdigest()
        payload = b"EHLO example.test\r\n"
        raw_input = struct.pack("<I", len(payload)) + payload
        input_hash = hashlib.sha256(raw_input).hexdigest()
        replay_log, reset_log = b"Size of the current packet 1\n", b"reset-and-validate: ok\n"
        frame_rows = [
            {"event": "session_begin", "schema": "loopfuzz-replay-frame-ledger-v1",
             "input_file": "id:000001", "input_size": len(raw_input), "protocol": "SMTP"},
            {"event": "frame", "frame": 1, "len": len(payload), "read_complete": True,
             "pre_recv_ok": True, "send_attempt": True, "sent_bytes": len(payload),
             "send_errno": 0, "post_recv_ok": True},
            {"event": "session_end", "frames_total": 1, "stop_reason": "eof"},
        ]
        frame_raw = b"".join((json.dumps(row) + "\n").encode() for row in frame_rows)
        replay = {"replay_log_file": "replay-000001.log",
                  "replay_log_sha256": hashlib.sha256(replay_log).hexdigest(),
                  "reset_command_succeeded": True,
                  "frame_ledger_file": "replay-000001-frame-ledger.jsonl",
                  "frame_ledger_sha256": hashlib.sha256(frame_raw).hexdigest(),
                  "frames_total": 1, "frames_attempted": 1, "frames_sent_complete": 1,
                  "frames_unattempted": 0, "send_stop_reason": "eof", "send_completeness": "complete"}
        reset = {"command": ["true"], "exit_code": 0, "command_succeeded": True,
                 "log_file": "reset-000001.log", "log_sha256": hashlib.sha256(reset_log).hexdigest()}
        plan = [{"filename": "id:000001", "input_sha256": input_hash}]
        ledger = [{"schema_version": "loopfuzz-coverage-v5-sampled-checkpoints", "idx": 1,
                   "filename": "id:000001", "input_sha256": input_hash,
                   "input_hash_verified_before_replay": True, "instrumented_objects_unchanged": True,
                   "reset": reset, "replay": replay, "checkpoint": True,
                   "coverage_event_idx": 1, "snapshot_file": "snapshot-000001.json.gz",
                   "snapshot_sha256": snapshot_hash}]
        event = {"schema_version": "loopfuzz-coverage-v5-sampled-checkpoints", "idx": 1,
                 "replay_input_idx": 1, "scope_sha256": scope["scope_sha256"],
                 "snapshot_file": "snapshot-000001.json.gz", "snapshot_sha256": snapshot_hash,
                 "replay": replay, "reset": reset, "snapshot_covered_branches": 1,
                 "cumulative_covered_branches": 1, "snapshot_covered_lines": 1,
                 "cumulative_covered_lines": 1,
                 "newly_covered_branch_ids": [["main.c", 1, 0]]}
        witness = {"idx": 1, "filename": "id:000001", "input_sha256": input_hash,
                   "checkpoint": True, "snapshot_sha256": snapshot_hash}
        terminal = {"schema_version": scope["schema_version"], "scope_sha256": scope["scope_sha256"],
                    "coverage_capture_mode": "sampled-step-plus-terminal",
                    "sampled_checkpoint_input_indices": [1], "n_replayed": 1,
                    "n_coverage_checkpoints": 1, "n_seed_replayed": 0,
                    "seed_replay_indices": [], "seed_covered_branch_ids": [],
                    "seed_covered_line_ids": [], "executed_input_witnesses": [witness],
                    "covered_branch_ids": [["main.c", 1, 0]], "covered_line_ids": [["main.c", 1]],
                    "coverage_complete": True, "acceptance": "complete",
                    "all_reset_commands_succeeded": True, "incomplete_replays": [],
                    "n_unreplayable_ledger_entries": 0, "replay_anomalies": {"total": 0},
                    "unexpected_snapshot_decrease": False}
        csv_io = io.StringIO()
        writer = csv.DictWriter(csv_io, fieldnames=("Time", "l_per", "l_abs", "b_per", "b_abs", "idx",
                                                    "scope_sha256", "snapshot_sha256"))
        writer.writeheader()
        writer.writerow({"Time": 1.0, "l_per": 100, "l_abs": 1, "b_per": 100, "b_abs": 1,
                         "idx": 1, "scope_sha256": scope["scope_sha256"],
                         "snapshot_sha256": snapshot_hash})
        members = {
            "cov_over_time.csv.v5/scope.json": json.dumps(scope).encode(),
            "cov_over_time.csv.v5/terminal.json": json.dumps(terminal).encode(),
            "cov_over_time.csv.v5/replay-plan.json": json.dumps(plan).encode(),
            "cov_over_time.csv.v5/replay-ledger.jsonl": (json.dumps(ledger[0]) + "\n").encode(),
            "cov_over_time.csv.v5/checkpoints.jsonl": (json.dumps(event) + "\n").encode(),
            "cov_over_time.csv.v5/snapshot-000001.json.gz": gzip.compress(raw_snapshot),
            "cov_over_time.csv.v5/replay-000001.log": replay_log,
            "cov_over_time.csv.v5/reset-000001.log": reset_log,
            "cov_over_time.csv.v5/replay-000001-frame-ledger.jsonl": frame_raw,
            "replayable-queue/id:000001": raw_input,
            "cov_over_time.csv": csv_io.getvalue().encode(),
        }
        return members, terminal

    def test_sampled_coverage_audit_reconstructs_terminal_from_every_input(self):
        members, terminal = self.sampled_coverage_fixture()
        result = audit_sampled_coverage_archive(
            lambda suffix: members[suffix], "exim", [
                "out-exim-loopfuzz/replayable-queue/id:000001",
            ],
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["inputs"], 1)
        self.assertEqual(result["checkpoints"], 1)
        with self.assertRaisesRegex(ValueError, "not permitted"):
            audit_sampled_coverage_archive(lambda suffix: members[suffix], "bftpd")
        with self.assertRaisesRegex(ValueError, "archived replay input hash"):
            changed = dict(members, **{"replayable-queue/id:000001": b"other input"})
            audit_sampled_coverage_archive(lambda suffix: changed[suffix], "exim")
        with self.assertRaisesRegex(ValueError, "archived replay input is empty"):
            changed = dict(members, **{"replayable-queue/id:000001": b""})
            audit_sampled_coverage_archive(lambda suffix: changed[suffix], "exim")

        smoke_terminal = dict(
            terminal, coverage_complete=False, acceptance="incomplete",
            replay_truncated=True, planned_n_replayed=2, replay_input_limit=1,
            smoke_mode=True, incomplete_reasons=["smoke-replay-input-cap"],
        )
        smoke_members = dict(members, **{
            "cov_over_time.csv.v5/terminal.json": json.dumps(smoke_terminal).encode(),
            "replayable-queue/id:000002": b"second full-queue input",
        })
        smoke_archive_names = [
            "out-exim-loopfuzz/replayable-queue/id:000001",
            "out-exim-loopfuzz/replayable-queue/id:000002",
        ]
        smoke_result = audit_sampled_coverage_archive(
            lambda suffix: smoke_members[suffix], "exim", smoke_archive_names)
        self.assertTrue(smoke_result["ok"])
        self.assertFalse(smoke_result["coverage_complete"])
        self.assertEqual(smoke_result["inputs"], 1)
        self.assertEqual(smoke_result["planned_inputs"], 2)
        with self.assertRaisesRegex(ValueError, "truncated replay plan"):
            audit_sampled_coverage_archive(
                lambda suffix: smoke_members[suffix], "exim", smoke_archive_names[:1])

    def test_sampled_reset_authoritative_record_without_optional_replay_copy(self):
        prefix = "cov_over_time.csv.v5/"
        for mismatch in (None, False):
            members, _ = self.sampled_coverage_fixture()
            ledger = audit_smoke.read_jsonl(members[prefix + "replay-ledger.jsonl"])
            event = audit_smoke.read_jsonl(members[prefix + "checkpoints.jsonl"])[0]
            replay = ledger[0]["replay"]
            if mismatch is None:
                replay.pop("reset_command_succeeded")
            else:
                replay["reset_command_succeeded"] = mismatch
            event["replay"] = replay
            members[prefix + "replay-ledger.jsonl"] = (json.dumps(ledger[0]) + "\n").encode()
            members[prefix + "checkpoints.jsonl"] = (json.dumps(event) + "\n").encode()
            if mismatch is None:
                self.assertTrue(audit_sampled_coverage_archive(members.__getitem__, "exim")["ok"])
            else:
                with self.assertRaisesRegex(ValueError, "reset result"):
                    audit_sampled_coverage_archive(members.__getitem__, "exim")

    def test_sampled_audit_rejects_missing_or_tampered_raw_evidence(self):
        for tail in ("replay-000001.log", "reset-000001.log", "replay-000001-frame-ledger.jsonl"):
            for tamper in (False, True):
                with self.subTest(artifact=tail, tamper=tamper):
                    members, _ = self.sampled_coverage_fixture()
                    key = "cov_over_time.csv.v5/" + tail
                    if tamper:
                        members[key] += b"tampered\n"
                    else:
                        del members[key]
                    with self.assertRaisesRegex(ValueError, "missing underlying evidence|hash"):
                        audit_sampled_coverage_archive(members.__getitem__, "exim")

    def test_sampled_audit_rejects_partial_send_even_with_rehashed_ledgers(self):
        for mutation in ("short-send", "unattempted", "recv-failure", "read-failure", "errno",
                         "prefix", "duplicate-end", "wrong-input", "wrong-size", "wrong-protocol",
                         "trailing-bytes", "false-reset-exit", "summary-count", "unsafe-ledger"):
            with self.subTest(mutation=mutation):
                members, _ = self.sampled_coverage_fixture()
                prefix = "cov_over_time.csv.v5/"
                frame_key = prefix + "replay-000001-frame-ledger.jsonl"
                frames = audit_smoke.read_jsonl(members[frame_key])
                ledger = audit_smoke.read_jsonl(members[prefix + "replay-ledger.jsonl"])
                event = audit_smoke.read_jsonl(members[prefix + "checkpoints.jsonl"])[0]
                replay = ledger[0]["replay"]
                if mutation == "short-send":
                    frames[1]["sent_bytes"] -= 1
                elif mutation == "unattempted":
                    frames[1].update(send_attempt=False, sent_bytes=-2)
                elif mutation == "recv-failure":
                    frames[1]["pre_recv_ok"] = False
                elif mutation == "read-failure":
                    frames[1]["read_complete"] = False
                elif mutation == "errno":
                    frames[1]["send_errno"] = 5
                elif mutation == "prefix":
                    # Add a second framed input but keep a coherent, fully sent
                    # first-frame ledger and its success summary unchanged.
                    raw = members["replayable-queue/id:000001"] + struct.pack("<I", 4) + b"QUIT"
                    members["replayable-queue/id:000001"] = raw
                    frames[0]["input_size"] = len(raw)
                    digest = hashlib.sha256(raw).hexdigest()
                    plan = json.loads(members[prefix + "replay-plan.json"])
                    plan[0]["input_sha256"] = digest
                    members[prefix + "replay-plan.json"] = json.dumps(plan).encode()
                    ledger[0]["input_sha256"] = digest
                    replay["frames_unattempted"] = 1
                    replay["send_completeness"] = "incomplete"
                elif mutation == "duplicate-end":
                    frames.append(frames[-1].copy())
                elif mutation == "wrong-input":
                    frames[0]["input_file"] = "id:000999"
                elif mutation == "wrong-size":
                    frames[0]["input_size"] += 1
                elif mutation == "wrong-protocol":
                    frames[0]["protocol"] = "FTP"
                elif mutation == "trailing-bytes":
                    raw = members["replayable-queue/id:000001"] + b"X"
                    members["replayable-queue/id:000001"] = raw
                    frames[0]["input_size"] = len(raw)
                    digest = hashlib.sha256(raw).hexdigest()
                    plan = json.loads(members[prefix + "replay-plan.json"])
                    plan[0]["input_sha256"] = digest
                    members[prefix + "replay-plan.json"] = json.dumps(plan).encode()
                    ledger[0]["input_sha256"] = digest
                elif mutation == "false-reset-exit":
                    ledger[0]["reset"]["exit_code"] = 1
                elif mutation == "summary-count":
                    replay["frames_sent_complete"] = 9
                elif mutation == "unsafe-ledger":
                    replay["frame_ledger_file"] = "../replay-000001-frame-ledger.jsonl"
                members[frame_key] = b"".join((json.dumps(row) + "\n").encode() for row in frames)
                replay["frame_ledger_sha256"] = hashlib.sha256(members[frame_key]).hexdigest()
                event["replay"] = replay
                event["reset"] = ledger[0]["reset"]
                members[prefix + "replay-ledger.jsonl"] = (json.dumps(ledger[0]) + "\n").encode()
                members[prefix + "checkpoints.jsonl"] = (json.dumps(event) + "\n").encode()
                with self.assertRaisesRegex(ValueError, "sampled input 1"):
                    audit_sampled_coverage_archive(members.__getitem__, "exim")

    def server_rejection_fixture(self):
        """One Exim input whose second frame follows an orderly server-side drop."""
        members, _ = self.sampled_coverage_fixture()
        prefix = "cov_over_time.csv.v5/"
        # Two framed messages; only the first is delivered before Exim closes.
        payload_1 = b"EHLO example.test\r\n"
        payload_2 = b"MAIL FROM:<ubuntu@ubuntu>\r\n"
        raw_input = (struct.pack("<I", len(payload_1)) + payload_1 +
                     struct.pack("<I", len(payload_2)) + payload_2)
        input_hash = hashlib.sha256(raw_input).hexdigest()
        members["replayable-queue/id:000001"] = raw_input
        replay_log = (
            b"Size of the current packet 1 is  17\n"
            b"--------------------------------\n"
            b"Responses from server:0-220-501-500-500-500-500-\n"
            b"++++++++++++++++++++++++++++++++\n"
            b"Responses in details:\n"
            b"220 host ESMTP Exim 4.96 Tue, 17 Nov 2026 04:40:31 +0000\r\n"
            b"501 NUL characters are not allowed in SMTP commands\r\n"
            b"500 unrecognized command\r\n"
            b"500-unrecognized command\r\n"
            b"500 Too many syntax or protocol errors\r\n"
            b"\n"
            b"-------------------------------- 4354 SIGTERM/SIGINT seen\n"
            b"4354 daemon forking for daemon-del-pidfile\n"
        )
        reset_log = b"reset-and-validate: ok\n"
        frame_rows = [
            {"event": "session_begin", "schema": "loopfuzz-replay-frame-ledger-v1",
             "input_file": "id:000001", "input_size": len(raw_input), "protocol": "SMTP"},
            {"event": "frame", "frame": 1, "len": len(payload_1), "read_complete": True,
             "pre_recv_ok": True, "send_attempt": True, "sent_bytes": len(payload_1),
             "send_errno": 0, "post_recv_ok": True, "peer_closed": False},
            {"event": "session_end", "frames_total": 1,
             "stop_reason": "peer-closed-before-input-end", "peer_closed": True},
        ]
        frame_raw = b"".join((json.dumps(row) + "\n").encode() for row in frame_rows)
        replay = {"replay_log_file": "replay-000001.log",
                  "replay_log_sha256": hashlib.sha256(replay_log).hexdigest(),
                  "reset_command_succeeded": True,
                  "frame_ledger_file": "replay-000001-frame-ledger.jsonl",
                  "frame_ledger_sha256": hashlib.sha256(frame_raw).hexdigest(),
                  "frames_total": 1, "frames_attempted": 1, "frames_sent_complete": 1,
                  "frames_unattempted": 1,
                  "send_stop_reason": "peer-closed-before-input-end",
                  "send_completeness": "incomplete",
                  "client_exit_code": 2, "client_timed_out": False,
                  "replay_anomaly": True, "anomaly_kind": "client-exit-2",
                  "server_crashed": False, "server_ready": True,
                  "session_coverage_missing": False}
        reset = {"command": ["true"], "exit_code": 0, "command_succeeded": True,
                 "log_file": "reset-000001.log", "log_sha256": hashlib.sha256(reset_log).hexdigest()}
        ledger = [{"schema_version": "loopfuzz-coverage-v5-sampled-checkpoints", "idx": 1,
                   "filename": "id:000001", "input_sha256": input_hash,
                   "input_hash_verified_before_replay": True, "instrumented_objects_unchanged": True,
                   "reset": reset, "replay": replay, "checkpoint": True,
                   "coverage_event_idx": 1, "snapshot_file": "snapshot-000001.json.gz",
                   "snapshot_sha256": json.loads(
                       members[prefix + "checkpoints.jsonl"].decode())["snapshot_sha256"]}]
        event = json.loads(members[prefix + "checkpoints.jsonl"].decode())
        event["replay"] = replay
        event["reset"] = reset
        terminal = json.loads(members[prefix + "terminal.json"].decode())
        terminal["executed_input_witnesses"][0]["input_sha256"] = input_hash
        terminal.update(
            coverage_complete=False, acceptance="incomplete",
            incomplete_replays=[{"filename": "id:000001",
                                 "reasons": ["client-exit-2", "frame-ledger-incomplete"]}],
            replay_anomalies={"kinds": {"client-exit-2": 1}, "total": 1})
        plan = [{"filename": "id:000001", "input_sha256": input_hash}]
        members["cov_over_time.csv.v5/terminal.json"] = json.dumps(terminal).encode()
        members[prefix + "replay-plan.json"] = json.dumps(plan).encode()
        members[prefix + "replay-ledger.jsonl"] = (json.dumps(ledger[0]) + "\n").encode()
        members[prefix + "checkpoints.jsonl"] = (json.dumps(event) + "\n").encode()
        members[prefix + "replay-000001.log"] = replay_log
        members[prefix + "reset-000001.log"] = reset_log
        members[prefix + "replay-000001-frame-ledger.jsonl"] = frame_raw
        return members, replay, frame_rows, replay_log

    def test_sampled_audit_accepts_evidenced_exim_server_rejection_as_incomplete(self):
        members, _, _, _ = self.server_rejection_fixture()
        result = audit_sampled_coverage_archive(members.__getitem__, "exim")
        self.assertTrue(result["ok"])
        self.assertFalse(result["coverage_complete"])
        self.assertEqual(result["complete_inputs"], 0)
        self.assertEqual(len(result["server_rejected_inputs"]), 1)
        rejection = result["server_rejected_inputs"][0]
        self.assertEqual(rejection["stop_reason"], "peer-closed-before-input-end")
        self.assertEqual(rejection["final_response"], "500 Too many syntax or protocol errors")
        self.assertEqual(rejection["frames_delivered"], 1)
        self.assertEqual(rejection["frames_unattempted"], 1)

    def test_sampled_audit_rejects_unproven_or_confounded_server_rejection(self):
        for mutation in ("clean-final-response", "no-prior-error", "send-short",
                         "client-exit-zero", "stop-reason-mismatch", "confounded-crash",
                         "terminal-disagreement"):
            with self.subTest(mutation=mutation):
                members, replay, frame_rows, replay_log = self.server_rejection_fixture()
                prefix = "cov_over_time.csv.v5/"
                ledger = audit_smoke.read_jsonl(members[prefix + "replay-ledger.jsonl"])
                terminal = json.loads(members[prefix + "terminal.json"].decode())
                if mutation == "clean-final-response":
                    replay_log = replay_log.replace(
                        b"500 Too many syntax or protocol errors\r\n", b"250 OK\r\n")
                    members[prefix + "replay-000001.log"] = replay_log
                    replay["replay_log_sha256"] = hashlib.sha256(replay_log).hexdigest()
                elif mutation == "no-prior-error":
                    replay_log = (replay_log.replace(b"501 NUL characters are not allowed in SMTP commands\r\n", b"")
                                  .replace(b"500 unrecognized command\r\n", b"")
                                  .replace(b"500-unrecognized command\r\n", b""))
                    members[prefix + "replay-000001.log"] = replay_log
                    replay["replay_log_sha256"] = hashlib.sha256(replay_log).hexdigest()
                elif mutation == "send-short":
                    frame_rows[1]["sent_bytes"] -= 1
                    replay["frames_sent_complete"] = 0
                elif mutation == "client-exit-zero":
                    replay["client_exit_code"] = 0
                elif mutation == "stop-reason-mismatch":
                    frame_rows[-1]["stop_reason"] = "send-short-or-error"
                    replay["send_stop_reason"] = "send-short-or-error"
                elif mutation == "confounded-crash":
                    replay["server_crashed"] = True
                    ledger[0]["replay"]["server_crashed"] = True
                    terminal["incomplete_replays"] = [{"filename": "id:000001", "reasons": [
                        "server-signal-exit", "client-exit-2", "frame-ledger-incomplete"]}]
                    terminal["replay_anomalies"] = {"kinds": {"client-exit-2": 1,
                                                              "server-signal-exit": 1}, "total": 2}
                elif mutation == "terminal-disagreement":
                    terminal["incomplete_replays"] = []
                if mutation != "terminal-disagreement":
                    members[prefix + "replay-000001-frame-ledger.jsonl"] = b"".join(
                        (json.dumps(row) + "\n").encode() for row in frame_rows)
                    replay["frame_ledger_sha256"] = hashlib.sha256(
                        members[prefix + "replay-000001-frame-ledger.jsonl"]).hexdigest()
                ledger[0]["replay"] = replay
                event = audit_smoke.read_jsonl(members[prefix + "checkpoints.jsonl"])[0]
                event["replay"] = replay
                members[prefix + "replay-ledger.jsonl"] = (json.dumps(ledger[0]) + "\n").encode()
                members[prefix + "checkpoints.jsonl"] = (json.dumps(event) + "\n").encode()
                members[prefix + "terminal.json"] = json.dumps(terminal).encode()
                with self.assertRaises(ValueError):
                    audit_sampled_coverage_archive(members.__getitem__, "exim")

    def test_sampled_audit_verifies_real_q1d_repair_archive_without_upgrading_smoke(self):
        archive = Path(__file__).parent / "q1d_repeat3_repair_20261117T011436Z" / "out-proftpd-loopfuzz_3.tar.gz"
        if not archive.is_file():
            self.skipTest("local repair archive is not installed")
        with tarfile.open(archive) as tf:
            # Read sequentially once, avoiding repeated gzip decompression.
            data = {info.name.removeprefix("./"): tf.extractfile(info).read()
                    for info in tf.getmembers() if info.isfile()}
        prefix = "out-proftpd-loopfuzz/"
        result = audit_sampled_coverage_archive(lambda name: data[prefix + name], "proftpd", data)
        self.assertEqual((result["inputs"], result["planned_inputs"]), (32, 254))
        self.assertEqual(result["verified_log_pairs"], 32)
        self.assertEqual(result["verified_frame_ledgers"], 32)
        self.assertEqual(result["verified_frames"], 128)
        self.assertFalse(result["coverage_complete"])
        self.assertTrue(result["replay_truncated"])

    def invocation_pair(self):
        start = {
            "event": "invocation_start", "campaign_id": "campaign", "attempt_id": 2,
            "invocation_id": 1, "execution_id_before": 0, "execution_id_after": 0,
            "executed": True,
        }
        end = {
            "event": "invocation_end", "campaign_id": "campaign", "attempt_id": 2,
            "invocation_id": 1, "execution_id_before": 0, "execution_id_after": 1,
            "executed": True,
        }
        return start, end

    def test_invocation_pair_requires_unique_ids_and_matching_coordinates(self):
        start, end = self.invocation_pair()
        self.assertTrue(audit_invocation_pairs([start, end])[0])

        self.assertFalse(audit_invocation_pairs([start, start.copy(), end])[0])
        changed = end.copy()
        changed["attempt_id"] = 99
        self.assertFalse(audit_invocation_pairs([start, changed])[0])
        changed = end.copy()
        changed["execution_id_before"] = 3
        self.assertFalse(audit_invocation_pairs([start, changed])[0])
        unchanged = end.copy()
        unchanged["execution_id_after"] = 0
        self.assertTrue(audit_invocation_pairs([start, unchanged])[0])
        regressed = end.copy()
        regressed["execution_id_after"] = -1
        self.assertFalse(audit_invocation_pairs([start, regressed])[0])

    def test_reset_attempt_must_match_its_execution_coordinate(self):
        executions = [
            {"event": "invocation_start", "attempt_id": 2, "invocation_id": 1,
             "execution_id_before": 0, "executed": True},
            {"event": "invocation_end", "attempt_id": 2, "invocation_id": 1,
             "execution_id_before": 0, "execution_id_after": 1, "executed": True},
            {"event": "invocation_start", "attempt_id": 3, "invocation_id": 2,
             "execution_id_before": 1, "executed": True},
            {"event": "invocation_end", "attempt_id": 3, "invocation_id": 2,
             "execution_id_before": 1, "execution_id_after": 2, "executed": True},
        ]
        resets = [
            {"attempt_id": 1, "stage": "pre-forkserver", "execution_id": 0, "success": True},
            {"attempt_id": 3, "stage": "invocation", "execution_id": 99, "success": True},
        ]
        result = audit_smoke.audit_resets(resets, executions, "campaign-call-budget")
        self.assertFalse(result["eligible"])
        self.assertEqual(result["reset_execution_id_mismatches"][0]["expected_execution_id"], 1)

    def test_comparison_requires_exact_complete_13_arm_set(self):
        paths = [Path(f"results-bftpd_ablation_{arm}_20261114T000000") for arm in sorted(EXPECTED_BATCH_ARM_LABELS)]
        self.assertTrue(audit_complete_batch(paths)[0])
        self.assertFalse(audit_complete_batch(paths[:-1])[0])
        self.assertFalse(audit_complete_batch(paths[:-1] + [paths[0]])[0])

    def test_target_protocol_map_covers_all_nine_protocol_targets(self):
        self.assertEqual(PROTOCOL_BY_TARGET, {
            "lightftp": "FTP", "bftpd": "FTP", "proftpd": "FTP",
            "pure-ftpd": "FTP", "exim": "SMTP", "live555": "RTSP",
            "kamailio": "SIP", "forked-daapd": "HTTP", "lighttpd1": "HTTP",
        })

    def test_other_target_defaults_to_eight_core_arms_and_matches_target_prefix(self):
        expected = frozenset(f"{base}512" for base in CORE_ARM_BASES)
        self.assertEqual(expected_arm_labels("exim", 512), expected)
        paths = [Path(f"results-exim_ablation_{arm}_20261114T000000") for arm in sorted(expected)]
        self.assertTrue(audit_complete_batch(paths, "exim", 512, expected)[0])
        wrong_target = [Path(f"results-bftpd_ablation_{arm}_20261114T000000") for arm in sorted(expected)]
        self.assertFalse(audit_complete_batch(wrong_target, "exim", 512, expected)[0])

    def test_explicit_q1_q2_arm_groups_expand_using_requested_threshold(self):
        all_bases = frozenset(label.rstrip("0123456789") for label in EXPECTED_BATCH_ARM_LABELS)
        self.assertEqual(parse_arm_bases("core,q1,q2", 512), all_bases)
        self.assertIn("q1a512", expected_arm_labels("live555", 512, "q1a,ordmatch"))
        with self.assertRaises(ValueError):
            parse_arm_bases("salvage1", 512)

    def test_expected_treatment_semantics_are_threshold_independent(self):
        self.assertEqual(expected_config("cal_ewma512"), {
            "calibration": True, "state_select_override": "ewma",
        })
        self.assertEqual(expected_config("q1d1"), {
            "q1_policy": "reflow", "code_retain": True,
        })

    def test_protocol_audit_separates_generic_ftp_preflight_from_campaign(self):
        cfg = {"no_llm": False, "mock_gateway": {"port": 8099, "protocol": "SMTP"}}
        valid = {
            "requests": 13, "campaign_requests": 12,
            "startup_preflight_requests": 1,
            "by_proto": {"SMTP": 13}, "port": 8099,
            "effective_config": {"protocol": "SMTP"},
        }
        self.assertTrue(audit_mock_protocol(valid, cfg, "SMTP")[0])
        for by_proto in ({}, {"FTP": 13}, {"SMTP": 11, "HTTP": 1, "FTP": 1}):
            with self.subTest(by_proto=by_proto):
                changed = dict(valid, by_proto=by_proto)
                self.assertFalse(audit_mock_protocol(changed, cfg, "SMTP")[0])
        self.assertTrue(audit_mock_protocol(
            dict(valid, by_proto={"FTP": 13}, effective_config={"protocol": "FTP"}),
            {"no_llm": False, "mock_gateway": {"port": 8099, "protocol": "FTP"}}, "FTP",
        )[0])
        self.assertFalse(audit_mock_protocol(
            dict(valid, effective_config={"protocol": None}), cfg, "SMTP",
        )[0], "unpinned legacy inference cannot establish target protocol")
        self.assertFalse(audit_mock_protocol(
            dict(valid, effective_config={}), cfg, "SMTP",
        )[0], "runner config alone cannot prove the mock's effective protocol")

    def test_forked_daapd_http_mock_must_be_pinned_to_http_bank(self):
        cfg = {"no_llm": False, "mock_gateway": {"port": 18101, "protocol": "HTTP"}}
        observed = {
            "requests": 31,
            "campaign_requests": 30,
            "startup_preflight_requests": 1,
            "by_proto": {"HTTP": 31},
            "port": 18101,
            "effective_config": {"protocol": "HTTP"},
        }
        self.assertTrue(audit_mock_protocol(observed, cfg, "HTTP")[0])
        self.assertFalse(audit_mock_protocol(
            dict(observed, by_proto={"HTTP": 30, "DAAP": 1}),
            cfg, "HTTP",
        )[0])
        self.assertFalse(audit_mock_protocol(
            dict(observed, by_proto={"HTTP": 30, "DAAP": 1},
                 effective_config={"protocol": "DAAP"}),
            cfg, "HTTP",
        )[0])

    def test_mock_protocol_pin_overrides_ambiguous_prompt_detection(self):
        mock_file = Path(__file__).resolve().parents[2] / "loopfuzz" / "llm_mock_v5.py"
        with patch.dict(os.environ, {
            "MOCK_PROTOCOL": "HTTP",
            "MOCK_TARGET": "forked-daapd",
        }):
            namespace = runpy.run_path(str(mock_file))
        prompt = "DAAP server runs over HTTP; use HTTP requests to query DAAP databases"
        self.assertEqual(namespace["detect_proto"](prompt), "HTTP")
        self.assertTrue(namespace["_is_forked_daapd_http"]())

    def test_mock_accounting_treats_truncation_as_http_200_subset(self):
        observed = {
            "requests": 31,
            "campaign_requests": 30,
            "startup_preflight_requests": 1,
            "requests_by_class": {"campaign": 30, "startup_preflight": 1},
            "http_200": 31,
            "http_429": 0,
            "http_500": 0,
            "truncated": 1,
            "reply_classes": {"templates": 10, "seed": 17, "plateau": 3},
        }
        self.assertEqual(audit_mock_request_accounting(observed)[0], True)
        self.assertFalse(audit_mock_request_accounting(
            dict(observed, requests_by_class={"campaign": 29, "startup_preflight": 1})
        )[0])
        self.assertFalse(audit_mock_request_accounting(
            dict(observed, http_200=30)
        )[0])
        self.assertFalse(audit_mock_request_accounting(
            dict(observed, truncated=32)
        )[0])

    def test_nollm_protocol_audit_requires_preflight_and_campaign_to_be_absent(self):
        cfg = {"no_llm": True, "mock_gateway": {"port": 8099, "protocol": "SMTP"}}
        self.assertTrue(audit_mock_protocol(
            {
                "requests": 0, "campaign_requests": 0,
                "startup_preflight_requests": 0, "by_proto": {}, "port": 8099,
                "effective_config": {"protocol": "SMTP"},
            }, cfg, "SMTP",
        )[0])
        self.assertFalse(audit_mock_protocol(
            {
                "requests": 1, "campaign_requests": 1,
                "startup_preflight_requests": 0,
                "by_proto": {"SMTP": 1}, "port": 8099,
                "effective_config": {"protocol": "SMTP"},
            }, cfg, "SMTP",
        )[0])
        self.assertFalse(audit_mock_protocol(
            {
                "requests": 1, "campaign_requests": 0,
                "startup_preflight_requests": 1,
                "by_proto": {"FTP": 1}, "port": 8099,
                "effective_config": {"protocol": "SMTP"},
            }, cfg, "SMTP",
        )[0])

    def test_multi_directory_cli_enforces_complete_batch(self):
        args = ["audit_smoke.py", "results-bftpd_ablation_pvstop1_20261114T000000",
                "results-bftpd_ablation_salvage1_20261114T000000"]
        output = StringIO()
        with patch.object(sys, "argv", args), patch.object(audit_smoke, "audit_result_dir", return_value=([], [])):
            with redirect_stdout(output):
                status = audit_smoke.main()
        self.assertEqual(status, 1)
        self.assertIn("complete bftpd threshold-1 arm set] FAIL", output.getvalue())

    def test_cli_threads_target_threshold_and_protocol_to_audit(self):
        args = ["audit_smoke.py", "--target", "exim", "--threshold", "512",
                "--timeout-min", "240", "--protocol", "SMTP", "--arms", "core",
                "results-exim_ablation_pvstop512_x"]
        output = StringIO()
        with patch.object(sys, "argv", args), patch.object(
            audit_smoke, "audit_result_dir", return_value=([], []),
        ) as audit_result:
            with redirect_stdout(output):
                status = audit_smoke.main()
        self.assertEqual(status, 0)
        audit_result.assert_called_once_with(Path(args[-1]), "exim", 512, "SMTP", 14_400_000,
                                             gateway="mock", profile="smoke")

    def test_cli_rejects_protocol_conflicting_with_target(self):
        args = ["audit_smoke.py", "--target", "exim", "--protocol", "FTP",
                "results-exim_ablation_pvstop1_x"]
        with patch.object(sys, "argv", args), redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit) as raised:
                audit_smoke.main()
        self.assertEqual(raised.exception.code, 2)


class AuditProfileTests(unittest.TestCase):
    def test_arm_defaults_require_explicit_profile_and_exact_controls(self):
        cfg = {"threshold_resolved": 512, "scheduler_warmup_max_selections": 64,
               "episode_energy_cap": 512, "cal_reward_window_invocations": 0}
        self.assertTrue(audit_smoke.audit_shared_controls(cfg, 512, "arm-default")[0])
        self.assertFalse(audit_smoke.audit_shared_controls(cfg, 512)[0])
        for field in cfg:
            for invalid in (None, True, False, cfg[field] + 1):
                with self.subTest(field=field, invalid=invalid):
                    self.assertFalse(audit_smoke.audit_shared_controls(
                        dict(cfg, **{field: invalid}), 512, "arm-default")[0])

    def test_smoke_controls_are_still_pinned(self):
        cfg = {"threshold_resolved": 512, "scheduler_warmup_max_selections": 8,
               "episode_energy_cap": 32, "cal_reward_window_invocations": 16}
        self.assertTrue(audit_smoke.audit_shared_controls(cfg, 512)[0])
        self.assertFalse(audit_smoke.audit_shared_controls(cfg, 512, "arm-default")[0])

    def test_cli_selects_original_pvstop512_profile(self):
        args = ["audit_smoke.py", "--target", "bftpd", "--gateway", "live",
                "--profile", "arm-default", "--threshold", "512", "--arms", "pvstop512",
                "--timeout-min", "30", "results-bftpd_ablation_pvstop512_20261117T200000"]
        with patch.object(sys, "argv", args), patch.object(
            audit_smoke, "audit_result_dir", return_value=([], []),
        ) as audit_result, redirect_stdout(StringIO()):
            self.assertEqual(audit_smoke.main(), 0)
        audit_result.assert_called_once_with(Path(args[-1]), "bftpd", 512, "FTP", 1_800_000,
                                             gateway="live", profile="arm-default")


class SummaryFormattingTests(unittest.TestCase):
    def test_sample_sd_is_reported_as_unavailable_for_fewer_than_two_runs(self):
        self.assertEqual(format_sample_sd([]), "n/a (n<2)")
        self.assertEqual(format_sample_sd([1.0]), "n/a (n<2)")

    def test_sample_sd_formats_two_or_more_runs(self):
        self.assertEqual(format_sample_sd([1.0, 3.0]), "1.41")


class LiveGatewayAuditTests(unittest.TestCase):
    """Offline fixtures exercise live evidence rules without a gateway request."""

    def fixture(self):
        cfg = {"model": "requested-model", "endpoint": "https://gateway.invalid/v1/chat/completions",
               "top_p": 0.9, "max_output_tokens": 128, "llm_total_call_cap": 2,
               "token_cap": 10000, "token_cap_enforced": 10000}
        row = {"request_id": "123-1", "pid": 123, "seq": 1, "status": "ok", "archived": True,
               "endpoint": cfg["endpoint"], "model_requested": cfg["model"], "model_served": "served-version",
               "prompt_tokens": 8, "completion_tokens": 2}
        request = {"model": cfg["model"], "max_tokens": 128, "top_p": 0.9,
                   "messages": [{"role": "user", "content": "Reply OK"}]}
        response = {"model": "served-version", "choices": [{"message": {"content": "OK"}}],
                    "usage": {"prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10}}
        files = {"llm-calls.jsonl": json.dumps(row).encode(),
                 "llm-archive/123-1.req": json.dumps(request).encode(),
                 "llm-archive/123-1.resp": json.dumps(response).encode()}
        return cfg, row, request, response, files

    def audit(self, cfg, files, end=None, profile="smoke", arm_label=None):
        return audit_smoke.audit_live_gateway(files.__getitem__, ["out-exim-loopfuzz/" + key for key in files],
                                              "out-exim-loopfuzz/", cfg, end or dict(cfg), profile=profile,
                                              arm_label=arm_label)

    def no_llm_fixture(self, **counter_overrides):
        cfg, _, _, _, _ = self.fixture()
        cfg.update(no_llm=True, llm_total_call_cap=-1, token_cap=0, token_cap_enforced=-1)
        counters = dict(llm_total_calls=0, llm_prompt_tokens=0, llm_completion_tok=0,
                        no_llm_mode=1)
        counters.update(counter_overrides)
        files = {"fuzzer_stats": "".join(f"{key}: {value}\n" for key, value in counters.items()).encode()}
        return cfg, files

    def test_live_no_llm_control_allows_missing_or_empty_ledger_with_zero_counters(self):
        for ledger in (None, b""):
            with self.subTest(ledger=ledger):
                cfg, files = self.no_llm_fixture()
                if ledger is not None:
                    files["llm-calls.jsonl"] = ledger
                result = self.audit(cfg, files, profile="arm-default", arm_label="nollm512")
                self.assertTrue(result["eligible"], result)
                self.assertEqual(result["evidence_mode"], "no-llm-control")
                self.assertEqual(result["outbound_attempts"], 0)
                self.assertEqual(result["reported_total_tokens"], 0)
                self.assertEqual(result["exchanges"], [])

    def test_live_no_llm_exception_requires_explicit_control_and_both_configurations(self):
        cfg, files = self.no_llm_fixture()
        for arm in (None, "wrapgate512", "nollm", "nollm0"):
            with self.subTest(arm=arm):
                self.assertFalse(self.audit(cfg, files, profile="arm-default", arm_label=arm)["eligible"])
        for value in (None, False, 1, "true"):
            with self.subTest(config=value):
                self.assertFalse(self.audit(dict(cfg, no_llm=value), files, profile="arm-default",
                                            arm_label="nollm512")["eligible"])
                self.assertFalse(self.audit(cfg, files, dict(cfg, no_llm=value), profile="arm-default",
                                            arm_label="nollm512")["eligible"])

    def test_live_no_llm_control_rejects_nonzero_missing_or_invalid_runtime_counters(self):
        for field in ("llm_total_calls", "llm_prompt_tokens", "llm_completion_tok", "no_llm_mode"):
            for invalid in (2, "unknown"):
                with self.subTest(field=field, invalid=invalid):
                    cfg, files = self.no_llm_fixture(**{field: invalid})
                    self.assertFalse(self.audit(cfg, files, profile="arm-default",
                                                arm_label="nollm512")["eligible"])
            cfg, files = self.no_llm_fixture()
            files["fuzzer_stats"] = b"\n".join(line for line in files["fuzzer_stats"].splitlines()
                                                 if not line.startswith(field.encode() + b":"))
            self.assertFalse(self.audit(cfg, files, profile="arm-default", arm_label="nollm512")["eligible"])

    def test_live_no_llm_control_rejects_call_records_and_raw_exchange_sidecars(self):
        cfg, empty = self.no_llm_fixture()
        _, _, _, _, requested = self.fixture()
        result = self.audit(cfg, dict(empty, **requested), profile="arm-default", arm_label="nollm512")
        self.assertFalse(result["eligible"])
        for name in ("llm-archive/orphan.req", "llm-archive/orphan.resp"):
            with self.subTest(sidecar=name):
                self.assertFalse(self.audit(cfg, dict(empty, **{name: b"{}"}), profile="arm-default",
                                            arm_label="nollm512")["eligible"])
        self.assertFalse(self.audit(cfg, dict(empty, **{"llm-calls.jsonl": b"not json"}),
                                    profile="arm-default", arm_label="nollm512")["eligible"])

    def test_live_success_reconciles_raw_model_and_usage(self):
        cfg, _, _, _, files = self.fixture()
        result = self.audit(cfg, files)
        self.assertTrue(result["eligible"], result)
        self.assertEqual(result["outbound_attempts"], 1)
        self.assertEqual(result["reported_total_tokens"], 10)
        self.assertEqual(result["exchanges"][0]["model_served"], "served-version")

    def test_uncapped_runtime_requires_explicit_arm_default_profile(self):
        cfg, _, _, _, files = self.fixture()
        cfg.update(llm_total_call_cap=-1, token_cap=0, token_cap_enforced=-1)
        self.assertFalse(self.audit(cfg, files)["eligible"])
        result = self.audit(cfg, files, profile="arm-default")
        self.assertTrue(result["eligible"], result)
        self.assertIsNone(result["llm_call_cap_enforced"])
        self.assertEqual(result["outbound_attempts"], 1)
        self.assertEqual(result["reported_total_tokens"], 10)
        self.assertFalse(self.audit(cfg, files, dict(cfg, llm_total_call_cap=2),
                                    profile="arm-default")["eligible"])

    def test_arm_default_rejects_invalid_cap_sentinels(self):
        cfg, _, _, _, files = self.fixture()
        for invalid in (None, 0, -2, True, False, "-1", -1.0):
            with self.subTest(cap=invalid):
                self.assertFalse(self.audit(dict(cfg, llm_total_call_cap=invalid), files,
                                            profile="arm-default")["eligible"])

    def test_arm_default_still_enforces_configured_positive_cap(self):
        cfg, row, request, _, files = self.fixture()
        failure = dict(row, request_id="123-2", seq=2, status="transport-error", model_served="",
                       prompt_tokens=0, completion_tokens=0)
        files["llm-calls.jsonl"] += b"\n" + json.dumps(failure).encode()
        files["llm-archive/123-2.req"] = json.dumps(request).encode()
        self.assertTrue(self.audit(cfg, files, profile="arm-default")["eligible"])
        self.assertFalse(self.audit(dict(cfg, llm_total_call_cap=1), files,
                                    profile="arm-default")["eligible"])

    def test_uncapped_profile_still_requires_raw_success_evidence(self):
        for mutation in ("no-calls", "missing-request", "missing-response", "unknown-usage", "tampered-request"):
            with self.subTest(mutation=mutation):
                cfg, row, request, response, files = self.fixture()
                cfg.update(llm_total_call_cap=-1, token_cap=0, token_cap_enforced=-1)
                if mutation == "no-calls":
                    files = {"llm-calls.jsonl": b""}
                elif mutation == "missing-request":
                    files.pop("llm-archive/123-1.req")
                elif mutation == "missing-response":
                    files.pop("llm-archive/123-1.resp")
                elif mutation == "unknown-usage":
                    response.pop("usage")
                    row.update(prompt_tokens=0, completion_tokens=0)
                    files["llm-calls.jsonl"] = json.dumps(row).encode()
                    files["llm-archive/123-1.resp"] = json.dumps(response).encode()
                else:
                    request["max_tokens"] = 4096
                    files["llm-archive/123-1.req"] = json.dumps(request).encode()
                self.assertFalse(self.audit(cfg, files, profile="arm-default")["eligible"])

    def test_live_missing_or_tampered_sidecar_fails(self):
        for mutation in ("missing-request", "missing-response", "request-model", "request-limit", "response-model", "response-usage"):
            with self.subTest(mutation=mutation):
                cfg, _, request, response, files = self.fixture()
                if mutation == "missing-request":
                    files.pop("llm-archive/123-1.req")
                elif mutation == "missing-response":
                    files.pop("llm-archive/123-1.resp")
                elif mutation.startswith("request-"):
                    request["model" if mutation == "request-model" else "max_tokens"] = "changed"
                    files["llm-archive/123-1.req"] = json.dumps(request).encode()
                else:
                    response["model" if mutation == "response-model" else "usage"] = "changed"
                    files["llm-archive/123-1.resp"] = json.dumps(response).encode()
                self.assertFalse(self.audit(cfg, files)["eligible"])

    def test_live_unknown_success_usage_is_explicit_and_ineligible(self):
        cfg, row, _, response, files = self.fixture()
        response.pop("usage")
        row.update(prompt_tokens=0, completion_tokens=0)
        files["llm-archive/123-1.resp"] = json.dumps(response).encode()
        files["llm-calls.jsonl"] = json.dumps(row).encode()
        result = self.audit(cfg, files)
        self.assertFalse(result["eligible"])
        self.assertEqual(result["unknown_usage_attempts"], 1)
        self.assertIsNone(result["reported_total_tokens"])
        self.assertEqual(result["exchanges"][0]["usage"], "unknown")

    def test_live_failure_is_archived_with_unknown_usage_and_requires_success(self):
        cfg, row, _, _, files = self.fixture()
        row.update(status="api-error", model_served="", prompt_tokens=0, completion_tokens=0)
        files["llm-calls.jsonl"] = json.dumps(row).encode()
        files["llm-archive/123-1.resp"] = json.dumps({"error": {"message": "invalid token"}}).encode()
        result = self.audit(cfg, files)
        self.assertFalse(result["eligible"])
        self.assertEqual(result["outbound_attempts"], 1)
        self.assertEqual(result["unknown_usage_attempts"], 1)
        self.assertIsNone(result["reported_total_tokens"])
        self.assertTrue(any("actual successful request" in error for error in result["errors"]))

    def test_live_no_calls_or_config_cap_mismatch_fails(self):
        cfg, _, _, _, files = self.fixture()
        self.assertFalse(self.audit(cfg, {"llm-calls.jsonl": b""})["eligible"])
        self.assertFalse(self.audit(cfg, files, dict(cfg, llm_total_call_cap=3))["eligible"])
        self.assertFalse(self.audit(dict(cfg, token_cap_enforced=1), files)["eligible"])

    def test_live_duplicate_or_orphan_identity_fails(self):
        cfg, row, _, _, files = self.fixture()
        files["llm-calls.jsonl"] += b"\n" + json.dumps(row).encode()
        self.assertFalse(self.audit(cfg, files)["eligible"])
        cfg, _, _, _, files = self.fixture()
        files["llm-archive/999-1.req"] = b"{}"
        self.assertFalse(self.audit(cfg, files)["eligible"])

    def test_live_transport_failure_usage_stays_unknown_with_a_success(self):
        cfg, row, request, _, files = self.fixture()
        failure = dict(row, request_id="123-2", seq=2, status="transport-error", model_served="",
                       prompt_tokens=0, completion_tokens=0)
        files["llm-calls.jsonl"] += b"\n" + json.dumps(failure).encode()
        files["llm-archive/123-2.req"] = json.dumps(request).encode()
        result = self.audit(cfg, files)
        self.assertTrue(result["eligible"], result)
        self.assertEqual(result["outbound_attempts"], 2)
        self.assertEqual(result["unknown_usage_attempts"], 1)
        self.assertIsNone(result["reported_total_tokens"])
        self.assertFalse(self.audit(dict(cfg, llm_total_call_cap=1), files)["eligible"])

    def test_live_cap_refusal_is_not_an_outbound_attempt(self):
        cfg, row, request, _, files = self.fixture()
        refused = dict(row, request_id="123-2", seq=2, status="cap-refused", model_served="",
                       prompt_tokens=0, completion_tokens=0)
        files["llm-calls.jsonl"] += b"\n" + json.dumps(refused).encode()
        files["llm-archive/123-2.req"] = json.dumps(request).encode()
        result = self.audit(cfg, files)
        self.assertTrue(result["eligible"], result)
        self.assertEqual(result["outbound_attempts"], 1)
        self.assertEqual(result["unknown_usage_attempts"], 0)
        self.assertEqual(result["exchanges"][1]["usage"], "not-sent")

    def deadline_fixture(self):
        cfg, row, request, _, files = self.fixture()
        cfg.update(campaign_stop_mode="wallclock", campaign_duration_sec=60, start_time_ms=1000)
        deadline = dict(row, request_id="123-2", seq=2, status="deadline-before-dispatch",
                        reservation_id=2, time_ms=61000, latency_ms=0, model_served="",
                        prompt_tokens=0, completion_tokens=0, usage_reported=False,
                        retry=False, outbound_attempted=False)
        files["llm-calls.jsonl"] += b"\n" + json.dumps(deadline).encode()
        files["llm-archive/123-2.req"] = json.dumps(request).encode()
        files["llm-archive/123-2.resp"] = b""
        return cfg, row, deadline, files

    def test_live_reserved_deadline_non_dispatch_does_not_count_as_outbound_or_usage(self):
        cfg, _, _, files = self.deadline_fixture()
        result = self.audit(cfg, files)
        self.assertTrue(result["eligible"], result)
        self.assertEqual(result["outbound_attempts"], 1)
        self.assertEqual(result["successful_requests"], 1)
        self.assertEqual(result["unknown_usage_attempts"], 0)
        self.assertEqual(result["reported_total_tokens"], 10)
        self.assertEqual(result["exchanges"][1]["usage"], "not-sent")

    def test_live_deadline_non_dispatch_rejects_forged_evidence(self):
        for fields in ({"time_ms": 60999}, {"reservation_id": 0},
                       {"outbound_attempted": True}, {"usage_reported": True},
                       {"retry": True}, {"model_served": "served"},
                       {"prompt_tokens": 1}, {"latency_ms": 1}):
            cfg, first, deadline, files = self.deadline_fixture()
            files["llm-calls.jsonl"] = (json.dumps(first) + "\n" +
                                       json.dumps(dict(deadline, **fields))).encode()
            with self.subTest(fields=fields):
                self.assertFalse(self.audit(cfg, files)["eligible"])
        cfg, _, _, files = self.deadline_fixture()
        self.assertFalse(self.audit(dict(cfg, campaign_stop_mode="call-budget"), files)["eligible"])

    def test_live_deadline_non_dispatch_requires_empty_response_and_valid_request(self):
        for response in (b"{}", b" ", b'{"usage":{"prompt_tokens":0,"completion_tokens":0}}'):
            cfg, _, _, files = self.deadline_fixture()
            files["llm-archive/123-2.resp"] = response
            self.assertFalse(self.audit(cfg, files)["eligible"])
        cfg, _, _, files = self.deadline_fixture()
        files.pop("llm-archive/123-2.resp")
        self.assertFalse(self.audit(cfg, files)["eligible"])
        cfg, _, _, files = self.deadline_fixture()
        files["llm-archive/123-2.req"] = b"{}"
        self.assertFalse(self.audit(cfg, files)["eligible"])

    def test_cli_live_is_explicit_and_default_remains_mock(self):
        args = ["audit_smoke.py", "--target", "exim", "--gateway", "live", "results-exim_ablation_q1a1_x"]
        with patch.object(sys, "argv", args), patch.object(audit_smoke, "audit_result_dir", return_value=([], [])) as audit_result:
            with redirect_stdout(StringIO()):
                self.assertEqual(audit_smoke.main(), 0)
        self.assertEqual(audit_result.call_args.kwargs["gateway"], "live")
        cfg, _, _, _, _ = self.fixture()
        identity = {field: "same" for field in SHARED_COMPARISON_FIELDS}
        identity.pop("mock_gateway")
        identity["live_gateway"] = cfg
        self.assertTrue(shared_identity_difference([identity], "live")[0])
        self.assertFalse(shared_identity_difference([identity])[0])


class V4DeepArtifactAuditTests(unittest.TestCase):
    """The v4 deep verifier must fail when underlying evidence is removed."""

    REAL_DIR = ("/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/"
                "ablation/results-pure-ftpd_ablation_pvstop1_20261115T181623")

    def test_saved_pureftpd_partial_sends_cannot_claim_complete(self):
        import tarfile
        base = Path(__file__).parent / "replay_verify_partial_masterv2_20261116T1945_v3"
        if not base.is_dir():
            self.skipTest("saved negative archives are unavailable")
        for run in (1, 2, 3):
            with self.subTest(run=run):
                name = f"pureftpd_nollm1_run{run}"
                prefix = "out-pure-ftpd-loopfuzz/"
                files = {prefix + "cov_over_time.csv.v4/" + p.name: p
                         for p in (base / name / "cov.csv.v4").iterdir() if p.is_file()}
                files.update({prefix + "replayable-queue/" + p.name: p for p in
                              (base / ("inputs-" + name) / "out-pure-ftpd-loopfuzz" /
                               "replayable-queue").iterdir() if p.is_file()})

                class Evidence:
                    def getmembers(self):
                        members = []
                        for name, path in files.items():
                            member = tarfile.TarInfo(name)
                            member.size = path.stat().st_size
                            members.append(member)
                        return members

                    def extractfile(self, member):
                        return files[member.name if hasattr(member, "name") else member].open("rb")

                with self.assertRaisesRegex(ValueError, "incomplete frame sending"):
                    audit_smoke.audit_v4_coverage_archive(Evidence(), prefix, "pure-ftpd")

    @unittest.skipUnless(os.path.isdir(REAL_DIR), "real smoke archive not available")
    def test_stripped_underlying_evidence_fails_deep_audit(self):
        import shutil
        import tarfile
        work = tempfile.mkdtemp(prefix="audit-smoke-deep-")
        try:
            copy = Path(work) / Path(self.REAL_DIR).name
            shutil.copytree(self.REAL_DIR, copy, ignore=shutil.ignore_patterns(".forensics"))
            for archive in sorted(copy.glob("out-*.tar.gz")):
                staging = Path(work) / archive.stem
                with tarfile.open(archive) as tf:
                    tf.extractall(staging)
                root = next(staging.iterdir())
                for item in (root / "cov_over_time.csv.v4").iterdir():
                    if item.name not in ("terminal.json", "scope.json",
                                         "replay-plan.json", "baseline.json",
                                         "incomplete.json"):
                        item.unlink()
                with tarfile.open(archive, "w:gz") as tf:
                    tf.add(root, arcname=root.name)
                shutil.rmtree(staging)
            rc = subprocess.run(
                ["python3", str(Path(__file__).with_name("audit_smoke.py")),
                 "--target", "pure-ftpd", str(copy)],
                capture_output=True, text=True, timeout=900)
            self.assertNotEqual(rc.returncode, 0)
            self.assertIn("missing underlying evidence", rc.stdout)
        finally:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
