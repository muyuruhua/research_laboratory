import unittest
import loopfuzz_metrics as metrics


class MetricsTests(unittest.TestCase):
    def start(self, root, source):
        return dict(kind="start", root_queue_id=root, source_class=source, horizon=64,
                    kernel="fuzz_one-full-session", start_virgin_hash="a")

    def test_productivity_censor_bounds_preserve_all_roots(self):
        events = [self.start(1, "provisional"),
                  dict(kind="first_gain", root_queue_id=1, charged_invocations=10),
                  dict(kind="complete", root_queue_id=1, charged_invocations=64),
                  self.start(2, "provisional"),
                  dict(kind="censor", root_queue_id=2, charged_invocations=12),
                  self.start(3, "ordinary_no_tracked_llm"),
                  dict(kind="complete", root_queue_id=3, charged_invocations=64)]
        result, samples = metrics.productivity(events)
        group = next(row for row in result["groups"] if row["source_class"] == "provisional")
        self.assertEqual(len(samples), 3)
        self.assertEqual(group["productivity_at64_complete_only"], 1)
        self.assertEqual(group["productivity_at64_all_started_lower"], .5)
        self.assertEqual(group["productivity_at64_all_started_upper"], 1)
        self.assertEqual(group["charged_invocations"], 76)

    def test_incomplete64_cannot_be_called_complete(self):
        with self.assertRaisesRegex(ValueError, "did not consume 64"):
            metrics.productivity([self.start(1, "provisional"),
                dict(kind="complete", root_queue_id=1, charged_invocations=63)])

    def test_missing_productivity_is_not_zero(self):
        result, _ = metrics.productivity([])
        self.assertFalse(result["available"])
        self.assertEqual(result["groups"], [])

    def test_calibration_config_is_not_activation(self):
        result = metrics.calibration(dict(calibration=True), [dict(reason="warmup-eligible")], [])
        self.assertFalse(result["activated_weighted_path"])
        self.assertIsNone(result["posterior_changed_choices"])

    def test_latency_union_cpu_and_wait_are_separate(self):
        calls = [dict(seq=1, request_id="a", start_time_ms=0, end_time_ms=1000, latency_ms=1000),
                 dict(seq=1, request_id="b", start_time_ms=500, end_time_ms=1500, latency_ms=1000)]
        result = metrics.costs(calls, {}, [dict(usage_usec=100), dict(usage_usec=1000100)])
        self.assertEqual(result["summed_request_latency_s"], 2)
        self.assertEqual(result["explicit_request_interval_union_s"], 1.5)
        self.assertEqual(result["container_cpu_delta_s"], 1)
        self.assertIsNone(result["total_llm_wait_wall_s"])
        self.assertEqual(result["seq_duplicate_extra_rows"], 1)
        self.assertTrue(result["unique_request_ids_valid"])

    def test_channel_and_policy_schema_aliases_are_counted(self):
        costs = metrics.costs([dict(seq=1, channel="grammar"),
                               dict(seq=2, request_type="plateau")], {}, [])
        self.assertEqual(costs["request_types"], {"grammar": 1, "plateau": 1})
        triggers = metrics.trigger_summary([dict(policy="response-gap"),
                                            dict(rule="code-stall")])
        self.assertEqual(triggers["kinds"], {"response-gap": 1, "code-stall": 1})
        self.assertTrue(metrics.trigger_summary([], ledger_present=True)["ledger_present"])

    def test_response_edges_are_an_identity_union(self):
        result = metrics.observed_edges({"ipsm.dot": 'digraph { 0 -> 220; 220 -> 230; 0 -> 220; }'})
        self.assertEqual(result["count"], 2)
        self.assertIsNone(metrics.observed_edges({})["edge_ids"])


if __name__ == "__main__":
    unittest.main()
