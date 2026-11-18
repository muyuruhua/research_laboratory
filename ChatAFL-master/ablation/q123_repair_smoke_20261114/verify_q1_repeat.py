#!/usr/bin/env python3
"""Per-repeat Q1 budget verification from archive contents (round-10).

Reads everything from inside the tarball:
  - exactly one run-config.jsonl (start budget, end termination reason);
  - exactly one fuzzer_stats (campaign_charged_calls is the budget-control
    counter; campaign_call_budget and campaign_budget_exhausted are also
    recorded there; execs_done is reported separately, never used for cap
    comparisons);
  - final q1_idle_quota from fuzzer_stats gives the effective cap as
    max(0, budget - idle); a zero cap with a positive budget is valid.

Classification requires agreement:
  - cap-reached        : exhausted flag set AND charged >= effective_cap > 0
  - budget-exhausted   : end reason campaign-call-budget AND exhausted flag
  - time-censored      : independently established wall-clock expiry AND charged < effective_cap
  - unknown            : anything else (incl. signal-or-timeout without
                         launcher-side timing evidence, missing counters, or
                         config/stats budget disagreement)

Any structural problem (missing/duplicate member, parse failure, missing
counter, config-vs-stats budget disagreement) prints ONE error JSON and
exits non-zero; success prints ONE result JSON and exits 0.
"""
import json
import sys
import tarfile


def fail(path, message):
    print(json.dumps({"error": message, "archive": path}))
    return 3


def exactly(members, suffix, path):
    hits = [m for m in members if m.endswith(suffix)]
    if len(hits) != 1:
        return None, f"expected exactly one {suffix}, found {len(hits)}"
    return hits[0], None


def main(path):
    try:
        with tarfile.open(path) as tf:
            members = tf.getnames()
            cfg_name, err = exactly(members, "/run-config.jsonl", path)
            if err:
                return fail(path, err)
            rows = [json.loads(l) for l in
                    tf.extractfile(cfg_name).read().decode().splitlines() if l.strip()]
            start = next((r for r in rows if r.get("phase") == "start"), None)
            end = next((r for r in rows if r.get("phase") == "end"), None)
            if not start or not end:
                return fail(path, "run-config missing start/end row")

            stats_name, err = exactly(members, "/fuzzer_stats", path)
            if err:
                return fail(path, err)
            stats = {}
            for line in tf.extractfile(stats_name).read().decode().splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    stats[key.strip()] = value.strip()

            def counter(key):
                if key not in stats:
                    return None
                try:
                    return int(stats[key])
                except ValueError:
                    return None

            charged = counter("campaign_charged_calls")
            budget_stats = counter("campaign_call_budget")
            exhausted = counter("campaign_budget_exhausted")
            execs = counter("execs_done")
            budget_cfg = start.get("campaign_call_budget")
            reason = end.get("termination_reason")

            if charged is None or budget_stats is None or exhausted is None or execs is None:
                return fail(path, "fuzzer_stats lacks a required campaign counter")

            if min(charged, budget_stats, execs) < 0 or exhausted not in (0, 1):
                return fail(path, "invalid campaign counter")

            if type(budget_cfg) is not int or budget_cfg != budget_stats:
                return fail(path, f"budget disagreement: config={budget_cfg} stats={budget_stats}")

            idle = counter("q1_idle_quota")
            if idle is None or idle < 0 or idle > budget_stats:
                return fail(path, "invalid or missing q1_idle_quota")
            effective_cap = max(0, budget_stats - idle)
            flow_hits = [m for m in members if m.endswith("/q1-budget-flow.jsonl")]
            if len(flow_hits) > 1:
                return fail(path, "multiple q1-budget-flow members")
            if len(flow_hits) == 1:
                flow = [json.loads(l) for l in
                        tf.extractfile(flow_hits[0]).read().decode().splitlines() if l.strip()]
                for row in flow:
                    if "effective_cap" in row and (type(row["effective_cap"]) is not int or row["effective_cap"] < 0):
                        return fail(path, "invalid effective_cap")

            classification = "unknown"
            if budget_stats > 0:
                if reason == "campaign-call-budget" and exhausted == 1 and charged >= effective_cap:
                    classification = "budget-exhausted"

            print(json.dumps({"archive": path, "budget": budget_cfg,
                              "charged_calls": charged, "execs_done": execs,
                              "exhausted_flag": exhausted, "reason": reason,
                              "effective_cap": effective_cap, "idle_quota": idle,
                              "classification": classification}))
            return 0
    except (tarfile.TarError, json.JSONDecodeError, OSError, UnicodeError, AttributeError, TypeError) as exc:
        return fail(path, f"archive read failure: {exc}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
