#!/usr/bin/env python3
"""Estimate FULL LLM cost for old experiment data (prior to the fix that
records all call sites in fuzzer_stats).

For old data, only stall/plateau costs are recorded.  Grammar and enrichment
costs are missing.  This script estimates them from observable artifacts in
the tar.gz archives:

  1. Grammar cost (fixed per run, shared by all variants):
     - TEMPLATE_CONSISTENCY_COUNT=5 iterations × 2 calls = 10 LLM calls
     - Each call: prompt ~260 tokens, completion ~500 tokens (measured)
     - Total: ~2600 PT, ~5000 CT → ~$0.0034 per run

  2. Enrichment cost (variable, from enriched_* file counts):
     - Count files matching "enriched_*" in the queue directory inside tar
     - Each enriched file = 1 LLM call
     - Avg tokens per enrichment call: ~350 PT, ~400 CT (measured on exim)
     - For LoopFuzz (parallel, C(n,2) combos): similar per-call cost

  3. Stall/plateau cost:
     - ChatAFL: tiktoken on stall-interactions/ files (precise)
     - LoopFuzz: from fuzzer_stats llm_prompt_tokens / llm_completion_tok
       (precise, but only covers plateau calls)

Usage:
    python3 estimate_full_llm_cost.py <tar.gz> [--fuzzer chatafl|loopfuzz]

Output (tab-separated):
    grammar_calls grammar_pt grammar_ct enrich_calls enrich_pt enrich_ct \
    stall_calls stall_pt stall_ct total_calls total_pt total_ct total_cost_usd
"""

import sys
import os
import re
import tarfile
import json
import argparse

# ── Constants from measurement ───────────────────────────────────
GRAMMAR_CALLS = 10  # 5 iters × 2 calls/iter
GRAMMAR_PT_PER_CALL = 260
GRAMMAR_CT_PER_CALL = 500

# Enrichment per-call average (measured on exim stall-interactions)
ENRICH_PT_PER_CALL = 350
ENRICH_CT_PER_CALL = 400

# Pricing: gpt-4o-mini
PRICE_PT = 0.15 / 1_000_000  # $/token
PRICE_CT = 0.60 / 1_000_000  # $/token
LOOPFUZZ_FUZZER = "loopfuzz"
LEGACY_LOOPFUZZ_MARKERS = (LOOPFUZZ_FUZZER, "chat" + "afl_opt", "chat" + "afl-opt")


def count_enriched_files(tf):
    """Count enriched_* files in the queue/ directory inside tar."""
    count = 0
    for m in tf.getmembers():
        basename = os.path.basename(m.name)
        if basename.startswith("enriched_") and m.isfile():
            count += 1
    return count


def extract_fuzzer_stats(tf):
    """Extract llm_* fields from fuzzer_stats if present."""
    for m in tf.getmembers():
        if m.name.endswith("fuzzer_stats"):
            f = tf.extractfile(m)
            if f is None:
                continue
            text = f.read().decode("utf-8", errors="replace")
            f.close()
            fields = {}
            for line in text.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    fields[k.strip()] = v.strip()
            return fields
    return {}


def count_stall_tiktoken(tf):
    """Use tiktoken (if available) to count stall interaction tokens."""
    try:
        import tiktoken
    except ImportError:
        return 0, 0, 0
    
    enc = tiktoken.get_encoding("o200k_base")
    
    prompts = {}
    responses = {}
    for m in tf.getmembers():
        basename = os.path.basename(m.name)
        if "/stall-interactions/" not in m.name:
            continue
        if basename.startswith("prompt-") and m.isfile():
            idx = basename.replace("prompt-", "")
            f = tf.extractfile(m)
            prompts[idx] = f.read().decode("utf-8", errors="replace") if f else ""
            if f:
                f.close()
        elif basename.startswith("response-") and m.isfile():
            idx = basename.replace("response-", "")
            f = tf.extractfile(m)
            responses[idx] = f.read().decode("utf-8", errors="replace") if f else ""
            if f:
                f.close()
    
    total_pt = 0
    total_ct = 0
    calls = 0
    
    for idx in sorted(prompts.keys()):
        prompt_text = prompts[idx]
        resp_text = responses.get(idx, "")
        
        # Prompt is a JSON messages array
        try:
            messages = json.loads(prompt_text)
            pt = 0
            for msg in messages:
                pt += 4  # overhead per message
                for k, v in msg.items():
                    pt += len(enc.encode(k))
                    pt += len(enc.encode(str(v)))
            pt += 2  # assistant priming
        except (json.JSONDecodeError, TypeError):
            pt = len(enc.encode(prompt_text))
        
        ct = len(enc.encode(resp_text))
        total_pt += pt
        total_ct += ct
        calls += 1
    
    return calls, total_pt, total_ct


def main():
    parser = argparse.ArgumentParser(description="Estimate full LLM cost for old experiment data")
    parser.add_argument("tarfile", help="Path to tar.gz archive")
    parser.add_argument("--fuzzer", default="auto",
                        help="Fuzzer variant: chatafl, loopfuzz, or auto (detect)")
    args = parser.parse_args()
    
    if not os.path.isfile(args.tarfile):
        print(f"Error: {args.tarfile} not found", file=sys.stderr)
        sys.exit(1)
    
    tf = tarfile.open(args.tarfile, "r:gz")
    
    # Auto-detect fuzzer from filename
    fuzzer = args.fuzzer
    if fuzzer == "auto":
        base = os.path.basename(args.tarfile).lower()
        if any(marker in base for marker in LEGACY_LOOPFUZZ_MARKERS):
            fuzzer = LOOPFUZZ_FUZZER
        elif "chatafl" in base:
            fuzzer = "chatafl"
        else:
            fuzzer = "unknown"
    elif fuzzer in LEGACY_LOOPFUZZ_MARKERS:
        fuzzer = LOOPFUZZ_FUZZER
    
    # ── 1. Grammar (estimated, same for all variants) ──
    grammar_calls = GRAMMAR_CALLS
    grammar_pt = GRAMMAR_CALLS * GRAMMAR_PT_PER_CALL
    grammar_ct = GRAMMAR_CALLS * GRAMMAR_CT_PER_CALL
    
    # ── 2. Enrichment (count from enriched_* files) ──
    enriched_count = count_enriched_files(tf)
    enrich_calls = enriched_count  # lower bound: failed calls not counted
    enrich_pt = enrich_calls * ENRICH_PT_PER_CALL
    enrich_ct = enrich_calls * ENRICH_CT_PER_CALL
    
    # ── 3. Stall/plateau ──
    stats = extract_fuzzer_stats(tf)
    
    if "llm_prompt_tokens" in stats and "llm_completion_tok" in stats:
        # LoopFuzz-style: exact from API (but only plateau calls in old data)
        stall_pt = int(stats.get("llm_prompt_tokens", "0"))
        stall_ct = int(stats.get("llm_completion_tok", "0"))
        stall_calls = int(stats.get("llm_total_calls", "0"))
        stall_source = "exact_plateau_only"
    else:
        # ChatAFL-style: tiktoken on stall files
        tf.close()
        tf = tarfile.open(args.tarfile, "r:gz")
        stall_calls, stall_pt, stall_ct = count_stall_tiktoken(tf)
        stall_source = "tiktoken_stall_only"
    
    # ── Totals ──
    total_calls = grammar_calls + enrich_calls + stall_calls
    total_pt = grammar_pt + enrich_pt + stall_pt
    total_ct = grammar_ct + enrich_ct + stall_ct
    total_cost = total_pt * PRICE_PT + total_ct * PRICE_CT
    
    tf.close()
    
    # Header + data
    print("# fuzzer\tgrammar_calls\tgrammar_pt\tgrammar_ct\t"
          "enrich_calls\tenrich_pt\tenrich_ct\t"
          f"stall_calls({stall_source})\tstall_pt\tstall_ct\t"
          "total_calls\ttotal_pt\ttotal_ct\ttotal_cost_usd")
    print(f"{fuzzer}\t{grammar_calls}\t{grammar_pt}\t{grammar_ct}\t"
          f"{enrich_calls}\t{enrich_pt}\t{enrich_ct}\t"
          f"{stall_calls}\t{stall_pt}\t{stall_ct}\t"
          f"{total_calls}\t{total_pt}\t{total_ct}\t"
          f"{total_cost:.6f}")


if __name__ == "__main__":
    main()
