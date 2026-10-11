#!/usr/bin/env python3
"""audit_infoleak.py — information-set audit for LoopFuzz de-injection.

Part of the de-injection work (2026-10-10, LoopFuzz/knowledge-level.h).
Verifies, machine-checkably, that a LoopFuzz binary / seed directory /
prompt log carries no per-target CVE knowledge:

  Layer 1 (binary):   CVE ids, catalog pattern ids, catalog-exclusive
                      payload literals, and the CVE prompt-section header
                      must be absent from the executable's strings.
  Layer 2 (seeds):    no attack_* seed files and no catalog-exclusive
                      literals in any seed content (deepstate_*.raw
                      generic templates are allowed).
  Layer 3 (prompts):  no CVE ids / CVE-pattern headers in recorded LLM
                      prompts (llm-calls.jsonl or any prompt dump).

Usage:
  audit_infoleak.py BINARY [--seeds DIR] [--prompts FILE]
                    [--expect-mode {clean,l3}]

  --expect-mode clean (default): all layers must PASS (no signatures).
  --expect-mode l3:              layer 1 must find the catalog (inverted
                                 check — catches a mis-built L3 binary).

Exit code: 0 = audit passed, 1 = violations found, 2 = usage error.

Signature provenance notes (deliberately NOT flagged):
  - "000022B8" (RTSP session id): present in the public AFLNet in-rtsp
    base seeds, so it is corpus-legitimate, not a catalog marker.
  - "2147483647" / "4294967295" / "-1": generic numeric boundary values
    (textbook boundary dictionaries); retained by the class-generic
    mutation operators by design.
"""

import argparse
import os
import re
import sys

# ── Signatures ────────────────────────────────────────────────────────

CVE_RE = re.compile(rb"CVE-\d{4}-\d{4,7}")

# Catalog pattern id strings (attack-catalog.c attack_pattern_t.id /
# cve_ref values and the deep CVE ids) — these only exist when the
# catalog is compiled in.
PATTERN_IDS = [
    b"rtsp_pause_play_uaf", b"rtsp_repeat_setup_uaf",
    b"rtsp_describe_nested_url", b"rtsp_setup_malformed_transport",
    b"rtsp_oversized_rtp_chunk", b"rtsp_repeat_setup_leak",
    b"rtsp_teardown_then_send", b"ftp_cwd_long_path",
    b"sip_invite_nested_via", b"smtp_auth_plain_oversized",
    b"mqtt_long_topic_sub_pub", b"mqtt_persistent_retained",
    b"mqtt_shared_sub", b"mqtt_sys_wildcard",
    b"deep_ftp_mlsd", b"deep_ftp_rename", b"deep_smtp_bdat",
    b"deep_sip_clen", b"deep_ftp_authfail", b"deep_http_rescan",
    b"pure-ftpd-domlsd", b"proftpd-rnto-oob", b"exim-bdat-uaf",
    b"kamailio-clen-ovf", b"owntone-teardown-uaf-stress",
]

# Payload literals that exist ONLY in catalog templates (verified against
# the public base seed corpora: none of these appear in in-rtsp/in-ftp/
# in-sip/in-smtp/in-mqtt).
PAYLOAD_LITERALS = [
    b"AGFhYQBhYWE=",          # SMTP AUTH PLAIN stub (catalog only)
    b"loopfuzz_rename",       # FTP rename template marker
    b"loopfuzz_renamed",
    b"$shared/attackgrp",     # MQTT shared-sub template marker
    b"attack/retained",       # MQTT retained template marker
]

# NOT flagged (verified legitimate): "deepfile" is generic-template
# content (deep_ftp_abor, RFC-level data-channel abort shape);
# "$SYS/broker/status" follows the MQTT-spec $SYS hierarchy convention
# and appears in the spec-level differential race harness (mqtt-race.c).

PROMPT_MARKERS = [b"BUG PATTERNS TO TRY", b"bug patterns to try"]

SEED_EXCLUSIVE_LITERALS = PAYLOAD_LITERALS + [
    b"rtsp://127.0.0.1:8554/mp3AudioTest/../track1",  # nested-url shape
]


def scan_binary(path, expect_l3):
    data = open(path, "rb").read()
    hits = []
    for m in CVE_RE.finditer(data):
        hits.append(("cve-id", m.group(0).decode("ascii", "replace")))
    for sig in PATTERN_IDS + PAYLOAD_LITERALS:
        if sig in data:
            hits.append(("catalog-literal", sig.decode("ascii")))
    found = bool(hits)
    if expect_l3:
        ok = found
        return ok, hits, ("catalog present" if ok else
                          "L3 binary MISSING catalog — built without L3=1?")
    return (not found), hits, ("clean" if not found else "CONTAMINATED")


def scan_seeds(seed_dir):
    hits = []
    for root, _dirs, files in os.walk(seed_dir):
        for fn in files:
            fp = os.path.join(root, fn)
            if fn.startswith("attack_"):
                hits.append(("attack-seed-file", fn))
            try:
                blob = open(fp, "rb").read()
            except OSError:
                continue
            for m in CVE_RE.finditer(blob):
                hits.append(("cve-id-in-seed", f"{fn}:{m.group(0).decode()}"))
            for sig in SEED_EXCLUSIVE_LITERALS:
                if sig in blob:
                    hits.append(("catalog-literal-in-seed",
                                 f"{fn}:{sig.decode('ascii')}"))
    return (not hits), hits


def scan_prompts(prompt_file):
    hits = []
    blob = open(prompt_file, "rb").read()
    for m in CVE_RE.finditer(blob):
        hits.append(("cve-id-in-prompt", m.group(0).decode("ascii")))
    for sig in PROMPT_MARKERS:
        if sig.lower() in blob.lower():
            hits.append(("cve-pattern-header-in-prompt",
                         sig.decode("ascii")))
    return (not hits), hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--seeds")
    ap.add_argument("--prompts")
    ap.add_argument("--expect-mode", choices=["clean", "l3"],
                    default="clean")
    args = ap.parse_args()

    ok_all = True

    ok, hits, note = scan_binary(args.binary, args.expect_mode == "l3")
    print(f"[{'PASS' if ok else 'FAIL'}] binary  ({args.binary}) {note}")
    for kind, what in hits[:20]:
        print(f"       {kind}: {what}")
    ok_all &= ok

    if args.seeds:
        ok, hits = scan_seeds(args.seeds)
        print(f"[{'PASS' if ok else 'FAIL'}] seeds   ({args.seeds})")
        for kind, what in hits[:20]:
            print(f"       {kind}: {what}")
        ok_all &= ok

    if args.prompts:
        ok, hits = scan_prompts(args.prompts)
        print(f"[{'PASS' if ok else 'FAIL'}] prompts ({args.prompts})")
        for kind, what in hits[:20]:
            print(f"       {kind}: {what}")
        ok_all &= ok

    print("AUDIT:", "PASS" if ok_all else "FAIL")
    sys.exit(0 if ok_all else 1)


if __name__ == "__main__":
    main()
