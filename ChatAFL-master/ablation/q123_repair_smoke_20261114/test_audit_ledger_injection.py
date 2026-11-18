#!/usr/bin/env python3
"""Repeatable audit-entry ledger injections (GLM53 round-5).

Cases (each builds a re-sealed archive copy from the real ProFTPD fixture
with a v4 policy and per-input ledger; only frame STATE differs):
  1. contradictory-full : all lengths/counts/SHA match, rows claim full send
     but read_complete=false / pre_recv_ok=false / errno=5 ->
     must FAIL with "send_completeness disagrees".
  2. legal-minus2       : full frame list, last frame send_attempt=false,
     sent_bytes=-2, replay row honestly "incomplete" ->
     ledger path classifies not-complete WITHOUT structural error
     (the archive may fail other checks; the required signal is that NO
     ledger/send disagreement error appears).
  3. prefix-ledger      : ledger records a strict prefix (1 of N frames),
     honest incomplete row -> accepted as valid partial evidence, no
     "lengths disagree" / "count disagrees" error.
Exit code: 0 iff all three behave as required.
"""
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

BASE = Path("/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master")
SRC = BASE / "ablation/results-proftpd_ablation_pvstop1_20261115T181353"
AUD = BASE / "ablation/q123_repair_smoke_20261114/audit_smoke.py"
sys.path.insert(0, str(AUD.parent))
import audit_smoke as A  # noqa: E402


def reseal(scope):
    identity = {f: scope[f] for f in A.SCOPE_IDENTITY_FIELDS if f in scope}
    scope["scope_sha256"] = hashlib.sha256(A._canonical(identity)).hexdigest()
    return scope


def ledger_bytes(rows):
    return "".join(json.dumps(r) + "\n" for r in rows).encode()


TAMPER_FIELDS = {
    "tamper-attempted": ("frames_attempted", lambda v: v + 1),
    "tamper-unattempted": ("frames_unattempted", lambda v: (v or 0) + 1),
    "tamper-stop-reason": ("send_stop_reason", lambda v: "eof" if v != "eof" else "client-recv-pre-send-failed"),
}


def build(case):
    tmp = Path(tempfile.mkdtemp())
    copy = tmp / SRC.name
    shutil.copytree(SRC, copy, ignore=shutil.ignore_patterns(".forensics"))
    import struct as _st
    for tgz in sorted(copy.glob("out-*.tar.gz")):
        stage = tmp / ("i" + tgz.stem)
        with tarfile.open(tgz) as tf:
            tf.extractall(stage)
        root = next(stage.iterdir())
        v4 = root / "cov_over_time.csv.v4"
        scope = json.loads((v4 / "scope.json").read_text())
        scope["replay_policy"]["name"] = "proftpd-ready-client-graceful-exit-v4"
        scope = reseal(scope)
        (v4 / "scope.json").write_text(json.dumps(scope))

        rows = [json.loads(l) for l in (v4 / "checkpoints.jsonl").read_text().splitlines()]
        for idx, row in enumerate(rows, 1):
            framed = (root / "replayable-queue" / row["filename"]).read_bytes()
            lens = []
            off = 0
            while off + 4 <= len(framed):
                (l,) = _st.unpack_from("<I", framed, off)
                lens.append(l)
                off += 4 + l
            n = len(lens)
            name = f"replay-{idx:06d}-frame-ledger.jsonl"

            if idx == 1 and case == "contradictory-full":
                frame_rows = [dict(event="frame", frame=i + 1, len=l,
                                   read_complete=False, pre_recv_ok=False,
                                   send_attempt=True, sent_bytes=l,
                                   send_errno=5, post_recv_ok=False)
                              for i, l in enumerate(lens)]
                end = dict(event="session_end", frames_total=n, stop_reason="eof")
                upd = dict(frames_total=n, frames_attempted=n,
                           frames_sent_complete=n,
                           send_stop_reason="eof", send_completeness="complete")
            elif idx == 1 and case == "legal-minus2":
                frame_rows = [dict(event="frame", frame=i + 1, len=l,
                                   read_complete=True, pre_recv_ok=True,
                                   send_attempt=True, sent_bytes=l,
                                   send_errno=0, post_recv_ok=True)
                              for i, l in enumerate(lens[:-1])]
                frame_rows.append(dict(event="frame", frame=n, len=lens[-1],
                                       read_complete=True, pre_recv_ok=False,
                                       send_attempt=False, sent_bytes=-2,
                                       send_errno=0, post_recv_ok=False))
                end = dict(event="session_end", frames_total=n,
                           stop_reason="client-recv-pre-send-failed")
                upd = dict(frames_total=n, frames_unattempted=1,
                           frames_attempted=n - 1, frames_sent_complete=n - 1,
                           send_stop_reason="client-recv-pre-send-failed",
                           send_completeness="incomplete")
            elif idx == 1 and case == "prefix-ledger":
                frame_rows = [dict(event="frame", frame=1, len=lens[0],
                                   read_complete=True, pre_recv_ok=True,
                                   send_attempt=True, sent_bytes=lens[0],
                                   send_errno=0, post_recv_ok=False)]
                end = dict(event="session_end", frames_total=1,
                           stop_reason="client-recv-post-send-failed")
                upd = dict(frames_total=1, frames_unattempted=n - 1,
                           frames_attempted=1, frames_sent_complete=0,
                           send_stop_reason="client-recv-post-send-failed",
                           send_completeness="incomplete")
            else:
                # healthy full-send ledger for every other input (and all
                # inputs of the healthy-full case)
                frame_rows = [dict(event="frame", frame=i + 1, len=l,
                                   read_complete=True, pre_recv_ok=True,
                                   send_attempt=True, sent_bytes=l,
                                   send_errno=0, post_recv_ok=True)
                              for i, l in enumerate(lens)]
                end = dict(event="session_end", frames_total=n, stop_reason="eof")
                upd = dict(frames_total=n, frames_unattempted=0,
                           frames_attempted=n, frames_sent_complete=n,
                           send_stop_reason="eof", send_completeness="complete")

            begin = dict(event="session_begin",
                         schema="loopfuzz-replay-frame-ledger-v1",
                         input_size=len(framed), protocol="FTP")
            data = ledger_bytes([begin] + frame_rows + [end])
            (v4 / name).write_bytes(data)
            row["replay"].update(frame_ledger_file=name,
                                 frame_ledger_sha256=hashlib.sha256(data).hexdigest(),
                                 **upd)
            if case in TAMPER_FIELDS and idx == 1:
                field, mutate = TAMPER_FIELDS[case]
                row["replay"][field] = mutate(row["replay"].get(field))
        (v4 / "checkpoints.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        term = json.loads((v4 / "terminal.json").read_text())
        term["scope_sha256"] = scope["scope_sha256"]
        pa = v4 / "proftpd-exit-policy-audit.json"
        if pa.is_file():
            pad = json.loads(pa.read_text())
            pad["policy_name"] = "proftpd-ready-client-graceful-exit-v4"
            pa.write_text(json.dumps(pad))
            term["proftpd_exit_policy_audit_sha256"] = hashlib.sha256(pa.read_bytes()).hexdigest()
        (v4 / "terminal.json").write_text(json.dumps(term))
        with tarfile.open(tgz, "w:gz") as tf:
            tf.add(root, arcname=root.name)
        shutil.rmtree(stage)
    return copy


def run(case, expect_rc_zero=False, must_contain=None, must_not_contain=None):
    copy = build(case)
    try:
        r = subprocess.run(["python3", str(AUD), "--target", "proftpd", str(copy)],
                           capture_output=True, text=True, timeout=1800)
        out = r.stdout
        if expect_rc_zero:
            ok = r.returncode == 0
            detail = " (acceptance: rc must be 0)"
        else:
            ok = r.returncode != 0
            detail = " (rejection: rc must be non-zero)"
        if must_contain:
            hit = any(must_contain in line for line in out.splitlines())
            ok = ok and hit
            detail += f" contains={must_contain!r}:{hit}"
        if must_not_contain:
            absent = not any(must_not_contain in line for line in out.splitlines())
            ok = ok and absent
            detail += f" absent={must_not_contain!r}:{absent}"
        print(f"{case}: rc={r.returncode}{detail} -> {'PASS' if ok else 'FAIL'}")
        if not ok:
            for line in out.splitlines():
                if line.strip().startswith("FAIL") or "Error" in line:
                    print("   ", line.strip()[:170])
        return ok
    finally:
        shutil.rmtree(copy.parent, ignore_errors=True)


# Positives must be ACCEPTED (exit 0): a healthy full-send ledger proves the
# positive path, and honest partial (-2 / prefix) ledgers are valid evidence
# that must not trip any ledger disagreement.
results = [
    run("healthy-full", expect_rc_zero=True),
    run("legal-minus2", expect_rc_zero=True,
        must_not_contain="send_completeness disagrees"),
    run("prefix-ledger", expect_rc_zero=True,
        must_not_contain="lengths disagree"),
    run("contradictory-full", must_contain="send_completeness disagrees"),
    run("tamper-attempted", must_contain="frames_attempted disagrees"),
    run("tamper-unattempted", must_contain="frames_unattempted disagrees"),
    run("tamper-stop-reason", must_contain="send_stop_reason disagrees"),
]
sys.exit(0 if all(results) else 1)
