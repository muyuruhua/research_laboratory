#!/usr/bin/env python3
"""Source-scoped branch identities and auditable cumulative corpus replay."""

import argparse
import contextlib
import csv
import dataclasses
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import tempfile
import subprocess
import sys
import time

SCHEMA = "loopfuzz-coverage-v4"
SAMPLED_SCHEMA = "loopfuzz-coverage-v5-sampled-checkpoints"
SAMPLED_ARTIFACT_SUFFIX = ".v5"
LEGACY_ARTIFACT_SUFFIX = ".v4"
# These targets retain gcda counters between replay inputs. BFTPD imports
# chrooted per-session gcda and Pure-FTPd resets counters during session exit;
# their per-input snapshots remain necessary for the established union audit.
ACCUMULATING_GCDA_TARGETS = (
    "lightftp", "lighttpd1", "forked-daapd", "kamailio", "exim", "proftpd", "live555")
TARGET_PROTOCOLS = {"lightftp": "FTP", "bftpd": "FTP", "proftpd": "FTP",
                    "pure-ftpd": "FTP", "exim": "SMTP", "live555": "RTSP",
                    "kamailio": "SIP", "forked-daapd": "HTTP", "lighttpd1": "HTTP"}
FRAME_AUDIT_HARNESS_VERSIONS = (
    "20261119-cross-target-frame-audit-bftpd-protocol-end-v2",
    "20261119-cross-target-frame-audit-bftpd-protocol-end-v3",
    "20261119-cross-target-frame-audit-bftpd-protocol-end-v4",
    "20261119-verified-peer-close-and-final-send-v5",
    "20261119-verified-terminal-quit-and-lightftp-boundary-v6",
    "20261119-verified-terminal-quit-and-lightftp-stream-boundary-v7",
    "20261119-smtp-quit-and-verified-target-boundaries-v8",
    "20261119-ftp-quit-proftpd-bftpd-audit-v9",
    "20261120-final-221-multiline-aware-replay-v10",
    "20261120-verified-overlong-policy-close-v11",
    "20261120-http-announced-close-smtp-final-reply-v12",
    "20261124-verified-load-truncation-retry-v13",
)
REPLAY_HARNESS_VERSION = FRAME_AUDIT_HARNESS_VERSIONS[-1]
LOOPFUZZ_REPLAYER_ENV = "COVERAGE_V4_LOOPFUZZ_REPLAYER"
_VERIFIED_LOOPFUZZ_REPLAYERS = {}


def replay_policy_version(harness_version):
    """Map the archived replay-harness revision to its protocol policy."""
    try:
        harness_index = FRAME_AUDIT_HARNESS_VERSIONS.index(harness_version)
    except ValueError as error:
        raise CoverageError("unknown replay harness version: " + str(harness_version)) from error
    return max(4, harness_index + 2)


BFTPD_EXIT_MARKER = "COVERAGE_REPLAY_SIGPIPE_NORMAL_EXIT_V2"
BFTPD_CHROOT_MARKER = "COVERAGE_REPLAY_CHROOT_GCOV_PREFIX_V1"
BFTPD_DATA_CHANNEL_MARKER = "COVERAGE_REPLAY_DATA_CHANNEL_CONTROL_FD_V1"
BFTPD_DATA_CHANNEL_OWNERSHIP_MARKER = "COVERAGE_REPLAY_DATA_CHANNEL_DUP_FD_OWNERSHIP_V1"
BFTPD_PASSIVE_FD_OWNERSHIP_MARKER = "COVERAGE_REPLAY_PASSIVE_TO_ACTIVE_FD_OWNERSHIP_V1"
BFTPD_DATA_SOCKET_LIFECYCLE_MARKER = "COVERAGE_REPLAY_DATA_SOCKET_LIFECYCLE_V1"
CSV_FIELDS = ("Time", "l_per", "l_abs", "b_per", "b_abs", "idx",
              "discovery_execution_id", "discovery_monotonic_ms", "campaign_id",
              "coordinate_source", "scope_sha256", "snapshot_sha256")


class CoverageError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def digest_file(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def relative_source(root, filename):
    root = Path(root).resolve()
    path = Path(filename)
    path = (root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        return path.relative_to(root).as_posix()
    except ValueError as error:
        raise CoverageError("source escapes fixed scope: " + str(path)) from error


def nonnegative_integer(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CoverageError(name + " must be a nonnegative integer")
    return value


@dataclasses.dataclass
class Snapshot:
    branches: set
    covered_branches: set
    lines: set
    covered_lines: set
    files: dict
    format_version: str
    resolution: dict = dataclasses.field(default_factory=dict)


def parse_snapshot(report, source_root, search_roots=None, allow_empty=False):
    """Read gcovr JSON 0.1 (4.2) and newer branch arrays, never summaries.

    `search_roots` extends the fingerprint lookup for instrumented trees that
    span directories (exim compiles .c copies inside its build directory but
    #includes headers from the original source tree). The primary root still
    defines the relative naming; every reported file must be found under at
    least one root and the per-file root index is recorded so audits resolve
    identically. `allow_empty` admits the zero-gcda baseline of trees whose
    images never executed the instrumented binary (callers must first verify
    on the filesystem that no gcda exist)."""
    roots = [Path(source_root).resolve()] + [Path(r).resolve() for r in (search_roots or [])]
    if not isinstance(report.get("files"), list):
        raise CoverageError("gcovr JSON must contain a files array")
    branches, covered_branches, lines, covered_lines, files, resolution = set(), set(), set(), set(), {}, {}
    for entry in report["files"]:
        # gcovr reports plain names for sources inside the primary root but
        # dotdot-relative (or absolute) paths for entries outside it; try
        # every root and take the first that both contains and holds the file.
        raw = Path(entry["file"])
        filename = source = None
        for index, root in enumerate(roots):
            candidate = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
            try:
                name = candidate.relative_to(root).as_posix()
            except ValueError:
                continue
            if candidate.is_file():
                filename, source = name, candidate
                resolution[filename] = index
                break
        if filename is None:
            # Last resort: some gcov/gcovr combinations flatten recorded
            # include paths (e.g. kamailio reports src/atomic_x86.h for
            # src/core/atomic/atomic_x86.h).  Resolve by basename; ambiguous
            # or absent basenames stay errors.
            matches = sorted({m for r in roots for m in r.rglob(raw.name)})
            if len(matches) == 1:
                for index, r in enumerate(roots):
                    try:
                        name = matches[0].relative_to(r).as_posix()
                    except ValueError:
                        continue
                    if (r / name).resolve() == matches[0].resolve():
                        filename, source = name, matches[0]
                        resolution[filename] = index
                        break
        if filename is None:
            raise CoverageError("source content cannot be fingerprinted: " + entry["file"])
        if filename in files:
            raise CoverageError("duplicate gcovr source entry: " + filename)
        files[filename] = digest_file(source)
        for line in entry.get("lines", []):
            if line.get("gcovr/excl_line", False):
                continue
            number = nonnegative_integer(line["line_number"], "line_number")
            line_id = (filename, number)
            if line_id in lines:
                raise CoverageError("duplicate source line: " + str(line_id))
            lines.add(line_id)
            if line.get("count", 0) > 0:
                covered_lines.add(line_id)
            for ordinal, branch in enumerate(line.get("branches", [])):
                if branch.get("gcovr/excluded", False):
                    continue
                # 4.2 uses array ordinals; newer JSON exposes branchno.
                # Format/tool versions and gcno hashes are part of scope identity.
                branchno = nonnegative_integer(branch.get("branchno", ordinal), "branchno")
                branch_id = (filename, number, branchno)
                if branch_id in branches:
                    raise CoverageError("duplicate branch identity: " + str(branch_id))
                branches.add(branch_id)
                if branch.get("count", 0) > 0:
                    covered_branches.add(branch_id)
    if (not files or not branches) and not allow_empty:
        raise CoverageError("empty source/branch scope; instrumentation is not validated")
    return Snapshot(branches, covered_branches, lines, covered_lines, files,
                    str(report.get("gcovr/format_version", "unknown")))


def instrument_identity(object_root):
    root = Path(object_root).resolve()
    notes = {path.relative_to(root).as_posix(): digest_file(path)
             for path in sorted(root.rglob("*.gcno")) if path.is_file()}
    if not notes:
        raise CoverageError("no gcno files under object root: " + str(root))
    return notes


SCOPE_IDENTITY_FIELDS = (
    "schema_version", "sources", "gcno", "branch_ids", "line_ids",
    "gcovr_format", "gcovr_version", "gcov_version", "branch_identity",
    "source_resolution", "replay_policy", "checkpoint_policy",
    "replay_harness_version",
)


def scope_identity_payload(manifest):
    """Return fields that define measurement identity, excluding locations."""
    return {field: manifest[field] for field in SCOPE_IDENTITY_FIELDS if field in manifest}


def scope_identity_hash(manifest):
    return digest_bytes(canonical(scope_identity_payload(manifest)).encode())


def scope_manifest(snapshot, notes, gcovr_version, gcov_version, replay_policy=None,
                   schema=SCHEMA, checkpoint_policy=None):
    value = dict(schema_version=schema, sources=snapshot.files, gcno=notes,
                 replay_harness_version=REPLAY_HARNESS_VERSION,
                 branch_ids=sorted(snapshot.branches), line_ids=sorted(snapshot.lines),
                 gcovr_format=snapshot.format_version, gcovr_version=gcovr_version,
                 gcov_version=gcov_version,
                 branch_identity="relative filename, line_number, branchno/array ordinal",
                 source_resolution=snapshot.resolution)
    if replay_policy is not None:
        value["replay_policy"] = replay_policy
    if checkpoint_policy is not None:
        value["checkpoint_policy"] = checkpoint_policy
    return seal_scope_manifest(value)


def seal_scope_manifest(value):
    """Hash measurement identity, leaving provenance paths outside the digest."""
    value["scope_sha256"] = scope_identity_hash(value)
    return value


def bftpd_exit_policy(cwd, allow_incomplete=False):
    """Authenticate the coverage-only SIGPIPE normal-exit build.

    A SIGPIPE in the replay harness is not evidence of a target vulnerability.
    In particular, the coverage subject substitutes fd 2 for the data socket.
    The coverage-only patch sets a flag on peer-close SIGPIPE and leaves the
    command loop through normal cleanup, allowing libgcov's atexit dump. No signal-time
    __gcov_dump call or change to the fuzz target is involved.
    """
    source, login, binary = Path(cwd) / "main.c", Path(cwd) / "login.c", Path(cwd) / "bftpd"
    commands = Path(cwd) / "commands.c"
    marker = BFTPD_EXIT_MARKER.encode()
    verified = (source.is_file() and login.is_file() and commands.is_file() and binary.is_file() and
                marker in source.read_bytes() and marker in binary.read_bytes() and
                BFTPD_CHROOT_MARKER.encode() in login.read_bytes() and
                BFTPD_CHROOT_MARKER.encode() in binary.read_bytes() and
                BFTPD_DATA_CHANNEL_MARKER.encode() in commands.read_bytes() and
                BFTPD_DATA_CHANNEL_MARKER.encode() in binary.read_bytes() and
                BFTPD_DATA_CHANNEL_OWNERSHIP_MARKER.encode() in commands.read_bytes() and
                BFTPD_DATA_CHANNEL_OWNERSHIP_MARKER.encode() in binary.read_bytes() and
                BFTPD_PASSIVE_FD_OWNERSHIP_MARKER.encode() in commands.read_bytes() and
                BFTPD_PASSIVE_FD_OWNERSHIP_MARKER.encode() in binary.read_bytes() and
                BFTPD_DATA_SOCKET_LIFECYCLE_MARKER.encode() in commands.read_bytes() and
                BFTPD_DATA_SOCKET_LIFECYCLE_MARKER.encode() in binary.read_bytes())
    if not verified and not allow_incomplete:
        raise CoverageError("bftpd coverage build lacks verified SIGPIPE normal-exit/data-channel/chroot policy; "
                            "run install_bftpd_coverage_exit.py in the gcov tree")
    return dict(name=BFTPD_EXIT_MARKER if verified else "legacy-unverified-exit",
                chroot_policy=BFTPD_CHROOT_MARKER if verified else "legacy-unverified-chroot",
                data_channel_policy=(BFTPD_DATA_CHANNEL_MARKER if verified
                                     else "legacy-unverified-data-channel"),
                data_channel_fd_ownership=(BFTPD_DATA_CHANNEL_OWNERSHIP_MARKER if verified
                                           else "legacy-unverified-fd-ownership"),
                passive_fd_ownership=(BFTPD_PASSIVE_FD_OWNERSHIP_MARKER if verified
                                      else "legacy-unverified-passive-fd-ownership"),
                data_socket_lifecycle=(BFTPD_DATA_SOCKET_LIFECYCLE_MARKER if verified
                                       else "legacy-unverified-data-socket-lifecycle"),
                session_policy="bftpd-client-lifetime-protocol-end-v5",
                completeness="all-frames-sent-or-audited-bftpd-2xx-control-close-or-reset",
                verified=verified, binary_sha256=digest_file(binary) if binary.is_file() else None,
                scope="coverage replay build only; fuzz target unchanged")


def proftpd_replay_policy(overlong_close=None):
    """Pin the supervised listener lifecycle used for ProFTPD corpus replay."""
    policy = dict(name="proftpd-ready-client-graceful-exit-v5", verified=True,
                  readiness="bound-tcp-listener",
                  shutdown="natural-exit-first;harness-sigterm-after-client-completion",
                  handled_shutdown_exit_signal=-signal.SIGSEGV,
                  handled_harness_shutdown_signal="SIGTERM",
                  acceptance_requires=["harness-requested-sigterm-shutdown-or-audited-quit-221",
                                       "server-ready", "client-exit-0",
                                       "no-client-timeout", "successful-reset",
                                       "ledger-verified-full-send",
                                       "session-gcda-touched"],
                  scope="coverage replay harness only; fuzz target unchanged")
    if overlong_close is not None:
        # v6 adds the mid-input E2BIG policy close: the server's own overlong
        # command defense ends the session with unread pipelined bytes, the
        # kernel converts the close into RST, and every frame after the
        # overlong one is unreachable by construction. Enabled only with a
        # source-derived boundary plus a live behavioral probe.
        policy["name"] = "proftpd-ready-client-graceful-exit-v6"
        policy["overlong_close"] = overlong_close
        policy["acceptance_requires"] = policy["acceptance_requires"] + [
            "verified-overlong-source-policy", "verified-overlong-behavior-probe"]
    return policy


def pureftpd_source_patch_markers(source_bytes):
    expected_regions = (
        b"void _EXIT(const int status)\n{\n    delete_atomic_file();\n"
        b"#ifdef FTPWHO\n    ftpwho_exit();\n#endif\n    exit(status);\n}",
        b"addreply(230, MSG_CURRENT_DIR_IS, wd);\n    }\n"
        b"    unsetenv(\"GCOV_PREFIX\");\n\n#ifndef NON_ROOT_FTP",
        b"sigaddset(&set, SIGCHLD);\n    sigprocmask(SIG_BLOCK, &set, NULL);\n"
        b"    nb_children++;\n    child = 0;",
    )
    return bool(source_bytes) and all(region in source_bytes for region in expected_regions)


def pureftpd_replay_policy(cwd, allow_incomplete=False):
    """Check source patch markers and executable presence for replay policy.

    The hashes are retained as evidence. This check does not prove that the
    executable was built from the source file in this directory.
    """
    source = Path(cwd) / "src/ftpd.c"
    binary = Path(cwd) / "src/pure-ftpd"
    source_bytes = source.read_bytes() if source.is_file() else b""
    source_patch_markers = pureftpd_source_patch_markers(source_bytes)
    binary_present = binary.is_file() and os.access(binary, os.X_OK)
    verified = bool(source_bytes) and source_patch_markers and binary_present
    if not verified and not allow_incomplete:
        raise CoverageError("pure-ftpd gcov source lacks the verified single-process "
                            "session-exit/coverage-flush patch")
    return dict(name="pure-ftpd-gcov-die-421-exit-251-252-v2",
                verified=verified,
                verified_scope="source patch markers present and executable present",
                source_patch_markers_verified=bool(source_bytes) and source_patch_markers,
                executable_present=binary_present,
                source_binary_build_association="not-verified",
                readiness="bound-tcp-listener",
                shutdown="harness-sigterm-after-client-completion",
                handled_session_exit_codes=[251, 252],
                handled_terminal_ftp_reply=421,
                acceptance_requires=["verified-source-patch", "successful-reset",
                                     "server-ready", "client-exit-0", "no-client-timeout",
                                     "final-ftp-reply-421", "session-gcda-imported"],
                source_sha256=digest_file(source) if source.is_file() else None,
                binary_sha256=digest_file(binary) if binary.is_file() else None,
                scope="coverage replay build only; fuzz target unchanged")


def forked_daapd_replay_policy():
    """Pin DAAP replay readiness and the gcov build's normal-exit signal."""
    return dict(name="forked-daapd-ready-client-sigusr1-exit0-v1", verified=True,
                readiness="bound-tcp-listener",
                shutdown="harness-sigusr1-after-client-completion;gcov-patch-exit0",
                scope="coverage replay harness only; fuzz target unchanged")


def replay_incompleteness(replay):
    reasons = []
    if replay.get("session_coverage_missing"):
        reasons.append("session-gcda-not-flushed")
    if replay.get("server_crashed"):
        reasons.append("server-signal-exit")
    if replay.get("replay_anomaly"):
        reasons.append(replay.get("anomaly_kind") or "replay-anomaly")
    if replay.get("client_timed_out"):
        reasons.append("client-timeout")
    if replay.get("server_ready") is False:
        reasons.append("server-not-ready")
    if replay.get("helper_ready") is False:
        reasons.append("helper-not-ready")
    if (("send_completeness" in replay or
            replay.get("harness_policy") in ("proftpd-ready-client-graceful-exit-v4",
                                              "proftpd-ready-client-graceful-exit-v5")) and
            replay.get("send_completeness") != "complete" and
            replay.get("bftpd_protocol_end_expected") is not True and
            replay.get("protocol_end_expected") is not True):
        reasons.append("frame-ledger-incomplete")
    return reasons


def ftp_reply_codes(text):
    """RFC 959 multi-line state machine, mirroring extract_response_codes_ftp.

    Emits single-line "ddd SP" replies and multi-line "ddd-" ... "ddd SP"
    bodies as their opening/closing code; body text (including digit-prefixed
    lines such as FEAT bodies) never emits. Non-reply lines are skipped.
    """
    codes = []
    pending, in_multiline = 0, False
    for raw in text.split("\r\n"):
        line = raw
        if len(line) >= 3 and line[:3].isdigit():
            code = int(line[:3])
            fourth = line[3] if len(line) >= 4 else " "
            if in_multiline:
                if code == pending and fourth == " ":
                    codes.append(code)
                    in_multiline = False
            elif fourth == "-":
                pending, in_multiline = code, True
            elif fourth == " " or len(line) == 3:
                codes.append(code)
        # non-reply text outside a body: skipped
    return codes


def pureftpd_final_reply_code(replay_log):
    """Read the final FTP reply only when summary and transcript agree.

    Both accountings use the multi-line state machine (2026-11-16, GLM53
    2.3): the client summary is produced by the same extractor, so agreement
    is required and any disagreement stays unparsed. The legacy
    prefix-extension rule for pre-state-machine summaries was removed;
    archives produced by the old extractor keep their recorded
    classification and are not re-derived.
    """
    try:
        text = Path(replay_log).read_text(errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    summary_indices = [i for i, line in enumerate(lines)
                       if line.strip().startswith("Responses from server:")]
    details_indices = [i for i, line in enumerate(lines)
                       if line.strip() == "Responses in details:"]
    if len(summary_indices) != 1 or len(details_indices) != 1:
        return None
    summary_index, details_index = summary_indices[0], details_indices[0]
    if details_index <= summary_index:
        return None
    summary = lines[summary_index].partition(":")[2].strip().strip("-")
    summary_parts = summary.split("-")
    if summary_parts and summary_parts[0] == "0":
        summary_parts = summary_parts[1:]
    if not summary_parts or any(len(part) != 3 or not part.isdigit()
                                for part in summary_parts):
        return None
    detail_lines = []
    for line in lines[details_index + 1:]:
        if line.strip().startswith("--------------------------------"):
            break
        detail_lines.append(line)
    transcript_codes = ftp_reply_codes("\r\n".join(detail_lines))
    if [str(code) for code in transcript_codes] != summary_parts:
        return None
    return transcript_codes[-1] if transcript_codes else None


def lightftp_final_reply_code(replay_log):
    """Read LightFTP's final reply, including its known thread-exit log race.

    LightFTP can append its thread-exit diagnostic to the replay client's
    response summary line. In that case the detailed CRLF transcript remains
    authoritative, while the uncorrupted summary codes must still match an
    exact prefix of that transcript. No other summary suffix is accepted.
    """
    parsed = pureftpd_final_reply_code(replay_log)
    if parsed is not None:
        return parsed
    try:
        raw = Path(replay_log).read_bytes()
    except OSError:
        return None

    summary_matches = list(re.finditer(
        rb"(?m)^Responses from server:([^\r\n]*)\r?$", raw))
    details_matches = list(re.finditer(
        rb"(?m)^Responses in details:\r?$", raw))
    if len(summary_matches) != 1 or len(details_matches) != 1:
        return None
    summary_match, details_match = summary_matches[0], details_matches[0]
    if details_match.start() <= summary_match.start():
        return None

    suffix = re.fullmatch(
        rb"0-(?P<codes>[0-9]{3}(?:-[0-9]{3})*)-"
        rb"[0-9]{2}-[0-9]{2}-[0-9]{4} "
        rb"[0-9]{2}:[0-9]{2}:[0-9]{2} S-id=[0-9]+ : "
        rb"<- Thread exit\. Thread counter g_threads=0",
        summary_match.group(1))
    if not suffix:
        return None
    summary_codes = [int(code) for code in suffix.group("codes").split(b"-")]

    details_start = details_match.end()
    if raw[details_start:details_start + 2] == b"\r\n":
        details_start += 2
    elif raw[details_start:details_start + 1] == b"\n":
        details_start += 1
    else:
        return None
    separators = list(re.finditer(
        rb"(?m)^--------------------------------\r?$", raw[details_start:]))
    if len(separators) != 1:
        return None
    details = raw[details_start:details_start + separators[0].start()]
    if details.endswith(b"\r\n\n"):
        details = details[:-1]
    if not details.endswith(b"\r\n"):
        return None

    detail_lines = details.split(b"\r\n")
    if detail_lines and detail_lines[-1] == b"":
        detail_lines.pop()
    terminal = (re.fullmatch(rb"([0-9]{3}) (?:[^\r\n]*)", detail_lines[-1])
                if detail_lines else None)
    if not terminal:
        return None
    terminal_code = int(terminal.group(1))
    transcript_codes = ftp_reply_codes(details.decode("utf-8", errors="replace"))
    if (terminal_code not in (221, 421) or not transcript_codes or
            transcript_codes[-1] != terminal_code or
            transcript_codes[:len(summary_codes)] != summary_codes):
        return None
    return terminal_code


def bftpd_final_reply_code(replay_log, allow_terminal_fallback=True):
    """Read BFTPD's final FTP reply from the complete detailed transcript.

    The BFTPD replay client's compact response-code summary can omit replies
    seen during a server-initiated control close. Use its detailed transcript
    as the source of truth, while requiring the normal, uniquely delimited
    replay output and a CRLF-delimited final FTP reply. Only a terminal 221
    may use the fallback for an earlier malformed multiline response.
    """
    try:
        raw = Path(replay_log).read_bytes()
    except OSError:
        return None

    # Header lines are emitted by the C client with LF, while FTP reply
    # records in the detailed transcript use CRLF. Preserve those bytes:
    # read_text()/splitlines() normalizes CRLF and can turn malformed bare-LF
    # replies into apparently valid FTP records.
    summary_matches = list(re.finditer(
        rb"(?m)^Responses from server:([^\r\n]*)\r?$", raw))
    details_matches = list(re.finditer(
        rb"(?m)^Responses in details:\r?$", raw))
    if len(summary_matches) != 1 or len(details_matches) != 1:
        return None
    summary_match, details_match = summary_matches[0], details_matches[0]
    if details_match.start() <= summary_match.start():
        return None

    try:
        summary = summary_match.group(1).decode("ascii").strip().strip("-")
    except UnicodeDecodeError:
        return None
    summary_codes = summary.split("-")
    if summary_codes and summary_codes[0] == "0":
        summary_codes = summary_codes[1:]
    if (not summary_codes or
            any(len(code) != 3 or not code.isdigit() for code in summary_codes)):
        return None

    details_start = details_match.end()
    if raw[details_start:details_start + 2] == b"\r\n":
        details_start += 2
    elif raw[details_start:details_start + 1] == b"\n":
        details_start += 1
    else:
        return None

    # The output delimiter is a standalone dashed line after the transcript.
    separators = list(re.finditer(rb"(?m)^--------------------------------\r?$", raw[details_start:]))
    if len(separators) != 1:
        return None
    separator_start = details_start + separators[0].start()
    details = raw[details_start:separator_start]
    # The replay client writes one blank LF before its separator. Remove only
    # that framing byte. Bodies such as STAT directory listings may contain
    # bare LF internally, but the terminal reply itself must occupy a CRLF
    # framed line and ftp_reply_codes will only recognize CRLF boundaries.
    if details.endswith(b"\r\n\n"):
        details = details[:-1]
    if not details.endswith(b"\r\n"):
        return None
    detail_lines = details.split(b"\r\n")
    if detail_lines and detail_lines[-1] == b"":
        detail_lines.pop()
    terminal_match = (re.fullmatch(rb"([0-9]{3})(?:[ -].*)?", detail_lines[-1])
                      if detail_lines else None)
    if not terminal_match:
        return None
    terminal_code = int(terminal_match.group(1))
    reply_codes = ftp_reply_codes(details.decode("utf-8", errors="replace"))
    # A malformed or truncated earlier multiline reply can leave the generic
    # RFC 959 parser inside a body, where it correctly suppresses later
    # code-looking lines. Only a final 221 can be independently accepted as
    # BFTPD's protocol-close evidence; other final codes must be recognized by
    # the generic parser so malformed bodies cannot hide a contradictory reply.
    if not reply_codes or reply_codes[-1] != terminal_code:
        if terminal_code != 221 or not allow_terminal_fallback:
            return None
        reply_codes.append(terminal_code)

    # BFTPD's compact summary can omit detail replies (and its terminal 221),
    # but any codes it does report must preserve the detailed transcript's
    # order. This accepts real omissions while rejecting a post-221 summary
    # reply or any other contradictory ordering.
    detail_iter = iter(reply_codes)
    for summary_code in map(int, summary_codes):
        if not any(code == summary_code for code in detail_iter):
            return None
    return terminal_code


def apply_pureftpd_session_exit_policy(flags, server_code, client_code,
                                       server_ready, client_timed_out,
                                       shutdown_requested, final_reply_code,
                                       imported_gcda, reset_succeeded):
    """Accept only observed Pure-FTPd 421-driven exits with full evidence."""
    evidence = dict(server_exit_code=server_code, client_exit_code=client_code,
                    server_ready=bool(server_ready),
                    client_timed_out=bool(client_timed_out),
                    harness_shutdown_requested=bool(shutdown_requested),
                    final_ftp_reply_code=final_reply_code,
                    imported_gcda_count=len(imported_gcda or []),
                    reset_command_succeeded=bool(reset_succeeded))
    accepted = (server_code in (251, 252) and client_code == 0 and
                server_ready is True and client_timed_out is False and
                shutdown_requested is False and final_reply_code == 421 and
                bool(imported_gcda) and reset_succeeded is True and
                flags.get("server_crashed") is False and
                flags.get("server_anomalous_exit") is True and
                flags.get("client_anomalous_exit") is False and
                flags.get("anomaly_kind") == "server-exit-%s" % server_code)
    result = dict(flags)
    result["pureftpd_session_exit_expected"] = bool(accepted)
    result["pureftpd_session_exit_evidence"] = evidence
    if accepted:
        result.update(server_crashed=False, server_anomalous_exit=False,
                      client_anomalous_exit=False, client_aborted_on_crash=False,
                      replay_anomaly=False, anomaly_kind="")
    return result


def framed_input_frames(path):
    """Count length-prefixed frames in a replayable-queue input file."""
    data = Path(path).read_bytes()
    frames, offset = 0, 0
    while offset + 4 <= len(data):
        (length,) = struct.unpack_from("<I", data, offset)
        if length > len(data) - offset - 4:
            raise CoverageError("framed replay input is corrupt: " + str(path))
        frames += 1
        offset += 4 + length
    if offset != len(data):
        raise CoverageError("framed replay input has trailing bytes: " + str(path))
    return frames


def transcript_packets_sent(replay_log):
    """Count the replay client's per-packet banners in a transcript.

    LEGACY EVIDENCE ONLY (2026-11-16, GLM53 plan 2.1): banners print BEFORE
    the send attempt, so a banner count proves loop entry, not delivery.
    New replays carry loopfuzz-replay-frame-ledger-v1; read_frame_ledger is
    the send-completeness authority for them.
    """
    try:
        return Path(replay_log).read_bytes().count(b"Size of the current packet")
    except OSError:
        return None


def ftp_frame_ends_with_quit(payload):
    """Whether an FTP byte stream ends in a QUIT line as BFTPD's fgets sees it.

    BFTPD reads control commands with ``fgets`` (LF-delimited), then removes
    the final CRLF pair. Fuzzed frames can therefore contain earlier bare-LF
    lines while still ending with a real ``QUIT\r\n`` command. Only the final
    LF-delimited line is relevant, and no bytes may follow that command.
    """
    upper = payload.upper()
    suffix = b"QUIT\r\n"
    if not upper.endswith(suffix):
        return False
    prefix = upper[:-len(suffix)]
    return not prefix or prefix.endswith(b"\n")


def bftpd_stream_has_quit(payload):
    """Mirror BFTPD 6.1's fgets(MAXCMD=255), strlen-2 and parsecmd prefix match."""
    offset = 0
    while offset < len(payload):
        chunk = payload[offset:offset + 254]
        newline = chunk.find(b"\n")
        if newline >= 0:
            chunk = chunk[:newline + 1]
        offset += len(chunk)
        # strlen stops at NUL, even when fgets consumed bytes beyond it.
        command = chunk.split(b"\0", 1)[0]
        command = command[:-2] if len(command) >= 2 else b""
        command = bytes(byte for byte in command if byte >= 32)
        if command[:4].upper() == b"QUIT":
            return True
    return False


def http_close_request(payload):
    """Recognize one complete HTTP/1.x request that asks to close the socket."""
    if not payload.endswith(b"\r\n\r\n") or payload.count(b"\r\n\r\n") != 1:
        return False
    lines = payload[:-4].split(b"\r\n")
    if not re.fullmatch(rb"[A-Z]+ [^\r\n ]+ HTTP/1\.[01]", lines[0]):
        return False
    headers = [line.split(b":", 1) for line in lines[1:]]
    if any(len(parts) != 2 for parts in headers):
        return False
    closes = [value.strip().lower() for name, value in headers
              if name.strip().lower() == b"connection"]
    lengths = [value.strip() for name, value in headers
               if name.strip().lower() == b"content-length"]
    return closes == [b"close"] and (not lengths or lengths == [b"0"])


def http_response_announced_close_complete(replay_log):
    """The server itself announced the connection close in the FINAL response.

    RFC 7230 semantics: a response carrying ``Connection: close`` states that
    the server will close after this response. lighttpd emits exactly that
    (after 200/404/501 alike; observed 2026-11-20 on 110 mid-input closes:
    every transcript ended with one complete length-checked response whose
    Connection header is close, followed by the FIN the ledger records).
    The final response must be complete — status line, well-formed headers,
    exactly one Connection: close, one Content-Length that matches the
    remaining body bytes exactly — so a truncated or non-final response
    never qualifies. """
    try:
        raw = Path(replay_log).read_bytes()
    except OSError:
        return False
    marker = b"Responses in details:\n"
    if raw.count(marker) != 1 or raw.count(b"Responses from server:") != 1:
        return False
    details = raw.split(marker, 1)[1].split(b"\n--------------------------------", 1)[0]
    starts = list(re.finditer(rb"HTTP/1\.[01] [1-5][0-9]{2} [^\r\n]*\r\n", details))
    if not starts:
        return False
    last = starts[-1]
    remainder = details[last.end():]
    if b"\r\n\r\n" not in remainder:
        return False
    head, body = remainder.split(b"\r\n\r\n", 1)
    headers = [line.split(b":", 1) for line in head.split(b"\r\n") if line]
    if any(len(parts) != 2 for parts in headers):
        return False
    closes = [value.strip().lower() for name, value in headers
              if name.strip().lower() == b"connection"]
    lengths = [value.strip() for name, value in headers
               if name.strip().lower() == b"content-length"]
    if (closes != [b"close"] or len(lengths) != 1 or
            not lengths[0].isdigit() or len(lengths[0]) > 18):
        return False
    # The server announced close AND sent its headers: a truncated body is
    # part of that teardown (observed 2026-11-22: lighttpd sent
    # Content-Length: 345 + Connection: close headers, then FINed without
    # the error-page body — three inputs on the rebuilt image). The
    # coverage from the sent prefix is real; requiring an exact body match
    # would reject the server's own abort-on-close behavior.
    return len(body) <= int(lengths[0])


def http_close_response_complete(replay_log):
    """Require a single, length-checked HTTP response and Connection: close."""
    try:
        raw = Path(replay_log).read_bytes()
    except OSError:
        return False
    marker = b"Responses in details:\n"
    if raw.count(marker) != 1 or raw.count(b"Responses from server:") != 1:
        return False
    details = raw.split(marker, 1)[1]
    if b"\r\n\r\n" not in details:
        return False
    head, rest = details.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [^\r\n]*", lines[0])
    if not match:
        return False
    summary = re.search(rb"(?m)^Responses from server:0-([0-9]{3})-\r?$", raw)
    if not summary or summary.group(1) != match.group(1):
        return False
    headers = [line.split(b":", 1) for line in lines[1:]]
    if any(len(parts) != 2 for parts in headers):
        return False
    closes = [value.strip().lower() for name, value in headers
              if name.strip().lower() == b"connection"]
    lengths = [value.strip() for name, value in headers
               if name.strip().lower() == b"content-length"]
    if (closes != [b"close"] or len(lengths) != 1 or
            not lengths[0].isdigit() or len(lengths[0]) > 18):
        return False
    size = int(lengths[0])
    if size > len(rest):
        return False
    return rest[size:].startswith(b"\n--------------------------------")


def http_head_request_frame(payload):
    """Recognize HEAD by its unambiguous method token, even for a bad URI."""
    if payload.count(b"\r\n\r\n") != 1 or not payload.endswith(b"\r\n\r\n"):
        return False
    return payload.startswith(b"HEAD ") and b" HTTP/1." in payload[5:]


def http_final_close_response_complete(replay_log, sent_frames=None):
    """Parse complete responses, including bodyless HEAD replies, through close."""
    try:
        raw = Path(replay_log).read_bytes()
    except OSError:
        return False
    marker = b"Responses in details:\n"
    footer = b"\n--------------------------------"
    if raw.count(marker) != 1 or raw.count(b"Responses from server:") != 1:
        return False
    summary = re.search(
        rb"(?m)^Responses from server:0(?P<states>(?:-[0-9]{3})+)-\r?$", raw)
    if not summary:
        return False
    summary_statuses = [int(code) for code in
                        re.findall(rb"-([0-9]{3})", summary.group("states"))]
    details = raw.split(marker, 1)[1]
    if footer not in details:
        return False
    details = details.rsplit(footer, 1)[0]
    offset, final_close, count, used_head = 0, False, 0, False
    detail_statuses = []
    while offset < len(details):
        header_end = details.find(b"\r\n\r\n", offset)
        if header_end < 0:
            return False
        lines = details[offset:header_end].split(b"\r\n")
        status = re.fullmatch(rb"HTTP/1\.[0-9] ([1-5][0-9]{2}) [^\r\n]*", lines[0])
        if not status:
            return False
        detail_statuses.append(int(status.group(1)))
        headers = [line.split(b":", 1) for line in lines[1:]]
        if any(len(parts) != 2 for parts in headers):
            return False
        closes = [value.strip().lower() for name, value in headers
                  if name.strip().lower() == b"connection"]
        lengths = [value.strip() for name, value in headers
                   if name.strip().lower() == b"content-length"]
        if any(name.strip().lower() == b"transfer-encoding" for name, _ in headers):
            return False
        if lengths and (len(lengths) != 1 or not lengths[0].isdigit() or
                        len(lengths[0]) > 18):
            return False
        head_reply = (sent_frames is not None and count < len(sent_frames) and
                      http_head_request_frame(sent_frames[count]))
        if head_reply:
            size = 0
            used_head = True
        elif lengths:
            size = int(lengths[0])
        elif int(status.group(1)) in (204, 304):
            size = 0
        else:
            return False
        offset = header_end + 4 + size
        if offset > len(details):
            return False
        if (int(status.group(1)) in (204, 304) and
                details[offset:offset + 7] == b"\r\nHTTP/"):
            offset += 2
        final_close = closes == [b"close"]
        count += 1
    return (count > 0 and detail_statuses == summary_statuses and final_close and
            (not used_head or count == len(sent_frames)))


def smtp_final_close_reply(replay_log, trailing_noise_ok=False):
    """Read an explicit SMTP close or Exim's error-limit close reply.

    With trailing_noise_ok (v12) the LAST SMTP reply line decides, because
    the transcript tail can carry post-session server teardown noise on the
    shared log stream (observed 2026-11-20: exim daemon termination lines
    flush after the client exits and the 221 is no longer the final byte);
    any reply after a 221/421 still invalidates it. """
    try:
        raw = Path(replay_log).read_bytes()
    except OSError:
        return None
    marker = b"Responses in details:\n"
    footer = b"\n--------------------------------"
    if raw.count(marker) != 1 or footer not in raw.split(marker, 1)[1]:
        return None
    details = raw.split(marker, 1)[1].rsplit(footer, 1)[0]
    if not trailing_noise_ok:
        match = re.search(
            rb"(?:^|\r\n)(221|421) [^\r\n]*\r\n$|"
            rb"(?:^|\r\n)(500|501|503) Too many "
            rb"(?:syntax or protocol errors|unrecognized commands)\r\n$",
            details)
        return int(match.group(1) or match.group(2)) if match else None
    replies = list(re.finditer(rb"(?:^|\r\n)(\d{3})[ -][^\r\n]*\r\n", details))
    if replies:
        last = replies[-1]
        code = int(last.group(1))
        if code in (221, 421):
            return code
        if code in (500, 501, 503):
            tail = details[last.start():last.end()].strip(b"\r\n")
            if re.fullmatch(rb"(?:500|501|503) Too many "
                            rb"(?:syntax or protocol errors|unrecognized commands)",
                            tail):
                return code
    # The details print can itself be truncated (observed 2026-11-20: an
    # exim transcript cut mid-reply while its state sequence — computed
    # from the complete buffer — still ended in 221). The single-line
    # sequence is written atomically, so its final code is the reliable
    # close witness; only a complete CRLF-terminated reply contributes.
    # Post-section daemon noise can share the same line tail ("...-221-53713
    # normal exit"), so the code run must not be anchored to end-of-line.
    sequence = re.search(rb"(?m)^Responses from server:0((?:-[0-9]{3})+)-", raw)
    if sequence:
        codes = sequence.group(1).rsplit(b"-", 1)[-1]
        if codes in (b"221", b"421"):
            return int(codes)
    return None


def read_frame_ledger(path, framed_bytes=None):
    """Validate a loopfuzz-replay-frame-ledger-v1 JSONL and count true sends.

    send_complete is only what the replayer recorded as net_send returning the
    full frame length; banners are never counted. When framed_bytes is given,
    every ledger frame length must match the framed input's prefixes exactly.
    """
    rows = []
    with open(path) as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict) or "event" not in row:
                raise CoverageError(f"frame ledger row {number} is malformed")
            rows.append(row)
    if not rows or rows[0].get("event") != "session_begin" or rows[0].get("schema") != "loopfuzz-replay-frame-ledger-v1":
        raise CoverageError("frame ledger lacks a valid session_begin row")
    frames = [row for row in rows if row.get("event") == "frame"]
    ends = [row for row in rows if row.get("event") == "session_end"]
    if len(ends) != 1 or rows[-1].get("event") != "session_end":
        raise CoverageError("frame ledger must end with exactly one session_end row")
    for index, row in enumerate(frames, 1):
        if row.get("frame") != index:
            raise CoverageError(f"frame ledger sequence breaks at frame {index}")
        if not isinstance(row.get("len"), int) or row["len"] < 0:
            raise CoverageError(f"frame ledger frame {index} has an invalid length")
    expected_payloads = None
    if framed_bytes is not None:
        expected_payloads, offset = [], 0
        data = framed_bytes
        while offset + 4 <= len(data):
            (length,) = struct.unpack_from("<I", data, offset)
            if length > len(data) - offset - 4:
                raise CoverageError("framed input is corrupt while validating ledger")
            expected_payloads.append(data[offset + 4:offset + 4 + length])
            offset += 4 + length
        if offset != len(data):
            raise CoverageError("framed input has trailing bytes outside any frame")
        # The ledger may record a strict PREFIX of the input's frames (the
        # server can close mid-input and the client stops reading); a prefix
        # needs separately verified protocol-close evidence for acceptance.
        led_lens = [row["len"] for row in frames]
        expected_lens = [len(payload) for payload in expected_payloads]
        if led_lens != expected_lens[:len(led_lens)] or len(led_lens) > len(expected_lens):
            raise CoverageError("frame ledger lengths disagree with the framed input")
        input_frame_count = len(expected_payloads)
    else:
        input_frame_count = None
    if ends[0].get("frames_total") != len(frames):
        raise CoverageError("frame ledger summary disagrees with its frame rows")
    # Per-frame state consistency (GLM53 verification 2.2 counterexamples): a
    # full send requires read_complete, a successful pre-recv, an attempted
    # send that wrote exactly the frame length with zero errno, and a
    # successful post-recv or a reset after the final input frame. Contradictory rows (e.g. sent_bytes==len with
    # nonzero errno, or a send claimed after a failed pre-recv) can never
    # count as complete delivery.
    consistent = True
    sent_complete = 0
    attempted = 0
    for index, row in enumerate(frames, 1):
        sent_bytes, length = row.get("sent_bytes"), row.get("len")
        if not isinstance(sent_bytes, int) or not isinstance(length, int):
            raise CoverageError("frame ledger has non-integer byte counts")
        if sent_bytes not in (-2, -1) and (sent_bytes < 0 or sent_bytes > length):
            raise CoverageError("frame ledger sent_bytes is out of range")
        if row.get("read_complete") is not True:
            consistent = False
        if row.get("send_attempt") is True:
            attempted += 1
            if row.get("pre_recv_ok") is not True:
                consistent = False
            if row.get("send_errno") not in (0, None):
                consistent = False
            final_reset = (input_frame_count == len(frames) and index == len(frames) and
                           ends[0].get("stop_reason") == "peer-reset-after-input-end" and
                           row.get("post_recv_ok") is False and
                           row.get("post_recv_errno") == errno.ECONNRESET)
            if sent_bytes == length and (row.get("post_recv_ok") is True or final_reset):
                sent_complete += 1
        elif sent_bytes not in (-2, None):
            consistent = False
    final_reset_end = ends[0].get("stop_reason") == "peer-reset-after-input-end"
    if final_reset_end and not (
            input_frame_count == len(frames) and frames and
            frames[-1].get("post_recv_ok") is False and
            frames[-1].get("post_recv_errno") == errno.ECONNRESET and
            ends[0].get("peer_closed") is False):
        consistent = False
    send_complete = bool(consistent and len(frames) > 0 and
                         sent_complete == len(frames) and attempted == len(frames) and
                         ends[0].get("stop_reason") in
                         ("eof", "peer-reset-after-input-end") and
                         (input_frame_count is None or len(frames) == input_frame_count))
    # Unattempted = every input frame the ledger never attempted, whether the
    # ledger ended early (prefix) or recorded an explicit not-attempted row.
    frames_unattempted = (input_frame_count - attempted) if input_frame_count is not None else None
    prefix_sent = bool(frames and all(
        r.get("read_complete") is True and r.get("pre_recv_ok") is True and
        r.get("send_attempt") is True and r.get("sent_bytes") == r["len"] and
        r.get("send_errno") == 0 for r in frames[:attempted]) and
        all(r.get("send_attempt") is not True for r in frames[attempted:]))
    # Frame boundaries are local to the replay client; TCP presents their
    # payloads as one byte stream. Check the concatenated sent prefix so a
    # trailing frame "QUIT\r\n" cannot turn a preceding partial command
    # such as "NOOP" into a false terminal-QUIT match.
    last_attempted_frame_is_quit = bool(
        prefix_sent and expected_payloads is not None and attempted > 0 and
        attempted <= len(expected_payloads) and
        ftp_frame_ends_with_quit(b"".join(expected_payloads[:attempted])))
    sent_prefix_has_bftpd_quit = bool(
        prefix_sent and expected_payloads is not None and attempted > 0 and
        attempted <= len(expected_payloads) and
        bftpd_stream_has_quit(b"".join(expected_payloads[:attempted])))
    last_attempted_frame_is_http_close = bool(
        prefix_sent and expected_payloads is not None and attempted > 0 and
        attempted <= len(expected_payloads) and
        http_close_request(expected_payloads[attempted - 1]))
    prior_post_recv_ok = bool(attempted > 0 and all(
        row.get("post_recv_ok") is True for row in frames[:attempted - 1]))
    last_attempted_post_recv = frames[attempted - 1] if attempted else {}
    # v12: structured close facts recorded by the replayer at the socket
    # layer. These are authoritative; transcript parsing is a fallback for
    # ledgers produced before this schema existed.
    def close_int(row, key):
        value = row.get(key) if isinstance(row, dict) else None
        return value if isinstance(value, int) else None
    last_reply_code = close_int(ends[0], "last_reply_code")
    response_bytes = close_int(ends[0], "response_bytes")
    last_reply_terminated = ends[0].get("last_reply_terminated") \
        if isinstance(ends[0], dict) else None
    close_initiator = ends[0].get("close_initiator") \
        if isinstance(ends[0], dict) else None
    close_kind = ends[0].get("close_kind") if isinstance(ends[0], dict) else None
    # The pre-send stop variant fails inside the NEXT (never-sent) frame's
    # pre-recv; expose its errno so acceptance can demand a real ECONNRESET
    # there instead of trusting the stop_reason label alone.
    next_unattempted_pre_recv_errno = None
    if 0 < attempted < len(frames):
        candidate = frames[attempted]
        if candidate.get("send_attempt") is not True and candidate.get("pre_recv_ok") is False:
            value = candidate.get("pre_recv_errno")
            next_unattempted_pre_recv_errno = value if isinstance(value, int) else None
    return dict(frames_total=len(frames), frames_unattempted=frames_unattempted,
                frames_attempted=attempted,
                frames_sent_complete=sent_complete,
                prefix_sent_complete=prefix_sent and attempted > 0,
                last_attempted_frame_is_quit=last_attempted_frame_is_quit,
                last_attempted_frame_is_http_close=last_attempted_frame_is_http_close,
                sent_prefix_has_bftpd_quit=sent_prefix_has_bftpd_quit,
                peer_closed=ends[0].get("peer_closed") is True,
                prior_post_recv_ok=prior_post_recv_ok,
                last_attempted_post_recv_ok=last_attempted_post_recv.get("post_recv_ok"),
                last_attempted_post_recv_errno=last_attempted_post_recv.get("post_recv_errno"),
                next_unattempted_pre_recv_errno=next_unattempted_pre_recv_errno,
                last_reply_code=last_reply_code,
                response_bytes=response_bytes,
                last_reply_terminated=last_reply_terminated,
                close_initiator=close_initiator,
                close_kind=close_kind,
                sent_payloads=(expected_payloads[:attempted]
                               if expected_payloads is not None else None),
                stop_reason=ends[0].get("stop_reason"),
                send_complete=send_complete)


def lightftp_replay_policy(source_root, object_root, allow_incomplete=False,
                           overlong_probe=None, build_record=None):
    """Describe LightFTP's bounded-command path; a reproducible-build record
    plus a live probe bind it to the measured executable.

    Source markers and hashes alone cannot tie an image's fftp binary to the
    source tree beside it, so the recorded v4 policy never authorized the
    protocol-close exception. v5 adds two independent bindings: the
    reproducible rebuild (same command, instruction-identical binary; see
    lightftp_build_record) and the behavioral probe (the harness drives the
    actual server with a minimum+1 byte CRLF-free command and requires the
    exact reset ledger shape the acceptance predicate demands). Only with
    both is the exception enabled; otherwise the policy stays the
    historical disabled v4 record.
    """
    source = Path(source_root) / "ftpserv.c"
    header = Path(source_root) / "ftpserv.h"
    binary = Path(object_root) / "fftp"
    source_bytes = source.read_bytes() if source.is_file() else b""
    header_bytes = header.read_bytes() if header.is_file() else b""
    required_source = (
        b"int recvcmd(PFTPCONTEXT context, char *buffer, size_t buffer_size)",
        b"--buffer_size;", b"while (buffer_size > 0)",
        b"if ( p >= 2 )", b"(buffer[p-2] == '\\r') && (buffer[p-1] == '\\n')",
        b"if ( !recvcmd(&ctx, rcvbuf, sizeof(rcvbuf)) )", b"close(ctx.ControlSocket);",
    )
    header_verified = b"#include <limits.h>" in header_bytes
    buffer_verified = re.search(rb"rcvbuf\s*\[\s*PATH_MAX\s*\]",
                                source_bytes) is not None
    source_verified = (bool(source_bytes) and header_verified and buffer_verified and
                       all(marker in source_bytes for marker in required_source))
    binary_present = binary.is_file() and os.access(binary, os.X_OK)
    path_max = None
    try:
        macros = subprocess.run(
            ["cc", "-dM", "-E", "-x", "c", "-"], input=b"#include <limits.h>\n",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
        macro = re.search(rb"(?m)^#define PATH_MAX ([0-9]+)$", macros.stdout)
        if macros.returncode == 0 and macro:
            path_max = int(macro.group(1))
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    command_buffer_size = path_max
    probe_verified = bool(isinstance(overlong_probe, dict) and
                          overlong_probe.get("verified") is True and
                          isinstance(overlong_probe.get("minimum_bytes"), int) and
                          overlong_probe.get("minimum_bytes") ==
                          (command_buffer_size - 1 if command_buffer_size else None))
    build_verified = bool(isinstance(build_record, dict) and
                          build_record.get("verified") is True and
                          build_record.get("binary_sha256") ==
                          (digest_file(binary) if binary_present else None))
    verified = bool(source_verified and binary_present and
                    command_buffer_size is not None and probe_verified and build_verified)
    if verified:
        return dict(name="lightftp-gcov-path-max-stream-close-v5", verified=True,
                    exception_enabled=True,
                    verified_scope="source markers, PATH_MAX, a reproducible rebuild "
                                   "record, and a live reset-shape probe against the "
                                   "measured executable",
                    source_structure_verified=True,
                    source_sha256=digest_file(source) if source.is_file() else None,
                    header_sha256=digest_file(header) if header.is_file() else None,
                    binary_sha256=digest_file(binary) if binary_present else None,
                    source_binary_build_association="reproducible-rebuild-and-behavioral-probe",
                    overlong_probe=overlong_probe,
                    build_record=build_record,
                    path_max=path_max,
                    command_buffer_size=command_buffer_size,
                    max_bytes_without_crlf=command_buffer_size - 1)
    # The checked-in Docker build pins source and compiler flags, but its
    # existing image contains no build record linking this executable to these
    # source bytes. Hashing both files independently does not establish that
    # relationship, so it cannot authorize a protocol-close exception.
    return dict(name="lightftp-gcov-path-max-stream-close-v4", verified=False,
                exception_enabled=False,
                verified_scope="source markers and PATH_MAX recorded; executable association unverified",
                source_structure_verified=source_verified,
                source_sha256=digest_file(source) if source.is_file() else None,
                header_sha256=digest_file(header) if header.is_file() else None,
                binary_sha256=digest_file(binary) if binary_present else None,
                source_binary_build_association="not-established",
                path_max=path_max,
                command_buffer_size=command_buffer_size,
                max_bytes_without_crlf=command_buffer_size - 1
                if command_buffer_size is not None else None)


def proftpd_overlong_source_policy(source_root, object_root, conf_path=None):
    """Derive ProFTPD's no-newline command give-up boundary from its source
    and the EFFECTIVE configuration of the run being certified.

    src/main.c defaults CommandBufferSize to PR_DEFAULT_CMD_BUFSZ
    (PR_TUNABLE_PATH_MAX + 7); pr_netio_telnet_gets2 fills one window of
    that size minus the NUL slot and returns E2BIG without a newline; and
    pr_cmd_read sleeps 250ms per strike, giving up once the counter passes
    its limit. The boundary is (limit+1) full windows:
    (limit+1) * (effective_CommandBufferSize - 1). The fuzzing run.sh
    injects ``CommandBufferSize 65535`` into basic.conf (boundary 262136),
    so a corpus from that environment must never be judged against the
    default-derived boundary (16408 with PATH_MAX 4096). Empirically
    confirmed 2026-11-20 against the pinned image: default-config boundary
    16408 bytes; under the 65535 conf the previously failing 18-27KB
    inputs replay to completion without any policy close.
    """
    main_c = Path(source_root) / "src" / "main.c"
    netio_c = Path(source_root) / "src" / "netio.c"
    binary = Path(object_root) / "proftpd" if object_root else None
    main_bytes = main_c.read_bytes() if main_c.is_file() else b""
    netio_bytes = netio_c.read_bytes() if netio_c.is_file() else b""
    default_bufsz = re.search(
        rb"(?m)^#\s*define\s+PR_DEFAULT_CMD_BUFSZ\s*\(PR_TUNABLE_PATH_MAX\s*\+\s*([0-9]+)\)",
        main_bytes)
    retry_limit = re.search(rb"too_large_count\s*>\s*([0-9]+)", main_bytes)
    sleep_ms = re.search(rb"pr_timer_usleep\(\s*([0-9]+)\s*\*\s*1000\s*\)", main_bytes)
    path_max = None
    try:
        macros = subprocess.run(
            ["cc", "-dM", "-E", "-x", "c", "-"], input=b"#include <limits.h>\n",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
        macro = re.search(rb"(?m)^#define PATH_MAX ([0-9]+)$", macros.stdout)
        if macros.returncode == 0 and macro:
            path_max = int(macro.group(1))
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    conf_override = None
    conf_bytes = b""
    if conf_path is not None and Path(conf_path).is_file():
        conf_bytes = Path(conf_path).read_bytes()
        directive = re.search(rb"(?im)^[ \t]*CommandBufferSize[ \t]+([0-9]+)", conf_bytes)
        if directive:
            conf_override = int(directive.group(1))
    structure_verified = bool(
        default_bufsz and retry_limit and sleep_ms and
        all(marker in netio_bytes for marker in (b"errno = E2BIG", b"saw_newline")) and
        all(marker in main_bytes for marker in
            (b"too_large_count", b"E2BIG", b"pr_cmd_read")))
    default_buffer = (path_max + int(default_bufsz.group(1))
                      if path_max is not None and default_bufsz else None)
    effective_buffer, buffer_source = (
        (conf_override, "conf-directive") if conf_override is not None
        else (default_buffer, "source-default"))
    retries = (int(retry_limit.group(1)) + 1
               if retry_limit else None)
    give_up_bytes = ((retries * (effective_buffer - 1))
                     if retries is not None and effective_buffer else None)
    binary_present = bool(binary and binary.is_file() and os.access(binary, os.X_OK))
    verified = bool(structure_verified and
                    binary_present and give_up_bytes is not None and give_up_bytes > 0)
    return dict(name="proftpd-e2big-retry-session-close-v1",
                verified=verified,
                exception_enabled=False,
                verified_scope="source-derived E2BIG retry boundary from the effective "
                               "CommandBufferSize; behavioral probe required before the "
                               "exception can be enabled",
                source_structure_verified=structure_verified,
                command_buffer_size_default=default_buffer,
                command_buffer_size_effective=effective_buffer,
                command_buffer_size_source=buffer_source,
                conf_sha256=digest_file(conf_path) if conf_path and Path(conf_path).is_file() else None,
                main_c_sha256=digest_file(main_c) if main_c.is_file() else None,
                netio_c_sha256=digest_file(netio_c) if netio_c.is_file() else None,
                binary_sha256=digest_file(binary) if binary_present else None,
                path_max=path_max,
                e2big_retry_limit=retries - 1 if retries is not None else None,
                retry_sleep_ms=int(sleep_ms.group(1)) if sleep_ms else None,
                give_up_bytes=give_up_bytes,
                probe_min_close_delay_ms=(retries * int(sleep_ms.group(1))
                                          if retries is not None and sleep_ms else None))


def probe_ftp_overlong_close(target, port, cwd, workdir, directory, source_policy,
                             allow_incomplete=False):
    """Behaviorally verify the measured binary policy-closes overlong commands
    with a TCP reset, before any corpus input can be accepted under the
    overlong-close exception.

    The probe drives the actual server executable through the same supervised
    launch the corpus replay uses, with a synthetic framed input whose first
    frame is minimum+1 terminator-free bytes followed by NOOP frames (they
    keep the client connected past the server's close). Verification demands
    the identical ledger shape the acceptance predicate later requires, plus
    the target's expected close delay (ProFTPD sleeps 250ms per E2BIG
    strike; the client cannot observe the reset early). """
    minimum = source_policy.get("give_up_bytes") if target == "proftpd" \
        else source_policy.get("max_bytes_without_crlf")
    if not isinstance(minimum, int) or minimum <= 0:
        raise CoverageError("%s overlong policy lacks a derived minimum" % target)
    terminator = b"\n" if target == "proftpd" else b"\r\n"
    probe_dir = Path(directory) / "overlong-close-probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    frames = [b"A" * (minimum + 1)] + [b"NOOP\r\n"] * 12
    input_path = probe_dir / "probe-input"
    input_path.write_bytes(b"".join(struct.pack("<I", len(frame)) + frame
                                    for frame in frames))
    ledger_path = probe_dir / "probe-frame-ledger.jsonl"
    log_path = probe_dir / "probe.log"
    env = os.environ.copy()
    env["LOOPFUZZ_REPLAY_LEDGER"] = str(ledger_path)
    client_command, server_command = replay_commands(target, input_path, port, 1,
                                                     cwd, workdir)
    started = time.monotonic()
    with log_path.open("wb") as log:
        supervised = run_supervised_session(target, client_command, server_command,
                                            {"path": str(input_path)}, 1, port,
                                            cwd, env, log)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    ledger = None
    try:
        ledger = read_frame_ledger(ledger_path, input_path.read_bytes())
    except (OSError, CoverageError):
        ledger = None
    payloads = ledger.get("sent_payloads") if ledger else None
    post_send_reset = bool(
        ledger and ledger.get("stop_reason") == "client-recv-post-send-failed" and
        ledger.get("last_attempted_post_recv_errno") == errno.ECONNRESET)
    # The policy reset can land between frames (observed 2026-11-20: the
    # v11c probe run); the evidence then lives in the never-sent frame's
    # pre-recv instead. Both variants are the same server policy close.
    pre_send_reset = bool(
        ledger and ledger.get("stop_reason") == "client-recv-pre-send-failed" and
        ledger.get("last_attempted_post_recv_ok") is True and
        ledger.get("next_unattempted_pre_recv_errno") == errno.ECONNRESET)
    probe = dict(
        name="overlong-policy-close-behavior-probe-v1",
        minimum_bytes=minimum,
        probe_input_sha256=digest_file(input_path),
        probe_ledger_file=ledger_path.name,
        probe_ledger_sha256=digest_file(ledger_path) if ledger_path.is_file() else None,
        probe_log_file=log_path.name,
        probe_log_sha256=digest_file(log_path),
        client_exit_code=supervised.get("client_exit_code"),
        server_exit_code=supervised.get("server_exit_code"),
        server_ready=supervised.get("server_ready"),
        client_timed_out=supervised.get("client_timed_out"),
        harness_shutdown_requested=supervised.get("harness_shutdown_requested"),
        elapsed_ms=elapsed_ms,
        minimum_close_delay_ms=source_policy.get("probe_min_close_delay_ms"),
        stop_reason=ledger.get("stop_reason") if ledger else None,
        last_attempted_post_recv_errno=(ledger.get("last_attempted_post_recv_errno")
                                        if ledger else None),
        next_unattempted_pre_recv_errno=(ledger.get("next_unattempted_pre_recv_errno")
                                         if ledger else None),
        trigger_frame=overlong_close_trigger_frame(payloads, minimum, terminator,
                                                   telnet_iac=(target == "proftpd"))
        if payloads else None)
    probe["verified"] = bool(
        ledger is not None and
        supervised.get("client_exit_code") == 2 and
        supervised.get("server_exit_code") == 0 and
        supervised.get("server_ready") is True and
        supervised.get("client_timed_out") is False and
        ledger.get("prefix_sent_complete") and
        ledger.get("prior_post_recv_ok") is True and
        (post_send_reset or pre_send_reset) and
        isinstance(ledger.get("frames_unattempted"), int) and
        ledger["frames_unattempted"] > 0 and
        probe["trigger_frame"] == 1 and
        (target != "proftpd" or
         (supervised.get("harness_shutdown_requested") is not True and
          elapsed_ms >= (source_policy.get("probe_min_close_delay_ms") or 0))))
    if not probe["verified"] and not allow_incomplete:
        raise CoverageError(
            "%s overlong-close behavior probe failed: client=%s server=%s ready=%s "
            "stop=%s errno=%s next_pre_errno=%s trigger=%s elapsed_ms=%s" %
            (target, supervised.get("client_exit_code"), supervised.get("server_exit_code"),
             supervised.get("server_ready"), probe.get("stop_reason"),
             probe.get("last_attempted_post_recv_errno"),
             probe.get("next_unattempted_pre_recv_errno"), probe.get("trigger_frame"),
             elapsed_ms))
    return probe


LIGHTFTP_GCOV_FLAGS = ("CFLAGS=-fprofile-arcs -ftest-coverage",
                       "CPPFLAGS=-fprofile-arcs -ftest-coverage",
                       "CXXFLAGS=-fprofile-arcs -ftest-coverage",
                       "LDFLAGS=-fprofile-arcs -ftest-coverage")


def _file_diff_byte_count(left, right):
    count = 0
    with open(left, "rb") as a, open(right, "rb") as b:
        while True:
            ca, cb = a.read(65536), b.read(65536)
            if ca != cb:
                if len(ca) != len(cb):
                    return None
                count += sum(1 for x, y in zip(ca, cb) if x != y)
            if not ca:
                return count


def lightftp_build_record(source_root, object_root, artifact_dir):
    """Bind the image's fftp executable to the source tree and the recorded
    compile parameters by an in-place reproducible rebuild.

    The Dockerfile builds the gcov tree with
    ``make CFLAGS=-fprofile-arcs -ftest-coverage ... clean all``. Rebuilding
    with the same command at the same path reproduces every object
    byte-for-byte except GCC's 4-byte random gcov stamp per object, and a
    linked binary whose disassembly (objdump -d) is instruction-identical
    to the image binary; the only differing bytes sit in the GNU build-id /
    aggregated stamp metadata. A divergence observed once in a live
    fuzzing container (2026-11-20 22:09 lightftp arm) did not reproduce on
    the frozen filesystem, so the record retries once and, on final
    failure, persists per-object diff counts and both disassemblies into
    the artifact directory for post-hoc diagnosis instead of leaving an
    unreproducible verdict. The originals are restored and hash-verified
    afterwards, and any surprise (dirty git state, restore mismatch,
    non-stamp object differences) fails closed.
    """
    record = _lightftp_build_record_once(source_root, object_root, artifact_dir)
    if not record.get("verified"):
        record["retried"] = True
        retry = _lightftp_build_record_once(source_root, object_root, artifact_dir)
        retry["retried"] = True
        if not retry.get("verified"):
            try:
                write_json(Path(artifact_dir) / "lightftp-rebuild-divergence.json",
                           dict(
                               schema_version="lightftp-rebuild-divergence-v1",
                               first_attempt={k: record.get(k) for k in
                                              ("git_head", "gcov_patch_sha256",
                                               "gcov_patch_reverse_appliable",
                                               "tracked_modifications_sorted",
                                               "tracked_modifications_confined_to_patch",
                                               "binary_sha256", "rebuilt_binary_sha256",
                                               "disassembly_identical", "objects_total",
                                               "objects_byte_identical",
                                               "objects_stamp_only_difference",
                                               "objects_unexpected_difference",
                                               "make_exit_code")},
                               second_attempt={k: retry.get(k) for k in
                                               ("binary_sha256", "rebuilt_binary_sha256",
                                                "disassembly_identical", "objects_total",
                                                "objects_byte_identical",
                                                "objects_stamp_only_difference",
                                                "objects_unexpected_difference",
                                                "make_exit_code")}))
            except OSError:
                pass
        return retry
    return record


def _lightftp_build_record_once(source_root, object_root, artifact_dir):
    source_root, object_root = Path(source_root), Path(object_root)
    record = dict(name="lightftp-reproducible-rebuild-record-v1",
                  compile_command=["make"] + list(LIGHTFTP_GCOV_FLAGS) + ["clean", "all"],
                  rebuild_log_file="lightftp-rebuild.log")
    binary = object_root / "fftp"
    if not binary.is_file():
        record.update(verified=False, reason="missing fftp executable")
        return record
    git_head = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                              timeout=30)
    # The Dockerfile checks out commit 139af7c and applies gcov.patch, so the
    # tree is legitimately dirty versus HEAD. Prove that exact state instead
    # of a naive cleanliness check: the patch must reverse-apply cleanly
    # (git apply --check -R) and no tracked file outside the patch may be
    # modified. Untracked files are build artifacts.
    gcov_patch = None
    for candidate in ([source_root.parent / "gcov.patch"] +
                      [ancestor / "gcov.patch" for ancestor in source_root.parents] +
                      [Path(os.environ.get("WORKDIR", "")) / "gcov.patch"]):
        if candidate.is_file():
            gcov_patch = candidate
            break
    if gcov_patch is None:
        gcov_patch = source_root.parent / "gcov.patch"
    patch_reverse = subprocess.run(
        ["git", "-C", str(source_root), "apply", "--check", "--reverse", str(gcov_patch)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)
    tracked = subprocess.run(
        ["git", "-C", str(source_root), "status", "--porcelain", "--untracked-files=no"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=30)
    patch_bytes = gcov_patch.read_bytes() if gcov_patch.is_file() else b""
    patch_touched = {name.decode() for name in re.findall(
        rb"(?m)^diff --git a/(\S+) b/\S+", patch_bytes)}
    modified = {line[3:].decode(errors="replace").strip()
                for line in tracked.stdout.splitlines() if line.startswith(b" M ")}
    record.update(git_head=git_head.stdout.decode(errors="replace").strip() or None,
                  gcov_patch_sha256=digest_file(gcov_patch) if gcov_patch.is_file() else None,
                  gcov_patch_reverse_appliable=patch_reverse.returncode == 0,
                  tracked_modifications_sorted=sorted(modified),
                  tracked_modifications_confined_to_patch=modified <= patch_touched)
    if not (git_head.returncode == 0 and record["gcov_patch_reverse_appliable"] and
            record["tracked_modifications_confined_to_patch"]):
        record.update(verified=False,
                      reason="source tree is not checkout+gcov.patch state")
        return record
    inventory = {"fftp": digest_file(binary)}
    products = sorted(object_root.glob("*.o")) + sorted(object_root.glob("*.gcno"))
    inventory.update({p.name: digest_file(p) for p in products})
    backup = Path(tempfile.mkdtemp(prefix="lightftp-rebuild-backup-"))
    try:
        for product in [binary] + products:
            shutil.copy2(product, backup / product.name)
        log_path = Path(artifact_dir) / record["rebuild_log_file"]
        with log_path.open("wb") as log:
            make = subprocess.run(["make"] + list(LIGHTFTP_GCOV_FLAGS) + ["clean", "all"],
                                  cwd=object_root, stdout=log, stderr=subprocess.STDOUT,
                                  check=False, timeout=600)
        record.update(make_exit_code=make.returncode)
        if make.returncode != 0 or not binary.is_file():
            record.update(verified=False, reason="rebuild make failed")
            return record
        record.update(binary_sha256=inventory["fftp"],
                      rebuilt_binary_sha256=digest_file(binary),
                      rebuild_log_sha256=digest_file(log_path))
        disassembly = subprocess.run(
            ["bash", "-c",
             'objdump -d "%s" | grep -v "file format" > "$1.new"; '
             'objdump -d "%s" | grep -v "file format" > "$1.orig"; '
             'cmp -s "$1.new" "$1.orig"' % (binary, backup / "fftp"),
             "sh", str(backup / "disasm")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=120)
        record.update(disassembly_identical=disassembly.returncode == 0)
        stamp_only, identical, unexpected = 0, 0, []
        for product in products:
            difference = _file_diff_byte_count(product, backup / product.name)
            if difference == 0:
                identical += 1
            elif difference <= 4:
                # GCC's gcov stamp is a random 32-bit value: any 1-4 of its
                # bytes can differ between builds (observed 2026-11-22: the
                # rebuilt image's stamp coincided in one byte, producing a
                # 3-byte diff that the ==4 check rejected as unexpected).
                stamp_only += 1
            else:
                unexpected.append(product.name)
        record.update(objects_total=len(products), objects_byte_identical=identical,
                      objects_stamp_only_difference=stamp_only,
                      objects_unexpected_difference=unexpected)
        record["verified"] = bool(
            record["disassembly_identical"] and not unexpected)
        return record
    finally:
        for name in inventory:
            restored = backup / name
            if restored.is_file():
                shutil.copy2(restored, object_root / name)
        shutil.rmtree(backup, ignore_errors=True)
        for name, expected in inventory.items():
            if digest_file(object_root / name) != expected:
                raise CoverageError(
                    "lightftp rebuild restore mismatch for %s; refusing to continue" % name)


def overlong_close_trigger_frame(payloads, minimum, terminator, telnet_iac=False):
    """Index (1-based) of the first sent frame that provably exhausts the
    target's bounded-command retry path, or None.

    The control stream is newline-delimited, so frame j can only start a fresh
    command when the concatenated prefix of frames 1..j-1 ends with CRLF
    (frame 1 always follows the banner). ProFTPD reads commands through a
    telnet filter whose IAC escapes consume raw bytes without emitting
    processed ones: a raw no-newline window of ``minimum + 3 * ff_count``
    bytes still guarantees ``minimum`` processed bytes without a newline,
    because each 0xFF consumes at most the two bytes after it.
    """
    prefix = b""
    for index, payload in enumerate(payloads):
        if (isinstance(payload, bytes) and len(payload) >= minimum and
                (index == 0 or prefix.endswith(b"\r\n"))):
            escape_slack = 3 * payload.count(b"\xff") if telnet_iac else 0
            window = payload[:minimum + escape_slack]
            if (terminator not in window and
                    len(window) >= minimum + escape_slack):
                return index + 1
        prefix += payload if isinstance(payload, bytes) else b""
    return None


def lightftp_command_line_extracts_quit(payloads):
    """Whether LightFTP's command parser extracts QUIT from the sent stream.

    ftpserv.c's loop skips leading non-alpha bytes of the (CRLF-terminated)
    line and then strncasecmp-matches the alpha run against known command
    names, so a garbage frame without a trailing newline glued in front of
    a bare ``QUIT\\r\\n`` frame still executes as QUIT (observed 2026-11-20:
    205 bytes of 0xF2 filler + QUIT closed the session with 221). Only the
    final line matters — recvcmd returns once the accumulated tail ends in
    CRLF. """
    stream = b"".join(payloads)
    if stream.endswith(b"\n"):
        stream = stream[:-1]
    line = stream.rsplit(b"\n", 1)[-1]
    # C isalpha() in the default locale is ASCII-only; Python's isalpha()
    # would treat 0xF2 as a letter and diverge from the target's parser.
    def c_isalpha(byte):
        return 65 <= byte <= 90 or 97 <= byte <= 122
    index = 0
    while index < len(line) and not c_isalpha(line[index]):
        index += 1
    run = bytearray()
    while index < len(line) and c_isalpha(line[index]):
        run.append(line[index])
        index += 1
    return bytes(run).upper() == b"QUIT"


def ftp_overlong_close_gates(replay, reset, ledger):
    """Process-level evidence that the server itself policy-closed mid-input.

    Both stop variants must carry a real ECONNRESET from the ledger rows: the
    post-send variant in the last attempted frame's post-recv, the pre-send
    variant in the next unattempted frame's pre-recv. """
    ledger = ledger or {}
    stop_reason = ledger.get("stop_reason")
    post_send_reset = (stop_reason == "client-recv-post-send-failed" and
                       ledger.get("last_attempted_post_recv_errno") == errno.ECONNRESET)
    pre_send_reset = (stop_reason == "client-recv-pre-send-failed" and
                      ledger.get("next_unattempted_pre_recv_errno") == errno.ECONNRESET)
    return bool(replay.get("server_exit_code") == 0 and
                replay.get("client_exit_code") == 2 and
                replay.get("server_ready") is True and
                replay.get("client_timed_out") is False and
                not replay.get("session_coverage_missing") and
                bool(replay.get("session_gcda_touched")) and
                reset.get("command_succeeded") is True and reset.get("exit_code") == 0 and
                ledger.get("prefix_sent_complete") and
                isinstance(ledger.get("frames_unattempted"), int) and
                ledger["frames_unattempted"] > 0 and
                ledger.get("prior_post_recv_ok") is True and
                (post_send_reset or pre_send_reset))


def proftpd_cross_protocol_close_expected(replay, reset, ledger, server_log_path):
    """ProFTPD drops clients that speak another wire protocol (Bug#4143).

    src/main.c cmd_loop disconnects with PR_SESS_DISCONNECT_BAD_PROTOCOL as
    soon as pr_cmd_read classifies a command as non-FTP (SMTP verbs HELO/
    EHLO/MAIL/RCPT/DATA/RSET/VRFY, HTTP verbs GET/POST/PUT/... — src/cmd.c
    http_ids/smtp_ids). The teardown runs through pr_session_end, which
    _exit()s without the gcov atexit flush — so a zero-gcda session with
    exit 0 is the EXPECTED artifact of this policy, not a flush failure
    (observed 2026-11-21: "client sent SMTP command 'HELO', disconnecting"
    in the separated server log, 0 touched gcda). The acceptance therefore
    keys on the server-log line itself, plus the full process gates. """
    if ledger is None:
        return False
    if ledger.get("stop_reason") != "peer-closed-before-input-end" or \
            ledger.get("peer_closed") is not True:
        return False
    try:
        raw = Path(server_log_path).read_bytes()
    except OSError:
        return False
    witnessed = re.search(
        rb"client sent (?:SMTP|HTTP) command '[^']*', disconnecting", raw)
    return bool(witnessed and
                replay.get("server_exit_code") == 0 and
                replay.get("client_exit_code") == 2 and
                replay.get("server_ready") is True and
                replay.get("client_timed_out") is False and
                replay.get("harness_shutdown_requested") is not True and
                reset.get("command_succeeded") is True and reset.get("exit_code") == 0 and
                ledger.get("prefix_sent_complete") and
                isinstance(ledger.get("frames_unattempted"), int) and
                ledger["frames_unattempted"] > 0 and
                ledger.get("prior_post_recv_ok") is True)


def proftpd_overlong_close_expected(replay, reset, ledger, replay_policy):
    """ProFTPD's pr_cmd_read abandons a session after its E2BIG retry budget.

    pr_netio_telnet_gets2 returns E2BIG when a full CommandBufferSize window
    holds no newline; pr_cmd_read sleeps 250ms per strike and gives up once
    the counter passes its limit. The close then lands on unread pipelined
    bytes and the kernel emits RST instead of FIN (reproduced 2026-11-20 on
    the pinned image: 16408 = 4*(4096+7-1) consecutive no-newline bytes close
    the session, 16407 do not). The give-up boundary and retry schedule are
    re-derived from the source by proftpd_overlong_source_policy and the
    executable is behaviorally probed before this exception can authorize
    anything. """
    policy = (replay_policy or {}).get("overlong_close") or {}
    minimum = policy.get("give_up_bytes")
    payloads = ledger.get("sent_payloads") if ledger else None
    if (not isinstance(payloads, list) or not payloads or
            not all(isinstance(payload, bytes) for payload in payloads)):
        return False
    return bool(policy.get("verified") is True and
                policy.get("exception_enabled") is True and
                isinstance(minimum, int) and minimum > 0 and
                replay.get("harness_shutdown_requested") is not True and
                overlong_close_trigger_frame(payloads, minimum, b"\n",
                                             telnet_iac=True) is not None and
                ftp_overlong_close_gates(replay, reset, ledger))


def lightftp_oversized_command_close_expected(replay, reset, ledger, policy):
    payloads = ledger.get("sent_payloads") if ledger else None
    if not isinstance(payloads, list) or not payloads:
        return False
    if not all(isinstance(payload, bytes) for payload in payloads):
        return False
    minimum = policy.get("max_bytes_without_crlf") if policy else None
    if not (policy and policy.get("verified") is True and
            isinstance(minimum, int) and minimum > 0):
        return False
    stream = b"".join(payloads)
    command_bytes = stream.rsplit(b"\r\n", 1)[-1]
    # v11: recvcmd also abandons mid-stream when one frame alone fills the
    # PATH_MAX command buffer without any CRLF, leaving every later frame
    # unread by construction (reproduced 2026-11-20: 4096 bytes reset, 4095
    # close cleanly, 4094 keep waiting). The historical tail shape (one
    # unterminated command running to end of input) stays accepted.
    midstream = overlong_close_trigger_frame(payloads, minimum, b"\r\n") is not None
    return bool(policy.get("exception_enabled") is True and
                ftp_overlong_close_gates(replay, reset, ledger) and
                (midstream or len(command_bytes) >= minimum))


def verify_lightftp_replay_policy(policy, source_root, object_root,
                                  artifact_root=None):
    source = Path(source_root) / "ftpserv.c"
    header = Path(source_root) / "ftpserv.h"
    binary = Path(object_root) / "fftp" if object_root else None
    if (not source.is_file() or not header.is_file() or binary is None or
            not binary.is_file() or not os.access(binary, os.X_OK)):
        return False
    source_bytes = source.read_bytes()
    header_bytes = header.read_bytes()
    markers = (
        b"int recvcmd(PFTPCONTEXT context, char *buffer, size_t buffer_size)",
        b"--buffer_size;", b"while (buffer_size > 0)",
        b"if ( p >= 2 )", b"(buffer[p-2] == '\\r') && (buffer[p-1] == '\\n')",
        b"if ( !recvcmd(&ctx, rcvbuf, sizeof(rcvbuf)) )", b"close(ctx.ControlSocket);",
    )
    header_verified = b"#include <limits.h>" in header_bytes
    buffer_verified = re.search(rb"rcvbuf\s*\[\s*PATH_MAX\s*\]",
                                source_bytes) is not None
    try:
        macros = subprocess.run(
            ["cc", "-dM", "-E", "-x", "c", "-"], input=b"#include <limits.h>\n",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=10)
        macro = re.search(rb"(?m)^#define PATH_MAX ([0-9]+)$", macros.stdout)
        path_max = int(macro.group(1)) if macros.returncode == 0 and macro else None
    except (OSError, subprocess.SubprocessError, ValueError):
        path_max = None
    command_buffer_size = path_max
    structure = bool(header_verified and buffer_verified and
                     all(marker in source_bytes for marker in markers))
    identity = bool(policy and
                    policy.get("source_sha256") == digest_file(source) and
                    policy.get("header_sha256") == digest_file(header) and
                    policy.get("binary_sha256") == digest_file(binary) and
                    policy.get("source_structure_verified") is True and
                    policy.get("path_max") == path_max and
                    policy.get("command_buffer_size") == command_buffer_size and
                    policy.get("max_bytes_without_crlf") == command_buffer_size - 1 and
                    re.fullmatch(r"[0-9a-f]{64}", policy.get("binary_sha256", "")))
    if policy and policy.get("name") == "lightftp-gcov-path-max-stream-close-v5":
        # v5 authorizes the protocol-close exception through the recorded
        # reproducible-build record and behavioral probe: verify the archived
        # artifacts by hash and require both records' verified shape against
        # this source identity.
        probe = policy.get("overlong_probe") or {}
        build = policy.get("build_record") or {}
        probe_dir = Path(artifact_root) / "overlong-close-probe" if artifact_root else None
        artifacts_ok = False
        if probe_dir is not None and probe_dir.is_dir():
            ledger_path = probe_dir / str(probe.get("probe_ledger_file") or "")
            log_path = probe_dir / str(probe.get("probe_log_file") or "")
            input_path = probe_dir / "probe-input"
            rebuild_log = probe_dir / str(build.get("rebuild_log_file") or "")
            artifacts_ok = bool(
                probe.get("verified") is True and
                probe.get("minimum_bytes") == command_buffer_size - 1 and
                build.get("verified") is True and
                build.get("binary_sha256") == digest_file(binary) and
                build.get("disassembly_identical") is True and
                isinstance(build.get("objects_unexpected_difference"), list) and
                not build["objects_unexpected_difference"] and
                input_path.is_file() and
                probe.get("probe_input_sha256") == digest_file(input_path) and
                ledger_path.is_file() and
                probe.get("probe_ledger_sha256") == digest_file(ledger_path) and
                log_path.is_file() and
                probe.get("probe_log_sha256") == digest_file(log_path) and
                rebuild_log.is_file() and
                isinstance(build.get("rebuild_log_sha256"), str) and
                build["rebuild_log_sha256"] == digest_file(rebuild_log))
        return bool(policy.get("verified") is True and
                    policy.get("exception_enabled") is True and
                    policy.get("source_binary_build_association") ==
                    "reproducible-rebuild-and-behavioral-probe" and
                    structure and identity and artifacts_ok)
    # This verifier validates the recorded disabled-policy identity. It does
    # not enable the close exception: that requires a separately auditable
    # source-to-binary build association, which the current image does not
    # provide.
    return bool(policy and policy.get("name") == "lightftp-gcov-path-max-stream-close-v4" and
                policy.get("verified") is False and
                policy.get("exception_enabled") is False and
                policy.get("source_binary_build_association") == "not-established" and
                identity and structure)


def replay_policy_verified_for_completeness(target, policy, source_root, object_root):
    """Require a verified policy, or a verified disabled LightFTP policy."""
    if policy is None or policy.get("verified") is True:
        return True
    return (target == "lightftp" and
            verify_lightftp_replay_policy(policy, source_root, object_root))


def bftpd_protocol_end_expected(replay, ledger, final_reply, reset, policy_version=1):
    """A fully evidenced 221 after BFTPD executes QUIT can close replay early.

    V1 requires an exact trailing QUIT frame. V2 follows BFTPD's command
    parser over the sent TCP prefix. V3 additionally recognizes a final
    ECONNRESET when BFTPD sends 221 and closes with unread fuzzed bytes.
    Unexplained resets, timeouts and non-221 replies remain incomplete.
    V5 widens the final-reply restriction to any complete 2xx success: every
    exit(0) path runs end_child(), which close(2)s stdin/out/err without
    shutdown(), so unread pipelined bytes turn ANY bftpd normal-exit close
    into an RST — observed 2026-11-21 after "226 Directory list has been
    submitted." (q1c id:000376); 4xx/5xx finals stay incomplete.
    """
    reply_ok = final_reply == 221 or (
        policy_version >= 5 and isinstance(final_reply, int) and
        200 <= final_reply <= 299)
    return bool(replay.get("server_exit_code") == 0 and
                replay.get("client_exit_code") == 2 and
                replay.get("server_ready") is True and
                replay.get("client_timed_out") is False and
                not replay.get("harness_shutdown_requested") and
                reset.get("command_succeeded") is True and reset.get("exit_code") == 0 and
                replay.get("imported_gcda") and
                not replay.get("session_coverage_missing") and reply_ok and
                ledger and ledger.get("prefix_sent_complete") and
                isinstance(ledger.get("frames_unattempted"), int) and
                ledger.get("frames_attempted", 0) > 0 and
                ledger.get("sent_prefix_has_bftpd_quit" if policy_version >= 2
                           else "last_attempted_frame_is_quit") is True and
                ledger.get("frames_unattempted") > 0 and
                ((ledger.get("peer_closed") and ledger.get("stop_reason") in
                  ("peer-closed-before-input-end", "peer-closed-before-frame")) or
                 (policy_version >= 4 and
                  ledger.get("stop_reason") == "protocol-close-after-quit" and
                  ledger.get("peer_closed") is True and
                  ledger.get("sent_prefix_has_bftpd_quit" if policy_version >= 2
                             else "last_attempted_frame_is_quit") is True and
                  ledger.get("last_attempted_post_recv_ok") is True) or
                 (policy_version >= 3 and not ledger.get("peer_closed") and
                  ledger.get("stop_reason") == "client-recv-post-send-failed" and
                  ledger.get("prior_post_recv_ok") is True and
                  ledger.get("last_attempted_post_recv_ok") is False and
                  ledger.get("last_attempted_post_recv_errno") == errno.ECONNRESET)))


def verify_bftpd_replay_evidence(replay, reset, directory, index, input_path,
                                 expected_input_sha256, input_filename,
                                 legacy_classification=False,
                                 legacy_reply_classification=False,
                                 policy_version=1):
    """Re-derive BFTPD classification from hashes, input bytes, and raw logs."""
    directory = Path(directory)
    input_path = Path(input_path)
    try:
        input_bytes = input_path.read_bytes()
    except OSError as error:
        raise CoverageError("BFTPD replay input is unavailable: " + str(input_path)) from error
    actual_input_sha256 = digest_bytes(input_bytes)
    if (not isinstance(expected_input_sha256, str) or
            actual_input_sha256 != expected_input_sha256):
        raise CoverageError("BFTPD replay input hash mismatch: " + str(input_path))
    for value, stem, file_key, hash_key in (
            (replay, "replay-%06d.log" % index, "replay_log_file", "replay_log_sha256"),
            (reset, "reset-%06d.log" % index, "log_file", "log_sha256"),
            (replay, "replay-%06d-frame-ledger.jsonl" % index,
             "frame_ledger_file", "frame_ledger_sha256")):
        path = directory / stem
        if (value.get(file_key) != stem or not path.is_file() or
                value.get(hash_key) != digest_file(path)):
            raise CoverageError("BFTPD replay evidence mismatch: " + stem)
    ledger_path = directory / replay["frame_ledger_file"]
    ledger = read_frame_ledger(ledger_path, input_bytes)
    with ledger_path.open() as source:
        first_row = json.loads(next(source))
    if (first_row.get("input_file") != input_filename or
            first_row.get("input_size") != len(input_bytes) or
            first_row.get("protocol") != "FTP"):
        raise CoverageError("BFTPD frame ledger input identity mismatch")
    final_reply = bftpd_final_reply_code(directory / replay["replay_log_file"])
    protocol_end = bftpd_protocol_end_expected(
        replay, ledger, final_reply, reset, policy_version=policy_version)
    flags = classify_replay_exit(replay.get("server_exit_code"), replay.get("client_exit_code"))
    if replay.get("harness_shutdown_requested") and replay.get("server_exit_code") == -signal.SIGTERM:
        flags = classify_replay_exit(124, replay.get("client_exit_code"))
    if protocol_end:
        flags.update(replay_anomaly=False, anomaly_kind="")
    expected = dict(replay, **flags)
    expected.update(final_ftp_reply_code=final_reply,
                    bftpd_protocol_end_expected=protocol_end,
                    frames_total=ledger["frames_total"],
                    frames_unattempted=ledger["frames_unattempted"],
                    frames_attempted=ledger["frames_attempted"],
                    frames_sent_complete=ledger["frames_sent_complete"],
                    last_attempted_frame_is_quit=ledger["last_attempted_frame_is_quit"],
                    send_stop_reason=ledger["stop_reason"],
                    send_completeness="complete" if ledger["send_complete"] else "incomplete")
    if policy_version >= 2:
        expected["sent_prefix_has_bftpd_quit"] = ledger["sent_prefix_has_bftpd_quit"]
    if policy_version >= 3:
        expected["last_attempted_post_recv_errno"] = ledger["last_attempted_post_recv_errno"]
    expected["incomplete_reasons"] = replay_incompleteness(expected)
    expected["coverage_complete"] = not expected["incomplete_reasons"]
    physical_fields = ("server_crashed", "client_aborted_on_crash", "server_anomalous_exit",
                       "client_anomalous_exit", "frames_total",
                       "frames_unattempted", "frames_attempted", "frames_sent_complete",
                       "send_stop_reason", "send_completeness")
    classification_fields = ("final_ftp_reply_code", "replay_anomaly", "anomaly_kind",
                             "bftpd_protocol_end_expected", "last_attempted_frame_is_quit", "incomplete_reasons",
                             "coverage_complete")
    if policy_version >= 2:
        classification_fields += ("sent_prefix_has_bftpd_quit",)
        if legacy_classification or legacy_reply_classification:
            raise CoverageError("BFTPD v2+ archive cannot use legacy classification")
    if policy_version >= 3:
        physical_fields += ("last_attempted_post_recv_errno",)
    if legacy_classification:
        # Validate the archived classification against its actual predecessor
        # rules before applying the stricter last-sent-frame and terminal-221
        # parsing rules. This permits only the known version transition and
        # still rejects arbitrary edits to present legacy fields.
        legacy_reply = bftpd_final_reply_code(
            directory / replay["replay_log_file"], allow_terminal_fallback=False)
        legacy_ledger = dict(ledger, last_attempted_frame_is_quit=True)
        legacy_protocol_end = bftpd_protocol_end_expected(
            replay, legacy_ledger, legacy_reply, reset)
        legacy_flags = classify_replay_exit(
            replay.get("server_exit_code"), replay.get("client_exit_code"))
        if (replay.get("harness_shutdown_requested") and
                replay.get("server_exit_code") == -signal.SIGTERM):
            legacy_flags = classify_replay_exit(124, replay.get("client_exit_code"))
        if legacy_protocol_end:
            legacy_flags.update(replay_anomaly=False, anomaly_kind="")
        legacy_expected = dict(replay, **legacy_flags)
        legacy_expected.update(final_ftp_reply_code=legacy_reply,
                              bftpd_protocol_end_expected=legacy_protocol_end)
        legacy_expected["incomplete_reasons"] = replay_incompleteness(legacy_expected)
        legacy_expected["coverage_complete"] = not legacy_expected["incomplete_reasons"]
        legacy_fields = ("final_ftp_reply_code", "replay_anomaly", "anomaly_kind",
                         "bftpd_protocol_end_expected", "incomplete_reasons",
                         "coverage_complete")
        if legacy_reply_classification:
            # A known archive writer stored only terminal 221s in this field.
            # The run-wide compatibility gate below verifies that exact
            # transform against every hash-checked replay log; downstream
            # classification still uses the reply parsed from the transcript.
            legacy_fields = tuple(field for field in legacy_fields
                                  if field != "final_ftp_reply_code")
        for field in legacy_fields:
            if field not in replay or replay.get(field) != legacy_expected[field]:
                raise CoverageError("BFTPD legacy classification mismatch: " + field)
    checked_classification_fields = classification_fields
    if legacy_reply_classification:
        checked_classification_fields = tuple(
            field for field in classification_fields
            if field != "final_ftp_reply_code")
    for field in physical_fields + (() if legacy_classification else checked_classification_fields):
        if field not in replay or replay.get(field) != expected[field]:
            raise CoverageError("BFTPD replay classification mismatch: " + field)
    expected["legacy_classification_recomputed"] = bool(legacy_classification)
    expected["classification_fields_changed"] = [
        field for field in classification_fields
        if field in replay and replay.get(field) != expected[field]]
    return expected


def bftpd_legacy_221_only_reply_classification(events, directory):
    """Recognize the archived BFTPD rule that cached only terminal 221s.

    This compatibility is run-wide and exact: every cached value must equal
    221 when the current transcript parser finds 221, and null for every
    other parsed or unparseable reply. At least one non-221 parsed reply must
    demonstrate the old transform, preventing current archives from entering
    the compatibility path accidentally.
    """
    directory = Path(directory)
    saw_non_221_transition = False
    if not events:
        return False
    for index, event in enumerate(events, 1):
        replay = event.get("replay", {})
        stem = "replay-%06d.log" % index
        path = directory / stem
        if (replay.get("replay_log_file") != stem or not path.is_file() or
                replay.get("replay_log_sha256") != digest_file(path)):
            return False
        parsed_reply = bftpd_final_reply_code(path)
        archived_reply = replay.get("final_ftp_reply_code")
        old_reply = 221 if parsed_reply == 221 else None
        if archived_reply != old_reply:
            return False
        if parsed_reply is not None and parsed_reply != 221:
            saw_non_221_transition = True
    return saw_non_221_transition


def verify_bftpd_replay_events(events, replay_plan, directory, replay_input_root=None,
                               policy_version=1):
    """Audit BFTPD evidence, reclassifying uniform pre-frame-quit archives."""
    if len(replay_plan) != len(events):
        raise CoverageError(
            "BFTPD protocol audit requires replay-plan.json matching replay evidence")
    missing_quit_field = [
        "last_attempted_frame_is_quit" not in event.get("replay", {})
        for event in events]
    if any(missing_quit_field) and not all(missing_quit_field):
        raise CoverageError("BFTPD replay classification mixes legacy and current frame evidence")
    legacy_classification = bool(missing_quit_field and all(missing_quit_field))
    legacy_reply_classification = (bftpd_legacy_221_only_reply_classification(
        events, directory) if policy_version == 1 else False)
    if policy_version >= 2 and legacy_classification:
        raise CoverageError("BFTPD v2+ archive lacks frame classification")
    root = Path(replay_input_root) if replay_input_root is not None else None
    verified_events = []
    reclassified_inputs = 0
    for index, (event, planned) in enumerate(zip(events, replay_plan), 1):
        planned_path = planned.get("path")
        filename = planned.get("filename")
        input_hash = planned.get("input_sha256")
        if not isinstance(planned_path, str) or not planned_path:
            raise CoverageError("BFTPD replay plan lacks an input path at index %d" % index)
        if (not isinstance(filename, str) or not filename or
                Path(planned_path).name != filename):
            raise CoverageError("BFTPD replay plan input filename mismatch at index %d" % index)
        if (event.get("filename") != filename or event.get("input_sha256") != input_hash or
                ("path" in event and event.get("path") != planned_path)):
            raise CoverageError("BFTPD replay event disagrees with replay plan at index %d" % index)
        input_path = Path(planned_path)
        if not input_path.is_file():
            if root is None:
                raise CoverageError("BFTPD archived input path is unavailable; pass --replay-input-root")
            input_path = root / filename
            try:
                input_path.resolve().relative_to(root.resolve())
            except ValueError as error:
                raise CoverageError("BFTPD replay input escapes replay input root") from error
        replay = event.get("replay", {})
        command = replay.get("client_command")
        if (not isinstance(command, list) or len(command) < 2 or
                command[1] != planned_path):
            raise CoverageError("BFTPD replay client command disagrees with replay plan at index %d" % index)
        derived = verify_bftpd_replay_evidence(
            replay, event.get("reset", {}), directory, index, input_path,
            input_hash, filename, legacy_classification=legacy_classification,
            legacy_reply_classification=legacy_reply_classification,
            policy_version=policy_version)
        reclassified_inputs += any(
            field != "last_attempted_frame_is_quit"
            for field in derived["classification_fields_changed"])
        verified_event = dict(event)
        verified_event["replay"] = derived
        verified_events.append(verified_event)
    return dict(events=verified_events, legacy_reclassification=legacy_classification,
                legacy_reply_classification=legacy_reply_classification,
                n_inputs=len(events), n_reclassified_inputs=reclassified_inputs,
                n_incomplete_inputs=sum(bool(e["replay"]["incomplete_reasons"])
                                        for e in verified_events),
                n_complete_inputs=sum(not e["replay"]["incomplete_reasons"]
                                      for e in verified_events))
    for index, event in enumerate(events, 1):
        planned_path = replay_plan[index - 1].get("path")
        if not isinstance(planned_path, str) or not planned_path:
            raise CoverageError("BFTPD replay plan lacks an input path at index %d" % index)
        verify_bftpd_replay_evidence(event.get("replay", {}), event.get("reset", {}),
                                     directory, index, planned_path)


def protocol_end_expected(target, replay, reset, ledger, replay_log, policy_version=4,
                          replay_policy=None):
    """Accept only a proven target-initiated protocol control close."""
    targets = (("lightftp", "pure-ftpd", "forked-daapd", "lighttpd1", "exim", "proftpd")
               if policy_version >= 8 else
               ("lightftp", "pure-ftpd", "forked-daapd", "lighttpd1", "exim")
               if policy_version >= 5 else
               ("lightftp", "pure-ftpd", "forked-daapd", "lighttpd1"))
    if target not in targets:
        return False
    server_code = replay.get("server_exit_code")
    if policy_version >= 5 and target == "pure-ftpd":
        # Pure-FTPd's die() encodes its syslog priority into the exit code
        # via _EXIT(-priority - 1): 252=LOG_ERR, 251=LOG_WARNING,
        # 250=LOG_NOTICE, 249=LOG_INFO. The audited 251/252 pair was the
        # observed subset; the whole family is the same die() policy path
        # (2026-11-20: a deterministic unknown-command session closed FIN
        # with a complete 500 reply and exited 249).
        die_exits = (251, 252) if policy_version < 12 else (249, 250, 251, 252)
        normal_exit = server_code == 0 or server_code in die_exits
    else:
        normal_exit = server_code == 0
    stopped_at_close = bool(ledger and (
        (ledger.get("peer_closed") and ledger.get("stop_reason") in
         ("peer-closed-before-input-end", "peer-closed-before-frame")) or
        (policy_version >= 5 and
         ledger.get("stop_reason") == "client-recv-post-send-failed" and
         ledger.get("peer_closed") is False and
         ledger.get("prior_post_recv_ok") and
         ledger.get("last_attempted_post_recv_ok") is False and
         ledger.get("last_attempted_post_recv_errno") == errno.ECONNRESET) or
        (policy_version >= 11 and
         # The same policy reset landing between frames fails the NEXT
         # frame's pre-recv instead; the evidence lives in the never-sent
         # frame's row (reproduced 2026-11-20, id:000259 v11b). The last
         # sent frame's own post-recv must have returned cleanly, else the
         # stop would have classified as the post-send variant.
         ledger.get("stop_reason") == "client-recv-pre-send-failed" and
         ledger.get("peer_closed") is False and
         ledger.get("prior_post_recv_ok") and
         ledger.get("last_attempted_post_recv_ok") is True and
         ledger.get("next_unattempted_pre_recv_errno") == errno.ECONNRESET) or
        (policy_version >= 6 and
         ledger.get("stop_reason") == "protocol-close-after-quit" and
         ledger.get("peer_closed") is True and
         (ledger.get("last_attempted_frame_is_quit") or
          (target == "lightftp" and policy_version >= 12 and
           # LightFTP extracts the command name after skipping non-alpha
           # bytes, so garbage glued before a bare QUIT still closes.
           isinstance(ledger.get("sent_payloads"), list) and
           lightftp_command_line_extracts_quit(ledger["sent_payloads"]))) and
         ledger.get("last_attempted_post_recv_ok") is True)))
    if not (normal_exit and
            replay.get("client_exit_code") == 2 and
            replay.get("server_ready") is True and
            replay.get("client_timed_out") is False and
            replay.get("helper_ready") is not False and
            reset.get("command_succeeded") is True and reset.get("exit_code") == 0 and
            (not replay.get("session_coverage_missing") or
             # ProFTPD's cross-protocol guard tears the session down through
             # pr_session_end, whose non-DEVEL build _exit()s and thereby
             # skips the gcov atexit flush: zero touched gcda is the
             # documented artifact of that policy, not a flush failure
             # (src/session.c pr_session_end; Bug#4143, observed 2026-11-21).
             (policy_version >= 12 and target == "proftpd" and
              proftpd_cross_protocol_close_expected(
                  replay, reset, ledger, replay.get("server_log_witness")))) and
            ledger and ledger.get("prefix_sent_complete") and
            isinstance(ledger.get("frames_unattempted"), int) and
            ledger["frames_unattempted"] > 0 and stopped_at_close):
        return False
    if policy_version >= 5:
        if target == "pure-ftpd":
            reply = pureftpd_final_reply_code(replay_log)
            return bool(replay.get("imported_gcda") and
                        reply in (221, 421) and
                        (server_code == 0 or reply == 421)) or \
                bool(policy_version >= 12 and
                     # die() exits with the priority-encoded code; the final
                     # reply is whatever die() emitted — a complete error
                     # reply plus FIN (observed: 500 unknown-command, 530
                     # auth-denied), so restrict to 4xx/5xx finals.
                     server_code in (249, 250, 251, 252) and
                     reply is not None and 400 <= reply <= 599 and
                     replay.get("imported_gcda"))
        if not replay.get("session_gcda_touched") and not (
                # ProFTPD's cross-protocol teardown _exit()s past the gcov
                # flush (src/session.c pr_session_end; Bug#4143): zero gcda
                # is the expected artifact of that policy close.
                policy_version >= 12 and target == "proftpd" and
                proftpd_cross_protocol_close_expected(
                    replay, reset, ledger, replay.get("server_log_witness"))):
            return False
        if target == "lightftp":
            return (lightftp_final_reply_code(replay_log) in (221, 421) or
                    (policy_version >= 6 and lightftp_oversized_command_close_expected(
                        replay, reset, ledger, replay_policy)))
        if target == "exim":
            return smtp_final_close_reply(
                replay_log, trailing_noise_ok=policy_version >= 12) is not None or \
                bool(policy_version >= 12 and
                     exim_error_limit_close_expected(replay, reset, ledger,
                                                     replay_log))
        if target == "proftpd":
            return bool(not replay.get("harness_shutdown_requested") and
                        ledger.get("last_attempted_frame_is_quit") and
                        pureftpd_final_reply_code(replay_log) == 221) or \
                bool(policy_version >= 11 and
                     proftpd_overlong_close_expected(replay, reset, ledger,
                                                     replay_policy)) or \
                bool(policy_version >= 12 and
                     proftpd_cross_protocol_close_expected(
                         replay, reset, ledger,
                         replay.get("server_log_witness")))
        return http_final_close_response_complete(replay_log, ledger.get("sent_payloads")) or \
            bool(policy_version >= 12 and
                 # v12: the server itself announced the close in the final
                 # response (Connection: close, length-complete), e.g. lighttpd
                 # after a 200/404/501; the ledger already proved the FIN and
                 # the outer gates proved the prefix, process, and reset
                 # evidence (2026-11-20: 110 lighttpd1 inputs).
                 http_response_announced_close_complete(replay_log))
    if target == "pure-ftpd":
        return bool(replay.get("imported_gcda") and
                    ledger.get("last_attempted_frame_is_quit") and
                    pureftpd_final_reply_code(replay_log) == 221)
    if not replay.get("session_gcda_touched"):
        return False
    if target == "lightftp":
        return bool(ledger.get("last_attempted_frame_is_quit") and
                    lightftp_final_reply_code(replay_log) == 221)
    return bool(ledger.get("last_attempted_frame_is_http_close") and
                http_close_response_complete(replay_log))


def exim_error_limit_close_expected(replay, reset, ledger, replay_log):
    """Exim drops the session after syntax/protocol errors pile up.

    src/smtp_in.c:2734 (and the BDAT path :3872) sets yield=1 once
    ++synprot_error_count exceeds smtp_max_synprot_errors — globals.c:1517
    defaults it to 3 — so a session that keeps offending is dropped, and
    the drop can cut the in-flight reply. The observable contract: the
    connection FINs mid-input, the FINAL complete reply is a 4xx/5xx, and
    the session accumulated more than the limit's worth of error replies
    (the counter resets on some valid commands, so the trailing visible
    run can be shorter than the limit; the total is the robust witness).
    The state sequence line is one atomic write (v12 replayer), so trailing
    noise from the daemon's debug stream cannot corrupt it. """
    ledger = ledger or {}
    if ledger.get("stop_reason") not in ("peer-closed-before-input-end",
                                         "peer-closed-before-frame") or \
            ledger.get("peer_closed") is not True:
        return False
    try:
        raw = Path(replay_log).read_bytes()
    except OSError:
        return False
    sequence = re.search(rb"(?m)^Responses from server:0((?:-[0-9]{3})+)-", raw)
    if not sequence:
        return False
    codes = [int(code) for code in re.findall(rb"-([0-9]{3})", sequence.group(1))]
    errors = [code for code in codes if 400 <= code <= 599]
    if not codes or not (400 <= codes[-1] <= 599) or len(errors) < 4:
        return False
    return bool(replay.get("server_exit_code") == 0 and
                replay.get("client_exit_code") == 2 and
                replay.get("server_ready") is True and
                replay.get("client_timed_out") is False and
                not replay.get("session_coverage_missing") and
                bool(replay.get("session_gcda_touched")) and
                reset.get("command_succeeded") is True and reset.get("exit_code") == 0 and
                ledger.get("prefix_sent_complete") and
                isinstance(ledger.get("frames_unattempted"), int) and
                ledger["frames_unattempted"] > 0 and
                ledger.get("prior_post_recv_ok") is True)


def verify_target_frame_replay(event, planned, directory, index, target,
                               replay_input_root=None, gcno=None,
                               protocol_end_required=False, policy_version=4,
                               replay_policy=None):
    """Recompute a non-BFTPD input's send evidence from its archived bytes."""
    replay, reset = event.get("replay", {}), event.get("reset", {})
    filename, planned_path = planned.get("filename"), planned.get("path")
    if (not isinstance(filename, str) or not isinstance(planned_path, str) or
            Path(planned_path).name != filename or event.get("filename") != filename or
            event.get("input_sha256") != planned.get("input_sha256") or
            ("path" in event and event.get("path") != planned_path)):
        raise CoverageError("replay plan/input identity mismatch at input %d" % index)
    input_path = Path(planned_path)
    if not input_path.is_file():
        if replay_input_root is None:
            raise CoverageError("replay input unavailable; pass --replay-input-root")
        root = Path(replay_input_root).resolve()
        input_path = (root / filename).resolve()
        try:
            input_path.relative_to(root)
        except ValueError as error:
            raise CoverageError("replay input escapes replay input root") from error
    if not input_path.is_file() or digest_file(input_path) != planned.get("input_sha256"):
        raise CoverageError("replay input hash mismatch at input %d" % index)
    command = replay.get("client_command")
    if (not isinstance(command, list) or len(command) != 7 or
            command[1:3] != [planned_path, TARGET_PROTOCOLS[target]] or
            not isinstance(command[3], str) or not command[3].isdigit() or
            command[4:] != ["0", "100", "10000"]):
        raise CoverageError("replay client ABI mismatch at input %d" % index)
    directory = Path(directory)
    for record, stem, name_key, hash_key in (
            (replay, "replay-%06d.log" % index, "replay_log_file", "replay_log_sha256"),
            (replay, "replay-%06d-frame-ledger.jsonl" % index,
             "frame_ledger_file", "frame_ledger_sha256"),
            (reset, "reset-%06d.log" % index, "log_file", "log_sha256")):
        path = directory / stem
        if (record.get(name_key) != stem or not path.is_file() or
                record.get(hash_key) != digest_file(path)):
            raise CoverageError("replay evidence mismatch: " + stem)
    server_log_path = directory / ("replay-%06d-server.log" % index)
    server_log_witness = None
    if replay.get("server_log_file"):
        if (replay.get("server_log_file") != server_log_path.name or
                not server_log_path.is_file() or
                replay.get("server_log_sha256") != digest_file(server_log_path)):
            raise CoverageError("replay evidence mismatch: " + server_log_path.name)
        server_log_witness = server_log_path
    ledger_path = directory / replay["frame_ledger_file"]
    ledger = read_frame_ledger(ledger_path, input_path.read_bytes())
    with ledger_path.open() as source:
        begin = json.loads(next(source))
    if (begin.get("input_file") != filename or
            begin.get("input_size") != input_path.stat().st_size or
            begin.get("protocol") != TARGET_PROTOCOLS[target]):
        raise CoverageError("frame ledger input identity mismatch at input %d" % index)
    expected = dict(frames_total=ledger["frames_total"],
                    frames_unattempted=ledger["frames_unattempted"],
                    frames_attempted=ledger["frames_attempted"],
                    frames_sent_complete=ledger["frames_sent_complete"],
                    send_stop_reason=ledger["stop_reason"],
                    send_completeness="complete" if ledger["send_complete"] else "incomplete")
    for field, value in expected.items():
        if replay.get(field) != value:
            raise CoverageError("frame ledger classification mismatch at input %d: %s" %
                                (index, field))
    if protocol_end_required and target in (("lightftp", "pure-ftpd", "forked-daapd", "lighttpd1", "exim", "proftpd")
                                                if policy_version >= 8 else
                                                ("lightftp", "pure-ftpd", "forked-daapd", "lighttpd1", "exim")
                                                if policy_version >= 5 else
                                                ("lightftp", "pure-ftpd", "forked-daapd", "lighttpd1")):
        ended = protocol_end_expected(target, dict(replay,
                                                   server_log_witness=server_log_witness),
                                      reset, ledger,
                                      directory / replay["replay_log_file"], policy_version,
                                      replay_policy)
        if (replay.get("protocol_end_expected") is not ended or
                (target in ("lightftp", "pure-ftpd", "forked-daapd", "lighttpd1") and
                 replay.get("last_attempted_frame_is_http_close") is not
                 ledger["last_attempted_frame_is_http_close"])):
            raise CoverageError("protocol end evidence mismatch at input %d" % index)
        if ended:
            flags = classify_replay_exit(replay.get("server_exit_code"),
                                         replay.get("client_exit_code"))
            if (replay.get("server_crashed") is not flags["server_crashed"] or
                    replay.get("client_anomalous_exit") is not flags["client_anomalous_exit"] or
                    replay.get("replay_anomaly") is not False or
                    replay.get("anomaly_kind") != ""):
                raise CoverageError("protocol end classification mismatch at input %d" % index)
    if gcno is not None and target in ACCUMULATING_GCDA_TARGETS:
        touched = replay.get("session_gcda_touched")
        allowed = {str(Path(name).with_suffix(".gcda")) for name in gcno}
        if (not isinstance(touched, list) or
                any(not isinstance(name, str) for name in touched) or
                len(touched) != len(set(touched)) or
                not set(touched).issubset(allowed) or
                replay.get("session_coverage_missing") is not (not bool(touched))):
            raise CoverageError("session gcda freshness evidence mismatch at input %d" % index)
    if replay.get("incomplete_reasons") != replay_incompleteness(replay):
        raise CoverageError("replay incomplete reasons mismatch at input %d" % index)
    if replay.get("coverage_complete") is not (not replay["incomplete_reasons"]):
        raise CoverageError("replay completeness mismatch at input %d" % index)


def apply_proftpd_shutdown_exit_policy(flags, server_code, client_code, supervised,
                                       reset_succeeded, frames_expected=None,
                                       packets_sent=None, ledger_send_complete=None,
                                       session_gcda_touched=None):
    """Accept harness-initiated ProFTPD shutdowns whose gcov listener dies by
    SIGSEGV inside the graceful-shutdown teardown.

    The supervised harness sends SIGTERM (ProFTPD's graceful shutdown signal)
    only after the replay client completed all frames. The gcov-instrumented
    listener's signal-handler re-raise can segfault during that teardown and
    surface exit code -11 instead of -15; the observed 2026-11-15 rerun set
    had 62/62 flagged inputs in exactly this shape (harness SIGTERM, client
    exit 0, ready, no timeout, reset OK) with benign USER/PASS/SYST content
    whose identical corpus copies replayed clean elsewhere. The v3 acceptance
    additionally requires transcript frame completeness (packets sent equals
    the framed input's frame count): the replay client can exit 0 after a
    partial send, so the client exit code alone is not send evidence.
    Unrequested signals (real mid-session crashes), client failures, failed
    resets, and partial sends remain anomalies.
    """
    evidence = dict(server_exit_code=server_code, client_exit_code=client_code,
                    server_ready=bool(supervised.get("server_ready")),
                    client_timed_out=bool(supervised.get("client_timed_out")),
                    harness_shutdown_requested=bool(supervised.get("harness_shutdown_requested")),
                    harness_shutdown_signal=supervised.get("harness_shutdown_signal"),
                    reset_command_succeeded=bool(reset_succeeded),
                    frames_expected=frames_expected, packets_sent=packets_sent,
                    ledger_send_complete=ledger_send_complete,
                    session_gcda_touched=sorted(session_gcda_touched or []))
    accepted = (server_code == -signal.SIGSEGV and
                supervised.get("harness_shutdown_requested") is True and
                supervised.get("harness_shutdown_signal") == "SIGTERM" and
                client_code == 0 and
                supervised.get("server_ready") is True and
                supervised.get("client_timed_out") is False and
                reset_succeeded is True and
                frames_expected is not None and packets_sent == frames_expected and
                ledger_send_complete is True and
                bool(session_gcda_touched) and
                flags.get("anomaly_kind") == "server-crash-finding")
    result = dict(flags)
    result["proftpd_shutdown_exit_expected"] = bool(accepted)
    result["proftpd_shutdown_exit_evidence"] = evidence
    if accepted:
        result.update(server_crashed=False, server_anomalous_exit=False,
                      client_anomalous_exit=False, client_aborted_on_crash=False,
                      replay_anomaly=False, anomaly_kind="")
    return result


def verify_pureftpd_replay_evidence(replay, reset, artifact_dir, index,
                                   instrumented_objects=None):
    """Recompute Pure-FTPd replay classification from immutable log evidence."""
    errors = []
    artifact_dir = Path(artifact_dir)
    replay_name = "replay-%06d.log" % index
    reset_name = "reset-%06d.log" % index
    replay_path = artifact_dir / replay_name
    reset_path = artifact_dir / reset_name
    if (replay.get("replay_log_file") != replay_name or not replay_path.is_file() or
            replay.get("replay_log_sha256") != digest_file(replay_path)):
        errors.append("replay-log-hash-mismatch")
    if (reset.get("log_file") != reset_name or not reset_path.is_file() or
            reset.get("log_sha256") != digest_file(reset_path)):
        errors.append("reset-log-hash-mismatch")

    parsed_reply = pureftpd_final_reply_code(replay_path) if replay_path.is_file() else None
    if replay.get("final_ftp_reply_code") != parsed_reply:
        errors.append("final-ftp-reply-disagrees-with-transcript")
    imported = replay.get("imported_gcda")
    if not isinstance(imported, list):
        imported = []
        errors.append("invalid-imported-gcda-list")
    if replay.get("session_coverage_missing") is bool(imported):
        errors.append("session-gcda-status-disagrees-with-import-list")
    if len(imported) != len(set(imported)):
        errors.append("duplicate-imported-gcda-entry")
    if instrumented_objects is not None:
        expected_gcda = {str(Path(name).with_suffix(".gcda"))
                         for name in instrumented_objects}
        if not set(imported).issubset(expected_gcda):
            errors.append("imported-gcda-not-in-pinned-instrumentation")

    server_code, client_code = replay.get("server_exit_code"), replay.get("client_exit_code")
    flags = classify_replay_exit(server_code, client_code)
    if replay.get("harness_shutdown_requested") is True and server_code == -signal.SIGTERM:
        flags = classify_replay_exit(124, client_code)
    reset_succeeded = (isinstance(reset.get("command"), list) and bool(reset["command"]) and
                       reset.get("command_succeeded") is True and
                       reset.get("exit_code") == 0 and
                       "reset-log-hash-mismatch" not in errors)
    expected = apply_pureftpd_session_exit_policy(
        flags, server_code, client_code, replay.get("server_ready"),
        replay.get("client_timed_out"), replay.get("harness_shutdown_requested"),
        parsed_reply, imported, reset_succeeded)
    if "send_completeness" in replay:
        expected["send_completeness"] = replay["send_completeness"]
    if "protocol_end_expected" in replay:
        expected["protocol_end_expected"] = replay["protocol_end_expected"]
        if replay["protocol_end_expected"] is True:
            expected.update(replay_anomaly=False, anomaly_kind="")
    for field in ("server_crashed", "server_anomalous_exit", "client_anomalous_exit",
                  "client_aborted_on_crash", "replay_anomaly", "anomaly_kind",
                  "pureftpd_session_exit_expected", "pureftpd_session_exit_evidence"):
        if replay.get(field) != expected[field]:
            errors.append("replay-classification-mismatch:" + field)
    incomplete_state = dict(expected, session_coverage_missing=not imported,
                            client_timed_out=replay.get("client_timed_out"),
                            server_ready=replay.get("server_ready"),
                            helper_ready=replay.get("helper_ready"))
    expected_incomplete = replay_incompleteness(incomplete_state)
    if replay.get("incomplete_reasons") != expected_incomplete:
        errors.append("incomplete-reasons-mismatch")
    if replay.get("coverage_complete") is not (not expected_incomplete):
        errors.append("coverage-complete-flag-mismatch")
    return sorted(set(errors))


def verify_proftpd_replay_evidence(replay, reset, artifact_dir, index, require_frames=False):
    """Recompute ProFTPD replay classification from immutable log evidence."""
    errors = []
    artifact_dir = Path(artifact_dir)
    replay_name = "replay-%06d.log" % index
    reset_name = "reset-%06d.log" % index
    replay_path = artifact_dir / replay_name
    reset_path = artifact_dir / reset_name
    if (replay.get("replay_log_file") != replay_name or not replay_path.is_file() or
            replay.get("replay_log_sha256") != digest_file(replay_path)):
        errors.append("replay-log-hash-mismatch")
    if (reset.get("log_file") != reset_name or not reset_path.is_file() or
            reset.get("log_sha256") != digest_file(reset_path)):
        errors.append("reset-log-hash-mismatch")
    server_code, client_code = replay.get("server_exit_code"), replay.get("client_exit_code")
    supervised = {key: replay.get(key) for key in
                  ("server_ready", "client_timed_out", "harness_shutdown_requested",
                   "harness_shutdown_signal")}
    reset_succeeded = (isinstance(reset.get("command"), list) and bool(reset["command"]) and
                       reset.get("command_succeeded") is True and
                       reset.get("exit_code") == 0 and
                       "reset-log-hash-mismatch" not in errors)
    frames_expected = None
    packets_sent = None
    ledger_send_complete = None
    session_gcda_touched = None
    if require_frames:
        client_command = replay.get("client_command") or []
        if len(client_command) > 1 and isinstance(client_command[1], str):
            frames_expected = framed_input_frames(client_command[1])
        packets_sent = transcript_packets_sent(replay_path)
        ledger_name = replay.get("frame_ledger_file")
        ledger_path = artifact_dir / str(ledger_name or "")
        if (isinstance(ledger_name, str) and ledger_path.is_file() and
                replay.get("frame_ledger_sha256") == digest_file(ledger_path)):
            framed_bytes = None
            if len(client_command) > 1 and isinstance(client_command[1], str):
                try:
                    framed_bytes = Path(client_command[1]).read_bytes()
                except OSError:
                    framed_bytes = None
            try:
                ledger = read_frame_ledger(ledger_path, framed_bytes)
                ledger_send_complete = ledger["send_complete"]
            except CoverageError:
                ledger_send_complete = None
        evidence = replay.get("proftpd_shutdown_exit_evidence") or {}
        touched = evidence.get("session_gcda_touched")
        session_gcda_touched = touched if isinstance(touched, list) else None
    flags = classify_replay_exit(server_code, client_code)
    if (supervised.get("harness_shutdown_requested") is True and
            server_code == -signal.SIGTERM):
        flags = classify_replay_exit(124, client_code)
    expected = apply_proftpd_shutdown_exit_policy(flags, server_code, client_code,
                                                  supervised, reset_succeeded,
                                                  frames_expected=frames_expected,
                                                  packets_sent=packets_sent,
                                                  ledger_send_complete=ledger_send_complete,
                                                  session_gcda_touched=session_gcda_touched)
    if "protocol_end_expected" in replay:
        # The generic frame audit already recomputed and matched this label
        # against the archived ledger before the policy audit runs; mirror
        # its post-acceptance clearing exactly as run_one_replay recorded it.
        expected["protocol_end_expected"] = replay["protocol_end_expected"]
        if replay["protocol_end_expected"] is True:
            expected.update(replay_anomaly=False, anomaly_kind="")
    for field in ("server_crashed", "server_anomalous_exit", "client_anomalous_exit",
                  "client_aborted_on_crash", "replay_anomaly", "anomaly_kind",
                  "proftpd_shutdown_exit_expected", "proftpd_shutdown_exit_evidence"):
        if replay.get(field) != expected[field]:
            errors.append("replay-classification-mismatch:" + field)
    incomplete_state = dict(expected, session_coverage_missing=replay.get("session_coverage_missing"),
                            client_timed_out=replay.get("client_timed_out"),
                            server_ready=replay.get("server_ready"),
                            helper_ready=replay.get("helper_ready"),
                            protocol_end_expected=replay.get("protocol_end_expected"))
    if require_frames:
        # Do not trust the cached completeness label: derive it from the
        # hash-checked frame ledger parsed above. The target-frame audit also
        # checks it against the archived input bytes when available.
        incomplete_state["send_completeness"] = (
            "complete" if ledger_send_complete is True else "incomplete")
    expected_incomplete = replay_incompleteness(incomplete_state)
    if replay.get("incomplete_reasons") != expected_incomplete:
        errors.append("incomplete-reasons-mismatch")
    if replay.get("coverage_complete") is not (not expected_incomplete):
        errors.append("coverage-complete-flag-mismatch")
    return sorted(set(errors))


def pureftpd_policy_audit_report(replay_policy, events):
    inputs = []
    for index, event in enumerate(events, 1):
        replay = event.get("replay", {})
        reset = event.get("reset", {})
        evidence = replay.get("pureftpd_session_exit_evidence", {})
        inputs.append(dict(
            idx=index, filename=event.get("filename"),
            server_exit_code=replay.get("server_exit_code"),
            client_exit_code=replay.get("client_exit_code"),
            server_ready=replay.get("server_ready"),
            client_timed_out=replay.get("client_timed_out"),
            harness_shutdown_requested=replay.get("harness_shutdown_requested"),
            final_ftp_reply_code=replay.get("final_ftp_reply_code"),
            imported_gcda_count=len(replay.get("imported_gcda", [])),
            reset_command_succeeded=reset.get("command_succeeded") is True,
            expected_session_exit=replay.get("pureftpd_session_exit_expected") is True,
            anomaly_kind=replay.get("anomaly_kind"),
            incomplete_reasons=replay.get("incomplete_reasons", []),
            policy_evidence=evidence))
    accepted = sum(row["expected_session_exit"] for row in inputs)
    return dict(schema_version="pureftpd-session-exit-audit-v1",
                policy_name=replay_policy.get("name"),
                policy_verified=replay_policy.get("verified") is True,
                verified_scope=replay_policy.get("verified_scope"),
                source_sha256=replay_policy.get("source_sha256"),
                binary_sha256=replay_policy.get("binary_sha256"),
                source_binary_build_association=
                    replay_policy.get("source_binary_build_association", "not-verified"),
                n_inputs=len(inputs), n_expected_session_exits=accepted,
                n_other_inputs=len(inputs) - accepted, inputs=inputs)


def proftpd_policy_audit_report(replay_policy, events):
    inputs = []
    for index, event in enumerate(events, 1):
        replay = event.get("replay", {})
        reset = event.get("reset", {})
        evidence = replay.get("proftpd_shutdown_exit_evidence", {})
        inputs.append(dict(
            idx=index, filename=event.get("filename"),
            server_exit_code=replay.get("server_exit_code"),
            client_exit_code=replay.get("client_exit_code"),
            server_ready=replay.get("server_ready"),
            client_timed_out=replay.get("client_timed_out"),
            harness_shutdown_requested=replay.get("harness_shutdown_requested"),
            harness_shutdown_signal=replay.get("harness_shutdown_signal"),
            reset_command_succeeded=reset.get("command_succeeded") is True,
            expected_shutdown_exit=replay.get("proftpd_shutdown_exit_expected") is True,
            anomaly_kind=replay.get("anomaly_kind"),
            incomplete_reasons=replay.get("incomplete_reasons", []),
            policy_evidence=evidence))
    accepted = sum(row["expected_shutdown_exit"] for row in inputs)
    return dict(schema_version="proftpd-shutdown-exit-audit-v1",
                policy_name=replay_policy.get("name"),
                policy_verified=replay_policy.get("verified") is True,
                verified_scope=replay_policy.get("verified_scope"),
                n_inputs=len(inputs), n_expected_shutdown_exits=accepted,
                n_other_inputs=len(inputs) - accepted, inputs=inputs)


def load_coordinates(path):
    if not Path(path).exists():
        return {}
    result, campaign = {}, None
    with Path(path).open() as source:
        for number, raw in enumerate(source, 1):
            if not raw.strip():
                continue
            record = json.loads(raw)
            if "schema_version" not in record:
                raise CoverageError("queue checkpoint lacks schema_version")
            filename = record.get("filename")
            if not filename or Path(filename).name != filename:
                raise CoverageError("checkpoint filename must be a basename at line " + str(number))
            current = record.get("campaign_id")
            if not current or (campaign is not None and campaign != current):
                raise CoverageError("queue ledger has missing/mixed campaign identity")
            campaign = current
            if record.get("kind") == "removal":
                # Provisional-subtree expiry unlinks the corpus files; the
                # ledger stays append-only, so the removal record closes the
                # earlier discovery join instead of leaving a ghost basename.
                if filename not in result:
                    raise CoverageError("removal without a prior checkpoint: " + filename)
                del result[filename]
                continue
            if filename in result:
                raise CoverageError("queue checkpoint join is not unique: " + filename)
            for field in ("queue_id", "discovery_time_ms", "monotonic_ms", "discovery_execution_id"):
                nonnegative_integer(record.get(field), field)
            result[filename] = record
    return result


def plan_corpus(folder, mode, coordinates, require_coordinates=False):
    directory = Path(folder) / ("replayable-queue" if mode == 1 else "queue")
    if not directory.is_dir():
        raise CoverageError("missing replay corpus: " + str(directory))
    files = sorted(path for path in directory.iterdir()
                   if path.is_file() and (path.name.startswith("id") or path.suffix == ".raw"))
    if not files:
        raise CoverageError("empty replay corpus")
    empty_files = [path.name for path in files if path.stat().st_size == 0]
    if empty_files:
        raise CoverageError("empty replay input(s): " + ", ".join(empty_files[:10]))
    records, matched_queue_ids = [], set()
    corpus_names = {path.name for path in files}
    # Every corpus file must carry a coordinate; a ledger name WITHOUT a
    # corpus file is legitimate (e.g. imported seeds whose structured replay
    # form was never materialized — replayable copies are written
    # conditionally during the initial dry-run), but it is reported so the
    # audit trail shows exactly what the replay did not cover.
    unreplayable = sorted(set(coordinates) - corpus_names) if coordinates else []
    for path in files:
        record = dict(coordinates.get(path.name, {}))
        if record:
            if record["queue_id"] in matched_queue_ids:
                raise CoverageError("one queue_id maps to multiple corpus files")
            matched_queue_ids.add(record["queue_id"])
        elif require_coordinates:
            raise CoverageError("no unique discovery coordinates for " + path.name)
        record.update(filename=path.name, path=str(path.resolve()), input_sha256=digest_file(path),
                      original_mtime_ns=path.stat().st_mtime_ns,
                      coordinate_source="queue-checkpoints.jsonl" if record else "queue_mtime_unverified")
        if not coordinates:
            record["discovery_time_ms"] = path.stat().st_mtime_ns // 1000000
        records.append(record)
    if coordinates and any(r["coordinate_source"] != "queue-checkpoints.jsonl" for r in records):
        raise CoverageError("partially joined ledger; refusing mixed time coordinates")
    records.sort(key=lambda r: (r["discovery_time_ms"],
                                r.get("monotonic_ms", r["discovery_time_ms"]),
                                r.get("discovery_execution_id", 0),
                                r.get("queue_id", 0), r["filename"]))
    previous = None
    for record in records:
        if previous and coordinates:
            for field in ("discovery_time_ms", "monotonic_ms", "discovery_execution_id"):
                if record[field] < previous[field]:
                    raise CoverageError("nonmonotonic discovery ledger: " + field)
        previous = record
    return records, unreplayable


def validate_initial_seed_prefix(plan):
    seed_indices = [index for index, record in enumerate(plan, 1)
                    if record.get("kind") == "initial-queue-name"]
    if seed_indices and seed_indices != list(range(1, len(seed_indices) + 1)):
        raise CoverageError("initial seed inputs must form a replay-plan prefix")
    return seed_indices


class CoverageUnion:
    def __init__(self, baseline, manifest):
        if baseline.covered_branches or baseline.covered_lines:
            raise CoverageError("baseline is not reset to zero coverage")
        self.baseline, self.manifest = baseline, manifest
        self.schema = manifest.get("schema_version", SCHEMA)
        self.covered, self.covered_lines = set(), set()
        # The gcovr reset report is not a seed baseline when the target has no
        # gcda yet.  Track the branch union of inputs explicitly identified as
        # initial seeds so terminal evidence can subtract a real baseline.
        self.seed_covered, self.seed_covered_lines = set(), set()
        self.seed_events = []
        self.previous_snapshot, self.events, self.previous_coordinates = set(), [], None

    def add(self, snapshot, coordinates, raw_sha256, expected_counter_reset=False,
            is_seed_input=False):
        if (self.manifest.get("zero_baseline_mode") and not self.baseline.branches
                and snapshot.branches):
            # Zero-gcda baseline: the first replayed checkpoint materializes
            # the branch/line universe (gcovr 4.x reports structure only for
            # objects that have gcda).  Coverage counts stay empty, so the
            # zero-baseline invariant is preserved; every later checkpoint
            # must then match the adopted universe exactly.
            self.baseline = Snapshot(set(snapshot.branches), set(), set(snapshot.lines),
                                     set(), dict(snapshot.files), snapshot.format_version,
                                     dict(snapshot.resolution))
            # The first replay materializes the universe for never-executed
            # build trees. Bind the adopted source and branch universe into the
            # pinned scope identity before recording this checkpoint.
            self.manifest["sources"] = snapshot.files
            self.manifest["source_resolution"] = snapshot.resolution
            self.manifest["gcovr_format"] = snapshot.format_version
            self.manifest["branch_ids"] = sorted(
                [list(b) if isinstance(b, (list, tuple)) else b
                 for b in snapshot.branches])
            self.manifest["line_ids"] = sorted(
                [list(l) if isinstance(l, (list, tuple)) else l
                 for l in snapshot.lines])
            seal_scope_manifest(self.manifest)
        for field in ("branches", "lines", "files", "format_version"):
            if getattr(snapshot, field) != getattr(self.baseline, field):
                raise CoverageError("coverage source/branch scope changed: " + field)
        if self.previous_coordinates is not None:
            for field in ("discovery_time_ms", "discovery_execution_id", "monotonic_ms"):
                before, after = self.previous_coordinates.get(field), coordinates.get(field)
                if before is not None and after is not None and after < before:
                    raise CoverageError("nonmonotonic checkpoint: " + field)
        previous_union = set(self.covered)
        self.covered.update(snapshot.covered_branches)
        self.covered_lines.update(snapshot.covered_lines)
        if is_seed_input:
            self.seed_covered.update(snapshot.covered_branches)
            self.seed_covered_lines.update(snapshot.covered_lines)
        dropped = self.previous_snapshot - snapshot.covered_branches
        event = dict(coordinates)
        event["queue_schema_version"] = event.pop("schema_version", None)
        event.update(schema_version=self.schema, idx=len(self.events) + 1,
                     snapshot_sha256=raw_sha256, scope_sha256=self.manifest["scope_sha256"],
                     snapshot_covered_branches=len(snapshot.covered_branches),
                     cumulative_covered_branches=len(self.covered),
                     snapshot_covered_lines=len(snapshot.covered_lines),
                     cumulative_covered_lines=len(self.covered_lines),
                     branch_total=len(self.baseline.branches), line_total=len(self.baseline.lines),
                     newly_covered_branch_ids=sorted(self.covered - previous_union),
                     dropped_snapshot_branch_ids=sorted(dropped),
                     expected_counter_reset=expected_counter_reset,
                     unexpected_nonmonotonic_snapshot=bool(dropped and not expected_counter_reset))
        event["is_seed_input"] = bool(is_seed_input)
        if is_seed_input:
            self.seed_events.append(event["idx"])
        self.events.append(event)
        self.previous_snapshot = set(snapshot.covered_branches)
        self.previous_coordinates = coordinates
        return event

    def csv_row(self, event):
        return dict(Time=event["discovery_time_ms"] / 1000,
                    l_per=100 * event["cumulative_covered_lines"] / event["line_total"],
                    l_abs=event["cumulative_covered_lines"],
                    b_per=100 * event["cumulative_covered_branches"] / event["branch_total"],
                    b_abs=event["cumulative_covered_branches"], idx=event["idx"],
                    discovery_execution_id=event.get("discovery_execution_id"),
                    discovery_monotonic_ms=event.get("monotonic_ms"),
                    campaign_id=event.get("campaign_id"), coordinate_source=event["coordinate_source"],
                    scope_sha256=event["scope_sha256"], snapshot_sha256=event["snapshot_sha256"])


def audit_csv(path, manifest, expected_events=None):
    """Detect aggregate divergence instead of silently taking a maximum."""
    with Path(path).open() as source:
        rows = list(csv.DictReader(source))
    previous_time, previous_branches, previous_lines = None, 0, 0
    if not rows:
        raise CoverageError("coverage CSV is empty")
    for row in rows:
        timestamp, branches, lines = float(row["Time"]), int(row["b_abs"]), int(row["l_abs"])
        if previous_time is not None and timestamp < previous_time:
            raise CoverageError("nonmonotonic CSV timestamp")
        if branches < previous_branches or lines < previous_lines:
            raise CoverageError("nonmonotonic cumulative coverage CSV")
        if row.get("scope_sha256") != manifest["scope_sha256"]:
            raise CoverageError("CSV uses a different scope")
        if not manifest["branch_ids"] or not manifest["line_ids"]:
            raise CoverageError(
                "empty branch/line universe: the zero-gcda adoption path "
                "never materialized a manifest universe (2026-11-07 audit "
                "fix — explicit INCONCLUSIVE-grade error instead of "
                "ZeroDivisionError)")
        bp = 100 * branches / len(manifest["branch_ids"])
        lp = 100 * lines / len(manifest["line_ids"])
        if not 0 <= branches <= len(manifest["branch_ids"]) or not 0 <= lines <= len(manifest["line_ids"]):
            raise CoverageError("aggregate exceeds the fixed branch/line universe")
        if abs(float(row["b_per"]) - bp) > 1e-8 or abs(float(row["l_per"]) - lp) > 1e-8:
            raise CoverageError("percentage disagrees with branch/line identities")
        if expected_events is not None:
            index = int(row["idx"]) - 1
            if not 0 <= index < len(expected_events):
                raise CoverageError("CSV checkpoint index is not a recorded replay")
            event = expected_events[index]
            if (branches != event["cumulative_covered_branches"] or
                    lines != event["cumulative_covered_lines"] or
                    timestamp != event["discovery_time_ms"] / 1000 or
                    row["snapshot_sha256"] != event["snapshot_sha256"] or
                    row.get("discovery_execution_id", "") != str(event.get("discovery_execution_id", ""))):
                raise CoverageError("CSV aggregate/coordinates disagree with checkpoint branch IDs")
        previous_time, previous_branches, previous_lines = timestamp, branches, lines
    return dict(rows=len(rows), terminal_branches=previous_branches, terminal_lines=previous_lines)


def collect_report(source_root, object_root, gcovr="gcovr", delete=False):
    # gcovr 4.x (the version inside the subject images) treats "--output -"
    # as a literal file named "-" and writes nothing to stdout, so the report
    # must go through an explicit temp file to stay version-agnostic.  gcovr
    # is also run with cwd == source_root: gcovr only relativizes source
    # paths against --root when invoked from it, and otherwise emits
    # absolute paths for every entry outside the invocation directory
    # (observed on exim's split build/source tree).
    with tempfile.NamedTemporaryFile(prefix="coverage-v4-", suffix=".json", delete=False) as handle:
        report_path = handle.name
    try:
        command = [gcovr, "--root", str(source_root), "--object-directory", str(object_root),
                   "--json", "--output", report_path, str(object_root)]
        if delete:
            command.append("--delete")
        result = subprocess.run(command, check=True, capture_output=True, text=True,
                                cwd=str(source_root))
        try:
            with open(report_path) as source:
                return json.load(source), result.stderr, command
        except (OSError, ValueError) as error:
            raise CoverageError("gcovr produced no parsable JSON report: " + str(error))
    finally:
        os.unlink(report_path)


# Some build systems (proftpd, pure-ftpd, live555) record BARE source names in the
# gcno, which gcov can only resolve when run from the directory holding the
# gcno.  For those targets collection runs once per gcno directory and the
# entries are prefixed with the directory path so names stay unique.
SUBDIR_COLLECTION_TARGETS = ("proftpd", "pure-ftpd", "live555")


def gcno_directories(object_root):
    return sorted({path.parent for path in object_root.rglob("*.gcno")})


def collect_report_multi(object_root, gcovr="gcovr", delete=False):
    merged = {"gcovr/format_version": None, "files": []}
    command = None
    stderr = ""
    base = Path(object_root).resolve()
    for directory in gcno_directories(base):
        report, run_stderr, command = collect_report(directory, directory, gcovr, delete)
        stderr += run_stderr
        if merged["gcovr/format_version"] is None:
            merged["gcovr/format_version"] = report.get("gcovr/format_version")
        for entry in report.get("files", []):
            entry = dict(entry)
            entry["file"] = directory.relative_to(base).joinpath(entry["file"]).as_posix()
            merged["files"].append(entry)
    return merged, stderr, command


def profile_paths(target, cwd):
    cwd = Path(cwd).resolve()
    if target == "lightftp":
        return cwd.parent, cwd
    if target == "lighttpd1":
        return cwd / "src", cwd
    if target in ("forked-daapd", "kamailio"):
        # gcov must run from the src directory holding the gcno: the build
        # records source names that only resolve from there (calibrated in
        # the subject images with real gcda present).
        return cwd / (target + "-gcov") / "src", cwd / (target + "-gcov") / "src"
    if target == "bftpd":
        return cwd, cwd
    if target == "exim":
        # cov_script runs from exim-gcov.  gcovr resolves the instrumented
        # build-tree copies correctly only when the gcovr root IS the build
        # directory (a broader root mis-resolves the per-module sources).
        return cwd / "src" / "build-Linux-x86_64", cwd / "src" / "build-Linux-x86_64"
    if target in ("proftpd", "pure-ftpd"):
        # bare source names in the gcno: collection is per gcno directory
        # (see SUBDIR_COLLECTION_TARGETS); names are dir-prefixed, so the
        # tree root resolves them.
        return cwd, cwd
    if target == "live555":
        # The server links instrumented libraries from sibling directories.
        # --root=testProgs filters those libraries out even when fingerprint
        # search roots can resolve their sources. Collect the whole gcov tree.
        return cwd.parent, cwd.parent
    raise CoverageError("unsupported target: " + target)


def source_search_roots(target, cwd, source_root):
    """Extra fingerprint roots for trees whose instrumented sources span
    directories. exim compiles .c copies inside build-Linux-x86_64 but
    #includes headers (with their own inline branch data) from the original
    src tree, which gcovr reports under the same relative names. Live555 is
    collected under its whole-tree root, including sibling libraries."""
    if target == "exim":
        original = Path(cwd).resolve() / "src" / "src"
        return [original] if original.is_dir() and original != Path(source_root) else []
    return []


def structured_message_count(path):
    """Count actual aflnet frames; reject truncated lengths before replay."""
    count = 0
    with Path(path).open("rb") as source:
        while True:
            length = source.read(4)
            if not length:
                return count
            if len(length) != 4:
                raise CoverageError("truncated replay frame length: " + str(path))
            size = struct.unpack("<I", length)[0]
            if len(source.read(size)) != size:
                raise CoverageError("truncated replay frame: " + str(path))
            count += 1


def client_timeout_seconds(client_command, path, mode):
    # aflnet-replay polls twice per message. SMTP's 100 ms response wait and
    # long saved sessions can legitimately exceed the old fixed 5 seconds.
    count = structured_message_count(path) if mode == 1 else 1
    poll_index = 5 if mode == 1 else 4
    poll_ms = int(client_command[poll_index]) if len(client_command) > poll_index else 1
    requested = max(5.0, 2.0 * count * poll_ms / 1000.0 + 5.0)
    # Explicit bounded diagnostic timeout, never scientific completeness.
    return min(requested, 180.0)


def loopfuzz_replayer():
    """Select only the frame-ledger-capable replayer for strict replay."""
    configured = os.environ.get(LOOPFUZZ_REPLAYER_ENV,
                                "/home/ubuntu/loopfuzz/aflnet-replay")
    path = Path(configured)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise CoverageError("LoopFuzz aflnet-replay is missing or not executable: " + configured)
    try:
        supports_frame_ledger = b"LOOPFUZZ_REPLAY_LEDGER" in path.read_bytes()
    except OSError as error:
        raise CoverageError("cannot inspect LoopFuzz replayer capabilities: " + str(error)) from error
    if not supports_frame_ledger:
        raise CoverageError("configured aflnet-replay lacks the LoopFuzz frame-ledger capability")
    identity = (path.stat().st_mtime_ns, path.stat().st_size)
    if _VERIFIED_LOOPFUZZ_REPLAYERS.get(str(path)) != identity:
        try:
            probe = subprocess.run([str(path)], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, timeout=5,
                                   check=False)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise CoverageError("cannot validate LoopFuzz replayer ABI: " + str(error)) from error
        usage = probe.stdout + probe.stderr
        if ("local_port" not in usage or "follow-up_resp_timeout(ms)" not in usage):
            raise CoverageError("configured aflnet-replay lacks the LoopFuzz local_port/poll/socket-timeout ABI")
        try:
            capabilities = subprocess.run(
                [str(path), "--capabilities"], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=5, check=False)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise CoverageError("cannot validate LoopFuzz replayer capabilities: " + str(error)) from error
        if (capabilities.returncode != 0 or
                "peer-reset-after-input-end-v1" not in capabilities.stdout.split() or
                "terminal-quit-reply-v6" not in capabilities.stdout.split()):
            raise CoverageError("configured aflnet-replay lacks verified terminal-QUIT handling")
        _VERIFIED_LOOPFUZZ_REPLAYERS[str(path)] = identity
    return str(path)


def bound_port(port, protocol):
    """Observe a bound socket without a probe that changes target state."""
    for suffix in ("", "6"):
        table = Path("/proc/net/" + protocol + suffix)
        if not table.exists():
            continue
        for row in table.read_text().splitlines()[1:]:
            fields = row.split()
            if (int(fields[1].rsplit(":", 1)[1], 16) == port and
                    (protocol == "udp" or fields[3] == "0A")):
                return True
    return False


def wait_bound_port(process, port, protocol, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if bound_port(port, protocol):
            return True
        if process is not None and process.poll() is not None:
            return False
        time.sleep(0.01)
    return False


def run_supervised_session(target, client_command, server_command, record,
                           mode, port, cwd, env, log, server_log=None):
    """Supervise targets needing readiness, full client, and gcov shutdown.

    The old UDP connect succeeded before Kamailio bound its socket, so replay
    could finish without delivering a request. The old SMTP lifetime expired
    while long clients were still sending. ProFTPD's three-second timeout
    could kill its listener while a valid FTP transfer was still in progress.
    LightFTP, Live555 and forked-daapd coverage builds use SIGUSR1 for a normal
    exit; Lighttpd1 flushes on its graceful SIGTERM path. Send either signal
    only after the client has completed.
    """
    # replay_commands retains historical timeout argv for other targets;
    # these targets are supervised here so the server remains alive for the
    # complete client and all process-group children receive shutdown.
    # BFTPD has a four-token timeout wrapper (``timeout -k 1s 3s``), while
    # the other supervised targets use the six-token form that also names a
    # signal (``timeout -k 1s -s SIGNAL 3s``).  Strip exactly the wrapper so
    # the supervised process starts at ``./bftpd``.
    command = server_command[4:] if target == "bftpd" else server_command[6:]
    timeout = client_timeout_seconds(client_command, record["path"], mode)
    server = client = helper = None
    ready = False
    helper_ready = None
    timed_out = False
    shutdown_requested = False
    # The server's own stdout/stderr (exim -d debug flows, daemon teardown
    # lines) must never share the client's evidence stream: per-write
    # interleaving previously corrupted the transcript mid-section
    # (2026-11-20 exim). A separate file keeps the replay log pure while
    # retaining the server-side evidence, hash-pinned in the replay record.
    server_stream = server_log if server_log is not None else log
    try:
        server = subprocess.Popen(command, cwd=cwd, env=env, stdout=server_stream,
                                  stderr=subprocess.STDOUT, start_new_session=True)
        ready = wait_bound_port(server, port, "udp" if target == "kamailio" else "tcp")
        if ready and target == "kamailio":
            helper = subprocess.Popen(["./run_pjsip"], cwd=cwd, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
            # The wrapper backgrounds pjsua then exits. Observe its real UDP
            # socket instead of treating the wrapper's exit as readiness.
            helper_ready = wait_bound_port(None, 5068, "udp")
        if ready and helper_ready is not False:
            client = subprocess.Popen(client_command, cwd=cwd, env=env, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
            try:
                client.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                stop_process(client)
        client_code = client.returncode if client is not None else 125
        shutdown_signal = (signal.SIGUSR1 if target in ("lightftp", "live555", "forked-daapd")
                           else signal.SIGTERM)
        if server.poll() is None and target in ("proftpd", "bftpd"):
            # ProFTPD's -X single-session listener exits itself at session
            # end and flushes gcov on that natural exit; the earlier harness
            # TERM raced that teardown and the gcov build can die with SIGSEGV
            # inside the signal handler instead. Give the natural exit a
            # short window before any harness signal (2026-11-16 v3 policy).
            for _ in range(50):
                if server.poll() is not None:
                    break
                time.sleep(0.1)
        if server.poll() is None:
            shutdown_requested = True
            os.killpg(server.pid, shutdown_signal)
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stop_process(server)
        server_code = server.returncode
        flags = classify_replay_exit(server_code, client_code)
        # An explicitly requested TERM is an expected harness shutdown, not
        # a crash finding. SIGKILL/SEGV and positive failures remain errors.
        if shutdown_requested and server_code == -signal.SIGTERM:
            flags = classify_replay_exit(124, client_code)
        return dict(server_exit_code=server_code, client_exit_code=client_code,
                    server_ready=ready, helper_ready=helper_ready,
                    client_timed_out=timed_out, client_timeout_seconds=timeout,
                    harness_shutdown_requested=shutdown_requested,
                    harness_shutdown_signal=signal.Signals(shutdown_signal).name,
                    harness_policy=("live555-ready-client-sigusr1-exit0-v2"
                                   if target == "live555" else
                                   forked_daapd_replay_policy()["name"]
                                   if target == "forked-daapd" else
                                   "pure-ftpd-ready-client-graceful-exit-v1"
                                   if target == "pure-ftpd" else
                                   proftpd_replay_policy()["name"]
                                   if target == "proftpd" else
                                   "bftpd-client-lifetime-protocol-end-v3"
                                   if target == "bftpd" else
                                   "ready-client-graceful-exit-v1"),
                    effective_server_command=command, **flags)
    finally:
        stop_process(client)
        stop_process(server)
        stop_process(helper)


def replay_commands(target, path, port, mode, cwd, workdir):
    replayer = loopfuzz_replayer() if mode == 1 else "afl-replay"
    protocol = TARGET_PROTOCOLS[target]
    client = ([replayer, str(path), protocol, str(port), "0", "100", "10000"]
              if mode == 1 else [replayer, str(path), protocol, str(port), "1"])
    timeout = ["timeout", "-k", "1s", "-s", "SIGUSR1", "3s"]
    configured = os.environ.get("COVERAGE_V4_TARGET_CONFIG")
    target_config = None
    if configured:
        target_config = Path(configured).resolve()
        if not target_config.is_file() or target_config.is_symlink():
            raise CoverageError("COVERAGE_V4_TARGET_CONFIG must be a regular non-symlink file")
    if target == "lightftp":
        server = timeout + ["./fftp", str(target_config or "fftp.conf"), str(port)]
    elif target == "lighttpd1":
        config = target_config or (workdir / "lighttpd.conf")
        server = timeout + ["./src/lighttpd", "-D", "-f", str(config),
                            "-m", str(cwd / "src/.libs")]
    elif target == "forked-daapd":
        server = ["timeout", "-k", "1s", "-s", "SIGUSR1", "10s",
                  "./forked-daapd-gcov/src/forked-daapd", "-d", "0", "-c",
                  str(target_config or "./forked-daapd.conf"), "-f"]
    elif target == "kamailio":
        if os.environ.get("KAMAILIO_TCP", "0") != "0":
            raise CoverageError("Kamailio TCP replay is not validated; refusing UDP substitution")
        server = ["timeout", "-k", "1s", "-s", "SIGTERM", "3s",
                  "./kamailio-gcov/src/kamailio", "-f", "./kamailio-basic.cfg",
                  "-L", "./kamailio-gcov/src/modules", "-Y", "./kamailio-gcov/runtime_dir/",
                  "-n", "1", "-D", "-E"]
    elif target == "exim":
        # -d keeps the daemon in the foreground under the timeout wrapper;
        # per-connection children exit normally and flush their own gcda.
        client = [replayer, str(path), "SMTP", str(port), "0", "100", "10000"]
        server = ["timeout", "-k", "1s", "-s", "SIGTERM", "3s",
                  "./src/build-Linux-x86_64/exim", "-bd", "-d", "-oX", str(port)]
    elif target == "proftpd":
        # ProFTPD exits its signal handler by re-raising (no gcov dump from
        # the listener); coverage comes from per-session children that exit
        # normally, and SIGTERM is its graceful shutdown signal.
        server = ["timeout", "-k", "1s", "-s", "SIGTERM", "3s",
                  "./proftpd", "-n", "-c",
                  str(target_config or (workdir / "basic.conf")), "-X"]
    elif target == "pure-ftpd":
        server = ["timeout", "-k", "1s", "-s", "SIGTERM", "3s", "src/pure-ftpd", "-A"]
    elif target == "live555":
        server = timeout + ["./testOnDemandRTSPServer", str(port)]
    else:
        server = ["timeout", "-k", "1s", "3s", "./bftpd", "-D", "-c",
                  str(target_config or (workdir / "basic.conf"))]
    return client, server


def stop_process(process):
    if process is not None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()


def run_reset(record, cwd, replay_log, allow_unverified):
    configured = os.environ.get("COVERAGE_V4_RESET_COMMAND_JSON")
    if not configured:
        if not allow_unverified:
            raise CoverageError("COVERAGE_V4_RESET_COMMAND_JSON is required for verified replay")
        return dict(command_succeeded=False, reason="no reset command supplied")
    command = json.loads(configured)
    if not isinstance(command, list) or not command or any(not isinstance(v, str) for v in command):
        raise CoverageError("reset command must be a nonempty JSON argv array")
    env = os.environ.copy()
    env["COVERAGE_V4_INPUT"] = record["path"]
    with Path(replay_log).open("wb") as log:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=log,
                                stderr=subprocess.STDOUT, timeout=30, check=True)
    return dict(command_succeeded=True, command=command, exit_code=result.returncode,
                log_file=Path(replay_log).name, log_sha256=digest_file(replay_log),
                limit="exit zero authenticates command success; command must itself validate reset")


def run_one_replay(target, record, port, mode, cwd, workdir, replay_log,
                   object_root, reset=None, replay_policy=None):
    client_command, server_command = replay_commands(target, record["path"], port, mode, cwd, workdir)
    env, remote = os.environ.copy(), None
    exit_trace = Path(str(replay_log) + ".exit-trace")
    if target == "bftpd":
        env["COVERAGE_V4_EXIT_TRACE"] = str(exit_trace.resolve())
    # Targets whose server chroots (bftpd into its jail, pure-ftpd into
    # /home/fuzzing) cannot write gcda at the compiled-in absolute paths, so
    # the object tree is mirrored under the chroot prefix via GCOV_PREFIX and
    # the produced gcda are imported back after each replay.
    chroot_prefixes = {"bftpd": "/home/ubuntu/ftpshare", "pure-ftpd": "/home/fuzzing"}
    if target in chroot_prefixes:
        prefix = Path(chroot_prefixes[target])
        remote = prefix / str(object_root).lstrip("/")
        remote.mkdir(parents=True, exist_ok=True)
        for note in object_root.rglob("*.gcno"):
            data_dir = remote / note.relative_to(object_root).parent
            data_dir.mkdir(parents=True, exist_ok=True)
            # A chroot+setuid session child (bftpd DO_CHROOT=yes demotes to
            # the logged-in uid; gcov.patch unsets GCOV_PREFIX inside the
            # chroot so its gcda land at the compiled-in paths mirrored
            # here) must be able to CREATE its .gcda inside the jail.  The
            # collector normally runs as root while the child runs as the
            # FTP user: a root-owned 0755 mirror silently loses every
            # logged-in session's coverage (reproduced 2026-10-31 in the
            # bftpd image: 0755 mirror -> 0 gcda after a successful login;
            # 0777 -> 12 gcda owned by the demoted uid).  The jail is wiped
            # and re-staged per replay by the reset contract, so
            # world-writable mirror dirs are safe here.
            data_dir.chmod(0o777)
            remote_data = note.relative_to(object_root).with_suffix(".gcda")
            remote_data = remote / remote_data
            if remote_data.is_file():
                remote_data.unlink()
        env["GCOV_PREFIX"] = str(prefix)
    started, server, client, helper = time.monotonic_ns(), None, None, None
    supervised = None
    # Per-frame send ledger (GLM53 2.1): the replayer writes send facts, not
    # banner counts; the artifact is archived next to the replay log.
    ledger_path = Path(str(replay_log).rsplit(".", 1)[0] + "-frame-ledger.jsonl")
    env["LOOPFUZZ_REPLAY_LEDGER"] = str(ledger_path)

    def gcda_inventory():
        return {str(p.relative_to(object_root)): (p.stat().st_size, p.stat().st_mtime_ns)
                for p in sorted(object_root.rglob("*.gcda")) if p.is_file()}

    gcda_inventory_before = gcda_inventory() if target in ACCUMULATING_GCDA_TARGETS else {}
    server_log_path = Path(str(replay_log).rsplit(".", 1)[0] + "-server.log")
    with Path(replay_log).open("wb") as log, \
            server_log_path.open("wb") as server_log:
        try:
            if target in TARGET_PROTOCOLS:
                supervised = run_supervised_session(target, client_command, server_command,
                    record, mode, port, cwd, env, log, server_log=server_log)
                server_code, client_code = (supervised["server_exit_code"],
                                             supervised["client_exit_code"])
            else:
                server_code, client_code = None, None
            # forked-daapd now uses the supervised path above: the listener
            # must be ready before replay, then SIGUSR1 lets the gcov build
            # flush and exit normally. Keep the legacy launch only for any
            # future unsupervised dispatch; otherwise this started a second
            # server after the supervised run and polluted replay state.
            if target == "forked-daapd" and supervised is None:
                server = subprocess.Popen(server_command, cwd=cwd, env=env, stdout=server_log,
                                          stderr=subprocess.STDOUT, start_new_session=True)
                time.sleep(1)
            if supervised is None:
                client = subprocess.Popen(client_command, cwd=cwd, env=env, stdout=log,
                                          stderr=subprocess.STDOUT, start_new_session=True)
                if server is None:
                    server = subprocess.Popen(server_command, cwd=cwd, env=env, stdout=server_log,
                                              stderr=subprocess.STDOUT, start_new_session=True)
                server_code = server.wait(timeout=15)
                try:
                    client_code = client.wait(timeout=client_timeout_seconds(
                        client_command, record["path"], mode))
                except subprocess.TimeoutExpired:
                    stop_process(client)
                    client_code = client.returncode
                    supervised = dict(client_timed_out=True)
        finally:
            stop_process(client)
            stop_process(server)
            stop_process(helper)
    gcda_inventory_after = gcda_inventory() if target in ACCUMULATING_GCDA_TARGETS else {}
    session_gcda_touched = sorted(
        path for path, state in gcda_inventory_after.items()
        if gcda_inventory_before.get(path) != state)
    frame_ledger_result = None
    if ledger_path.is_file():
        framed_bytes = None
        try:
            framed_bytes = Path(record["path"]).read_bytes()
        except OSError:
            framed_bytes = None
        try:
            frame_ledger_result = read_frame_ledger(ledger_path, framed_bytes)
        except (OSError, CoverageError):
            frame_ledger_result = None
    proftpd_frame_ledger = {"path": ledger_path, "result": frame_ledger_result}
    imported = []
    if remote is not None:
        for source in sorted(remote.rglob("*.gcda")):
            destination = object_root / source.relative_to(remote)
            if not destination.with_suffix(".gcno").is_file():
                raise CoverageError("BFTPD gcda has no corresponding gcno: " + str(source))
            shutil.copy2(source, destination)
            imported.append(source.relative_to(remote).as_posix())
        # Missing data is an incomplete measurement, never a zero-coverage
        # observation. Retain any union evidence but fail strict acceptance.
        session_coverage_missing = not imported
    else:
        session_coverage_missing = target in ACCUMULATING_GCDA_TARGETS and not session_gcda_touched
    flags = classify_replay_exit(server_code, client_code)
    if supervised and "server_crashed" in supervised:
        flags.update(supervised)
    final_reply_code = None
    if target == "pure-ftpd":
        final_reply_code = pureftpd_final_reply_code(replay_log)
        flags = apply_pureftpd_session_exit_policy(
            flags, server_code, client_code,
            supervised.get("server_ready") if supervised else None,
            supervised.get("client_timed_out", False) if supervised else False,
            supervised.get("harness_shutdown_requested", False) if supervised else False,
            final_reply_code, imported,
            bool(reset and reset.get("command_succeeded")))
    if target == "proftpd":
        try:
            frames_expected = framed_input_frames(record["path"])
        except (OSError, CoverageError):
            frames_expected = None
        packets_sent = transcript_packets_sent(replay_log)
        ledger = frame_ledger_result
        flags = apply_proftpd_shutdown_exit_policy(
            flags, server_code, client_code, supervised or {},
            bool(reset and reset.get("command_succeeded")),
            frames_expected=frames_expected, packets_sent=packets_sent,
            ledger_send_complete=(ledger or {}).get("send_complete") if ledger else None,
            session_gcda_touched=session_gcda_touched)
    result = dict(server_exit_code=server_code, client_exit_code=client_code,
                session_coverage_missing=session_coverage_missing,
                server_crashed=flags["server_crashed"],
                replay_anomaly=flags["replay_anomaly"],
                anomaly_kind=flags["anomaly_kind"],
                replay_elapsed_ns=time.monotonic_ns() - started, imported_gcda=imported,
                replay_log_file=Path(replay_log).name,
                replay_log_sha256=digest_file(replay_log),
                server_log_file=server_log_path.name,
                server_log_sha256=digest_file(server_log_path),
                client_command=client_command, server_command=server_command)
    if supervised:
        result.update(supervised)
    if target in ACCUMULATING_GCDA_TARGETS:
        result["session_gcda_touched"] = session_gcda_touched
    if target == "pure-ftpd":
        result["final_ftp_reply_code"] = final_reply_code
        result["reset_command_succeeded"] = bool(reset and reset.get("command_succeeded"))
        for field in ("server_crashed", "replay_anomaly", "anomaly_kind",
                      "server_anomalous_exit", "client_anomalous_exit",
                      "client_aborted_on_crash", "pureftpd_session_exit_expected",
                      "pureftpd_session_exit_evidence"):
            result[field] = flags[field]
    if target == "proftpd":
        result["reset_command_succeeded"] = bool(reset and reset.get("command_succeeded"))
        for field in ("server_crashed", "replay_anomaly", "anomaly_kind",
                      "server_anomalous_exit", "client_anomalous_exit",
                      "client_aborted_on_crash", "proftpd_shutdown_exit_expected",
                      "proftpd_shutdown_exit_evidence"):
            result[field] = flags[field]
    if frame_ledger_result is not None:
        result.update(frame_ledger_file=ledger_path.name,
                      frame_ledger_sha256=digest_file(ledger_path),
                      frames_total=frame_ledger_result["frames_total"],
                      frames_unattempted=frame_ledger_result.get("frames_unattempted"),
                      frames_attempted=frame_ledger_result["frames_attempted"],
                      frames_sent_complete=frame_ledger_result["frames_sent_complete"],
                      last_attempted_frame_is_quit=frame_ledger_result["last_attempted_frame_is_quit"],
                      peer_closed=frame_ledger_result.get("peer_closed"),
                      close_initiator=frame_ledger_result.get("close_initiator"),
                      close_kind=frame_ledger_result.get("close_kind"),
                      last_reply_code=frame_ledger_result.get("last_reply_code"),
                      last_reply_terminated=frame_ledger_result.get("last_reply_terminated"),
                      send_stop_reason=frame_ledger_result["stop_reason"],
                      send_completeness="complete" if frame_ledger_result["send_complete"] else "incomplete")
        if target == "bftpd":
            result["sent_prefix_has_bftpd_quit"] = frame_ledger_result["sent_prefix_has_bftpd_quit"]
            result["last_attempted_post_recv_errno"] = frame_ledger_result[
                "last_attempted_post_recv_errno"]
        if target in ("lightftp", "pure-ftpd", "forked-daapd", "lighttpd1"):
            result["last_attempted_frame_is_http_close"] = frame_ledger_result[
                "last_attempted_frame_is_http_close"]
    else:
        # Legacy replayer without the ledger: banner counts are loop-entry
        # evidence only; send facts are unknown and never inferred (2.1).
        result["send_completeness"] = "unknown"
    if target == "bftpd":
        result["final_ftp_reply_code"] = bftpd_final_reply_code(replay_log)
        result["bftpd_protocol_end_expected"] = bftpd_protocol_end_expected(
            result, frame_ledger_result, result["final_ftp_reply_code"], reset or {},
            policy_version=5)
        if result["bftpd_protocol_end_expected"]:
            result.update(replay_anomaly=False, anomaly_kind="")
    if target in ("lightftp", "pure-ftpd", "forked-daapd", "lighttpd1", "exim", "proftpd"):
        result["protocol_end_expected"] = protocol_end_expected(
            target, dict(result, server_log_witness=server_log_path),
            reset or {}, frame_ledger_result, replay_log,
            policy_version=replay_policy_version(REPLAY_HARNESS_VERSION),
            replay_policy=replay_policy)
        if result["protocol_end_expected"]:
            result.update(replay_anomaly=False, anomaly_kind="")
    result["incomplete_reasons"] = replay_incompleteness(result)
    result["coverage_complete"] = not result["incomplete_reasons"]
    result["sigpipe_normal_exit_observed"] = (target == "bftpd" and exit_trace.is_file() and
        BFTPD_EXIT_MARKER in exit_trace.read_text(errors="replace"))
    return result


def classify_replay_exit(server_code, client_code):
    """Classify one replay's process exits.

    A server killed by a signal on a crash-input is a fuzzing FINDING, not a
    measurement failure: whatever coverage children flushed before the crash
    is kept and the exit code is recorded.  A client failing on the same
    crashed server (connection reset) is part of that finding.

    Unexpected positive server exits and lone client failures are recorded
    as per-input anomalies. The Pure-FTPd 421 policy is applied later, after
    readiness, transcript, reset, and gcda evidence are available.
    """
    server_crashed = server_code is not None and server_code < 0
    client_aborted_on_crash = server_crashed and client_code != 0
    server_anomalous = server_code is not None and server_code not in (0, 124) and not server_crashed
    client_anomalous = client_code is not None and client_code != 0 and not client_aborted_on_crash
    if server_crashed:
        kind = "server-crash-finding"
    elif server_anomalous:
        kind = "server-exit-%s" % server_code
    elif client_anomalous:
        kind = "client-exit-%s" % client_code
    else:
        kind = ""
    return dict(server_crashed=server_crashed,
                client_aborted_on_crash=client_aborted_on_crash,
                server_anomalous_exit=server_anomalous,
                client_anomalous_exit=client_anomalous,
                replay_anomaly=kind != "" and kind != "server-crash-finding",
                anomaly_kind=kind)


def resolve_replay_limit(args):
    """Resolve the optional smoke cap and fail closed outside smoke mode."""
    smoke = bool(getattr(args, "smoke", False))
    max_replay_inputs = getattr(args, "max_replay_inputs", None)
    if max_replay_inputs is None:
        raw_limit = os.environ.get("COVERAGE_V4_MAX_REPLAY_INPUTS")
        if raw_limit not in (None, ""):
            try:
                max_replay_inputs = int(raw_limit)
            except ValueError as error:
                raise CoverageError("COVERAGE_V4_MAX_REPLAY_INPUTS must be a positive integer") from error
    if os.environ.get("COVERAGE_V4_SMOKE", "0") == "1":
        smoke = True
    if max_replay_inputs is not None:
        if isinstance(max_replay_inputs, bool) or max_replay_inputs < 1:
            raise CoverageError("max replay inputs must be a positive integer")
        if not smoke:
            raise CoverageError("max replay inputs is smoke-only; set --smoke or COVERAGE_V4_SMOKE=1")
    return smoke, max_replay_inputs


def run_replay(args):
    folder, output, cwd = args.folder.resolve(), args.output.resolve(), Path.cwd().resolve()
    sampled = bool(getattr(args, "sampled_checkpoints", False))
    smoke, max_replay_inputs = resolve_replay_limit(args)
    schema = SAMPLED_SCHEMA if sampled else SCHEMA
    artifact_suffix = SAMPLED_ARTIFACT_SUFFIX if sampled else LEGACY_ARTIFACT_SUFFIX
    directory = Path(str(output) + artifact_suffix)
    if output.exists() or directory.exists() or Path(str(output) + ".final").exists():
        raise CoverageError("refusing to overwrite coverage artifacts; select a new output path")
    if args.step < 1:
        raise CoverageError("step must be positive")
    if sampled and args.target not in ACCUMULATING_GCDA_TARGETS:
        raise CoverageError("sampled checkpoints require an accumulating-gcda target; "
                            "use per-input collection for " + args.target)
    source_root, object_root = profile_paths(args.target, cwd)
    allow_incomplete = getattr(args, "allow_incomplete", False)
    replay_policy = (bftpd_exit_policy(cwd, allow_incomplete) if args.target == "bftpd" else
                     pureftpd_replay_policy(cwd, allow_incomplete) if args.target == "pure-ftpd" else
                     forked_daapd_replay_policy() if args.target == "forked-daapd" else None)
    search_roots = source_search_roots(args.target, cwd, source_root)
    workdir = Path(os.environ.get("WORKDIR", str(cwd)))
    coordinates = load_coordinates(folder / "queue-checkpoints.jsonl")
    plan, unreplayable = plan_corpus(folder, args.mode, coordinates, args.require_coordinates)
    planned_n_replayed = len(plan)
    replay_truncated = max_replay_inputs is not None and max_replay_inputs < planned_n_replayed
    if replay_truncated:
        plan = plan[:max_replay_inputs]
        if not plan:
            raise CoverageError("max replay inputs removed the entire replay plan")
    # A smoke cap is a diagnostic lower bound.  Keep the full planned count in
    # terminal metadata so an archive cannot be mistaken for a complete corpus
    # replay even when every executed input is individually valid.
    seed_indices = validate_initial_seed_prefix(plan)
    checkpoint_indices = {index for index in range(1, len(plan) + 1)
                          if index % args.step == 0 or index == len(plan)}
    # Preserve the exact seed-only endpoint used by downstream analyses even
    # when the initial corpus is shorter than --step.
    if sampled and seed_indices:
        checkpoint_indices.add(seed_indices[-1])
    notes = instrument_identity(object_root)
    directory.mkdir(parents=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(directory / "replay-plan.json", plan)
    if unreplayable:
        # Ledger entries without a replayable corpus file (e.g. imported
        # seeds whose structured form was never written).  Not an error, but
        # the coverage endpoint must disclose what the union does NOT include.
        write_json(directory / "unreplayable-ledger-entries.json",
                   dict(count=len(unreplayable), filenames=unreplayable))
    if args.target in ("proftpd", "lightftp"):
        if args.mode == 1:
            # v11: the overlong-close exception requires the source-derived
            # boundary AND a live probe of the measured executable. The probe
            # runs before the baseline reset below, so its gcda cannot leak
            # into the measurement.
            if args.target == "proftpd":
                configured = os.environ.get("COVERAGE_V4_TARGET_CONFIG")
                conf_path = (Path(configured) if configured else workdir / "basic.conf")
                source_policy = proftpd_overlong_source_policy(source_root, object_root,
                                                               conf_path)
                overlong = None
                if source_policy.get("verified"):
                    probe = probe_ftp_overlong_close(
                        args.target, args.port, cwd, workdir, directory,
                        source_policy, allow_incomplete)
                    if probe.get("verified"):
                        overlong = dict(source_policy, exception_enabled=True,
                                        overlong_probe=probe)
                elif not allow_incomplete:
                    raise CoverageError("ProFTPD overlong-close source policy is unverifiable")
                replay_policy = proftpd_replay_policy(overlong_close=overlong)
            else:
                base_policy = lightftp_replay_policy(source_root, object_root,
                                                     allow_incomplete)
                replay_policy = base_policy
                if base_policy.get("source_structure_verified") and \
                        base_policy.get("binary_sha256"):
                    probe_dir = directory / "overlong-close-probe"
                    if not probe_dir.is_dir():
                        probe_dir.mkdir()
                    build = lightftp_build_record(source_root, object_root, probe_dir)
                    if not build.get("verified") and not allow_incomplete:
                        raise CoverageError(
                            "LightFTP reproducible-build record is unverifiable: %s" %
                            build.get("reason", "rebuild divergence"))
                    probe = probe_ftp_overlong_close(
                        args.target, args.port, cwd, workdir, directory,
                        base_policy, allow_incomplete)
                    if probe.get("verified") and build.get("verified"):
                        replay_policy = lightftp_replay_policy(
                            source_root, object_root, allow_incomplete,
                            overlong_probe=probe, build_record=build)
        else:
            replay_policy = (proftpd_replay_policy() if args.target == "proftpd"
                             else lightftp_replay_policy(source_root, object_root,
                                                         allow_incomplete))
    gcovr_version = subprocess.check_output([args.gcovr, "--version"], text=True).strip()
    gcov_version = subprocess.check_output(["gcov", "--version"], text=True).splitlines()[0]
    # Delete through gcovr, then independently verify a zero baseline.
    collect = (lambda delete=False: collect_report_multi(object_root, args.gcovr, delete)) \
        if args.target in SUBDIR_COLLECTION_TARGETS else \
        (lambda delete=False: collect_report(source_root, object_root, args.gcovr, delete))
    _, reset_stderr, reset_command = collect(delete=True)
    baseline_report, baseline_stderr, collection_command = collect()
    zero_baseline_mode = ""
    try:
        baseline = parse_snapshot(baseline_report, source_root, search_roots)
    except CoverageError as error:
        # gcovr 4.x only reports line/branch structure for objects that have
        # gcda. Images that never executed the instrumented binary during
        # build (live555, proftpd, kamailio, forked-daapd) therefore have an
        # empty baseline universe. If the filesystem PROVES no gcda survive
        # the delete pass, zero coverage holds by construction and the
        # universe crystallizes from the first replayed checkpoint instead.
        if "empty source/branch scope" not in str(error) or any(object_root.rglob("*.gcda")):
            raise
        baseline = parse_snapshot(baseline_report, source_root, search_roots, allow_empty=True)
        zero_baseline_mode = "filesystem-verified-no-gcda"
    checkpoint_policy = (dict(kind="step-plus-terminal-and-seed-boundary",
                              step=args.step, final_checkpoint_required=True,
                              seed_boundary_required=True,
                              every_input_has_replay_ledger=True)
                         if sampled else None)
    manifest = scope_manifest(baseline, notes, gcovr_version, gcov_version, replay_policy,
                              schema=schema, checkpoint_policy=checkpoint_policy)
    manifest.update(source_root=str(source_root), object_root=str(object_root), target=args.target,
                    source_search_roots=[str(r) for r in search_roots],
                    zero_baseline_mode=zero_baseline_mode)
    seal_scope_manifest(manifest)
    write_json(directory / "scope.json", manifest)
    write_json(directory / "baseline.json", baseline_report)
    union = CoverageUnion(baseline, manifest)
    unexpected_drop = False
    anomaly_kinds = {}
    incomplete_replays = []
    # Every mid-input stop stays listed here whether or not a policy accepts
    # it: accepting a server-initiated close must never silently swallow the
    # input from view. This inventory is the durable record of "problem
    # places" (close kind, final reply, unattempted frames, acceptance
    # basis) and the audit recomputes it from the archived evidence.
    protocol_close_inventory = []
    policy_replay_events = []
    all_resets_verified = True
    ledger_name = "replay-ledger.jsonl" if sampled else "checkpoints.jsonl"
    ledger_context = ((directory / ledger_name).open("x") if sampled
                      else contextlib.nullcontext(None))
    with output.open("x", newline="") as csv_output, \
            (directory / "checkpoints.jsonl").open("x") as events, \
            ledger_context as ledger_output:
        writer = csv.DictWriter(csv_output, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for index, record in enumerate(plan, 1):
            if digest_file(record["path"]) != record["input_sha256"]:
                raise CoverageError("corpus changed after planning: " + record["filename"])
            reset = run_reset(record, cwd, directory / ("reset-%06d.log" % index), args.allow_unverified_reset)
            all_resets_verified &= bool(reset.get("command_succeeded"))
            replay = run_one_replay(args.target, record, args.port, args.mode, cwd, workdir,
                                    directory / ("replay-%06d.log" % index), object_root,
                                    reset=reset, replay_policy=replay_policy)
            # Load-shaped truncation retry (2026-11-24): under multi-container
            # replay storms forked-daapd can reset the connection mid-input
            # (close_kind="reset", client-recv-{pre,post}-send-failed,
            # pre/post_recv_errno 104=ECONNRESET) although the same input
            # replays to eof on a quiet host: the exact 34-input corpus that
            # truncated 8 sessions under 36-way replay concurrency replayed
            # to eof when re-run quiet (response_bytes identical). Refusing
            # the whole terminal for an environmental truncation discards
            # real campaign coverage; blanket-accepting a truncation would
            # silently undercount it. Retry the session once from a fresh
            # reset and judge the retry by the same acceptance policy, so a
            # deterministic target-side reset still refuses. Artifacts land
            # at the final names only on success (originals restored from
            # backup otherwise), keeping the archive hashes self-consistent.
            retried_close = False
            if (replay.get("close_kind") == "reset" and
                    replay.get("send_stop_reason") in
                    ("client-recv-pre-send-failed", "client-recv-post-send-failed")):
                index_str = "%06d" % index
                backups = {}
                for artifact in ("replay-%s.log" % index_str,
                                 "replay-%s-frame-ledger.jsonl" % index_str,
                                 "replay-%s-server.log" % index_str,
                                 "reset-%s.log" % index_str):
                    source = directory / artifact
                    if source.is_file():
                        backup = directory / (artifact + ".retry-bak")
                        shutil.move(str(source), str(backup))
                        backups[artifact] = backup
                try:
                    retry_reset = run_reset(record, cwd,
                                            directory / ("reset-%s.log" % index_str),
                                            args.allow_unverified_reset)
                    retry_replay = run_one_replay(args.target, record, args.port, args.mode,
                                                  cwd, workdir,
                                                  directory / ("replay-%s.log" % index_str),
                                                  object_root,
                                                  reset=retry_reset, replay_policy=replay_policy)
                    for backup in backups.values():
                        backup.unlink()
                    reset = retry_reset
                    replay = retry_replay
                    retried_close = True
                    all_resets_verified &= bool(retry_reset.get("command_succeeded"))
                except (CoverageError, OSError, subprocess.SubprocessError):
                    for artifact, backup in backups.items():
                        shutil.move(str(backup), str(directory / artifact))
            incomplete = replay_incompleteness(replay)
            if incomplete:
                incomplete_replays.append(dict(filename=record["filename"], reasons=incomplete))
            if replay.get("send_stop_reason") not in ("eof", None):
                protocol_close_inventory.append(dict(
                    idx=index, filename=record["filename"],
                    stop_reason=replay.get("send_stop_reason"),
                    peer_closed=replay.get("peer_closed"),
                    close_initiator=replay.get("close_initiator"),
                    close_kind=replay.get("close_kind"),
                    last_reply_code=replay.get("last_reply_code"),
                    last_reply_terminated=replay.get("last_reply_terminated"),
                    frames_unattempted=replay.get("frames_unattempted"),
                    accepted=(replay.get("protocol_end_expected") is True or
                              replay.get("bftpd_protocol_end_expected") is True),
                    accepted_by=(replay_policy or {}).get("name")
                    if replay.get("protocol_end_expected") is True else None,
                    retried_close=retried_close,
                    incomplete_reasons=incomplete))
            if replay.get("replay_anomaly"):
                anomaly_kinds[replay["anomaly_kind"]] = anomaly_kinds.get(replay["anomaly_kind"], 0) + 1
            if instrument_identity(object_root) != notes:
                raise CoverageError("instrumented objects changed during replay")
            checkpoint = not sampled or index in checkpoint_indices
            ledger_record = dict(
                schema_version=SAMPLED_SCHEMA if sampled else SCHEMA,
                idx=index, filename=record["filename"], input_sha256=record["input_sha256"],
                input_hash_verified_before_replay=True, reset=reset, replay=replay,
                instrumented_objects_unchanged=True, checkpoint=checkpoint)
            policy_replay_events.append(dict(
                idx=index, filename=record["filename"], replay=replay, reset=reset))
            for field in ("campaign_id", "queue_id", "discovery_time_ms", "monotonic_ms",
                          "discovery_execution_id", "coordinate_source", "kind"):
                if field in record:
                    ledger_record[field] = record[field]
            if checkpoint:
                report, stderr, _ = collect()
                raw = canonical(report).encode()
                snapshot_path = directory / ("snapshot-%06d.json.gz" % index)
                with gzip.open(snapshot_path, "wb") as snapshot_output:
                    snapshot_output.write(raw)
                # Initial queue entries are the only inputs eligible for the
                # measured seed baseline. The seed-boundary checkpoint captures
                # their accumulated gcda before any mutated input is replayed.
                is_seed_input = record.get("kind") == "initial-queue-name"
                event = union.add(parse_snapshot(report, source_root, search_roots), record,
                                  digest_bytes(raw),
                                  expected_counter_reset=args.target in ("bftpd", "pure-ftpd"),
                                  is_seed_input=is_seed_input)
                # A zero-gcda baseline adopts its fixed source/branch universe
                # from this first collected snapshot.
                write_json(directory / "scope.json", manifest)
                event.update(replay_input_idx=index, replay=replay, reset=reset,
                             gcovr_stderr=stderr, snapshot_file=snapshot_path.name,
                             replay_retry_attempted=retried_close)
                events.write(canonical(event) + "\n")
                events.flush()
                ledger_record.update(coverage_event_idx=event["idx"],
                                     snapshot_file=snapshot_path.name,
                                     snapshot_sha256=event["snapshot_sha256"])
                unexpected_drop |= event["unexpected_nonmonotonic_snapshot"]
                if sampled or index % args.step == 0 or index == len(plan):
                    writer.writerow(union.csv_row(event))
                    csv_output.flush()
            if ledger_output is not None:
                ledger_output.write(canonical(ledger_record) + "\n")
                ledger_output.flush()
    pureftpd_audit_file = None
    pureftpd_audit_sha256 = None
    if args.target == "pure-ftpd":
        pureftpd_audit_file = "pureftpd-exit-policy-audit.json"
        pureftpd_audit_path = directory / pureftpd_audit_file
        write_json(pureftpd_audit_path,
                   pureftpd_policy_audit_report(replay_policy, policy_replay_events))
        pureftpd_audit_sha256 = digest_file(pureftpd_audit_path)
    proftpd_audit_file = None
    proftpd_audit_sha256 = None
    if args.target == "proftpd":
        proftpd_audit_file = "proftpd-exit-policy-audit.json"
        proftpd_audit_path = directory / proftpd_audit_file
        write_json(proftpd_audit_path,
                   proftpd_policy_audit_report(replay_policy, policy_replay_events))
        proftpd_audit_sha256 = digest_file(proftpd_audit_path)
    counts = audit_csv(output, manifest, union.events)
    if counts["terminal_branches"] != len(union.covered):
        raise CoverageError("terminal aggregate disagrees with branch-ID union")
    measurement_complete = (not replay_truncated and not incomplete_replays and not unreplayable and all_resets_verified and
                            replay_policy_verified_for_completeness(
                                args.target, replay_policy, source_root, object_root))
    # Preserve a replay-verifiable witness for every input.  The witness is
    # the queue identity plus the content and snapshot hashes; audit_artifacts
    # recomputes these joins instead of trusting the aggregate count.
    input_witnesses = ([dict(idx=e["idx"], filename=e["filename"],
                             input_sha256=e["input_sha256"],
                             snapshot_sha256=e["snapshot_sha256"])
                       for e in union.events] if not sampled else
                       [dict(idx=e["idx"], filename=e["filename"],
                             input_sha256=e["input_sha256"], checkpoint=e["checkpoint"],
                             snapshot_sha256=e.get("snapshot_sha256"))
                        for e in (json.loads(line) for line in
                                  (directory / ledger_name).read_text().splitlines())])
    # Durable, human-greppable record of every mid-input stop (accepted or
    # not): the audit recomputes and compares it, so an acceptance change
    # can never make problem inputs vanish from the archive silently.
    write_json(directory / "protocol-close-inventory.json",
               dict(schema_version="protocol-close-inventory-v1",
                     n_closes=len(protocol_close_inventory),
                     n_accepted=sum(1 for row in protocol_close_inventory
                                    if row["accepted"]),
                     policy=(replay_policy or {}).get("name"),
                     entries=protocol_close_inventory))
    write_json(directory / "terminal.json", dict(
        schema_version=schema, scope_sha256=manifest["scope_sha256"],
        covered_branch_ids=sorted(union.covered), covered_line_ids=sorted(union.covered_lines),
        seed_covered_branch_ids=sorted(union.seed_covered),
        seed_covered_line_ids=sorted(union.seed_covered_lines),
        seed_replay_indices=(seed_indices if sampled else sorted(union.seed_events)),
        n_seed_replayed=(len(seed_indices) if sampled else len(union.seed_events)),
        executed_input_witnesses=input_witnesses,
        n_replayed=len(plan), fixed_execution_coordinates_valid=bool(coordinates),
        accepted_protocol_closes=[dict(
            filename=event["filename"],
            frames_unattempted=event["replay"]["frames_unattempted"],
            send_stop_reason=event["replay"]["send_stop_reason"])
            for event in policy_replay_events
            if event["replay"].get("protocol_end_expected") is True],
        planned_n_replayed=planned_n_replayed,
        replay_input_limit=max_replay_inputs,
        replay_truncated=replay_truncated,
        smoke_mode=smoke,
        protocol_close_inventory=protocol_close_inventory,
        coverage_capture_mode="sampled-step-plus-terminal" if sampled else "every-input",
        sampled_checkpoint_input_indices=sorted(checkpoint_indices) if sampled else None,
        n_coverage_checkpoints=len(union.events),
        n_unreplayable_ledger_entries=len(unreplayable),
        coverage_complete=measurement_complete,
        incomplete_replays=incomplete_replays,
        acceptance="complete" if measurement_complete else "incomplete",
        pureftpd_exit_policy_audit_file=pureftpd_audit_file,
        pureftpd_exit_policy_audit_sha256=pureftpd_audit_sha256,
        proftpd_exit_policy_audit_file=proftpd_audit_file,
        proftpd_exit_policy_audit_sha256=proftpd_audit_sha256,
        replay_anomalies=dict(total=sum(anomaly_kinds.values()), kinds=anomaly_kinds),
        all_reset_commands_succeeded=all_resets_verified,
        execution_coordinate_unit="fuzzer total_execs, not network requests",
        unexpected_snapshot_decrease=unexpected_drop, csv_audit=counts,
        reset_command=reset_command, reset_stderr=reset_stderr,
        baseline_stderr=baseline_stderr, collection_command=collection_command,
        measurement="cumulative corpus replay branch union, not same-runtime bitmap coverage",
        temporal_limit="queue save time does not establish first branch discovery time",
        incomplete_reasons=( ["smoke-replay-input-cap"] if replay_truncated else [] )))
    # No synthetic campaign-end row: terminal.json describes the last actual checkpoint.
    if unexpected_drop:
        raise CoverageError("raw snapshot decreased; union preserved, audit requires investigation")
    if not measurement_complete and not allow_incomplete:
        raise CoverageError("coverage is incomplete; terminal evidence preserved, "
                            "refusing scientific acceptance (diagnostic only: --allow-incomplete)")
    return 0


def audit_artifacts(output, source_root=None, replay_input_root=None):
    output = Path(output)
    legacy_directory = Path(str(output) + LEGACY_ARTIFACT_SUFFIX)
    sampled_directory = Path(str(output) + SAMPLED_ARTIFACT_SUFFIX)
    if legacy_directory.exists() and sampled_directory.exists():
        raise CoverageError("ambiguous coverage artifacts: both v4 and v5 directories exist")
    directory = sampled_directory if sampled_directory.exists() else legacy_directory
    manifest = json.loads((directory / "scope.json").read_text())
    schema = manifest.get("schema_version")
    if schema not in (SCHEMA, SAMPLED_SCHEMA):
        raise CoverageError("unsupported coverage artifact schema: " + str(schema))
    if ((schema == SAMPLED_SCHEMA) != (directory == sampled_directory)):
        raise CoverageError("coverage artifact directory and schema version disagree")
    recorded_scope_hash = manifest.get("scope_sha256")
    if recorded_scope_hash != scope_identity_hash(manifest):
        raise CoverageError("scope manifest hash mismatch")
    root = source_root or manifest["source_root"]
    # An explicit --source-root relocates the whole tree as a single root;
    # otherwise the recorded multi-root resolution (e.g. exim's build copies
    # plus original headers) is replayed exactly.
    roots = [] if source_root else [Path(p) for p in manifest.get("source_search_roots", [])]
    baseline = parse_snapshot(json.loads((directory / "baseline.json").read_text()), root, roots,
                              allow_empty=bool(manifest.get("zero_baseline_mode")))
    empty_adopted_baseline = bool(manifest.get("zero_baseline_mode") and not baseline.branches)
    if (not empty_adopted_baseline and
            (baseline.files != manifest["sources"] or
             baseline.resolution != manifest.get("source_resolution", baseline.resolution) or
             sorted(map(list, baseline.branches)) != manifest["branch_ids"] or
             sorted(map(list, baseline.lines)) != manifest["line_ids"])):
        raise CoverageError("baseline identities disagree with pinned scope")
    union = CoverageUnion(baseline, manifest)
    coordinate_fields = ("filename", "campaign_id", "queue_id", "discovery_time_ms", "monotonic_ms",
                         "discovery_execution_id", "coordinate_source")
    saved_events = []
    sampled = schema == SAMPLED_SCHEMA
    replay_ledger = []
    # The plan is useful for independent evidence audits even in the legacy
    # every-input schema (BFTPD replays need the original framed input to
    # validate the ledger).  Older artifacts may omit it, so keep the empty
    # fallback and let target-specific audits report a precise error.
    replay_plan_path = directory / "replay-plan.json"
    replay_plan = json.loads(replay_plan_path.read_text()) if replay_plan_path.is_file() else []
    if not isinstance(replay_plan, list):
        raise CoverageError("replay plan must be a JSON list")
    expected_samples = set()
    if sampled:
        policy = manifest.get("checkpoint_policy", {})
        if (policy.get("kind") != "step-plus-terminal-and-seed-boundary" or
                policy.get("final_checkpoint_required") is not True or
                policy.get("seed_boundary_required") is not True or
                policy.get("every_input_has_replay_ledger") is not True):
            raise CoverageError("sampled schema has an unsupported checkpoint policy")
        step = nonnegative_integer(policy.get("step"), "checkpoint step")
        if step < 1:
            raise CoverageError("checkpoint step must be positive")
        with (directory / "replay-ledger.jsonl").open() as source:
            replay_ledger = [json.loads(line) for line in source if line.strip()]
        if not replay_plan or len(replay_ledger) != len(replay_plan):
            raise CoverageError("per-input replay ledger length disagrees with replay plan")
        seed_indices = [i for i, record in enumerate(replay_plan, 1)
                        if record.get("kind") == "initial-queue-name"]
        if seed_indices and seed_indices != list(range(1, len(seed_indices) + 1)):
            raise CoverageError("sampled replay plan has a non-prefix initial seed set")
        expected_samples = {i for i in range(1, len(replay_plan) + 1)
                            if i % step == 0 or i == len(replay_plan)}
        if seed_indices:
            expected_samples.add(seed_indices[-1])
        for index, (planned, record) in enumerate(zip(replay_plan, replay_ledger), 1):
            if (record.get("schema_version") != SAMPLED_SCHEMA or record.get("idx") != index or
                    record.get("filename") != planned.get("filename") or
                    record.get("input_sha256") != planned.get("input_sha256") or
                    record.get("input_hash_verified_before_replay") is not True or
                    record.get("instrumented_objects_unchanged") is not True or
                    not isinstance(record.get("reset"), dict) or
                    not isinstance(record.get("replay"), dict) or
                    record.get("checkpoint") is not (index in expected_samples)):
                raise CoverageError("invalid per-input replay ledger entry: " + str(index))
            if index in expected_samples:
                if (record.get("coverage_event_idx") is None or
                        not record.get("snapshot_file") or
                        not record.get("snapshot_sha256")):
                    raise CoverageError("sampled input lacks snapshot evidence: " + str(index))
            elif any(field in record for field in
                     ("coverage_event_idx", "snapshot_file", "snapshot_sha256")):
                raise CoverageError("unsampled input unexpectedly has snapshot evidence: " + str(index))
        if [record["idx"] for record in replay_ledger if record["checkpoint"]] != sorted(expected_samples):
            raise CoverageError("replay ledger checkpoint sequence is incomplete")
    with (directory / "checkpoints.jsonl").open() as source:
        for raw in source:
            saved = json.loads(raw)
            saved_events.append(saved)
            if sampled:
                replay_idx = nonnegative_integer(saved.get("replay_input_idx"), "replay_input_idx")
                if not 1 <= replay_idx <= len(replay_ledger):
                    raise CoverageError("checkpoint references an unknown replay input")
                linked = replay_ledger[replay_idx - 1]
                if (not linked.get("checkpoint") or
                        linked.get("coverage_event_idx") != len(saved_events) or
                        linked.get("snapshot_file") != saved.get("snapshot_file") or
                        linked.get("snapshot_sha256") != saved.get("snapshot_sha256") or
                        canonical(linked.get("replay")) != canonical(saved.get("replay")) or
                        canonical(linked.get("reset")) != canonical(saved.get("reset"))):
                    raise CoverageError("sampled checkpoint disagrees with replay ledger")
            snapshot_path = directory / saved["snapshot_file"]
            if snapshot_path.parent.resolve() != directory.resolve():
                raise CoverageError("snapshot path escapes artifact directory")
            with gzip.open(snapshot_path, "rb") as snapshot_source:
                snapshot_bytes = snapshot_source.read()
            if digest_bytes(snapshot_bytes) != saved["snapshot_sha256"]:
                raise CoverageError("snapshot content hash mismatch")
            event = union.add(parse_snapshot(json.loads(snapshot_bytes), root, roots),
                              {key: saved[key] for key in coordinate_fields if key in saved},
                              saved["snapshot_sha256"], saved["expected_counter_reset"],
                              saved.get("is_seed_input", False))
            for field in ("idx", "scope_sha256", "cumulative_covered_branches", "cumulative_covered_lines",
                          "snapshot_covered_branches", "snapshot_covered_lines", "newly_covered_branch_ids",
                          "dropped_snapshot_branch_ids", "is_seed_input"):
                if canonical(saved[field]) != canonical(event[field]):
                    raise CoverageError("checkpoint aggregate disagrees with snapshot branch IDs: " + field)
            if sampled and (saved.get("schema_version") != SAMPLED_SCHEMA or
                            event.get("scope_sha256") != recorded_scope_hash):
                raise CoverageError("sampled checkpoint has the wrong schema or scope")
    if sampled and len(saved_events) != len(expected_samples):
        raise CoverageError("sampled checkpoint count disagrees with step policy")
    policy_events = replay_ledger if sampled else saved_events
    # Empty baselines acquire their pinned universe at the first actual sample.
    if (empty_adopted_baseline and
            (baseline.files != manifest["sources"] or
             baseline.resolution != manifest.get("source_resolution") or
             sorted(map(list, baseline.branches)) != manifest["branch_ids"] or
             sorted(map(list, baseline.lines)) != manifest["line_ids"])):
        raise CoverageError("adopted baseline identities disagree with pinned scope")
    if canonical(manifest) != canonical(json.loads((directory / "scope.json").read_text())):
        raise CoverageError("reconstructed scope disagrees with saved scope")
    terminal = json.loads((directory / "terminal.json").read_text())
    pureftpd_policy_audit_verified = False
    lightftp_policy_audit_verified = False
    if manifest.get("target") == "pure-ftpd":
        policy = manifest.get("replay_policy", {})
        if policy.get("name") == "pure-ftpd-gcov-die-421-exit-251-252-v2":
            source = Path(root) / "src/ftpd.c"
            binary = Path(manifest.get("object_root", "")) / "src/pure-ftpd"
            if (policy.get("verified") is not True or
                    policy.get("source_patch_markers_verified") is not True or
                    policy.get("executable_present") is not True or
                    policy.get("source_binary_build_association") != "not-verified" or
                    not source.is_file() or not binary.is_file() or
                    not pureftpd_source_patch_markers(source.read_bytes()) or
                    digest_file(source) != policy.get("source_sha256") or
                    digest_file(binary) != policy.get("binary_sha256")):
                raise CoverageError("Pure-FTPd source or executable identity disagrees with replay policy")
            if len(policy_events) != terminal.get("n_replayed"):
                raise CoverageError("Pure-FTPd policy audit lacks a per-input checkpoint")
            for index, event in enumerate(policy_events, 1):
                errors = verify_pureftpd_replay_evidence(
                    event.get("replay", {}), event.get("reset", {}), directory,
                    index, manifest.get("gcno", {}))
                if errors:
                    raise CoverageError("Pure-FTPd replay evidence failed at input %d: %s" %
                                        (index, ",".join(errors)))
            audit_name = terminal.get("pureftpd_exit_policy_audit_file")
            audit_path = directory / "pureftpd-exit-policy-audit.json"
            expected_audit = pureftpd_policy_audit_report(policy, policy_events)
            if (audit_name != audit_path.name or not audit_path.is_file() or
                    terminal.get("pureftpd_exit_policy_audit_sha256") != digest_file(audit_path) or
                    canonical(json.loads(audit_path.read_text())) != canonical(expected_audit)):
                raise CoverageError("Pure-FTPd per-input policy audit disagrees with replay evidence")
            pureftpd_policy_audit_verified = True
        elif terminal.get("coverage_complete") is True:
            raise CoverageError("legacy Pure-FTPd policy cannot certify a complete replay")
    if manifest.get("target") == "lightftp":
        lightftp_policy_audit_verified = verify_lightftp_replay_policy(
            manifest.get("replay_policy", {}), root, manifest.get("object_root"),
            artifact_root=directory)
        if (manifest.get("replay_policy", {}).get("verified") is True and
                not lightftp_policy_audit_verified):
            raise CoverageError("LightFTP source or replay policy identity mismatch")
    proftpd_policy_audit_verified = False
    bftpd_policy_audit = None
    if manifest.get("target") == "proftpd":
        policy = manifest.get("replay_policy", {})
        policy_name = policy.get("name")
        if policy_name in ("proftpd-ready-client-graceful-exit-v2",
                           "proftpd-ready-client-graceful-exit-v3",
                           "proftpd-ready-client-graceful-exit-v4",
                           "proftpd-ready-client-graceful-exit-v5",
                           "proftpd-ready-client-graceful-exit-v6"):
            require_frames = policy_name in ("proftpd-ready-client-graceful-exit-v3",
                                             "proftpd-ready-client-graceful-exit-v4",
                                             "proftpd-ready-client-graceful-exit-v5",
                                             "proftpd-ready-client-graceful-exit-v6")
            if (policy.get("verified") is not True or
                    policy.get("handled_shutdown_exit_signal") != -signal.SIGSEGV or
                    policy.get("handled_harness_shutdown_signal") != "SIGTERM"):
                raise CoverageError("ProFTPD replay policy identity disagrees with the shutdown audit")
            if policy_name == "proftpd-ready-client-graceful-exit-v6":
                overlong = policy.get("overlong_close") or {}
                probe = overlong.get("overlong_probe") or {}
                probe_dir = directory / "overlong-close-probe"
                probe_input = probe_dir / "probe-input"
                probe_ledger = probe_dir / str(probe.get("probe_ledger_file") or "")
                probe_log = probe_dir / str(probe.get("probe_log_file") or "")
                if (overlong.get("verified") is not True or
                        overlong.get("exception_enabled") is not True or
                        not isinstance(overlong.get("give_up_bytes"), int) or
                        overlong.get("give_up_bytes") <= 0 or
                        probe.get("verified") is not True or
                        probe.get("minimum_bytes") != overlong.get("give_up_bytes") or
                        probe.get("trigger_frame") != 1 or
                        not probe_input.is_file() or
                        probe.get("probe_input_sha256") != digest_file(probe_input) or
                        not probe_ledger.is_file() or
                        probe.get("probe_ledger_sha256") != digest_file(probe_ledger) or
                        not probe_log.is_file() or
                        probe.get("probe_log_sha256") != digest_file(probe_log)):
                    raise CoverageError("ProFTPD overlong-close policy evidence mismatch")
                for name, key in (("src/main.c", "main_c_sha256"),
                                  ("src/netio.c", "netio_c_sha256"),
                                  ("proftpd", "binary_sha256")):
                    recorded = overlong.get(key)
                    live = manifest.get("source_root") and \
                        Path(manifest["source_root"]) / name
                    if recorded and live and live.is_file() and digest_file(live) != recorded:
                        raise CoverageError("ProFTPD overlong-close source identity mismatch: " + name)
            if len(policy_events) != terminal.get("n_replayed"):
                raise CoverageError("ProFTPD policy audit lacks a per-input checkpoint")
            for index, event in enumerate(policy_events, 1):
                errors = verify_proftpd_replay_evidence(
                    event.get("replay", {}), event.get("reset", {}), directory, index,
                    require_frames=require_frames)
                if errors:
                    raise CoverageError("ProFTPD replay evidence failed at input %d: %s" %
                                        (index, ",".join(errors)))
            audit_name = terminal.get("proftpd_exit_policy_audit_file")
            audit_path = directory / "proftpd-exit-policy-audit.json"
            expected_audit = proftpd_policy_audit_report(policy, policy_events)
            if (audit_name != audit_path.name or not audit_path.is_file() or
                    terminal.get("proftpd_exit_policy_audit_sha256") != digest_file(audit_path) or
                    canonical(json.loads(audit_path.read_text())) != canonical(expected_audit)):
                raise CoverageError("ProFTPD per-input policy audit disagrees with replay evidence")
            proftpd_policy_audit_verified = True
        elif terminal.get("coverage_complete") is True:
            raise CoverageError("legacy ProFTPD policy cannot certify a complete replay")
    if "coverage_complete" in terminal:
        replay_policy = manifest.get("replay_policy")
        evidence_events = replay_ledger if sampled else saved_events
        session_policy = (replay_policy or {}).get("session_policy")
        if (manifest.get("target") == "bftpd" and session_policy in
                ("bftpd-client-lifetime-protocol-end-v1",
                 "bftpd-client-lifetime-protocol-end-v2",
                 "bftpd-client-lifetime-protocol-end-v3",
                 "bftpd-client-lifetime-protocol-end-v4",
                 "bftpd-client-lifetime-protocol-end-v5")):
            bftpd_policy_audit = verify_bftpd_replay_events(
                evidence_events, replay_plan, directory, replay_input_root,
                policy_version=int(session_policy.rsplit("-v", 1)[1]))
        if (manifest.get("replay_harness_version") in FRAME_AUDIT_HARNESS_VERSIONS and
                manifest.get("target") in TARGET_PROTOCOLS and
                manifest.get("target") != "bftpd"):
            if len(replay_plan) != len(evidence_events):
                raise CoverageError("target frame audit lacks a complete replay plan")
            for index, (event, planned) in enumerate(zip(evidence_events, replay_plan), 1):
                version = manifest.get("replay_harness_version")
                strict_end = version in FRAME_AUDIT_HARNESS_VERSIONS[4:]
                verify_target_frame_replay(
                    event, planned, directory, index, manifest["target"],
                    replay_input_root, manifest.get("gcno") if strict_end else None,
                    strict_end,
                    replay_policy_version(version),
                    replay_policy)
        replay_truncated = terminal.get("replay_truncated", False)
        if not isinstance(replay_truncated, bool):
            raise CoverageError("terminal replay_truncated must be boolean")
        planned_n_replayed = terminal.get("planned_n_replayed", terminal.get("n_replayed"))
        if (isinstance(planned_n_replayed, bool) or not isinstance(planned_n_replayed, int) or
                planned_n_replayed < terminal.get("n_replayed", 0) or
                replay_truncated != (planned_n_replayed > terminal.get("n_replayed", 0))):
            raise CoverageError("terminal replay plan count disagrees with truncation metadata")
        recomputed_events = (bftpd_policy_audit["events"]
                             if bftpd_policy_audit is not None else evidence_events)
        if manifest.get("replay_harness_version") in FRAME_AUDIT_HARNESS_VERSIONS:
            expected_incomplete = [dict(filename=event["filename"],
                                        reasons=event["replay"]["incomplete_reasons"])
                                   for event in recomputed_events
                                   if event["replay"]["incomplete_reasons"]]
            if terminal.get("incomplete_replays") != expected_incomplete:
                raise CoverageError("terminal incomplete replay list disagrees with input evidence")
        if manifest.get("replay_harness_version") in FRAME_AUDIT_HARNESS_VERSIONS[5:]:
            expected_closes = [dict(
                filename=event["filename"],
                frames_unattempted=event["replay"]["frames_unattempted"],
                send_stop_reason=event["replay"]["send_stop_reason"])
                for event in recomputed_events
                if event["replay"].get("protocol_end_expected") is True]
            if terminal.get("accepted_protocol_closes") != expected_closes:
                raise CoverageError("accepted protocol closes disagree with input evidence")
        # v12: the close inventory must list EVERY mid-input stop, accepted
        # or not, and match the archived per-input evidence exactly — an
        # acceptance widening can no longer make problem inputs disappear.
        # v13: each entry additionally carries retried_close, the recorded
        # load-truncation retry flag. The flag is measurement-process
        # metadata (the retry is judged by the same acceptance policy and
        # cannot widen acceptance); it is read from the recorded per-input
        # event, not recomputed, because a successful retry leaves no
        # distinguishing trace in the session artifacts by design.
        if manifest.get("replay_harness_version") in FRAME_AUDIT_HARNESS_VERSIONS[10:]:
            _inventory_with_retry = (
                manifest.get("replay_harness_version") == FRAME_AUDIT_HARNESS_VERSIONS[-1])
            expected_inventory = [dict(
                idx=index, filename=event["filename"],
                stop_reason=event["replay"].get("send_stop_reason"),
                peer_closed=event["replay"].get("peer_closed"),
                close_initiator=event["replay"].get("close_initiator"),
                close_kind=event["replay"].get("close_kind"),
                last_reply_code=event["replay"].get("last_reply_code"),
                last_reply_terminated=event["replay"].get("last_reply_terminated"),
                frames_unattempted=event["replay"].get("frames_unattempted"),
                accepted=(event["replay"].get("protocol_end_expected") is True or
                          event["replay"].get("bftpd_protocol_end_expected") is True),
                accepted_by=(replay_policy or {}).get("name")
                if (event["replay"].get("protocol_end_expected") is True or
                    event["replay"].get("bftpd_protocol_end_expected") is True) else None,
                incomplete_reasons=event["replay"].get("incomplete_reasons"),
                **({"retried_close": bool(event.get("replay_retry_attempted"))}
                   if _inventory_with_retry else {}))
                for index, event in enumerate(recomputed_events, 1)
                if event["replay"].get("send_stop_reason") not in ("eof", None)]
            inventory_file = directory / "protocol-close-inventory.json"
            recorded = terminal.get("protocol_close_inventory")
            if (recorded != expected_inventory or not inventory_file.is_file() or
                    canonical(json.loads(inventory_file.read_text())) != canonical(
                        dict(schema_version="protocol-close-inventory-v1",
                             n_closes=len(expected_inventory),
                             n_accepted=sum(1 for row in expected_inventory
                                            if row["accepted"]),
                             policy=(replay_policy or {}).get("name"),
                             entries=expected_inventory))):
                raise CoverageError("protocol close inventory disagrees with input evidence")
        recomputed_complete = (not any(replay_incompleteness(event.get("replay", {}))
                                       for event in recomputed_events)
                               and not terminal.get("n_unreplayable_ledger_entries", 0)
                               and all(event.get("reset", {}).get("command_succeeded")
                                       for event in recomputed_events)
                               and not replay_truncated
                               and replay_policy_verified_for_completeness(
                                   manifest.get("target"), replay_policy, root,
                                   manifest.get("object_root"))
                               and (manifest.get("target") != "pure-ftpd" or
                                    pureftpd_policy_audit_verified)
                               and (manifest.get("target") != "proftpd" or
                                    proftpd_policy_audit_verified))
        if terminal["coverage_complete"] is not bool(recomputed_complete):
            raise CoverageError("terminal completeness disagrees with replay/reset evidence")
    expected_seed_indices = ([i for i, record in enumerate(replay_plan, 1)
                              if record.get("kind") == "initial-queue-name"]
                             if sampled else sorted(union.seed_events))
    if (terminal["covered_branch_ids"] != sorted(map(list, union.covered)) or
            terminal["covered_line_ids"] != sorted(map(list, union.covered_lines)) or
            terminal["n_replayed"] != (len(replay_ledger) if sampled else len(union.events)) or
            terminal.get("seed_covered_branch_ids") != sorted(map(list, union.seed_covered)) or
            terminal.get("seed_covered_line_ids") != sorted(map(list, union.seed_covered_lines)) or
            terminal.get("seed_replay_indices") != expected_seed_indices or
            terminal.get("n_seed_replayed") != len(expected_seed_indices)):
        raise CoverageError("terminal aggregate disagrees with cumulative branch-ID union")
    if sampled:
        expected_witnesses = [dict(idx=record["idx"], filename=record["filename"],
                                   input_sha256=record["input_sha256"],
                                   checkpoint=record["checkpoint"],
                                   snapshot_sha256=record.get("snapshot_sha256"))
                             for record in replay_ledger]
        if (terminal.get("schema_version") != SAMPLED_SCHEMA or
                terminal.get("coverage_capture_mode") != "sampled-step-plus-terminal" or
                terminal.get("sampled_checkpoint_input_indices") != sorted(expected_samples) or
                terminal.get("n_coverage_checkpoints") != len(saved_events) or
                terminal.get("executed_input_witnesses") != expected_witnesses):
            raise CoverageError("sampled terminal metadata disagrees with replay ledger")
    audit_result = audit_csv(output, manifest, union.events)
    if bftpd_policy_audit is not None:
        reason_counts = {}
        for event in bftpd_policy_audit["events"]:
            for reason in event["replay"]["incomplete_reasons"]:
                reason_counts[reason] = reason_counts.get(reason, 0) + 1
        audit_result["bftpd_replay_audit"] = {
            key: bftpd_policy_audit[key]
            for key in ("legacy_reclassification", "legacy_reply_classification",
                        "n_inputs", "n_reclassified_inputs",
                        "n_incomplete_inputs", "n_complete_inputs")}
        audit_result["bftpd_replay_audit"]["incomplete_reason_counts"] = reason_counts
    return audit_result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    replay = sub.add_parser("replay")
    replay.add_argument("--target", required=True, choices=("lightftp", "lighttpd1", "forked-daapd", "bftpd", "kamailio", "exim", "proftpd", "pure-ftpd", "live555"))
    replay.add_argument("--folder", required=True, type=Path)
    replay.add_argument("--port", required=True, type=int)
    replay.add_argument("--step", required=True, type=int)
    replay.add_argument("--sampled-checkpoints", action="store_true",
                        help="opt in to v5 gcda-accumulating checkpoint snapshots; every input is still replayed and audited")
    replay.add_argument("--smoke", action="store_true",
                        help="mark this as a diagnostic smoke run; required when replay input truncation is enabled")
    replay.add_argument("--max-replay-inputs", type=int,
                        help="smoke-only cap on corpus inputs to replay; capped runs are always incomplete")
    replay.add_argument("--output", required=True, type=Path)
    replay.add_argument("--mode", required=True, type=int, choices=(0, 1))
    replay.add_argument("--gcovr", default="gcovr")
    replay.add_argument("--require-coordinates", action="store_true")
    replay.add_argument("--allow-unverified-reset", action="store_true")
    replay.add_argument("--allow-incomplete", action="store_true",
                        help="diagnostic lower-bound union only; terminal remains incomplete")
    audit = sub.add_parser("audit")
    audit.add_argument("output", type=Path)
    audit.add_argument("--source-root", type=Path)
    audit.add_argument("--replay-input-root", type=Path,
                       help="corpus directory for archived plans whose recorded absolute input paths are unavailable")
    args = parser.parse_args(argv)
    existing_output = (args.command == "replay" and
                       (args.output.exists() or
                        Path(str(args.output) + LEGACY_ARTIFACT_SUFFIX).exists() or
                        Path(str(args.output) + SAMPLED_ARTIFACT_SUFFIX).exists()))
    try:
        if args.command == "audit":
            print(json.dumps(audit_artifacts(args.output, args.source_root,
                                             args.replay_input_root), sort_keys=True))
            return 0
        return run_replay(args)
    except (CoverageError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        if args.command == "replay" and not existing_output:
            suffix = (SAMPLED_ARTIFACT_SUFFIX
                      if getattr(args, "sampled_checkpoints", False)
                      else LEGACY_ARTIFACT_SUFFIX)
            directory = Path(str(args.output.resolve()) + suffix)
            if directory.is_dir():
                write_json(directory / "incomplete.json", dict(coverage_complete=False,
                           failure=str(error), measurement="incomplete corpus replay; do not use as a complete endpoint"))
        print("coverage-v4: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
