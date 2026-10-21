#!/usr/bin/env python3
"""Source-scoped branch identities and auditable cumulative corpus replay."""

import argparse
import csv
import dataclasses
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import tempfile
import subprocess
import sys
import time

SCHEMA = "loopfuzz-coverage-v4"
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


def scope_manifest(snapshot, notes, gcovr_version, gcov_version):
    value = dict(schema_version=SCHEMA, sources=snapshot.files, gcno=notes,
                 branch_ids=sorted(snapshot.branches), line_ids=sorted(snapshot.lines),
                 gcovr_format=snapshot.format_version, gcovr_version=gcovr_version,
                 gcov_version=gcov_version,
                 branch_identity="relative filename, line_number, branchno/array ordinal",
                 source_resolution=snapshot.resolution)
    value["scope_sha256"] = digest_bytes(canonical(value).encode())
    return value


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
    records.sort(key=lambda r: (r["discovery_time_ms"], r.get("discovery_execution_id", 0), r["filename"]))
    previous = None
    for record in records:
        if previous and coordinates:
            for field in ("discovery_time_ms", "monotonic_ms", "discovery_execution_id"):
                if record[field] < previous[field]:
                    raise CoverageError("nonmonotonic discovery ledger: " + field)
        previous = record
    return records, unreplayable


class CoverageUnion:
    def __init__(self, baseline, manifest):
        if baseline.covered_branches or baseline.covered_lines:
            raise CoverageError("baseline is not reset to zero coverage")
        self.baseline, self.manifest = baseline, manifest
        self.covered, self.covered_lines = set(), set()
        self.previous_snapshot, self.events, self.previous_coordinates = set(), [], None

    def add(self, snapshot, coordinates, raw_sha256, expected_counter_reset=False):
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
        dropped = self.previous_snapshot - snapshot.covered_branches
        event = dict(coordinates)
        event["queue_schema_version"] = event.pop("schema_version", None)
        event.update(schema_version=SCHEMA, idx=len(self.events) + 1,
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


# Some build systems (proftpd, pure-ftpd) record BARE source names in the
# gcno, which gcov can only resolve when run from the directory holding the
# gcno.  For those targets collection runs once per gcno directory and the
# entries are prefixed with the directory path so names stay unique.
SUBDIR_COLLECTION_TARGETS = ("proftpd", "pure-ftpd")


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
        # cov_script runs from live-gcov/testProgs, the server's build dir;
        # gcno there reference sibling trees relatively, resolved through
        # the whole-tree search root.
        return cwd, cwd
    raise CoverageError("unsupported target: " + target)


def source_search_roots(target, cwd, source_root):
    """Extra fingerprint roots for trees whose instrumented sources span
    directories. exim compiles .c copies inside build-Linux-x86_64 but
    #includes headers (with their own inline branch data) from the original
    src tree, which gcovr reports under the same relative names; live555's
    testProgs gcno reference the sibling trees via relative paths."""
    if target == "exim":
        original = Path(cwd).resolve() / "src" / "src"
        return [original] if original.is_dir() and original != Path(source_root) else []
    if target == "live555":
        whole = Path(source_root).resolve().parent
        return [whole] if whole != Path(source_root) else []
    return []


def replay_commands(target, path, port, mode, cwd, workdir):
    replayer = "aflnet-replay" if mode == 1 else "afl-replay"
    protocol = {"lightftp": "FTP", "bftpd": "FTP", "lighttpd1": "HTTP",
                "forked-daapd": "HTTP", "kamailio": "SIP", "exim": "SMTP",
                "proftpd": "FTP", "pure-ftpd": "FTP", "live555": "RTSP"}[target]
    client = [replayer, str(path), protocol, str(port), "1"]
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
        client = [replayer, str(path), "HTTP", str(port), "100", "10000"]
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
        client = [replayer, str(path), "SMTP", str(port), "100"]
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
                  str(workdir / "basic.conf")]
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
                limit="exit zero authenticates command success; command must itself validate reset")


def run_one_replay(target, record, port, mode, cwd, workdir, replay_log, object_root):
    client_command, server_command = replay_commands(target, record["path"], port, mode, cwd, workdir)
    env, remote = os.environ.copy(), None
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
            remote_data = remote / note.relative_to(object_root).with_suffix(".gcda")
            if remote_data.is_file():
                remote_data.unlink()
        env["GCOV_PREFIX"] = str(prefix)
    started, server, client, helper = time.monotonic_ns(), None, None, None
    with Path(replay_log).open("wb") as log:
        try:
            if target == "forked-daapd":
                server = subprocess.Popen(server_command, cwd=cwd, env=env, stdout=log,
                                          stderr=subprocess.STDOUT, start_new_session=True)
                time.sleep(1)
            if target == "kamailio":
                helper = subprocess.Popen(["./run_pjsip"], cwd=cwd, stdout=log,
                                          stderr=subprocess.STDOUT, start_new_session=True)
            client = subprocess.Popen(client_command, cwd=cwd, stdout=log,
                                      stderr=subprocess.STDOUT, start_new_session=True)
            if server is None:
                server = subprocess.Popen(server_command, cwd=cwd, env=env, stdout=log,
                                          stderr=subprocess.STDOUT, start_new_session=True)
            server_code = server.wait(timeout=15)
            client_code = client.wait(timeout=5)
        finally:
            stop_process(client)
            stop_process(server)
            stop_process(helper)
    imported = []
    if remote is not None:
        for source in sorted(remote.rglob("*.gcda")):
            destination = object_root / source.relative_to(remote)
            if not destination.with_suffix(".gcno").is_file():
                raise CoverageError("BFTPD gcda has no corresponding gcno: " + str(source))
            shutil.copy2(source, destination)
            imported.append(source.relative_to(remote).as_posix())
        # A session child that crashes or is killed cannot flush its gcov
        # data (libgcov dumps only on a normal exit), so a crash-input
        # replay legitimately yields an empty import.  It is recorded, not
        # fatal: the union simply gains nothing from this input.
        session_coverage_missing = not imported
    else:
        session_coverage_missing = False
    # A server killed by a signal on a crash-input is a fuzzing FINDING,
    # not a measurement failure: whatever coverage children flushed before
    # the crash is kept and the exit code is recorded.
    server_crashed = server_code is not None and server_code < 0
    # When the server crashes on an input the client may legitimately fail
    # too (connection reset); both are recorded as a crash finding.
    client_aborted_on_crash = server_crashed and client_code != 0
    if ((server_code not in (0, 124) and not server_crashed)
            or (client_code != 0 and not client_aborted_on_crash)):
        raise CoverageError("replay failed: server=%s client=%s; see %s" % (server_code, client_code, replay_log))
    return dict(server_exit_code=server_code, client_exit_code=client_code,
                session_coverage_missing=session_coverage_missing,
                server_crashed=server_crashed,
                replay_elapsed_ns=time.monotonic_ns() - started, imported_gcda=imported,
                client_command=client_command, server_command=server_command)


def run_replay(args):
    folder, output, cwd = args.folder.resolve(), args.output.resolve(), Path.cwd().resolve()
    directory = Path(str(output) + ".v4")
    if output.exists() or directory.exists() or Path(str(output) + ".final").exists():
        raise CoverageError("refusing to overwrite coverage artifacts; select a new output path")
    if args.step < 1:
        raise CoverageError("step must be positive")
    source_root, object_root = profile_paths(args.target, cwd)
    search_roots = source_search_roots(args.target, cwd, source_root)
    workdir = Path(os.environ.get("WORKDIR", str(cwd)))
    coordinates = load_coordinates(folder / "queue-checkpoints.jsonl")
    plan, unreplayable = plan_corpus(folder, args.mode, coordinates, args.require_coordinates)
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
    manifest = scope_manifest(baseline, notes, gcovr_version, gcov_version)
    manifest.update(source_root=str(source_root), object_root=str(object_root), target=args.target,
                    source_search_roots=[str(r) for r in search_roots],
                    zero_baseline_mode=zero_baseline_mode)
    write_json(directory / "scope.json", manifest)
    write_json(directory / "baseline.json", baseline_report)
    union = CoverageUnion(baseline, manifest)
    unexpected_drop = False
    with output.open("x", newline="") as csv_output, (directory / "checkpoints.jsonl").open("x") as events:
        writer = csv.DictWriter(csv_output, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for index, record in enumerate(plan, 1):
            if digest_file(record["path"]) != record["input_sha256"]:
                raise CoverageError("corpus changed after planning: " + record["filename"])
            reset = run_reset(record, cwd, directory / ("reset-%06d.log" % index), args.allow_unverified_reset)
            replay = run_one_replay(args.target, record, args.port, args.mode, cwd, workdir,
                                    directory / ("replay-%06d.log" % index), object_root)
            if instrument_identity(object_root) != notes:
                raise CoverageError("instrumented objects changed during replay")
            report, stderr, _ = collect()
            raw = canonical(report).encode()
            snapshot_path = directory / ("snapshot-%06d.json.gz" % index)
            with gzip.open(snapshot_path, "wb") as snapshot_output:
                snapshot_output.write(raw)
            event = union.add(parse_snapshot(report, source_root, search_roots), record, digest_bytes(raw),
                              expected_counter_reset=args.target == "bftpd")
            event.update(replay=replay, reset=reset, gcovr_stderr=stderr, snapshot_file=snapshot_path.name)
            events.write(canonical(event) + "\n")
            events.flush()
            unexpected_drop |= event["unexpected_nonmonotonic_snapshot"]
            # Every replay enters the union, including rows omitted by step.
            if index % args.step == 0 or index == len(plan):
                writer.writerow(union.csv_row(event))
                csv_output.flush()
    counts = audit_csv(output, manifest, union.events)
    if counts["terminal_branches"] != len(union.covered):
        raise CoverageError("terminal aggregate disagrees with branch-ID union")
    write_json(directory / "terminal.json", dict(
        schema_version=SCHEMA, scope_sha256=manifest["scope_sha256"],
        covered_branch_ids=sorted(union.covered), covered_line_ids=sorted(union.covered_lines),
        n_replayed=len(plan), fixed_execution_coordinates_valid=bool(coordinates),
        n_unreplayable_ledger_entries=len(unreplayable),
        all_reset_commands_succeeded=all(event["reset"]["command_succeeded"] for event in union.events),
        execution_coordinate_unit="fuzzer total_execs, not network requests",
        unexpected_snapshot_decrease=unexpected_drop, csv_audit=counts,
        reset_command=reset_command, reset_stderr=reset_stderr,
        baseline_stderr=baseline_stderr, collection_command=collection_command,
        measurement="cumulative corpus replay branch union, not same-runtime bitmap coverage",
        temporal_limit="queue save time does not establish first branch discovery time"))
    # No synthetic campaign-end row: terminal.json describes the last actual checkpoint.
    if unexpected_drop:
        raise CoverageError("raw snapshot decreased; union preserved, audit requires investigation")
    return 0


def audit_artifacts(output, source_root=None):
    output = Path(output)
    directory = Path(str(output) + ".v4")
    manifest = json.loads((directory / "scope.json").read_text())
    root = source_root or manifest["source_root"]
    # An explicit --source-root relocates the whole tree as a single root;
    # otherwise the recorded multi-root resolution (e.g. exim's build copies
    # plus original headers) is replayed exactly.
    roots = [] if source_root else [Path(p) for p in manifest.get("source_search_roots", [])]
    baseline = parse_snapshot(json.loads((directory / "baseline.json").read_text()), root, roots,
                              allow_empty=bool(manifest.get("zero_baseline_mode")))
    if (baseline.files != manifest["sources"] or
            baseline.resolution != manifest.get("source_resolution", baseline.resolution) or
            sorted(map(list, baseline.branches)) != manifest["branch_ids"] or
            sorted(map(list, baseline.lines)) != manifest["line_ids"]):
        raise CoverageError("baseline identities disagree with pinned scope")
    union = CoverageUnion(baseline, manifest)
    coordinate_fields = ("filename", "campaign_id", "queue_id", "discovery_time_ms", "monotonic_ms",
                         "discovery_execution_id", "coordinate_source")
    with (directory / "checkpoints.jsonl").open() as source:
        for raw in source:
            saved = json.loads(raw)
            snapshot_path = directory / saved["snapshot_file"]
            if snapshot_path.parent.resolve() != directory.resolve():
                raise CoverageError("snapshot path escapes artifact directory")
            with gzip.open(snapshot_path, "rb") as snapshot_source:
                snapshot_bytes = snapshot_source.read()
            if digest_bytes(snapshot_bytes) != saved["snapshot_sha256"]:
                raise CoverageError("snapshot content hash mismatch")
            event = union.add(parse_snapshot(json.loads(snapshot_bytes), root, roots),
                              {key: saved[key] for key in coordinate_fields if key in saved},
                              saved["snapshot_sha256"], saved["expected_counter_reset"])
            for field in ("idx", "scope_sha256", "cumulative_covered_branches", "cumulative_covered_lines",
                          "snapshot_covered_branches", "snapshot_covered_lines", "newly_covered_branch_ids",
                          "dropped_snapshot_branch_ids"):
                if canonical(saved[field]) != canonical(event[field]):
                    raise CoverageError("checkpoint aggregate disagrees with snapshot branch IDs: " + field)
    terminal = json.loads((directory / "terminal.json").read_text())
    if (terminal["covered_branch_ids"] != sorted(map(list, union.covered)) or
            terminal["covered_line_ids"] != sorted(map(list, union.covered_lines)) or
            terminal["n_replayed"] != len(union.events)):
        raise CoverageError("terminal aggregate disagrees with cumulative branch-ID union")
    return audit_csv(output, manifest, union.events)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    replay = sub.add_parser("replay")
    replay.add_argument("--target", required=True, choices=("lightftp", "lighttpd1", "forked-daapd", "bftpd", "kamailio", "exim", "proftpd", "pure-ftpd", "live555"))
    replay.add_argument("--folder", required=True, type=Path)
    replay.add_argument("--port", required=True, type=int)
    replay.add_argument("--step", required=True, type=int)
    replay.add_argument("--output", required=True, type=Path)
    replay.add_argument("--mode", required=True, type=int, choices=(0, 1))
    replay.add_argument("--gcovr", default="gcovr")
    replay.add_argument("--require-coordinates", action="store_true")
    replay.add_argument("--allow-unverified-reset", action="store_true")
    audit = sub.add_parser("audit")
    audit.add_argument("output", type=Path)
    audit.add_argument("--source-root", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            print(json.dumps(audit_artifacts(args.output, args.source_root), sort_keys=True))
            return 0
        return run_replay(args)
    except (CoverageError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print("coverage-v4: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
