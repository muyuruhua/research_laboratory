#!/bin/bash

# merge_tar.sh — Merge result tarballs from multiple run directories
#
# Usage:
#   Mode 1 (original): merge_tar.sh <main_dir> <subdir1> [subdir2 ...]
#     Explicitly merge tarballs from subdirs into main_dir, renaming
#     sequentially to avoid conflicts.
#
#   Mode 2 (auto): merge_tar.sh --auto <parent_dir>
#     Scan parent_dir for all results-<target>_<timestamp> subdirectories,
#     group them by target name, merge into the earliest-timestamp directory
#     for each target, then delete the redundant later directories.
#
# Information-preservation contract (2026-10-10 revision):
#   For every merged tarball out-<prefix>_<old>.tar.gz -> out-<prefix>_<new>.tar.gz
#   the merge also
#     * rewrites the appended run_summary.csv rows (source + run columns) to
#       the NEW archive name, so every CSV row keeps matching a real file;
#     * copies .sample_status/<old>.status to <new>.status and rewrites its
#       archive_name= line (preserves status/reason/exit_code/container_id/
#       finished_at, the source of invalid_reason/exit_code/diagnostics_dir
#       for later CSV regeneration);
#     * appends .result_manifest.tsv rows with the archive_name/run columns
#       rewritten.
#   DRY_RUN=1 now performs no mutation at all (it used to merge then skip
#   only the deletion).
#
# Target-to-protocol mapping (for validation/reporting):
#   FTP:  lightftp, bftpd, proftpd, pure-ftpd
#   SMTP: exim
#   RTSP: live555
#   SIP:  kamailio
#   DAAP: forked-daapd
#   HTTP: lighttpd1
#   MQTT: mosquitto

set -e

# ── Protocol map (for display only; merging is name-based) ──────────
declare -A PROTO_MAP=(
    [lightftp]=FTP [bftpd]=FTP [proftpd]=FTP [pure-ftpd]=FTP
    [exim]=SMTP [live555]=RTSP [kamailio]=SIP [forked-daapd]=DAAP
    [lighttpd1]=HTTP [mosquitto]=MQTT
)

# ── Helpers ─────────────────────────────────────────────────────────
log()  { echo "[$(date +%H:%M:%S)] $*"; }
warn() { echo "[$(date +%H:%M:%S)] ⚠ $*" >&2; }
die()  { echo "[$(date +%H:%M:%S)] ✗ $*" >&2; exit 1; }

# Rewrite a .status sidecar for a renamed archive: copy <src> to <dst>
# and replace the archive_name= line with the new name.
copy_status_sidecar() {
    local src_status="$1" dst_status="$2" new_name
    new_name=$(basename "$dst_status" .status)
    sed -e "s|^archive_name=.*|archive_name=${new_name}|" "$src_status" > "$dst_status"
}

# Append manifest rows with archive_name (and run number) rewritten.
# Usage: merge_manifest <src_dir> <dst_dir> <map_file>
# map_file lines: <old_basename>\t<new_basename>
merge_manifest() {
    local src_dir="$1" dst_dir="$2" map_file="$3"
    local src_tsv="$src_dir/.result_manifest.tsv" dst_tsv="$dst_dir/.result_manifest.tsv"
    [ -f "$src_tsv" ] || return 0
    if [ ! -f "$dst_tsv" ]; then
        cp "$src_tsv" "$dst_tsv"
        log "  copied .result_manifest.tsv from $(basename "$src_dir")"
        return 0
    fi
    python3 - "$src_tsv" "$dst_tsv" "$map_file" <<'PY'
import csv, sys
src, dst, map_file = sys.argv[1], sys.argv[2], sys.argv[3]
rename = {}
for line in open(map_file):
    line = line.rstrip("\n")
    if "\t" in line:
        old, new = line.split("\t", 1)
        rename[old] = new
def new_run(name):
    # out-<prefix>_<N>.tar.gz -> N
    import re
    m = re.search(r"_(\d+)\.tar\.gz$", name)
    return str(int(m.group(1))) if m else ""
with open(src, newline="") as f:
    rows = list(csv.reader(f, delimiter="\t"))
if not rows:
    sys.exit(0)
header, body = rows[0], rows[1:]
try:
    arch_i = header.index("archive_name")
except ValueError:
    arch_i = None
run_i = None
for i, h in enumerate(header):
    if h.strip() == "run":
        run_i = i
        break
with open(dst, "a", newline="") as f:
    w = csv.writer(f, delimiter="\t")
    for row in body:
        if arch_i is not None and arch_i < len(row) and row[arch_i] in rename:
            new = rename[row[arch_i]]
            row[arch_i] = new
            if run_i is not None and run_i < len(row):
                row[run_i] = new_run(new)
        w.writerow(row)
PY
    log "  appended manifest rows from $(basename "$src_dir")"
}

# Extract the "max run number" for a given tarball prefix in a directory
# e.g., for out-proftpd-loopfuzz_3.tar.gz → prefix=out-proftpd-loopfuzz, num=3
scan_counters() {
    local dir="$1"
    declare -gA counter=()
    for f in "$dir"/*.tar.gz; do
        [ -e "$f" ] || continue
        local filename prefix num
        filename=$(basename "$f")
        prefix=$(echo "$filename" | sed -E 's/_[0-9]+\.tar\.gz$//')
        num=$(echo "$filename" | sed -E 's/^.*_([0-9]+)\.tar\.gz$/\1/')
        if [[ -z "${counter[$prefix]}" || ${counter[$prefix]} -lt $num ]]; then
            counter[$prefix]=$num
        fi
    done
}

# Copy tarballs from src_dir into dst_dir with sequential renaming.
# Also migrates .sample_status sidecars and .result_manifest rows, and
# records the old->new mapping for the CSV rewrite in merge_summaries.
merge_into() {
    local src_dir="$1" dst_dir="$2"
    [ -d "$src_dir" ] || { warn "skip non-existent: $src_dir"; return 0; }
    [ "$src_dir" == "$dst_dir" ] && return 0

    scan_counters "$dst_dir"

    local map_file
    map_file=$(mktemp /tmp/merge_map.XXXXXX)

    local count=0
    for f in "$src_dir"/*.tar.gz; do
        [ -e "$f" ] || continue
        local filename prefix new_name
        filename=$(basename "$f")
        prefix=$(echo "$filename" | sed -E 's/_[0-9]+\.tar\.gz$//')
        if [[ -z "${counter[$prefix]}" ]]; then
            counter[$prefix]=0
        fi
        counter[$prefix]=$((counter[$prefix] + 1))
        new_name="${prefix}_${counter[$prefix]}.tar.gz"
        cp "$f" "$dst_dir/$new_name"
        printf '%s\t%s\n' "$filename" "$new_name" >> "$map_file"
        # migrate status sidecar
        if [ -f "$src_dir/.sample_status/$filename.status" ]; then
            mkdir -p "$dst_dir/.sample_status"
            copy_status_sidecar "$src_dir/.sample_status/$filename.status" \
                               "$dst_dir/.sample_status/$new_name.status"
        else
            warn "  no status sidecar for $filename (from $(basename "$src_dir"))"
        fi
        count=$((count + 1))
    done

    # migrate manifest rows (no-op when the source has no manifest)
    merge_manifest "$src_dir" "$dst_dir" "$map_file"

    # export the mapping for merge_summaries via a per-pair file list
    MERGE_MAP_FILES+=("$map_file")

    log "  merged $count tarballs from $(basename "$src_dir")"
}

# Merge run_summary.csv files: append source rows with the `source` and
# `run` columns rewritten to the NEW archive names recorded by merge_into.
merge_summaries() {
    local dst_dir="$1"; shift
    local target_csv="$dst_dir/run_summary.csv"

    # If target has no CSV, synthesize one from the first source that has one,
    # applying its rename map (the map for that pair is MERGE_MAP_FILES[0]).
    if [ ! -f "$target_csv" ]; then
        local idx=0
        for src in "$@"; do
            if [ -f "$src/run_summary.csv" ]; then
                python3 - "$src/run_summary.csv" "$target_csv" "${MERGE_MAP_FILES[$idx]}" <<'PY'
import csv, sys, re
src_csv, dst_csv, map_file = sys.argv[1], sys.argv[2], sys.argv[3]
rename = {}
for line in open(map_file):
    line = line.rstrip("\n")
    if "\t" in line:
        old, new = line.split("\t", 1)
        rename[old] = new
def new_run(name):
    m = re.search(r"_(\d+)\.tar\.gz$", name)
    return str(int(m.group(1))) if m else None
with open(src_csv, newline="") as f:
    reader = csv.DictReader(f)
    fields = reader.fieldnames
    rows = list(reader)
with open(dst_csv, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for row in rows:
        old = row.get("source", "")
        if old in rename:
            row["source"] = rename[old]
            nr = new_run(rename[old])
            if nr is not None and "run" in row:
                row["run"] = nr
        w.writerow(row)
PY
                log "  copied run_summary.csv from $(basename "$src") (renamed)"
                break
            fi
            idx=$((idx + 1))
        done
        return 0
    fi

    # Append rows from each source, rewriting source/run per its map.
    local idx=0
    for src in "$@"; do
        if [ -f "$src/run_summary.csv" ]; then
            python3 - "$src/run_summary.csv" "$target_csv" "${MERGE_MAP_FILES[$idx]}" <<'PY'
import csv, sys, re
src_csv, dst_csv, map_file = sys.argv[1], sys.argv[2], sys.argv[3]
rename = {}
for line in open(map_file):
    line = line.rstrip("\n")
    if "\t" in line:
        old, new = line.split("\t", 1)
        rename[old] = new
def new_run(name):
    m = re.search(r"_(\d+)\.tar\.gz$", name)
    return str(int(m.group(1))) if m else None
appended = unmatched = 0
with open(src_csv, newline="") as f:
    reader = csv.DictReader(f)
    fields = reader.fieldnames
    rows = list(reader)
with open(dst_csv, "a", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    for row in rows:
        old = row.get("source", "")
        if old in rename:
            row["source"] = rename[old]
            nr = new_run(rename[old])
            if nr is not None and "run" in row:
                row["run"] = nr
            appended += 1
        else:
            unmatched += 1
        w.writerow(row)
if unmatched:
    sys.stderr.write(f"[merge_tar] WARN: {unmatched} row(s) in {src_csv} had no archive mapping\n")
PY
            log "  appended rows from $(basename "$src")/run_summary.csv (renamed)"
        fi
        idx=$((idx + 1))
    done
}

# ── Mode detection ─────────────────────────────────────────────────
if [ "$1" == "--auto" ]; then
    # ══════════════════════════════════════════════════════════════
    # Mode 2: Auto-merge by target name
    # ══════════════════════════════════════════════════════════════
    PARENT_DIR="$2"
    [ -z "$PARENT_DIR" ] && die "Usage: $0 --auto <parent_dir>"
    [ ! -d "$PARENT_DIR" ] && die "parent dir not found: $PARENT_DIR"

    log "Auto-merge mode: scanning $PARENT_DIR"

    # Discover all results-* directories, extract target name and timestamp
    declare -A target_dirs   # target → space-separated list of "ts dir"
    for d in "$PARENT_DIR"/results-*; do
        [ -d "$d" ] || continue
        dname=$(basename "$d")
        # Parse: results-<target>_<Month>-<DD>_<HH>-<MM>-<SS>
        if [[ "$dname" =~ ^results-(.+)_(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-([0-9]{2})_([0-9]{2})-([0-9]{2})-([0-9]{2})$ ]]; then
            target="${BASH_REMATCH[1]}"
            month="${BASH_REMATCH[2]}"
            day="${BASH_REMATCH[3]}"
            ts="${BASH_REMATCH[4]}${BASH_REMATCH[5]}${BASH_REMATCH[6]}"

            # Convert month name to number for proper sorting
            case "$month" in
                Jan) m=01;; Feb) m=02;; Mar) m=03;; Apr) m=04;;
                May) m=05;; Jun) m=06;; Jul) m=07;; Aug) m=08;;
                Sep) m=09;; Oct) m=10;; Nov) m=11;; Dec) m=12;;
            esac

            # Build sortable timestamp: YYYYMMDDHHMMSS (use current year)
            year=$(date +%Y)
            sortkey="${year}${m}${day}${ts}"
            target_dirs[$target]="${target_dirs[$target]:-} $sortkey|$d"
        elif [[ "$dname" =~ ^results-(.+)_([0-9]{8}T[0-9]{6})$ ]]; then
            # Alternate timestamp format: results-<target>_<YYYYMMDD>T<HHMMSS>
            target="${BASH_REMATCH[1]}"
            sortkey="${BASH_REMATCH[2]}"
            target_dirs[$target]="${target_dirs[$target]:-} $sortkey|$d"
        else
            warn "unrecognized pattern: $dname (skipped)"
        fi
    done

    # Process each target
    for target in "${!target_dirs[@]}"; do
        proto="${PROTO_MAP[$target]:-unknown}"
        log ""
        log "=== Target: $target ($proto) ==="

        # Sort dirs by timestamp (earliest first)
        sorted=$(echo "${target_dirs[$target]}" | tr ' ' '\n' | sort -t'|' -k1,1 | head -n -0)
        # Get the earliest directory (main dir)
        main_dir=""
        others=()
        while IFS='|' read -r sk dir; do
            [ -z "$dir" ] && continue
            if [ -z "$main_dir" ]; then
                main_dir="$dir"
                log "  main (earliest): $(basename "$dir")"
            else
                others+=("$dir")
                log "  to merge: $(basename "$dir")"
            fi
        done <<< "$sorted"

        # Skip if only one directory
        [ ${#others[@]} -eq 0 ] && { log "  only one dir, nothing to merge"; continue; }

        # DRY_RUN performs no mutation at all: report the plan only.
        if [ "${DRY_RUN:-0}" == "1" ]; then
            log "  [DRY RUN] would merge ${#others[@]} dir(s) into $(basename "$main_dir") and delete them"
            continue
        fi

        MERGE_MAP_FILES=()
        # Merge tarballs (+ sidecars + manifests)
        for src in "${others[@]}"; do
            merge_into "$src" "$main_dir"
        done

        # Merge run_summary.csv (with rename-aware row rewriting)
        merge_summaries "$main_dir" "${others[@]}"

        # Clean up map files
        rm -f "${MERGE_MAP_FILES[@]:-/dev/null}"

        # Delete redundant directories only after their CSV rows, status
        # sidecars, and manifest rows have been merged into the main dir.
        for src in "${others[@]}"; do
            rm -rf "$src"
            log "  deleted: $(basename "$src")"
        done

        # Report totals
        total=$(ls "$main_dir"/*.tar.gz 2>/dev/null | wc -l)
        n_status=$(ls "$main_dir"/.sample_status/*.status 2>/dev/null | wc -l)
        n_csv=$(awk 'NR>1' "$main_dir/run_summary.csv" 2>/dev/null | wc -l)
        log "  result: $total tarballs, $n_status status files, $n_csv csv rows in $(basename "$main_dir")"
    done

    log ""
    log "✅ Auto-merge done."

else
    # ══════════════════════════════════════════════════════════════
    # Mode 1: Original explicit merge (or auto-detect single parent dir)
    # ══════════════════════════════════════════════════════════════
    MAIN_DIR="$1"
    shift

    if [ -z "$MAIN_DIR" ]; then
        echo "Usage: $0 <main_dir> <subdir1> [subdir2 ...]"
        echo "       $0 --auto <parent_dir>"
        echo "       $0 <parent_dir>          (auto-detected if it contains results-* subdirs)"
        exit 1
    fi

    [ ! -d "$MAIN_DIR" ] && die "dir not found: $MAIN_DIR"

    # Auto-detect: single argument that is a parent dir containing results-* subdirs
    if [ $# -eq 0 ]; then
        n_results=$(ls -d "$MAIN_DIR"/results-* 2>/dev/null | wc -l)
        n_tarballs=$(ls "$MAIN_DIR"/*.tar.gz 2>/dev/null | wc -l)

        if [ "$n_results" -gt 0 ] && [ "$n_tarballs" -eq 0 ]; then
            # It's a parent directory with results-* subdirs → switch to auto mode
            log "Auto-detected parent dir with $n_results results-* subdirs, switching to auto mode"
            PARENT_DIR="$MAIN_DIR"
            # Re-invoke the auto-merge logic inline (can't re-enter the if-block)
            # Fall through by setting a flag
            AUTO_MODE=1
        else
            die "single dir '$MAIN_DIR' has no results-* subdirs (and is not a main dir with subdirs).\nUsage: $0 <main_dir> <subdir1> [...] or $0 --auto <parent_dir>"
        fi
    fi

    if [ "${AUTO_MODE:-0}" == "1" ]; then
        # ── Inline auto-merge (same logic as --auto mode) ──
        log "Auto-merge mode: scanning $PARENT_DIR"

        declare -A target_dirs
        for d in "$PARENT_DIR"/results-*; do
            [ -d "$d" ] || continue
            dname=$(basename "$d")
            if [[ "$dname" =~ ^results-(.+)_(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-([0-9]{2})_([0-9]{2})-([0-9]{2})-([0-9]{2})$ ]]; then
                target="${BASH_REMATCH[1]}"
                month="${BASH_REMATCH[2]}"
                day="${BASH_REMATCH[3]}"
                ts="${BASH_REMATCH[4]}${BASH_REMATCH[5]}${BASH_REMATCH[6]}"
                case "$month" in
                    Jan) m=01;; Feb) m=02;; Mar) m=03;; Apr) m=04;;
                    May) m=05;; Jun) m=06;; Jul) m=07;; Aug) m=08;;
                    Sep) m=09;; Oct) m=10;; Nov) m=11;; Dec) m=12;;
                esac
                year=$(date +%Y)
                sortkey="${year}${m}${day}${ts}"
                target_dirs[$target]="${target_dirs[$target]:-} $sortkey|$d"
            elif [[ "$dname" =~ ^results-(.+)_([0-9]{8}T[0-9]{6})$ ]]; then
                # Alternate timestamp format: results-<target>_<YYYYMMDD>T<HHMMSS>
                target="${BASH_REMATCH[1]}"
                sortkey="${BASH_REMATCH[2]}"
                target_dirs[$target]="${target_dirs[$target]:-} $sortkey|$d"
            else
                warn "unrecognized pattern: $dname (skipped)"
            fi
        done

        for target in "${!target_dirs[@]}"; do
            proto="${PROTO_MAP[$target]:-unknown}"
            # Try to extract base target name (strip _ablation_ suffix etc.)
            base_target=$(echo "$target" | sed 's/_ablation_.*//;s/_EFF$//')
            proto="${PROTO_MAP[$base_target]:-${PROTO_MAP[$target]:-unknown}}"
            log ""
            log "=== Target: $target ($proto) ==="

            sorted=$(echo "${target_dirs[$target]}" | tr ' ' '\n' | sort -t'|' -k1,1)
            main_dir=""
            others=()
            while IFS='|' read -r sk dir; do
                [ -z "$dir" ] && continue
                if [ -z "$main_dir" ]; then
                    main_dir="$dir"
                    log "  main (earliest): $(basename "$dir")"
                else
                    others+=("$dir")
                    log "  to merge: $(basename "$dir")"
                fi
            done <<< "$sorted"

            [ ${#others[@]} -eq 0 ] && { log "  only one dir, nothing to merge"; continue; }

            # DRY_RUN performs no mutation at all: report the plan only.
            if [ "${DRY_RUN:-0}" == "1" ]; then
                log "  [DRY RUN] would merge ${#others[@]} dir(s) into $(basename "$main_dir") and delete them"
                continue
            fi

            MERGE_MAP_FILES=()
            for src in "${others[@]}"; do
                merge_into "$src" "$main_dir"
            done

            merge_summaries "$main_dir" "${others[@]}"

            rm -f "${MERGE_MAP_FILES[@]:-/dev/null}"

            for src in "${others[@]}"; do
                rm -rf "$src"
                log "  deleted: $(basename "$src")"
            done

            total=$(ls "$main_dir"/*.tar.gz 2>/dev/null | wc -l)
            n_status=$(ls "$main_dir"/.sample_status/*.status 2>/dev/null | wc -l)
            n_csv=$(awk 'NR>1' "$main_dir/run_summary.csv" 2>/dev/null | wc -l)
            log "  result: $total tarballs, $n_status status files, $n_csv csv rows in $(basename "$main_dir")"
        done

        log ""
        log "✅ Auto-merge done."
        exit 0
    fi

    log "Main dir: $MAIN_DIR"
    log "Sub dirs: $*"

    scan_counters "$MAIN_DIR"
    MERGE_MAP_FILES=()
    MERGED_DIRS=()

    for dir in "$@"; do
        [ ! -d "$dir" ] && { warn "skip non-existent: $dir"; continue; }
        [ "$dir" == "$MAIN_DIR" ] && continue

        log "Processing: $dir"
        merge_into "$dir" "$MAIN_DIR"
        MERGED_DIRS+=("$dir")
    done

    # Mode 1 now also merges the CSVs (it used to leave source rows behind).
    # Only actually-merged dirs are passed so the rename maps stay aligned.
    [ ${#MERGED_DIRS[@]} -gt 0 ] && merge_summaries "$MAIN_DIR" "${MERGED_DIRS[@]}"
    rm -f "${MERGE_MAP_FILES[@]:-/dev/null}"

    log "✅ Merge done."
fi
