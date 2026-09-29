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
die()  { echo "[$(date +%H:%H:%M)] ✗ $*" >&2; exit 1; }

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

# Copy tarballs from src_dir into dst_dir with sequential renaming
merge_into() {
    local src_dir="$1" dst_dir="$2"
    [ -d "$src_dir" ] || { warn "skip non-existent: $src_dir"; return 0; }
    [ "$src_dir" == "$dst_dir" ] && return 0

    scan_counters "$dst_dir"

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
        count=$((count + 1))
    done
    log "  merged $count tarballs from $(basename "$src_dir")"
}

# Merge run_summary.csv files (append non-header rows from sources to target)
merge_summaries() {
    local dst_dir="$1"; shift
    local target_csv="$dst_dir/run_summary.csv"

    # If target has no CSV, copy the first source that has one
    if [ ! -f "$target_csv" ]; then
        for src in "$@"; do
            if [ -f "$src/run_summary.csv" ]; then
                cp "$src/run_summary.csv" "$target_csv"
                log "  copied run_summary.csv from $(basename "$src")"
                break
            fi
        done
        return 0
    fi

    # Append rows from each source (skip header)
    for src in "$@"; do
        if [ -f "$src/run_summary.csv" ]; then
            # Skip header, append
            tail -n +2 "$src/run_summary.csv" >> "$target_csv" 2>/dev/null || true
            log "  appended rows from $(basename "$src")/run_summary.csv"
        fi
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

        # Merge tarballs
        for src in "${others[@]}"; do
            merge_into "$src" "$main_dir"
        done

        # Merge run_summary.csv
        merge_summaries "$main_dir" "${others[@]}"

        # Delete redundant directories (ask for confirmation in dry-run mode)
        if [ "${DRY_RUN:-0}" == "1" ]; then
            log "  [DRY RUN] would delete: ${others[*]}"
        else
            for src in "${others[@]}"; do
                rm -rf "$src"
                log "  deleted: $(basename "$src")"
            done
        fi

        # Report totals
        total=$(ls "$main_dir"/*.tar.gz 2>/dev/null | wc -l)
        log "  result: $total tarballs in $(basename "$main_dir")"
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

            for src in "${others[@]}"; do
                merge_into "$src" "$main_dir"
            done

            merge_summaries "$main_dir" "${others[@]}"

            if [ "${DRY_RUN:-0}" == "1" ]; then
                log "  [DRY RUN] would delete: ${others[*]}"
            else
                for src in "${others[@]}"; do
                    rm -rf "$src"
                    log "  deleted: $(basename "$src")"
                done
            fi

            total=$(ls "$main_dir"/*.tar.gz 2>/dev/null | wc -l)
            log "  result: $total tarballs in $(basename "$main_dir")"
        done

        log ""
        log "✅ Auto-merge done."
        exit 0
    fi

    log "Main dir: $MAIN_DIR"
    log "Sub dirs: $*"

    scan_counters "$MAIN_DIR"

    for dir in "$@"; do
        [ ! -d "$dir" ] && { warn "skip non-existent: $dir"; continue; }
        [ "$dir" == "$MAIN_DIR" ] && continue

        log "Processing: $dir"
        merge_into "$dir" "$MAIN_DIR"
    done

    log "✅ Merge done."
fi
