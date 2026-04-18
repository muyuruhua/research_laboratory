#!/bin/bash

set -e

MAIN_DIR="$1"
shift   # 后面全是子目录

if [ -z "$MAIN_DIR" ] || [ $# -eq 0 ]; then
    echo "Usage: $0 <main_dir> <subdir1> [subdir2 ...]"
    exit 1
fi

if [ ! -d "$MAIN_DIR" ]; then
    echo "Error: main dir not found: $MAIN_DIR"
    exit 1
fi

echo "Main dir: $MAIN_DIR"
echo "Sub dirs: $@"

declare -A counter

# ==========================
# Step 1: 初始化主目录编号
# ==========================
for f in "$MAIN_DIR"/*.tar.gz; do
    [ -e "$f" ] || continue

    filename=$(basename "$f")
    prefix=$(echo "$filename" | sed -E 's/_[0-9]+\.tar\.gz$//')
    num=$(echo "$filename" | sed -E 's/^.*_([0-9]+)\.tar\.gz$/\1/')

    if [[ -z "${counter[$prefix]}" || ${counter[$prefix]} -lt $num ]]; then
        counter[$prefix]=$num
    fi
done

# ==========================
# Step 2: 只处理指定目录
# ==========================
for dir in "$@"; do
    if [ ! -d "$dir" ]; then
        echo "Warning: skip non-existent dir $dir"
        continue
    fi

    # 防止把主目录自己又处理一遍
    if [ "$dir" == "$MAIN_DIR" ]; then
        continue
    fi

    echo "Processing: $dir"

    for f in "$dir"/*.tar.gz; do
        [ -e "$f" ] || continue

        filename=$(basename "$f")
        prefix=$(echo "$filename" | sed -E 's/_[0-9]+\.tar\.gz$//')

        if [[ -z "${counter[$prefix]}" ]]; then
            counter[$prefix]=0
        fi

        counter[$prefix]=$((counter[$prefix] + 1))
        new_name="${prefix}_${counter[$prefix]}.tar.gz"

        echo "Copy: $filename -> $new_name"
        cp "$f" "$MAIN_DIR/$new_name"
    done
done

echo "✅ Merge done."