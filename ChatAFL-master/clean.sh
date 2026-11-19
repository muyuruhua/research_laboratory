#!/bin/bash
set -euo pipefail

subjects=(lightftp bftpd proftpd pure-ftpd exim live555 kamailio forked-daapd lighttpd1 mosquitto proftpd-state-machines pure-ftpd-state-machines exim-state-machines live555-state-machines kamailio-state-machines forked-daapd-state-machines)

if ! docker info >/dev/null 2>&1; then
    echo "Docker is unavailable; no containers or images were removed." >&2
    exit 1
fi

# Check every subject before deleting anything, so a cleanup cannot leave an
# active campaign partially removed.
running=()
for subject in "${subjects[@]}"; do
    if ! ids=$(docker ps --quiet --no-trunc --filter "ancestor=${subject}:latest"); then
        echo "Cannot check running containers for ${subject}; no containers or images were removed." >&2
        exit 1
    fi
    while IFS= read -r id; do
        [[ -n "$id" ]] && running+=("${subject}:${id}")
    done <<< "$ids"
done

if (( ${#running[@]} > 0 )); then
    printf 'Refusing cleanup: %d subject container(s) are still running:\n' "${#running[@]}" >&2
    printf '  %s\n' "${running[@]}" >&2
    echo 'Wait for result collection and coverage audit before cleaning up.' >&2
    exit 1
fi

for subject in "${subjects[@]}"; do
    if ! ids=$(docker ps --all --quiet --no-trunc --filter "ancestor=${subject}:latest"); then
        echo "Cannot list stopped containers for ${subject}; cleanup stopped." >&2
        exit 1
    fi
    while IFS= read -r id; do
        [[ -n "$id" ]] && docker rm "$id"
    done <<< "$ids"
    docker rmi "${subject}:latest" 2>/dev/null || true
done

echo "Clean complete"
