#!/usr/bin/env bash
# Monitor arm extensions: add a resolver and register it before the legacy fallback.
# A resolver prints one label and returns 0 on a match, or returns 1 to defer.
# Arguments: runtime arm/calibration/gamma, legacy flags, stats, whitelisted env.
MONITOR_ABLATION_RESOLVERS=(monitor_resolve_wrapped_arm resolve_ablation_label)
MONITOR_ABLATION_ENV_KEYS=(
    CHATAFL_SALVAGE CHATAFL_PLAINTEXT_WRAP
    CHATAFL_NO_ADAPTIVE CHATAFL_ABLATION_THRESHOLD
)

monitor_ablation_stat() {
    awk -F: -v key="$2" '
        { name=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", name) }
        name == key { value=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value; exit }
    ' <<< "$1"
}

monitor_ablation_env() {
    local line
    while IFS= read -r line; do
        if [[ "$line" == "$2="* ]]; then
            printf '%s\n' "${line#*=}"
            return 0
        fi
    done <<< "$1"
    return 1
}

monitor_resolve_ablation_label() {
    local resolver label
    for resolver in "${MONITOR_ABLATION_RESOLVERS[@]}"; do
        if label=$("$resolver" "$@"); then
            if [[ -n "$label" ]]; then
                printf '%s\n' "$label"
                return 0
            fi
        fi
    done
    return 1
}

# Q1 families share their fixed threshold; no per-threshold/per-arm dispatch cases.
monitor_resolve_wrapped_arm() {
    local arm="$1" calibration="$2" flags="$4" stats="${5:-}" env="${6:-}"
    local -a values=()
    read -r -a values <<< "$flags"
    local no_hyp="${values[0]:-0}" no_refine="${values[1]:-0}"
    local no_frontier="${values[2]:-0}" no_adaptive="${values[3]:-0}"
    local no_sp="${values[4]:-0}" no_admission="${values[5]:-0}"
    local cal_env="${values[6]:-0}" threshold_env="${values[8]:--}"
    local mode="${values[9]:--}" prov="${values[10]:--}"
    local shadow="${values[11]:--}" retain="${values[13]:-0}"
    local wrap salvage threshold setting family

    wrap=$(monitor_ablation_stat "$stats" plaintext_wrap_enabled)
    if [[ -z "$wrap" ]]; then
        setting=$(monitor_ablation_env "$env" CHATAFL_PLAINTEXT_WRAP) || setting=""
        wrap=0
        [[ -n "$setting" && "$setting" != "0" ]] && wrap=1
    fi
    [[ "$wrap" == "1" ]] || return 1

    salvage=$(monitor_ablation_stat "$stats" salvage_enabled)
    if [[ -z "$salvage" ]]; then
        setting=$(monitor_ablation_env "$env" CHATAFL_SALVAGE) || setting=""
        salvage=0
        [[ -n "$setting" && "$setting" != "0" ]] && salvage=1
    fi
    [[ "$salvage" == "0" || "$salvage" == "1" ]] || return 1

    # In the fuzzer NO_ADAPTIVE is enabled by presence, including an empty value.
    if monitor_ablation_env "$env" CHATAFL_NO_ADAPTIVE >/dev/null; then
        no_adaptive=1
    fi
    [[ "$no_adaptive" == "1" ]] || return 1
    threshold=$(monitor_ablation_stat "$stats" plateau_threshold)
    if [[ -z "$threshold" ]]; then
        threshold=$(monitor_ablation_env "$env" CHATAFL_ABLATION_THRESHOLD) || threshold="$threshold_env"
    fi
    [[ "$threshold" =~ ^[1-9][0-9]*$ ]] || return 1

    # Runtime identity outranks launch settings; an unknown identity must defer.
    case "$arm" in
        loopfuzz-direct) mode=direct ;;
        loopfuzz-gated-fixed) mode=gate ;;
        "") [[ "$mode" == "-" && "$no_admission" == "1" ]] && mode=direct ;;
        *) return 1 ;;
    esac
    [[ -n "$calibration" && "$calibration" != "-" ]] || calibration="$cal_env"
    [[ "$calibration" == "0" && "$retain" == "0" ]] || return 1
    [[ "$no_hyp" == "0" && "$no_refine" == "0" && "$no_frontier" == "0" && "$no_sp" == "0" ]] || return 1

    if [[ "$mode" == "direct" && "$salvage" == "0" ]]; then
        family=wrapdirect
    elif [[ "$mode" == "gate" && "$prov" != "0" && "$shadow" != "0" ]]; then
        family=wrapgate
        [[ "$salvage" == "1" ]] && family=salvage
    else
        return 1
    fi
    printf '%s%s\n' "$family" "$threshold"
}
