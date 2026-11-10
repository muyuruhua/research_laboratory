#!/usr/bin/env bash
# Monitor arm extensions: add a resolver and register it before the legacy fallback.
# A resolver prints one label and returns 0 on a match, or returns 1 to defer.
# Arguments: runtime arm/calibration/gamma, legacy flags, stats, whitelisted env.
# monitor_resolve_predicate_shadow_arm MUST precede monitor_resolve_wrapped_arm:
# the P0-9/P0-21 arms share wrap+gate+threshold with wrapgateN/salvageN and would
# otherwise be collapsed into those coarser labels by the family resolver.
MONITOR_ABLATION_RESOLVERS=(monitor_resolve_new_arms monitor_resolve_predicate_shadow_arm monitor_resolve_wrapped_arm resolve_ablation_label)
MONITOR_ABLATION_ENV_KEYS=(
    CHATAFL_SALVAGE CHATAFL_PLAINTEXT_WRAP
    CHATAFL_NO_ADAPTIVE CHATAFL_ABLATION_THRESHOLD
    CHATAFL_ADMIT_NO_P CHATAFL_ADMIT_NO_U CHATAFL_ADMIT_NO_R
    CHATAFL_ADMIT_NO_GCODE CHATAFL_ADMIT_NO_GSTATE
    CHATAFL_SHADOW_SAMPLE
    CHATAFL_SALVAGE_PROBE_GATE
    CHATAFL_NO_LLM CHATAFL_NO_GRAMMAR CHATAFL_NO_ENRICH CHATAFL_NO_PLATEAU
    CHATAFL_U_POLICY CHATAFL_ORDINARY_BUDGET
    CHATAFL_TRIGGER_POLICY CHATAFL_SCHEDULER_WARMUP_MAX
    CHATAFL_CODE_RETAIN
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

# 2026-11-02 audit/Q-matrix arms (CSV#7/#8/#12/#18/#20).  Axes are env-keyed;
# runtime stats (u_policy_name / no_llm / llm_trigger_policy) outrank env where
# the fuzzer writes them.  MUST run before monitor_resolve_wrapped_arm: these
# arms share the wrapgate8 base and would otherwise be collapsed into
# wrapgate8/calibrated labels (nollm8 was invisible for exactly this reason).
# Component lattice note: enrichment depends on grammar's message-type
# discovery (ledger-proven), so grammar-off implies enrichment-dead.
monitor_resolve_new_arms() {
    local arm="$1" cal="$2" flags="$4" stats="${5:-}" env="${6:-}"
    local -a values=()
    read -r -a values <<< "$flags"
    case "$arm" in
        loopfuzz-gated-fixed|loopfuzz-gated-calibrated) ;;
        "") [[ "${values[9]:--}" == "gate" ]] || return 1 ;;
        *) return 1 ;;
    esac

    local v
    # nollm8 outranks every other axis: the whole LLM stack is off.
    v=$(monitor_ablation_stat "$stats" no_llm)
    if [[ "$v" != "1" ]]; then
        if v=$(monitor_ablation_env "$env" CHATAFL_NO_LLM) && [[ "$v" == "1" ]]; then v=1; fi
    fi
    [[ "$v" == "1" ]] && { echo "nollm8"; return 0; }

    # LLM component lattice (G=grammar, E=enrichment, P=plateau channels).
    local g=0 e=0 p=0 val
    if val=$(monitor_ablation_env "$env" CHATAFL_NO_GRAMMAR) && [[ "$val" != "0" ]]; then g=1; fi
    if val=$(monitor_ablation_env "$env" CHATAFL_NO_ENRICH)   && [[ "$val" != "0" ]]; then e=1; fi
    if val=$(monitor_ablation_env "$env" CHATAFL_NO_PLATEAU)  && [[ "$val" != "0" ]]; then p=1; fi
    if (( g || e || p )); then
        if (( g )); then echo "plateauonly8"; return 0; fi
        if (( e && p )); then echo "gramonly8"; return 0; fi
        if (( p )); then echo "genrich8"; return 0; fi
        echo "enrich-dead(grammar-off)"; return 0
    fi

    # U-policy arms (stats u_policy_name is runtime truth).
    v=$(monitor_ablation_stat "$stats" u_policy_name)
    [[ -z "$v" ]] && { v=$(monitor_ablation_env "$env" CHATAFL_U_POLICY) || v=""; }
    case "$v" in
        soft)     echo "softu8";   return 0 ;;
        protocol) echo "protou8";  return 0 ;;
    esac

    # CSV#8 fourth U-policy arm: U-fail-but-code-bearing retention channel.
    if val=$(monitor_ablation_env "$env" CHATAFL_CODE_RETAIN) && [[ "$val" != "0" ]]; then
        echo "code_retain8"; return 0
    fi

    # P3 PV early-stop arm (2026-11-09): salvage base + CHATAFL_PV_EARLY_STOP.
    # Must be checked BEFORE the generic salvage/wrapped fallback, otherwise
    # pvstop gets mislabeled as salvageN (they share the salvage=1 signal).
    if val=$(monitor_ablation_env "$env" CHATAFL_PV_EARLY_STOP) && [[ "$val" != "0" ]]; then
        local thr="$(monitor_ablation_stat "$stats" plateau_threshold)"
        [[ -z "$thr" ]] && thr="$(monitor_ablation_env "$env" CHATAFL_ABLATION_THRESHOLD)" || thr="$thr"
        [[ -z "$thr" ]] && thr="8"
        echo "pvstop${thr}"; return 0
    fi

    # P2 request-gate arm (2026-11-09): gate base + CHATAFL_REQUEST_GATE.
    if val=$(monitor_ablation_env "$env" CHATAFL_REQUEST_GATE) && [[ "$val" != "0" ]]; then
        local thr2="$(monitor_ablation_stat "$stats" plateau_threshold)"
        [[ -z "$thr2" ]] && thr2="$(monitor_ablation_env "$env" CHATAFL_ABLATION_THRESHOLD)" || thr2="$thr2"
        [[ -z "$thr2" ]] && thr2="8"
        echo "reqgate${thr2}"; return 0
    fi

    # S2 state-retain arm (2026-11-05).
    if val=$(monitor_ablation_env "$env" CHATAFL_STATE_RETAIN) && [[ "$val" != "0" ]]; then
        echo "stateretain8"; return 0
    fi

    # CSV#7 matched ordinary cohort.
    if val=$(monitor_ablation_env "$env" CHATAFL_ORDINARY_BUDGET) && [[ "$val" != "0" ]]; then
        echo "ordmatch8"; return 0
    fi

    # CSV#18 trigger arms: claim only when the policy was EXPLICITLY exported
    # (llm_trigger_policy stats defaults to code-stall in every arm).
    if v=$(monitor_ablation_env "$env" CHATAFL_TRIGGER_POLICY); then
        case "$v" in
            response-gap)  echo "trigrg8"; return 0 ;;
            fixed-interval) echo "trigfi8"; return 0 ;;
            code-stall)    echo "trigcg8"; return 0 ;;
        esac
    fi

    # Calibration estimator variants — only on the wrapgate8 base so the
    # legacy paper arms (calibrated / cal_ewma, wrap off) keep their labels.
    v=$(monitor_ablation_stat "$stats" plaintext_wrap_enabled)
    if [[ "$v" == "1" && "$cal" == "1" ]]; then
        local ssel="${values[12]:--}" warmup=""
        if v=$(monitor_ablation_env "$env" CHATAFL_STATE_SELECT); then ssel="$v"; fi
        if v=$(monitor_ablation_env "$env" CHATAFL_SCHEDULER_WARMUP_MAX); then warmup="$v"; fi
        case "$ssel" in
            shrink) [[ "$warmup" == "16" ]] && { echo "calshrink8"; return 0; }
                    echo "cal_shrink";  return 0 ;;
            ewma)   [[ "$warmup" == "16" ]] && { echo "calewma16"; return 0; }
                    echo "cal_ewma8";   return 0 ;;
            *)      [[ "$warmup" == "16" ]] && { echo "calibrated16"; return 0; }
                    echo "calibrated8"; return 0 ;;
        esac
    fi
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

# P0-9/P0-21 arms (2026-10-29), labels identical to run_ablation.sh group names:
#   lop8/lou8/lor8/logc8/logs8  leave-one-out predicate arms (gate + exactly one
#                               CHATAFL_ADMIT_NO_* axis; suffix from the live
#                               threshold, so lopN for other N needs no edit here)
#   shadowrandN                 salvage arm + CHATAFL_SHADOW_SAMPLE=random
# Axes are env-only (fuzzer_stats carries no per-predicate/shadow-sample fields);
# threshold and salvage still prefer fuzzer_stats runtime truth, env as fallback.
monitor_resolve_predicate_shadow_arm() {
    local arm="$1" flags="$4" stats="${5:-}" env="${6:-}"
    local -a values=()
    read -r -a values <<< "$flags"
    local threshold_env="${values[8]:--}"
    local threshold salvage sample predicate n_pred

    case "$arm" in
        loopfuzz-gated-fixed) ;;
        # Startup window (fuzzer_stats not yet written -> arm empty): fall
        # back to launch-env-only resolution, mirroring the empty-arm
        # fallback of monitor_resolve_wrapped_arm.  Without this the three
        # env-keyed arms (lo*/shadowrand/salvagepg) are mislabeled as
        # wrapgate8/salvage8 for the first minutes of each container.
        "") [[ "${values[9]:--}" == "gate" ]] || return 1 ;;
        *) return 1 ;;
    esac

    threshold=$(monitor_ablation_stat "$stats" plateau_threshold)
    if [[ -z "$threshold" ]]; then
        threshold=$(monitor_ablation_env "$env" CHATAFL_ABLATION_THRESHOLD) || threshold="$threshold_env"
    fi
    [[ "$threshold" =~ ^[1-9][0-9]*$ ]] || return 1

    predicate=""; n_pred=0
    monitor_ablation_env "$env" CHATAFL_ADMIT_NO_P      >/dev/null && { predicate="p";  n_pred=$((n_pred+1)); }
    monitor_ablation_env "$env" CHATAFL_ADMIT_NO_U      >/dev/null && { predicate="u";  n_pred=$((n_pred+1)); }
    monitor_ablation_env "$env" CHATAFL_ADMIT_NO_R      >/dev/null && { predicate="r";  n_pred=$((n_pred+1)); }
    monitor_ablation_env "$env" CHATAFL_ADMIT_NO_GCODE  >/dev/null && { predicate="gc"; n_pred=$((n_pred+1)); }
    monitor_ablation_env "$env" CHATAFL_ADMIT_NO_GSTATE >/dev/null && { predicate="gs"; n_pred=$((n_pred+1)); }
    if [[ "$n_pred" -eq 1 ]]; then
        printf 'lo%s%s\n' "$predicate" "$threshold"
        return 0
    fi
    [[ "$n_pred" -eq 0 ]] || return 1

    # salvagepgN: salvage + probe-gate (L1/L2 fix arm, 2026-10-30)
    if monitor_ablation_env "$env" CHATAFL_SALVAGE_PROBE_GATE >/dev/null; then
        printf 'salvagepg%s\n' "$threshold"
        return 0
    fi
    sample=$(monitor_ablation_env "$env" CHATAFL_SHADOW_SAMPLE) || sample=""
    [[ "$sample" == "random" ]] || return 1
    salvage=$(monitor_ablation_stat "$stats" salvage_enabled)
    if [[ -z "$salvage" ]]; then
        salvage=$(monitor_ablation_env "$env" CHATAFL_SALVAGE) || salvage=""
    fi
    [[ "$salvage" == "1" ]] || return 1
    printf 'shadowrand%s\n' "$threshold"
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
