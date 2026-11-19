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
    CHATAFL_PV_EARLY_STOP CHATAFL_REQUEST_GATE CHATAFL_STATE_RETAIN
    CHATAFL_Q1_DIRECT_SERVICE CHATAFL_Q1_NO_REFLOW CHATAFL_Q1_REFLOW
    CHATAFL_CALIBRATION CHATAFL_STATE_SELECT
    CHATAFL_ADMISSION_MODE CHATAFL_PROVISIONAL CHATAFL_SHADOW
    CHATAFL_ORDINARY_EDF
)

monitor_ablation_stat() {
    awk -F: -v keys="$2" '
        BEGIN {
            count=split(keys, names, /[[:space:]]+/)
            for (i=1; i<=count; i++) if (names[i] != "") wanted[names[i]]=1
        }
        { name=$1; gsub(/^[[:space:]]+|[[:space:]]+$/, "", name) }
        name in wanted {
            value=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            if (value == "-" || value == "") next
            if (value == "true") value="1"
            if (value == "false") value="0"
            print value; exit
        }
    ' <<< "$1"
}

# Resolve a named runtime field (including aliases), then the fuzzer's launch
# environment, then the legacy positional field.  A runtime zero is a value,
# not a missing field.  Match aliases in blob order so an earlier runtime
# field outranks an appended run-config field regardless of spelling.  Do not
# use event counters as configuration switches.
monitor_ablation_value() {
    local stats="$1" env="$2" value
    value=$(monitor_ablation_stat "$stats" "$3")
    if [[ -n "$value" ]]; then
        printf '%s\n' "$value"
        return 0
    fi
    if [[ -n "$4" ]] && value=$(monitor_ablation_env "$env" "$4"); then
        printf '%s\n' "$value"
    else
        printf '%s\n' "${5:-}"
    fi
}

monitor_ablation_enabled() {
    [[ -n "$1" && "$1" != "0" && "$1" != "-" ]]
}

monitor_ablation_calibration() {
    local arm="$1" calibration="$2" stats="$3" env="$4" fallback="${5:-0}"
    case "$calibration" in
        true) echo 1; return 0 ;;
        false) echo 0; return 0 ;;
        0|1) printf '%s\n' "$calibration"; return 0 ;;
    esac
    calibration=$(monitor_ablation_stat "$stats" calibration)
    if [[ -n "$calibration" ]]; then printf '%s\n' "$calibration"; return 0; fi
    case "$arm" in
        loopfuzz-gated-calibrated) echo 1; return 0 ;;
        loopfuzz-gated-fixed|loopfuzz-direct|loopfuzz-native-retention) echo 0; return 0 ;;
    esac
    calibration=$(monitor_ablation_value "" "$env" "" CHATAFL_CALIBRATION "$fallback")
    if monitor_ablation_enabled "$calibration"; then echo 1; else echo 0; fi
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
# runtime stats (u_policy_name / no_llm_mode / llm_trigger_policy) outrank env where
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

    local v threshold
    # These N-suffixed variants use a fixed threshold.  An explicit runtime
    # adaptive setting must not be relabeled from a stale fixed launch flag.
    v=$(monitor_ablation_stat "$stats" no_adaptive)
    [[ "$v" == "0" ]] && return 1
    threshold=$(monitor_ablation_value "$stats" "$env" "plateau_threshold threshold_resolved" \
        CHATAFL_ABLATION_THRESHOLD "${values[8]:-8}")
    # Preserve the original threshold-8 component labels for old callers that
    # supply no threshold; fixed runtime/launch thresholds always take priority.
    [[ "$threshold" =~ ^[1-9][0-9]*$ ]] || threshold=8
    cal=$(monitor_ablation_calibration "$arm" "$cal" "$stats" "$env" "${values[6]:-0}")

    # nollmN outranks every other axis: the whole LLM stack is off.
    v=$(monitor_ablation_value "$stats" "$env" "no_llm_mode no_llm" CHATAFL_NO_LLM)
    monitor_ablation_enabled "$v" && { echo "nollm${threshold}"; return 0; }

    # LLM component lattice (G=grammar, E=enrichment, P=plateau channels).
    local g=0 e=0 p=0 val
    val=$(monitor_ablation_value "$stats" "$env" no_grammar CHATAFL_NO_GRAMMAR)
    monitor_ablation_enabled "$val" && g=1
    val=$(monitor_ablation_value "$stats" "$env" no_enrich CHATAFL_NO_ENRICH)
    monitor_ablation_enabled "$val" && e=1
    val=$(monitor_ablation_value "$stats" "$env" no_plateau CHATAFL_NO_PLATEAU)
    monitor_ablation_enabled "$val" && p=1
    if (( g || e || p )); then
        if (( g )); then echo "plateauonly${threshold}"; return 0; fi
        if (( e && p )); then echo "gramonly${threshold}"; return 0; fi
        if (( p )); then echo "genrich${threshold}"; return 0; fi
        echo "enrich-dead(grammar-off)"; return 0
    fi

    # U-policy arms (stats u_policy_name is runtime truth).
    v=$(monitor_ablation_value "$stats" "$env" "u_policy_name u_policy" CHATAFL_U_POLICY)
    case "$v" in
        soft)     echo "softu${threshold}";   return 0 ;;
        protocol) echo "protou${threshold}";  return 0 ;;
    esac

    # Q1 strategy arms (2026-11-06): the fate of the validation quota freed by
    # gate rejects.  Runtime q1_policy (run-config projection: direct-service /
    # no-reflow / reflow / none) outranks the launch env, and "none" is a real
    # runtime identity, not a missing field.  MUST run before the generic
    # code_retain check below (q1d = reflow + retain shares retain=1 with
    # code_retainN) and before the wrapped fallback (q1a/b/c share the
    # wrapgate base and would collapse into wrapgateN).
    local q1_kind=""
    v=$(monitor_ablation_stat "$stats" q1_policy)
    if [[ -n "$v" ]]; then
        case "$v" in
            direct-service) q1_kind=a ;;
            no-reflow)      q1_kind=b ;;
            reflow)         q1_kind=c ;;
        esac
    elif monitor_ablation_env "$env" CHATAFL_Q1_DIRECT_SERVICE >/dev/null; then
        q1_kind=a
    elif monitor_ablation_env "$env" CHATAFL_Q1_NO_REFLOW >/dev/null; then
        q1_kind=b
    elif monitor_ablation_env "$env" CHATAFL_Q1_REFLOW >/dev/null; then
        q1_kind=c
    fi
    if [[ "$q1_kind" == "c" ]]; then
        val=$(monitor_ablation_value "$stats" "$env" code_retain CHATAFL_CODE_RETAIN)
        monitor_ablation_enabled "$val" && q1_kind=d
    fi
    # Same strategy-ablation guard as the calibration estimator block below:
    # a q1 base with an explicit wo_* switch is not the canonical paper arm
    # (no_adaptive/threshold are part of the q1 base and never disqualify).
    [[ -n "$q1_kind" && "${values[0]:-0}" == "0" && "${values[1]:-0}" == "0" \
       && "${values[2]:-0}" == "0" && "${values[4]:-0}" == "0" ]] && \
        { echo "q1${q1_kind}${threshold}"; return 0; }

    # CSV#8 fourth U-policy arm: U-fail-but-code-bearing retention channel.
    val=$(monitor_ablation_value "$stats" "$env" code_retain CHATAFL_CODE_RETAIN)
    if monitor_ablation_enabled "$val"; then
        echo "code_retain${threshold}"; return 0
    fi

    # P3 PV early-stop arm (2026-11-09): salvage base + CHATAFL_PV_EARLY_STOP.
    # Must be checked BEFORE the generic salvage/wrapped fallback, otherwise
    # pvstop gets mislabeled as salvageN (they share the salvage=1 signal).
    val=$(monitor_ablation_value "$stats" "$env" pv_early_stop_k CHATAFL_PV_EARLY_STOP)
    if [[ "$val" =~ ^[0-9]+$ ]] && (( 10#$val >= 4 && 10#$val <= 64 )); then
        echo "pvstop${threshold}"; return 0
    fi

    # P2 request-gate arm (2026-11-09): gate base + CHATAFL_REQUEST_GATE.
    val=$(monitor_ablation_value "$stats" "$env" "request_gate_enabled request_gate" CHATAFL_REQUEST_GATE)
    if monitor_ablation_enabled "$val"; then
        echo "reqgate${threshold}"; return 0
    fi

    # S2 state-retain arm (2026-11-05).
    val=$(monitor_ablation_value "$stats" "$env" "state_retain_enabled state_retain" CHATAFL_STATE_RETAIN)
    if monitor_ablation_enabled "$val"; then
        echo "stateretain${threshold}"; return 0
    fi

    # CSV#7 matched ordinary cohort.
    val=$(monitor_ablation_value "$stats" "$env" ordinary_budget CHATAFL_ORDINARY_BUDGET)
    if monitor_ablation_enabled "$val"; then
        val=$(monitor_ablation_value "$stats" "$env" ordinary_edf CHATAFL_ORDINARY_EDF)
        if monitor_ablation_enabled "$val"; then echo "ordedf${threshold}"; else echo "ordmatch${threshold}"; fi
        return 0
    fi

    # CSV#18 trigger arms: claim only when the policy was EXPLICITLY exported
    # (llm_trigger_policy stats defaults to code-stall in every arm).
    if v=$(monitor_ablation_env "$env" CHATAFL_TRIGGER_POLICY); then
        case "$v" in
            response-gap)  echo "trigrg${threshold}"; return 0 ;;
            fixed-interval) echo "trigfi${threshold}"; return 0 ;;
            code-stall)    echo "trigcg${threshold}"; return 0 ;;
        esac
    fi

    # Calibration estimator variants — only on the fixed wrapped base so the
    # legacy paper arms (calibrated / cal_ewma, wrap off) keep their labels.
    v=$(monitor_ablation_value "$stats" "$env" plaintext_wrap_enabled CHATAFL_PLAINTEXT_WRAP)
    local fixed="${values[3]:-0}" salvage retain prov shadow
    val=$(monitor_ablation_stat "$stats" no_adaptive)
    if [[ -n "$val" ]]; then
        fixed="$val"
    elif monitor_ablation_env "$env" CHATAFL_NO_ADAPTIVE >/dev/null; then
        fixed=1
    fi
    salvage=$(monitor_ablation_value "$stats" "$env" salvage_enabled CHATAFL_SALVAGE 0)
    retain=$(monitor_ablation_value "$stats" "$env" code_retain CHATAFL_CODE_RETAIN "${values[13]:-0}")
    prov=$(monitor_ablation_value "$stats" "$env" provisional_enabled CHATAFL_PROVISIONAL "${values[10]:--}")
    shadow=$(monitor_ablation_value "$stats" "$env" shadow_enabled CHATAFL_SHADOW "${values[11]:--}")
    if monitor_ablation_enabled "$v" && [[ "$cal" == "1" && "$fixed" == "1" \
            && "$salvage" == "0" && "$retain" == "0" && "$prov" != "0" && "$shadow" != "0" \
            && "${values[0]:-0}" == "0" && "${values[1]:-0}" == "0" \
            && "${values[2]:-0}" == "0" && "${values[4]:-0}" == "0" ]]; then
        local ssel warmup
        ssel=$(monitor_ablation_value "$stats" "$env" "cal_estimator state_select_override" \
            CHATAFL_STATE_SELECT "${values[12]:--}")
        warmup=$(monitor_ablation_value "$stats" "$env" scheduler_warmup_max_selections CHATAFL_SCHEDULER_WARMUP_MAX)
        case "$ssel" in
            shrink) [[ "$threshold" == "8" && "$warmup" == "16" ]] && { echo "calshrink8"; return 0; }
                    [[ "$threshold" == "8" ]] && { echo "cal_shrink"; return 0; }
                    echo "cal_shrink${threshold}"; return 0 ;;
            ewma)   [[ "$threshold" == "8" && "$warmup" == "16" ]] && { echo "calewma16"; return 0; }
                    echo "cal_ewma${threshold}"; return 0 ;;
            run_rate) echo "cal_run_rate${threshold}"; return 0 ;;
            *)      [[ "$threshold" == "8" && "$warmup" == "16" ]] && { echo "calibrated16"; return 0; }
                    echo "calibrated${threshold}"; return 0 ;;
        esac
    fi
    return 1
}

monitor_resolve_ablation_label() {
    local resolver label
    local arm="${1:-}" calibration="${2:-}" gamma="${3:-}" flags="${4:-NONE}"
    local stats="${5:-}" env="${6:-}" value index key
    local -a values=() defaults=(0 0 0 0 0 0 0 - - - - - - 0)
    read -r -a values <<< "$flags"
    # Missing-value sentinels must not look like a runtime identity.  Also
    # project known runtime axes into the legacy fallback's positional API so
    # stale launch flags cannot re-enable calibration or change admission mode.
    [[ "$arm" == "-" ]] && arm=""
    [[ "$calibration" == "-" ]] && calibration=""
    [[ -z "$arm" ]] && arm=$(monitor_ablation_stat "$stats" arm)
    if [[ -n "$stats" || -n "$env" ]] \
            && [[ "$flags" != "NONE" || -n "$env" || -n "$arm" || "$calibration" == "1" ]]; then
        if [[ "$flags" == "NONE" ]]; then
            values=(0 0 0 0 0 0 0 - - - - - - 0)
        fi
        for index in 1 2 3 4 13; do
            case "$index" in
                1) key=no_refinement ;;
                2) key=no_frontier ;;
                3) key=no_adaptive ;;
                4) key=no_state_prompt ;;
                13) key=code_retain ;;
            esac
            value=$(monitor_ablation_stat "$stats" "$key")
            [[ -n "$value" ]] && values[$index]="$value"
        done
        # hypothesis is a dynamic mode that may turn off after grammar
        # fallback. Only a same-run startup switch identifies its ablation.
        value=$(monitor_ablation_stat "$stats" hypothesis_configured)
        [[ "$value" == "0" ]] && values[0]=1
        [[ "$value" == "1" ]] && values[0]=0
        value=$(monitor_ablation_stat "$stats" provisional_enabled)
        [[ -n "$value" ]] && values[10]="$value"
        value=$(monitor_ablation_stat "$stats" shadow_enabled)
        [[ -n "$value" ]] && values[11]="$value"
        value=$(monitor_ablation_stat "$stats" state_select_override)
        [[ -n "$value" ]] && values[12]="$value"
        value=$(monitor_ablation_value "$stats" "" "plateau_threshold threshold_resolved" "")
        [[ -n "$value" ]] && values[8]="$value"
        calibration=$(monitor_ablation_calibration "$arm" "$calibration" "$stats" "$env" "${values[6]:-0}")
        values[6]="$calibration"
        case "$arm" in
            loopfuzz-direct) values[9]=direct; values[5]=1 ;;
            loopfuzz-gated-fixed|loopfuzz-gated-calibrated) values[9]=gate; values[5]=0 ;;
            loopfuzz-native-retention) values[9]=native; values[5]=0 ;;
            *) value=$(monitor_ablation_value "$stats" "$env" admission_mode CHATAFL_ADMISSION_MODE "${values[9]:--}")
               values[9]="$value" ;;
        esac
        # Fill unset fields when an older nine-field caller supplies stats.
        for index in {0..13}; do
            [[ -v values[$index] ]] || values[$index]="${defaults[$index]}"
        done
        flags="${values[*]}"
    fi
    for resolver in "${MONITOR_ABLATION_RESOLVERS[@]}"; do
        if label=$("$resolver" "$arm" "$calibration" "$gamma" "$flags" "$stats" "$env"); then
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
    setting=$(monitor_ablation_stat "$stats" no_adaptive)
    if [[ -n "$setting" ]]; then
        no_adaptive="$setting"
    elif monitor_ablation_env "$env" CHATAFL_NO_ADAPTIVE >/dev/null; then
        no_adaptive=1
    fi
    [[ "$no_adaptive" == "1" ]] || return 1
    threshold=$(monitor_ablation_value "$stats" "$env" "plateau_threshold threshold_resolved" \
        CHATAFL_ABLATION_THRESHOLD "$threshold_env")
    [[ "$threshold" =~ ^[1-9][0-9]*$ ]] || return 1

    # Runtime identity outranks launch settings; an unknown identity must defer.
    case "$arm" in
        loopfuzz-direct) mode=direct ;;
        loopfuzz-gated-fixed) mode=gate ;;
        loopfuzz-native-retention) mode=native ;;
        "") [[ "$mode" == "-" && "$no_admission" == "1" ]] && mode=direct ;;
        *) return 1 ;;
    esac
    calibration=$(monitor_ablation_calibration "$arm" "$calibration" "$stats" "$env" "$cal_env")
    [[ "$calibration" == "0" && "$retain" == "0" ]] || return 1
    [[ "$no_hyp" == "0" && "$no_refine" == "0" && "$no_frontier" == "0" && "$no_sp" == "0" ]] || return 1

    if [[ "$mode" == "native" && "$salvage" == "0" ]]; then
        family=native
    elif [[ "$mode" == "direct" && "$salvage" == "0" ]]; then
        family=wrapdirect
    elif [[ "$mode" == "gate" && "$prov" != "0" && "$shadow" != "0" ]]; then
        family=wrapgate
        [[ "$salvage" == "1" ]] && family=salvage
    else
        return 1
    fi
    printf '%s%s\n' "$family" "$threshold"
}
