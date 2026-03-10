#!/bin/bash
# ============================================================================
# monitor.sh — 实时监控运行中容器的覆盖率和状态空间探索
#
# 用法:
#   ./monitor.sh                     # 监控所有运行中的模糊测试容器
#   ./monitor.sh exim                # 只监控 exim 协议的容器
#   ./monitor.sh exim,mosquitto      # 监控多个协议 (逗号分隔)
#   ./monitor.sh exim -i 60          # 监控 exim，每60秒刷新
#   ./monitor.sh -o /tmp/monitor     # 指定输出目录
#   ./monitor.sh -1                  # 只采集一次然后退出
#   ./monitor.sh --csv               # 同时输出CSV文件供后续绘图
#
# 原理:
#   通过 docker exec 只读读取容器内 fuzzer_stats / plot_data / ipsm.dot
#   仅使用 cat / grep / wc 等轻量命令，不影响容器内模糊测试进程
# ============================================================================

set -euo pipefail

# ─── 颜色 ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RST='\033[0m'

# ─── 默认参数 ───────────────────────────────────────────────────────────────
INTERVAL=30
ONCE=0
OUT_DIR=""
CSV_MODE=0
FILTER=""           # 协议过滤器，空=全部

usage() {
    echo "Usage: $0 [PROTOCOL[,PROTOCOL...]] [-i interval_sec] [-o output_dir] [-1] [--csv] [-h]"
    echo ""
    echo "  PROTOCOL   协议名 (exim, mosquitto, pure-ftpd, ...) 多个用逗号分隔"
    echo "             不指定则监控所有运行中的容器"
    echo "  -i SEC     采集间隔秒数 (默认 30)"
    echo "  -o DIR     输出目录 (默认仅终端输出)"
    echo "  -1         单次采集后退出"
    echo "  --csv      同时生成CSV时间序列文件"
    echo "  -h         显示帮助"
    echo ""
    echo "Examples:"
    echo "  $0                     # 监控全部"
    echo "  $0 exim                # 只看 exim"
    echo "  $0 exim,mosquitto -1   # 看 exim 和 mosquitto，单次"
    echo "  $0 exim -i 60 --csv    # exim，60s间隔，输出CSV"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i)   INTERVAL="$2"; shift 2 ;;
        -o)   OUT_DIR="$2"; shift 2 ;;
        -1)   ONCE=1; shift ;;
        --csv) CSV_MODE=1; shift ;;
        -h|--help) usage ;;
        -*) echo "Unknown option: $1"; usage ;;
        *)  # 位置参数 → 协议过滤器
            if [[ -z "$FILTER" ]]; then
                FILTER="$1"
            else
                FILTER="${FILTER},$1"
            fi
            shift ;;
    esac
done

if [[ -n "$OUT_DIR" ]]; then
    mkdir -p "$OUT_DIR"
    CSV_MODE=1  # 指定输出目录时自动启用CSV
fi

# ─── 工具函数 ───────────────────────────────────────────────────────────────

# 从容器中读取 fuzzer_stats 中某个字段的值
# 用法: get_stat <container_id> <stat_file_path> <key>
get_stat() {
    local cid="$1" fpath="$2" key="$3"
    docker exec "$cid" grep -m1 "^${key}" "$fpath" 2>/dev/null \
        | sed 's/.*: *//' | tr -d '[:space:]' || echo "N/A"
}

# 自动探测容器内的 out-* 目录路径
# 支持结构:
#   单层: /home/ubuntu/experiments/out-<target>-<fuzzer>          (mosquitto等)
#   两层: /home/ubuntu/experiments/<target>/out-<target>-<fuzzer> (exim/proftpd等)
#   三层: /home/ubuntu/experiments/<a>/<b>/out-<target>-<fuzzer>  (live555: live/testProgs/out-live555-*)
#   四层: /home/ubuntu/experiments/<a>/<b>/<c>/out-<target>-<fuzzer> (lightftp: LightFTP/Source/Release/out-lightftp-*)
detect_outdir() {
    local cid="$1"
    docker exec "$cid" bash -c '
        d=$(ls -d /home/ubuntu/experiments/*/out-* 2>/dev/null | head -1)
        if [ -z "$d" ]; then
            d=$(ls -d /home/ubuntu/experiments/out-* 2>/dev/null | head -1)
        fi
        if [ -z "$d" ]; then
            d=$(ls -d /home/ubuntu/experiments/*/*/out-* 2>/dev/null | head -1)
        fi
        if [ -z "$d" ]; then
            d=$(ls -d /home/ubuntu/experiments/*/*/*/out-* 2>/dev/null | head -1)
        fi
        echo "$d"
    ' 2>/dev/null || echo ""
}

# 从 out-dir 名称推断 fuzzer 标签
# out-exim-chatafl_opt      → CHATAFL-OPT
# out-pure-ftpd-chatafl_opt → CHATAFL-OPT  (目标名含连字符)
# out-exim-aflnet            → AFLNET
# 方法: 从尾部匹配已知 fuzzer 后缀 (fuzzer 名用下划线, 不会与连字符冲突)
fuzzer_label() {
    local outdir="$1"
    local base rest
    base=$(basename "$outdir")
    rest="${base#out-}"          # 去掉 out- 前缀
    if   [[ "$rest" == *-chatafl_opt ]]; then echo "CHATAFL-OPT"
    elif [[ "$rest" == *-chatafl_cl1 ]]; then echo "CHATAFL-CL1"
    elif [[ "$rest" == *-chatafl_cl2 ]]; then echo "CHATAFL-CL2"
    elif [[ "$rest" == *-chatafl ]];     then echo "CHATAFL"
    elif [[ "$rest" == *-aflnet ]];      then echo "AFLNET"
    else echo "${rest##*-}" | tr '[:lower:]' '[:upper:]'
    fi
}

# 从 out-dir 名称推断 target
# out-exim-chatafl_opt      → exim
# out-pure-ftpd-chatafl_opt → pure-ftpd  (正确保留连字符)
# out-mosquitto-aflnet       → mosquitto
# 方法: 去掉 out- 前缀后, 从尾部剥离已知 fuzzer 后缀, 剩余即为 target
target_label() {
    local outdir="$1"
    local base rest
    base=$(basename "$outdir")
    rest="${base#out-}"
    if   [[ "$rest" == *-chatafl_opt ]]; then echo "${rest%-chatafl_opt}"
    elif [[ "$rest" == *-chatafl_cl1 ]]; then echo "${rest%-chatafl_cl1}"
    elif [[ "$rest" == *-chatafl_cl2 ]]; then echo "${rest%-chatafl_cl2}"
    elif [[ "$rest" == *-chatafl ]];     then echo "${rest%-chatafl}"
    elif [[ "$rest" == *-aflnet ]];      then echo "${rest%-aflnet}"
    else echo "${rest%-*}"
    fi
}

# 从 ipsm.dot 计算节点数和边数 (轻量: 只用 grep -c)
get_ipsm_stats() {
    local cid="$1" dot_path="$2"
    local nodes edges
    nodes=$(docker exec "$cid" grep -c '\[color=blue\]' "$dot_path" 2>/dev/null || echo "0")
    edges=$(docker exec "$cid" grep -c '\->' "$dot_path" 2>/dev/null || echo "0")
    echo "${nodes} ${edges}"
}

# 计算运行时长 (分钟)
calc_runtime_min() {
    local start_ts="$1"
    local now
    now=$(date +%s)
    echo $(( (now - start_ts) / 60 ))
}

# ─── 协议过滤 ───────────────────────────────────────────────────────────────

# 检查 target 是否匹配过滤器
# FILTER 为空 → 全部匹配; 否则 target 必须在逗号分隔列表中
target_matches_filter() {
    local target="$1"
    [[ -z "$FILTER" ]] && return 0  # 无过滤 → 全部通过
    local f
    for f in $(echo "$FILTER" | tr ',' ' '); do
        [[ "$target" == "$f" ]] && return 0
    done
    return 1
}

# ─── 发现所有运行中的模糊测试容器 ──────────────────────────────────────────

discover_containers() {
    local cids=()
    local all_running
    all_running=$(docker ps -q 2>/dev/null)
    
    if [[ -z "$all_running" ]]; then
        echo ""
        return
    fi

    for cid in $all_running; do
        # 检查容器内是否有 out-* 目录 (即正在跑模糊测试)
        local outdir
        outdir=$(detect_outdir "$cid")
        if [[ -n "$outdir" ]]; then
            # 协议过滤
            local t
            t=$(target_label "$outdir")
            if target_matches_filter "$t"; then
                cids+=("$cid")
            fi
        fi
    done
    echo "${cids[*]:-}"
}

# ─── 采集单个容器的数据 ────────────────────────────────────────────────────

collect_one() {
    local cid="$1"
    local outdir
    outdir=$(detect_outdir "$cid")
    
    if [[ -z "$outdir" ]]; then
        return 1
    fi

    local stats_file="${outdir}/fuzzer_stats"
    local dot_file="${outdir}/ipsm.dot"
    local target fuzzer

    target=$(target_label "$outdir")
    fuzzer=$(fuzzer_label "$outdir")

    # 读取 fuzzer_stats (只执行一次 docker exec, 批量 grep)
    local stats_blob
    stats_blob=$(docker exec "$cid" cat "$stats_file" 2>/dev/null || echo "")
    
    if [[ -z "$stats_blob" ]]; then
        return 1
    fi

    # 解析关键字段
    local start_time bitmap paths_total paths_favored execs_done execs_per_sec
    local unique_crashes unique_hangs cycles_done pending_total stability
    local chat_times llm_total_calls llm_prompt_tokens llm_completion_tok
    local hyp_count hyp_fitness plateau_calls plateau_threshold

    start_time=$(echo "$stats_blob"    | grep -m1 '^start_time'        | sed 's/.*: *//' | tr -d '[:space:]')
    bitmap=$(echo "$stats_blob"        | grep -m1 '^bitmap_cvg'        | sed 's/.*: *//' | tr -d '[:space:]')
    paths_total=$(echo "$stats_blob"   | grep -m1 '^paths_total'       | sed 's/.*: *//' | tr -d '[:space:]')
    paths_favored=$(echo "$stats_blob" | grep -m1 '^paths_favored'     | sed 's/.*: *//' | tr -d '[:space:]')
    execs_done=$(echo "$stats_blob"    | grep -m1 '^execs_done'        | sed 's/.*: *//' | tr -d '[:space:]')
    execs_per_sec=$(echo "$stats_blob" | grep -m1 '^execs_per_sec'     | sed 's/.*: *//' | tr -d '[:space:]')
    unique_crashes=$(echo "$stats_blob"| grep -m1 '^unique_crashes'    | sed 's/.*: *//' | tr -d '[:space:]')
    unique_hangs=$(echo "$stats_blob"  | grep -m1 '^unique_hangs'      | sed 's/.*: *//' | tr -d '[:space:]')
    cycles_done=$(echo "$stats_blob"   | grep -m1 '^cycles_done'       | sed 's/.*: *//' | tr -d '[:space:]')
    pending_total=$(echo "$stats_blob" | grep -m1 '^pending_total'     | sed 's/.*: *//' | tr -d '[:space:]')
    stability=$(echo "$stats_blob"     | grep -m1 '^stability'         | sed 's/.*: *//' | tr -d '[:space:]')

    # ChatAFL/Opt 专有字段 (不存在时默认 -)
    chat_times=$(echo "$stats_blob"       | grep -m1 '^plateau_calls'        | sed 's/.*: *//' | tr -d '[:space:]')
    llm_total_calls=$(echo "$stats_blob"  | grep -m1 '^llm_total_calls'      | sed 's/.*: *//' | tr -d '[:space:]')
    llm_prompt_tokens=$(echo "$stats_blob"| grep -m1 '^llm_prompt_tokens'    | sed 's/.*: *//' | tr -d '[:space:]')
    llm_completion_tok=$(echo "$stats_blob"|grep -m1 '^llm_completion_tok'    | sed 's/.*: *//' | tr -d '[:space:]')
    hyp_count=$(echo "$stats_blob"        | grep -m1 '^hypothesis_count'     | sed 's/.*: *//' | tr -d '[:space:]')
    hyp_fitness=$(echo "$stats_blob"      | grep -m1 '^hypothesis_avg_fitness'| sed 's/.*: *//' | tr -d '[:space:]')
    plateau_calls=$(echo "$stats_blob"    | grep -m1 '^plateau_calls'        | sed 's/.*: *//' | tr -d '[:space:]')
    plateau_threshold=$(echo "$stats_blob"| grep -m1 '^plateau_threshold'    | sed 's/.*: *//' | tr -d '[:space:]')

    # 默认值
    chat_times=${chat_times:-"-"}
    llm_total_calls=${llm_total_calls:-"-"}
    llm_prompt_tokens=${llm_prompt_tokens:-"-"}
    llm_completion_tok=${llm_completion_tok:-"-"}
    hyp_count=${hyp_count:-"-"}
    hyp_fitness=${hyp_fitness:-"-"}
    plateau_calls=${plateau_calls:-"-"}
    plateau_threshold=${plateau_threshold:-"-"}

    # Fallback: chatafl baseline has no llm_* in fuzzer_stats → estimate from stall-interactions
    local token_source="-"
    if [[ "$llm_total_calls" == "-" ]]; then
        local _si_dir="${outdir}/stall-interactions"
        local _si_calls
        _si_calls=$(docker exec "$cid" bash -c "ls \"${_si_dir}/prompt-\"* 2>/dev/null | wc -l" 2>/dev/null || echo "0")
        _si_calls="${_si_calls//[^0-9]/}"
        if [[ "${_si_calls:-0}" -gt 0 ]]; then
            local _si_pbytes _si_cbytes
            _si_pbytes=$(docker exec "$cid" bash -c "cat \"${_si_dir}/prompt-\"* 2>/dev/null | wc -c" 2>/dev/null || echo "0")
            _si_cbytes=$(docker exec "$cid" bash -c "cat \"${_si_dir}/response-\"* 2>/dev/null | wc -c" 2>/dev/null || echo "0")
            llm_total_calls="$_si_calls"
            llm_prompt_tokens=$(( ${_si_pbytes//[^0-9]/} / 4 ))
            llm_completion_tok=$(( ${_si_cbytes//[^0-9]/} / 4 ))
            token_source="est"
        fi
    else
        token_source="exact"
    fi

    # IPSM 节点/边
    local ipsm_info nodes edges
    ipsm_info=$(get_ipsm_stats "$cid" "$dot_file")
    nodes=$(echo "$ipsm_info" | awk '{print $1}')
    edges=$(echo "$ipsm_info" | awk '{print $2}')

    # 运行时长
    local runtime_min="?"
    if [[ -n "$start_time" && "$start_time" != "N/A" ]]; then
        runtime_min=$(calc_runtime_min "$start_time")
    fi

    # plot_data 最后一行的时间戳 (用于判断是否还在活跃更新)
    local last_plot_ts
    last_plot_ts=$(docker exec "$cid" tail -1 "${outdir}/plot_data" 2>/dev/null | awk -F',' '{print $1}' | tr -d '[:space:]')
    local last_update_ago="?"
    if [[ -n "$last_plot_ts" && "$last_plot_ts" =~ ^[0-9]+$ ]]; then
        last_update_ago=$(( $(date +%s) - last_plot_ts ))
    fi

    # 输出结构体 (用 | 分隔, 方便后续格式化)
    echo "${cid}|${target}|${fuzzer}|${runtime_min}|${bitmap}|${paths_total}|${paths_favored}|${execs_done}|${execs_per_sec}|${unique_crashes}|${unique_hangs}|${cycles_done}|${pending_total}|${stability}|${nodes}|${edges}|${chat_times}|${llm_total_calls}|${llm_prompt_tokens}|${llm_completion_tok}|${hyp_count}|${hyp_fitness}|${plateau_calls}|${plateau_threshold}|${last_update_ago}|${token_source}"
}

# ─── 格式化输出 ─────────────────────────────────────────────────────────────

print_header() {
    local now
    now=$(date '+%Y-%m-%d %H:%M:%S')
    local count="$1"
    local filter_info="all protocols"
    [[ -n "$FILTER" ]] && filter_info="$FILTER"
    
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════════════════════╗${RST}"
    echo -e "${BOLD}║  📊 Fuzzing Monitor — ${now}  (${count} containers, ${filter_info})${RST}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════════════════════╝${RST}"
}

print_table() {
    local -a data=("$@")
    
    if [[ ${#data[@]} -eq 0 ]]; then
        echo -e "${RED}  No active fuzzing containers found.${RST}"
        return
    fi

    # 按 target 分组 → fuzzer 分组 → T(min) 降序
    # 确保同协议的容器聚在一起，不会被其他协议打断
    local sorted
    sorted=$(printf '%s\n' "${data[@]}" | sort -t'|' -k2,2 -k3,3 -k4,4rn)

    local prev_target=""

    while IFS='|' read -r cid target fuzzer runtime bitmap paths_total paths_fav execs execs_sec \
                          crashes hangs cycles pending stab nodes edges \
                          chat_t llm_calls llm_ptok llm_ctok hyp_cnt hyp_fit \
                          plat_calls plat_thresh last_upd token_source; do
        
        # 新 target 分组
        if [[ "$target" != "$prev_target" ]]; then
            prev_target="$target"
            echo ""
            echo -e "${CYAN}${BOLD}  ┌─ ${target^^} ─────────────────────────────────────────────────────────────────┐${RST}"
            printf "  ${DIM}%-14s %-12s %6s %8s %7s %6s %8s %5s %5s %5s %6s %6s${RST}\n" \
                "FUZZER" "CID" "T(min)" "Bitmap" "Paths" "Favrd" "Execs" "Exec/s" "Crash" "Hangs" "Nodes" "Edges"
            echo -e "  ${DIM}$(printf '─%.0s' {1..110})${RST}"
        fi

        # 颜色选择
        local fc="$RST"
        case "$fuzzer" in
            CHATAFL-OPT) fc="$GREEN" ;;
            CHATAFL*)    fc="$YELLOW" ;;
            AFLNET)      fc="$CYAN" ;;
        esac

        # 活跃状态指示
        local alive_mark="●"
        if [[ "$last_upd" =~ ^[0-9]+$ ]] && (( last_upd > 120 )); then
            alive_mark="○"  # 超过2分钟没更新
        fi

        printf "  ${fc}%-14s${RST} %-12s %6s %8s %7s %6s %8s %5s %5s %5s %6s %6s  %s\n" \
            "$fuzzer" "${cid:0:12}" "$runtime" "$bitmap" "$paths_total" "$paths_fav" \
            "$execs" "$execs_sec" "$crashes" "$hangs" "$nodes" "$edges" "$alive_mark"

    done <<< "$sorted"

    echo ""

    # ─── LLM 专有指标 (仅对有 LLM 的 fuzzer 显示) ────────────────────
    local has_llm=0
    while IFS='|' read -r cid target fuzzer runtime bitmap paths_total paths_fav execs execs_sec \
                          crashes hangs cycles pending stab nodes edges \
                          chat_t llm_calls llm_ptok llm_ctok hyp_cnt hyp_fit \
                          plat_calls plat_thresh last_upd token_source; do
        if [[ "$llm_calls" != "-" && -n "$llm_calls" ]]; then
            has_llm=1
            break
        fi
    done <<< "$sorted"

    if [[ $has_llm -eq 1 ]]; then
        echo -e "${BOLD}  🤖 LLM / Token Cost (gpt-4o-mini: \$0.15/1M prompt, \$0.60/1M compl):${RST}"
        printf "  ${DIM}%-14s %-12s %8s %11s %11s %9s %8s %11s %8s %8s %5s${RST}\n" \
            "FUZZER" "CID" "LLM#" "Prompt_Tok" "Compl_Tok" "Cost(\$)" "\$/24h" "Tok/24h" "Plateau" "Fitness" "Src"
        echo -e "  ${DIM}$(printf '─%.0s' {1..122})${RST}"

        while IFS='|' read -r cid target fuzzer runtime bitmap paths_total paths_fav execs execs_sec \
                              crashes hangs cycles pending stab nodes edges \
                              chat_t llm_calls llm_ptok llm_ctok hyp_cnt hyp_fit \
                              plat_calls plat_thresh last_upd token_source; do
            
            [[ "$llm_calls" == "-" || -z "$llm_calls" ]] && continue

            local fc="$RST"
            case "$fuzzer" in
                CHATAFL-OPT) fc="$GREEN" ;;
                CHATAFL*)    fc="$YELLOW" ;;
            esac

            # Cost calculation (gpt-4o-mini pricing)
            local _ptok="${llm_ptok//[^0-9]/}"
            local _ctok="${llm_ctok//[^0-9]/}"
            local _rmin="${runtime//[^0-9]/}"
            local _cost_usd _tok_per_24h _cost_per_24h
            _cost_usd=$(awk "BEGIN{printf \"%.4f\", (${_ptok:-0} * 0.15 + ${_ctok:-0} * 0.60) / 1000000}")
            _tok_per_24h=$(awk "BEGIN{ r=${_rmin:-0}; if(r>0) printf \"%.0f\", (${_ptok:-0}+${_ctok:-0})/r*1440; else print \"-\"}")
            _cost_per_24h=$(awk "BEGIN{ r=${_rmin:-0}; if(r>0) printf \"%.4f\", (${_ptok:-0}*0.15+${_ctok:-0}*0.60)/1000000/r*1440; else print \"-\"}")

            # ~ prefix for estimated (bytes/4) values
            local _disp_ptok="$llm_ptok" _disp_ctok="$llm_ctok"
            [[ "$token_source" == "est" ]] && _disp_ptok="~${llm_ptok}" && _disp_ctok="~${llm_ctok}"

            printf "  ${fc}%-14s${RST} %-12s %8s %11s %11s %9s %8s %11s %8s %8s %5s\n" \
                "$fuzzer" "${cid:0:12}" "$llm_calls" "$_disp_ptok" "$_disp_ctok" \
                "$_cost_usd" "$_cost_per_24h" "$_tok_per_24h" "$plat_calls" "$hyp_fit" "${token_source:--}"

        done <<< "$sorted"
        echo ""
    fi

    # ─── 按 fuzzer 分组的汇总统计 ───────────────────────────────────
    echo -e "${BOLD}  📈 Summary (mean across runs):${RST}"
    printf "  ${DIM}%-14s %5s %10s %8s %7s %8s %5s %5s %6s %6s${RST}\n" \
        "FUZZER" "N" "AvgTime" "Bitmap" "Paths" "Execs" "Crash" "Hangs" "Nodes" "Edges"
    echo -e "  ${DIM}$(printf '─%.0s' {1..95})${RST}"

    # 收集每个 fuzzer 类型的汇总
    local -A sum_bitmap sum_paths sum_execs sum_crashes sum_hangs sum_nodes sum_edges sum_runtime count_by_fuzzer

    while IFS='|' read -r cid target fuzzer runtime bitmap paths_total paths_fav execs execs_sec \
                          crashes hangs cycles pending stab nodes edges \
                          chat_t llm_calls llm_ptok llm_ctok hyp_cnt hyp_fit \
                          plat_calls plat_thresh last_upd token_source; do
        local key="${target}::${fuzzer}"
        local bval
        bval=$(echo "$bitmap" | tr -d '%')

        # 截断浮点/非数字字段为整数（处理 execs_per_sec 误入、"?"、"-"、空值）
        local _paths="${paths_total%%.*}"; _paths="${_paths//[^0-9]/}"
        local _execs="${execs%%.*}";       _execs="${_execs//[^0-9]/}"
        local _crashes="${crashes%%.*}";   _crashes="${_crashes//[^0-9]/}"
        local _hangs="${hangs%%.*}";       _hangs="${_hangs//[^0-9]/}"
        local _nodes="${nodes%%.*}";       _nodes="${_nodes//[^0-9]/}"
        local _edges="${edges%%.*}";       _edges="${_edges//[^0-9]/}"
        local _runtime="${runtime%%.*}";   _runtime="${_runtime//[^0-9]/}"

        sum_bitmap[$key]=$(awk "BEGIN{print ${sum_bitmap[$key]:-0} + ${bval:-0}}")
        sum_paths[$key]=$(( ${sum_paths[$key]:-0} + ${_paths:-0} ))
        sum_execs[$key]=$(( ${sum_execs[$key]:-0} + ${_execs:-0} ))
        sum_crashes[$key]=$(( ${sum_crashes[$key]:-0} + ${_crashes:-0} ))
        sum_hangs[$key]=$(( ${sum_hangs[$key]:-0} + ${_hangs:-0} ))
        sum_nodes[$key]=$(( ${sum_nodes[$key]:-0} + ${_nodes:-0} ))
        sum_edges[$key]=$(( ${sum_edges[$key]:-0} + ${_edges:-0} ))
        sum_runtime[$key]=$(( ${sum_runtime[$key]:-0} + ${_runtime:-0} ))
        count_by_fuzzer[$key]=$(( ${count_by_fuzzer[$key]:-0} + 1 ))
    done <<< "$sorted"

    for key in $(echo "${!count_by_fuzzer[@]}" | tr ' ' '\n' | sort); do
        local n=${count_by_fuzzer[$key]}
        local tgt="${key%%::*}"
        local fzr="${key##*::}"

        local avg_bmp avg_paths avg_execs avg_crashes avg_hangs avg_nodes avg_edges avg_runtime
        avg_bmp=$(awk "BEGIN{printf \"%.2f%%\", ${sum_bitmap[$key]} / $n}")
        avg_paths=$(( ${sum_paths[$key]} / n ))
        avg_execs=$(( ${sum_execs[$key]} / n ))
        avg_crashes=$(( ${sum_crashes[$key]} / n ))
        avg_hangs=$(( ${sum_hangs[$key]} / n ))
        avg_nodes=$(( ${sum_nodes[$key]} / n ))
        avg_edges=$(( ${sum_edges[$key]} / n ))
        avg_runtime=$(( ${sum_runtime[$key]} / n ))

        local fc="$RST"
        case "$fzr" in
            CHATAFL-OPT) fc="$GREEN" ;;
            CHATAFL*)    fc="$YELLOW" ;;
            AFLNET)      fc="$CYAN" ;;
        esac

        printf "  ${fc}%-14s${RST} %5s %10s %8s %7s %8s %5s %5s %6s %6s  ${DIM}[%s]${RST}\n" \
            "$fzr" "$n" "$avg_runtime" "$avg_bmp" "$avg_paths" "$avg_execs" \
            "$avg_crashes" "$avg_hangs" "$avg_nodes" "$avg_edges" "$tgt"
    done
    echo ""
}

# ─── CSV 输出 ───────────────────────────────────────────────────────────────

write_csv() {
    local -a data=("$@")
    local csv_file="${OUT_DIR:-/tmp}/monitor_$(date +%Y%m%d).csv"
    local ts
    ts=$(date +%s)
    local human_ts
    human_ts=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 写表头 (仅首次)
    if [[ ! -f "$csv_file" ]]; then
        echo "timestamp,human_time,container_id,target,fuzzer,runtime_min,bitmap_pct,paths_total,paths_favored,execs_done,execs_per_sec,unique_crashes,unique_hangs,cycles_done,pending_total,stability,ipsm_nodes,ipsm_edges,plateau_calls,llm_total_calls,llm_prompt_tokens,llm_completion_tokens,hypothesis_count,hypothesis_fitness,plateau_threshold,cost_usd,prompt_per_24h,compl_per_24h,cost_per_24h,token_source" \
            > "$csv_file"
    fi

    for line in "${data[@]}"; do
        IFS='|' read -r cid target fuzzer runtime bitmap paths_total paths_fav execs execs_sec \
                       crashes hangs cycles pending stab nodes edges \
                       chat_t llm_calls llm_ptok llm_ctok hyp_cnt hyp_fit \
                       plat_calls plat_thresh last_upd token_source <<< "$line"
        
        local bval
        bval=$(echo "$bitmap" | tr -d '%')
        local stab_val
        stab_val=$(echo "$stab" | tr -d '%')

        # LLM cost columns (gpt-4o-mini: $0.15/1M prompt, $0.60/1M completion)
        local _csv_ptok="${llm_ptok//[^0-9]/}"
        local _csv_ctok="${llm_ctok//[^0-9]/}"
        local _csv_rmin="${runtime//[^0-9]/}"
        local _csv_cost _csv_ptok24 _csv_ctok24 _csv_cost24
        _csv_cost=$(awk "BEGIN{printf \"%.6f\", (${_csv_ptok:-0}*0.15+${_csv_ctok:-0}*0.60)/1000000}")
        _csv_ptok24=$(awk "BEGIN{ r=${_csv_rmin:-0}; if(r>0) printf \"%.0f\", ${_csv_ptok:-0}/r*1440; else print 0}")
        _csv_ctok24=$(awk "BEGIN{ r=${_csv_rmin:-0}; if(r>0) printf \"%.0f\", ${_csv_ctok:-0}/r*1440; else print 0}")
        _csv_cost24=$(awk "BEGIN{ r=${_csv_rmin:-0}; if(r>0) printf \"%.6f\", (${_csv_ptok:-0}*0.15+${_csv_ctok:-0}*0.60)/1000000/r*1440; else print 0}")
        
        echo "${ts},${human_ts},${cid:0:12},${target},${fuzzer},${runtime},${bval},${paths_total},${paths_fav},${execs},${execs_sec},${crashes},${hangs},${cycles},${pending},${stab_val},${nodes},${edges},${plat_calls:-},${llm_calls:-},${llm_ptok:-},${llm_ctok:-},${hyp_cnt:-},${hyp_fit:-},${plat_thresh:-},${_csv_cost},${_csv_ptok24},${_csv_ctok24},${_csv_cost24},${token_source:-}" \
            >> "$csv_file"
    done

    echo -e "  ${DIM}📁 CSV → ${csv_file}${RST}"
}

# ─── 主循环 ─────────────────────────────────────────────────────────────────

main() {
    local filter_msg="all protocols"
    [[ -n "$FILTER" ]] && filter_msg="filter: $FILTER"
    echo -e "${BOLD}🔍 Discovering fuzzing containers (${filter_msg})...${RST}"
    
    while true; do
        local container_list
        container_list=$(discover_containers)

        if [[ -z "$container_list" ]]; then
            echo -e "${RED}No running fuzzing containers found for [${filter_msg}]. Waiting...${RST}"
            if [[ $ONCE -eq 1 ]]; then exit 1; fi
            sleep "$INTERVAL"
            continue
        fi

        # 并行采集所有容器数据
        local -a results=()
        local count=0
        
        for cid in $container_list; do
            local row
            row=$(collect_one "$cid" 2>/dev/null || echo "")
            if [[ -n "$row" ]]; then
                results+=("$row")
                ((count++)) || true
            fi
        done

        # 清屏并输出
        clear 2>/dev/null || printf '\033c'
        print_header "$count"
        print_table "${results[@]}"

        # CSV 输出
        if [[ $CSV_MODE -eq 1 && ${#results[@]} -gt 0 ]]; then
            write_csv "${results[@]}"
        fi

        echo -e "  ${DIM}Next refresh in ${INTERVAL}s ... (Ctrl+C to quit)${RST}"

        if [[ $ONCE -eq 1 ]]; then
            exit 0
        fi

        sleep "$INTERVAL"
    done
}

# ─── Ctrl+C 优雅退出 ───────────────────────────────────────────────────────
trap 'echo -e "\n${YELLOW}Monitor stopped.${RST}"; exit 0' INT TERM

main
