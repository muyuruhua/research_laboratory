#!/bin/bash

# ═══ SAFETY WARNING ═════════════════════════════════════════════════
# NEVER run: rm -rf benchmark/results-*_phase2_*  while campaigns are
# active or their containers are retained. This has caused data loss.
# Use the specific full timestamp path when cleaning up completed runs.
# Use salvage_from_container.sh for manual container data recovery.
# ═══════════════════════════════════════════════════════════════════
# ============================================================
# run_ablation.sh — 严谨版消融实验启动器
#
# 用法：
#   export KEY="sk-..."
#   export SKIPCOUNT=40
#   sudo -E ./run_ablation.sh [TARGET] [RUNS] [TIMEOUT_MIN] [PRESET]
#   sudo -E ./run_ablation.sh [TARGET] [RUNS] [TIMEOUT_MIN] --groups name1,name2,...
#
# 默认：TARGET=live555  RUNS=5  TIMEOUT=1470  PRESET=core
#
# --groups 参数枚举（与 monitor.sh Ablation 值等价）：
#   wo_all, wo_hypothesis, full, wo_admission, wo_refinement, wo_frontier,
#   wo_adaptive, wo_state_prompt, adaptive_full,
#   fixed150, fixed200, fixed300, fixed512
# Paper-v2 因果 arm 组（2026-09 新增，对应论文 §七 5-arm 矩阵）：
#   direct         = arm C（CHATAFL_NO_ADMISSION=1，parseable→durable）
#   gated_fixed    = arm D（证据门控+两级队列，固定 state policy）——别名 of full
#   calibrated     = arm E（D + CHATAFL_CALIBRATION=1 后验调度）
#   wo_calibration = arm D 显式别名（D vs E 单变量对照的另一半）
#   cal_gamma099 / cal_gamma100 = γ∈{0.99,1.0} 敏感性（论文 §五.3，冻结后仅此两档）
#   多个用逗号分隔，如: --groups full,wo_adaptive,wo_all
#   --groups 覆盖 PRESET 参数，不修改任何预设函数（开闭原则）
#
# 预设：
#   core      单变量消融矩阵：wo_all + full + wo_hypothesis + no-admission + 4策略消融（8组，默认）
#   threshold 阈值子实验：adaptive vs fixed150/200/300/512（5组）
#   appendix  完整消融：core(8组) + threshold(5组) = 13组
#   legacy    旧 bundled 7 组，仅用于复现/对齐历史结果
#
# core 设计原则（2026-05 修订，严格单变量消融，8组）：
#   - wo_all:            全部策略 OFF + Hypothesis OFF + fixed=512（下界基线）
#   - wo_hypothesis:     full − 仅 Hypothesis OFF（需求1+2+3 独立消融）
#   - full:              全部策略 ON + Hypothesis ON + 自适应阈值 ON（初始=512，上界）
#   - wo_admission:      full − 仅 NO_ADMISSION（runtime admission 因果消融）
#   - wo_refinement:     full − 仅 NO_REFINEMENT（需求3 CEGAR 消融）
#   - wo_frontier:       full − 仅 NO_FRONTIER（需求4 frontier 消融）
#   - wo_adaptive:       full − 仅 NO_ADAPTIVE + fixed=512（需求4 自适应 消融）
#   - wo_state_prompt:   full − 仅 NO_STATE_PROMPT（需求4 state prompt 消融）
#   - 每个消融组与 full 仅差一个开关，消除多变量混淆
# ============================================================

# ── 解析 --groups 标志 ────────────────────────────────────────────────
CUSTOM_GROUPS=""
REMAINING_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --groups|-g)
      CUSTOM_GROUPS="${2:-}"
      shift 2
      ;;
    *)
      REMAINING_ARGS+=("$1")
      shift
      ;;
  esac
done

TARGET="${REMAINING_ARGS[0]:-live555}"
RUNS="${REMAINING_ARGS[1]:-5}"
TIMEOUT="${REMAINING_ARGS[2]:-1470}"
PRESET="${REMAINING_ARGS[3]:-${ABLATION_PRESET:-core}}"

# ── 新格式兼容（ABLATION_GUIDE.md 文档格式）──────────────────────
# 支持 <runs> <minutes> <target> custom <arms>（指南新格式）
# 与   <target> <runs> <minutes> custom <arms>（旧顺序）两种写法。
if [[ "${REMAINING_ARGS[0]:-}" =~ ^[0-9]+$ && "${REMAINING_ARGS[1]:-}" =~ ^[0-9]+$ \
      && -n "${REMAINING_ARGS[2]:-}" && ! "${REMAINING_ARGS[2]:-}" =~ ^[0-9]+$ ]]; then
  RUNS="${REMAINING_ARGS[0]}"
  TIMEOUT="${REMAINING_ARGS[1]}"
  TARGET="${REMAINING_ARGS[2]}"
  PRESET="${REMAINING_ARGS[3]:-core}"
fi
if [[ "$PRESET" == "custom" ]]; then
  if [[ -n "${REMAINING_ARGS[4]:-}" ]]; then
    CUSTOM_GROUPS="${REMAINING_ARGS[4]}"
    PRESET=""
  else
    echo "[ERROR] custom 预置需要第 5 个位置参数提供臂列表："
    echo "        ./run_ablation.sh <target> <runs> <minutes> custom direct,gate,..."
    exit 1
  fi
fi
# 每组同时运行的消融组数（默认6）。多个目标脚本同时运行时会叠加
# （2026-10-13 事故：89 个容器并发 → 实际内存冲破 62GB+swap，整机假死断电）。
# 预检与每个批次前按"全机 fuzz 容器实际内存占用"（非 6G 上限）自动收敛本值。
# 设1=串行（最安全最慢），设3=半并行
ABLATION_PARALLEL="${ABLATION_PARALLEL:-6}"
MEMORY_PER_FUZZER=6  # must match --memory in profuzzbench_exec_common_dev.sh

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_BASE_DIR="${BASE_DIR}/ablation"
mkdir -p "${RESULTS_BASE_DIR}"
RESULT_OWNER="${SUDO_USER:-$USER}"
RESULT_GROUP="$(id -gn "${RESULT_OWNER}")"
chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_BASE_DIR}"
chmod u+rwx "${RESULTS_BASE_DIR}"
export RESULTS_ROOT="../ablation"
declare -a GROUP_SPECS=()   # "label|VAR1=val1,VAR2=val2,..."
declare -a GROUP_PIDS=()
declare -a GROUP_LABELS=()

CHATAFL_MOCK_LLM="${CHATAFL_MOCK_LLM:-0}"
# Explicit, shared validation controls are applied AFTER arm isolation.
# Keeping them outside CHATAFL_* prevents silent removal by the isolation
# sweep. Defaults remain the published arm definitions.
for _validation_var in ABLATION_THRESHOLD_OVERRIDE ABLATION_WARMUP_MAX_OVERRIDE ABLATION_EPISODE_ENERGY_OVERRIDE ABLATION_CALL_BUDGET_OVERRIDE; do
  _validation_value="${!_validation_var}"
  if [[ -n "$_validation_value" && ! "$_validation_value" =~ ^[1-9][0-9]*$ ]]; then
    echo "[ERROR] ${_validation_var} must be a positive integer" >&2
    exit 2
  fi
done
if [[ "$CHATAFL_MOCK_LLM" == "1" ]]; then
  MOCK_PORT="${MOCK_PORT:-8099}"
  if [[ ! "$MOCK_PORT" =~ ^[0-9]+$ ]] || (( MOCK_PORT < 1 || MOCK_PORT > 65535 )); then
    echo "[ERROR] MOCK_PORT must be an integer in [1, 65535]" >&2
    exit 2
  fi
  KEY="${KEY:-loopfuzz-mock-key}"
  CHATAFL_NO_LLM="${CHATAFL_NO_LLM:-0}"   # arm exports (nollm8=1) must win
  CHATAFL_LLM_BASE="http://127.0.0.1:${MOCK_PORT}/v1/chat/completions"
  export CHATAFL_MOCK_LLM MOCK_PORT CHATAFL_NO_LLM CHATAFL_LLM_BASE
  echo "[MODE] container-local LoopFuzz Mock enabled (port ${MOCK_PORT}); host gateway preflight skipped"
elif [[ -z "$KEY" ]]; then
  echo "[ERROR] 请先 export KEY=\"sk-...\""
  exit 1
fi

# ── 批次时间戳（提前生成 + 醒目打印，便于事后检索结果目录）──────────
# 每组子 shell 各自生成精确的 per-group TIMESTAMP（秒级），
# 但它们共享同一日期前缀（YYYYMMDD）。在脚本开头打印该前缀，
# 用户可通过 `ls -d ablation/results-*_<前缀>T*` 检索本批全部结果。
_BATCH_TS="$(date +%Y%m%dT%H%M%S)"
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  批次启动时间戳: ${_BATCH_TS}"
echo "║  结果目录模式:   ablation/results-${TARGET}_ablation_<label>_<TS>T*/"
echo "║  检索命令:       ls -d ablation/results-${TARGET}_ablation_*${_BATCH_TS:0:8}T*"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Pre-flight checks ────────────────────────────────────────────────
echo ""
echo "[PREFLIGHT] System resource check:"
echo "  Docker memory limit per fuzzer container: 6g (down from 8g, see profuzzbench_exec_common_dev.sh)"

# 全局内存预算：fuzz 容器"实际占用"总和超过此值前自动限流（62GB 主机约 46GB）。
# 关键区分：--memory 6g 只是防泄漏的硬上限，典型容器实际仅占 ~0.1-1.5GB。
# 准入必须按实际用量计量（上限叠加会 6-10 倍高估，误杀正常并发）；
# 上限仍保留作兜底：泄漏目标（如 forked-daapd）到 6G 会被 cgroup OOM 杀掉而不拖垮宿主机。
TOTAL_MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "unknown")
MEM_BUDGET_GB=$(( TOTAL_MEM_KB / 1024 / 1024 * 3 / 4 ))
MEM_BUDGET_MB=$(( MEM_BUDGET_GB * 1024 ))
ABLATION_MEM_EST_MB="${ABLATION_MEM_EST_MB:-1536}"   # 新容器未测量前的实际占用估算(MB)，可按目标调
MEM_HEADROOM_GB=8                                    # 留给桌面/内核的底线
# 读取所有运行中容器的 cgroup 实际内存（cgroup v1，含 page cache，略保守）。
# 注意必须用 --no-trunc：cgroup 目录名是 64 位完整 ID，短 ID 永远匹配不上。
fuzz_actual_usage_mb() {
  local total_kb=0 id kb
  for id in $(docker ps -q --no-trunc 2>/dev/null); do
    kb=$(awk '{print int($1/1024)}' "/sys/fs/cgroup/memory/docker/${id}/memory.usage_in_bytes" 2>/dev/null)
    [[ -n "${kb}" ]] && total_kb=$((total_kb + kb))
  done
  echo $(( total_kb / 1024 ))
}
RUNNING_CONTAINERS=$(docker ps -q 2>/dev/null | wc -l)
USED_MB=$(fuzz_actual_usage_mb)
AVAIL_MEM_KB=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo "unknown")
if [[ "$AVAIL_MEM_KB" != "unknown" ]]; then
  AVAIL_MEM_GB=$((AVAIL_MEM_KB / 1024 / 1024))
  echo "  Host total/available memory: ~$(( TOTAL_MEM_KB / 1024 / 1024 )) GB / ~${AVAIL_MEM_GB} GB, fuzz budget: ${MEM_BUDGET_GB} GB (by actual usage)"
  echo "  Already-running containers: ${RUNNING_CONTAINERS}, actual usage ≈$((USED_MB/1024)) GB (caps NOT counted)"
  TOTAL_CONTAINERS_EST=$((ABLATION_PARALLEL * RUNS))
  NEEDED_MB=$(( TOTAL_CONTAINERS_EST * ABLATION_MEM_EST_MB ))
  if (( USED_MB + NEEDED_MB > MEM_BUDGET_MB )); then
    # 自动收敛并发：按剩余预算反解最大组数，宁可慢也不能把宿主机拖死
    local_max=$(( (MEM_BUDGET_MB - USED_MB) / (RUNS * ABLATION_MEM_EST_MB) ))
    (( local_max < 1 )) && local_max=1
    if (( local_max < ABLATION_PARALLEL )); then
      echo "  ⚠️  实际占用 ${USED_MB}MB + 新批次估算 ${NEEDED_MB}MB 超出预算 ${MEM_BUDGET_MB}MB，ABLATION_PARALLEL 自动下调 ${ABLATION_PARALLEL} → ${local_max}"
      ABLATION_PARALLEL=$local_max
    fi
  fi
  TOTAL_CONTAINERS_EST=$((ABLATION_PARALLEL * RUNS))
  echo "  ✓ 本批次计划并发 ${ABLATION_PARALLEL} 组 × ${RUNS} run = ${TOTAL_CONTAINERS_EST} 容器"
fi
echo "  SKIPCOUNT=${SKIPCOUNT:-'(not set, using default)'}"
echo "  Docker images required: ${TARGET} (and brokers if MQTT)"
echo ""

if [[ -z "${SKIPCOUNT}" ]]; then
  echo "[WARN] SKIPCOUNT not set. Coverage-over-time granularity may be coarse."
  echo "       Recommended: export SKIPCOUNT=40"
fi

queue_group() {
  local label="$1"
  shift
  local vars=""
  for a in "$@"; do
    vars="${vars},${a}"
  done
  GROUP_SPECS+=("${label}|${vars#,}")
}

run_queued_groups() {
  local total=${#GROUP_SPECS[@]}
  local batch_num=0
  local failed=0

  if [[ "${ABLATION_DRY_RUN:-0}" == "1" ]]; then
    for _dry_spec in "${GROUP_SPECS[@]}"; do
      printf '[ARM_SPEC] %s\n' "$_dry_spec"
    done
    printf '[SHARED_OVERRIDES] threshold=%s warmup_max=%s episode_energy=%s call_budget=%s\n' \
      "${ABLATION_THRESHOLD_OVERRIDE:-arm-default}" \
      "${ABLATION_WARMUP_MAX_OVERRIDE:-arm-default}" \
      "${ABLATION_EPISODE_ENERGY_OVERRIDE:-arm-default}" \
      "${ABLATION_CALL_BUDGET_OVERRIDE:-off}"
    exit 0
  fi

  for ((start=0; start<total; start+=ABLATION_PARALLEL)); do
    GROUP_PIDS=()
    GROUP_LABELS=()
    batch_num=$((batch_num + 1))

    # ── 批次门槛：按实际内存占用准入（多脚本叠加时也不会冲垮宿主机）──
    while :; do
      USED_MB=$(fuzz_actual_usage_mb)
      AVAIL_MB=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 9999999)
      local_max=$(( (MEM_BUDGET_MB - USED_MB) / (RUNS * ABLATION_MEM_EST_MB) ))
      (( local_max < 1 )) && local_max=1
      if (( local_max < ABLATION_PARALLEL )); then
        echo "  [ABLATION] 运行中容器实际占用 $((USED_MB/1024))GB / 预算 ${MEM_BUDGET_GB}GB，本批并发收敛 ${ABLATION_PARALLEL} → ${local_max} 组"
        ABLATION_PARALLEL=$local_max
        break
      fi
      # 估算放得下时还要看真实水位：可用内存触底才等待（此时等待是对的，占用会随批次结束回落）
      if (( AVAIL_MB < (MEM_HEADROOM_GB + 2) * 1024 )); then
        echo "  [ABLATION] 宿主机可用内存 $((AVAIL_MB/1024))GB 低于底线，fuzz 实际占用 $((USED_MB/1024))GB，等待 60s ..."
        sleep 60
      else
        break
      fi
    done

    local batch_end=$((start + ABLATION_PARALLEL))
    ((batch_end > total)) && batch_end=$total

    echo ""
    echo "  [ABLATION] === 批次 ${batch_num}: 启动 ${start}-$((batch_end-1)) / ${total} 组 === "

    # ── Launch this batch in parallel ──
    for ((i=start; i<batch_end; i++)); do
      IFS='|' read -r label vars <<< "${GROUP_SPECS[$i]}"

      (
        # ── 臂隔离（审计 2026-11-01 #23 根因修复）────────────────────
        # 旧实现维护手写 unset 清单，新增机制旋钮（CHATAFL_CODE_RETAIN 曾漏、
        # CHATAFL_NO_LLM/CHATAFL_EPISODE_ENERGY/CHATAFL_U_POLICY 等均未覆盖）
        # 会从父环境静漏进名义臂。改为模式清扫：unset 所有 CHATAFL_*，
        # 仅保留跨臂基础设施允许清单（网关/mock/超时/token，对全部臂公平）。
        # 臂专属变量在清扫之后由组规格重新 export，因此顺序保证语义。
        local _iso_v _iso_allow=" CHATAFL_MOCK_LLM CHATAFL_LLM_BASE CHATAFL_NO_LLM CHATAFL_TOKEN_CAP CHATAFL_MAX_TOKENS CHATAFL_LLM_TIMEOUT_MS CHATAFL_LLM_CONNECT_TIMEOUT CHATAFL_ENRICH_TIMEOUT CHATAFL_LLM_MODEL "
        while IFS= read -r _iso_v; do
          [[ -z "$_iso_v" ]] && continue
          [[ "$_iso_allow" == *" $_iso_v "* ]] && continue
          unset "$_iso_v" 2>/dev/null || true
        done < <(compgen -A variable CHATAFL_ 2>/dev/null | sort -u)
        unset TIMESTAMP

        if [[ -n "$vars" ]]; then
          IFS=',' read -ra ASSIGN <<< "$vars"
          for a in "${ASSIGN[@]}"; do
            [[ -n "$a" ]] && export "$a"
          done
        fi

        if [[ -n "${ABLATION_THRESHOLD_OVERRIDE:-}" ]]; then
          export CHATAFL_ABLATION_THRESHOLD="$ABLATION_THRESHOLD_OVERRIDE"
          export CHATAFL_NO_ADAPTIVE=1
        fi
        [[ -n "${ABLATION_WARMUP_MAX_OVERRIDE:-}" ]] && \
          export CHATAFL_SCHEDULER_WARMUP_MAX="$ABLATION_WARMUP_MAX_OVERRIDE"
        [[ -n "${ABLATION_EPISODE_ENERGY_OVERRIDE:-}" ]] && \
          export CHATAFL_EPISODE_ENERGY="$ABLATION_EPISODE_ENERGY_OVERRIDE"

        # Stage-2 T03: uniform fixed target-invocation budget across arms
        # (the first-round primary endpoint runs under a common call cap).
        [[ -n "${ABLATION_CALL_BUDGET_OVERRIDE:-}" ]] && \
          export CHATAFL_CAMPAIGN_CALL_BUDGET="$ABLATION_CALL_BUDGET_OVERRIDE"

        export CHATAFL_NO_HETERO_BROKERS=1
        export CHATAFL_FROM_ABLATION=1
        export CHATAFL_ADMISSION_LOG=1
        export TIMESTAMP="ablation_${label}_$(date +%Y%m%dT%H%M%S)"

        echo "[ABLATION:${label}] 启动 → ablation/results-${TARGET}_${TIMESTAMP}/"
        echo "  HYP=${CHATAFL_HYPOTHESIS:-1} NO_REF=${CHATAFL_NO_REFINEMENT:-0} NO_FRONT=${CHATAFL_NO_FRONTIER:-0} NO_ADAPT=${CHATAFL_NO_ADAPTIVE:-0} NO_SP=${CHATAFL_NO_STATE_PROMPT:-0} NO_ADM=${CHATAFL_NO_ADMISSION:-0} MODE=${CHATAFL_ADMISSION_MODE:-default-gate} PROV=${CHATAFL_PROVISIONAL:-1} SHADOW=${CHATAFL_SHADOW:-1} ADM_LOG=${CHATAFL_ADMISSION_LOG:-0} THR=${CHATAFL_ABLATION_THRESHOLD:-adaptive} CAL=${CHATAFL_CALIBRATION:-0} GAMMA=${CHATAFL_CAL_GAMMA:-0.995} PROV_BUDGET=${CHATAFL_PROVISIONAL_BUDGET:-64}"

        cd "$BASE_DIR" || exit 1
        ./run_dev.sh "$RUNS" "$TIMEOUT" "$TARGET" loopfuzz
        rc=$?
        if [[ $rc -ne 0 ]]; then
          echo "[ABLATION:${label}] 失败 (run_dev.sh exit=${rc})"
          exit "$rc"
        fi
        echo "[ABLATION:${label}] 完成"
      ) &

      GROUP_PIDS+=("$!")
      GROUP_LABELS+=("$label")
      echo "[ABLATION] 已启动 ${label} (PID=${GROUP_PIDS[-1]})"
    done

    # ── Wait for this batch to complete ──
    echo "  [ABLATION] 等待批次 ${batch_num} 完成..."
    for idx in "${!GROUP_PIDS[@]}"; do
      pid="${GROUP_PIDS[$idx]}"
      label="${GROUP_LABELS[$idx]}"

      if wait "$pid"; then
        echo "[ABLATION] ${label} 成功结束"
      else
        ret=$?
        echo "[ABLATION] ${label} 失败 (exit=${ret})"
        failed=$((failed + 1))
      fi
    done
  done

  return $failed
}

# ═══════════════════════════════════════════════════════════════════════
# launch_custom_groups — 根据 monitor.sh Ablation 标签名入队指定组
#
# 参数: 逗号分隔的组名，如 "full,wo_adaptive,wo_all"
# 枚举: wo_all, wo_hypothesis, full, wo_admission, wo_refinement, wo_frontier,
#        wo_adaptive, wo_state_prompt, adaptive_full,
#        fixed150, fixed200, fixed300, fixed512
#
# 不修改任何预设函数，符合开闭原则。
# ═══════════════════════════════════════════════════════════════════════
launch_custom_groups() {
  local names="$1"
  local -a valid=()
  IFS=',' read -ra NAMES <<< "$names"

  for name in "${NAMES[@]}"; do
    name=$(echo "$name" | xargs)  # trim whitespace
    [[ -z "$name" ]] && continue

    case "$name" in
      wo_all)
        valid+=("$name")
        queue_group "wo_all" \
          "CHATAFL_HYPOTHESIS=0" \
          "CHATAFL_NO_REFINEMENT=1" \
          "CHATAFL_NO_FRONTIER=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_NO_STATE_PROMPT=1" \
          "CHATAFL_ABLATION_THRESHOLD=512"
        ;;
      wo_hypothesis)
        valid+=("$name")
        queue_group "wo_hypothesis" "CHATAFL_HYPOTHESIS=0"
        ;;
      full|adaptive_full)
        valid+=("$name")
        queue_group "$name" ""
        ;;
      wo_admission|direct)
        # arm C (loopfuzz-direct): parseable 候选直接 durable 队列。
        # ADMISSION_MODE=direct 与 n=5 mock 波次驱动器完全一致（NO_ADMISSION=1
        # 为等价的历史路径，双设保证 run-config 的 mode 标签一致）
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=direct" \
          "CHATAFL_NO_ADMISSION=1"
        ;;
      gated_fixed|wo_calibration)
        # arm D (loopfuzz-gated-fixed): 证据门控 + provisional 两级队列 +
        # 固定 state policy（full 的显式别名，用于 D vs E 单变量对照）
        valid+=("$name")
        queue_group "$name" ""
        ;;
      calibrated)
        # arm E (loopfuzz-gated-calibrated): = D + 在线后验调度（唯一差异）
        valid+=("$name")
        queue_group "calibrated" "CHATAFL_CALIBRATION=1"
        ;;
      calibrated8|cal_ewma8)
        # Q3 生产对比臂（2026-11-02）：与 wrapgate8(D) 完全同底座（wrap/阈值8/
        # NO_ADAPTIVE/TTL 全同），唯一差异 = 校准估计器；默认 warmup（64 选择
        # 或五遍历）。注意：paper 老臂 calibrated/cal_ewma 不带本底座，与
        # wrapgate8 混比是多变量混淆，勿用于三问矩阵。calibrated16/calewma16
        # 是 WARMUP_MAX=16 冒烟变体，勿用于正式战役。
        valid+=("$name")
        local prod_esel="calibrated"
        [[ "$name" == "cal_ewma8" ]] && prod_esel="ewma"
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_CALIBRATION=1" \
          "CHATAFL_STATE_SELECT=${prod_esel}"
        ;;
      cal_shrink)
        # CSV#12 生产收缩臂（2026-11-02）：θ_s=(succ_s+κ·r)/(episodes_s+κ)，
        # 默认 warmup（64 选择或五遍历）——真实多小时战役用本臂；
        # calshrink8 是 WARMUP_MAX=16 的激活验证变体，勿混入正式对比。
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_CALIBRATION=1" \
          "CHATAFL_STATE_SELECT=shrink" \
          "CHATAFL_CAL_SHRINK_PSEUDO=8"
        ;;
      calibrated16|calewma16)
        # calibrated8/cal_ewma8 的机制验证变体（2026-11-02 Q3 矩阵冒烟）：
        # 唯一差异 = CHATAFL_SCHEDULER_WARMUP_MAX=16（默认 64 需 ~3h 才越过
        # warmup，短冒烟内 weighted=0 无法验证激活）。生产/正式战役请用
        # calibrated / cal_ewma + 默认 warmup，并以 weighted-eligible 计数
        # 报告实际剂量。
        valid+=("$name")
        local esel="thompson"
        [[ "$name" == "calewma16" ]] && esel="ewma"
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_CALIBRATION=1" \
          "CHATAFL_STATE_SELECT=${esel}" \
          "CHATAFL_SCHEDULER_WARMUP_MAX=16"
        ;;
      cal_gamma099)
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_CALIBRATION=1" \
          "CHATAFL_CAL_GAMMA=0.99"
        ;;
      cal_gamma100)
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_CALIBRATION=1" \
          "CHATAFL_CAL_GAMMA=1.0"
        ;;
      cal_ewma)
        # 专家问题三简单基线：E 臂同构打分，θ̃ 换成 EWMA(0.05)
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_CALIBRATION=1" \
          "CHATAFL_STATE_SELECT=ewma"
        ;;
      cal_run_rate)
        # 专家问题三简单基线：θ̃ 换成平滑经验报酬率
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_CALIBRATION=1" \
          "CHATAFL_STATE_SELECT=run_rate"
        ;;
      native)
        # 专家 #4 公平对照：AFLNet/ChatAFL 原生保留规则 + 相同 LLM 候选。
        # fuzzer 侧自动关闭 provisional/shadow（原生路径无两级队列）。
        valid+=("$name")
        queue_group "native" "CHATAFL_ADMISSION_MODE=native"
        ;;
      gate_only)
        # 专家 #5 因子化消融 cell-1：仅准入门控（无 provisional/shadow）
        valid+=("$name")
        queue_group "gate_only" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=0" \
          "CHATAFL_SHADOW=0"
        ;;
      gate_prov)
        # 专家 #5 因子化消融 cell-2：gate + provisional（无 shadow）
        valid+=("$name")
        queue_group "gate_prov" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=0"
        ;;
      gate|gate_prov_shadow)
        # 专家 #5 因子化消融 cell-3：gate + provisional + shadow（= D，
        # 因子显式钉死，保证与 cell-1/2 的差异只有这两个因子）。
        # "gate" 是 D 臂的短别名（与 monitor.sh / n=5 波次命名一致）
        valid+=("$name")
        queue_group "gate_prov_shadow" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1"
        ;;
      code_retain)
        # 专家 P0-3 保留策略臂：D + CHATAFL_CODE_RETAIN=1。
        # P∧R∧¬U 的候选走 code-retain 通道而非硬拒绝；与 D 的差异仅
        # CODE_RETAIN 一个因子（EC_CODE_RETAIN 在 PROVISIONAL=0 时会被
        # 降级为 reject，故本臂必须钉死 PROVISIONAL=1）
        valid+=("$name")
        queue_group "code_retain" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_CODE_RETAIN=1"
        ;;
      wo_refinement)
        valid+=("$name")
        queue_group "wo_refinement" "CHATAFL_NO_REFINEMENT=1"
        ;;
      wo_frontier)
        valid+=("$name")
        queue_group "wo_frontier" "CHATAFL_NO_FRONTIER=1"
        ;;
      wo_adaptive)
        valid+=("$name")
        queue_group "wo_adaptive" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=512"
        ;;
      wo_state_prompt)
        valid+=("$name")
        queue_group "wo_state_prompt" "CHATAFL_NO_STATE_PROMPT=1"
        ;;
      fixed8ttl)
        # v3 机制验证组：arm D + 阈值 8 + provisional TTL 放宽到 10 分钟。
        # 依据：三次独立 run 复现 30s TTL < 600+ 队列的调度可达延迟，
        # provisional 在被选中 fuzz 前即 expire（desc_execs=0）——放宽 TTL
        # 使逐 descendant 预算钩子可在验证窗口内真实执行。
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=600000"
        ;;
      fixed8|fixed16|fixed32|fixed64|fixed150|fixed200|fixed300|fixed512)
        # v3 验证组泛化：fixedN = arm D（满效果）+ 固定 plateau 阈值 N。
        # 阈值必须是组自带变量——父 shell 导出的 CHATAFL_NO_ADAPTIVE/
        # CHATAFL_ABLATION_THRESHOLD 会被本函数开头的 unset 清掉（arm 隔离），
        # 这是 2026-10-05 两次消融 e2e 零候选的真实根因。
        valid+=("$name")
        local thr="${name#fixed}"
        queue_group "$name" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=${thr}"
        ;;
      salvage8|salvage16|salvage32|salvage64|salvage150|salvage200|salvage300|salvage512)
        # Q1 证据回收臂（处理组）：D + SALVAGE + PLAINTEXT_WRAP + 固定阈值 N。
        # 与 wrapgateN 的差异仅 SALVAGE 一个因子；与 wrapdirectN 的差异是
        # 整个准入策略。阈值入组变量（臂隔离会清父 shell 导出）。
        valid+=("$name")
        local thr="${name#salvage}"
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_SALVAGE=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=${thr}" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000"
        ;;
      wrapgate8|wrapgate16|wrapgate32|wrapgate64|wrapgate150|wrapgate200|wrapgate300|wrapgate512)
        # Q1 对照组1：D + PLAINTEXT_WRAP + 固定阈值 N（无 salvage）。
        # 与 salvageN 单因子差异 = SALVAGE。
        valid+=("$name")
        local thr="${name#wrapgate}"
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=${thr}" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000"
        ;;
      lop8|lou8|lor8|logc8|logs8)
        # P0-9 leave-one-out 谓词消融臂：gate 全开，仅禁用一个准入谓词
        #（被禁谓词强制通过，决策 = 其余谓词的 AND）。
        # lop=无P, lou=无U, lor=无R, logc=无G_code, logs=无G_state。
        # 基线对照 = wrapgate8（全部谓词在位，其余参数全同）。
        # lop8 特例（2026-11-02 根因）：P 在上游 schema 门失败，而
        # PLAINTEXT_WRAP 会把一切非空纯文本包成合法 schema → wrap 开启时
        # P 永不失守、消融零剂量。lop8 因此关闭 WRAP：纯文本回复真实落
        # p_fail，NO_P 把它们送进有界 trial（p_pass_observed=false）。
        # lop8 的配对基线 = 同参数无 NO_P 的 gate 臂（p_fail 全丢弃）。
        valid+=("$name")
        local pred=""
        local lop_wrap="CHATAFL_PLAINTEXT_WRAP=1"
        case "$name" in
          lop8)  pred="CHATAFL_ADMIT_NO_P=1"; lop_wrap="CHATAFL_PLAINTEXT_WRAP=0" ;;
          lou8)  pred="CHATAFL_ADMIT_NO_U=1" ;;
          lor8)  pred="CHATAFL_ADMIT_NO_R=1" ;;
          logc8) pred="CHATAFL_ADMIT_NO_GCODE=1" ;;
          logs8) pred="CHATAFL_ADMIT_NO_GSTATE=1" ;;
        esac
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "${lop_wrap}" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "${pred}"
        ;;
      salvagepg8)
        # L1/L2 修复臂（2026-10-30 探针前置）：salvage8 基础上，探测执行
        # 提前到准入之前——剥离会话若无法完成则在门控处诚实再拒，
        # 不再占用队列位/存活上限/审计噪音；入队条目用探针响应注释。
        # 基线对照 = salvage8（唯一差异 = PROBE_GATE）。
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_SALVAGE=1" \
          "CHATAFL_SALVAGE_PROBE_GATE=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000"
        ;;
      shadowrand8)
        # P0-21 无偏影子抽样臂：salvage8 基础上，shadow 验证改为对全部
        # 被拒候选的均匀 Bernoulli 抽样（p=0.25），用于估计总体误拒率。
        # 基线对照 = salvage8（evidence-selected 影子，其余参数全同）。
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_SALVAGE=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_SHADOW_SAMPLE=random" \
          "CHATAFL_SHADOW_RATE=0.25"
        ;;
      ordedf8)
        # Q2 fair comparison arm (2026-11-04): ordmatch8 + EDF service for
        # ordinary roots. Same 64-call budget as provisional, same EDF
        # priority, DIFFERENT retention (ordinary keeps files on close).
        # ordmatch8 vs ordedf8 isolates the EDF switch. salvage8 is an
        # additional provisional-policy comparison: favored and live-cap
        # semantics still differ, and independently generated streams are
        # not frozen paired candidates.
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_SALVAGE=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_ORDINARY_BUDGET=1" \
          "CHATAFL_ORDINARY_RATE=1.0" \
          "CHATAFL_ORDINARY_EDF=1"
        ;;
      cal_run_rate8)
        # Q3 missing arm (2026-11-04 codex gap): wrapgate8 base + run_rate
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_CALIBRATION=1" \
          "CHATAFL_STATE_SELECT=run_rate"
        ;;
      noprefix8)
        # S1 on/off pair arm (2026-11-06, GLM53 audit gap): code_retain8 base
        # + only CHATAFL_PROV_PREFIX_PROTECT=0 — forced provisional service
        # mutates the WHOLE session again (legacy M2). Baseline = code_retain8
        # (same batch, single factor = prefix protection). Must be launched in
        # the SAME batch as code_retain8 for a same-version comparison.
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_CODE_RETAIN=1" \
          "CHATAFL_PROV_PREFIX_PROTECT=0"
        ;;
      q1a8|q1b8|q1c8)
        # Stage-2 T03 Q1 strategies (2026-11-06): single-factor triplet on
        # the fate of the 64-call quota freed by gate rejects of executable
        # candidates. All three share the wrapgate8 generation base and the
        # SAME campaign call budget (set via ABLATION_CALL_BUDGET_OVERRIDE
        # so the A-vs-C comparison is fixed-call, not fixed-wallclock).
        #   q1a8 = A direct service (no gate decision; every p&r candidate
        #          gets the same bounded validation service)
        #   q1b8 = B gate + idle (freed quota parked; effective cap shrinks)
        #   q1c8 = C gate + reflow (freed quota refills ordinary mutation)
        valid+=("$name")
        local q1var=""
        case "$name" in
          q1a8) q1var="CHATAFL_Q1_DIRECT_SERVICE=1" ;;
          q1b8) q1var="CHATAFL_Q1_NO_REFLOW=1" ;;
          q1c8) q1var="CHATAFL_Q1_REFLOW=1" ;;
        esac
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "${q1var}"
        ;;
      stateretain8)
        # S2 state-evidence entry (2026-11-05): wrapgate8 + only
        # CHATAFL_STATE_RETAIN=1 -- U-fail ∧ R ∧ Gstate ∧ ¬Gcode candidates
        # (the structurally empty natural provisional cell) enter the
        # bounded validation tier with S1 prefix-protected service.
        # Baseline = wrapgate8 (single factor = STATE_RETAIN).
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_STATE_RETAIN=1"
        ;;
      native8)
        # CSV#4 fair native control (2026-11-05): native retention + the
        # wrapgate8 generation base (PLAINTEXT_WRAP/fixed threshold/
        # NO_ADAPTIVE) so the remaining difference vs wrapgate8 is the
        # admission/retention policy itself (wrapdirect8 is a forced-
        # durable policy PACKAGE, not a native control). Native mode
        # disables the two-tier queue fuzzer-side; no TTL to align.
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=native" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8"
        ;;
      code_retain8)
        # CSV#8 U-policy 4th cell (2026-11-03): full wrapgate8 base + only
        # CHATAFL_CODE_RETAIN=1 (U-fail & R & Gcode -> provisional retention,
        # durability only via descendant code gain). Single-variable
        # comparable with wrapgate8(strict)/softu8(soft). The legacy
        # code_retain arm keeps the paper base -- do NOT mix-compare.
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_CODE_RETAIN=1"
        ;;
      wrapgate1)
        # Cross-protocol span-fix verification arm (2026-11-03): wrapgate8
        # with CHATAFL_ABLATION_THRESHOLD=1 for fast LLM consultation on
        # slow targets (kamailio/live555/forked-daapd/lighttpd1) where
        # threshold=8 produced 0-3 trials in 75min. NOT for Q1/Q2 judgment
        # (threshold confound); span-binding verification only.
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=1" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000"
        ;;
      softu8|protou8)
        # CSV#8 U 四政策臂（2026-11-02）：wrapgate8 基础上仅换 U 政策。
        # softu8  = soft U（错误响应不再单独否决，结构性失败才拒；
        #           u_error_states/u_soft_tolerated 记录剂量，误接纳可测）。
        # protou8 = protocol U（文本协议保持 4xx/5xx；二进制协议用各自的
        #           语义错误指示：SSH DISCONNECT/TLS ALERT/DNS RCODE/DICOM RJ）。
        # 四政策的另两格 = wrapgate8（原 strict U）与 code_retain 臂
        # （Gcode 条件下绕过 U）。基线对照 = wrapgate8，其余参数全同。
        valid+=("$name")
        local upol="strict"
        [[ "$name" == "softu8" ]] && upol="soft"
        [[ "$name" == "protou8" ]] && upol="protocol"
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_U_POLICY=${upol}"
        ;;
      ordmatch8)
        # CSV#7 同预算 ordinary 对照臂（2026-11-02）：与 salvage8 完全相同
        # 的准入决策流/预算台账/首次增益归因，但临时通道准入的候选改走
        # ordinary-match 队列（regular provisional 根优先；无 favored 加成；
        # 无 regular 根时使用确定性 fallback 服务；预算或 TTL 关闭时保留
        # 语料）。Productivity@64 在两臂间同口径比较，ordinary probe 不计入
        # descendant dose。基线对照 = salvage8（唯一差异 = ORDINARY_BUDGET;
        # strict U 下 G_state-only 准入稀少，salvage 通道保证可比剂量）。
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_SALVAGE=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_ORDINARY_BUDGET=1" \
          "CHATAFL_ORDINARY_RATE=1.0"
        ;;
      calshrink8)
        # CSV#12 run-level 基础率收缩臂（2026-11-02）：θ_s=(succ_s+κ·r)/
        # (episodes_s+κ)，r 为全战役 pooled 奖励率（离线获胜的 campaign级
        # 信息的原则性在线转化），κ=CHATAFL_CAL_SHRINK_PSEUDO。
        # 对照 = calibrated8（Thompson）与 cal_ewma8/cal_run_rate8。
        # WARMUP_MAX=16 让 weighted 选择在 ~40min 内激活（默认 64 需 ~3h；
        # 激活以 scheduler-selections 的 weighted-eligible>0 为准）。
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_CALIBRATION=1" \
          "CHATAFL_STATE_SELECT=shrink" \
          "CHATAFL_SCHEDULER_WARMUP_MAX=16" \
          "CHATAFL_CAL_SHRINK_PSEUDO=8"
        ;;
      salvageop8)
        # Q1 opportunity-gate arm (2026-11-06 marginal semantics): salvage8
        # base + CHATAFL_SALVAGE_OPPORTUNITY=4.0 (any value >0 enables;
        # the numeric value no longer carries threshold semantics). The
        # gate parks provisional EDF service while the ORDINARY channel's
        # recent new-edge yield exceeds the lineage channel's (channel-
        # consistent counters incl. converted roots; <64 lineage samples
        # per window = underexposed, no decision). Every park/resume is
        # ledgered (provisional-events kind=opportunity-gate with
        # ordinary_yield/validation_yield/underexposed_window).
        # Baseline = salvage8 (only diff = the gate).
        valid+=("$name")
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_SALVAGE=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_SALVAGE_OPPORTUNITY=4.0"
        ;;
      nollm8|gramonly8|genrich8|plateauonly8)
        # CSV#20 LLM 组件控制臂（2026-11-02）：wrapgate8 基础上仅换 LLM 通道组合。
        # 通道在 chat_with_llm 入口短路（无请求/无token/无账目行），
        # llm-calls.jsonl 每行带 channel 字段，组件隔离按 run-config 可验。
        # 组件格架（冒烟实测）：enrichment 依赖 grammar 的消息类型发现——
        # 关 grammar 后 enrichment 0 调用（架构级依赖，台账证实），
        # 因此"仅 enrichment"不存在，用 genrich8(G+E) 使 E 的边际贡献
        # = genrich8 − gramonly8 可分解。
        #   nollm8      = 全关（P0-7 同码对照；总 LLM 贡献 = wrapgate8 − nollm8）
        #   gramonly8   = 仅 grammar（协议模板+语法假设）
        #   genrich8    = grammar+enrichment（无 plateau）
        #   plateauonly8= 仅 plateau（停滞咨询候选）
        # 基线对照 = wrapgate8（三通道全开，其余参数全同）。
        valid+=("$name")
        local chans=""
        case "$name" in
          nollm8)       chans="CHATAFL_NO_LLM=1" ;;
          gramonly8)    chans="CHATAFL_NO_ENRICH=1,CHATAFL_NO_PLATEAU=1" ;;
          genrich8)     chans="CHATAFL_NO_PLATEAU=1" ;;
          plateauonly8) chans="CHATAFL_NO_GRAMMAR=1,CHATAFL_NO_ENRICH=1" ;;
        esac
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "${chans}"
        ;;
      trigcg8|trigrg8|trigfi8)
        # CSV#18 触发策略臂（2026-11-02）：wrapgate8 基础上仅换 LLM 咨询触发信号，
        # 阈值与下游一切不变；每次触发写 trigger-events.jsonl（策略/计数/阈值/成本）。
        #   trigcg8 = code-stall（连续无新代码覆盖，默认语义的显式臂）
        #   trigrg8 = response-gap（连续无响应侧新颖：观测账本+IPSM状态边）
        #   trigfi8 = fixed-interval（距上次咨询的轮数，零反馈依赖对照）
        # 基线对照 = trigcg8（=wrapgate8 语义；三臂间互相为对照）。
        valid+=("$name")
        local tpol="code-stall"
        [[ "$name" == "trigrg8" ]] && tpol="response-gap"
        [[ "$name" == "trigfi8" ]] && tpol="fixed-interval"
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=gate" \
          "CHATAFL_PROVISIONAL=1" \
          "CHATAFL_SHADOW=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=8" \
          "CHATAFL_PROVISIONAL_TTL_MS=3600000" \
          "CHATAFL_TRIGGER_POLICY=${tpol}"
        ;;
      wrapdirect8|wrapdirect16|wrapdirect32|wrapdirect64|wrapdirect150|wrapdirect200|wrapdirect300|wrapdirect512)
        # Q1 对照组2：C(direct) + PLAINTEXT_WRAP + 固定阈值 N。
        # 可解析候选全收（parseable→durable）。与 salvageN 的差异 =
        # 完整准入策略；与原生 direct 组的差异 = WRAP+固定阈值（剂量对齐）。
        valid+=("$name")
        local thr="${name#wrapdirect}"
        queue_group "$name" \
          "CHATAFL_ADMISSION_MODE=direct" \
          "CHATAFL_NO_ADMISSION=1" \
          "CHATAFL_PLAINTEXT_WRAP=1" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=${thr}"
        ;;
      *)
        echo "[ERROR] 未知消融组: '$name'"
        echo "        可用枚举值（与 monitor.sh Ablation 等价）:"
        echo "          wo_all, wo_hypothesis, full, wo_admission, wo_refinement, wo_frontier,"
        echo "          wo_adaptive, wo_state_prompt, adaptive_full,"
        echo "          fixed150, fixed200, fixed300, fixed512"
        echo "        Paper-v2 因果 arm 组:"
        echo "          direct(=C), gated_fixed|wo_calibration(=D), calibrated(=E),"
        echo "          cal_gamma099, cal_gamma100 (γ 敏感性)"
        echo "        Phase-2 因子化组 (专家 #4/#5):"
        echo "          native (#4 原生保留+同LLM候选), gate_only, gate_prov,"
        echo "          gate|gate_prov_shadow (=D 因子显式), code_retain (D+保留策略)"
        echo "        简单在线基线 (专家问题三):"
        echo "          cal_ewma, cal_run_rate (E 臂同构，仅换 θ̃ 估计器)"
        echo "        Q1 证据回收组 (salvage):"
        echo "          salvageN / wrapgateN / wrapdirectN, N∈{8,16,32,64,150,200,300,512}"
        echo "          三臂对比: -g wrapdirect8,wrapgate8,salvage8"
        echo "        P0-9/P0-21 消融臂 (2026-10-29):"
        echo "          lop8/lou8/lor8/logc8/logs8 (leave-one-out 谓词)"
        echo "          shadowrand8 (无偏随机影子抽样)"
        echo "        CSV#8/#7/#12 审计修复臂 (2026-11-02):"
        echo "          softu8/protou8 (U 政策: soft/protocol; strict=wrapgate8, 绕U=code_retain)"
        echo "          ordmatch8 (ordinary 同预算对照, Productivity@64)"
        echo "          calshrink8 (run-level 基础率收缩, WARMUP_MAX=16)"
        echo "        CSV#20/#18 组件与触发臂 (2026-11-02):"
        echo "          nollm8/gramonly8/genrich8/plateauonly8 (LLM 通道隔离; E依赖G)"
        echo "          trigcg8/trigrg8/trigfi8 (触发策略: code-stall/response-gap/fixed-interval)"
        ;;
    esac
  done

  if [[ ${#valid[@]} -eq 0 ]]; then
    echo "[FATAL] 没有有效的消融组名，退出"
    exit 1
  fi

  echo "[CUSTOM] 已入队 ${#valid[@]} 组: ${valid[*]}"
  # P0-2: 随机化运行顺序（消除组序与时间相关的混杂）；ABLATION_SHUFFLE=1 启用
  if [[ "${ABLATION_SHUFFLE:-0}" == "1" && ${#GROUP_SPECS[@]} -gt 1 ]]; then
    mapfile -t GROUP_SPECS < <(printf '%s\n' "${GROUP_SPECS[@]}" | shuf)
    echo "[CUSTOM] ABLATION_SHUFFLE=1 → 随机化后顺序: ${GROUP_SPECS[*]}"
  fi
}

launch_core_preset() {
  # ── 严格单变量消融矩阵（8 组）──────────────────────────────────────
  # 设计原则：
  #   - wo_all 关闭全部策略（含 Hypothesis），作为 LoopFuzz 内部下界锚点，不替代 ChatAFL/ 基线
  #   - full 打开全部策略，作为完整系统的性能上界
  #   - wo_hypothesis 仅关闭 Hypothesis（需求1+2+3），保留需求4全开
  #   - no-admission 与四个策略消融组各自仅关闭一个策略，其他全部 ON
  #   - 每个消融组与 full 仅差一个开关，消除多变量混淆
  #   - 自适应阈值初始=512（与 ChatAFL 基线 UNINTERESTING_THRESHOLD 一致）

  # Layer 0: 全禁用基线（Hypothesis + 全部策略 OFF）
  queue_group "wo_all" \
    "CHATAFL_HYPOTHESIS=0" \
    "CHATAFL_NO_REFINEMENT=1" \
    "CHATAFL_NO_FRONTIER=1" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_NO_STATE_PROMPT=1" \
    "CHATAFL_ABLATION_THRESHOLD=512"

  # Layer 1: 全启用（所有策略 ON，自适应阈值 ON，Hypothesis ON）
  queue_group "full" ""

  # Layer 2: Hypothesis 系统独立消融（需求1+2+3 OFF，需求4 全 ON）
  queue_group "wo_hypothesis" \
    "CHATAFL_HYPOTHESIS=0"

  # Layer 3: Runtime admission 因果消融（仅关闭 admission gate）
  queue_group "wo_admission" \
    "CHATAFL_NO_ADMISSION=1"

  # Layer 4: 四个单变量消融（每个仅关闭一个策略）
  queue_group "wo_refinement" \
    "CHATAFL_NO_REFINEMENT=1"

  queue_group "wo_frontier" \
    "CHATAFL_NO_FRONTIER=1"

  queue_group "wo_adaptive" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=512"

  queue_group "wo_state_prompt" \
    "CHATAFL_NO_STATE_PROMPT=1"
}

launch_threshold_preset() {
  queue_group "adaptive_full"
  queue_group "fixed150_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=150"
  queue_group "fixed200_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=200"
  queue_group "fixed300_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=300"
  queue_group "fixed512_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=512"
}

launch_appendix_preset() {
  # core 预设：wo_all + full + wo_hypothesis + wo_admission + 4策略消融（8组）
  # threshold 预设：5组阈值变体
  # 合计 13 组完整消融矩阵
  launch_core_preset
  launch_threshold_preset
}

launch_legacy_preset() {
  queue_group "full_opt"
  queue_group "wo_refinement" \
    "CHATAFL_NO_REFINEMENT=1"
  queue_group "wo_frontier" \
    "CHATAFL_NO_FRONTIER=1"
  queue_group "wo_adaptive_100" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=100"
  queue_group "wo_adaptive_512" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=512"
  queue_group "wo_state_prompt" \
    "CHATAFL_NO_STATE_PROMPT=1"
  queue_group "wo_all" \
    "CHATAFL_NO_REFINEMENT=1" \
    "CHATAFL_NO_FRONTIER=1" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_NO_STATE_PROMPT=1" \
    "CHATAFL_ABLATION_THRESHOLD=512"
}

# ── 自定义消融组模式（--groups 覆盖 PRESET）─────────────────────────
if [[ -n "$CUSTOM_GROUPS" ]]; then
  PRESET_DESC="自定义消融组: ${CUSTOM_GROUPS}"
  launch_custom_groups "$CUSTOM_GROUPS"
else
  case "$PRESET" in
    core)
      PRESET_DESC="严格单变量消融：wo_all + full + wo_hypothesis + wo_admission + 4策略消融（8组）"
      ;;
    threshold)
      PRESET_DESC="阈值子实验：adaptive vs fixed150 / 200 / 300 / 512（5组）"
      ;;
    appendix)
      PRESET_DESC="完整消融：core(8组) + threshold(5组) = 13组"
      ;;
    legacy)
      PRESET_DESC="旧 bundled 7 组：仅用于复现与历史对齐（含显式 fixed100）"
      ;;
    *)
      echo "[ERROR] 未知 PRESET: ${PRESET}"
      echo "        可选：core | threshold | appendix | legacy | custom <臂列表>"
      echo "        或使用 --groups name1,name2,... 指定消融组"
      exit 1
      ;;
  esac
fi

echo "========================================================"
echo "  [ABLATION] 消融实验（批次执行）"
echo "  目标: ${TARGET}  每组重复: ${RUNS}  时长: ${TIMEOUT} min"
echo "  预设: ${PRESET}  批次大小: ${ABLATION_PARALLEL} 组/批"
echo "  说明: ${PRESET_DESC}"
echo "  结果目录: benchmark/results-${TARGET}_ablation_<label>/"
echo "========================================================"

if [[ -n "$CUSTOM_GROUPS" ]]; then
  # 自定义组已入队，跳过预设调度
  :
else
case "$PRESET" in
  core)      launch_core_preset ;;
  threshold) launch_threshold_preset ;;
  appendix)  launch_appendix_preset ;;
  legacy)    launch_legacy_preset ;;
esac
fi

GROUP_COUNT=${#GROUP_SPECS[@]}
EFFECTIVE_PARALLEL=$(( ABLATION_PARALLEL < GROUP_COUNT ? ABLATION_PARALLEL : GROUP_COUNT ))
EFFECTIVE_CONTAINERS=$(( EFFECTIVE_PARALLEL * RUNS ))
EFFECTIVE_MEM_NEEDED=$(( EFFECTIVE_CONTAINERS * MEMORY_PER_FUZZER + EFFECTIVE_PARALLEL * 1 + 2 ))
# ↑ fuzzers + brokers(est. ~1GB per group for stable/multi/hetero) + overhead
echo ""
echo "  [ABLATION] ${GROUP_COUNT} 组已入队，分 $(( (GROUP_COUNT + ABLATION_PARALLEL - 1) / ABLATION_PARALLEL )) 批执行"
if [[ "$AVAIL_MEM_KB" != "unknown" ]]; then
  echo "  [ABLATION] 实际最大并发: ${EFFECTIVE_PARALLEL} 组 × ${RUNS} 容器/组 = ${EFFECTIVE_CONTAINERS} fuzzer 容器"
  echo "  [ABLATION] 估算总内存需求: ~${EFFECTIVE_MEM_NEEDED} GB (可用: ~${AVAIL_MEM_GB} GB)"
  if [[ $AVAIL_MEM_GB -lt $EFFECTIVE_MEM_NEEDED ]]; then
    echo "  ⚠️  CRITICAL: 实际内存不足！建议: export ABLATION_PARALLEL=$(( EFFECTIVE_PARALLEL - 1 >= 1 ? EFFECTIVE_PARALLEL - 1 : 1 )) 并重试"
  else
    echo "  ✓ 内存充足，安全余量 ~$(( AVAIL_MEM_GB - EFFECTIVE_MEM_NEEDED )) GB"
  fi
fi
echo ""

# Real-gateway runs check the actual client on the host. Mock runs perform
# the same check inside each isolated fuzz container against its local server.
if [[ "$CHATAFL_MOCK_LLM" == "1" ]]; then
  echo "[PREFLIGHT] Mock mode: each LoopFuzz container starts and probes its own local gateway before fuzzing."
elif ! "${BASE_DIR}/scripts/check_llm.sh"; then
  echo "[ERROR] LLM 预检失败；未启动本批消融实验。请核对当前 KEY、LLM_MODEL 和 CHATAFL_LLM_BASE。" >&2
  exit 1
fi

# ── Execute queued groups in batches ──
run_queued_groups
failed=$?

echo ""
echo "========================================================"
echo "  [ABLATION] 预设 ${PRESET} 全部完成！"
[[ $failed -gt 0 ]] && echo "  ⚠️  WARNING: ${failed} 组子进程返回非零退出码，请检查日志"
echo "  结果目录："
ls -d "$BASE_DIR/ablation/results-${TARGET}_ablation_"* 2>/dev/null | sort | xargs -r -I{} basename {}
echo "========================================================"

# ── Post-run diagnostics ──────────────────────────────────────────────
echo ""
echo "[POSTRUN] Scanning for anomalies in ablation results..."
for RESULTS_DIR in "$BASE_DIR"/ablation/results-${TARGET}_ablation_*; do
  [[ -d "$RESULTS_DIR" ]] || continue
  DIR_NAME=$(basename "$RESULTS_DIR")
  ISSUES=""

  for STATUS_FILE in "$RESULTS_DIR"/.sample_status/*.status; do
    [[ -f "$STATUS_FILE" ]] || continue
    EXIT_CODE=$(grep '^exit_code=' "$STATUS_FILE" 2>/dev/null | cut -d= -f2)
    ARCHIVE_NAME=$(grep '^archive_name=' "$STATUS_FILE" 2>/dev/null | cut -d= -f2)

    if [[ "$EXIT_CODE" == "137" ]]; then
      # 审计 2026-11-01 #23 纠正：137 ≠ 必然 OOM。kernel OOM kill 会置
      # State.OOMKilled=true；否则最常见是 campaign 到期 SIGTERM 后宽限
      # 期内未退出被 SIGKILL（宽限已提升至 360s，见 profuzzbench 注释）。
      # 优先读完成时记录的 oom_killed 字段，缺失再 docker inspect；
      # 无法确认时标 unknown 而不是断言 OOM。
      _137_OOM=$(grep '^oom_killed=' "$STATUS_FILE" 2>/dev/null | cut -d= -f2)
      if [[ -z "$_137_OOM" ]]; then
        _137_CONTAINER=$(grep '^container_id=' "$STATUS_FILE" 2>/dev/null | cut -d= -f2)
        if [[ -n "$_137_CONTAINER" ]] && command -v docker >/dev/null 2>&1; then
          _137_OOM=$(docker inspect -f '{{.State.OOMKilled}}' "$_137_CONTAINER" 2>/dev/null || echo "inspect-failed")
        fi
      fi
      case "$_137_OOM" in
        true)  _137_TAG="oomkilled=true" ;;
        false) _137_TAG="oomkilled=false,sigkill-after-timeout-or-grace" ;;
        *)     _137_TAG="oomkilled=${_137_OOM:-unknown}" ;;
      esac
      ISSUES="${ISSUES}  EXIT_137_SIGKILL(${_137_TAG}:${ARCHIVE_NAME})"
    elif [[ "$EXIT_CODE" == "139" ]]; then
      ISSUES="${ISSUES}  SEGFAULT(exit=139:${ARCHIVE_NAME})"
    elif [[ "$EXIT_CODE" == "134" ]]; then
      ISSUES="${ISSUES}  HEAP_ABORT(exit=134:${ARCHIVE_NAME})"
    elif [[ "$EXIT_CODE" != "0" && "$EXIT_CODE" != "" ]]; then
      ISSUES="${ISSUES}  ABNORMAL_EXIT(${EXIT_CODE}:${ARCHIVE_NAME})"
    fi
  done

  # Check for missing cov_html
  for TARBALL in "$RESULTS_DIR"/out-*.tar.gz; do
    [[ -f "$TARBALL" ]] || continue
    if ! tar tzf "$TARBALL" 2>/dev/null | grep -q 'cov_html/'; then
      ISSUES="${ISSUES}  NO_COV_HTML($(basename "$TARBALL"))"
    fi
  done

  if [[ -n "$ISSUES" ]]; then
    echo "  ⚠️  ${DIR_NAME}:${ISSUES}"
  else
    echo "  ✓ ${DIR_NAME}: clean"
  fi
done
echo "[POSTRUN] Diagnostics complete."

RESULT_OWNER="${SUDO_USER:-$USER}"
RESULT_GROUP="$(id -gn "${RESULT_OWNER}")"
chown "${RESULT_OWNER}:${RESULT_GROUP}" "${RESULTS_BASE_DIR}"
chmod u+rwx "${RESULTS_BASE_DIR}"
for RESULTS_DIR in "$BASE_DIR"/ablation/results-${TARGET}_ablation_*; do
  [[ -d "$RESULTS_DIR" ]] || continue
  chown -R "${RESULT_OWNER}:${RESULT_GROUP}" "$RESULTS_DIR"
  chmod -R u+rwX "$RESULTS_DIR"
done
