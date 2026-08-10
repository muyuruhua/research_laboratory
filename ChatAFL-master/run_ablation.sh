#!/bin/bash
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
# 每组同时运行的消融组数（默认6=全并行，内存限制已移除，62GB主机安全）
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

if [[ -z "$KEY" ]]; then
  echo "[ERROR] 请先 export KEY=\"sk-...\""
  exit 1
fi

# ── Pre-flight checks ────────────────────────────────────────────────
echo ""
echo "[PREFLIGHT] System resource check:"
echo "  Docker memory limit per fuzzer container: 6g (down from 8g, see profuzzbench_exec_common_dev.sh)"
AVAIL_MEM_KB=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo "unknown")
if [[ "$AVAIL_MEM_KB" != "unknown" ]]; then
  AVAIL_MEM_GB=$((AVAIL_MEM_KB / 1024 / 1024))
  echo "  Host available memory: ~${AVAIL_MEM_GB} GB"
  TOTAL_CONTAINERS_EST=$((ABLATION_PARALLEL * RUNS))
  NEEDED_GB=$((TOTAL_CONTAINERS_EST * MEMORY_PER_FUZZER + 2))
  if [[ $AVAIL_MEM_GB -lt $NEEDED_GB ]]; then
    echo "  ⚠️  WARNING: Estimated ~${TOTAL_CONTAINERS_EST} containers × ${MEMORY_PER_FUZZER}GB (batch size) + 2GB overhead = ~${NEEDED_GB} GB needed"
    echo "  ⚠️  Available memory (${AVAIL_MEM_GB} GB) may be insufficient — expect OOM kills!"
  else
    echo "  ✓ Sufficient memory for ~${TOTAL_CONTAINERS_EST} containers"
  fi
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

  for ((start=0; start<total; start+=ABLATION_PARALLEL)); do
    GROUP_PIDS=()
    GROUP_LABELS=()
    batch_num=$((batch_num + 1))
    local batch_end=$((start + ABLATION_PARALLEL))
    ((batch_end > total)) && batch_end=$total

    echo ""
    echo "  [ABLATION] === 批次 ${batch_num}: 启动 ${start}-$((batch_end-1)) / ${total} 组 === "

    # ── Launch this batch in parallel ──
    for ((i=start; i<batch_end; i++)); do
      IFS='|' read -r label vars <<< "${GROUP_SPECS[$i]}"

      (
        unset CHATAFL_HYPOTHESIS \
              CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
              CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
              CHATAFL_NO_ADMISSION \
              CHATAFL_ADMISSION_LOG CHATAFL_ABLATION_THRESHOLD TIMESTAMP

        if [[ -n "$vars" ]]; then
          IFS=',' read -ra ASSIGN <<< "$vars"
          for a in "${ASSIGN[@]}"; do
            [[ -n "$a" ]] && export "$a"
          done
        fi

        export CHATAFL_NO_HETERO_BROKERS=1
        export CHATAFL_FROM_ABLATION=1
        export CHATAFL_ADMISSION_LOG=1
        export TIMESTAMP="ablation_${label}_$(date +%Y%m%dT%H%M%S)"

        echo "[ABLATION:${label}] 启动 → ablation/results-${TARGET}_${TIMESTAMP}/"
        echo "  HYP=${CHATAFL_HYPOTHESIS:-1} NO_REF=${CHATAFL_NO_REFINEMENT:-0} NO_FRONT=${CHATAFL_NO_FRONTIER:-0} NO_ADAPT=${CHATAFL_NO_ADAPTIVE:-0} NO_SP=${CHATAFL_NO_STATE_PROMPT:-0} NO_ADM=${CHATAFL_NO_ADMISSION:-0} ADM_LOG=${CHATAFL_ADMISSION_LOG:-0} THR=${CHATAFL_ABLATION_THRESHOLD:-adaptive}"

        cd "$BASE_DIR" || exit 1
        ./run_dev.sh "$RUNS" "$TIMEOUT" "$TARGET" loopfuzz

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
      wo_admission)
        valid+=("$name")
        queue_group "wo_admission" "CHATAFL_NO_ADMISSION=1"
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
      fixed150|fixed200|fixed300|fixed512)
        valid+=("$name")
        local thr="${name#fixed}"
        queue_group "$name" \
          "CHATAFL_NO_ADAPTIVE=1" \
          "CHATAFL_ABLATION_THRESHOLD=${thr}"
        ;;
      *)
        echo "[ERROR] 未知消融组: '$name'"
        echo "        可用枚举值（与 monitor.sh Ablation 等价）:"
        echo "          wo_all, wo_hypothesis, full, wo_admission, wo_refinement, wo_frontier,"
        echo "          wo_adaptive, wo_state_prompt, adaptive_full,"
        echo "          fixed150, fixed200, fixed300, fixed512"
        ;;
    esac
  done

  if [[ ${#valid[@]} -eq 0 ]]; then
    echo "[FATAL] 没有有效的消融组名，退出"
    exit 1
  fi

  echo "[CUSTOM] 已入队 ${#valid[@]} 组: ${valid[*]}"
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
      echo "        可选：core | threshold | appendix | legacy"
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
      ISSUES="${ISSUES}  OOM_KILL(exit=137:${ARCHIVE_NAME})"
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
