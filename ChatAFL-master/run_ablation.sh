#!/bin/bash
# ============================================================
# run_ablation.sh — 严谨版消融实验启动器
#
# 用法：
#   export KEY="sk-..."
#   export SKIPCOUNT=40
#   sudo -E ./run_ablation.sh [TARGET] [RUNS] [TIMEOUT_MIN] [PRESET]
#
# 默认：TARGET=live555  RUNS=5  TIMEOUT=1470  PRESET=core
#
# 预设：
#   core      当前代码主矩阵：shipped 行为 + 3 个策略 bundle + 2 个阈值对照（默认）
#   threshold 阈值子实验：adaptive vs fixed150/200/300/512
#   appendix  主矩阵 + wo_all 粗粒度 sanity-check
#   legacy    旧 bundled 7 组，仅用于复现/对齐历史结果；其中 wo_adaptive_100 显式固定 100
# ============================================================

TARGET="${1:-live555}"
RUNS="${2:-5}"
TIMEOUT="${3:-1470}"
PRESET="${4:-${ABLATION_PRESET:-core}}"
# 每组同时运行的消融组数（默认6=全并行，内存限制已移除，62GB主机安全）
# 设1=串行（最安全最慢），设3=半并行
ABLATION_PARALLEL="${ABLATION_PARALLEL:-6}"

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
echo "  Docker memory limit per fuzzer container: 8g (up from 6g, see profuzzbench_exec_common_dev.sh)"
AVAIL_MEM_KB=$(awk '/MemAvailable/ {print $2}' /proc/meminfo 2>/dev/null || echo "unknown")
if [[ "$AVAIL_MEM_KB" != "unknown" ]]; then
  AVAIL_MEM_GB=$((AVAIL_MEM_KB / 1024 / 1024))
  echo "  Host available memory: ~${AVAIL_MEM_GB} GB"
  TOTAL_CONTAINERS_EST=$((ABLATION_PARALLEL * RUNS))
  NEEDED_GB=$((TOTAL_CONTAINERS_EST * 8 + 2))
  if [[ $AVAIL_MEM_GB -lt $NEEDED_GB ]]; then
    echo "  ⚠️  WARNING: Estimated ~${TOTAL_CONTAINERS_EST} containers × 8GB (batch size) + 2GB overhead = ~${NEEDED_GB} GB needed"
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
        unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
              CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
              CHATAFL_ABLATION_THRESHOLD TIMESTAMP

        if [[ -n "$vars" ]]; then
          IFS=',' read -ra ASSIGN <<< "$vars"
          for a in "${ASSIGN[@]}"; do
            [[ -n "$a" ]] && export "$a"
          done
        fi

        export CHATAFL_NO_HETERO_BROKERS=1
        export TIMESTAMP="ablation_${label}_$(date +%Y%m%dT%H%M%S)"

        echo "[ABLATION:${label}] 启动 → ablation/results-${TARGET}_${TIMESTAMP}/"
        echo "  NO_REF=${CHATAFL_NO_REFINEMENT:-0} NO_FRONT=${CHATAFL_NO_FRONTIER:-0} NO_ADAPT=${CHATAFL_NO_ADAPTIVE:-0} NO_SP=${CHATAFL_NO_STATE_PROMPT:-0} THR=${CHATAFL_ABLATION_THRESHOLD:-adaptive}"

        cd "$BASE_DIR" || exit 1
        ./run_dev.sh "$RUNS" "$TIMEOUT" "$TARGET" chatafl-opt

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

launch_core_preset() {
  queue_group "adaptive_full"
  queue_group "wo_refinement" \
    "CHATAFL_NO_REFINEMENT=1"
  queue_group "wo_frontier" \
    "CHATAFL_NO_FRONTIER=1"
  queue_group "wo_state_prompt" \
    "CHATAFL_NO_STATE_PROMPT=1"
  queue_group "fixed200_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=200"
  queue_group "fixed512_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=512"
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
  launch_core_preset
  queue_group "wo_all" \
    "CHATAFL_NO_REFINEMENT=1" \
    "CHATAFL_NO_FRONTIER=1" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_NO_STATE_PROMPT=1" \
    "CHATAFL_ABLATION_THRESHOLD=512"
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

case "$PRESET" in
  core)
    PRESET_DESC="主矩阵：当前 shipped 行为 + 3 个策略 bundle + 2 个阈值对照"
    ;;
  threshold)
    PRESET_DESC="阈值子实验：adaptive vs fixed150 / 200 / 300 / 512"
    ;;
  appendix)
    PRESET_DESC="主矩阵 + wo_all 粗粒度 sanity-check"
    ;;
  legacy)
    PRESET_DESC="旧 bundled 7 组：仅用于复现与历史对齐（含显式 fixed100）"
    ;;
  *)
    echo "[ERROR] 未知 PRESET: ${PRESET}"
    echo "        可选：core | threshold | appendix | legacy"
    exit 1
    ;;
esac

echo "========================================================"
echo "  [ABLATION] 消融实验（批次执行）"
echo "  目标: ${TARGET}  每组重复: ${RUNS}  时长: ${TIMEOUT} min"
echo "  预设: ${PRESET}  批次大小: ${ABLATION_PARALLEL} 组/批"
echo "  说明: ${PRESET_DESC}"
echo "  结果目录: benchmark/results-${TARGET}_ablation_<label>/"
echo "========================================================"

case "$PRESET" in
  core)      launch_core_preset ;;
  threshold) launch_threshold_preset ;;
  appendix)  launch_appendix_preset ;;
  legacy)    launch_legacy_preset ;;
esac

GROUP_COUNT=${#GROUP_SPECS[@]}
echo ""
echo "  [ABLATION] ${GROUP_COUNT} 组已入队，分 $(( (GROUP_COUNT + ABLATION_PARALLEL - 1) / ABLATION_PARALLEL )) 批执行"
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
