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

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
declare -a GROUP_PIDS=()
declare -a GROUP_LABELS=()

if [[ -z "$KEY" ]]; then
  echo "[ERROR] 请先 export KEY=\"sk-...\""
  exit 1
fi

run_group_bg() {
  local label="$1"
  shift

  (
    unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
          CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
          CHATAFL_ABLATION_THRESHOLD TIMESTAMP

    for assign in "$@"; do
      export "$assign"
    done

    export TIMESTAMP="ablation_${label}_$(date +%Y%m%dT%H%M%S)"

    echo "[ABLATION:${label}] 启动 → benchmark/results-${TARGET}_ablation_${label}_${TIMESTAMP}/"
    echo "  NO_REF=${CHATAFL_NO_REFINEMENT:-0} NO_FRONT=${CHATAFL_NO_FRONTIER:-0} NO_ADAPT=${CHATAFL_NO_ADAPTIVE:-0} NO_SP=${CHATAFL_NO_STATE_PROMPT:-0} THR=${CHATAFL_ABLATION_THRESHOLD:-adaptive}"

    cd "$BASE_DIR" || exit 1
    ./run_dev.sh "$RUNS" "$TIMEOUT" "$TARGET" chatafl-opt

    echo "[ABLATION:${label}] 完成"
  ) &

  local bg_pid=$!
  GROUP_PIDS+=("$bg_pid")
  GROUP_LABELS+=("$label")
  echo "[ABLATION] 已启动 ${label} (PID=${bg_pid})"
}

launch_core_preset() {
  run_group_bg "adaptive_full"
  run_group_bg "wo_refinement" \
    "CHATAFL_NO_REFINEMENT=1"
  run_group_bg "wo_frontier" \
    "CHATAFL_NO_FRONTIER=1"
  run_group_bg "wo_state_prompt" \
    "CHATAFL_NO_STATE_PROMPT=1"
  run_group_bg "fixed200_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=200"
  run_group_bg "fixed512_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=512"
}

launch_threshold_preset() {
  run_group_bg "adaptive_full"
  run_group_bg "fixed150_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=150"
  run_group_bg "fixed200_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=200"
  run_group_bg "fixed300_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=300"
  run_group_bg "fixed512_full" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=512"
}

launch_appendix_preset() {
  launch_core_preset
  run_group_bg "wo_all" \
    "CHATAFL_NO_REFINEMENT=1" \
    "CHATAFL_NO_FRONTIER=1" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_NO_STATE_PROMPT=1" \
    "CHATAFL_ABLATION_THRESHOLD=512"
}

launch_legacy_preset() {
  run_group_bg "full_opt"
  run_group_bg "wo_refinement" \
    "CHATAFL_NO_REFINEMENT=1"
  run_group_bg "wo_frontier" \
    "CHATAFL_NO_FRONTIER=1"
  run_group_bg "wo_adaptive_100" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=100"
  run_group_bg "wo_adaptive_512" \
    "CHATAFL_NO_ADAPTIVE=1" \
    "CHATAFL_ABLATION_THRESHOLD=512"
  run_group_bg "wo_state_prompt" \
    "CHATAFL_NO_STATE_PROMPT=1"
  run_group_bg "wo_all" \
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
echo "  [ABLATION] 并行启动消融实验"
echo "  目标: ${TARGET}  每组重复: ${RUNS}  时长: ${TIMEOUT} min"
echo "  预设: ${PRESET}"
echo "  说明: ${PRESET_DESC}"
echo "  结果目录: benchmark/results-${TARGET}_ablation_<label>/"
echo "========================================================"

case "$PRESET" in
  core)      launch_core_preset ;;
  threshold) launch_threshold_preset ;;
  appendix)  launch_appendix_preset ;;
  legacy)    launch_legacy_preset ;;
esac

GROUP_COUNT=${#GROUP_LABELS[@]}
TOTAL_CONTAINERS=$((RUNS * GROUP_COUNT))

echo ""
echo "  [ABLATION] ${GROUP_COUNT} 组已全部在后台启动，等待完成..."
echo "  可用 'docker ps | grep ${TARGET}' 查看运行中的容器（应有 ${TOTAL_CONTAINERS} 个）"
echo "  可用 'sudo ./monitor.sh' 监控整体进度"
echo ""

failed=0
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

echo ""
echo "========================================================"
echo "  [ABLATION] 预设 ${PRESET} 全部完成！"
[[ $failed -gt 0 ]] && echo "  ⚠️  WARNING: ${failed} 组子进程返回非零退出码，请检查日志"
echo "  结果目录："
ls -d "$BASE_DIR/benchmark/results-${TARGET}_ablation_"* 2>/dev/null | sort | xargs -r -I{} basename {}
echo "========================================================"
