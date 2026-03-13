#!/bin/bash
# ============================================================
# run_ablation.sh — 7 组消融实验全并行（约 24.5 小时完成）
#
# 用法：
#   export KEY="sk-..."
#   export SKIPCOUNT=40
#   sudo -E ./run_ablation.sh [TARGET] [RUNS] [TIMEOUT_MIN]
#
# 默认值：TARGET=live555  RUNS=5  TIMEOUT=1470
#
# 资源：7组×5容器=35容器，每容器 --cpus=1 → 32核机器约109%利用率，
#       Linux CFS 调度器正常处理，实际耗时仅约 1470 min。
# ============================================================

TARGET="${1:-live555}"
RUNS="${2:-5}"
TIMEOUT="${3:-1470}"

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ -z "$KEY" ]]; then
  echo "[ERROR] 请先 export KEY=\"sk-...\""
  exit 1
fi

# 在子进程中运行单组（每组独立子shell，env var 互不干扰）
# 用法: run_group_bg <label> [VAR=VALUE ...]
run_group_bg() {
  local label="$1"; shift

  (
    # 清空消融变量，再按需设置
    unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
          CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
          CHATAFL_ABLATION_THRESHOLD
    for assign in "$@"; do export $assign; done

    # 注入 label 作为 TIMESTAMP，结果目录名变为 results-live555_ablation_<label>/
    # profuzzbench_exec_all_dev.sh 已改为 ${TIMESTAMP:-$(date...)}，不会覆盖此值
    export TIMESTAMP="ablation_${label}"

    echo "[ABLATION:${label}] 启动 → benchmark/results-${TARGET}_ablation_${label}/"
    echo "  NO_REF=${CHATAFL_NO_REFINEMENT:-0} NO_FRONT=${CHATAFL_NO_FRONTIER:-0} NO_ADAPT=${CHATAFL_NO_ADAPTIVE:-0} NO_SP=${CHATAFL_NO_STATE_PROMPT:-0} THR=${CHATAFL_ABLATION_THRESHOLD:-auto}"

    cd "$BASE_DIR"
    ./run_dev.sh "$RUNS" "$TIMEOUT" "$TARGET" chatafl-opt

    echo "[ABLATION:${label}] 完成"
  ) &
  local bg_pid=$!
  echo "[ABLATION] 已启动 ${label} (PID=${bg_pid})"
}

echo "========================================================"
echo "  [ABLATION] 并行启动 7 组消融实验"
echo "  目标: ${TARGET}  每组重复: ${RUNS}  时长: ${TIMEOUT} min"
echo "  结果目录将命名为: benchmark/results-${TARGET}_ablation_<label>/"
echo "  预计完成时间: ~${TIMEOUT} 分钟后（所有组并行，约 24.5 小时）"
echo "========================================================"

# ① Full-Opt（消融基准，所有优化开启）
run_group_bg "full_opt"

# ② w/o Refinement（Tier-2 LLM 精炼禁用；Tier-1 仍运行）
run_group_bg "wo_refinement" \
  "CHATAFL_NO_REFINEMENT=1"

# ③ w/o Frontier（拓扑加权+接受度惩罚联合禁用）
run_group_bg "wo_frontier" \
  "CHATAFL_NO_FRONTIER=1"

# ④ w/o Adaptive（固定阈值 100，Opt 最激进频率）
run_group_bg "wo_adaptive_100" \
  "CHATAFL_NO_ADAPTIVE=1"

# ⑤ w/o Adaptive（固定阈值 512，与 ChatAFL 基线触发频率对齐）
run_group_bg "wo_adaptive_512" \
  "CHATAFL_NO_ADAPTIVE=1" \
  "CHATAFL_ABLATION_THRESHOLD=512"

# ⑥ w/o State-Prompt（rich prompt + actions[] 联合禁用）
run_group_bg "wo_state_prompt" \
  "CHATAFL_NO_STATE_PROMPT=1"

# ⑦ w/o All（量化不可消融工程改进的基础贡献）
run_group_bg "wo_all" \
  "CHATAFL_NO_REFINEMENT=1" \
  "CHATAFL_NO_FRONTIER=1" \
  "CHATAFL_NO_ADAPTIVE=1" \
  "CHATAFL_NO_STATE_PROMPT=1" \
  "CHATAFL_ABLATION_THRESHOLD=512"

echo ""
echo "  [ABLATION] 7 组已全部在后台启动，等待完成..."
echo "  可用 'docker ps | grep ${TARGET}' 查看运行中的容器（应有 $((RUNS * 7)) 个）"
echo "  可用 'sudo ./monitor.sh' 监控整体进度"
echo ""

# 等待所有子进程完成，收集退出码
failed=0
while wait -n 2>/dev/null; ret=$?; [[ $ret -ne 127 ]]; do
  [[ $ret -ne 0 ]] && failed=$((failed+1))
done
# bash < 4.3 兜底（wait -n 不可用时直接 wait）
wait

echo ""
echo "========================================================"
echo "  [ABLATION] 全部 7 组消融实验完成！"
[[ $failed -gt 0 ]] && echo "  ⚠️  WARNING: ${failed} 组子进程返回非零退出码，请检查日志"
echo "  结果目录："
ls -d "$BASE_DIR/benchmark/results-${TARGET}_ablation_"* 2>/dev/null | sort | xargs -I{} basename {}
echo "========================================================"
