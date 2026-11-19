#!/usr/bin/env bash
# ============================================================
# run_patch.sh — 批量隔离执行预设命令
#
# 效果等同于：为每条命令单独打开一个终端窗口执行。
# 实现方式：每条命令在独立的 bash 子进程中运行，因此
#   - 各命令之间的 export / unset 互不可见（无环境污染）
#   - 每条命令的输出写入各自的日志文件（= 各终端窗口的屏幕内容）
#   - 默认并行执行（= 同时打开多个终端窗口）
#     ./run_patch.sh --sequential  则逐条顺序执行
#
# 用法：
#   ./run_patch.sh              # 并行执行全部预设命令
#   ./run_patch.sh --sequential # 顺序执行（一条结束后才跑下一条）
#
# 命令清单：run_patch.txt（与脚本同目录），每行一条完整命令，
# 保持终端手敲原样（含 cd / export / unset）。空行忽略；
# # 开头的行作为注释跳过，可用来临时禁用某条命令。
#
# 日志：logs/run_patch/<时间戳>/<序号>_<名称>.log
# 运行期间可 tail -f 对应日志实时查看输出（等效于盯着那个终端窗口）。
#
# Ctrl+C 不会中断本脚本与子任务：主进程只打印提示并继续等待，
# 每个子任务运行在独立进程组中且对 SIGINT 免疫，只有全部子任务
# 结束后脚本才会退出。如确需中止：kill -TERM <脚本PID>
# ============================================================
set -u -m   # -m: 每个后台任务独占进程组，Ctrl+C 的终端信号不再波及子任务

BASE_DIR="/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master"

# ── 从 run_patch.txt 读取预设命令（每行一条）────────────────
CMDS_FILE="$BASE_DIR/run_patch.txt"
if [[ ! -r "$CMDS_FILE" ]]; then
  echo "[ERROR] 找不到命令文件: $CMDS_FILE"
  exit 2
fi

COMMANDS=()
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"                          # 兼容 Windows 换行符
  [[ -z "${line//[[:space:]]/}" ]] && continue  # 跳过空行
  [[ "$line" =~ ^[[:space:]]*# ]] && continue   # 跳过注释行
  COMMANDS+=("$line")
done < "$CMDS_FILE"

if (( ${#COMMANDS[@]} == 0 )); then
  echo "[ERROR] $CMDS_FILE 中没有可执行的命令"
  exit 2
fi

# 自动生成任务名称（用于日志文件与汇总显示）：
# 优先取命令中 run_ablation.sh 的 <目标名> 与 -g <臂名>，便于对号入座；
# 识别不出时退化为 cmd。序号前缀保证日志文件名永不重复。
derive_name() {
  local cmd="$1" hint="" arm=""
  hint=$(printf '%s' "$cmd" | grep -oP 'run_ablation\.sh\s+\K[^\s]+' || true)
  arm=$(printf '%s' "$cmd" | grep -oP '\s-g\s+\K[^\s]+' || true)
  [[ -n "$hint" && -n "$arm" ]] && hint="${hint}_${arm}"
  hint=$(printf '%s' "${hint:-cmd}" | tr -c 'A-Za-z0-9_.-' '_' | sed 's/_*$//')
  printf '%s' "${hint:-cmd}"
}

# ── 运行模式 ──────────────────────────────────────────────
MODE="parallel"
case "${1:-}" in
  --sequential|-s) MODE="sequential" ;;
  "")              ;;
  *) echo "用法: $0 [--sequential]"; exit 2 ;;
esac

N=${#COMMANDS[@]}
TS=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$BASE_DIR/logs/run_patch/$TS"
mkdir -p "$LOG_DIR"

echo "══════════════════════════════════════════════════════════"
echo " run_patch.sh  模式: $MODE  任务数: $N"
echo " 日志目录: $LOG_DIR"
echo "══════════════════════════════════════════════════════════"

# 每个任务一个后台子进程：bash -c 保证环境隔离（等同独立终端窗口），
# 退出码与耗时写入 .status 文件供主进程汇总。
# 子进程内 trap '' INT：SIGINT 设为忽略会被整棵进程树继承，
# 保证 Ctrl+C 时任务本身（含 run_ablation.sh 及其后代）不受影响。

# Ctrl+C：仅提示，绝不终止；只有全部子任务结束脚本才退出
on_int() {
  echo ""
  echo "[run_patch] 收到 Ctrl+C：已忽略，子任务继续运行。等待全部任务结束..."
}
trap on_int INT

# kill -TERM <脚本PID>：手动中止入口，按进程组终止所有子任务
cleanup() {
  echo ""
  echo "[run_patch] 收到 TERM，按进程组终止所有子任务..."
  for pid in "${CHILD_PIDS[@]:-}"; do
    kill -- -"$pid" 2>/dev/null || kill "$pid" 2>/dev/null
  done
  exit 130
}

declare -a CHILD_PIDS=()
i=0
for cmd in "${COMMANDS[@]}"; do
  i=$((i+1))
  name="$(derive_name "$cmd")"
  prefix=$(printf '%02d' "$i")
  log="$LOG_DIR/${prefix}_${name}.log"
  status="$LOG_DIR/${prefix}_${name}.status"

  echo "[${i}/${N}] 启动: $name"
  echo "       实时查看: tail -f $log"
  (
    trap '' INT
    start=$(date +%s)
    cd "$BASE_DIR" && bash -c "$cmd" >"$log" 2>&1
    rc=$?
    end=$(date +%s)
    printf '%s\t%s\n' "$rc" "$((end-start))" > "$status"
  ) &
  CHILD_PIDS+=($!)

  # 顺序模式：等当前任务真正结束（.status 落盘）后再启动下一条
  if [[ "$MODE" == "sequential" ]]; then
    while [[ ! -s "$status" ]]; do
      wait "${CHILD_PIDS[-1]}" 2>/dev/null || true
      sleep 0.2
    done
  fi
done

trap cleanup TERM

echo ""
echo "等待全部任务结束..."
for pid in "${CHILD_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done

# ── 汇总 ──────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════"
echo " 执行结果汇总"
echo "══════════════════════════════════════════════════════════"
ALL_OK=1
i=0
for cmd in "${COMMANDS[@]}"; do
  i=$((i+1))
  name="$(derive_name "$cmd")"
  prefix=$(printf '%02d' "$i")
  status="$LOG_DIR/${prefix}_${name}.status"
  rc=$(cut -f1 "$status" 2>/dev/null || echo "?")
  secs=$(cut -f2 "$status" 2>/dev/null || echo "?")
  if [[ "$rc" == "0" ]]; then mark="OK  "; else mark="FAIL"; ALL_OK=0; fi
  printf ' [%s] %-22s 退出码=%-3s 耗时=%sm%ss\n' "$mark" "$name" "$rc" "$((secs/60))" "$((secs%60))"
  echo "        日志: $LOG_DIR/${prefix}_${name}.log"
done
echo "══════════════════════════════════════════════════════════"

exit $((1 - ALL_OK))
