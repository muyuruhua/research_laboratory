#!/usr/bin/env bash
# ============================================================
# delete_docker_container.sh — 停止所有运行中的容器，并删除所有已停止的容器
#
# 包装的原命令：
#   docker ps -q | xargs -r docker stop && docker ps -a -q -f status=exited | xargs -r docker rm
#
# 用法：
#   ./delete_docker_container.sh        # 先列出容器，确认后执行
#   ./delete_docker_container.sh -y     # 跳过确认直接执行
#
# ⚠ 警告：这会停止本机所有正在运行的容器——包括进行中的实验
#   campaign（fuzzing 数据可能来不及回收），并删除全部已停止容器
#   （其中可能有未 salvage 的结果，参见 run_ablation.sh 顶部警告与
#   salvage_from_container.sh）。确认数据已保存再执行。
# ============================================================
set -u

ASSUME_YES=0
case "${1:-}" in
  -y|--yes) ASSUME_YES=1 ;;
  "")       ;;
  *) echo "用法: $0 [-y|--yes]"; exit 2 ;;
esac

RUNNING_IDS=$(docker ps -q)
EXITED_IDS=$(docker ps -a -q -f status=exited)

if [[ -z "$RUNNING_IDS" && -z "$EXITED_IDS" ]]; then
  echo "没有任何容器（运行中或已停止），无需清理。"
  exit 0
fi

if [[ -n "$RUNNING_IDS" ]]; then
  RCOUNT=$(wc -l <<< "$RUNNING_IDS")
  echo "⚠ 将【停止】以下 ${RCOUNT} 个正在运行的容器："
  docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}'
  echo ""
fi

if [[ -n "$EXITED_IDS" ]]; then
  ECOUNT=$(wc -l <<< "$EXITED_IDS")
  echo "将【删除】以下 ${ECOUNT} 个已停止(exited)的容器："
  docker ps -a -f status=exited --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}'
  echo ""
  echo "（注：上面停止的容器停止后也会转为 exited，将被一并删除）"
fi

if (( ! ASSUME_YES )); then
  read -r -p "确认停止并删除以上全部容器？(y/N) " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { echo "已取消，未做任何改动。"; exit 1; }
fi

# 与原命令语义一致：先停止全部运行容器，成功后再删除全部 exited 容器
STOPPED=$(docker ps -q | xargs -r docker stop | wc -l)
RC1=$?
if (( RC1 != 0 )); then
  echo "[WARN] docker stop 有失败项（退出码 ${RC1}），已停止 ${STOPPED} 个；按原命令语义跳过删除步骤。"
  exit 1
fi

REMOVED=$(docker ps -a -q -f status=exited | xargs -r docker rm | wc -l)
RC2=$?
if (( RC2 != 0 )); then
  echo "[WARN] docker rm 有失败项（退出码 ${RC2}），已删除 ${REMOVED} 个，请检查上方输出。"
  exit 1
fi
echo "完成：停止 ${STOPPED} 个容器，删除 ${REMOVED} 个容器。"
