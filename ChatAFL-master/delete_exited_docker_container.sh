#!/usr/bin/env bash
# ============================================================
# delete_exited_docker_container.sh — 删除所有已停止(exited)的容器
#
# 包装的原命令：
#   docker ps -a -q -f status=exited | xargs -r docker rm
#
# 用法：
#   ./delete_exited_docker_container.sh        # 先列出待删容器，确认后删除
#   ./delete_exited_docker_container.sh -y     # 跳过确认直接删除
#
# ⚠ 注意：消融实验结束后保留的容器一旦 exited，其中可能仍有
#   未 salvage 的结果数据（参见 run_ablation.sh 顶部警告与
#   salvage_from_container.sh）。确认数据已保存再删。
# ============================================================
set -u

ASSUME_YES=0
case "${1:-}" in
  -y|--yes) ASSUME_YES=1 ;;
  "")       ;;
  *) echo "用法: $0 [-y|--yes]"; exit 2 ;;
esac

IDS=$(docker ps -a -q -f status=exited)

if [[ -z "$IDS" ]]; then
  echo "没有已停止(exited)的容器，无需清理。"
  exit 0
fi

COUNT=$(wc -l <<< "$IDS")
echo "发现 ${COUNT} 个已停止的容器："
docker ps -a -f status=exited --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}'
echo ""

if (( ! ASSUME_YES )); then
  read -r -p "确认删除以上全部容器？(y/N) " ans
  [[ "$ans" =~ ^[Yy]$ ]] || { echo "已取消，未删除任何容器。"; exit 1; }
fi

REMOVED=$(echo "$IDS" | xargs -r docker rm | wc -l)
RC=$?

if (( RC != 0 )); then
  echo "[WARN] 有容器删除失败（xargs 退出码 ${RC}），成功删除 ${REMOVED}/${COUNT} 个，请检查上方输出。"
  exit 1
fi
echo "完成：已删除 ${REMOVED}/${COUNT} 个容器。"
