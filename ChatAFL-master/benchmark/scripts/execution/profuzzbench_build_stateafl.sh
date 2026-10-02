#!/bin/bash

# ── StateAFL 镜像构建（开闭扩展：自动发现，不改 profuzzbench_build_all.sh 既有段）──
#
# 目标发现规则：凡 subjects/<proto>/<target>/ 下存在 Dockerfile-stateafl 的目录
# 即被构建为 <image>-stateafl（目标必须用 StateAFL 自带 afl-clang-fast 编译，
# 见 stateafl/README.md）。新增 StateAFL 目标 = 放入 Dockerfile-stateafl 即可，
# 本脚本与 exec 分发钩子无需修改。
#
# 用法：
#   PFBENCH=<benchmark路径> [FORCE=1|0] [NO_CACHE=--no-cache] \
#       scripts/execution/profuzzbench_build_stateafl.sh
#
#   FORCE=1（默认）：无条件重建（与 build_all 其余目标语义一致）
#   FORCE=0       ：镜像已存在则跳过（幂等快速路径）
#
# 前置条件：subject 目录内须有 stateafl/ 源码副本（由 setup.sh 同步），
# 以及 in-*-replay 种子目录（replayable 格式，StateAFL 的通用请求解析器只认
# 4 字节长度前缀格式）。

FORCE="${FORCE:-1}"

cd $PFBENCH || exit 1

found=0
for dockerfile in subjects/*/*/Dockerfile-stateafl; do
    [ -f "$dockerfile" ] || continue
    dir="$(dirname "$dockerfile")"
    dirbase="$(basename "$dir")"

    # 目录名 → 镜像名：默认转小写（ProFTPD→proftpd, Live555→live555,
    # Kamailio→kamailio, forked-daapd→forked-daapd）；小写后与镜像名不一致的
    # 目标在下面 case 中登记。
    img="$(echo "$dirbase" | tr 'A-Z' 'a-z')"
    case "$dirbase" in
        PureFTPD) img="pure-ftpd" ;;
    esac

    found=1
    if [ "$FORCE" != "1" ] && docker image inspect "${img}-stateafl" >/dev/null 2>&1; then
        echo "[stateafl] 镜像 ${img}-stateafl 已存在，跳过（FORCE=1 强制重建）"
        continue
    fi

    echo "[stateafl] Building ${img}-stateafl from ${dir} ..."
    docker build -f "$dockerfile" "$dir" -t "${img}-stateafl" --build-arg MAKE_OPT ${NO_CACHE} || exit 1
done

if [ "$found" -ne 1 ]; then
    echo "[stateafl] 未发现任何 Dockerfile-stateafl（当前支持 proftpd/live555/kamailio/forked-daapd）"
fi
