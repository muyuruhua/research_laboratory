#!/bin/bash

# 快速开发测试脚本 - 直接挂载本地代码到已有镜像
# 用法：./quick_test.sh <target_image> <fuzzer> <timeout_minutes>
# 示例：./quick_test.sh lightftp chatafl-opt 5

set -e

TARGET_IMAGE="${1:-lightftp}"
FUZZER="${2:-chatafl-opt}"
TIMEOUT_MINUTES="${3:-5}"
TIMEOUT_SECONDS=$((TIMEOUT_MINUTES * 60))

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
WORKDIR="/home/ubuntu/experiments"
OUTDIR="results-${FUZZER}"

# 根据target确定protocol和options
case "$TARGET_IMAGE" in
    lightftp|bftpd|proftpd|pure-ftpd)
        PROTOCOL="FTP"
        AFL_OPTIONS="-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t 5000+"
        ;;
    live555)
        PROTOCOL="RTSP"
        AFL_OPTIONS="-P RTSP -D 10000 -q 3 -s 3 -E -K -m none -t 5000+"
        ;;
    kamailio)
        PROTOCOL="SIP"
        AFL_OPTIONS="-P SIP -D 10000 -q 3 -s 3 -E -K -m none -t 5000+"
        ;;
    exim)
        PROTOCOL="SMTP"
        AFL_OPTIONS="-P SMTP -D 10000 -q 3 -s 3 -E -K -m none -t 5000+"
        ;;
    lighttpd*)
        PROTOCOL="HTTP"
        AFL_OPTIONS="-P HTTP -D 10000 -K -m none -t 5000+"
        ;;
    forked-daapd)
        PROTOCOL="DAAP"
        AFL_OPTIONS="-P DAAP -D 10000 -m none -t 5000+"
        ;;
    *)
        echo "⚠ 警告: 未知target ${TARGET_IMAGE}，使用默认FTP配置"
        PROTOCOL="FTP"
        AFL_OPTIONS="-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t 5000+"
        ;;
esac

echo "=========================================="
echo "快速开发测试模式 (Volume挂载)"
echo "=========================================="
echo "镜像: ${TARGET_IMAGE}"
echo "Fuzzer: ${FUZZER}"
echo "超时: ${TIMEOUT_MINUTES} 分钟"
echo "本地代码: ${PROJECT_ROOT}/${FUZZER^^}"
echo "=========================================="

# 检查镜像是否存在
if ! docker image inspect ${TARGET_IMAGE} >/dev/null 2>&1; then
    echo "❌ 错误: 镜像 ${TARGET_IMAGE} 不存在"
    echo ""
    echo "请先构建镜像："
    echo "  cd ${PROJECT_ROOT}/benchmark/subjects/FTP/${TARGET_IMAGE^^}"
    echo "  export KEY=\"your-api-key\""
    echo "  sudo docker build --no-cache -t ${TARGET_IMAGE} ."
    echo ""
    exit 1
fi

# 确定本地fuzzer目录
case "$FUZZER" in
    chatafl-opt)
        LOCAL_FUZZER_DIR="${PROJECT_ROOT}/ChatAFL-Opt"
        CONTAINER_FUZZER_DIR="/home/ubuntu/chatafl-opt"
        ENABLE_HYPOTHESIS=1
        ;;
    chatafl)
        LOCAL_FUZZER_DIR="${PROJECT_ROOT}/ChatAFL"
        CONTAINER_FUZZER_DIR="/home/ubuntu/chatafl"
        ENABLE_HYPOTHESIS=0
        ;;
    chatafl-cl1)
        LOCAL_FUZZER_DIR="${PROJECT_ROOT}/ChatAFL-CL1"
        CONTAINER_FUZZER_DIR="/home/ubuntu/chatafl-cl1"
        ENABLE_HYPOTHESIS=0
        ;;
    chatafl-cl2)
        LOCAL_FUZZER_DIR="${PROJECT_ROOT}/ChatAFL-CL2"
        CONTAINER_FUZZER_DIR="/home/ubuntu/chatafl-cl2"
        ENABLE_HYPOTHESIS=0
        ;;
    aflnet)
        # aflnet不挂载，使用镜像内编译好的版本
        LOCAL_FUZZER_DIR=""
        CONTAINER_FUZZER_DIR="/home/ubuntu/aflnet"
        ENABLE_HYPOTHESIS=0
        ;;
    *)
        echo "❌ 错误: 未知fuzzer ${FUZZER}"
        echo "支持的fuzzer: chatafl-opt, chatafl, chatafl-cl1, chatafl-cl2, aflnet"
        exit 1
        ;;
esac

# 检查环境变量
if [ "$ENABLE_HYPOTHESIS" == "1" ] && [ -z "$KEY" ]; then
    echo "⚠ 警告: 未设置 KEY 环境变量，Grammar Hypothesis 功能可能无法使用"
    echo "请运行: export KEY=\"your-api-key\""
fi

# 挂载输出目录到本地（便于实时查看）
RESULTS_DIR="${PROJECT_ROOT}/quick_test_results/${FUZZER}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "${RESULTS_DIR}"

echo "📂 结果输出: ${RESULTS_DIR}"
if [ -n "$LOCAL_FUZZER_DIR" ]; then
    echo "📦 代码挂载: ${LOCAL_FUZZER_DIR} -> ${CONTAINER_FUZZER_DIR}"
fi
echo "🎯 协议: ${PROTOCOL}"
echo "⚙️  AFL选项: ${AFL_OPTIONS}"
echo "=========================================="

# 运行容器 (使用数组避免shell转义问题)
docker run --rm -it --cpus=1 \
  -e "KEY=${KEY}" \
  ${ENABLE_HYPOTHESIS:+-e CHATAFL_HYPOTHESIS=1} \
  ${LOCAL_FUZZER_DIR:+-v "${LOCAL_FUZZER_DIR}:${CONTAINER_FUZZER_DIR}"} \
  -v "${RESULTS_DIR}:/home/ubuntu/results" \
  ${TARGET_IMAGE} /bin/bash -c "
    set -e
    cd ${WORKDIR}
    echo '✓ 进入工作目录: \$(pwd)'
    echo '✓ 验证Fuzzer路径:'
    ls -la /home/ubuntu/${FUZZER}/ | head -15
    echo ''
    echo '🚀 开始 ${TIMEOUT_MINUTES} 分钟测试...'
    echo 'AFL命令: run ${FUZZER} ${OUTDIR} \"${AFL_OPTIONS}\" ${TIMEOUT_SECONDS} 1'
    timeout ${TIMEOUT_SECONDS} run ${FUZZER} ${OUTDIR} '${AFL_OPTIONS}' ${TIMEOUT_SECONDS} 1 || true
    echo ''
    echo '📥 复制结果到 /home/ubuntu/results/'
    cp -r ${OUTDIR}* /home/ubuntu/results/ 2>/dev/null || echo '⚠ 无结果输出'
    echo '✅ 测试完成!'
"

echo ""
echo "=========================================="
echo "✅ 测试完成！"
echo "📊 结果目录: ${RESULTS_DIR}"
echo "=========================================="
echo ""
echo "查看日志："
echo "  tail -100 ${RESULTS_DIR}/${OUTDIR}/fuzzer-0/fuzz.log"
echo ""
echo "查看覆盖率："
echo "  cat ${RESULTS_DIR}/${OUTDIR}/fuzzer-0/plot_data"
echo ""
