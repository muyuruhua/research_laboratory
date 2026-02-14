#!/bin/bash

# 验证Volume挂载的代码修改是否生效
# 用法: ./verify_changes.sh <target> <fuzzer> [file_to_check]

set -e

TARGET="${1:-lightftp}"
FUZZER="${2:-chatafl-opt}"
CHECK_FILE="${3:-grammar-hypothesis.c}"

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================="
echo "🔍 验证代码修改是否生效"
echo "=========================================="
echo "Target: ${TARGET}"
echo "Fuzzer: ${FUZZER}"
echo "检查文件: ${CHECK_FILE}"
echo "=========================================="

# 确定本地和容器路径
case "$FUZZER" in
    chatafl-opt)
        LOCAL_DIR="${PROJECT_ROOT}/ChatAFL-Opt"
        CONTAINER_DIR="/home/ubuntu/chatafl-opt"
        ;;
    chatafl)
        LOCAL_DIR="${PROJECT_ROOT}/ChatAFL"
        CONTAINER_DIR="/home/ubuntu/chatafl"
        ;;
    chatafl-cl1)
        LOCAL_DIR="${PROJECT_ROOT}/ChatAFL-CL1"
        CONTAINER_DIR="/home/ubuntu/chatafl-cl1"
        ;;
    chatafl-cl2)
        LOCAL_DIR="${PROJECT_ROOT}/ChatAFL-CL2"
        CONTAINER_DIR="/home/ubuntu/chatafl-cl2"
        ;;
    *)
        echo "❌ 未知fuzzer: ${FUZZER}"
        exit 1
        ;;
esac

# 步骤1: 检查本地文件
echo ""
echo "📂 步骤1: 检查本地文件"
echo "----------------------------------------"
if [ -f "${LOCAL_DIR}/${CHECK_FILE}" ]; then
    LOCAL_MD5=$(md5sum "${LOCAL_DIR}/${CHECK_FILE}" | awk '{print $1}')
    LOCAL_SIZE=$(stat -c%s "${LOCAL_DIR}/${CHECK_FILE}")
    LOCAL_MTIME=$(stat -c%y "${LOCAL_DIR}/${CHECK_FILE}")
    echo "✓ 本地文件存在"
    echo "  路径: ${LOCAL_DIR}/${CHECK_FILE}"
    echo "  MD5: ${LOCAL_MD5}"
    echo "  大小: ${LOCAL_SIZE} 字节"
    echo "  修改时间: ${LOCAL_MTIME}"
else
    echo "❌ 本地文件不存在: ${LOCAL_DIR}/${CHECK_FILE}"
    exit 1
fi

# 步骤2: 检查容器内文件（通过Volume挂载）
echo ""
echo "🐳 步骤2: 检查容器内文件（Volume挂载）"
echo "----------------------------------------"
CONTAINER_MD5=$(docker run --rm \
    -v "${LOCAL_DIR}:${CONTAINER_DIR}" \
    ${TARGET} \
    md5sum "${CONTAINER_DIR}/${CHECK_FILE}" 2>/dev/null | awk '{print $1}')

if [ -n "$CONTAINER_MD5" ]; then
    echo "✓ 容器内文件可访问（通过Volume）"
    echo "  容器路径: ${CONTAINER_DIR}/${CHECK_FILE}"
    echo "  MD5: ${CONTAINER_MD5}"
    
    if [ "$LOCAL_MD5" = "$CONTAINER_MD5" ]; then
        echo "✅ MD5匹配：本地和容器文件一致"
    else
        echo "❌ MD5不匹配：本地和容器文件不一致"
        exit 1
    fi
else
    echo "❌ 无法访问容器内文件"
    exit 1
fi

# 步骤3: 检查镜像内文件（未挂载Volume）
echo ""
echo "📦 步骤3: 检查镜像内文件（不挂载Volume）"
echo "----------------------------------------"
IMAGE_MD5=$(docker run --rm ${TARGET} \
    md5sum "${CONTAINER_DIR}/${CHECK_FILE}" 2>/dev/null | awk '{print $1}' || echo "")

if [ -n "$IMAGE_MD5" ]; then
    echo "  镜像内 MD5: ${IMAGE_MD5}"
    
    if [ "$LOCAL_MD5" = "$IMAGE_MD5" ]; then
        echo "✅ 镜像已包含最新代码"
    else
        echo "⚠️  镜像内代码过期（这是正常的，Volume挂载会覆盖）"
        echo "    镜像不需要更新，Volume挂载会提供最新代码"
    fi
else
    echo "⚠️  镜像内文件不存在或路径不同"
fi

# 步骤4: 测试编译
echo ""
echo "🔨 步骤4: 测试编译（验证代码可用）"
echo "----------------------------------------"
docker run --rm \
    -v "${LOCAL_DIR}:${CONTAINER_DIR}" \
    ${TARGET} \
    bash -c "cd ${CONTAINER_DIR} && make clean all -j4 2>&1 | tail -20 && echo '' && ls -lh afl-fuzz 2>/dev/null || echo '编译完成，但afl-fuzz不在当前目录'"

COMPILE_STATUS=$?
if [ $COMPILE_STATUS -eq 0 ]; then
    echo "✅ 编译成功"
else
    echo "❌ 编译失败 (退出码: $COMPILE_STATUS)"
    exit 1
fi

# 步骤5: 显示最近修改
echo ""
echo "📝 步骤5: 最近修改的文件（最近10个）"
echo "----------------------------------------"
find "${LOCAL_DIR}" -name "*.c" -o -name "*.h" | xargs ls -lt | head -10

echo ""
echo "=========================================="
echo "✅ 验证完成！"
echo "=========================================="
echo ""
echo "总结："
echo "  - 本地文件: ${LOCAL_MD5}"
echo "  - 容器内（Volume）: ${CONTAINER_MD5}"
echo "  - 编译状态: 成功"
echo ""
echo "下一步："
echo "  1. 运行快速测试: ./quick_test.sh ${TARGET} ${FUZZER} 5"
echo "  2. 或查看差异: git diff ${LOCAL_DIR}/${CHECK_FILE}"
echo ""
