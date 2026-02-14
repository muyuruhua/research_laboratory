#!/bin/bash

# 快速重新构建镜像并测试脚本
# 用法: ./rebuild_and_test.sh <target> <fuzzer> <timeout_minutes>
# 示例: ./rebuild_and_test.sh lightftp chatafl-opt 5

set -e

TARGET="${1:-lightftp}"
FUZZER="${2:-chatafl-opt}"
TIMEOUT="${3:-5}"

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${PROJECT_ROOT}/benchmark/subjects/FTP/${TARGET^^}"

echo "=========================================="
echo "🔧 重新构建 + 测试"
echo "=========================================="
echo "Target: ${TARGET}"
echo "Fuzzer: ${FUZZER}"
echo "Timeout: ${TIMEOUT} 分钟"
echo "=========================================="

# 检查环境变量
if [ -z "$KEY" ]; then
    echo "❌ 错误: 未设置 KEY 环境变量"
    echo "请运行: export KEY=\"your-api-key\""
    exit 1
fi

# 检查目标目录
if [ ! -d "$TARGET_DIR" ]; then
    echo "❌ 错误: 目标目录不存在: $TARGET_DIR"
    exit 1
fi

# 步骤1: 重新构建镜像
echo ""
echo "📦 步骤1: 重新构建镜像..."
echo "----------------------------------------"
cd "$TARGET_DIR"
sudo docker build --no-cache -t ${TARGET} . 2>&1 | tee /tmp/${TARGET}-rebuild.log | grep -E "Step [0-9]+/[0-9]+|Successfully|error|Error|ERROR" || true
BUILD_STATUS=$?

if [ $BUILD_STATUS -ne 0 ]; then
    echo "❌ 构建失败！查看完整日志: /tmp/${TARGET}-rebuild.log"
    exit 1
fi

echo "✅ 镜像构建成功"

# 步骤2: 快速测试
echo ""
echo "🚀 步骤2: 运行快速测试..."
echo "----------------------------------------"
cd "$PROJECT_ROOT"
./quick_test.sh ${TARGET} ${FUZZER} ${TIMEOUT}

echo ""
echo "=========================================="
echo "✅ 全部完成！"
echo "=========================================="
