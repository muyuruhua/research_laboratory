#!/bin/bash
# 快速验证ChatAFL-Enhanced功能是否正确启用
# 用法: ./verify_enhanced_config.sh [docker_image_name]

set -e

DOCKER_IMAGE=${1:-lightftp}

echo "========================================="
echo "验证 ChatAFL-Enhanced 配置"
echo "========================================="
echo ""

echo "📋 测试镜像: $DOCKER_IMAGE"
echo ""

echo "🔍 步骤1: 检查Docker镜像是否存在..."
if ! docker images | grep -q "$DOCKER_IMAGE"; then
    echo "❌ Docker镜像不存在: $DOCKER_IMAGE"
    exit 1
fi
echo "✅ 镜像存在"
echo ""

echo "🔍 步骤2: 检查afl-fuzz可执行文件..."
docker run --rm "$DOCKER_IMAGE" bash -c "ls -la /home/ubuntu/chatafl-enhanced/afl-fuzz" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✅ afl-fuzz存在"
else
    echo "❌ afl-fuzz不存在"
    exit 1
fi
echo ""

echo "🔍 步骤3: 测试环境变量传递..."
ENV_TEST=$(docker run --rm \
    -e CHATAFL_CEGAR_ENABLE=1 \
    -e TEST_VAR=123 \
    "$DOCKER_IMAGE" bash -c 'echo "CHATAFL_CEGAR_ENABLE=$CHATAFL_CEGAR_ENABLE"')

if [[ "$ENV_TEST" == *"CHATAFL_CEGAR_ENABLE=1"* ]]; then
    echo "✅ 环境变量可以正确传递"
else
    echo "❌ 环境变量传递失败"
    echo "   输出: $ENV_TEST"
    exit 1
fi
echo ""

echo "🔍 步骤4: 检查Enhanced模块文件..."
MODULES_CHECK=$(docker run --rm "$DOCKER_IMAGE" bash -c "ls -1 /home/ubuntu/chatafl-enhanced/*.h 2>/dev/null | grep -E '(verifier|cegar|state-graph|state-scheduler)' | wc -l")

if [ "$MODULES_CHECK" -ge 4 ]; then
    echo "✅ Enhanced模块文件存在 ($MODULES_CHECK 个头文件)"
else
    echo "⚠️  部分模块文件可能缺失 (找到 $MODULES_CHECK 个)"
fi
echo ""

echo "🔍 步骤5: 验证配置脚本中的环境变量..."
if [ -f "compare_fuzzers_docker.sh" ]; then
    ENV_COUNT=$(grep -A 20 "启动ChatAFL-Enhanced容器" compare_fuzzers_docker.sh | grep "^    -e CHATAFL" | wc -l)
    if [ "$ENV_COUNT" -ge 10 ]; then
        echo "✅ 配置脚本包含 $ENV_COUNT 个Enhanced环境变量"
        echo ""
        echo "   已配置的环境变量:"
        grep -A 20 "启动ChatAFL-Enhanced容器" compare_fuzzers_docker.sh | grep "^    -e CHATAFL" | sed 's/^    /     /'
    else
        echo "⚠️  配置脚本只有 $ENV_COUNT 个环境变量（预期>=10）"
    fi
else
    echo "⚠️  未找到 compare_fuzzers_docker.sh"
fi
echo ""

echo "========================================="
echo "✅ 验证完成！"
echo "========================================="
echo ""
echo "下一步:"
echo "  1. 运行快速测试 (10分钟):"
echo "     ./compare_fuzzers_docker.sh LightFTP FTP 10"
echo ""
echo "  2. 运行完整测试 (60分钟):"
echo "     ./compare_fuzzers_docker.sh LightFTP FTP 60"
echo ""
echo "  3. 查看配置文档:"
echo "     cat ENHANCED_FEATURES_ENABLED.md"
echo ""
