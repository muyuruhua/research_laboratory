#!/bin/bash
#
# ChatAFL-Enhanced 快速测试脚本 (5分钟示例)
# 使用 Kamailio (SIP服务器) 作为测试目标
#

set -e

echo "======================================================================"
echo "ChatAFL-Enhanced 快速模糊测试 (5分钟)"
echo "======================================================================"
echo ""

# 检查 API Key
if [ -z "$KEY" ]; then
    echo "❌ 错误：未设置 OpenAI API Key"
    echo ""
    echo "请先设置环境变量："
    echo "  export KEY=\"your-openai-api-key\""
    echo ""
    echo "然后重新运行："
    echo "  sudo -E ./quick_test_enhanced.sh"
    exit 1
fi

echo "✅ API Key 已设置"
echo ""

# 参数配置
NUM_CONTAINERS=1        # 使用1个容器（快速测试）
TIMEOUT_MINUTES=5       # 运行5分钟
TARGET="kamailio"       # 测试目标：Kamailio SIP服务器
FUZZER="chatafl-enhanced"

echo "======================================================================"
echo "测试配置"
echo "======================================================================"
echo "目标程序:     $TARGET (SIP协议服务器)"
echo "Fuzzer:       $FUZZER"
echo "容器数量:     $NUM_CONTAINERS"
echo "运行时长:     $TIMEOUT_MINUTES 分钟"
echo "======================================================================"
echo ""

# 询问是否继续
read -p "是否继续？(y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "测试已取消"
    exit 0
fi

echo ""
echo "======================================================================"
echo "步骤 1/3: 更新 API Key"
echo "======================================================================"

# 更新 ChatAFL-Enhanced 的 API Key
echo "正在更新 ChatAFL-Enhanced/chat-llm.h ..."

# 由于 ChatAFL-Enhanced 已移除硬编码 token，我们通过环境变量传递
# 但为了兼容性，我们仍然检查文件
if [ -f "ChatAFL-Enhanced/chat-llm.h" ]; then
    echo "✅ ChatAFL-Enhanced API 配置就绪（使用环境变量 KEY）"
else
    echo "❌ 找不到 ChatAFL-Enhanced/chat-llm.h"
    exit 1
fi

echo ""
echo "======================================================================"
echo "步骤 2/3: 检查 Docker 镜像"
echo "======================================================================"

# 检查是否已构建 Docker 镜像
if docker images | grep -q "$TARGET"; then
    echo "✅ Docker 镜像 '$TARGET' 已存在"
    read -p "是否重新构建镜像？(y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "正在重新构建..."
        ./setup.sh
    fi
else
    echo "⚠️  Docker 镜像 '$TARGET' 不存在，需要先构建"
    echo "正在运行 setup.sh 构建镜像（这可能需要几分钟）..."
    ./setup.sh
fi

echo ""
echo "======================================================================"
echo "步骤 3/3: 开始模糊测试"
echo "======================================================================"
echo ""
echo "📊 实时统计将在测试开始后显示"
echo "⏱️  测试将在 $TIMEOUT_MINUTES 分钟后自动停止"
echo ""
echo "按 Ctrl+C 可随时停止测试"
echo ""

# 等待3秒
echo -n "测试将在 3 秒后开始"
for i in {3..1}; do
    sleep 1
    echo -n "."
done
echo " 开始！"
echo ""

# 记录开始时间
START_TIME=$(date +%s)

# 执行模糊测试
./run.sh $NUM_CONTAINERS $TIMEOUT_MINUTES $TARGET $FUZZER

# 记录结束时间
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "======================================================================"
echo "测试完成！"
echo "======================================================================"
echo "实际运行时间: $((ELAPSED / 60)) 分 $((ELAPSED % 60)) 秒"
echo ""

# 查找结果目录
RESULT_DIR=$(ls -td res_${TARGET}_* 2>/dev/null | head -1)

if [ -n "$RESULT_DIR" ] && [ -d "$RESULT_DIR" ]; then
    echo "结果目录: $RESULT_DIR"
    echo ""
    
    # 显示基本统计
    if [ -d "$RESULT_DIR/replayable-queue" ]; then
        QUEUE_SIZE=$(ls -1 "$RESULT_DIR/replayable-queue" 2>/dev/null | wc -l)
        echo "📈 生成的测试用例: $QUEUE_SIZE 个"
    fi
    
    if [ -d "$RESULT_DIR/replayable-crashes" ]; then
        CRASH_COUNT=$(ls -1 "$RESULT_DIR/replayable-crashes" 2>/dev/null | wc -l)
        echo "💥 发现的崩溃: $CRASH_COUNT 个"
    fi
    
    if [ -d "$RESULT_DIR/replayable-hangs" ]; then
        HANG_COUNT=$(ls -1 "$RESULT_DIR/replayable-hangs" 2>/dev/null | wc -l)
        echo "⏸️  发现的挂起: $HANG_COUNT 个"
    fi
    
    if [ -f "$RESULT_DIR/plot_data" ]; then
        echo ""
        echo "📊 详细统计数据:"
        tail -1 "$RESULT_DIR/plot_data"
    fi
    
    echo ""
    echo "======================================================================"
    echo "查看详细结果:"
    echo "======================================================================"
    echo "1. 队列目录:   $RESULT_DIR/replayable-queue/"
    echo "2. 崩溃目录:   $RESULT_DIR/replayable-crashes/"
    echo "3. 覆盖率数据: $RESULT_DIR/plot_data"
    echo "4. 状态机图:   $RESULT_DIR/ipsm.dot"
    echo ""
    echo "可视化状态机:"
    echo "  dot -Tpng $RESULT_DIR/ipsm.dot -o $RESULT_DIR/ipsm.png"
    echo ""
else
    echo "⚠️  未找到结果目录"
fi

echo "======================================================================"
echo "💡 提示"
echo "======================================================================"
echo "1. 运行更长时间的测试："
echo "   sudo -E ./run.sh 2 60 kamailio chatafl-enhanced  # 60分钟"
echo ""
echo "2. 对比 ChatAFL 和 ChatAFL-Enhanced："
echo "   sudo -E ./run.sh 1 30 kamailio chatafl           # ChatAFL"
echo "   sudo -E ./run.sh 1 30 kamailio chatafl-enhanced  # ChatAFL-Enhanced"
echo ""
echo "3. 测试其他目标："
echo "   lightftp, bftpd, proftpd, live555, exim, 等"
echo "======================================================================"
