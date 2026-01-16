#!/bin/bash
# 对比实验自动化脚本
# 用法: ./run_comparison.sh <target> <runs> <time_minutes>

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET=${1:-exim}
RUNS=${2:-5}
TIME=${3:-240}

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║       ChatAFL vs ChatAFL-Enhanced 对比实验                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""
echo "📋 实验配置:"
echo "  • 目标程序: $TARGET"
echo "  • 并行容器数: $RUNS"
echo "  • 运行时长: $TIME 分钟 ($(($TIME / 60)) 小时)"
echo ""

# 检查 ChatAFL-Enhanced 是否存在
if [ ! -d "ChatAFL-Enhanced" ]; then
    echo "❌ ChatAFL-Enhanced 文件夹不存在"
    echo "   请运行: cp -r ChatAFL/ ChatAFL-Enhanced"
    exit 1
fi

# 检查是否已运行 setup.sh
if [ ! -d "benchmark/subjects/SMTP/Exim/chatafl-enhanced" ] && [ "$TARGET" == "exim" ]; then
    echo "⚠️  检测到 chatafl-enhanced 未集成到 benchmark"
    echo "   正在运行 setup.sh..."
    if [ -z "$KEY" ]; then
        echo "❌ 请先设置 OpenAI API Key: export KEY='sk-xxx'"
        exit 1
    fi
    ./setup.sh
fi

# 显示资源需求
TOTAL_CONTAINERS=$(($RUNS * 2))
echo "💻 资源需求:"
echo "  • CPU 核心: $TOTAL_CONTAINERS (每个容器 1 核)"
echo "  • 内存: 约 $(($TOTAL_CONTAINERS * 2))GB"
echo "  • 磁盘: 约 $(($TOTAL_CONTAINERS * 1))GB (用于结果存储)"
echo ""

read -p "🚀 是否开始实验? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ 实验已取消"
    exit 1
fi

# 运行实验（依次运行两个版本）
echo ""
echo "⏳ 启动 chatafl 容器..."
./run.sh $RUNS $TIME $TARGET chatafl
wait  # 等待所有后台容器启动脚本完成

echo ""
echo "⏳ 启动 chatafl-enhanced 容器..."
./run.sh $RUNS $TIME $TARGET chatafl-enhanced
wait  # 等待所有后台容器启动脚本完成

# 监控进度
echo ""
echo "📊 实时监控 (Ctrl+C 退出监控，不影响后台容器):"
echo ""

# 记录开始时间
START_TIME=$(date +%s)

# 监控容器运行
while docker ps | grep -q "$TARGET"; do
    ACTIVE=$(docker ps | grep "$TARGET" | wc -l)
    ELAPSED=$(($(date +%s) - START_TIME))
    ELAPSED_MIN=$((ELAPSED / 60))
    echo -ne "\r  运行中的容器: $ACTIVE/$TOTAL_CONTAINERS | 已运行: ${ELAPSED_MIN}分钟 | $(date +%H:%M:%S)    "
    sleep 10
done

# 等待监控结束

echo ""
echo ""
echo "✅ 所有容器已完成运行"

# 分析结果
echo ""
echo "📈 分析结果..."
./analyze.sh $TARGET $TIME

# 显示结果位置
RESULT_DIR=$(ls -td res_${TARGET}_* 2>/dev/null | head -1)
if [ -d "$RESULT_DIR" ]; then
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                    实验完成！                             ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    echo "📁 结果保存在: $RESULT_DIR"
    echo ""
    echo "📊 生成的文件:"
    ls -lh $RESULT_DIR/*.png 2>/dev/null | awk '{print "  📈 " $9 " (" $5 ")"}'
    ls -lh $RESULT_DIR/*.csv 2>/dev/null | awk '{print "  📋 " $9 " (" $5 ")"}'
    echo ""
    
    # 显示快速对比
    if [ -f "$RESULT_DIR/cov_over_time_${TARGET}.csv" ]; then
        echo "🔍 快速对比 (最终数据):"
        tail -1 "$RESULT_DIR/cov_over_time_${TARGET}.csv"
    fi
else
    echo "⚠️  未找到分析结果文件夹"
    echo "   请手动运行: ./analyze.sh $TARGET $TIME"
fi

echo ""
echo "💡 提示:"
echo "  • 查看图表: xdg-open $RESULT_DIR/cov_over_time_${TARGET}.png"
echo "  • 查看原始数据: cd benchmark/results-${TARGET}/"
echo "  • 重新分析: ./analyze.sh $TARGET $TIME"
echo ""
