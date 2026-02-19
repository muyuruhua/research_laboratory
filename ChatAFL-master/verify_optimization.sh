#!/bin/bash
# ChatAFL-Opt 优化验证脚本
# 用于快速验证Hypothesis动态反馈和自适应Plateau触发机制

set -e

echo "=========================================="
echo "ChatAFL-Opt 优化验证"
echo "=========================================="
echo ""

# 配置
TARGET=${1:-bftpd}
DURATION=${2:-10}  # 默认10分钟快速验证
REPEAT=${3:-1}

echo "[*] 目标: $TARGET"
echo "[*] 时长: ${DURATION}分钟"
echo "[*] 重复: ${REPEAT}次"
echo ""

# 运行实验
echo "[*] 启动实验..."
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"
sudo -E ./run_dev.sh $REPEAT $DURATION $TARGET chatafl-opt,chatafl

# 等待完成
echo ""
echo "[*] 实验完成，开始分析..."
sleep 2

# 获取最新结果目录
RESULTS_DIR=$(ls -td results-${TARGET}_* | head -1)
echo "[*] 结果目录: $RESULTS_DIR"
echo ""

# 验证新增的统计指标
echo "=========================================="
echo "优化指标验证"
echo "=========================================="
echo ""

for variant in chatafl chatafl_opt; do
    STATS_FILE="$RESULTS_DIR/out-${TARGET}-${variant}_1/fuzzer_stats"
    
    if [ ! -f "$STATS_FILE" ]; then
        echo "⚠️  未找到 $STATS_FILE"
        continue
    fi
    
    echo "=== $variant ==="
    
    # 检查Hypothesis统计
    if grep -q "hypothesis_count" "$STATS_FILE"; then
        echo "✅ Hypothesis统计:"
        grep "hypothesis_count" "$STATS_FILE"
        grep "hypothesis_parse_success" "$STATS_FILE"
        grep "hypothesis_parse_failure" "$STATS_FILE"
        grep "hypothesis_avg_fitness" "$STATS_FILE"
    else
        echo "❌ 未找到Hypothesis统计"
    fi
    
    # 检查Plateau统计
    if grep -q "plateau_calls" "$STATS_FILE"; then
        echo "✅ Plateau统计:"
        grep "plateau_calls" "$STATS_FILE"
        grep "plateau_threshold" "$STATS_FILE"
        grep "edges_growth_rate" "$STATS_FILE"
    else
        echo "❌ 未找到Plateau统计"
    fi
    
    # 基础指标
    echo "📊 基础指标:"
    grep "execs_done" "$STATS_FILE"
    grep "execs_per_sec" "$STATS_FILE"
    grep "bitmap_cvg" "$STATS_FILE"
    grep "variable_paths" "$STATS_FILE"
    
    echo ""
done

# 检查日志中的动态调整信息
echo "=========================================="
echo "运行时日志验证"
echo "=========================================="
echo ""

CONTAINER_IDS=$(docker ps -a --format "{{.ID}}" --filter "ancestor=${TARGET}" | head -2)

for CID in $CONTAINER_IDS; do
    echo "=== 容器 $CID ==="
    
    # 检查adaptive-plateau日志
    if docker logs "$CID" 2>&1 | grep -q "adaptive-plateau"; then
        echo "✅ 发现自适应Plateau日志:"
        docker logs "$CID" 2>&1 | grep "adaptive-plateau" | tail -5
    else
        echo "⚠️  未发现adaptive-plateau日志"
    fi
    
    # 检查hypothesis fitness日志
    if docker logs "$CID" 2>&1 | grep -q "hypothesis.*fitness"; then
        echo "✅ 发现Hypothesis fitness日志:"
        docker logs "$CID" 2>&1 | grep "hypothesis.*fitness" | tail -5
    else
        echo "⚠️  未发现hypothesis fitness日志"
    fi
    
    # 检查plateau触发日志
    if docker logs "$CID" 2>&1 | grep -q "plateau-trigger"; then
        echo "✅ 发现Plateau触发日志:"
        docker logs "$CID" 2>&1 | grep "plateau-trigger" | tail -3
    else
        echo "ℹ️  未发现plateau触发（可能未达到阈值）"
    fi
    
    echo ""
done

# 对比edges增长
echo "=========================================="
echo "覆盖率对比"
echo "=========================================="
echo ""

if [ -f "$RESULTS_DIR/states.csv" ]; then
    echo "📈 状态覆盖 (nodes/edges):"
    tail -2 "$RESULTS_DIR/states.csv"
else
    echo "⚠️  未找到states.csv"
fi

echo ""
echo "=========================================="
echo "验证完成"
echo "=========================================="
echo ""
echo "💡 提示:"
echo "  1. parse_success/failure > 0: 动态反馈机制工作正常"
echo "  2. adaptive_plateau_threshold变化: 自适应触发工作正常"
echo "  3. edges_growth_rate数值合理: 增长率计算正确"
echo "  4. 对比chatafl vs chatafl_opt的variable_paths: 优化效果"
echo ""
