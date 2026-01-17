#!/bin/bash
# 快速验证修复效果

echo "运行快速验证测试（2分钟）..."
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

# 运行短时间测试（2分钟足够生成统计数据）
./compare_fuzzers_docker.sh LightFTP FTP 2

# 检查结果
RESULT_DIR=$(ls -t comparison_results/ | head -1)
echo ""
echo "========== 验证结果 =========="

CHATAFL_PATHS=$(grep "paths_total" "comparison_results/$RESULT_DIR/chatafl/fuzzer_stats" 2>/dev/null | awk '{print $NF}')
ENHANCED_PATHS=$(grep "paths_total" "comparison_results/$RESULT_DIR/chatafl-enhanced/fuzzer_stats" 2>/dev/null | awk '{print $NF}')

echo "ChatAFL paths: ${CHATAFL_PATHS:-N/A}"
echo "Enhanced paths: ${ENHANCED_PATHS:-N/A}"

# 检查是否有数据
if [ -z "$CHATAFL_PATHS" ] || [ -z "$ENHANCED_PATHS" ]; then
    echo "✗ 错误: 未找到fuzzer_stats文件，测试可能失败"
    echo "  查看日志: cat comparison_results/$RESULT_DIR/chatafl.log"
    echo "  查看日志: cat comparison_results/$RESULT_DIR/enhanced.log"
    exit 1
fi

# 计算95%基准
BASELINE=$(echo "$CHATAFL_PATHS * 0.95" | bc 2>/dev/null | cut -d. -f1)

if [ "$ENHANCED_PATHS" -ge "$BASELINE" ] 2>/dev/null; then
    echo "✓ 修复成功：Enhanced性能已恢复到ChatAFL的95%以上"
    exit 0
else
    echo "✗ 修复不完整：Enhanced仍低于ChatAFL的95%"
    exit 1
fi
