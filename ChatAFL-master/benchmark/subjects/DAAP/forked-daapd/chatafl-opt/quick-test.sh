#!/bin/bash
#
# ChatAFL-Opt 快速测试脚本
# 用途：验证编译和基本功能是否正常
#

set -e

echo "=== ChatAFL-Opt 快速功能测试 ==="
echo ""

# 检查编译
if [ ! -f "afl-fuzz" ]; then
    echo "错误: afl-fuzz 不存在，请先运行 'make'"
    exit 1
fi

# 准备种子文件
echo "[1/4] 准备测试环境..."
mkdir -p /tmp/afl_in_test
echo -e "USER anonymous\r\nPASS test\r\nQUIT\r\n" > /tmp/afl_in_test/seed.txt
echo "  ✓ 创建种子文件: /tmp/afl_in_test/seed.txt"

# 检查 API Key
if [ -z "$KEY" ]; then
    echo ""
    echo "[2/4] 设置 API Key..."
    read -p "  请输入您的 OpenAI API Key (或按回车跳过): " api_key
    if [ -n "$api_key" ]; then
        export KEY="$api_key"
        echo "  ✓ API Key 已设置"
    else
        echo "  ⚠ 未设置 API Key，LLM 功能将不可用"
    fi
else
    echo "[2/4] API Key 已设置 ✓"
fi

# 设置环境变量
echo ""
echo "[3/4] 设置环境变量..."
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
echo "  ✓ AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1"
echo "  ✓ AFL_SKIP_CPUFREQ=1"

# 运行短时间测试
echo ""
echo "[4/4] 运行 10 秒测试..."
echo "  命令: timeout 10s ./afl-fuzz -i /tmp/afl_in_test -o /tmp/afl_out_test -N tcp://127.0.0.1/21 -P FTP -- /bin/true"
echo ""

timeout 10s ./afl-fuzz -i /tmp/afl_in_test -o /tmp/afl_out_test -N tcp://127.0.0.1/21 -P FTP -- /bin/true || true

echo ""
echo "=== 测试完成 ==="
echo ""

# 检查输出
if [ -d "/tmp/afl_out_test" ]; then
    echo "✓ 输出目录已创建: /tmp/afl_out_test"
    
    if [ -f "/tmp/afl_out_test/hypotheses.json" ]; then
        echo "✓ 生成假设文件"
        echo ""
        echo "假设内容预览:"
        head -20 /tmp/afl_out_test/hypotheses.json || true
    fi
    
    if [ -f "/tmp/afl_out_test/statistics.txt" ]; then
        echo ""
        echo "✓ 生成统计文件"
        echo ""
        echo "统计内容:"
        cat /tmp/afl_out_test/statistics.txt || true
    fi
else
    echo "⚠ 未找到输出目录"
fi

echo ""
echo "清理测试文件..."
rm -rf /tmp/afl_in_test /tmp/afl_out_test
echo "✓ 清理完成"

echo ""
echo "下一步："
echo "1. 编译真实目标程序: CC=afl-clang-fast make"
echo "2. 运行完整测试: ./afl-fuzz -i in_dir -o out_dir -N tcp://target:port -P PROTOCOL -- /path/to/target"
echo "3. 或使用 Docker: ./docker-run.sh interactive"
