#!/bin/bash
#
# ChatAFL-Opt LightFTP 模糊测试脚本
# 用途：编译并模糊测试 LightFTP 服务器
#

set -e

echo "=== ChatAFL-Opt LightFTP 模糊测试 ==="
echo ""

# 检查编译
if [ ! -f "afl-fuzz" ]; then
    echo "错误: afl-fuzz 不存在，请先运行 'make'"
    exit 1
fi

# 准备 LightFTP
echo "[1/6] 准备 LightFTP 目标程序..."
LIGHTFTP_DIR="/tmp/lightftp"
SCRIPT_DIR="$PWD"

if [ ! -d "$LIGHTFTP_DIR" ]; then
    echo "  克隆 LightFTP..."
    git clone https://github.com/hfiref0x/LightFTP.git $LIGHTFTP_DIR
fi

cd $LIGHTFTP_DIR/src/Release
echo "  编译 LightFTP (使用 afl-clang-fast)..."
CC=$SCRIPT_DIR/afl-clang-fast make clean all 2>&1 | grep -v "warning:" || true
echo "  ✓ LightFTP 已编译: $LIGHTFTP_DIR/src/Release/fftp"

# 创建 FTP 共享目录
mkdir -p /tmp/ftpshare
ech$SCRIPT_DIR目录: /tmp/ftpshare"

cd - > /dev/null

# 准备种子文件
echo ""
echo "[2/6] 准备测试环境..."
mkdir -p /tmp/lightftp_in
echo -e "USER anonymous\r\nPASS test\r\nQUIT\r\n" > /tmp/lightftp_in/ftp_seed
echo "  ✓ 创建种子文件: /tmp/lightftp_in/ftp_seed"

# 检查 API Key
if [ -z "$KEY" ]; then
    echo ""
    echo "[3/6] 设置 API Key..."
    read -p "  请输入您的 OpenAI API Key (或按回车跳过): " api_key
    if [ -n "$api_key" ]; then
        export KEY="$api_key"
        echo "  ✓ API Key 已设置"
    else
        echo "  ⚠ 未设置 API Key，LLM 功能将不可用"
    fi
else
    echo ""
    echo "[3/6] API Key 已设置 ✓"
fi

# 设置环境变量
echo ""
echo "[4/6] 设置环境变量..."
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
echo "  ✓ AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1"
echo "  ✓ AFL_SKIP_CPUFREQ=1"

# 停止可能存在的旧进程
echo ""
echo "[5/6] 清理环境..."
pkill -9 fftp 2>/dev/null || true
rm -rf /tmp/lightftp_out
sleep 1
echo "  ✓ 已清理旧进程和输出目录"

# 运行模糊测试
echo ""
echo "[6/6] 运行模糊测试 (5 分钟)..."
echo "  目标: $LIGHTFTP_DIR/Source/Release/fftp 2200 /tmp/ftpshare"
echo "  参数: -dlightftp_out" ]; then
    echo "✓ 输出目录已创建: /tmp/lightftp_out"
    echo ""
    
    if [ -f "/tmp/lightftp_out/fuzzer_stats" ]; then
        echo "=== 性能统计 ==="
        grep -E "^(execs_per_sec|paths_total|execs_done|unique_crashes|unique_hangs)" /tmp/lightftp_out/fuzzer_stats
        echo ""
        echo "=== ChatAFL-Opt 扩展模块统计 ==="
        grep "^chatafl_" /tmp/lightftp_out/fuzzer_stats || echo "  (尚未触发扩展模块)"
    fi
    
    if [ -f "/tmp/lightftp_out/hypotheses.json" ]; then
        echo ""
        echo "✓ 生成假设文件"
        echo "假设数量: $(grep -c '"hypothesis"' /tmp/lightftp_out/hypotheses.json || echo 0)"
    fi
    
    if [ -d "/tmp/lightftp_out/queue" ]; then
        queue_count=$(ls -1 /tmp/lightftp_out/queue | wc -l)
        echo "✓ 队列文件数: $queue_count"
    fi
    
    if [ -d "/tmp/lightftp_out/crashes" ]; then
        crash_count=$(ls -1 /tmp/lightftp_out/crashes 2>/dev/null | wc -l)
        if [ $crash_count -gt 0 ]; then
            echo "✓ 发现崩溃: $crash_count"
        fi
    fi
else
    echo "⚠ 未找到输出目录"
fi

echo ""
echo "=== 输出文件保留位置 ==="
echo "  种子输入: /tmp/lightftp_in/"
echo "  模糊测试输出: /tmp/lightftp_out/"
echo "  LightFTP 源码: /tmp/lightftp/"
echo ""
echo "提示："
echo "  - 查看详细统计: cat /tmp/lightftp_out/fuzzer_stats"
echo "  - 查看假设生成: cat /tmp/lightftp_out/hypotheses.json"
echo "  - 查看队列文件: ls -lh /tmp/lightftp_out/queue/"
echo "  - 清理所有文件: rm -rf /tmp/lightftp_in /tmp/lightftp_out /tmp/lightftp /tmp/ftpshar true
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
