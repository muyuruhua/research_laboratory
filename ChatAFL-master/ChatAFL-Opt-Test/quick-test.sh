#!/bin/bash
#
# ChatAFL-Opt LightFTP 模糊测试脚本
# 用途：编译并模糊测试 LightFTP 服务器
#

# 移除 set -e，改为手动错误检查，避免因为 sudo 等问题导致脚本意外退出
set +e

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
echo "  准备编译 LightFTP..."
cd $LIGHTFTP_DIR/src/Release || { echo "  ✗ 无法进入目录"; exit 1; }

echo "  检查 gnutls 依赖..."
if dpkg -l 2>/dev/null | grep -q "^ii.*libgnutls28-dev"; then
    echo "  ✓ gnutls 已安装"
else
    echo "  ⚠ libgnutls28-dev 未安装"
    echo "  请手动运行: sudo apt-get install -y libgnutls28-dev"
    echo "  继续尝试编译..."
fi

echo "  清理旧文件..."
make clean >/dev/null 2>&1

echo "  开始编译 (使用 afl-gcc)..."
echo "  这可能需要1-2分钟，请稍候..."
CC=$SCRIPT_DIR/afl-gcc make all 2>&1 | tee /tmp/lightftp_compile.log | tail -5

if [ -f "fftp" ]; then
    echo "  ✓ LightFTP 编译成功: $LIGHTFTP_DIR/src/Release/fftp"
    ls -lh fftp
else
    echo "  ✗ LightFTP 编译失败"
    echo "  查看完整日志: cat /tmp/lightftp_compile.log"
    echo "  常见问题: 缺少 libgnutls28-dev 依赖"
    exit 1
fi

# 创建 FTP 共享目录
mkdir -p /tmp/ftpshare
echo "  ✓ FTP 共享目录: /tmp/ftpshare"

cd - > /dev/null

# 准备种子文件
echo ""
echo "[2/6] 准备测试环境..."
mkdir -p /tmp/lightftp_in
echo -e "USER anonymous\r\nPASS test\r\nQUIT\r\n" > /tmp/lightftp_in/ftp_seed
echo "  ✓ 创建种子文件: /tmp/lightftp_in/ftp_seed"

# 设置 API Key
echo ""
echo "[3/6] 设置 API Key..."
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"
echo "  ✓ API Key 已设置"

# 设置环境变量
echo ""
echo "[4/6] 设置环境变量..."
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_ENABLE_CHATAFL_OPT=1
export AFL_OUT_DIR=/tmp/lightftp_out
echo "  ✓ AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1"
echo "  ✓ AFL_SKIP_CPUFREQ=1"
echo "  ✓ AFL_ENABLE_CHATAFL_OPT=1 (启用 ChatAFL-Opt 优化)"
echo "  ✓ AFL_OUT_DIR=/tmp/lightftp_out"

# 停止可能存在的旧进程
echo ""
echo "[5/6] 清理环境..."
pkill -9 fftp 2>/dev/null || true
rm -rf /tmp/lightftp_out
sleep 1
echo "  ✓ 已清理旧进程和输出目录"

# 运行模糊测试
echo ""
echo "[6/6] 运行 ChatAFL-Opt 模糊测试 (5 分钟)..."
echo "  目标: $LIGHTFTP_DIR/src/Release/fftp 2200 /tmp/ftpshare"
echo "  参数: -i /tmp/lightftp_in -o /tmp/lightftp_out -N tcp://127.0.0.1/2200 -P FTP -t 5000"
echo "  ChatAFL-Opt 特性: LLM假设生成 + 4阶段验证 + CEGAR修正 + STT调度"
echo ""
echo "  开始模糊测试..."
timeout 300 $SCRIPT_DIR/afl-fuzz -i /tmp/lightftp_in -o /tmp/lightftp_out -N tcp://127.0.0.1/2200 -P FTP -t 5000 -- $LIGHTFTP_DIR/src/Release/fftp 2200 /tmp/ftpshare || true
echo ""
echo "  模糊测试已完成 (或超时退出)"

echo ""
echo "=== 模糊测试完成 ==="
if [ -d "/tmp/lightftp_out" ]; then
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
echo "  - 清理所有文件: rm -rf /tmp/lightftp_in /tmp/lightftp_out /tmp/lightftp /tmp/ftpshare"
