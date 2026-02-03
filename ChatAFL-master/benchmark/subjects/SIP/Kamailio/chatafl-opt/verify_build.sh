#!/bin/bash
#
# ChatAFL-Opt 编译验证脚本
#

set -e

cd "$(dirname "$0")"

echo "=== ChatAFL-Opt 编译验证 ==="
echo ""

# 检查关键二进制文件
echo "[1/4] 检查二进制文件..."
for binary in afl-fuzz afl-gcc afl-showmap afl-tmin; do
    if [ -f "$binary" ]; then
        echo "  ✓ $binary ($(stat -c%s $binary | numfmt --to=iec))"
    else
        echo "  ✗ $binary 缺失"
        exit 1
    fi
done

# 检查模块目标文件
echo ""
echo "[2/4] 检查模块目标文件..."
for obj in hypothesis.o verifier.o cegar.o state_scheduler.o chatafl_opt.o; do
    if [ -f "$obj" ]; then
        echo "  ✓ $obj"
    else
        echo "  ✗ $obj 缺失"
        exit 1
    fi
done

# 检查符号
echo ""
echo "[3/4] 检查关键符号..."
if nm afl-fuzz | grep -q "init_hypothesis_context"; then
    echo "  ✓ Hypothesis 模块集成"
else
    echo "  ✗ Hypothesis 模块未集成"
fi

if nm afl-fuzz | grep -q "init_verification_context"; then
    echo "  ✓ Verifier 模块集成"
else
    echo "  ✗ Verifier 模块未集成"
fi

if nm afl-fuzz | grep -q "init_cegar_context"; then
    echo "  ✓ CEGAR 模块集成"
else
    echo "  ✗ CEGAR 模块未集成"
fi

if nm afl-fuzz | grep -q "init_scheduler_context"; then
    echo "  ✓ Scheduler 模块集成"
else
    echo "  ✗ Scheduler 模块未集成"
fi

# 测试基本功能
echo ""
echo "[4/4] 测试基本功能..."
if ./afl-fuzz -h 2>&1 | grep -q "afl-fuzz"; then
    echo "  ✓ afl-fuzz 可执行"
else
    echo "  ✗ afl-fuzz 无法执行"
    exit 1
fi

echo ""
echo "=== 编译验证通过 ✓ ==="
echo ""
echo "下一步："
echo "1. 使用本地编译运行:"
echo "   export KEY=\"your-api-key\""
echo "   ./afl-fuzz -i in_dir -o out_dir -N tcp://127.0.0.1/21 -P FTP -- /path/to/target"
echo ""
echo "2. 或使用 Docker:"
echo "   ./docker-run.sh build"
echo "   ./docker-run.sh interactive"
