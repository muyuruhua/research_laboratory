#!/bin/bash
# ChatAFL-Enhanced编译测试脚本

cd /home/ckt/Documents/000_2026_dev/research_laboratory/ChatAFL-master/ChatAFL-Enhanced

echo "[1/5] 清理旧编译文件..."
make clean

echo ""
echo "[2/5] 编译新模块 (verifier, cegar, state-scheduler)..."
make verifier.o cegar.o state-scheduler.o

if [ $? -ne 0 ]; then
    echo "❌ 模块编译失败！"
    exit 1
fi

echo ""
echo "[3/5] 编译chat-llm模块..."
make chat-llm.o

if [ $? -ne 0 ]; then
    echo "❌ chat-llm编译失败！"
    exit 1
fi

echo ""
echo "[4/5] 编译主fuzzer (afl-fuzz)..."
make afl-fuzz

if [ $? -ne 0 ]; then
    echo "❌ afl-fuzz编译失败！"
    exit 1
fi

echo ""
echo "[5/5] 编译其他工具..."
make afl-gcc afl-showmap afl-replay

echo ""
echo "✅ ChatAFL-Enhanced编译成功！"
echo ""
echo "生成的文件："
ls -lh afl-fuzz afl-gcc verifier.o cegar.o state-scheduler.o
echo ""
echo "下一步："
echo "  1. 运行单元测试（如果有）"
echo "  2. 重新构建Docker镜像: sudo KEY='your-key' ./setup.sh"
echo "  3. 运行对比实验: ./run_comparison.sh <target> 5 60"
