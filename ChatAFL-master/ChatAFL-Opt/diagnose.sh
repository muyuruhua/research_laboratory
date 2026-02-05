#!/bin/bash
echo "=== 诊断脚本 ==="
echo ""

echo "1. 检查 gnutls 库是否安装:"
dpkg -l | grep libgnutls28-dev && echo "  ✓ 已安装" || echo "  ✗ 未安装"
echo ""

echo "2. 检查 LightFTP 是否克隆:"
if [ -d "/tmp/lightftp" ]; then
    echo "  ✓ /tmp/lightftp 存在"
else
    echo "  ✗ /tmp/lightftp 不存在"
fi
echo ""

echo "3. 检查 fftp 是否编译:"
if [ -f "/tmp/lightftp/src/Release/fftp" ]; then
    echo "  ✓ fftp 已编译"
    ls -lh /tmp/lightftp/src/Release/fftp
else
    echo "  ✗ fftp 未编译"
fi
echo ""

echo "4. 手动编译测试 (不使用 afl-gcc):"
if [ -d "/tmp/lightftp/src/Release" ]; then
    cd /tmp/lightftp/src/Release
    echo "  尝试编译..."
    make clean 2>&1 | tail -3
    make 2>&1 | tail -10
    if [ -f "fftp" ]; then
        echo "  ✓ 编译成功"
    else
        echo "  ✗ 编译失败，可能缺少依赖"
    fi
else
    echo "  ✗ 源码目录不存在"
fi
echo ""

echo "5. 检查 AFL 工具:"
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/ChatAFL-Opt
if [ -f "afl-gcc" ]; then
    echo "  ✓ afl-gcc 存在"
    ./afl-gcc --version 2>&1 | head -3
else
    echo "  ✗ afl-gcc 不存在"
fi
echo ""

echo "诊断完成！"
